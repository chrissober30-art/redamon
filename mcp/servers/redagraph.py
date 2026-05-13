#!/usr/bin/env python3
"""
redagraph — Tenant-scoped CLI for the RedAmon graph database.

Runs inside kali-sandbox. Reads REDAMON_USER_ID and REDAMON_PROJECT_ID from
the environment (injected by the terminal server when launched from the
webapp Graph -> Terminal tab) and silently scopes every Cypher query to that
tenant. Supports raw Cypher, natural-language questions (text-to-cypher via
the agent), and shorthand commands like `ls <NodeType>`.

Output is plain (one value per line) by default so it composes with grep,
sort, uniq, wc, jq, and shell redirection.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from graph_db.tenant_filter import (
    find_disallowed_write_operation,
    inject_tenant_filter,
)

import re

_LABEL_NODE_RE = re.compile(r'\(\w+:\w+')


def _eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def _require_tenant() -> tuple[str, str]:
    user_id = os.environ.get("REDAMON_USER_ID", "").strip()
    project_id = os.environ.get("REDAMON_PROJECT_ID", "").strip()
    if not user_id or not project_id:
        _eprint(
            "redagraph: no active project. Open the terminal via the webapp "
            "Graph -> Terminal tab so the project context is set."
        )
        sys.exit(2)
    return user_id, project_id


def _connect():
    from neo4j import GraphDatabase

    uri = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "changeme123")
    return GraphDatabase.driver(uri, auth=(user, password))


def _to_plain(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)


def _coerce(v: Any) -> Any:
    """Recursively convert Neo4j driver values (Node, Relationship, Path, list)
    into JSON-serialisable primitives so output formats stay clean."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, list):
        return [_coerce(x) for x in v]
    if isinstance(v, tuple):
        return [_coerce(x) for x in v]
    if isinstance(v, dict):
        return {k: _coerce(x) for k, x in v.items()}
    # Neo4j Node: has `labels` and supports .items() for properties.
    labels = getattr(v, "labels", None)
    if labels is not None and hasattr(v, "items"):
        return {
            "_kind": "node",
            "labels": sorted(labels) if hasattr(labels, "__iter__") else [str(labels)],
            "properties": {k: _coerce(x) for k, x in v.items()},
        }
    # Neo4j Relationship: has `type` and supports .items().
    rel_type = getattr(v, "type", None)
    if rel_type is not None and hasattr(v, "items") and hasattr(v, "nodes"):
        return {
            "_kind": "relationship",
            "type": str(rel_type),
            "properties": {k: _coerce(x) for k, x in v.items()},
        }
    if hasattr(v, "items"):
        return {k: _coerce(x) for k, x in v.items()}
    return str(v)


def _record_to_dict(record) -> Dict[str, Any]:
    return {key: _coerce(record[key]) for key in record.keys()}


def _node_display(coerced: Any) -> Any:
    """For plain/tsv emit: render a coerced node or relationship as a compact
    `key=value key=value ...` form so all properties survive the trip to text.
    The CLI deliberately does NOT pick a single attribute — that would override
    the user's NL intent (e.g. when they asked "return all attributes").
    Use `redagraph -f json` for full structured output."""
    if isinstance(coerced, dict) and coerced.get("_kind") in ("node", "relationship"):
        props = coerced.get("properties", {})
        return " ".join(f"{k}={_to_plain(v)}" for k, v in props.items())
    return coerced


def _emit(records: List, fmt: str, out) -> None:
    if not records:
        return
    keys = list(records[0].keys())
    rows = [{k: _coerce(r[k]) for k in keys} for r in records]

    if fmt == "json":
        for row in rows:
            out.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
        return

    if fmt == "tsv":
        out.write("\t".join(keys) + "\n")
        for row in rows:
            out.write("\t".join(_to_plain(_node_display(row[k])) for k in keys) + "\n")
        return

    # plain
    if len(keys) == 1:
        k = keys[0]
        for row in rows:
            out.write(_to_plain(_node_display(row[k])) + "\n")
    else:
        _eprint("\t".join(keys))
        for row in rows:
            out.write("\t".join(_to_plain(_node_display(row[k])) for k in keys) + "\n")


def _execute(cypher: str, user_id: str, project_id: str, require_labels: bool = True) -> List:
    bad = find_disallowed_write_operation(cypher)
    if bad:
        _eprint(f"redagraph: write operation rejected ({bad}). This CLI is read-only.")
        sys.exit(3)

    # The tenant filter only injects on labelled node patterns. A query with no
    # labelled patterns (e.g. `MATCH (n) RETURN n`) would run un-scoped and leak
    # cross-tenant data. Refuse it unless the caller already wired explicit WHERE
    # filters with $tenant_user_id / $tenant_project_id.
    if require_labels and not _LABEL_NODE_RE.search(cypher):
        _eprint(
            "redagraph: query has no labelled node patterns; tenant filter cannot "
            "scope it. Add a label, e.g. (n:Subdomain), or use `redagraph types`."
        )
        sys.exit(3)

    filtered = inject_tenant_filter(cypher, user_id, project_id)
    params = {"tenant_user_id": user_id, "tenant_project_id": project_id}

    driver = _connect()
    try:
        with driver.session() as session:
            return list(session.run(filtered, params))
    finally:
        driver.close()


def cmd_whoami(args, _user_id: str, _project_id: str) -> int:
    print(f"user_id    {_user_id}")
    print(f"project_id {_project_id}")
    print(f"neo4j_uri  {os.environ.get('NEO4J_URI', 'bolt://neo4j:7687')}")
    print(f"agent_url  {os.environ.get('REDAMON_AGENT_URL', 'http://agent:8080')}")
    return 0


def cmd_types(args, user_id: str, project_id: str) -> int:
    # Anonymous MATCH (n) is NOT touched by the inline-property tenant filter
    # (the regex requires a labelled node), so use an explicit WHERE instead.
    cypher = (
        "MATCH (n) "
        "WHERE n.user_id = $tenant_user_id AND n.project_id = $tenant_project_id "
        "UNWIND labels(n) AS label "
        "RETURN DISTINCT label AS type "
        "ORDER BY type"
    )
    records = _execute(cypher, user_id, project_id, require_labels=False)
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_schema(args, user_id: str, project_id: str) -> int:
    driver = _connect()
    try:
        with driver.session() as session:
            records = list(session.run("CALL db.schema.visualization()"))
    finally:
        driver.close()
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_ls(args, user_id: str, project_id: str) -> int:
    label = args.node_type
    if not label.isidentifier():
        _eprint(f"redagraph: invalid node type {label!r}")
        return 2
    attr = args.attr
    if not attr.replace("_", "").isalnum():
        _eprint(f"redagraph: invalid attribute {attr!r}")
        return 2

    limit_clause = f" LIMIT {int(args.limit)}" if args.limit else ""
    cypher = (
        f"MATCH (n:{label}) "
        f"RETURN n.{attr} AS {attr} "
        f"ORDER BY {attr}{limit_clause}"
    )
    records = _execute(cypher, user_id, project_id)
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_cypher(args, user_id: str, project_id: str) -> int:
    records = _execute(args.query, user_id, project_id)
    _emit(records, args.format, sys.stdout)
    return 0


def cmd_ask(args, user_id: str, project_id: str) -> int:
    import requests

    agent_url = os.environ.get("REDAMON_AGENT_URL", "http://agent:8080").rstrip("/")
    question = " ".join(args.question) if isinstance(args.question, list) else args.question
    try:
        resp = requests.post(
            f"{agent_url}/text-to-cypher",
            json={
                "question": question,
                "user_id": user_id,
                "project_id": project_id,
                # Tell the agent we want scalar values, not whole nodes — so a
                # question like "subdomain names only" yields RETURN s.name.
                "for_graph_view": False,
            },
            timeout=120,
        )
    except requests.RequestException as e:
        _eprint(f"redagraph: cannot reach agent at {agent_url}: {e}")
        return 4

    if resp.status_code != 200:
        try:
            err = resp.json().get("error", resp.text)
        except Exception:
            err = resp.text
        _eprint(f"redagraph: agent returned {resp.status_code}: {err}")
        return 4

    cypher = resp.json().get("cypher", "").strip()
    if not cypher:
        _eprint("redagraph: agent returned empty Cypher")
        return 4

    if args.show:
        _eprint(f"# {cypher}")

    records = _execute(cypher, user_id, project_id)
    _emit(records, args.format, sys.stdout)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redagraph",
        description="Tenant-scoped graph CLI for RedAmon. Read-only.",
    )
    p.add_argument(
        "--format", "-f",
        choices=("plain", "json", "tsv"),
        default="plain",
        help="Output format (default: plain — one value per line for single-column results).",
    )
    p.add_argument(
        "-o", "--output",
        help="Write to FILE instead of stdout (same effect as shell '> FILE').",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("whoami", help="Print active user_id / project_id.")
    sp.set_defaults(func=cmd_whoami)

    sp = sub.add_parser("types", help="List distinct node labels present in this project.")
    sp.set_defaults(func=cmd_types)

    sp = sub.add_parser("schema", help="Dump the live Neo4j schema (labels + relationships).")
    sp.set_defaults(func=cmd_schema)

    sp = sub.add_parser("ls", help="List nodes of a given type, emitting one attribute per line.")
    sp.add_argument("node_type", help="Node label (e.g. Subdomain, Endpoint, IP).")
    sp.add_argument("-a", "--attr", default="name", help="Attribute to emit (default: name).")
    sp.add_argument("--limit", type=int, default=0, help="Max rows (0 = unlimited).")
    sp.set_defaults(func=cmd_ls)

    sp = sub.add_parser("cypher", help="Run a literal Cypher query (read-only).")
    sp.add_argument("query", help="Cypher query (tenant filter is added automatically).")
    sp.set_defaults(func=cmd_cypher)

    sp = sub.add_parser("ask", help="Natural-language question; agent generates the Cypher.")
    sp.add_argument("question", nargs="+", help="Plain-English question about the graph (no need to quote).")
    sp.add_argument("--show", action="store_true", help="Print the generated Cypher to stderr.")
    sp.set_defaults(func=cmd_ask)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    user_id, project_id = _require_tenant()

    if args.output:
        # Replace stdout with the requested file for the duration of the command.
        try:
            f = open(args.output, "w", encoding="utf-8")
        except OSError as e:
            _eprint(f"redagraph: cannot open {args.output}: {e}")
            return 2
        sys.stdout = f
        try:
            return args.func(args, user_id, project_id)
        finally:
            sys.stdout.flush()
            f.close()
    return args.func(args, user_id, project_id)


if __name__ == "__main__":
    sys.exit(main())
