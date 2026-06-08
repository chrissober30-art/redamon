#!/usr/bin/env python3
"""Verify the AI surface recon lap-1 graph state after a scan against the lab.

Runs the three plan queries from
``internal/ADVERSARIAL_AI/AI_SURFACE_RECON.md §16.4`` against the running
Neo4j and prints a pass/fail report. Returns exit code 0 when every
expected annotation is present (or the matching `--expect-*-empty` flag
explicitly says it should be absent), 1 otherwise.

Usage:

    # Standard verification — every expected AI annotation must be present.
    python3 verify_lab_graph_state.py --project-id <pid> --user-id <uid>

    # Toggle smoke — assert that specific AI annotations are ABSENT after
    # the corresponding toggle was flipped off and the scan re-ran:
    python3 verify_lab_graph_state.py --project-id <pid> --user-id <uid> \\
        --expect-port-ai-empty           # PORT_SCAN_AI_PORT_CATALOG_ENABLED=false
    python3 verify_lab_graph_state.py --project-id <pid> --user-id <uid> \\
        --expect-http-ai-empty           # HTTP_PROBE_AI_HEADER_SCAN_ENABLED=false
    python3 verify_lab_graph_state.py --project-id <pid> --user-id <uid> \\
        --expect-dns-ai-empty            # DOMAIN_RECON_AI_TXT_HINT_ENABLED=false

Environment overrides:
    NEO4J_URI       (default: bolt://localhost:7687)
    NEO4J_PASSWORD  (default: changeme123)
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Iterable


# ANSI colour codes for pretty terminal output (degrades gracefully when piped)
_C_GREEN = "\x1b[32m" if sys.stdout.isatty() else ""
_C_RED = "\x1b[31m" if sys.stdout.isatty() else ""
_C_YEL = "\x1b[33m" if sys.stdout.isatty() else ""
_C_END = "\x1b[0m" if sys.stdout.isatty() else ""


def _print_check(ok: bool, label: str, detail: str = "") -> None:
    tag = f"{_C_GREEN}PASS{_C_END}" if ok else f"{_C_RED}FAIL{_C_END}"
    print(f"  [{tag}] {label}{(': ' + detail) if detail else ''}")


def _print_warn(label: str, detail: str = "") -> None:
    print(f"  [{_C_YEL}WARN{_C_END}] {label}{(': ' + detail) if detail else ''}")


def _driver():
    from neo4j import GraphDatabase  # type: ignore
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    pwd = os.environ.get("NEO4J_PASSWORD", "changeme123")
    return GraphDatabase.driver(uri, auth=("neo4j", pwd))


def _q1_ai_technology_rollup(session, uid: str, pid: str) -> list[dict]:
    rows = session.run(
        """
        MATCH (t:Technology)
        WHERE t.category STARTS WITH 'ai-'
          AND t.user_id = $uid AND t.project_id = $pid
        RETURN t.category AS category, t.name AS name
        ORDER BY category, name
        """,
        uid=uid, pid=pid,
    )
    return [dict(r) for r in rows]


def _q2_ai_baseurls(session, uid: str, pid: str) -> list[dict]:
    rows = session.run(
        """
        MATCH (u:BaseURL)
        WHERE u.is_ai_framework_detected = true
          AND u.user_id = $uid AND u.project_id = $pid
        RETURN u.url AS url, u.ai_framework_name AS framework,
               u.ai_frontend_product_guess AS product
        """,
        uid=uid, pid=pid,
    )
    return [dict(r) for r in rows]


def _q3_ai_subdomain_hints(session, uid: str, pid: str) -> list[dict]:
    rows = session.run(
        """
        MATCH (s:Subdomain)
        WHERE s.ai_service_hint IS NOT NULL
          AND s.user_id = $uid AND s.project_id = $pid
        RETURN s.name AS name, s.ai_service_hint AS hint
        """,
        uid=uid, pid=pid,
    )
    return [dict(r) for r in rows]


def _q4_catchall_ai_annotated_nodes(session, uid: str, pid: str) -> list[dict]:
    rows = session.run(
        """
        MATCH (n)
        WHERE any(k IN keys(n)
                  WHERE k STARTS WITH 'ai_' OR k STARTS WITH 'is_ai_')
          AND n.user_id = $uid AND n.project_id = $pid
        RETURN labels(n) AS label, count(*) AS n
        """,
        uid=uid, pid=pid,
    )
    return [dict(r) for r in rows]


def _q5_disambiguate_port_8000_is_not_ai(session, uid: str, pid: str) -> int:
    """Chroma listens on port 8000 (`disambiguate=True` in catalog). Lap 1
    must NOT auto-promote it to an AI Technology node from port_scan
    alone. Returns count of ai-vector-db Technology nodes tied to a
    port-8000 Service. Must be 0."""
    row = session.run(
        """
        MATCH (svc:Service {port_number: 8000})-[r:USES_TECHNOLOGY]->(t:Technology)
        WHERE t.category = 'ai-vector-db'
          AND svc.user_id = $uid AND svc.project_id = $pid
          AND r.detected_by IN ['naabu-ai-port', 'masscan-ai-port']
        RETURN count(t) AS n
        """,
        uid=uid, pid=pid,
    ).single()
    return row["n"] if row else 0


def _expected_runtime_technologies() -> Iterable[tuple[str, str]]:
    return [("ai-runtime", "ollama")]


def _expected_frontend_baseurl_marker() -> tuple[str, str]:
    return ("open-webui", "ai-frontend")


def verify(args: argparse.Namespace) -> int:
    drv = _driver()
    try:
        drv.verify_connectivity()
    except Exception as exc:
        print(f"[{_C_RED}FAIL{_C_END}] Neo4j unreachable at {os.environ.get('NEO4J_URI', 'bolt://localhost:7687')}: {exc}")
        return 2

    failures: list[str] = []
    try:
        with drv.session() as s:
            print(f"\n→ Phase 6 verification (project_id={args.project_id}, user_id={args.user_id})\n")

            # Query 1 — Technology rollup
            techs = _q1_ai_technology_rollup(s, args.user_id, args.project_id)
            print(f"Q1 — AI Technology rollup ({len(techs)} rows):")
            for t in techs:
                print(f"        {t['category']:14s}  {t['name']}")
            tech_names = {t["name"] for t in techs}
            if args.expect_port_ai_empty:
                expected_runtime_present = "ollama" in tech_names
                ok = not expected_runtime_present
                _print_check(
                    ok,
                    "port-toggle-off invariant — no ai-runtime Technology from port_scan",
                    "" if ok else f"unexpected: {sorted(tech_names)}",
                )
                if not ok:
                    failures.append("Q1: port_scan AI annotations still present after toggle off")
            else:
                for category, name in _expected_runtime_technologies():
                    found = any(t["category"] == category and t["name"] == name for t in techs)
                    _print_check(
                        found,
                        f"Technology({name}, category={category}) present",
                        "" if found else f"expected one of {sorted(tech_names)}",
                    )
                    if not found:
                        failures.append(f"Q1: missing Technology({name}, category={category})")

            # Query 2 — AI BaseURLs
            urls = _q2_ai_baseurls(s, args.user_id, args.project_id)
            print(f"\nQ2 — AI-flagged BaseURLs ({len(urls)} rows):")
            for u in urls:
                print(f"        {u['url']}  framework={u['framework']}  product={u['product']}")
            if args.expect_http_ai_empty:
                ok = not urls
                _print_check(
                    ok,
                    "http-toggle-off invariant — no BaseURL is_ai_framework_detected",
                    "" if ok else f"got {len(urls)} rows",
                )
                if not ok:
                    failures.append("Q2: http_probe AI annotations still present after toggle off")
            else:
                product_expect, _category_expect = _expected_frontend_baseurl_marker()
                hit = any(
                    u.get("framework") == product_expect or u.get("product") == product_expect
                    for u in urls
                )
                _print_check(
                    hit,
                    f"BaseURL with framework/product='{product_expect}' present",
                    "" if hit else f"got {[u.get('framework') or u.get('product') for u in urls]}",
                )
                if not hit:
                    failures.append(f"Q2: no BaseURL tagged with {product_expect}")

            # Query 3 — Subdomain AI hints
            subs = _q3_ai_subdomain_hints(s, args.user_id, args.project_id)
            print(f"\nQ3 — Subdomains with ai_service_hint ({len(subs)} rows):")
            for sub in subs[:10]:
                print(f"        {sub['name']:50s}  hint={sub['hint']}")
            if args.expect_dns_ai_empty:
                ok = not subs
                _print_check(
                    ok,
                    "dns-toggle-off invariant — no Subdomain.ai_service_hint",
                    "" if ok else f"got {len(subs)} rows",
                )
                if not ok:
                    failures.append("Q3: domain_recon AI hints still present after toggle off")
            else:
                # The lab fixture does NOT set up a DNS record for AI vendors.
                # An empty result here is acceptable for the lab; warn but
                # don't fail unless the operator explicitly required it.
                if subs and args.require_dns_ai:
                    _print_check(True, "Subdomain ai_service_hint present (required)")
                elif not subs and args.require_dns_ai:
                    _print_check(False, "Subdomain ai_service_hint missing but --require-dns-ai set")
                    failures.append("Q3: no Subdomain ai_service_hint despite --require-dns-ai")
                elif not subs:
                    _print_warn("no Subdomain ai_service_hint (lab fixture has no AI-vendor DNS records)")

            # Query 4 — catch-all by prefix
            catchall = _q4_catchall_ai_annotated_nodes(s, args.user_id, args.project_id)
            print(f"\nQ4 — Any node carrying ai_* / is_ai_* ({len(catchall)} label groups):")
            for row in catchall:
                print(f"        {str(row['label']):30s}  count={row['n']}")

            # Query 5 — disambiguate guard for port 8000
            ambig = _q5_disambiguate_port_8000_is_not_ai(s, args.user_id, args.project_id)
            print(f"\nQ5 — Disambiguate guard on port 8000:")
            ok = ambig == 0
            _print_check(
                ok,
                "port 8000 (Chroma in lab) NOT auto-promoted by port_scan",
                "" if ok else f"got {ambig} ai-vector-db edges (lap 1 must skip disambiguate ports)",
            )
            if not ok:
                failures.append("Q5: disambiguate=True port 8000 was auto-promoted (regression)")

    finally:
        drv.close()

    print()
    if failures:
        print(f"{_C_RED}{len(failures)} CHECK(S) FAILED:{_C_END}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"{_C_GREEN}All checks passed.{_C_END}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    ap.add_argument("--project-id", required=True, help="Project ID of the scan to verify")
    ap.add_argument("--user-id", required=True, help="User ID owning the project")
    ap.add_argument("--expect-port-ai-empty", action="store_true",
                    help="Assert NO port_scan AI annotations (toggle off smoke)")
    ap.add_argument("--expect-http-ai-empty", action="store_true",
                    help="Assert NO http_probe AI annotations (toggle off smoke)")
    ap.add_argument("--expect-dns-ai-empty", action="store_true",
                    help="Assert NO domain_recon AI hints (toggle off smoke)")
    ap.add_argument("--require-dns-ai", action="store_true",
                    help="Fail when no Subdomain ai_service_hint exists (otherwise warn only — the lab fixture doesn't set up AI-vendor DNS records)")
    return verify(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
