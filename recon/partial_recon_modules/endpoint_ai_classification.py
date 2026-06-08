"""Partial recon for the Endpoint AI Classifier.

Re-classifies every Endpoint and Parameter already in the graph without
re-running the URL-discovery tools (Katana / Hakrawler / GAU / FFuf /
ParamSpider / Arjun / Kiterunner / jsluice). Use cases:

  * Operator updated the AI signal catalogue and wants existing endpoints
    re-tagged.
  * A new lap of AI annotations shipped (new path patterns, new param
    names) and the operator wants the graph back-filled without burning
    a full crawl.
  * Toggle was off during the original scan and operator wants to turn
    classification on now.

Reads:  every Endpoint + Parameter + BaseURL for the project.
Writes: Endpoint.ai_interface_type, Endpoint.is_ai_rag_ingest,
        Parameter.is_ai_prompt_injectable.

No new traffic to the target. Pure pattern matching over data the graph
already holds.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_endpoint_ai_classifier(config: dict) -> None:
    """Re-run the AI endpoint/parameter classifier over the existing graph.

    config keys used:
      - user_id / project_id (also pulled from env as fallback)
      - include_graph_targets (ignored — this tool only reads from graph)
      - settings_overrides (rarely used)

    Returns nothing. Prints a one-line summary to stdout.
    """
    from recon.project_settings import get_settings
    from recon.main_recon_modules.resource_enum import _annotate_ai_endpoint_classifier
    from graph_db.neo4j_client import Neo4jClient

    user_id = os.environ.get("USER_ID", "") or config.get("user_id", "")
    project_id = os.environ.get("PROJECT_ID", "") or config.get("project_id", "")

    if not (user_id and project_id):
        print("[!][ResourceEnum-AI] Missing USER_ID or PROJECT_ID — refusing to run")
        return

    print(f"\n{'=' * 50}")
    print(f"[*][ResourceEnum-AI] Partial recon: Endpoint AI Classifier")
    print(f"[*][ResourceEnum-AI] Project: {project_id}")
    print(f"{'=' * 50}\n")

    settings = get_settings()

    # Force the master toggle on for the partial run — the operator explicitly
    # asked for it. Sub-toggles still honour whatever the project settings say.
    settings["RESOURCE_ENUM_AI_CLASSIFIER_ENABLED"] = True

    # Build a synthetic organized_data dict by reading existing Endpoints +
    # Parameters from Neo4j. We need:
    #   organized_data = {
    #     "by_base_url": {
    #       <base_url>: {
    #         "endpoints": {
    #           <path>: {"parameters": {"query": [...], "body": [...], "path": [...]}, ...}
    #         }
    #       }
    #     }
    #   }
    client = Neo4jClient()
    organized_data: dict = {"by_base_url": {}}

    with client.driver.session() as session:
        # Capture the method per (baseurl, path) so the mixin's MERGE re-matches
        # the existing Endpoint row instead of creating a duplicate with method=GET.
        # An Endpoint row can have one method per (path, method, baseurl) key,
        # but multiple methods can share a path — aggregate into a list.
        ep_rows = session.run(
            """
            MATCH (e:Endpoint {user_id:$u, project_id:$p})
            RETURN e.baseurl AS baseurl, e.path AS path, e.method AS method
            """,
            u=user_id, p=project_id,
        )
        ep_total = 0
        for row in ep_rows:
            ep_total += 1
            base = row["baseurl"] or "unknown"
            path = row["path"] or "/"
            method = row["method"] or "GET"
            by_base = organized_data["by_base_url"].setdefault(base, {"endpoints": {}})
            ep = by_base["endpoints"].setdefault(
                path,
                {"parameters": {"query": [], "body": [], "path": []}, "methods": []},
            )
            if method not in ep["methods"]:
                ep["methods"].append(method)

        # Attach parameters
        param_rows = session.run(
            """
            MATCH (e:Endpoint {user_id:$u, project_id:$p})-[:HAS_PARAMETER]->(p:Parameter)
            RETURN e.baseurl AS baseurl, e.path AS path,
                   p.name AS name, p.position AS position
            """,
            u=user_id, p=project_id,
        )
        param_total = 0
        for row in param_rows:
            param_total += 1
            base = row["baseurl"] or "unknown"
            path = row["path"] or "/"
            name = row["name"]
            position = row["position"] or "query"
            if base not in organized_data["by_base_url"]:
                continue
            ep = organized_data["by_base_url"][base]["endpoints"].get(path)
            if not ep:
                continue
            ep["parameters"].setdefault(position, []).append({"name": name})

    print(f"[*][ResourceEnum-AI] Loaded {ep_total} endpoint(s) + {param_total} parameter(s) from graph")

    if ep_total == 0:
        print("[-][ResourceEnum-AI] No endpoints in graph — nothing to classify")
        client.close()
        return

    # Build a minimal recon_data so _build_parent_ai_map can read http_probe.by_url.
    # Pull existing AI tags from BaseURL→Endpoint paths to determine parent-AI.
    recon_data: dict = {"http_probe": {"by_url": {}}}
    with client.driver.session() as session:
        ai_rows = session.run(
            """
            MATCH (b:BaseURL {user_id:$u, project_id:$p})-[:HAS_ENDPOINT]->(e:Endpoint)
            WHERE e.is_ai_framework_detected = true
            RETURN b.url AS base_url
            """,
            u=user_id, p=project_id,
        )
        for row in ai_rows:
            base = row["base_url"]
            if base:
                recon_data["http_probe"]["by_url"][base + "/"] = {"is_ai_framework_detected": True}

    summary = _annotate_ai_endpoint_classifier(organized_data, settings, recon_data)
    print(
        f"[+][ResourceEnum-AI] Classified — "
        f"paths={summary.get('paths', 0)}, "
        f"rag={summary.get('rag_paths', 0)}, "
        f"prompt-params={summary.get('prompt_params', 0)}"
    )

    # Write back via the mixin. The mixin re-matches existing Endpoints by
    # (path, method, baseurl) and SETs the new AI properties via COALESCE,
    # so existing non-AI fields stay untouched.
    #
    # Per-endpoint methods were captured above; compute parameter_count from
    # the actual loaded params so the mixin's `has_parameters` derivation
    # stays accurate (zeros here would reset that field to False).
    for base_data in organized_data["by_base_url"].values():
        for endpoint in base_data["endpoints"].values():
            # Methods already populated from Neo4j. Default to ['GET'] only if
            # somehow we got a row with null method — shouldn't happen.
            endpoint.setdefault("methods", ["GET"])
            params = endpoint.get("parameters") or {}
            q = len(params.get("query") or [])
            b = len(params.get("body") or [])
            pp = len(params.get("path") or [])
            endpoint["parameter_count"] = {
                "total": q + b + pp,
                "query": q,
                "body": b,
                "path": pp,
            }

    recon_data_for_mixin = {
        "resource_enum": {
            "by_base_url": organized_data["by_base_url"],
        }
    }
    client.update_graph_from_resource_enum(recon_data_for_mixin, user_id, project_id)
    client.close()

    print(f"[+][ResourceEnum-AI] Partial classification complete")
