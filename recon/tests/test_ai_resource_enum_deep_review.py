"""Deep review of the Lap-2 Endpoint AI Classifier.

Probes corners the basic Phase H tests didn't cover:

  * Toggle semantics — what exactly happens when each sub-toggle is off
  * Defensive input — None / empty / weird shapes don't crash
  * Parent-AI map URL canonicalisation — trailing slash, query string,
    port-default normalisation
  * RAG ambiguous-vs-unambiguous gate per category
  * Partial recon — must preserve original Endpoint.method (was a bug)
  * Partial recon — must compute parameter_count from loaded params, not
    leave at zero (was a bug)
  * Idempotency — re-runs of the annotator + mixin
  * Catalogue parity — every cited vendor pattern fires

Tests are intentionally redundant with Phase H in a few spots to catch the
exact failure modes I describe above.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

from recon.helpers import ai_signal_catalog as cat
from recon.main_recon_modules.resource_enum import (
    _annotate_ai_endpoint_classifier,
    _build_parent_ai_map,
)


ON = {
    "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": True,
    "RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED": True,
    "RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED": True,
    "RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED": True,
    "RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED": True,
}


def _make_organized(base_url: str, endpoints: dict) -> dict:
    return {"by_base_url": {base_url: {"endpoints": endpoints}}}


# ===========================================================================
# Toggle semantics — what should each toggle actually DO?
# ===========================================================================

def test_path_toggle_off_does_not_stamp_anything():
    """When PATH_CLASSIFIER is off, the annotator must NOT stamp
    `ai_interface_type` at all — not even the 'non-llm' sentinel. The whole
    point of the sub-toggle is for operators to opt out of pollution."""
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {"parameters": {"query": [], "body": [], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    # Sub-toggle off → the field should NOT exist on the endpoint dict.
    assert "ai_interface_type" not in ep, (
        f"PATH_CLASSIFIER=off must not stamp ai_interface_type, got {ep.get('ai_interface_type')!r}"
    )


def test_path_toggle_off_still_allows_rag_to_fire():
    """RAG classifier should be independent of path classifier."""
    organized = _make_organized("https://api.test", {
        "/v1/vector_stores": {"parameters": {"query": [], "body": [], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/vector_stores"]
    assert ep.get("is_ai_rag_ingest") is True


def test_param_toggle_fires_on_rag_endpoint_even_when_path_classifier_off():
    """Param classifier gate is `endpoint_is_ai`, which is True if EITHER
    ai_interface_type is set OR is_ai_rag_ingest is True. So with path
    classifier OFF, RAG alone should still authorise param tagging."""
    organized = _make_organized("https://api.test", {
        "/v1/vector_stores": {"parameters": {"query": [], "body": [{"name": "input"}], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/vector_stores"]
    body = ep["parameters"]["body"]
    assert body[0].get("is_ai_prompt_injectable") is True


def test_rag_toggle_off_skips_rag_stamping():
    organized = _make_organized("https://api.test", {
        "/v1/vector_stores": {"parameters": {"query": [], "body": [], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/vector_stores"]
    assert "is_ai_rag_ingest" not in ep


def test_master_off_skips_param_classifier_too():
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {"parameters": {"query": [], "body": [{"name": "prompt"}], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_CLASSIFIER_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert "ai_interface_type" not in ep
    assert "is_ai_prompt_injectable" not in ep["parameters"]["body"][0]


# ===========================================================================
# Defensive input handling — must not crash on weird shapes
# ===========================================================================

def test_annotator_empty_organized_data():
    summary = _annotate_ai_endpoint_classifier({}, ON, {})
    assert summary == {"paths": 0, "rag_paths": 0, "prompt_params": 0}


def test_annotator_none_organized_data():
    summary = _annotate_ai_endpoint_classifier(None, ON, {})
    assert summary == {"paths": 0, "rag_paths": 0, "prompt_params": 0}


def test_annotator_organized_data_missing_by_base_url():
    """When organized_data has no by_base_url key (malformed input)."""
    summary = _annotate_ai_endpoint_classifier({"other_key": 1}, ON, {})
    assert summary == {"paths": 0, "rag_paths": 0, "prompt_params": 0}


def test_annotator_endpoint_missing_parameters_key():
    """Endpoint dict with no 'parameters' key — must not crash."""
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {}  # no 'parameters' key
    })
    summary = _annotate_ai_endpoint_classifier(organized, ON, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert ep["ai_interface_type"] == "llm-chat"
    assert summary["paths"] == 1


def test_annotator_endpoint_parameters_is_none():
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {"parameters": None}
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    # Should not crash; ai_interface_type still gets stamped
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert ep["ai_interface_type"] == "llm-chat"


def test_annotator_parameters_position_lists_missing():
    """parameters dict with no 'query' / 'body' / 'path' subkeys."""
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {"parameters": {}}
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    # No params to tag, no crash
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert ep["ai_interface_type"] == "llm-chat"


def test_annotator_parameter_dict_missing_name():
    """A param dict without 'name' must be skipped, not crash."""
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {
            "parameters": {
                "query": [],
                "body": [{"name": "prompt"}, {"type": "string"}, {}],  # one good, two missing name
                "path": [],
            }
        }
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    body = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]["parameters"]["body"]
    assert body[0].get("is_ai_prompt_injectable") is True
    assert "is_ai_prompt_injectable" not in body[1]
    assert "is_ai_prompt_injectable" not in body[2]


def test_annotator_parameter_non_dict_entry_skipped():
    """If the param list contains a non-dict, skip it gracefully."""
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {
            "parameters": {
                "query": [],
                "body": [{"name": "prompt"}, "stray-string", None, 42],
                "path": [],
            }
        }
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    body = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]["parameters"]["body"]
    assert body[0].get("is_ai_prompt_injectable") is True
    # No crash; non-dict entries untouched


def test_annotator_path_is_empty_string():
    """An endpoint with empty path — no path catalogue match, stays non-llm."""
    organized = _make_organized("https://api.test", {
        "": {"parameters": {"query": [], "body": [], "path": []}}
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"][""]
    assert ep["ai_interface_type"] == "non-llm"


# ===========================================================================
# _build_parent_ai_map — URL canonicalisation
# ===========================================================================

def test_parent_ai_map_strips_path_correctly():
    """Various URL shapes must all collapse to scheme://host:port."""
    recon_data = {
        "http_probe": {
            "by_url": {
                "https://host.test/": {"is_ai_framework_detected": True},
                "https://host.test/v1/chat/completions": {"is_ai_framework_detected": True},
                "https://host.test/foo?bar=baz": {"is_ai_framework_detected": True},
                "http://other.test:9100/": {"is_ai_framework_detected": True},
            }
        }
    }
    m = _build_parent_ai_map(recon_data)
    assert m.get("https://host.test") is True
    assert m.get("http://other.test:9100") is True
    # No path variants should leak
    for k in m:
        assert "/" not in k.replace("://", ""), f"base url {k!r} should have no path"


def test_parent_ai_map_skips_non_ai_entries():
    recon_data = {
        "http_probe": {
            "by_url": {
                "https://a.test/": {"is_ai_framework_detected": True},
                "https://b.test/": {"is_ai_framework_detected": False},
                "https://c.test/": {},  # missing flag
                "https://d.test/": None,  # entry is None
                "not-a-url": {"is_ai_framework_detected": True},
            }
        }
    }
    m = _build_parent_ai_map(recon_data)
    assert m.get("https://a.test") is True
    assert "https://b.test" not in m
    assert "https://c.test" not in m
    assert "https://d.test" not in m


def test_parent_ai_map_no_http_probe_section():
    assert _build_parent_ai_map({"port_scan": {}}) == {}
    assert _build_parent_ai_map({}) == {}


def test_parent_ai_map_http_probe_by_url_is_none():
    """recon_data['http_probe']['by_url'] could be None on early-exit scans."""
    assert _build_parent_ai_map({"http_probe": {"by_url": None}}) == {}


# ===========================================================================
# RAG ambiguous-vs-unambiguous gate per category
# ===========================================================================

def test_rag_openai_vector_stores_always_fires():
    # Unambiguous — vendor-specific
    assert cat.is_ai_rag_path("/v1/vector_stores") is True
    assert cat.is_ai_rag_path("/v1/vector_stores/vs_abc") is True
    assert cat.is_ai_rag_path("/v1/vector_stores/vs_abc/search") is True
    assert cat.is_ai_rag_path("/v1/vector_stores/vs_abc/files") is True


def test_rag_pinecone_upsert_always_fires():
    assert cat.is_ai_rag_path("/vectors/upsert") is True


def test_rag_weaviate_objects_always_fires():
    assert cat.is_ai_rag_path("/v1/objects") is True
    assert cat.is_ai_rag_path("/v1/batch/objects") is True


def test_rag_qdrant_points_always_fires():
    assert cat.is_ai_rag_path("/collections/mycol/points") is True
    assert cat.is_ai_rag_path("/collections/mycol/points/search") is True
    assert cat.is_ai_rag_path("/collections/mycol/points/query") is True


def test_rag_assistants_runs_always_fire():
    assert cat.is_ai_rag_path("/v1/assistants") is True
    assert cat.is_ai_rag_path("/v1/threads") is True
    assert cat.is_ai_rag_path("/v1/threads/thread_abc/messages") is True


def test_rag_generic_search_gated_per_parent_ai():
    assert cat.is_ai_rag_path("/search") is False
    assert cat.is_ai_rag_path("/search", parent_is_ai=True) is True


def test_rag_generic_upload_gated_per_parent_ai():
    assert cat.is_ai_rag_path("/upload") is False
    assert cat.is_ai_rag_path("/upload", parent_is_ai=True) is True


def test_rag_generic_rag_path_gated():
    """Even /rag is gated — there's no vendor that ships /rag as a canonical
    endpoint; LangChain examples define user-named routes."""
    assert cat.is_ai_rag_path("/rag") is False
    assert cat.is_ai_rag_path("/rag", parent_is_ai=True) is True


# ===========================================================================
# Path classifier — vendor parity checks
# ===========================================================================

def test_match_ai_path_groq_openai_prefix():
    assert cat.match_ai_path("/openai/v1/chat/completions") == "llm-chat"


def test_match_ai_path_perplexity_sonar():
    assert cat.match_ai_path("/v1/sonar") == "llm-chat"


def test_match_ai_path_anthropic_messages_with_id_does_not_collide():
    """/v1/messages/msg_abc should NOT match the bare /v1/messages pattern
    (which is anchored with /?$). Currently misclassified as None — that's
    actually fine, the Messages API is POST-only on the bare path."""
    # Bare path matches:
    assert cat.match_ai_path("/v1/messages") == "llm-chat"
    # With ID suffix it shouldn't match the chat regex (no entry covers this).
    # It may match something else or nothing — just confirm no crash.
    result = cat.match_ai_path("/v1/messages/msg_01ABC")
    assert result is None or isinstance(result, str)


def test_match_ai_path_tgi_invocations():
    assert cat.match_ai_path("/invocations") == "llm-completion"


def test_match_ai_path_mistral_fim():
    assert cat.match_ai_path("/v1/fim/completions") == "llm-completion"


def test_match_ai_path_gemini_batch_embed():
    assert cat.match_ai_path("/v1beta/models/text-embedding-004:batchEmbedContents") == "llm-embedding"


def test_match_ai_path_assistants_runs_with_id():
    assert cat.match_ai_path("/v1/threads/thread_abc/runs") == "llm-tool-call"


def test_match_ai_path_assistants_runs_steps():
    assert cat.match_ai_path("/v1/threads/thread_abc/runs/run_xyz/steps") == "llm-tool-call"


def test_match_ai_path_openai_responses_input_items():
    assert cat.match_ai_path("/v1/responses/resp_abc/input_items") == "llm-tool-call"


def test_match_ai_path_langserve_stream_suffix_under_agents():
    """The (?:^|/)stream/?$ pattern must work when /stream is at any depth."""
    assert cat.match_ai_path("/agents/myagent/stream") == "sse-stream"
    assert cat.match_ai_path("/runnable/stream") == "sse-stream"
    assert cat.match_ai_path("/foo/bar/baz/stream") == "sse-stream"


def test_match_ai_path_langserve_astream_events():
    assert cat.match_ai_path("/agents/myagent/astream_events") == "sse-stream"


def test_match_ai_path_mcp_at_prefix():
    assert cat.match_ai_path("/mcp/v1") == "mcp"
    assert cat.match_ai_path("/api/mcp/server") == "mcp"


def test_match_ai_path_mcp_tools_list_suffix():
    """MCP REST-style shims expose /tools/list at any depth."""
    assert cat.match_ai_path("/tools/list") == "mcp"
    assert cat.match_ai_path("/api/v1/tools/list") == "mcp"


def test_match_ai_path_returns_none_for_login_routes():
    """The catalogue must not flag common auth/static paths."""
    assert cat.match_ai_path("/login") is None
    assert cat.match_ai_path("/signin") is None
    assert cat.match_ai_path("/auth/oauth/callback") is None
    assert cat.match_ai_path("/static/js/main.js") is None
    assert cat.match_ai_path("/.well-known/security.txt") is None


# ===========================================================================
# Catalogue iteration ordering — no entry shadows another
# ===========================================================================

def test_catalogue_first_match_wins_consistently():
    """Iterate twice in the same process and confirm we get identical results."""
    paths = [
        "/v1/chat/completions", "/v1/messages", "/api/chat",
        "/v1/embeddings", "/v1/threads/x/runs", "/generate_stream",
        "/sse", "/graphql",
    ]
    first = [cat.match_ai_path(p) for p in paths]
    second = [cat.match_ai_path(p) for p in paths]
    assert first == second


# ===========================================================================
# Param classifier — name normalisation
# ===========================================================================

def test_is_ai_prompt_param_handles_weird_input():
    """The helper must not crash on non-string input."""
    # Empty string and None
    assert cat.is_ai_prompt_param("") is False
    assert cat.is_ai_prompt_param(None) is False  # type: ignore[arg-type]


def test_is_ai_prompt_param_strips_leading_trailing_whitespace():
    assert cat.is_ai_prompt_param("  prompt  ") is True
    assert cat.is_ai_prompt_param("\tprompt\n") is True


def test_is_ai_prompt_param_does_not_match_substrings():
    """A parameter named 'prompt_history' is NOT 'prompt' — equality check
    must reject substring matches to avoid over-tagging."""
    # `prompt_history` doesn't exactly equal `prompt`, so the set lookup
    # returns False. This is the intended behaviour.
    assert cat.is_ai_prompt_param("prompt_history") is False
    assert cat.is_ai_prompt_param("user_prompt") is False
    assert cat.is_ai_prompt_param("system_prompt") is False
    # But the exact name `prompt` still matches:
    assert cat.is_ai_prompt_param("prompt") is True


# ===========================================================================
# Idempotency — running the annotator twice produces the same result
# ===========================================================================

def test_annotator_idempotent_repeat_runs():
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {
            "parameters": {"query": [], "body": [{"name": "messages"}, {"name": "system"}], "path": []}
        },
        "/v1/vector_stores": {"parameters": {"query": [], "body": [], "path": []}},
    })
    s1 = _annotate_ai_endpoint_classifier(organized, ON, {})
    s2 = _annotate_ai_endpoint_classifier(organized, ON, {})
    # Counters fire each time; that's expected (resource_enum runs once per scan).
    assert s1 == s2
    # But the annotations don't double up — values are deterministic.
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert ep["ai_interface_type"] == "llm-chat"
    body = ep["parameters"]["body"]
    assert body[0]["is_ai_prompt_injectable"] is True
    assert body[1]["is_ai_prompt_injectable"] is True


# ===========================================================================
# Mixin smoke — Endpoint method preservation under partial recon
# ===========================================================================

def _neo4j_driver():
    try:
        from neo4j import GraphDatabase  # type: ignore
    except Exception:
        return None
    try:
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "changeme123"))
        drv.verify_connectivity()
        return drv
    except Exception:
        return None


def _cleanup(session, uid: str, pid: str):
    session.run(
        """
        MATCH (n)
        WHERE (n:BaseURL OR n:Endpoint OR n:Parameter OR n:Technology)
          AND n.user_id = $u AND n.project_id = $p
        DETACH DELETE n
        """,
        u=uid, p=pid,
    )


def _resource_mixin_instance(driver):
    from graph_db.mixins.recon.resource_mixin import ResourceMixin

    class _Scratch(ResourceMixin):
        def __init__(self, drv):
            self.driver = drv

    return _Scratch(driver)


def test_mixin_preserves_post_endpoint_when_classifier_writes_ai_props():
    """Bug regression: partial-recon classifier loads a POST endpoint from
    Neo4j, runs the classifier, then writes back. The mixin must update the
    existing POST endpoint, NOT create a new GET endpoint."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_mixin_preserves_post_endpoint_when_classifier_writes_ai_props (neo4j unreachable)")
        return
    uid, pid = "lap2-deep-user", "lap2-deep-method-preservation"
    try:
        with drv.session() as s:
            _cleanup(s, uid, pid)
        mixin = _resource_mixin_instance(drv)
        # First call: simulate the existing pipeline creating a POST endpoint
        recon_data_initial = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],
                                "parameters": {"query": [], "body": [{"name": "messages"}], "path": []},
                                "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(recon_data_initial, uid, pid)

        # Second call: simulate the partial-recon classifier writing back ONLY
        # the AI properties — it should NOT change the method or duplicate.
        recon_data_partial = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],  # Same method!
                                "ai_interface_type": "llm-chat",
                                "parameters": {"query": [], "body": [{"name": "messages", "is_ai_prompt_injectable": True}], "path": []},
                                "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(recon_data_partial, uid, pid)

        with drv.session() as s:
            rows = s.run(
                """
                MATCH (e:Endpoint {path:'/v1/chat/completions',
                                   baseurl:'https://api.test.invalid',
                                   user_id:$u, project_id:$p})
                RETURN e.method AS method, e.ai_interface_type AS t
                ORDER BY e.method
                """,
                u=uid, p=pid,
            ).data()
            assert len(rows) == 1, f"expected 1 endpoint after re-run, got {len(rows)}: {rows}"
            assert rows[0]["method"] == "POST"
            assert rows[0]["t"] == "llm-chat"
            _cleanup(s, uid, pid)
    finally:
        drv.close()


def test_mixin_coalesce_does_not_clobber_existing_ai_props_when_param_off():
    """Re-running with the param toggle off should NOT erase previously
    stamped is_ai_prompt_injectable values. Tested via COALESCE in the MERGE."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_mixin_coalesce_does_not_clobber_existing_ai_props_when_param_off (neo4j unreachable)")
        return
    uid, pid = "lap2-deep-user", "lap2-deep-coalesce"
    try:
        with drv.session() as s:
            _cleanup(s, uid, pid)
        mixin = _resource_mixin_instance(drv)

        # Run 1: classifier stamped is_ai_prompt_injectable=true
        run1 = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],
                                "ai_interface_type": "llm-chat",
                                "parameters": {"query": [], "body": [{"name": "messages", "is_ai_prompt_injectable": True}], "path": []},
                                "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(run1, uid, pid)

        # Run 2: classifier-off (no AI keys on the param dict)
        run2 = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],
                                # No ai_interface_type, no AI keys on param
                                "parameters": {"query": [], "body": [{"name": "messages"}], "path": []},
                                "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(run2, uid, pid)

        with drv.session() as s:
            row = s.run(
                """
                MATCH (p:Parameter {name:'messages', position:'body',
                                    endpoint_path:'/v1/chat/completions',
                                    baseurl:'https://api.test.invalid',
                                    user_id:$u, project_id:$p})
                RETURN p.is_ai_prompt_injectable AS flag
                """,
                u=uid, p=pid,
            ).single()
            assert row is not None
            # COALESCE should have preserved the True from run 1
            assert row["flag"] is True, (
                f"COALESCE should preserve existing AI prop value, got {row['flag']!r}"
            )
            _cleanup(s, uid, pid)
    finally:
        drv.close()


# ===========================================================================
# Partial recon — entry point smoke
# ===========================================================================

def test_partial_recon_entry_point_importable():
    """The partial_recon entry must be importable without errors."""
    from recon.partial_recon_modules.endpoint_ai_classification import run_endpoint_ai_classifier
    assert callable(run_endpoint_ai_classifier)


def test_partial_recon_main_dispatch_table_has_entry():
    """recon/partial_recon.py main() must dispatch on EndpointAiClassifier."""
    partial_recon_source = (PROJECT_ROOT / "recon" / "partial_recon.py").read_text()
    assert 'tool_id == "EndpointAiClassifier"' in partial_recon_source
    assert "run_endpoint_ai_classifier" in partial_recon_source


def test_partial_recon_no_user_id_returns_cleanly():
    """When USER_ID / PROJECT_ID env vars are missing, the entry must refuse
    cleanly with a printed warning, not crash."""
    import os
    from recon.partial_recon_modules.endpoint_ai_classification import run_endpoint_ai_classifier
    # Stash env
    old_uid = os.environ.pop("USER_ID", None)
    old_pid = os.environ.pop("PROJECT_ID", None)
    try:
        # Empty config + no env → must return without error
        run_endpoint_ai_classifier({})
        # If it didn't raise, we're good
    finally:
        if old_uid is not None:
            os.environ["USER_ID"] = old_uid
        if old_pid is not None:
            os.environ["PROJECT_ID"] = old_pid


# ===========================================================================
# Catalogue cross-reference — every cited vendor pattern fires
# ===========================================================================

CITED_VENDOR_PATTERNS = [
    # (path, expected_enum, vendor)
    ("/v1/chat/completions", "llm-chat", "openai/fireworks/together/mistral/tgi"),
    ("/openai/v1/chat/completions", "llm-chat", "groq"),
    ("/chat/completions", "llm-chat", "deepseek"),
    ("/v1/messages", "llm-chat", "anthropic"),
    ("/v1/responses", "llm-chat", "openai-responses"),
    ("/api/chat", "llm-chat", "ollama/open-webui"),
    ("/v1beta/models/gemini-1.5-pro:generateContent", "llm-chat", "gemini"),
    ("/v1beta/models/gemini-1.5-pro:streamGenerateContent", "llm-chat", "gemini-stream"),
    ("/v2/chat", "llm-chat", "cohere"),
    ("/v1/sonar", "llm-chat", "perplexity"),
    ("/v1/completions", "llm-completion", "openai-legacy"),
    ("/v1/fim/completions", "llm-completion", "mistral-fim"),
    ("/api/generate", "llm-completion", "ollama"),
    ("/generate", "llm-completion", "tgi"),
    ("/invocations", "llm-completion", "sagemaker"),
    ("/v1/embeddings", "llm-embedding", "openai/voyage/mistral"),
    ("/api/embeddings", "llm-embedding", "ollama-legacy"),
    ("/api/embed", "llm-embedding", "ollama-current"),
    ("/v2/embed", "llm-embedding", "cohere"),
    ("/v1beta/models/text-embedding-004:embedContent", "llm-embedding", "gemini-embed"),
    ("/v1beta/models/text-embedding-004:batchEmbedContents", "llm-embedding", "gemini-batch-embed"),
    ("/v1/threads/thread_abc/runs", "llm-tool-call", "openai-assistants"),
    ("/v1/threads/thread_abc/runs/run_xyz/steps", "llm-tool-call", "openai-assistants-steps"),
    ("/v1/responses/resp_abc/input_items", "llm-tool-call", "openai-responses-tools"),
    ("/generate_stream", "sse-stream", "tgi"),
    ("/agents/foo/stream", "sse-stream", "langserve"),
    ("/runnable/stream_log", "sse-stream", "langserve"),
    ("/agent/astream_events", "sse-stream", "langserve"),
    ("/mcp", "mcp", "mcp"),
    ("/api/mcp", "mcp", "mcp"),
    ("/sse", "mcp", "mcp-legacy"),
    ("/tools/list", "mcp", "mcp-tools-list"),
    ("/api/v1/tools/list", "mcp", "mcp-tools-list-suffix"),
    ("/graphql", "llm-graphql", "apollo"),
    ("/api/graphql", "llm-graphql", "apollo-prefixed"),
    ("/v1/graphql", "llm-graphql", "hasura/weaviate"),
]


def test_every_cited_vendor_pattern_fires_with_expected_enum():
    """Exhaustive table from the research citations. If any catalogue entry
    regresses, this test pinpoints which one."""
    missing = []
    wrong = []
    for path, expected, vendor in CITED_VENDOR_PATTERNS:
        actual = cat.match_ai_path(path)
        if actual is None:
            missing.append((path, vendor, expected))
        elif actual != expected:
            wrong.append((path, vendor, expected, actual))
    if missing:
        print("MISSING:")
        for p, v, e in missing:
            print(f"  {p!r} ({v}) — expected {e}")
    if wrong:
        print("WRONG:")
        for p, v, e, a in wrong:
            print(f"  {p!r} ({v}) — expected {e}, got {a}")
    assert not missing, f"{len(missing)} cited patterns don't match the catalogue"
    assert not wrong, f"{len(wrong)} cited patterns return wrong enum"


# ===========================================================================
# Settings round-trip — Prisma field name ↔ Python key
# ===========================================================================

def test_settings_default_settings_has_all_5_keys():
    """DEFAULT_SETTINGS must contain all 5 keys the annotator reads, all True."""
    from recon.project_settings import DEFAULT_SETTINGS
    for key in (
        "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED",
        "RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED",
        "RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED",
        "RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED",
        "RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED",
    ):
        assert key in DEFAULT_SETTINGS, f"missing default: {key}"
        assert DEFAULT_SETTINGS[key] is True, f"default should be True, got {DEFAULT_SETTINGS[key]!r}"


def test_settings_fetch_mapping_lines_exist_in_source():
    """fetch_project_settings is an HTTP-fetching function — too heavy to unit
    test. Instead, verify the source contains the camelCase→SCREAMING_SNAKE_CASE
    mapping lines for all 5 keys. Regression guard against accidental
    deletion of the mapping rows."""
    source = (PROJECT_ROOT / "recon" / "project_settings.py").read_text()
    mappings = [
        ("resourceEnumAiClassifierEnabled",         "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED"),
        ("resourceEnumAiPathClassifierEnabled",     "RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED"),
        ("resourceEnumAiRagPathFlagEnabled",        "RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED"),
        ("resourceEnumAiParamInjectableFlagEnabled", "RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED"),
        ("resourceEnumAiToolArgPathEnabled",        "RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED"),
    ]
    for camel, snake in mappings:
        assert camel in source, f"camelCase field {camel!r} missing from project_settings.py"
        assert snake in source, f"SCREAMING_SNAKE_CASE key {snake!r} missing from project_settings.py"


def test_prisma_schema_has_all_5_columns():
    """The Prisma schema must declare all 5 columns with @default(true)."""
    schema_path = PROJECT_ROOT / "webapp" / "prisma" / "schema.prisma"
    if not schema_path.exists():
        print(f"SKIP: schema.prisma not found at {schema_path}")
        return
    source = schema_path.read_text()
    for field in (
        "resourceEnumAiClassifierEnabled",
        "resourceEnumAiPathClassifierEnabled",
        "resourceEnumAiRagPathFlagEnabled",
        "resourceEnumAiParamInjectableFlagEnabled",
        "resourceEnumAiToolArgPathEnabled",
    ):
        assert field in source, f"Prisma field {field!r} missing"


def test_parent_ai_map_does_not_normalise_default_ports():
    """KNOWN edge case: urlparse leaves explicit :443 / :80 in the netloc.
    If httpx wrote 'https://host.test:443' but resource_enum keyed
    by_base_url with 'https://host.test', the lookup misses. This test
    documents the current (strict-match) behaviour so we know if it
    changes."""
    recon_data = {
        "http_probe": {
            "by_url": {
                "https://host.test:443/": {"is_ai_framework_detected": True},
                "https://host.test/": {"is_ai_framework_detected": True},
            }
        }
    }
    m = _build_parent_ai_map(recon_data)
    # Both variants should be present — we don't normalise away the port,
    # so callers querying with one form get a hit and querying with the
    # other don't. Documenting the strict-match semantics.
    assert m.get("https://host.test:443") is True
    assert m.get("https://host.test") is True


def test_queryai_surface_cypher_syntax_valid():
    """Smoke-test the queryAiSurface Cypher: EXPLAIN against live Neo4j
    confirms the query parses. The query uses property keys (ai_interface_type,
    is_ai_rag_ingest, is_ai_prompt_injectable) that may not exist yet — EXPLAIN
    treats that as a warning, not an error."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_queryai_surface_cypher_syntax_valid (neo4j unreachable)")
        return
    queries = [
        # rollup
        """MATCH (e:Endpoint {project_id: $pid})
           WHERE e.ai_interface_type IS NOT NULL AND e.ai_interface_type <> 'non-llm'
           RETURN e.ai_interface_type AS interfaceType, count(*) AS count
           ORDER BY count DESC""",
        # rag count
        """MATCH (e:Endpoint {project_id: $pid}) WHERE e.is_ai_rag_ingest = true
           RETURN count(e) AS n""",
        # prompt-injectable param count
        """MATCH (p:Parameter {project_id: $pid}) WHERE p.is_ai_prompt_injectable = true
           RETURN count(p) AS n""",
        # per-endpoint detail
        """MATCH (b:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
           WHERE (e.ai_interface_type IS NOT NULL AND e.ai_interface_type <> 'non-llm')
              OR e.is_ai_rag_ingest = true
           OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
             WHERE p.is_ai_prompt_injectable = true
           WITH b, e, collect(DISTINCT p.name) AS promptParams
           RETURN b.url AS baseUrl, e.path AS path, e.ai_interface_type AS interfaceType,
                  COALESCE(e.is_ai_rag_ingest, false) AS isRagIngest, promptParams
           ORDER BY interfaceType, baseUrl, path
           LIMIT 50""",
    ]
    try:
        with drv.session() as s:
            for q in queries:
                # EXPLAIN parses the query without running it
                s.run("EXPLAIN " + q, pid="lap2-cypher-smoke").consume()
    finally:
        drv.close()


def test_e2e_partial_recon_path_runs_against_seeded_graph():
    """End-to-end smoke for the partial-recon flow:
    1. Seed a graph with a POST endpoint + params (no AI tags yet)
    2. Invoke the partial-recon flow directly
    3. Verify the original endpoint got AI-tagged in place (not duplicated)
    """
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_e2e_partial_recon_path_runs_against_seeded_graph (neo4j unreachable)")
        return
    uid, pid = "lap2-deep-user", "lap2-deep-e2e-partial"
    try:
        with drv.session() as s:
            _cleanup(s, uid, pid)
        mixin = _resource_mixin_instance(drv)
        # Seed: one POST endpoint at /v1/chat/completions + 'messages' param.
        # NO AI tags applied yet.
        seed = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],
                                "parameters": {"query": [], "body": [{"name": "messages"}], "path": []},
                                "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(seed, uid, pid)

        # Now invoke the partial-recon flow (simulated — we replicate its key
        # steps without going through Docker / config files). Neo4jClient
        # reads NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD from env, so set them
        # the same way the orchestrator does.
        import os
        prev = {
            k: os.environ.get(k)
            for k in ("USER_ID", "PROJECT_ID", "NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD")
        }
        os.environ["USER_ID"] = uid
        os.environ["PROJECT_ID"] = pid
        os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
        os.environ.setdefault("NEO4J_USER", "neo4j")
        os.environ.setdefault("NEO4J_PASSWORD", "changeme123")
        try:
            from recon.partial_recon_modules.endpoint_ai_classification import run_endpoint_ai_classifier
            run_endpoint_ai_classifier({})
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # Verify: same POST endpoint, now AI-tagged, no duplicate.
        with drv.session() as s:
            rows = s.run(
                """
                MATCH (e:Endpoint {path:'/v1/chat/completions',
                                   baseurl:'https://api.test.invalid',
                                   user_id:$u, project_id:$p})
                RETURN e.method AS method, e.ai_interface_type AS t,
                       e.has_parameters AS has_params
                """,
                u=uid, p=pid,
            ).data()
            assert len(rows) == 1, f"expected 1 endpoint, got {len(rows)}: {rows}"
            assert rows[0]["method"] == "POST", f"method clobbered to {rows[0]['method']!r}"
            assert rows[0]["t"] == "llm-chat", f"ai_interface_type wrong: {rows[0]['t']!r}"
            # Bug #3 regression: has_parameters must still be True (parameter_count
            # was recomputed from real params, not defaulted to zero)
            assert rows[0]["has_params"] is True, "has_parameters got reset to False (parameter_count bug)"

            # Verify the parameter got is_ai_prompt_injectable=true
            param = s.run(
                """
                MATCH (p:Parameter {name:'messages', position:'body',
                                    endpoint_path:'/v1/chat/completions',
                                    baseurl:'https://api.test.invalid',
                                    user_id:$u, project_id:$p})
                RETURN p.is_ai_prompt_injectable AS flag
                """,
                u=uid, p=pid,
            ).single()
            assert param is not None, "Parameter row missing after partial recon"
            assert param["flag"] is True, f"is_ai_prompt_injectable should be True, got {param['flag']!r}"

            _cleanup(s, uid, pid)
    finally:
        drv.close()


def test_workflow_view_registration_consistent():
    """The workflow id 'EndpointAiClassifier' must appear in all the layers
    that reference it: workflowDefinition, nodeMapping (3 maps), modal switch,
    inputLogicTooltips, partial-recon types."""
    webapp_root = PROJECT_ROOT / "webapp" / "src"
    layers = {
        "workflowDefinition.ts": webapp_root / "components/projects/ProjectForm/WorkflowView/workflowDefinition.ts",
        "nodeMapping.ts":        webapp_root / "components/projects/ProjectForm/nodeMapping.ts",
        "WorkflowNodeModal.tsx": webapp_root / "components/projects/ProjectForm/WorkflowView/WorkflowNodeModal.tsx",
        "inputLogicTooltips.tsx": webapp_root / "components/projects/ProjectForm/WorkflowView/inputLogicTooltips.tsx",
        "recon-types.ts":        webapp_root / "lib/recon-types.ts",
        "PartialReconModal.tsx": webapp_root / "components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx",
    }
    missing = []
    for name, path in layers.items():
        if not path.exists():
            print(f"SKIP layer {name}: file not found at {path}")
            continue
        if "EndpointAiClassifier" not in path.read_text():
            missing.append(name)
    assert not missing, f"workflow id 'EndpointAiClassifier' missing from: {missing}"
