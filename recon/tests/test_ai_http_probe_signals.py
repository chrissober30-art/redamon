"""Unit + integration + live-Neo4j tests for Phase 4 — http_probe AI signatures.

Covers:

  1. ``_annotate_ai_http_signals`` — header / favicon / title / wappalyzer toggles
  2. ``parse_httpx_output`` — JSONL file → by_url with AI annotations and summary counters
  3. Pattern coverage — every entry in AI_HEADER_PATTERNS and AI_TITLE_PATTERNS fires
  4. Real-world header shapes — dict, CRLF-joined string, mixed case
  5. Callsite verification — ``run_http_probe`` threads ``settings=settings`` through
  6. Live Neo4j — ``update_graph_from_http_probe`` writes BaseURL.is_ai_framework_detected
     and MERGEs Technology(category=ai-*) with the correct ``detected_by``

Run:
    docker run --rm --network host --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_http_probe_signals.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

from recon.helpers.ai_signal_catalog import AI_HEADER_PATTERNS, AI_TITLE_PATTERNS
from recon.main_recon_modules.http_probe import (
    _annotate_ai_http_signals,
    parse_httpx_output,
)


ON = {
    "HTTP_PROBE_AI_HEADER_SCAN_ENABLED": True,
    "HTTP_PROBE_AI_FAVICON_HASH_ENABLED": True,
    "HTTP_PROBE_AI_TITLE_DETECTION_ENABLED": True,
    "HTTP_PROBE_AI_WAPPALYZER_ENABLED": True,
}


def _entry(headers=None, title=None, favicon=None):
    e = {}
    if headers is not None:
        e["headers"] = headers
    if title is not None:
        e["title"] = title
    if favicon is not None:
        e["favicon_hash"] = favicon
    return e


# ---------------------------------------------------------------------------
# _annotate_ai_http_signals — header path
# ---------------------------------------------------------------------------

def test_annotator_fires_on_runtime_header():
    e = _entry(headers={"x-vllm-cache-hit": "1", "content-type": "application/json"})
    fired = _annotate_ai_http_signals(e, ON)
    assert fired["header"] == "vllm"
    assert e["is_ai_framework_detected"] is True
    assert e["ai_framework_name"] == "vllm"
    assert e["ai_framework_category"] == "ai-runtime"


def test_annotator_fires_on_underscore_form_header():
    """Regression guard for Patch E.

    Httpx normalises HTTP header names from dash-form (`x-vllm-cache-hit`) to
    underscore-form (`x_vllm_cache_hit`) when it serialises responses. The
    AI header annotator must match BOTH forms. Caught when scan #3 graph
    audit showed 0 header matches even though all 20 expected AI headers
    were present as Header nodes (with underscore names) on the BaseURLs.
    """
    e = _entry(headers={
        "x_vllm_cache_hit": "1",        # underscore form (real httpx output)
        "content_type": "application/json",
    })
    fired = _annotate_ai_http_signals(e, ON)
    assert fired["header"] == "vllm", (
        "underscore-form header didn't match the dash-form regex — Patch E "
        "regression. Re-apply normalisation in _annotate_ai_http_signals."
    )
    assert e["is_ai_framework_detected"] is True


def test_annotator_underscore_form_works_for_every_pattern():
    """Parameterised over the full AI_HEADER_PATTERNS catalog: every
    pattern's expected header in underscore-form must still fire."""
    from recon.helpers.ai_signal_catalog import AI_HEADER_PATTERNS
    # The same fixture used by test_every_ai_header_pattern_fires_on_a_synthetic_header,
    # but converted to underscore form (production shape from httpx)
    underscore_samples = {
        "vllm":                       "x_vllm_cache_hit",
        "tgi":                        "x_tgi_request_id",
        "text-embeddings-inference":  "x_tei_version",
        "bentoml":                    "x_bentoml_version",
        "baseten":                    "x_baseten_deployment",
        "modal":                      "x_modal_task_id",
        "replicate":                  "x_replicate_prediction",
        "runpod":                     "x_runpod_pod_id",
        "langchain":                  "x_langchain_run_id",
        "llamaindex":                 "x_llamaindex_trace_id",
        "langfuse":                   "langfuse_trace_id",
        "mcp":                        "x_mcp_server_name",
        "litellm":                    "x_litellm_model_id",
        "helicone":                   "x_helicone_cache",
        "portkey":                    "x_portkey_cache",
        "omniroute":                  "x_omniroute_trace",
        "cloudflare-ai-gateway":      "cf_aig_cache_status",
        "together":                   "together_request_id",
        "openai":                     "openai_organization",
        "anthropic":                  "anthropic_version",
        "azure-openai":               "x_ms_region",
        "fireworks":                  "x_fireworks_account_id",
    }
    expected = {fw for _pat, fw, _cat in AI_HEADER_PATTERNS}
    missing = expected - set(underscore_samples)
    assert not missing, f"underscore fixture missing samples for: {missing}"

    for framework, header_name in underscore_samples.items():
        e = _entry(headers={header_name: "x"})
        _annotate_ai_http_signals(e, ON)
        assert e.get("ai_framework_name") == framework, (
            f"underscore-form {header_name!r} did not match {framework!r}; "
            f"got {e.get('ai_framework_name')!r}"
        )


def test_annotator_fires_on_framework_header():
    e = _entry(headers={"x-langchain-run-id": "abc"})
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "langchain"
    assert e["ai_framework_category"] == "ai-framework"


def test_annotator_fires_on_proxy_header():
    e = _entry(headers={"x-litellm-model-id": "gpt-4"})
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "litellm"
    assert e["ai_framework_category"] == "ai-proxy"


def test_annotator_fires_on_sdk_client_header():
    e = _entry(headers={"anthropic-ratelimit-requests-remaining": "100"})
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "anthropic"
    assert e["ai_framework_category"] == "ai-sdk-client"


def test_annotator_header_first_match_wins_across_multiple_matches():
    """When two headers both match different patterns, the first matching
    *pattern* in AI_HEADER_PATTERNS wins — not the first header iterated."""
    e = _entry(headers={
        "x-langchain-run-id": "abc",  # framework — appears later in catalog
        "x-vllm-cache-hit": "1",       # runtime — appears earlier
    })
    _annotate_ai_http_signals(e, ON)
    # vllm is listed before langchain in AI_HEADER_PATTERNS by design
    assert e["ai_framework_name"] == "vllm"


def test_annotator_header_case_insensitive_match():
    e = _entry(headers={"X-VLLM-CACHE-HIT": "1"})
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "vllm"


def test_annotator_no_match_on_unrelated_headers():
    e = _entry(headers={"content-type": "text/html", "server": "nginx", "x-frame-options": "DENY"})
    fired = _annotate_ai_http_signals(e, ON)
    assert fired["header"] is None
    assert "is_ai_framework_detected" not in e


def test_annotator_handles_crlf_string_headers():
    """httpx sometimes stores headers as a single CRLF-joined string."""
    e = _entry(headers="x-vllm-cache-hit: 1\nContent-Type: application/json\n")
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "vllm"


def test_annotator_tolerates_empty_headers():
    e = _entry(headers={})
    fired = _annotate_ai_http_signals(e, ON)
    assert fired["header"] is None
    assert "is_ai_framework_detected" not in e


def test_annotator_tolerates_missing_headers_key():
    e = _entry()
    fired = _annotate_ai_http_signals(e, ON)
    assert fired["header"] is None


# ---------------------------------------------------------------------------
# _annotate_ai_http_signals — title path
# ---------------------------------------------------------------------------

def test_annotator_title_fires_on_known_product():
    e = _entry(title="Open WebUI")
    _annotate_ai_http_signals(e, ON)
    assert e["ai_frontend_product_guess"] == "open-webui"
    assert e["ai_framework_name"] == "open-webui"
    assert e["ai_framework_category"] == "ai-frontend"
    assert e["is_ai_framework_detected"] is True


def test_annotator_title_case_insensitive():
    e = _entry(title="GRADIO Demo")
    _annotate_ai_http_signals(e, ON)
    assert e["ai_frontend_product_guess"] == "gradio"


def test_annotator_title_no_match_on_unrelated():
    e = _entry(title="Apache HTTP Server Test Page")
    _annotate_ai_http_signals(e, ON)
    assert "ai_frontend_product_guess" not in e


def test_annotator_title_none_or_empty():
    for title in (None, "", "   "):
        e = _entry(title=title)
        _annotate_ai_http_signals(e, ON)
        assert "ai_frontend_product_guess" not in e


# ---------------------------------------------------------------------------
# _annotate_ai_http_signals — favicon path
# ---------------------------------------------------------------------------

def test_annotator_favicon_no_match_when_catalogue_empty():
    """AI_FAVICON_HASHES is intentionally empty until Phase 15 vendoring.
    The annotator must not crash and must not set ai_frontend_product_guess."""
    e = _entry(favicon=12345678)
    _annotate_ai_http_signals(e, ON)
    assert "ai_frontend_product_guess" not in e


def test_annotator_favicon_match_takes_priority_over_title(monkeypatch=None):
    """When both favicon and title would set ai_frontend_product_guess,
    favicon must win (stronger signal). Patch the catalog locally."""
    # Production code reads via `helpers.ai_signal_catalog` (recon path layout).
    # Mutate that same module object so monkey-patches propagate.
    import helpers.ai_signal_catalog as ai_signal_catalog
    saved = dict(ai_signal_catalog.AI_FAVICON_HASHES)
    try:
        ai_signal_catalog.AI_FAVICON_HASHES[999111] = "librechat"
        e = _entry(favicon=999111, title="Open WebUI")
        _annotate_ai_http_signals(e, ON)
        # Favicon hit landed first → title path must not overwrite
        assert e["ai_frontend_product_guess"] == "librechat"
    finally:
        ai_signal_catalog.AI_FAVICON_HASHES.clear()
        ai_signal_catalog.AI_FAVICON_HASHES.update(saved)


def test_annotator_favicon_accepts_string_int():
    """httpx -hash mmh3 can serialise as a stringified int. The annotator
    must coerce."""
    # Production code reads via `helpers.ai_signal_catalog` (recon path layout).
    # Mutate that same module object so monkey-patches propagate.
    import helpers.ai_signal_catalog as ai_signal_catalog
    saved = dict(ai_signal_catalog.AI_FAVICON_HASHES)
    try:
        ai_signal_catalog.AI_FAVICON_HASHES[42] = "flowise"
        e = _entry(favicon="42")
        _annotate_ai_http_signals(e, ON)
        assert e["ai_frontend_product_guess"] == "flowise"
    finally:
        ai_signal_catalog.AI_FAVICON_HASHES.clear()
        ai_signal_catalog.AI_FAVICON_HASHES.update(saved)


def test_annotator_favicon_garbage_value_does_not_crash():
    e = _entry(favicon={"not": "an int"})
    _annotate_ai_http_signals(e, ON)  # must not raise
    assert "ai_frontend_product_guess" not in e


# ---------------------------------------------------------------------------
# _annotate_ai_http_signals — toggle gating
# ---------------------------------------------------------------------------

def test_annotator_settings_none_is_noop():
    e = _entry(headers={"x-vllm-cache-hit": "1"}, title="Open WebUI")
    fired = _annotate_ai_http_signals(e, None)
    assert all(v in (None, False) for v in fired.values())
    assert "ai_framework_name" not in e
    assert "ai_frontend_product_guess" not in e


def test_annotator_header_toggle_off_only():
    e = _entry(headers={"x-vllm-cache-hit": "1"}, title="Open WebUI")
    s = {**ON, "HTTP_PROBE_AI_HEADER_SCAN_ENABLED": False}
    _annotate_ai_http_signals(e, s)
    assert "ai_framework_name" not in e or e.get("ai_framework_name") == "open-webui"
    # title still fires
    assert e["ai_frontend_product_guess"] == "open-webui"


def test_annotator_title_toggle_off_only():
    e = _entry(title="Open WebUI", headers={"content-type": "text/html"})
    s = {**ON, "HTTP_PROBE_AI_TITLE_DETECTION_ENABLED": False}
    _annotate_ai_http_signals(e, s)
    assert "ai_frontend_product_guess" not in e


def test_annotator_favicon_toggle_off_only():
    # Production code reads via `helpers.ai_signal_catalog` (recon path layout).
    # Mutate that same module object so monkey-patches propagate.
    import helpers.ai_signal_catalog as ai_signal_catalog
    saved = dict(ai_signal_catalog.AI_FAVICON_HASHES)
    try:
        ai_signal_catalog.AI_FAVICON_HASHES[42] = "flowise"
        s = {**ON, "HTTP_PROBE_AI_FAVICON_HASH_ENABLED": False}
        e = _entry(favicon=42)
        _annotate_ai_http_signals(e, s)
        assert "ai_frontend_product_guess" not in e
    finally:
        ai_signal_catalog.AI_FAVICON_HASHES.clear()
        ai_signal_catalog.AI_FAVICON_HASHES.update(saved)


def test_annotator_all_toggles_off_is_full_noop():
    e = _entry(headers={"x-vllm-cache-hit": "1"}, title="Open WebUI")
    s = {k: False for k in ON}
    _annotate_ai_http_signals(e, s)
    assert "ai_framework_name" not in e
    assert "ai_frontend_product_guess" not in e
    assert "is_ai_framework_detected" not in e


def test_annotator_idempotent_on_repeat_runs():
    e = _entry(headers={"x-vllm-cache-hit": "1"})
    _annotate_ai_http_signals(e, ON)
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "vllm"
    assert e["is_ai_framework_detected"] is True


# ---------------------------------------------------------------------------
# Pattern coverage — every header / title pattern actually fires
# ---------------------------------------------------------------------------

def test_every_ai_header_pattern_fires_on_a_synthetic_header():
    """Synthesise a header name from each pattern's source regex and assert
    the annotator returns the expected framework + category. Drift guard:
    fails if a new pattern is added without a test sample."""
    # Curated samples that satisfy each pattern. Patterns mostly use prefix
    # anchors like `^x-vllm-` so any string starting with that prefix works.
    samples = {
        "vllm": ("x-vllm-cache-hit", "ai-runtime"),
        "tgi": ("x-tgi-request-id", "ai-runtime"),
        "text-embeddings-inference": ("x-tei-version", "ai-runtime"),
        "bentoml": ("x-bentoml-version", "ai-runtime"),
        "baseten": ("x-baseten-deployment", "ai-runtime"),
        "modal": ("x-modal-task-id", "ai-runtime"),
        "replicate": ("x-replicate-prediction", "ai-runtime"),
        "runpod": ("x-runpod-pod-id", "ai-runtime"),
        "langchain": ("x-langchain-run-id", "ai-framework"),
        "llamaindex": ("x-llamaindex-trace-id", "ai-framework"),
        "langfuse": ("langfuse-trace-id", "ai-framework"),
        "litellm": ("x-litellm-model-id", "ai-proxy"),
        "helicone": ("x-helicone-cache", "ai-proxy"),
        "portkey": ("x-portkey-cache", "ai-proxy"),
        "omniroute": ("x-omniroute-trace", "ai-proxy"),
        "cloudflare-ai-gateway": ("cf-aig-cache-status", "ai-proxy"),
        "together": ("together-request-id", "ai-proxy"),
        "openai": ("openai-organization", "ai-sdk-client"),
        "anthropic": ("anthropic-version", "ai-sdk-client"),
        "azure-openai": ("x-ms-region", "ai-sdk-client"),
        "fireworks": ("x-fireworks-account-id", "ai-sdk-client"),
        "mcp": ("x-mcp-server-name", "ai-framework"),
    }
    expected = {framework for _pat, framework, _cat in AI_HEADER_PATTERNS}
    missing = expected - set(samples)
    assert not missing, f"test fixture missing samples for: {missing}"
    extra = set(samples) - expected
    assert not extra, f"test fixture has stale entries no longer in catalog: {extra}"

    for framework, (header_name, expected_category) in samples.items():
        e = _entry(headers={header_name: "x"})
        _annotate_ai_http_signals(e, ON)
        assert e.get("ai_framework_name") == framework, (
            f"header {header_name!r} should map to {framework!r}; got {e.get('ai_framework_name')!r}"
        )
        assert e.get("ai_framework_category") == expected_category


def test_every_ai_title_pattern_fires_on_a_synthetic_title():
    samples = {
        "open-webui":     "Open WebUI",
        "librechat":      "LibreChat",
        "anythingllm":    "AnythingLLM Workspace",
        "flowise":        "Flowise",
        "langflow":       "Langflow",
        "dify":           "Dify Dashboard",
        "comfyui":        "ComfyUI",
        "gradio":         "Gradio demo",
        "streamlit":      "Streamlit App",
        "betterchatgpt":  "BetterChatGPT",
        "onyx":           "Onyx — AI Assistant",
        "chatgpt-clone":  "ChatGPT for everyone",
        "hf-chat-ui":     "HuggingFace Chat UI",
        "lobechat":       "LobeChat workspace",
        "nextchat":       "NextChat",
        "sillytavern":    "SillyTavern",
        "jan":            "Jan - Open Source AI",
        "h2ogpt":         "h2oGPT",
        "privategpt":     "PrivateGPT",
        "quivr":          "Quivr",
        # Image-gen frontends (Gradio shell)
        "invokeai":       "Invoke - Community Edition",
        "automatic1111":  "Stable Diffusion",
        # MLOps / observability
        "mlflow":         "MLflow",
        "label-studio":   "Labelstudio",
        "ray-dashboard":  "Ray Dashboard",
        "redis-insight":  "RedisInsight",
        "autogen-studio": "AutoGen Studio",
        "langfuse-ui":    "Langfuse Dashboard",
        "phoenix-arize":  "Arize Phoenix",
        "argilla":        "Argilla — annotate datasets",
        "gpt-researcher": "GPT Researcher",
    }
    expected = {p for _pat, p in AI_TITLE_PATTERNS}
    missing = expected - set(samples)
    assert not missing, f"test fixture missing title samples for: {missing}"
    extra = set(samples) - expected
    assert not extra, f"test fixture has stale title entries: {extra}"

    for product, title in samples.items():
        e = _entry(title=title)
        _annotate_ai_http_signals(e, ON)
        assert e.get("ai_frontend_product_guess") == product, (
            f"title {title!r} should map to {product!r}; got {e.get('ai_frontend_product_guess')!r}"
        )


# ---------------------------------------------------------------------------
# Annotator — favicon hash catalogue (Patch F)
# ---------------------------------------------------------------------------

def test_favicon_hash_match_sets_product_guess():
    """When httpx's `favicon_hash` matches a catalogued AI frontend, the
    annotator must set `ai_frontend_product_guess` + the frontend category."""
    import helpers.ai_signal_catalog as cat
    # 1470014414 is the upstream open-webui favicon hash baked into the catalog.
    e = {"favicon_hash": 1470014414, "headers": {}, "title": "Some Site"}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_frontend_product_guess") == "open-webui"
    assert e.get("ai_framework_category") == "ai-frontend"
    assert e.get("is_ai_framework_detected") is True
    # Ensure the catalogued hash is still wired (catches accidental empty dict).
    assert 1470014414 in cat.AI_FAVICON_HASHES, "open-webui favicon hash dropped from AI_FAVICON_HASHES"


def test_favicon_hash_lookup_skipped_when_toggle_off():
    e = {"favicon_hash": 1470014414, "headers": {}, "title": "Some Site"}
    settings = dict(ON)
    settings["HTTP_PROBE_AI_FAVICON_HASH_ENABLED"] = False
    _annotate_ai_http_signals(e, settings)
    assert e.get("ai_frontend_product_guess") is None


def test_favicon_hash_unknown_value_does_not_tag():
    """A favicon_hash not in the catalogue must leave the entry unannotated."""
    e = {"favicon_hash": 12345, "headers": {}, "title": "Some Site"}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_frontend_product_guess") is None


def test_favicon_catalog_has_at_least_one_entry():
    """Regression guard: an empty AI_FAVICON_HASHES means the toggle is a no-op
    and operators see no favicon-based detections. The plan ships a small but
    non-empty starter catalog."""
    import helpers.ai_signal_catalog as cat
    assert len(cat.AI_FAVICON_HASHES) > 0, "AI_FAVICON_HASHES must contain at least one entry"


# ---------------------------------------------------------------------------
# Annotator — Wappalyzer-style body fingerprint catalogue (Patch F)
# ---------------------------------------------------------------------------

def test_body_fingerprint_langchain_global_fires():
    e = {"headers": {}, "title": "x",
         "body": "<html><script>window.__LANGCHAIN__ = {tracing:true};</script></html>"}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "langchain"
    assert e.get("ai_framework_category") == "ai-framework"
    assert e.get("is_ai_framework_detected") is True


def test_body_fingerprint_langchain_import_string_fires():
    e = {"headers": {}, "title": "x",
         "body": 'import { ChatOpenAI } from "@langchain/openai";'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "langchain"


def test_body_fingerprint_llamaindex_global_fires():
    e = {"headers": {}, "title": "x",
         "body": '<script>window.LlamaIndex = {};</script>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "llamaindex"


def test_body_fingerprint_tgi_form_action_fires():
    e = {"headers": {}, "title": "Inference",
         "body": '<form action="/generate_stream" method="POST">'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "tgi"
    assert e.get("ai_framework_category") == "ai-runtime"


def test_body_fingerprint_vllm_cookie_literal_fires():
    e = {"headers": {}, "title": "x",
         "body": '{"error":"missing cookie vllm_session"}'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "vllm"


def test_body_fingerprint_gradio_tag_fires():
    e = {"headers": {}, "title": "ML demo",
         "body": '<body><gradio-app src="/" theme="dark"></gradio-app></body>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "gradio"
    assert e.get("ai_framework_category") == "ai-frontend"


def test_body_fingerprint_streamlit_marker_fires():
    e = {"headers": {}, "title": "Dashboard",
         "body": '<div data-testid="stApp"><div>Hello</div></div>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "streamlit"


def test_body_fingerprint_anthropic_sdk_import_fires():
    e = {"headers": {}, "title": "x",
         "body": 'import Anthropic from "@anthropic-ai/sdk";'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "anthropic"
    assert e.get("ai_framework_category") == "ai-sdk-client"


def test_body_fingerprint_automatic1111_textarea_fires():
    e = {"headers": {}, "title": "Stable Diffusion",
         "body": '<textarea id="txt2img_textarea" placeholder="prompt..."></textarea>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "automatic1111"
    assert e.get("ai_framework_category") == "ai-frontend"


def test_body_fingerprint_fooocus_literal_fires():
    e = {"headers": {}, "title": "Fooocus",
         "body": '<script>const ver="fooocus_v2";</script>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "fooocus"


def test_body_fingerprint_invokeai_favicon_path_fires():
    e = {"headers": {}, "title": "Invoke - Community Edition",
         "body": '<link rel="icon" href="/assets/images/invoke-favicon.svg">'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "invokeai"


def test_body_fingerprint_comfyui_splash_fires():
    e = {"headers": {}, "title": "x",
         "body": '<svg aria-label="Loading ComfyUI" viewBox="0 0 100 100"></svg>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "comfyui"


def test_body_fingerprint_mlflow_class_fires():
    # Use a non-AI title so the body fingerprint is the only channel that fires
    # (otherwise the title regex would win and default to ai-frontend).
    e = {"headers": {}, "title": "Dashboard",
         "body": '<div id="root" class="mlflow-ui-container"></div>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "mlflow"
    assert e.get("ai_framework_category") == "ai-mlops"


def test_body_fingerprint_weaviate_meta_shape_fires():
    e = {"headers": {}, "title": "",
         "body": '{"hostname":"weaviate","version":"1.24.0","modules":{"text2vec":{"name":"text2vec-openai"}}}'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "weaviate"
    assert e.get("ai_framework_category") == "ai-vector-db"


def test_body_fingerprint_chroma_heartbeat_fires():
    e = {"headers": {}, "title": "",
         "body": '{"nanosecond heartbeat": 1234567890}'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "chroma"


def test_body_fingerprint_sglang_model_info_fires():
    e = {"headers": {}, "title": "",
         "body": '{"is_generation": true, "model_path": "/models/llama"}'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "sglang"


def test_body_fingerprint_koboldcpp_response_fires():
    e = {"headers": {}, "title": "",
         "body": '{"result":"KoboldCpp","version":"1.50"}'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "koboldcpp"


def test_body_fingerprint_localai_gallery_fires():
    e = {"headers": {}, "title": "",
         "body": '<a href="/models/apply">Install</a>'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "localai"


def test_body_fingerprint_openai_dangerously_allow_browser_fires():
    e = {"headers": {}, "title": "x",
         "body": 'new OpenAI({ apiKey, dangerouslyAllowBrowser: true })'}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") == "openai"
    assert e.get("ai_framework_category") == "ai-sdk-client"


def test_catalog_extensive_enough():
    """Sanity: catalogs should be substantial after lap-1 expansion.
    Numbers here are lower-bounds, not exact — so adding more entries
    doesn't fail the test. Numbers are the floor that proves the catalogs
    aren't accidentally reverted to the lap-1 starter set."""
    from recon.helpers import ai_signal_catalog as cat
    assert len(cat.AI_PORTS) >= 25, f"AI_PORTS only has {len(cat.AI_PORTS)} entries"
    assert len(cat.AI_HEADER_PATTERNS) >= 20, f"AI_HEADER_PATTERNS only has {len(cat.AI_HEADER_PATTERNS)}"
    assert len(cat.AI_TITLE_PATTERNS) >= 25, f"AI_TITLE_PATTERNS only has {len(cat.AI_TITLE_PATTERNS)}"
    assert len(cat.AI_BODY_FINGERPRINTS) >= 15, f"AI_BODY_FINGERPRINTS only has {len(cat.AI_BODY_FINGERPRINTS)}"
    assert len(cat.AI_FAVICON_HASHES) >= 20, f"AI_FAVICON_HASHES only has {len(cat.AI_FAVICON_HASHES)}"


def test_body_fingerprint_does_not_overwrite_header_winner():
    """When header already won, the body fingerprint must NOT clobber it
    (header is the highest-confidence channel)."""
    e = {"headers": {"x-vllm-cache-hit": "1"}, "title": "x",
         "body": '<gradio-app src="/"></gradio-app>'}
    _annotate_ai_http_signals(e, ON)
    # Header fired first → name stays vllm even though body says gradio
    assert e.get("ai_framework_name") == "vllm"
    assert e.get("ai_framework_category") == "ai-runtime"


def test_body_fingerprint_toggle_off_disables_scan():
    e = {"headers": {}, "title": "x",
         "body": '<gradio-app src="/"></gradio-app>'}
    settings = dict(ON)
    settings["HTTP_PROBE_AI_WAPPALYZER_ENABLED"] = False
    _annotate_ai_http_signals(e, settings)
    assert e.get("ai_framework_name") is None


def test_body_fingerprint_skips_oversized_bodies():
    """Bodies > 512KB are skipped to bound per-URL cost. The marker is still
    present in the body but won't fire."""
    big = "x" * (513 * 1024) + '<gradio-app src="/"></gradio-app>'
    e = {"headers": {}, "title": "x", "body": big}
    _annotate_ai_http_signals(e, ON)
    assert e.get("ai_framework_name") is None


def test_body_fingerprint_no_match_leaves_entry_untouched():
    e = {"headers": {}, "title": "Plain", "body": "<html><body>Hello</body></html>"}
    _annotate_ai_http_signals(e, ON)
    assert "ai_framework_name" not in e
    assert "is_ai_framework_detected" not in e


def test_body_fingerprint_summary_counter_increments():
    entries = [{
        "url": "https://lc.test.invalid/",
        "input": "https://lc.test.invalid/",
        "host": "lc.test.invalid",
        "status_code": 200, "content_length": 1234, "title": "App",
        "header": {"content-type": "text/html"},
        "body": '<gradio-app src="/" theme="dark"></gradio-app>',
    }]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)
    assert result["summary"]["ai_wappalyzer_matches"] == 1
    assert result["by_url"]["https://lc.test.invalid/"]["ai_framework_name"] == "gradio"


# ---------------------------------------------------------------------------
# parse_httpx_output integration — JSONL file → annotated by_url
# ---------------------------------------------------------------------------

def _write_httpx_jsonl(entries: list[dict]) -> str:
    """httpx JSONL output is one JSON object per line. Write a temp file."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for e in entries:
        tmp.write(json.dumps(e) + "\n")
    tmp.close()
    return tmp.name


def test_parse_httpx_output_emits_ai_header_match_and_summary_counter():
    entries = [{
        "url": "https://ai.example.invalid/",
        "input": "https://ai.example.invalid/",
        "host": "ai.example.invalid",
        "status_code": 200, "content_length": 1234, "title": "API",
        "header": {"x-vllm-cache-hit": "1", "content-type": "application/json"},
    }]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)
    url_entry = result["by_url"]["https://ai.example.invalid/"]
    assert url_entry["is_ai_framework_detected"] is True
    assert url_entry["ai_framework_name"] == "vllm"
    assert url_entry["ai_framework_category"] == "ai-runtime"
    assert result["summary"]["ai_header_matches"] == 1
    assert result["summary"]["ai_title_matches"] == 0


def test_parse_httpx_output_emits_title_match_when_no_header_signal():
    entries = [{
        "url": "https://ui.example.invalid/",
        "input": "https://ui.example.invalid/",
        "host": "ui.example.invalid",
        "status_code": 200, "title": "Open WebUI",
        "header": {"content-type": "text/html"},
    }]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)
    url_entry = result["by_url"]["https://ui.example.invalid/"]
    assert url_entry["ai_frontend_product_guess"] == "open-webui"
    assert url_entry["ai_framework_category"] == "ai-frontend"
    assert result["summary"]["ai_title_matches"] == 1
    assert result["summary"]["ai_header_matches"] == 0


def test_parse_httpx_output_with_settings_none_emits_zero_ai_counters():
    """Legacy callers (no settings) must continue to work; AI fields stay
    unset and counters are zero."""
    entries = [{
        "url": "https://ai.example.invalid/",
        "input": "https://ai.example.invalid/",
        "host": "ai.example.invalid",
        "status_code": 200, "title": "Open WebUI",
        "header": {"x-vllm-cache-hit": "1"},
    }]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path)
    finally:
        Path(path).unlink(missing_ok=True)
    url_entry = result["by_url"]["https://ai.example.invalid/"]
    assert "is_ai_framework_detected" not in url_entry
    assert "ai_framework_name" not in url_entry
    assert "ai_frontend_product_guess" not in url_entry
    assert result["summary"]["ai_header_matches"] == 0
    assert result["summary"]["ai_title_matches"] == 0


def test_parse_httpx_output_preserves_existing_shape_when_no_ai_signal():
    """Regression: a plain non-AI URL must still pass through all the
    existing fields (status_code, title, server, technologies, …)."""
    entries = [{
        "url": "https://plain.example.invalid/",
        "input": "https://plain.example.invalid/",
        "host": "plain.example.invalid",
        "status_code": 200, "title": "Plain page", "webserver": "nginx",
        "content_length": 99, "content_type": "text/html",
        "tech": ["nginx"], "header": {"content-type": "text/html"},
    }]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)
    u = result["by_url"]["https://plain.example.invalid/"]
    assert u["status_code"] == 200 and u["title"] == "Plain page"
    assert u["server"] == "nginx" and u["technologies"] == ["nginx"]
    assert "is_ai_framework_detected" not in u


# ---------------------------------------------------------------------------
# Callsite verification
# ---------------------------------------------------------------------------

def _extract_call(source: str, opener: str) -> str:
    idx = source.find(opener)
    if idx == -1:
        return ""
    open_paren = source.find("(", idx)
    depth = 0
    i = open_paren
    while i < len(source):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return source[idx:i + 1]
        i += 1
    return source[idx:]


def test_callsite_run_http_probe_passes_settings_to_parse():
    src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "http_probe.py").read_text()
    call = _extract_call(src, "parse_httpx_output(str(httpx_output)")
    assert call, "could not locate parse_httpx_output callsite"
    assert "settings=settings" in call, f"settings missing: {call!r}"


# ---------------------------------------------------------------------------
# Patch A regression guard — httpx must run with --net=host
# ---------------------------------------------------------------------------

def test_httpx_docker_command_joins_paths_with_commas_not_repeated_flag():
    """Regression guard for the Patch C fix.

    httpx CLI's ``-path`` is single-value — repeating ``-path /a -path /b``
    silently keeps only the LAST one. Before the lap-1 Patch C fix, the
    recon's build_httpx_command did exactly that, so multi-path scans (e.g.
    the AI surface lab's /header/* + /title/* showroom of 39 paths) all
    collapsed to a single path probe per BaseURL.

    The fix joins paths with commas, which httpx accepts as a list.
    """
    from recon.main_recon_modules.http_probe import build_httpx_command
    settings = {
        "HTTPX_PATHS": ["/", "/header/vllm", "/header/langchain", "/title/open-webui"],
    }
    cmd = build_httpx_command(
        targets_file="/tmp/fake-targets.txt",
        output_file="/tmp/fake-output.json",
        settings=settings,
        use_proxy=False,
    )
    # Exactly ONE `-path` flag with all 4 paths joined by commas
    path_flag_count = sum(1 for arg in cmd if arg == "-path")
    assert path_flag_count == 1, (
        f"expected exactly one -path flag (comma-joined), got {path_flag_count}. "
        f"If the count is > 1, httpx will silently keep only the last path. "
        f"Re-apply the lap-1 Patch C fix in build_httpx_command()."
    )
    # The flag's value carries all 4 paths
    path_idx = cmd.index("-path")
    path_value = cmd[path_idx + 1]
    assert path_value == "/,/header/vllm,/header/langchain,/title/open-webui", (
        f"expected comma-joined paths, got {path_value!r}"
    )


def test_httpx_docker_command_omits_path_flag_when_no_paths_configured():
    """When HTTPX_PATHS is empty, the -path flag should not appear at all
    (httpx falls back to its default of just `/`). Catches a future
    refactor that accidentally emits `-path ''`."""
    from recon.main_recon_modules.http_probe import build_httpx_command
    cmd = build_httpx_command(
        targets_file="/tmp/x.txt",
        output_file="/tmp/y.json",
        settings={"HTTPX_PATHS": []},
        use_proxy=False,
    )
    assert "-path" not in cmd, "empty HTTPX_PATHS must not emit a -path flag"


def test_httpx_docker_command_includes_net_host():
    """Regression guard for the Patch A fix.

    Without ``--net=host``, the spawned httpx container runs on the default
    Docker bridge where 127.0.0.1 == httpx itself, not the recon host. That
    blocks every loopback scan (the guinea pig + agentic/labs/ai-surface).

    Naabu has had ``--net=host`` since the original recon shipped (line 12
    of port_scan.py's docker command). Httpx didn't, until lap-1 added it.
    This guard fails fast if anyone strips the flag later.
    """
    from recon.main_recon_modules.http_probe import build_httpx_command
    cmd = build_httpx_command(
        targets_file="/tmp/fake-targets.txt",
        output_file="/tmp/fake-output.json",
        settings={},
        use_proxy=False,
    )
    assert "--net=host" in cmd, (
        "httpx docker run is missing --net=host — loopback targets will "
        "all return ConnectionRefused. Re-apply the lap-1 Patch A fix in "
        "recon/main_recon_modules/http_probe.py:build_httpx_command()."
    )
    # And the order must be: --rm comes first, --net=host next (consistent
    # with naabu's pattern). Catches an accidental "added at end where it
    # gets eaten by docker as an image arg" mistake.
    net_idx = cmd.index("--net=host")
    rm_idx = cmd.index("--rm")
    image_idx = next(i for i, x in enumerate(cmd) if "httpx" in x and ":" in x)
    assert rm_idx < net_idx < image_idx, (
        f"--net=host must sit between --rm and the image; got {cmd[:net_idx+2]!r}"
    )


# ---------------------------------------------------------------------------
# Live Neo4j — http_mixin
# ---------------------------------------------------------------------------

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


def _cleanup_http_test_data(session, uid: str, pid: str):
    session.run(
        """
        MATCH (n)
        WHERE (n:BaseURL OR n:Endpoint OR n:Technology OR n:Certificate OR n:Header)
          AND n.user_id = $u AND n.project_id = $p
        DETACH DELETE n
        """,
        u=uid, p=pid,
    )


def _http_mixin_instance(driver):
    from graph_db.mixins.recon.http_mixin import HttpMixin

    class _ScratchGraph(HttpMixin):
        def __init__(self, drv):
            self.driver = drv

    return _ScratchGraph(driver)


def _make_http_recon_data(url, *, ai_header=None, ai_title=None):
    """Build a recon_data dict that update_graph_from_http_probe accepts.
    Either ai_header or ai_title (or both) triggers AI annotation upstream;
    here we simulate the annotator's output directly."""
    url_info = {
        "host": url.split("/")[2],
        "status_code": 200,
        "content_length": 1234,
        "content_type": "text/html",
        "title": ai_title or "Plain",
        "server": "nginx",
        "is_cdn": False,
        "technologies": [],
    }
    if ai_header:
        url_info.update({
            "is_ai_framework_detected": True,
            "ai_framework_name": ai_header,
            "ai_framework_category": "ai-runtime" if ai_header == "vllm" else "ai-framework",
        })
    if ai_title and not ai_header:
        url_info.update({
            "is_ai_framework_detected": True,
            "ai_framework_name": ai_title,
            "ai_framework_category": "ai-frontend",
            "ai_frontend_product_guess": ai_title,
        })
    return {
        "http_probe": {
            "by_url": {url: url_info},
            "by_host": {},
            "technologies_found": {},
            "wappalyzer": {},
        }
    }


def test_neo4j_http_mixin_sets_baseurl_ai_props_from_header():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_http_mixin_sets_baseurl_ai_props_from_header (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-header"
    url = "https://api.llm-test.invalid/v1/chat"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_make_http_recon_data(url, ai_header="vllm"), uid, pid)
        with drv.session() as s:
            row = _read_endpoint_ai_props(s, url, uid, pid)
            assert row is not None
            assert row["d"] is True
            assert row["f"] == "vllm"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_http_mixin_merges_ai_technology_and_links_baseurl():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_http_mixin_merges_ai_technology_and_links_baseurl (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-tech"
    url = "https://api.llm-test.invalid/v1/chat"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_make_http_recon_data(url, ai_header="vllm"), uid, pid)
        with drv.session() as s:
            tech = s.run(
                """
                MATCH (t:Technology {name:'vllm', user_id:$u, project_id:$p})
                RETURN t.category AS cat, t.source AS src
                """,
                u=uid, p=pid,
            ).single()
            assert tech is not None, "Technology(vllm) not created"
            assert tech["cat"] == "ai-runtime"
            assert tech["src"] == "ai-surface-recon"

            rel = _read_baseurl_tech_edge(s, url, uid, pid, "vllm")
            assert rel is not None, "USES_TECHNOLOGY edge missing"
            assert rel["detected_by"].startswith("httpx-ai-"), (
                f"detected_by should be httpx-ai-*, got {rel['detected_by']!r}"
            )
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_http_mixin_no_ai_tech_when_no_ai_signal():
    """A plain (non-AI) BaseURL must NOT trigger an AI Technology MERGE."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_http_mixin_no_ai_tech_when_no_ai_signal (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-plain"
    url = "https://plain.example.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_make_http_recon_data(url), uid, pid)  # no ai_header/title
        with drv.session() as s:
            n = s.run(
                "MATCH (t:Technology {user_id:$u, project_id:$p}) WHERE t.category STARTS WITH 'ai-' RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n == 0, f"plain URL produced {n} AI Technology node(s)"
            # And Endpoint exists but without is_ai_framework_detected = true
            row = _read_endpoint_ai_props(s, url, uid, pid)
            assert row is not None
            assert row["d"] is None or row["d"] is False
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_http_mixin_repeat_runs_keep_single_tech_edge():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_http_mixin_repeat_runs_keep_single_tech_edge (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-rerun"
    url = "https://api.llm-test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_make_http_recon_data(url, ai_header="vllm"), uid, pid)
        mixin.update_graph_from_http_probe(_make_http_recon_data(url, ai_header="vllm"), uid, pid)
        with drv.session() as s:
            base_url, path = _split_url_test(url)
            n_rel = s.run(
                """
                MATCH (e:Endpoint {path:$path, method:'GET', baseurl:$base_url, user_id:$u, project_id:$p})
                      -[r:USES_TECHNOLOGY]->(t:Technology {name:'vllm'})
                RETURN count(r) AS n
                """,
                path=path, base_url=base_url, u=uid, p=pid,
            ).single()["n"]
            assert n_rel == 1, f"expected 1 USES_TECHNOLOGY edge, got {n_rel}"
            n_tech = s.run(
                "MATCH (t:Technology {name:'vllm', user_id:$u, project_id:$p}) RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n_tech == 1
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


# ---------------------------------------------------------------------------
# Mixin — detected_by resolution exhaustive coverage
# ---------------------------------------------------------------------------

def _populate_favicon_catalog(hash_int: int, product: str):
    """Push a hash → product entry through the production-side module so the
    mixin's annotator/lookup can find it. Returns a cleanup callable."""
    import helpers.ai_signal_catalog as cat
    cat.AI_FAVICON_HASHES[hash_int] = product

    def _cleanup():
        cat.AI_FAVICON_HASHES.pop(hash_int, None)

    return _cleanup


def _split_url_test(url: str) -> tuple[str, str]:
    """Mirror of graph_db/mixins/recon/http_mixin._split_url for test queries.
    Returns (base_url, path) so tests can hit the right Endpoint key
    (path, method='GET', baseurl=base_url) after Patch D."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}", p.path or "/"


def _read_baseurl_tech_edge(session, url: str, uid: str, pid: str, tech_name: str):
    """Patch D: AI USES_TECHNOLOGY moved from BaseURL to Endpoint.
    This helper retains the legacy test signature (`url`) but issues the
    new Cypher against Endpoint keyed by (path, method, baseurl)."""
    base_url, path = _split_url_test(url)
    return session.run(
        """
        MATCH (e:Endpoint {path:$path, method:'GET', baseurl:$base_url, user_id:$u, project_id:$p})
              -[r:USES_TECHNOLOGY]->(t:Technology {name:$tech, user_id:$u, project_id:$p})
        RETURN r.detected_by AS detected_by, t.category AS category
        """,
        path=path, base_url=base_url, u=uid, p=pid, tech=tech_name,
    ).single()


def _read_endpoint_ai_props(session, url: str, uid: str, pid: str):
    """Same legacy-signature wrapper for the BaseURL property read."""
    base_url, path = _split_url_test(url)
    return session.run(
        """
        MATCH (e:Endpoint {path:$path, method:'GET', baseurl:$base_url, user_id:$u, project_id:$p})
        RETURN e.is_ai_framework_detected AS d,
               e.ai_framework_name AS f,
               e.ai_frontend_product_guess AS product
        """,
        path=path, base_url=base_url, u=uid, p=pid,
    ).single()


def _recon_data_with_url_entry(url: str, url_entry: dict) -> dict:
    """Wrap an already-annotated url_entry in the recon_data shape expected
    by update_graph_from_http_probe."""
    url_entry.setdefault("host", url.split("/")[2])
    url_entry.setdefault("status_code", 200)
    url_entry.setdefault("is_cdn", False)
    url_entry.setdefault("technologies", [])
    return {
        "http_probe": {
            "by_url": {url: url_entry},
            "by_host": {},
            "technologies_found": {},
            "wappalyzer": {},
        }
    }


def test_neo4j_mixin_detected_by_is_header_when_only_header_fires():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_detected_by_is_header_when_only_header_fires (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-db-header-only"
    url = "https://header-only.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        # Header-only: simulate the annotator's output
        url_entry = {
            "is_ai_framework_detected": True,
            "ai_framework_name": "vllm",
            "ai_framework_category": "ai-runtime",
        }
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_recon_data_with_url_entry(url, url_entry), uid, pid)
        with drv.session() as s:
            row = _read_baseurl_tech_edge(s, url, uid, pid, "vllm")
            assert row is not None
            assert row["detected_by"] == "httpx-ai-header", (
                f"expected detected_by=httpx-ai-header, got {row['detected_by']!r}"
            )
            assert row["category"] == "ai-runtime"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_detected_by_is_title_when_only_title_fires():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_detected_by_is_title_when_only_title_fires (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-db-title-only"
    url = "https://title-only.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        # Title-only: ai_framework_name == ai_frontend_product_guess; no favicon_hash
        url_entry = {
            "is_ai_framework_detected": True,
            "ai_framework_name": "open-webui",
            "ai_framework_category": "ai-frontend",
            "ai_frontend_product_guess": "open-webui",
        }
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_recon_data_with_url_entry(url, url_entry), uid, pid)
        with drv.session() as s:
            row = _read_baseurl_tech_edge(s, url, uid, pid, "open-webui")
            assert row is not None
            assert row["detected_by"] == "httpx-ai-title", (
                f"expected detected_by=httpx-ai-title, got {row['detected_by']!r}"
            )
            assert row["category"] == "ai-frontend"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_detected_by_is_favicon_when_favicon_hash_present():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_detected_by_is_favicon_when_favicon_hash_present (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-db-favicon"
    url = "https://favicon-only.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        # Favicon-only: ai_framework_name == ai_frontend_product_guess AND favicon_hash present
        url_entry = {
            "is_ai_framework_detected": True,
            "ai_framework_name": "librechat",
            "ai_framework_category": "ai-frontend",
            "ai_frontend_product_guess": "librechat",
            "favicon_hash": -123456789,
        }
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_recon_data_with_url_entry(url, url_entry), uid, pid)
        with drv.session() as s:
            row = _read_baseurl_tech_edge(s, url, uid, pid, "librechat")
            assert row is not None
            assert row["detected_by"] == "httpx-ai-favicon", (
                f"expected detected_by=httpx-ai-favicon, got {row['detected_by']!r}"
            )
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_detected_by_header_wins_when_header_and_favicon_both_fire():
    """When header fires AND favicon fires, ai_framework_name (from header)
    differs from ai_frontend_product_guess (from favicon). The mixin must
    pick the header source for detected_by since that's the source of the
    MERGEd Technology node's name."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_detected_by_header_wins_when_header_and_favicon_both_fire (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-db-mixed"
    url = "https://mixed.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        url_entry = {
            "is_ai_framework_detected": True,
            "ai_framework_name": "vllm",                  # from header
            "ai_framework_category": "ai-runtime",
            "ai_frontend_product_guess": "open-webui",    # from favicon
            "favicon_hash": 12345,
        }
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(_recon_data_with_url_entry(url, url_entry), uid, pid)
        with drv.session() as s:
            # Only the header-named Technology (vllm) is MERGEd per plan
            row = _read_baseurl_tech_edge(s, url, uid, pid, "vllm")
            assert row is not None
            assert row["detected_by"] == "httpx-ai-header"
            assert row["category"] == "ai-runtime"
            # No Technology(name='open-webui') is created because plan says
            # one Technology per BaseURL, named from ai_framework_name.
            n_other = s.run(
                "MATCH (t:Technology {name:'open-webui', user_id:$u, project_id:$p}) RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n_other == 0, "open-webui Technology should NOT be created when header already produced vllm"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


# ---------------------------------------------------------------------------
# Mixin — regression that existing httpx + wappalyzer Technology blocks still work
# ---------------------------------------------------------------------------

def test_neo4j_mixin_existing_httpx_technologies_block_still_creates_nodes():
    """The AI Technology block was inserted between the httpx block and the
    wappalyzer block. Verify the httpx block still emits its Technology
    nodes (`name/version` shape, `source='httpx'`, `confidence` on the edge).
    """
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_existing_httpx_technologies_block_still_creates_nodes (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-existing-tech"
    url = "https://classic.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        recon_data = {
            "http_probe": {
                "by_url": {url: {
                    "host": "classic.test.invalid", "status_code": 200,
                    "is_cdn": False,
                    "technologies": ["nginx:1.18.0", "PHP:7.4"],
                }},
                "by_host": {},
                "technologies_found": {},
                "wappalyzer": {},
            }
        }
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(recon_data, uid, pid)
        with drv.session() as s:
            n_nginx = s.run(
                "MATCH (t:Technology {name:'nginx', version:'1.18.0', user_id:$u, project_id:$p}) RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n_nginx == 1, "classic httpx Technology block broken — nginx node missing"
            n_ai = s.run(
                "MATCH (t:Technology {user_id:$u, project_id:$p}) WHERE t.category STARTS WITH 'ai-' RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n_ai == 0, f"non-AI URL produced {n_ai} AI Technology nodes"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_ai_and_classic_technologies_coexist_for_same_baseurl():
    """A BaseURL can carry BOTH classic Technology(name=nginx/1.18.0) AND
    AI Technology(name=vllm, category=ai-runtime). They are separate nodes
    and the BaseURL has two USES_TECHNOLOGY edges with different detected_by."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_ai_and_classic_technologies_coexist_for_same_baseurl (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-coexist"
    url = "https://coexist.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        recon_data = {
            "http_probe": {
                "by_url": {url: {
                    "host": "coexist.test.invalid", "status_code": 200,
                    "is_cdn": False,
                    "technologies": ["nginx:1.25.0"],
                    "is_ai_framework_detected": True,
                    "ai_framework_name": "vllm",
                    "ai_framework_category": "ai-runtime",
                }},
                "by_host": {},
                "technologies_found": {},
                "wappalyzer": {},
            }
        }
        mixin = _http_mixin_instance(drv)
        mixin.update_graph_from_http_probe(recon_data, uid, pid)
        base_url, path = _split_url_test(url)
        with drv.session() as s:
            classic = s.run(
                """
                MATCH (e:Endpoint {path:$path, method:'GET', baseurl:$base_url, user_id:$u, project_id:$p})
                      -[r:USES_TECHNOLOGY]->(t:Technology {name:'nginx'})
                RETURN r.detected_by AS detected_by
                """,
                path=path, base_url=base_url, u=uid, p=pid,
            ).single()
            ai = s.run(
                """
                MATCH (e:Endpoint {path:$path, method:'GET', baseurl:$base_url, user_id:$u, project_id:$p})
                      -[r:USES_TECHNOLOGY]->(t:Technology {name:'vllm'})
                RETURN r.detected_by AS detected_by, t.category AS category
                """,
                path=path, base_url=base_url, u=uid, p=pid,
            ).single()
            assert classic is not None, "classic nginx tech edge missing"
            assert classic["detected_by"] == "httpx"
            assert ai is not None, "AI vllm tech edge missing"
            assert ai["detected_by"] == "httpx-ai-header"
            assert ai["category"] == "ai-runtime"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_ai_technology_category_preserved_across_reruns():
    """If the first scan tags a Technology as ai-runtime and a re-scan tags
    the same name again, the category property must stay ai-runtime — not
    get clobbered by a stale node from a different source."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_ai_technology_category_preserved_across_reruns (neo4j unreachable)")
        return
    uid, pid = "phase4-test-user", "phase4-test-project-tech-rerun"
    url = "https://rerun.test.invalid/"
    try:
        with drv.session() as s:
            _cleanup_http_test_data(s, uid, pid)
        mixin = _http_mixin_instance(drv)
        url_entry = {
            "is_ai_framework_detected": True,
            "ai_framework_name": "litellm",
            "ai_framework_category": "ai-proxy",
        }
        mixin.update_graph_from_http_probe(_recon_data_with_url_entry(url, url_entry), uid, pid)
        mixin.update_graph_from_http_probe(_recon_data_with_url_entry(url, url_entry), uid, pid)
        with drv.session() as s:
            cat_value = s.run(
                "MATCH (t:Technology {name:'litellm', user_id:$u, project_id:$p}) RETURN t.category AS c",
                u=uid, p=pid,
            ).single()["c"]
            assert cat_value == "ai-proxy", f"category drifted on re-run, got {cat_value!r}"
            _cleanup_http_test_data(s, uid, pid)
    finally:
        drv.close()


# ---------------------------------------------------------------------------
# parse_httpx_output — batch / multi-URL behaviour
# ---------------------------------------------------------------------------

def test_parse_httpx_output_handles_batch_of_mixed_urls():
    """Three URLs, three different paths: header match, title match, plain.
    Counters and per-URL annotations must all be correct."""
    entries = [
        {
            "url": "https://ai-runtime.test.invalid/", "input": "ai-runtime.test.invalid",
            "host": "ai-runtime.test.invalid", "status_code": 200, "title": "API",
            "header": {"x-vllm-cache-hit": "1"},
        },
        {
            "url": "https://ai-frontend.test.invalid/", "input": "ai-frontend.test.invalid",
            "host": "ai-frontend.test.invalid", "status_code": 200, "title": "Open WebUI",
            "header": {"content-type": "text/html"},
        },
        {
            "url": "https://plain.test.invalid/", "input": "plain.test.invalid",
            "host": "plain.test.invalid", "status_code": 200, "title": "Plain page",
            "header": {"server": "nginx"},
        },
    ]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)

    rt = result["by_url"]["https://ai-runtime.test.invalid/"]
    fe = result["by_url"]["https://ai-frontend.test.invalid/"]
    pl = result["by_url"]["https://plain.test.invalid/"]
    assert rt["ai_framework_name"] == "vllm"
    assert rt["ai_framework_category"] == "ai-runtime"
    assert fe["ai_frontend_product_guess"] == "open-webui"
    assert fe["ai_framework_category"] == "ai-frontend"
    assert "is_ai_framework_detected" not in pl
    assert result["summary"]["ai_header_matches"] == 1
    assert result["summary"]["ai_title_matches"] == 1
    assert result["summary"]["ai_favicon_matches"] == 0


def test_parse_httpx_output_each_url_annotated_independently():
    """Annotations on one URL must not bleed into other URLs (shared-state guard)."""
    entries = [
        {"url": f"https://h{i}.test.invalid/", "input": f"h{i}.test.invalid",
         "host": f"h{i}.test.invalid", "status_code": 200,
         "header": {"x-vllm-cache-hit": "1"} if i % 2 == 0 else {"content-type": "text/html"}}
        for i in range(6)
    ]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)
    for i in range(6):
        u = result["by_url"][f"https://h{i}.test.invalid/"]
        if i % 2 == 0:
            assert u["ai_framework_name"] == "vllm"
        else:
            assert "ai_framework_name" not in u
    assert result["summary"]["ai_header_matches"] == 3


def test_parse_httpx_output_header_match_in_one_url_does_not_pollute_summary_for_zero_match_url():
    """Regression: the per-URL `ai_fired` dict must be re-created for each
    URL. A bug that re-used the same dict across iterations would
    over-count matches in `summary.ai_header_matches`."""
    entries = [
        {"url": "https://a.test.invalid/", "input": "a.test.invalid",
         "host": "a.test.invalid", "status_code": 200,
         "header": {"x-vllm-cache-hit": "1"}},
        {"url": "https://b.test.invalid/", "input": "b.test.invalid",
         "host": "b.test.invalid", "status_code": 200,
         "header": {"content-type": "text/html"}},  # no AI signal
    ]
    path = _write_httpx_jsonl(entries)
    try:
        result = parse_httpx_output(path, settings=ON)
    finally:
        Path(path).unlink(missing_ok=True)
    assert result["summary"]["ai_header_matches"] == 1
    assert "is_ai_framework_detected" not in result["by_url"]["https://b.test.invalid/"]


# ---------------------------------------------------------------------------
# Annotator — CRLF header parsing edge cases
# ---------------------------------------------------------------------------

def test_annotator_crlf_headers_skip_lines_without_colon():
    """Some malformed responses produce blank or colon-less lines. The
    annotator must skip them, not raise."""
    e = _entry(headers="HTTP/1.1 200 OK\nx-vllm-cache-hit: 1\n\nbody-starts-here\n")
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "vllm"


def test_annotator_crlf_headers_handle_value_with_colon():
    """Header values can contain colons (e.g. timestamps). The split must
    only happen once."""
    e = _entry(headers="x-vllm-cache-hit: HIT: at 2025-01-01T12:00:00\ncontent-type: text/plain\n")
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "vllm"


def test_annotator_crlf_headers_empty_name_after_strip_is_skipped():
    """Lines like ': value' produce empty header names. Must not match
    anything (regex patterns require the prefix)."""
    e = _entry(headers=": value\n  : another\nx-vllm-cache-hit: 1\n")
    _annotate_ai_http_signals(e, ON)
    # vllm still wins because line 3 matches
    assert e["ai_framework_name"] == "vllm"


def test_annotator_dict_headers_with_empty_key_does_not_crash():
    e = _entry(headers={"": "junk", "x-vllm-cache-hit": "1"})
    _annotate_ai_http_signals(e, ON)
    assert e["ai_framework_name"] == "vllm"


# ---------------------------------------------------------------------------
# Annotator — favicon zero-hash edge case
# ---------------------------------------------------------------------------

def test_annotator_favicon_zero_hash_is_falsy_but_handled():
    """mmh3 can occasionally hash to 0. The annotator must NOT short-circuit
    on `if favicon_int is not None:` for the integer 0."""
    import helpers.ai_signal_catalog as cat
    cat.AI_FAVICON_HASHES[0] = "zero-hash-fake-product"
    try:
        e = _entry(favicon=0)
        _annotate_ai_http_signals(e, ON)
        assert e.get("ai_frontend_product_guess") == "zero-hash-fake-product"
    finally:
        cat.AI_FAVICON_HASHES.pop(0, None)


def test_annotator_favicon_negative_int_handled():
    """mmh3 returns signed int32 — negative values are normal."""
    import helpers.ai_signal_catalog as cat
    cat.AI_FAVICON_HASHES[-987654321] = "fake-neg"
    try:
        e = _entry(favicon=-987654321)
        _annotate_ai_http_signals(e, ON)
        assert e["ai_frontend_product_guess"] == "fake-neg"
    finally:
        cat.AI_FAVICON_HASHES.pop(-987654321, None)


# ---------------------------------------------------------------------------
# Annotator — settings type robustness
# ---------------------------------------------------------------------------

def test_annotator_treats_falsy_toggle_value_as_off():
    """A toggle set to 0, '', or False must disable that signal."""
    e = _entry(headers={"x-vllm-cache-hit": "1"})
    for falsy in (False, 0, "", None):
        e2 = dict(e)
        _annotate_ai_http_signals(e2, {"HTTP_PROBE_AI_HEADER_SCAN_ENABLED": falsy})
        assert "ai_framework_name" not in e2, (
            f"falsy toggle {falsy!r} did NOT disable header scan"
        )


def test_annotator_treats_truthy_non_bool_toggle_as_on():
    """A toggle set to 1 or 'true' must enable that signal."""
    for truthy in (True, 1, "yes", "true"):
        e = _entry(headers={"x-vllm-cache-hit": "1"})
        _annotate_ai_http_signals(e, {"HTTP_PROBE_AI_HEADER_SCAN_ENABLED": truthy})
        assert e.get("ai_framework_name") == "vllm", (
            f"truthy toggle {truthy!r} did NOT enable header scan"
        )


# ---------------------------------------------------------------------------
# Pattern coverage — case sensitivity
# ---------------------------------------------------------------------------

def test_every_header_pattern_matches_uppercase_variant():
    """HTTP headers are case-insensitive. The annotator must match the
    same framework whether the header is lower / upper / mixed case."""
    # Use the same fixture as the parameterised pattern test
    samples = {
        "vllm": ("x-vllm-cache-hit", "ai-runtime"),
        "langchain": ("x-langchain-run-id", "ai-framework"),
        "litellm": ("x-litellm-model-id", "ai-proxy"),
        "anthropic": ("anthropic-version", "ai-sdk-client"),
    }
    for framework, (name, category) in samples.items():
        for transform in (str.upper, str.lower, str.title):
            e = _entry(headers={transform(name): "x"})
            _annotate_ai_http_signals(e, ON)
            assert e.get("ai_framework_name") == framework, (
                f"case variant {transform(name)!r} did not match {framework!r}"
            )


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    failures: list[tuple[str, str]] = []
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append((name, str(exc)))
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append((name, f"{type(exc).__name__}: {exc}"))
    print()
    print(f"{passed} passed, {len(failures)} failed")
    if failures:
        print()
        print("Failures:")
        for n, err in failures:
            print(f"  - {n}: {err}")
        sys.exit(1)
    sys.exit(0)
