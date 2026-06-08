"""
Signal catalogue the guinea pig emits.

Must mirror what `recon/helpers/ai_signal_catalog.py` is built to detect.
When the recon catalog changes, this file must be updated in lockstep —
the e2e driver does a parity check between the two before running the
scan, so any drift fails fast.

Three tables:
  - PORT_LISTENERS: one entry per port the guinea pig binds. Each port
    serves an HTML page on `/` with a deterministic title + Server header
    that fires (or deliberately skips, for disambiguate ports) the
    matching detection.
  - HEADER_VARIANTS: one entry per AI_HEADER_PATTERNS pattern. Served
    from the header-showroom port on `/header/<framework>`.
  - TITLE_VARIANTS: one entry per AI_TITLE_PATTERNS pattern. Served
    from the title-showroom port on `/title/<product>`.

No regex on this side — we only emit bytes. The recon catalog does
the matching.
"""
from __future__ import annotations


HEADER_SHOWROOM_PORT = 9100
TITLE_SHOWROOM_PORT = 9101
# Lap-2 — resource_enum AI classifier showroom. Serves an HTML index with
# links to every catalogued AI path. Katana crawls, builds Endpoint nodes,
# and the resource_enum AI classifier tags each one.
ENDPOINT_AI_CLASSIFIER_PORT = 9103
# Lap-3 (Phase 6) — js_recon AI SDK showroom. Serves an HTML index whose
# <script> tags point at fixture JS files. Each file is engineered to trip
# one or more match_ai_sdk() patterns — SDK imports, hard-coded provider
# keys, the dangerouslyAllowBrowser opt-in, AI-frontend markers in shipped
# JS chunks, provider base URLs. The js_recon module downloads each file,
# runs match_ai_sdk(), and writes JsReconFinding(finding_type='ai-sdk-*')
# nodes. The Phase 6 mixin then enriches matching Secret nodes with
# ai_provider/ai_finding_id.
JS_RECON_AI_SDK_PORT = 9104

# ZAP Ajax Spider showroom — exercises the browser-driven discovery paths
# that static crawlers (Katana, Hakrawler) cannot reach. Every "endpoint"
# on this port is discovered through a different runtime mechanism: JS-
# only XHR, runtime-templated URL, history.pushState navigation, click-
# cascade reveal, form submission, GraphQL POST, and an auth-gated branch
# that only fires when ZAP injects an Authorization header via Replacer.
# Logout-style links and static-asset noise are included to verify
# logoutAvoidance and excludePatterns behaviour.
ZAP_AJAX_SHOWROOM_PORT = 9105


# ---------------------------------------------------------------------------
# ZAP Ajax Spider showroom — what each discovery branch tests
# ---------------------------------------------------------------------------
# Each entry documents one endpoint, how ZAP would reach it via the
# browser, and what static crawlers (Katana/Hakrawler) would miss.

ZAP_AJAX_TEST_ENDPOINTS: list[dict] = [
    {
        "path": "/about",
        "method": "GET",
        "discovery": "Static <a href> in HTML",
        "katana_finds": True,
        "zap_finds": True,
        "note": "Baseline. Both crawlers find it. Sanity check.",
    },
    {
        "path": "/api/users/list",
        "method": "GET",
        "discovery": "fetch() in onclick handler",
        "katana_finds": False,
        "zap_finds": True,
        "note": "URL only exists inside a JS function body. Browser must click the button.",
    },
    {
        "path": "/api/projects/42",
        "method": "GET",
        "discovery": "Runtime-templated URL (`/api/projects/${id}`)",
        "katana_finds": False,
        "zap_finds": True,
        "note": "Path constructed via template literal — id is computed at runtime.",
    },
    {
        "path": "/spa/dashboard",
        "method": "GET",
        "discovery": "history.pushState route change",
        "katana_finds": False,
        "zap_finds": True,
        "note": "SPA client-side navigation, no real HTTP request to /spa/dashboard.",
    },
    {
        "path": "/api/dashboard-data",
        "method": "GET",
        "discovery": "fetch() after pushState",
        "katana_finds": False,
        "zap_finds": True,
        "note": "Data XHR fired after the SPA route change.",
    },
    {
        "path": "/api/secret-page",
        "method": "GET",
        "discovery": "Cascade — second button only appears after first click",
        "katana_finds": False,
        "zap_finds": True,
        "note": "Tests that ZAP follows reveal chains, not just first-level elements.",
    },
    {
        "path": "/graphql",
        "method": "POST",
        "discovery": "fetch with POST body from button onclick",
        "katana_finds": False,
        "zap_finds": True,
        "note": "GraphQL POST — Katana doesn't generate POST traffic.",
    },
    {
        "path": "/api/search",
        "method": "GET",
        "discovery": "form.onsubmit triggers fetch with query string",
        "katana_finds": False,
        "zap_finds": True,
        "note": "Form discovery — exercises randomInputs path if enabled.",
    },
    {
        "path": "/api/auth/logout",
        "method": "GET",
        "discovery": "<a href> with text 'Sign out'",
        "katana_finds": True,
        "zap_finds": False,  # When logoutAvoidance=true (default)
        "note": "logoutAvoidance=true MUST skip this. Verifies session safety.",
    },
    {
        "path": "/static/logo.png",
        "method": "GET",
        "discovery": "<img src> in HTML",
        "katana_finds": True,
        "zap_finds": True,  # Unless excluded via excludePatterns
        "note": "Static asset noise. Filter via excludePatterns: \\.png$",
    },
    {
        "path": "/api/me",
        "method": "GET",
        "discovery": "Auth-aware fetch on load (always called)",
        "katana_finds": False,
        "zap_finds": True,
        "note": "Server returns header 'x-redamon-authed: true' when Authorization header is injected.",
    },
    {
        "path": "/api/admin/users",
        "method": "GET",
        "discovery": "JS-injected <a> only rendered when /api/me reports authed",
        "katana_finds": False,
        "zap_finds": "auth-only",
        "note": "Discoverable ONLY when ZAP injects Authorization header via Replacer. Exercises the customHeaders flow end-to-end.",
    },
    {
        "path": "/api/admin/audit-log",
        "method": "GET",
        "discovery": "Cascade fetch after /api/me returned authed",
        "katana_finds": False,
        "zap_finds": "auth-only",
        "note": "Auth-gated deep endpoint. Without Authorization header, ZAP never reaches it.",
    },
]


# ---------------------------------------------------------------------------
# Per-port listeners — exercise port_scan catalog + nmap version regex
# ---------------------------------------------------------------------------

PORT_LISTENERS: list[dict] = [
    # ─── Unambiguous AI ports (11) — port_scan MUST emit Technology(ai-*) ─
    {
        "port": 11434, "name": "ollama",
        "html_title": "Ollama",
        "server_header": "Ollama/0.1.32",
        "expected_port_catalog": {"name": "ollama", "category": "ai-runtime"},
        "expected_nmap_runtime": "ollama",
    },
    {
        "port": 1234, "name": "lm-studio",
        "html_title": "LM Studio",
        "server_header": "lm-studio/0.2.10",
        "expected_port_catalog": {"name": "lm-studio", "category": "ai-runtime"},
        "expected_nmap_runtime": None,  # not in AI_NMAP_VERSION_PATTERNS
    },
    {
        "port": 4000, "name": "litellm",
        "html_title": "LiteLLM",
        "server_header": "LiteLLM/1.30",
        "expected_port_catalog": {"name": "litellm", "category": "ai-proxy"},
        "expected_nmap_runtime": "litellm",
    },
    {
        "port": 6333, "name": "qdrant",
        "html_title": "Qdrant",
        "server_header": "qdrant/1.7.0",
        "expected_port_catalog": {"name": "qdrant", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 6334, "name": "qdrant-grpc",
        "html_title": "Qdrant gRPC",
        "server_header": "qdrant/1.7.0",
        "expected_port_catalog": {"name": "qdrant-grpc", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 19530, "name": "milvus",
        "html_title": "Milvus",
        "server_header": "milvus/2.3.0",
        "expected_port_catalog": {"name": "milvus", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 9091, "name": "milvus-metrics",
        "html_title": "Milvus Metrics",
        "server_header": "milvus/2.3.0",
        "expected_port_catalog": {"name": "milvus-metrics", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 7860, "name": "gradio",
        "html_title": "Gradio Demo",
        "server_header": "gradio/4.0",
        "expected_port_catalog": {"name": "gradio", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 8188, "name": "comfyui",
        "html_title": "ComfyUI",
        "server_header": "ComfyUI/0.1.0",
        "expected_port_catalog": {"name": "comfyui", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 8501, "name": "streamlit",
        "html_title": "Streamlit App",
        "server_header": "Streamlit/1.30",
        "expected_port_catalog": {"name": "streamlit", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 3001, "name": "anythingllm",
        "html_title": "AnythingLLM Workspace",
        "server_header": "AnythingLLM/0.2.0",
        "expected_port_catalog": {"name": "anythingllm", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },

    # ─── Disambiguate ports (2) — port_scan MUST skip; one still fires
    #     via http_probe title regex for :8080 ────────────────────────────
    #
    # Three catalog disambiguate ports CANNOT be bound here because Redamon
    # services publish them on the host:
    #   - 8000: kali-sandbox MCP network-recon
    #   - 8002: kali-sandbox MCP nuclei
    #   - 3000: webapp (the UI itself)
    # The disambiguate behaviour is still validated by 8001 + 8080.
    # The vllm nmap-regex test is preserved by binding `vllm/0.4.1` on
    # off-catalog port 18000.
    {
        "port": 18000, "name": "vllm-banner-only",
        "html_title": "vLLM API",
        "server_header": "vllm/0.4.1",
        # Outside the AI port catalog → port_scan must NOT tag, nmap regex MUST tag
        "expected_port_catalog": None,
        "expected_nmap_runtime": "vllm",
    },
    {
        "port": 8001, "name": "triton-or-vllm",
        "html_title": "Triton API",
        "server_header": "triton-server/24.05",
        "expected_port_catalog": None,
        "expected_nmap_runtime": "triton",
    },
    {
        "port": 8080, "name": "open-webui-front",
        # IMPORTANT: title fires `http_probe` AI title regex → BaseURL gets
        # is_ai_framework_detected=true via httpx-ai-title path, even though
        # port_scan skipped 8080 because it's disambiguate=True. Proves the
        # plan's "disambiguate ports can still be promoted by http_probe" rule.
        "html_title": "Open WebUI",
        "server_header": "nginx/1.18",
        "expected_port_catalog": None,
        "expected_nmap_runtime": None,
        "expected_http_title": "open-webui",
    },
]


# ---------------------------------------------------------------------------
# Header showroom (port 9100) — exercise every AI_HEADER_PATTERNS entry
# ---------------------------------------------------------------------------

HEADER_VARIANTS: dict[str, dict] = {
    # Runtimes
    "vllm":       {"headers": {"x-vllm-cache-hit": "1"},
                   "expected_framework": "vllm", "expected_category": "ai-runtime"},
    "tgi":        {"headers": {"x-tgi-request-id": "stub"},
                   "expected_framework": "tgi", "expected_category": "ai-runtime"},
    "tei":        {"headers": {"x-tei-version": "1.2"},
                   "expected_framework": "text-embeddings-inference", "expected_category": "ai-runtime"},
    "bentoml":    {"headers": {"x-bentoml-version": "1.1.0"},
                   "expected_framework": "bentoml", "expected_category": "ai-runtime"},
    "baseten":    {"headers": {"x-baseten-deployment": "dep-abc"},
                   "expected_framework": "baseten", "expected_category": "ai-runtime"},
    "modal":      {"headers": {"x-modal-task-id": "task-xyz"},
                   "expected_framework": "modal", "expected_category": "ai-runtime"},
    "replicate":  {"headers": {"x-replicate-prediction": "pred-123"},
                   "expected_framework": "replicate", "expected_category": "ai-runtime"},
    "runpod":     {"headers": {"x-runpod-pod-id": "pod-456"},
                   "expected_framework": "runpod", "expected_category": "ai-runtime"},

    # Frameworks / orchestrators
    "langchain":  {"headers": {"x-langchain-run-id": "run-789"},
                   "expected_framework": "langchain", "expected_category": "ai-framework"},
    "llamaindex": {"headers": {"x-llamaindex-trace-id": "trace-abc"},
                   "expected_framework": "llamaindex", "expected_category": "ai-framework"},
    "langfuse":   {"headers": {"langfuse-trace-id": "lf-trace-1"},
                   "expected_framework": "langfuse", "expected_category": "ai-framework"},
    "mcp":        {"headers": {"x-mcp-server-name": "stub"},
                   "expected_framework": "mcp", "expected_category": "ai-framework"},

    # Proxies / gateways
    "litellm":    {"headers": {"x-litellm-model-id": "gpt-4"},
                   "expected_framework": "litellm", "expected_category": "ai-proxy"},
    "helicone":   {"headers": {"x-helicone-cache": "HIT"},
                   "expected_framework": "helicone", "expected_category": "ai-proxy"},
    "portkey":    {"headers": {"x-portkey-cache": "x"},
                   "expected_framework": "portkey", "expected_category": "ai-proxy"},
    "omniroute":  {"headers": {"x-omniroute-trace": "x"},
                   "expected_framework": "omniroute", "expected_category": "ai-proxy"},
    "cloudflare": {"headers": {"cf-aig-cache-status": "hit"},
                   "expected_framework": "cloudflare-ai-gateway", "expected_category": "ai-proxy"},
    "together":   {"headers": {"together-request-id": "req-1"},
                   "expected_framework": "together", "expected_category": "ai-proxy"},

    # SDK clients
    "openai":     {"headers": {"openai-organization": "org-abc"},
                   "expected_framework": "openai", "expected_category": "ai-sdk-client"},
    "anthropic":  {"headers": {"anthropic-version": "2023-06-01"},
                   "expected_framework": "anthropic", "expected_category": "ai-sdk-client"},
}


# ---------------------------------------------------------------------------
# Title showroom (port 9101) — exercise every AI_TITLE_PATTERNS entry
# ---------------------------------------------------------------------------

TITLE_VARIANTS: dict[str, dict] = {
    "open-webui":     {"title": "Open WebUI",
                       "expected_product": "open-webui"},
    "librechat":      {"title": "LibreChat",
                       "expected_product": "librechat"},
    "anythingllm":    {"title": "AnythingLLM Workspace",
                       "expected_product": "anythingllm"},
    "flowise":        {"title": "Flowise",
                       "expected_product": "flowise"},
    "langflow":       {"title": "Langflow",
                       "expected_product": "langflow"},
    "dify":           {"title": "Dify Dashboard",
                       "expected_product": "dify"},
    "comfyui":        {"title": "ComfyUI",
                       "expected_product": "comfyui"},
    "gradio":         {"title": "Gradio demo",
                       "expected_product": "gradio"},
    "streamlit":      {"title": "Streamlit App",
                       "expected_product": "streamlit"},
    "chatgpt-clone":  {"title": "ChatGPT for everyone",
                       "expected_product": "chatgpt-clone"},
    "hf-chat-ui":     {"title": "HuggingFace Chat UI",
                       "expected_product": "hf-chat-ui"},
    "lobechat":       {"title": "LobeChat workspace",
                       "expected_product": "lobechat"},
    "nextchat":       {"title": "NextChat",
                       "expected_product": "nextchat"},
    "sillytavern":    {"title": "SillyTavern",
                       "expected_product": "sillytavern"},
    "jan":            {"title": "Jan - Open Source AI",
                       "expected_product": "jan"},
    "h2ogpt":         {"title": "h2oGPT",
                       "expected_product": "h2ogpt"},
    "privategpt":     {"title": "PrivateGPT",
                       "expected_product": "privategpt"},
    "quivr":          {"title": "Quivr",
                       "expected_product": "quivr"},
}


def all_ports() -> list[int]:
    """Every TCP port the guinea pig binds. Pass this to naabuCustomPorts."""
    return (
        [d["port"] for d in PORT_LISTENERS]
        + [
            HEADER_SHOWROOM_PORT,
            TITLE_SHOWROOM_PORT,
            ENDPOINT_AI_CLASSIFIER_PORT,
            JS_RECON_AI_SDK_PORT,
        ]
    )


def header_paths() -> list[str]:
    """Every /header/* path the title-showroom serves. Pass this to httpxPaths."""
    return [f"/header/{f}" for f in HEADER_VARIANTS]


def title_paths() -> list[str]:
    """Every /title/* path the title-showroom serves. Pass this to httpxPaths."""
    return [f"/title/{p}" for p in TITLE_VARIANTS]


# ---------------------------------------------------------------------------
# Lap-2 — resource_enum AI classifier showroom (port 9103)
# ---------------------------------------------------------------------------
#
# One entry per ai_interface_type the resource_enum classifier can stamp.
# Each entry carries the path Katana should discover plus the enum value the
# classifier must produce.
#
# Each link on the index page also carries query-string params: one or two
# from AI_PARAM_NAMES (must get `is_ai_prompt_injectable=true`) and one
# control name like `model`/`temperature` (must NOT get tagged). This lets
# the e2e check both the positive AND negative paths of the param classifier.

RESOURCE_ENUM_AI_PATHS: list[dict] = [
    # ── llm-chat ────────────────────────────────────────────────────────
    {"path": "/v1/chat/completions", "enum": "llm-chat",
     "prompt_params": ["messages", "system"], "control_params": ["model", "temperature"]},
    {"path": "/v1/messages", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["model"]},
    {"path": "/api/chat", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["stream"]},
    {"path": "/v1beta/models/gemini-1.5-pro:generateContent", "enum": "llm-chat",
     "prompt_params": ["contents"], "control_params": ["model"]},
    {"path": "/v2/chat", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["model"]},
    {"path": "/v1/sonar", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["model"]},

    # ── llm-completion ──────────────────────────────────────────────────
    {"path": "/v1/completions", "enum": "llm-completion",
     "prompt_params": ["prompt"], "control_params": ["max_tokens"]},
    {"path": "/v1/fim/completions", "enum": "llm-completion",
     "prompt_params": ["prompt", "suffix"], "control_params": ["model"]},
    {"path": "/api/generate", "enum": "llm-completion",
     "prompt_params": ["prompt", "system"], "control_params": ["model"]},

    # ── llm-embedding ───────────────────────────────────────────────────
    {"path": "/v1/embeddings", "enum": "llm-embedding",
     "prompt_params": ["input"], "control_params": ["model"]},
    {"path": "/api/embed", "enum": "llm-embedding",
     "prompt_params": ["input"], "control_params": ["model"]},
    {"path": "/v2/embed", "enum": "llm-embedding",
     "prompt_params": ["inputs"], "control_params": ["model"]},

    # ── llm-tool-call ───────────────────────────────────────────────────
    {"path": "/v1/threads/thread_demo/runs", "enum": "llm-tool-call",
     "prompt_params": ["instructions"], "control_params": ["assistant_id"]},
    {"path": "/v1/responses/resp_demo/input_items", "enum": "llm-tool-call",
     "prompt_params": ["input"], "control_params": ["order"]},

    # ── sse-stream ──────────────────────────────────────────────────────
    {"path": "/generate_stream", "enum": "sse-stream",
     "prompt_params": ["prompt"], "control_params": ["max_new_tokens"]},
    {"path": "/agents/demo/stream", "enum": "sse-stream",
     "prompt_params": ["input"], "control_params": ["config"]},

    # ── mcp ─────────────────────────────────────────────────────────────
    {"path": "/mcp", "enum": "mcp",
     "prompt_params": ["arguments"], "control_params": ["method"]},
    {"path": "/api/mcp", "enum": "mcp",
     "prompt_params": ["arguments"], "control_params": ["method"]},
    {"path": "/sse", "enum": "mcp",
     "prompt_params": [], "control_params": []},
    {"path": "/tools/list", "enum": "mcp",
     "prompt_params": [], "control_params": ["cursor"]},

    # ── llm-graphql (gated on parent-AI — fires here because the showroom
    #    BaseURL is parent-AI-tagged via the http_probe header showroom
    #    when the e2e driver runs both showrooms on the same host) ──────
    {"path": "/graphql", "enum": "llm-graphql",
     "prompt_params": ["query"], "control_params": ["operationName"]},
]


# Unambiguous RAG paths. Each must get is_ai_rag_ingest=true regardless of
# parent-AI status. Ambiguous RAG paths (/search, /upload, /query) are not
# included here — they need parent-AI corroboration and are exercised by the
# http_probe header showroom that tags this same host.
RESOURCE_ENUM_AI_RAG_PATHS: list[dict] = [
    {"path": "/v1/files",
     "prompt_params": [], "control_params": ["purpose"]},
    {"path": "/v1/uploads",
     "prompt_params": [], "control_params": ["filename"]},
    {"path": "/v1/vector_stores",
     "prompt_params": [], "control_params": ["name"]},
    {"path": "/v1/vector_stores/vs_demo/search",
     "prompt_params": ["query"], "control_params": ["max_num_results"]},
    {"path": "/v1/assistants",
     "prompt_params": ["instructions"], "control_params": ["model"]},
    {"path": "/vectors/upsert",
     "prompt_params": [], "control_params": ["namespace"]},
    {"path": "/v1/objects",
     "prompt_params": [], "control_params": ["class"]},
    {"path": "/collections/demo/points/search",
     "prompt_params": ["query"], "control_params": ["limit"]},
]


def resource_enum_paths() -> list[str]:
    """Every classifier-targeted path with its full query string. Pass to
    httpxPaths so httpx probes them when Katana follows the showroom links."""
    out: list[str] = []
    for entry in RESOURCE_ENUM_AI_PATHS + RESOURCE_ENUM_AI_RAG_PATHS:
        params = entry.get("prompt_params", []) + entry.get("control_params", [])
        if params:
            qs = "&".join(f"{p}=demo" for p in params)
            out.append(f"{entry['path']}?{qs}")
        else:
            out.append(entry["path"])
    return out


# ---------------------------------------------------------------------------
# Lap-3 (Phase 6) — js_recon AI SDK fixtures (port 9104)
# ---------------------------------------------------------------------------
#
# Each entry pairs a served JS file with the set of findings match_ai_sdk()
# is expected to emit. The fixtures are EXHAUSTIVE — every detection branch
# the catalogue ships has at least one positive fixture, plus negative
# fixtures (clean jQuery, Stripe-only) to guard against regex over-reach.
#
# Tokens used in fixtures:
#   FAKE_OPENAI_KEY  — looks like a real `sk-proj-…T3BlbkFJ…` key (51 chars
#                      after the prefix marker) so the OpenAI prefix
#                      pattern fires. Filled with 'a'*40 + 'T3BlbkFJ' + 'b'*40.
#                      NOT a real key.
#   FAKE_ANTHROPIC_KEY — `sk-ant-api03-` + 93 padding chars + `AA`. NOT real.
#   FAKE_GROQ_KEY    — `gsk_` + 52 alphanumerics. NOT real.
#   FAKE_REPLICATE_KEY — `r8_` + 37 alphanumerics.
#   FAKE_GEMINI_KEY  — `AIzaSyA` + 32 chars (Gemini = same format as Maps).
#
# The strings are crafted to match the patterns in
# recon/helpers/ai_signal_catalog.py exactly. If a pattern there changes,
# the corresponding fixture below may need updating.

_FAKE_OPENAI_KEY = "sk-proj-" + "a" * 40 + "T3BlbkFJ" + "b" * 40
_FAKE_OPENAI_USER_KEY = "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20
_FAKE_ANTHROPIC_KEY = "sk-ant-api03-" + "x" * 93 + "AA"
_FAKE_GROQ_KEY = "gsk_" + "A1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2"
_FAKE_REPLICATE_KEY = "r8_" + "AbcDef1234567890AbcDef1234567890ABCDe"  # 37 chars
_FAKE_GEMINI_KEY = "AIzaSyA" + "b" * 32
_FAKE_HF_TOKEN = "hf_" + "AbcDefGhIjKlMnOpQrStUvWxYzAbCdEfGhIj"  # 36 alphabetic
_FAKE_LANGFUSE_SECRET = "sk-lf-12345678-1234-1234-1234-1234567890ab"
_FAKE_PINECONE_KEY = "pcsk_" + "abcdef1234567890_abcdef1234567890abcdef1234567890_"
_FAKE_OPENROUTER_KEY = "sk-or-v1-" + "0" * 64
_FAKE_PERPLEXITY_KEY = "pplx-" + "a" * 48
_FAKE_STRIPE_KEY = "sk_live_" + "z" * 99
_FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


JS_RECON_AI_SDK_FIXTURES: list[dict] = [
    # ── Smoking-gun OpenAI ───────────────────────────────────────────────
    {
        "filename": "openai-leaked.js",
        "description": "OpenAI SDK shipped to browser with hardcoded apiKey "
                       "and dangerouslyAllowBrowser opt-in. The single most "
                       "damaging real-world JS leak shape.",
        "content": (
            'import OpenAI from "openai";\n'
            'fetch("https://api.openai.com/v1/chat/completions");\n'
            'const c = new OpenAI({\n'
            f'  apiKey: "{_FAKE_OPENAI_KEY}",\n'
            '  dangerouslyAllowBrowser: true,\n'
            '});\n'
            'export default c;\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "OpenAI"},
            {"category": "ai-sdk-key-literal", "sdk_name": "OpenAI SDK constructor"},
            {"category": "ai-sdk-browser-allowed", "sdk_name": "dangerouslyAllowBrowser"},
            {"category": "ai-provider-url", "sdk_name": "OpenAI API endpoint"},
        ],
    },

    # ── Anthropic via SDK ────────────────────────────────────────────────
    {
        "filename": "anthropic-direct.js",
        "description": "Direct @anthropic-ai/sdk usage with constructor key "
                       "literal — also exercises the loosened browser-flag "
                       "regex (!0 terser variant).",
        "content": (
            'import Anthropic from "@anthropic-ai/sdk";\n'
            'fetch("https://api.anthropic.com/v1/messages");\n'
            f'var a = new Anthropic({{apiKey: "{_FAKE_ANTHROPIC_KEY}", '
            'dangerouslyAllowBrowser: !0}});\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "Anthropic"},
            {"category": "ai-sdk-key-literal", "sdk_name": "Anthropic SDK constructor"},
            {"category": "ai-sdk-browser-allowed", "sdk_name": "dangerouslyAllowBrowser"},
            {"category": "ai-provider-url", "sdk_name": "Anthropic API endpoint"},
        ],
    },

    # ── Gemini disambiguation: WITH context (escalate to critical) ──────
    {
        "filename": "gemini-with-context.js",
        "description": "AIzaSy* key paired with @google/generative-ai import. "
                       "The disambiguation rule must escalate to 'Google "
                       "Gemini API Key' / critical.",
        "content": (
            'import { GoogleGenerativeAI } from "@google/generative-ai";\n'
            f'const genAI = new GoogleGenerativeAI("{_FAKE_GEMINI_KEY}");\n'
            'fetch("https://generativelanguage.googleapis.com/v1beta/models/'
            'gemini-1.5-pro:generateContent");\n'
        ),
        "expected_findings": [
            # Fixture imports @google/generative-ai (the legacy SDK name).
            # If you also need to test the unified @google/genai detection,
            # add a separate fixture importing that package.
            {"category": "ai-sdk-client", "sdk_name": "Google Gemini (legacy SDK)"},
            {"category": "ai-sdk-key-literal", "sdk_name": "Google Gemini SDK constructor"},
            {"category": "ai-provider-url", "sdk_name": "Google Gemini API endpoint"},
        ],
    },

    # ── Gemini disambiguation: WITHOUT context (downgrade to medium) ────
    {
        "filename": "google-maps-key.js",
        "description": "AIzaSy* key WITHOUT any Gemini SDK or endpoint nearby. "
                       "The disambiguation rule must downgrade to 'Google API "
                       "Key (likely Maps/Firebase)' / medium.",
        "content": (
            '// Standard Google Maps embed — not Gemini.\n'
            f'const MAPS_KEY = "{_FAKE_GEMINI_KEY}";\n'
            'const script = document.createElement("script");\n'
            'script.src = `https://maps.googleapis.com/maps/api/js?key=${MAPS_KEY}`;\n'
            'document.head.appendChild(script);\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-key-literal", "sdk_name": "Google API Key (likely Maps/Firebase)"},
        ],
    },

    # ── LangChain ecosystem ─────────────────────────────────────────────
    {
        "filename": "langchain-stack.js",
        "description": "Realistic LangChain.js app with multiple sub-packages. "
                       "Tests that the same SDK can be detected via several "
                       "different sub-path patterns.",
        "content": (
            'import { ChatOpenAI } from "@langchain/openai";\n'
            'import { ChatAnthropic } from "@langchain/anthropic";\n'
            'import { StateGraph } from "@langchain/langgraph";\n'
            'import { Document } from "@langchain/core/documents";\n'
            'import { OpenAIEmbeddings } from "@langchain/openai";\n'
            'const llm = new ChatOpenAI({ apiKey: process.env.OPENAI_API_KEY });\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "LangChain Core"},
            {"category": "ai-sdk-client", "sdk_name": "LangChain OpenAI"},
            {"category": "ai-sdk-client", "sdk_name": "LangChain Anthropic"},
            {"category": "ai-sdk-client", "sdk_name": "LangGraph"},
        ],
    },

    # ── Vercel AI SDK multi-provider ────────────────────────────────────
    {
        "filename": "vercel-ai-multi.js",
        "description": "Vercel AI SDK with multiple provider sub-imports. The "
                       "ai/react sub-import is detected, the bare 'ai' is "
                       "intentionally skipped (too generic).",
        "content": (
            'import { useChat } from "ai/react";\n'
            'import { openai } from "@ai-sdk/openai";\n'
            'import { anthropic } from "@ai-sdk/anthropic";\n'
            'import { google } from "@ai-sdk/google";\n'
            'import { mistral } from "@ai-sdk/mistral";\n'
            'const messages = useChat({ api: "/api/chat" });\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "Vercel AI SDK"},
            {"category": "ai-sdk-client", "sdk_name": "Vercel AI SDK — OpenAI provider"},
            {"category": "ai-sdk-client", "sdk_name": "Vercel AI SDK — provider"},
        ],
    },

    # ── Vector DB clients ───────────────────────────────────────────────
    {
        "filename": "vector-dbs.js",
        "description": "Pinecone + Qdrant + Chroma + Weaviate client imports "
                       "shipped to browser. Pinecone constructor with literal "
                       "key.",
        "content": (
            'import { Pinecone } from "@pinecone-database/pinecone";\n'
            'import { QdrantClient } from "@qdrant/js-client-rest";\n'
            'import { ChromaClient } from "chromadb";\n'
            'import weaviate from "weaviate-client";\n'
            f'const pc = new Pinecone({{apiKey: "{_FAKE_PINECONE_KEY}"}});\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "Pinecone"},
            {"category": "ai-sdk-client", "sdk_name": "Qdrant"},
            {"category": "ai-sdk-client", "sdk_name": "Chroma DB"},
            {"category": "ai-sdk-client", "sdk_name": "Weaviate"},
            {"category": "ai-sdk-key-literal", "sdk_name": "Pinecone SDK constructor"},
        ],
    },

    # ── MCP (Model Context Protocol) ────────────────────────────────────
    {
        "filename": "mcp-client.js",
        "description": "MCP SDK + reference server imports — strongly implies "
                       "a self-hosted AI playground with browser-side creds.",
        "content": (
            'import { Server } from "@modelcontextprotocol/sdk/server";\n'
            'import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";\n'
            'import { filesystem } from "@modelcontextprotocol/server-filesystem";\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "MCP SDK"},
            {"category": "ai-sdk-client", "sdk_name": "MCP Server (reference)"},
        ],
    },

    # ── Env-var leak via Next.js NEXT_PUBLIC_ ──────────────────────────
    {
        "filename": "next-public-leak.js",
        "description": "Next.js NEXT_PUBLIC_OPENAI_API_KEY hydration into the "
                       "client bundle. The NEXT_PUBLIC_ prefix explicitly "
                       "marks the variable as client-visible, so it's "
                       "critical when paired with an AI provider name.",
        "content": (
            'const config = {\n'
            f'  NEXT_PUBLIC_OPENAI_API_KEY: "{_FAKE_OPENAI_KEY}",\n'
            '  NEXT_PUBLIC_API_BASE: "https://api.openai.com/v1",\n'
            '};\n'
            'export default config;\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-key-literal", "sdk_name": "Framework-public AI key leak"},
            {"category": "ai-provider-url", "sdk_name": "OpenAI API endpoint"},
        ],
    },

    # ── Bearer-header literal (bypasses SDK entirely) ──────────────────
    {
        "filename": "bearer-fetch.js",
        "description": "Hand-written fetch() with hardcoded Bearer header — "
                       "bypasses the SDK so prefix-only detection wouldn't "
                       "fire. The Bearer-header constructor pattern catches it.",
        "content": (
            '// No SDK import — raw fetch with Bearer.\n'
            'const data = await fetch("https://api.groq.com/openai/v1/chat/completions", {\n'
            '  method: "POST",\n'
            '  headers: {\n'
            f'    "Authorization": "Bearer {_FAKE_GROQ_KEY}",\n'
            '    "Content-Type": "application/json",\n'
            '  },\n'
            '  body: JSON.stringify({ messages: [] }),\n'
            '});\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-key-literal", "sdk_name": "Bearer-header AI key literal"},
            {"category": "ai-provider-url", "sdk_name": "Groq API"},
        ],
    },

    # ── Anthropic x-api-key header literal ─────────────────────────────
    {
        "filename": "anthropic-header.js",
        "description": "Direct Anthropic call via fetch + x-api-key header "
                       "(Anthropic uses x-api-key, not Bearer).",
        "content": (
            'await fetch("https://api.anthropic.com/v1/messages", {\n'
            '  headers: {\n'
            f'    "x-api-key": "{_FAKE_ANTHROPIC_KEY}",\n'
            '    "anthropic-version": "2023-06-01",\n'
            '  },\n'
            '});\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-key-literal", "sdk_name": "Anthropic x-api-key header literal"},
            {"category": "ai-provider-url", "sdk_name": "Anthropic API endpoint"},
        ],
    },

    # ── Open WebUI frontend markers ─────────────────────────────────────
    {
        "filename": "openwebui-frontend.js",
        "description": "Open WebUI SvelteKit build constants — the type of "
                       "marker the http_probe Wappalyzer pass cannot see "
                       "because it lives in an async-loaded JS chunk.",
        "content": (
            'window.WEBUI_NAME = "Open WebUI";\n'
            'window.WEBUI_VERSION = "0.3.32";\n'
            'window.WEBUI_API_BASE_URL = "/api/v1";\n'
            'fetch("/api/v1/chats");\n'
            'fetch("/api/v1/models");\n'
        ),
        "expected_findings": [
            {"category": "ai-frontend-detected", "sdk_name": "Open WebUI"},
        ],
    },

    # ── Gradio frontend markers ─────────────────────────────────────────
    {
        "filename": "gradio-frontend.js",
        "description": "Gradio app — customElements.define('gradio-app', ...) "
                       "+ window.gradio_config global. Both markers in one "
                       "file; the frontend dedup logic must emit exactly one "
                       "Gradio finding.",
        "content": (
            'customElements.define("gradio-app", class extends HTMLElement {});\n'
            'window.gradio_config = { theme: "default" };\n'
            'window.__gradio_mode__ = "stable";\n'
            'fetch("/gradio_api/info");\n'
            'fetch("/queue/join");\n'
        ),
        "expected_findings": [
            {"category": "ai-frontend-detected", "sdk_name": "Gradio"},
        ],
    },

    # ── Flowise frontend markers ────────────────────────────────────────
    {
        "filename": "flowise-frontend.js",
        "description": "Flowise React app — chatflowid constant + /api/v1/"
                       "prediction route.",
        "content": (
            'const chatflowid = "abc-123-flowise";\n'
            'const chatFlowDomain = "https://flowise.example.com";\n'
            'await fetch("/api/v1/prediction/" + chatflowid);\n'
        ),
        "expected_findings": [
            {"category": "ai-frontend-detected", "sdk_name": "Flowise"},
        ],
    },

    # ── SillyTavern frontend markers ────────────────────────────────────
    {
        "filename": "sillytavern-frontend.js",
        "description": "SillyTavern — high abuse risk for hosted instances.",
        "content": (
            'const SillyTavernSettings = { mode: "chat" };\n'
            'function loadSillyTavern() { return SillyTavernSettings; }\n'
        ),
        "expected_findings": [
            {"category": "ai-frontend-detected", "sdk_name": "SillyTavern"},
        ],
    },

    # ── JSON-stringified browser flag (Next.js __NEXT_DATA__ shape) ────
    {
        "filename": "next-data-blob.js",
        "description": "JSON-dehydrated React Server Components blob with the "
                       "browser-mode flag in JSON-string form. Tests the "
                       "loosened browser-flag regex that accepts quoted keys.",
        "content": (
            'window.__NEXT_DATA__ = {\n'
            '  "props": {\n'
            '    "pageProps": {\n'
            '      "openaiConfig": {"dangerouslyAllowBrowser":true,"apiKey":"redacted"}\n'
            '    }\n'
            '  }\n'
            '};\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-browser-allowed", "sdk_name": "dangerouslyAllowBrowser"},
        ],
    },

    # ── Real-shaped minified bundle ─────────────────────────────────────
    {
        "filename": "minified-vendor.js",
        "description": "Real-world minified shape: no whitespace, !0 truthy, "
                       "comma-fused statements. Should still match every "
                       "channel.",
        "content": (
            'var n;import OpenAI from"openai";'
            'fetch("https://api.openai.com/v1/embeddings");'
            f'var c=new OpenAI({{apiKey:"{_FAKE_OPENAI_KEY}",dangerouslyAllowBrowser:!0}});'
            'export{c as default};'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "OpenAI"},
            {"category": "ai-sdk-key-literal", "sdk_name": "OpenAI SDK constructor"},
            {"category": "ai-sdk-browser-allowed", "sdk_name": "dangerouslyAllowBrowser"},
            {"category": "ai-provider-url", "sdk_name": "OpenAI API endpoint"},
        ],
    },

    # ── HuggingFace constructor ─────────────────────────────────────────
    {
        "filename": "huggingface-inference.js",
        "description": "HfInference positional constructor — captures the "
                       "hf_ token literal.",
        "content": (
            'import { HfInference } from "@huggingface/inference";\n'
            f'const hf = new HfInference("{_FAKE_HF_TOKEN}");\n'
            'fetch("https://api-inference.huggingface.co/models/gpt2");\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "HuggingFace Inference"},
            {"category": "ai-sdk-key-literal", "sdk_name": "HuggingFace SDK constructor"},
            {"category": "ai-provider-url", "sdk_name": "HuggingFace Inference API"},
        ],
    },

    # ── Langfuse observability client ──────────────────────────────────
    {
        "filename": "langfuse-tracing.js",
        "description": "Langfuse client with secret-key constructor — high "
                       "severity (gives ingest access to the project's "
                       "telemetry).",
        "content": (
            'import { Langfuse } from "langfuse";\n'
            f'const lf = new Langfuse({{ secretKey: "{_FAKE_LANGFUSE_SECRET}", '
            'publicKey: "pk-lf-12345678-1234-1234-1234-1234567890ab" }});\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-client", "sdk_name": "Langfuse"},
            {"category": "ai-sdk-key-literal", "sdk_name": "Langfuse SDK constructor (secretKey)"},
        ],
    },

    # ── OpenRouter multi-provider router key ───────────────────────────
    {
        "filename": "openrouter-bearer.js",
        "description": "OpenRouter Bearer — leaking this key drains credits "
                       "across every model the user has configured.",
        "content": (
            'await fetch("https://openrouter.ai/api/v1/chat/completions", {\n'
            f'  headers: {{ "Authorization": "Bearer {_FAKE_OPENROUTER_KEY}" }},\n'
            '});\n'
        ),
        "expected_findings": [
            {"category": "ai-sdk-key-literal", "sdk_name": "Bearer-header AI key literal"},
            {"category": "ai-provider-url", "sdk_name": "OpenRouter API"},
        ],
    },

    # ── Dedup test: a Secret AND an AI key on the same file ────────────
    {
        "filename": "secret-dup-test.js",
        "description": "The existing JS_SECRET_PATTERNS scan catches this as "
                       "a 'OpenAI API Key' Secret; our AI SDK scan ALSO "
                       "catches the same byte range. The mixin must enrich "
                       "the Secret with ai_provider rather than emit a "
                       "parallel taxonomy.",
        "content": (
            f'const apiKey = "{_FAKE_OPENAI_USER_KEY}";\n'
            'const ENDPOINT = "https://api.openai.com/v1/chat/completions";\n'
            'fetch(ENDPOINT, { headers: { Authorization: "Bearer " + apiKey } });\n'
        ),
        "expected_findings": [
            # Loose prefix matches the bare key
            {"category": "ai-sdk-key-literal"},  # exact sdk_name varies (loose fallback)
            {"category": "ai-provider-url", "sdk_name": "OpenAI API endpoint"},
        ],
    },

    # ── NEGATIVE: clean jQuery bundle (must produce zero findings) ─────
    {
        "filename": "negative-jquery.js",
        "description": "Clean jQuery bundle stub. Regression guard against "
                       "catalogue regex over-reach.",
        "content": (
            '/*! jQuery v3.7.0 | (c) OpenJS Foundation */\n'
            '(function(global, factory) {\n'
            '  var jQuery = function(selector) { return new jQuery.fn.init(selector); };\n'
            '  jQuery.fn = jQuery.prototype = { jquery: "3.7.0" };\n'
            '})(window);\n'
        ),
        "expected_findings": [],
    },

    # ── NEGATIVE: Stripe-only (must NOT trigger AI patterns) ───────────
    {
        "filename": "negative-stripe.js",
        "description": "Stripe SDK with a real Stripe key shape. The Stripe "
                       "sk_live_ prefix must NOT trip any AI key pattern.",
        "content": (
            'import { loadStripe } from "@stripe/stripe-js";\n'
            f'const stripe = await loadStripe("{_FAKE_STRIPE_KEY}");\n'
            f'const awsKey = "{_FAKE_AWS_KEY}";\n'
        ),
        "expected_findings": [],
    },
]


def js_recon_ai_sdk_paths() -> list[str]:
    """Every JS fixture path the showroom serves. Pass to httpxPaths so the
    fixtures get probed + downloaded by the recon pipeline."""
    return [f"/static/{f['filename']}" for f in JS_RECON_AI_SDK_FIXTURES]
