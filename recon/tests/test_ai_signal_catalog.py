"""Tests for recon/helpers/ai_signal_catalog.py.

Covers the data shape of every constant the AI surface recon distributed hooks
will import (`AI_PORTS`, `AI_HEADER_PATTERNS`, `AI_TITLE_PATTERNS`,
`AI_TXT_PATTERNS`, `AI_NS_HINT_PATTERNS`, `AI_NMAP_VERSION_PATTERNS`,
`AI_FAVICON_HASHES`), the matcher functions (`match_ai_txt_hint`,
`match_ai_ns_hint`, `lookup_ai_port`, `match_ai_header`, `match_ai_title`,
`match_ai_nmap_version`), and the forward-declared stubs that later laps
fill in.

Runs under pytest or as a plain Python script:

    docker exec redamon-recon-orchestrator python3 -m pytest \
        /app/recon/tests/test_ai_signal_catalog.py -v

    # OR (no pytest required)
    docker run --rm --entrypoint python3 \
        -v "$PWD/recon:/app/recon:ro" -w /app redamon-recon:latest \
        recon/tests/test_ai_signal_catalog.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import ai_signal_catalog as cat


# ---------------------------------------------------------------------------
# Smoke — module imports and exposes the advertised surface
# ---------------------------------------------------------------------------

def test_smoke_module_imports():
    """The module loads cleanly and every advertised symbol is present."""
    expected = {
        "AI_TXT_PATTERNS", "AI_NS_HINT_PATTERNS",
        "AI_PORTS", "AI_NMAP_VERSION_PATTERNS",
        "AI_HEADER_PATTERNS", "AI_TITLE_PATTERNS", "AI_FAVICON_HASHES",
        # forward-declared stubs filled by later laps
        "AI_SDK_IMPORT_REGEX", "AI_PATH_PATTERNS", "AI_RAG_PATH_PATTERNS",
        "AI_PARAM_NAMES", "AI_TAKEOVER_PROVIDERS", "AI_VHOST_WORDLIST",
        "AI_CVE_LIBRARIES", "AI_ATLAS_MAPPING",
        "AI_SHODAN_QUERIES", "AI_CENSYS_QUERIES",
        "AI_FOFA_QUERIES", "AI_ZOOMEYE_QUERIES",
        # matcher helpers
        "match_ai_txt_hint", "match_ai_ns_hint", "lookup_ai_port",
        "match_ai_header", "match_ai_title", "match_ai_nmap_version",
    }
    missing = expected - set(dir(cat))
    assert not missing, f"ai_signal_catalog missing expected symbols: {missing}"


# ---------------------------------------------------------------------------
# Unit — AI_PORTS shape
# ---------------------------------------------------------------------------

def test_ai_ports_keys_are_int():
    for port in cat.AI_PORTS:
        assert isinstance(port, int), f"port key {port!r} is not int"
        assert 1 <= port <= 65535, f"port {port} out of TCP/UDP range"


def test_ai_ports_values_have_name_and_category():
    for port, descriptor in cat.AI_PORTS.items():
        assert "name" in descriptor, f"port {port} missing 'name'"
        assert "category" in descriptor, f"port {port} missing 'category'"
        assert isinstance(descriptor["name"], str) and descriptor["name"], f"port {port} name empty"
        assert isinstance(descriptor["category"], str) and descriptor["category"], f"port {port} category empty"


def test_ai_ports_categories_use_ai_prefix():
    """Every AI port descriptor's category must start with 'ai-' so the
    text-to-cypher path can identify AI annotations structurally."""
    valid = {"ai-runtime", "ai-vector-db", "ai-proxy", "ai-frontend", "ai-framework", "ai-sdk-client", "ai-mlops"}
    for port, descriptor in cat.AI_PORTS.items():
        assert descriptor["category"] in valid, (
            f"port {port} has unexpected category {descriptor['category']!r}, "
            f"expected one of {valid}"
        )


def test_ai_ports_disambiguate_flag_is_bool():
    for port, descriptor in cat.AI_PORTS.items():
        if "disambiguate" in descriptor:
            assert isinstance(descriptor["disambiguate"], bool), (
                f"port {port} disambiguate is {type(descriptor['disambiguate'])}, expected bool"
            )


def test_ai_ports_well_known_entries_present():
    """Lap-1 lab fixture depends on these specific entries being present."""
    assert 11434 in cat.AI_PORTS, "Ollama port 11434 missing — lab fixture won't detect it"
    assert cat.AI_PORTS[11434]["name"] == "ollama"
    assert cat.AI_PORTS[11434]["category"] == "ai-runtime"

    assert 6333 in cat.AI_PORTS, "Qdrant port 6333 missing"
    assert cat.AI_PORTS[6333]["category"] == "ai-vector-db"

    assert 8080 in cat.AI_PORTS, "Open WebUI port 8080 missing"
    assert cat.AI_PORTS[8080]["category"] == "ai-frontend"
    assert cat.AI_PORTS[8080].get("disambiguate") is True, (
        "Port 8080 is shared with many non-AI services — must require disambiguation"
    )

    assert 8000 in cat.AI_PORTS, "8000 (vllm/chroma/langserve) missing"
    assert cat.AI_PORTS[8000].get("disambiguate") is True, (
        "Port 8000 is shared with many non-AI services — must require disambiguation"
    )


# ---------------------------------------------------------------------------
# Unit — pattern lists shape
# ---------------------------------------------------------------------------

def _is_compiled_regex(obj) -> bool:
    return isinstance(obj, re.Pattern)


def test_ai_txt_patterns_shape():
    assert cat.AI_TXT_PATTERNS, "AI_TXT_PATTERNS empty — lap 1 needs DNS hints"
    for entry in cat.AI_TXT_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 2, f"bad TXT entry: {entry!r}"
        pattern, hint = entry
        assert _is_compiled_regex(pattern), f"TXT pattern not compiled: {pattern!r}"
        assert isinstance(hint, str) and hint, f"TXT hint empty: {hint!r}"


def test_ai_ns_hint_patterns_shape():
    assert cat.AI_NS_HINT_PATTERNS, "AI_NS_HINT_PATTERNS empty — lap 1 needs NS hints"
    for entry in cat.AI_NS_HINT_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 2
        pattern, hint = entry
        assert _is_compiled_regex(pattern)
        assert isinstance(hint, str) and hint


def test_ai_nmap_version_patterns_shape():
    assert cat.AI_NMAP_VERSION_PATTERNS, "AI_NMAP_VERSION_PATTERNS empty"
    for entry in cat.AI_NMAP_VERSION_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 2
        pattern, runtime = entry
        assert _is_compiled_regex(pattern)
        assert isinstance(runtime, str) and runtime


def test_ai_header_patterns_shape():
    assert cat.AI_HEADER_PATTERNS, "AI_HEADER_PATTERNS empty"
    valid_categories = {"ai-framework", "ai-runtime", "ai-proxy", "ai-frontend", "ai-sdk-client"}
    for entry in cat.AI_HEADER_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 3, f"bad header entry: {entry!r}"
        pattern, framework, category = entry
        assert _is_compiled_regex(pattern)
        assert isinstance(framework, str) and framework
        assert category in valid_categories, f"header category {category!r} not AI-prefixed"


def test_ai_title_patterns_shape():
    assert cat.AI_TITLE_PATTERNS, "AI_TITLE_PATTERNS empty"
    for entry in cat.AI_TITLE_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 2
        pattern, product = entry
        assert _is_compiled_regex(pattern)
        assert isinstance(product, str) and product


def test_ai_favicon_hashes_shape():
    """Currently a stub; ensure the type contract is right even when empty."""
    assert isinstance(cat.AI_FAVICON_HASHES, dict)
    for h, product in cat.AI_FAVICON_HASHES.items():
        assert isinstance(h, int)
        assert isinstance(product, str) and product


# ---------------------------------------------------------------------------
# Unit — forward-declared stubs (later laps fill these)
# ---------------------------------------------------------------------------

def test_forward_stubs_have_correct_types_even_when_empty():
    """Later-lap stubs must be present with the right container type so
    distributed hooks landing in those laps can import without crashing.

    Note: AI_PATH_PATTERNS is now a list of (regex, ai_interface_type) tuples
    (was a forward-declared empty dict; shipped with the resource_enum lap).
    AI_RAG_PATH_PATTERNS likewise carries (regex, requires_parent_ai) tuples."""
    assert isinstance(cat.AI_SDK_IMPORT_REGEX, list)
    assert isinstance(cat.AI_PATH_PATTERNS, list)
    assert isinstance(cat.AI_RAG_PATH_PATTERNS, list)
    assert isinstance(cat.AI_PARAM_NAMES, set)
    assert isinstance(cat.AI_TOOL_ARG_PATH_DIALECTS, list)
    assert isinstance(cat.AI_TAKEOVER_PROVIDERS, dict)
    assert isinstance(cat.AI_VHOST_WORDLIST, list)
    assert isinstance(cat.AI_CVE_LIBRARIES, list)
    assert isinstance(cat.AI_ATLAS_MAPPING, dict)
    assert isinstance(cat.AI_SHODAN_QUERIES, list)
    assert isinstance(cat.AI_CENSYS_QUERIES, list)
    assert isinstance(cat.AI_FOFA_QUERIES, list)
    assert isinstance(cat.AI_ZOOMEYE_QUERIES, list)


# ---------------------------------------------------------------------------
# Unit — match_ai_txt_hint
# ---------------------------------------------------------------------------

def test_match_ai_txt_hint_returns_provider_on_known_vendor():
    cases = [
        ("v=spf1 include:_spf.anthropic.com ~all", "anthropic"),
        ("v=spf1 include:openai.com -all", "openai"),
        ("v=spf1 include:replicate.com ~all", "replicate"),
        ("huggingface.co domain verification", "huggingface"),
        ("langchain.com api key", "langchain"),
        ("v=DKIM1; k=rsa; p=...; together.ai", "together"),
        ("groq.com=verified", "groq"),
    ]
    for record, expected in cases:
        actual = cat.match_ai_txt_hint(record)
        assert actual == expected, f"{record!r} → got {actual!r}, expected {expected!r}"


def test_match_ai_txt_hint_returns_none_on_unrelated_record():
    unrelated = [
        "v=spf1 include:_spf.google.com ~all",
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        "MS=ms12345678",
        "stripe-verification=abc",
        "",
        "   ",
    ]
    for record in unrelated:
        actual = cat.match_ai_txt_hint(record)
        assert actual is None, f"{record!r} should not match, got {actual!r}"


def test_match_ai_txt_hint_handles_none_and_empty():
    assert cat.match_ai_txt_hint("") is None
    assert cat.match_ai_txt_hint(None) is None  # type: ignore[arg-type]


def test_match_ai_txt_hint_is_case_insensitive():
    assert cat.match_ai_txt_hint("INCLUDE:ANTHROPIC.COM") == "anthropic"
    assert cat.match_ai_txt_hint("OpenAI.COM") == "openai"


# ---------------------------------------------------------------------------
# Unit — match_ai_ns_hint
# ---------------------------------------------------------------------------

def test_match_ai_ns_hint_returns_provider_on_known_host():
    cases = [
        ("ns1.vercel-dns.com", "vercel"),
        ("dns3.nsone.net", "netlify"),
        ("replit.com", "replit"),
        ("modal-dns.example", "modal"),
    ]
    for ns, expected in cases:
        actual = cat.match_ai_ns_hint(ns)
        assert actual == expected, f"{ns!r} → got {actual!r}, expected {expected!r}"


def test_match_ai_ns_hint_returns_none_on_unrelated():
    for ns in ["ns1.example.com", "dns1.googledomains.com", "", "  "]:
        assert cat.match_ai_ns_hint(ns) is None


# ---------------------------------------------------------------------------
# Unit — lookup_ai_port
# ---------------------------------------------------------------------------

def test_lookup_ai_port_returns_descriptor_for_known_port():
    descriptor = cat.lookup_ai_port(11434)
    assert descriptor is not None
    assert descriptor["name"] == "ollama"
    assert descriptor["category"] == "ai-runtime"


def test_lookup_ai_port_returns_none_for_unknown_port():
    assert cat.lookup_ai_port(22) is None
    assert cat.lookup_ai_port(443) is None
    assert cat.lookup_ai_port(99999) is None


def test_lookup_ai_port_disambiguate_flag_present_for_shared_ports():
    """Shared ports (8000, 8080) MUST be flagged so port_scan does not
    promote them to a Technology node without corroborating evidence."""
    for shared_port in (8000, 8080):
        descriptor = cat.lookup_ai_port(shared_port)
        assert descriptor is not None
        assert descriptor.get("disambiguate") is True, (
            f"shared port {shared_port} must be flagged disambiguate=True"
        )


# ---------------------------------------------------------------------------
# Unit — match_ai_header
# ---------------------------------------------------------------------------

def test_match_ai_header_returns_runtime_signals():
    cases = [
        ("x-vllm-cache-hit", "vllm", "ai-runtime"),
        ("x-tgi-request-id", "tgi", "ai-runtime"),
        ("x-bentoml-version", "bentoml", "ai-runtime"),
        ("x-modal-task-id", "modal", "ai-runtime"),
    ]
    for header, framework, category in cases:
        result = cat.match_ai_header(header)
        assert result == (framework, category), (
            f"{header!r} → got {result!r}, expected {(framework, category)!r}"
        )


def test_match_ai_header_returns_framework_signals():
    assert cat.match_ai_header("x-langchain-run-id") == ("langchain", "ai-framework")
    assert cat.match_ai_header("langfuse-trace-id") == ("langfuse", "ai-framework")
    assert cat.match_ai_header("x-mcp-server-name") == ("mcp", "ai-framework")


def test_match_ai_header_returns_proxy_signals():
    assert cat.match_ai_header("x-litellm-model-id") == ("litellm", "ai-proxy")
    assert cat.match_ai_header("x-helicone-cache") == ("helicone", "ai-proxy")
    assert cat.match_ai_header("cf-aig-cache-status") == ("cloudflare-ai-gateway", "ai-proxy")


def test_match_ai_header_returns_sdk_client_signals():
    assert cat.match_ai_header("openai-organization") == ("openai", "ai-sdk-client")
    assert cat.match_ai_header("anthropic-version") == ("anthropic", "ai-sdk-client")
    assert cat.match_ai_header("anthropic-ratelimit-requests-remaining") == ("anthropic", "ai-sdk-client")


def test_match_ai_header_is_case_insensitive():
    assert cat.match_ai_header("X-VLLM-CACHE-HIT") == ("vllm", "ai-runtime")
    assert cat.match_ai_header("X-Langchain-Run-Id") == ("langchain", "ai-framework")


def test_match_ai_header_returns_none_on_unrelated_headers():
    for header in [
        "content-type", "server", "x-frame-options", "cache-control",
        "x-amzn-request-id", "cf-ray", "x-powered-by",
        "", None,
    ]:
        result = cat.match_ai_header(header)  # type: ignore[arg-type]
        assert result is None, f"{header!r} should not match, got {result!r}"


# ---------------------------------------------------------------------------
# Unit — match_ai_title
# ---------------------------------------------------------------------------

def test_match_ai_title_returns_product_on_known_title():
    cases = [
        ("Open WebUI", "open-webui"),
        ("LibreChat", "librechat"),
        ("AnythingLLM Workspace", "anythingllm"),
        ("Flowise — Build LLM Apps", "flowise"),
        ("Dify - Dashboard", "dify"),
        ("ComfyUI", "comfyui"),
        ("Gradio Demo", "gradio"),
        ("Streamlit App", "streamlit"),
    ]
    for title, expected in cases:
        actual = cat.match_ai_title(title)
        assert actual == expected, f"{title!r} → got {actual!r}, expected {expected!r}"


def test_match_ai_title_is_case_insensitive():
    assert cat.match_ai_title("OPEN WEBUI") == "open-webui"
    assert cat.match_ai_title("librechat") == "librechat"


def test_match_ai_title_returns_none_on_unrelated():
    for title in ["Apache HTTP Server Test Page", "nginx", "Welcome to my blog", "", None]:
        actual = cat.match_ai_title(title)  # type: ignore[arg-type]
        assert actual is None, f"{title!r} should not match, got {actual!r}"


# ---------------------------------------------------------------------------
# Unit — match_ai_nmap_version
# ---------------------------------------------------------------------------

def test_match_ai_nmap_version_returns_runtime_on_match():
    cases = [
        ("Ollama/0.1.32", "ollama"),
        ("vllm/0.4.1", "vllm"),
        ("LiteLLM/1.30", "litellm"),
        ("TGI/2.0", "tgi"),
        ("text-generation-inference/2.0.4", "tgi"),
        ("triton-server/24.05", "triton"),
        ("llama.cpp/b3001", "llama.cpp"),
    ]
    for product, expected in cases:
        actual = cat.match_ai_nmap_version(product)
        assert actual == expected, f"{product!r} → got {actual!r}, expected {expected!r}"


def test_match_ai_nmap_version_returns_none_on_unrelated():
    for product in ["Apache/2.4.41", "nginx/1.18.0", "OpenSSH/8.9p1", "", None]:
        actual = cat.match_ai_nmap_version(product)  # type: ignore[arg-type]
        assert actual is None


# ---------------------------------------------------------------------------
# Regression — pattern uniqueness and no shadowing
# ---------------------------------------------------------------------------

def test_no_duplicate_ai_port_names():
    """Two ports may share a name only when both refer to the same product
    (e.g. Qdrant HTTP vs gRPC). Bare duplicates indicate a typo."""
    by_name: dict[str, list[int]] = {}
    for port, descriptor in cat.AI_PORTS.items():
        by_name.setdefault(descriptor["name"], []).append(port)
    # Names referencing multiple ports must explicitly share a prefix
    for name, ports in by_name.items():
        if len(ports) > 1:
            # Allow only known split products (qdrant-http vs qdrant-grpc, milvus, triton)
            assert any(tag in name for tag in ("qdrant", "milvus", "triton")), (
                f"unexpected duplicate name {name!r} for ports {ports}"
            )


def test_no_duplicate_header_patterns_for_same_framework():
    """Two patterns may map to the same framework, but ordering matters —
    first-wins. Make sure no entry shadows itself with the same pattern."""
    seen_patterns: set[str] = set()
    for pattern, framework, category in cat.AI_HEADER_PATTERNS:
        key = pattern.pattern
        assert key not in seen_patterns, f"duplicate header pattern {key!r}"
        seen_patterns.add(key)


def test_title_patterns_dont_overmatch_generic_words():
    """Sanity: a literal product name like 'Jan' must not match generic
    English text. The catalogue gates 'Jan' on '- Open Source' suffix."""
    assert cat.match_ai_title("January meeting notes") is None
    # 'Streamlit' is unique enough to allow as a bare match
    assert cat.match_ai_title("My Streamlit dashboard") == "streamlit"


# ---------------------------------------------------------------------------
# Standalone runner (no pytest dependency)
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
        for name, err in failures:
            print(f"  - {name}: {err}")
        sys.exit(1)
    sys.exit(0)
