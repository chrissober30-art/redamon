"""Unit tests for the central-ai_surface_recon additions to ai_signal_catalog.

Covers the new constants (AI_CHAT_PROBE_PATHS, AI_CHAT_RESPONSE_SHAPES,
AI_MCP_PROBE_PATHS, AI_OPENAPI_DISCOVERY_PATHS, AI_VECTOR_DB_READS,
AI_MODEL_FAMILY_TOKENS) and helpers (classify_ai_chat_response,
guess_model_family, pick_tool_dialect, resolve_ai_tool_arg_path).

Run inside the recon image:
    docker run --rm --entrypoint python3 -v "$PWD/recon:/app/recon:ro" -w /app \
        redamon-recon:latest recon/tests/test_ai_surface_catalog.py
"""
from __future__ import annotations
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import ai_signal_catalog as cat


# --- constants ---------------------------------------------------------------
def test_chat_probe_paths_present_and_canonical():
    assert isinstance(cat.AI_CHAT_PROBE_PATHS, list) and cat.AI_CHAT_PROBE_PATHS
    assert "/v1/chat/completions" in cat.AI_CHAT_PROBE_PATHS
    assert "/v1/messages" in cat.AI_CHAT_PROBE_PATHS
    assert all(p.startswith("/") for p in cat.AI_CHAT_PROBE_PATHS)


def test_mcp_probe_paths():
    for p in ("/mcp", "/sse", "/messages"):
        assert p in cat.AI_MCP_PROBE_PATHS


def test_openapi_discovery_paths():
    for p in ("/openapi.json", "/v1/models", "/.well-known/ai-plugin.json", "/api/tags"):
        assert p in cat.AI_OPENAPI_DISCOVERY_PATHS


def test_vector_db_reads_shape():
    assert set(cat.AI_VECTOR_DB_READS) >= {"chroma", "qdrant", "weaviate", "milvus"}
    for name, reads in cat.AI_VECTOR_DB_READS.items():
        # tech -> ordered list of (path, expected-substring) read attempts
        assert isinstance(reads, list) and reads
        for val in reads:
            assert isinstance(val, tuple) and len(val) == 2
            assert val[0].startswith("/")
            assert isinstance(val[1], str)


def test_response_shapes_well_formed():
    for fam, keys, iface in cat.AI_CHAT_RESPONSE_SHAPES:
        assert isinstance(fam, str) and fam
        assert isinstance(keys, list) and keys
        assert iface in {"llm-chat", "llm-completion", "sse-stream"}


# --- classify_ai_chat_response ----------------------------------------------
def test_classify_openai_chat():
    body = {"id": "x", "choices": [{"message": {"content": "hi"}}],
            "usage": {"prompt_tokens": 1}}
    assert cat.classify_ai_chat_response(body) == "llm-chat"


def test_classify_anthropic():
    body = {"content": [{"text": "hi"}], "stop_reason": "end_turn", "model": "claude-3"}
    assert cat.classify_ai_chat_response(body) == "llm-chat"


def test_classify_ollama_completion():
    body = {"response": "hello", "eval_count": 5}
    assert cat.classify_ai_chat_response(body) == "llm-completion"


def test_classify_gemini():
    body = {"candidates": [{"content": {"parts": [{"text": "hi"}]}}]}
    assert cat.classify_ai_chat_response(body) == "llm-chat"


def test_classify_none_for_unrelated_and_nondict():
    assert cat.classify_ai_chat_response({"foo": "bar"}) is None
    assert cat.classify_ai_chat_response(None) is None
    assert cat.classify_ai_chat_response([1, 2, 3]) is None


# --- guess_model_family ------------------------------------------------------
def test_guess_family_basic():
    assert cat.guess_model_family(["gpt-4o", "gpt-4o-mini"]) == "gpt"
    assert cat.guess_model_family(["claude-3-5-sonnet"]) == "claude"
    assert cat.guess_model_family(["mixtral-8x7b"]) == "mixtral"


def test_guess_family_longest_token_wins():
    # 'command-r' must beat 'command'; 'codellama' must beat 'llama'
    assert cat.guess_model_family(["command-r-plus"]) == "command-r"
    assert cat.guess_model_family(["codellama:13b"]) == "codellama"


def test_guess_family_empty_and_nomatch():
    assert cat.guess_model_family([]) is None
    assert cat.guess_model_family(["totally-unknown-xyz"]) is None


# --- pick_tool_dialect + resolve_ai_tool_arg_path ---------------------------
def test_pick_dialect():
    assert cat.pick_tool_dialect({"inputSchema": {"properties": {}}}) == "mcp-tools-list"
    assert cat.pick_tool_dialect({"input_schema": {"properties": {}}}) == "anthropic-tools"
    assert cat.pick_tool_dialect({"function": {"parameters": {}}}) == "openai-functions"
    assert cat.pick_tool_dialect({"parameters": {"properties": {}}}) == "openai-functions"
    assert cat.pick_tool_dialect({"nope": 1}) is None


def test_resolve_arg_path_mcp():
    spec = {"inputSchema": {"properties": {"query": {"type": "string"}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "mcp-tools-list", "query") == \
        "/inputSchema/properties/query"
    assert cat.resolve_ai_tool_arg_path(spec, "mcp-tools-list", "missing") is None


def test_resolve_arg_path_anthropic():
    spec = {"input_schema": {"properties": {"location": {}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "anthropic-tools", "location") == \
        "/input_schema/properties/location"


if __name__ == "__main__":
    failures = []
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"  PASS  {name}"); passed += 1
            except AssertionError as e:
                print(f"  FAIL  {name}: {e}"); failures.append((name, str(e)))
            except Exception as e:
                print(f"  ERROR {name}: {type(e).__name__}: {e}")
                failures.append((name, f"{type(e).__name__}: {e}"))
    print(f"\n{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)
