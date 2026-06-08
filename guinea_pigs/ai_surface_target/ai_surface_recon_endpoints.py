"""HTTP target surface for validating the central ai_surface_recon module.

A dependency-free (stdlib http.server) target that responds to every HTTP probe
the module sends, with the exact response *shapes* its parsers expect:

  * chat-shape probes  -> OpenAI / Anthropic / Ollama / Gemini / LangServe / SSE
  * OpenAPI/manifest    -> /openapi.json, /.well-known/ai-plugin.json, /swagger.json
  * model listings      -> /v1/models (OpenAI), /api/tags (Ollama)
  * Julius fingerprints -> GET / "Ollama is running" + /api/tags + /v1/models
  * vector-DB read      -> /collections (Qdrant shape)
  * MCP detect branches -> /mcp-auth (401+WWW-Authenticate), /mcp-badversion (version mismatch)

Run standalone:  python3 ai_surface_recon_endpoints.py 9110
Or import `serve_in_thread(port)` from the validation harness.

The real MCP Streamable-HTTP server (for handshake + tools/list enumeration via
the official SDK) lives in mcp_poison_server.py — it must be a spec-compliant
server, which this stdlib handler cannot be.
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- canonical response bodies (shapes the module's classifiers key on) ----
_OPENAI_CHAT = {"id": "x", "object": "chat.completion",
                "choices": [{"message": {"role": "assistant", "content": "pong"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
_ANTHROPIC = {"id": "msg_x", "type": "message", "model": "claude-3-5-sonnet",
              "content": [{"type": "text", "text": "pong"}], "stop_reason": "end_turn"}
_OLLAMA_GEN = {"model": "llama3", "response": "pong", "done": True, "eval_count": 1}
_OLLAMA_CHAT = {"model": "llama3", "message": {"role": "assistant", "content": "pong"},
                "done": True}
_GEMINI = {"candidates": [{"content": {"parts": [{"text": "pong"}]}}]}
_LANGSERVE = {"output": "pong", "metadata": {"run_id": "abc-123"}}
_V1_MODELS = {"object": "list", "data": [
    {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
    {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"}]}
_API_TAGS = {"models": [{"name": "llama3:latest", "model": "llama3:latest",
             "details": {"family": "llama", "parameter_size": "8B",
                         "quantization_level": "Q4_K_M"}}]}
_OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Demo AI API", "version": "1.0"},
    "paths": {
        "/v1/chat/completions": {
            "post": {
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {
                        "messages": {"type": "array"},
                        "stream": {"type": "boolean"},
                        "image_url": {"type": "string"},
                    }}}}},
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
    # OpenAI-style tool/function schema so supports_tools fires
    "x-tools": [{"type": "function", "function": {
        "name": "get_weather", "description": "Get weather",
        "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}}}],
}
_AI_PLUGIN = {"schema_version": "v1", "name_for_human": "Demo",
              "name_for_model": "demo",
              "description_for_model": "Demo AI plugin for testing.",
              "api": {"type": "openapi", "url": "http://127.0.0.1/openapi.json"},
              "auth": {"type": "none"}}
_QDRANT_COLLECTIONS = {"result": {"collections": [{"name": "docs"}]}, "status": "ok",
                       "time": 0.001}
_MCP_BADVERSION = {"jsonrpc": "2.0", "id": 1, "error": {
    "code": -32602, "message": "Unsupported protocol version",
    "data": {"supported": ["2024-11-05", "2025-03-26", "2025-06-18"]}}}


def _body(d):
    return json.dumps(d).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "RedAmonAISurfaceTarget/1.0"

    def log_message(self, *a):  # silence
        pass

    def _send(self, code, payload, ctype="application/json", extra_headers=None):
        if isinstance(payload, (dict, list)):
            payload = _body(payload)
        elif isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    # ---- GET ----
    def do_GET(self):
        p = self.path.split("?", 1)[0].rstrip("/") or "/"
        if p == "/":
            return self._send(200, "Ollama is running", ctype="text/plain")
        if p == "/api/tags":
            return self._send(200, _API_TAGS)
        if p == "/api/version":
            return self._send(200, {"version": "0.3.0"})
        if p in ("/v1/models", "/models"):
            return self._send(200, _V1_MODELS)
        if p == "/openapi.json":
            return self._send(200, _OPENAPI)
        if p == "/swagger.json":
            return self._send(200, _OPENAPI)
        if p == "/v3/api-docs":
            return self._send(200, _OPENAPI)
        if p == "/.well-known/ai-plugin.json":
            return self._send(200, _AI_PLUGIN)
        if p == "/collections":                     # Qdrant vector-DB read
            return self._send(200, _QDRANT_COLLECTIONS)
        if p == "/api/v1/collections":              # Chroma vector-DB read
            return self._send(200, {"collections": []})
        if p == "/healthz":
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    # ---- POST ----
    def do_POST(self):
        p = self.path.split("?", 1)[0]
        # strip trailing slash except keep gemini ":generateContent"
        pp = p.rstrip("/") if not p.endswith("generateContent") else p
        try:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length) if length else b""
        except Exception:
            pass

        if pp in ("/v1/chat/completions", "/v1/completions", "/v1/responses",
                  "/chat/completions", "/completion"):
            return self._send(200, _OPENAI_CHAT)
        if pp == "/v1/messages":
            return self._send(200, _ANTHROPIC)
        if pp == "/api/generate":
            return self._send(200, _OLLAMA_GEN)
        if pp == "/api/chat":
            return self._send(200, _OLLAMA_CHAT)
        if pp.endswith(":generateContent") or "/v1beta/models/" in pp:
            return self._send(200, _GEMINI)
        if pp in ("/invoke", "/generate"):
            return self._send(200, _LANGSERVE)
        if pp == "/stream":                          # SSE streaming chat (OpenAI payload)
            sse = ("data: " + json.dumps(_OPENAI_CHAT) + "\n\n"
                   "data: [DONE]\n\n")
            return self._send(200, sse, ctype="text/event-stream")
        if pp == "/stream-opaque":                    # SSE with non-chat data -> sse-stream
            sse = "data: {\"event\": \"token\", \"value\": \"p\"}\n\ndata: [DONE]\n\n"
            return self._send(200, sse, ctype="text/event-stream")
        if pp == "/secured/v1/chat/completions":     # 401 + OpenAI error body
            return self._send(401, {"error": {"message": "missing api key",
                                              "type": "invalid_request_error"}})
        if pp == "/mcp-auth":                         # MCP behind auth
            return self._send(401, {"error": "unauthorized"},
                              extra_headers={"WWW-Authenticate":
                                             'Bearer resource_metadata="http://127.0.0.1/.well-known/oauth"'})
        if pp == "/mcp-badversion":                   # MCP version-mismatch leak
            return self._send(200, _MCP_BADVERSION)
        return self._send(404, {"error": "not found"})


def make_server(port: int, bind: str = "127.0.0.1") -> ThreadingHTTPServer:
    return ThreadingHTTPServer((bind, port), Handler)


def serve_in_thread(port: int, bind: str = "127.0.0.1") -> ThreadingHTTPServer:
    srv = make_server(port, bind)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9110
    print(f"[ai_surface_recon_endpoints] serving on 127.0.0.1:{port}")
    make_server(port).serve_forever()
