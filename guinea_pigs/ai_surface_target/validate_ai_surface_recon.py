"""End-to-end live validation of EVERY ai_surface_recon workload/probe.

Starts real servers and runs the module's ACTUAL functions against them — no
mocks. Closes the gaps unit tests can't: live HTTP, the real `mcp` SDK handshake
+ tools/list, real YARA on real tool manifests, real prance/jq parsing, the real
Julius matcher against the vendored packs, and the vector-DB confirmation read.

What it spins up:
  * HTTP target (stdlib) on 127.0.0.1:9110  — all chat shapes, OpenAPI, models, Julius
  * same handler on 127.0.0.1:6333          — Qdrant vector-DB read persona
  * real MCP server (FastMCP subprocess) on 127.0.0.1:9111 — poisoned tool manifest

Run INSIDE the recon image (it has the vendored packs + deps; pip-install the
few that aren't baked yet):

    docker run --rm --entrypoint sh \
      -v "$PWD/recon:/app/recon:ro" -v "$PWD/graph_db:/app/graph_db:ro" \
      -v "$PWD/guinea_pigs:/app/guinea_pigs:ro" -w /app redamon-recon:latest -c '
      pip install -q pyyaml yara-python jq prance openapi-spec-validator "mcp>=1.27" uvicorn &&
      python3 guinea_pigs/ai_surface_target/validate_ai_surface_recon.py'

Exit code 0 == 100% of probes validated.
"""
from __future__ import annotations

import os
import sys
import time
import socket
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import requests  # noqa: E402
from recon.main_recon_modules import ai_surface_recon as M  # noqa: E402
from recon.helpers import ai_signal_catalog as cat  # noqa: E402
import ai_surface_recon_endpoints as TARGET  # noqa: E402

HTTP_PORT = 9110
VDB_PORT = 6333          # Qdrant in the AI_PORTS catalog
MCP_PORT = 9111
HTTP_BASE = f"http://127.0.0.1:{HTTP_PORT}"
MCP_BASE = f"http://127.0.0.1:{MCP_PORT}"

_results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    _results.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))


def _wait_port(host: str, port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "RedAmon-AISurfaceRecon/1.0"})
    return s


# --------------------------------------------------------------------------- #
def validate_chat(sess):
    print("\n[1] Chat-shape probes (live)")
    timeout = 5.0
    families = [
        ("/v1/chat/completions", "llm-chat", "llm-chat", "openai"),
        ("/v1/messages", "llm-chat", "llm-chat", "anthropic"),
        ("/api/generate", "llm-completion", "llm-completion", "ollama"),
        ("/api/chat", "llm-chat", "llm-chat", "ollama-chat"),
        ("/v1beta/models/gemini-pro:generateContent", "llm-chat", "llm-chat", "gemini"),
        ("/invoke", "llm-chat", "llm-chat", "langserve"),
        # SSE carrying an OpenAI payload -> classified precisely as llm-chat (+streaming)
        ("/stream", "sse-stream", "llm-chat", "sse-openai"),
        # SSE with opaque (non-chat) data -> bare sse-stream fallback
        ("/stream-opaque", "sse-stream", "sse-stream", "sse-bare"),
        ("/secured/v1/chat/completions", "llm-chat", "llm-chat", "401-error"),
    ]
    for path, hint, expect, fam in families:
        cand = {"host_is_ai": True, "endpoints": [{"path": path, "iface": hint}]}
        res = M._probe_chat(HTTP_BASE, cand, sess, timeout, latency_on=True)
        got = res.get("ai_interface_type")
        check(f"chat:{fam} ({path}) -> {expect}", got == expect, f"got {got!r}")
    # streaming flag + latency recorded
    cand = {"host_is_ai": True, "endpoints": [{"path": "/stream", "iface": "sse-stream"}]}
    res = M._probe_chat(HTTP_BASE, cand, sess, 5.0, latency_on=True)
    check("chat:sse supports_streaming=True", res.get("supports_streaming") is True)
    cand = {"host_is_ai": True, "endpoints": [{"path": "/v1/chat/completions", "iface": "llm-chat"}]}
    res = M._probe_chat(HTTP_BASE, cand, sess, 5.0, latency_on=True)
    check("chat:latency_p50_ms recorded", isinstance(res.get("latency_p50_ms"), float))
    # static AI_CHAT_PROBE_PATHS fallback branch (AI host, no classified endpoint)
    res = M._probe_chat(HTTP_BASE, {"host_is_ai": True, "endpoints": []}, sess, 5.0, latency_on=False)
    check("chat:static fallback paths probed",
          res.get("ai_interface_type") in M._CHAT_IFACES, str(res.get("ai_interface_type")))


def validate_openapi(sess):
    print("\n[2] OpenAPI / manifest / model-family (live, real prance + jq)")
    specs = Path("/tmp/redamon_validate_specs")   # writable (HERE is mounted read-only)
    oa = M._probe_openapi(HTTP_BASE, sess, 5.0, model_list_on=True, specs_dir=specs)
    check("openapi:supports_tools", oa.get("supports_tools") is True, str(oa.get("supports_tools")))
    check("openapi:supports_vision", oa.get("supports_vision") is True, str(oa.get("supports_vision")))
    check("openapi:tool_schema_ref cached", bool(oa.get("tool_schema_ref"))
          and Path(oa["tool_schema_ref"]).exists(), str(oa.get("tool_schema_ref")))
    # target serves both /v1/models (gpt) and /api/tags (llama); guess is deterministic
    check("openapi:model_family_guess recognized",
          oa.get("model_family_guess") in {"gpt", "llama"}, str(oa.get("model_family_guess")))


def validate_julius(sess):
    print("\n[3] Julius fingerprint pack (live, real engine + vendored packs)")
    jl = M._probe_julius(HTTP_BASE, 5.0, "RedAmon-AISurfaceRecon/1.0")
    check("julius:service detected", bool(jl.get("service")), str(jl.get("service")))
    check("julius:ollama wins by specificity", jl.get("service") == "ollama", str(jl.get("service")))


def validate_vectordb(sess):
    print("\n[4] Vector-DB confirmation read (live, Qdrant persona on 6333)")
    cr = {"port_scan": {"by_host": {"127.0.0.1": {"ip": "127.0.0.1", "ports": [VDB_PORT]}}}}
    vdb = M._confirm_vector_dbs(cr, sess, 5.0)
    names = {v.get("tech_name") for v in vdb}
    check("vectordb:qdrant confirmed", "qdrant" in names, str(names))


def validate_mcp(sess):
    print("\n[5] MCP handshake + tools/list + static YARA (live, real mcp SDK)")
    det = M._mcp_detect(MCP_BASE, sess, 5.0)
    check("mcp:detected via real handshake", bool(det and not det.get("auth_required")),
          str(det and det.get("path")))

    res = M._probe_mcp(MCP_BASE, sess, 8.0, list_tools=True, yara_on=True)
    mcp = (res or {}).get("mcp", {})
    findings = (res or {}).get("findings", [])
    check("mcp:is_mcp", mcp.get("is_mcp") is True)
    check("mcp:server_name captured", bool(mcp.get("server_name")), str(mcp.get("server_name")))
    check("mcp:tools enumerated (>=4)", (mcp.get("tool_count") or 0) >= 4, str(mcp.get("tool_count")))
    check("mcp:tools_hash (rug-pull pin)", bool(mcp.get("tools_hash")))
    # Deep-control: prove model_dump(by_alias=True) actually captured inputSchema
    # (the bug class fixed earlier) and that the mixin's exact Parameter arg-path
    # resolution works against the REAL SDK output.
    tools = mcp.get("tools") or []
    with_schema = [t for t in tools if (t.get("input_schema") or {}).get("properties")]
    check("mcp:tool input_schema captured (by_alias)", bool(with_schema),
          f"{len(with_schema)}/{len(tools)} tools carry input_schema.properties")
    if with_schema:
        t0 = with_schema[0]
        arg = next(iter(t0["input_schema"]["properties"].keys()))
        ptr = cat.resolve_ai_tool_arg_path({"inputSchema": t0["input_schema"]},
                                           "mcp-tools-list", arg)
        check("mcp:ai_tool_arg_path resolves (exact mixin call)",
              ptr == f"/inputSchema/properties/{arg}", str(ptr))
    ftypes = {f.get("type") for f in findings}
    check("mcp:tool_poisoning finding", "mcp_tool_poisoning" in ftypes, str(ftypes))
    check("mcp:data_exfiltration finding", "mcp_data_exfiltration" in ftypes, str(ftypes))
    check("mcp:annotation_mismatch finding", "mcp_annotation_mismatch" in ftypes, str(ftypes))
    check("mcp:findings carry owasp+atlas",
          all(f.get("owasp_llm_id") and f.get("atlas_technique") for f in findings) and bool(findings))

    # auth-required + version-mismatch branches (point the probe-path list at the
    # dedicated stdlib endpoints)
    saved = cat.AI_MCP_PROBE_PATHS
    try:
        cat.AI_MCP_PROBE_PATHS = ["/mcp-auth"]
        d_auth = M._mcp_detect(HTTP_BASE, sess, 5.0)
        check("mcp:auth-required branch (401+WWW-Authenticate)",
              bool(d_auth and d_auth.get("auth_required")), str(d_auth))
        cat.AI_MCP_PROBE_PATHS = ["/mcp-badversion"]
        d_ver = M._mcp_detect(HTTP_BASE, sess, 5.0)
        check("mcp:version-mismatch leaks supported list",
              bool(d_ver and d_ver.get("supported_versions")), str(d_ver and d_ver.get("supported_versions")))
    finally:
        cat.AI_MCP_PROBE_PATHS = saved


def validate_end_to_end():
    print("\n[6] run_ai_surface_recon end-to-end (integrated output assembly)")
    combined = {
        "metadata": {"project_id": "validate", "scan_timestamp": "t"},
        "resource_enum": {"by_base_url": {
            HTTP_BASE: {"endpoints": {
                "/v1/chat/completions": {"methods": ["POST"], "ai_interface_type": "llm-chat"},
            }},
            MCP_BASE: {"endpoints": {
                "/mcp": {"methods": ["POST"], "ai_interface_type": "mcp"},
            }},
        }},
        "http_probe": {"by_url": {
            HTTP_BASE + "/": {"is_ai_framework_detected": True},
            MCP_BASE + "/": {"is_ai_framework_detected": True},
        }},
        "port_scan": {"by_host": {"127.0.0.1": {"ip": "127.0.0.1", "ports": [VDB_PORT]}}},
    }
    settings = {"AI_SURFACE_RECON_ENABLED": True, "AI_SURFACE_RECON_TIMEOUT": 8,
                "AI_SURFACE_RECON_MAX_WORKERS": 4}
    out = M.run_ai_surface_recon(combined, settings=settings)
    asr = out.get("ai_surface_recon", {})
    s = asr.get("summary", {})
    check("e2e:ai_surface_recon section present", bool(asr))
    check("e2e:mcp_servers>=1", (s.get("mcp_servers") or 0) >= 1, str(s.get("mcp_servers")))
    check("e2e:chat_endpoints>=1", (s.get("chat_endpoints") or 0) >= 1, str(s.get("chat_endpoints")))
    check("e2e:mcp_poisoning_findings>=2", (s.get("mcp_poisoning_findings") or 0) >= 2,
          str(s.get("mcp_poisoning_findings")))
    check("e2e:vector_dbs_confirmed>=1", (s.get("vector_dbs_confirmed") or 0) >= 1,
          str(s.get("vector_dbs_confirmed")))
    check("e2e:model_families non-empty", bool(s.get("model_families")), str(s.get("model_families")))
    check("e2e:findings list populated", len(asr.get("findings") or []) >= 2)


def main() -> int:
    print("=" * 64)
    print("ai_surface_recon — live 100% probe validation")
    print("=" * 64)

    TARGET.serve_in_thread(HTTP_PORT)
    TARGET.serve_in_thread(VDB_PORT)
    if not (_wait_port("127.0.0.1", HTTP_PORT) and _wait_port("127.0.0.1", VDB_PORT)):
        print("[!] HTTP target failed to start"); return 2

    mcp_proc = subprocess.Popen(
        [sys.executable, str(HERE / "mcp_poison_server.py"), str(MCP_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not _wait_port("127.0.0.1", MCP_PORT, timeout=25):
            print("[!] MCP server failed to start"); return 2
        time.sleep(1.5)  # let uvicorn finish binding routes

        sess = _session()
        validate_chat(sess)
        validate_openapi(sess)
        validate_julius(sess)
        validate_vectordb(sess)
        validate_mcp(sess)
        validate_end_to_end()
    finally:
        mcp_proc.terminate()
        try:
            mcp_proc.wait(timeout=5)
        except Exception:
            mcp_proc.kill()

    passed = sum(1 for _, ok, _ in _results if ok)
    failed = [n for n, ok, _ in _results if not ok]
    print("\n" + "=" * 64)
    print(f"{passed}/{len(_results)} checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(f"  - {n}")
    print("=" * 64)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
