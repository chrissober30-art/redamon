"""Container entrypoint for the AI surface guinea pig.

Runs the aiohttp multi-port target (server.main, all lap-1..6 ports + the
central ai_surface_recon HTTP surface on 9106) AND the real MCP Streamable-HTTP
server (FastMCP) on 9107 as a subprocess. With both up, a full recon scan using
the "AI / LLM Surface Recon" preset triggers every check end-to-end:

  http_probe AI signatures, port AI catalogue, resource_enum AI classifier,
  js_recon AI SDK, AND the central ai_surface_recon module (chat-shape probes,
  MCP handshake + tools/list + tool-poisoning YARA, OpenAPI/manifest parsing,
  model-family guess, Julius fingerprint, vector-DB confirmation read).
"""
import asyncio
import subprocess
import sys

import server


def main() -> None:
    # Real MCP server in its own process (uvicorn installs signal handlers, so it
    # needs to be the main thread of its own process). Bind 0.0.0.0 to match the
    # aiohttp listeners (recon reaches it via loopback under network_mode: host).
    mcp_proc = subprocess.Popen(
        [sys.executable, "-u", "mcp_poison_server.py", str(server.MCP_TARGET_PORT), "0.0.0.0"]
    )
    try:
        asyncio.run(server.main())
    finally:
        mcp_proc.terminate()
        try:
            mcp_proc.wait(timeout=5)
        except Exception:
            mcp_proc.kill()


if __name__ == "__main__":
    main()
