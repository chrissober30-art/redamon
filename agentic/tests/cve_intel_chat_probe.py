"""
End-to-end chat probe for cve_intel.

Connects to the agent's WebSocket endpoint as if it were the chat UI, sends
a single natural-language question, and prints a structured trace of:

  - thinking text (truncated)
  - every tool call (name + args)
  - tool output (truncated)
  - final response

Designed to run INSIDE the redamon-agent container (which already has the
`websockets` library) via:

  docker compose exec -T agent python3 /app/tests/cve_intel_chat_probe.py "QUESTION"

Exits non-zero on protocol error or timeout.
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime

import websockets

# ---------------------------------------------------------------------------
# Config -- override via env if needed
# ---------------------------------------------------------------------------
WS_URL    = os.environ.get("PROBE_WS_URL", "ws://127.0.0.1:8080/ws/agent")
USER_ID   = os.environ.get("PROBE_USER_ID", "cmnxhb92m0000qp01u89ic4x5")
PROJECT_ID = os.environ.get("PROBE_PROJECT_ID", "06e579144ce6478a9187fc0a8")
TIMEOUT   = int(os.environ.get("PROBE_TIMEOUT_SEC", "360"))

TRUNCATE  = 600   # chars per stream chunk before truncation


def t(s: str, n: int = TRUNCATE) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f" ...[truncated {len(s) - n} chars]"


async def probe(question: str) -> int:
    session_id = f"probe-{uuid.uuid4().hex[:12]}"
    print(f"[{datetime.utcnow().isoformat()}Z] connecting → {WS_URL}")
    print(f"  user_id={USER_ID}  project_id={PROJECT_ID}  session_id={session_id}")
    print(f"  question={question!r}")
    print("-" * 78)

    # Index tool calls by (wave_id, tool_name, step_index) so parallel-wave
    # tool_output_chunk events route to the correct buffer.
    tool_calls_idx: dict[tuple, dict] = {}
    tool_calls: list[dict] = []
    final_response = ""
    error_msg = ""
    thinking_tokens = 0

    def _key(payload: dict) -> tuple:
        return (
            payload.get("wave_id", ""),
            payload.get("tool_name", ""),
            payload.get("step_index", 0),
        )

    async with websockets.connect(
        WS_URL,
        max_size=10 * 1024 * 1024,
        ping_interval=None,   # agent's streaming events serve as keepalive
        ping_timeout=None,
    ) as ws:
        # ---- 1. INIT ----
        await ws.send(json.dumps({
            "type": "init",
            "payload": {
                "user_id": USER_ID,
                "project_id": PROJECT_ID,
                "session_id": session_id,
            },
        }))

        # ---- 2. wait for CONNECTED, then send QUERY ----
        connected = False
        async with asyncio.timeout(30):
            while not connected:
                raw = await ws.recv()
                msg = json.loads(raw)
                if msg.get("type") == "connected":
                    print(f"  ← connected (protocol_version="
                          f"{msg.get('payload', {}).get('protocol_version')}, "
                          f"features={msg.get('payload', {}).get('features')})")
                    connected = True
                elif msg.get("type") == "error":
                    print(f"  ← ERROR during init: {msg}")
                    return 2

        await ws.send(json.dumps({
            "type": "query",
            "payload": {"question": question},
        }))
        print("  → query sent")
        print("-" * 78)

        # ---- 3. stream events until task_complete or error ----
        try:
            async with asyncio.timeout(TIMEOUT):
                async for raw in ws:
                    msg = json.loads(raw)
                    mtype = msg.get("type")
                    payload = msg.get("payload", {}) or {}

                    if mtype == "thinking":
                        text = (payload.get("thought") or
                                payload.get("text") or "").strip()
                        if text:
                            print(f"[THINK] {t(text, 300)}")
                    elif mtype == "thinking_chunk":
                        thinking_tokens += 1
                    elif mtype == "tool_start":
                        name = payload.get("tool_name", "?")
                        args = payload.get("tool_args", {})
                        wave = payload.get("wave_id", "")
                        step = payload.get("step_index", 0)
                        print(f"\n>>> TOOL START: {name}  wave={wave}  step={step}")
                        print(f"    args = {json.dumps(args, indent=2)[:800]}")
                        rec = {"name": name, "args": args, "output": "",
                               "wave": wave, "step": step}
                        tool_calls.append(rec)
                        tool_calls_idx[_key(payload)] = rec
                    elif mtype == "tool_output_chunk":
                        chunk = payload.get("chunk", "")
                        rec = tool_calls_idx.get(_key(payload))
                        if rec is not None:
                            rec["output"] += chunk
                    elif mtype == "tool_complete":
                        name = payload.get("tool_name", "?")
                        rec = tool_calls_idx.get(_key(payload))
                        # If we never saw chunks, take the full output from the
                        # complete event (some tools emit only the final blob).
                        if rec is not None and not rec["output"]:
                            rec["output"] = payload.get("output", "")
                        out = rec["output"] if rec is not None else payload.get("output", "")
                        print(f"<<< TOOL COMPLETE: {name}  wave={payload.get('wave_id','')}  step={payload.get('step_index',0)}  ({len(out)} chars)")
                        print(f"    output[:{TRUNCATE}] = {t(out)}")
                    elif mtype == "phase_update":
                        print(f"[PHASE] {payload.get('phase')}")
                    elif mtype == "approval_request":
                        # Auto-approve to keep the probe non-interactive
                        print(f"[APPROVAL REQUEST] auto-approving {payload}")
                        await ws.send(json.dumps({
                            "type": "approval",
                            "payload": {"decision": "approve"},
                        }))
                    elif mtype == "tool_confirmation_request":
                        # cve_intel is NOT in DANGEROUS_TOOLS so this shouldn't fire,
                        # but if it does for some other tool, auto-approve to continue.
                        print(f"[TOOL CONFIRMATION] auto-approving {payload}")
                        await ws.send(json.dumps({
                            "type": "tool_confirmation",
                            "payload": {"decision": "approve"},
                        }))
                    elif mtype == "question_request":
                        # Auto-answer with a generic continuation
                        print(f"[QUESTION REQUEST] auto-replying: continue")
                        await ws.send(json.dumps({
                            "type": "answer",
                            "payload": {"answer": "Please proceed using your best judgment."},
                        }))
                    elif mtype == "response":
                        text = payload.get("content") or payload.get("text", "")
                        if text:
                            final_response += text
                    elif mtype == "task_complete":
                        print("\n=== TASK COMPLETE ===")
                        break
                    elif mtype == "error":
                        error_msg = payload.get("message") or json.dumps(payload)
                        print(f"\n!!! AGENT ERROR: {error_msg}")
                        break
        except asyncio.TimeoutError:
            print(f"\n!!! TIMEOUT after {TIMEOUT}s -- printing partial summary anyway")
            error_msg = f"timeout-{TIMEOUT}s"

    # ---- 4. summary (always printed) ----
    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"thinking_chunks: {thinking_tokens}")
    print(f"tool_calls:      {len(tool_calls)}")
    for tc in tool_calls:
        args_str = json.dumps(tc['args'])
        if len(args_str) > 300:
            args_str = args_str[:300] + "..."
        print(f"  - [{tc['name']}] args={args_str}  out_chars={len(tc['output'])}")
    print(f"\nFINAL RESPONSE ({len(final_response)} chars):")
    print(t(final_response, 2000) if final_response else "(none -- agent did not emit a 'response' event before stream ended)")
    if error_msg:
        print(f"\nEXIT REASON: {error_msg}")
    print("=" * 78)

    if error_msg.startswith("timeout"):
        return 3
    if error_msg:
        return 4
    return 0


def main():
    if len(sys.argv) < 2:
        print("Usage: cve_intel_chat_probe.py 'natural-language question'")
        return 1
    q = " ".join(sys.argv[1:])
    return asyncio.run(probe(q))


if __name__ == "__main__":
    sys.exit(main())
