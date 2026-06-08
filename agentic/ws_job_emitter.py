"""
WebSocket fan-out for JobRegistry job_update events.

Lives in its own module (not api.py) so it can be unit-tested without
importing the full FastAPI/langgraph/orchestrator stack. api.py calls
set_ws_manager() at startup and registers emit_job_update on the
JobRegistry via reg.set_ws_emitter().
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Late binding: api.py calls set_ws_manager() during lifespan startup.
# Tests can inject a fake manager directly.
_ws_manager = None


def set_ws_manager(manager) -> None:
    """Register the live WebSocketManager (or a fake in tests)."""
    global _ws_manager
    _ws_manager = manager


class _JobUpdateMessageType:
    """Tiny shim that matches the duck-typed contract of MessageType for
    WebSocketConnection.send_message (which calls `message_type.value`).

    Defined here so this module does NOT import websocket_api - that chain
    pulls in langgraph / orchestrator_helpers and would prevent unit-testing
    this fan-out logic in isolation. The string value mirrors
    MessageType.JOB_UPDATE.value in websocket_api.py; a registry test
    (test_workspace_ws_emitter) locks the two together.
    """
    value = "job_update"


_JOB_UPDATE = _JobUpdateMessageType()


async def emit_job_update(evt: dict) -> None:
    """
    Fan out a job_update event to every authenticated WebSocket connection
    whose project_id matches evt['project_id'].

    Send failures on individual connections are logged but do not abort the
    fan-out to other connections.
    """
    if _ws_manager is None:
        return
    # Defensive: bad events from a misbehaving caller must not break the
    # asyncio task this runs inside (the JobRegistry's _run loop).
    if not isinstance(evt, dict):
        return
    target_project = evt.get("project_id")
    if not target_project:
        return
    for conn in list(_ws_manager.active_connections.values()):
        if getattr(conn, "project_id", None) != target_project:
            continue
        if not getattr(conn, "authenticated", False):
            continue
        try:
            await conn.send_message(_JOB_UPDATE, evt)
        except Exception as e:
            logger.warning(
                f"job_update fan-out to {conn.get_key()} failed: {e}"
            )
