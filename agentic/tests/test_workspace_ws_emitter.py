"""
Integration tests for ws_job_emitter.emit_job_update + JobRegistry fan-out.

Verifies:
  - emit_job_update only sends to connections with matching project_id
  - unauthenticated connections are skipped
  - a send failure on one connection does not break fan-out to others
  - missing project_id is a no-op
  - JobRegistry.set_ws_emitter wiring end-to-end (spawn -> events fan out)

ws_job_emitter is its own tiny module so this test does NOT need the
full FastAPI/langgraph stack to load.

Run with: python3 -m unittest tests.test_workspace_ws_emitter -v
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

# Stub the heavy deps that websocket_api imports (it has MessageType which
# the emitter pulls in lazily). The MessageType enum itself is plain stdlib.
# ws_job_emitter is intentionally decoupled from websocket_api, so this test
# can run without stubbing the langgraph / orchestrator / prompts chain.
import ws_job_emitter  # noqa: E402
import job_runner  # noqa: E402
import workspace_fs  # noqa: E402


def _job_update_value() -> str:
    """The MessageType.JOB_UPDATE.value string. Asserting on this catches
    drift between ws_job_emitter._JOB_UPDATE.value and the real enum entry."""
    return "job_update"


_conn_seq = [0]


def _next_session_id() -> str:
    _conn_seq[0] += 1
    return f"s{_conn_seq[0]}"


class FakeConnection:
    def __init__(self, project_id: str, authenticated: bool = True):
        self.project_id = project_id
        self.user_id = "u"
        # Distinct session_id per FakeConnection so the FakeWsManager dict
        # doesn't collapse two connections on the same project.
        self.session_id = _next_session_id()
        self.authenticated = authenticated
        self.sent: list[tuple] = []
        self.should_raise = False

    async def send_message(self, message_type, payload):
        if self.should_raise:
            raise RuntimeError("simulated websocket dead")
        self.sent.append((message_type, payload))

    def get_key(self) -> str:
        return f"{self.user_id}:{self.project_id}:{self.session_id}"


class FakeWsManager:
    def __init__(self):
        self.active_connections: dict[str, FakeConnection] = {}

    def add(self, conn: FakeConnection):
        self.active_connections[conn.get_key()] = conn


class WsEmitterTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-ws-emit-")
        self._orig_root_jr = job_runner.WORKSPACE_ROOT
        self._orig_root_wf = workspace_fs.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        job_runner._registry = None
        self.fake_ws = FakeWsManager()
        ws_job_emitter.set_ws_manager(self.fake_ws)

    async def asyncTearDown(self):
        if job_runner._registry is not None:
            tasks = [h.task for h in job_runner._registry._jobs.values()
                     if h.task and not h.task.done()]
            for t in tasks:
                t.cancel()
            for t in tasks:
                try:
                    await t
                except Exception:
                    pass
        ws_job_emitter.set_ws_manager(None)
        job_runner.WORKSPACE_ROOT = self._orig_root_jr
        workspace_fs.WORKSPACE_ROOT = self._orig_root_wf
        job_runner._registry = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tearDown(self):
        pass


# =============================================================================
# emit_job_update unit behaviour
# =============================================================================

class TestEmitJobUpdate(WsEmitterTestBase):
    async def test_only_matching_project_receives(self):
        c1 = FakeConnection("proj-A")
        c2 = FakeConnection("proj-B")
        c3 = FakeConnection("proj-A")
        self.fake_ws.add(c1); self.fake_ws.add(c2); self.fake_ws.add(c3)

        await ws_job_emitter.emit_job_update({
            "type": "job_update", "project_id": "proj-A",
            "job_id": "abc", "status": "running",
        })

        self.assertEqual(len(c1.sent), 1)
        self.assertEqual(len(c3.sent), 1)
        self.assertEqual(len(c2.sent), 0, "proj-B should not have received")
        # Verify the payload shape made it through unchanged. The emitter
        # passes MessageType.JOB_UPDATE (enum); we duck-type the assertion
        # by reading .value, which both real MessageType and any stub provide.
        msg_type, payload = c1.sent[0]
        self.assertEqual(getattr(msg_type, "value", msg_type), _job_update_value())
        self.assertEqual(payload["job_id"], "abc")

    async def test_unauthenticated_skipped(self):
        c1 = FakeConnection("proj-A", authenticated=False)
        c2 = FakeConnection("proj-A", authenticated=True)
        self.fake_ws.add(c1); self.fake_ws.add(c2)
        await ws_job_emitter.emit_job_update({
            "type": "job_update", "project_id": "proj-A",
            "job_id": "abc", "status": "done",
        })
        self.assertEqual(len(c1.sent), 0)
        self.assertEqual(len(c2.sent), 1)

    async def test_send_failure_does_not_break_fanout(self):
        c1 = FakeConnection("proj-A"); c1.should_raise = True
        c2 = FakeConnection("proj-A")
        c3 = FakeConnection("proj-A")
        self.fake_ws.add(c1); self.fake_ws.add(c2); self.fake_ws.add(c3)
        await ws_job_emitter.emit_job_update({
            "type": "job_update", "project_id": "proj-A",
            "job_id": "abc", "status": "failed",
        })
        self.assertEqual(len(c1.sent), 0)
        self.assertEqual(len(c2.sent), 1)
        self.assertEqual(len(c3.sent), 1)

    async def test_missing_project_id_no_op(self):
        c1 = FakeConnection("proj-A")
        self.fake_ws.add(c1)
        await ws_job_emitter.emit_job_update({"type": "job_update"})
        self.assertEqual(len(c1.sent), 0)

    async def test_no_ws_manager_no_op(self):
        ws_job_emitter.set_ws_manager(None)
        # Should not raise
        await ws_job_emitter.emit_job_update({
            "type": "job_update", "project_id": "p1",
            "job_id": "x", "status": "running",
        })


# =============================================================================
# End-to-end: registry wired to emitter triggers fan-out on lifecycle
# =============================================================================

class TestRegistryEmitterWiring(WsEmitterTestBase):
    async def test_spawn_triggers_running_and_done_to_matching_project(self):
        reg = job_runner.get_registry()
        reg.set_ws_emitter(ws_job_emitter.emit_job_update)

        c1 = FakeConnection("proj-X")
        c2 = FakeConnection("proj-Y")
        self.fake_ws.add(c1); self.fake_ws.add(c2)

        async def quick(name, args, append_log):
            return {"success": True, "output": "done"}

        result = await reg.spawn("proj-X", "fake_tool", {}, quick)
        await reg.wait("proj-X", result["job_id"], timeout_sec=2.0)

        statuses_x = [p.get("status") for (_, p) in c1.sent]
        self.assertIn("running", statuses_x)
        self.assertIn("done", statuses_x)
        # proj-Y should be untouched
        self.assertEqual(len(c2.sent), 0)


class TestEmitterEdges(WsEmitterTestBase):
    """Edge cases not covered by the happy-path tests."""

    async def test_emit_with_empty_connections_no_op(self):
        # No connections at all - should complete cleanly.
        await ws_job_emitter.emit_job_update({
            "type": "job_update", "project_id": "p1",
            "job_id": "x", "status": "running",
        })

    async def test_emit_with_non_dict_evt_is_safe(self):
        # If someone misuses the emitter with a non-dict, it should not
        # explode the asyncio task running the JobRegistry. Currently the
        # code does evt.get(...) which would raise AttributeError. Lock in
        # the desired behaviour: no-op on bad input.
        c1 = FakeConnection("p1")
        self.fake_ws.add(c1)
        try:
            await ws_job_emitter.emit_job_update("not a dict")
        except AttributeError:
            self.fail("emit_job_update should not raise AttributeError on non-dict input")
        self.assertEqual(len(c1.sent), 0)

    async def test_emit_with_none_evt(self):
        try:
            await ws_job_emitter.emit_job_update(None)
        except (AttributeError, TypeError):
            self.fail("emit_job_update should not raise on None input")

    async def test_emit_safe_under_concurrent_connection_removal(self):
        # The emitter snapshots active_connections via list(...). Verify
        # that mutating the dict mid-iteration doesn't trip the emitter.
        # We simulate by mutating from inside one connection's send_message.
        removal_target = FakeConnection("p1")
        normal = FakeConnection("p1")

        original_send = removal_target.send_message

        async def sneaky_send(message_type, payload):
            # Remove ourselves mid-emit
            self.fake_ws.active_connections.pop(removal_target.get_key(), None)
            await original_send(message_type, payload)
        removal_target.send_message = sneaky_send

        self.fake_ws.add(removal_target)
        self.fake_ws.add(normal)

        await ws_job_emitter.emit_job_update({
            "type": "job_update", "project_id": "p1",
            "job_id": "x", "status": "running",
        })
        # Both should have received (snapshot was taken before mutation)
        self.assertEqual(len(removal_target.sent), 1)
        self.assertEqual(len(normal.sent), 1)

    async def test_emit_with_payload_containing_unicode(self):
        # Job tool names / labels can be UTF-8 strings.
        c1 = FakeConnection("p1")
        self.fake_ws.add(c1)
        evt = {
            "type": "job_update", "project_id": "p1",
            "job_id": "abc", "status": "running",
            "label": "scan résumé café",
        }
        await ws_job_emitter.emit_job_update(evt)
        self.assertEqual(len(c1.sent), 1)
        _, payload = c1.sent[0]
        self.assertEqual(payload["label"], "scan résumé café")


class TestMessageTypeDriftGuard(unittest.TestCase):
    """REGRESSION GUARD: ws_job_emitter._JOB_UPDATE.value must match
    websocket_api.MessageType.JOB_UPDATE.value. The emitter uses a local
    shim to stay decoupled from the heavy websocket_api import chain - this
    test loads the real enum (when available) and asserts they agree.

    Skips on the host where websocket_api can't import due to missing
    langgraph / orchestrator deps; runs in the container.
    """

    def test_shim_value_matches_real_messagetype(self):
        try:
            from websocket_api import MessageType
        except ImportError as e:
            self.skipTest(f"websocket_api transitive deps unavailable: {e}")
        self.assertEqual(
            ws_job_emitter._JOB_UPDATE.value,
            MessageType.JOB_UPDATE.value,
            "ws_job_emitter._JOB_UPDATE.value drifted from MessageType.JOB_UPDATE.value",
        )


if __name__ == "__main__":
    unittest.main()
