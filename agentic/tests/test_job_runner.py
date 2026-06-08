"""
Unit + integration tests for agentic/job_runner.py.

Covers:
  - spawn() returns synchronously with job_id + paths
  - runner output is tee'd to the .log file as it appears
  - status() returns size + tail mid-flight and post-completion
  - wait() with timeout (returns whatever status is at deadline)
  - cancel() terminates the task and flips status
  - list() with active filter
  - recover_on_boot() flips orphaned 'running' meta to 'interrupted'
  - WS emitter is called on lifecycle transitions

Run with: python3 -m unittest tests.test_job_runner -v
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import job_runner  # noqa: E402


class JobRunnerTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-jobs-")
        self._orig_root = job_runner.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        # Fresh registry per test (the module-level singleton would leak
        # state across tests otherwise).
        job_runner._registry = None
        self.reg = job_runner.get_registry()

    async def asyncTearDown(self):
        # Cancel any in-flight jobs BEFORE restoring WORKSPACE_ROOT so their
        # finally-blocks don't write meta to the real /workspace path.
        if job_runner._registry is not None:
            tasks = [h.task for h in job_runner._registry._jobs.values()
                     if h.task and not h.task.done()]
            for t in tasks:
                t.cancel()
            for t in tasks:
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        job_runner.WORKSPACE_ROOT = self._orig_root
        job_runner._registry = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tearDown(self):
        pass  # async version above does the work


# =============================================================================
# Lifecycle
# =============================================================================

class TestSpawn(JobRunnerTestBase):
    async def test_spawn_returns_immediately(self):
        async def slow_runner(name, args, append_log):
            await append_log("starting")
            await asyncio.sleep(0.5)
            return {"success": True, "output": "done"}

        result = await self.reg.spawn("p1", "fake_tool", {"x": 1}, slow_runner)
        self.assertIn("job_id", result)
        self.assertIn("output_path", result)
        self.assertEqual(result["status"], "running")
        # Should be on disk
        log_path = Path(result["output_path"])
        self.assertTrue(log_path.exists())
        meta_path = log_path.with_name(f"{result['job_id']}.meta.json")
        self.assertTrue(meta_path.exists())
        # Clean up by awaiting completion
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)

    async def test_spawn_without_project_returns_error(self):
        async def runner(*a):
            return {"success": True}
        result = await self.reg.spawn("", "x", {}, runner)
        self.assertIn("error", result)

    async def test_tee_appends_to_log(self):
        async def emitter(name, args, append_log):
            for chunk in ("alpha\n", "beta\n", "gamma\n"):
                await append_log(chunk)
            return {"success": True, "output": "done"}

        result = await self.reg.spawn("p1", "echo", {}, emitter)
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)
        log = Path(result["output_path"]).read_text()
        self.assertIn("alpha", log)
        self.assertIn("beta", log)
        self.assertIn("gamma", log)
        self.assertIn("--- final ---", log)
        self.assertIn("done", log)


class TestStatus(JobRunnerTestBase):
    async def test_status_shows_tail_and_size_after_completion(self):
        async def runner(name, args, append_log):
            await append_log("hello")
            return {"success": True, "output": "world"}

        result = await self.reg.spawn("p1", "x", {}, runner)
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)
        status = self.reg.status("p1", result["job_id"])
        self.assertEqual(status["status"], "done")
        self.assertEqual(status["exit_code"], 0)
        self.assertGreater(status["size_bytes"], 0)
        self.assertIn("hello", status["tail"])

    async def test_status_unknown_job(self):
        s = self.reg.status("p1", "nope")
        self.assertIn("error", s)

    async def test_status_failed_runner(self):
        async def runner(name, args, append_log):
            return {"success": False, "error": "boom"}

        result = await self.reg.spawn("p1", "x", {}, runner)
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)
        status = self.reg.status("p1", result["job_id"])
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["exit_code"], 1)
        self.assertEqual(status["error"], "boom")

    async def test_status_runner_exception(self):
        async def runner(name, args, append_log):
            raise RuntimeError("crashed inside runner")

        result = await self.reg.spawn("p1", "x", {}, runner)
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)
        status = self.reg.status("p1", result["job_id"])
        self.assertEqual(status["status"], "failed")
        self.assertIn("crashed", (status.get("error") or ""))


class TestWaitTimeout(JobRunnerTestBase):
    async def test_wait_timeout_returns_running_status(self):
        async def slow(name, args, append_log):
            await asyncio.sleep(2.0)
            return {"success": True}

        result = await self.reg.spawn("p1", "slow", {}, slow)
        status = await self.reg.wait("p1", result["job_id"], timeout_sec=0.2)
        # Job should still be running when we time out
        self.assertEqual(status["status"], "running")
        # Clean up
        await self.reg.cancel("p1", result["job_id"])


class TestCancel(JobRunnerTestBase):
    async def test_cancel_flips_status(self):
        async def slow(name, args, append_log):
            await asyncio.sleep(5.0)
            return {"success": True}

        result = await self.reg.spawn("p1", "slow", {}, slow)
        await asyncio.sleep(0.05)  # let it start
        s = await self.reg.cancel("p1", result["job_id"])
        self.assertEqual(s["status"], "cancelled")


class TestList(JobRunnerTestBase):
    async def test_list_filters_by_active(self):
        async def quick(name, args, append_log):
            return {"success": True}

        async def slow(name, args, append_log):
            await asyncio.sleep(3.0)
            return {"success": True}

        done = await self.reg.spawn("p1", "q", {}, quick)
        await self.reg.wait("p1", done["job_id"], timeout_sec=2.0)
        running = await self.reg.spawn("p1", "s", {}, slow)
        await asyncio.sleep(0.05)

        all_jobs = self.reg.list("p1")
        self.assertEqual(len(all_jobs), 2)
        active = self.reg.list("p1", active=True)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["job_id"], running["job_id"])
        finished = self.reg.list("p1", active=False)
        self.assertEqual(len(finished), 1)
        self.assertEqual(finished[0]["job_id"], done["job_id"])

        await self.reg.cancel("p1", running["job_id"])

    async def test_list_isolates_projects(self):
        async def quick(name, args, append_log):
            return {"success": True}

        j1 = await self.reg.spawn("p1", "x", {}, quick)
        j2 = await self.reg.spawn("p2", "x", {}, quick)
        await self.reg.wait("p1", j1["job_id"], timeout_sec=2.0)
        await self.reg.wait("p2", j2["job_id"], timeout_sec=2.0)
        self.assertEqual([j["job_id"] for j in self.reg.list("p1")], [j1["job_id"]])
        self.assertEqual([j["job_id"] for j in self.reg.list("p2")], [j2["job_id"]])


# =============================================================================
# Recovery
# =============================================================================

class TestRecoverOnBoot(JobRunnerTestBase):
    async def test_running_meta_flipped_to_interrupted(self):
        # Simulate a prior agent process that died mid-job: write a meta file
        # marked 'running' but no live asyncio task.
        proj_jobs = job_runner.WORKSPACE_ROOT / "p1" / "jobs"
        proj_jobs.mkdir(parents=True, exist_ok=True)
        meta = proj_jobs / "abc.meta.json"
        meta.write_text(json.dumps({
            "job_id": "abc",
            "project_id": "p1",
            "tool_name": "execute_nuclei",
            "status": "running",
            "started_at": "2026-01-01T00:00:00+00:00",
        }))
        # Fresh registry, run recovery
        job_runner._registry = None
        reg2 = job_runner.get_registry()
        reg2.recover_on_boot()
        data = json.loads(meta.read_text())
        self.assertEqual(data["status"], "interrupted")
        self.assertIsNotNone(data.get("ended_at"))

    async def test_done_meta_left_alone(self):
        proj_jobs = job_runner.WORKSPACE_ROOT / "p1" / "jobs"
        proj_jobs.mkdir(parents=True, exist_ok=True)
        meta = proj_jobs / "xyz.meta.json"
        meta.write_text(json.dumps({
            "job_id": "xyz",
            "project_id": "p1",
            "tool_name": "x",
            "status": "done",
            "started_at": "2026-01-01T00:00:00+00:00",
        }))
        self.reg.recover_on_boot()
        self.assertEqual(json.loads(meta.read_text())["status"], "done")

    async def test_status_loads_from_disk_post_restart(self):
        proj_jobs = job_runner.WORKSPACE_ROOT / "p1" / "jobs"
        proj_jobs.mkdir(parents=True, exist_ok=True)
        meta = proj_jobs / "ghost.meta.json"
        meta.write_text(json.dumps({
            "job_id": "ghost",
            "project_id": "p1",
            "tool_name": "x",
            "status": "done",
            "started_at": "2026-01-01T00:00:00+00:00",
        }))
        (proj_jobs / "ghost.log").write_text("tail-content")
        s = self.reg.status("p1", "ghost")
        self.assertEqual(s["status"], "done")
        self.assertEqual(s["size_bytes"], len("tail-content"))


# =============================================================================
# WS emitter
# =============================================================================

class TestWebSocketEmitter(JobRunnerTestBase):
    async def test_emitter_called_on_lifecycle(self):
        events: list[dict] = []

        async def collect(evt):
            events.append(evt)

        self.reg.set_ws_emitter(collect)

        async def runner(name, args, append_log):
            return {"success": True}

        result = await self.reg.spawn("p1", "x", {}, runner)
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)
        # Should have at least: running (on spawn) and done (on completion)
        statuses = [e.get("status") for e in events if e.get("type") == "job_update"]
        self.assertIn("running", statuses)
        self.assertIn("done", statuses)

    async def test_failed_emitter_doesnt_break_spawn(self):
        async def broken(evt):
            raise RuntimeError("WS dead")

        self.reg.set_ws_emitter(broken)

        async def runner(name, args, append_log):
            return {"success": True}

        # Should still complete normally despite emitter raising
        result = await self.reg.spawn("p1", "x", {}, runner)
        await self.reg.wait("p1", result["job_id"], timeout_sec=2.0)
        status = self.reg.status("p1", result["job_id"])
        self.assertEqual(status["status"], "done")


if __name__ == "__main__":
    unittest.main()
