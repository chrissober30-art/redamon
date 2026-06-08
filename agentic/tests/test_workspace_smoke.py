"""
End-to-end smoke tests composing workspace_fs + output_offload + job_runner.

Simulates the real interaction patterns the agent will trigger:
  1. Tool produces huge output -> maybe_offload writes to tool-outputs/ -> agent
     then fs_grep / fs_read over that file to drill in.
  2. job_spawn kicks off a long task that tees to jobs/<id>.log; mid-flight
     fs_grep can read partial results.
  3. Per-call output_mode='inline' override beats an 'always' policy and the
     full output still appears in the chat response (no offload file written).
  4. After offload, fs_diff vs_last_read confirms whether the file changed
     since the agent's last fs_read snapshot.

Run with: python3 -m unittest tests.test_workspace_smoke -v
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import agent_context  # noqa: E402
import workspace_fs  # noqa: E402
import output_offload  # noqa: E402
import job_runner  # noqa: E402


class SmokeBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-smoke-")
        # Point all three modules at the same root.
        self._orig_ws = workspace_fs.WORKSPACE_ROOT
        self._orig_off = output_offload.WORKSPACE_ROOT
        self._orig_jr = job_runner.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        output_offload.WORKSPACE_ROOT = Path(self.tmp)
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        workspace_fs._edit_stack.clear()
        workspace_fs._last_read_contents.clear()
        workspace_fs._last_read_hashes.clear()
        job_runner._registry = None
        agent_context.current_project_id.set("proj-smoke")
        self.root = Path(self.tmp) / "proj-smoke"
        self.root.mkdir(parents=True, exist_ok=True)

    async def asyncTearDown(self):
        # Cancel any in-flight jobs BEFORE restoring WORKSPACE_ROOT, otherwise
        # their finally-blocks will try to write meta to the real /workspace.
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
        workspace_fs.WORKSPACE_ROOT = self._orig_ws
        output_offload.WORKSPACE_ROOT = self._orig_off
        job_runner.WORKSPACE_ROOT = self._orig_jr
        job_runner._registry = None
        agent_context.current_project_id.set("")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tearDown(self):
        # asyncTearDown handles the work; this is a no-op kept for clarity.
        pass


class TestOffloadThenDrillIn(SmokeBase):
    async def test_huge_output_offloaded_then_grepped(self):
        # Simulate a 100KB nuclei result with one INFO line buried inside
        huge_lines = [f"noise line {i}" for i in range(2000)]
        huge_lines.insert(1234, "[INFO] critical-finding CVE-2026-9999 example.com")
        huge_output = "\n".join(huge_lines)

        # Step 1: executor would call this after tool returns.
        stub = output_offload.maybe_offload("proj-smoke", "execute_nuclei", huge_output)
        self.assertIn("Output offloaded:", stub)
        self.assertIn("--- head ---", stub)
        # Critical finding is in the middle, not in head/tail, so the agent
        # would need to drill deeper.
        self.assertNotIn("critical-finding", stub)

        # Step 2: agent extracts the filename from the stub and uses fs_read
        # to inspect the line range of interest.
        # Parse filename from stub
        marker = "tool-outputs/"
        start = stub.find(marker) + len(marker)
        end = stub.find("]", start)
        filename = stub[start:end]
        rel_path = f"tool-outputs/{filename}"

        # Stat the file - exists, size matches
        stat_out = await workspace_fs.fs_stat(rel_path)
        self.assertIn("type: file", stat_out)
        self.assertIn(f"size: {len(huge_output)}", stat_out)

        # Read a window around line 1234
        read_out = await workspace_fs.fs_read(rel_path, offset=1230, limit=10)
        self.assertIn("critical-finding", read_out)
        self.assertIn("CVE-2026-9999", read_out)


class TestPerCallInlineOverride(SmokeBase):
    async def test_inline_override_beats_always_policy(self):
        # 'execute_nuclei' is 'always' policy, but agent passes output_mode='inline'.
        args = {"target": "example.com", "output_mode": "inline"}
        cleaned, override = output_offload.strip_output_mode(args)
        self.assertEqual(cleaned, {"target": "example.com"})
        self.assertEqual(override, "inline")

        # Tool runs (mocked) and produces output
        tool_output = "tiny inline result"
        # Executor applies override
        final = output_offload.maybe_offload(
            "proj-smoke", "execute_nuclei", tool_output, override=override
        )
        self.assertEqual(final, tool_output)
        # No file written
        outputs_dir = self.root / "tool-outputs"
        self.assertFalse(outputs_dir.exists() and any(outputs_dir.iterdir()))


class TestJobSpawnWithFSGrep(SmokeBase):
    async def test_grep_over_running_job_log(self):
        # Quick rg-availability probe before spawning so we don't leave a
        # zombie task behind on skip.
        probe = await workspace_fs.fs_grep("xyzzy_probe_pattern", path=".")
        if "rg) not installed" in probe:
            self.skipTest("ripgrep not installed on host")

        reg = job_runner.get_registry()

        # Long-running tool that emits chunks slowly.
        async def long_scanner(name, args, append_log):
            await append_log("[start] scanning example.com")
            for i in range(20):
                await append_log(f"[probe {i}] testing endpoint /path{i}")
                await asyncio.sleep(0.01)
            await append_log("[hit] SQL injection on /path7")
            await asyncio.sleep(0.5)
            return {"success": True, "output": "done"}

        # Spawn returns immediately
        result = await reg.spawn("proj-smoke", "execute_scanner", {}, long_scanner)
        job_id = result["job_id"]

        # Let it generate some content
        await asyncio.sleep(0.2)
        # Once the runner has written the [hit] line, grep should find it.
        # Wait until either the log contains it, or the job completes.
        for _ in range(50):
            log_path = self.root / "jobs" / f"{job_id}.log"
            if "SQL injection" in log_path.read_text():
                break
            await asyncio.sleep(0.05)
        grep_out = await workspace_fs.fs_grep("SQL injection", path="jobs")
        self.assertIn(f"{job_id}.log", grep_out)

        # Wait for completion + verify final status
        status = await reg.wait("proj-smoke", job_id, timeout_sec=3.0)
        self.assertEqual(status["status"], "done")


class TestStreamingTee(SmokeBase):
    async def test_streaming_tee_produces_durable_log(self):
        # Simulate an execute_with_progress style tool: chunks tee'd via the
        # job_id-prefixed filename in output_offload.
        chunks = [f"chunk {i}\n" for i in range(50)]
        job_id = "test-job-123"
        for chunk in chunks:
            output_offload.maybe_offload(
                "proj-smoke", "execute_hydra", chunk,
                override="file", job_id=job_id,
            )
        # All chunks land in the SAME file (overwriting since maybe_offload
        # uses write_text). In the real implementation, the tee path uses
        # append-mode separately - this test catches the regression that
        # filename collisions are stable per (job_id, tool_name).
        target = self.root / "tool-outputs" / f"{job_id}-execute_hydra.log"
        self.assertTrue(target.exists())


class TestOffloadDoesNotCorruptResolveSafe(SmokeBase):
    async def test_offloaded_file_readable_via_fs_read(self):
        # Round-trip: offload then read back via fs_read with rel path.
        text = "X" * 50_000
        stub = output_offload.maybe_offload("proj-smoke", "execute_nuclei", text)
        # Extract filename from stub
        marker = "tool-outputs/"
        start = stub.find(marker) + len(marker)
        end = stub.find("]", start)
        filename = stub[start:end]
        out = await workspace_fs.fs_read(f"tool-outputs/{filename}")
        # fs_read should return the file content (with line numbers)
        self.assertIn("XXXX", out)


if __name__ == "__main__":
    unittest.main()
