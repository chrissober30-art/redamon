"""
Regression tests for Phase-6 bug #14 fix (workspace files host-writability).

The agent container runs as root, but the bind-mount `agent-workspace/` is
host-owned (typically UID 1000). Without intervention, files the agent
creates would be root:root mode 644/755, blocking host-side rm/edit and
breaking the plan's "browsable from the host" promise.

The fix is `os.umask(0)` at the top of api.py's lifespan, which causes
all subsequent file creation in the agent process to use mode 666 (files)
and 777 (dirs). Host user can then rm/edit despite ownership being root.

These tests protect that fix from accidental removal AND verify the
workspace_fs helpers produce the expected modes when umask is 0.

Run with: python3 -m unittest tests.test_phase6_umask_regression -v
"""
from __future__ import annotations

import asyncio
import io
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import agent_context  # noqa: E402
import job_runner  # noqa: E402
import output_offload  # noqa: E402
import workspace_fs  # noqa: E402


# =============================================================================
# Static regression: the umask call must remain in api.py lifespan
# =============================================================================

class TestUmaskCallStillPresent(unittest.TestCase):
    """If someone refactors api.py and removes os.umask(0), this fires.

    The check is source-text-based because api.py imports langgraph and the
    full orchestrator stack, which won't load on the host (only in container).
    """

    # Regex tolerates spacing + alternate zero literals: os.umask(0),
    # os.umask( 0 ), os.umask(0o000), os.umask(0o0), os.umask(value=0).
    UMASK_ZERO_RE = re.compile(
        r"os\.umask\(\s*(?:value\s*=\s*)?(?:0|0o0+)\s*\)"
    )

    def test_api_py_lifespan_calls_umask_zero(self):
        api_path = Path(_AGENTIC_DIR) / "api.py"
        src = api_path.read_text()
        match = self.UMASK_ZERO_RE.search(src)
        self.assertIsNotNone(
            match,
            "Phase-6 bug #14 regression: os.umask(0) must be set in api.py "
            "lifespan, otherwise workspace files end up root:root on host "
            "and the user can't rm/edit them."
        )
        # And it must be in the lifespan body, not in some commented-out spot
        lifespan_idx = src.find("async def lifespan(app: FastAPI)")
        self.assertGreater(lifespan_idx, 0, "lifespan() function not found")
        umask_idx = match.start()
        self.assertGreater(umask_idx, lifespan_idx,
                           "os.umask zero call must appear inside lifespan(), not before/after")
        # And it must be before `yield` (i.e. in the startup half, not shutdown)
        yield_idx = src.find("yield", lifespan_idx)
        self.assertLess(umask_idx, yield_idx,
                        "os.umask zero call must run at startup, before lifespan yield")


# =============================================================================
# Mode verification under umask 0: workspace files end up world-writable
# =============================================================================

class TestWorkspaceFileModesUnderUmaskZero(unittest.TestCase):
    """With umask 0 (as set in production by api.py lifespan), confirm the
    workspace_fs helpers produce dirs at 0o777 and files at 0o666."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-phase6-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        self._orig_umask = os.umask(0)  # mirror production
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        agent_context.current_project_id.set("perm-test")

    def tearDown(self):
        os.umask(self._orig_umask)
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        # Restore mode so rmtree can clean even root-owned dirs
        for p, dirs, files in os.walk(self.tmp):
            for d in dirs:
                try:
                    os.chmod(Path(p) / d, 0o777)
                except Exception:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)
        agent_context.current_project_id.set("")

    def _mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    async def _async_fs_write(self):
        return await workspace_fs.fs_write("created.txt", "hello")

    def test_project_root_dir_is_0777(self):
        # Trigger auto-creation by resolving the project root
        root = workspace_fs.resolve_for_project("perm-test", ".")
        self.assertEqual(self._mode(root), 0o777,
                         f"project root should be 0o777, got {oct(self._mode(root))}")

    def test_default_subdirs_are_0777(self):
        workspace_fs.resolve_for_project("perm-test", ".")
        root = Path(self.tmp) / "perm-test"
        for sub in ("notes", "tool-outputs", "jobs", "uploads"):
            d = root / sub
            self.assertEqual(self._mode(d), 0o777,
                             f"{sub} should be 0o777, got {oct(self._mode(d))}")

    def test_fs_write_creates_file_mode_0666(self):
        asyncio.run(self._async_fs_write())
        written = Path(self.tmp) / "perm-test" / "created.txt"
        self.assertTrue(written.exists())
        self.assertEqual(self._mode(written), 0o666,
                         f"fs_write file should be 0o666, got {oct(self._mode(written))}")

    def test_fs_edit_preserves_file_mode_0666(self):
        # fs_edit does atomic tmp+replace; the replace must not regress
        # the file mode to system default (644).
        asyncio.run(workspace_fs.fs_write("e.txt", "alpha"))
        asyncio.run(workspace_fs.fs_edit("e.txt", "alpha", "beta"))
        edited = Path(self.tmp) / "perm-test" / "e.txt"
        self.assertEqual(self._mode(edited), 0o666,
                         f"fs_edit file should stay 0o666, got {oct(self._mode(edited))}")

    def test_fs_multi_edit_preserves_file_mode_0666(self):
        asyncio.run(workspace_fs.fs_write("m.txt", "a b c"))
        asyncio.run(workspace_fs.fs_multi_edit("m.txt", [
            {"old_string": "a", "new_string": "A"},
            {"old_string": "b", "new_string": "B"},
        ]))
        edited = Path(self.tmp) / "perm-test" / "m.txt"
        self.assertEqual(self._mode(edited), 0o666)

    def test_fs_mkdir_creates_dir_mode_0777(self):
        asyncio.run(workspace_fs.fs_mkdir("custom/deep"))
        created = Path(self.tmp) / "perm-test" / "custom" / "deep"
        self.assertTrue(created.is_dir())
        self.assertEqual(self._mode(created), 0o777,
                         f"fs_mkdir should produce 0o777, got {oct(self._mode(created))}")

    def test_fs_archive_tarball_is_0666(self):
        asyncio.run(workspace_fs.fs_write("a.txt", "1"))
        asyncio.run(workspace_fs.fs_archive(["a.txt"], "bundle.tar.gz"))
        archive = Path(self.tmp) / "perm-test" / "bundle.tar.gz"
        self.assertTrue(archive.exists())
        self.assertEqual(self._mode(archive), 0o666,
                         f"fs_archive output should be 0o666, got {oct(self._mode(archive))}")

    def test_fs_archive_zip_is_0666(self):
        asyncio.run(workspace_fs.fs_write("a.txt", "1"))
        asyncio.run(workspace_fs.fs_archive(["a.txt"], "bundle.zip", format="zip"))
        archive = Path(self.tmp) / "perm-test" / "bundle.zip"
        self.assertEqual(self._mode(archive), 0o666)

    def test_fs_copy_recursive_normalizes_modes_in_tree(self):
        # Plant a restrictive tree: dir 0o700, file 0o600.
        asyncio.run(workspace_fs.fs_mkdir("."))
        root = Path(self.tmp) / "perm-test"
        srcdir = root / "src"
        srcdir.mkdir()
        (srcdir / "inner.txt").write_bytes(b"v")
        (srcdir / "sub").mkdir()
        (srcdir / "sub" / "deep.txt").write_bytes(b"d")
        os.chmod(srcdir / "inner.txt", 0o600)
        os.chmod(srcdir / "sub" / "deep.txt", 0o600)
        os.chmod(srcdir / "sub", 0o700)
        os.chmod(srcdir, 0o700)

        asyncio.run(workspace_fs.fs_copy("src", "dst", recursive=True))
        dst = root / "dst"
        # All dirs in copied tree -> 0o777
        self.assertEqual(self._mode(dst), 0o777)
        self.assertEqual(self._mode(dst / "sub"), 0o777)
        # All files in copied tree -> 0o666
        self.assertEqual(self._mode(dst / "inner.txt"), 0o666)
        self.assertEqual(self._mode(dst / "sub" / "deep.txt"), 0o666)

    def test_fs_copy_promotes_to_0666_even_from_restricted_source(self):
        # shutil.copy2 PRESERVES source mode. If host user uploaded a file
        # at mode 0o600 (or a tool wrote it at 0o644), the copy stays
        # restrictive - breaking the "host-editable" promise. This test
        # locks in the desired behaviour: workspace files are 0o666
        # regardless of where they came from.
        restricted = Path(self.tmp) / "perm-test" / "src.txt"
        # Auto-create the project dir first
        asyncio.run(workspace_fs.fs_mkdir("."))
        restricted.write_bytes(b"v")
        os.chmod(restricted, 0o600)
        asyncio.run(workspace_fs.fs_copy("src.txt", "dst.txt"))
        copied = Path(self.tmp) / "perm-test" / "dst.txt"
        self.assertEqual(
            self._mode(copied), 0o666,
            f"fs_copy must override source mode to 0o666 so host can edit; "
            f"got {oct(self._mode(copied))} (source was 0o600)"
        )

    def test_fs_extract_zip_entries_are_0666(self):
        # Build a zip whose inner file has a restrictive mode, then extract.
        # Extracted files should be normalised to 0o666.
        # First create the workspace via a benign fs op.
        asyncio.run(workspace_fs.fs_mkdir("."))
        root = Path(self.tmp) / "perm-test"
        # Build the zip on the host filesystem (outside workspace_fs's create path)
        zpath = root / "in.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            info = zipfile.ZipInfo("inner.txt")
            info.external_attr = 0o600 << 16  # restrictive
            zf.writestr(info, b"hello")
        asyncio.run(workspace_fs.fs_extract("in.zip", "out"))
        extracted = root / "out" / "inner.txt"
        self.assertTrue(extracted.exists())
        self.assertEqual(
            self._mode(extracted), 0o666,
            f"fs_extract must override entry mode to 0o666; "
            f"got {oct(self._mode(extracted))}"
        )


# =============================================================================
# output_offload + job_runner write paths must also produce 0o666 files
# =============================================================================

class TestOffloadAndJobModes(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-phase6b-")
        self._orig_off = output_offload.WORKSPACE_ROOT
        self._orig_jr = job_runner.WORKSPACE_ROOT
        self._orig_umask = os.umask(0)
        output_offload.WORKSPACE_ROOT = Path(self.tmp)
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        job_runner._registry = None

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
        os.umask(self._orig_umask)
        output_offload.WORKSPACE_ROOT = self._orig_off
        job_runner.WORKSPACE_ROOT = self._orig_jr
        job_runner._registry = None
        for p, dirs, files in os.walk(self.tmp):
            for d in dirs:
                try:
                    os.chmod(Path(p) / d, 0o777)
                except Exception:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    async def test_offloaded_file_is_0666(self):
        # 100k chars > threshold; force offload via 'always' policy
        out = output_offload.maybe_offload("proj", "execute_nuclei", "X" * 100_000)
        self.assertIn("[Output offloaded:", out)
        outputs_dir = Path(self.tmp) / "proj" / "tool-outputs"
        files = list(outputs_dir.iterdir())
        self.assertEqual(len(files), 1)
        self.assertEqual(
            self._mode(files[0]), 0o666,
            f"offload file should be 0o666, got {oct(self._mode(files[0]))}"
        )

    async def test_job_log_and_meta_are_0666(self):
        reg = job_runner.get_registry()

        async def quick(name, args, append_log):
            await append_log("hi")
            return {"success": True, "output": "done"}

        result = await reg.spawn("proj", "fake_tool", {}, quick)
        await reg.wait("proj", result["job_id"], timeout_sec=2.0)

        jobs_dir = Path(self.tmp) / "proj" / "jobs"
        log_path = jobs_dir / f"{result['job_id']}.log"
        meta_path = jobs_dir / f"{result['job_id']}.meta.json"
        self.assertTrue(log_path.exists())
        self.assertTrue(meta_path.exists())
        self.assertEqual(self._mode(log_path), 0o666,
                         f"job log should be 0o666, got {oct(self._mode(log_path))}")
        self.assertEqual(self._mode(meta_path), 0o666,
                         f"job meta should be 0o666, got {oct(self._mode(meta_path))}")


if __name__ == "__main__":
    unittest.main()
