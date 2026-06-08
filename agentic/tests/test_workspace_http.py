"""
Unit + safety tests for the Phase-4 HTTP-shape helpers in workspace_fs.py.

These functions back the /workspace/* FastAPI routes. Testing them directly
(without standing up the FastAPI app) keeps tests host-runnable: fastapi is
not installed locally but workspace_fs is pure-stdlib.

Covers:
  - resolve_for_project rejects traversal (.. + absolute outside)
  - resolve_for_project requires non-empty project_id
  - list_dir_for_project returns the structured shape the drawer expects
  - tree_for_project respects max_depth and max_entries
  - download_for_project returns bytes + correct mime
  - rename_for_project rejects /-bearing or .. names and existing destinations
  - delete_for_project enforces recursive flag for dirs
  - Per-project isolation: project A cannot see project B's files

Run with: python3 -m unittest tests.test_workspace_http -v
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import workspace_fs  # noqa: E402


class HttpHelperTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-ws-http-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)

    def tearDown(self):
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, project_id: str, files: dict[str, bytes]) -> Path:
        root = workspace_fs.resolve_for_project(project_id, ".")  # creates subdirs
        for rel, content in files.items():
            full = root / rel
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(content)
        return root


# =============================================================================
# resolve_for_project (security boundary)
# =============================================================================

class TestResolveForProject(HttpHelperTestBase):
    def test_requires_project_id(self):
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project("", ".")
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project(None, ".")

    def test_rejects_parent_traversal(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project("p1", "../escape.txt")

    def test_rejects_absolute_path_outside(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.resolve_for_project("p1", "/etc/passwd")

    def test_allows_absolute_inside_workspace(self):
        root = self._seed("p1", {"notes/a.txt": b"hi"})
        abs_path = str(root / "notes" / "a.txt")
        resolved = workspace_fs.resolve_for_project("p1", abs_path)
        self.assertEqual(resolved.name, "a.txt")

    def test_auto_creates_default_subdirs(self):
        root = workspace_fs.resolve_for_project("p1", ".")
        for sub in ("notes", "tool-outputs", "jobs", "uploads"):
            self.assertTrue((root / sub).is_dir(), f"missing {sub}")

    def test_no_contextvar_dependency(self):
        # Helper must work without any contextvar being set - that's the
        # whole point (HTTP layer should not have to fiddle with contextvars).
        import agent_context
        agent_context.current_project_id.set("")  # explicit empty
        root = workspace_fs.resolve_for_project("p1", ".")
        self.assertTrue(root.exists())


# =============================================================================
# list_dir_for_project
# =============================================================================

class TestListDir(HttpHelperTestBase):
    def test_returns_structured_entries(self):
        self._seed("p1", {"notes/a.md": b"hi", "notes/b.txt": b"world"})
        entries = workspace_fs.list_dir_for_project("p1", "notes")
        names = [e["name"] for e in entries]
        self.assertIn("a.md", names)
        self.assertIn("b.txt", names)
        for e in entries:
            for required in ("name", "path", "isDir", "isSymlink", "size", "mtime"):
                self.assertIn(required, e, f"entry missing {required}: {e}")

    def test_dirs_sorted_before_files(self):
        self._seed("p1", {"notes/zzz.txt": b"x"})
        # Pre-create a dir AFTER the file so default ordering would put files first
        (workspace_fs.WORKSPACE_ROOT / "p1" / "notes" / "aaa").mkdir()
        entries = workspace_fs.list_dir_for_project("p1", "notes")
        kinds = [e["isDir"] for e in entries]
        # All True (dirs) should precede all False (files)
        false_started = False
        for k in kinds:
            if not k:
                false_started = True
            elif false_started:
                self.fail(f"dir appeared after file in: {[(e['name'], e['isDir']) for e in entries]}")

    def test_relative_path_is_relative_to_project_root(self):
        self._seed("p1", {"notes/sub/x.txt": b"v"})
        entries = workspace_fs.list_dir_for_project("p1", "notes/sub")
        x = next(e for e in entries if e["name"] == "x.txt")
        self.assertEqual(x["path"], "notes/sub/x.txt")
        # Path must NOT be absolute - the drawer renders it as a relative URL.
        self.assertFalse(x["path"].startswith("/"))

    def test_not_a_directory_raises(self):
        self._seed("p1", {"notes/file.txt": b"x"})
        with self.assertRaises(ValueError):
            workspace_fs.list_dir_for_project("p1", "notes/file.txt")

    def test_path_traversal_rejected(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.list_dir_for_project("p1", "../..")


# =============================================================================
# tree_for_project
# =============================================================================

class TestTreeForProject(HttpHelperTestBase):
    def test_respects_max_depth(self):
        self._seed("p1", {
            "a/b/c/d/e.txt": b"x",
            "a/sibling.txt": b"y",
        })
        out = workspace_fs.tree_for_project("p1", ".", max_depth=2)
        self.assertIn("a/", out)
        self.assertIn("sibling.txt", out)
        # Depth 4 children should NOT appear
        self.assertNotIn("e.txt", out)

    def test_truncates_at_max_entries(self):
        files = {f"notes/file{i}.txt": b"x" for i in range(20)}
        self._seed("p1", files)
        out = workspace_fs.tree_for_project("p1", "notes", max_depth=2, max_entries=10)
        self.assertIn("[truncated at 10 entries]", out)


# =============================================================================
# download_for_project
# =============================================================================

class TestDownload(HttpHelperTestBase):
    def test_returns_bytes_and_mime(self):
        self._seed("p1", {"notes/hello.txt": b"hello world"})
        content, mime = workspace_fs.download_for_project("p1", "notes/hello.txt")
        self.assertEqual(content, b"hello world")
        self.assertEqual(mime, "text/plain")

    def test_pdf_gets_pdf_mime(self):
        self._seed("p1", {"notes/report.pdf": b"%PDF-1.4"})
        _, mime = workspace_fs.download_for_project("p1", "notes/report.pdf")
        self.assertEqual(mime, "application/pdf")

    def test_unknown_extension_defaults_to_octet_stream(self):
        self._seed("p1", {"notes/blob.weird": b"\x00\x01"})
        _, mime = workspace_fs.download_for_project("p1", "notes/blob.weird")
        self.assertEqual(mime, "application/octet-stream")

    def test_directory_rejected(self):
        self._seed("p1", {"notes/x.txt": b"x"})
        with self.assertRaises(ValueError):
            workspace_fs.download_for_project("p1", "notes")

    def test_traversal_rejected(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.download_for_project("p1", "../../etc/passwd")


# =============================================================================
# rename_for_project
# =============================================================================

class TestRename(HttpHelperTestBase):
    def test_happy_rename(self):
        self._seed("p1", {"notes/old.txt": b"v"})
        new_rel = workspace_fs.rename_for_project("p1", "notes/old.txt", "new.txt")
        self.assertEqual(new_rel, "notes/new.txt")
        root = workspace_fs.WORKSPACE_ROOT / "p1"
        self.assertFalse((root / "notes/old.txt").exists())
        self.assertTrue((root / "notes/new.txt").exists())

    def test_rejects_slash_in_new_name(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "../escape.txt")
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "sub/x.txt")

    def test_rejects_dot_new_name(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "..")
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", ".")

    def test_rejects_empty_new_name(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "")

    def test_rejects_existing_destination(self):
        self._seed("p1", {"notes/a.txt": b"v", "notes/b.txt": b"w"})
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "b.txt")

    def test_rejects_missing_source(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "ghost.txt", "anything.txt")


# =============================================================================
# delete_for_project
# =============================================================================

class TestDelete(HttpHelperTestBase):
    def test_file_delete(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        workspace_fs.delete_for_project("p1", "notes/a.txt")
        self.assertFalse((workspace_fs.WORKSPACE_ROOT / "p1" / "notes" / "a.txt").exists())

    def test_dir_requires_recursive(self):
        self._seed("p1", {"notes/sub/x.txt": b"v"})
        with self.assertRaises(ValueError):
            workspace_fs.delete_for_project("p1", "notes/sub")
        # With recursive=True it works
        workspace_fs.delete_for_project("p1", "notes/sub", recursive=True)
        self.assertFalse((workspace_fs.WORKSPACE_ROOT / "p1" / "notes" / "sub").exists())

    def test_missing_path_rejected(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.delete_for_project("p1", "ghost.txt")

    def test_traversal_rejected(self):
        self._seed("p1", {})
        with self.assertRaises(ValueError):
            workspace_fs.delete_for_project("p1", "../../etc/passwd")


# =============================================================================
# Project isolation
# =============================================================================

class TestProjectIsolation(HttpHelperTestBase):
    def test_list_does_not_see_other_projects(self):
        self._seed("p1", {"notes/only-in-p1.txt": b"x"})
        self._seed("p2", {"notes/only-in-p2.txt": b"y"})
        p1_names = [e["name"] for e in workspace_fs.list_dir_for_project("p1", "notes")]
        p2_names = [e["name"] for e in workspace_fs.list_dir_for_project("p2", "notes")]
        self.assertIn("only-in-p1.txt", p1_names)
        self.assertNotIn("only-in-p2.txt", p1_names)
        self.assertIn("only-in-p2.txt", p2_names)
        self.assertNotIn("only-in-p1.txt", p2_names)

    def test_download_cannot_cross_projects_via_traversal(self):
        self._seed("p1", {"notes/secret.txt": b"P1-SECRET"})
        self._seed("p2", {})
        # Attempt to read p1's file via p2's project context with a traversal path
        with self.assertRaises(ValueError):
            workspace_fs.download_for_project("p2", "../p1/notes/secret.txt")


if __name__ == "__main__":
    unittest.main()
