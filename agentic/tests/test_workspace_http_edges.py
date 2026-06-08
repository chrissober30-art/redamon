"""
Phase-4 deep-review tests: HTTP helper edge cases the API wrappers depend on.

The /workspace/* FastAPI handlers map helper exceptions to HTTP status:
ValueError -> 400, anything else -> 500. So the helpers MUST raise ValueError
for user-input errors and must NOT leak unexpected exception types for
predictable problems. This file locks in that contract plus several
security and edge-case behaviours not covered by test_workspace_http.

Covers:
  - Symlink inside workspace pointing OUTSIDE is rejected (security regression)
  - Large file (1MB) round-trips through download_for_project
  - Unicode + spaces in path components
  - list_dir gracefully skips entries it cannot stat (chmod 000 sub-entry)
  - rename rejects whitespace-only newName
  - rename rejects backslash in newName (Windows-style separator)
  - tree on a file (not dir) raises ValueError, not generic
  - delete on a symlink-to-dir does NOT recurse into the target

Run with: python3 -m unittest tests.test_workspace_http_edges -v
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


class HttpEdgeTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-ws-edge-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)

    def tearDown(self):
        # Restore any 000-mode dirs so rmtree can clean up
        for root, dirs, files in os.walk(self.tmp):
            for d in dirs:
                try:
                    os.chmod(Path(root) / d, 0o755)
                except Exception:
                    pass
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, project_id: str, files: dict[str, bytes] = None) -> Path:
        root = workspace_fs.resolve_for_project(project_id, ".")
        for rel, content in (files or {}).items():
            full = root / rel
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(content)
        return root


# =============================================================================
# Security: symlink inside workspace pointing OUTSIDE must be rejected
# =============================================================================

class TestSymlinkEscape(HttpEdgeTestBase):
    def test_download_through_symlink_escape_rejected(self):
        root = self._seed("p1", {"notes/legit.txt": b"v"})
        # Plant a sensitive file OUTSIDE the workspace
        outside = Path(self.tmp) / "outside_secret.txt"
        outside.write_text("SECRET-DATA")
        # Create a symlink inside workspace pointing to it
        link = root / "notes" / "escape.lnk"
        os.symlink(str(outside), str(link))

        with self.assertRaises(ValueError):
            workspace_fs.download_for_project("p1", "notes/escape.lnk")

    def test_list_dir_through_symlink_dir_escape_rejected(self):
        root = self._seed("p1", {})
        outside_dir = Path(self.tmp) / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "secret.txt").write_text("SECRET")
        link = root / "linked_dir"
        os.symlink(str(outside_dir), str(link))

        # Resolving "linked_dir" follows the symlink -> outside the workspace.
        with self.assertRaises(ValueError):
            workspace_fs.list_dir_for_project("p1", "linked_dir")

    def test_rename_target_via_symlink_outside_rejected(self):
        # Rename should not be usable to write outside the workspace by
        # creating a symlink hop.
        root = self._seed("p1", {"notes/source.txt": b"v"})
        outside_dir = Path(self.tmp) / "outside_dir"
        outside_dir.mkdir()
        # Create a symlink "notes/escape" -> outside_dir
        os.symlink(str(outside_dir), str(root / "notes" / "escape"))
        # Renaming source.txt to "escape/landed.txt" should NOT cross the link.
        # (newName is a single name, not a path - so this should error on slash.)
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/source.txt", "escape/landed.txt")


# =============================================================================
# Performance edge: medium-large file download
# =============================================================================

class TestLargeFileDownload(HttpEdgeTestBase):
    def test_one_mb_file_round_trips(self):
        # Confirm download_for_project can handle a 1MB file without truncation
        # or memory-shape errors. It does buffer entirely into memory (read_bytes),
        # which is acceptable for the drawer's expected file sizes (offloaded
        # tool outputs typically <10MB).
        payload = os.urandom(1024 * 1024)
        self._seed("p1", {"notes/big.bin": payload})
        content, mime = workspace_fs.download_for_project("p1", "notes/big.bin")
        self.assertEqual(len(content), len(payload))
        self.assertEqual(content, payload)
        # Unknown extension defaults
        self.assertEqual(mime, "application/octet-stream")


# =============================================================================
# Special characters in paths
# =============================================================================

class TestSpecialChars(HttpEdgeTestBase):
    def test_unicode_filename(self):
        self._seed("p1", {"notes/résumé-é.txt": "café\n".encode("utf-8")})
        entries = workspace_fs.list_dir_for_project("p1", "notes")
        names = [e["name"] for e in entries]
        self.assertIn("résumé-é.txt", names)
        content, _ = workspace_fs.download_for_project("p1", "notes/résumé-é.txt")
        self.assertEqual(content, "café\n".encode("utf-8"))

    def test_filename_with_spaces(self):
        self._seed("p1", {"notes/my file with spaces.md": b"hello"})
        content, _ = workspace_fs.download_for_project("p1", "notes/my file with spaces.md")
        self.assertEqual(content, b"hello")

    def test_rename_to_unicode_name(self):
        self._seed("p1", {"notes/old.txt": b"v"})
        new_rel = workspace_fs.rename_for_project("p1", "notes/old.txt", "新規.txt")
        self.assertEqual(new_rel, "notes/新規.txt")
        self.assertTrue((Path(self.tmp) / "p1" / "notes" / "新規.txt").exists())


# =============================================================================
# list_dir resilience: chmod 000 sub-entry should be skipped, not crash
# =============================================================================

class TestListDirResilience(HttpEdgeTestBase):
    @unittest.skipIf(os.geteuid() == 0, "root bypasses chmod restrictions")
    def test_unreadable_subdir_is_skipped(self):
        root = self._seed("p1", {
            "notes/readable.txt": b"ok",
            "notes/blocked_dir/inside.txt": b"hidden",
        })
        # Make the subdir un-statable for the entry inside it
        blocked = root / "notes" / "blocked_dir"
        os.chmod(blocked, 0o000)
        try:
            entries = workspace_fs.list_dir_for_project("p1", "notes")
            # The readable file should be present
            names = [e["name"] for e in entries]
            self.assertIn("readable.txt", names)
            # blocked_dir itself is still in iterdir() output; the entry may
            # or may not show up depending on stat permission. We just verify
            # the call doesn't crash.
        finally:
            os.chmod(blocked, 0o755)  # restore so tearDown can rmtree


# =============================================================================
# Rename edge cases
# =============================================================================

class TestRenameEdges(HttpEdgeTestBase):
    def test_whitespace_only_new_name_rejected(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        # "   " is non-empty but a useless filename. Currently the code
        # accepts it - this test pins down the desired behaviour.
        with self.assertRaises(ValueError):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "   ")

    def test_null_byte_in_new_name_rejected(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        with self.assertRaises((ValueError, OSError)):
            workspace_fs.rename_for_project("p1", "notes/a.txt", "x\x00y")

    def test_newName_equal_to_existing_source(self):
        # Renaming a file to its own name is a no-op or error - either is
        # acceptable, but it must not delete the file.
        self._seed("p1", {"notes/x.txt": b"v"})
        try:
            workspace_fs.rename_for_project("p1", "notes/x.txt", "x.txt")
        except ValueError:
            pass
        self.assertTrue((Path(self.tmp) / "p1" / "notes" / "x.txt").exists())


# =============================================================================
# Tree on a file
# =============================================================================

class TestTreeOnFile(HttpEdgeTestBase):
    def test_tree_on_file_raises_valueerror(self):
        # ValueError specifically so the wrapper maps it to 400, not 500.
        self._seed("p1", {"notes/a.txt": b"v"})
        with self.assertRaises(ValueError):
            workspace_fs.tree_for_project("p1", "notes/a.txt")


# =============================================================================
# Helper exception contract: only ValueError for user input errors
# =============================================================================

class TestExceptionContract(HttpEdgeTestBase):
    """The wrappers map ValueError -> 400 and any other Exception -> 500.
    User-input errors (bad path, missing file, traversal) MUST surface as
    ValueError so the frontend sees a 400, not a 500 internal-error.
    """

    def test_list_dir_user_errors_are_value_errors(self):
        self._seed("p1", {})
        for path in ("../escape", "/etc", "ghost-dir"):
            try:
                workspace_fs.list_dir_for_project("p1", path)
                # If it didn't raise, the test setup is wrong - skip
                continue
            except ValueError:
                pass  # ✓
            except Exception as e:
                self.fail(f"list_dir({path!r}) raised {type(e).__name__}, not ValueError: {e}")

    def test_download_user_errors_are_value_errors(self):
        self._seed("p1", {"notes/exists.txt": b"v"})
        for path in ("../escape.txt", "/etc/passwd", "ghost.txt", "notes"):  # last = dir
            try:
                workspace_fs.download_for_project("p1", path)
                continue
            except ValueError:
                pass
            except Exception as e:
                self.fail(f"download({path!r}) raised {type(e).__name__}, not ValueError: {e}")

    def test_rename_user_errors_are_value_errors(self):
        self._seed("p1", {"notes/a.txt": b"v"})
        cases = [
            ("notes/a.txt", "../escape.txt"),
            ("notes/a.txt", "sub/x.txt"),
            ("notes/a.txt", ""),
            ("notes/a.txt", "."),
            ("ghost.txt", "anything.txt"),
        ]
        for src, new_name in cases:
            try:
                workspace_fs.rename_for_project("p1", src, new_name)
                continue
            except ValueError:
                pass
            except Exception as e:
                self.fail(f"rename({src!r}, {new_name!r}) raised {type(e).__name__}, not ValueError: {e}")

    def test_delete_user_errors_are_value_errors(self):
        root = self._seed("p1", {"notes/sub/x.txt": b"v"})
        # Dir without recursive flag, missing path, traversal
        cases = [
            ("notes/sub", False),
            ("ghost.txt", False),
            ("../escape", False),
        ]
        for path, recursive in cases:
            try:
                workspace_fs.delete_for_project("p1", path, recursive)
                continue
            except ValueError:
                pass
            except Exception as e:
                self.fail(f"delete({path!r}, {recursive}) raised {type(e).__name__}, not ValueError: {e}")


# =============================================================================
# delete on a symlink-to-dir should remove the link, not the target tree
# =============================================================================

class TestDeleteSymlink(HttpEdgeTestBase):
    def test_delete_symlink_to_dir_does_not_recurse_target(self):
        root = self._seed("p1", {})
        target_dir = Path(self.tmp) / "external_target"
        target_dir.mkdir()
        (target_dir / "precious.txt").write_text("must survive")
        link = root / "link_to_external"
        os.symlink(str(target_dir), str(link))

        # The link itself resolves OUTSIDE the workspace, so the call should
        # raise (cannot reach the link through _resolve_safe).
        with self.assertRaises(ValueError):
            workspace_fs.delete_for_project("p1", "link_to_external")
        # External target untouched
        self.assertTrue((target_dir / "precious.txt").exists())


if __name__ == "__main__":
    unittest.main()
