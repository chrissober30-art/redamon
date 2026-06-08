"""
Stage-A deep-review tests: edge cases + security probes the happy-path
tests can't catch.

  - is_protected_path bypass via path normalization (./notes, notes//, etc.)
  - archive_dir_for_project must NOT follow symlinks (exfiltration risk)
  - Edge cases: empty upload, mkdir on existing file, preview/properties
    on unusual file states.

Run with: python3 -m unittest tests.test_stage_a_review -v
"""
from __future__ import annotations

import io
import os
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

import workspace_fs  # noqa: E402


class StageAReviewBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-stagea-rev-")
        self._orig_root = workspace_fs.WORKSPACE_ROOT
        self._orig_umask = os.umask(0)
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)

    def tearDown(self):
        os.umask(self._orig_umask)
        workspace_fs.WORKSPACE_ROOT = self._orig_root
        for p, dirs, files in os.walk(self.tmp):
            for d in dirs:
                try:
                    os.chmod(Path(p) / d, 0o777)
                except Exception:
                    pass
            for f in files:
                try:
                    os.chmod(Path(p) / f, 0o666)
                except Exception:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)


# =============================================================================
# Security: protected-path bypass via path normalization
# =============================================================================

class TestProtectedPathNormalization(StageAReviewBase):
    """Anyone sending `./notes` or `notes//` from the frontend would
    bypass is_protected_path because the simple split() check doesn't
    normalize first.

    Confirmed bypass attack chain:
        - Drawer sends DELETE /workspace?path=./notes
        - is_protected_path('./notes') returns False (bypass!)
        - resolve_for_project resolves to root/notes
        - shutil.rmtree wipes the protected default subdir

    These tests document the desired protection and will catch any
    fix that doesn't cover the normalization variants.
    """

    PROTECTED_VARIANTS = [
        "./notes",
        "./notes/",
        "notes/",
        "notes//",
        "//notes",
        "./tool-outputs",
        "jobs/",
        "./uploads/",
        "./",  # root, also protected
        "",
        ".",
    ]

    def test_normalized_protected_paths_all_blocked(self):
        for variant in self.PROTECTED_VARIANTS:
            self.assertTrue(
                workspace_fs.is_protected_path(variant),
                f"protected path variant {variant!r} should be blocked",
            )

    def test_delete_for_project_rejects_normalized_variants(self):
        workspace_fs.resolve_for_project("proj", ".")
        for variant in ("./notes", "./tool-outputs", "jobs/"):
            with self.assertRaises(ValueError,
                                   msg=f"delete via {variant!r} should be rejected"):
                workspace_fs.delete_for_project("proj", variant, recursive=True)
            # Subdir survives
            self.assertTrue(
                (Path(self.tmp) / "proj" / variant.strip("./")).is_dir(),
                f"protected subdir was deleted via {variant!r}",
            )

    def test_rename_for_project_rejects_normalized_variants(self):
        workspace_fs.resolve_for_project("proj", ".")
        for variant in ("./notes", "notes/"):
            with self.assertRaises(ValueError):
                workspace_fs.rename_for_project("proj", variant, "renamed")
            self.assertTrue((Path(self.tmp) / "proj" / "notes").is_dir())


# =============================================================================
# Security: archive_dir_for_project must NOT follow symlinks
# =============================================================================

class TestArchiveDoesNotFollowSymlinks(StageAReviewBase):
    """tarfile.add() follows symlinks by default. zipfile rglob includes
    symlinked dirs too. If a project's workspace contains a symlink
    pointing to /etc, archive_dir_for_project could include /etc/passwd
    in the tarball served to the user.

    Realistic attack: an attacker who can write into the workspace
    plants a symlink (via fs_symlink_create or via a kali_shell tool
    that writes there), then asks the drawer to download the parent
    folder as a tar.gz - the archive leaks the target.
    """

    def test_tar_does_not_include_symlink_target_content(self):
        root = workspace_fs.resolve_for_project("proj", ".")
        outside = Path(self.tmp) / "OUTSIDE_SECRET.txt"
        outside.write_text("CONFIDENTIAL")
        (root / "scan").mkdir()
        (root / "scan" / "legit.txt").write_text("ok")
        # Plant a symlink inside the project that points OUTSIDE
        link = root / "scan" / "leak.lnk"
        os.symlink(str(outside), str(link))

        archive_bytes, _ = workspace_fs.archive_dir_for_project("proj", "scan")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            # Extract member contents in-memory and confirm CONFIDENTIAL
            # never appears - regardless of how the symlink is stored.
            for m in tf.getmembers():
                if m.isfile():
                    f = tf.extractfile(m)
                    if f is not None:
                        body = f.read()
                        self.assertNotIn(
                            b"CONFIDENTIAL", body,
                            f"Symlink target leaked through tar member {m.name!r}",
                        )

    def test_zip_does_not_include_symlink_target_content(self):
        root = workspace_fs.resolve_for_project("proj", ".")
        outside = Path(self.tmp) / "OUTSIDE_SECRET.txt"
        outside.write_text("CONFIDENTIAL")
        (root / "scan").mkdir()
        (root / "scan" / "legit.txt").write_text("ok")
        link = root / "scan" / "leak.lnk"
        os.symlink(str(outside), str(link))

        archive_bytes, _ = workspace_fs.archive_dir_for_project(
            "proj", "scan", format="zip",
        )
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for name in zf.namelist():
                body = zf.read(name)
                self.assertNotIn(
                    b"CONFIDENTIAL", body,
                    f"Symlink target leaked through zip entry {name!r}",
                )


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases(StageAReviewBase):
    def test_upload_empty_file(self):
        workspace_fs.resolve_for_project("proj", ".")
        new_path = workspace_fs.upload_for_project(
            "proj", "uploads", b"", "empty.txt",
        )
        self.assertEqual(new_path, "uploads/empty.txt")
        target = Path(self.tmp) / "proj" / "uploads" / "empty.txt"
        self.assertEqual(target.read_bytes(), b"")

    def test_upload_unicode_filename(self):
        workspace_fs.resolve_for_project("proj", ".")
        new_path = workspace_fs.upload_for_project(
            "proj", "uploads", b"v", "résumé café.txt",
        )
        self.assertEqual(new_path, "uploads/résumé café.txt")

    def test_mkdir_on_existing_file_raises(self):
        # Plant a regular file, then try to mkdir at the same path.
        root = workspace_fs.resolve_for_project("proj", ".")
        (root / "collision").write_bytes(b"v")
        with self.assertRaises(ValueError):
            workspace_fs.mkdir_for_project("proj", "collision")

    def test_archive_empty_directory(self):
        root = workspace_fs.resolve_for_project("proj", ".")
        (root / "empty").mkdir()
        archive_bytes, _ = workspace_fs.archive_dir_for_project("proj", "empty")
        # Should be a valid tarball with just the dir entry (or empty).
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            names = tf.getnames()
        # Must include the dir itself (or be empty); must not raise.
        for n in names:
            self.assertTrue(n.startswith("empty"), f"unexpected member {n}")

    def test_properties_on_broken_symlink(self):
        # Symlink to a path that doesn't exist
        root = workspace_fs.resolve_for_project("proj", ".")
        os.symlink(str(root / "ghost"), str(root / "notes" / "broken"))
        props = workspace_fs.properties_for_project("proj", "notes/broken")
        self.assertEqual(props["type"], "symlink")
        self.assertIn("target", props)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses chmod restrictions")
    def test_preview_unreadable_file_surfaces_clean_error(self):
        # File with mode 0 cannot be opened
        root = workspace_fs.resolve_for_project("proj", ".")
        target = root / "notes" / "locked.txt"
        target.write_bytes(b"secret")
        os.chmod(target, 0o000)
        try:
            with self.assertRaises((ValueError, PermissionError, OSError)):
                workspace_fs.preview_for_project("proj", "notes/locked.txt")
        finally:
            os.chmod(target, 0o600)  # let tearDown clean up


if __name__ == "__main__":
    unittest.main()
