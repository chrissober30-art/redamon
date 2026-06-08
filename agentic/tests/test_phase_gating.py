"""
Unit + regression tests for project_settings.is_tool_allowed_in_phase()
after the Phase-2 fs_*/job_* foundational-tool bypass was added.

Covers:
  - fs_* and job_* are allowed in every phase (foundational bypass)
  - Pre-existing TOOL_PHASE_MAP entries still work (regression)
  - Unknown tool with no manifest entry still returns False (regression)
  - Bypass uses prefix match - 'fs_x' / 'job_x' work, 'fsx' / 'fooFs' don't

Run with: python3 -m unittest tests.test_phase_gating -v
"""
from __future__ import annotations

import os
import sys
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import project_settings  # noqa: E402


class TestFoundationalBypass(unittest.TestCase):
    def test_every_fs_tool_allowed_in_every_phase(self):
        fs_tools = [
            "fs_read", "fs_write", "fs_edit", "fs_multi_edit", "fs_undo_edit",
            "fs_delete", "fs_move", "fs_copy", "fs_mkdir", "fs_chmod",
            "fs_symlink_create", "fs_grep", "fs_glob", "fs_find", "fs_list",
            "fs_tree", "fs_symbols", "fs_symlink_read", "fs_hash", "fs_diff",
            "fs_extract", "fs_archive", "fs_stat", "fs_read_many",
        ]
        for tool in fs_tools:
            for phase in ("informational", "exploitation", "post_exploitation"):
                self.assertTrue(
                    project_settings.is_tool_allowed_in_phase(tool, phase),
                    f"{tool} should be allowed in {phase}",
                )

    def test_every_job_tool_allowed_in_every_phase(self):
        for tool in ("job_spawn", "job_status", "job_wait", "job_cancel", "job_list"):
            for phase in ("informational", "exploitation", "post_exploitation"):
                self.assertTrue(
                    project_settings.is_tool_allowed_in_phase(tool, phase),
                    f"{tool} should be allowed in {phase}",
                )

    def test_bypass_is_prefix_match_not_substring(self):
        # 'fsx' or 'fooFs' must NOT match the fs_ prefix bypass.
        self.assertFalse(project_settings.is_tool_allowed_in_phase("fsx", "informational"))
        self.assertFalse(project_settings.is_tool_allowed_in_phase("fooFs_read", "informational"))
        self.assertFalse(project_settings.is_tool_allowed_in_phase("xjob_spawn", "informational"))

    def test_arbitrary_phase_string_still_allowed_for_fs(self):
        # The bypass returns True regardless of phase string - even garbage phases.
        # This is intentional: fs_* shouldn't care about phase at all.
        self.assertTrue(project_settings.is_tool_allowed_in_phase("fs_read", "nonsense"))


class TestRegressionPreservedNonFsBehaviour(unittest.TestCase):
    def setUp(self):
        # Force the cached settings to a known map so we don't depend on
        # whatever was loaded from postgres earlier.
        project_settings._settings = {
            "TOOL_PHASE_MAP": {
                "execute_hydra": ["exploitation", "post_exploitation"],
                "query_graph": ["informational", "exploitation", "post_exploitation"],
            },
        }
        project_settings._current_project_id = "test-cached"

    def tearDown(self):
        project_settings._settings = None
        project_settings._current_project_id = None

    def test_hydra_rejected_in_informational(self):
        self.assertFalse(
            project_settings.is_tool_allowed_in_phase("execute_hydra", "informational")
        )

    def test_hydra_allowed_in_exploitation(self):
        self.assertTrue(
            project_settings.is_tool_allowed_in_phase("execute_hydra", "exploitation")
        )

    def test_query_graph_allowed_in_all(self):
        for phase in ("informational", "exploitation", "post_exploitation"):
            self.assertTrue(
                project_settings.is_tool_allowed_in_phase("query_graph", phase)
            )

    def test_unknown_tool_rejected_when_not_in_map_and_not_in_manifest(self):
        # An unknown tool (no map entry, no manifest entry) should still be
        # rejected. The Phase-2 bypass MUST NOT have widened this gate.
        self.assertFalse(
            project_settings.is_tool_allowed_in_phase("totally_unknown_tool", "informational")
        )


class TestGetAllowedToolsIncludesFoundational(unittest.TestCase):
    """BUG #20a regression: get_allowed_tools_for_phase (which builds the
    LLM's visible-tools enum) must include fs_*/job_* tools. Without this,
    the LLM literally doesn't know they exist and falls back to
    `kali_shell mkdir` for filesystem ops - defeating project scoping and
    the workspace umask discipline."""

    def setUp(self):
        project_settings._settings = {
            "TOOL_PHASE_MAP": {
                "execute_curl": ["informational", "exploitation", "post_exploitation"],
                "kali_shell": ["informational", "exploitation", "post_exploitation"],
            },
        }
        project_settings._current_project_id = "test-cached"

    def tearDown(self):
        project_settings._settings = None
        project_settings._current_project_id = None

    def test_fs_tools_present_in_each_phase(self):
        for phase in ("informational", "exploitation", "post_exploitation"):
            allowed = set(project_settings.get_allowed_tools_for_phase(phase))
            for fs_tool in ("fs_read", "fs_write", "fs_mkdir", "fs_grep",
                            "fs_edit", "fs_extract"):
                self.assertIn(
                    fs_tool, allowed,
                    f"{fs_tool} missing from allowed_tools for phase {phase!r} - "
                    f"LLM enum would omit it (bug #20a regression)",
                )

    def test_job_tools_present_in_each_phase(self):
        for phase in ("informational", "exploitation", "post_exploitation"):
            allowed = set(project_settings.get_allowed_tools_for_phase(phase))
            for job_tool in ("job_spawn", "job_status", "job_wait",
                             "job_cancel", "job_list"):
                self.assertIn(
                    job_tool, allowed,
                    f"{job_tool} missing from allowed_tools for phase {phase!r}",
                )

    def test_existing_map_tools_still_present(self):
        # Non-regression: the fix mustn't have crowded out the existing entries.
        allowed = set(project_settings.get_allowed_tools_for_phase("informational"))
        self.assertIn("execute_curl", allowed)
        self.assertIn("kali_shell", allowed)


if __name__ == "__main__":
    unittest.main()
