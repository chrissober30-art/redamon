"""Tests for the Anthropic prompt-caching infrastructure (FAPP-55).

Pins the contract: REACT_SYSTEM_PROMPT contains the cache-prefix marker at
the correct boundary, and partitioning on that marker produces a clean
static prefix (no per-iteration interpolation) plus a dynamic suffix.

The runtime behaviour (cache_read > 0 on iterations 2-10) is not tested
here — that requires an active Anthropic API key and is verified at
operator runtime per the FIX_REPORT.md testing notes.
"""

from __future__ import annotations

import os
import sys
import unittest

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from prompts.base import REACT_SYSTEM_PROMPT, CACHE_PREFIX_END_MARKER  # noqa: E402


class PromptCachingMarkerTests(unittest.TestCase):

    def test_marker_constant_is_nonempty_opaque_string(self):
        """The marker must be distinctive enough not to collide with prompt
        content. Picked an underscore-bracketed sentinel; assert basic shape."""
        self.assertIsInstance(CACHE_PREFIX_END_MARKER, str)
        self.assertGreater(len(CACHE_PREFIX_END_MARKER), 8)
        self.assertIn("<<", CACHE_PREFIX_END_MARKER)
        self.assertIn(">>", CACHE_PREFIX_END_MARKER)

    def test_marker_is_present_exactly_once_in_template(self):
        """The marker must appear exactly once — multiple occurrences would
        confuse the partition()-based split in think_node."""
        self.assertEqual(REACT_SYSTEM_PROMPT.count(CACHE_PREFIX_END_MARKER), 1)

    def test_partition_yields_static_prefix_before_current_state(self):
        """The marker sits at the static/dynamic boundary — the prefix should
        contain the persona/tool-registry sections, NOT the per-iteration
        Current State / chain context / todo list placeholders."""
        prefix, sep, suffix = REACT_SYSTEM_PROMPT.partition(CACHE_PREFIX_END_MARKER)
        self.assertEqual(sep, CACHE_PREFIX_END_MARKER)
        self.assertGreater(len(prefix), 0)
        self.assertGreater(len(suffix), 0)

        # Static prefix should contain the stable sections.
        self.assertIn("You are RedAmon", prefix)
        self.assertIn("Your Operating Model", prefix)
        self.assertIn("Available Tools", prefix)
        self.assertIn("{available_tools}", prefix)
        self.assertIn("Attack Skill", prefix)

        # Dynamic suffix should contain the per-iteration sections.
        self.assertIn("Current State", suffix)
        self.assertIn("{iteration}", suffix)
        self.assertIn("{chain_context}", suffix)
        self.assertIn("{todo_list}", suffix)
        self.assertIn("{target_info}", suffix)

    def test_prefix_has_no_per_iteration_placeholders(self):
        """Critical: the cached prefix must NOT contain any interpolation
        that varies per iteration. {iteration}, {chain_context}, {todo_list},
        {target_info}, {qa_history} are all per-call values — if any leak
        into the prefix, caching becomes worthless (every call has a unique
        prefix and the cache never hits)."""
        prefix, _, _ = REACT_SYSTEM_PROMPT.partition(CACHE_PREFIX_END_MARKER)
        per_iteration_placeholders = [
            "{iteration}",
            "{chain_context}",
            "{todo_list}",
            "{target_info}",
            "{qa_history}",
            "{objective_history_summary}",
            "{prior_chain_history}",
        ]
        for ph in per_iteration_placeholders:
            self.assertNotIn(
                ph, prefix,
                f"per-iteration placeholder {ph!r} leaked into the cache "
                f"prefix — every call would have a unique prefix and the "
                f"cache would never hit",
            )

    def test_prefix_contains_only_phase_stable_placeholders(self):
        """The prefix's interpolations should only depend on phase/attack-path/
        settings (which are stable across iterations within the same phase),
        not on per-call state. This is a positive assertion of which
        placeholders ARE acceptable in the prefix."""
        prefix, _, _ = REACT_SYSTEM_PROMPT.partition(CACHE_PREFIX_END_MARKER)
        # These are session-stable (or phase-stable) and acceptable.
        acceptable_in_prefix = [
            "{current_phase}",
            "{phase_definitions}",
            "{informational_guidance}",
            "{available_tools}",
            "{attack_path_type}",
            "{attack_path_behavior}",
        ]
        for ph in acceptable_in_prefix:
            self.assertIn(
                ph, prefix,
                f"expected phase-stable placeholder {ph!r} to appear in the "
                f"cache prefix",
            )


if __name__ == "__main__":
    unittest.main()
