"""
Semantic correctness tests for Phase-3 TOOL_REGISTRY entries.

The Phase-2 completeness test (`test_tool_registry_completeness`) verifies
structural integrity (every fs_/job_ tool has an entry, fields are present,
descriptions are non-trivial). This file adds the semantic checks the LLM
actually relies on:

  - `args_format` must mention every REQUIRED argument of the underlying
    coroutine, by introspecting the signature. Catches "the doc said 'path'
    but the function takes 'file_path'" regressions.
  - Cross-references inside descriptions must point at real tools. Catches
    docs rot when a tool is renamed elsewhere.
  - The render pipeline in prompts/base.py actually emits Phase-3 entries
    when they appear in `allowed_tools`. Catches the case where the registry
    has the entry but the renderer filters it out.
  - No em-dashes (per project convention - they read as AI-generated).
  - `purpose` is a short single line (convention).

Run with: python3 -m unittest tests.test_tool_registry_semantics -v
"""
from __future__ import annotations

import inspect
import os
import re
import sys
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

import workspace_fs  # noqa: E402
import job_runner  # noqa: E402
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402
from prompts.base import (  # noqa: E402
    build_informational_tool_descriptions,
    build_tool_args_section,
    build_tool_availability_table,
    build_compact_tool_list,
)


def _new_tool_names() -> list[str]:
    return [n for n in TOOL_REGISTRY if n.startswith(("fs_", "job_"))]


# =============================================================================
# args_format must mention all required positional/keyword args
# =============================================================================

class TestArgsFormatMatchesSignature(unittest.TestCase):
    """For each fs_* tool, verify that every REQUIRED parameter of the
    underlying coroutine appears (as a quoted key) in args_format.

    Optional params (those with defaults) don't have to be mentioned, but
    required params absolutely do - otherwise the LLM will call the tool
    without them and trigger a TypeError that surfaces as 'bad arguments'.
    """

    def _required_params(self, fn):
        sig = inspect.signature(fn)
        return [
            name for name, p in sig.parameters.items()
            if p.default is inspect.Parameter.empty
            and p.kind not in (inspect.Parameter.VAR_POSITIONAL,
                               inspect.Parameter.VAR_KEYWORD)
        ]

    def test_fs_tools_args_format_lists_required_params(self):
        missing_overall = []
        for name, fn in workspace_fs.DISPATCH.items():
            required = self._required_params(fn)
            args_format = TOOL_REGISTRY[name]["args_format"]
            for p in required:
                # Look for the param name as a JSON-style key in the args_format.
                if f'"{p}"' not in args_format:
                    missing_overall.append(f"{name}: missing required param '{p}'")
        self.assertEqual(missing_overall, [], "\n".join(missing_overall))

    def test_job_tools_args_format_well_formed(self):
        # job_* tools are not in DISPATCH (they dispatch through tools.py),
        # so we hand-list their required args.
        expected_required = {
            "job_spawn": {"tool_name"},  # 'args' and 'label' are optional in spec
            "job_status": {"job_id"},
            "job_wait": {"job_id"},
            "job_cancel": {"job_id"},
            "job_list": set(),
        }
        for name, required in expected_required.items():
            args_format = TOOL_REGISTRY[name]["args_format"]
            for p in required:
                self.assertIn(
                    f'"{p}"', args_format,
                    f"{name}: args_format missing required '{p}'",
                )


# =============================================================================
# Description cross-references resolve to real tools
# =============================================================================

class TestDescriptionCrossReferences(unittest.TestCase):
    """Only flag INTENTIONAL tool references - cases where the description
    invokes a tool by name in a call-like context (`fs_grep("...")`,
    `fs_read jobs/...`). We deliberately ignore bare snake_case identifiers
    inside example JSON since those are field names, not tool refs.
    """

    # Match: backticked tool-call style (`fs_grep(...)`, `fs_read x`, `fs_read_many`)
    # OR explicit "use fs_xxx" / "via fs_xxx" / "use job_xxx" prose.
    BACKTICK_CALL = re.compile(
        r"`(fs_[a-z_]+|job_[a-z_]+|execute_[a-z_]+|query_graph|web_search|"
        r"cve_intel|kali_shell|metasploit_console|tradecraft_lookup|msf_restart)"
        r"(?:[(\s`])"
    )
    PROSE_REF = re.compile(
        r"\b(?:use|via|call|run|prefer|use AFTER|pass to)\s+"
        r"(fs_[a-z_]+|job_[a-z_]+|execute_[a-z_]+|query_graph|web_search|"
        r"cve_intel|kali_shell|metasploit_console|tradecraft_lookup|msf_restart)\b"
    )

    def test_no_references_to_nonexistent_tools(self):
        known = set(TOOL_REGISTRY.keys())
        bad = []
        for name in _new_tool_names():
            desc = TOOL_REGISTRY[name].get("description", "")
            refs = set(self.BACKTICK_CALL.findall(desc)) | set(self.PROSE_REF.findall(desc))
            for ref in refs:
                if ref == name:
                    continue
                if ref not in known:
                    bad.append(f"{name}.description references '{ref}' which is not in TOOL_REGISTRY")
        self.assertEqual(bad, [], "\n".join(bad))


# =============================================================================
# Render pipeline emits Phase-3 entries
# =============================================================================

class TestRenderPipeline(unittest.TestCase):
    def test_descriptions_block_includes_all_fs_tools(self):
        names = sorted(workspace_fs.FS_TOOL_NAMES)
        out = build_informational_tool_descriptions(names)
        # The renderer prepends "<n>. " to each entry; check that all names
        # appear as bold markers in the output.
        for name in names:
            self.assertIn(f"**{name}**", out, f"{name} missing from rendered descriptions")

    def test_descriptions_block_includes_all_job_tools(self):
        names = sorted(job_runner.JOB_TOOL_NAMES)
        out = build_informational_tool_descriptions(names)
        for name in names:
            self.assertIn(f"**{name}**", out, f"{name} missing from rendered descriptions")

    def test_args_section_lists_every_phase3_tool(self):
        names = _new_tool_names()
        out = build_tool_args_section(names)
        for name in names:
            self.assertIn(f"\n- {name}: ", out, msg=f"{name} not in args section")

    def test_compact_list_emits_purpose_for_each(self):
        names = _new_tool_names()
        out = build_compact_tool_list(names)
        for name in names:
            self.assertIn(f"**{name}**", out)
            # Should also contain the purpose text
            purpose = TOOL_REGISTRY[name]["purpose"]
            # Be permissive - just check first few words appear
            first_words = " ".join(purpose.split()[:3])
            self.assertIn(first_words, out, f"{name} purpose not rendered")

    def test_availability_table_renders_one_row_per_tool(self):
        names = _new_tool_names()
        out = build_tool_availability_table("informational", names, show_phase_allows_line=False)
        # Header + separator + 29 rows = at least 31 pipe-leading lines
        rows = [line for line in out.splitlines() if line.startswith("|")]
        # Header (1) + alignment row (1) + 29 tool rows = 31
        self.assertEqual(len(rows), 2 + len(names), f"unexpected row count: {len(rows)}")


# =============================================================================
# Convention checks
# =============================================================================

class TestConventions(unittest.TestCase):
    def test_no_em_dashes_anywhere_in_phase3_entries(self):
        em = "\u2014"
        hits = []
        for name in _new_tool_names():
            entry = TOOL_REGISTRY[name]
            for field, val in entry.items():
                if em in str(val):
                    hits.append(f"{name}.{field}")
        self.assertEqual(hits, [],
                         f"em-dash found in Phase-3 entries: {hits} "
                         f"(project convention: use plain '-' or '--')")

    def test_purpose_is_single_line(self):
        bad = []
        for name in _new_tool_names():
            purpose = TOOL_REGISTRY[name]["purpose"]
            if "\n" in purpose:
                bad.append(f"{name}: purpose contains newline")
            if len(purpose) > 120:
                bad.append(f"{name}: purpose >120 chars ({len(purpose)})")
        self.assertEqual(bad, [], "\n".join(bad))

    def test_when_to_use_non_trivial(self):
        bad = []
        for name in _new_tool_names():
            when = TOOL_REGISTRY[name].get("when_to_use", "")
            if len(when) < 30:
                bad.append(f"{name}: when_to_use too short ({len(when)} chars)")
        self.assertEqual(bad, [], "\n".join(bad))


if __name__ == "__main__":
    unittest.main()
