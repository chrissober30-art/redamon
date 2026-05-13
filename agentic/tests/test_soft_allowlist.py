"""
Tests for the soft skill allowlist (Changes A + B + C).

Feature:
  - A. The member system prompt splits the tool registry into a "Primary tools"
    block (full descriptions, filtered to declared skills + query_graph) and a
    "Fallback toolbox" block (compact name+purpose only, everything else).
  - B. LLMDecision.tool_expansion_reason field. Members reaching for a
    fallback tool must justify why their primary skills cannot do the job; the
    semantic gate in fireteam_member_think_node re-prompts when missing.
  - C. FireteamMemberState carries fallback_uses_this_run +
    iterations_since_new_finding + last_findings_count. The member's prompt
    surfaces a graduated "skill expansion budget" warning when the counters
    cross thresholds without producing new findings, escalating to a
    "Recommendation: complete" when the member is flailing.

Touched files:
  - state.py (LLMDecision field + FireteamMemberState fields)
  - prompts/__init__.py (get_phase_tools tool_filter kwarg + export)
  - prompts/base.py (build_compact_tool_list helper)
  - orchestrator_helpers/nodes/fireteam_deploy_node.py (seed counters)
  - orchestrator_helpers/nodes/fireteam_member_think_node.py (split rendering,
    validator, counter updates, budget prefix)

Coverage layers:
  1. Unit — build_compact_tool_list + get_phase_tools(tool_filter=...)
  2. Unit — LLMDecision.tool_expansion_reason field present + optional
  3. Unit — _validate_tool_expansion gate semantics
  4. Unit — _build_member_prompt renders primary + fallback split + budget prefix
  5. Unit — _build_member_state seeds the three counter fields to zero
  6. Regression — TypedDict declarations, backward compat (tools=[] path)
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Shared helpers
# =============================================================================

def _make_parent_state(plan=None, **overrides):
    base = {
        "current_phase": "informational",
        "attack_path_type": "",
        "user_id": "u", "project_id": "p", "session_id": "s",
        "target_info": {"primary_target": "1.2.3.4", "ports": [80, 443]},
        "chain_findings_memory": [],
        "chain_failures_memory": [],
        "chain_decisions_memory": [],
        "execution_trace": [],
    }
    if plan is not None:
        base["_current_fireteam_plan"] = plan
    base.update(overrides)
    return base


def _make_member_state(**overrides):
    base = {
        "messages": [],
        "current_iteration": 1,
        "max_iterations": 10,
        "task_complete": False,
        "completion_reason": None,
        "current_phase": "informational",
        "attack_path_type": "cve_exploit",
        "user_id": "u", "project_id": "p", "session_id": "s",
        "parent_target_info": {"primary_target": "1.2.3.4", "ports": [80]},
        "member_name": "Member A", "member_id": "member-0-abc",
        "fireteam_id": "fteam-1",
        "tools": ["execute_curl", "execute_httpx"],
        "task": "scan target A",
        "execution_trace": [],
        "target_info": {"primary_target": "1.2.3.4", "ports": [80]},
        "chain_findings_memory": [],
        "chain_failures_memory": [],
        "_parent_chain_findings": [],
        "_parent_chain_failures": [],
        "_parent_chain_decisions": [],
        "_parent_execution_trace": [],
        "_peer_tasks": [],
        "_pending_confirmation": None,
        "_current_plan": None,
        "_current_step": None,
        "_decision": None,
        "_last_chain_step_id": None,
        "_guardrail_blocked": False,
        "tokens_used": 0,
        "input_tokens_used": 0,
        "output_tokens_used": 0,
        "_input_tokens_this_turn": 0,
        "_output_tokens_this_turn": 0,
        "fallback_uses_this_run": 0,
        "iterations_since_new_finding": 0,
        "last_findings_count": 0,
    }
    base.update(overrides)
    return base


# =============================================================================
# 1. UNIT — build_compact_tool_list + get_phase_tools(tool_filter=...)
# =============================================================================

class CompactToolListTests(unittest.TestCase):
    """build_compact_tool_list emits a minimal name+purpose bullet list."""

    def test_empty_set_returns_empty_string(self):
        from prompts.base import build_compact_tool_list
        self.assertEqual(build_compact_tool_list([]), "")
        self.assertEqual(build_compact_tool_list(set()), "")

    def test_emits_bullet_per_tool_with_name_and_purpose(self):
        from prompts.base import build_compact_tool_list
        out = build_compact_tool_list(["execute_curl", "execute_httpx"])
        self.assertIn("- **execute_curl**:", out)
        self.assertIn("- **execute_httpx**:", out)

    def test_skips_unknown_tools(self):
        """Unknown tool names (not in TOOL_REGISTRY) are filtered out by the
        underlying _get_visible_tools, so the output is clean."""
        from prompts.base import build_compact_tool_list
        out = build_compact_tool_list(["execute_curl", "not_a_real_tool_xyz"])
        self.assertIn("**execute_curl**", out)
        self.assertNotIn("not_a_real_tool_xyz", out)

    def test_does_not_include_flag_examples(self):
        """Compact mode must NOT include the full description/flag examples —
        that's the friction point (model knows it exists, has to think about
        why a primary tool can't do it)."""
        from prompts.base import build_compact_tool_list
        out = build_compact_tool_list(["execute_nuclei"])
        # The full description of execute_nuclei in the registry includes
        # flag examples like "-u URL -id CVE-2021-..." — those must be absent.
        self.assertNotIn("-id CVE", out)
        self.assertNotIn("Examples:", out)


class GetPhaseToolsFilterTests(unittest.TestCase):
    """get_phase_tools accepts tool_filter and restricts the rendered list."""

    def test_no_filter_renders_full_phase_set(self):
        from prompts import get_phase_tools
        out = get_phase_tools("informational")
        # Phase allowlist for informational includes httpx, curl, nuclei, etc.
        self.assertIn("execute_httpx", out)
        self.assertIn("execute_nuclei", out)

    def test_filter_restricts_to_subset(self):
        from prompts import get_phase_tools
        out = get_phase_tools(
            "informational",
            tool_filter={"execute_httpx", "query_graph"},
        )
        self.assertIn("execute_httpx", out)
        self.assertIn("query_graph", out)
        # execute_nuclei NOT in filter → must NOT appear in the rendered
        # tool table / descriptions section.
        self.assertNotIn("**execute_nuclei**", out)

    def test_empty_filter_emits_empty_tool_list(self):
        """tool_filter=set() (not None) means "no tools allowed" — defensive
        edge case; the rendering should not crash."""
        from prompts import get_phase_tools
        out = get_phase_tools("informational", tool_filter=set())
        # Some phase headers / kali rules may still render; the per-tool
        # table should be empty or near-empty. We just assert no crash.
        self.assertIsInstance(out, str)

    def test_filter_intersects_with_phase_allowlist(self):
        """tool_filter cannot expand beyond the phase's allowed tools. If a
        tool is filter-allowed but phase-disallowed, it must NOT render."""
        from prompts import get_phase_tools
        # `metasploit_console` is exploitation-only; passing it via the
        # informational filter should NOT show it.
        out = get_phase_tools(
            "informational",
            tool_filter={"execute_httpx", "metasploit_console"},
        )
        self.assertIn("execute_httpx", out)
        # No exploitation-only entries should appear.
        self.assertNotIn("**metasploit_console**", out)


# =============================================================================
# 2. UNIT — LLMDecision.tool_expansion_reason field
# =============================================================================

class LLMDecisionToolExpansionFieldTests(unittest.TestCase):

    def test_field_is_optional_default_none(self):
        from state import LLMDecision
        d = LLMDecision(thought="t", reasoning="r", action="complete",
                        completion_reason="done")
        self.assertIsNone(d.tool_expansion_reason)

    def test_field_accepts_string(self):
        from state import LLMDecision
        d = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_nuclei", tool_args={"args": "-u x"},
            tool_expansion_reason="curl cannot run nuclei templates",
        )
        self.assertEqual(d.tool_expansion_reason,
                         "curl cannot run nuclei templates")

    def test_field_round_trips_through_model_dump(self):
        from state import LLMDecision
        d = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_nuclei", tool_args={"args": "-u x"},
            tool_expansion_reason="need CVE template",
        )
        dumped = d.model_dump()
        self.assertEqual(dumped["tool_expansion_reason"], "need CVE template")
        d2 = LLMDecision(**dumped)
        self.assertEqual(d2.tool_expansion_reason, "need CVE template")


# =============================================================================
# 3. UNIT — _validate_tool_expansion gate
# =============================================================================

class ValidateToolExpansionTests(unittest.TestCase):

    def _decision(self, action="use_tool", tool_name=None, plan_steps=None,
                  reason=None):
        from state import LLMDecision, ToolPlan, ToolPlanStep
        kwargs = dict(
            thought="t", reasoning="r", action=action,
            tool_expansion_reason=reason,
        )
        if action == "use_tool":
            kwargs["tool_name"] = tool_name
            kwargs["tool_args"] = {"args": "x"}
        elif action == "plan_tools":
            steps = [
                ToolPlanStep(tool_name=t, tool_args={"args": "x"}, rationale="r")
                for t in (plan_steps or [])
            ]
            kwargs["tool_plan"] = ToolPlan(steps=steps, plan_rationale="r")
        elif action == "complete":
            kwargs["completion_reason"] = "done"
        return LLMDecision(**kwargs)

    def test_no_declared_tools_skips_gate(self):
        """Members with tools=[] bypass the soft allowlist entirely."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(tool_name="execute_nuclei")  # would be fallback
        self.assertIsNone(_validate_tool_expansion(d, set()))

    def test_primary_tool_passes(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(tool_name="execute_curl")
        self.assertIsNone(
            _validate_tool_expansion(d, {"execute_curl", "execute_httpx"})
        )

    def test_query_graph_always_allowed(self):
        """query_graph is the universal read-only anchor."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(tool_name="query_graph")
        self.assertIsNone(
            _validate_tool_expansion(d, {"execute_curl"})
        )

    def test_fallback_without_reason_returns_correction(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(tool_name="execute_nuclei")
        err = _validate_tool_expansion(d, {"execute_curl"})
        self.assertIsNotNone(err)
        self.assertIn("execute_nuclei", err)
        self.assertIn("tool_expansion_reason", err)

    def test_fallback_with_reason_passes(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(
            tool_name="execute_nuclei",
            reason="need CVE template scan, curl cannot",
        )
        self.assertIsNone(_validate_tool_expansion(d, {"execute_curl"}))

    def test_fallback_with_empty_string_reason_fails(self):
        """Whitespace-only or empty reason doesn't satisfy the gate."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(tool_name="execute_nuclei", reason="   ")
        err = _validate_tool_expansion(d, {"execute_curl"})
        self.assertIsNotNone(err)

    def test_plan_with_mixed_steps_one_fallback_requires_reason(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        # Primary curl + fallback nuclei in one plan
        d = self._decision(
            action="plan_tools",
            plan_steps=["execute_curl", "execute_nuclei"],
        )
        err = _validate_tool_expansion(d, {"execute_curl"})
        self.assertIsNotNone(err)
        # nuclei must appear in the "reaching for fallback tools" list
        self.assertIn("execute_nuclei", err)
        # curl is primary → must NOT appear in the fallback list section.
        # The error message has the structure:
        #   "reaching for fallback tools: [<expanded list>]. Your declared
        #    primary skills are [<primary list>]. ..."
        # We isolate the fallback-list segment between the two known anchors
        # and assert curl is absent there. (curl IS legitimately echoed in
        # the "declared primary tools" listing as informational clarification.)
        fallback_segment = err.split("Your declared primary tools")[0]
        self.assertNotIn("execute_curl", fallback_segment)

    def test_plan_with_all_primary_passes(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(
            action="plan_tools",
            plan_steps=["execute_curl", "execute_httpx", "query_graph"],
        )
        self.assertIsNone(
            _validate_tool_expansion(d, {"execute_curl", "execute_httpx"})
        )

    def test_complete_action_skips_gate(self):
        """`complete` has no tool_name; gate must not fire."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _validate_tool_expansion,
        )
        d = self._decision(action="complete")
        self.assertIsNone(_validate_tool_expansion(d, {"execute_curl"}))


# =============================================================================
# 4. UNIT — _build_member_prompt renders primary + fallback split
# =============================================================================

class BuildMemberPromptSoftAllowlistTests(unittest.TestCase):

    def test_primary_block_header_renders_when_skills_set(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl", "execute_httpx"],
        ))
        self.assertIn("## Primary tools (your assigned toolbox", prompt)

    def test_fallback_block_header_renders_when_skills_set(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
        ))
        self.assertIn("## Fallback toolbox", prompt)
        self.assertIn("tool_expansion_reason", prompt)

    def test_no_skills_uses_legacy_unrestricted_view(self):
        """Members without declared skills get the full unrestricted phase
        rendering — backward-compatible with pre-feature behavior."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(tools=[]))
        # No primary/fallback split when skills is empty.
        self.assertNotIn("## Primary tools (your assigned toolbox", prompt)
        self.assertNotIn("## Fallback toolbox", prompt)

    def test_primary_block_includes_declared_tools_full_descriptions(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl", "execute_httpx"],
        ))
        # Both declared skills should appear in the prompt with full
        # descriptions (the table mentions them).
        # Locate the primary block region.
        primary_start = prompt.find("## Primary tools")
        fallback_start = prompt.find("## Fallback toolbox")
        self.assertGreater(primary_start, -1)
        self.assertGreater(fallback_start, primary_start)
        primary_region = prompt[primary_start:fallback_start]
        self.assertIn("execute_curl", primary_region)
        self.assertIn("execute_httpx", primary_region)

    def test_fallback_block_lists_non_declared_phase_tools_compact(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
        ))
        fallback_start = prompt.find("## Fallback toolbox")
        self.assertGreater(fallback_start, -1)
        fallback_region = prompt[fallback_start:]
        # nuclei is informational-allowed but NOT in skills → fallback bullet
        self.assertIn("**execute_nuclei**", fallback_region)
        # httpx is NOT in skills here → also fallback
        self.assertIn("**execute_httpx**", fallback_region)

    def test_query_graph_appears_in_primary_block_even_when_not_declared(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],  # query_graph not in declared skills
        ))
        # query_graph should still show up as primary (the read-only anchor).
        primary_start = prompt.find("## Primary tools")
        fallback_start = prompt.find("## Fallback toolbox")
        primary_region = prompt[primary_start:fallback_start]
        self.assertIn("query_graph", primary_region)


# =============================================================================
# 5. UNIT — budget prefix (Change C)
# =============================================================================

class BudgetPrefixTests(unittest.TestCase):

    def test_no_prefix_at_zero_uses(self):
        """A productive member with no fallback uses sees no warning."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
            fallback_uses_this_run=0,
            iterations_since_new_finding=0,
        ))
        self.assertNotIn("Tool expansion budget", prompt)
        self.assertNotIn("Recommendation: complete", prompt)

    def test_no_prefix_at_one_use(self):
        """Threshold is 2 — a single fallback use is fine."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
            fallback_uses_this_run=1,
        ))
        self.assertNotIn("Tool expansion budget", prompt)

    def test_budget_warning_at_two_uses(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
            fallback_uses_this_run=2,
            iterations_since_new_finding=0,
        ))
        self.assertIn("Tool expansion budget", prompt)
        # Soft warning, not the hard "Recommendation: complete" yet
        self.assertNotIn("Recommendation: complete", prompt)

    def test_recommend_complete_at_4_uses_plus_stall(self):
        """4 fallback uses + 2 stalled iterations → escalate to recommend."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
            fallback_uses_this_run=4,
            iterations_since_new_finding=2,
        ))
        self.assertIn("Recommendation: complete", prompt)

    def test_4_uses_but_recent_finding_stays_soft(self):
        """4 fallback uses BUT a finding came in last iter → only soft warning."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
            fallback_uses_this_run=4,
            iterations_since_new_finding=0,  # just got a finding
        ))
        # Productive expansion — show the soft budget warning, NOT the
        # complete recommendation.
        self.assertIn("Tool expansion budget", prompt)
        self.assertNotIn("Recommendation: complete", prompt)

    def test_prefix_is_above_mission(self):
        """Budget prefix sits ABOVE the mission header so the LLM reads it first."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
            fallback_uses_this_run=2,
        ))
        budget_pos = prompt.find("Tool expansion budget")
        mission_pos = prompt.find("## Your mission")
        self.assertGreater(budget_pos, -1)
        self.assertGreater(mission_pos, -1)
        self.assertLess(budget_pos, mission_pos)


# =============================================================================
# 6. UNIT — _build_member_state seeds counter fields
# =============================================================================

class BuildMemberStateCounterSeedingTests(unittest.TestCase):

    def test_seeds_fallback_uses_to_zero(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import (
            _build_member_state,
        )
        spec = {"name": "X", "task": "t", "tools": []}
        state = _build_member_state(_make_parent_state(), spec, "m-0", "fteam-1")
        self.assertEqual(state["fallback_uses_this_run"], 0)

    def test_seeds_iterations_since_new_finding_to_zero(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import (
            _build_member_state,
        )
        spec = {"name": "X", "task": "t", "tools": []}
        state = _build_member_state(_make_parent_state(), spec, "m-0", "fteam-1")
        self.assertEqual(state["iterations_since_new_finding"], 0)

    def test_seeds_last_findings_count_to_zero(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import (
            _build_member_state,
        )
        spec = {"name": "X", "task": "t", "tools": []}
        state = _build_member_state(_make_parent_state(), spec, "m-0", "fteam-1")
        self.assertEqual(state["last_findings_count"], 0)


# =============================================================================
# 7. REGRESSION — TypedDict declarations + backward compat
# =============================================================================

class SoftAllowlistRegressionTests(unittest.TestCase):

    def test_fallback_uses_declared_in_typeddict(self):
        from state import FireteamMemberState
        self.assertIn("fallback_uses_this_run",
                      FireteamMemberState.__annotations__)

    def test_iterations_since_new_finding_declared_in_typeddict(self):
        from state import FireteamMemberState
        self.assertIn("iterations_since_new_finding",
                      FireteamMemberState.__annotations__)

    def test_last_findings_count_declared_in_typeddict(self):
        from state import FireteamMemberState
        self.assertIn("last_findings_count",
                      FireteamMemberState.__annotations__)

    def test_tool_expansion_reason_declared_on_llm_decision(self):
        from state import LLMDecision
        self.assertIn("tool_expansion_reason",
                      LLMDecision.model_fields)

    def test_get_phase_tools_legacy_no_filter_kwarg_still_works(self):
        """Existing callers (root agent) don't pass tool_filter; must still
        produce the full phase rendering."""
        from prompts import get_phase_tools
        out = get_phase_tools("informational")
        self.assertIsInstance(out, str)
        self.assertGreater(len(out), 100)
        self.assertIn("execute_httpx", out)

    def test_member_prompt_no_skills_still_renders(self):
        """tools=[] path must not break (back-compat with old fixtures)."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(tools=[]))
        self.assertIn("## Your mission", prompt)
        self.assertIn("scan target A", prompt)


# =============================================================================
# 8. INTEGRATION — counter helpers and rendering work together
# =============================================================================

class SoftAllowlistIntegrationTests(unittest.TestCase):

    def test_skills_path_renders_primary_fallback_and_no_prefix(self):
        """Happy path: declared skills, no fallback uses, no stall → split
        rendering present, no budget warnings."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
        ))
        self.assertIn("## Primary tools", prompt)
        self.assertIn("## Fallback toolbox", prompt)
        self.assertNotIn("Tool expansion budget", prompt)
        self.assertNotIn("Recommendation: complete", prompt)

    def test_collect_called_tools_use_tool(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _collect_called_tools,
        )
        from state import LLMDecision
        d = LLMDecision(thought="t", reasoning="r", action="use_tool",
                        tool_name="execute_curl", tool_args={"args": "x"})
        self.assertEqual(_collect_called_tools(d), ["execute_curl"])

    def test_collect_called_tools_plan_tools(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _collect_called_tools,
        )
        from state import LLMDecision, ToolPlan, ToolPlanStep
        d = LLMDecision(
            thought="t", reasoning="r", action="plan_tools",
            tool_plan=ToolPlan(
                steps=[
                    ToolPlanStep(tool_name="execute_curl",
                                 tool_args={"args": "x"}, rationale="r"),
                    ToolPlanStep(tool_name="execute_httpx",
                                 tool_args={"args": "y"}, rationale="r"),
                ],
                plan_rationale="r",
            ),
        )
        self.assertEqual(_collect_called_tools(d),
                         ["execute_curl", "execute_httpx"])

    def test_collect_called_tools_complete_returns_empty(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _collect_called_tools,
        )
        from state import LLMDecision
        d = LLMDecision(thought="t", reasoning="r", action="complete",
                        completion_reason="done")
        self.assertEqual(_collect_called_tools(d), [])


# =============================================================================
# 9. BUG FIXES — regression guards for issues found in self-review
# =============================================================================

class BugFixPhaseAllowsLineTests(unittest.TestCase):
    """Bug #1: 'Current phase allows' line lied in the primary block.

    Before fix: get_phase_tools(tool_filter=primary) rendered a summary line
    listing only primary tools, implying fallback tools were forbidden.
    After fix: the line is suppressed when a tool_filter is active, and the
    fallback block carries no such misleading summary either.
    """

    def test_phase_allows_line_absent_when_filter_active(self):
        from prompts import get_phase_tools
        out = get_phase_tools(
            "informational",
            tool_filter={"execute_curl", "query_graph"},
        )
        self.assertNotIn("**Current phase allows:**", out)

    def test_phase_allows_line_present_when_no_filter(self):
        """Legacy callers (root agent) still see the summary line."""
        from prompts import get_phase_tools
        out = get_phase_tools("informational")
        self.assertIn("**Current phase allows:**", out)

    def test_explicit_show_phase_allows_line_false_suppresses(self):
        """build_tool_availability_table honors the explicit kwarg too."""
        from prompts.base import build_tool_availability_table
        out = build_tool_availability_table(
            "informational",
            ["execute_curl", "execute_httpx"],
            show_phase_allows_line=False,
        )
        self.assertNotIn("**Current phase allows:**", out)
        # Table itself still renders
        self.assertIn("execute_curl", out)
        self.assertIn("execute_httpx", out)

    def test_member_prompt_primary_block_does_not_lie_about_phase(self):
        """End-to-end: the primary block in a member prompt must NOT carry a
        'Current phase allows: <primary only>' line that contradicts the
        fallback toolbox listing below."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],
        ))
        # The fallback toolbox includes execute_nuclei (among others). If the
        # primary block claimed the phase only allows curl/query_graph, the
        # contradiction would be visible. Assert no such line exists between
        # the Primary header and the Fallback header.
        primary_start = prompt.find("## Primary tools")
        fallback_start = prompt.find("## Fallback toolbox")
        self.assertGreater(primary_start, -1)
        self.assertGreater(fallback_start, primary_start)
        primary_region = prompt[primary_start:fallback_start]
        self.assertNotIn("**Current phase allows:**", primary_region)


class BugFixKaliRulesTests(unittest.TestCase):
    """Bug #8: when a member's primary skills don't include kali_shell but
    the phase DOES allow it (so it lives in the member's fallback toolbox),
    the kali install warning was being silently dropped. Fix: check the
    unfiltered phase allowlist for kali_shell, independent of the filter.
    """

    def test_kali_rules_render_when_kali_in_phase_even_if_filtered_out(self):
        from prompts import get_phase_tools
        # Filter excludes kali_shell, but the informational phase allows it.
        out = get_phase_tools(
            "informational",
            tool_filter={"execute_curl", "query_graph"},
        )
        self.assertIn("Kali Shell — Library Installation: DISABLED", out)

    def test_kali_rules_present_in_member_prompt_when_kali_in_fallback(self):
        """End-to-end check: a member whose skills do NOT include kali_shell
        still sees the kali install warning, because kali_shell is reachable
        via the fallback toolbox."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl"],  # kali_shell NOT declared → fallback
        ))
        self.assertIn("Kali Shell — Library Installation: DISABLED", prompt)

    def test_kali_rules_still_present_when_kali_is_primary(self):
        """Pre-fix behavior preserved: kali declared as primary → rules render."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_member_prompt,
        )
        prompt = _build_member_prompt(_make_member_state(
            tools=["execute_curl", "kali_shell"],
        ))
        self.assertIn("Kali Shell — Library Installation: DISABLED", prompt)


class BugFixSemanticRetryPrepTests(unittest.IsolatedAsyncioTestCase):
    """Bug #2: when the semantic gate triggered a retry, the next attempt's
    HumanMessage wrapper said 'Your previous JSON failed validation' — a lie
    that confused the model into rewriting tool_name instead of adding the
    missing tool_expansion_reason. Fix: branch the prep text on the prior
    error kind (json vs semantic).

    These tests exercise the actual fireteam_member_think_node async function
    with a mocked LLM to capture which HumanMessage gets injected on retry.
    """

    def _build_state(self, **over):
        return _make_member_state(tools=["execute_curl"], **over)

    async def test_semantic_retry_prep_does_not_say_json_failed(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            fireteam_member_think_node,
        )
        from state import LLMDecision

        # Two responses:
        # 1) decision uses fallback execute_nuclei without reason → semantic gate fires
        # 2) same decision but with reason → passes
        d_no_reason = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_nuclei", tool_args={"args": "-u x"},
        )
        d_with_reason = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_nuclei", tool_args={"args": "-u x"},
            tool_expansion_reason="curl cannot run nuclei CVE templates",
        )

        responses = [
            MagicMock(content=d_no_reason.model_dump_json(), usage_metadata={}),
            MagicMock(content=d_with_reason.model_dump_json(), usage_metadata={}),
        ]
        llm = MagicMock()
        llm.get_num_tokens_from_messages = MagicMock(return_value=100)
        captured = []

        async def fake_retry(llm_, messages, label=""):
            captured.append(list(messages))
            return responses[len(captured) - 1]

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.retry_llm_call",
            new=fake_retry,
        ):
            state = self._build_state()
            await fireteam_member_think_node(
                state, config=None, llm=llm,
                neo4j_creds=None, streaming_callbacks=None,
                graph_view_cyphers=None,
            )

        # Two attempts were made (semantic retry).
        self.assertEqual(len(captured), 2)
        # The SECOND attempt's last HumanMessage is the retry-prep injected
        # by the loop. It should NOT contain the misleading "JSON failed" wrapper.
        retry_messages = captured[1]
        # Find the last HumanMessage with non-empty content
        from langchain_core.messages import HumanMessage
        humans = [m for m in retry_messages if isinstance(m, HumanMessage)]
        self.assertGreaterEqual(len(humans), 1)
        retry_prep_content = humans[-1].content
        self.assertNotIn("Your previous JSON failed validation", retry_prep_content)
        # But it SHOULD carry the semantic correction (the [system] message).
        self.assertIn("tool_expansion_reason", retry_prep_content)

    async def test_json_retry_prep_still_says_json_failed(self):
        """Sanity: when the prior error was JSON parse, the wrapper text is
        unchanged (existing behavior preserved)."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            fireteam_member_think_node,
        )
        from state import LLMDecision

        d_good = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_curl", tool_args={"args": "-u x"},
        )
        responses = [
            MagicMock(content="this is not json at all", usage_metadata={}),
            MagicMock(content=d_good.model_dump_json(), usage_metadata={}),
        ]
        llm = MagicMock()
        llm.get_num_tokens_from_messages = MagicMock(return_value=100)
        captured = []

        async def fake_retry(llm_, messages, label=""):
            captured.append(list(messages))
            return responses[len(captured) - 1]

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.retry_llm_call",
            new=fake_retry,
        ):
            state = self._build_state()
            await fireteam_member_think_node(
                state, config=None, llm=llm,
                neo4j_creds=None, streaming_callbacks=None,
                graph_view_cyphers=None,
            )

        self.assertEqual(len(captured), 2)
        from langchain_core.messages import HumanMessage
        humans = [m for m in captured[1] if isinstance(m, HumanMessage)]
        retry_prep_content = humans[-1].content
        # JSON-parse retry still uses the original wrapper
        self.assertIn("Your previous JSON failed validation", retry_prep_content)


class BugFixIter1StallTests(unittest.IsolatedAsyncioTestCase):
    """Bug #3: on iteration 1, with no tool calls in the trace, the stall
    counter was being incremented (current_findings=0, last=0 → else branch).
    Fix: skip the stall update when no work has been done yet.
    """

    async def test_iter_1_with_no_trace_does_not_increment_stall(self):
        """Direct test of the post-think update: an iter-1 state with no
        execution trace, no completed step, no pending plan → stall counter
        stays at 0 (its seeded value)."""
        from unittest.mock import MagicMock, patch
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            fireteam_member_think_node,
        )
        from state import LLMDecision

        d = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_curl", tool_args={"args": "-u x"},
        )
        llm = MagicMock()
        llm.get_num_tokens_from_messages = MagicMock(return_value=100)

        async def fake_retry(llm_, messages, label=""):
            return MagicMock(content=d.model_dump_json(), usage_metadata={})

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.retry_llm_call",
            new=fake_retry,
        ):
            state = _make_member_state(
                tools=["execute_curl"],
                current_iteration=0,
                execution_trace=[],
                chain_findings_memory=[],
                _completed_step=None,
                _current_step=None,
                _current_plan=None,
                iterations_since_new_finding=0,
                last_findings_count=0,
            )
            result = await fireteam_member_think_node(
                state, config=None, llm=llm,
                neo4j_creds=None, streaming_callbacks=None,
                graph_view_cyphers=None,
            )

        # Stall counter MUST NOT have been bumped — no work has happened yet.
        # Either the field is absent from the update (preserving seeded 0) or
        # explicitly equals 0.
        self.assertEqual(result.get("iterations_since_new_finding", 0), 0)

    async def test_iter_2_with_trace_increments_stall_when_no_new_findings(self):
        """Once at least one tool has run, the stall logic kicks in normally:
        no new findings → bump by 1."""
        from unittest.mock import MagicMock, patch
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            fireteam_member_think_node,
        )
        from state import LLMDecision

        d = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_curl", tool_args={"args": "-u x"},
        )
        llm = MagicMock()
        llm.get_num_tokens_from_messages = MagicMock(return_value=100)

        async def fake_retry(llm_, messages, label=""):
            return MagicMock(content=d.model_dump_json(), usage_metadata={})

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.retry_llm_call",
            new=fake_retry,
        ):
            # Iter 2 state: there's a prior tool in the trace, no new
            # findings this turn, stall=0 from last turn.
            state = _make_member_state(
                tools=["execute_curl"],
                current_iteration=1,
                execution_trace=[{"tool_name": "execute_curl", "iteration": 1}],
                chain_findings_memory=[],
                iterations_since_new_finding=0,
                last_findings_count=0,
            )
            result = await fireteam_member_think_node(
                state, config=None, llm=llm,
                neo4j_creds=None, streaming_callbacks=None,
                graph_view_cyphers=None,
            )

        self.assertEqual(result.get("iterations_since_new_finding"), 1)

    async def test_new_findings_reset_stall_to_zero(self):
        """When chain_findings_memory grew, stall MUST reset to 0
        regardless of prior value."""
        from unittest.mock import MagicMock, patch
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            fireteam_member_think_node,
        )
        from state import LLMDecision

        d = LLMDecision(
            thought="t", reasoning="r", action="use_tool",
            tool_name="execute_curl", tool_args={"args": "-u x"},
        )
        llm = MagicMock()
        llm.get_num_tokens_from_messages = MagicMock(return_value=100)

        async def fake_retry(llm_, messages, label=""):
            return MagicMock(content=d.model_dump_json(), usage_metadata={})

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.retry_llm_call",
            new=fake_retry,
        ):
            state = _make_member_state(
                tools=["execute_curl"],
                current_iteration=3,
                execution_trace=[{"tool_name": "execute_curl", "iteration": 1}],
                chain_findings_memory=[{"finding": "x"}, {"finding": "y"}],
                iterations_since_new_finding=2,  # was stalling
                last_findings_count=1,  # just got a new one (count is now 2)
            )
            result = await fireteam_member_think_node(
                state, config=None, llm=llm,
                neo4j_creds=None, streaming_callbacks=None,
                graph_view_cyphers=None,
            )

        self.assertEqual(result.get("iterations_since_new_finding"), 0)
        self.assertEqual(result.get("last_findings_count"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
