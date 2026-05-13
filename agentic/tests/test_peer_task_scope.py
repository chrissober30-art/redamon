"""
Tests for the peer-task scope feature.

Feature: fireteam members receive an `_peer_tasks` snapshot listing what each
sibling in the same wave is covering, rendered into the system prompt as an
"OUT OF SCOPE" block immediately after the mission section. Goal: discourage
scope creep where Member A pivots into Member B's surface when its own runs
dry (observed in session 2026-05-12 16:11 where Member 2 / CI-CD probed
ports owned by Member 4 / IP-direct).

Touched files:
  - state.py                                            (TypedDict field)
  - orchestrator_helpers/nodes/fireteam_deploy_node.py  (populates state)
  - orchestrator_helpers/nodes/fireteam_member_think_node.py  (renders prompt)

Coverage layers:
  1. Unit — _build_member_state populates _peer_tasks correctly
  2. Unit — _build_member_prompt renders peer_block correctly
  3. Smoke — edge cases (no plan, single member, missing names, unicode)
  4. Regression — TypedDict declared, single-member compatibility, format()
     does not raise KeyError, existing test fixtures still work
"""

import unittest
import sys
import os

# Allow running both as `python3 -m unittest tests.test_peer_task_scope`
# from /app and as `python3 -m unittest test_peer_task_scope` from /app/tests.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Shared helpers
# =============================================================================

def _make_plan(member_specs):
    """Wrap a list of member specs in the shape parent_state stores."""
    return {
        "members": list(member_specs),
        "plan_rationale": "test plan",
    }


def _make_parent_state(plan=None, **overrides):
    """Minimal AgentState for _build_member_state."""
    base = {
        "current_phase": "informational",
        "attack_path_type": "",
        "user_id": "u",
        "project_id": "p",
        "session_id": "s",
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
    """Minimal FireteamMemberState — sufficient for _build_member_prompt."""
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
        "tools": ["execute_curl"], "task": "scan target A",
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
    }
    base.update(overrides)
    return base


# =============================================================================
# 1. UNIT — _build_member_state populates _peer_tasks
# =============================================================================

class BuildMemberStatePeerTasksTests(unittest.TestCase):
    """Verify the deploy node copies sibling specs onto each member's state."""

    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _build_member_state
        self._fn = _build_member_state

    def test_excludes_self_by_name(self):
        plan = _make_plan([
            {"name": "Alpha", "task": "task-A", "tools": ["execute_curl"]},
            {"name": "Bravo", "task": "task-B", "tools": ["execute_httpx"]},
            {"name": "Charlie", "task": "task-C", "tools": ["execute_katana"]},
        ])
        parent = _make_parent_state(plan=plan)
        spec = plan["members"][1]  # Bravo
        state = self._fn(parent, spec, "member-1-xx", "fteam-1")

        peers = state.get("_peer_tasks")
        self.assertIsNotNone(peers)
        names = [p["name"] for p in peers]
        self.assertEqual(set(names), {"Alpha", "Charlie"})
        self.assertNotIn("Bravo", names)

    def test_includes_task_summary_and_skills(self):
        plan = _make_plan([
            {"name": "Alpha", "task": "Fingerprint admin subdomain", "tools": ["execute_curl"]},
            {"name": "Bravo", "task": "Probe IP ports", "tools": ["execute_httpx"]},
        ])
        parent = _make_parent_state(plan=plan)
        state = self._fn(parent, plan["members"][0], "member-0-xx", "fteam-1")

        peers = state["_peer_tasks"]
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["name"], "Bravo")
        self.assertEqual(peers[0]["task_summary"], "Probe IP ports")
        self.assertEqual(peers[0]["tools"], ["execute_httpx"])

    def test_truncates_long_task_to_240_chars(self):
        long_task = "X" * 500
        plan = _make_plan([
            {"name": "Alpha", "task": "short", "tools": []},
            {"name": "Bravo", "task": long_task, "tools": []},
        ])
        state = self._fn(_make_parent_state(plan=plan), plan["members"][0], "m-0", "fteam-1")
        peer_summary = state["_peer_tasks"][0]["task_summary"]
        self.assertEqual(len(peer_summary), 240)
        self.assertEqual(peer_summary, "X" * 240)

    def test_missing_plan_yields_empty_peer_list(self):
        """No _current_fireteam_plan on parent (single-member or pre-deploy)."""
        parent = _make_parent_state(plan=None)
        spec = {"name": "Solo", "task": "do everything", "tools": []}
        state = self._fn(parent, spec, "m-0", "fteam-1")
        self.assertEqual(state["_peer_tasks"], [])

    def test_single_member_wave_yields_empty_peer_list(self):
        plan = _make_plan([{"name": "Solo", "task": "do everything", "tools": []}])
        parent = _make_parent_state(plan=plan)
        state = self._fn(parent, plan["members"][0], "m-0", "fteam-1")
        self.assertEqual(state["_peer_tasks"], [])

    def test_missing_member_name_is_handled(self):
        """Defensive: a member spec without `name` should still produce a valid
        peer entry from the OTHER members' perspective."""
        plan = _make_plan([
            {"task": "no name task A", "tools": []},      # no name
            {"name": "Bravo", "task": "task-B", "tools": []},
        ])
        parent = _make_parent_state(plan=plan)
        # From Bravo's perspective, the unnamed peer should appear.
        state = self._fn(parent, plan["members"][1], "m-1", "fteam-1")
        peers = state["_peer_tasks"]
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["name"], "(unnamed)")

    def test_missing_task_field_is_handled(self):
        plan = _make_plan([
            {"name": "Alpha", "tools": []},  # no task
            {"name": "Bravo", "task": "task-B", "tools": []},
        ])
        parent = _make_parent_state(plan=plan)
        state = self._fn(parent, plan["members"][1], "m-1", "fteam-1")
        self.assertEqual(state["_peer_tasks"][0]["task_summary"], "")

    def test_peer_list_does_not_share_reference_with_plan(self):
        """The peer list should be a fresh list of fresh dicts so mutating the
        plan later (e.g. fireteam_id injection in the deploy node) does not
        affect already-built member states."""
        plan = _make_plan([
            {"name": "Alpha", "task": "task-A", "tools": ["execute_curl"]},
            {"name": "Bravo", "task": "task-B", "tools": ["execute_httpx"]},
        ])
        parent = _make_parent_state(plan=plan)
        state = self._fn(parent, plan["members"][0], "m-0", "fteam-1")

        # Mutate the original plan
        plan["members"][1]["task"] = "MUTATED"
        plan["members"][1]["tools"].append("execute_nuclei")

        # The member's snapshot should reflect what was at deploy time.
        self.assertEqual(state["_peer_tasks"][0]["task_summary"], "task-B")
        self.assertEqual(state["_peer_tasks"][0]["tools"], ["execute_httpx"])

    def test_each_member_sees_different_peer_set(self):
        """In a 3-member wave, each member's peer set is the other 2."""
        plan = _make_plan([
            {"name": "Alpha", "task": "A", "tools": []},
            {"name": "Bravo", "task": "B", "tools": []},
            {"name": "Charlie", "task": "C", "tools": []},
        ])
        parent = _make_parent_state(plan=plan)
        states = [
            self._fn(parent, plan["members"][i], f"m-{i}", "fteam-1")
            for i in range(3)
        ]
        peer_sets = [
            {p["name"] for p in s["_peer_tasks"]}
            for s in states
        ]
        self.assertEqual(peer_sets[0], {"Bravo", "Charlie"})
        self.assertEqual(peer_sets[1], {"Alpha", "Charlie"})
        self.assertEqual(peer_sets[2], {"Alpha", "Bravo"})


# =============================================================================
# 2. UNIT — _build_member_prompt renders peer_block
# =============================================================================

class BuildMemberPromptPeerBlockTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import _build_member_prompt
        self._fn = _build_member_prompt

    def test_peer_block_renders_when_peers_present(self):
        state = _make_member_state(_peer_tasks=[
            {"name": "Infra Recon", "task_summary": "Probe k8s subdomain", "tools": ["execute_httpx"]},
            {"name": "Web Recon", "task_summary": "Crawl marketing site", "tools": ["execute_katana"]},
        ])
        prompt = self._fn(state)

        self.assertIn("Sibling members in this wave", prompt)
        self.assertIn("OUT OF SCOPE", prompt)
        self.assertIn("**Infra Recon**", prompt)
        self.assertIn("Probe k8s subdomain", prompt)
        self.assertIn("**Web Recon**", prompt)
        self.assertIn("Crawl marketing site", prompt)

    def test_peer_block_absent_when_no_peers(self):
        """Single-member waves should not show a confusing empty block."""
        state = _make_member_state(_peer_tasks=[])
        prompt = self._fn(state)
        self.assertNotIn("Sibling members in this wave", prompt)
        self.assertNotIn("OUT OF SCOPE", prompt)

    def test_peer_block_absent_when_field_missing(self):
        """state.get('_peer_tasks') returning None is treated like []."""
        state = _make_member_state()
        del state["_peer_tasks"]
        prompt = self._fn(state)
        self.assertNotIn("Sibling members in this wave", prompt)

    def test_peer_block_placed_above_constraints(self):
        """The block must appear AFTER mission and BEFORE constraints so it
        weights heavily in instruction following."""
        state = _make_member_state(_peer_tasks=[
            {"name": "X", "task_summary": "Y", "tools": []},
        ])
        prompt = self._fn(state)
        mission_pos = prompt.find("## Your mission")
        peer_pos = prompt.find("## Sibling members in this wave")
        constraints_pos = prompt.find("## Constraints")

        self.assertGreater(mission_pos, -1)
        self.assertGreater(peer_pos, -1)
        self.assertGreater(constraints_pos, -1)
        self.assertLess(mission_pos, peer_pos)
        self.assertLess(peer_pos, constraints_pos)

    def test_peer_block_renders_action_complete_directive(self):
        """The block must instruct the LLM to complete (not pivot) when its
        own surface is exhausted — this is the core anti-scope-creep nudge."""
        state = _make_member_state(_peer_tasks=[
            {"name": "Other", "task_summary": "elsewhere", "tools": []},
        ])
        prompt = self._fn(state)
        self.assertIn("action=complete", prompt)

    def test_peer_block_does_not_break_format_when_task_has_braces(self):
        """Task strings with `{` / `}` must not break str.format() rendering.
        Regression guard — the mission injects {task} via .format(), and a
        peer task summary going through the same template path must be safe."""
        # Member's own task contains braces — should already work because
        # _MEMBER_SYSTEM_PROMPT.format(task=...) substitutes literally.
        state = _make_member_state(
            task="probe {endpoint} with {payload}",
            _peer_tasks=[
                {"name": "Other", "task_summary": "scan {host}", "tools": []},
            ],
        )
        # Must not raise KeyError or IndexError
        prompt = self._fn(state)
        self.assertIn("probe {endpoint}", prompt)
        self.assertIn("scan {host}", prompt)

    def test_peer_block_preserves_unicode(self):
        state = _make_member_state(_peer_tasks=[
            {"name": "Récon-α", "task_summary": "探测 端口 → API", "tools": []},
        ])
        prompt = self._fn(state)
        self.assertIn("Récon-α", prompt)
        self.assertIn("探测 端口", prompt)

    def test_peer_block_renders_skills_independently_of_block_content(self):
        """The skills array goes into _peer_tasks but should not be rendered
        in the prompt today (we only show name + task_summary). This guard
        prevents accidental leak of internal fields if someone adds a render
        for skills later without an opt-in."""
        state = _make_member_state(_peer_tasks=[
            {"name": "Other", "task_summary": "do stuff", "tools": ["execute_metasploit"]},
        ])
        prompt = self._fn(state)
        # Skills are not rendered today — keep this guard explicit so a future
        # change is a deliberate decision.
        self.assertNotIn("execute_metasploit", prompt)


# =============================================================================
# 3. SMOKE — edge cases that should not crash
# =============================================================================

class PeerTaskSmokeTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _build_member_state
        from orchestrator_helpers.nodes.fireteam_member_think_node import _build_member_prompt
        self._build_state = _build_member_state
        self._build_prompt = _build_member_prompt

    def test_full_pipeline_renders_with_realistic_5_member_wave(self):
        """End-to-end smoke: 5 members like the real session, no exceptions."""
        plan = _make_plan([
            {"name": "Main & Admin Recon",
             "task": "Fingerprint gpigs.devergolabs.com and admin.gpigs.devergolabs.com.",
             "tools": ["execute_httpx", "execute_katana", "execute_curl"]},
            {"name": "Infra & Internal Recon",
             "task": "Fingerprint k8s.gpigs.devergolabs.com and internal.gpigs.devergolabs.com.",
             "tools": ["execute_httpx", "execute_katana", "execute_curl"]},
            {"name": "CI/CD & Staging Recon",
             "task": "Fingerprint jenkins.gpigs.devergolabs.com and staging.gpigs.devergolabs.com.",
             "tools": ["execute_httpx", "execute_katana", "execute_curl"]},
            {"name": "Web Properties Recon",
             "task": "Fingerprint marketing.gpigs.devergolabs.com and news.gpigs.devergolabs.com.",
             "tools": ["execute_httpx", "execute_katana", "execute_curl"]},
            {"name": "IP Ports Direct Recon",
             "task": "Probe 15.160.68.117 on ports 80, 8080, 8888, 9090 directly.",
             "tools": ["execute_httpx", "execute_katana", "execute_curl"]},
        ])
        parent = _make_parent_state(plan=plan)

        for i, spec in enumerate(plan["members"]):
            deploy_state = self._build_state(parent, spec, f"member-{i}-xx", "fteam-1")
            # Bridge: deploy_state has only the fields _build_member_state
            # writes. Patch in the others a real member state would have.
            member_state = _make_member_state(
                member_name=spec["name"],
                task=spec["task"],
                tools=spec["tools"],
                _peer_tasks=deploy_state["_peer_tasks"],
            )
            prompt = self._build_prompt(member_state)
            self.assertIn(spec["task"][:60], prompt,
                          f"member {i}: own task missing from prompt")
            # The 4 OTHER members must appear by name.
            for j, other in enumerate(plan["members"]):
                if i == j:
                    continue
                self.assertIn(other["name"], prompt,
                              f"member {i}: peer {other['name']} missing from prompt")

    def test_empty_peer_task_summary_does_not_crash(self):
        state = _make_member_state(_peer_tasks=[
            {"name": "Empty Task", "task_summary": "", "tools": []},
        ])
        prompt = self._build_prompt(state)
        self.assertIn("**Empty Task**", prompt)

    def test_many_peers_render_in_order(self):
        """8 peers (above current FIRETEAM_MAX_MEMBERS=5 — defensive)."""
        peers = [{"name": f"M{i}", "task_summary": f"task-{i}", "tools": []}
                 for i in range(8)]
        state = _make_member_state(_peer_tasks=peers)
        prompt = self._build_prompt(state)
        # All 8 names appear and in declaration order.
        positions = [prompt.find(f"**M{i}**") for i in range(8)]
        for p in positions:
            self.assertGreater(p, -1)
        self.assertEqual(positions, sorted(positions))


# =============================================================================
# 4. REGRESSION — TypedDict declaration, backward compat, format() safety
# =============================================================================

class PeerTaskRegressionTests(unittest.TestCase):

    def test_peer_tasks_declared_in_typeddict(self):
        """LangGraph strips undeclared TypedDict keys on merge — confirm the
        field is declared so updates from deploy actually reach the member."""
        from state import FireteamMemberState
        # TypedDict annotations live in __annotations__
        self.assertIn("_peer_tasks", FireteamMemberState.__annotations__,
                      "_peer_tasks must be declared on FireteamMemberState "
                      "or LangGraph will drop it at merge time")

    def test_build_member_state_legacy_no_plan_still_seeds_all_token_fields(self):
        """Pre-existing test_token_tracking expectation: token fields stay
        seeded to zero. Confirm the peer-task addition didn't disturb that."""
        from orchestrator_helpers.nodes.fireteam_deploy_node import _build_member_state
        parent = _make_parent_state(plan=None)
        spec = {"name": "X", "task": "x", "tools": []}
        state = _build_member_state(parent, spec, "m-0", "fteam-1")
        self.assertEqual(state["tokens_used"], 0)
        self.assertEqual(state["input_tokens_used"], 0)
        self.assertEqual(state["output_tokens_used"], 0)

    def test_build_member_prompt_format_does_not_raise_when_peer_tasks_absent(self):
        """str.format on _MEMBER_SYSTEM_PROMPT must not raise KeyError when
        peer_block resolves to '' (the default for missing/empty peer list)."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import _build_member_prompt
        state = _make_member_state(_peer_tasks=[])
        # Must not raise
        prompt = _build_member_prompt(state)
        self.assertIn("## Your mission", prompt)
        self.assertIn("## Constraints", prompt)

    def test_build_member_prompt_format_handles_brace_in_peer_task(self):
        """The peer block must escape OR pre-render in a way that doesn't
        break str.format(). Regression for the obvious format-injection
        footgun: a peer task containing `{foo}` would otherwise crash."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import _build_member_prompt
        # Both placeholders that go through .format would be dangerous if
        # peer_block were treated as a format template. _build_member_prompt
        # must format peer_block ONCE before substitution into the parent
        # template — confirm no KeyError surfaces.
        state = _make_member_state(_peer_tasks=[
            {"name": "Tricky", "task_summary": "needs {api_key} and {endpoint}", "tools": []},
        ])
        prompt = _build_member_prompt(state)
        # Literal braces survive to output (not interpreted as placeholders).
        self.assertIn("{api_key}", prompt)
        self.assertIn("{endpoint}", prompt)

    def test_member_state_has_peer_tasks_key_after_build(self):
        """Even single-member waves must populate the key (with []), so the
        prompt code's state.get('_peer_tasks') is never missing."""
        from orchestrator_helpers.nodes.fireteam_deploy_node import _build_member_state
        plan = _make_plan([{"name": "Solo", "task": "x", "tools": []}])
        parent = _make_parent_state(plan=plan)
        state = _build_member_state(parent, plan["members"][0], "m-0", "fteam-1")
        self.assertIn("_peer_tasks", state)
        self.assertEqual(state["_peer_tasks"], [])


# =============================================================================
# 5. DEFENSIVE — malformed plan shapes and task content quirks
# =============================================================================

class PeerTaskDefensiveTests(unittest.TestCase):
    """Plans come from an LLM; assume nothing about their well-formedness."""

    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _build_member_state
        from orchestrator_helpers.nodes.fireteam_member_think_node import _build_member_prompt
        self._build_state = _build_member_state
        self._build_prompt = _build_member_prompt

    def test_empty_plan_dict_yields_empty_peer_list(self):
        """_current_fireteam_plan = {} (no members key)."""
        parent = _make_parent_state(plan={})
        spec = {"name": "X", "task": "t", "tools": []}
        state = self._build_state(parent, spec, "m-0", "fteam-1")
        self.assertEqual(state["_peer_tasks"], [])

    def test_plan_with_none_members_yields_empty_peer_list(self):
        parent = _make_parent_state(plan={"members": None})
        spec = {"name": "X", "task": "t", "tools": []}
        state = self._build_state(parent, spec, "m-0", "fteam-1")
        self.assertEqual(state["_peer_tasks"], [])

    def test_plan_with_empty_members_list_yields_empty_peer_list(self):
        parent = _make_parent_state(plan={"members": []})
        spec = {"name": "X", "task": "t", "tools": []}
        state = self._build_state(parent, spec, "m-0", "fteam-1")
        self.assertEqual(state["_peer_tasks"], [])

    def test_duplicate_member_names_degrade_gracefully(self):
        """If the planner emits two members with the same name, both will
        peer-exclude each other (and themselves). The system degrades to a
        single-member-style state — no crash, no peers shown. This is the
        safer failure mode than rendering a misleading peer list."""
        plan = _make_plan([
            {"name": "Recon", "task": "task-A", "tools": []},
            {"name": "Recon", "task": "task-B", "tools": []},
        ])
        parent = _make_parent_state(plan=plan)
        state = self._build_state(parent, plan["members"][0], "m-0", "fteam-1")
        # Both have the same name → exclusion is over-eager. Acceptable:
        # never crash, never leak a wrong-name peer. The list may be empty.
        for p in state["_peer_tasks"]:
            # If any peer survives, it must NOT carry our own name.
            self.assertNotEqual(p["name"], "Recon")

    def test_task_summary_with_embedded_newlines_does_not_break_list(self):
        """A peer task with literal '\\n' chars renders the bullet point —
        the next bullet should still be parseable as a separate item by a
        reader (no concatenation). We don't normalize newlines but we
        document the behavior here."""
        state = _make_member_state(_peer_tasks=[
            {"name": "Multi", "task_summary": "line1\nline2", "tools": []},
            {"name": "Single", "task_summary": "just-one", "tools": []},
        ])
        prompt = self._build_prompt(state)
        # Both peers present
        self.assertIn("**Multi**", prompt)
        self.assertIn("**Single**", prompt)
        # The Single bullet must still start with "- **Single**" on its own
        # line — confirms the embedded newline in Multi's summary didn't
        # consume the next bullet's marker.
        self.assertIn("\n- **Single**", prompt)

    def test_peer_list_built_with_no_self_match_when_name_is_none(self):
        """spec.name=None and a peer name=None: the equality check
        (`p.get('name') != spec.get('name')`) treats both as None → equal,
        so the unnamed peer is excluded along with self. This guards
        against the obvious None-equality footgun."""
        plan = _make_plan([
            {"task": "self task", "tools": []},      # no name = None
            {"name": "Real", "task": "real task", "tools": []},
        ])
        parent = _make_parent_state(plan=plan)
        # spec is the unnamed one
        state = self._build_state(parent, plan["members"][0], "m-0", "fteam-1")
        # Only "Real" should appear as a peer; we did NOT add ourselves back.
        names = [p["name"] for p in state["_peer_tasks"]]
        self.assertEqual(names, ["Real"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
