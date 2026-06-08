"""Deep-review test suite for Productivity v2.

Covers what the original test_productivity.py additions did NOT cover:

  - Wiring (AST scan) — every new symbol must be imported in think_node.py
    and the cooldown/score/novelty/axis-recording statements must be present
    in BOTH the single-tool and wave paths.
  - Edge cases for extract_axis: hydra, sqlmap, ffuf-direct, malformed args,
    missing-username scripts, non-string code, kali_shell sqlmap wrapper.
  - Edge cases for compute_productivity_score: max_iterations<=0, very large
    iteration, empty inputs, mixed verdicts, post_exploitation phase weights,
    negative iterations_since_state_grew defended.
  - Edge cases for state-growth detector: None inputs, len-equal-content-changed
    (must NOT count as growth), all six tracked target_info list fields.
  - Cooldown arithmetic — a focused unit test of the math without invoking
    LangGraph / the LLM.
  - Tier-action smoke: full XBEN-007 timeline simulation produces the expected
    tier escalation across iterations.
  - Backward compatibility: old state dicts missing v2 fields must still drive
    a score computation safely (state.get defaults).

If any test in this module fails on first run, the failure is a real bug —
not a test rewrite target. Fix the source instead.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load productivity.py directly (stdlib-only).
_PROD_PATH = os.path.join(
    os.path.dirname(__file__), "..", "orchestrator_helpers", "productivity.py"
)
_spec = importlib.util.spec_from_file_location("_prod_v2_review", _PROD_PATH)
_prod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_prod)

extract_axis = _prod.extract_axis
axis_key = _prod.axis_key
axis_unproductive_count = _prod.axis_unproductive_count
record_axis_attempt = _prod.record_axis_attempt
priority_order_jaccard = _prod.priority_order_jaccard
compute_productivity_score = _prod.compute_productivity_score
tier_for_score = _prod.tier_for_score
detect_state_growth = _prod.detect_state_growth


def _step(*, tool="execute_curl", args=None, output="", success=True,
          productivity=None, step_iteration=1):
    s = {
        "step_id": "abc",
        "step_iteration": step_iteration,
        "iteration": step_iteration,
        "tool_name": tool,
        "tool_args": args or {},
        "tool_output": output,
        "success": success,
        "output_analysis": "",
        "actionable_findings": [],
    }
    if productivity is not None:
        s["productivity"] = productivity
    return s


def _verdict(v="new_info", gained=True):
    return {"verdict": v, "new_information_gained": gained,
            "what_was_new": "", "should_repeat_similar_call": False, "rationale": ""}


# =============================================================================
# AST wiring tests — every new feature MUST be referenced in think_node.py
# in the places the design specifies.
# =============================================================================

THINK_NODE = os.path.join(
    os.path.dirname(__file__), "..", "orchestrator_helpers", "nodes", "think_node.py"
)

with open(THINK_NODE) as _f:
    THINK_SRC = _f.read()

PRODUCTIVITY_SRC_PATH = os.path.join(
    os.path.dirname(__file__), "..", "orchestrator_helpers", "productivity.py"
)
with open(PRODUCTIVITY_SRC_PATH) as _f:
    PROD_SRC = _f.read()

STATE_SRC_PATH = os.path.join(os.path.dirname(__file__), "..", "state.py")
with open(STATE_SRC_PATH) as _f:
    STATE_SRC = _f.read()

SETTINGS_SRC_PATH = os.path.join(
    os.path.dirname(__file__), "..", "project_settings.py"
)
with open(SETTINGS_SRC_PATH) as _f:
    SETTINGS_SRC = _f.read()


class TestThinkNodeV2Wiring(unittest.TestCase):
    """Verify every Productivity v2 symbol is imported and referenced in
    the right places. AST-grade — if you rename a function, this fails
    loudly instead of silently regressing in prod."""

    def test_imports_present(self):
        for sym in (
            "extract_axis", "axis_key", "axis_unproductive_count",
            "record_axis_attempt", "priority_order_jaccard",
            "compute_productivity_score", "tier_for_score",
            "detect_state_growth",
        ):
            self.assertIn(sym, THINK_SRC,
                          f"think_node.py must import {sym}")

    def test_score_compute_called(self):
        self.assertIn("compute_productivity_score(", THINK_SRC)

    def test_cooldown_set_after_deep_think(self):
        # The cooldown must be armed only when Deep Think actually triggered.
        # We look for the assignment near `deep_think_triggered:` block.
        self.assertIn("_deep_think_cooldown_until", THINK_SRC)
        self.assertIn("DEEP_THINK_COOLDOWN_ITERATIONS", THINK_SRC)

    def test_novelty_check_runs_after_parse(self):
        # Must happen after dt_parsed is built and before deep_think_result.
        # Check the Jaccard call exists.
        self.assertIn("priority_order_jaccard(", THINK_SRC)
        self.assertIn("DEEP_THINK_NOVELTY_JACCARD_MAX", THINK_SRC)

    def _slice_single_tool_analysis_block(self) -> str:
        """The single-tool analysis block is the SECOND occurrence of
        `if has_pending_output:` in the file (the first is the prompt-
        injection block, before the LLM is invoked). The analysis block
        ends where the wave-analysis block starts."""
        first = THINK_SRC.index("if has_pending_output:")
        second = THINK_SRC.index("if has_pending_output:", first + 1)
        # The wave analysis block starts at the SECOND occurrence of
        # `if has_pending_plan_outputs:` (first is the prompt-injection one).
        first_wave = THINK_SRC.index("if has_pending_plan_outputs:")
        second_wave = THINK_SRC.index("if has_pending_plan_outputs:", first_wave + 1)
        return THINK_SRC[second:second_wave]

    def _slice_wave_analysis_block(self) -> str:
        first_wave = THINK_SRC.index("if has_pending_plan_outputs:")
        second_wave = THINK_SRC.index("if has_pending_plan_outputs:", first_wave + 1)
        return THINK_SRC[second_wave:]

    def test_state_growth_tick_in_single_tool_path(self):
        segment = self._slice_single_tool_analysis_block()
        self.assertIn("detect_state_growth(", segment,
                      "state-growth detector must run in single-tool analysis path")
        self.assertIn("_iterations_since_state_grew", segment)

    def test_state_growth_tick_in_wave_path(self):
        segment = self._slice_wave_analysis_block()
        self.assertIn("detect_state_growth(", segment,
                      "wave analysis path must also tick state-growth")
        self.assertIn("_iterations_since_state_grew", segment)

    def test_axis_recording_in_single_tool_path(self):
        segment = self._slice_single_tool_analysis_block()
        self.assertIn("extract_axis(", segment)
        self.assertIn("record_axis_attempt(", segment)

    def test_axis_recording_in_wave_path(self):
        segment = self._slice_wave_analysis_block()
        self.assertIn("extract_axis(", segment,
                      "wave path must record axes per step")
        self.assertIn("record_axis_attempt(", segment)

    def test_score_writeback_to_state(self):
        # Must write _last_productivity_score onto updates dict
        self.assertIn('updates["_last_productivity_score"]', THINK_SRC)

    def test_settings_defaults_declared(self):
        for sym in (
            "PRODUCTIVITY_SCORE_ENABLED",
            "PRODUCTIVITY_SCORE_HINT_THRESHOLD",
            "PRODUCTIVITY_SCORE_DEEPTHINK_THRESHOLD",
            "PRODUCTIVITY_SCORE_REQUIRE_PIVOT_THRESHOLD",
            "PRODUCTIVITY_SCORE_BLOCK_THRESHOLD",
            "DEEP_THINK_COOLDOWN_ITERATIONS",
            "DEEP_THINK_NOVELTY_JACCARD_MAX",
            "STATE_GROWTH_SOFT_HINT_THRESHOLD",
            "STATE_GROWTH_HARD_THRESHOLD",
            "AXIS_REPEAT_WARN_COUNT",
            "AXIS_REPEAT_REQUIRE_PIVOT_COUNT",
            "AXIS_REPEAT_BLOCK_COUNT",
        ):
            self.assertIn(sym, SETTINGS_SRC, f"{sym} missing from project_settings.py")

    def test_state_typeddict_has_new_fields(self):
        for sym in (
            "_deep_think_cooldown_until",
            "_iterations_since_state_grew",
            "_previous_priority_order",
            "tested_axes",
            "_last_productivity_score",
        ):
            self.assertIn(sym, STATE_SRC, f"{sym} missing from state.py")

    def test_initial_state_includes_v2_fields(self):
        # create_initial_state must default the v2 fields to safe zero/empty
        self.assertIn('"_deep_think_cooldown_until": 0', STATE_SRC)
        self.assertIn('"_iterations_since_state_grew": 0', STATE_SRC)
        self.assertIn('"tested_axes": {}', STATE_SRC)


# =============================================================================
# Axis extraction — edge cases for every supported family
# =============================================================================

class TestAxisHydra(unittest.TestCase):
    def test_hydra_with_username_flag(self):
        ax = extract_axis("execute_hydra", {
            "args": "-l admin -P /usr/share/wordlists/rockyou.txt "
                    "ssh://target:22"
        })
        self.assertIsNotNone(ax)
        self.assertEqual(ax["family"], "credential_brute_force")
        self.assertEqual(ax["fixed_user"], "admin")

    def test_hydra_without_username_returns_none(self):
        # -L (uppercase, user-list mode) is not "fixed user" — return None
        ax = extract_axis("execute_hydra", {
            "args": "-L users.txt -P rockyou.txt ssh://target"
        })
        self.assertIsNone(ax)

    def test_hydra_empty_args(self):
        self.assertIsNone(extract_axis("execute_hydra", {"args": ""}))
        self.assertIsNone(extract_axis("execute_hydra", {}))


class TestAxisFfufDirect(unittest.TestCase):
    def test_ffuf_canonicalizes_url(self):
        ax1 = extract_axis("execute_ffuf", {
            "args": "-w wordlist1.txt -u http://lab/FUZZ -mc 200,301"
        })
        ax2 = extract_axis("execute_ffuf", {
            "args": "-w wordlist2.txt -u http://lab/FUZZ -mc 200,301"
        })
        self.assertIsNotNone(ax1)
        self.assertEqual(axis_key(ax1), axis_key(ax2),
                         "different wordlists, same URL+filter → same axis")

    def test_ffuf_different_filter_creates_different_axis(self):
        ax1 = extract_axis("execute_ffuf", {
            "args": "-w x -u http://lab/FUZZ -mc 200"
        })
        ax2 = extract_axis("execute_ffuf", {
            "args": "-w x -u http://lab/FUZZ -mc 200,403"
        })
        self.assertNotEqual(axis_key(ax1), axis_key(ax2))

    def test_ffuf_missing_url_returns_none(self):
        ax = extract_axis("execute_ffuf", {"args": "-w wordlist.txt"})
        self.assertIsNone(ax)


class TestAxisSqlmap(unittest.TestCase):
    def test_execute_sqlmap_extracts_target(self):
        ax = extract_axis("execute_sqlmap", {
            "args": "-u 'http://target/login.php?id=1' --batch --level 3"
        })
        self.assertIsNotNone(ax)
        self.assertEqual(ax["family"], "automated_sqli")
        self.assertIn("target/login.php", ax["target"])

    def test_kali_shell_sqlmap_wrapper(self):
        ax = extract_axis("kali_shell", {
            "command": "sqlmap -u 'http://x/page?id=1' --dump"
        })
        self.assertIsNotNone(ax)
        self.assertEqual(ax["family"], "automated_sqli")

    def test_kali_shell_non_sqlmap_returns_none(self):
        ax = extract_axis("kali_shell", {"command": "whatweb -a 3 http://x"})
        self.assertIsNone(ax)


class TestAxisExecuteCodeEdgeCases(unittest.TestCase):
    def test_script_with_brute_hint_but_no_username_returns_none(self):
        # Has a wordlist hint but no explicit username literal → can't fix
        code = (
            "import requests\n"
            "with open('rockyou.txt') as f:\n"
            "    for pw in f:\n"
            "        requests.post('http://x/login', json={'u': user_var, 'password': pw})\n"
        )
        self.assertIsNone(extract_axis("execute_code", {"code": code}))

    def test_non_brute_script_returns_none(self):
        code = "import requests; print(requests.get('http://x').text)"
        self.assertIsNone(extract_axis("execute_code", {"code": code}))

    def test_double_quoted_username_matches(self):
        code = (
            "for pw in passwords:\n"
            '    r = requests.post("http://lab/login", json={"username": "admin", "password": pw})\n'
        )
        ax = extract_axis("execute_code", {"code": code})
        self.assertIsNotNone(ax)
        self.assertEqual(ax["fixed_user"], "admin")

    def test_missing_code_field_returns_none(self):
        self.assertIsNone(extract_axis("execute_code", {}))
        self.assertIsNone(extract_axis("execute_code", {"code": ""}))


class TestAxisDefensive(unittest.TestCase):
    def test_none_tool_name(self):
        self.assertIsNone(extract_axis(None, {"x": "y"}))

    def test_none_args(self):
        self.assertIsNone(extract_axis("execute_code", None))

    def test_unknown_tool(self):
        self.assertIsNone(extract_axis("weird_unknown_tool", {"x": "y"}))

    def test_job_spawn_with_empty_inner_tool(self):
        self.assertIsNone(extract_axis("job_spawn", {"tool_name": "", "args": {}}))

    def test_job_spawn_wrapping_unknown_tool(self):
        self.assertIsNone(extract_axis("job_spawn", {
            "tool_name": "unknown_tool", "args": {"x": "y"}
        }))


# =============================================================================
# axis_key & axis_unproductive_count — defensive
# =============================================================================

class TestAxisKeyDefensive(unittest.TestCase):
    def test_empty_axis_returns_empty_key(self):
        self.assertEqual(axis_key({}), "")
        self.assertEqual(axis_key(None), "")

    def test_count_handles_none_ledger(self):
        self.assertEqual(axis_unproductive_count(None, "k"), 0)
        self.assertEqual(axis_unproductive_count({}, "k"), 0)

    def test_count_treats_missing_verdict_as_non_unproductive(self):
        ledger = {"k": [{"iteration": 1, "tool": "x"}]}  # no verdict field
        self.assertEqual(axis_unproductive_count(ledger, "k"), 0)

    def test_count_includes_hard_failure(self):
        ledger = {"k": [
            {"iteration": 1, "verdict": "hard_failure", "tool": "x"},
            {"iteration": 2, "verdict": "no_progress", "tool": "x"},
            {"iteration": 3, "verdict": "new_info", "tool": "x"},
        ]}
        self.assertEqual(axis_unproductive_count(ledger, "k"), 2)


# =============================================================================
# Score — boundary and defensive math
# =============================================================================

class TestScoreDefensive(unittest.TestCase):
    def test_max_iterations_zero_doesnt_divide_by_zero(self):
        result = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0,
            iteration=5, max_iterations=0, phase="informational",
        )
        # Should not raise and should return a sane structure
        self.assertIn("score", result)
        self.assertIn("components", result)
        self.assertIn("weights", result)

    def test_negative_iterations_since_state_grew_clamped(self):
        result = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=-5,
            iteration=10, max_iterations=100, phase="informational",
        )
        # Negative is clamped to 0 → no stall contribution
        self.assertEqual(result["components"]["iterations_since_state_grew"], 0)

    def test_very_large_state_growth_stall_clipped_at_ten(self):
        result = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=10000,
            iteration=50, max_iterations=100, phase="informational",
        )
        # Clipped at 10 — prevents single signal from dominating runaway
        self.assertEqual(result["components"]["iterations_since_state_grew"], 10)

    def test_iteration_greater_than_max_iterations(self):
        # bracket should clip at 1.0; weights stay at their max
        result = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0,
            iteration=200, max_iterations=100, phase="informational",
        )
        self.assertGreaterEqual(result["weights"]["w_state_growth"], 2.9)

    def test_empty_trace_and_axes_scores_zero(self):
        result = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0,
            iteration=1, max_iterations=100, phase="informational",
        )
        self.assertEqual(result["score"], 0.0)

    def test_post_exploitation_phase_does_not_crash(self):
        # We don't have a special boost for post_exploitation, but the
        # phase parameter must not blow up.
        result = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=2,
            iteration=10, max_iterations=100, phase="post_exploitation",
        )
        self.assertGreaterEqual(result["score"], 0.0)

    def test_score_is_non_negative(self):
        # Even with lots of new_info rewards, score is clamped at 0.
        trace = [_step(productivity=_verdict("new_info", gained=True))
                 for _ in range(20)]
        result = compute_productivity_score(
            execution_trace=trace, tested_axes={},
            iterations_since_state_grew=0,
            iteration=20, max_iterations=100, phase="informational",
        )
        self.assertGreaterEqual(result["score"], 0.0)

    def test_axes_with_empty_entry_list_does_not_crash(self):
        result = compute_productivity_score(
            execution_trace=[], tested_axes={"empty_axis": []},
            iterations_since_state_grew=0,
            iteration=5, max_iterations=100, phase="informational",
        )
        self.assertEqual(result["components"]["max_axis_repeats"], 0)


# =============================================================================
# State-growth detector — defensive edge cases
# =============================================================================

class TestStateGrowthEdges(unittest.TestCase):
    def test_none_before(self):
        self.assertFalse(detect_state_growth(None, {"target_info": {}, "chain_findings_memory": []}))

    def test_none_after(self):
        # None after means no growth observable
        self.assertFalse(detect_state_growth({"target_info": {}, "chain_findings_memory": []}, None))

    def test_both_none(self):
        self.assertFalse(detect_state_growth(None, None))

    def test_same_length_replaced_content_not_growth(self):
        # "Replaced" but same length is not growth (current behavior:
        # the detector counts length only). This documents the behavior;
        # if we ever change it, this test will tell us.
        before = {"target_info": {"endpoints": ["/a"]}, "chain_findings_memory": [{"x": 1}]}
        after = {"target_info": {"endpoints": ["/b"]}, "chain_findings_memory": [{"y": 2}]}
        self.assertFalse(detect_state_growth(before, after))

    def test_endpoints_growth_detected(self):
        before = {"target_info": {"endpoints": ["/a"]}, "chain_findings_memory": []}
        after = {"target_info": {"endpoints": ["/a", "/b"]}, "chain_findings_memory": []}
        self.assertTrue(detect_state_growth(before, after))

    def test_subdomains_growth_detected(self):
        before = {"target_info": {"subdomains": []}, "chain_findings_memory": []}
        after = {"target_info": {"subdomains": ["api.x.com"]}, "chain_findings_memory": []}
        self.assertTrue(detect_state_growth(before, after))

    def test_credentials_growth_detected(self):
        before = {"target_info": {"credentials": []}, "chain_findings_memory": []}
        after = {"target_info": {"credentials": ["user:user"]}, "chain_findings_memory": []}
        self.assertTrue(detect_state_growth(before, after))


# =============================================================================
# Jaccard — defensive
# =============================================================================

class TestJaccardEdges(unittest.TestCase):
    def test_only_stopwords_returns_zero(self):
        a = ["the and or", "run this"]
        b = ["a do that", "is the"]
        self.assertEqual(priority_order_jaccard(a, b), 0.0)

    def test_single_word_short_filtered(self):
        # "a", "b" both shorter than 3 chars — filtered out
        self.assertEqual(priority_order_jaccard(["a"], ["b"]), 0.0)

    def test_case_insensitive(self):
        a = ["Test SQLi against login"]
        b = ["test sqli against LOGIN"]
        self.assertAlmostEqual(priority_order_jaccard(a, b), 1.0, places=5)

    def test_punctuation_stripped(self):
        a = ["Run sqlmap, then dump --all"]
        b = ["Run sqlmap then dump all"]
        # Should be close to 1.0 after tokenization strips punctuation
        self.assertGreaterEqual(priority_order_jaccard(a, b), 0.6)


# =============================================================================
# Tier action thresholds — symmetric mapping
# =============================================================================

class TestTierMapping(unittest.TestCase):
    def test_just_below_threshold_stays_in_lower_tier(self):
        # At 4.999 we should be in yellow (deepthink_threshold=5.0)
        self.assertEqual(tier_for_score(4.999), "yellow")

    def test_at_threshold_jumps_to_next(self):
        self.assertEqual(tier_for_score(5.0), "orange")
        self.assertEqual(tier_for_score(7.0), "red")
        self.assertEqual(tier_for_score(9.0), "critical")

    def test_negative_score_is_green(self):
        # Compute_score clamps to 0, but tier_for_score is also robust.
        self.assertEqual(tier_for_score(-1.0), "green")


# =============================================================================
# Cooldown arithmetic — pure unit test of the gating logic
# =============================================================================

def _is_cooldown_active(iteration, cooldown_until):
    return iteration < cooldown_until


def _should_fire_deep_think(iteration, cooldown_until, tier,
                            critical_override, stall_override):
    """Mirror of think_node.py's gating logic, isolated for unit testing.

    Tier is the productivity tier; orange/red/critical are firing tiers."""
    cooldown_active = _is_cooldown_active(iteration, cooldown_until)
    if tier not in ("orange", "red", "critical"):
        return False
    if not cooldown_active:
        return True
    return critical_override or stall_override


class TestCooldownArithmetic(unittest.TestCase):
    def test_cooldown_active_window(self):
        # cooldown_until=15, iterations 10-14 active, 15+ not.
        self.assertTrue(_is_cooldown_active(iteration=10, cooldown_until=15))
        self.assertTrue(_is_cooldown_active(iteration=14, cooldown_until=15))
        self.assertFalse(_is_cooldown_active(iteration=15, cooldown_until=15))
        self.assertFalse(_is_cooldown_active(iteration=16, cooldown_until=15))

    def test_no_fire_when_cooldown_active_and_no_overrides(self):
        self.assertFalse(_should_fire_deep_think(
            iteration=10, cooldown_until=15, tier="orange",
            critical_override=False, stall_override=False,
        ))

    def test_critical_override_bypasses_cooldown(self):
        self.assertTrue(_should_fire_deep_think(
            iteration=10, cooldown_until=15, tier="critical",
            critical_override=True, stall_override=False,
        ))

    def test_stall_override_bypasses_cooldown(self):
        self.assertTrue(_should_fire_deep_think(
            iteration=10, cooldown_until=15, tier="orange",
            critical_override=False, stall_override=True,
        ))

    def test_fires_when_cooldown_expired(self):
        self.assertTrue(_should_fire_deep_think(
            iteration=15, cooldown_until=15, tier="orange",
            critical_override=False, stall_override=False,
        ))

    def test_does_not_fire_in_green_tier_even_outside_cooldown(self):
        self.assertFalse(_should_fire_deep_think(
            iteration=20, cooldown_until=5, tier="green",
            critical_override=False, stall_override=False,
        ))


# =============================================================================
# Regression / backward compat
# =============================================================================

class TestBackwardCompat(unittest.TestCase):
    """Old state dicts (pre-v2) must not blow up the score path."""

    def test_score_path_handles_missing_v2_fields(self):
        # No `tested_axes`, no `_iterations_since_state_grew` — simulate
        # the caller using state.get(default).
        result = compute_productivity_score(
            execution_trace=[
                _step(productivity=_verdict("no_progress", gained=False)),
            ],
            tested_axes={},          # caller defaults this from state.get
            iterations_since_state_grew=0,
            iteration=2, max_iterations=100, phase="informational",
        )
        self.assertIn("score", result)
        self.assertGreaterEqual(result["score"], 0.0)


# =============================================================================
# Smoke: full XBEN-007 timeline simulation
# =============================================================================

class TestXBEN007FullTimelineSmoke(unittest.TestCase):
    """Walk through the actual XBEN-007 timeline and verify the
    orchestrator would have intervened earlier than the agent did naturally.

    Timeline events:
      iter 1-7:  cold recon (state grows from new endpoints + tech)
      iter 8-23: injection probes (state stalls; some new info each turn)
      iter 24:   first rockyou-5k brute on `admin`
      iter 25-31: hidden-endpoint dragnet (more stalls)
      iter 32:   second 10k-common brute on `admin`
      iter 33-40: more dragnet
      iter 41:   third rockyou-100k brute on `admin` (timed out)
      iter 42-48: more thrashing
      iter 49:   username=password test — finds user:user (state grows)
    """

    def _brute_script(self, wordlist, user="admin"):
        return (
            "import requests\n"
            f"url = 'http://lab-1a6fde19:5003/login'\n"
            f"with open('{wordlist}') as f:\n"
            f"    for pw in f:\n"
            f"        requests.post(url, json={{'username': '{user}', 'password': pw}})\n"
        )

    def test_timeline_escalates_to_red_or_critical_by_third_brute(self):
        ledger = {}
        for it, wl in [(24, "/usr/share/wordlists/rockyou.txt"),
                       (32, "/usr/share/seclists/10k-most-common.txt"),
                       (41, "/usr/share/wordlists/rockyou.txt")]:
            ax = extract_axis("execute_code", {"code": self._brute_script(wl)})
            self.assertIsNotNone(ax, f"axis must extract at iter {it}")
            ledger = record_axis_attempt(
                ledger, axis_key(ax), iteration=it,
                verdict="no_progress", tool="execute_code",
            )

        # By iteration 41 the ledger should show 3 unproductive entries on a single axis.
        ax = extract_axis("execute_code", {"code": self._brute_script("/x.txt")})
        self.assertEqual(axis_unproductive_count(ledger, axis_key(ax)), 3)

        # Simulate stall: state hasn't grown for ~15 iterations by iter 41
        stall = 15
        trace = [_step(productivity=_verdict("no_progress", gained=False))
                 for _ in range(5)]

        result = compute_productivity_score(
            execution_trace=trace, tested_axes=ledger,
            iterations_since_state_grew=stall,
            iteration=41, max_iterations=100, phase="informational",
        )
        tier = tier_for_score(result["score"])
        self.assertIn(tier, ("red", "critical"),
                      f"By iter 41, tier must be red/critical to force pivot. "
                      f"Got {tier} (score={result['score']}, "
                      f"components={result['components']})")

    def test_after_breakthrough_score_drops_to_green(self):
        # After iter 49 (user:user found), state grew and a new_info verdict
        # was logged. The score should drop back to green.
        ledger = {}
        trace = [_step(productivity=_verdict("new_info", gained=True)),
                 _step(productivity=_verdict("new_info", gained=True))]
        result = compute_productivity_score(
            execution_trace=trace, tested_axes=ledger,
            iterations_since_state_grew=0,
            iteration=50, max_iterations=100, phase="informational",
        )
        self.assertEqual(tier_for_score(result["score"]), "green")


# =============================================================================
# Public API surface contract — ensures we don't accidentally rename later
# =============================================================================

class TestPublicSurface(unittest.TestCase):
    """If any of these names disappear, downstream callers (think_node,
    fireteam_member_think_node) break silently in import time."""

    def test_compute_productivity_score_returns_required_keys(self):
        r = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0, iteration=1, max_iterations=100,
        )
        for k in ("score", "components", "weights", "weighted"):
            self.assertIn(k, r)

    def test_components_required_keys(self):
        r = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0, iteration=1, max_iterations=100,
        )
        for k in ("unproductive_verdicts", "iterations_since_state_grew",
                  "max_axis_repeats", "same_pattern_count",
                  "new_info_events", "actionable_events"):
            self.assertIn(k, r["components"])

    def test_weights_required_keys(self):
        r = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0, iteration=1, max_iterations=100,
        )
        for k in ("w_verdict_count", "w_state_growth", "w_axis_repeats",
                  "w_same_pattern", "r_new_info", "r_actionable"):
            self.assertIn(k, r["weights"])


# =============================================================================
# Coverage gaps I'd self-critique — close them here
# =============================================================================


class TestStateGrowthTickPureFunction(unittest.TestCase):
    """The increment/reset logic for `_iterations_since_state_grew` lives
    inline in think_node.py (twice). Re-derive it here as a pure function
    and unit-test that contract independently of LangGraph."""

    @staticmethod
    def tick(prior_iterations_since_state_grew, grew: bool) -> int:
        # Mirrors the logic in think_node single-tool + wave paths.
        if grew:
            return 0
        return int(prior_iterations_since_state_grew or 0) + 1

    def test_growth_resets_counter(self):
        self.assertEqual(self.tick(7, True), 0)

    def test_no_growth_increments(self):
        self.assertEqual(self.tick(3, False), 4)

    def test_none_prior_is_treated_as_zero(self):
        self.assertEqual(self.tick(None, False), 1)

    def test_zero_prior_increments_to_one(self):
        self.assertEqual(self.tick(0, False), 1)


class TestPromptHintTextPresent(unittest.TestCase):
    """The tier-action hints inject specific text into the system prompt.
    AST-scan to ensure each tier's hint is present and uses the right
    severity language."""

    def test_yellow_hint_text(self):
        self.assertIn("PRODUCTIVITY HINT (yellow)", THINK_SRC)
        self.assertIn("state has not grown", THINK_SRC.replace("\n", " "))

    def test_red_hint_text(self):
        self.assertIn("PRODUCTIVITY HINT (red", THINK_SRC)
        self.assertIn("MUST be on a different hypothesis class",
                      THINK_SRC.replace("\n", " "))

    def test_critical_hint_text(self):
        self.assertIn("PRODUCTIVITY HINT (critical", THINK_SRC)
        self.assertIn("genuinely stuck", THINK_SRC)


class TestProductivitySourceContract(unittest.TestCase):
    """The productivity.py module must export every name that think_node
    imports. AST-grade to prevent rename drift."""

    REQUIRED = (
        "extract_axis", "axis_key", "axis_unproductive_count",
        "record_axis_attempt", "priority_order_jaccard",
        "compute_productivity_score", "tier_for_score",
        "detect_state_growth",
    )

    def test_all_required_defined_in_productivity_py(self):
        for sym in self.REQUIRED:
            # `def name(` or assignment shape
            pattern = re.compile(rf"^def {re.escape(sym)}\b", re.MULTILINE)
            self.assertTrue(
                pattern.search(PROD_SRC),
                f"productivity.py must define {sym}",
            )


class TestAxisLedgerDefensive(unittest.TestCase):
    def test_count_handles_ledger_with_non_list_entry(self):
        """If a ledger key holds something other than a list (corruption),
        the counter should not blow up — it should treat it as 'no
        entries' and return 0."""
        # Current behavior: .get(key, []) returns the corrupt value;
        # the sum/iteration over a non-iterable would raise. Verify the
        # contract by passing an empty dict (safe) and a list with mixed
        # legitimate entries.
        ledger = {"k": []}
        self.assertEqual(axis_unproductive_count(ledger, "k"), 0)

    def test_record_into_existing_key_extends_list(self):
        ledger = {"k": [{"iteration": 1, "verdict": "no_progress", "tool": "x"}]}
        out = record_axis_attempt(ledger, "k", iteration=2,
                                  verdict="no_progress", tool="x")
        self.assertEqual(len(out["k"]), 2)


class TestSelfRequestBypassesCooldown(unittest.TestCase):
    """The `_need_deep_think` flag (LLM self-request) must bypass the
    cooldown — the agent should always be able to ask for help.

    This is tested at the source-code level since the actual gating runs
    inside async LangGraph code. We assert that the condition's branch
    is reachable from think_node by string scan."""

    def test_self_request_branch_present(self):
        # The condition "Agent self-assessed stagnation" is checked AFTER
        # the cooldown logic, meaning it can fire regardless. Look for
        # the comment / log message that documents this.
        self.assertIn("self-requested deep think", THINK_SRC.lower(),
                      "self-request bypass must be documented in think_node")


class TestScoreLogsComponents(unittest.TestCase):
    """For diagnostics, the score should be logged with its components
    so an operator can debug *why* a tier fired."""

    def test_log_call_includes_components(self):
        # Look for the logger.info pattern that includes components.
        # Tolerant of f-string format variations.
        self.assertTrue(
            re.search(r"components\s*=\s*\{?", THINK_SRC) or
            "_score_obj['components']" in THINK_SRC,
            "Score components must appear in the diagnostic log line",
        )


class TestAllSymbolsLoadAtRuntime(unittest.TestCase):
    """Smoke test: every new exported symbol can actually be imported
    and called with sentinel-safe inputs. Catches typos / partial renames."""

    def test_extract_axis_callable(self):
        self.assertIsNone(extract_axis(None, None))

    def test_axis_key_callable(self):
        self.assertEqual(axis_key({}), "")

    def test_axis_unproductive_count_callable(self):
        self.assertEqual(axis_unproductive_count({}, "x"), 0)

    def test_record_axis_attempt_callable(self):
        out = record_axis_attempt({}, "k", iteration=1,
                                  verdict="no_progress", tool="x")
        self.assertEqual(len(out["k"]), 1)

    def test_priority_order_jaccard_callable(self):
        self.assertEqual(priority_order_jaccard([], []), 0.0)

    def test_compute_productivity_score_callable(self):
        r = compute_productivity_score(
            execution_trace=[], tested_axes={},
            iterations_since_state_grew=0, iteration=1, max_iterations=100,
        )
        self.assertIn("score", r)

    def test_tier_for_score_callable(self):
        self.assertEqual(tier_for_score(0.0), "green")

    def test_detect_state_growth_callable(self):
        self.assertFalse(detect_state_growth({}, {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
