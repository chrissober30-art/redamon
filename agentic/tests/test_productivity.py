"""Tests for the productivity-based loop detector.

Covers four layers:

1. Unit — every helper in productivity.py, with mock step dicts.
2. State integration — the new ProductivityVerdict + OutputAnalysisInline field.
3. Loop-detector behavior — does the orchestrator's "is this an unproductive
   streak?" decision match expectations across the failure modes that
   triggered the original XBEN-001-24 loop?
4. Regression — every legacy keyword failure case still trips.

Test fixtures construct step dicts that mirror what think_node persists onto
execution_trace, so the helpers receive realistic shapes (productivity at the
top level, plus the older nested fallback for safety).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

# Ensure agent/ is importable for the pydantic-dependent state tests below.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load productivity.py DIRECTLY (no package import) so the stdlib-only tests
# work without pydantic installed. The package __init__ pulls in state.py
# which requires pydantic; the productivity module itself does not.
_PROD_PATH = os.path.join(
    os.path.dirname(__file__), "..", "orchestrator_helpers", "productivity.py"
)
_spec = importlib.util.spec_from_file_location("_prod_under_test", _PROD_PATH)
_prod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_prod)

_normalize_args_pattern = _prod._normalize_args_pattern
_output_fingerprint = _prod._output_fingerprint
_read_productivity = _prod._read_productivity
audit_productivity_claim = _prod.audit_productivity_claim
build_productivity_audit_section = _prod.build_productivity_audit_section
detect_uniform_response_anomaly = _prod.detect_uniform_response_anomaly
# Productivity v2 exports
extract_axis = _prod.extract_axis
axis_key = _prod.axis_key
axis_unproductive_count = _prod.axis_unproductive_count
record_axis_attempt = _prod.record_axis_attempt
priority_order_jaccard = _prod.priority_order_jaccard
compute_productivity_score = _prod.compute_productivity_score
tier_for_score = _prod.tier_for_score
detect_state_growth = _prod.detect_state_growth
detect_diagnostic_progress = _prod.detect_diagnostic_progress
downgrade_verdict_to_no_progress = _prod.downgrade_verdict_to_no_progress
is_unproductive = _prod.is_unproductive
_same_pattern_count = _prod._same_pattern_count
update_stall_counters = _prod.update_stall_counters


def _make_step(*, tool="execute_curl", args=None, output="", success=True,
               productivity=None, step_iteration=1):
    """Build a step dict that mirrors what think_node persists."""
    step = {
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
        step["productivity"] = productivity
    return step


def _verdict(verdict="new_info", gained=True, what="", repeat=False, why=""):
    return {
        "verdict": verdict,
        "new_information_gained": gained,
        "what_was_new": what,
        "should_repeat_similar_call": repeat,
        "rationale": why,
    }


class TestNormalizeArgsPattern(unittest.TestCase):
    """Different IDs at the same path must collapse to one pattern, but
    different paths or different tools must stay distinct."""

    def test_integer_ids_collapse(self):
        sig_a = _normalize_args_pattern("execute_curl", {"args": "GET /order/300500/receipt"})
        sig_b = _normalize_args_pattern("execute_curl", {"args": "GET /order/300600/receipt"})
        self.assertEqual(sig_a, sig_b, "Two URLs differing only in <int> must share a pattern")

    def test_different_paths_distinct(self):
        sig_a = _normalize_args_pattern("execute_curl", {"args": "GET /order/300500/receipt"})
        sig_b = _normalize_args_pattern("execute_curl", {"args": "GET /profile"})
        self.assertNotEqual(sig_a, sig_b)

    def test_different_tools_distinct(self):
        sig_a = _normalize_args_pattern("execute_curl", {"args": "GET /x"})
        sig_b = _normalize_args_pattern("execute_nmap", {"args": "-sV /x"})
        self.assertNotEqual(sig_a, sig_b)

    def test_hex_tokens_collapse(self):
        sig_a = _normalize_args_pattern("execute_curl", {"args": "GET /api/a1b2c3d4e5f6"})
        sig_b = _normalize_args_pattern("execute_curl", {"args": "GET /api/deadbeef1234"})
        self.assertEqual(sig_a, sig_b, "Long hex tokens must collapse to <hex>")

    def test_ips_collapse(self):
        sig_a = _normalize_args_pattern("execute_curl", {"args": "http://192.168.1.10/"})
        sig_b = _normalize_args_pattern("execute_curl", {"args": "http://10.0.0.5/"})
        self.assertEqual(sig_a, sig_b)

    def test_handles_none_args(self):
        sig = _normalize_args_pattern("execute_curl", None)
        self.assertIn("execute_curl", sig)

    def test_handles_none_tool(self):
        sig = _normalize_args_pattern(None, {"x": 1})
        self.assertIn("?", sig)


class TestOutputFingerprint(unittest.TestCase):
    """Same logical content must produce the same fingerprint, even with
    trivial diffs like whitespace, timestamps, or UUIDs."""

    def test_identical_outputs_same_fingerprint(self):
        a = _make_step(output="<html><body>Empty receipt</body></html>")
        b = _make_step(output="<html><body>Empty receipt</body></html>")
        self.assertEqual(_output_fingerprint(a), _output_fingerprint(b))

    def test_whitespace_does_not_change_fingerprint(self):
        a = _make_step(output="<html><body>Empty\nreceipt</body></html>")
        b = _make_step(output="<html><body>Empty    receipt</body></html>")
        self.assertEqual(_output_fingerprint(a), _output_fingerprint(b))

    def test_timestamps_normalized(self):
        a = _make_step(output="<p>2026-05-17T08:14:01.234Z OK</p>")
        b = _make_step(output="<p>2026-05-17T09:42:11.000Z OK</p>")
        self.assertEqual(_output_fingerprint(a), _output_fingerprint(b),
                         "ISO timestamps must collapse to <ts>")

    def test_uuids_normalized(self):
        a = _make_step(output="request_id=abcd1234-aaaa-bbbb-cccc-deadbeef1234 done")
        b = _make_step(output="request_id=99887766-5544-3322-1100-ffeeddccbbaa done")
        self.assertEqual(_output_fingerprint(a), _output_fingerprint(b))

    def test_different_content_different_fingerprint(self):
        a = _make_step(output="Empty receipt for missing order")
        b = _make_step(output="Order 300123 found, $50,000 trade in AAPL")
        self.assertNotEqual(_output_fingerprint(a), _output_fingerprint(b))

    def test_empty_output_stable(self):
        a = _make_step(output="")
        b = _make_step(output="")
        self.assertEqual(_output_fingerprint(a), _output_fingerprint(b))

    def test_fingerprint_length_is_8(self):
        fp = _output_fingerprint(_make_step(output="anything"))
        self.assertEqual(len(fp), 8)


class TestReadProductivity(unittest.TestCase):
    """The helper must accept both shapes the codebase uses:
    top-level step['productivity'] (preferred, used by think_node) and
    nested step['output_analysis']['productivity'] (forward-compat)."""

    def test_top_level(self):
        step = _make_step(productivity=_verdict(verdict="no_progress", gained=False))
        p = _read_productivity(step)
        self.assertEqual(p["verdict"], "no_progress")

    def test_nested(self):
        step = _make_step()
        step["output_analysis"] = {"productivity": _verdict(verdict="duplicate")}
        p = _read_productivity(step)
        self.assertEqual(p["verdict"], "duplicate")

    def test_top_level_wins(self):
        step = _make_step(productivity=_verdict(verdict="new_info"))
        step["output_analysis"] = {"productivity": _verdict(verdict="duplicate")}
        p = _read_productivity(step)
        self.assertEqual(p["verdict"], "new_info",
                         "When both shapes are present, top-level must take priority")

    def test_missing_returns_empty(self):
        step = _make_step()
        self.assertEqual(_read_productivity(step), {})

    def test_none_step(self):
        self.assertEqual(_read_productivity(None), {})

    def test_output_analysis_is_string(self):
        """Real-world: think_node stores output_analysis as a string
        (the interpretation). Must not crash."""
        step = _make_step()
        step["output_analysis"] = "some interpretation text"
        # No productivity anywhere — must return {}
        self.assertEqual(_read_productivity(step), {})


class TestIsUnproductive(unittest.TestCase):
    """The boolean dispatcher consumed by the loop counter."""

    def test_new_info_is_productive(self):
        step = _make_step(productivity=_verdict(verdict="new_info", gained=True))
        self.assertFalse(is_unproductive(step))

    def test_confirmation_is_productive(self):
        step = _make_step(productivity=_verdict(verdict="confirmation", gained=True))
        self.assertFalse(is_unproductive(step),
                         "confirmation is acceptable; only no_progress/duplicate/blocked count")

    def test_no_progress_is_unproductive(self):
        step = _make_step(productivity=_verdict(verdict="no_progress", gained=False))
        self.assertTrue(is_unproductive(step))

    def test_duplicate_is_unproductive(self):
        step = _make_step(productivity=_verdict(verdict="duplicate", gained=False))
        self.assertTrue(is_unproductive(step))

    def test_blocked_is_unproductive(self):
        step = _make_step(productivity=_verdict(verdict="blocked", gained=False))
        self.assertTrue(is_unproductive(step))

    def test_gained_false_overrides_optimistic_verdict(self):
        """If the LLM claims 'new_info' but flags gained=False, treat as unproductive.
        Defends against schema-confused responses."""
        step = _make_step(productivity=_verdict(verdict="new_info", gained=False))
        self.assertTrue(is_unproductive(step))

    def test_missing_productivity_is_productive_by_default(self):
        """No verdict field means we fall back to keyword detection (legacy
        behavior is preserved). is_unproductive itself returns False."""
        step = _make_step()
        self.assertFalse(is_unproductive(step))


class TestAuditProductivityClaim(unittest.TestCase):
    """The honesty cross-check that catches optimistic LLM claims."""

    def test_no_productivity_returns_none(self):
        self.assertIsNone(audit_productivity_claim({}, {}, [], False))

    def test_honest_new_info_passes(self):
        result = audit_productivity_claim(
            productivity=_verdict(verdict="new_info", gained=True),
            extracted_info={"ports": [80, 443]},
            actionable_findings=[],
            findings_grew=False,
        )
        self.assertIsNone(result, "extracted_info populated → claim is honest")

    def test_dishonest_claim_caught(self):
        result = audit_productivity_claim(
            productivity=_verdict(verdict="new_info", gained=True),
            extracted_info={},
            actionable_findings=[],
            findings_grew=False,
        )
        self.assertIsNotNone(result, "Claimed new info but nothing grew")
        self.assertIn("new_information_gained=true", result)

    def test_findings_growth_alone_is_enough(self):
        result = audit_productivity_claim(
            productivity=_verdict(verdict="new_info", gained=True),
            extracted_info={},
            actionable_findings=[],
            findings_grew=True,
        )
        self.assertIsNone(result)

    def test_actionable_findings_alone_is_enough(self):
        result = audit_productivity_claim(
            productivity=_verdict(verdict="new_info", gained=True),
            extracted_info={},
            actionable_findings=["explore /admin"],
            findings_grew=False,
        )
        self.assertIsNone(result)

    def test_no_progress_verdict_never_flagged(self):
        """An honest 'no_progress' claim with no growth must NOT be flagged
        as a discrepancy — it's already a self-admission."""
        result = audit_productivity_claim(
            productivity=_verdict(verdict="no_progress", gained=False),
            extracted_info={},
            actionable_findings=[],
            findings_grew=False,
        )
        self.assertIsNone(result)

    def test_extracted_info_with_only_primary_target_does_not_save(self):
        """primary_target is required for every iteration; it does not count
        as 'new info' on its own."""
        result = audit_productivity_claim(
            productivity=_verdict(verdict="new_info", gained=True),
            extracted_info={"primary_target": "host"},
            actionable_findings=[],
            findings_grew=False,
        )
        self.assertIsNotNone(result,
            "primary_target alone is required boilerplate, not new info")


class TestDowngradeVerdict(unittest.TestCase):
    """Verdict downgrade for dishonest claims."""

    def test_downgrades_verdict(self):
        v = _verdict(verdict="new_info", gained=True)
        out = downgrade_verdict_to_no_progress(v, "test reason")
        self.assertEqual(out["verdict"], "no_progress")
        self.assertFalse(out["new_information_gained"])
        self.assertEqual(out["_original_verdict"], "new_info")
        self.assertEqual(out["_downgrade_reason"], "test reason")

    def test_preserves_other_fields(self):
        v = _verdict(verdict="new_info", gained=True, what="found admin", why="cited evidence")
        out = downgrade_verdict_to_no_progress(v, "test reason")
        self.assertEqual(out["what_was_new"], "found admin")
        self.assertEqual(out["rationale"], "cited evidence")

    def test_handles_empty_input(self):
        out = downgrade_verdict_to_no_progress({}, "missing field")
        self.assertEqual(out["verdict"], "no_progress")
        self.assertFalse(out["new_information_gained"])
        self.assertEqual(out["_downgrade_reason"], "missing field")

    def test_does_not_mutate_input(self):
        v = _verdict(verdict="new_info", gained=True)
        _ = downgrade_verdict_to_no_progress(v, "x")
        self.assertEqual(v["verdict"], "new_info", "Input must be left untouched")


class TestBuildProductivityAuditSection(unittest.TestCase):
    """The prompt block that shows the model its own recent fingerprints."""

    def test_empty_trace_no_section(self):
        self.assertEqual(build_productivity_audit_section([]), "")

    def test_fewer_than_three_same_pattern_no_section(self):
        trace = [
            _make_step(args={"args": "GET /order/300500/receipt"}, output="empty"),
            _make_step(args={"args": "GET /order/300600/receipt"}, output="empty"),
        ]
        self.assertEqual(build_productivity_audit_section(trace), "")

    def test_three_same_pattern_triggers(self):
        trace = [
            _make_step(args={"args": "GET /order/300500/receipt"}, output="empty"),
            _make_step(args={"args": "GET /order/300600/receipt"}, output="empty"),
            _make_step(args={"args": "GET /order/300700/receipt"}, output="empty"),
        ]
        section = build_productivity_audit_section(trace)
        self.assertIn("Productivity Audit", section)
        self.assertIn("fp=", section, "Must show fingerprints")

    def test_diversity_hint_when_all_identical(self):
        trace = [
            _make_step(args={"args": "GET /order/300500/receipt"}, output="empty receipt"),
            _make_step(args={"args": "GET /order/300600/receipt"}, output="empty receipt"),
            _make_step(args={"args": "GET /order/300700/receipt"}, output="empty receipt"),
            _make_step(args={"args": "GET /order/300800/receipt"}, output="empty receipt"),
        ]
        section = build_productivity_audit_section(trace)
        self.assertIn("ALL identical", section)

    def test_diversity_hint_when_varied(self):
        trace = [
            _make_step(args={"args": "GET /order/1/receipt"}, output="result A"),
            _make_step(args={"args": "GET /order/2/receipt"}, output="result B"),
            _make_step(args={"args": "GET /order/3/receipt"}, output="result C"),
        ]
        section = build_productivity_audit_section(trace)
        self.assertIn("unique fingerprints", section)
        self.assertNotIn("ALL identical", section)

    def test_picks_most_repeated_pattern_when_no_current(self):
        """With no current step provided, the helper must surface whichever
        pattern is repeating the most in the recent window."""
        trace = [
            _make_step(args={"args": "GET /profile"}, output="profile"),
            _make_step(args={"args": "GET /order/1/receipt"}, output="empty"),
            _make_step(args={"args": "GET /order/2/receipt"}, output="empty"),
            _make_step(args={"args": "GET /order/3/receipt"}, output="empty"),
        ]
        section = build_productivity_audit_section(trace)
        self.assertIn("/order/", section)
        self.assertNotIn("/profile", section.split("Productivity Audit")[1])

    def test_filters_to_current_pattern(self):
        trace = [
            _make_step(args={"args": "GET /profile"}),
            _make_step(args={"args": "GET /order/1/receipt"}),
            _make_step(args={"args": "GET /order/2/receipt"}),
            _make_step(args={"args": "GET /order/3/receipt"}),
        ]
        section = build_productivity_audit_section(
            trace,
            current_tool_name="execute_curl",
            current_tool_args={"args": "GET /order/4/receipt"},
        )
        # Only the order-receipt pattern should appear in the listing block.
        listing = section.split("Recent same-pattern")[1] if "Recent same-pattern" in section else section
        self.assertIn("/order/", listing)
        self.assertNotIn("/profile", listing)

    def test_includes_decision_rules(self):
        trace = [
            _make_step(args={"args": f"GET /x/{i}/y"}, output="same") for i in range(4)
        ]
        section = build_productivity_audit_section(trace)
        self.assertIn("duplicate", section)
        self.assertIn("blocked", section)
        self.assertIn("confirmation", section)


# ---------------------------------------------------------------------------
# Layer 2: state-model smoke (requires pydantic; gracefully skipped if not).
# ---------------------------------------------------------------------------

try:
    from state import OutputAnalysisInline, ProductivityVerdict  # type: ignore
    _HAS_PYDANTIC = True
except Exception:
    _HAS_PYDANTIC = False


@unittest.skipUnless(_HAS_PYDANTIC, "pydantic not installed in this env")
class TestProductivitySchema(unittest.TestCase):
    """The new field on OutputAnalysisInline must accept valid verdicts,
    reject invalid ones, and round-trip cleanly through model_dump."""

    def test_default_construction(self):
        p = ProductivityVerdict()
        self.assertEqual(p.verdict, "new_info")
        self.assertTrue(p.new_information_gained)

    def test_each_verdict_value_accepted(self):
        for v in ("new_info", "confirmation", "no_progress", "blocked", "duplicate"):
            p = ProductivityVerdict(verdict=v, new_information_gained=False)
            self.assertEqual(p.verdict, v)

    def test_invalid_verdict_rejected(self):
        with self.assertRaises(Exception):
            ProductivityVerdict(verdict="bogus")

    def test_round_trip_through_model_dump(self):
        p = ProductivityVerdict(
            verdict="duplicate", new_information_gained=False,
            what_was_new="", should_repeat_similar_call=False,
            rationale="same fingerprint as last 3",
        )
        d = p.model_dump()
        self.assertEqual(d["verdict"], "duplicate")
        self.assertEqual(d["rationale"], "same fingerprint as last 3")
        p2 = ProductivityVerdict(**d)
        self.assertEqual(p2.verdict, "duplicate")

    def test_output_analysis_inline_has_productivity(self):
        oa = OutputAnalysisInline()
        self.assertIsInstance(oa.productivity, ProductivityVerdict)
        self.assertEqual(oa.productivity.verdict, "new_info")

    def test_output_analysis_inline_accepts_explicit_productivity(self):
        oa = OutputAnalysisInline(
            interpretation="probed receipt endpoint",
            productivity=ProductivityVerdict(
                verdict="no_progress", new_information_gained=False,
                what_was_new="", should_repeat_similar_call=False,
                rationale="empty receipt template",
            ),
        )
        self.assertEqual(oa.productivity.verdict, "no_progress")
        self.assertFalse(oa.productivity.new_information_gained)

    def test_backward_compat_missing_productivity_uses_default(self):
        """Old LLM outputs without productivity must still parse."""
        oa = OutputAnalysisInline.model_validate({
            "interpretation": "x",
            "actionable_findings": [],
            "recommended_next_steps": [],
            "exploit_succeeded": False,
        })
        self.assertEqual(oa.productivity.verdict, "new_info",
                         "Default verdict applied when LLM omits the field")


# ---------------------------------------------------------------------------
# Layer 3: loop-detector simulation.
# Reproduces the think_node Place-1 logic against a synthetic execution_trace.
# Verifies the new detector catches the XBEN-001-24 failure mode that the
# legacy keyword detector missed.
# ---------------------------------------------------------------------------

def _simulate_loop_detector(execution_trace, window=6, threshold=3):
    """Mirror of think_node Place-1 logic. Returns True if the orchestrator
    would fire Deep Think on the unproductive-streak condition."""
    if len(execution_trace) < threshold:
        return False
    count = 0
    for step in execution_trace[-window:]:
        out = ((step.get("tool_output") or "")[:500]).lower()
        kw_fail = (
            not step.get("success", True)
            or "failed" in out
            or "error" in out
            or "exploit completed, but no session" in out
        )
        if kw_fail or is_unproductive(step):
            count += 1
    return count >= threshold


class TestLoopDetectorEndToEnd(unittest.TestCase):
    """Integration: simulate think_node's logic against canned traces."""

    def test_xben_001_loop_now_caught(self):
        """The exact failure mode we observed: 200 OK with empty-receipt body
        repeated, LLM verdicts honestly mark them as no_progress."""
        trace = [
            _make_step(
                args={"args": f"GET /order/{i}/receipt"},
                output="HTTP 200 ... <code></code> ...",
                success=True,
                productivity=_verdict(verdict="no_progress", gained=False),
                step_iteration=i,
            )
            for i in range(300100, 300600, 100)
        ]
        self.assertTrue(_simulate_loop_detector(trace),
            "Empty-receipt streak with no_progress verdicts must trip detector")

    def test_xben_001_loop_legacy_detector_missed(self):
        """The same streak — but WITHOUT the productivity field. This simulates
        the world before this patch, and the detector should NOT fire (proving
        the legacy keyword check was blind here)."""
        trace = [
            _make_step(
                args={"args": f"GET /order/{i}/receipt"},
                output="HTTP 200 ... <code></code> ...",
                success=True,
                # No productivity field — pure legacy keyword path.
                step_iteration=i,
            )
            for i in range(300100, 300600, 100)
        ]
        self.assertFalse(_simulate_loop_detector(trace),
            "Legacy-only detector must NOT fire on this (proves the bug)")

    def test_productive_run_does_not_trigger(self):
        """A healthy run of varied productive steps must not trigger."""
        trace = [
            _make_step(
                args={"args": f"GET /endpoint/{i}"},
                output=f"unique content {i}",
                success=True,
                productivity=_verdict(verdict="new_info", gained=True),
                step_iteration=i,
            )
            for i in range(5)
        ]
        self.assertFalse(_simulate_loop_detector(trace))

    def test_mixed_run_below_threshold_does_not_trigger(self):
        """Two unproductive + four productive in a 6-window → below threshold."""
        trace = [
            _make_step(productivity=_verdict(verdict="no_progress", gained=False)),
            _make_step(productivity=_verdict(verdict="new_info", gained=True)),
            _make_step(productivity=_verdict(verdict="new_info", gained=True)),
            _make_step(productivity=_verdict(verdict="no_progress", gained=False)),
            _make_step(productivity=_verdict(verdict="new_info", gained=True)),
            _make_step(productivity=_verdict(verdict="new_info", gained=True)),
        ]
        self.assertFalse(_simulate_loop_detector(trace))

    def test_mixed_run_at_threshold_triggers(self):
        """Three unproductive in a six-window — at threshold, must fire."""
        trace = [
            _make_step(productivity=_verdict(verdict="no_progress", gained=False)),
            _make_step(productivity=_verdict(verdict="new_info", gained=True)),
            _make_step(productivity=_verdict(verdict="duplicate", gained=False)),
            _make_step(productivity=_verdict(verdict="blocked", gained=False)),
            _make_step(productivity=_verdict(verdict="new_info", gained=True)),
            _make_step(productivity=_verdict(verdict="confirmation", gained=True)),
        ]
        self.assertTrue(_simulate_loop_detector(trace))

    def test_blocked_streak_triggers(self):
        """WAF returning 403s — keyword 'forbidden' may or may not appear, but
        the LLM's 'blocked' verdict must trip the detector regardless."""
        trace = [
            _make_step(
                output="<html>403 Forbidden</html>",
                productivity=_verdict(verdict="blocked", gained=False),
            )
            for _ in range(4)
        ]
        self.assertTrue(_simulate_loop_detector(trace))

    def test_window_respected(self):
        """An old unproductive streak outside the window must not count."""
        trace = (
            [_make_step(productivity=_verdict(verdict="no_progress", gained=False))] * 3
            + [_make_step(productivity=_verdict(verdict="new_info", gained=True))] * 6
        )
        # Last 6 are all productive, so detector must not fire.
        self.assertFalse(_simulate_loop_detector(trace))


# ---------------------------------------------------------------------------
# Layer 4: regression — every legacy keyword failure still fires.
# Guarantees we did not weaken any existing case.
# ---------------------------------------------------------------------------

class TestLegacyKeywordRegressions(unittest.TestCase):
    """Every keyword case the old detector caught must STILL trip the new one,
    because we OR'd the keyword check with is_unproductive."""

    def test_success_false_streak_triggers(self):
        trace = [
            _make_step(success=False, output="connection reset")
            for _ in range(3)
        ]
        self.assertTrue(_simulate_loop_detector(trace))

    def test_failed_keyword_streak_triggers(self):
        trace = [
            _make_step(success=True, output="[-] Failed to bind socket")
            for _ in range(3)
        ]
        self.assertTrue(_simulate_loop_detector(trace))

    def test_error_keyword_streak_triggers(self):
        trace = [
            _make_step(success=True, output="HTTP 500 Internal Error")
            for _ in range(3)
        ]
        self.assertTrue(_simulate_loop_detector(trace))

    def test_metasploit_no_session_phrase_triggers(self):
        trace = [
            _make_step(
                tool="metasploit_console", success=True,
                output="[*] Exploit completed, but no session was created.",
            )
            for _ in range(3)
        ]
        self.assertTrue(_simulate_loop_detector(trace))

    def test_legacy_and_new_compose(self):
        """Two legacy failures + one LLM-flagged unproductive = 3 → trips."""
        trace = [
            _make_step(success=False, output="error"),
            _make_step(success=True, output="HTTP 200 OK", productivity=_verdict(verdict="duplicate", gained=False)),
            _make_step(success=True, output="failed to read"),
        ]
        self.assertTrue(_simulate_loop_detector(trace))


# ---------------------------------------------------------------------------
# Layer 5: smoke — productivity helpers under odd inputs must not crash.
# ---------------------------------------------------------------------------

class TestSettingsDefaults(unittest.TestCase):
    """Verify the two new settings are declared in DEFAULT_AGENT_SETTINGS so
    the orchestrator picks up sensible defaults if a project has not been
    upgraded. Reads project_settings.py as text to avoid needing pydantic."""

    def test_settings_declared(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "project_settings.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("'PRODUCTIVITY_AUDIT_WINDOW'", content)
        self.assertIn("'UNPRODUCTIVE_STREAK_THRESHOLD'", content)

    def test_defaults_are_sensible(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "project_settings.py"
        )
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # Window default 6, threshold default 3 — explicit so behavior is locked.
        self.assertIn("'PRODUCTIVITY_AUDIT_WINDOW': 6", content)
        self.assertIn("'UNPRODUCTIVE_STREAK_THRESHOLD': 3", content)


class TestThinkNodeWiring(unittest.TestCase):
    """Verify the patched think_node imports and call sites are syntactically
    integrated. Reads the file as text — catches typos, missed imports, and
    accidental removal of legacy logic. Cheap and high-value."""

    def setUp(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "orchestrator_helpers",
            "nodes", "think_node.py",
        )
        with open(path, "r", encoding="utf-8") as f:
            self.content = f.read()

    def test_productivity_imports_present(self):
        self.assertIn("from orchestrator_helpers.productivity import", self.content)
        self.assertIn("is_unproductive", self.content)
        self.assertIn("audit_productivity_claim", self.content)
        self.assertIn("build_productivity_audit_section", self.content)
        self.assertIn("downgrade_verdict_to_no_progress", self.content)

    def test_legacy_keyword_check_preserved_place_1(self):
        """The keyword path must stay so legacy failure cases still trigger."""
        self.assertIn('"failed" in _out', self.content)
        self.assertIn('"error" in _out', self.content)
        self.assertIn('"exploit completed, but no session" in _out', self.content)

    def test_legacy_keyword_check_preserved_place_2(self):
        # Place 2 uses output_lower (different variable name)
        self.assertIn('"failed" in output_lower', self.content)
        self.assertIn('"error" in output_lower', self.content)

    def test_new_check_or_composed_with_legacy(self):
        """The new is_unproductive call must be OR-ed with the legacy check,
        not replacing it."""
        # Look for the OR pattern in either Place 1 or Place 2.
        self.assertIn("is_unproductive(_step)", self.content)
        self.assertIn("is_unproductive(step)", self.content)

    def test_audit_section_injected(self):
        self.assertIn("build_productivity_audit_section", self.content)
        self.assertIn("_last_productivity_discrepancy", self.content)

    def test_productivity_persisted_on_step(self):
        """Each exec_step (wave + single) must persist the productivity dict."""
        self.assertIn('"productivity": dict(_wave_productivity)', self.content)
        self.assertIn('pending_step["productivity"]', self.content)

    def test_settings_referenced(self):
        self.assertIn("PRODUCTIVITY_AUDIT_WINDOW", self.content)
        self.assertIn("UNPRODUCTIVE_STREAK_THRESHOLD", self.content)


class TestFireteamMemberWiring(unittest.TestCase):
    """Same syntactic-integration check for the fireteam member node."""

    def setUp(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "orchestrator_helpers",
            "nodes", "fireteam_member_think_node.py",
        )
        with open(path, "r", encoding="utf-8") as f:
            self.content = f.read()

    def test_productivity_imports_present(self):
        self.assertIn("from orchestrator_helpers.productivity import", self.content)
        self.assertIn("audit_productivity_claim", self.content)
        self.assertIn("build_productivity_audit_section", self.content)

    def test_audit_section_injection_present(self):
        self.assertIn("build_productivity_audit_section", self.content)
        self.assertIn("_last_productivity_discrepancy", self.content)

    def test_productivity_persisted_on_completed_step(self):
        self.assertIn('completed_step["productivity"]', self.content)

    def test_productivity_persisted_on_wave_steps(self):
        self.assertIn('"productivity": dict(_wave_productivity)', self.content)

    def test_existing_stall_counters_preserved(self):
        """We added productivity as a SECOND layer on top of the existing
        fireteam stall counter — must not have removed the original."""
        self.assertIn("iterations_since_new_finding", self.content)
        self.assertIn("fallback_uses_this_run", self.content)


class TestPromptSchemaSync(unittest.TestCase):
    """Verify the prompt JSON-schema example documents the new productivity
    field, so the LLM knows it must emit it."""

    def setUp(self):
        base_path = os.path.join(
            os.path.dirname(__file__), "..", "prompts", "base.py"
        )
        with open(base_path, "r", encoding="utf-8") as f:
            self.base = f.read()
        member_path = os.path.join(
            os.path.dirname(__file__), "..", "orchestrator_helpers",
            "nodes", "fireteam_member_think_node.py",
        )
        with open(member_path, "r", encoding="utf-8") as f:
            self.member = f.read()

    def test_root_single_section_has_productivity(self):
        # Find the PENDING_OUTPUT_ANALYSIS_SECTION block.
        section = self.base.split("PENDING_OUTPUT_ANALYSIS_SECTION = ")[1].split(
            "PENDING_PLAN_OUTPUTS_SECTION"
        )[0]
        self.assertIn('"productivity"', section)
        self.assertIn("new_info", section)
        self.assertIn("no_progress", section)
        self.assertIn("duplicate", section)
        self.assertIn("blocked", section)

    def test_root_plan_section_has_productivity(self):
        section = self.base.split("PENDING_PLAN_OUTPUTS_SECTION = ")[1]
        self.assertIn('"productivity"', section)
        self.assertIn("no_progress", section)

    def test_member_single_section_has_productivity(self):
        section = self.member.split("_MEMBER_PENDING_OUTPUT_SECTION = ")[1].split(
            "_MEMBER_PENDING_PLAN_OUTPUTS_SECTION"
        )[0]
        self.assertIn('"productivity"', section)
        self.assertIn("no_progress", section)

    def test_member_plan_section_has_productivity(self):
        section = self.member.split("_MEMBER_PENDING_PLAN_OUTPUTS_SECTION = ")[1]
        self.assertIn('"productivity"', section)

    def test_all_five_verdicts_documented(self):
        """The model must see all 5 verdict values somewhere in the prompt."""
        all_text = self.base + self.member
        for verdict in ("new_info", "confirmation", "no_progress", "blocked", "duplicate"):
            self.assertIn(verdict, all_text, f"Missing verdict {verdict!r} from prompts")

    def test_diagnostic_progress_verdict_documented_in_root(self):
        """Fix 1: the new verdict must be documented in BOTH root sections
        (single + plan), so the main agent knows it may emit it. Kept separate
        from the fireteam check, which intentionally does not expose it."""
        single = self.base.split("PENDING_OUTPUT_ANALYSIS_SECTION = ")[1].split(
            "PENDING_PLAN_OUTPUTS_SECTION"
        )[0]
        plan = self.base.split("PENDING_PLAN_OUTPUTS_SECTION = ")[1]
        self.assertIn("diagnostic_progress", single)
        self.assertIn("diagnostic_progress", plan)

    def test_prompt_verdicts_match_model_literal(self):
        """Guard against drift: every verdict offered in the root prompt schema
        must be a value the ProductivityVerdict model actually accepts. (Runs
        only where pydantic is importable; skipped in the stdlib-only path.)"""
        try:
            from state import ProductivityVerdict  # noqa
            import typing
            allowed = set(typing.get_args(
                ProductivityVerdict.model_fields["verdict"].annotation))
        except Exception:
            self.skipTest("pydantic/state not importable in this environment")
        # Pull the verdict enum string from the root single section.
        section = self.base.split("PENDING_OUTPUT_ANALYSIS_SECTION = ")[1].split(
            "PENDING_PLAN_OUTPUTS_SECTION"
        )[0]
        line = [l for l in section.splitlines() if '"verdict"' in l][0]
        offered = {v.strip() for v in line.split('"verdict":')[1].split('|')}
        offered = {v.strip().strip('", ') for v in line.split(":", 1)[1].split("|")}
        offered = {v for v in offered if v.isidentifier()}
        self.assertTrue(offered.issubset(allowed),
                        f"prompt offers verdicts not in model: {offered - allowed}")
        self.assertIn("diagnostic_progress", offered)


class TestDowngradeIdempotence(unittest.TestCase):
    """Calling downgrade twice on the same dict must remain coherent: the
    second call sees an already-no_progress verdict and behaves sensibly."""

    def test_double_downgrade_preserves_no_progress(self):
        v = _verdict(verdict="new_info", gained=True)
        once = downgrade_verdict_to_no_progress(v, "first")
        twice = downgrade_verdict_to_no_progress(once, "second")
        self.assertEqual(twice["verdict"], "no_progress")
        self.assertFalse(twice["new_information_gained"])

    def test_double_downgrade_keeps_latest_reason(self):
        v = _verdict(verdict="new_info", gained=True)
        once = downgrade_verdict_to_no_progress(v, "first")
        twice = downgrade_verdict_to_no_progress(once, "second")
        self.assertEqual(twice["_downgrade_reason"], "second")


class TestSmokeRobustness(unittest.TestCase):
    """Defensive checks: every helper must handle missing/None/odd inputs
    without crashing. The orchestrator may pass partial state during
    interrupted runs."""

    def test_is_unproductive_handles_missing_keys(self):
        self.assertFalse(is_unproductive({}))
        self.assertFalse(is_unproductive({"foo": "bar"}))

    def test_normalize_handles_none(self):
        sig = _normalize_args_pattern(None, None)
        self.assertIsInstance(sig, str)
        self.assertGreater(len(sig), 0)

    def test_fingerprint_handles_none_output(self):
        step = _make_step(output=None)
        step["tool_output"] = None
        fp = _output_fingerprint(step)
        self.assertEqual(len(fp), 8)

    def test_fingerprint_handles_very_long_output(self):
        step = _make_step(output="X" * 100000)
        fp = _output_fingerprint(step)
        self.assertEqual(len(fp), 8)

    def test_audit_handles_none_inputs(self):
        self.assertIsNone(audit_productivity_claim(None, None, None, False))

    def test_audit_handles_partial_productivity(self):
        # Productivity dict missing fields — must not crash, must not falsely
        # flag (verdict defaults to None, new claim defaults to False).
        result = audit_productivity_claim(
            productivity={"verdict": "no_progress"},
            extracted_info={},
            actionable_findings=[],
            findings_grew=False,
        )
        self.assertIsNone(result)

    def test_build_section_handles_step_without_args(self):
        trace = [
            {"tool_name": "execute_curl", "tool_output": "x"}
            for _ in range(3)
        ]
        # Should not crash even though args/iteration keys are missing.
        section = build_productivity_audit_section(trace)
        self.assertIsInstance(section, str)


# ---------------------------------------------------------------------------
# detect_uniform_response_anomaly — P3 (response-uniformity cliff detector)
# ---------------------------------------------------------------------------

def _uniform_step(*, error_class="application_5xx_fast", output="Internal Server Error",
                  duration_ms=3, success=True, tool="execute_curl", args=None):
    """Build a step dict shaped like execute_plan_node persists post-feature."""
    return {
        "tool_name": tool,
        "tool_args": args or {"args": "-X POST http://target/"},
        "tool_output": output,
        "success": success,
        "error_class": error_class,
        "duration_ms": duration_ms,
        "iteration": 1,
    }


class TestDetectUniformResponseAnomalyFiresCorrectly(unittest.TestCase):
    """The exact failure mode from XBEN-006-24 iter 11: twelve different SQL
    payloads all returned 500-in-3ms. Without this detector the LLM marked
    SQLi 'tested' and pivoted away. With it, the prompt now carries a
    warning that the input is being rejected at parse time."""

    def test_fires_on_twelve_fast_5xx(self):
        trace = [
            _uniform_step(duration_ms=d)
            for d in [3, 4, 2, 5, 3, 4, 2, 3, 5, 4, 3, 2]
        ]
        warning = detect_uniform_response_anomaly(trace)
        self.assertIsNotNone(warning, "Should fire on 12 fast 5xx in window")
        self.assertIn("RESPONSE-UNIFORMITY ANOMALY", warning)
        self.assertIn("application_5xx_fast", warning)
        # Remediation hint must mention parse-time / early-guard for this class
        self.assertIn("parse time", warning.lower())

    def test_fires_on_six_shell_parser_errors(self):
        trace = [
            _uniform_step(
                error_class="shell_parser_error",
                output="[ERROR] No closing quotation",
                duration_ms=8,
                success=False,
            )
            for _ in range(6)
        ]
        warning = detect_uniform_response_anomaly(trace)
        self.assertIsNotNone(warning)
        self.assertIn("shell_parser_error", warning)
        # Hint must steer toward switching tool family
        self.assertIn("execute_code", warning)

    def test_fires_on_transport_error_streak(self):
        trace = [
            _uniform_step(
                error_class="transport_error",
                output="Could not resolve host",
                duration_ms=15,
                success=False,
            )
            for _ in range(5)
        ]
        warning = detect_uniform_response_anomaly(trace)
        self.assertIsNotNone(warning)
        self.assertIn("transport_error", warning)

    def test_fires_on_tool_internal_streak(self):
        """The iter-6 file-read failure repeated five times would land here."""
        trace = [
            _uniform_step(
                error_class="tool_internal_error",
                output="[ERROR] execute_curl failed: returncode=26",
                duration_ms=10,
                success=False,
            )
            for _ in range(5)
        ]
        warning = detect_uniform_response_anomaly(trace)
        self.assertIsNotNone(warning)

    def test_silent_on_uniform_4xx_streak(self):
        """4xx is a legitimate semantic rejection — the server DID process
        the request and gave a real answer (404 = not found, 405 = method
        not allowed, etc). The detector must NOT fire on uniform 4xx because
        firing would tell the agent 'your input never reached the layer'
        when in fact the layer responded conclusively. Firing on benign
        4xx would also burn the warning's signal value: if the agent gets
        false-positive 'do not mark this tested' warnings on legitimate
        404s during recon, it learns to ignore the warning, blunting it
        for the cases where it's actually true (uniform fast-5xx, shell
        quoting failures, etc).

        The fire-only-on-diagnostic-failure-classes filter (mirrored from
        `error_class.is_diagnostic_failure`) is what enforces this — 4xx
        is excluded from the diagnostic-failure set."""
        trace = [
            _uniform_step(
                error_class="application_4xx",
                output="HTTP/1.1 405 Method Not Allowed",
                duration_ms=10,
            )
            for _ in range(5)
        ]
        warning = detect_uniform_response_anomaly(trace)
        self.assertIsNone(
            warning,
            "Detector fired on uniform 4xx — that's a false positive. 4xx "
            "is a legitimate negative result, not a parse-time crash. "
            "Firing here would teach the agent to ignore real warnings.",
        )


class TestDetectUniformResponseAnomalyStaysSilent(unittest.TestCase):
    """The detector must NOT cry wolf. Successful baselines, mixed latency,
    too few samples, and legacy traces (no error_class) should all pass
    through silently."""

    def test_silent_on_clean_successes(self):
        trace = [
            _uniform_step(
                error_class="success",
                output='[{"id":1}]',
                duration_ms=20,
            )
            for _ in range(8)
        ]
        self.assertIsNone(detect_uniform_response_anomaly(trace))

    def test_silent_when_latency_breaks_fast_pattern(self):
        """One 200ms call in the streak breaks 'rejected at the door' — the
        request reached *something* deep enough to take real time."""
        trace = [
            _uniform_step(duration_ms=d)
            for d in [3, 4, 5, 3, 200, 3, 4, 5]
        ]
        self.assertIsNone(detect_uniform_response_anomaly(trace))

    def test_silent_below_min_count(self):
        """4 fast 5xx is suspicious but not yet evidence — min_count=5."""
        trace = [_uniform_step() for _ in range(4)]
        self.assertIsNone(detect_uniform_response_anomaly(trace))

    def test_silent_on_legacy_trace_without_error_class(self):
        """Backward compat: steps written before P2 shipped have no
        error_class field. They land in a '_legacy' bucket that never
        reaches min_count, so the detector stays silent."""
        trace = [
            {
                "tool_name": "execute_curl",
                "tool_args": {"args": "-X GET /"},
                "tool_output": "some body",
                "success": False,
                "duration_ms": 10,
                # No error_class
            }
            for _ in range(8)
        ]
        self.assertIsNone(detect_uniform_response_anomaly(trace))

    def test_silent_when_signatures_diverge(self):
        """Mixed classes — no signature reaches min_count."""
        trace = (
            [_uniform_step(error_class="application_5xx_fast") for _ in range(3)] +
            [_uniform_step(error_class="application_4xx") for _ in range(3)] +
            [_uniform_step(error_class="success") for _ in range(2)]
        )
        self.assertIsNone(detect_uniform_response_anomaly(trace))

    def test_silent_on_empty_trace(self):
        self.assertIsNone(detect_uniform_response_anomaly([]))

    def test_silent_on_zero_duration_treated_as_unknown(self):
        """duration_ms=0 means timing wasn't captured. The 'fast' mask
        requires d > 0 AND d < threshold, so unknown-timing streaks don't
        fire false positives."""
        trace = [
            _uniform_step(duration_ms=0)
            for _ in range(8)
        ]
        self.assertIsNone(detect_uniform_response_anomaly(trace))


class TestDetectUniformResponseAnomalyBoundaries(unittest.TestCase):
    """Window/threshold/tolerance edge cases — must behave predictably at
    every boundary the orchestrator can configure via project_settings."""

    def test_fires_exactly_at_min_count(self):
        trace = [_uniform_step() for _ in range(5)]
        self.assertIsNotNone(detect_uniform_response_anomaly(trace, min_count=5))

    def test_silent_one_below_min_count(self):
        trace = [_uniform_step() for _ in range(4)]
        self.assertIsNone(detect_uniform_response_anomaly(trace, min_count=5))

    def test_duration_threshold_boundary(self):
        """All durations must be STRICTLY less than threshold."""
        # 49ms with threshold=50 → fires
        trace = [_uniform_step(duration_ms=49) for _ in range(5)]
        self.assertIsNotNone(detect_uniform_response_anomaly(
            trace, duration_threshold_ms=50,
        ))
        # 50ms with threshold=50 → silent (not strictly less)
        trace = [_uniform_step(duration_ms=50) for _ in range(5)]
        self.assertIsNone(detect_uniform_response_anomaly(
            trace, duration_threshold_ms=50,
        ))

    def test_size_tolerance_groups_near_equal(self):
        """Two responses of 21 and 31 bytes with size_tolerance=32 share
        the same bucket (both fall in bucket 0: 21//32 = 31//32 = 0).
        At exactly the tolerance boundary, sizes cross into the next
        bucket — that's intentional (32//32 = 1, not 0)."""
        trace = (
            [_uniform_step(output="X" * 21) for _ in range(3)] +
            [_uniform_step(output="X" * 31) for _ in range(3)]
        )
        self.assertIsNotNone(detect_uniform_response_anomaly(
            trace, size_tolerance=32,
        ))

    def test_size_tolerance_separates_distant(self):
        """A 2000-byte response and a 21-byte response must NOT share a
        bucket — they came from different code paths."""
        trace = (
            [_uniform_step(output="X" * 21) for _ in range(3)] +
            [_uniform_step(output="X" * 2000) for _ in range(3)]
        )
        # Neither half reaches min_count=5 by itself
        self.assertIsNone(detect_uniform_response_anomaly(
            trace, size_tolerance=32,
        ))


class TestDetectUniformResponseAnomalyOutputShape(unittest.TestCase):
    """The warning is injected verbatim into the system prompt. Its shape
    must be stable so prompt-budget calculations don't regress."""

    def test_warning_has_required_sections(self):
        trace = [_uniform_step() for _ in range(8)]
        w = detect_uniform_response_anomaly(trace)
        self.assertIsNotNone(w)
        # Headers / cues the LLM was asked to look for
        self.assertIn("## RESPONSE-UNIFORMITY ANOMALY", w)
        self.assertIn("classification:", w)
        self.assertIn("response size:", w)
        self.assertIn("duration:", w)
        self.assertIn("What to do:", w)
        self.assertIn("INCONCLUSIVE, not NEGATIVE", w)

    def test_warning_carries_class_specific_remediation(self):
        """Each error_class should pull its own remediation hint, not a
        generic 'try again'."""
        # shell_parser_error → execute_code switch
        trace = [
            _uniform_step(error_class="shell_parser_error", success=False)
            for _ in range(5)
        ]
        w = detect_uniform_response_anomaly(trace)
        self.assertIn("execute_code", w)

        # transport_error → reachability hint
        trace = [
            _uniform_step(error_class="transport_error", success=False)
            for _ in range(5)
        ]
        w = detect_uniform_response_anomaly(trace)
        self.assertIn("reachability", w.lower())


# =============================================================================
# Productivity v2 — axis extraction, novelty, score, tiers
# =============================================================================


class TestAxisExtractor(unittest.TestCase):
    """The axis extractor must collapse 'admin brute force with bigger N'
    into a single axis key — the XBEN-007 scenario."""

    def test_brute_force_python_three_wordlists_collapse(self):
        """rockyou-5k, 10k-common, and rockyou-100k against admin → same axis."""
        script_template = (
            "import requests\n"
            "url = 'http://lab-1a6fde19:5003/login'\n"
            "with open('{wordlist}') as f:\n"
            "    for pw in f:\n"
            "        requests.post(url, json={{'username': 'admin', 'password': pw}})\n"
        )
        axes = []
        for wl in ("/usr/share/wordlists/rockyou.txt",
                   "/usr/share/seclists/10k-most-common.txt",
                   "/usr/share/wordlists/rockyou.txt"):
            args = {"code": script_template.format(wordlist=wl),
                    "language": "python", "filename": "brute"}
            ax = extract_axis("execute_code", args)
            self.assertIsNotNone(ax)
            axes.append(ax)
        # All three should produce the same axis key
        keys = {axis_key(a) for a in axes}
        self.assertEqual(len(keys), 1,
                         f"axes should collapse, got distinct keys: {keys}")
        self.assertEqual(axes[0]["family"], "credential_brute_force")
        self.assertEqual(axes[0]["fixed_user"], "admin")

    def test_different_username_creates_different_axis(self):
        """Same target, same script shape, different fixed_user → different axes."""
        script_admin = (
            "import requests\n"
            "url = 'http://lab/login'\n"
            "for pw in passwords:\n"
            "    requests.post(url, json={'username': 'admin', 'password': pw})\n"
        )
        script_user = script_admin.replace("admin", "user")
        ax1 = extract_axis("execute_code", {"code": script_admin})
        ax2 = extract_axis("execute_code", {"code": script_user})
        self.assertIsNotNone(ax1)
        self.assertIsNotNone(ax2)
        self.assertNotEqual(axis_key(ax1), axis_key(ax2))

    def test_recon_curl_returns_none(self):
        """Plain curl probes are NOT tracked — only expensive repeat-prone tools."""
        ax = extract_axis("execute_curl", {"args": "-s http://lab/robots.txt"})
        self.assertIsNone(ax)

    def test_job_spawn_unwraps_inner_tool(self):
        """job_spawn wrapping ffuf should produce a ffuf axis."""
        ax = extract_axis("job_spawn", {
            "tool_name": "execute_ffuf",
            "args": {"args": "-w /usr/share/wordlists/x.txt "
                             "-u http://lab/FUZZ -mc 200,301"},
        })
        self.assertIsNotNone(ax)
        self.assertEqual(ax["family"], "directory_brute_force")


class TestAxisLedger(unittest.TestCase):
    def test_record_and_count(self):
        ledger = {}
        ledger = record_axis_attempt(ledger, "k1", iteration=1, verdict="no_progress", tool="execute_code")
        ledger = record_axis_attempt(ledger, "k1", iteration=4, verdict="duplicate", tool="execute_code")
        ledger = record_axis_attempt(ledger, "k1", iteration=8, verdict="new_info", tool="execute_code")
        self.assertEqual(axis_unproductive_count(ledger, "k1"), 2)
        self.assertEqual(axis_unproductive_count(ledger, "nonexistent"), 0)

    def test_record_is_immutable(self):
        ledger = {"k1": [{"iteration": 1, "verdict": "no_progress", "tool": "x"}]}
        before = dict(ledger)
        _ = record_axis_attempt(ledger, "k1", iteration=2, verdict="no_progress", tool="x")
        self.assertEqual(ledger, before, "record_axis_attempt must not mutate input")


class TestPriorityOrderJaccard(unittest.TestCase):
    def test_identical_lists_score_one(self):
        a = ["Run sqlmap against /login", "Try admin brute-force", "Spawn naabu"]
        self.assertAlmostEqual(priority_order_jaccard(a, list(a)), 1.0, places=5)

    def test_disjoint_lists_score_zero(self):
        a = ["XSS dom probe on home.html"]
        b = ["LFI traversal on download endpoint"]
        self.assertLess(priority_order_jaccard(a, b), 0.2)

    def test_empty_inputs_score_zero(self):
        self.assertEqual(priority_order_jaccard([], ["x"]), 0.0)
        self.assertEqual(priority_order_jaccard(None, None), 0.0)

    def test_paraphrased_plans_score_high(self):
        a = ["Run admin brute-force with rockyou wordlist", "Spawn naabu port scan"]
        b = ["Continue admin brute-force with larger rockyou wordlist", "Run naabu"]
        # Stopwords + numerics are stripped; meaningful overlap should be
        # at least 0.5 (the project default threshold is 0.6, but >=0.5
        # is enough to demonstrate the signal is meaningful).
        self.assertGreaterEqual(priority_order_jaccard(a, b), 0.5)


class TestStateGrowthDetector(unittest.TestCase):
    def test_target_info_grew(self):
        before = {"target_info": {"ports": []}, "chain_findings_memory": []}
        after = {"target_info": {"ports": [80]}, "chain_findings_memory": []}
        self.assertTrue(detect_state_growth(before, after))

    def test_chain_findings_grew(self):
        before = {"target_info": {}, "chain_findings_memory": []}
        after = {"target_info": {}, "chain_findings_memory": [{"x": 1}]}
        self.assertTrue(detect_state_growth(before, after))

    def test_no_growth(self):
        before = {"target_info": {"ports": [80]}, "chain_findings_memory": [{"x": 1}]}
        after = dict(before)
        self.assertFalse(detect_state_growth(before, after))


class TestComputeProductivityScore(unittest.TestCase):
    def _trace_with_unproductive(self, n):
        return [
            _make_step(productivity=_verdict("no_progress", gained=False))
            for _ in range(n)
        ]

    def test_clean_session_scores_zero(self):
        trace = [
            _make_step(productivity=_verdict("new_info", gained=True, what="found endpoint"))
            for _ in range(3)
        ]
        result = compute_productivity_score(
            execution_trace=trace, tested_axes={},
            iterations_since_state_grew=0,
            iteration=3, max_iterations=100, phase="informational",
        )
        # 3 new_info events × reward 2.0 = -6.0, clamped to 0
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["components"]["new_info_events"], 3)

    def test_unproductive_streak_scores_positive(self):
        trace = self._trace_with_unproductive(5)
        result = compute_productivity_score(
            execution_trace=trace, tested_axes={},
            iterations_since_state_grew=4,
            iteration=20, max_iterations=100, phase="informational",
        )
        self.assertGreater(result["score"], 3.0)
        self.assertEqual(result["components"]["unproductive_verdicts"], 5)
        self.assertEqual(result["components"]["iterations_since_state_grew"], 4)

    def test_axis_repeats_dominate_score(self):
        # Three brute-forces on same axis, all unproductive
        axes = {
            "credential_brute_force::admin": [
                {"iteration": 5, "verdict": "no_progress", "tool": "execute_code"},
                {"iteration": 12, "verdict": "no_progress", "tool": "execute_code"},
                {"iteration": 22, "verdict": "no_progress", "tool": "execute_code"},
            ]
        }
        # Trace itself is mostly clean (other probes)
        trace = [_make_step(productivity=_verdict("new_info", gained=True))]
        result = compute_productivity_score(
            execution_trace=trace, tested_axes=axes,
            iterations_since_state_grew=0,
            iteration=22, max_iterations=100, phase="informational",
        )
        # axis_repeats = 3, weighted ~ 2.0+2.0*(22/100) * 3 = 7.32
        self.assertGreater(result["score"], 4.0)
        self.assertEqual(result["components"]["max_axis_repeats"], 3)

    def test_late_session_punishes_more(self):
        trace = self._trace_with_unproductive(4)
        axes = {"k": [{"iteration": 1, "verdict": "no_progress", "tool": "x"},
                      {"iteration": 2, "verdict": "no_progress", "tool": "x"}]}
        early = compute_productivity_score(
            execution_trace=trace, tested_axes=axes,
            iterations_since_state_grew=3,
            iteration=5, max_iterations=100, phase="informational",
        )
        late = compute_productivity_score(
            execution_trace=trace, tested_axes=axes,
            iterations_since_state_grew=3,
            iteration=80, max_iterations=100, phase="informational",
        )
        self.assertGreater(late["score"], early["score"],
                           "late session should score higher for same signals")

    def test_exploitation_phase_punishes_axis_repeats_more(self):
        axes = {"k": [{"iteration": 1, "verdict": "no_progress", "tool": "x"},
                      {"iteration": 2, "verdict": "no_progress", "tool": "x"}]}
        trace = []
        info_score = compute_productivity_score(
            execution_trace=trace, tested_axes=axes,
            iterations_since_state_grew=0, iteration=10,
            max_iterations=100, phase="informational",
        )
        expl_score = compute_productivity_score(
            execution_trace=trace, tested_axes=axes,
            iterations_since_state_grew=0, iteration=10,
            max_iterations=100, phase="exploitation",
        )
        self.assertGreater(expl_score["score"], info_score["score"])


class TestTierForScore(unittest.TestCase):
    def test_tier_boundaries(self):
        self.assertEqual(tier_for_score(0.0), "green")
        self.assertEqual(tier_for_score(2.9), "green")
        self.assertEqual(tier_for_score(3.0), "yellow")
        self.assertEqual(tier_for_score(4.9), "yellow")
        self.assertEqual(tier_for_score(5.0), "orange")
        self.assertEqual(tier_for_score(6.9), "orange")
        self.assertEqual(tier_for_score(7.0), "red")
        self.assertEqual(tier_for_score(8.9), "red")
        self.assertEqual(tier_for_score(9.0), "critical")
        self.assertEqual(tier_for_score(15.0), "critical")

    def test_custom_thresholds(self):
        # Stricter project: Deep Think fires earlier
        self.assertEqual(
            tier_for_score(3.5, hint_threshold=2.0, deepthink_threshold=3.0),
            "orange",
        )


class TestXBEN007Scenario(unittest.TestCase):
    """End-to-end scenario test: simulate three brute-force attempts on
    `admin` across iterations 24, 32, 41 (the XBEN-007 timeline) and verify
    the axis ledger flags lock-in and the score crosses the block tier."""

    def test_three_brute_forces_against_admin_trigger_critical_tier(self):
        script = (
            "import requests\n"
            "url = 'http://lab-1a6fde19:5003/login'\n"
            "for pw in passwords:\n"
            "    requests.post(url, json={'username': 'admin', 'password': pw})\n"
        )
        ledger = {}
        # Three sequential brute-force attempts on the same axis
        for i, it in enumerate([24, 32, 41]):
            ax = extract_axis("execute_code", {"code": script + f"  # attempt {i}"})
            self.assertIsNotNone(ax)
            ledger = record_axis_attempt(
                ledger, axis_key(ax), iteration=it,
                verdict="no_progress", tool="execute_code",
            )
        # By the 3rd attempt, the axis count is 3 (all unproductive)
        ax = extract_axis("execute_code", {"code": script})
        self.assertEqual(axis_unproductive_count(ledger, axis_key(ax)), 3)
        # And the score crosses critical when this is observed mid-session
        result = compute_productivity_score(
            execution_trace=[
                _make_step(productivity=_verdict("no_progress", gained=False))
                for _ in range(4)
            ],
            tested_axes=ledger,
            iterations_since_state_grew=7,
            iteration=41, max_iterations=100, phase="informational",
        )
        tier = tier_for_score(result["score"])
        self.assertIn(tier, ("red", "critical"),
                      f"expected red/critical, got {tier} (score={result['score']})")


class TestDiagnosticProgress(unittest.TestCase):
    """Fix 1: debugging a correct-but-failing approach counts as progress."""

    def _step(self, *, output, args, tool="execute_code", productivity=None,
              error_class=None):
        s = _make_step(tool=tool, args=args, output=output, productivity=productivity)
        if error_class is not None:
            s["error_class"] = error_class
        return s

    # NOTE: `_normalize_args_pattern` only collapses standalone digits / long
    # hex / key=value query strings and truncates at 160 chars; it does NOT turn
    # an arbitrary JSON string value into <val>. So to exercise the "same
    # approach" branch deterministically we hold the arg shape constant (same
    # args) and vary the OUTPUT — which is exactly the debugging signal: the same
    # kind of call producing a different result.
    _ARGS = {"code": "JSFUCK_PAYLOAD"}

    def test_same_approach_different_result_is_progress(self):
        prev = self._step(output="page renders, no alert", args=self._ARGS)
        cur = self._step(output="Oops: TypeError ...", args=self._ARGS)
        self.assertTrue(detect_diagnostic_progress(prev, cur))

    def test_same_approach_identical_result_is_not_progress(self):
        # Same shape, IDENTICAL response -> not progress (cannot be gamed).
        prev = self._step(output="Sorry you can't use: '`'", args=self._ARGS)
        cur = self._step(output="Sorry you can't use: '`'", args=self._ARGS)
        self.assertFalse(detect_diagnostic_progress(prev, cur))

    def test_different_tool_is_not_diagnostic_by_output_alone(self):
        # A pivot to a different tool that happens to differ in output must NOT
        # silently reset the stall counter via the observed signal.
        prev = self._step(tool="execute_curl", output="200 OK", args={"url": "http://t/"})
        cur = self._step(tool="web_search", output="some results", args={"query": "x"})
        self.assertFalse(detect_diagnostic_progress(prev, cur))

    def test_explicit_diagnostic_verdict_counts(self):
        cur = self._step(output="same-ish", args={"code": "z"},
                         productivity={"verdict": "diagnostic_progress",
                                       "new_information_gained": False,
                                       "what_was_new": "ruled out modern-engine theory"})
        self.assertTrue(detect_diagnostic_progress(None, cur))

    def test_explicit_diagnostic_verdict_without_cause_does_not_count(self):
        # Layer A: an empty 'diagnostic_progress' claim must NOT reset the stall
        # counter — otherwise it is trivially gameable to suppress the streak.
        cur = self._step(output="x", args={"code": "z"},
                         productivity={"verdict": "diagnostic_progress",
                                       "new_information_gained": False,
                                       "what_was_new": ""})
        self.assertFalse(detect_diagnostic_progress(None, cur))

    def test_ruled_out_phrase_counts(self):
        cur = self._step(output="x", args={"code": "z"},
                         productivity={"verdict": "no_progress",
                                       "new_information_gained": False,
                                       "what_was_new": "Ruled out the WAF hypothesis"})
        self.assertTrue(detect_diagnostic_progress(None, cur))

    def test_changed_error_class_counts(self):
        # Same shape + same body, but a DIFFERENT error_class surfaced.
        prev = self._step(output="boom", args=self._ARGS, error_class="application_5xx_fast")
        cur = self._step(output="boom", args=self._ARGS, error_class="transport_error")
        self.assertTrue(detect_diagnostic_progress(prev, cur))

    def test_diagnostic_progress_verdict_is_not_unproductive(self):
        # Fix 1: even with new_information_gained=False, diagnostic_progress is
        # never counted as an unproductive step.
        step = _make_step(productivity={"verdict": "diagnostic_progress",
                                        "new_information_gained": False,
                                        "what_was_new": "ruled out X"})
        self.assertFalse(is_unproductive(step))


class TestSamePatternCountFingerprintAware(unittest.TestCase):
    """Fix 2: a 'repeat' requires same input shape AND same result."""

    def _trace_jsfuck(self):
        # The real XBEN-010 debugging trace: 6 execute_code calls that share the
        # same normalized arg shape (held constant here), with mostly different
        # responses and two genuine repeats. Old shape-only counting would call
        # this "6 identical calls"; Fix 2 counts the most-repeated (shape, fp)
        # pair, which appears only twice.
        same_args = {"code": "JSFUCK_PAYLOAD"}
        outs = [
            "page renders, no alert",      # aaaa
            "Oops: TypeError ...",         # bbbb
            "Oops: different error ...",   # cccc
            "Oops: TypeError ...",         # bbbb (same as #2)
            "Sorry you can't use: '`'",    # dddd
            "Sorry you can't use: '`'",    # dddd (literal repeat of #5)
        ]
        return [
            _make_step(tool="execute_code", args=same_args, output=o)
            for o in outs
        ]

    def test_distinct_results_not_counted_as_loop(self):
        # Old behavior would have returned 6 (all collapse to code=<val>).
        # Fix 2: the most-repeated (shape, fingerprint) pair appears only twice.
        self.assertEqual(_same_pattern_count(self._trace_jsfuck()), 2)

    def test_true_loop_still_detected(self):
        # Same call, same response, 4 times -> genuinely looping -> 4.
        trace = [
            _make_step(tool="execute_curl", args={"url": "http://t/x"}, output="403 Forbidden")
            for _ in range(4)
        ]
        self.assertEqual(_same_pattern_count(trace), 4)


class TestDiagnosticProgressAudit(unittest.TestCase):
    """Layer B: the honesty audit downgrades empty diagnostic_progress claims."""

    def test_empty_diagnostic_progress_flagged(self):
        disc = audit_productivity_claim(
            productivity={"verdict": "diagnostic_progress",
                          "new_information_gained": False, "what_was_new": ""},
            extracted_info={}, actionable_findings=[], findings_grew=False,
        )
        self.assertIsNotNone(disc)
        self.assertIn("diagnostic_progress", disc)

    def test_diagnostic_progress_with_cause_not_flagged(self):
        disc = audit_productivity_claim(
            productivity={"verdict": "diagnostic_progress",
                          "new_information_gained": False,
                          "what_was_new": "ruled out the WAF hypothesis"},
            extracted_info={}, actionable_findings=[], findings_grew=False,
        )
        self.assertIsNone(disc)

    def test_downgraded_empty_claim_is_unproductive_again(self):
        # End-to-end of Layer A+B: an empty diagnostic_progress claim, once
        # downgraded to no_progress, is counted as unproductive (so it cannot
        # both dodge the streak AND fail the audit).
        prod = {"verdict": "diagnostic_progress", "new_information_gained": False,
                "what_was_new": ""}
        disc = audit_productivity_claim(prod, {}, [], False)
        self.assertIsNotNone(disc)
        downgraded = downgrade_verdict_to_no_progress(prod, disc)
        step = _make_step(productivity=downgraded)
        self.assertTrue(is_unproductive(step))


class TestUpdateStallCounters(unittest.TestCase):
    """Layer C: diagnostic progress resets the stall counter but is capped."""

    def test_real_growth_resets_both(self):
        self.assertEqual(update_stall_counters(5, 4, grew=True, diag=False), (0, 0))
        self.assertEqual(update_stall_counters(5, 4, grew=True, diag=True), (0, 0))

    def test_diagnostic_resets_stall_and_increments_streak(self):
        self.assertEqual(update_stall_counters(3, 0, grew=False, diag=True, cap=6), (0, 1))
        self.assertEqual(update_stall_counters(3, 2, grew=False, diag=True, cap=6), (0, 3))

    def test_no_progress_climbs(self):
        self.assertEqual(update_stall_counters(3, 2, grew=False, diag=False), (4, 2))

    def test_cap_stops_suppression(self):
        # At the cap, diagnostic progress no longer resets the stall counter.
        self.assertEqual(update_stall_counters(0, 6, grew=False, diag=True, cap=6), (1, 6))
        self.assertEqual(update_stall_counters(2, 7, grew=False, diag=True, cap=6), (3, 7))

    def test_cap_is_per_run_of_diagnostic_only(self):
        # Walk a sequence: 6 diagnostic resets, then the 7th must climb.
        its, ds = 0, 0
        for _ in range(6):
            its, ds = update_stall_counters(its, ds, grew=False, diag=True, cap=6)
        self.assertEqual((its, ds), (0, 6))            # still suppressed at the boundary
        its, ds = update_stall_counters(its, ds, grew=False, diag=True, cap=6)
        self.assertEqual((its, ds), (1, 6))            # cap hit -> stall now climbs

    def test_real_growth_after_cap_resets_budget(self):
        its, ds = update_stall_counters(3, 6, grew=True, diag=True, cap=6)
        self.assertEqual((its, ds), (0, 0))            # a real finding refills the budget


class TestDebuggingDoesNotTriggerStreakIntegration(unittest.TestCase):
    """Integration: a realistic debugging run (the XBEN-010 shape) must NOT trip
    the unproductive-streak detector now, while a genuine stall still does.

    Exercises the real interaction of detect_state_growth + detect_diagnostic_
    progress + update_stall_counters + _same_pattern_count + is_unproductive as
    the orchestrator wires them, without importing the pydantic-heavy think_node.
    """

    def _run(self, steps, cap=6):
        """Replay the orchestrator's per-step stall bookkeeping over a trace of
        (args, output, productivity) tuples; return the final stall counter and
        the max same_pattern_count seen — the two inputs that drive the streak."""
        its, ds = 0, 0
        trace = []
        for args, output, prod in steps:
            step = _make_step(tool="execute_code", args=args, output=output,
                              productivity=prod)
            prev = trace[-1] if trace else None
            trace.append(step)
            grew = False  # no target facts in a pure debugging run
            diag = detect_diagnostic_progress(prev, step)
            its, ds = update_stall_counters(its, ds, grew=grew, diag=diag, cap=cap)
        return its, _same_pattern_count(trace)

    def test_genuine_debugging_stays_below_streak(self):
        same = {"code": "JSFUCK_PAYLOAD"}
        steps = [
            (same, "page renders, no alert", None),
            (same, "Oops: TypeError ...", None),
            (same, "Oops: different error ...", None),
            (same, "Sorry you can't use: '`'", None),
            (same, "Congratulations? no — Oops still", None),
        ]
        its, same_count = self._run(steps)
        # Each attempt produced a different result -> diagnostic progress each
        # time -> stall counter stayed at 0; and no two results are identical so
        # same_pattern_count is 1. Neither feeds an unproductive streak.
        self.assertEqual(its, 0)
        self.assertEqual(same_count, 1)

    def test_genuine_stall_still_climbs(self):
        same = {"code": "SAME"}
        # Identical call, identical "blocked" result, 5 times: no diagnostic
        # progress, so the stall counter climbs and same_pattern_count is high.
        steps = [(same, "403 Forbidden", None) for _ in range(5)]
        its, same_count = self._run(steps)
        self.assertEqual(its, 5)
        self.assertEqual(same_count, 5)

    def test_capped_diagnostic_churn_eventually_stalls(self):
        # Alternating two different results forever would reset the stall counter
        # on every step via the observed branch — the cap stops that.
        a = {"code": "P"}
        steps = [(a, "result-A" if i % 2 == 0 else "result-B", None) for i in range(10)]
        its, _ = self._run(steps, cap=6)
        self.assertGreater(its, 0)  # cap kicked in; the churn no longer suppresses


class TestScoreToTierIntegration(unittest.TestCase):
    """The real payoff: feed each trace through compute_productivity_score with
    the stall counter our bookkeeping would produce, and assert the *tier*
    (which gates Deep Think / the streak) reacts correctly. This closes the gap
    between the pure counter logic and the score the orchestrator actually acts
    on."""

    def _stall_after(self, steps, cap=6):
        its, ds = 0, 0
        trace = []
        for item in steps:
            args, output = item[0], item[1]
            prod = item[2] if len(item) > 2 else None
            step = _make_step(tool="execute_code", args=args, output=output,
                              productivity=prod)
            prev = trace[-1] if trace else None
            trace.append(step)
            diag = detect_diagnostic_progress(prev, step)
            its, ds = update_stall_counters(its, ds, grew=False, diag=diag, cap=cap)
        return trace, its

    def test_debugging_run_stays_green(self):
        same = {"code": "JSFUCK"}
        # A realistic debugging run: the agent emits diagnostic_progress with a
        # cited cause, and the tool outputs contain the word "error"/"TypeError"
        # (as the real XBEN-010 "Oops! ... TypeError" responses did). Neither the
        # verdict path nor the legacy keyword path may flag these as a streak.
        def dp(cause):
            return {"verdict": "diagnostic_progress", "new_information_gained": False,
                    "what_was_new": cause}
        steps = [
            (same, "page renders, no alert", dp("string-only encoding does not fire")),
            (same, "Oops: TypeError noise", dp("ruled out: payload reaches the bot")),
            (same, "Oops: a different error", dp("different error -> encoding changed")),
            (same, "Sorry you can't use backtick", dp("ruled out backtick avenue")),
            (same, "still Oops, new detail", dp("narrowed to eval-wrap missing")),
        ]
        trace, stall = self._stall_after(steps)
        score = compute_productivity_score(
            execution_trace=trace, tested_axes={},
            iterations_since_state_grew=stall,
            iteration=20, max_iterations=100, phase="exploitation",
        )
        tier = tier_for_score(score["score"])
        self.assertEqual(stall, 0)
        self.assertEqual(tier, "green",
                         f"debugging run should stay green, got score={score['score']}")

    def test_true_stall_escalates(self):
        same = {"code": "SAME"}
        steps = [(same, "403 Forbidden") for _ in range(6)]
        trace, stall = self._stall_after(steps)
        score = compute_productivity_score(
            execution_trace=trace, tested_axes={},
            iterations_since_state_grew=stall,
            iteration=20, max_iterations=100, phase="exploitation",
        )
        tier = tier_for_score(score["score"])
        self.assertGreaterEqual(stall, 6)
        self.assertIn(tier, ("orange", "red", "critical"),
                      f"genuine stall should escalate, got score={score['score']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
