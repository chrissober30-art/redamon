"""End-to-end integration tests for the P1/P2/P3 diagnostic pipeline.

Replays the XBEN-006-24 iter-11 failure mode (twelve different SQL payloads
all producing 500-in-3ms) through the real classifier and detector, then
asserts that:

  1. Each step gets the right error_class            (P2)
  2. format_chain_context surfaces duration + class  (P1)
  3. detect_uniform_response_anomaly fires           (P3)
  4. The warning carries actionable remediation text

This is the regression test for the entire feature. If a future refactor
breaks any of the four layers, this suite catches it.

These tests need state.py (pydantic). Run inside the agent container or any
env with pydantic installed. The error_class + productivity tests below
keep their dependency-free loader so they still run standalone too.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Real modules — these tests verify cross-module integration, so import
# normally rather than the file-path workaround used in the unit suites.
from orchestrator_helpers.error_class import classify_error_class
from orchestrator_helpers.productivity import (
    detect_uniform_response_anomaly,
)
from state import format_chain_context


# ---------------------------------------------------------------------------
# Session-replay fixtures
# ---------------------------------------------------------------------------

# The twelve SQL payloads the agent fired at iter 11 of XBEN-006-24, with
# the actual response shape every one of them returned. These are the
# inputs the diagnostic pipeline must handle correctly to catch the
# failure mode that broke that session.
_ITER_11_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' UNION SELECT 1,2,3,4 --",
    "' UNION SELECT 1,2,3,4,5 --",
    "' UNION SELECT 1,2,3,4,5,6 --",
    "' AND '1'='1",
    "' AND '1'='2",
    "' OR SLEEP(3) --",
    "' OR pg_sleep(3) --",
    "' OR WAITFOR DELAY '0:0:3' --",
]


def _build_iter_11_trace():
    """Build the execution_trace as it would exist AFTER the execute nodes
    have populated error_class. One step per payload, all 5xx in 3-5ms."""
    trace = []
    for i, payload in enumerate(_ITER_11_PAYLOADS):
        tool_output = "Status: 500, Body: Internal Server Error"
        duration_ms = 3 + (i % 3)  # 3, 4, 5, 3, 4, 5...
        ec = classify_error_class(
            success=True,
            tool_output=tool_output,
            error_message=None,
            duration_ms=duration_ms,
            tool_name="execute_code",
        )
        trace.append({
            "iteration": i + 1,
            "phase": "informational",
            "tool_name": "execute_code",
            "tool_args": {"code": f"requests.post(..., json={{'job_type': '{payload}'}})"},
            "success": True,
            "tool_output": tool_output,
            "duration_ms": duration_ms,
            "error_class": ec,
            "output_analysis": f"SQLi payload {payload!r} returned 500",
            "actionable_findings": [],
        })
    return trace


# ---------------------------------------------------------------------------
# Layer 1 — classifier hits the right class for the session signature
# ---------------------------------------------------------------------------

class TestClassifierOnSessionReplay(unittest.TestCase):

    def test_every_iter_11_payload_classifies_as_5xx_fast(self):
        """If even ONE payload misclassifies, the anomaly detector won't
        fire and the LLM stays in the dark."""
        trace = _build_iter_11_trace()
        classes = [s["error_class"] for s in trace]
        for i, ec in enumerate(classes):
            self.assertEqual(
                ec, "application_5xx_fast",
                f"Payload #{i} ({_ITER_11_PAYLOADS[i]!r}) misclassified as {ec}",
            )

    def test_iter_5_shell_quoting_misfire_recognized(self):
        """The very first SQLi attempt that misled the whole session."""
        ec = classify_error_class(
            success=False,
            tool_output="[ERROR] No closing quotation",
            error_message="shell quoting",
            duration_ms=12,
            tool_name="execute_curl",
        )
        self.assertEqual(ec, "shell_parser_error")

    def test_iter_6_curl_at_file_failure_recognized(self):
        """The wave-parallelism casualty: execute_code wrote the file while
        execute_curl tried to read it, in parallel. Curl returned a clean
        error that should be tagged tool_internal_error, NOT 'SQLi blocked'."""
        ec = classify_error_class(
            success=False,
            tool_output=(
                "[ERROR] execute_curl failed: returncode=26, "
                "stderr=curl: option -d: error encountered when reading a file"
            ),
            error_message=None,
            duration_ms=20,
            tool_name="execute_curl",
        )
        self.assertEqual(ec, "tool_internal_error")


# ---------------------------------------------------------------------------
# Layer 2 — chain context renders the diagnostics so the LLM can see them
# ---------------------------------------------------------------------------

class TestChainContextRender(unittest.TestCase):

    def test_iter_11_trace_renders_timing_and_class(self):
        trace = _build_iter_11_trace()
        rendered = format_chain_context([], [], [], trace)

        # The diagnostic suffix must appear at least once for every step.
        # We check a representative sample rather than all 12 to keep the
        # assertion message readable on failure.
        self.assertIn("application_5xx_fast", rendered)
        # Duration of at least one step should be present
        self.assertTrue(
            any(f"{d}ms" in rendered for d in [3, 4, 5]),
            "Expected timing annotation '3ms/4ms/5ms' missing from chain context",
        )
        # The legacy '[None]' bug must not creep back
        self.assertNotIn("[None]", rendered)

    def test_mixed_trace_distinguishes_failure_modes(self):
        """A trace mixing shell errors, 5xx_fast, and 4xx must show
        different annotations — that's the whole point of P2."""
        trace = [
            {
                "iteration": 1, "phase": "informational",
                "tool_name": "execute_curl",
                "tool_args": {"args": "broken"}, "success": False,
                "tool_output": "[ERROR] No closing quotation",
                "duration_ms": 12,
                "error_class": "shell_parser_error",
                "output_analysis": "shell glitch",
                "error_message": "shell quoting",
            },
            {
                "iteration": 2, "phase": "informational",
                "tool_name": "execute_curl",
                "tool_args": {"args": "ok"}, "success": True,
                "tool_output": "Status: 500\nInternal Server Error",
                "duration_ms": 3,
                "error_class": "application_5xx_fast",
                "output_analysis": "fast crash",
            },
            {
                "iteration": 3, "phase": "informational",
                "tool_name": "execute_curl",
                "tool_args": {"args": "ok"}, "success": True,
                "tool_output": "HTTP/1.1 405 Method Not Allowed",
                "duration_ms": 8,
                "error_class": "application_4xx",
                "output_analysis": "wrong method",
            },
        ]
        rendered = format_chain_context([], [], [], trace)
        self.assertIn("shell_parser_error", rendered)
        self.assertIn("application_5xx_fast", rendered)
        self.assertIn("application_4xx", rendered)


# ---------------------------------------------------------------------------
# Layer 3 — anomaly detector fires on the session-replay trace
# ---------------------------------------------------------------------------

class TestAnomalyDetectorOnReplay(unittest.TestCase):

    def test_anomaly_fires_on_iter_11_window(self):
        """The whole feature exists for this test. If this fails, we've
        regressed the iter-11 failure mode."""
        trace = _build_iter_11_trace()
        warning = detect_uniform_response_anomaly(trace)
        self.assertIsNotNone(
            warning,
            "Anomaly detector failed to fire on the 12-SQL-payload trace "
            "that broke XBEN-006-24 iter 11.",
        )
        self.assertIn("application_5xx_fast", warning)
        self.assertIn("parse time", warning.lower())

    def test_anomaly_remediation_steers_away_from_marking_tested(self):
        """The most important payload of the warning: 'do not mark this
        vector tested.' That's the bug it's preventing."""
        trace = _build_iter_11_trace()
        warning = detect_uniform_response_anomaly(trace)
        self.assertIn("Do NOT mark", warning)
        self.assertIn("INCONCLUSIVE", warning)


# ---------------------------------------------------------------------------
# Layer 4 — backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompat(unittest.TestCase):
    """Steps written before this feature shipped (no error_class,
    no duration_ms) must continue to render cleanly and must not trigger
    false-positive anomaly warnings."""

    def test_legacy_trace_renders_without_diagnostic_artifacts(self):
        legacy_trace = [
            {
                "iteration": i,
                "phase": "informational",
                "tool_name": "execute_curl",
                "tool_args": {"args": "-s /"},
                "success": True,
                "tool_output": f"some body {i}",
                "output_analysis": f"step {i}",
            }
            for i in range(1, 10)
        ]
        out = format_chain_context([], [], [], legacy_trace)
        # No 'None' artifacts from the new diagnostic suffix
        for bad in ("[None]", "[None,", ", None]", "[, ", " ]"):
            self.assertNotIn(bad, out, f"Legacy render leaked artifact {bad!r}")

    def test_legacy_trace_does_not_trigger_anomaly(self):
        legacy_trace = [
            {
                "tool_name": "execute_curl",
                "tool_args": {"args": "-s /"},
                "tool_output": "x",
                "success": False,
                "duration_ms": 10,
                # No error_class
            }
            for _ in range(8)
        ]
        self.assertIsNone(detect_uniform_response_anomaly(legacy_trace))


# ---------------------------------------------------------------------------
# Wiring guard — execute nodes must call the classifier
# ---------------------------------------------------------------------------

class TestExecuteNodeWiring(unittest.TestCase):
    """The whole pipeline depends on execute_plan_node and execute_tool_node
    calling classify_error_class on every completed step. If a future
    refactor removes the call, every other test in this suite stays green
    because it builds steps by hand — but in production, error_class would
    silently be missing and the chain-context render / anomaly detector
    would degrade to legacy behavior.

    Source-level inspection is the cheapest guard: it catches the regression
    without spinning up the full async tool executor pipeline."""

    def _read(self, rel_path: str) -> str:
        p = os.path.join(
            os.path.dirname(__file__), "..", rel_path,
        )
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

    def test_execute_plan_node_calls_classifier(self):
        src = self._read("orchestrator_helpers/nodes/execute_plan_node.py")
        self.assertIn("from orchestrator_helpers.error_class import classify_error_class", src,
                      "execute_plan_node lost its classify_error_class import")
        self.assertIn('step["error_class"] = classify_error_class(', src,
                      "execute_plan_node no longer populates step['error_class']")

    def test_execute_tool_node_calls_classifier(self):
        src = self._read("orchestrator_helpers/nodes/execute_tool_node.py")
        self.assertIn("from orchestrator_helpers.error_class import classify_error_class", src,
                      "execute_tool_node lost its classify_error_class import")
        self.assertIn('step_data["error_class"] = classify_error_class(', src,
                      "execute_tool_node no longer populates step_data['error_class']")

    def test_think_node_calls_anomaly_detector(self):
        src = self._read("orchestrator_helpers/nodes/think_node.py")
        self.assertIn("detect_uniform_response_anomaly", src,
                      "think_node no longer references detect_uniform_response_anomaly")
        # Must actually CALL it, not just import
        self.assertIn("detect_uniform_response_anomaly(", src,
                      "detect_uniform_response_anomaly is imported but never called")
        # And the warning must actually be appended to the prompt
        self.assertIn("_anomaly_warning", src,
                      "anomaly warning result is never captured")

    def test_think_node_plan_wave_propagates_diagnostics(self):
        """Caught in production: the plan-wave path in think_node rebuilds
        each step into a fresh exec_step dict, copying only a subset of
        fields. If error_class and duration_ms aren't in that subset, the
        whole P1+P2+P3 pipeline silently degrades to legacy behavior for
        every plan_tools wave — and waves are the dominant code path.

        Source-level guard: the exec_step dict must explicitly copy both
        fields from plan_step.
        """
        src = self._read("orchestrator_helpers/nodes/think_node.py")
        self.assertIn(
            '"duration_ms": plan_step.get("duration_ms")',
            src,
            "plan-wave exec_step no longer propagates duration_ms — "
            "P1 chain-context timing annotations will silently disappear",
        )
        self.assertIn(
            '"error_class": plan_step.get("error_class")',
            src,
            "plan-wave exec_step no longer propagates error_class — "
            "P2 chain-context class annotations AND P3 anomaly detector "
            "will silently degrade to legacy behavior",
        )

    def test_project_settings_declares_anomaly_knobs(self):
        src = self._read("project_settings.py")
        for knob in (
            "UNIFORM_RESPONSE_WINDOW",
            "UNIFORM_RESPONSE_MIN_COUNT",
            "UNIFORM_RESPONSE_DURATION_MS",
        ):
            self.assertIn(knob, src, f"project_settings missing knob: {knob}")


# ---------------------------------------------------------------------------
# Long-output robustness — classifier truncation must not hide a status line
# ---------------------------------------------------------------------------

class TestLongOutputRobustness(unittest.TestCase):

    def test_status_at_start_classified_correctly_with_huge_body(self):
        """HTTP wrappers put the status line near the top. A 50KB body
        with status at position 0 must still classify correctly even though
        the classifier truncates its haystack."""
        big_body = "X" * 50_000
        ec = classify_error_class(
            success=True,
            tool_output=f"HTTP/1.1 500 Internal Server Error\n{big_body}",
            error_message=None,
            duration_ms=3,
            tool_name="execute_curl",
        )
        self.assertEqual(ec, "application_5xx_fast")

    def test_huge_clean_200_still_classifies_success(self):
        big_body = '[{"id":1}]' + ("," * 50_000)
        ec = classify_error_class(
            success=True,
            tool_output=f"HTTP/1.1 200 OK\n{big_body}",
            error_message=None,
            duration_ms=18,
            tool_name="execute_curl",
        )
        self.assertEqual(ec, "success")


if __name__ == "__main__":
    unittest.main(verbosity=2)
