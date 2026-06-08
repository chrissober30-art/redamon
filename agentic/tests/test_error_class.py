"""Unit tests for orchestrator_helpers/error_class.py.

The classifier is the diagnostic foundation for both the chain-context render
(P1+P2) and the uniform-response anomaly detector (P3). If it misclassifies,
every downstream signal misfires.

Coverage:
  - Every error class (8 total) hit by at least one positive case
  - Every signature regex family exercised
  - HTTP status extraction across the four shapes (HTTP/1.1, "Status:",
    "[INFO] HTTP:", bare 3-digit on its own line)
  - Generic-body fallback (FastAPI "Internal Server Error" without status)
  - Duration thresholds: 5xx_fast vs 5xx_normal at the 50ms boundary
  - Negative cases (clean 200, success without HTTP context)
  - Edge cases: None inputs, empty strings, garbled output

The classifier has zero deps beyond `re`, so it's loaded by direct file path
to keep the test runnable without pydantic / orchestrator_helpers/__init__.py.
"""

from __future__ import annotations

import importlib.util
import os
import unittest

_EC_PATH = os.path.join(
    os.path.dirname(__file__), "..", "orchestrator_helpers", "error_class.py"
)
_spec = importlib.util.spec_from_file_location("_ec_under_test", _EC_PATH)
_ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ec)

classify_error_class = _ec.classify_error_class
_extract_http_status = _ec._extract_http_status
is_diagnostic_failure = _ec.is_diagnostic_failure
ERROR_CLASS_HINTS = _ec.ERROR_CLASS_HINTS
FAST_RESPONSE_THRESHOLD_MS = _ec.FAST_RESPONSE_THRESHOLD_MS


def _classify(**kwargs):
    """Defaults that mirror what the orchestrator passes when a field is
    missing. Lets tests focus on the field under test without ceremony."""
    return classify_error_class(
        success=kwargs.get("success", True),
        tool_output=kwargs.get("tool_output", ""),
        error_message=kwargs.get("error_message"),
        duration_ms=kwargs.get("duration_ms"),
        tool_name=kwargs.get("tool_name"),
    )


# ---------------------------------------------------------------------------
# Shell-parser errors — request never left the harness
# ---------------------------------------------------------------------------

class TestShellParserErrors(unittest.TestCase):
    """The iter-5 failure that misled the whole XBEN-006-24 session: a
    JSON-in-bash double-escape that produced "No closing quotation" before
    curl ever saw the URL."""

    def test_no_closing_quotation(self):
        self.assertEqual(
            _classify(success=False, tool_output="[ERROR] No closing quotation"),
            "shell_parser_error",
        )

    def test_unexpected_end_of_file(self):
        self.assertEqual(
            _classify(success=False, tool_output="bash: unexpected end of file"),
            "shell_parser_error",
        )

    def test_shlex_value_error(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output="ValueError: No closing quotation\n  at shlex.split",
            ),
            "shell_parser_error",
        )

    def test_bash_syntax_error_line(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output="bash: line 4: syntax error near unexpected token `)'",
            ),
            "shell_parser_error",
        )


# ---------------------------------------------------------------------------
# Transport errors — network failure, request never reached the app
# ---------------------------------------------------------------------------

class TestTransportErrors(unittest.TestCase):

    def test_dns_could_not_resolve(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output="curl: (6) Could not resolve host: lab-xxx",
            ),
            "transport_error",
        )

    def test_connection_refused(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output="curl: (7) Failed to connect: Connection refused",
            ),
            "transport_error",
        )

    def test_connection_timeout(self):
        self.assertEqual(
            _classify(success=False, tool_output="Connection timed out after 30s"),
            "transport_error",
        )

    def test_python_new_connection_error(self):
        # Mirrors the ngrok warning seen throughout the XBEN session
        self.assertEqual(
            _classify(
                success=False,
                tool_output=(
                    "requests.exceptions.ConnectionError: "
                    "HTTPConnectionPool(...): NewConnectionError(...)"
                ),
            ),
            "transport_error",
        )

    def test_no_route_to_host(self):
        self.assertEqual(
            _classify(success=False, tool_output="No route to host"),
            "transport_error",
        )


# ---------------------------------------------------------------------------
# Tool-internal errors — wrapper failed before/during execution
# ---------------------------------------------------------------------------

class TestToolInternalErrors(unittest.TestCase):
    """Iter-6 failure: execute_curl ran with -d @/tmp/X before execute_code
    had written /tmp/X (the orchestrator parallelizes wave steps). Curl
    returned a clean returncode=26 'option -d: error encountered when
    reading a file' — a tool-wrapper failure, not a server response."""

    def test_curl_returncode_envelope(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output=(
                    "[ERROR] execute_curl failed: returncode=26, stderr=curl: "
                    "option -d: error encountered when reading a file"
                ),
            ),
            "tool_internal_error",
        )

    def test_file_not_found(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output="No such file or directory: /tmp/payload.json",
            ),
            "tool_internal_error",
        )

    def test_playwright_internal(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output=(
                    "playwright._impl._errors.Error: It looks like you are "
                    "using Playwright Sync API inside the asyncio loop."
                ),
            ),
            "tool_internal_error",
        )

    def test_command_timed_out(self):
        self.assertEqual(
            _classify(
                success=False,
                tool_output="[ERROR] Command timed out after 300 seconds.",
            ),
            "tool_internal_error",
        )

    def test_failure_without_recognizable_signature_falls_back(self):
        """When success=False but no signature matches, we still surface
        SOMETHING actionable — defaulting to tool_internal_error keeps the
        diagnostic class field populated for every failed step."""
        self.assertEqual(
            _classify(success=False, tool_output="weird gibberish output"),
            "tool_internal_error",
        )


# ---------------------------------------------------------------------------
# HTTP 4xx — legitimate server semantic rejection
# ---------------------------------------------------------------------------

class TestApplication4xx(unittest.TestCase):

    def test_405_from_curl_v(self):
        self.assertEqual(
            _classify(tool_output="HTTP/1.1 405 Method Not Allowed\nallow: POST"),
            "application_4xx",
        )

    def test_403_with_fastapi_body(self):
        # The XBEN-006-24 admin gate response
        self.assertEqual(
            _classify(
                tool_output=(
                    'HTTP/1.1 403 Forbidden\n'
                    '{"detail":"Only admins can see private jobs"}'
                ),
            ),
            "application_4xx",
        )

    def test_status_colon_format(self):
        self.assertEqual(
            _classify(tool_output="Status: 401\nBody: {\"error\":\"unauthorized\"}"),
            "application_4xx",
        )

    def test_generic_body_method_not_allowed(self):
        # No explicit status line — body marker should still flag 4xx
        self.assertEqual(
            _classify(tool_output='{"detail":"Method Not Allowed"}'),
            "application_4xx",
        )


# ---------------------------------------------------------------------------
# HTTP 5xx — fast vs normal latency
# ---------------------------------------------------------------------------

class TestApplication5xxLatencyBranch(unittest.TestCase):
    """The whole reason P2 exists: same status code, opposite meaning.
    A 5xx in <50ms is parse-time crash (input never reached business logic).
    A 5xx in >=50ms is application/DB-level error."""

    def test_5xx_fast_explicit_status(self):
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=3,
            ),
            "application_5xx_fast",
        )

    def test_5xx_fast_generic_body(self):
        # FastAPI default plain-text 500 page (the iter-11 signature)
        self.assertEqual(
            _classify(
                tool_output="Status: 500, Body: Internal Server Error",
                duration_ms=4,
            ),
            "application_5xx_fast",
        )

    def test_5xx_networked_fast_latency(self):
        """140ms on a networked target falls into the networked-fast tier:
        still a parse-time / early-guard crash signature, but reaching the
        target over the network adds ~100ms of round-trip overhead."""
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=140,
            ),
            "application_5xx_networked_fast",
        )

    def test_5xx_normal_latency(self):
        """>=200ms means the application reached its deep error path
        (DB / business-logic crash), not an early guard."""
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=350,
            ),
            "application_5xx_normal",
        )

    def test_5xx_boundary_just_below(self):
        """49ms is localhost-fast; 50ms crosses into the networked-fast tier."""
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=FAST_RESPONSE_THRESHOLD_MS - 1,
            ),
            "application_5xx_fast",
        )

    def test_5xx_boundary_at_threshold(self):
        """At exactly FAST_RESPONSE_THRESHOLD_MS (50ms), classification
        promotes to the networked-fast tier — still a parse-time-crash
        signature, just with the networking overhead included."""
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=FAST_RESPONSE_THRESHOLD_MS,
            ),
            "application_5xx_networked_fast",
        )

    def test_5xx_networked_boundary_at_threshold(self):
        """At exactly NETWORKED_FAST_THRESHOLD_MS (200ms), classification
        promotes to the normal tier — deep error path was reached."""
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=_ec.NETWORKED_FAST_THRESHOLD_MS,
            ),
            "application_5xx_normal",
        )

    def test_5xx_with_zero_duration_falls_normal(self):
        """duration_ms=0 means we didn't capture timing; defaulting to fast
        would create false positives, so the classifier treats unknown as
        normal-latency."""
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=0,
            ),
            "application_5xx_normal",
        )

    def test_5xx_with_none_duration_falls_normal(self):
        self.assertEqual(
            _classify(
                tool_output="HTTP/1.1 500 Internal Server Error",
                duration_ms=None,
            ),
            "application_5xx_normal",
        )

    def test_503_service_unavailable_fast(self):
        self.assertEqual(
            _classify(tool_output="HTTP/1.1 503 Service Unavailable", duration_ms=8),
            "application_5xx_fast",
        )


# ---------------------------------------------------------------------------
# Success — clean 200s and friends
# ---------------------------------------------------------------------------

class TestSuccess(unittest.TestCase):

    def test_clean_200(self):
        self.assertEqual(
            _classify(
                tool_output='HTTP/1.1 200 OK\n[{"id":1,"name":"Senior Frontend Dev"}]',
                duration_ms=18,
            ),
            "success",
        )

    def test_201_created(self):
        self.assertEqual(
            _classify(tool_output="HTTP/1.1 201 Created"),
            "success",
        )

    def test_204_no_content(self):
        self.assertEqual(
            _classify(tool_output="HTTP/1.1 204 No Content"),
            "success",
        )

    def test_success_with_no_http_context(self):
        """Some tools (execute_naabu output, nmap, etc.) don't return HTTP
        responses at all. success=True with no failure signature → success."""
        self.assertEqual(
            _classify(
                tool_output="172.24.0.8:80\n172.24.0.8:443\n",
                duration_ms=2300,
            ),
            "success",
        )


# ---------------------------------------------------------------------------
# HTTP status extraction
# ---------------------------------------------------------------------------

class TestExtractHttpStatus(unittest.TestCase):
    """Four shapes the wrapper might surface. Failing to detect any one of
    them collapses 4xx/5xx back into the generic success/fail bucket."""

    def test_http_version_line(self):
        self.assertEqual(_extract_http_status("HTTP/1.1 405 Method Not Allowed"), 405)

    def test_http_2_status_line(self):
        self.assertEqual(_extract_http_status("HTTP/2 503 Service Unavailable"), 503)

    def test_status_colon_format(self):
        self.assertEqual(_extract_http_status("Status: 500\nBody: foo"), 500)

    def test_info_status_prefix(self):
        self.assertEqual(_extract_http_status("[INFO] Status: 403"), 403)

    def test_status_code_equals_format(self):
        self.assertEqual(_extract_http_status("StatusCode=200 elapsed=12ms"), 200)

    def test_bare_three_digit_curl_writeout(self):
        # curl -w '%{http_code}' bare output
        self.assertEqual(_extract_http_status("200\n"), 200)

    def test_no_status_returns_none(self):
        self.assertIsNone(_extract_http_status("plain text response, no status"))

    def test_random_three_digit_in_middle_not_picked(self):
        """A 3-digit number embedded in body text should NOT be picked up
        as a status. This guards against false-positive classification."""
        self.assertIsNone(_extract_http_status("count was 200 items returned"))


# ---------------------------------------------------------------------------
# is_diagnostic_failure
# ---------------------------------------------------------------------------

class TestIsDiagnosticFailure(unittest.TestCase):
    """Helper used by future coverage-map logic to distinguish 'real
    negative result' from 'harness glitch'."""

    def test_shell_parser_is_diagnostic(self):
        self.assertTrue(is_diagnostic_failure("shell_parser_error"))

    def test_transport_is_diagnostic(self):
        self.assertTrue(is_diagnostic_failure("transport_error"))

    def test_tool_internal_is_diagnostic(self):
        self.assertTrue(is_diagnostic_failure("tool_internal_error"))

    def test_5xx_fast_is_diagnostic(self):
        self.assertTrue(is_diagnostic_failure("application_5xx_fast"))

    def test_4xx_is_real_signal(self):
        self.assertFalse(is_diagnostic_failure("application_4xx"))

    def test_5xx_normal_is_real_signal(self):
        self.assertFalse(is_diagnostic_failure("application_5xx_normal"))

    def test_success_not_diagnostic(self):
        self.assertFalse(is_diagnostic_failure("success"))

    def test_none_not_diagnostic(self):
        self.assertFalse(is_diagnostic_failure(None))


# ---------------------------------------------------------------------------
# Robustness — None / empty / mixed inputs
# ---------------------------------------------------------------------------

class TestRobustness(unittest.TestCase):

    def test_all_none_inputs(self):
        """The classifier must never raise. Empty/None fields → tool_internal
        when success=False, success when success=True."""
        self.assertEqual(
            classify_error_class(
                success=False,
                tool_output=None,
                error_message=None,
                duration_ms=None,
                tool_name=None,
            ),
            "tool_internal_error",
        )

    def test_all_none_success_true(self):
        self.assertEqual(
            classify_error_class(
                success=True,
                tool_output=None,
                error_message=None,
                duration_ms=None,
                tool_name=None,
            ),
            "success",
        )

    def test_empty_strings_success_true(self):
        self.assertEqual(_classify(tool_output="", error_message=""), "success")

    def test_error_message_carries_signature(self):
        """Some failures put the signature in error_message, not tool_output."""
        self.assertEqual(
            classify_error_class(
                success=False,
                tool_output="",
                error_message="[ERROR] No closing quotation",
                duration_ms=10,
                tool_name="execute_curl",
            ),
            "shell_parser_error",
        )

    def test_signature_priority_shell_beats_transport(self):
        """If both signatures appear (shouldn't happen in practice but the
        order is defined): shell parser wins because the harness died first."""
        self.assertEqual(
            _classify(
                success=False,
                tool_output=(
                    "[ERROR] No closing quotation\n"
                    "Could not resolve host: example.com"
                ),
            ),
            "shell_parser_error",
        )

    def test_signature_priority_status_beats_internal(self):
        """An explicit HTTP status takes precedence over a generic 'Tool
        execution failed' line in the same body — the status line is the
        more authoritative signal."""
        self.assertEqual(
            _classify(
                success=False,
                tool_output="HTTP/1.1 401 Unauthorized\nTool execution failed: auth",
            ),
            "application_4xx",
        )


# ---------------------------------------------------------------------------
# Hints dictionary — every class has a human description
# ---------------------------------------------------------------------------

class TestErrorClassHints(unittest.TestCase):

    def test_every_class_has_hint(self):
        """If a new class is added to classify_error_class without a hint,
        the chain-context render will silently show the class name with no
        explanation. This guard catches that."""
        expected_classes = {
            "success",
            "shell_parser_error",
            "transport_error",
            "tool_internal_error",
            "application_4xx",
            "application_5xx_fast",
            "application_5xx_networked_fast",
            "application_5xx_normal",
        }
        self.assertEqual(
            set(ERROR_CLASS_HINTS.keys()),
            expected_classes,
            "ERROR_CLASS_HINTS drifted from classify_error_class output set",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
