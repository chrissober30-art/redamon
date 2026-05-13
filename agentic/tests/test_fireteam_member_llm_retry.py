"""Fireteam member LLM transient-error retry — regression + classifier + integration.

Locks the behavior introduced by PR #111 (3-attempt retry on transient LLM
errors) and the follow-up classifier optimization (type-MRO + word-boundary
HTTP-status regex) that addresses two bugs found during deep review:

  * Bare numeric substrings ("500", "502", "503", "504", "529") in the
    PR-#111 keyword list false-positive on messages like "max_tokens
    50000 exceeded" — a permanent token-limit error was being retried 3x.
  * PR-#111's classifier used substring matching ONLY; a bare
    `anthropic.InternalServerError` with a generic message ("Server
    returned an error") would not match any keyword and was therefore
    classified non-transient, breaking out after the first attempt.
  * The retry loop slept after the FINAL attempt with no further retry
    to perform — 4s of wasted latency before returning the llm_error.

Run (inside agent container):
    docker run --rm \\
        -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -v "/path/knowledge_base:/app/knowledge_base:ro" \\
        -w /app redamon-agent python -m unittest \\
        tests.test_fireteam_member_llm_retry -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# =============================================================================
# Synthetic exception classes — mirror SDK class names without importing the
# SDKs. The classifier walks type(exc).__mro__ matching on __name__, so the
# class name MUST be identical to the SDK's. Defined locally to keep the
# tests independent of langchain_anthropic / openai / httpx installs.
# =============================================================================

class APIConnectionError(Exception):
    """Mirrors anthropic.APIConnectionError / openai.APIConnectionError."""


class APITimeoutError(APIConnectionError):
    """Mirrors anthropic.APITimeoutError (subclass of APIConnectionError).

    Tests that the MRO walk catches subclasses whose own __name__ is also
    in the transient set, AND that the parent name catches via MRO when a
    subclass is unknown."""


class RateLimitError(Exception):
    pass


class InternalServerError(Exception):
    pass


class ReadTimeout(Exception):  # mirrors httpx.ReadTimeout
    pass


class _PermanentAuthError(Exception):
    """A non-transient permanent error — used to verify break-out behavior."""


# =============================================================================
# 1. UNIT: classifier (_is_transient_llm_error)
# =============================================================================

class IsTransientLLMErrorTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.llm_retry import is_transient_llm_error
        self.fn = is_transient_llm_error

    # ----- Type-MRO match (the optimization's new path) -----

    def test_apiconnectionerror_class_name_matches(self):
        self.assertTrue(self.fn(APIConnectionError("any msg")))

    def test_apitimeouterror_subclass_matches_via_mro(self):
        """APITimeoutError's __name__ IS in the set, but also tests MRO walk
        works for classes whose immediate name is in the set."""
        self.assertTrue(self.fn(APITimeoutError("read took too long")))

    def test_ratelimiterror_class_name_matches(self):
        self.assertTrue(self.fn(RateLimitError("retry after 60s")))

    def test_internalservererror_class_name_matches(self):
        """PR #111 keyword-only classifier would have missed this because
        the message has no transient keyword. Locks the type-MRO addition."""
        self.assertTrue(self.fn(
            InternalServerError("Server returned an error")
        ))

    def test_httpx_readtimeout_class_name_matches(self):
        self.assertTrue(self.fn(ReadTimeout("some opaque msg")))

    def test_subclass_inherits_transient_via_mro(self):
        """User-defined subclass of a transient base must still classify."""
        class _SubAPIConn(APIConnectionError):
            pass
        self.assertTrue(self.fn(_SubAPIConn("inherited")))

    # ----- Keyword (phrase) match -----

    def test_overloaded_phrase_matches(self):
        self.assertTrue(self.fn(Exception("server is overloaded, try later")))

    def test_service_unavailable_phrase_matches(self):
        self.assertTrue(self.fn(Exception("Service Unavailable")))

    def test_internal_server_error_phrase_matches(self):
        self.assertTrue(self.fn(Exception("Internal Server Error")))

    def test_bad_gateway_phrase_matches(self):
        self.assertTrue(self.fn(Exception("502 Bad Gateway from upstream")))

    def test_gateway_timeout_phrase_matches(self):
        self.assertTrue(self.fn(Exception("Gateway Timeout")))

    def test_rate_limit_phrase_matches(self):
        self.assertTrue(self.fn(Exception("rate limit exceeded")))

    def test_connection_keyword_matches(self):
        self.assertTrue(self.fn(Exception("Connection error: refused")))

    def test_timeout_keyword_matches(self):
        self.assertTrue(self.fn(Exception("Request timed out after 30s")))

    def test_case_insensitive(self):
        self.assertTrue(self.fn(Exception("TIMEOUT")))
        self.assertTrue(self.fn(Exception("INTERNAL SERVER ERROR")))

    # ----- HTTP status code regex match (word-boundary) -----

    def test_status_503_matches(self):
        self.assertTrue(self.fn(Exception("HTTP 503 from upstream")))

    def test_status_502_matches(self):
        self.assertTrue(self.fn(Exception("Got 502 response")))

    def test_status_500_matches(self):
        self.assertTrue(self.fn(Exception("Server returned 500")))

    def test_status_504_matches(self):
        self.assertTrue(self.fn(Exception("upstream returned 504")))

    def test_status_529_matches(self):
        self.assertTrue(self.fn(Exception("status: 529")))

    def test_status_429_matches(self):
        """429 is added by the optimization (not in PR #111's keywords)."""
        self.assertTrue(self.fn(Exception("HTTP 429 too many requests")))

    # ----- BUG GUARDS: numeric substring false positives -----

    def test_no_false_positive_max_tokens_50000(self):
        """BUG GUARD: '500' substring of '50000' must NOT classify transient.
        Pre-fix this triggered 14s of retries on a permanent token-limit
        error before still failing."""
        self.assertFalse(self.fn(Exception(
            "max_tokens: 50000 exceeded model context window"
        )))

    def test_no_false_positive_token_count_50007(self):
        self.assertFalse(self.fn(Exception("Token count 50007 over limit")))

    def test_no_false_positive_5001(self):
        """A bare '5001' (not a real status) must not fire on '500'."""
        self.assertFalse(self.fn(Exception("Error code 5001: domain-specific")))

    def test_no_false_positive_5290(self):
        """'5290' must not fire on '529'."""
        self.assertFalse(self.fn(Exception("Field value 5290 invalid")))

    def test_no_false_positive_1500(self):
        """'1500' must not fire on '500'."""
        self.assertFalse(self.fn(Exception("Wait 1500 ms before retry")))

    # ----- Genuine non-transient errors -----

    def test_invalid_api_key_not_transient(self):
        self.assertFalse(self.fn(_PermanentAuthError("Invalid API key")))

    def test_bad_request_not_transient(self):
        self.assertFalse(self.fn(Exception("Bad request: schema invalid")))

    def test_model_not_found_not_transient(self):
        self.assertFalse(self.fn(Exception(
            "Model 'claude-opus-9' not found"
        )))

    def test_permission_denied_not_transient(self):
        self.assertFalse(self.fn(Exception(
            "Permission denied: org lacks access to this model"
        )))


# =============================================================================
# 2. INTEGRATION: retry loop inside fireteam_member_think_node
# =============================================================================

def _base_member_state(**overrides):
    """Minimal FireteamMemberState that traverses to the LLM call."""
    base = {
        "messages": [], "current_iteration": 1, "max_iterations": 10,
        "task_complete": False, "completion_reason": None,
        "current_phase": "informational", "attack_path_type": "cve_exploit",
        "user_id": "u", "project_id": "p", "session_id": "s",
        "parent_target_info": {}, "member_name": "Web Tester",
        "member_id": "member-0-abc", "fireteam_id": "fteam-1",
        "tools": ["xss"], "task": "scan target",
        "execution_trace": [], "target_info": {}, "chain_findings_memory": [],
        "chain_failures_memory": [], "_pending_confirmation": None,
        "_current_plan": None, "tokens_used": 0, "_decision": None,
        "_current_step": {
            "tool_name": "execute_nmap",
            "tool_args": {"target": "10.0.0.1"},
            "tool_output": "PORT 80/tcp open http",
            "success": True, "iteration": 1,
            "thought": "scan", "reasoning": "recon",
            "error_message": None,
        },
        "_last_chain_step_id": None,
        "_guardrail_blocked": False,
    }
    base.update(overrides)
    return base


_DECISION_JSON = (
    '{"thought":"t","reasoning":"r","action":"complete",'
    '"completion_reason":"done"}'
)


class FireteamMemberRetryIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Integration tests for the retry loop wrapping ``llm.ainvoke``.

    Each test patches ``asyncio.sleep`` in the module under test so backoff
    is instantaneous and we can assert the exact call count — that is
    the bug guard for "no wasted sleep after the final attempt".
    """

    async def _run(self, mock_llm, state_overrides=None):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            fireteam_member_think_node,
        )
        state = _base_member_state(**(state_overrides or {}))
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph",
            MagicMock(),
        ), patch(
            "orchestrator_helpers.llm_retry.asyncio.sleep",
            new_callable=AsyncMock,
        ) as mock_sleep:
            update = await fireteam_member_think_node(
                state, None,
                llm=mock_llm,
                neo4j_creds=None,
                streaming_callbacks=None,
            )
            return update, mock_sleep

    # ----- Happy path -----

    async def test_first_attempt_success_no_retry_no_sleep(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=_DECISION_JSON)
        )
        update, mock_sleep = await self._run(mock_llm)

        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(mock_sleep.await_count, 0)
        self.assertFalse(
            (update.get("completion_reason") or "").startswith("llm_error"),
            f"unexpected llm_error: {update.get('completion_reason')!r}",
        )

    # ----- Core regression: PR #111 -----

    async def test_one_transient_then_success_does_not_terminate(self):
        """REGRESSION (master pre-#111): ONE transient exception used to
        terminate the member with ``llm_error: …``. Locks the 3-attempt
        retry behavior."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("connection refused"),
            MagicMock(content=_DECISION_JSON),
        ])
        update, mock_sleep = await self._run(mock_llm)

        self.assertEqual(mock_llm.ainvoke.await_count, 2)
        self.assertEqual(mock_sleep.await_count, 1,
                         "exactly one backoff between the two attempts")
        self.assertFalse(
            (update.get("completion_reason") or "").startswith("llm_error"),
        )

    async def test_two_transient_then_success(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("first"),
            ReadTimeout("second"),
            MagicMock(content=_DECISION_JSON),
        ])
        update, mock_sleep = await self._run(mock_llm)

        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        self.assertEqual(mock_sleep.await_count, 2)
        self.assertFalse(
            (update.get("completion_reason") or "").startswith("llm_error"),
        )

    # ----- Exhaustion -----

    async def test_three_transient_failures_terminate_with_llm_error(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(
            side_effect=APIConnectionError("nope")
        )
        update, mock_sleep = await self._run(mock_llm)

        self.assertTrue(update.get("task_complete"))
        reason = update.get("completion_reason") or ""
        self.assertTrue(reason.startswith("llm_error"),
                        f"expected llm_error reason, got {reason!r}")
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        # BUG GUARD: must NOT sleep after the 3rd (final) attempt.
        self.assertEqual(mock_sleep.await_count, 2,
                         "must not sleep after the final attempt — no retry follows")

    # ----- Non-transient break-out -----

    async def test_non_transient_breaks_immediately(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(
            side_effect=_PermanentAuthError("Invalid API key")
        )
        update, mock_sleep = await self._run(mock_llm)

        self.assertTrue(update.get("task_complete"))
        self.assertTrue(
            (update.get("completion_reason") or "").startswith("llm_error")
        )
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(mock_sleep.await_count, 0)

    # ----- Classifier-driven regressions -----

    async def test_internal_server_error_class_triggers_retry(self):
        """The optimization's type-MRO check: a bare InternalServerError
        with no transient keyword in its message MUST be retried. Under
        PR #111's keyword-only classifier this terminated on first attempt."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            InternalServerError("Server returned an error"),
            MagicMock(content=_DECISION_JSON),
        ])
        update, mock_sleep = await self._run(mock_llm)

        self.assertEqual(mock_llm.ainvoke.await_count, 2)
        self.assertEqual(mock_sleep.await_count, 1)
        self.assertFalse(
            (update.get("completion_reason") or "").startswith("llm_error"),
        )

    async def test_max_tokens_50000_is_not_retried(self):
        """BUG GUARD: '500' inside '50000' must NOT trigger transient retry.
        Pre-fix (substring numerics) this paid 14s of useless backoff on a
        permanent token-limit error before still failing."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=Exception(
            "max_tokens: 50000 exceeded model context window"
        ))
        update, mock_sleep = await self._run(mock_llm)

        self.assertEqual(mock_llm.ainvoke.await_count, 1,
                         "permanent token-limit error must NOT be retried")
        self.assertEqual(mock_sleep.await_count, 0)
        self.assertTrue(update.get("task_complete"))


if __name__ == "__main__":
    unittest.main()
