"""Unit tests for the shared ``orchestrator_helpers.llm_retry`` module.

Direct tests of ``is_transient_llm_error`` and ``retry_llm_call`` — the
shared helper used by fireteam_member_think_node, root think_node, and
guardrail. These tests do NOT exercise any node integration; for that
see ``tests/test_fireteam_member_llm_retry.py`` (fireteam side) and
``tests/test_think_node_llm_retry.py`` (root side).

Run (inside agent container):
    docker run --rm \\
        -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -v "/path/knowledge_base:/app/knowledge_base:ro" \\
        -w /app redamon-agent python -m unittest \\
        tests.test_llm_retry -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# Synthetic SDK exception classes — names match the real SDK class names
# because is_transient_llm_error matches on ``type(exc).__name__``.

class APIConnectionError(Exception):
    pass


class APITimeoutError(APIConnectionError):
    pass


class RateLimitError(Exception):
    pass


class InternalServerError(Exception):
    pass


class _PermanentAuthError(Exception):
    """Non-transient; must NOT trigger retry."""


_VALID_RESPONSE = MagicMock(content='{"thought":"t","reasoning":"r","action":"complete"}')


class RetryLLMCallTests(unittest.IsolatedAsyncioTestCase):
    """Direct tests of ``retry_llm_call``.

    Patches ``asyncio.sleep`` in the llm_retry module so backoff is
    instantaneous and we can assert exact ``await_count`` for both the
    LLM and the sleep — that double-count is the only way to lock the
    "no wasted sleep after the final attempt" bug fix in place.
    """

    async def _invoke(self, mock_llm, *, max_attempts: int = 3):
        from orchestrator_helpers.llm_retry import retry_llm_call
        with patch(
            "orchestrator_helpers.llm_retry.asyncio.sleep",
            new_callable=AsyncMock,
        ) as mock_sleep:
            try:
                result = await retry_llm_call(
                    mock_llm, ["msg"],
                    label="test", max_attempts=max_attempts,
                )
                return result, mock_sleep, None
            except Exception as exc:
                return None, mock_sleep, exc

    # ----- Happy path -----

    async def test_first_attempt_success_no_retry(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=_VALID_RESPONSE)
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(sleep.await_count, 0)

    # ----- Transient retry then success -----

    async def test_one_transient_then_success(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("blip"),
            _VALID_RESPONSE,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 2)
        self.assertEqual(sleep.await_count, 1)

    async def test_two_transient_then_success(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("first"),
            RateLimitError("second"),
            _VALID_RESPONSE,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertIsNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        self.assertEqual(sleep.await_count, 2)

    # ----- Exhaustion: re-raise last exception -----

    async def test_three_transient_failures_raise_last(self):
        last = APIConnectionError("third")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("first"),
            APIConnectionError("second"),
            last,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIsNone(result)
        self.assertIs(exc, last,
                      "exhaustion must re-raise the LAST exception unchanged")
        self.assertEqual(mock_llm.ainvoke.await_count, 3)
        # BUG GUARD: no sleep after the FINAL attempt.
        self.assertEqual(sleep.await_count, 2,
                         "must not sleep after the final attempt")

    # ----- Non-transient: immediate re-raise -----

    async def test_non_transient_reraises_immediately(self):
        permanent = _PermanentAuthError("Invalid API key")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=permanent)
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIsNone(result)
        self.assertIs(exc, permanent,
                      "non-transient must propagate unchanged")
        self.assertEqual(mock_llm.ainvoke.await_count, 1,
                         "non-transient must NOT retry")
        self.assertEqual(sleep.await_count, 0)

    # ----- Max attempts is honored -----

    async def test_max_attempts_1_means_no_retry(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=APIConnectionError("once"))
        result, sleep, exc = await self._invoke(mock_llm, max_attempts=1)
        self.assertIsNotNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 1)
        self.assertEqual(sleep.await_count, 0,
                         "max_attempts=1 — no inter-attempt sleeps possible")

    async def test_max_attempts_5_allows_5_attempts(self):
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=APIConnectionError("repeated"))
        result, sleep, exc = await self._invoke(mock_llm, max_attempts=5)
        self.assertIsNotNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 5)
        self.assertEqual(sleep.await_count, 4)

    # ----- Mixed transient + non-transient (transient first, then permanent) -----

    async def test_transient_then_permanent_reraises_permanent(self):
        permanent = _PermanentAuthError("auth bug after the blip")
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            APIConnectionError("transient"),
            permanent,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(exc, permanent)
        self.assertEqual(mock_llm.ainvoke.await_count, 2,
                         "second attempt fires after transient, then permanent breaks")
        self.assertEqual(sleep.await_count, 1)

    # ----- Type classification used for retry decision (regression for
    # PR-#111 classifier optimization) -----

    async def test_internal_server_error_classified_transient_and_retried(self):
        """Bare InternalServerError with no transient keyword in the message
        must still be retried — proves type-MRO classification is wired
        through retry_llm_call (and not just keyword matching)."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=[
            InternalServerError("Server returned an error"),
            _VALID_RESPONSE,
        ])
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIs(result, _VALID_RESPONSE)
        self.assertEqual(mock_llm.ainvoke.await_count, 2)

    async def test_max_tokens_50000_is_not_retried(self):
        """Numeric-substring bug guard: '500' inside '50000' must NOT
        classify as transient."""
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(side_effect=Exception(
            "max_tokens: 50000 exceeded model context window"
        ))
        result, sleep, exc = await self._invoke(mock_llm)
        self.assertIsNotNone(exc)
        self.assertEqual(mock_llm.ainvoke.await_count, 1,
                         "token-limit error must fail fast — no retry")
        self.assertEqual(sleep.await_count, 0)


if __name__ == "__main__":
    unittest.main()
