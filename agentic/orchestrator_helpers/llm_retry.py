"""Shared LLM transient-error classifier + retry helper.

Background. PR #111 added a 3-attempt retry around the fireteam member's
``await llm.ainvoke(...)`` because a single transient error (network blip,
HTTP 529 overload, rate-limit) was terminating an entire fireteam member.
A subsequent review found the same root-cause pattern in two other
places:

  * Root ``think_node`` — calls ``ainvoke`` with NO try/except, so a
    transient there crashes the whole session, not just one specialist.
  * ``guardrail`` — has a 3-attempt loop but with a broad ``except
    Exception`` that retries permanent errors (invalid API key, schema
    bugs) 3x, wasting budget and producing a worse error message.

This module centralizes the classification and retry policy so all three
call sites use identical logic and a new transient exception type added
in the wild (e.g. a future SDK ``RetryableError``) only needs to be added
in one place.

Public API:
  * ``is_transient_llm_error(exc)`` — classify a raised exception
  * ``retry_llm_call(llm, messages, *, label, max_attempts)`` — async
    wrapper around ``llm.ainvoke`` that retries on transient errors
    only, exponential backoff, and re-raises the last exception on
    exhaustion or first non-transient error.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# Class names from anthropic, openai, and httpx SDKs that indicate transient
# failures. Matched against ``type(exc).__mro__`` so SDK subclasses (e.g.
# ``APITimeoutError`` extends ``APIConnectionError``) are caught even when
# only the parent name is enumerated.
_TRANSIENT_EXC_NAMES = frozenset({
    "APIConnectionError", "APITimeoutError", "RateLimitError",
    "InternalServerError", "ServiceUnavailableError", "OverloadedError",
    "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
    "PoolTimeout", "TimeoutException", "RemoteProtocolError",
})

# Phrase fallback for wrapped exceptions or providers whose class names we
# don't enumerate (Bedrock, Gemini, custom). Lowercased substring match on
# ``str(exc)``.
_TRANSIENT_KEYWORDS = (
    "connection", "timeout", "timed out", "overloaded",
    "rate_limit", "rate limit", "apiconnectionerror",
    "service unavailable", "bad gateway", "gateway timeout",
    "internal server error", "server_error",
)

# Bare HTTP status codes matched with WORD BOUNDARIES so "500" does NOT
# fire on "50000" — e.g. a permanent ``max_tokens: 50000 exceeded`` error
# must not be classified transient. 429 is added even though it's < 500
# because it's rate-limit, retry-worthy.
_TRANSIENT_STATUS_RE = re.compile(r"\b(429|500|502|503|504|529)\b")


def is_transient_llm_error(exc: BaseException) -> bool:
    """Classify an LLM-call exception as transient (worth retrying) or not.

    Order: type-MRO match first (cheapest, most specific), then message
    substring, then bare HTTP status code regex.
    """
    for base in type(exc).__mro__:
        if base.__name__ in _TRANSIENT_EXC_NAMES:
            return True
    err_str = str(exc).lower()
    if any(k in err_str for k in _TRANSIENT_KEYWORDS):
        return True
    return bool(_TRANSIENT_STATUS_RE.search(err_str))


async def retry_llm_call(
    llm: Any,
    messages: list,
    *,
    label: str = "llm",
    max_attempts: int = 3,
) -> Any:
    """Call ``await llm.ainvoke(messages)`` with transient-error retry.

    Behavior:
      * On transient errors (as classified by ``is_transient_llm_error``),
        retries up to ``max_attempts`` total attempts with exponential
        backoff: ``min(2 ** attempt, 8)`` seconds between attempts. No
        sleep after the final attempt — wasted latency before the raise.
      * On non-transient errors (auth, schema, model-not-found, token
        limit, etc.), re-raises immediately — no point retrying.
      * On exhaustion, re-raises the last exception unchanged so callers
        can match on the original type/message.

    The label is included in every log line so concurrent fireteam waves
    can be disambiguated in the log stream.
    """
    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return await llm.ainvoke(messages)
        except Exception as exc:
            last_exc = exc
            transient = is_transient_llm_error(exc)
            logger.warning(
                "[%s] LLM attempt %d/%d error (transient=%s, type=%s): %s",
                label, attempt + 1, max_attempts, transient,
                type(exc).__name__, exc,
            )
            if not transient:
                raise
            if attempt < max_attempts - 1:
                await asyncio.sleep(min(2 ** attempt, 8))
    assert last_exc is not None  # pragma: no cover — loop body always assigns
    raise last_exc
