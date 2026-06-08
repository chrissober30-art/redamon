"""
Diagnostic classification of tool-step outcomes.

A single `success: bool` flag conflates fundamentally different failure modes:
a shell-quoting glitch (request never sent) looks identical to a 405 Method
Not Allowed (legitimate server rejection) which looks identical to a 500 with
a 3ms duration (parse-time crash before the application's business logic ever
ran). The LLM cannot distinguish these from the chain context, so it marks
whole vector classes as "tested" on the basis of failures that never reached
the target.

`classify_error_class` returns one of:

    success                          — succeeded, no embedded error, no 4xx/5xx detected
    shell_parser_error               — bash/shlex/quoting; request never left the harness
    transport_error                  — DNS/connection/network; request never reached the app
    tool_internal_error              — tool wrapper itself failed (curl returncode, MCP error)
    application_4xx                  — server returned 4xx (legitimate semantic rejection)
    application_5xx_fast             — server returned 5xx in <50ms (localhost-grade parse-time / early guard crash)
    application_5xx_networked_fast   — server returned 5xx in 50..200ms (parse-time crash with networking overhead)
    application_5xx_normal           — server returned 5xx after >=200ms (DB / business-logic crash)

Surfaced in `format_chain_context` so the LLM sees, per step, what kind of
failure happened — not just that something failed.
"""

from __future__ import annotations

import re
from typing import Optional


# Order matters in classify_error_class — the first matching family wins.
# Patterns are evaluated against (tool_output + error_message)[:6000].

_SHELL_PARSER_PATTERNS = [
    re.compile(r"\bno closing quot", re.IGNORECASE),
    re.compile(r"unexpected end of file", re.IGNORECASE),
    re.compile(r"syntax error near unexpected token", re.IGNORECASE),
    re.compile(r"\bshlex\.", re.IGNORECASE),
    re.compile(r"ValueError:\s*No closing", re.IGNORECASE),
    # Heredoc / bash quoting failures the MCP wrapper surfaces verbatim
    re.compile(r"bash: line \d+: syntax error", re.IGNORECASE),
]

_TRANSPORT_PATTERNS = [
    re.compile(r"could not resolve host", re.IGNORECASE),
    re.compile(r"connection refused", re.IGNORECASE),
    re.compile(r"connection timed out", re.IGNORECASE),
    re.compile(r"name or service not known", re.IGNORECASE),
    re.compile(r"network is unreachable", re.IGNORECASE),
    re.compile(r"no route to host", re.IGNORECASE),
    re.compile(r"ssl(?:v\d)?\s+handshake", re.IGNORECASE),
    re.compile(r"NewConnectionError", re.IGNORECASE),
    re.compile(r"ConnectTimeoutError", re.IGNORECASE),
    re.compile(r"\bENETUNREACH\b"),
    re.compile(r"\bEHOSTUNREACH\b"),
]

# Tool wrapper failures: curl returncode != 0, MCP "Tool execution failed",
# file-not-found from -d @file with a missing file, Playwright crashes, etc.
_TOOL_INTERNAL_PATTERNS = [
    re.compile(r"\[ERROR\]\s*execute_\w+\s+failed:\s*returncode=", re.IGNORECASE),
    re.compile(r"option\s+-\w+:\s*error encountered when reading a file", re.IGNORECASE),
    re.compile(r"file not found\b", re.IGNORECASE),
    re.compile(r"no such file or directory", re.IGNORECASE),
    re.compile(r"Tool execution failed:", re.IGNORECASE),
    re.compile(r"Tool execution returned no result", re.IGNORECASE),
    re.compile(r"playwright\._impl\._errors\.", re.IGNORECASE),
    re.compile(r"Command timed out after", re.IGNORECASE),
    re.compile(r"command not found", re.IGNORECASE),
]

# HTTP status extraction. Multiple shapes because MCP wrappers, curl -v,
# httpx, and ad-hoc Python all format status differently.
_HTTP_STATUS_PATTERNS = [
    re.compile(r"HTTP/[0-9.]+\s+(\d{3})\b"),
    re.compile(r"^\s*Status[:\s]+(\d{3})\b", re.MULTILINE),
    re.compile(r"\[INFO\]\s+(?:Status|HTTP)[:\s]+(\d{3})\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"\bStatus(?:Code)?[:=]\s*(\d{3})\b"),
    # Curl --write-out '%{http_code}' often emits a bare 3-digit number on its own line
    re.compile(r"^\s*(\d{3})\s*$", re.MULTILINE),
]

# FastAPI / Starlette / nginx default short 5xx bodies that arrive without
# an explicit status line in the body. If we see one of these, treat it as
# 5xx and let duration_ms decide fast-vs-normal.
_GENERIC_5XX_BODY_MARKERS = (
    "internal server error",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
)

# Common 4xx body markers used when no status line is in the body
_GENERIC_4XX_BODY_MARKERS = (
    "method not allowed",
    "not found",
    "unauthorized",
    "forbidden",
    "bad request",
)

FAST_RESPONSE_THRESHOLD_MS = 50
# Networked targets reachable over a docker network (or any non-localhost
# bridge) add ~50-150ms of round-trip overhead. A parse-time crash that
# would be <50ms on localhost lands at 100-150ms on these targets and would
# otherwise get bucketed as `application_5xx_normal` ("DB-level error") even
# though the input never reached the database. The networked-fast tier
# preserves the parse-time-crash semantic for these cases.
NETWORKED_FAST_THRESHOLD_MS = 200


def classify_error_class(
    *,
    success: bool,
    tool_output: Optional[str],
    error_message: Optional[str],
    duration_ms: Optional[int],
    tool_name: Optional[str] = None,
) -> str:
    """Classify a completed tool step. Never raises; defaults to 'success'
    when success=True and no failure signature matches, 'tool_internal_error'
    otherwise."""
    output = tool_output or ""
    err = error_message or ""
    haystack = (output + "\n" + err)[:6000]
    dur = int(duration_ms or 0)

    for pat in _SHELL_PARSER_PATTERNS:
        if pat.search(haystack):
            return "shell_parser_error"
    for pat in _TRANSPORT_PATTERNS:
        if pat.search(haystack):
            return "transport_error"

    status = _extract_http_status(haystack)
    if status is not None:
        if 400 <= status < 500:
            return "application_4xx"
        if 500 <= status < 600:
            return _classify_5xx(dur)
        if 200 <= status < 400 and success:
            return "success"

    # Body markers as fallback when no explicit status line
    low = haystack.lower()
    if any(m in low for m in _GENERIC_5XX_BODY_MARKERS):
        return _classify_5xx(dur)
    if any(m in low for m in _GENERIC_4XX_BODY_MARKERS):
        return "application_4xx"

    for pat in _TOOL_INTERNAL_PATTERNS:
        if pat.search(haystack):
            return "tool_internal_error"

    if not success:
        return "tool_internal_error"
    return "success"


def _classify_5xx(duration_ms: int) -> str:
    if 0 < duration_ms < FAST_RESPONSE_THRESHOLD_MS:
        return "application_5xx_fast"
    if 0 < duration_ms < NETWORKED_FAST_THRESHOLD_MS:
        return "application_5xx_networked_fast"
    return "application_5xx_normal"


def _extract_http_status(text: str) -> Optional[int]:
    for pat in _HTTP_STATUS_PATTERNS:
        m = pat.search(text)
        if m:
            try:
                return int(m.group(1))
            except (ValueError, IndexError):
                continue
    return None


# One-line human descriptions used by format_chain_context. Keep terse —
# these render inline next to every tool call in the recent window.
ERROR_CLASS_HINTS = {
    "shell_parser_error":            "shell quoting broke request; switch to execute_code",
    "transport_error":               "network failure; request never reached the app",
    "tool_internal_error":           "tool wrapper failed; request likely never left the harness",
    "application_4xx":               "server semantic rejection (auth, method, content-type)",
    "application_5xx_fast":          "parse-time crash <50ms; vector NOT proven negative (input never reached the layer)",
    "application_5xx_networked_fast":"parse-time crash 50-200ms (networked); vector NOT proven negative",
    "application_5xx_normal":        "deep crash >=200ms (DB or business-logic error path reached)",
    "success":                       "ok",
}


def is_diagnostic_failure(error_class: Optional[str]) -> bool:
    """True for error classes that indicate the test never reached its
    intended target (and should not count as 'vector tested').

    Used by the uniform-response anomaly detector and by future coverage-map
    logic that needs to distinguish 'real negative result' from 'harness
    glitch'.
    """
    return error_class in (
        "shell_parser_error",
        "transport_error",
        "tool_internal_error",
        "application_5xx_fast",
        "application_5xx_networked_fast",
    )
