"""Regression tests for the ``on_tool_complete`` emission gate in
``orchestrator_helpers.streaming.emit_streaming_events``.

## Background — the bug

Fireteam members running with operator approval enabled ("REQUIRE_TOOL_CONFIRMATION=true")
showed an accumulating pile of UI cards stuck in ``RUNNING`` state on the
same member panel:

    execute_curl  [Running 106s]   <- iter 1, never flipped to error
    execute_curl  [Running 24s]    <- iter 2, never flipped to error
    Wave - 1 tools [Awaiting approval]  <- iter 3, the new ask

Root cause: the ``on_tool_complete`` emission gate at streaming.py:146
(pre-fix) required ``cstep.get("output_analysis")`` to be **truthy**. When
a tool produced empty output (curl status 000 on connection failure, httpx
"No live hosts found", kali_shell silent failure) AND the LLM's analysis
of that empty output was itself short / empty, ``output_analysis`` became
the empty string ``""`` (falsy). The gate failed, ``on_tool_complete`` was
never emitted, and the UI card stayed RUNNING forever.

Compounded by a secondary bug in the deduplication key: the dedup ID was
``tc|<tool_name>|<output_analysis>`` — content-based, so two consecutive
tool calls of the same name with similar (or empty) outputs produced the
SAME dedup ID. Even if the gate later passed for the second one, dedup
would silently drop it.

Why operator-approval mode made this visible: without approval the agent
moves through iterations fast enough that ghost RUNNING cards are
short-lived. With approval the operator pauses to look — every retried
empty-output tool leaves a ghost RUNNING card on the screen.

## The fix (in streaming.py)

1. Drop the ``cstep.get("output_analysis")`` requirement from the gate at
   line 146. ``success is not None`` is sufficient to know the tool has
   a terminal verdict; output_analysis being empty is a legitimate state
   (empty stdout, connection refused, etc.) — the UI must still flip the
   card from RUNNING to a terminal badge.

2. Switch the dedup key from content-based to step_id-based when
   ``cstep["step_id"]`` is available (uuid4 — unique per step). Fall back
   to the old content-based ID when step_id is absent, preserving
   backward compatibility for any legacy state shapes that lack step_id.

## Test taxonomy

* **Bug reproductions (4)** — synthesize the exact ``_completed_step``
  shapes that triggered the production bug, assert ``on_tool_complete``
  IS now emitted. These are the highest-signal tests: they would fail
  against pre-fix streaming.py.
* **Regression tests (5)** — the gate's other conditions
  (``tool_name`` presence, ``"tool_rejection"`` exclusion, ``success``
  set check, dedup of duplicates within a session, ``awaiting_tool_confirmation``
  short-circuit) must still hold.
* **Smoke tests (2)** — end-to-end style: synthesize a multi-iteration
  state-update sequence that mirrors a real fireteam member running
  several failing curls in a row, assert ALL iterations land their
  ``on_tool_complete`` calls and the card-flip event count matches
  the iteration count.

Run (inside agent container):

    docker run --rm \\
        -v "/path/agentic:/app" \\
        -v "/path/graph_db:/app/graph_db:ro" \\
        -w /app redamon-agent python -m unittest \\
        tests.test_tool_complete_emission -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from orchestrator_helpers.streaming import emit_streaming_events  # noqa: E402


# =============================================================================
# Helpers
# =============================================================================

def _make_callback() -> MagicMock:
    """Build a mock callback whose async methods record their calls AND has
    the dedup-set attributes that emit_streaming_events writes to.

    emit_streaming_events deduplicates emissions via sets stored ON the
    callback object (so dedup survives state-dict reconstruction across
    LangGraph checkpoint resumes). A clean callback per test simulates
    a fresh astream session.
    """
    cb = MagicMock()
    # Async methods used by emit_streaming_events.
    for name in (
        "on_phase_update", "on_todo_update", "on_approval_request",
        "on_question_request", "on_tool_complete", "on_execution_step",
        "on_file_ready", "on_thinking", "on_tool_start",
        "on_tool_output_chunk", "on_tool_confirmation_request",
        "on_task_complete",
    ):
        setattr(cb, name, AsyncMock())
    # Dedup state — emit_streaming_events reads/writes these attributes.
    cb._emitted_tool_complete_ids = set()
    cb._emitted_thinking_ids = set()
    cb._emitted_tool_start_ids = set()
    cb._emitted_tool_output_ids = set()
    cb._emitted_approval_key = None
    cb._emitted_question_key = None
    cb._emitted_tool_confirmation_key = None
    return cb


def _completed_step(
    *,
    tool_name: str = "execute_curl",
    success: bool | None = True,
    output_analysis: str = "Probe succeeded with status 200.",
    tool_output: str = "HTTP/1.1 200 OK\n",
    step_id: str | None = None,
    **extra,
) -> dict:
    """Construct a ``_completed_step`` shape matching the real one written
    by fireteam_member_think_node._on_pending_single_output() and the root
    think_node's pending-step finalizer.
    """
    s = {
        "step_id": step_id if step_id is not None else uuid4().hex,
        "iteration": 1,
        "phase": "informational",
        "tool_name": tool_name,
        "tool_args": {"target": "https://example.com"},
        "tool_output": tool_output,
        "success": success,
        "output_analysis": output_analysis,
        "actionable_findings": [],
        "recommended_next_steps": [],
        "duration_ms": 123,
    }
    s.update(extra)
    return s


def _state(*, completed_step: dict | None = None, **extra) -> dict:
    """Minimal state dict accepted by emit_streaming_events. Only the
    completed-step path is exercised here, so other fields stay empty.
    """
    s: dict = {
        "current_phase": "informational",
        "current_iteration": 1,
    }
    if completed_step is not None:
        s["_completed_step"] = completed_step
    s.update(extra)
    return s


# =============================================================================
# 1. BUG REPRODUCTIONS — would FAIL against pre-fix streaming.py
# =============================================================================

class EmptyOutputAnalysisStillEmits(unittest.IsolatedAsyncioTestCase):
    """REGRESSION: empty ``output_analysis`` must NOT block on_tool_complete.

    Pre-fix gate required ``cstep.get("output_analysis")`` truthy. Empty
    string ``""`` is falsy, so the emission was silently dropped. This
    accumulated ghost RUNNING cards in the fireteam UI under operator
    approval mode.
    """

    async def test_empty_string_output_analysis_emits_complete(self):
        cb = _make_callback()
        step = _completed_step(
            success=False,
            output_analysis="",                # <- empty (the bug trigger)
            tool_output="",                    # tool produced no stdout
        )
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(
            cb.on_tool_complete.await_count, 1,
            "on_tool_complete MUST fire when success is set, even if "
            "output_analysis is the empty string — the card must flip "
            "from RUNNING to error/success regardless of content length.",
        )
        args, kwargs = cb.on_tool_complete.await_args
        self.assertEqual(args[0], "execute_curl")
        self.assertEqual(args[1], False)
        self.assertEqual(args[2], "")          # empty string surfaces verbatim

    async def test_none_output_analysis_emits_complete(self):
        """``output_analysis`` literally missing (None) must also emit.
        Some early code paths in the root think_node leave the field
        unset entirely rather than empty-string."""
        cb = _make_callback()
        step = _completed_step(success=True, output_analysis=None)
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(
            cb.on_tool_complete.await_count, 1,
            "Missing output_analysis must not block emission.",
        )

    async def test_curl_status_000_empty_output_emits_complete(self):
        """The exact production scenario the user reported: curl times
        out / can't connect → status 000 → empty body → LLM analyzed
        with empty interpretation. Pre-fix this left a ghost RUNNING
        card per failed curl attempt."""
        cb = _make_callback()
        step = _completed_step(
            tool_name="execute_curl",
            success=False,
            output_analysis="",
            tool_output="",
            error_message="curl: (28) Operation timed out",
        )
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 1)
        # Caller still gets the success/duration metadata, just with
        # empty body — that's the truth of what happened.
        self.assertEqual(cb.on_tool_complete.await_args.args[1], False)
        self.assertEqual(
            cb.on_tool_complete.await_args.kwargs.get("duration_ms"), 123,
        )

    async def test_two_consecutive_empty_failures_both_emit(self):
        """Pre-fix the dedup ID was ``tc|<tool>|<output_analysis>`` —
        purely content-based. Two consecutive curl failures with the
        same empty output collided on the same dedup ID; even if the
        first had passed the gate, the second would have been silently
        deduped. Post-fix the dedup is step_id-based (uuid per step),
        so both emit correctly."""
        cb = _make_callback()
        step1 = _completed_step(
            tool_name="execute_curl", success=False, output_analysis="",
            tool_output="", step_id="step-alpha",
        )
        step2 = _completed_step(
            tool_name="execute_curl", success=False, output_analysis="",
            tool_output="", step_id="step-beta",
        )
        await emit_streaming_events(_state(completed_step=step1), cb)
        await emit_streaming_events(_state(completed_step=step2), cb)
        self.assertEqual(
            cb.on_tool_complete.await_count, 2,
            "Two distinct step_ids must yield two emissions — pre-fix "
            "the content-based dedup ID `tc|execute_curl|` collided "
            "between them and only the first survived.",
        )


# =============================================================================
# 2. UNIT TESTS — the gate's individual condition predicates
# =============================================================================

class ToolCompleteGateConditions(unittest.IsolatedAsyncioTestCase):
    """Each gate predicate validated in isolation."""

    async def test_no_completed_step_emits_nothing(self):
        cb = _make_callback()
        await emit_streaming_events(_state(), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 0)

    async def test_explicit_none_completed_step_emits_nothing(self):
        """``_completed_step is None`` is the steady state between
        iterations and must short-circuit even when the key exists."""
        cb = _make_callback()
        await emit_streaming_events({"_completed_step": None}, cb)
        self.assertEqual(cb.on_tool_complete.await_count, 0)

    async def test_missing_tool_name_does_not_emit(self):
        cb = _make_callback()
        step = _completed_step()
        step["tool_name"] = None
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 0)

    async def test_tool_rejection_is_excluded(self):
        """The special pseudo-tool ``tool_rejection`` is used when an
        operator denies a confirmation — it must not surface as a real
        completed tool card."""
        cb = _make_callback()
        step = _completed_step(tool_name="tool_rejection")
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 0)

    async def test_success_none_blocks_emission(self):
        """``success is None`` means the step hasn't been verdicted yet
        (transient state between tool_start and tool_finish). Must not
        emit a premature completion."""
        cb = _make_callback()
        step = _completed_step(success=None)
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 0)


# =============================================================================
# 3. REGRESSION — dedup, ordering, and other invariants
# =============================================================================

class DedupAndOrderingRegression(unittest.IsolatedAsyncioTestCase):

    async def test_same_step_id_emitted_only_once(self):
        """Idempotency within a single astream session: re-yielding the
        same _completed_step (e.g., the state passes through several
        downstream nodes that don't modify it) must not duplicate the
        completion event."""
        cb = _make_callback()
        step = _completed_step(step_id="stable-step-id-001")
        await emit_streaming_events(_state(completed_step=step), cb)
        await emit_streaming_events(_state(completed_step=step), cb)
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(
            cb.on_tool_complete.await_count, 1,
            "Same step_id seen 3 times must emit exactly once",
        )

    async def test_legacy_state_without_step_id_uses_content_fallback(self):
        """For state shapes that don't carry step_id (older callers,
        custom integrations, tests) the dedup falls back to the
        content-based ID so backward compatibility holds."""
        cb = _make_callback()
        step = _completed_step()
        step.pop("step_id")     # legacy: no step_id at all
        await emit_streaming_events(_state(completed_step=step), cb)
        # Same dict, second pass — must dedup via content key.
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 1)

    async def test_emission_includes_findings_and_duration(self):
        """The contract on the callback payload must not regress: the
        actionable_findings, recommended_next_steps, and duration_ms
        fields are read by the WebSocket layer + persistence."""
        cb = _make_callback()
        step = _completed_step(
            actionable_findings=["host alive", "redirects to /en/portfolio"],
            recommended_next_steps=["fingerprint nextjs version"],
            duration_ms=4521,
        )
        await emit_streaming_events(_state(completed_step=step), cb)
        kwargs = cb.on_tool_complete.await_args.kwargs
        self.assertEqual(kwargs["actionable_findings"],
                         ["host alive", "redirects to /en/portfolio"])
        self.assertEqual(kwargs["recommended_next_steps"],
                         ["fingerprint nextjs version"])
        self.assertEqual(kwargs["duration_ms"], 4521)

    async def test_execution_step_summary_also_emitted(self):
        """Per the production code, emit_streaming_events ALSO emits
        on_execution_step right after a successful on_tool_complete.
        This regression locks that pairing so a future refactor can't
        split them silently."""
        cb = _make_callback()
        step = _completed_step()
        await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 1)
        self.assertEqual(cb.on_execution_step.await_count, 1)

    async def test_step_id_based_dedup_does_not_collide_across_tools(self):
        """A failure mode of the OLD content-based dedup: two unrelated
        tools that happen to produce the same analysis text shared a
        dedup slot. Lock that this no longer happens — two distinct
        step_ids always emit, even with identical analysis content."""
        cb = _make_callback()
        a = _completed_step(tool_name="execute_curl",
                            output_analysis="Same body",
                            step_id="A")
        b = _completed_step(tool_name="execute_httpx",
                            output_analysis="Same body",
                            step_id="B")
        await emit_streaming_events(_state(completed_step=a), cb)
        await emit_streaming_events(_state(completed_step=b), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 2)


# =============================================================================
# 4. SMOKE TESTS — multi-iteration sequences resembling production
# =============================================================================

class FireteamMemberSmokeFlows(unittest.IsolatedAsyncioTestCase):
    """End-to-end sequences mirroring a fireteam member's lifecycle. These
    don't run a real LangGraph — they replay the state-update stream that
    LangGraph would yield, in order, and assert the cumulative emit shape.
    """

    async def test_four_failing_curls_in_a_row_all_complete(self):
        """Replays the production scenario the user reported: a fireteam
        member retries ``execute_curl`` 4 times against an unreachable
        host. Each attempt yields:
          - step.tool_output = ""        (curl status 000)
          - step.success = False
          - step.output_analysis = ""    (LLM analysis was empty too)

        Pre-fix: 0 on_tool_complete emissions, 4 ghost RUNNING cards
        accumulating. Post-fix: 4 on_tool_complete emissions, each card
        flips correctly.
        """
        cb = _make_callback()
        for i in range(4):
            step = _completed_step(
                tool_name="execute_curl",
                success=False,
                output_analysis="",
                tool_output="",
                error_message="curl: (28) Operation timed out",
                step_id=f"iter-{i}-step",
                iteration=i + 1,
            )
            await emit_streaming_events(
                _state(completed_step=step, current_iteration=i + 1), cb,
            )
        self.assertEqual(
            cb.on_tool_complete.await_count, 4,
            "Each retry's completion must flip its own UI card. Pre-fix "
            "this was 0 — that's the visible 'stuck at running' bug.",
        )
        # Each emission carries the right tool_name + verdict.
        for call in cb.on_tool_complete.await_args_list:
            self.assertEqual(call.args[0], "execute_curl")
            self.assertEqual(call.args[1], False)

    async def test_mixed_success_failure_sequence(self):
        """Mixed-outcome sequence: 1st curl fails empty → 2nd curl
        succeeds with body → 3rd curl times out empty again. All three
        must flip their cards independently (no cross-iteration dedup
        collision)."""
        cb = _make_callback()
        seq = [
            _completed_step(tool_name="execute_curl", success=False,
                            output_analysis="", tool_output="",
                            step_id="s1"),
            _completed_step(tool_name="execute_curl", success=True,
                            output_analysis="200 OK, body of 12 KB",
                            tool_output="<html>...</html>",
                            step_id="s2"),
            _completed_step(tool_name="execute_curl", success=False,
                            output_analysis="", tool_output="",
                            step_id="s3"),
        ]
        for step in seq:
            await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 3)
        verdicts = [c.args[1] for c in cb.on_tool_complete.await_args_list]
        self.assertEqual(verdicts, [False, True, False])

    async def test_idempotent_replay_of_same_iteration(self):
        """LangGraph can re-yield the same state across nodes within
        one iteration. The dedup must collapse those redundant emits
        to exactly one. This is essential to keep the WebSocket layer
        from spamming the frontend with duplicate completion events."""
        cb = _make_callback()
        step = _completed_step(step_id="single-iter-step")
        # Same state yielded 5 times (simulating multiple node yields
        # all forwarding the same state shape).
        for _ in range(5):
            await emit_streaming_events(_state(completed_step=step), cb)
        self.assertEqual(cb.on_tool_complete.await_count, 1)


# =============================================================================
# 5. PENDING-CONFIRMATION GUARD — on_tool_start must NOT fire while a
#    fireteam member is escalating a dangerous tool to the operator
# =============================================================================
#
# Background — the second bug
# ---------------------------
# A fireteam member that decides to use a dangerous tool sets BOTH
# ``_current_step`` (with a fresh uuid step_id) and ``_pending_confirmation``
# in the same think_node update. emit_streaming_events then runs against
# that update.
#
# Pre-fix the on_tool_start gate at streaming.py:206 only checked
# ``not state.get("awaiting_tool_confirmation")``. That flag is the
# ROOT-AGENT flag, not the fireteam-MEMBER flag — members signal pending
# confirmation via ``_pending_confirmation``. So the guard didn't fire and
# on_tool_start was emitted, adding a RUNNING tool card to the UI BEFORE
# the operator had any chance to approve.
#
# Then on operator approval, process_fireteam_confirmation_node redeploys
# the tool inside a NEW single-member fireteam whose events carry a
# different member_id. The original member's RUNNING card is therefore
# never matched by the new fireteam's TOOL_COMPLETE → stuck forever.
#
# The fix adds ``and not state.get("_pending_confirmation")`` to the
# tool_start gate. These tests pin that behaviour.

class PendingConfirmationBlocksToolStart(unittest.IsolatedAsyncioTestCase):

    async def test_pending_confirmation_set_blocks_tool_start(self):
        """REGRESSION: with `_pending_confirmation` set, on_tool_start
        must NOT fire even though `_current_step` is fully populated.

        Pre-fix this was the source of the ghost-RUNNING card on the
        original member panel after a dangerous-tool escalation."""
        cb = _make_callback()
        step = {
            "step_id": "step-pending-1",
            "tool_name": "kali_shell",
            "tool_args": {"command": "printf '/admin\\n' > /tmp/paths.txt"},
            "iteration": 1,
            "phase": "exploitation",
        }
        await emit_streaming_events(
            {
                "_current_step": step,
                "_pending_confirmation": {
                    "tools": [{"tool_name": "kali_shell"}],
                    "reasoning": "create wordlist",
                },
            },
            cb,
        )
        self.assertEqual(
            cb.on_tool_start.await_count, 0,
            "tool_start emitted while pending_confirmation set — pre-fix "
            "bug. Renders an UNAPPROVED tool as RUNNING in the UI.",
        )

    async def test_pending_confirmation_cleared_unblocks_tool_start(self):
        """After the operator decides (approve/reject) and
        `_pending_confirmation` is cleared, a subsequent emit cycle
        with the SAME `_current_step` must now fire on_tool_start."""
        cb = _make_callback()
        step = {
            "step_id": "step-now-running",
            "tool_name": "kali_shell",
            "tool_args": {"command": "printf 'x' > /tmp/y"},
            "iteration": 2,
            "phase": "exploitation",
        }
        # First pass — pending: blocked
        await emit_streaming_events(
            {"_current_step": step, "_pending_confirmation": {"tools": []}},
            cb,
        )
        self.assertEqual(cb.on_tool_start.await_count, 0)
        # Second pass — pending cleared (None) AND awaiting_tool_confirmation
        # also unset: emit_streaming_events should now fire tool_start.
        await emit_streaming_events(
            {"_current_step": step, "_pending_confirmation": None},
            cb,
        )
        self.assertEqual(
            cb.on_tool_start.await_count, 1,
            "Once pending is cleared, tool_start must finally fire.",
        )

    async def test_awaiting_tool_confirmation_still_blocks(self):
        """Regression — the original guard (`awaiting_tool_confirmation`)
        must still work. This is the ROOT-AGENT case."""
        cb = _make_callback()
        step = {
            "step_id": "s",
            "tool_name": "execute_nmap",
            "tool_args": {"target": "x"},
        }
        await emit_streaming_events(
            {"_current_step": step, "awaiting_tool_confirmation": True},
            cb,
        )
        self.assertEqual(cb.on_tool_start.await_count, 0)

    async def test_both_flags_set_blocks(self):
        """Belt-and-suspenders: if both flags are accidentally set (would
        be a state corruption scenario), still block."""
        cb = _make_callback()
        step = {
            "step_id": "s",
            "tool_name": "execute_curl",
            "tool_args": {"url": "x"},
        }
        await emit_streaming_events(
            {
                "_current_step": step,
                "awaiting_tool_confirmation": True,
                "_pending_confirmation": {"tools": []},
            },
            cb,
        )
        self.assertEqual(cb.on_tool_start.await_count, 0)

    async def test_neither_flag_set_emits_normally(self):
        """Sanity: with neither flag set (normal execution path), the
        tool_start emit fires once and the dedup id is recorded."""
        cb = _make_callback()
        step = {
            "step_id": "s-go",
            "tool_name": "execute_curl",
            "tool_args": {"url": "https://x"},
        }
        await emit_streaming_events({"_current_step": step}, cb)
        self.assertEqual(cb.on_tool_start.await_count, 1)
        # Idempotent on replay.
        await emit_streaming_events({"_current_step": step}, cb)
        self.assertEqual(cb.on_tool_start.await_count, 1)


if __name__ == "__main__":
    unittest.main()
