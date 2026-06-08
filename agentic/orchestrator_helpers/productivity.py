"""
Productivity-based loop detection helpers.

Replaces the keyword-based `is_failure` check (which only caught steps whose
output contained "failed" / "error") with an LLM-emitted verdict that classifies
every tool call into one of five productivity buckets:

    new_info      — the call revealed something we did not already know
    confirmation  — already suspected, this call only confirms
    no_progress   — call succeeded but yielded no usable information
    blocked       — WAF, 403, captcha, rate limit, auth wall
    duplicate     — output essentially identical to a recent call

The verdict lives on `OutputAnalysisInline.productivity` (see state.py). This
module exposes:

    is_unproductive(step)               read the verdict; returns bool
    audit_productivity_claim(step,      cross-check the LLM's claim against
                             before,    actual state growth; returns a
                             after)     discrepancy string or None
    build_productivity_audit_section(   compute the per-iteration prompt
        execution_trace, window)        block that shows the model its own
                                        recent fingerprints, so claiming
                                        "confirmation" 10 times in a row
                                        becomes visibly dishonest

The orchestrator owns three small responsibilities: show history in the
prompt, audit the claim against state delta, count unproductive steps. The
model owns the per-step judgment.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Optional, Tuple, List


def _normalize_args_pattern(tool_name: str, tool_args: dict) -> str:
    """Generalize tool args to a 'shape' so /order/300500 and /order/300600
    collapse into the same pattern. Integers become <int>, hex tokens become
    <hex>, query-string values become <val>, IPs become <ip>.
    """
    try:
        raw = json.dumps(tool_args or {}, sort_keys=True, ensure_ascii=False)
    except Exception:
        raw = str(tool_args or {})
    # Strip every long alphanumeric token; the URL path shape is what matters.
    normalized = re.sub(r"\b\d+\b", "<int>", raw)
    normalized = re.sub(r"\b[a-f0-9]{8,}\b", "<hex>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<ip>", normalized)
    normalized = re.sub(r"=[^&\"'\s]+", "=<val>", normalized)
    return f"{tool_name or '?'}::{normalized[:160]}"


def _output_fingerprint(step: dict) -> str:
    """Stable 8-hex fingerprint of the response body, normalized for trivial
    diffs (whitespace, timestamps, common varying tokens). Two responses with
    the same fingerprint are functionally identical."""
    raw = (step.get("tool_output") or "")[:8000]
    # Normalize whitespace
    normalized = re.sub(r"\s+", " ", raw).strip()
    # Strip ISO timestamps, UUIDs, RFC3339, request IDs
    normalized = re.sub(r"\d{4}-\d{2}-\d{2}T[\d:.\-+Z]+", "<ts>", normalized)
    normalized = re.sub(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "<uuid>", normalized)
    normalized = re.sub(r"\b\d{10,}\b", "<num>", normalized)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:8]


def _output_size(step: dict) -> int:
    return len((step.get("tool_output") or ""))


def _read_productivity(step: dict) -> dict:
    """Read the productivity verdict from a step, tolerating both the
    top-level shape (step["productivity"]) and the nested shape
    (step["output_analysis"]["productivity"]). The think_node stores it at
    the top level; this dual-path lookup keeps the helper robust against
    future schema drift."""
    if not step:
        return {}
    top = step.get("productivity")
    if isinstance(top, dict) and top:
        return top
    nested = step.get("output_analysis")
    if isinstance(nested, dict):
        p = nested.get("productivity") or {}
        if isinstance(p, dict):
            return p
    return {}


def is_unproductive(step: dict) -> bool:
    """Read the LLM's productivity verdict for this step. The orchestrator's
    loop counter ORs this with the legacy keyword check, so a missing field
    just falls back to keyword behavior (productive-by-default)."""
    p = _read_productivity(step)
    if not p:
        return False
    if p.get("verdict") == "diagnostic_progress":
        # Fix 1: debugging a correct-but-failing approach. Learning a sub-cause
        # (a changed failure mode, a ruled-out hypothesis) is genuine progress,
        # so it is NEVER unproductive — even though no new *target* fact was
        # added and new_information_gained may be False. Return early so the
        # new_information_gained guard below does not re-flag it.
        return False
    if p.get("verdict") in ("no_progress", "duplicate", "blocked"):
        return True
    if p.get("new_information_gained") is False:
        return True
    return False


def _target_info_grew(before: dict, after: dict) -> bool:
    """True if any list-typed field in target_info grew between iterations."""
    b = (before or {}).get("target_info") or {}
    a = (after or {}).get("target_info") or {}
    for key in ("ports", "services", "technologies", "vulnerabilities",
                "credentials", "sessions", "subdomains", "endpoints"):
        if len(a.get(key, []) or []) > len(b.get(key, []) or []):
            return True
    return False


def audit_productivity_claim(
    productivity: dict,
    extracted_info: dict,
    actionable_findings: list,
    findings_grew: bool,
) -> Optional[str]:
    """Cross-check the LLM's productivity claim against actual state delta.

    Returns a one-line discrepancy string if the claim is inconsistent, else
    None. Callers typically downgrade the verdict to 'no_progress' in place
    and surface the reason in the next prompt.

    Inputs are plain dicts (no Pydantic dependency) so this helper is reusable
    from both root and fireteam paths and from tests.
    """
    if not productivity:
        return None

    verdict = productivity.get("verdict")
    claims_new = productivity.get("new_information_gained", False)

    extracted_any = any(
        (extracted_info or {}).get(k)
        for k in ("ports", "services", "technologies",
                  "vulnerabilities", "credentials", "sessions")
    )
    state_grew = bool(findings_grew or extracted_any or actionable_findings)

    if claims_new and not state_grew:
        return ("Claimed new_information_gained=true but no chain finding was "
                "appended, no extracted_info was populated, and no actionable "
                "finding was produced.")
    if verdict == "new_info" and not state_grew:
        return ("Verdict='new_info' but the engagement state did not grow this "
                "iteration.")
    if verdict == "diagnostic_progress" and not (productivity.get("what_was_new") or "").strip():
        return ("Verdict='diagnostic_progress' but what_was_new is empty — cite "
                "the ruled-out cause or the changed result, otherwise this is "
                "no_progress.")
    return None


def downgrade_verdict_to_no_progress(productivity: dict, reason: str) -> dict:
    """Return a copy of the productivity dict with the verdict downgraded to
    'no_progress' and the reason recorded. Caller is responsible for writing
    the returned dict back onto whatever shape the step expects."""
    if not productivity:
        return {
            "verdict": "no_progress",
            "new_information_gained": False,
            "what_was_new": "",
            "should_repeat_similar_call": False,
            "rationale": "",
            "_original_verdict": None,
            "_downgrade_reason": reason,
        }
    out = dict(productivity)
    out["_original_verdict"] = out.get("verdict")
    out["verdict"] = "no_progress"
    out["new_information_gained"] = False
    out["_downgrade_reason"] = reason
    return out


def detect_uniform_response_anomaly(
    execution_trace: list,
    *,
    window: int = 8,
    min_count: int = 5,
    size_tolerance: int = 32,
    duration_threshold_ms: int = 50,
) -> Optional[str]:
    """Detect a 'uniform response cliff' — a streak of recent tool calls whose
    outputs share the same error_class, a near-identical body size, AND all
    completed in under `duration_threshold_ms`.

    This is the diagnostic signature of input being rejected at parse time or
    by an early guard clause, rather than being processed by the layer the
    agent thinks it is testing. Twelve "500 Internal Server Error" responses
    in 3ms each are NOT twelve failed SQLi tests — they are twelve probes
    that never reached the SQL layer at all.

    Returns a multi-paragraph warning string when the pattern is detected,
    else None. The orchestrator injects the warning into the next prompt so
    the LLM re-examines whether its probes ever reached the target component
    instead of marking the vector class 'tested' on the basis of uniform
    front-door rejections.

    Args:
        execution_trace:        full execution_trace list from state
        window:                 how many recent steps to consider
        min_count:              minimum repeats of the same signature to fire
        size_tolerance:         bucket size (bytes) for grouping near-equal sizes
        duration_threshold_ms:  steps slower than this are NOT uniform-fast
    """
    if not execution_trace or len(execution_trace) < min_count:
        return None

    recent = execution_trace[-window:]
    if len(recent) < min_count:
        return None

    # Signature = (error_class, size_bucket). Steps missing error_class
    # contribute a "_legacy" bucket that will never reach min_count on its
    # own — backward compatible with traces from before this feature shipped.
    from collections import Counter

    signatures: list[tuple] = []
    durations: list[int] = []
    for step in recent:
        ec = step.get("error_class")
        if not ec:
            ec = "success" if step.get("success", True) else "_legacy"
        size = len(step.get("tool_output") or "")
        size_bucket = size // max(size_tolerance, 1)
        signatures.append((ec, size_bucket))
        durations.append(int(step.get("duration_ms") or 0))

    # Diagnostic-failure classes (mirror of error_class.is_diagnostic_failure).
    # Inlined to keep productivity.py standalone-loadable by tests that use
    # importlib.spec_from_file_location to dodge the orchestrator_helpers
    # __init__.py (which pulls in pydantic via state.py). The canonical
    # source of truth is `error_class.is_diagnostic_failure` — when adding
    # a new failure class, update BOTH.
    _DIAGNOSTIC_FAILURE_CLASSES = frozenset({
        "shell_parser_error",
        "transport_error",
        "tool_internal_error",
        "application_5xx_fast",
        "application_5xx_networked_fast",
    })

    sig_counts = Counter(signatures)

    # Find the most-common signature that represents a *failure mode the LLM
    # might mis-classify as 'vector tested'*. The previous implementation
    # only checked the single most-common signature; in sessions where the
    # agent does a lot of successful baseline probing (common in early
    # turns), the success bucket dominates and the detector returned None
    # WITHOUT examining the smaller failure clusters at all. Iterate through
    # the ranked signatures in descending order and pick the first one that
    # (a) belongs to a diagnostic-failure class AND (b) meets the min_count
    # threshold.
    #
    # The diagnostic-failure filter is critical for signal quality: a
    # uniform `application_4xx` pattern (3 recon GETs all returning 404)
    # is NOT a "your input didn't reach the layer" signal — it's a
    # legitimate negative result (the paths don't exist). Firing on those
    # would be false-positive noise that trains the agent to ignore the
    # warning, blunting it for the cases where the warning is actually true
    # (uniform fast-5xx, shell-quoting failures, network errors).
    top_sig = None
    top_count = 0
    for sig, count in sig_counts.most_common():
        if count < min_count:
            break  # subsequent entries are smaller — stop scanning
        ec_candidate, _ = sig
        if ec_candidate not in _DIAGNOSTIC_FAILURE_CLASSES:
            continue  # success / 4xx / normal-latency 5xx are not anomalies; try next
        top_sig = sig
        top_count = count
        break

    if top_sig is None:
        return None

    top_ec, top_size_bucket = top_sig

    matching_indices = [i for i, s in enumerate(signatures) if s == top_sig]
    matching_durations = [durations[i] for i in matching_indices]
    # All matching durations must be fast. A single >threshold call breaks
    # the "rejected at the door" signal — the request reached SOMETHING.
    fast_mask = [d > 0 and d < duration_threshold_ms for d in matching_durations]
    if not all(fast_mask):
        return None

    approx_size = top_size_bucket * size_tolerance
    avg_dur = sum(matching_durations) / max(len(matching_durations), 1)

    # Per-class remediation hints. The error_class already tells the LLM
    # what kind of failure it is; this section translates that into action.
    remediation_hint = {
        "shell_parser_error":
            "Switch tool: prefer `execute_code` with Python `requests` (no shell escaping) "
            "over `execute_curl` with bash-escaped JSON. Your payloads are dying in bash, "
            "not on the wire.",
        "transport_error":
            "Re-verify reachability: the target hostname/IP may have rotated, the network "
            "alias may have been disconnected, or a previous tool tore down the route. "
            "Run a single baseline GET / before resuming probes.",
        "tool_internal_error":
            "The tool wrapper itself is failing — check the tool args shape and any "
            "file-path / @file references. The request likely never left the harness.",
        "application_5xx_fast":
            "All probes are 5xx in <50ms — the application is crashing at parse time or "
            "in an early guard clause, BEFORE the layer you intend to test (e.g. SQL, "
            "templating, auth). Your input is not being exercised the way you think. "
            "Re-examine: (a) Is the JSON shape valid for the framework? (b) Is the "
            "Content-Type correct? (c) Try a deliberately VALID body once to see what "
            "a 'normal' processed response looks like, then compare. (d) Consider that "
            "the vector class you're testing may not even be reachable with your current "
            "payload structure.",
        "application_5xx_networked_fast":
            "All probes are 5xx in 50-200ms — the application is crashing at parse time "
            "or in an early guard clause, BEFORE the layer you intend to test, on a "
            "networked target (latency includes the docker-network round-trip). Same "
            "interpretation as `application_5xx_fast`: your input is not being exercised "
            "the way you think. Re-examine: (a) Is the JSON/body shape valid for the "
            "framework? (b) Is the Content-Type correct? (c) Try a deliberately VALID "
            "body once to see what a 'normal' processed response looks like, then "
            "compare. (d) If you've been testing a vector class (SQLi, NoSQL, SSTI, "
            "etc.) with manual payloads via execute_curl / execute_code and all of them "
            "returned this signature, the class is NOT proven negative — escalate to a "
            "specialized tool for the class (sqlmap with --ignore-code=500 for SQLi, "
            "dalfox for XSS, etc.) before pivoting to a different vulnerability class.",
        "application_4xx":
            "Uniform 4xx — the server is rejecting these requests semantically. The "
            "endpoint may not accept this method, content-type, or auth shape. This is "
            "a legitimate signal — the layer is reachable, it just disagrees with the "
            "request envelope, not the payload content.",
        "application_5xx_normal":
            "Uniform 5xx with normal latency — the application is reaching a consistent "
            "crash point. This may be a real exploitable signal (e.g. type confusion, "
            "panic on malformed input) — capture the exact crash signature and pivot to "
            "extracting information from the error.",
    }.get(top_ec, "Re-examine whether the probe actually exercises the layer under test.")

    return (
        f"## RESPONSE-UNIFORMITY ANOMALY\n\n"
        f"Of your last {len(recent)} tool calls, {top_count} share an identical response shape:\n"
        f"  - classification: `{top_ec}`\n"
        f"  - response size:  ~{approx_size} bytes (bucket {top_size_bucket}, ±{size_tolerance}B)\n"
        f"  - duration:       all <{duration_threshold_ms}ms (avg {avg_dur:.0f}ms)\n\n"
        f"Same status + same size + sub-{duration_threshold_ms}ms latency across {top_count} probes is NOT "
        f"a 'this vector is blocked' signal. It means every probe is being short-circuited "
        f"uniformly — your input is not being processed by the layer you think you're testing.\n\n"
        f"**What to do:** {remediation_hint}\n\n"
        f"**Do NOT mark the current vector class 'tested' on the basis of these responses.** "
        f"The test result is INCONCLUSIVE, not NEGATIVE.\n"
    )


# =============================================================================
# Axis extraction & session-long lock-in detection
# =============================================================================
#
# Each expensive tool call has a "semantic axis" — the dials the agent is
# *holding constant* across attempts. A bigger wordlist against the same
# username with the same target is the SAME axis, even though the args differ
# textually. The axis ledger lets us detect this case session-wide, outside
# the 6-step rolling window the verdict counter is bound to.

# Heuristic regex matchers for inferring brute-force-shaped activity inside
# `execute_code` / `kali_shell` scripts. We don't try to be smart — we just
# look for the textual fingerprints of credential-guessing loops. False
# negatives are fine (axis check silently skipped); false positives are also
# fine (axis just won't repeat-match anything).
_RX_BRUTE_USERNAME = re.compile(
    r"['\"]username['\"]\s*:\s*['\"]([^'\"]{1,64})['\"]",
)
_RX_BRUTE_TARGET = re.compile(
    r"https?://([a-zA-Z0-9_.\-:]+(?:/[^\s'\"]*)?)",
)
_RX_BRUTE_LOOP_HINTS = (
    "for pw in",
    "for password in",
    "rockyou",
    "wordlist",
    "10k-most-common",
    "passwords.txt",
    "common-credentials",
    "for line in f:",
)
_RX_HYDRA_USER = re.compile(r"-l\s+([^\s]+)")
_RX_HYDRA_PASS = re.compile(r"-(?:p|P)\s+([^\s]+)")


def _looks_like_brute_force_script(code: str) -> bool:
    """True if a script body has the textual hallmarks of credential brute force."""
    if not code:
        return False
    low = code.lower()
    return any(hint in low for hint in _RX_BRUTE_LOOP_HINTS)


def extract_axis(tool_name: Optional[str], tool_args: Optional[dict]) -> Optional[dict]:
    """Return a semantic axis dict for the given tool call, or None if the
    tool is too cheap / one-shot to track.

    An axis is a small dict whose stringified form is the dedup key. Each
    tool family has its own definition of "the dials that stay fixed". For
    families not listed here, the function returns None and the caller skips
    the axis check entirely.

    The intent is conservative: only track tool calls where repeated attempts
    on the same axis are usually wasteful (brute force, large fuzzers,
    automated injection tooling). Recon probes are explicitly NOT tracked —
    repeating a curl against a different path is normal exploration.
    """
    if not tool_name:
        return None

    args = tool_args or {}

    # job_spawn wraps another tool — unwrap before classifying
    inner_tool = tool_name
    inner_args = args
    if tool_name == "job_spawn":
        inner_tool = (args.get("tool_name") or "").strip()
        inner_args = args.get("args") or {}
        if not inner_tool:
            return None

    # ── Family: credential brute force (inline Python) ──────────────────
    if inner_tool == "execute_code":
        code = (inner_args.get("code") or "") if isinstance(inner_args, dict) else ""
        if not _looks_like_brute_force_script(code):
            return None
        username_match = _RX_BRUTE_USERNAME.search(code)
        target_match = _RX_BRUTE_TARGET.search(code)
        if not username_match:
            return None
        username = username_match.group(1)
        target = target_match.group(1) if target_match else "<unknown>"
        return {
            "family": "credential_brute_force",
            "target": target.split("?")[0][:120],
            "fixed_user": username[:64],
            "varied": "password",
        }

    # ── Family: hydra ────────────────────────────────────────────────────
    if inner_tool == "execute_hydra":
        hydra_args = inner_args.get("args") if isinstance(inner_args, dict) else None
        argstr = hydra_args if isinstance(hydra_args, str) else json.dumps(inner_args)
        u_match = _RX_HYDRA_USER.search(argstr or "")
        if not u_match:
            return None
        return {
            "family": "credential_brute_force",
            "target": "<hydra>",
            "fixed_user": u_match.group(1)[:64],
            "varied": "password",
        }

    # ── Family: directory brute force (ffuf) ─────────────────────────────
    if inner_tool in ("execute_ffuf",):
        ffuf_args = inner_args.get("args") if isinstance(inner_args, dict) else ""
        argstr = ffuf_args if isinstance(ffuf_args, str) else json.dumps(inner_args)
        url_match = re.search(r"-u\s+(\S+)", argstr or "")
        if not url_match:
            return None
        # Strip FUZZ marker variations to canonicalize the target
        url = url_match.group(1)
        url_canonical = re.sub(r"FUZZ\d*", "FUZZ", url).split("?")[0][:140]
        mc_match = re.search(r"-mc\s+([\d,]+)", argstr or "")
        return {
            "family": "directory_brute_force",
            "target": url_canonical,
            "fixed_filter": mc_match.group(1) if mc_match else "<default>",
            "varied": "wordlist",
        }

    # ── Family: automated SQLi tooling ──────────────────────────────────
    if inner_tool == "execute_sqlmap" or (
        inner_tool == "kali_shell"
        and isinstance(inner_args, dict)
        and "sqlmap" in str(inner_args.get("command") or "")
    ):
        cmd_or_args = inner_args.get("command") or inner_args.get("args") or ""
        argstr = cmd_or_args if isinstance(cmd_or_args, str) else json.dumps(cmd_or_args)
        url_match = re.search(r"-u\s+['\"]?(https?://[^\s'\"]+)", argstr)
        if not url_match:
            return None
        return {
            "family": "automated_sqli",
            "target": url_match.group(1).split("?")[0][:140],
            "varied": "tamper_or_technique",
        }

    return None


def axis_key(axis: dict) -> str:
    """Stable string key for an axis dict, suitable for use as a ledger map key."""
    if not axis:
        return ""
    return "::".join(
        f"{k}={axis.get(k, '')}" for k in sorted(axis.keys())
    )


def axis_unproductive_count(tested_axes: dict, key: str) -> int:
    """Count of prior entries on this axis whose verdict was unproductive
    (no_progress, duplicate, blocked, or hard failure)."""
    entries = (tested_axes or {}).get(key, [])
    unproductive = {"no_progress", "duplicate", "blocked", "hard_failure"}
    return sum(1 for e in entries if (e.get("verdict") or "") in unproductive)


def record_axis_attempt(
    tested_axes: dict,
    key: str,
    iteration: int,
    verdict: str,
    tool: str,
) -> dict:
    """Return a new tested_axes dict with the attempt appended (immutable
    update — does not mutate the input). Verdict should be one of the five
    productivity values, or 'hard_failure' for steps where success=False."""
    if not key:
        return tested_axes or {}
    out = dict(tested_axes or {})
    history = list(out.get(key, []))
    history.append({
        "iteration": int(iteration),
        "verdict": verdict or "",
        "tool": tool or "",
    })
    out[key] = history
    return out


# =============================================================================
# Deep Think novelty (Jaccard similarity on priority_order)
# =============================================================================

def _tokenize_priority(items: List[str]) -> set:
    """Tokenize a priority_order list into a set of normalized lowercase words
    after stripping common boilerplate (numbering, punctuation, stopwords)."""
    if not items:
        return set()
    stop = {"a", "an", "the", "and", "or", "to", "of", "for", "with",
            "then", "via", "by", "in", "on", "from", "if", "is", "are",
            "be", "do", "this", "that", "step", "try", "use", "run",
            "check", "test", "next", "first", "second", "third"}
    tokens: set = set()
    for it in items:
        if not it:
            continue
        # Lowercase, strip punctuation, split, drop stopwords and short tokens
        words = re.findall(r"[a-zA-Z][a-zA-Z_\-]{2,}", it.lower())
        for w in words:
            if w not in stop:
                tokens.add(w)
    return tokens


def priority_order_jaccard(
    new_priority: List[str],
    old_priority: Optional[List[str]],
) -> float:
    """Token-level Jaccard similarity between two priority_order lists.

    Returns 0.0 if either list is empty. 1.0 means identical token sets.
    Used by think_node to detect Deep Think outputs that paraphrase the
    previous Deep Think without actually changing strategy.
    """
    new_tokens = _tokenize_priority(new_priority or [])
    old_tokens = _tokenize_priority(old_priority or [])
    if not new_tokens or not old_tokens:
        return 0.0
    intersection = new_tokens & old_tokens
    union = new_tokens | old_tokens
    if not union:
        return 0.0
    return len(intersection) / len(union)


# =============================================================================
# Continuous productivity score
# =============================================================================
#
# Combines five observed signals (all derivable from state — no LLM
# self-report dependency for the load-bearing terms) plus rewards for actual
# progress. Returns a dict with the score and component breakdown so the
# orchestrator can log *why* a tier fired.

# Verdicts considered "unproductive" for streak/axis counting
_UNPRODUCTIVE_VERDICTS = frozenset({"no_progress", "duplicate", "blocked"})


def _compute_weights(
    iteration: int,
    max_iterations: int,
    phase: str,
) -> dict:
    """Compute dynamic weights for the score formula based on session age
    and phase. Weights shift emphasis from tolerance (early) to urgency
    (late) and from exploration (informational) to discipline (exploitation).

    The shape: state-growth-stall and axis-repeats become *more* punitive
    as iterations accumulate; new_info bonus *shrinks* late in a session
    (you've already had your chance to explore). Phase 'exploitation'
    bumps axis-repeats further (each shot should be deliberate).
    """
    if not max_iterations or max_iterations <= 0:
        max_iterations = 100
    bracket = max(0.0, min(1.0, iteration / max_iterations))

    weights = {
        "w_verdict_count":    1.0,                       # constant
        "w_state_growth":     1.0 + 2.0 * bracket,       # 1.0 → 3.0
        "w_axis_repeats":     2.0 + 2.0 * bracket,       # 2.0 → 4.0
        "w_same_pattern":     0.5,                       # constant; mild
        "r_new_info":         2.0 - 1.0 * bracket,       # 2.0 → 1.0
        "r_actionable":       1.0 - 0.5 * bracket,       # 1.0 → 0.5
    }
    if phase == "exploitation":
        weights["w_axis_repeats"] += 1.0
        weights["w_verdict_count"] += 0.5
    return weights


def _same_pattern_count(execution_trace: list, window: int = 6) -> int:
    """Max count of any single (tool_name + normalized_args + output_fingerprint)
    pattern in the last `window` steps.

    Fix 2: a "repeat" requires the same input shape AND the same result. Two
    structurally different payloads (which `_normalize_args_pattern` collapses to
    the same `<val>` shape) that produced DIFFERENT responses are distinct
    attempts — legitimate debugging — not loop iterations. Pairing the arg shape
    with `_output_fingerprint` means only genuinely identical retries (same call,
    same response) are counted as repeats, which is what "looping" should mean.
    Note: variants that all produce the *identical* response still collapse to
    one pattern — that is correct, because identical results mean you are not
    learning anything from the differences."""
    if not execution_trace:
        return 0
    from collections import Counter
    recent = execution_trace[-window:]
    sigs = [
        (
            _normalize_args_pattern(s.get("tool_name"), s.get("tool_args") or {}),
            _output_fingerprint(s),
        )
        for s in recent
    ]
    if not sigs:
        return 0
    return max(Counter(sigs).values())


def _unproductive_count(execution_trace: list, window: int = 6) -> int:
    """Count of unproductive verdicts (or hard failures) in the last `window`
    steps, mirroring the legacy streak counter logic for backward parity."""
    if not execution_trace:
        return 0
    n = 0
    for step in execution_trace[-window:]:
        # Prefer the explicit, honesty-audited verdict when the step has one.
        # The legacy keyword heuristic ("failed"/"error" in the output, or a
        # non-zero exit) is only a FALLBACK for steps with no verdict — as the
        # module docstring intends. Without this, a step that made genuine
        # progress (incl. diagnostic_progress) would be re-flagged as
        # unproductive whenever its output merely contains the word "error",
        # which is extremely common while debugging an exploit and would defeat
        # Fix 1 (see test_genuine_debugging_*).
        if _read_productivity(step):
            if is_unproductive(step):
                n += 1
            continue
        out_low = ((step.get("tool_output") or "")[:500]).lower()
        if (not step.get("success", True)) or "failed" in out_low or "error" in out_low:
            n += 1
    return n


def _new_info_events_in_window(execution_trace: list, window: int = 5) -> Tuple[int, int]:
    """Returns (new_info_count, actionable_count) over the last `window` steps."""
    if not execution_trace:
        return 0, 0
    new_info = 0
    actionable = 0
    for step in execution_trace[-window:]:
        prod = _read_productivity(step)
        if prod.get("verdict") == "new_info":
            new_info += 1
        af = step.get("actionable_findings") or []
        if af:
            actionable += 1
    return new_info, actionable


def _max_axis_repeats(tested_axes: dict) -> int:
    """Max unproductive count across all known axes in the ledger."""
    if not tested_axes:
        return 0
    unproductive = {"no_progress", "duplicate", "blocked", "hard_failure"}
    best = 0
    for entries in tested_axes.values():
        c = sum(1 for e in entries if (e.get("verdict") or "") in unproductive)
        if c > best:
            best = c
    return best


def compute_productivity_score(
    *,
    execution_trace: list,
    tested_axes: dict,
    iterations_since_state_grew: int,
    iteration: int,
    max_iterations: int,
    phase: str = "informational",
    window: int = 6,
    new_info_window: int = 5,
) -> dict:
    """Compute the continuous productivity score and return a structured
    breakdown of components and weights. Pure function — no I/O, no state
    mutation. The caller maps the score to a tier and applies actions.

    Returns:
        {
          "score": float,                  # final aggregated score
          "tier": str,                     # "green" | "yellow" | "orange" | "red" | "critical"
          "components": {                  # raw signal values (pre-weight)
            "unproductive_verdicts": int,
            "iterations_since_state_grew": int,
            "max_axis_repeats": int,
            "same_pattern_count": int,
            "new_info_events": int,
            "actionable_events": int,
          },
          "weights": {...},                # the weights used (post dynamic adjustment)
          "weighted": {...},               # per-component contribution to score
        }
    """
    weights = _compute_weights(iteration, max_iterations, phase)

    unproductive = _unproductive_count(execution_trace, window=window)
    stall = max(0, min(int(iterations_since_state_grew or 0), 10))
    axis_max = _max_axis_repeats(tested_axes or {})
    same_pat = _same_pattern_count(execution_trace, window=window)
    new_info, actionable = _new_info_events_in_window(execution_trace, window=new_info_window)

    weighted = {
        "unproductive_verdicts":      weights["w_verdict_count"] * unproductive,
        "iterations_since_state_grew": weights["w_state_growth"] * stall,
        "max_axis_repeats":           weights["w_axis_repeats"] * axis_max,
        "same_pattern_count":         weights["w_same_pattern"] * same_pat,
        "new_info_events":          - weights["r_new_info"]     * new_info,
        "actionable_events":        - weights["r_actionable"]   * actionable,
    }
    score = sum(weighted.values())
    score = max(0.0, score)  # clamp at zero; negatives are just "very healthy"

    return {
        "score": round(score, 2),
        "components": {
            "unproductive_verdicts": unproductive,
            "iterations_since_state_grew": stall,
            "max_axis_repeats": axis_max,
            "same_pattern_count": same_pat,
            "new_info_events": new_info,
            "actionable_events": actionable,
        },
        "weights": {k: round(v, 2) for k, v in weights.items()},
        "weighted": {k: round(v, 2) for k, v in weighted.items()},
    }


def tier_for_score(
    score: float,
    *,
    hint_threshold: float = 3.0,
    deepthink_threshold: float = 5.0,
    require_pivot_threshold: float = 7.0,
    block_threshold: float = 9.0,
) -> str:
    """Map a numeric score to a tier label. Tiers escalate:

        green     — no action
        yellow    — inject soft hint into next prompt
        orange    — fire Deep Think (subject to cooldown + novelty check)
        red       — require axis_pivot / what_is_different rationale
        critical  — block next expensive call
    """
    if score >= block_threshold:
        return "critical"
    if score >= require_pivot_threshold:
        return "red"
    if score >= deepthink_threshold:
        return "orange"
    if score >= hint_threshold:
        return "yellow"
    return "green"


# =============================================================================
# State-growth signal
# =============================================================================

def detect_state_growth(before_state: dict, after_state: dict) -> bool:
    """Return True if any of the engagement-state collections grew between
    snapshots: target_info lists, chain_findings_memory length, or any
    actionable_findings on the latest step.

    The signal is observed (orchestrator owns the data) — it does not depend
    on the LLM's self-reported verdict, which is exactly what makes it a
    reliable "are we still making progress?" indicator.
    """
    if _target_info_grew(before_state, after_state):
        return True
    before_cfm = len((before_state or {}).get("chain_findings_memory") or [])
    after_cfm = len((after_state or {}).get("chain_findings_memory") or [])
    if after_cfm > before_cfm:
        return True
    return False


def detect_diagnostic_progress(prev_step: dict, cur_step: dict) -> bool:
    """Return True when the current step taught us something that narrows the
    problem, even if no new *target* fact was added (so detect_state_growth is
    False). This is what separates genuine debugging of a correct-but-failing
    approach from idle spinning.

    Counts as diagnostic progress when ANY holds:
      - the LLM's verdict is 'diagnostic_progress', or its `what_was_new`
        explicitly cites a ruled-out cause (self-reported, cheap signal);
      - the step is a RE-ATTEMPT of the same approach as the previous step
        (same normalized arg shape) that produced a DIFFERENT response
        fingerprint or a DIFFERENT error_class (observed signal — the last
        change had an observable effect, i.e. we are learning).

    Guardrails against faking progress:
      - The observed signal only fires for *same-approach* re-attempts, so a
        normal pivot to a different tool does not silently reset the stall
        counter (detect_state_growth / the explicit verdict handle those).
      - A different-looking payload that yields the *identical* response
        (same fingerprint) is NOT progress — churning inputs cannot game it.
    """
    if not cur_step:
        return False

    # 1) Self-reported diagnostic learning. Require a cited cause so an empty
    #    'diagnostic_progress' claim cannot silently reset the stall counter.
    #    (The orchestrator also downgrades empty claims via
    #    audit_productivity_claim — this is defense in depth.)
    p = _read_productivity(cur_step)
    note = (p.get("what_was_new") or "").strip()
    if p.get("verdict") == "diagnostic_progress" and note:
        return True
    note_l = note.lower()
    if note_l and ("ruled out" in note_l or "ruled-out" in note_l or "different error" in note_l):
        return True

    if not prev_step:
        return False

    # 2) Observed: a re-attempt of the SAME approach with a DIFFERENT result.
    same_approach = (
        _normalize_args_pattern(prev_step.get("tool_name"), prev_step.get("tool_args") or {})
        == _normalize_args_pattern(cur_step.get("tool_name"), cur_step.get("tool_args") or {})
    )
    if not same_approach:
        return False
    if _output_fingerprint(cur_step) != _output_fingerprint(prev_step):
        return True
    if (cur_step.get("error_class") or "") != (prev_step.get("error_class") or ""):
        return True
    return False


def update_stall_counters(
    iterations_since_grew,
    diagnostic_streak,
    *,
    grew: bool,
    diag: bool,
    cap: int = 6,
) -> Tuple[int, int]:
    """Pure decision for the orchestrator's per-step stall bookkeeping. Returns
    ``(new_iterations_since_grew, new_diagnostic_streak)``.

    Rules:
      - Real target-state growth resets BOTH counters to 0.
      - Diagnostic progress (a same-approach re-attempt with a different result,
        or a cited ruled-out cause) also resets the stall counter to 0 — but only
        up to ``cap`` consecutive times between two real findings. This bounds
        the feature: an agent cannot suppress the unproductive streak forever by
        eking out (or claiming) diagnostic progress on a dead approach. Once the
        diagnostic budget is spent, the stall counter climbs normally so a
        genuine stall eventually surfaces and the diagnose-or-pivot prompt fires.
      - Otherwise the stall counter climbs and the diagnostic streak is kept.

    Extracted from think_node so the combined logic is unit-testable without the
    node's dependency graph; both the single-tool and wave paths call it.
    """
    its = int(iterations_since_grew or 0)
    ds = int(diagnostic_streak or 0)
    cap = int(cap)
    if grew:
        return 0, 0
    if diag and ds < cap:
        return 0, ds + 1
    return its + 1, ds


def build_productivity_audit_section(
    execution_trace: list,
    current_tool_name: Optional[str] = None,
    current_tool_args: Optional[dict] = None,
    window: int = 6,
) -> str:
    """Build the prompt block that shows the model its own recent same-pattern
    fingerprints. Returns empty string if fewer than 3 same-pattern calls
    are in the recent window (no audit needed yet).

    The presence of this block is what makes the LLM verdict robust: when
    three of the last four calls share fingerprint a7c3 and produced no
    finding, claiming "confirmation" on the fourth is visibly dishonest.
    """
    if not execution_trace:
        return ""

    recent = execution_trace[-max(window, 1):]
    if current_tool_name and current_tool_args is not None:
        target_pattern = _normalize_args_pattern(current_tool_name, current_tool_args)
        same = [s for s in recent
                if _normalize_args_pattern(s.get("tool_name"), s.get("tool_args") or {}) == target_pattern]
    else:
        # No specific current step: pick the most-repeated pattern in the window.
        counts: dict[str, list] = {}
        for s in recent:
            sig = _normalize_args_pattern(s.get("tool_name"), s.get("tool_args") or {})
            counts.setdefault(sig, []).append(s)
        if not counts:
            return ""
        target_pattern, same = max(counts.items(), key=lambda kv: len(kv[1]))

    if len(same) < 3:
        return ""

    lines = []
    for s in same:
        fp = _output_fingerprint(s)
        size = _output_size(s)
        args_short = json.dumps(s.get("tool_args") or {}, ensure_ascii=False)[:90]
        lines.append(
            f"  [step {s.get('step_iteration', '?')}] "
            f"{s.get('tool_name', '?')} {args_short}  "
            f"{size}B  fp={fp}"
        )

    fingerprints = {_output_fingerprint(s) for s in same}
    diversity_hint = (
        "ALL identical fingerprints — definitely looping."
        if len(fingerprints) == 1
        else f"{len(fingerprints)} unique fingerprints across {len(same)} calls "
             f"({'high' if len(fingerprints) / len(same) > 0.7 else 'low'} variance)."
    )

    return f"""
## Productivity Audit (compare against your own recent calls)

Before filling `output_analysis.productivity`, honestly assess: did this call
yield new information, or did it repeat what you already saw?

Recent same-pattern tool calls (fp = sha256-truncated fingerprint of normalized
response body — same fp means functionally identical output):

{chr(10).join(lines)}

{diversity_hint}

Decision rules:
  - If 3+ recent same-pattern calls share the same fingerprint AND you have no
    new fact to cite in `what_was_new` → verdict MUST be `duplicate` or
    `no_progress`. Marking it `confirmation` is dishonest.
  - If the call hit 401/403/captcha/WAF → verdict is `blocked`.
  - If you can cite ONE specific new fact in `what_was_new` that is not already
    in your findings list → verdict is `new_info`.
  - If the output merely confirms a fact you already had → verdict is
    `confirmation` (acceptable for a single confirmation, not for repeats).

If your prior `productivity` claim was downgraded as inconsistent, the reason
appears below. Take it seriously — repeating the same dishonest claim wastes
budget.
"""
