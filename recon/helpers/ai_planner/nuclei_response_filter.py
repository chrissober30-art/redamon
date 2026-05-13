"""
Nuclei AI False-Positive Response Filter
========================================
Augments the static keyword-based WAF/rate-limit detection in
helpers/nuclei_helpers.is_false_positive() with an LLM that classifies
the Nuclei response body when the keyword list misses or fires on
ambiguous text.

Two failure modes the keyword list has:
- False positives: the string "WAF" or "Access Denied" appears in
  legitimate responses (admin panels with "WAF settings: enabled",
  documentation pages, API responses with `waf_status`).
- False negatives: rebranded WAF block pages don't contain any of the
  hardcoded keywords (custom Imperva pages, AWS WAF JSON `{"message":
  "Forbidden"}`, Fortinet themed pages, empty 406 bodies).

The LLM call is delegated to the agent container's /llm/nuclei-fp-filter
endpoint so the recon image stays free of LLM SDKs and per-user API keys
live in one place. Mirrors waf_classifier.py and nuclei_tags.py.

All log lines use the `[symbol][Nuclei-FP-AI]` format so they surface in
the recon drawer SSE stream.
"""

import json
import os
import re
from typing import Dict, Optional

import requests

# Returned on any failure (network, auth, schema, validation). Keeps the
# call graph defensive: callers always get a usable dict.
SAFE_FALLBACK: Dict = {
    "is_blocked": False,
    "reason": "",
    "confidence": 0,
    "source": "ai_unavailable",
}

REASON_REGEX = re.compile(r'^[\x20-\x7e]{0,500}$')

LLM_TIMEOUT = 20
RESPONSE_SAMPLE_BYTES = 4096


def _fingerprint(response_text: str, status_line: str) -> str:
    """Build a cache key from parts of the response that disclose a
    block-vs-real-finding signal. Multiple Nuclei findings against the
    same WAF-fronted host produce identical block pages -- one LLM call
    should cover them all."""
    body = (response_text or "")[:RESPONSE_SAMPLE_BYTES]
    size_bucket = len(body) // 256  # 256-byte granularity
    head = body[:96].encode('utf-8', errors='replace').hex()
    return f"status={status_line[:32]}|size={size_bucket}|head={head}"


def _validate_classification(raw) -> Optional[Dict]:
    """Return a sanitized classification dict or None if the payload is
    malformed. Defends against prompt-injection through the response body."""
    if not isinstance(raw, dict):
        return None

    is_blocked = raw.get("is_blocked")
    if not isinstance(is_blocked, bool):
        return None

    confidence = raw.get("confidence")
    if not isinstance(confidence, (int, float)):
        return None
    confidence = int(confidence)
    if confidence < 0 or confidence > 100:
        return None

    reason = raw.get("reason") or ""
    if not isinstance(reason, str):
        reason = ""
    reason = reason[:500]
    # Strip non-printable / control chars to keep log lines safe.
    reason = ''.join(c for c in reason if 0x20 <= ord(c) <= 0x7e)

    return {
        "is_blocked": is_blocked,
        "reason": reason,
        "confidence": confidence,
        "source": "ai_classifier",
    }


def classify_nuclei_response(
    response_text: str,
    template_id: str,
    tags: list,
    model: str,
    cache: Optional[Dict[str, Dict]] = None,
    user_id: str = '',
    project_id: str = '',
) -> Dict:
    """
    Ask the agent to classify whether *response_text* is a WAF/rate-limit
    block page rather than a real Nuclei hit. Never raises -- returns
    SAFE_FALLBACK on any failure so callers can keep the static path.

    Args:
        response_text: Full Nuclei response field (status line + headers
            + body, as captured by Nuclei).
        template_id: Nuclei template id (e.g. "sqli/error-based-mysql").
        tags: Template tags from the Nuclei finding (e.g. ["sqli",
            "injection"]).
        model: LLM model id (same format as agentOpenaiModel).
        cache: Optional dict keyed by response fingerprint to dedupe across
            many similar findings in a single scan.
        user_id, project_id: Forwarded to the agent for per-user LLM key
            resolution.

    Returns:
        Dict with keys: is_blocked (bool), reason (str), confidence
        (0-100), source (str).
    """
    cache = cache if cache is not None else {}

    response_text = response_text or ""
    if not response_text.strip():
        return dict(SAFE_FALLBACK)

    # First non-empty line is usually the status line ("HTTP/1.1 403 ...").
    status_line = response_text.splitlines()[0] if response_text else ""

    fp = _fingerprint(response_text, status_line)
    if fp in cache:
        cached = cache[fp]
        print(f"[+][Nuclei-FP-AI] Cache hit -> blocked={cached.get('is_blocked')} "
              f"conf={cached.get('confidence')} ({template_id})")
        return cached

    body_sample = response_text[:RESPONSE_SAMPLE_BYTES]

    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')
    payload = {
        'template_id': template_id or '',
        'tags': list(tags or []),
        'status_line': status_line,
        'response_sample': body_sample,
        'model': model,
        'user_id': user_id,
        'project_id': project_id,
    }
    endpoint = f"{agent_api_url}/llm/nuclei-fp-filter"
    print(f"[*][Nuclei-FP-AI] Calling agent {endpoint} with model={model} "
          f"(template={template_id}, body={len(body_sample)}B)")

    try:
        resp = requests.post(endpoint, json=payload, timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        print(f"[!][Nuclei-FP-AI] Agent request failed: {e}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    if resp.status_code != 200:
        print(f"[!][Nuclei-FP-AI] Agent returned HTTP {resp.status_code}: "
              f"{resp.text[:200]}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][Nuclei-FP-AI] Agent returned non-JSON response: {e}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    validated = _validate_classification(data)
    if validated is None:
        print(f"[!][Nuclei-FP-AI] Agent response failed schema validation: "
              f"{str(data)[:200]}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    cache[fp] = validated

    if validated["is_blocked"]:
        print(f"[+][Nuclei-FP-AI] Block page detected (confidence={validated['confidence']}): "
              f"{validated['reason'][:100]}")
    else:
        print(f"[+][Nuclei-FP-AI] Real finding (confidence={validated['confidence']})")

    return validated
