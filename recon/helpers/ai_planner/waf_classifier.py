"""
WAF AI Classifier
=================
Augments the static `_has_cdn_markers` / `check_waf_bypass` header-token logic
in helpers/security_checks.py with an LLM that scores WAF presence from the
full response (status, headers, body sample, response time).

Modern WAFs strip or rebrand the headers that the static path keys off of
(cf-ray, x-amz-cf-id, Server: cloudflare, ...). The LLM picks up on body
fingerprints (challenge pages, "Request blocked"), cookie shapes
(`__cf_bm`, `incap_ses_`), latency outliers, and status+body mismatches that
no fixed list can.

The LLM call is delegated to the agent container's /llm/waf-classify endpoint
so the recon image stays free of LLM SDKs and per-user API keys live in one
place. Mirrors ffuf_extensions.py and nuclei_tags.py.

All log lines use the `[symbol][WAF-AI]` format so they surface in the recon
drawer SSE stream.
"""

import json
import os
import re
from typing import Dict, Optional

import requests

# Returned on any failure (network, auth, schema, validation). Keeps the call
# graph defensive: callers always get a usable dict.
SAFE_FALLBACK: Dict = {
    "waf_detected": False,
    "waf_type": None,
    "confidence": 0,
    "reasoning": "",
    "source": "ai_unavailable",
}

WAF_TYPE_REGEX = re.compile(r'^[a-z0-9_-]{2,30}$')

LLM_TIMEOUT = 20
BODY_SAMPLE_BYTES = 4096


def _fingerprint(response) -> str:
    """Build a cache key from the parts of a response that actually disclose
    a WAF. Identical responses on different IPs hit the LLM once, not once
    per IP."""
    headers = response.headers or {}
    server = headers.get("Server", "")
    status = response.status_code
    # Bucket size into 1KB granularity so tiny variations don't bust the cache.
    body = response.content or b""
    size_bucket = len(body) // 1024
    # First 64 bytes of the body fingerprint the page shape (challenge page
    # vs HTML vs JSON error) without making the key depend on per-request
    # tokens like CSRF nonces.
    body_head = body[:64].hex()
    return f"server={server}|status={status}|size={size_bucket}|head={body_head}"


def _validate_classification(raw) -> Optional[Dict]:
    """Return a sanitized classification dict or None if the payload is malformed.
    Defends against prompt-injection through the response body."""
    if not isinstance(raw, dict):
        return None

    detected = raw.get("waf_detected")
    if not isinstance(detected, bool):
        return None

    confidence = raw.get("confidence")
    if not isinstance(confidence, (int, float)):
        return None
    confidence = int(confidence)
    if confidence < 0 or confidence > 100:
        return None

    waf_type = raw.get("waf_type")
    if waf_type is not None:
        if not isinstance(waf_type, str) or not WAF_TYPE_REGEX.match(waf_type):
            return None

    reasoning = raw.get("reasoning") or ""
    if not isinstance(reasoning, str):
        reasoning = ""
    reasoning = reasoning[:500]

    return {
        "waf_detected": detected,
        "waf_type": waf_type if detected else None,
        "confidence": confidence,
        "reasoning": reasoning,
        "source": "ai_classifier",
    }


def classify_waf(
    response,
    model: str,
    cache: Optional[Dict[str, Dict]] = None,
    user_id: str = '',
    project_id: str = '',
    response_time_ms: int = 0,
) -> Dict:
    """
    Ask the agent to classify whether *response* came through a WAF/CDN.
    Never raises -- returns ``SAFE_FALLBACK`` on any failure so callers can
    keep their cascade fallback to the static path.

    Args:
        response: A `requests.Response` (must expose .status_code, .headers,
            .content, .url).
        model: LLM model id (same format as agentOpenaiModel).
        cache: Optional dict keyed by response fingerprint to dedupe across
            many similar responses in a single scan.
        user_id, project_id: Forwarded to the agent for per-user LLM key
            resolution.
        response_time_ms: Optional latency hint. WAFs often add 50-200ms.

    Returns:
        Dict with keys: waf_detected (bool), waf_type (str|None),
        confidence (0-100), reasoning (str), source (str).
    """
    cache = cache if cache is not None else {}

    if response is None:
        return dict(SAFE_FALLBACK)

    url = getattr(response, 'url', '') or ''
    print(f"[*][WAF-AI] Classifying {url}")

    fp = _fingerprint(response)
    if fp in cache:
        cached = cache[fp]
        print(f"[+][WAF-AI] Cache hit -> detected={cached.get('waf_detected')} "
              f"type={cached.get('waf_type')} conf={cached.get('confidence')}")
        return cached

    body_bytes = (response.content or b'')[:BODY_SAMPLE_BYTES]
    body_sample = body_bytes.decode('utf-8', errors='replace')
    headers = {k: v for k, v in (response.headers or {}).items()}

    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')
    payload = {
        'url': url,
        'status_code': int(response.status_code),
        'headers': headers,
        'body_sample': body_sample,
        'response_time_ms': int(response_time_ms),
        'model': model,
        'user_id': user_id,
        'project_id': project_id,
    }
    endpoint = f"{agent_api_url}/llm/waf-classify"
    print(f"[*][WAF-AI] Calling agent {endpoint} with model={model} (status={response.status_code}, body={len(body_sample)}B)")

    try:
        resp = requests.post(endpoint, json=payload, timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        print(f"[!][WAF-AI] Agent request failed: {e}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    if resp.status_code != 200:
        print(f"[!][WAF-AI] Agent returned HTTP {resp.status_code}: {resp.text[:200]}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][WAF-AI] Agent returned non-JSON response: {e}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    validated = _validate_classification(data)
    if validated is None:
        print(f"[!][WAF-AI] Agent response failed schema validation: {str(data)[:200]}. Using safe fallback.")
        return dict(SAFE_FALLBACK)

    cache[fp] = validated

    if validated["waf_detected"]:
        print(f"[+][WAF-AI] {validated['waf_type'] or 'unknown'} detected (confidence={validated['confidence']})")
    else:
        print(f"[+][WAF-AI] No WAF detected (confidence={validated['confidence']})")

    return validated
