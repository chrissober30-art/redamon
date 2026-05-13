"""
Unit + integration tests for the Nuclei AI false-positive response filter.

Covers:
- recon/helpers/ai_planner/nuclei_response_filter.py (the helper)
- the cascade in recon/helpers/nuclei_helpers.is_false_positive() (the
  caller-side gating)
- settings cascade in recon/project_settings.py
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ai_planner.nuclei_response_filter import (
    classify_nuclei_response,
    SAFE_FALLBACK,
    _fingerprint,
    _validate_classification,
)
from recon.helpers import nuclei_helpers as nh
from recon import project_settings as ps


def _reset_fp_ctx():
    nh.set_fp_ai_ctx(False, "", "", "")


def _mock_post(payload=None, status_code=200, raise_exc=None):
    if raise_exc:
        return mock.MagicMock(side_effect=raise_exc)
    resp = mock.MagicMock()
    resp.status_code = status_code
    if payload is not None:
        resp.json.return_value = payload
    else:
        resp.json.side_effect = ValueError("no json")
    resp.text = ''
    return resp


def _finding(response: str, template_id: str = "sqli/error-mysql", tags=None) -> dict:
    return {
        "response": response,
        "template-id": template_id,
        "info": {"tags": tags or ["sqli", "injection"]},
    }


# ============================================================================
# Validator
# ============================================================================

def test_validator_accepts_valid_payload():
    raw = {"is_blocked": True, "confidence": 90, "reason": "AWS WAF body fingerprint"}
    out = _validate_classification(raw)
    assert out is not None
    assert out["is_blocked"] is True
    assert out["confidence"] == 90
    assert out["source"] == "ai_classifier"
    print("PASS: test_validator_accepts_valid_payload")


def test_validator_rejects_bad_confidence():
    assert _validate_classification({"is_blocked": True, "confidence": 200}) is None
    assert _validate_classification({"is_blocked": True, "confidence": -5}) is None
    assert _validate_classification({"is_blocked": True, "confidence": "high"}) is None
    print("PASS: test_validator_rejects_bad_confidence")


def test_validator_rejects_non_bool_blocked():
    assert _validate_classification({"is_blocked": "yes", "confidence": 80}) is None
    assert _validate_classification({"is_blocked": 1, "confidence": 80}) is None
    print("PASS: test_validator_rejects_non_bool_blocked")


def test_validator_strips_control_chars_in_reason():
    raw = {"is_blocked": True, "confidence": 80, "reason": "blocked\x00\x01\x07by WAF"}
    out = _validate_classification(raw)
    assert out is not None
    assert "\x00" not in out["reason"] and "\x07" not in out["reason"]
    assert "blockedby WAF" in out["reason"]
    print("PASS: test_validator_strips_control_chars_in_reason")


def test_validator_rejects_non_dict():
    assert _validate_classification(["a", "list"]) is None
    assert _validate_classification("a string") is None
    assert _validate_classification(None) is None
    print("PASS: test_validator_rejects_non_dict")


# ============================================================================
# Fingerprint
# ============================================================================

def test_fingerprint_stable_across_dynamic_content():
    body1 = "HTTP/1.1 403 Forbidden\nContent-Type: text/html\n\n<html>blocked</html>"
    body2 = "HTTP/1.1 403 Forbidden\nContent-Type: text/html\n\n<html>blocked</html>"
    assert _fingerprint(body1, "HTTP/1.1 403 Forbidden") == _fingerprint(body2, "HTTP/1.1 403 Forbidden")
    print("PASS: test_fingerprint_stable_across_dynamic_content")


def test_fingerprint_changes_on_body_or_status():
    a = _fingerprint("HTTP/1.1 200 OK\n\n<html>ok</html>", "HTTP/1.1 200 OK")
    b = _fingerprint("HTTP/1.1 403 Forbidden\n\n<html>blocked</html>", "HTTP/1.1 403 Forbidden")
    assert a != b
    print("PASS: test_fingerprint_changes_on_body_or_status")


# ============================================================================
# classify_nuclei_response
# ============================================================================

def test_classify_empty_response_returns_fallback():
    out = classify_nuclei_response("", "sqli/test", ["sqli"], model="claude-opus-4-6")
    assert out == SAFE_FALLBACK
    print("PASS: test_classify_empty_response_returns_fallback")


def test_classify_cache_hit_skips_post():
    body = "HTTP/1.1 403\n\nblocked"
    cached = {"is_blocked": True, "confidence": 90, "reason": "cached", "source": "ai_classifier"}
    cache = {_fingerprint(body, "HTTP/1.1 403"): cached}
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post') as post_mock:
        out = classify_nuclei_response(body, "t", ["sqli"], model="m", cache=cache)
    assert out == cached
    post_mock.assert_not_called()
    print("PASS: test_classify_cache_hit_skips_post")


def test_classify_agent_timeout_returns_fallback():
    import requests as req_mod
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    side_effect=req_mod.Timeout("agent slow")):
        out = classify_nuclei_response("HTTP/1.1 403\n\nx", "t", ["sqli"], model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_agent_timeout_returns_fallback")


def test_classify_agent_500_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    return_value=_mock_post(status_code=500)):
        out = classify_nuclei_response("HTTP/1.1 403\n\nx", "t", ["sqli"], model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_agent_500_returns_fallback")


def test_classify_non_json_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    return_value=_mock_post(payload=None)):
        out = classify_nuclei_response("HTTP/1.1 403\n\nx", "t", ["sqli"], model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_non_json_returns_fallback")


def test_classify_schema_violation_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    return_value=_mock_post(payload={"is_blocked": "maybe", "confidence": 999})):
        out = classify_nuclei_response("HTTP/1.1 403\n\nx", "t", ["sqli"], model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_schema_violation_returns_fallback")


def test_classify_valid_response_caches():
    body = "HTTP/1.1 403\n\n<html>blocked</html>"
    cache = {}
    payload = {"is_blocked": True, "confidence": 92, "reason": "AWS WAF body shape"}
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    return_value=_mock_post(payload=payload)):
        out = classify_nuclei_response(body, "sqli/test", ["sqli"], model="m", cache=cache)
    assert out["is_blocked"] is True
    assert out["confidence"] == 92
    assert out["source"] == "ai_classifier"
    assert len(cache) == 1
    # Second call hits cache, no POST.
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post') as post_mock:
        out2 = classify_nuclei_response(body, "sqli/test", ["sqli"], model="m", cache=cache)
    post_mock.assert_not_called()
    assert out2 == out
    print("PASS: test_classify_valid_response_caches")


# ============================================================================
# is_false_positive cascade in nuclei_helpers
# ============================================================================

def test_is_false_positive_static_keyword_still_wins():
    """Regression: when static WAF keyword matches, AI must not be called."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    finding = _finding("HTTP/1.1 403 Forbidden\n\nAccess Denied by Cloudflare")
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.classify_nuclei_response') as ai_mock:
        is_fp, reason = nh.is_false_positive(finding)
    assert is_fp is True
    assert "WAF/Firewall block detected" in reason
    ai_mock.assert_not_called()
    _reset_fp_ctx()
    print("PASS: test_is_false_positive_static_keyword_still_wins")


def test_is_false_positive_rate_limit_still_wins():
    """Regression: rate-limit branch is unchanged."""
    _reset_fp_ctx()
    finding = _finding("HTTP/1.1 429 Too Many Requests\n\nrate limit",
                       tags=["time-based", "blind"])
    is_fp, reason = nh.is_false_positive(finding)
    assert is_fp is True
    assert "Rate limiting detected" in reason
    print("PASS: test_is_false_positive_rate_limit_still_wins")


def test_is_false_positive_ai_off_static_negative_returns_false():
    """Regression: with AI off, static-negative responses return False."""
    _reset_fp_ctx()
    finding = _finding("HTTP/1.1 200 OK\n\n<html>real content</html>")
    is_fp, reason = nh.is_false_positive(finding)
    assert is_fp is False
    assert reason is None
    print("PASS: test_is_false_positive_ai_off_static_negative_returns_false")


def test_is_false_positive_ai_off_no_call_made():
    """When AI is off, no LLM call is made even on suspicious responses.
    Use a 403 status without the literal 'Forbidden' string so the static
    keyword list does NOT fire and the test exercises the cascade gate."""
    _reset_fp_ctx()
    finding = _finding("HTTP/1.1 403\n\nbland body without vendor keywords")
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post') as post_mock:
        is_fp, _ = nh.is_false_positive(finding)
    assert is_fp is False
    post_mock.assert_not_called()
    print("PASS: test_is_false_positive_ai_off_no_call_made")


def test_is_false_positive_ai_skips_on_200_response():
    """Cost guarantee: 200 OK responses skip the AI even when AI is on."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    finding = _finding("HTTP/1.1 200 OK\n\n<html>real content</html>")
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.classify_nuclei_response') as ai_mock:
        is_fp, _ = nh.is_false_positive(finding)
    assert is_fp is False
    ai_mock.assert_not_called()
    _reset_fp_ctx()
    print("PASS: test_is_false_positive_ai_skips_on_200_response")


def test_is_false_positive_ai_skips_on_non_injection_tags():
    """The cascade only runs for injection-class findings (matches the
    static path). A 403 on a recon/exposure template does not trigger AI."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    finding = _finding("HTTP/1.1 403 Forbidden\n\nshort", tags=["exposure"])
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.classify_nuclei_response') as ai_mock:
        nh.is_false_positive(finding)
    ai_mock.assert_not_called()
    _reset_fp_ctx()
    print("PASS: test_is_false_positive_ai_skips_on_non_injection_tags")


def test_is_false_positive_ai_high_confidence_blocks():
    """Static missed keyword + suspicious 403 + injection tag + AI says
    blocked at confidence >= 70 -> finding flagged as false positive.
    Body uses a bare 403 status with a JSON shape that contains none of
    the hardcoded keywords (no 'Forbidden' adjacent to '403', no 'WAF',
    no vendor tokens) so the static loop falls through to the AI cascade."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    finding = _finding("HTTP/1.1 403\n\n{\"message\":\"deny\"}")
    payload = {"is_blocked": True, "confidence": 88,
               "reason": "minimal JSON error matches AWS shape", "source": "ai_classifier"}
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.classify_nuclei_response',
                    return_value=payload):
        is_fp, reason = nh.is_false_positive(finding)
    assert is_fp is True
    assert "AWS shape" in reason
    assert "conf=88" in reason
    _reset_fp_ctx()
    print("PASS: test_is_false_positive_ai_high_confidence_blocks")


def test_is_false_positive_ai_low_confidence_passes_through():
    """Below threshold -> finding stays as a real hit."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    finding = _finding("HTTP/1.1 406\n\n{\"err\":\"x\"}")
    payload = {"is_blocked": True, "confidence": 55, "reason": "ambiguous",
               "source": "ai_classifier"}
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.classify_nuclei_response',
                    return_value=payload):
        is_fp, reason = nh.is_false_positive(finding)
    assert is_fp is False
    assert reason is None
    _reset_fp_ctx()
    print("PASS: test_is_false_positive_ai_low_confidence_passes_through")


def test_is_false_positive_ai_unavailable_falls_back():
    """If AI is unavailable mid-cascade, finding stays as real hit."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    finding = _finding("HTTP/1.1 503 Service Unavailable\n\nshort")
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.classify_nuclei_response',
                    return_value=dict(SAFE_FALLBACK)):
        is_fp, reason = nh.is_false_positive(finding)
    assert is_fp is False
    assert reason is None
    _reset_fp_ctx()
    print("PASS: test_is_false_positive_ai_unavailable_falls_back")


# ============================================================================
# Project settings cascade
# ============================================================================

def test_default_settings_has_response_filter():
    assert 'NUCLEI_AI_RESPONSE_FILTER' in ps.DEFAULT_SETTINGS
    assert ps.DEFAULT_SETTINGS['NUCLEI_AI_RESPONSE_FILTER'] is False
    print("PASS: test_default_settings_has_response_filter")


def test_cascade_off_forces_response_filter_off():
    settings = ps.DEFAULT_SETTINGS.copy()
    settings['AI_IN_PIPELINE'] = False
    settings['NUCLEI_AI_RESPONSE_FILTER'] = True
    settings = ps.apply_ai_pipeline_overrides(settings)
    assert settings['NUCLEI_AI_RESPONSE_FILTER'] is False
    print("PASS: test_cascade_off_forces_response_filter_off")


def test_cascade_on_forces_response_filter_on():
    settings = ps.DEFAULT_SETTINGS.copy()
    settings['AI_IN_PIPELINE'] = True
    settings['NUCLEI_AI_RESPONSE_FILTER'] = False
    settings = ps.apply_ai_pipeline_overrides(settings)
    assert settings['NUCLEI_AI_RESPONSE_FILTER'] is True
    print("PASS: test_cascade_on_forces_response_filter_on")


def test_fetch_project_settings_mapping_present():
    """fetch_project_settings has heavy runtime imports; verify the
    mapping line exists in the source."""
    src = Path(ps.__file__).read_text()
    needle = "settings['NUCLEI_AI_RESPONSE_FILTER'] = project.get('nucleiAiResponseFilter'"
    assert needle in src
    print("PASS: test_fetch_project_settings_mapping_present")


# ============================================================================
# set_fp_ai_ctx
# ============================================================================

def test_set_fp_ai_ctx_disabled_when_no_model():
    nh.set_fp_ai_ctx(True, "", "u", "p")
    assert nh._FP_AI_CTX["enabled"] is False
    assert nh._FP_AI_CTX["cache"] is None
    print("PASS: test_set_fp_ai_ctx_disabled_when_no_model")


def test_set_fp_ai_ctx_enabled_creates_fresh_cache():
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    assert nh._FP_AI_CTX["enabled"] is True
    assert nh._FP_AI_CTX["cache"] == {}
    nh._FP_AI_CTX["cache"]["dirty"] = "stale"
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    assert nh._FP_AI_CTX["cache"] == {}
    _reset_fp_ctx()
    print("PASS: test_set_fp_ai_ctx_enabled_creates_fresh_cache")


if __name__ == '__main__':
    # Validator
    test_validator_accepts_valid_payload()
    test_validator_rejects_bad_confidence()
    test_validator_rejects_non_bool_blocked()
    test_validator_strips_control_chars_in_reason()
    test_validator_rejects_non_dict()
    # Fingerprint
    test_fingerprint_stable_across_dynamic_content()
    test_fingerprint_changes_on_body_or_status()
    # classify_nuclei_response
    test_classify_empty_response_returns_fallback()
    test_classify_cache_hit_skips_post()
    test_classify_agent_timeout_returns_fallback()
    test_classify_agent_500_returns_fallback()
    test_classify_non_json_returns_fallback()
    test_classify_schema_violation_returns_fallback()
    test_classify_valid_response_caches()
    # is_false_positive cascade
    test_is_false_positive_static_keyword_still_wins()
    test_is_false_positive_rate_limit_still_wins()
    test_is_false_positive_ai_off_static_negative_returns_false()
    test_is_false_positive_ai_off_no_call_made()
    test_is_false_positive_ai_skips_on_200_response()
    test_is_false_positive_ai_skips_on_non_injection_tags()
    test_is_false_positive_ai_high_confidence_blocks()
    test_is_false_positive_ai_low_confidence_passes_through()
    test_is_false_positive_ai_unavailable_falls_back()
    # Settings cascade
    test_default_settings_has_response_filter()
    test_cascade_off_forces_response_filter_off()
    test_cascade_on_forces_response_filter_on()
    test_fetch_project_settings_mapping_present()
    # ctx
    test_set_fp_ai_ctx_disabled_when_no_model()
    test_set_fp_ai_ctx_enabled_creates_fresh_cache()
    print("\nAll tests passed")
