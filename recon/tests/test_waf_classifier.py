"""
Unit tests for recon.helpers.ai_planner.waf_classifier.classify_waf().

Verifies:
- Cache hit returns without HTTP/LLM call
- Agent timeout / 5xx / non-JSON / schema violation -> SAFE_FALLBACK
- Valid response is sanitized and cached
- Validator rejects malformed waf_type / out-of-range confidence
- None response is handled defensively
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ai_planner.waf_classifier import (
    classify_waf,
    SAFE_FALLBACK,
    _fingerprint,
    _validate_classification,
    WAF_TYPE_REGEX,
)


def _mock_response(status_code=200, headers=None, body=b'', url='https://target.com/'):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.content = body
    resp.url = url
    return resp


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


# ----- Validator -----

def test_validator_accepts_valid_payload():
    raw = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 92, "reasoning": "cf-ray header"}
    out = _validate_classification(raw)
    assert out is not None
    assert out["waf_detected"] is True
    assert out["waf_type"] == "cloudflare"
    assert out["confidence"] == 92
    assert out["source"] == "ai_classifier"
    print("PASS: test_validator_accepts_valid_payload")


def test_validator_clears_waf_type_when_not_detected():
    raw = {"waf_detected": False, "waf_type": "cloudflare", "confidence": 5}
    out = _validate_classification(raw)
    assert out is not None
    assert out["waf_detected"] is False
    assert out["waf_type"] is None, "waf_type must be None when waf_detected is False"
    print("PASS: test_validator_clears_waf_type_when_not_detected")


def test_validator_rejects_bad_confidence():
    assert _validate_classification({"waf_detected": True, "confidence": 150}) is None
    assert _validate_classification({"waf_detected": True, "confidence": -1}) is None
    assert _validate_classification({"waf_detected": True, "confidence": "high"}) is None
    print("PASS: test_validator_rejects_bad_confidence")


def test_validator_rejects_bad_waf_type():
    # Uppercase, special chars, too long -> rejected.
    assert _validate_classification({"waf_detected": True, "waf_type": "Cloudflare", "confidence": 90}) is None
    assert _validate_classification({"waf_detected": True, "waf_type": "$(rm -rf)", "confidence": 90}) is None
    assert _validate_classification({"waf_detected": True, "waf_type": "x" * 50, "confidence": 90}) is None
    print("PASS: test_validator_rejects_bad_waf_type")


def test_validator_rejects_non_dict():
    assert _validate_classification(["a", "list"]) is None
    assert _validate_classification("a string") is None
    assert _validate_classification(None) is None
    print("PASS: test_validator_rejects_non_dict")


def test_validator_truncates_reasoning():
    raw = {"waf_detected": True, "waf_type": "akamai", "confidence": 80, "reasoning": "x" * 1000}
    out = _validate_classification(raw)
    assert out is not None
    assert len(out["reasoning"]) == 500
    print("PASS: test_validator_truncates_reasoning")


def test_waf_type_regex_basics():
    assert WAF_TYPE_REGEX.match("cloudflare")
    assert WAF_TYPE_REGEX.match("aws_waf")
    assert WAF_TYPE_REGEX.match("azure-frontdoor")
    assert not WAF_TYPE_REGEX.match("Cloudflare")  # uppercase
    assert not WAF_TYPE_REGEX.match("a")            # too short
    assert not WAF_TYPE_REGEX.match("waf!")          # special char
    print("PASS: test_waf_type_regex_basics")


# ----- Fingerprint -----

def test_fingerprint_is_stable_across_dynamic_headers():
    r1 = _mock_response(status_code=403, headers={"Server": "cloudflare", "Date": "now"}, body=b"<html>blocked</html>")
    r2 = _mock_response(status_code=403, headers={"Server": "cloudflare", "Date": "later"}, body=b"<html>blocked</html>")
    assert _fingerprint(r1) == _fingerprint(r2)
    print("PASS: test_fingerprint_is_stable_across_dynamic_headers")


def test_fingerprint_changes_on_status_or_server():
    base = _mock_response(status_code=200, headers={"Server": "nginx"}, body=b"hello")
    diff_status = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"hello")
    diff_server = _mock_response(status_code=200, headers={"Server": "cloudflare"}, body=b"hello")
    assert _fingerprint(base) != _fingerprint(diff_status)
    assert _fingerprint(base) != _fingerprint(diff_server)
    print("PASS: test_fingerprint_changes_on_status_or_server")


# ----- classify_waf cascade behavior -----

def test_classify_waf_none_response_returns_fallback():
    out = classify_waf(None, model="claude-opus-4-6")
    assert out == SAFE_FALLBACK
    print("PASS: test_classify_waf_none_response_returns_fallback")


def test_classify_waf_cache_hit_skips_post():
    cached = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 92, "reasoning": "cached", "source": "ai_classifier"}
    resp = _mock_response(status_code=403, headers={"Server": "cloudflare"}, body=b"blocked")
    cache = {_fingerprint(resp): cached}
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post') as post_mock:
        result = classify_waf(resp, model="claude-opus-4-6", cache=cache)
    assert result == cached
    post_mock.assert_not_called()
    print("PASS: test_classify_waf_cache_hit_skips_post")


def test_classify_waf_agent_timeout_returns_fallback():
    import requests as req_mod
    resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"blocked")
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post',
                    side_effect=req_mod.Timeout("agent slow")):
        result = classify_waf(resp, model="claude-opus-4-6")
    assert result["source"] == "ai_unavailable"
    assert result["waf_detected"] is False
    print("PASS: test_classify_waf_agent_timeout_returns_fallback")


def test_classify_waf_agent_500_returns_fallback():
    resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"blocked")
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post',
                    return_value=_mock_post(status_code=500)):
        result = classify_waf(resp, model="claude-opus-4-6")
    assert result["source"] == "ai_unavailable"
    print("PASS: test_classify_waf_agent_500_returns_fallback")


def test_classify_waf_non_json_returns_fallback():
    resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"blocked")
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post',
                    return_value=_mock_post(payload=None, status_code=200)):
        result = classify_waf(resp, model="claude-opus-4-6")
    assert result["source"] == "ai_unavailable"
    print("PASS: test_classify_waf_non_json_returns_fallback")


def test_classify_waf_schema_violation_returns_fallback():
    resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"blocked")
    bogus = {"waf_detected": "maybe", "confidence": "very high"}  # wrong types
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post',
                    return_value=_mock_post(payload=bogus)):
        result = classify_waf(resp, model="claude-opus-4-6")
    assert result["source"] == "ai_unavailable"
    print("PASS: test_classify_waf_schema_violation_returns_fallback")


def test_classify_waf_valid_response_caches():
    cache = {}
    resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"<html>access denied | reference #...</html>")
    payload = {"waf_detected": True, "waf_type": "akamai", "confidence": 85, "reasoning": "reference id pattern"}
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post',
                    return_value=_mock_post(payload=payload)):
        result = classify_waf(resp, model="claude-opus-4-6", cache=cache)
    assert result["waf_detected"] is True
    assert result["waf_type"] == "akamai"
    assert result["confidence"] == 85
    assert result["source"] == "ai_classifier"
    assert len(cache) == 1
    # Second call same fingerprint -> cache hit, no POST
    with mock.patch('recon.helpers.ai_planner.waf_classifier.requests.post') as post_mock:
        result2 = classify_waf(resp, model="claude-opus-4-6", cache=cache)
    post_mock.assert_not_called()
    assert result2 == result
    print("PASS: test_classify_waf_valid_response_caches")


if __name__ == '__main__':
    test_validator_accepts_valid_payload()
    test_validator_clears_waf_type_when_not_detected()
    test_validator_rejects_bad_confidence()
    test_validator_rejects_bad_waf_type()
    test_validator_rejects_non_dict()
    test_validator_truncates_reasoning()
    test_waf_type_regex_basics()
    test_fingerprint_is_stable_across_dynamic_headers()
    test_fingerprint_changes_on_status_or_server()
    test_classify_waf_none_response_returns_fallback()
    test_classify_waf_cache_hit_skips_post()
    test_classify_waf_agent_timeout_returns_fallback()
    test_classify_waf_agent_500_returns_fallback()
    test_classify_waf_non_json_returns_fallback()
    test_classify_waf_schema_violation_returns_fallback()
    test_classify_waf_valid_response_caches()
    print("\nAll tests passed")
