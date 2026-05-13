"""
Unit + integration tests for the Subdomain Takeover AI cascade.

Covers:
- recon/helpers/ai_planner/takeover_classifier.py (the helper + vendor short-circuit)
- the disambiguation pass _apply_ai_waf_disambiguation in subdomain_takeover.py
- score_finding penalty for ai_waf_likely
- settings cascade
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ai_planner.takeover_classifier import (
    classify_takeover_response,
    has_third_party_vendor_token,
    SAFE_FALLBACK,
    _fingerprint,
    _validate_classification,
)
from recon.helpers.takeover_helpers import score_finding
from recon.main_recon_modules import subdomain_takeover as st
from recon import project_settings as ps


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


# ============================================================================
# Vendor token short-circuit
# ============================================================================

def test_vendor_token_heroku_header():
    assert has_third_party_vendor_token({"Heroku-Request-Id": "abc-123"}) is True
    print("PASS: test_vendor_token_heroku_header")


def test_vendor_token_aws_s3_header():
    assert has_third_party_vendor_token({"x-amz-bucket-region": "us-east-1"}) is True
    assert has_third_party_vendor_token({"Server": "AmazonS3"}) is True
    print("PASS: test_vendor_token_aws_s3_header")


def test_vendor_token_github_pages():
    assert has_third_party_vendor_token({"Server": "GitHub.com"}) is True
    print("PASS: test_vendor_token_github_pages")


def test_vendor_token_netlify_vercel():
    assert has_third_party_vendor_token({"Server": "Netlify"}) is True
    assert has_third_party_vendor_token({"x-vercel-id": "fra1::abc"}) is True
    print("PASS: test_vendor_token_netlify_vercel")


def test_no_vendor_token_on_generic_response():
    assert has_third_party_vendor_token({"Server": "nginx"}) is False
    assert has_third_party_vendor_token({}) is False
    assert has_third_party_vendor_token(None) is False
    print("PASS: test_no_vendor_token_on_generic_response")


def test_vendor_token_case_insensitive():
    assert has_third_party_vendor_token({"server": "amazons3"}) is True
    assert has_third_party_vendor_token({"HEROKU-REQUEST-ID": "x"}) is True
    print("PASS: test_vendor_token_case_insensitive")


# ============================================================================
# Validator
# ============================================================================

def test_validator_accepts_valid_payload():
    raw = {"is_waf_block": True, "confidence": 88, "reason": "WAF Ray ID present"}
    out = _validate_classification(raw)
    assert out is not None
    assert out["is_waf_block"] is True
    assert out["confidence"] == 88
    assert out["source"] == "ai_classifier"
    print("PASS: test_validator_accepts_valid_payload")


def test_validator_rejects_bad_types():
    assert _validate_classification({"is_waf_block": "yes", "confidence": 80}) is None
    assert _validate_classification({"is_waf_block": True, "confidence": "high"}) is None
    assert _validate_classification({"is_waf_block": True, "confidence": 200}) is None
    assert _validate_classification({"is_waf_block": True, "confidence": -5}) is None
    print("PASS: test_validator_rejects_bad_types")


def test_validator_rejects_non_dict():
    assert _validate_classification([]) is None
    assert _validate_classification("nope") is None
    assert _validate_classification(None) is None
    print("PASS: test_validator_rejects_non_dict")


# ============================================================================
# Fingerprint
# ============================================================================

def test_fingerprint_stable_across_dynamic_content():
    a = _fingerprint("There's nothing here yet", 404)
    b = _fingerprint("There's nothing here yet", 404)
    assert a == b
    print("PASS: test_fingerprint_stable_across_dynamic_content")


def test_fingerprint_changes_on_status_or_body():
    base = _fingerprint("Heroku page", 404)
    diff_status = _fingerprint("Heroku page", 403)
    diff_body = _fingerprint("AWS WAF block", 404)
    assert base != diff_status
    assert base != diff_body
    print("PASS: test_fingerprint_changes_on_status_or_body")


# ============================================================================
# classify_takeover_response cascade
# ============================================================================

def test_classify_empty_body_returns_fallback():
    out = classify_takeover_response("h", "heroku", "", 404, {}, model="m")
    assert out == SAFE_FALLBACK
    print("PASS: test_classify_empty_body_returns_fallback")


def test_classify_cache_hit_skips_post():
    body = "blocked"
    cached = {"is_waf_block": True, "confidence": 85, "reason": "cached", "source": "ai_classifier"}
    cache = {_fingerprint(body, 403): cached}
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post') as post_mock:
        out = classify_takeover_response("h", "heroku", body, 403, {}, model="m", cache=cache)
    assert out == cached
    post_mock.assert_not_called()
    print("PASS: test_classify_cache_hit_skips_post")


def test_classify_agent_timeout_returns_fallback():
    import requests as req_mod
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    side_effect=req_mod.Timeout("agent slow")):
        out = classify_takeover_response("h", "heroku", "body", 404, {}, model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_agent_timeout_returns_fallback")


def test_classify_agent_500_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    return_value=_mock_post(status_code=500)):
        out = classify_takeover_response("h", "heroku", "body", 404, {}, model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_agent_500_returns_fallback")


def test_classify_non_json_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    return_value=_mock_post(payload=None)):
        out = classify_takeover_response("h", "heroku", "body", 404, {}, model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_non_json_returns_fallback")


def test_classify_schema_violation_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    return_value=_mock_post(payload={"is_waf_block": "maybe", "confidence": 999})):
        out = classify_takeover_response("h", "heroku", "body", 404, {}, model="m")
    assert out["source"] == "ai_unavailable"
    print("PASS: test_classify_schema_violation_returns_fallback")


def test_classify_valid_response_caches():
    cache = {}
    payload = {"is_waf_block": True, "confidence": 90, "reason": "Cloudflare Ray ID"}
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    return_value=_mock_post(payload=payload)):
        out = classify_takeover_response("h", "heroku", "body", 403, {}, model="m", cache=cache)
    assert out["is_waf_block"] is True
    assert out["confidence"] == 90
    assert len(cache) == 1
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post') as post_mock:
        out2 = classify_takeover_response("h", "heroku", "body", 403, {}, model="m", cache=cache)
    post_mock.assert_not_called()
    assert out2 == out
    print("PASS: test_classify_valid_response_caches")


# ============================================================================
# score_finding penalty for ai_waf_likely
# ============================================================================

def test_score_finding_demoted_by_ai_waf_likely():
    """A multi-tool-confirmed Heroku finding (high score = confirmed) should
    drop in score when ai_waf_likely=True is added, ideally enough to demote
    the verdict at the default threshold."""
    base = {
        "hostname": "x.example.com",
        "takeover_provider": "heroku",
        "takeover_method": "cname",
        # Two-source confirm + auto-exploitable + cname = max-confidence finding
        "sources": ["subjack", "nuclei_takeover"],
    }
    confirmed = score_finding(dict(base), confidence_threshold=60)
    # Without AI flag: 30(2+ tools) + 25(subjack) + 15(nuclei) + 20(auto-exploit) + 10(cname) = 100
    assert confirmed["verdict"] == "confirmed"
    assert confirmed["confidence"] == 100

    base_with_ai = dict(base)
    base_with_ai["ai_waf_likely"] = True
    demoted = score_finding(base_with_ai, confidence_threshold=60)
    # With AI flag: 100 - 40 = 60. Verdict "likely" (>= threshold), one bucket
    # below "confirmed". The 40-point penalty proves the cascade can move the
    # needle even on the strongest possible static signal.
    assert demoted["confidence"] == 60
    assert demoted["verdict"] == "likely"
    assert demoted["confidence"] < confirmed["confidence"]
    print("PASS: test_score_finding_demoted_by_ai_waf_likely")


def test_score_finding_ai_demotes_weaker_to_manual_review():
    """A single-tool finding that lands as 'likely' without the AI flag
    drops to manual_review when ai_waf_likely=True is set."""
    base = {
        "hostname": "x.example.com",
        "takeover_provider": "heroku",
        "takeover_method": "cname",
        "sources": ["subjack"],
    }
    # 25(subjack) + 20(auto-exploit) + 10(cname) = 55 -> manual_review at threshold 60
    # but threshold 50 -> likely. Use 50 to give the static path a "likely" verdict.
    likely = score_finding(dict(base), confidence_threshold=50)
    assert likely["verdict"] == "likely"
    # With AI flag: 55 - 40 = 15 -> manual_review
    base_with_ai = dict(base)
    base_with_ai["ai_waf_likely"] = True
    demoted = score_finding(base_with_ai, confidence_threshold=50)
    assert demoted["verdict"] == "manual_review"
    print("PASS: test_score_finding_ai_demotes_weaker_to_manual_review")


def test_score_finding_ai_flag_absent_unchanged():
    """Regression: if ai_waf_likely is unset, the score must equal the
    legacy score (no penalty applied)."""
    base = {
        "hostname": "x.example.com",
        "takeover_provider": "heroku",
        "takeover_method": "cname",
        "sources": ["subjack"],
    }
    a = score_finding(dict(base))
    base2 = dict(base)
    base2["ai_waf_likely"] = False  # explicit false should also not penalize
    b = score_finding(base2)
    assert a["confidence"] == b["confidence"]
    print("PASS: test_score_finding_ai_flag_absent_unchanged")


# ============================================================================
# _apply_ai_waf_disambiguation cascade
# ============================================================================

def test_disambiguation_skips_when_probe_fails():
    """If the hostname probe fails (NXDOMAIN, connection refused), the
    finding is left untouched -- static signal stands."""
    findings = [{"hostname": "dead.example.com", "takeover_provider": "heroku"}]
    with mock.patch.object(st, '_probe_for_ai_disambiguation', return_value=(None, {}, "")), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response') as classify_mock:
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert "ai_waf_likely" not in findings[0]
    classify_mock.assert_not_called()
    print("PASS: test_disambiguation_skips_when_probe_fails")


def test_disambiguation_short_circuits_on_vendor_token():
    """When the response carries an unambiguous third-party vendor token,
    the AI is not called -- the finding is genuinely from the SaaS."""
    findings = [{"hostname": "h.example.com", "takeover_provider": "heroku"}]
    with mock.patch.object(st, '_probe_for_ai_disambiguation',
                           return_value=(404, {"Heroku-Request-Id": "abc"}, "There's nothing here yet")), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response') as classify_mock:
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert "ai_waf_likely" not in findings[0]
    classify_mock.assert_not_called()
    print("PASS: test_disambiguation_short_circuits_on_vendor_token")


def test_disambiguation_flags_finding_when_ai_says_waf():
    """No vendor token + AI says WAF block at confidence >= 70 -> the
    finding gets ai_waf_likely=True and confidence/reasoning fields."""
    findings = [{"hostname": "h.example.com", "takeover_provider": "heroku"}]
    payload = {
        "is_waf_block": True, "confidence": 85,
        "reason": "Cloudflare challenge body shape", "source": "ai_classifier",
    }
    with mock.patch.object(st, '_probe_for_ai_disambiguation',
                           return_value=(403, {"Server": "nginx"}, "<html>blocked</html>")), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response',
                    return_value=payload):
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert findings[0]["ai_waf_likely"] is True
    assert findings[0]["ai_confidence"] == 85
    assert "Cloudflare" in findings[0]["ai_reasoning"]
    print("PASS: test_disambiguation_flags_finding_when_ai_says_waf")


def test_disambiguation_no_flag_when_ai_says_real():
    """AI says NOT a WAF block -> finding stays without ai_waf_likely."""
    findings = [{"hostname": "h.example.com", "takeover_provider": "heroku"}]
    payload = {
        "is_waf_block": False, "confidence": 90,
        "reason": "Heroku-branded unclaimed page", "source": "ai_classifier",
    }
    with mock.patch.object(st, '_probe_for_ai_disambiguation',
                           return_value=(404, {"Server": "nginx"}, "There's nothing here yet")), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response',
                    return_value=payload):
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert "ai_waf_likely" not in findings[0]
    print("PASS: test_disambiguation_no_flag_when_ai_says_real")


def test_disambiguation_no_flag_below_threshold():
    """AI says WAF but confidence < 70 -> no flag (avoid demoting a real
    takeover on a weak AI signal)."""
    findings = [{"hostname": "h.example.com", "takeover_provider": "heroku"}]
    payload = {
        "is_waf_block": True, "confidence": 55,
        "reason": "ambiguous shape", "source": "ai_classifier",
    }
    with mock.patch.object(st, '_probe_for_ai_disambiguation',
                           return_value=(403, {"Server": "nginx"}, "blocked")), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response',
                    return_value=payload):
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert "ai_waf_likely" not in findings[0]
    print("PASS: test_disambiguation_no_flag_below_threshold")


def test_disambiguation_skips_when_ai_unavailable():
    """If the classifier hits SAFE_FALLBACK (source=ai_unavailable), the
    cascade returns nothing and the finding stays as a static signal."""
    findings = [{"hostname": "h.example.com", "takeover_provider": "heroku"}]
    with mock.patch.object(st, '_probe_for_ai_disambiguation',
                           return_value=(403, {"Server": "nginx"}, "x")), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response',
                    return_value=dict(SAFE_FALLBACK)):
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert "ai_waf_likely" not in findings[0]
    print("PASS: test_disambiguation_skips_when_ai_unavailable")


# ============================================================================
# Settings cascade
# ============================================================================

def test_default_settings_has_takeover_ai_classifier():
    assert 'TAKEOVER_AI_CLASSIFIER' in ps.DEFAULT_SETTINGS
    assert ps.DEFAULT_SETTINGS['TAKEOVER_AI_CLASSIFIER'] is False
    print("PASS: test_default_settings_has_takeover_ai_classifier")


def test_cascade_off_forces_takeover_ai_off():
    settings = ps.DEFAULT_SETTINGS.copy()
    settings['AI_IN_PIPELINE'] = False
    settings['TAKEOVER_AI_CLASSIFIER'] = True
    settings = ps.apply_ai_pipeline_overrides(settings)
    assert settings['TAKEOVER_AI_CLASSIFIER'] is False
    print("PASS: test_cascade_off_forces_takeover_ai_off")


def test_cascade_on_forces_takeover_ai_on():
    settings = ps.DEFAULT_SETTINGS.copy()
    settings['AI_IN_PIPELINE'] = True
    settings['TAKEOVER_AI_CLASSIFIER'] = False
    settings = ps.apply_ai_pipeline_overrides(settings)
    assert settings['TAKEOVER_AI_CLASSIFIER'] is True
    print("PASS: test_cascade_on_forces_takeover_ai_on")


def test_fetch_project_settings_mapping_present():
    src = Path(ps.__file__).read_text()
    needle = "settings['TAKEOVER_AI_CLASSIFIER'] = project.get('takeoverAiClassifier'"
    assert needle in src
    print("PASS: test_fetch_project_settings_mapping_present")


if __name__ == '__main__':
    # Vendor short-circuit
    test_vendor_token_heroku_header()
    test_vendor_token_aws_s3_header()
    test_vendor_token_github_pages()
    test_vendor_token_netlify_vercel()
    test_no_vendor_token_on_generic_response()
    test_vendor_token_case_insensitive()
    # Validator
    test_validator_accepts_valid_payload()
    test_validator_rejects_bad_types()
    test_validator_rejects_non_dict()
    # Fingerprint
    test_fingerprint_stable_across_dynamic_content()
    test_fingerprint_changes_on_status_or_body()
    # classify_takeover_response
    test_classify_empty_body_returns_fallback()
    test_classify_cache_hit_skips_post()
    test_classify_agent_timeout_returns_fallback()
    test_classify_agent_500_returns_fallback()
    test_classify_non_json_returns_fallback()
    test_classify_schema_violation_returns_fallback()
    test_classify_valid_response_caches()
    # score_finding
    test_score_finding_demoted_by_ai_waf_likely()
    test_score_finding_ai_demotes_weaker_to_manual_review()
    test_score_finding_ai_flag_absent_unchanged()
    # _apply_ai_waf_disambiguation
    test_disambiguation_skips_when_probe_fails()
    test_disambiguation_short_circuits_on_vendor_token()
    test_disambiguation_flags_finding_when_ai_says_waf()
    test_disambiguation_no_flag_when_ai_says_real()
    test_disambiguation_no_flag_below_threshold()
    test_disambiguation_skips_when_ai_unavailable()
    # Settings cascade
    test_default_settings_has_takeover_ai_classifier()
    test_cascade_off_forces_takeover_ai_off()
    test_cascade_on_forces_takeover_ai_on()
    test_fetch_project_settings_mapping_present()
    print("\nAll tests passed")
