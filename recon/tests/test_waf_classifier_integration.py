"""
Integration / smoke / regression tests for the WAF AI classifier feature.

Covers the cascade integration in helpers/security_checks.py (the part
test_waf_classifier.py doesn't touch):
- _set_ai_ctx initialization correctness
- _classify_waf_ai filters out the SAFE_FALLBACK source
- _has_cdn_markers static-positive short-circuits AI (no LLM call)
- _has_cdn_markers static-negative + AI off returns False without AI call
- _has_cdn_markers static-negative + AI on respects confidence threshold
- check_waf_bypass static path unchanged when AI is off (regression)
- check_waf_bypass AI cascade fires only when static missed
- check_waf_bypass with AI-WAF-on-IP suppresses the bypass finding
- AI_IN_PIPELINE cascade override behavior in project_settings
- fetch_project_settings maps wafAiClassifier from the project payload
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks as sc
from recon.helpers.ai_planner.waf_classifier import SAFE_FALLBACK
from recon import project_settings as ps


def _reset_ai_ctx():
    """Each test starts with a clean _AI_CTX. Module-level state persists
    across tests so we explicitly reset here."""
    sc._set_ai_ctx(False, "", "", "")


def _mock_response(status_code=200, headers=None, body=b'', text=None, url='https://target.com/'):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.content = body
    resp.text = text if text is not None else (body.decode('utf-8', errors='replace') if isinstance(body, bytes) else str(body))
    resp.url = url
    return resp


# ============================================================================
# _set_ai_ctx
# ============================================================================

def test_set_ai_ctx_disabled_when_no_model():
    sc._set_ai_ctx(True, "", "u", "p")
    assert sc._AI_CTX["enabled"] is False
    assert sc._AI_CTX["cache"] is None
    print("PASS: test_set_ai_ctx_disabled_when_no_model")


def test_set_ai_ctx_disabled_when_flag_off():
    sc._set_ai_ctx(False, "claude-opus-4-6", "u", "p")
    assert sc._AI_CTX["enabled"] is False
    assert sc._AI_CTX["cache"] is None
    print("PASS: test_set_ai_ctx_disabled_when_flag_off")


def test_set_ai_ctx_enabled_creates_fresh_cache():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    assert sc._AI_CTX["enabled"] is True
    assert sc._AI_CTX["cache"] == {}
    # Re-init must clear any prior cache (per-scan freshness).
    sc._AI_CTX["cache"]["dirty"] = "stale"
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    assert sc._AI_CTX["cache"] == {}
    _reset_ai_ctx()
    print("PASS: test_set_ai_ctx_enabled_creates_fresh_cache")


# ============================================================================
# _classify_waf_ai wrapper
# ============================================================================

def test_classify_waf_ai_returns_none_when_disabled():
    _reset_ai_ctx()
    resp = _mock_response()
    assert sc._classify_waf_ai(resp) is None
    print("PASS: test_classify_waf_ai_returns_none_when_disabled")


def test_classify_waf_ai_returns_none_when_response_none():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    assert sc._classify_waf_ai(None) is None
    _reset_ai_ctx()
    print("PASS: test_classify_waf_ai_returns_none_when_response_none")


def test_classify_waf_ai_filters_safe_fallback():
    """When the underlying classifier hits its SAFE_FALLBACK (agent down,
    bad schema), the wrapper must return None so callers fall back to
    the static behavior rather than treat ai_unavailable as 'no WAF'."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response()
    with mock.patch('recon.helpers.ai_planner.waf_classifier.classify_waf',
                    return_value=dict(SAFE_FALLBACK)):
        out = sc._classify_waf_ai(resp)
    assert out is None
    _reset_ai_ctx()
    print("PASS: test_classify_waf_ai_filters_safe_fallback")


def test_classify_waf_ai_returns_real_classification():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response()
    payload = {
        "waf_detected": True, "waf_type": "akamai", "confidence": 88,
        "reasoning": "ref-id pattern", "source": "ai_classifier",
    }
    with mock.patch('recon.helpers.ai_planner.waf_classifier.classify_waf',
                    return_value=payload):
        out = sc._classify_waf_ai(resp)
    assert out == payload
    _reset_ai_ctx()
    print("PASS: test_classify_waf_ai_returns_real_classification")


# ============================================================================
# _has_cdn_markers cascade
# ============================================================================

def test_has_cdn_markers_static_positive_skips_ai():
    """If the static check finds a Server token, the AI must not be called.
    That's the cost guarantee."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response(headers={"Server": "cloudflare"})
    with mock.patch.object(sc, '_classify_waf_ai') as ai_mock:
        result = sc._has_cdn_markers(resp)
    assert result is True
    ai_mock.assert_not_called()
    _reset_ai_ctx()
    print("PASS: test_has_cdn_markers_static_positive_skips_ai")


def test_has_cdn_markers_static_positive_via_header_skips_ai():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response(headers={"CF-RAY": "abcd1234-MIA"})
    with mock.patch.object(sc, '_classify_waf_ai') as ai_mock:
        result = sc._has_cdn_markers(resp)
    assert result is True
    ai_mock.assert_not_called()
    _reset_ai_ctx()
    print("PASS: test_has_cdn_markers_static_positive_via_header_skips_ai")


def test_has_cdn_markers_static_negative_ai_off_returns_false():
    """Regression: existing behavior unchanged when AI is off. The wrapper
    is still invoked but internally early-returns None when AI is disabled,
    so no LLM HTTP call is made."""
    _reset_ai_ctx()
    resp = _mock_response(headers={"Server": "nginx"})
    # Mock the underlying classify_waf to confirm no HTTP-bound call happens.
    with mock.patch('recon.helpers.ai_planner.waf_classifier.classify_waf') as classify_mock:
        result = sc._has_cdn_markers(resp)
    assert result is False
    classify_mock.assert_not_called()
    print("PASS: test_has_cdn_markers_static_negative_ai_off_returns_false")


def test_has_cdn_markers_ai_high_confidence_flips_to_true():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response(headers={"Server": "nginx"})
    with mock.patch.object(sc, '_classify_waf_ai',
                           return_value={"waf_detected": True, "waf_type": "aws_waf", "confidence": 85}):
        result = sc._has_cdn_markers(resp)
    assert result is True
    _reset_ai_ctx()
    print("PASS: test_has_cdn_markers_ai_high_confidence_flips_to_true")


def test_has_cdn_markers_ai_low_confidence_stays_false():
    """Below the 70 threshold the AI verdict is too weak to override the
    static negative."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response(headers={"Server": "nginx"})
    with mock.patch.object(sc, '_classify_waf_ai',
                           return_value={"waf_detected": True, "waf_type": "custom", "confidence": 55}):
        result = sc._has_cdn_markers(resp)
    assert result is False
    _reset_ai_ctx()
    print("PASS: test_has_cdn_markers_ai_low_confidence_stays_false")


def test_has_cdn_markers_ai_says_no_waf_stays_false():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    resp = _mock_response(headers={"Server": "nginx"})
    with mock.patch.object(sc, '_classify_waf_ai',
                           return_value={"waf_detected": False, "waf_type": None, "confidence": 90}):
        result = sc._has_cdn_markers(resp)
    assert result is False
    _reset_ai_ctx()
    print("PASS: test_has_cdn_markers_ai_says_no_waf_stays_false")


def test_has_cdn_markers_none_response():
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    assert sc._has_cdn_markers(None) is False
    _reset_ai_ctx()
    print("PASS: test_has_cdn_markers_none_response")


# ============================================================================
# check_waf_bypass cascade -- AI off (regression: existing behavior)
# ============================================================================

def test_check_waf_bypass_ai_off_static_path_unchanged():
    """Regression: when AI is disabled, the original static logic path
    must produce identical findings to before this change."""
    _reset_ai_ctx()
    sub_resp = _mock_response(status_code=200, headers={"Server": "cloudflare"}, body=b"<html>cf</html>")
    ip_resp = _mock_response(status_code=200, headers={"Server": "nginx"}, body=b"<html>origin</html>")
    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")
    assert result is not None
    assert result["type"] == "waf_bypass"
    assert result["severity"] == "high"
    assert result["detection_method"] == "static_headers"
    assert "waf_type" not in result   # static path doesn't add AI fields
    print("PASS: test_check_waf_bypass_ai_off_static_path_unchanged")


def test_check_waf_bypass_ai_off_no_waf_no_finding():
    """No static WAF on subdomain + dissimilar bodies: no bypass finding."""
    _reset_ai_ctx()
    sub_resp = _mock_response(status_code=200, headers={"Server": "nginx"}, body=b"<html>" + b"x" * 5000 + b"</html>")
    ip_resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"forbidden")
    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")
    assert result is None
    print("PASS: test_check_waf_bypass_ai_off_no_waf_no_finding")


# ============================================================================
# check_waf_bypass cascade -- AI on
# ============================================================================

def test_check_waf_bypass_static_positive_skips_ai():
    """When the static check finds a WAF on the hostname, AI must not be
    invoked. Cost guarantee + identical finding shape to AI-off."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    sub_resp = _mock_response(status_code=200, headers={"Server": "cloudflare"}, body=b"cf")
    ip_resp = _mock_response(status_code=200, headers={"Server": "nginx"}, body=b"origin")
    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]), \
         mock.patch.object(sc, '_classify_waf_ai') as ai_mock:
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")
    assert result is not None
    assert result["detection_method"] == "static_headers"
    ai_mock.assert_not_called()
    _reset_ai_ctx()
    print("PASS: test_check_waf_bypass_static_positive_skips_ai")


def test_check_waf_bypass_ai_detects_waf_on_hostname_only():
    """Static missed the WAF (rebranded headers); AI flags it on the
    hostname. AI says no WAF on IP -> emit AI-source bypass finding."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    sub_resp = _mock_response(status_code=403, headers={"Server": "nginx"},
                               body=b"<html>Attention Required</html>")
    ip_resp = _mock_response(status_code=200, headers={"Server": "nginx"}, body=b"<html>origin</html>")

    def fake_classify(response, response_time_ms=0):
        # Subdomain response = WAF detected high conf; IP response = no WAF.
        if response is sub_resp:
            return {"waf_detected": True, "waf_type": "cloudflare", "confidence": 92,
                    "reasoning": "challenge page", "source": "ai_classifier"}
        return {"waf_detected": False, "waf_type": None, "confidence": 80,
                "reasoning": "plain origin", "source": "ai_classifier"}

    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]), \
         mock.patch.object(sc, '_classify_waf_ai', side_effect=fake_classify):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")

    assert result is not None
    assert result["detection_method"] == "ai_classifier"
    assert result["waf_type"] == "cloudflare"
    assert result["waf_confidence"] == 92
    assert result["ai_reasoning"] == "challenge page"
    assert "AI classifier" in result["evidence"]
    _reset_ai_ctx()
    print("PASS: test_check_waf_bypass_ai_detects_waf_on_hostname_only")


def test_check_waf_bypass_ai_detects_waf_on_both_no_finding():
    """AI flags WAF on hostname AND on the IP -> origin is also protected,
    so this is NOT a bypass and no finding should be emitted."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    sub_resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"blocked")
    ip_resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"blocked")

    def fake_classify(response, response_time_ms=0):
        return {"waf_detected": True, "waf_type": "aws_waf", "confidence": 90,
                "reasoning": "blocked body", "source": "ai_classifier"}

    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]), \
         mock.patch.object(sc, '_classify_waf_ai', side_effect=fake_classify):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")

    assert result is None
    _reset_ai_ctx()
    print("PASS: test_check_waf_bypass_ai_detects_waf_on_both_no_finding")


def test_check_waf_bypass_ai_low_confidence_no_finding():
    """AI flags WAF on hostname but with confidence below threshold ->
    don't promote to a bypass finding."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    sub_resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"403")
    ip_resp = _mock_response(status_code=200, headers={"Server": "nginx"}, body=b"<html>origin</html>")

    def fake_classify(response, response_time_ms=0):
        return {"waf_detected": True, "waf_type": "custom", "confidence": 55,
                "reasoning": "weak signal", "source": "ai_classifier"}

    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]), \
         mock.patch.object(sc, '_classify_waf_ai', side_effect=fake_classify):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")

    # Could still emit "Origin Server Directly Accessible" if bodies are
    # similar enough. With body sizes 3 and 21, the abs(diff) = 18 < 1000,
    # so the fallback "directly accessible" branch fires. That branch
    # predates this change and intentionally has no detection_method/AI
    # fields, so verify they are absent (the AI cascade did NOT promote
    # this to an AI-bypass finding).
    if result is not None:
        assert result.get("detection_method") != "ai_classifier"
        assert "waf_confidence" not in result
        assert "waf_type" not in result
    _reset_ai_ctx()
    print("PASS: test_check_waf_bypass_ai_low_confidence_no_finding")


def test_check_waf_bypass_ai_unavailable_falls_back():
    """If the agent endpoint is down / SAFE_FALLBACK, the wrapper returns
    None and the static path's verdict stands. No false bypass emitted."""
    sc._set_ai_ctx(True, "claude-opus-4-6", "u", "p")
    sub_resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"403")
    ip_resp = _mock_response(status_code=403, headers={"Server": "nginx"}, body=b"403")
    with mock.patch('recon.helpers.security_checks.requests.get',
                    side_effect=[sub_resp, ip_resp]), \
         mock.patch.object(sc, '_classify_waf_ai', return_value=None):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")
    # No static WAF and AI unavailable -> we fall through to the
    # "Origin Server Directly Accessible" branch only if status==200.
    # Both are 403, so no finding.
    assert result is None
    _reset_ai_ctx()
    print("PASS: test_check_waf_bypass_ai_unavailable_falls_back")


# ============================================================================
# project_settings cascade override
# ============================================================================

def test_apply_ai_pipeline_overrides_off_forces_waf_classifier_off():
    settings = ps.DEFAULT_SETTINGS.copy()
    settings['AI_IN_PIPELINE'] = False
    settings['WAF_AI_CLASSIFIER'] = True  # try to subvert the cascade
    settings = ps.apply_ai_pipeline_overrides(settings)
    assert settings['WAF_AI_CLASSIFIER'] is False
    assert settings['FFUF_AI_EXTENSIONS'] is False
    assert settings['NUCLEI_AI_TAGS'] is False
    print("PASS: test_apply_ai_pipeline_overrides_off_forces_waf_classifier_off")


def test_apply_ai_pipeline_overrides_on_forces_waf_classifier_on():
    settings = ps.DEFAULT_SETTINGS.copy()
    settings['AI_IN_PIPELINE'] = True
    settings['WAF_AI_CLASSIFIER'] = False  # try to subvert the cascade
    settings = ps.apply_ai_pipeline_overrides(settings)
    assert settings['WAF_AI_CLASSIFIER'] is True
    assert settings['FFUF_AI_EXTENSIONS'] is True
    assert settings['NUCLEI_AI_TAGS'] is True
    print("PASS: test_apply_ai_pipeline_overrides_on_forces_waf_classifier_on")


def test_default_settings_has_waf_ai_classifier():
    assert 'WAF_AI_CLASSIFIER' in ps.DEFAULT_SETTINGS
    assert ps.DEFAULT_SETTINGS['WAF_AI_CLASSIFIER'] is False
    print("PASS: test_default_settings_has_waf_ai_classifier")


# ============================================================================
# fetch project payload mapping
# ============================================================================

def test_fetch_project_settings_has_waf_ai_classifier_mapping():
    """fetch_project_settings is too coupled to the recon container's
    runtime (graph_db helpers, key rotation imports) to invoke directly
    in a unit test. Instead, verify the source contains the mapping line.
    Pairs with the cascade-override tests above to give end-to-end
    confidence without the runtime coupling."""
    src_path = Path(ps.__file__)
    src = src_path.read_text()
    needle = "settings['WAF_AI_CLASSIFIER'] = project.get('wafAiClassifier'"
    assert needle in src, f"Expected mapping line not found in {src_path}"
    print("PASS: test_fetch_project_settings_has_waf_ai_classifier_mapping")


# ============================================================================
# Smoke test: end-to-end through run_security_checks
# ============================================================================

def test_run_security_checks_initializes_ai_ctx():
    """Calling run_security_checks with ai_classifier_enabled=True must
    set _AI_CTX correctly so downstream check functions see the cascade."""
    _reset_ai_ctx()
    recon = {"domain": "target.com", "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}}, "subdomains": {}}}
    sc.run_security_checks(
        recon_data=recon,
        enabled_checks={},  # nothing enabled, just exercise the entry path
        timeout=1, max_workers=1,
        ai_classifier_enabled=True, ai_model='claude-opus-4-6',
        ai_user_id='u', ai_project_id='p',
    )
    assert sc._AI_CTX["enabled"] is True
    assert sc._AI_CTX["model"] == 'claude-opus-4-6'
    assert sc._AI_CTX["user_id"] == 'u'
    _reset_ai_ctx()
    print("PASS: test_run_security_checks_initializes_ai_ctx")


def test_run_security_checks_disables_ai_ctx_when_off():
    sc._set_ai_ctx(True, 'claude-opus-4-6', 'old', 'old')  # leftover from prior scan
    recon = {"domain": "target.com", "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}}, "subdomains": {}}}
    sc.run_security_checks(
        recon_data=recon, enabled_checks={}, timeout=1, max_workers=1,
        ai_classifier_enabled=False,
    )
    assert sc._AI_CTX["enabled"] is False
    print("PASS: test_run_security_checks_disables_ai_ctx_when_off")


if __name__ == '__main__':
    # Unit: AI ctx
    test_set_ai_ctx_disabled_when_no_model()
    test_set_ai_ctx_disabled_when_flag_off()
    test_set_ai_ctx_enabled_creates_fresh_cache()
    test_classify_waf_ai_returns_none_when_disabled()
    test_classify_waf_ai_returns_none_when_response_none()
    test_classify_waf_ai_filters_safe_fallback()
    test_classify_waf_ai_returns_real_classification()
    # Cascade: _has_cdn_markers
    test_has_cdn_markers_static_positive_skips_ai()
    test_has_cdn_markers_static_positive_via_header_skips_ai()
    test_has_cdn_markers_static_negative_ai_off_returns_false()
    test_has_cdn_markers_ai_high_confidence_flips_to_true()
    test_has_cdn_markers_ai_low_confidence_stays_false()
    test_has_cdn_markers_ai_says_no_waf_stays_false()
    test_has_cdn_markers_none_response()
    # Regression + AI cascade: check_waf_bypass
    test_check_waf_bypass_ai_off_static_path_unchanged()
    test_check_waf_bypass_ai_off_no_waf_no_finding()
    test_check_waf_bypass_static_positive_skips_ai()
    test_check_waf_bypass_ai_detects_waf_on_hostname_only()
    test_check_waf_bypass_ai_detects_waf_on_both_no_finding()
    test_check_waf_bypass_ai_low_confidence_no_finding()
    test_check_waf_bypass_ai_unavailable_falls_back()
    # Cascade override
    test_apply_ai_pipeline_overrides_off_forces_waf_classifier_off()
    test_apply_ai_pipeline_overrides_on_forces_waf_classifier_on()
    test_default_settings_has_waf_ai_classifier()
    # Project payload mapping
    test_fetch_project_settings_has_waf_ai_classifier_mapping()
    # Smoke
    test_run_security_checks_initializes_ai_ctx()
    test_run_security_checks_disables_ai_ctx_when_off()
    print("\nAll integration tests passed")
