"""
Deep-review tests for #3 (Nuclei FP filter) and #5 (Takeover AI cascade).

Focuses on gaps the per-feature suites don't cover:
- Multi-finding cascades (cache reuse across iterations).
- End-to-end is_false_positive going through requests.post (not just
  the wrapper layer).
- HTTP probe robustness (non-RequestException errors must not abort the pass).
- Per-finding error isolation in _apply_ai_waf_disambiguation.
- _execute_nuclei_pass fully wires AI verdicts into the false_positives list.
- Body sample size enforcement when nuclei response is large.
- Settings cascade interaction with stealth mode.
- Module-level state hygiene across multiple run_vuln_scan invocations.
"""
import io
import json
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ai_planner import nuclei_response_filter as nrf
from recon.helpers.ai_planner import takeover_classifier as tc
from recon.helpers.ai_planner.nuclei_response_filter import SAFE_FALLBACK as NRF_FB
from recon.helpers.ai_planner.takeover_classifier import SAFE_FALLBACK as TC_FB
from recon.helpers import nuclei_helpers as nh
from recon.main_recon_modules import subdomain_takeover as st
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


def _finding(response="", template_id="sqli/x", tags=None):
    return {
        "response": response,
        "template-id": template_id,
        "info": {"tags": tags or ["sqli", "injection"]},
    }


# ============================================================================
# #3 — Nuclei FP filter deep-review
# ============================================================================

def test_fp_cascade_caches_across_findings():
    """Two findings with byte-identical block-page responses -> exactly ONE
    LLM call (POST), the second hits the cache."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    body = "HTTP/1.1 403\n\n{\"err\":\"deny\"}"
    f1 = _finding(body, template_id="sqli/a")
    f2 = _finding(body, template_id="sqli/b")
    payload = {"is_blocked": True, "confidence": 90, "reason": "AWS shape"}
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    return_value=_mock_post(payload=payload)) as post_mock:
        is_fp1, _ = nh.is_false_positive(f1)
        is_fp2, _ = nh.is_false_positive(f2)
    assert is_fp1 is True and is_fp2 is True
    assert post_mock.call_count == 1, f"Expected 1 LLM call, got {post_mock.call_count}"
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_caches_across_findings")


def test_fp_cascade_distinct_responses_dont_share_cache():
    """Findings with different fingerprints each cost one LLM call."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    f1 = _finding("HTTP/1.1 403\n\n{\"err\":\"a\"}", template_id="sqli/a")
    f2 = _finding("HTTP/1.1 503\n\n<html>down</html>", template_id="sqli/b")
    payload = {"is_blocked": True, "confidence": 80, "reason": "block"}
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    return_value=_mock_post(payload=payload)) as post_mock:
        nh.is_false_positive(f1)
        nh.is_false_positive(f2)
    assert post_mock.call_count == 2
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_distinct_responses_dont_share_cache")


def test_fp_cascade_full_path_through_requests_post():
    """End-to-end: cascade invokes the helper which POSTs to the agent
    endpoint. Verifies the URL + payload shape."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "alice", "proj-1")
    body = "HTTP/1.1 429\n\nslow down"
    f = _finding(body, template_id="sqli/blind", tags=["sqli", "blind", "injection"])
    captured = {}
    def fake_post(url, json=None, timeout=None):
        captured['url'] = url
        captured['json'] = json
        return _mock_post(payload={"is_blocked": True, "confidence": 80, "reason": "rate limit"})
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    side_effect=fake_post):
        is_fp, reason = nh.is_false_positive(f)
    # NOTE: 429 IS in the rate_limit_indicators list (literally
    # "HTTP/1.1 429"), so the static path actually fires first and the AI
    # cascade never runs. That's the intended layering -- static is cheap
    # and authoritative for known patterns. So this test really verifies
    # the static-precedence guarantee: AI is NOT called when static fires.
    assert is_fp is True
    assert "Rate limiting" in reason
    assert 'url' not in captured, "AI must not be called when static rate-limit indicator matches"
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_full_path_through_requests_post")


def test_fp_cascade_full_path_real_post_when_static_misses():
    """Static misses (no keyword + no rate-limit substring), suspicious
    status 503 + injection tag -> AI cascade runs and the request body
    has the expected shape."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "alice", "proj-1")
    body = "HTTP/1.1 503\n\n<html>boom</html>"
    f = _finding(body, template_id="sqli/error", tags=["sqli", "injection"])
    captured = {}
    def fake_post(url, json=None, timeout=None):
        captured['url'] = url
        captured['json'] = json
        return _mock_post(payload={"is_blocked": True, "confidence": 90, "reason": "503 block"})
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    side_effect=fake_post):
        is_fp, reason = nh.is_false_positive(f)
    assert is_fp is True
    assert "503 block" in reason and "conf=90" in reason
    assert captured['url'].endswith("/llm/nuclei-fp-filter")
    payload = captured['json']
    assert payload['template_id'] == "sqli/error"
    assert payload['tags'] == ["sqli", "injection"]
    assert payload['user_id'] == "alice"
    assert payload['project_id'] == "proj-1"
    assert payload['model'] == "claude-opus-4-6"
    assert payload['response_sample'] == body  # short body, all included
    assert payload['status_line'].startswith("HTTP/1.1 503")
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_full_path_real_post_when_static_misses")


def test_fp_cascade_truncates_large_body():
    """Bodies larger than RESPONSE_SAMPLE_BYTES (4096) must be trimmed
    before the POST so we don't ship megabytes of HTML to the LLM."""
    nh.set_fp_ai_ctx(True, "claude-opus-4-6", "u", "p")
    huge = "HTTP/1.1 503\n\n" + ("A" * 50000)
    f = _finding(huge, template_id="sqli/x")
    captured = {}
    def fake_post(url, json=None, timeout=None):
        captured['json'] = json
        return _mock_post(payload={"is_blocked": True, "confidence": 80, "reason": "x"})
    with mock.patch('recon.helpers.ai_planner.nuclei_response_filter.requests.post',
                    side_effect=fake_post):
        nh.is_false_positive(f)
    sample = captured['json']['response_sample']
    assert len(sample) <= 4096, f"Sample not trimmed: {len(sample)}"
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_truncates_large_body")


def test_set_fp_ai_ctx_disables_clears_cache():
    """Toggling AI off mid-process must drop the cache so the next scan
    starts clean. Otherwise stale verdicts could leak across scans."""
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    nh._FP_AI_CTX["cache"]["fp1"] = {"is_blocked": True, "confidence": 90, "reason": "x", "source": "ai_classifier"}
    nh.set_fp_ai_ctx(False, "m", "u", "p")
    assert nh._FP_AI_CTX["cache"] is None
    print("PASS: test_set_fp_ai_ctx_disables_clears_cache")


def test_fp_cascade_handles_response_field_missing():
    """A nuclei finding with no `response` key must not crash the cascade."""
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    f = {"template-id": "sqli/x", "info": {"tags": ["sqli"]}}  # no "response"
    is_fp, reason = nh.is_false_positive(f)
    assert is_fp is False
    assert reason is None
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_handles_response_field_missing")


def test_fp_cascade_handles_response_none():
    """response=None must not crash."""
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    f = {"response": None, "template-id": "sqli/x", "info": {"tags": ["sqli"]}}
    is_fp, reason = nh.is_false_positive(f)
    assert is_fp is False
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_handles_response_none")


def test_fp_cascade_handles_missing_info():
    """info dict missing should default to no tags -> not injection -> no AI."""
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    f = {"response": "HTTP/1.1 403\n\nx", "template-id": "sqli/x"}  # no info
    is_fp, reason = nh.is_false_positive(f)
    assert is_fp is False
    _reset_fp_ctx()
    print("PASS: test_fp_cascade_handles_missing_info")


def test_fp_cascade_run_vuln_scan_initializes_ctx():
    """The vuln_scan module must call set_fp_ai_ctx with the right flag.
    Spot-check by importing the function symbol -- a missing import would
    fail this test."""
    from recon.main_recon_modules import vuln_scan
    src = Path(vuln_scan.__file__).read_text()
    assert "set_fp_ai_ctx(" in src
    assert "NUCLEI_AI_RESPONSE_FILTER" in src
    print("PASS: test_fp_cascade_run_vuln_scan_initializes_ctx")


# ============================================================================
# #5 — Takeover AI cascade deep-review
# ============================================================================

def test_takeover_disambiguation_caches_across_findings():
    """Two findings against hosts that respond identically -> ONE LLM call."""
    findings = [
        {"hostname": "a.example.com", "takeover_provider": "heroku"},
        {"hostname": "b.example.com", "takeover_provider": "heroku"},
    ]
    body = "<html>blocked</html>"
    payload = {"is_waf_block": True, "confidence": 85, "reason": "shape", "source": "ai_classifier"}
    with mock.patch.object(st, '_probe_for_ai_disambiguation',
                           return_value=(403, {"Server": "nginx"}, body)), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    return_value=_mock_post(payload={"is_waf_block": True, "confidence": 85, "reason": "shape"})) as post_mock:
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    assert post_mock.call_count == 1
    assert findings[0]["ai_waf_likely"] is True and findings[1]["ai_waf_likely"] is True
    print("PASS: test_takeover_disambiguation_caches_across_findings")


def test_takeover_disambiguation_empty_findings():
    """Empty findings list must be a no-op (no error, no probe calls)."""
    with mock.patch.object(st, '_probe_for_ai_disambiguation') as probe_mock:
        st._apply_ai_waf_disambiguation([], model="m", user_id="u", project_id="p")
    probe_mock.assert_not_called()
    print("PASS: test_takeover_disambiguation_empty_findings")


def test_takeover_disambiguation_skips_findings_without_hostname():
    """Findings with empty/None hostname must be skipped without probing."""
    findings = [
        {"hostname": "", "takeover_provider": "heroku"},
        {"hostname": None, "takeover_provider": "heroku"},
        {"takeover_provider": "heroku"},  # no hostname key at all
    ]
    with mock.patch.object(st, '_probe_for_ai_disambiguation') as probe_mock:
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    probe_mock.assert_not_called()
    for f in findings:
        assert "ai_waf_likely" not in f
    print("PASS: test_takeover_disambiguation_skips_findings_without_hostname")


def test_takeover_disambiguation_isolates_per_finding_failures():
    """A probe that crashes on finding 1 must not abort the whole pass --
    finding 2 must still get its AI verdict."""
    findings = [
        {"hostname": "broken.example.com", "takeover_provider": "heroku"},
        {"hostname": "ok.example.com", "takeover_provider": "heroku"},
    ]
    call_count = {"n": 0}
    def probe(hostname, timeout=10):
        call_count["n"] += 1
        if hostname == "broken.example.com":
            raise RuntimeError("simulated weird non-RequestException")
        return 403, {"Server": "nginx"}, "blocked"
    payload = {"is_waf_block": True, "confidence": 85, "reason": "shape", "source": "ai_classifier"}
    with mock.patch.object(st, '_probe_for_ai_disambiguation', side_effect=probe), \
         mock.patch('recon.helpers.ai_planner.takeover_classifier.classify_takeover_response',
                    return_value=payload):
        st._apply_ai_waf_disambiguation(findings, model="m", user_id="u", project_id="p")
    # Probe was called for both
    assert call_count["n"] == 2
    # First finding crashed during probe, no flag
    assert "ai_waf_likely" not in findings[0]
    # Second finding succeeded
    assert findings[1]["ai_waf_likely"] is True
    print("PASS: test_takeover_disambiguation_isolates_per_finding_failures")


def test_takeover_probe_handles_non_request_exception():
    """The probe function must catch arbitrary exceptions, not just
    RequestException."""
    import requests
    with mock.patch('requests.get', side_effect=MemoryError("oom")):
        status, headers, body = st._probe_for_ai_disambiguation("x.example.com", timeout=1)
    assert status is None
    assert headers == {}
    assert body == ""
    print("PASS: test_takeover_probe_handles_non_request_exception")


def test_takeover_probe_falls_back_https_to_http():
    """If HTTPS fails the probe must try HTTP."""
    import requests as req_mod
    https_resp = mock.MagicMock(side_effect=req_mod.exceptions.SSLError("bad cert"))
    http_resp = mock.MagicMock()
    http_resp.status_code = 200
    http_resp.headers = {"Server": "nginx"}
    http_resp.text = "ok"
    call_log = []
    def fake_get(url, **kw):
        call_log.append(url)
        if url.startswith("https://"):
            raise req_mod.exceptions.SSLError("bad cert")
        return http_resp
    with mock.patch('requests.get', side_effect=fake_get):
        status, headers, body = st._probe_for_ai_disambiguation("x.example.com", timeout=1)
    assert status == 200
    assert headers == {"Server": "nginx"}
    assert body == "ok"
    assert call_log[0].startswith("https://")
    assert call_log[1].startswith("http://")
    print("PASS: test_takeover_probe_falls_back_https_to_http")


def test_takeover_probe_caps_body_to_4kb():
    """Probe must trim the response body to <=4KB before returning."""
    import requests as req_mod
    huge_resp = mock.MagicMock()
    huge_resp.status_code = 200
    huge_resp.headers = {}
    huge_resp.text = "X" * 50000
    with mock.patch('requests.get', return_value=huge_resp):
        status, headers, body = st._probe_for_ai_disambiguation("x.example.com", timeout=1)
    assert len(body) <= 4096
    print("PASS: test_takeover_probe_caps_body_to_4kb")


def test_takeover_classify_truncates_large_body():
    """When the body would exceed RESPONSE_SAMPLE_BYTES, the helper must
    trim before POSTing."""
    huge = "B" * 50000
    captured = {}
    def fake_post(url, json=None, timeout=None):
        captured['json'] = json
        return _mock_post(payload={"is_waf_block": True, "confidence": 85, "reason": "x"})
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    side_effect=fake_post):
        tc.classify_takeover_response("h", "heroku", huge, 403, {}, model="m")
    assert len(captured['json']['response_sample']) <= 4096
    print("PASS: test_takeover_classify_truncates_large_body")


def test_takeover_classify_filters_uninteresting_headers():
    """The agent payload only carries identifying headers (Server, x-*,
    cf-*, set-cookie, content-type) -- not arbitrary noise."""
    headers = {
        "Server": "nginx",
        "Content-Type": "text/html",
        "X-Custom-Header": "important",
        "Cf-Ray": "abc-123",
        "Set-Cookie": "abc=def",
        "Date": "Mon, 1 Jan 2026",  # noise -- should be dropped
        "Last-Modified": "earlier",  # noise -- should be dropped
    }
    captured = {}
    def fake_post(url, json=None, timeout=None):
        captured['json'] = json
        return _mock_post(payload={"is_waf_block": True, "confidence": 85, "reason": "x"})
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    side_effect=fake_post):
        tc.classify_takeover_response("h", "heroku", "body", 403, headers, model="m")
    sent = captured['json']['headers']
    assert "Server" in sent and "Cf-Ray" in sent and "X-Custom-Header" in sent
    assert "Date" not in sent and "Last-Modified" not in sent
    print("PASS: test_takeover_classify_filters_uninteresting_headers")


def test_takeover_classify_payload_shape():
    """Verify the agent gets exactly the fields the endpoint expects."""
    captured = {}
    def fake_post(url, json=None, timeout=None):
        captured['url'] = url
        captured['json'] = json
        return _mock_post(payload={"is_waf_block": True, "confidence": 85, "reason": "x"})
    with mock.patch('recon.helpers.ai_planner.takeover_classifier.requests.post',
                    side_effect=fake_post):
        tc.classify_takeover_response(
            hostname="dev.example.com",
            expected_provider="heroku",
            response_text="There's nothing here yet",
            status_code=404,
            headers={"Server": "Cowboy"},
            model="claude-opus-4-6",
            user_id="alice", project_id="proj-1",
        )
    assert captured['url'].endswith("/llm/takeover-classify")
    p = captured['json']
    assert p['hostname'] == "dev.example.com"
    assert p['expected_provider'] == "heroku"
    assert p['status_code'] == 404
    assert p['response_sample'] == "There's nothing here yet"
    assert p['model'] == "claude-opus-4-6"
    assert p['user_id'] == "alice"
    assert p['project_id'] == "proj-1"
    print("PASS: test_takeover_classify_payload_shape")


# ============================================================================
# Settings cascade interplay across all five AI hooks
# ============================================================================

def test_all_five_ai_flags_governed_by_master_cascade():
    """AI_IN_PIPELINE False -> all 5 flags False, even if individually True."""
    settings = {
        'AI_IN_PIPELINE': False,
        'FFUF_AI_EXTENSIONS': True,
        'NUCLEI_AI_TAGS': True,
        'WAF_AI_CLASSIFIER': True,
        'NUCLEI_AI_RESPONSE_FILTER': True,
        'TAKEOVER_AI_CLASSIFIER': True,
    }
    out = ps.apply_ai_pipeline_overrides(settings)
    assert out['FFUF_AI_EXTENSIONS'] is False
    assert out['NUCLEI_AI_TAGS'] is False
    assert out['WAF_AI_CLASSIFIER'] is False
    assert out['NUCLEI_AI_RESPONSE_FILTER'] is False
    assert out['TAKEOVER_AI_CLASSIFIER'] is False
    print("PASS: test_all_five_ai_flags_governed_by_master_cascade")


def test_all_five_ai_flags_forced_on_by_master():
    """AI_IN_PIPELINE True -> all 5 flags True, even if individually False."""
    settings = {
        'AI_IN_PIPELINE': True,
        'FFUF_AI_EXTENSIONS': False,
        'NUCLEI_AI_TAGS': False,
        'WAF_AI_CLASSIFIER': False,
        'NUCLEI_AI_RESPONSE_FILTER': False,
        'TAKEOVER_AI_CLASSIFIER': False,
    }
    out = ps.apply_ai_pipeline_overrides(settings)
    assert out['FFUF_AI_EXTENSIONS'] is True
    assert out['NUCLEI_AI_TAGS'] is True
    assert out['WAF_AI_CLASSIFIER'] is True
    assert out['NUCLEI_AI_RESPONSE_FILTER'] is True
    assert out['TAKEOVER_AI_CLASSIFIER'] is True
    print("PASS: test_all_five_ai_flags_forced_on_by_master")


# ============================================================================
# Module-level state hygiene
# ============================================================================

def test_fp_ctx_isolated_from_takeover_state():
    """The two AI cascades use independent caches -- enabling one must not
    leak state into the other."""
    nh.set_fp_ai_ctx(True, "m", "u", "p")
    # Takeover has no module-level enable flag; its cache is per-call.
    # Sanity: nuclei_helpers state didn't leak into takeover_classifier.
    import recon.helpers.ai_planner.takeover_classifier as t
    # No global cache or enabled flag in the takeover classifier module --
    # caches are per-_apply_ai_waf_disambiguation invocation.
    assert not hasattr(t, "_AI_CTX")
    assert not hasattr(t, "_FP_AI_CTX")
    _reset_fp_ctx()
    print("PASS: test_fp_ctx_isolated_from_takeover_state")


# ============================================================================
# Smoke test: the agent endpoint handlers parse syntactically
# ============================================================================

def test_agent_endpoints_present_in_api():
    """Sanity: the agent file declares the two new endpoints + their
    request models and prompts."""
    import recon  # ensure import works
    api_path = PROJECT_ROOT / "agentic" / "api.py"
    src = api_path.read_text()
    assert "/llm/nuclei-fp-filter" in src
    assert "/llm/takeover-classify" in src
    assert "class NucleiFpFilterRequest" in src
    assert "class TakeoverClassifyRequest" in src
    assert "_NUCLEI_FP_FILTER_SYSTEM_PROMPT" in src
    assert "_TAKEOVER_CLASSIFY_SYSTEM_PROMPT" in src
    print("PASS: test_agent_endpoints_present_in_api")


if __name__ == '__main__':
    # #3 deep-review
    test_fp_cascade_caches_across_findings()
    test_fp_cascade_distinct_responses_dont_share_cache()
    test_fp_cascade_full_path_through_requests_post()
    test_fp_cascade_full_path_real_post_when_static_misses()
    test_fp_cascade_truncates_large_body()
    test_set_fp_ai_ctx_disables_clears_cache()
    test_fp_cascade_handles_response_field_missing()
    test_fp_cascade_handles_response_none()
    test_fp_cascade_handles_missing_info()
    test_fp_cascade_run_vuln_scan_initializes_ctx()
    # #5 deep-review
    test_takeover_disambiguation_caches_across_findings()
    test_takeover_disambiguation_empty_findings()
    test_takeover_disambiguation_skips_findings_without_hostname()
    test_takeover_disambiguation_isolates_per_finding_failures()
    test_takeover_probe_handles_non_request_exception()
    test_takeover_probe_falls_back_https_to_http()
    test_takeover_probe_caps_body_to_4kb()
    test_takeover_classify_truncates_large_body()
    test_takeover_classify_filters_uninteresting_headers()
    test_takeover_classify_payload_shape()
    # Cross-cutting
    test_all_five_ai_flags_governed_by_master_cascade()
    test_all_five_ai_flags_forced_on_by_master()
    test_fp_ctx_isolated_from_takeover_state()
    test_agent_endpoints_present_in_api()
    print("\nAll deep-review tests passed")
