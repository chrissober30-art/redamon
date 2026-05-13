"""
Unit tests for recon.helpers.ai_planner.ffuf_extensions.get_ai_extensions().

Verifies:
- Cache hit returns without HTTP/LLM call
- Empty AI response is respected (no fallback)
- HTTP errors fall back to safe defaults
- LLM errors fall back to safe defaults
- Regex validator strips suspicious extensions
- Fingerprint cache key is computed from tech-disclosing headers only
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ai_planner.ffuf_extensions import (
    get_ai_extensions,
    SAFE_FALLBACK,
    _fingerprint,
    _validate_extensions,
    EXT_REGEX,
)


def _mock_head(headers):
    resp = mock.MagicMock()
    resp.headers = headers
    return resp


def _mock_post(extensions=None, status_code=200, raise_exc=None):
    if raise_exc:
        return mock.MagicMock(side_effect=raise_exc)
    resp = mock.MagicMock()
    resp.status_code = status_code
    if extensions is not None:
        resp.json.return_value = {'extensions': extensions}
    else:
        resp.json.side_effect = ValueError("no json")
    resp.text = ''
    return resp


def test_fingerprint_uses_only_tech_headers():
    fp1 = _fingerprint({'Server': 'nginx', 'X-Powered-By': 'PHP/8.1', 'Date': 'now'})
    fp2 = _fingerprint({'Server': 'nginx', 'X-Powered-By': 'PHP/8.1', 'Date': 'later'})
    assert fp1 == fp2, "Fingerprint must ignore Date and other non-tech headers"
    print("PASS: test_fingerprint_uses_only_tech_headers")


def test_validator_rejects_suspicious_strings():
    raw = ['.php', '.bak', '../etc/passwd', '.PHP', '$(rm -rf /)', '.json']
    validated = _validate_extensions(raw)
    assert validated == ['.php', '.bak', '.json']
    print("PASS: test_validator_rejects_suspicious_strings")


def test_ext_regex_basics():
    assert EXT_REGEX.match('.php')
    assert EXT_REGEX.match('.json')
    assert EXT_REGEX.match('.tar')
    assert not EXT_REGEX.match('php')          # missing dot
    assert not EXT_REGEX.match('.PHP')         # uppercase
    assert not EXT_REGEX.match('.php.bak')     # double dot
    assert not EXT_REGEX.match('.toolongextension')
    print("PASS: test_ext_regex_basics")


def test_get_ai_extensions_cache_hit_skips_llm():
    cache = {'Server=nginx|X-Powered-By=PHP/8.1|X-AspNet-Version=|X-AspNetMvc-Version=': ['.php']}
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    return_value=_mock_head({'Server': 'nginx', 'X-Powered-By': 'PHP/8.1'})), \
         mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.post') as post_mock:
        result = get_ai_extensions('https://target.com/', 'claude-opus-4-6', cache=cache)
    assert result == ['.php']
    post_mock.assert_not_called()
    print("PASS: test_get_ai_extensions_cache_hit_skips_llm")


def test_get_ai_extensions_empty_response_is_respected():
    """Empty list from LLM means 'no extensions for this target' -- not fallback."""
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    return_value=_mock_head({'Server': 'nginx'})), \
         mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.post',
                    return_value=_mock_post(extensions=[])):
        result = get_ai_extensions('https://cdn.example.com/static/', 'claude-opus-4-6')
    assert result == [], f"Expected empty list, got {result}"
    print("PASS: test_get_ai_extensions_empty_response_is_respected")


def test_get_ai_extensions_head_error_returns_fallback():
    import requests as req_mod
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    side_effect=req_mod.ConnectionError("dns fail")):
        result = get_ai_extensions('https://dead.example.com/', 'claude-opus-4-6')
    assert result == SAFE_FALLBACK[:6]
    print("PASS: test_get_ai_extensions_head_error_returns_fallback")


def test_get_ai_extensions_agent_500_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    return_value=_mock_head({'Server': 'apache'})), \
         mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.post',
                    return_value=_mock_post(status_code=500)):
        result = get_ai_extensions('https://target.com/', 'claude-opus-4-6')
    assert result == SAFE_FALLBACK[:6]
    print("PASS: test_get_ai_extensions_agent_500_returns_fallback")


def test_get_ai_extensions_agent_invalid_json_returns_fallback():
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    return_value=_mock_head({'Server': 'apache'})), \
         mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.post',
                    return_value=_mock_post(extensions=None, status_code=200)):
        result = get_ai_extensions('https://target.com/', 'claude-opus-4-6')
    assert result == SAFE_FALLBACK[:6]
    print("PASS: test_get_ai_extensions_agent_invalid_json_returns_fallback")


def test_get_ai_extensions_filters_invalid_and_caches():
    cache = {}
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    return_value=_mock_head({'Server': 'apache', 'X-Powered-By': 'PHP/8.1'})), \
         mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.post',
                    return_value=_mock_post(extensions=['.php', '$(rm)', '.bak', '.PHP'])):
        result = get_ai_extensions('https://target.com/', 'claude-opus-4-6', cache=cache)
    assert result == ['.php', '.bak'], f"Expected only valid extensions, got {result}"
    # Cache populated
    assert len(cache) == 1
    # Second call same fingerprint -> cache hit (no post)
    with mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.head',
                    return_value=_mock_head({'Server': 'apache', 'X-Powered-By': 'PHP/8.1'})), \
         mock.patch('recon.helpers.ai_planner.ffuf_extensions.requests.post') as post_mock:
        result2 = get_ai_extensions('https://other.example.com/', 'claude-opus-4-6', cache=cache)
    assert result2 == ['.php', '.bak']
    post_mock.assert_not_called()
    print("PASS: test_get_ai_extensions_filters_invalid_and_caches")


if __name__ == '__main__':
    test_fingerprint_uses_only_tech_headers()
    test_validator_rejects_suspicious_strings()
    test_ext_regex_basics()
    test_get_ai_extensions_cache_hit_skips_llm()
    test_get_ai_extensions_empty_response_is_respected()
    test_get_ai_extensions_head_error_returns_fallback()
    test_get_ai_extensions_agent_500_returns_fallback()
    test_get_ai_extensions_agent_invalid_json_returns_fallback()
    test_get_ai_extensions_filters_invalid_and_caches()
    print("\nAll tests passed")
