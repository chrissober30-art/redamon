"""
Unit tests for recon.helpers.ai_planner.nuclei_tags.

Verifies:
- _load_candidates() reads/caches/falls back correctly (count threshold, regex
  filtering, dedup/sort, fallback when file is missing or malformed).
- _validate_tags() strips invalid types, regex-failing strings, and tags not
  in the candidate set (prompt-injection defense).
- get_ai_tags() honours all failure modes:
    * empty fingerprint + no fallback urls -> short-circuit to current_tags
    * empty fingerprint + fallback urls -> opportunistic HEAD probe
    * LLM 503 / 502 / non-JSON / missing 'tags' / non-list -> current_tags
    * all returned tags rejected by validation -> current_tags
      (NOT empty list, which would skip the detection pass entirely)
    * max_tags is enforced after validation
- All fallback paths return ``current_tags`` (never raise, never empty).
"""
import json
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Important: reset module-level cache between tests.
import recon.helpers.ai_planner.nuclei_tags as nt
from recon.helpers.ai_planner.nuclei_tags import (
    _validate_tags,
    get_ai_tags,
    TAG_REGEX,
    _FALLBACK_CANDIDATES,
)


def _reset_candidates_cache():
    nt._candidates_cache = None


def _mock_resp(json_data=None, status_code=200, raise_json=False):
    resp = mock.MagicMock()
    resp.status_code = status_code
    if raise_json:
        resp.json.side_effect = ValueError("bad json")
    else:
        resp.json.return_value = json_data
    resp.text = ''
    return resp


def _mock_head(server=None, x_powered_by=None):
    headers = {}
    if server is not None:
        headers['Server'] = server
    if x_powered_by is not None:
        headers['X-Powered-By'] = x_powered_by
    resp = mock.MagicMock()
    resp.headers = headers
    return resp


# ---------- TAG_REGEX ----------

def test_tag_regex_accepts_valid():
    for tag in ['cve', 'xss', 'wp-plugin', 'cve2024', 'default-login', 'oast']:
        assert TAG_REGEX.match(tag), f"{tag!r} should match"
    print("PASS: test_tag_regex_accepts_valid")


def test_tag_regex_rejects_invalid():
    bad = [
        'CVE',                      # uppercase
        'a',                        # too short
        'a' * 31,                   # too long
        '../etc/passwd',            # traversal
        'foo,bar',                  # comma
        'rm -rf /',                 # spaces
        'inj"ect',                  # quote
        '',                         # empty
        'tag.with.dots',            # dots
    ]
    for tag in bad:
        assert not TAG_REGEX.match(tag), f"{tag!r} should NOT match"
    print("PASS: test_tag_regex_rejects_invalid")


# ---------- _load_candidates() ----------

def test_load_candidates_uses_fallback_when_file_missing(tmp_path=None):
    _reset_candidates_cache()
    with mock.patch.object(nt, 'TEMPLATES_STATS_PATH', '/nonexistent/path.json'):
        result = nt._load_candidates()
    assert result == list(_FALLBACK_CANDIDATES)
    print("PASS: test_load_candidates_uses_fallback_when_file_missing")


def test_load_candidates_uses_fallback_on_malformed_json(tmp_path):
    _reset_candidates_cache()
    bad_file = tmp_path / "stats.json"
    bad_file.write_text("not-json{{{")
    with mock.patch.object(nt, 'TEMPLATES_STATS_PATH', str(bad_file)):
        result = nt._load_candidates()
    assert result == list(_FALLBACK_CANDIDATES)
    print("PASS: test_load_candidates_uses_fallback_on_malformed_json")


def test_load_candidates_filters_by_count_and_regex(tmp_path):
    _reset_candidates_cache()
    stats_file = tmp_path / "stats.json"
    stats_file.write_text(json.dumps({
        "tags": [
            {"name": "cve", "count": 4000},
            {"name": "xss", "count": 1000},
            {"name": "rare-tag", "count": 49},     # below threshold
            {"name": "wordpress", "count": 1500},
            {"name": "BAD_UPPER", "count": 500},   # regex fail (uppercase + underscore)
            {"name": "../traversal", "count": 500},  # regex fail
            {"name": "wordpress", "count": 200},   # dup -> coalesced
        ]
    }))
    with mock.patch.object(nt, 'TEMPLATES_STATS_PATH', str(stats_file)):
        result = nt._load_candidates()
    assert result == ['cve', 'wordpress', 'xss']
    print("PASS: test_load_candidates_filters_by_count_and_regex")


def test_load_candidates_caches_across_calls(tmp_path):
    _reset_candidates_cache()
    stats_file = tmp_path / "stats.json"
    stats_file.write_text(json.dumps({
        "tags": [{"name": "cve", "count": 100}]
    }))
    with mock.patch.object(nt, 'TEMPLATES_STATS_PATH', str(stats_file)):
        first = nt._load_candidates()
        # Now point to nonexistent path; cache should still serve old result
        with mock.patch.object(nt, 'TEMPLATES_STATS_PATH', '/gone'):
            second = nt._load_candidates()
    assert first == second == ['cve']
    print("PASS: test_load_candidates_caches_across_calls")


def test_load_candidates_handles_missing_tags_key(tmp_path):
    _reset_candidates_cache()
    stats_file = tmp_path / "stats.json"
    stats_file.write_text(json.dumps({"authors": []}))  # no 'tags' key
    with mock.patch.object(nt, 'TEMPLATES_STATS_PATH', str(stats_file)):
        result = nt._load_candidates()
    # Empty stats.tags + no fallback trigger (file IS readable) -> empty list
    # _validate_tags will then reject everything in get_ai_tags, which is
    # exactly the behavior we want (caller falls back to current_tags).
    assert result == []
    print("PASS: test_load_candidates_handles_missing_tags_key")


# ---------- _validate_tags() ----------

def test_validate_tags_filters_non_strings():
    out = _validate_tags(['cve', 123, None, 'xss'], ['cve', 'xss'])
    assert out == ['cve', 'xss']
    print("PASS: test_validate_tags_filters_non_strings")


def test_validate_tags_rejects_non_candidates():
    """Critical security boundary: model cannot inject tags outside the universe."""
    out = _validate_tags(
        ['cve', 'wordpress', 'evil-injected-tag'],
        candidates=['cve', 'wordpress', 'xss'],
    )
    assert out == ['cve', 'wordpress']
    print("PASS: test_validate_tags_rejects_non_candidates")


def test_validate_tags_rejects_regex_failing():
    out = _validate_tags(
        ['cve', '../etc/passwd', 'BAD_UPPER', 'rm -rf'],
        candidates=['cve', '../etc/passwd', 'BAD_UPPER', 'rm -rf'],
    )
    assert out == ['cve']
    print("PASS: test_validate_tags_rejects_regex_failing")


def test_validate_tags_preserves_order():
    out = _validate_tags(['xss', 'cve', 'rce'], candidates=['cve', 'rce', 'xss'])
    assert out == ['xss', 'cve', 'rce']
    print("PASS: test_validate_tags_preserves_order")


# ---------- get_ai_tags() ----------

def test_get_ai_tags_empty_fingerprint_no_fallback_skips_llm():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve', 'xss']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post') as post_mock:
        result = get_ai_tags(
            tech_fingerprint={'technologies': [], 'servers': []},
            current_tags=['cve', 'xss', 'sqli'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss', 'sqli']
    post_mock.assert_not_called()
    print("PASS: test_get_ai_tags_empty_fingerprint_no_fallback_skips_llm")


def test_get_ai_tags_empty_fingerprint_head_probe_succeeds():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve', 'apache', 'wordpress']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.head',
                    return_value=_mock_head(server='Apache/2.4.52', x_powered_by='PHP/8.1')), \
         mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['cve', 'apache']})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': [], 'servers': []},
            current_tags=['cve', 'xss'],
            model='claude-haiku-4-5',
            fallback_urls=['https://example.com/'],
        )
    assert result == ['cve', 'apache']
    print("PASS: test_get_ai_tags_empty_fingerprint_head_probe_succeeds")


def test_get_ai_tags_head_probe_total_failure_returns_current():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    import requests as req_mod
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.head',
                    side_effect=req_mod.ConnectionError("dns fail")), \
         mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post') as post_mock:
        result = get_ai_tags(
            tech_fingerprint={'technologies': [], 'servers': []},
            current_tags=['cve', 'xss', 'sqli'],
            model='claude-haiku-4-5',
            fallback_urls=['https://dead.example/', 'https://other.dead/'],
        )
    assert result == ['cve', 'xss', 'sqli']
    post_mock.assert_not_called()
    print("PASS: test_get_ai_tags_head_probe_total_failure_returns_current")


def test_get_ai_tags_llm_503_returns_current():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve', 'xss']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(status_code=503)):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['wordpress'], 'servers': ['apache']},
            current_tags=['cve', 'xss', 'sqli'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss', 'sqli']
    print("PASS: test_get_ai_tags_llm_503_returns_current")


def test_get_ai_tags_llm_malformed_json_returns_current():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(raise_json=True, status_code=200)):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss']
    print("PASS: test_get_ai_tags_llm_malformed_json_returns_current")


def test_get_ai_tags_llm_missing_tags_key_returns_current():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'wrong_key': []})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss']
    print("PASS: test_get_ai_tags_llm_missing_tags_key_returns_current")


def test_get_ai_tags_llm_non_list_tags_returns_current():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': 'not-a-list'})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss']
    print("PASS: test_get_ai_tags_llm_non_list_tags_returns_current")


def test_get_ai_tags_network_error_returns_current():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    import requests as req_mod
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    side_effect=req_mod.ConnectionError("agent down")):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss', 'sqli'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss', 'sqli']
    print("PASS: test_get_ai_tags_network_error_returns_current")


def test_get_ai_tags_all_rejected_returns_current_not_empty():
    """Critical: if validation strips everything (e.g. model returned tags
    outside candidates), we MUST fall back to current_tags. Returning an
    empty list would skip the entire detection pass."""
    _reset_candidates_cache()
    nt._candidates_cache = ['cve', 'xss']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['evil', 'INJECTED', '../etc']})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['wordpress'], 'servers': []},
            current_tags=['cve', 'xss', 'sqli'],
            model='claude-haiku-4-5',
        )
    assert result == ['cve', 'xss', 'sqli'], \
        f"All-invalid should fall back to current, got {result}"
    print("PASS: test_get_ai_tags_all_rejected_returns_current_not_empty")


def test_get_ai_tags_max_tags_enforced():
    _reset_candidates_cache()
    nt._candidates_cache = ['cve', 'xss', 'sqli', 'rce', 'lfi']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['cve', 'xss', 'sqli', 'rce', 'lfi']})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve'],
            model='claude-haiku-4-5',
            max_tags=3,
        )
    assert result == ['cve', 'xss', 'sqli']
    print("PASS: test_get_ai_tags_max_tags_enforced")


def test_get_ai_tags_respects_agent_api_url_env():
    """The helper must honour AGENT_API_URL so the recon container can reach
    the agent across the docker network."""
    import os as _os
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    captured = {}
    def _fake_post(url, json, timeout):
        captured['url'] = url
        return _mock_resp(json_data={'tags': ['cve']})
    with mock.patch.dict(_os.environ, {'AGENT_API_URL': 'http://agent.docker:8090'}, clear=False), \
         mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post', side_effect=_fake_post):
        get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve'],
            model='claude-haiku-4-5',
        )
    assert captured.get('url') == 'http://agent.docker:8090/llm/nuclei-tags', \
        f"Endpoint should use AGENT_API_URL, got {captured.get('url')}"
    print("PASS: test_get_ai_tags_respects_agent_api_url_env")


def test_get_ai_tags_head_probe_caps_at_limit():
    """HEAD_PROBE_LIMIT=5 must cap the number of URLs probed even if many are
    passed, so a partial-recon scan with 100 user URLs doesn't fan out 100
    HEAD requests."""
    _reset_candidates_cache()
    nt._candidates_cache = ['cve']
    head_calls = []
    def _fake_head(url, allow_redirects, timeout):
        head_calls.append(url)
        return _mock_head(server='Apache')
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.head', side_effect=_fake_head), \
         mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['cve']})):
        get_ai_tags(
            tech_fingerprint={'technologies': [], 'servers': []},
            current_tags=['cve'],
            model='claude-haiku-4-5',
            fallback_urls=[f'https://h{i}.example.com/' for i in range(20)],
        )
    assert len(head_calls) == 5, \
        f"Expected exactly HEAD_PROBE_LIMIT=5 probes, got {len(head_calls)}"
    print("PASS: test_get_ai_tags_head_probe_caps_at_limit")


def test_get_ai_tags_success_round_trip():
    """End-to-end happy path: fingerprint -> POST -> validate -> return."""
    _reset_candidates_cache()
    nt._candidates_cache = ['cve', 'xss', 'sqli', 'wordpress', 'apache', 'php']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={
                        'tags': ['cve', 'wordpress', 'apache', 'php', 'xss']
                    })) as post_mock:
        result = get_ai_tags(
            tech_fingerprint={
                'technologies': ['wordpress 6.4', 'php 8.1'],
                'servers': ['apache'],
            },
            current_tags=['cve', 'xss', 'sqli'],
            model='claude-haiku-4-5',
            user_id='u1',
            project_id='p1',
        )
    assert result == ['cve', 'wordpress', 'apache', 'php', 'xss']
    # Confirm payload structure
    call_args = post_mock.call_args
    payload = call_args.kwargs['json']
    assert payload['technologies'] == ['php 8.1', 'wordpress 6.4']  # sorted dedup
    assert payload['servers'] == ['apache']
    assert payload['user_id'] == 'u1'
    assert payload['project_id'] == 'p1'
    assert payload['model'] == 'claude-haiku-4-5'
    print("PASS: test_get_ai_tags_success_round_trip")


# ---------- _build_tech_fingerprint() (lives in vuln_scan.py) ----------

def test_build_tech_fingerprint_empty():
    from recon.main_recon_modules.vuln_scan import _build_tech_fingerprint
    fp = _build_tech_fingerprint({})
    assert fp == {'technologies': [], 'servers': []}
    print("PASS: test_build_tech_fingerprint_empty")


def test_build_tech_fingerprint_aggregates_from_by_url():
    from recon.main_recon_modules.vuln_scan import _build_tech_fingerprint
    fp = _build_tech_fingerprint({
        'by_url': {
            'https://a.example.com': {
                'technologies': ['WordPress 6.4', 'PHP 8.1'],
                'server': 'Apache/2.4.52',
            },
            'https://b.example.com': {
                'technologies': ['jQuery 3.6', 'WordPress 6.4'],  # dup
                'server': 'nginx/1.20',
            },
        }
    })
    # Lowercased, deduped, sorted
    assert fp['technologies'] == ['jquery 3.6', 'php 8.1', 'wordpress 6.4']
    # Server header split on slash, lowercased
    assert fp['servers'] == ['apache', 'nginx']
    print("PASS: test_build_tech_fingerprint_aggregates_from_by_url")


def test_build_tech_fingerprint_unions_technologies_found():
    from recon.main_recon_modules.vuln_scan import _build_tech_fingerprint
    fp = _build_tech_fingerprint({
        'by_url': {
            'https://x': {'technologies': ['WordPress'], 'server': 'apache'},
        },
        'technologies_found': {
            'WordPress': ['https://x'],
            'PHP 8.1': ['https://x'],
            'CloudFlare': ['https://y'],
        }
    })
    # technologies_found keys are unioned in (lowercased)
    assert 'wordpress' in fp['technologies']
    assert 'php 8.1' in fp['technologies']
    assert 'cloudflare' in fp['technologies']
    print("PASS: test_build_tech_fingerprint_unions_technologies_found")


def test_build_tech_fingerprint_handles_missing_keys():
    from recon.main_recon_modules.vuln_scan import _build_tech_fingerprint
    # Entries without 'technologies' or 'server' should not crash
    fp = _build_tech_fingerprint({
        'by_url': {
            'https://bare.example.com': {'url': 'https://bare.example.com'},
            'https://partial.example.com': {'server': ''},  # empty server skipped
        }
    })
    assert fp == {'technologies': [], 'servers': []}
    print("PASS: test_build_tech_fingerprint_handles_missing_keys")


def test_build_tech_fingerprint_none_technologies_list():
    """Defensive: by_url entries can have technologies=None (httpx sometimes does)."""
    from recon.main_recon_modules.vuln_scan import _build_tech_fingerprint
    fp = _build_tech_fingerprint({
        'by_url': {'https://x': {'technologies': None, 'server': None}}
    })
    assert fp == {'technologies': [], 'servers': []}
    print("PASS: test_build_tech_fingerprint_none_technologies_list")


if __name__ == '__main__':
    test_tag_regex_accepts_valid()
    test_tag_regex_rejects_invalid()
    test_load_candidates_uses_fallback_when_file_missing()
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        from pathlib import Path as _P
        test_load_candidates_uses_fallback_on_malformed_json(_P(d))
        test_load_candidates_filters_by_count_and_regex(_P(d))
        test_load_candidates_caches_across_calls(_P(d))
        test_load_candidates_handles_missing_tags_key(_P(d))
    test_validate_tags_filters_non_strings()
    test_validate_tags_rejects_non_candidates()
    test_validate_tags_rejects_regex_failing()
    test_validate_tags_preserves_order()
    test_get_ai_tags_empty_fingerprint_no_fallback_skips_llm()
    test_get_ai_tags_empty_fingerprint_head_probe_succeeds()
    test_get_ai_tags_head_probe_total_failure_returns_current()
    test_get_ai_tags_llm_503_returns_current()
    test_get_ai_tags_llm_malformed_json_returns_current()
    test_get_ai_tags_llm_missing_tags_key_returns_current()
    test_get_ai_tags_llm_non_list_tags_returns_current()
    test_get_ai_tags_network_error_returns_current()
    test_get_ai_tags_all_rejected_returns_current_not_empty()
    test_get_ai_tags_max_tags_enforced()
    test_get_ai_tags_respects_agent_api_url_env()
    test_get_ai_tags_head_probe_caps_at_limit()
    test_get_ai_tags_success_round_trip()
    test_build_tech_fingerprint_empty()
    test_build_tech_fingerprint_aggregates_from_by_url()
    test_build_tech_fingerprint_unions_technologies_found()
    test_build_tech_fingerprint_handles_missing_keys()
    test_build_tech_fingerprint_none_technologies_list()
    print("\nAll tests passed")
