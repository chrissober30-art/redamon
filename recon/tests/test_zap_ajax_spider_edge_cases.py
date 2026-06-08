"""
Additional unit tests for ZAP Ajax Spider helpers covering edge cases
not exercised by the original test_zap_ajax_spider.py suite.

Focus areas:
- Sensitive output redaction (critical for log safety)
- YAML plan-builder escaping and reject-on-invalid-header
- URL filtering edges (unlimited cap, invalid regex, no scope)
- Export URL extraction (HTML entities, trailing punctuation)
- Debug env var parsing
- Merge tolerance for malformed URLs
- Mask helper input validation
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


def _load_zap_module():
    module_path = (
        Path(__file__).resolve().parents[1]
        / "helpers"
        / "resource_enum"
        / "zap_ajax_spider_helpers.py"
    )
    spec = importlib.util.spec_from_file_location("zap_ajax_spider_helpers_edge", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -----------------------------------------------------------
# _redact_sensitive_output
# -----------------------------------------------------------

def test_redact_sensitive_output_replaces_all_header_values():
    zap = _load_zap_module()
    headers = [
        {"name": "Authorization", "value": "Bearer eyJhbGc.secret-token"},
        {"name": "Cookie", "value": "session=abc123"},
    ]
    raw = (
        "INFO: outgoing request with Bearer eyJhbGc.secret-token\n"
        "DEBUG: cookie header session=abc123 set\n"
        "ERROR: timeout after Bearer eyJhbGc.secret-token retry"
    )
    redacted = zap._redact_sensitive_output(raw, headers)
    assert "secret-token" not in redacted
    assert "session=abc123" not in redacted
    # Three replacements expected
    assert redacted.count("***") == 3


def test_redact_sensitive_output_empty_inputs():
    zap = _load_zap_module()
    assert zap._redact_sensitive_output("", []) == ""
    assert zap._redact_sensitive_output(None, []) == ""
    assert zap._redact_sensitive_output("plain text", []) == "plain text"


def test_redact_sensitive_output_ignores_blank_header_values():
    zap = _load_zap_module()
    headers = [{"name": "X-Empty", "value": ""}, {"name": "Token", "value": "real"}]
    out = zap._redact_sensitive_output("token=real and empty=", headers)
    assert "real" not in out
    # Empty value must not over-replace
    assert out.count("***") == 1


# -----------------------------------------------------------
# YAML plan builder safety
# -----------------------------------------------------------

def test_plan_rejects_header_with_whitespace_in_name():
    zap = _load_zap_module()
    with pytest.raises(ValueError, match="Invalid ZAP Ajax header"):
        zap.build_zap_ajax_automation_plan(
            seed_url="https://app.example.com",
            export_file_name="export.txt",
            headers=[{"name": "Bad Header", "value": "value"}],
        )


def test_plan_rejects_header_with_control_chars_in_value():
    zap = _load_zap_module()
    with pytest.raises(ValueError, match="Invalid ZAP Ajax header"):
        zap.build_zap_ajax_automation_plan(
            seed_url="https://app.example.com",
            export_file_name="export.txt",
            headers=[{"name": "Authorization", "value": "Bearer\x00token"}],
        )


def test_plan_emits_empty_rules_array_when_no_headers():
    zap = _load_zap_module()
    plan = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com",
        export_file_name="export.txt",
        headers=[],
    )
    assert "rules: []" in plan
    # Replacer job still present
    assert 'type: "replacer"' in plan


def test_plan_escapes_double_quotes_in_header_value():
    zap = _load_zap_module()
    headers = [{"name": "X-Token", "value": 'a"quoted"value'}]
    plan = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com",
        export_file_name="export.txt",
        headers=headers,
    )
    # Escaped double-quotes in YAML output
    assert r'\"quoted\"' in plan


def test_plan_lowercases_logout_avoidance_boolean():
    zap = _load_zap_module()
    plan_on = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com",
        export_file_name="export.txt",
        logout_avoidance=True,
    )
    plan_off = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com",
        export_file_name="export.txt",
        logout_avoidance=False,
    )
    assert "logoutAvoidance: true" in plan_on
    assert "logoutAvoidance: false" in plan_off


def test_plan_export_path_uses_basename_only():
    zap = _load_zap_module()
    # Even if caller passes a path, only basename should land in fileName
    plan = zap.build_zap_ajax_automation_plan(
        seed_url="https://app.example.com",
        export_file_name="/host/path/export.txt",
    )
    assert 'fileName: "/zap/wrk/export.txt"' in plan


# -----------------------------------------------------------
# filter_zap_ajax_urls edge cases
# -----------------------------------------------------------

def test_filter_max_urls_zero_means_unlimited():
    zap = _load_zap_module()
    urls = [f"https://app.example.com/path{i}" for i in range(2000)]
    filtered, meta = zap.filter_zap_ajax_urls(
        urls, allowed_hosts={"app.example.com"}, exclude_patterns=[], max_urls=0,
    )
    assert len(filtered) == 2000
    assert meta["max_url_dropped"] == 0


def test_filter_no_scope_allows_any_host():
    """Empty allowed_hosts means no scope filtering - all valid URLs accepted."""
    zap = _load_zap_module()
    filtered, meta = zap.filter_zap_ajax_urls(
        ["https://anywhere.com/api", "https://other.org/x"],
        allowed_hosts=set(),
        exclude_patterns=[],
        max_urls=100,
    )
    assert len(filtered) == 2
    assert meta["out_of_scope"] == 0


def test_filter_invalid_regex_is_tolerated():
    """An invalid regex in exclude_patterns should not crash; the bad pattern is just skipped."""
    zap = _load_zap_module()
    filtered, meta = zap.filter_zap_ajax_urls(
        ["https://app.example.com/users"],
        allowed_hosts={"app.example.com"},
        exclude_patterns=["[invalid(regex", "/users"],  # first is bad, second is valid
        max_urls=100,
    )
    # /users matched the valid second pattern, so it's excluded
    assert filtered == []
    assert meta["invalid_exclude_patterns"] == 1
    assert meta["excluded_by_pattern"] == 1


def test_filter_strips_dangerous_url_endings_via_html_unescape():
    """HTML entities in URLs should be decoded before comparison."""
    zap = _load_zap_module()
    filtered, meta = zap.filter_zap_ajax_urls(
        ["https://app.example.com/page?a=1&amp;b=2"],
        allowed_hosts={"app.example.com"},
        exclude_patterns=[],
        max_urls=100,
    )
    # The &amp; should decode to & so URL is parseable as having two query params
    assert len(filtered) == 1
    assert "&amp;" not in filtered[0]


def test_filter_records_dropped_url_metadata_without_leaking_values():
    """dropped_urls metadata must not contain raw query values."""
    zap = _load_zap_module()
    _filtered, meta = zap.filter_zap_ajax_urls(
        ["https://other.com/admin?token=SECRET"],
        allowed_hosts={"app.example.com"},
        exclude_patterns=[],
        max_urls=100,
    )
    drops = meta["dropped_urls"]
    assert len(drops) >= 1
    for d in drops:
        # The URL detail must not contain the raw query value
        assert "SECRET" not in d.get("url", "")


# -----------------------------------------------------------
# parse_zap_ajax_export_urls
# -----------------------------------------------------------

def test_parse_export_urls_strips_trailing_punctuation(tmp_path):
    zap = _load_zap_module()
    f = tmp_path / "urls.txt"
    f.write_text(
        "https://app.example.com/a).\n"
        "<a href=\"https://app.example.com/b\"/>\n"
        "https://app.example.com/c;\n"
    )
    urls = zap.parse_zap_ajax_export_urls(f)
    assert "https://app.example.com/a" in urls
    assert "https://app.example.com/b" in urls
    assert "https://app.example.com/c" in urls
    # No trailing punctuation should remain
    for u in urls:
        assert not u.endswith(("(", ")", ".", ";", "]"))


def test_parse_export_urls_html_unescapes_amps(tmp_path):
    zap = _load_zap_module()
    f = tmp_path / "urls.txt"
    f.write_text("Found: https://app.example.com/x?a=1&amp;b=2 in payload\n")
    urls = zap.parse_zap_ajax_export_urls(f)
    assert urls == ["https://app.example.com/x?a=1&b=2"]


def test_parse_export_urls_handles_missing_file(tmp_path):
    zap = _load_zap_module()
    urls = zap.parse_zap_ajax_export_urls(tmp_path / "does-not-exist.txt")
    assert urls == []


def test_parse_export_urls_deduplicates_preserving_order(tmp_path):
    zap = _load_zap_module()
    f = tmp_path / "urls.txt"
    f.write_text(
        "https://app.example.com/a\n"
        "https://app.example.com/b\n"
        "https://app.example.com/a\n"
    )
    urls = zap.parse_zap_ajax_export_urls(f)
    assert urls == ["https://app.example.com/a", "https://app.example.com/b"]


# -----------------------------------------------------------
# Debug env var
# -----------------------------------------------------------

def test_debug_env_var_truthy_values(monkeypatch):
    zap = _load_zap_module()
    for v in ("1", "true", "TRUE", "yes", "on", "  ON  "):
        monkeypatch.setenv("REDAMON_ZAP_AJAX_DEBUG", v)
        assert zap._zap_ajax_debug_enabled() is True, f"Failed for {v!r}"


def test_debug_env_var_falsy_values(monkeypatch):
    zap = _load_zap_module()
    for v in ("0", "false", "FALSE", "no", "off", "", "anything-else"):
        monkeypatch.setenv("REDAMON_ZAP_AJAX_DEBUG", v)
        assert zap._zap_ajax_debug_enabled() is False, f"Failed for {v!r}"


def test_debug_env_var_unset(monkeypatch):
    zap = _load_zap_module()
    monkeypatch.delenv("REDAMON_ZAP_AJAX_DEBUG", raising=False)
    assert zap._zap_ajax_debug_enabled() is False


# -----------------------------------------------------------
# mask_zap_ajax_header_line input validation
# -----------------------------------------------------------

def test_mask_returns_triple_star_for_invalid_input():
    zap = _load_zap_module()
    assert zap.mask_zap_ajax_header_line("not a header") == "***"
    assert zap.mask_zap_ajax_header_line(": no name") == "***"
    assert zap.mask_zap_ajax_header_line("name: ") == "***"
    assert zap.mask_zap_ajax_header_line("") == "***"


def test_mask_handles_header_with_colon_in_value():
    """Headers like Date: 2026-05-28 14:30:00 must split only on first colon."""
    zap = _load_zap_module()
    assert zap.mask_zap_ajax_header_line("Date: 2026-05-28 14:30:00") == "Date: ***"


# -----------------------------------------------------------
# merge tolerance
# -----------------------------------------------------------

def test_merge_skips_malformed_urls():
    zap = _load_zap_module()
    existing = {}
    merged, stats = zap.merge_zap_ajax_into_by_base_url(
        ["not-a-url", "ftp://bad.com/x", "https://good.example.com/api"],
        existing,
    )
    assert stats["zap_ajax_spider_total"] == 3
    assert stats["zap_ajax_spider_parsed"] == 1  # only the good one
    assert stats["zap_ajax_spider_new"] == 1
    assert "https://good.example.com" in merged


def test_merge_handles_empty_input():
    zap = _load_zap_module()
    merged, stats = zap.merge_zap_ajax_into_by_base_url([], {})
    assert merged == {}
    assert stats["zap_ajax_spider_total"] == 0
    assert stats["zap_ajax_spider_parsed"] == 0


def test_merge_appends_source_when_url_already_exists_from_different_tool():
    zap = _load_zap_module()
    existing = {
        "https://app.example.com": {
            "base_url": "https://app.example.com",
            "endpoints": {
                "/api": {
                    "path": "/api", "methods": ["GET"],
                    "parameters": {"query": [], "body": [], "path": []},
                    "parameter_count": {"query": 0, "body": 0, "path": 0, "total": 0},
                    "category": "api", "sources": ["hakrawler"],
                    "sample_urls": ["https://app.example.com/api"], "urls_found": 1,
                },
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0,
                        "methods": {"GET": 1}, "categories": {"api": 1}},
        },
    }
    merged, stats = zap.merge_zap_ajax_into_by_base_url(
        ["https://app.example.com/api"], existing,
    )
    assert stats["zap_ajax_spider_overlap"] == 1
    sources = merged["https://app.example.com"]["endpoints"]["/api"]["sources"]
    assert "hakrawler" in sources
    assert "zap_ajax_spider" in sources


# -----------------------------------------------------------
# Header parsing edge cases not covered by original tests
# -----------------------------------------------------------

def test_header_parsing_strips_whitespace_around_name_and_value():
    zap = _load_zap_module()
    parsed, invalid = zap.parse_zap_ajax_header_lines(["  X-Token  :   abc123  "])
    assert invalid == ["  X-Token  :   abc123  "]


def test_header_parsing_accepts_empty_input():
    zap = _load_zap_module()
    parsed, invalid = zap.parse_zap_ajax_header_lines([])
    assert parsed == []
    assert invalid == []
    parsed, invalid = zap.parse_zap_ajax_header_lines(None)
    assert parsed == []
    assert invalid == []


def test_header_parsing_treats_whitespace_only_lines_as_skipped():
    zap = _load_zap_module()
    parsed, invalid = zap.parse_zap_ajax_header_lines(["   ", "\t\n", "Authorization: x"])
    assert len(parsed) == 1
    assert invalid == []  # whitespace lines are silently skipped, not flagged


# -----------------------------------------------------------
# Port allocator
# -----------------------------------------------------------

def test_port_allocator_returns_distinct_ports_across_calls():
    zap = _load_zap_module()
    # We can't guarantee strict distinct without holding sockets, but two consecutive
    # calls on a quiet system should rarely collide.
    p1 = zap._allocate_zap_proxy_port()
    p2 = zap._allocate_zap_proxy_port()
    assert isinstance(p1, int) and isinstance(p2, int)
    assert 1024 < p1 < 65536
    assert 1024 < p2 < 65536
