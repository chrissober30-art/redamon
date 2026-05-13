"""
Tests for the CDN false-positive filter on Direct IP Access checks.

Covers cases 1, 2, 3 of the FP analysis:
    1. Naabu-flagged CDN IP                  -> port_scan.by_ip[ip].is_cdn
    2. httpx-flagged CDN URL                 -> http_probe.by_url[url].is_cdn
    3. Cloudflare edge IP                    -> prefix list, ASN, response markers

Test pyramid:
    Unit        - cdn_ranges helpers in isolation
    Integration - run_direct_ip_checks + check_direct_ip_* with mocked HTTP
    End-to-end  - run_security_checks against synthetic recon_data
    Smoke       - imports, edge inputs (None, empty, malformed)
    Regression  - non-CDN paths still produce findings as before

Run:
    docker exec redamon-recon-orchestrator python -m pytest \
        /app/recon/tests/test_cdn_filter.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import cdn_ranges as cr
from recon.helpers.cdn_ranges import (
    CDN_ASNS,
    RELIABLE_EDGE_CDN_NAMES,
    cdn_name_from_asn,
    collect_asn_cdn_ips,
    collect_prefix_cdn_ips,
    collect_reliable_edge_ips,
    extract_asn_number,
    is_cloudflare_ip,
    is_reliable_edge_cdn_name,
    response_is_cdn_edge,
)

# Capture the real fetch helper BEFORE the autouse fixture replaces it,
# so live-fetch tests can opt back in.
_REAL_FETCH_PREFIX_LIST = cr._fetch_prefix_list
from recon.helpers.security_checks import (
    _has_cdn_markers,
    _is_bare_origin_match,
    check_direct_ip_http,
    check_direct_ip_https,
    check_ip_api_exposed,
    run_direct_ip_checks,
    run_security_checks,
)


# Force the lazy prefix loader to use the hardcoded fallback so tests do not
# hit the network. Each test that touches is_cloudflare_ip resets this fixture.
@pytest.fixture(autouse=True)
def _force_prefix_fallback(monkeypatch):
    cr._cloudflare_networks_cache = None
    monkeypatch.setattr(cr, "_fetch_prefix_list", lambda *_a, **_kw: [])
    yield
    cr._cloudflare_networks_cache = None


def _mock_response(status=200, headers=None, body=""):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = body
    return r


# ===========================================================================
# UNIT - extract_asn_number
# ===========================================================================

class TestExtractAsnNumber:
    @pytest.mark.parametrize("value,expected", [
        (13335, 13335),
        ("13335", 13335),
        ("AS13335", 13335),
        ("as13335", 13335),
        ("AS13335 Cloudflare, Inc.", 13335),
        ("AS54113 Fastly", 54113),
        (" 209242 ", 209242),
    ])
    def test_parses_valid(self, value, expected):
        assert extract_asn_number(value) == expected

    @pytest.mark.parametrize("value", [None, "", "   ", "AS", "no-numbers", []])
    def test_returns_none_for_invalid(self, value):
        assert extract_asn_number(value) is None


# ===========================================================================
# UNIT - cdn_name_from_asn
# ===========================================================================

class TestCdnNameFromAsn:
    def test_cloudflare_primary_asn(self):
        assert cdn_name_from_asn(13335) == "cloudflare"
        assert cdn_name_from_asn("AS13335") == "cloudflare"

    def test_cloudflare_secondary_asn(self):
        assert cdn_name_from_asn(209242) == "cloudflare"

    def test_unknown_asn_returns_none(self):
        # Phase 1 is Cloudflare-only; Fastly should NOT match.
        assert cdn_name_from_asn(54113) is None
        assert cdn_name_from_asn("AS16509") is None

    def test_invalid_inputs_return_none(self):
        assert cdn_name_from_asn(None) is None
        assert cdn_name_from_asn("") is None
        assert cdn_name_from_asn("garbage") is None

    def test_phase1_scope_is_cloudflare_only(self):
        # Guard against accidental CDN_ASNS expansion that would change
        # behavior for cases 4-7. This test is meant to fail loudly when
        # Phase 2 lands and is updated explicitly.
        assert set(CDN_ASNS.values()) == {"cloudflare"}


# ===========================================================================
# UNIT - is_cloudflare_ip (uses hardcoded fallback prefixes)
# ===========================================================================

class TestIsCloudflareIp:
    @pytest.mark.parametrize("ip", [
        "104.16.0.1",      # 104.16.0.0/13 (covers 104.16-23)
        "104.23.255.254",  # last addr in 104.16.0.0/13
        "104.27.5.5",      # inside 104.24.0.0/14 (covers 104.24-27)
        "172.64.0.1",      # 172.64.0.0/13
        "131.0.72.1",      # 131.0.72.0/22
        "173.245.48.1",    # 173.245.48.0/20
    ])
    def test_v4_in_published_range(self, ip):
        assert is_cloudflare_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "104.28.0.1",      # outside both /13 and /14, intentionally NOT CF
        "104.31.255.254",  # same gap
    ])
    def test_v4_in_cf_gap_returns_false(self, ip):
        # Cloudflare publishes 104.16/13 + 104.24/14 — there is a gap from
        # 104.28-31 that legitimately belongs to other AWS-region orgs,
        # not Cloudflare. Ensure we do not over-block.
        assert is_cloudflare_ip(ip) is False

    @pytest.mark.parametrize("ip", [
        "2606:4700::1",
        "2400:cb00::dead",
        "2c0f:f248::1",
    ])
    def test_v6_in_published_range(self, ip):
        assert is_cloudflare_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "1.1.1.1",          # CF DNS resolver, not in edge prefixes
        "8.8.8.8",
        "192.168.1.1",
        "10.0.0.5",
        "2001:db8::1",
    ])
    def test_outside_range(self, ip):
        assert is_cloudflare_ip(ip) is False

    @pytest.mark.parametrize("bad", ["", "not-an-ip", "999.999.999.999", None])
    def test_malformed_returns_false(self, bad):
        # Should not raise even on garbage input.
        assert is_cloudflare_ip(bad or "") is False


# ===========================================================================
# UNIT - response_is_cdn_edge
# ===========================================================================

class TestResponseIsCdnEdge:
    def test_cf_ray_header(self):
        r = _mock_response(200, {"CF-RAY": "abc123-LHR"})
        assert response_is_cdn_edge(r) == "cloudflare"

    def test_cf_cache_status_header(self):
        r = _mock_response(200, {"cf-cache-status": "HIT"})
        assert response_is_cdn_edge(r) == "cloudflare"

    def test_server_header(self):
        r = _mock_response(200, {"Server": "cloudflare"})
        assert response_is_cdn_edge(r) == "cloudflare"

    def test_server_header_case_insensitive(self):
        r = _mock_response(200, {"server": "Cloudflare"})
        assert response_is_cdn_edge(r) == "cloudflare"

    def test_body_marker_with_suspicious_status(self):
        r = _mock_response(403, {}, "Error 1003 / Direct IP access not allowed")
        assert response_is_cdn_edge(r) == "cloudflare"

    def test_body_marker_with_unsuspicious_status_does_not_match(self):
        # Body inspection only runs for 400/403/404/421/409. A 200 with
        # CDN error text in it (highly unusual) must not false-positive.
        r = _mock_response(200, {}, "Error 1003 / Direct IP access not allowed")
        assert response_is_cdn_edge(r) is None

    def test_no_markers_returns_none(self):
        r = _mock_response(200, {"Server": "nginx"}, "<html>hello</html>")
        assert response_is_cdn_edge(r) is None

    def test_empty_response_returns_none(self):
        r = _mock_response(200, {}, "")
        assert response_is_cdn_edge(r) is None

    def test_none_input(self):
        assert response_is_cdn_edge(None) is None

    def test_body_read_failure_does_not_crash(self):
        # response.text raising must not propagate.
        r = MagicMock()
        r.status_code = 403
        r.headers = {}
        type(r).text = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
        assert response_is_cdn_edge(r) is None


# ===========================================================================
# UNIT - collect_asn_cdn_ips / collect_prefix_cdn_ips
# ===========================================================================

class TestCollectAsnCdnIps:
    def test_http_probe_cdn_asn(self):
        recon = {"http_probe": {"by_url": {
            "https://x/": {"ip": "1.2.3.4", "asn": "AS13335 Cloudflare, Inc."},
            "https://y/": {"ip": "5.6.7.8", "asn": "AS54113 Fastly"},
        }}}
        assert collect_asn_cdn_ips(recon) == {"1.2.3.4"}

    def test_port_scan_cdn_asn(self):
        recon = {"port_scan": {"by_ip": {
            "9.9.9.9": {"asn": 13335},
            "8.8.8.8": {"asn": 15169},
        }}}
        assert collect_asn_cdn_ips(recon) == {"9.9.9.9"}

    def test_mixed_sources_unioned(self):
        recon = {
            "http_probe": {"by_url": {"u": {"ip": "1.1.1.1", "asn": "AS13335"}}},
            "port_scan": {"by_ip": {"2.2.2.2": {"asn": "AS209242"}}},
        }
        assert collect_asn_cdn_ips(recon) == {"1.1.1.1", "2.2.2.2"}

    def test_missing_keys_does_not_crash(self):
        assert collect_asn_cdn_ips({}) == set()
        assert collect_asn_cdn_ips({"http_probe": None, "port_scan": None}) == set()

    def test_entries_without_ip_are_ignored(self):
        recon = {"http_probe": {"by_url": {"u": {"asn": "AS13335"}}}}
        assert collect_asn_cdn_ips(recon) == set()


class TestCollectPrefixCdnIps:
    def test_filters_cloudflare_only(self):
        ips = ["104.16.0.5", "1.1.1.1", "8.8.8.8", "172.64.5.5"]
        assert collect_prefix_cdn_ips(ips) == {"104.16.0.5", "172.64.5.5"}

    def test_empty_input(self):
        assert collect_prefix_cdn_ips([]) == set()

    def test_handles_falsy_entries(self):
        assert collect_prefix_cdn_ips([None, "", "104.16.0.1"]) == {"104.16.0.1"}


# ===========================================================================
# INTEGRATION - check_direct_ip_http / _https response gating
# ===========================================================================

class TestCheckDirectIpHttpFingerprint:
    def test_skips_finding_on_cf_ray(self):
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"CF-RAY": "abc-LHR"}, "")
            assert check_direct_ip_http("203.0.113.5", timeout=1) is None

    def test_skips_finding_on_server_cloudflare(self):
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "cloudflare"}, "")
            assert check_direct_ip_https("203.0.113.5", timeout=1) is None

    def test_skips_finding_on_body_error_1003(self):
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(
                403, {"Server": "cloudflare"},
                "Error 1003 Direct IP access not allowed"
            )
            assert check_direct_ip_http("203.0.113.5", timeout=1) is None


class TestCheckIpApiExposedFingerprint:
    def test_skips_when_cdn_response(self):
        # Even though /api would normally trigger a 401/JSON path, the CDN
        # marker should short-circuit before the finding is built.
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(
                401, {"CF-RAY": "abc", "Content-Type": "application/json"}, ""
            )
            assert check_ip_api_exposed("203.0.113.5", timeout=1) is None


# ===========================================================================
# INTEGRATION - run_direct_ip_checks prefilter
# ===========================================================================

class TestRunDirectIpChecksPrefilter:
    def test_cdn_ips_are_not_probed(self):
        """IPs in cdn_ips must not trigger any HTTP probe calls."""
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            findings = run_direct_ip_checks(
                ips=["1.2.3.4"],
                subdomains_to_ips={},
                enabled_checks={
                    "direct_ip_http": True,
                    "direct_ip_https": True,
                    "ip_api_exposed": True,
                    "waf_bypass": False,
                },
                timeout=1,
                max_workers=1,
                cdn_ips={"1.2.3.4"},
            )
        assert findings == []
        assert mock_get.call_count == 0

    def test_non_cdn_ip_still_probes(self):
        """IPs not in cdn_ips proceed to probe normally."""
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            findings = run_direct_ip_checks(
                ips=["203.0.113.10"],
                subdomains_to_ips={},
                enabled_checks={
                    "direct_ip_http": True,
                    "direct_ip_https": False,
                    "ip_api_exposed": False,
                    "waf_bypass": False,
                },
                timeout=1,
                max_workers=1,
                cdn_ips=set(),
            )
        # at least one HTTP probe issued
        assert mock_get.call_count >= 1
        assert any(f["type"] == "direct_ip_http" for f in findings)

    def test_cdn_ips_default_none_does_not_crash(self):
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.side_effect = Exception("network down")
            findings = run_direct_ip_checks(
                ips=["203.0.113.10"],
                subdomains_to_ips={},
                enabled_checks={"direct_ip_http": True},
                timeout=1,
                max_workers=1,
            )
        assert findings == []

    def test_waf_bypass_skips_cdn_ips(self):
        with patch(
            "recon.helpers.security_checks.check_waf_bypass"
        ) as mock_waf:
            mock_waf.return_value = None
            run_direct_ip_checks(
                ips=[],
                subdomains_to_ips={"foo.example.com": ["1.2.3.4"]},
                enabled_checks={"waf_bypass": True},
                timeout=1,
                max_workers=1,
                cdn_ips={"1.2.3.4"},
            )
            assert mock_waf.call_count == 0


# ===========================================================================
# END-TO-END - run_security_checks builds cdn_ips and skips probing
# ===========================================================================

class TestRunSecurityChecksEndToEnd:
    def _recon_data(self, ip, *, is_cdn=False, asn=None):
        return {
            "domain": "example.com",
            "dns": {
                "domain": {
                    "ips": {"ipv4": [ip], "ipv6": []},
                    "has_records": True,
                },
                "subdomains": {},
            },
            "port_scan": {
                "by_ip": {ip: {"is_cdn": is_cdn, "cdn": "cloudflare" if is_cdn else None, "asn": asn}}
            } if (is_cdn or asn) else {"by_ip": {}},
            "http_probe": {"by_url": {}},
        }

    def _enabled(self):
        # Only direct_ip_http to keep the test focused; everything else off.
        return {
            "direct_ip_http": True,
            "direct_ip_https": False,
            "ip_api_exposed": False,
            "waf_bypass": False,
        }

    def test_naabu_cdn_ip_yields_no_finding(self):
        recon = self._recon_data("104.16.99.99", is_cdn=True)
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            result = run_security_checks(
                recon_data=recon, enabled_checks=self._enabled(),
                timeout=1, max_workers=1,
            )
        assert mock_get.call_count == 0
        findings = result.get("security_checks", {}).get("findings", [])
        assert all(f.get("matched_ip") != "104.16.99.99" for f in findings)

    def test_cloudflare_prefix_ip_yields_no_finding(self):
        # No is_cdn flag set, but the IP is in a published Cloudflare prefix.
        recon = self._recon_data("104.16.50.50", is_cdn=False)
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            run_security_checks(
                recon_data=recon, enabled_checks=self._enabled(),
                timeout=1, max_workers=1,
            )
        assert mock_get.call_count == 0

    def test_cloudflare_asn_ip_yields_no_finding(self):
        # No is_cdn flag, IP outside published prefix, but ASN matches CF.
        recon = self._recon_data("198.51.100.7", is_cdn=False, asn="AS13335 Cloudflare")
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            run_security_checks(
                recon_data=recon, enabled_checks=self._enabled(),
                timeout=1, max_workers=1,
            )
        assert mock_get.call_count == 0

    def test_non_cdn_ip_still_probed(self):
        recon = self._recon_data("198.51.100.42", is_cdn=False)
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            run_security_checks(
                recon_data=recon, enabled_checks=self._enabled(),
                timeout=1, max_workers=1,
            )
        assert mock_get.call_count >= 1


# ===========================================================================
# SMOKE
# ===========================================================================

class TestSmoke:
    def test_public_symbols_importable(self):
        # All consumed symbols are present at the module surface.
        for name in (
            "extract_asn_number", "cdn_name_from_asn", "is_cloudflare_ip",
            "response_is_cdn_edge", "collect_asn_cdn_ips",
            "collect_prefix_cdn_ips", "CDN_ASNS",
        ):
            assert hasattr(cr, name), f"missing {name}"

    def test_run_direct_ip_checks_signature_accepts_cdn_ips(self):
        import inspect
        sig = inspect.signature(run_direct_ip_checks)
        assert "cdn_ips" in sig.parameters
        # Must be optional (default None) so old callers do not break.
        assert sig.parameters["cdn_ips"].default is None

    def test_module_loads_without_network(self, monkeypatch):
        cr._cloudflare_networks_cache = None
        monkeypatch.setattr(cr, "_fetch_prefix_list", lambda *_a, **_kw: [])
        # Touching is_cloudflare_ip must not raise even when fetch fails
        # because the hardcoded fallback covers Cloudflare prefixes.
        assert is_cloudflare_ip("104.16.0.1") is True


# ===========================================================================
# REGRESSION - non-CDN paths still emit findings as before
# ===========================================================================

class TestRegression:
    def test_plain_http_200_still_emits_medium_finding(self):
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            finding = check_direct_ip_http("198.51.100.10", timeout=1)
        assert finding is not None
        assert finding["type"] == "direct_ip_http"
        assert finding["severity"] == "medium"

    def test_https_200_still_emits_low_finding(self):
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            finding = check_direct_ip_https("198.51.100.10", timeout=1)
        assert finding is not None
        assert finding["type"] == "direct_ip_https"
        assert finding["severity"] == "low"

    def test_redirect_to_hostname_still_info_finding(self):
        # Case 11 was NOT included in this implementation; verify it still
        # behaves the way the code did before (emits info-severity finding).
        # _analyze_redirect_chain is called with a fresh requests.get; we
        # patch it directly to return a hostname-redirect verdict.
        with patch(
            "recon.helpers.security_checks._analyze_redirect_chain"
        ) as mock_chain, patch(
            "recon.helpers.security_checks.requests.get"
        ) as mock_get:
            mock_get.return_value = _mock_response(301, {"Server": "nginx"}, "")
            mock_chain.return_value = {
                "redirects": True,
                "final_url": "https://example.com",
                "final_host": "example.com",
                "redirects_to_hostname": True,
                "redirect_count": 1,
                "initial_status_code": 301,
            }
            finding = check_direct_ip_http("198.51.100.10", timeout=1)
        assert finding is not None
        assert finding["severity"] == "info"

    def test_orchestrator_with_no_cdn_data_does_not_misclassify(self):
        # No port_scan / http_probe sections at all. The prefilter should
        # produce an empty cdn_ips set and probing must continue.
        recon = {
            "domain": "example.com",
            "dns": {
                "domain": {"ips": {"ipv4": ["198.51.100.99"], "ipv6": []}, "has_records": True},
                "subdomains": {},
            },
        }
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            run_security_checks(
                recon_data=recon,
                enabled_checks={
                    "direct_ip_http": True, "direct_ip_https": False,
                    "ip_api_exposed": False, "waf_bypass": False,
                },
                timeout=1, max_workers=1,
            )
        assert mock_get.call_count >= 1


# ===========================================================================
# Gap 1 - Live prefix fetch success branch
# ===========================================================================

class TestLivePrefixFetch:
    """The auto-use fixture forces the fetch helper to fail. These tests
    bypass that and exercise the success path of _load_cloudflare_networks
    by patching requests.get to return canned prefix lists."""

    def _stubbed_get(self, body):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = body
        return resp

    def test_fetch_parses_v4_and_v6_prefixes(self, monkeypatch):
        cr._cloudflare_networks_cache = None
        # Restore the real fetch helper so we can exercise it end-to-end.
        monkeypatch.setattr(cr, "_fetch_prefix_list", _REAL_FETCH_PREFIX_LIST)

        v4_body = "203.0.113.0/24\n198.51.100.0/24\n"
        v6_body = "2001:db8::/32\n"

        def fake_get(url, timeout=5):
            if "ips-v4" in url:
                return self._stubbed_get(v4_body)
            if "ips-v6" in url:
                return self._stubbed_get(v6_body)
            return self._stubbed_get("")

        with patch("recon.helpers.cdn_ranges.requests.get", side_effect=fake_get):
            assert cr.is_cloudflare_ip("203.0.113.5") is True
            assert cr.is_cloudflare_ip("198.51.100.42") is True
            assert cr.is_cloudflare_ip("2001:db8::cafe") is True
            assert cr.is_cloudflare_ip("8.8.8.8") is False

    def test_fetch_caches_result_across_calls(self, monkeypatch):
        cr._cloudflare_networks_cache = None
        monkeypatch.setattr(cr, "_fetch_prefix_list", _REAL_FETCH_PREFIX_LIST)
        call_count = {"n": 0}

        def fake_get(url, timeout=5):
            call_count["n"] += 1
            return self._stubbed_get("203.0.113.0/24\n" if "ips-v4" in url else "")

        with patch("recon.helpers.cdn_ranges.requests.get", side_effect=fake_get):
            cr.is_cloudflare_ip("203.0.113.1")
            cr.is_cloudflare_ip("203.0.113.2")
            cr.is_cloudflare_ip("203.0.113.3")
        # Two GETs for v4+v6 on the first call, zero on subsequent calls.
        assert call_count["n"] == 2

    def test_fetch_skips_invalid_prefix_entries(self, monkeypatch):
        cr._cloudflare_networks_cache = None
        monkeypatch.setattr(cr, "_fetch_prefix_list", _REAL_FETCH_PREFIX_LIST)

        def fake_get(url, timeout=5):
            if "ips-v4" in url:
                return self._stubbed_get("203.0.113.0/24\nnot-a-cidr\n\n  \n")
            return self._stubbed_get("")

        with patch("recon.helpers.cdn_ranges.requests.get", side_effect=fake_get):
            assert cr.is_cloudflare_ip("203.0.113.10") is True
            # Garbage line was skipped; cache built without crashing.
            assert cr._cloudflare_networks_cache is not None
            assert len(cr._cloudflare_networks_cache) == 1

    def test_fetch_non_200_falls_back_to_hardcoded(self, monkeypatch):
        cr._cloudflare_networks_cache = None

        def fake_get(url, timeout=5):
            r = MagicMock()
            r.status_code = 503
            r.text = "Service Unavailable"
            return r

        with patch("recon.helpers.cdn_ranges.requests.get", side_effect=fake_get):
            # Real Cloudflare prefix from the hardcoded fallback.
            assert cr.is_cloudflare_ip("104.16.0.1") is True


# ===========================================================================
# Gap 5 - collect_prefix_cdn_ips with mixed v4/v6
# ===========================================================================

class TestCollectPrefixCdnIpsV6:
    def test_v4_and_v6_mixed(self):
        ips = ["104.16.0.1", "2606:4700::1", "8.8.8.8", "2001:db8::1"]
        assert collect_prefix_cdn_ips(ips) == {"104.16.0.1", "2606:4700::1"}


# ===========================================================================
# Gap 6 - All body markers in _CDN_BODY_MARKERS
# ===========================================================================

class TestAllBodyMarkers:
    @pytest.mark.parametrize("marker", [m[0] for m in cr._CDN_BODY_MARKERS])
    def test_each_marker_matches_with_suspicious_status(self, marker):
        # Wrap the marker in surrounding text + uppercase variation to make
        # sure the substring match in response_is_cdn_edge is robust.
        body = f"<html>...{marker.upper()}...</html>"
        r = _mock_response(403, {}, body)
        assert response_is_cdn_edge(r) == "cloudflare", (
            f"marker {marker!r} did not match"
        )

    def test_all_markers_count_matches_body_constant(self):
        # Lock the constant so adding a new marker without a test fails here.
        assert len(cr._CDN_BODY_MARKERS) == 3


# ===========================================================================
# Gap 3 - Lazy collect_cdn_ips import path is resolvable
# ===========================================================================

class TestLazyImportPath:
    def test_collect_cdn_ips_module_path_exists(self):
        import importlib
        mod = importlib.import_module("recon.main_recon_modules.ip_filter")
        assert hasattr(mod, "collect_cdn_ips"), (
            "run_security_checks does a lazy import of "
            "recon.main_recon_modules.ip_filter.collect_cdn_ips; "
            "if this attribute is missing the orchestrator will raise at runtime."
        )
        # Must accept a recon_data dict and return a set.
        out = mod.collect_cdn_ips({"port_scan": {"by_ip": {}}, "http_probe": {"by_url": {}}})
        assert isinstance(out, set)


# ===========================================================================
# Gap 2 - Concurrency: results aggregate correctly across workers
# ===========================================================================

class TestConcurrency:
    def test_five_ips_three_workers_all_findings_returned(self):
        ips = [f"198.51.100.{i}" for i in range(1, 6)]
        with patch("recon.helpers.security_checks.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            findings = run_direct_ip_checks(
                ips=ips,
                subdomains_to_ips={},
                enabled_checks={
                    "direct_ip_http": True,
                    "direct_ip_https": False,
                    "ip_api_exposed": False,
                    "waf_bypass": False,
                },
                timeout=1,
                max_workers=3,
                cdn_ips=set(),
            )
        # One direct_ip_http finding per IP, no losses, no duplicates.
        matched = sorted(f["matched_ip"] for f in findings if f["type"] == "direct_ip_http")
        assert matched == sorted(ips)

    def test_concurrent_run_with_partial_cdn_filter(self):
        # 5 IPs, 2 are CDN. The 3 non-CDN should produce findings; the
        # 2 CDN ones should never be probed.
        ips = [f"198.51.100.{i}" for i in range(1, 6)]
        cdn = {"198.51.100.2", "198.51.100.4"}
        probed_ips: list[str] = []

        def record_call(url, *args, **kwargs):
            # url is "http://<ip>" — extract the host.
            host = url.split("//", 1)[1].split("/", 1)[0]
            probed_ips.append(host)
            return _mock_response(200, {"Server": "nginx"}, "ok")

        with patch("recon.helpers.security_checks.requests.get", side_effect=record_call):
            findings = run_direct_ip_checks(
                ips=ips,
                subdomains_to_ips={},
                enabled_checks={
                    "direct_ip_http": True,
                    "direct_ip_https": False,
                    "ip_api_exposed": False,
                    "waf_bypass": False,
                },
                timeout=1,
                max_workers=3,
                cdn_ips=cdn,
            )
        assert set(probed_ips).isdisjoint(cdn)
        matched = {f["matched_ip"] for f in findings}
        assert matched == set(ips) - cdn


# ===========================================================================
# Gap 4 (light) - Cypher hydration columns are present in graph_builders
# ===========================================================================

class TestPartialReconCypherHydration:
    def test_vuln_scan_query_returns_cdn_columns(self):
        import inspect
        from recon.partial_recon_modules.graph_builders import (
            _build_vuln_scan_data_from_graph,
        )
        src = inspect.getsource(_build_vuln_scan_data_from_graph)
        # The two IP-resolution queries must hydrate is_cdn / cdn_name / asn
        # off the IP node so collect_cdn_ips and collect_asn_cdn_ips work
        # in partial-recon mode.
        for col in ("i.is_cdn", "i.cdn_name", "i.asn"):
            assert col in src, (
                f"expected {col!r} in _build_vuln_scan_data_from_graph; "
                "without it partial-recon will not see CDN flags from Neo4j"
            )

    def test_vuln_scan_data_has_port_scan_by_ip_section(self):
        import inspect
        from recon.partial_recon_modules.graph_builders import (
            _build_vuln_scan_data_from_graph,
        )
        src = inspect.getsource(_build_vuln_scan_data_from_graph)
        # collect_cdn_ips reads port_scan.by_ip; the rebuild must allocate it.
        assert '"port_scan"' in src
        assert '"by_ip"' in src


# ===========================================================================
# Reliable-edge-CDN-name gate (regression guard for the cdn=aws bug)
# ===========================================================================

class TestReliableEdgeCdnName:
    @pytest.mark.parametrize("name", [
        "cloudflare", "Cloudflare", "CLOUDFLARE",
        "cloudfront", "akamai", "akamaighost", "fastly",
        "imperva", "incapsula", "sucuri", "stackpath",
        "azurefrontdoor", "gcore",
    ])
    def test_reliable_names_match(self, name):
        assert is_reliable_edge_cdn_name(name) is True

    @pytest.mark.parametrize("name", [
        "aws",        # generic AWS — covers bare ALB/EC2 origins
        "amazon",
        "azure",      # generic Azure
        "gcp",
        "google",
        "",
        None,
        "  ",
        "unknown-cdn",
    ])
    def test_ambiguous_or_unknown_names_do_not_match(self, name):
        # Critical regression guard: cdn="aws" must NOT count as a CDN edge,
        # otherwise bare ALB origins get false-suppressed (devergolabs case).
        assert is_reliable_edge_cdn_name(name) is False

    def test_collect_reliable_edge_ips_excludes_aws_label(self):
        recon = {
            "port_scan": {"by_ip": {
                "5.5.5.5":  {"is_cdn": True, "cdn": "cloudflare"},  # included
                "6.6.6.6":  {"is_cdn": True, "cdn": "aws"},         # excluded
                "7.7.7.7":  {"is_cdn": True, "cdn": None},          # excluded
            }},
            "http_probe": {"by_url": {
                "https://x/": {"ip": "8.8.8.8", "is_cdn": True, "cdn": "cloudfront"},
                "https://y/": {"ip": "9.9.9.9", "is_cdn": True, "cdn": "azure"},
            }},
        }
        assert collect_reliable_edge_ips(recon) == {"5.5.5.5", "8.8.8.8"}


# ===========================================================================
# _has_cdn_markers
# ===========================================================================

class TestHasCdnMarkers:
    def test_cf_ray_header(self):
        r = _mock_response(200, {"CF-RAY": "abc"})
        assert _has_cdn_markers(r) is True

    def test_x_amz_cf_id_header(self):
        r = _mock_response(200, {"X-Amz-Cf-Id": "xyz"})
        assert _has_cdn_markers(r) is True

    def test_x_served_by_fastly(self):
        r = _mock_response(200, {"X-Served-By": "cache-iad-kjyo7100"})
        assert _has_cdn_markers(r) is True

    def test_server_token_cloudfront(self):
        r = _mock_response(200, {"Server": "CloudFront"})
        assert _has_cdn_markers(r) is True

    def test_server_token_awselb_does_NOT_match(self):
        # awselb is a Cloud LB, not a WAF/CDN front. Must not register
        # as CDN markers, otherwise the bare-origin comparison flips.
        r = _mock_response(200, {"Server": "awselb/2.0"})
        assert _has_cdn_markers(r) is False

    def test_plain_nginx_no_markers(self):
        r = _mock_response(200, {"Server": "nginx/1.24.0"})
        assert _has_cdn_markers(r) is False

    def test_none_response(self):
        assert _has_cdn_markers(None) is False


# ===========================================================================
# _is_bare_origin_match (the comparison test)
# ===========================================================================

class TestIsBareOriginMatch:
    def _route(self, ip_resp, host_resp):
        """Return a fake requests.get that distinguishes IP from hostname URLs."""
        def fake(url, *a, **kw):
            host = url.split("//", 1)[1].split("/", 1)[0]
            return ip_resp if host == "1.2.3.4" else host_resp
        return fake

    def test_identical_responses_no_cdn_returns_true(self):
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "x" * 1000)
        ip_resp.content = b"x" * 1000
        host_resp = _mock_response(200, {"Server": "awselb/2.0"}, "x" * 1000)
        host_resp.content = b"x" * 1000
        with patch(
            "recon.helpers.security_checks.requests.get",
            side_effect=self._route(ip_resp, host_resp),
        ):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "http", timeout=1
            ) is True

    def test_hostname_has_cdn_ip_does_not_returns_false(self):
        # Real bypass scenario: hostname goes through CF, IP does not.
        ip_resp = _mock_response(200, {"Server": "nginx"}, "origin")
        ip_resp.content = b"origin"
        host_resp = _mock_response(200, {"CF-RAY": "abc-LHR", "Server": "cloudflare"}, "frontend")
        host_resp.content = b"frontend"
        with patch(
            "recon.helpers.security_checks.requests.get",
            side_effect=self._route(ip_resp, host_resp),
        ):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "https", timeout=1
            ) is False

    def test_different_status_codes_returns_false(self):
        ip_resp = _mock_response(200, {"Server": "nginx"}, "ok")
        ip_resp.content = b"ok"
        host_resp = _mock_response(403, {"Server": "nginx"}, "forbidden")
        host_resp.content = b"forbidden"
        with patch(
            "recon.helpers.security_checks.requests.get",
            side_effect=self._route(ip_resp, host_resp),
        ):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "http", timeout=1
            ) is False

    def test_different_servers_returns_false(self):
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "ok")
        ip_resp.content = b"ok"
        host_resp = _mock_response(200, {"Server": "Microsoft-IIS/10.0"}, "ok")
        host_resp.content = b"ok"
        with patch(
            "recon.helpers.security_checks.requests.get",
            side_effect=self._route(ip_resp, host_resp),
        ):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "http", timeout=1
            ) is False

    def test_size_delta_too_large_returns_false(self):
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "x")
        ip_resp.content = b"x" * 100
        host_resp = _mock_response(200, {"Server": "awselb/2.0"}, "x")
        host_resp.content = b"x" * 50000  # well beyond 10% / 500-byte delta
        with patch(
            "recon.helpers.security_checks.requests.get",
            side_effect=self._route(ip_resp, host_resp),
        ):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "http", timeout=1
            ) is False

    def test_ip_unreachable_returns_false(self):
        import requests as _r
        with patch(
            "recon.helpers.security_checks.requests.get",
            side_effect=_r.exceptions.ConnectTimeout("boom"),
        ):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "http", timeout=1
            ) is False

    def test_hostname_unreachable_falls_through_to_false(self):
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "ok")
        ip_resp.content = b"ok"
        import requests as _r

        def fake(url, *a, **kw):
            host = url.split("//", 1)[1].split("/", 1)[0]
            if host == "1.2.3.4":
                return ip_resp
            raise _r.exceptions.ConnectTimeout("dns-fail")

        with patch("recon.helpers.security_checks.requests.get", side_effect=fake):
            assert _is_bare_origin_match(
                "1.2.3.4", ["www.example.com"], "http", timeout=1
            ) is False


# ===========================================================================
# Integration: check_direct_ip_http / _https with hostnames
# ===========================================================================

class TestCheckDirectIpHttpWithHostnames:
    def test_bare_origin_match_suppresses_finding(self):
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "ok")
        ip_resp.content = b"hello world"
        host_resp = _mock_response(200, {"Server": "awselb/2.0"}, "ok")
        host_resp.content = b"hello world"

        def fake(url, *a, **kw):
            host = url.split("//", 1)[1].split("/", 1)[0]
            return ip_resp if host == "203.0.113.5" else host_resp

        with patch("recon.helpers.security_checks.requests.get", side_effect=fake):
            f = check_direct_ip_http(
                "203.0.113.5", hostnames=["www.example.com"], timeout=1
            )
        assert f is None  # bare origin -> no finding

    def test_hostname_with_waf_ip_without_emits_finding(self):
        # Real bypass: hostname response has CF, IP response does not.
        ip_resp = _mock_response(200, {"Server": "nginx"}, "")
        ip_resp.content = b"origin content"
        host_resp = _mock_response(200, {"CF-RAY": "abc", "Server": "cloudflare"}, "")
        host_resp.content = b"frontend content"

        def fake(url, *a, **kw):
            host = url.split("//", 1)[1].split("/", 1)[0]
            return ip_resp if host == "203.0.113.5" else host_resp

        with patch("recon.helpers.security_checks.requests.get", side_effect=fake):
            f = check_direct_ip_http(
                "203.0.113.5", hostnames=["www.example.com"], timeout=1
            )
        assert f is not None
        assert f["type"] == "direct_ip_http"

    def test_no_hostnames_falls_back_to_legacy(self):
        # Backward compat: when hostnames is None, the comparison is skipped
        # and the original probe-the-IP-only behavior emits the finding.
        with patch("recon.helpers.security_checks.requests.get") as m:
            m.return_value = _mock_response(200, {"Server": "nginx"}, "ok")
            f = check_direct_ip_http("203.0.113.5", timeout=1)  # no hostnames
        assert f is not None
        assert f["severity"] == "medium"


class TestCheckDirectIpHttpsWithHostnames:
    def test_bare_origin_match_suppresses_finding(self):
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "")
        ip_resp.content = b"app"
        host_resp = _mock_response(200, {"Server": "awselb/2.0"}, "")
        host_resp.content = b"app"

        def fake(url, *a, **kw):
            host = url.split("//", 1)[1].split("/", 1)[0]
            return ip_resp if host == "203.0.113.5" else host_resp

        with patch("recon.helpers.security_checks.requests.get", side_effect=fake):
            assert check_direct_ip_https(
                "203.0.113.5", hostnames=["www.example.com"], timeout=1
            ) is None


# ===========================================================================
# run_direct_ip_checks plumbs hostnames through subdomains_to_ips
# ===========================================================================

class TestRunDirectIpChecksHostnamePlumb:
    def test_subdomains_to_ips_drives_bare_origin_suppression(self):
        # 18.x is the AWS-style bare-ALB case: same content via hostname
        # and via IP, no CDN markers either side -> must be suppressed.
        ip_resp = _mock_response(200, {"Server": "awselb/2.0"}, "")
        ip_resp.content = b"content body"
        host_resp = _mock_response(200, {"Server": "awselb/2.0"}, "")
        host_resp.content = b"content body"

        def fake(url, *a, **kw):
            host = url.split("//", 1)[1].split("/", 1)[0]
            return ip_resp if host == "18.102.144.144" else host_resp

        with patch("recon.helpers.security_checks.requests.get", side_effect=fake):
            findings = run_direct_ip_checks(
                ips=["18.102.144.144"],
                subdomains_to_ips={"www.example.com": ["18.102.144.144"]},
                enabled_checks={
                    "direct_ip_http": True, "direct_ip_https": False,
                    "ip_api_exposed": False, "waf_bypass": False,
                },
                timeout=1, max_workers=1, cdn_ips=set(),
            )
        assert findings == []
