"""
Unit tests for Criminal IP enrichment (recon/criminalip_enrich.py).

Mocks requests.get for https://api.criminalip.io/v1/*.
Mock responses use the real API format (tags/count+data wrappers).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon"))

from criminalip_enrich import run_criminalip_enrichment, run_criminalip_enrichment_isolated


def _combined_result() -> dict:
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}}, "subdomains": {}},
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _cip_ip_body() -> dict:
    """Real API format: tags object + count/data wrappers for whois and port."""
    return {
        "ip": "1.2.3.4",
        "tags": {
            "is_vpn": True,
            "is_proxy": False,
            "is_tor": False,
            "is_hosting": True,
            "is_cloud": False,
            "is_mobile": False,
            "is_darkweb": False,
            "is_scanner": False,
            "is_snort": True,
        },
        "score": {"inbound": 5, "outbound": 1},
        "whois": {
            "count": 1,
            "data": [
                {
                    "org_name": "TestOrg",
                    "org_country_code": "US",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "as_name": "TestNet LLC",
                    "as_no": 12345,
                }
            ],
        },
        "port": {
            "count": 2,
            "data": [
                {
                    "open_port_no": 80,
                    "socket": "tcp",
                    "protocol": "HTTP",
                    "app_name": "Apache",
                    "app_version": "2.4.29",
                    "banner": "HTTP/1.1 200 OK",
                },
                {
                    "open_port_no": 443,
                    "socket": "tcp",
                    "protocol": "HTTPS",
                    "app_name": "Apache",
                    "app_version": "2.4.29",
                    "banner": None,
                },
            ],
        },
        "vulnerability": {
            "count": 1,
            "data": [
                {
                    "cve_id": "CVE-2023-25690",
                    "cve_description": "HTTP Request Smuggling in Apache",
                    "cvssv2_score": 0.0,
                    "cvssv3_score": 9.8,
                    "app_name": "Apache",
                    "app_version": "2.4.29",
                }
            ],
        },
        "ip_category": {
            "count": 2,
            "data": [
                {"type": "malware", "detect_source": "C-TAS"},
                {"type": "scanner", "detect_source": "internal"},
            ],
        },
        "ids": {"count": 3, "data": []},
        "scanning_record": {"count": 12, "data": []},
        "status": 200,
    }


def _cip_domain_body() -> dict:
    return {"data": {"risk_score": "high", "risk_grade": "B", "abuse_record_count": 5}}


class TestCriminalipEnrich(unittest.TestCase):
    """Criminal IP API enrichment with mocked HTTP (real API format)."""

    def _settings(self, rotator=None, **overrides) -> dict:
        base = {
            "CRIMINALIP_ENABLED": True,
            "CRIMINALIP_API_KEY": "cip-key",
            "CRIMINALIP_KEY_ROTATOR": rotator,
        }
        base.update(overrides)
        return base

    def _path_from_url(self, url: str) -> str:
        return url.replace("https://api.criminalip.io/v1/", "")

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._path_from_url(url)
            if path.startswith("domain/report"):
                return _mock_response(200, _cip_domain_body())
            if path.startswith("ip/data"):
                return _mock_response(200, _cip_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings())

        self.assertIn("criminalip", out)

        # Domain report
        dr = out["criminalip"]["domain_report"]
        self.assertIsNotNone(dr)
        self.assertEqual(dr["domain"], "example.com")
        self.assertEqual(dr["risk"].get("score"), "high")
        self.assertEqual(dr["risk"].get("grade"), "B")
        self.assertEqual(dr["risk"].get("abuse_record_count"), 5)

        ipr = out["criminalip"]["ip_reports"]
        self.assertEqual(len(ipr), 1)
        rep = ipr[0]
        self.assertEqual(rep["ip"], "1.2.3.4")

        # Score
        self.assertEqual(rep["score"]["inbound"], "5")
        self.assertEqual(rep["score"]["outbound"], "1")

        # Tags (real API format via "tags" key)
        self.assertIs(rep["issues"]["is_vpn"], True)
        self.assertIs(rep["issues"]["is_proxy"], False)
        self.assertIs(rep["issues"]["is_hosting"], True)
        self.assertIs(rep["issues"]["is_cloud"], False)
        self.assertIs(rep["issues"]["is_snort"], True)

        # Whois (unwrapped from count/data)
        self.assertEqual(rep["whois"]["org_name"], "TestOrg")
        self.assertEqual(rep["whois"]["country"], "US")
        self.assertEqual(rep["whois"]["city"], "New York")
        self.assertAlmostEqual(rep["whois"]["latitude"], 40.7128)
        self.assertAlmostEqual(rep["whois"]["longitude"], -74.0060)
        self.assertEqual(rep["whois"]["asn_name"], "TestNet LLC")
        self.assertEqual(rep["whois"]["asn_no"], 12345)

        # Ports (unwrapped from count/data)
        self.assertEqual(len(rep["ports"]), 2)
        p80 = rep["ports"][0]
        self.assertEqual(p80["port"], 80)
        self.assertEqual(p80["socket"], "tcp")
        self.assertEqual(p80["app_name"], "Apache")
        self.assertEqual(p80["app_version"], "2.4.29")
        self.assertEqual(p80["banner"], "HTTP/1.1 200 OK")

        # Vulnerabilities
        self.assertEqual(len(rep["vulnerabilities"]), 1)
        v = rep["vulnerabilities"][0]
        self.assertEqual(v["cve_id"], "CVE-2023-25690")
        self.assertAlmostEqual(v["cvssv3_score"], 9.8)
        self.assertEqual(v["app_name"], "Apache")

        # Categories + counts
        self.assertIn("malware", rep["categories"])
        self.assertIn("scanner", rep["categories"])
        self.assertEqual(rep["ids_count"], 3)
        self.assertEqual(rep["scanning_count"], 12)

    @patch("criminalip_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings(CRIMINALIP_API_KEY=""))
        self.assertNotIn("criminalip", out)
        mock_get.assert_not_called()

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (401, 500):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_criminalip_enrichment(cr, self._settings())
                self.assertIsNone(out["criminalip"]["domain_report"])
                self.assertEqual(out["criminalip"]["ip_reports"], [])

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_rate_limit(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, {}, text="rl")
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings())
        self.assertIsNone(out["criminalip"]["domain_report"])
        self.assertEqual(out["criminalip"]["ip_reports"], [])
        backoff = [c for c in mock_sleep.call_args_list if c[0] and c[0][0] == 2]
        self.assertGreaterEqual(len(backoff), 1)

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(404, {})
        cr = _combined_result()
        out = run_criminalip_enrichment(cr, self._settings())
        self.assertIsNone(out["criminalip"]["domain_report"])
        self.assertEqual(out["criminalip"]["ip_reports"], [])

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_key_rotator_tick_after_requests(self, mock_get, _sleep):
        rotator = MagicMock()
        rotator.has_keys = True
        rotator.current_key = "rk"

        def side_effect(url, **_kwargs):
            path = self._path_from_url(url)
            if path.startswith("domain/report"):
                return _mock_response(200, _cip_domain_body())
            if path.startswith("ip/data"):
                return _mock_response(200, _cip_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        run_criminalip_enrichment(_combined_result(), self._settings(rotator=rotator, CRIMINALIP_API_KEY=""))
        self.assertEqual(rotator.tick.call_count, 2)

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_full_param_sent(self, mock_get, _sleep):
        """Verify full=true is sent in the ip/data request."""
        call_params = {}

        def side_effect(url, **kwargs):
            if "ip/data" in url:
                call_params.update(kwargs.get("params") or {})
                return _mock_response(200, _cip_ip_body())
            return _mock_response(200, _cip_domain_body())

        mock_get.side_effect = side_effect
        run_criminalip_enrichment(_combined_result(), self._settings())
        self.assertEqual(call_params.get("full"), "true")

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        def side_effect(url, **_kwargs):
            path = self._path_from_url(url)
            if path.startswith("domain/report"):
                return _mock_response(200, _cip_domain_body())
            if path.startswith("ip/data"):
                return _mock_response(200, _cip_ip_body())
            return _mock_response(404, {})

        mock_get.side_effect = side_effect
        combined = _combined_result()
        sub = run_criminalip_enrichment_isolated(combined, self._settings())
        self.assertIn("ip_reports", sub)
        self.assertIn("domain_report", sub)
        self.assertNotIn("criminalip", combined)

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_missing_vulnerability_fields_skipped(self, mock_get, _sleep):
        """CVE entries without cve_id are silently skipped."""
        body = _cip_ip_body()
        body["vulnerability"]["data"].append({"app_name": "nginx"})  # no cve_id

        def side_effect(url, **_kwargs):
            if "ip/data" in url:
                return _mock_response(200, body)
            return _mock_response(200, _cip_domain_body())

        mock_get.side_effect = side_effect
        out = run_criminalip_enrichment(_combined_result(), self._settings())
        self.assertEqual(len(out["criminalip"]["ip_reports"][0]["vulnerabilities"]), 1)

    @patch("criminalip_enrich.time.sleep")
    @patch("criminalip_enrich.requests.get")
    def test_legacy_flat_whois_format(self, mock_get, _sleep):
        """Flat whois dict (old mock format) is still handled gracefully."""
        body = {
            "score": {"inbound": "critical", "outbound": "safe"},
            "issues": {"is_vpn": True, "is_proxy": False, "is_tor": False},
            "whois": {"org_name": "LegacyOrg", "org_country_code": "DE"},
            "port": [{"open_port_no": 80}, {"open_port_no": 443}],
        }

        def side_effect(url, **_kwargs):
            if "ip/data" in url:
                return _mock_response(200, body)
            return _mock_response(200, _cip_domain_body())

        mock_get.side_effect = side_effect
        out = run_criminalip_enrichment(_combined_result(), self._settings())
        rep = out["criminalip"]["ip_reports"][0]
        # tags from "issues" fallback
        self.assertIs(rep["issues"]["is_vpn"], True)
        # whois flat format
        self.assertEqual(rep["whois"]["org_name"], "LegacyOrg")
        self.assertEqual(rep["whois"]["country"], "DE")
        # ports from direct list
        self.assertEqual(len(rep["ports"]), 2)
        self.assertEqual(rep["ports"][0]["port"], 80)


if __name__ == "__main__":
    unittest.main()
