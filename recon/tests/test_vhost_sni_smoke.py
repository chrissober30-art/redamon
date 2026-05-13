"""
Smoke test for VHost & SNI enumeration -- runs the REAL module against a
REAL local HTTP server with multiple vhosts. No curl mocking.

Validates that the L7 (Host header) detection path actually works end-to-end:
real curl subprocess -> real HTTP requests -> real anomaly detection.

L4 (TLS SNI) is not exercised here -- it would need a real TLS reverse proxy
with SNI-based routing. That's covered by the unit tests with mocked curl.

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_smoke.py -v -s
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules.vhost_sni_enum import (
    _is_curl_available,
    run_vhost_sni_enrichment,
)


# ============================================================================
# Multi-vhost HTTP server simulating real-world Apache/Nginx vhost routing
# ============================================================================
class MultiVhostHandler(BaseHTTPRequestHandler):
    """
    Serves different content based on the HTTP Host header:
      - Host: admin.example.com           -> 200 + 4000-byte admin page
      - Host: staging.example.com         -> 200 + 2500-byte staging page
      - Host: blog.example.com            -> 200 + 1000-byte blog page (similar size to baseline)
      - Host: notfound.example.com        -> baseline (404)
      - Host: <anything else> or no host  -> 404 baseline page
    """

    BASELINE_BODY = b"<html><body>Default vhost - 404</body></html>"  # ~45 bytes

    def do_GET(self):
        host = self.headers.get("Host", "").lower().split(":")[0]

        if host == "admin.example.com":
            body = b"<html><body>" + b"X" * 4000 + b"</body></html>"
            self.send_response(200)
        elif host == "staging.example.com":
            body = b"<html><body>" + b"S" * 2500 + b"</body></html>"
            self.send_response(200)
        elif host == "blog.example.com":
            # Different status (200) but with a body big enough to be flagged
            # against a 45-byte 404 baseline (delta > 50)
            body = b"<html><body>" + b"B" * 1000 + b"</body></html>"
            self.send_response(200)
        else:
            body = self.BASELINE_BODY
            self.send_response(404)

        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence stderr access logs
        pass


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(_is_curl_available(), "curl not in PATH -- skipping smoke test")
class TestVhostSniSmoke(unittest.TestCase):
    """End-to-end against a real local server with real curl invocations."""

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.server = HTTPServer(("127.0.0.1", cls.port), MultiVhostHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # Wait for server to be ready
        for _ in range(20):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _recon_data(self):
        return {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {
                "by_host": {
                    "host1": {
                        "ip": "127.0.0.1",
                        # Force HTTP scheme on the test port
                        "ports": [{"port": self.port, "scheme": "http"}],
                    },
                },
            },
        }

    def _settings(self, **overrides):
        s = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": False,  # L4/SNI test would need real TLS
            "VHOST_SNI_TIMEOUT": 2,
            "VHOST_SNI_CONCURRENCY": 4,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin\nstaging\nblog\nnotfound",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
        }
        s.update(overrides)
        return s

    # --------------------------------------------------------------------
    # Detection of three real anomalies + one baseline match
    # --------------------------------------------------------------------
    def test_detects_real_hidden_vhosts(self):
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings())

        result = recon["vhost_sni"]
        findings_by_host = {f["hostname"]: f for f in result["findings"]}

        # Three vhosts (admin / staging / blog) return different content -> flagged
        self.assertIn("admin.example.com", findings_by_host)
        self.assertIn("staging.example.com", findings_by_host)
        self.assertIn("blog.example.com", findings_by_host)

        # notfound returns the same 404 baseline -> NOT flagged
        self.assertNotIn("notfound.example.com", findings_by_host)

    def test_admin_gets_medium_severity(self):
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings())
        admin = next(f for f in recon["vhost_sni"]["findings"] if f["hostname"] == "admin.example.com")
        self.assertEqual(admin["severity"], "medium")
        self.assertEqual(admin["internal_pattern_match"], "admin")
        self.assertEqual(admin["layer"], "L7")
        self.assertEqual(admin["observed_status"], 200)
        self.assertEqual(admin["baseline_status"], 404)

    def test_staging_gets_medium_severity(self):
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings())
        staging = next(f for f in recon["vhost_sni"]["findings"] if f["hostname"] == "staging.example.com")
        # 'staging' is in INTERNAL_KEYWORDS
        self.assertEqual(staging["severity"], "medium")
        self.assertEqual(staging["internal_pattern_match"], "staging")

    def test_blog_gets_low_severity(self):
        # blog has different status than baseline but no internal keyword match
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings())
        blog = next(f for f in recon["vhost_sni"]["findings"] if f["hostname"] == "blog.example.com")
        self.assertEqual(blog["severity"], "low")
        self.assertIsNone(blog["internal_pattern_match"])

    def test_baseline_recorded_correctly(self):
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings())
        ip_result = recon["vhost_sni"]["by_ip"]["127.0.0.1"]
        baseline = ip_result["baseline"]
        # Baseline should match the 404 default response
        self.assertEqual(baseline["status"], 404)
        self.assertEqual(baseline["size"], len(MultiVhostHandler.BASELINE_BODY))

    def test_size_tolerance_suppresses_minor_jitter(self):
        # With huge tolerance, only status-code differences should remain
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings(VHOST_SNI_BASELINE_SIZE_TOLERANCE=100000))

        findings_by_host = {f["hostname"]: f for f in recon["vhost_sni"]["findings"]}
        # All three test vhosts have different status (200 vs baseline 404) -> still anomalies
        self.assertIn("admin.example.com", findings_by_host)
        self.assertIn("staging.example.com", findings_by_host)
        self.assertIn("blog.example.com", findings_by_host)

    def test_concurrency_setting_is_used(self):
        # Smoke check that the run completes regardless of concurrency 1 or 20
        for c in (1, 20):
            recon = self._recon_data()
            run_vhost_sni_enrichment(recon, settings=self._settings(VHOST_SNI_CONCURRENCY=c))
            self.assertEqual(len(recon["vhost_sni"]["findings"]), 3)

    def test_all_candidate_responses_match_baseline_no_findings(self):
        # Use only candidates the server doesn't recognise
        recon = self._recon_data()
        run_vhost_sni_enrichment(
            recon,
            settings=self._settings(VHOST_SNI_CUSTOM_WORDLIST="random1\nrandom2\nrandom3"),
        )
        self.assertEqual(recon["vhost_sni"]["findings"], [])
        self.assertEqual(recon["vhost_sni"]["summary"]["candidates_total"], 3)

    def test_discovered_baseurl_injected_into_http_probe(self):
        recon = self._recon_data()
        run_vhost_sni_enrichment(recon, settings=self._settings())

        injected = recon.get("http_probe", {}).get("by_url", {})
        # admin.example.com:port URL should have been injected
        admin_url = next((u for u in injected if "admin.example.com" in u), None)
        self.assertIsNotNone(admin_url, "admin vhost URL was not injected into http_probe.by_url")
        self.assertEqual(injected[admin_url]["discovery_source"], "vhost_sni_enum")

    def test_cancels_dead_target_within_timeout(self):
        # Point at a port nothing is listening on. The whole scan should complete
        # within (timeout * 3 + 2) seconds per probe instead of hanging.
        recon = {
            "domain": "example.com",
            "port_scan": {
                "by_host": {
                    "host1": {
                        "ip": "127.0.0.1",
                        "ports": [{"port": 1, "scheme": "http"}],   # port 1 = unlikely to be listening
                    },
                },
            },
        }
        start = time.time()
        run_vhost_sni_enrichment(recon, settings=self._settings(VHOST_SNI_TIMEOUT=1))
        elapsed = time.time() - start
        # With baseline failing fast, candidate probes shouldn't fire and the
        # whole pass must complete in <10s even with tiny concurrency.
        self.assertLess(elapsed, 15, f"Scan against dead port hung ({elapsed:.1f}s)")
        # Also confirm graceful degradation: empty results, no crash
        self.assertEqual(recon["vhost_sni"]["findings"], [])


if __name__ == "__main__":
    unittest.main()
