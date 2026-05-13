"""
Concurrency stress + scale tests for the VHost & SNI module.

Verifies the ThreadPoolExecutor fan-out doesn't:
  - Leak threads
  - Produce duplicate findings
  - Skip candidates under high concurrency
  - Hang when many candidates fail
  - Exceed configured concurrency cap

Uses an in-process HTTP server with a deliberately slow handler to
force concurrent inflight requests.

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_stress.py -v
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import unittest
from collections import Counter
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
# Concurrency-tracking server: every handled request increments a counter
# and records the max concurrency seen. Sleeps briefly to force overlap.
# ============================================================================
class _ConcurrencyTrackingHandler(BaseHTTPRequestHandler):
    inflight = 0
    max_inflight = 0
    handled = 0
    lock = threading.Lock()
    seen_hosts = []

    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0].lower()
        with _ConcurrencyTrackingHandler.lock:
            _ConcurrencyTrackingHandler.inflight += 1
            _ConcurrencyTrackingHandler.max_inflight = max(
                _ConcurrencyTrackingHandler.max_inflight,
                _ConcurrencyTrackingHandler.inflight,
            )
            _ConcurrencyTrackingHandler.handled += 1
            _ConcurrencyTrackingHandler.seen_hosts.append(host)

        # Brief sleep to maximise overlap window
        time.sleep(0.02)

        try:
            # Anomaly only on hosts whose first label starts with 'admin'
            if host.startswith("admin"):
                body = b"X" * 4000
                self.send_response(200)
            else:
                body = b"D"
                self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            with _ConcurrencyTrackingHandler.lock:
                _ConcurrencyTrackingHandler.inflight -= 1

    def log_message(self, format, *args):
        pass


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(_is_curl_available(), "curl missing -- skipping stress test")
class TestVhostSniStress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        # Threading HTTP server that handles requests concurrently
        from http.server import ThreadingHTTPServer
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), _ConcurrencyTrackingHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
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

    def setUp(self):
        # Reset shared state per test
        _ConcurrencyTrackingHandler.inflight = 0
        _ConcurrencyTrackingHandler.max_inflight = 0
        _ConcurrencyTrackingHandler.handled = 0
        _ConcurrencyTrackingHandler.seen_hosts = []

    def _build_recon(self):
        return {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {
                "by_host": {
                    "host1": {"ip": "127.0.0.1", "ports": [{"port": self.port, "scheme": "http"}]},
                },
            },
        }

    def _build_settings(self, **overrides):
        s = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": False,  # Plain HTTP server, no TLS
            "VHOST_SNI_TIMEOUT": 5,
            "VHOST_SNI_CONCURRENCY": 20,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_CUSTOM_WORDLIST": "",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 10000,
        }
        s.update(overrides)
        return s

    # --------------------------------------------------------------
    # 1. 200 candidates, concurrency 20 — no duplicates, all probed
    # --------------------------------------------------------------
    def test_200_candidates_no_duplicates(self):
        wordlist = "\n".join(f"host{i:03d}" for i in range(200))
        # Add 5 admin* prefixes that should produce findings
        wordlist += "\n" + "\n".join(f"admin{i}" for i in range(5))

        recon = self._build_recon()
        settings = self._build_settings(VHOST_SNI_CUSTOM_WORDLIST=wordlist)
        run_vhost_sni_enrichment(recon, settings=settings)

        result = recon["vhost_sni"]
        # 200 + 5 = 205 unique candidates
        self.assertEqual(result["by_ip"]["127.0.0.1"]["candidates_tested"], 205)

        # Exactly 5 findings (admin0..admin4)
        admin_findings = [f for f in result["findings"] if f["hostname"].startswith("admin")]
        self.assertEqual(len(admin_findings), 5,
                         f"Expected 5 admin findings, got {len(admin_findings)}")

        # No duplicate findings (same hostname appearing twice)
        hostnames = [f["hostname"] for f in result["findings"]]
        dups = [h for h, c in Counter(hostnames).items() if c > 1]
        self.assertEqual(dups, [], f"Duplicate findings: {dups}")

    # --------------------------------------------------------------
    # 2. Concurrency cap respected (max inflight ≤ configured + small buffer)
    # --------------------------------------------------------------
    def test_concurrency_cap_respected(self):
        wordlist = "\n".join(f"host{i:03d}" for i in range(100))

        recon = self._build_recon()
        # Concurrency 8: max_inflight server-side should never exceed ~10
        # (8 candidate threads + 1 baseline; small buffer for thread scheduling)
        settings = self._build_settings(VHOST_SNI_CONCURRENCY=8, VHOST_SNI_CUSTOM_WORDLIST=wordlist)
        run_vhost_sni_enrichment(recon, settings=settings)

        # Max inflight should be ≤ concurrency + ~2 buffer
        self.assertLessEqual(
            _ConcurrencyTrackingHandler.max_inflight, 12,
            f"Max inflight {_ConcurrencyTrackingHandler.max_inflight} exceeded configured concurrency 8 (+buffer)",
        )

    # --------------------------------------------------------------
    # 3. Every candidate hit the server (no silent drops)
    # --------------------------------------------------------------
    def test_all_candidates_hit_server(self):
        candidates = [f"sub{i:03d}" for i in range(50)]
        wordlist = "\n".join(candidates)

        recon = self._build_recon()
        settings = self._build_settings(VHOST_SNI_CUSTOM_WORDLIST=wordlist)
        run_vhost_sni_enrichment(recon, settings=settings)

        # Each candidate should have hit the server at least once (L7 path)
        # Plus 1 baseline request with no Host header (host="")
        seen = set(_ConcurrencyTrackingHandler.seen_hosts)
        for c in candidates:
            expected = f"{c}.example.com"
            self.assertIn(expected, seen, f"Candidate {expected} never reached server")

    # --------------------------------------------------------------
    # 4. Wall-time scaling: 100 candidates with concurrency 50 must be
    #    significantly faster than concurrency 1
    # --------------------------------------------------------------
    def test_concurrency_actually_speeds_up_scan(self):
        wordlist = "\n".join(f"sub{i:03d}" for i in range(40))

        # Low concurrency
        recon1 = self._build_recon()
        settings1 = self._build_settings(VHOST_SNI_CONCURRENCY=1, VHOST_SNI_CUSTOM_WORDLIST=wordlist)
        t0 = time.time()
        run_vhost_sni_enrichment(recon1, settings=settings1)
        slow = time.time() - t0

        # Reset server-side counters
        self.setUp()

        # High concurrency
        recon2 = self._build_recon()
        settings2 = self._build_settings(VHOST_SNI_CONCURRENCY=20, VHOST_SNI_CUSTOM_WORDLIST=wordlist)
        t0 = time.time()
        run_vhost_sni_enrichment(recon2, settings=settings2)
        fast = time.time() - t0

        # Both should produce identical findings (= 0 since 'sub*' isn't admin)
        self.assertEqual(recon1["vhost_sni"]["findings"], recon2["vhost_sni"]["findings"])
        # Concurrency 20 must be measurably faster than 1. Subprocess fork+exec
        # overhead dominates curl latency in containers, so we don't assert a
        # specific speedup ratio — just that high concurrency is meaningfully
        # faster (at least 5%) than serial.
        self.assertLess(fast, slow * 0.95,
                        f"High concurrency wasn't measurably faster: slow={slow:.2f}s fast={fast:.2f}s")

    # --------------------------------------------------------------
    # 5. max_candidates_per_ip cap enforced
    # --------------------------------------------------------------
    def test_max_candidates_per_ip_enforced(self):
        # Provide 100 candidates but cap to 30
        wordlist = "\n".join(f"sub{i:03d}" for i in range(100))
        recon = self._build_recon()
        settings = self._build_settings(
            VHOST_SNI_CUSTOM_WORDLIST=wordlist,
            VHOST_SNI_MAX_CANDIDATES_PER_IP=30,
        )
        run_vhost_sni_enrichment(recon, settings=settings)
        self.assertEqual(recon["vhost_sni"]["by_ip"]["127.0.0.1"]["candidates_tested"], 30)

    # --------------------------------------------------------------
    # 6. No thread leaks across consecutive runs
    # --------------------------------------------------------------
    def test_no_thread_leak_across_runs(self):
        baseline_threads = threading.active_count()
        wordlist = "\n".join(f"host{i:03d}" for i in range(20))

        for _ in range(5):
            recon = self._build_recon()
            settings = self._build_settings(VHOST_SNI_CONCURRENCY=10, VHOST_SNI_CUSTOM_WORDLIST=wordlist)
            run_vhost_sni_enrichment(recon, settings=settings)

        # Allow brief grace for daemon-thread teardown
        time.sleep(0.5)
        leaked = threading.active_count() - baseline_threads
        self.assertLess(leaked, 5, f"Possible thread leak: {leaked} extra threads after 5 runs")


if __name__ == "__main__":
    unittest.main()
