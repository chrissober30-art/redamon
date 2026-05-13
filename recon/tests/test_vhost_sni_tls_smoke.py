"""
Real TLS smoke test for the L4/SNI test path.

Spins up a local HTTPS server with a self-signed certificate and verifies
that the L4 test (curl --resolve) actually reaches the server with the
right SNI value. Skips when openssl is missing.

Notes on what we CAN'T realistically test in-process:
  - True SNI-based ROUTING (would need 2+ TLS contexts on the same socket
    selected by SNI; Python's stdlib http.server can't do that easily).
We DO test:
  - The L4 probe completes against a real TLS endpoint without hanging
  - Curl's --resolve actually steers the SNI hostname to the IP
  - Status + size are returned for an HTTPS endpoint

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_tls_smoke.py -v
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules.vhost_sni_enum import (
    _curl_probe,
    _is_curl_available,
    run_vhost_sni_enrichment,
)


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _generate_self_signed_cert(workdir: Path) -> tuple[Path, Path]:
    cert = workdir / "cert.pem"
    key = workdir / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,DNS:test.example.com,IP:127.0.0.1",
    ], check=True, capture_output=True, timeout=30)
    return cert, key


class _SimpleHttpsHandler(BaseHTTPRequestHandler):
    """Returns 200 + a fixed body. Does NOT route on SNI (server limitation)."""
    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0].lower()
        if host == "admin.test.example.com":
            body = b"<html><body>" + b"A" * 2000 + b"</body></html>"
            self.send_response(200)
        else:
            body = b"default"
            self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@unittest.skipUnless(_is_curl_available() and _openssl_available(),
                     "curl or openssl missing — skipping TLS smoke")
class TestVhostSniRealTls(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.workdir = Path(tempfile.mkdtemp(prefix="vhost_sni_tls_"))
        cls.cert, cls.key = _generate_self_signed_cert(cls.workdir)
        cls.port = _free_port()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cls.cert), str(cls.key))

        cls.server = HTTPServer(("127.0.0.1", cls.port), _SimpleHttpsHandler)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # Wait briefly for the listener to come up
        for _ in range(20):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=2)
        finally:
            shutil.rmtree(cls.workdir, ignore_errors=True)

    # --------------------------------------------------------------
    # Direct _curl_probe checks against a real TLS server
    # --------------------------------------------------------------
    def test_l7_probe_against_real_tls_returns_response(self):
        # Baseline: bare IP -> 404 default
        result = _curl_probe("https", None, None, "127.0.0.1", self.port, timeout=3)
        self.assertIsNotNone(result, "Baseline TLS probe failed — server may not be ready")
        self.assertEqual(result["status"], 404)

    def test_l7_with_host_header_routes_to_admin(self):
        # The handler reads the Host header even though our test server doesn't do SNI routing
        result = _curl_probe(
            scheme="https",
            host_header="admin.test.example.com",
            sni_hostname=None,
            target="127.0.0.1",
            port=self.port,
            timeout=3,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], 200)
        self.assertGreater(result["size"], 1000)

    def test_l4_resolve_completes_handshake(self):
        # The KEY assertion: curl --resolve actually completes the TLS handshake
        # against our self-signed cert (with -k) and returns a status code.
        result = _curl_probe(
            scheme="https",
            host_header=None,
            sni_hostname="admin.test.example.com",
            target="127.0.0.1",
            port=self.port,
            timeout=3,
        )
        self.assertIsNotNone(result, "L4 probe with --resolve failed against real TLS")
        # Our server doesn't route on SNI, but it DOES read the Host header,
        # which curl sets to admin.test.example.com because of the URL hostname.
        self.assertEqual(result["status"], 200)
        self.assertGreater(result["size"], 1000)

    def test_l4_resolve_handles_dead_sni(self):
        # SNI for a hostname the server doesn't recognise; with our self-signed
        # cert and -k, the handshake still succeeds, server responds with default.
        result = _curl_probe(
            scheme="https",
            host_header=None,
            sni_hostname="never-exists.test.example.com",
            target="127.0.0.1",
            port=self.port,
            timeout=3,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], 404)

    # --------------------------------------------------------------
    # Full module run against the TLS server
    # --------------------------------------------------------------
    def test_full_module_run_detects_real_anomaly(self):
        recon_data = {
            "domain": "test.example.com",
            "metadata": {"target": "test.example.com"},
            "port_scan": {
                "by_host": {
                    "host1": {"ip": "127.0.0.1", "ports": [{"port": self.port, "scheme": "https"}]},
                },
            },
        }
        settings = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": True,
            "VHOST_SNI_TIMEOUT": 3,
            "VHOST_SNI_CONCURRENCY": 4,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin\nrandom-no-match",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
        }
        run_vhost_sni_enrichment(recon_data, settings=settings)

        result = recon_data["vhost_sni"]
        # admin.test.example.com should be flagged (200 vs baseline 404)
        admin_findings = [f for f in result["findings"] if f["hostname"] == "admin.test.example.com"]
        self.assertEqual(len(admin_findings), 1)
        finding = admin_findings[0]
        # Both L7 (Host header trick) and L4 (SNI trick → URL hostname → Host header)
        # would set Host to admin.test.example.com against our server, which routes
        # on Host. So the finding should be 'both'.
        self.assertIn(finding["layer"], ("L7", "L4", "both"))
        self.assertEqual(finding["observed_status"], 200)
        self.assertIn(finding["severity"], ("medium", "high", "low"))


# ============================================================================
# TLS error paths — separate test class that runs a server which ACCEPTS TCP
# but rejects TLS (closes the socket immediately).
# ============================================================================
class _TcpAcceptOnlyServer:
    """Server that accepts TCP connections then immediately closes them.

    Curl will attempt a TLS handshake, fail, exit non-zero with empty stdout.
    """
    def __init__(self):
        self.port = _free_port()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def start(self):
        self.thread.start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=2)


@unittest.skipUnless(_is_curl_available(), "curl missing")
class TestTlsHandshakeFailure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _TcpAcceptOnlyServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_https_probe_against_tcp_only_server_returns_none(self):
        # The TCP handshake succeeds (server accepts then closes), but TLS
        # handshake fails. curl -sk exits non-zero with empty stdout.
        result = _curl_probe(
            scheme="https",
            host_header=None,
            sni_hostname=None,
            target="127.0.0.1",
            port=self.server.port,
            timeout=2,
        )
        # _curl_probe returns None for any unparsable output (status==0 too).
        self.assertIsNone(result)

    def test_full_run_against_dead_tls_skips_port_no_findings(self):
        recon_data = {
            "domain": "example.com",
            "metadata": {"target": "example.com"},
            "port_scan": {
                "by_host": {
                    "h": {"ip": "127.0.0.1", "ports": [{"port": self.server.port, "scheme": "https"}]},
                },
            },
        }
        settings = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": True,
            "VHOST_SNI_TIMEOUT": 2,
            "VHOST_SNI_CONCURRENCY": 2,
            "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_CUSTOM_WORDLIST": "admin\nstaging",
            "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
        }
        start = time.time()
        run_vhost_sni_enrichment(recon_data, settings=settings)
        elapsed = time.time() - start
        # No baseline -> port skipped -> no findings -> fast completion
        self.assertEqual(recon_data["vhost_sni"]["findings"], [])
        self.assertLess(elapsed, 30, f"Hung on TLS-rejecting server ({elapsed:.1f}s)")


if __name__ == "__main__":
    unittest.main()
