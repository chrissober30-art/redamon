"""
Tests for the Naabu custom-port scope feature (issue #136).

Background
----------
When a user sets "Custom Ports" on the Naabu module (e.g. ``4280``) the whole
recon must stay within that port scope. The bug was that http_probe's DNS
fallback ignored ``NAABU_CUSTOM_PORTS`` and probed a hardcoded list (80, 443,
8080, 9000, ...), so a custom-port scan produced phantom 443/9000 nodes and
never even tried the requested port.

What this exercises (recon.main_recon_modules.http_probe):
  - parse_port_spec          single / list / range / blank / full / junk
  - url_port                 scheme-default + explicit port extraction
  - _urls_for_host_ports     protocol heuristic per port
  - build_targets_from_dns   fallback honors custom ports; default list otherwise
  - build_targets_from_naabu by_host wins; empty -> fallback honors custom ports
  - apply_custom_port_scope  hard guard + partial-recon opt-out
  - run_http_probe           callsite wiring (source-level smoke)
  - Issue #136 regression    Naabu-empty + custom 4280 -> only :4280, no 443/9000

Run (inside the recon image, where dnspython/neo4j deps exist):
    docker run --rm --entrypoint python3 -v "$PWD:/work:ro" -w /work \\
        redamon-recon:latest recon/tests/test_custom_port_scope.py
or:
    python3 -m unittest recon.tests.test_custom_port_scope -v
"""
from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

_RECON_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _RECON_DIR.parent
for _p in (str(_PROJECT_ROOT), str(_RECON_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.main_recon_modules.http_probe import (  # noqa: E402
    HTTP_PORTS,
    HTTPS_PORTS,
    apply_custom_port_scope,
    build_targets_from_dns,
    build_targets_from_naabu,
    parse_port_spec,
    run_http_probe,
    url_port,
    _urls_for_host_ports,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ports_of(urls):
    """Set of effective ports across a URL list."""
    return {url_port(u) for u in urls}


def _dns_recon(domain="ex.com", ipv4=("1.2.3.4",), subdomains=None, metadata=None):
    """Build a minimal recon_data dict with DNS records but no port_scan."""
    data = {
        "domain": domain,
        "dns": {
            "domain": {"ips": {"ipv4": list(ipv4), "ipv6": []}, "has_records": True},
            "subdomains": subdomains or {},
        },
    }
    if metadata is not None:
        data["metadata"] = metadata
    return data


# ===========================================================================
# UNIT: parse_port_spec
# ===========================================================================
class TestParsePortSpec(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_port_spec("4280"), {4280})

    def test_comma_list(self):
        self.assertEqual(parse_port_spec("80,443,8080"), {80, 443, 8080})

    def test_range(self):
        self.assertEqual(parse_port_spec("8080-8082"), {8080, 8081, 8082})

    def test_mixed_list_and_range(self):
        self.assertEqual(parse_port_spec("80,443,8080-8082"), {80, 443, 8080, 8081, 8082})

    def test_whitespace_tolerant(self):
        self.assertEqual(parse_port_spec(" 80 , 443 , 8080-8081 "), {80, 443, 8080, 8081})

    def test_blank_is_empty(self):
        self.assertEqual(parse_port_spec(""), set())

    def test_none_is_empty(self):
        self.assertEqual(parse_port_spec(None), set())

    def test_full_means_no_restriction(self):
        # "full"/"all"/"-" map to "no custom restriction" -> empty set
        self.assertEqual(parse_port_spec("full"), set())
        self.assertEqual(parse_port_spec("all"), set())
        self.assertEqual(parse_port_spec("-"), set())

    def test_case_insensitive_keyword(self):
        self.assertEqual(parse_port_spec("FULL"), set())

    def test_junk_token_skipped(self):
        self.assertEqual(parse_port_spec("abc,90"), {90})

    def test_reversed_range_ignored(self):
        self.assertEqual(parse_port_spec("9000-8000"), set())

    def test_out_of_range_ignored(self):
        self.assertEqual(parse_port_spec("70000,99999"), set())
        self.assertEqual(parse_port_spec("80,70000"), {80})

    def test_boundary_ports(self):
        self.assertEqual(parse_port_spec("0"), {0})
        self.assertEqual(parse_port_spec("65535"), {65535})

    def test_single_port_range(self):
        self.assertEqual(parse_port_spec("443-443"), {443})

    def test_int_input_coerced(self):
        # settings may carry an int rather than a string
        self.assertEqual(parse_port_spec(4280), {4280})

    def test_trailing_comma(self):
        self.assertEqual(parse_port_spec("80,443,"), {80, 443})


# ===========================================================================
# UNIT: url_port
# ===========================================================================
class TestUrlPort(unittest.TestCase):

    def test_http_default(self):
        self.assertEqual(url_port("http://h"), 80)

    def test_https_default(self):
        self.assertEqual(url_port("https://h"), 443)

    def test_explicit_port(self):
        self.assertEqual(url_port("https://h:4280"), 4280)
        self.assertEqual(url_port("http://h:9000"), 9000)

    def test_uppercase_scheme(self):
        self.assertEqual(url_port("HTTPS://h"), 443)
        self.assertEqual(url_port("HTTP://h:8080"), 8080)

    def test_with_path_and_port(self):
        self.assertEqual(url_port("http://h:8000/login"), 8000)

    def test_with_path_no_port(self):
        self.assertEqual(url_port("https://h/a/b"), 443)

    def test_malformed_returns_minus_one(self):
        self.assertEqual(url_port("not-a-url"), -1)

    def test_non_http_scheme_returns_minus_one(self):
        self.assertEqual(url_port("ftp://h:21"), -1)


# ===========================================================================
# UNIT: _urls_for_host_ports (protocol heuristic)
# ===========================================================================
class TestUrlsForHostPorts(unittest.TestCase):

    def test_443_is_https_without_suffix(self):
        self.assertEqual(_urls_for_host_ports("h", [443]), ["https://h"])

    def test_80_is_http_without_suffix(self):
        self.assertEqual(_urls_for_host_ports("h", [80]), ["http://h"])

    def test_known_https_port(self):
        self.assertEqual(_urls_for_host_ports("h", [8443]), ["https://h:8443"])

    def test_known_http_port(self):
        self.assertEqual(_urls_for_host_ports("h", [9000]), ["http://h:9000"])

    def test_unknown_port_tries_both(self):
        out = _urls_for_host_ports("h", [4280])
        self.assertEqual(set(out), {"http://h:4280", "https://h:4280"})

    def test_sorted_and_deduped_input(self):
        out = _urls_for_host_ports("h", [443, 443, 80])
        # both protocols, deterministic by sorted port order
        self.assertEqual(out, ["http://h", "https://h"])

    def test_classification_constants_consistent(self):
        # guard against accidental overlap that would make a port both http+https
        self.assertEqual(HTTP_PORTS & HTTPS_PORTS, set())


# ===========================================================================
# INTEGRATION: build_targets_from_dns
# ===========================================================================
class TestBuildTargetsFromDns(unittest.TestCase):

    def test_custom_ports_only(self):
        urls = build_targets_from_dns(_dns_recon(), {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(_ports_of(urls), {4280})
        self.assertTrue(all("ex.com:4280" in u for u in urls))

    def test_custom_multi_ports(self):
        urls = build_targets_from_dns(_dns_recon(), {"NAABU_CUSTOM_PORTS": "4280,8888"})
        self.assertEqual(_ports_of(urls), {4280, 8888})

    def test_no_custom_uses_default_list(self):
        urls = build_targets_from_dns(_dns_recon(), {})
        ports = _ports_of(urls)
        # the firewall-evasion guess list must still include 443 and 9000
        self.assertIn(443, ports)
        self.assertIn(9000, ports)
        self.assertIn(80, ports)

    def test_no_settings_arg_uses_default_list(self):
        # backward-compat: settings defaults to None
        urls = build_targets_from_dns(_dns_recon())
        self.assertIn(443, _ports_of(urls))

    def test_subdomains_included(self):
        recon = _dns_recon(subdomains={
            "api.ex.com": {"has_records": True, "ips": {"ipv4": ["1.2.3.5"]}},
        })
        urls = build_targets_from_dns(recon, {"NAABU_CUSTOM_PORTS": "4280"})
        hosts = {u.split("//", 1)[1].split(":")[0].split("/")[0] for u in urls}
        self.assertIn("ex.com", hosts)
        self.assertIn("api.ex.com", hosts)

    def test_subdomain_without_records_skipped(self):
        recon = _dns_recon(subdomains={
            "dead.ex.com": {"has_records": False, "ips": {"ipv4": []}},
        })
        urls = build_targets_from_dns(recon, {"NAABU_CUSTOM_PORTS": "4280"})
        hosts = {u.split("//", 1)[1].split(":")[0] for u in urls}
        self.assertNotIn("dead.ex.com", hosts)

    def test_domain_without_records_skipped(self):
        recon = {
            "domain": "ex.com",
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                    "subdomains": {}},
        }
        urls = build_targets_from_dns(recon, {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(urls, [])

    def test_ip_mode_mock_subdomain_uses_actual_ip(self):
        recon = _dns_recon(
            domain="1.2.3.4",
            ipv4=[],  # no domain records; only mock subdomain
            subdomains={
                "mock-host": {
                    "has_records": True, "is_mock": True,
                    "actual_ip": "1.2.3.4", "ips": {"ipv4": ["1.2.3.4"]},
                },
            },
            metadata={"ip_mode": True},
        )
        # domain has no records here, so only the mock subdomain path fires
        recon["dns"]["domain"]["has_records"] = False
        urls = build_targets_from_dns(recon, {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(_ports_of(urls), {4280})
        self.assertTrue(all("1.2.3.4:4280" in u for u in urls))
        self.assertFalse(any("mock-host" in u for u in urls))


# ===========================================================================
# INTEGRATION: build_targets_from_naabu
# ===========================================================================
class TestBuildTargetsFromNaabu(unittest.TestCase):

    def _recon_with_ports(self, host, port_details):
        return {
            "domain": host,
            "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": {host: {"host": host, "port_details": port_details}}},
        }

    def test_real_ports_443_is_https_no_suffix(self):
        recon = self._recon_with_ports("ex.com", [{"port": 443, "service": "https"}])
        urls = build_targets_from_naabu(recon, {})
        self.assertEqual(urls, ["https://ex.com"])

    def test_unknown_port_4280_tries_both(self):
        recon = self._recon_with_ports("ex.com", [{"port": 4280, "service": ""}])
        urls = build_targets_from_naabu(recon, {})
        self.assertEqual(set(urls), {"http://ex.com:4280", "https://ex.com:4280"})

    def test_empty_by_host_falls_back_and_honors_custom(self):
        # THE core regression: naabu found nothing, custom scope = 4280
        recon = {
            "domain": "ex.com",
            "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": {}},
        }
        urls = build_targets_from_naabu(recon, {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(_ports_of(urls), {4280})
        self.assertNotIn(443, _ports_of(urls))
        self.assertNotIn(9000, _ports_of(urls))

    def test_empty_by_host_no_custom_uses_default_list(self):
        recon = {
            "domain": "ex.com",
            "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": {}},
        }
        urls = build_targets_from_naabu(recon, {})
        self.assertIn(9000, _ports_of(urls))


# ===========================================================================
# UNIT/INTEGRATION: apply_custom_port_scope (the hard guard)
# ===========================================================================
class TestApplyCustomPortScope(unittest.TestCase):

    def test_drops_out_of_scope_keeps_in_scope(self):
        urls = ["https://h", "http://h:9000", "https://h:4280", "http://h:4280"]
        kept, dropped, ports = apply_custom_port_scope(urls, {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(set(kept), {"https://h:4280", "http://h:4280"})
        self.assertEqual(dropped, 2)
        self.assertEqual(ports, {4280})

    def test_no_custom_is_passthrough(self):
        urls = ["https://h", "http://h:9000"]
        kept, dropped, ports = apply_custom_port_scope(urls, {})
        self.assertEqual(kept, urls)
        self.assertEqual(dropped, 0)
        self.assertEqual(ports, set())

    def test_enforce_flag_false_is_passthrough(self):
        # partial-recon opt-out: even with custom ports, nothing is dropped
        urls = ["http://h:8000", "https://h"]
        kept, dropped, _ = apply_custom_port_scope(
            urls, {"NAABU_CUSTOM_PORTS": "4280", "HTTPX_ENFORCE_CUSTOM_PORT_SCOPE": False}
        )
        self.assertEqual(kept, urls)
        self.assertEqual(dropped, 0)

    def test_enforce_flag_default_true(self):
        urls = ["http://h:8000"]
        kept, dropped, _ = apply_custom_port_scope(urls, {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(kept, [])
        self.assertEqual(dropped, 1)

    def test_default_scheme_port_respected(self):
        # https://h == port 443; in-scope when 443 is in custom set
        urls = ["https://h", "http://h"]
        kept, _, _ = apply_custom_port_scope(urls, {"NAABU_CUSTOM_PORTS": "443"})
        self.assertEqual(kept, ["https://h"])

    def test_empty_urls(self):
        kept, dropped, _ = apply_custom_port_scope([], {"NAABU_CUSTOM_PORTS": "4280"})
        self.assertEqual(kept, [])
        self.assertEqual(dropped, 0)

    def test_none_settings_passthrough(self):
        urls = ["https://h"]
        kept, dropped, _ = apply_custom_port_scope(urls, None)
        self.assertEqual(kept, urls)
        self.assertEqual(dropped, 0)


# ===========================================================================
# SMOKE: run_http_probe callsite wiring
# ===========================================================================
class TestRunHttpProbeWiring(unittest.TestCase):

    def test_run_http_probe_calls_the_guard(self):
        src = inspect.getsource(run_http_probe)
        self.assertIn("apply_custom_port_scope(urls, settings)", src)

    def test_run_http_probe_threads_settings_into_builders(self):
        src = inspect.getsource(run_http_probe)
        self.assertIn("build_targets_from_naabu(recon_data, settings)", src)
        self.assertIn("build_targets_from_dns(recon_data, settings)", src)


# ===========================================================================
# REGRESSION: issue #136 end-to-end URL selection
# ===========================================================================
class TestIssue136Regression(unittest.TestCase):
    """Reproduce the reported scenario at the URL-selection layer.

    Project: pentest-ground.com, custom port 4280, only Naabu enabled, and
    Naabu reports no open ports (empty by_host). The pipeline must NOT emit
    443/9000 URLs and MUST emit a 4280 probe attempt.
    """

    def _select_urls(self, recon, settings):
        """Mirror run_http_probe's URL-selection + guard, without Docker."""
        if recon.get("port_scan"):
            urls = build_targets_from_naabu(recon, settings)
        else:
            urls = build_targets_from_dns(recon, settings)
        urls, _dropped, _ports = apply_custom_port_scope(urls, settings)
        return urls

    def test_naabu_empty_custom_4280_no_phantom_ports(self):
        recon = {
            "domain": "pentest-ground.com",
            "dns": {"domain": {"ips": {"ipv4": ["178.79.134.182"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": {}},  # naabu found nothing
        }
        settings = {"NAABU_CUSTOM_PORTS": "4280", "HTTPX_ENFORCE_CUSTOM_PORT_SCOPE": True}
        urls = self._select_urls(recon, settings)

        ports = _ports_of(urls)
        self.assertEqual(ports, {4280}, f"expected only 4280, got {sorted(ports)}: {urls}")
        self.assertTrue(any("pentest-ground.com:4280" in u for u in urls))

    def test_leaked_upstream_port_is_filtered(self):
        # Even if a stray by_host port slipped through, the guard removes it.
        recon = {
            "domain": "pentest-ground.com",
            "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": {"pentest-ground.com": {
                "host": "pentest-ground.com",
                "port_details": [
                    {"port": 4280, "service": ""},
                    {"port": 9000, "service": "http"},   # leaked out-of-scope port
                ],
            }}},
        }
        settings = {"NAABU_CUSTOM_PORTS": "4280", "HTTPX_ENFORCE_CUSTOM_PORT_SCOPE": True}
        urls = self._select_urls(recon, settings)
        self.assertEqual(_ports_of(urls), {4280})

    def test_default_behavior_unchanged_when_no_custom(self):
        # Regression guard for the no-custom path: 443/9000 still probed.
        recon = {
            "domain": "pentest-ground.com",
            "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": {}},
        }
        urls = self._select_urls(recon, {})
        ports = _ports_of(urls)
        self.assertIn(443, ports)
        self.assertIn(9000, ports)


# ===========================================================================
# INTEGRATION: run_http_probe driven through the guard (Docker layer mocked)
# ===========================================================================
class TestRunHttpProbeIntegration(unittest.TestCase):
    """Exercise the REAL run_http_probe, mocking only the Docker/subprocess
    boundary, to prove the guard runs in the live function flow."""

    _HP = "recon.main_recon_modules.http_probe"

    def _recon(self, by_host):
        return {
            "domain": "ex.com",
            "dns": {"domain": {"ips": {"ipv4": ["1.2.3.4"]}, "has_records": True},
                    "subdomains": {}},
            "port_scan": {"by_host": by_host},
        }

    def test_all_out_of_scope_urls_trigger_early_return(self):
        from unittest.mock import patch
        from recon.main_recon_modules import http_probe as hp

        # naabu reported only an out-of-scope port; custom scope is 4280
        recon = self._recon({"ex.com": {"host": "ex.com",
                                        "port_details": [{"port": 9000, "service": "http"}]}})
        settings = {"NAABU_CUSTOM_PORTS": "4280", "HTTPX_ENFORCE_CUSTOM_PORT_SCOPE": True}

        with patch.object(hp, "is_docker_installed", return_value=True), \
             patch.object(hp, "is_docker_running", return_value=True), \
             patch.object(hp, "pull_httpx_docker_image", return_value=True), \
             patch.object(hp, "subprocess") as mock_sub:
            out = hp.run_http_probe(recon, output_file=None, settings=settings)

        # All URLs filtered -> early return BEFORE any subprocess call
        mock_sub.Popen.assert_not_called()
        self.assertNotIn("http_probe", out)

    def test_in_scope_urls_only_reach_targets_file(self):
        from unittest.mock import patch, MagicMock
        from recon.main_recon_modules import http_probe as hp

        recon = self._recon({"ex.com": {"host": "ex.com", "port_details": [
            {"port": 4280, "service": ""},     # in scope
            {"port": 9000, "service": "http"},  # out of scope, must be dropped
        ]}})
        settings = {"NAABU_CUSTOM_PORTS": "4280", "HTTPX_ENFORCE_CUSTOM_PORT_SCOPE": True}

        captured = {}

        def fake_popen(cmd, *a, **k):
            # targets file is written before Popen is invoked — read it now
            tfile = Path("/tmp/redamon/.httpx_temp/targets.txt")
            captured["lines"] = tfile.read_text().splitlines() if tfile.exists() else []
            raise RuntimeError("stop-after-capture")  # caught by run_http_probe

        with patch.object(hp, "is_docker_installed", return_value=True), \
             patch.object(hp, "is_docker_running", return_value=True), \
             patch.object(hp, "pull_httpx_docker_image", return_value=True), \
             patch.object(hp, "build_httpx_command", return_value=["true"]), \
             patch.object(hp.subprocess, "Popen", side_effect=fake_popen):
            hp.run_http_probe(recon, output_file=None, settings=settings)

        ports = {url_port(u) for u in captured.get("lines", [])}
        self.assertEqual(ports, {4280}, f"targets file should hold only 4280: {captured}")

    def test_partial_recon_opt_out_keeps_all_ports(self):
        from unittest.mock import patch
        from recon.main_recon_modules import http_probe as hp

        recon = self._recon({"ex.com": {"host": "ex.com", "port_details": [
            {"port": 8000, "service": "http"},
        ]}})
        # project-level custom ports differ from the partial-run port, but the
        # opt-out flag means run_http_probe must NOT drop 8000
        settings = {"NAABU_CUSTOM_PORTS": "4280", "HTTPX_ENFORCE_CUSTOM_PORT_SCOPE": False}

        captured = {}

        def fake_popen(cmd, *a, **k):
            tfile = Path("/tmp/redamon/.httpx_temp/targets.txt")
            captured["lines"] = tfile.read_text().splitlines() if tfile.exists() else []
            raise RuntimeError("stop-after-capture")

        with patch.object(hp, "is_docker_installed", return_value=True), \
             patch.object(hp, "is_docker_running", return_value=True), \
             patch.object(hp, "pull_httpx_docker_image", return_value=True), \
             patch.object(hp, "build_httpx_command", return_value=["true"]), \
             patch.object(hp.subprocess, "Popen", side_effect=fake_popen):
            hp.run_http_probe(recon, output_file=None, settings=settings)

        ports = {url_port(u) for u in captured.get("lines", [])}
        self.assertIn(8000, ports)


if __name__ == "__main__":
    unittest.main(verbosity=2)
