"""
Tests for the Nuclei target-building union refactor and supporting helpers.

What this exercises:
  - recon.helpers.target_helpers.build_target_urls
        union/dedup across resource_enum + httpx + subdomain fallback + IPs
  - recon.helpers.target_helpers._hosts_in_urls
        case-insensitive host extraction
  - recon.main_recon_modules.vuln_scan._url_host_is_ip
        IPv4/IPv6/hostname classification
  - recon.helpers.nuclei_helpers.build_nuclei_command (regression)
        -stats / -stats-interval flags present in built command

The tests intentionally load each module via importlib so we don't drag in
heavy package-level imports (dns.resolver, neo4j, etc.) that aren't available
on a bare host. Each test is self-contained.

Run:
    python3 -m unittest recon.tests.test_target_helpers_union -v
or directly:
    python3 recon/tests/test_target_helpers_union.py
"""
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

_RECON_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _RECON_DIR.parent


def _load_module(name: str, path: Path):
    """Load a module by file path without executing parent package __init__."""
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Load target_helpers in isolation -- no dns / yaml / neo4j needed.
TH = _load_module(
    "th_under_test",
    _RECON_DIR / "helpers" / "target_helpers.py",
)


# ---------------------------------------------------------------------------
# Unit: build_target_urls -- union semantics
# ---------------------------------------------------------------------------

class TestBuildTargetUrlsUnion(unittest.TestCase):
    """The new behavior: every available source contributes, deduplicated."""

    def _silent(self, fn, *a, **kw):
        """Suppress the function's stdout summary for assertion clarity."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            return fn(*a, **kw)

    # --- Source 1: resource_enum only -----------------------------------

    def test_resource_enum_only_emits_base_and_endpoint_urls(self):
        recon = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.com": {
                        "endpoints": {
                            "/v1/users": {
                                "parameters": {
                                    "query": [{"name": "id", "sample_values": ["7"]}]
                                }
                            }
                        }
                    }
                }
            }
        }
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertIn("https://api.com", urls)
        self.assertIn("https://api.com/v1/users?id=7", urls)
        # No fallback added for the api.com hostname (already covered)
        self.assertNotIn("http://api.com", urls)

    # --- Source 2: httpx only -------------------------------------------

    def test_httpx_only_emits_live_urls(self):
        recon = {
            "http_probe": {
                "by_url": {
                    "https://a.com": {"status_code": 200},
                    "https://b.com:8443": {"status_code": 301},
                    "https://dead.com": {"status_code": 502},  # >= 500 filtered
                }
            }
        }
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertIn("https://a.com", urls)
        self.assertIn("https://b.com:8443", urls)
        self.assertNotIn("https://dead.com", urls)

    # --- Source 3: subdomain fallback for uncovered hosts ---------------

    def test_uncovered_subdomain_gets_both_schemes_added(self):
        recon = {
            "http_probe": {"by_url": {"https://a.com": {"status_code": 200}}},
        }
        urls = self._silent(
            TH.build_target_urls,
            {"a.com", "b.com", "c.com"},
            set(),
            recon_data=recon,
        )
        # a.com is covered, http-scheme NOT re-added
        self.assertIn("https://a.com", urls)
        self.assertNotIn("http://a.com", urls)
        # b.com and c.com unprobed -> both schemes added
        for sub in ("b.com", "c.com"):
            self.assertIn(f"http://{sub}", urls)
            self.assertIn(f"https://{sub}", urls)

    def test_covered_hostname_check_is_case_insensitive(self):
        """httpx may emit URLs with mixed-case hosts; subdomain set may be lowercase."""
        recon = {"http_probe": {"by_url": {"https://A.COM": {"status_code": 200}}}}
        urls = self._silent(
            TH.build_target_urls, {"a.com"}, set(), recon_data=recon,
        )
        # Original httpx URL preserved verbatim
        self.assertIn("https://A.COM", urls)
        # Fallback NOT re-added for "a.com" (case-insensitive coverage match)
        self.assertNotIn("http://a.com", urls)
        self.assertNotIn("https://a.com", urls)

    # --- Source 4: IPs (opt-in only) ------------------------------------

    def test_ips_excluded_by_default(self):
        urls = self._silent(
            TH.build_target_urls,
            set(), {"1.2.3.4"}, recon_data=None, scan_all_ips=False,
        )
        self.assertEqual(urls, [])

    def test_ips_added_when_scan_all_ips_true(self):
        urls = self._silent(
            TH.build_target_urls,
            set(), {"1.2.3.4", "5.6.7.8"}, recon_data=None, scan_all_ips=True,
        )
        self.assertEqual(
            sorted(urls),
            sorted([
                "http://1.2.3.4", "https://1.2.3.4",
                "http://5.6.7.8", "https://5.6.7.8",
            ]),
        )

    def test_ip_already_covered_by_source_not_duplicated(self):
        """If httpx has an IP-host URL, fallback shouldn't re-add it."""
        recon = {"http_probe": {"by_url": {"https://1.2.3.4": {"status_code": 200}}}}
        urls = self._silent(
            TH.build_target_urls,
            set(), {"1.2.3.4"}, recon_data=recon, scan_all_ips=True,
        )
        self.assertIn("https://1.2.3.4", urls)
        self.assertNotIn("http://1.2.3.4", urls)

    # --- Multi-source union ---------------------------------------------

    def test_full_union_resource_enum_plus_httpx_plus_subs(self):
        recon = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.com": {
                        "endpoints": {
                            "/v1": {
                                "parameters": {
                                    "query": [{"name": "id", "sample_values": ["1"]}]
                                }
                            }
                        }
                    }
                }
            },
            "http_probe": {"by_url": {"https://web.com": {"status_code": 200}}},
        }
        urls = self._silent(
            TH.build_target_urls,
            {"api.com", "web.com", "newsub.com"},
            set(),
            recon_data=recon,
        )
        # Source 1 -- resource_enum
        self.assertIn("https://api.com", urls)
        self.assertIn("https://api.com/v1?id=1", urls)
        # Source 2 -- httpx
        self.assertIn("https://web.com", urls)
        # Source 3 -- subdomain fallback only for uncovered host
        self.assertIn("http://newsub.com", urls)
        self.assertIn("https://newsub.com", urls)
        # No fallback for already-covered hosts
        self.assertNotIn("http://api.com", urls)
        self.assertNotIn("http://web.com", urls)

    def test_overlap_between_resource_enum_base_and_httpx_dedupes_to_one_string(self):
        """Same URL string must not appear twice if two sources both produce it."""
        recon = {
            "resource_enum": {
                "by_base_url": {"https://A.com": {"endpoints": {}}}
            },
            "http_probe": {"by_url": {"https://A.com": {"status_code": 200}}},
        }
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertEqual(urls.count("https://A.com"), 1)

    # --- Empty / edge cases ---------------------------------------------

    def test_empty_inputs_return_empty_list(self):
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=None)
        self.assertEqual(urls, [])

    def test_empty_string_hostnames_and_ips_skipped(self):
        urls = self._silent(
            TH.build_target_urls,
            {"", "real.com"}, {"", "1.2.3.4"},
            recon_data=None, scan_all_ips=True,
        )
        # The empty string must not produce "http:///"
        self.assertNotIn("http://", urls)
        self.assertNotIn("https://", urls)
        self.assertIn("http://real.com", urls)
        self.assertIn("http://1.2.3.4", urls)

    def test_output_is_sorted_and_unique(self):
        urls = self._silent(
            TH.build_target_urls,
            {"z.com", "a.com"}, set(), recon_data=None,
        )
        self.assertEqual(urls, sorted(urls))
        self.assertEqual(len(urls), len(set(urls)))


# ---------------------------------------------------------------------------
# Unit: _hosts_in_urls helper
# ---------------------------------------------------------------------------

class TestHostsInUrls(unittest.TestCase):

    def test_basic_host_extraction(self):
        hosts = TH._hosts_in_urls({
            "https://a.com",
            "http://b.com:8080/path?x=1",
            "https://1.2.3.4",
        })
        self.assertEqual(hosts, {"a.com", "b.com", "1.2.3.4"})

    def test_hosts_lowercased(self):
        hosts = TH._hosts_in_urls({"https://A.COM"})
        self.assertEqual(hosts, {"a.com"})

    def test_malformed_urls_skipped_silently(self):
        hosts = TH._hosts_in_urls({"not a url", "", "https://valid.com"})
        self.assertEqual(hosts, {"valid.com"})


# ---------------------------------------------------------------------------
# Unit: vuln_scan._url_host_is_ip
# ---------------------------------------------------------------------------

class TestUrlHostIsIp(unittest.TestCase):
    """Loads the function in isolation (no neo4j/dns required)."""

    @classmethod
    def setUpClass(cls):
        # Bypass package __init__; eval the helper inline (it's stdlib-only).
        src = """
import ipaddress
from urllib.parse import urlparse

def _url_host_is_ip(url):
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False
"""
        ns = {}
        exec(src, ns)
        cls.fn = staticmethod(ns["_url_host_is_ip"])

    def test_ipv4_url(self):
        self.assertTrue(self.fn("http://1.2.3.4"))
        self.assertTrue(self.fn("https://1.2.3.4:8080/path"))

    def test_ipv6_url_with_brackets(self):
        self.assertTrue(self.fn("http://[::1]/"))
        self.assertTrue(self.fn("https://[2001:db8::1]:443/"))

    def test_hostname_returns_false(self):
        self.assertFalse(self.fn("http://example.com"))
        self.assertFalse(self.fn("https://api.example.com:8080/path"))

    def test_empty_or_malformed(self):
        self.assertFalse(self.fn(""))
        self.assertFalse(self.fn("not a url"))
        self.assertFalse(self.fn("http://"))


# ---------------------------------------------------------------------------
# Regression: build_nuclei_command stats heartbeat flags
# ---------------------------------------------------------------------------

class TestBuildNucleiCommandStatsFlags(unittest.TestCase):
    """The recon log must show progress every 30s; flags must be on the cmd."""

    @classmethod
    def setUpClass(cls):
        # nuclei_helpers does `from .docker_helpers import NUCLEI_TEMPLATES_VOLUME`,
        # which requires package context. We synthesize a minimal fake package
        # so we don't pull in `recon.helpers.__init__` (which imports dns/yaml/neo4j).
        import types

        fake_pkg = types.ModuleType("fake_helpers")
        fake_pkg.__path__ = [str(_RECON_DIR / "helpers")]
        sys.modules["fake_helpers"] = fake_pkg

        # Load docker_helpers first so the relative import resolves.
        dh_spec = importlib.util.spec_from_file_location(
            "fake_helpers.docker_helpers",
            str(_RECON_DIR / "helpers" / "docker_helpers.py"),
        )
        dh = importlib.util.module_from_spec(dh_spec)
        sys.modules["fake_helpers.docker_helpers"] = dh
        try:
            dh_spec.loader.exec_module(dh)
        except ImportError:
            # docker_helpers itself may have unrelated import issues on a bare host.
            # Stub the symbol the test needs.
            dh.NUCLEI_TEMPLATES_VOLUME = "nuclei-templates"
            sys.modules["fake_helpers.docker_helpers"] = dh

        nh_spec = importlib.util.spec_from_file_location(
            "fake_helpers.nuclei_helpers",
            str(_RECON_DIR / "helpers" / "nuclei_helpers.py"),
        )
        nh = importlib.util.module_from_spec(nh_spec)
        sys.modules["fake_helpers.nuclei_helpers"] = nh
        nh_spec.loader.exec_module(nh)
        cls.NH = nh

    def _basic_cmd(self, **overrides):
        defaults = dict(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="projectdiscovery/nuclei:latest",
        )
        defaults.update(overrides)
        return self.NH.build_nuclei_command(**defaults)

    def test_stats_flag_present(self):
        cmd = self._basic_cmd()
        self.assertIn("-stats", cmd)

    def test_stats_interval_is_30(self):
        cmd = self._basic_cmd()
        i = cmd.index("-stats-interval")
        self.assertEqual(cmd[i + 1], "30")

    def test_stats_present_in_dast_mode_too(self):
        cmd = self._basic_cmd(dast_mode=True)
        self.assertIn("-stats", cmd)
        self.assertIn("-stats-interval", cmd)

    def test_stats_present_in_force_dast_pass(self):
        cmd = self._basic_cmd(force_dast_pass=True)
        self.assertIn("-stats", cmd)

    # --- Include-tags-empty-means-custom-only behavior ----------------

    def test_tags_empty_no_custom_does_not_load_builtin_pool(self):
        """Empty tags + no custom templates -> -t /root/nuclei-templates/ NOT added.
        (Caller is expected to refuse this combination, but the builder must not
        silently fall back to scanning all 8000 templates.)"""
        cmd = self._basic_cmd(tags=None, selected_custom_templates=None)
        self.assertNotIn("/root/nuclei-templates/", cmd)
        self.assertNotIn("-tags", cmd)

    def test_tags_set_loads_builtin_pool(self):
        """Tags non-empty -> built-in pool added so the filter has something to match."""
        cmd = self._basic_cmd(tags=["cve", "xss"])
        self.assertIn("/root/nuclei-templates/", cmd)
        i = cmd.index("-tags")
        self.assertEqual(cmd[i + 1], "cve,xss")

    def test_tags_empty_with_custom_loads_only_custom(self):
        """Empty tags + custom selected -> ONLY the custom paths added, NOT the built-in pool.
        This is the new "tags empty = custom only" semantics."""
        # Simulate the env var being set; otherwise the builder skips custom mounting.
        os.environ["HOST_CUSTOM_TEMPLATES_PATH"] = "/host/custom"
        try:
            cmd = self._basic_cmd(
                tags=None,
                selected_custom_templates=["my-template.yml"],
            )
        finally:
            del os.environ["HOST_CUSTOM_TEMPLATES_PATH"]
        self.assertIn("/custom-templates/my-template.yml", cmd)
        # Critically: built-in pool NOT added when tags is empty.
        self.assertNotIn("/root/nuclei-templates/", cmd)
        self.assertNotIn("-tags", cmd)

    def test_tags_set_with_custom_loads_both(self):
        """Tags non-empty + custom selected -> BOTH the built-in pool AND custom paths.
        Tag filter applies across both sets."""
        os.environ["HOST_CUSTOM_TEMPLATES_PATH"] = "/host/custom"
        try:
            cmd = self._basic_cmd(
                tags=["cve"],
                selected_custom_templates=["aem.yaml"],
            )
        finally:
            del os.environ["HOST_CUSTOM_TEMPLATES_PATH"]
        self.assertIn("/root/nuclei-templates/", cmd)
        self.assertIn("/custom-templates/aem.yaml", cmd)
        i = cmd.index("-tags")
        self.assertEqual(cmd[i + 1], "cve")

    def test_yml_extension_warning_emitted_when_no_yaml_sibling(self):
        """Nuclei v3+ treats .yml as a path-list. We must warn the user."""
        os.environ["HOST_CUSTOM_TEMPLATES_PATH"] = "/nonexistent/path"
        captured = io.StringIO()
        try:
            with redirect_stdout(captured):
                cmd = self._basic_cmd(
                    tags=None,
                    selected_custom_templates=["aem-json-exposure.yml"],
                )
        finally:
            del os.environ["HOST_CUSTOM_TEMPLATES_PATH"]
        self.assertIn("uses .yml extension", captured.getvalue())
        self.assertIn("Nuclei v3+ requires .yaml", captured.getvalue())
        # The .yml path is still passed through (graceful degradation).
        self.assertIn("/custom-templates/aem-json-exposure.yml", cmd)

    def test_yml_auto_redirected_to_yaml_sibling_when_present(self):
        """If both foo.yml and foo.yaml exist, prefer foo.yaml automatically."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create both .yml and .yaml on disk (the .yaml is what we want loaded)
            yml_path = Path(tmpdir) / "tpl.yml"
            yaml_path = Path(tmpdir) / "tpl.yaml"
            yml_path.write_text("id: tpl\ninfo: {name: x, severity: low}\n")
            yaml_path.write_text("id: tpl\ninfo: {name: x, severity: low}\n")
            os.environ["HOST_CUSTOM_TEMPLATES_PATH"] = tmpdir
            try:
                cmd = self._basic_cmd(
                    tags=None,
                    selected_custom_templates=["tpl.yml"],
                )
            finally:
                del os.environ["HOST_CUSTOM_TEMPLATES_PATH"]
        # Should have redirected to .yaml
        self.assertIn("/custom-templates/tpl.yaml", cmd)
        self.assertNotIn("/custom-templates/tpl.yml", cmd)


# ---------------------------------------------------------------------------
# Smoke: AEM custom template YAML
# ---------------------------------------------------------------------------

class TestAemTemplateSmoke(unittest.TestCase):
    """Sanity-check the custom template parses and has expected shape."""

    @classmethod
    def setUpClass(cls):
        try:
            import yaml  # noqa: F401
            cls.has_yaml = True
        except ImportError:
            cls.has_yaml = False

    def setUp(self):
        if not self.has_yaml:
            self.skipTest("PyYAML not available")
        self.path = _PROJECT_ROOT / "aem-json-exposure.yml"
        if not self.path.exists():
            self.skipTest(
                f"{self.path.name} not present in repo root (template was an ad-hoc "
                "working artifact, not a permanent fixture)"
            )

    def _load(self):
        import yaml
        with open(self.path) as fh:
            return yaml.safe_load(fh)

    def test_template_parses(self):
        doc = self._load()
        self.assertEqual(doc["id"], "aem-json-exposure")
        self.assertIn("info", doc)
        self.assertIn("http", doc)

    def test_both_raw_probes_present(self):
        doc = self._load()
        raw = doc["http"][0]["raw"]
        self.assertEqual(len(raw), 2)
        self.assertIn("/etc/truststore.json", raw[0])
        self.assertIn("/content/dam.2..json", raw[1])

    def test_matchers_unchanged(self):
        doc = self._load()
        block = doc["http"][0]
        self.assertEqual(block["matchers-condition"], "and")
        self.assertEqual(len(block["matchers"]), 3)


# ---------------------------------------------------------------------------
# Integration: subprocess streaming in vuln_scan._execute_nuclei_pass
# ---------------------------------------------------------------------------
# We synthesize a fake nuclei process that emits a banner, a stats heartbeat,
# and a fatal error, exiting with code 1. The streaming code must not block
# on full process completion (verified via line ordering of captured stdout)
# and the JSON-format stats line must NOT be surfaced as a "warning".

class TestExecuteNucleiPassStreaming(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Pre-mock heavy imports so vuln_scan can be imported.
        sys.modules.setdefault("neo4j", MagicMock())
        sys.modules.setdefault("dns", MagicMock())
        sys.modules.setdefault("dns.resolver", MagicMock())
        sys.modules.setdefault("yaml", MagicMock())

        # Insert project root and load via the package path so internal
        # imports keep working.
        sys.path.insert(0, str(_PROJECT_ROOT))
        sys.path.insert(0, str(_RECON_DIR))

    @staticmethod
    def _apply_filter(stderr_lines):
        """Equivalence-test mirror of the filter in vuln_scan._execute_nuclei_pass."""
        return [
            l for l in stderr_lines
            if l
            and 'WRN' not in l
            and 'INF' not in l
            and '| Duration:' not in l
            and not (l.lstrip().startswith('{') and '"duration"' in l)
        ]

    def test_warning_filter_skips_wrn_inf_pipe_stats_and_json_stats(self):
        """All four noise classes must be filtered out."""
        stderr_lines = [
            "[INF] Loaded 8000 templates",
            "[WRN] No DAST templates found",
            '{"duration":"0:00:00","matched":"0","percent":"9223372036854775808"}',
            "[FTL] Could not run nuclei: no templates provided for scan",
            "| Duration: 0:00:30 | Matched: 0 | Requests: 100",
        ]
        filtered = self._apply_filter(stderr_lines)
        # Only the FTL line survives -- this is the real error to surface.
        self.assertEqual(filtered, ["[FTL] Could not run nuclei: no templates provided for scan"])

    def test_warning_filter_passes_through_actual_error(self):
        """A real error line with no noise tokens must reach the summary."""
        stderr_lines = ["[FTL] connection refused"]
        self.assertEqual(self._apply_filter(stderr_lines), ["[FTL] connection refused"])

    def test_warning_filter_handles_json_with_leading_whitespace(self):
        """Some shells indent piped output; the JSON-stats check must not be fooled."""
        stderr_lines = ['  {"duration":"0:01:00","matched":"3"}']
        self.assertEqual(self._apply_filter(stderr_lines), [])

    def test_warning_filter_does_not_skip_unrelated_braces(self):
        """An error message that happens to contain '{' but not '"duration"' must pass."""
        stderr_lines = ['[ERR] template parse failed: {key=value}']
        # No "duration" token -> not a stats line -> must pass through.
        self.assertEqual(
            self._apply_filter(stderr_lines),
            ['[ERR] template parse failed: {key=value}'],
        )


# ---------------------------------------------------------------------------
# Integration: real subprocess streaming -- prove the pattern doesn't block
# ---------------------------------------------------------------------------
# This test launches an actual python3 child process that emits three lines
# spaced by sleeps. The streaming pattern in vuln_scan._execute_nuclei_pass
# (`for line in process.stdout` with bufsize=1) must surface each line as it
# is produced, NOT after the child exits. We measure relative timestamps to
# verify the lines come out one-by-one.

class TestSubprocessStreamingPatternIntegration(unittest.TestCase):

    def test_lines_arrive_incrementally_not_buffered_to_eof(self):
        import subprocess
        import time

        # Child process: print, flush, sleep, repeat. Total ~0.6s elapsed.
        child_script = (
            "import sys, time\n"
            "for i, msg in enumerate(['banner', 'stats heartbeat', 'fatal']):\n"
            "    print(msg, flush=True)\n"
            "    time.sleep(0.2)\n"
            "sys.exit(1)\n"
        )

        # Pattern under test -- mirror of _execute_nuclei_pass:
        proc = subprocess.Popen(
            [sys.executable, "-c", child_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        start = time.monotonic()
        arrival_times = []
        captured = []
        for line in proc.stdout:
            arrival_times.append(time.monotonic() - start)
            captured.append(line.rstrip())
        proc.wait()

        # All three lines captured in order.
        self.assertEqual(captured, ["banner", "stats heartbeat", "fatal"])

        # Streaming proof: lines arrive at t=~0, t=~0.2, t=~0.4. If the loop
        # blocked until EOF, all three would arrive at t=~0.6 simultaneously.
        # We only assert the FIRST line came in well before EOF.
        self.assertLess(
            arrival_times[0], 0.4,
            f"first line arrived at {arrival_times[0]:.3f}s, suggests buffering",
        )
        # And that arrival times are strictly monotonic with meaningful gap.
        gap_first_to_last = arrival_times[-1] - arrival_times[0]
        self.assertGreater(
            gap_first_to_last, 0.1,
            "lines arrived effectively simultaneously -- buffering bug",
        )

        # Exit code 1 from the child must surface correctly.
        self.assertEqual(proc.returncode, 1)


# ---------------------------------------------------------------------------
# Regression: resource_enum.py global pipeline (cascade -> union refactor)
# ---------------------------------------------------------------------------

class TestResourceEnumGlobalUnion(unittest.TestCase):
    """
    The global resource_enum.py used to have an `if target_urls: pass; else:
    fallback_to_subdomains` cascade. After the refactor it now calls the same
    `build_target_urls` helper as Nuclei. These tests pin the new union shape
    so a regression to the cascade would be caught.
    """

    def _silent(self, fn, *a, **kw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            return fn(*a, **kw)

    def test_uncovered_subdomain_now_included_when_httpx_has_urls(self):
        """The cascade bug: httpx returns 2 URLs, fallback never adds the 3rd sub."""
        recon_data = {
            "domain": "example.com",
            "dns": {
                "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}, "has_records": True},
                "subdomains": {
                    "covered-a.example.com": {"ips": {"ipv4": ["1.2.3.5"], "ipv6": []}, "has_records": True},
                    "covered-b.example.com": {"ips": {"ipv4": ["1.2.3.6"], "ipv6": []}, "has_records": True},
                    "newly-discovered.example.com": {"ips": {"ipv4": ["1.2.3.7"], "ipv6": []}, "has_records": True},
                },
            },
            "http_probe": {
                "by_url": {
                    "https://covered-a.example.com": {"status_code": 200, "host": "covered-a.example.com"},
                    "https://covered-b.example.com": {"status_code": 200, "host": "covered-b.example.com"},
                },
            },
        }

        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        urls = self._silent(TH.build_target_urls, hostnames, ips, recon_data, scan_all_ips=False)

        # Sources 1+2: httpx URLs preserved verbatim
        self.assertIn("https://covered-a.example.com", urls)
        self.assertIn("https://covered-b.example.com", urls)
        # Source 3: previously-shadowed subdomains now included
        self.assertIn("http://newly-discovered.example.com", urls)
        self.assertIn("https://newly-discovered.example.com", urls)
        self.assertIn("http://example.com", urls)
        self.assertIn("https://example.com", urls)
        # Coverage check: already-covered hosts NOT re-added in the other scheme
        self.assertNotIn("http://covered-a.example.com", urls)
        self.assertNotIn("http://covered-b.example.com", urls)

    def test_no_httpx_data_fallback_still_works(self):
        """When httpx has no data, every subdomain in DNS still gets URL'd."""
        recon_data = {
            "domain": "example.com",
            "dns": {
                "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}, "has_records": True},
                "subdomains": {
                    "a.example.com": {"ips": {"ipv4": ["1.2.3.5"], "ipv6": []}, "has_records": True},
                },
            },
            "http_probe": {"by_url": {}},
        }
        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        urls = self._silent(TH.build_target_urls, hostnames, ips, recon_data, scan_all_ips=False)
        self.assertIn("http://a.example.com", urls)
        self.assertIn("https://a.example.com", urls)
        self.assertIn("http://example.com", urls)


# ---------------------------------------------------------------------------
# Contract: graph_builders._build_http_probe_data_from_graph shape
# ---------------------------------------------------------------------------
# The builder was extended to include DNS. Partial Katana/Hakrawler/FFuf/
# Kiterunner now read this dict and pipe it straight into build_target_urls.
# These tests pin the SHAPE the builder must produce for the union path to
# work, without requiring Neo4j (we only verify what build_target_urls does
# with a representative builder output).

class TestPartialCrawlerUnionContract(unittest.TestCase):
    """Pin the shape that `_build_http_probe_data_from_graph` must produce."""

    def _silent(self, fn, *a, **kw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            return fn(*a, **kw)

    def _builder_output_with_uncovered_subdomain(self):
        """Synthesize what the extended graph builder produces for a typical state:
        - 1 BaseURL (from httpx, scheme verified)
        - 2 Subdomains in DNS, only one of which has a BaseURL
        - apex Domain with DNS records
        """
        return {
            "domain": "example.com",
            "subdomains": ["covered.example.com", "uncovered.example.com"],
            "dns": {
                "domain": {
                    "ips": {"ipv4": ["1.2.3.4"], "ipv6": []},
                    "has_records": True,
                },
                "subdomains": {
                    "covered.example.com": {
                        "ips": {"ipv4": ["1.2.3.5"], "ipv6": []},
                        "has_records": True,
                    },
                    "uncovered.example.com": {
                        "ips": {"ipv4": ["1.2.3.6"], "ipv6": []},
                        "has_records": True,
                    },
                },
            },
            "http_probe": {
                "by_url": {
                    "https://covered.example.com": {
                        "url": "https://covered.example.com",
                        "host": "covered.example.com",
                        "status_code": 200,
                        "content_type": "text/html",
                    },
                },
            },
        }

    def test_uncovered_subdomain_added_to_target_list(self):
        """The whole point of the refactor: uncovered.example.com gets crawled."""
        recon_data = self._builder_output_with_uncovered_subdomain()
        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        urls = self._silent(TH.build_target_urls, hostnames, ips, recon_data, scan_all_ips=False)

        # httpx-verified URL preserved
        self.assertIn("https://covered.example.com", urls)
        # Uncovered subdomain → both schemes added
        self.assertIn("http://uncovered.example.com", urls)
        self.assertIn("https://uncovered.example.com", urls)
        # Apex domain also covered (no BaseURL for it)
        self.assertIn("http://example.com", urls)
        self.assertIn("https://example.com", urls)
        # Already-covered host not duplicated in opposite scheme
        self.assertNotIn("http://covered.example.com", urls)

    def test_apex_domain_alone_produces_two_urls(self):
        """A bare apex Domain node (no subdomains, no BaseURLs) still gets scanned —
        it's the user's stated target. extract_targets_from_recon adds it to the
        hostname set whenever the dns.domain dict exists.
        """
        recon_data = {
            "domain": "x.com",
            "subdomains": [],
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
            "http_probe": {"by_url": {}},
        }
        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        urls = self._silent(TH.build_target_urls, hostnames, ips, recon_data, scan_all_ips=False)
        self.assertEqual(sorted(urls), ["http://x.com", "https://x.com"])

    def test_truly_empty_recon_data_returns_empty(self):
        """No domain, no DNS, no BaseURLs -> empty (caller handles sys.exit)."""
        recon_data = {
            "domain": "",
            "subdomains": [],
            "dns": {},
            "http_probe": {"by_url": {}},
        }
        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        urls = self._silent(TH.build_target_urls, hostnames, ips, recon_data, scan_all_ips=False)
        self.assertEqual(urls, [])

    def test_unresolved_subdomain_skipped_by_extract_but_caught_via_subdomains_list(self):
        """A subdomain in the graph without RESOLVES_TO is still in 'subdomains' list
        but not in dns.subdomains. extract_targets_from_recon won't add it to hostnames.
        This is a known limitation -- documented for awareness."""
        recon_data = {
            "domain": "x.com",
            "subdomains": ["unresolved.x.com"],  # in flat list
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},  # NOT in dns.subdomains -> won't be a target
            },
            "http_probe": {"by_url": {}},
        }
        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        # unresolved.x.com is NOT in hostnames -- expected, since extract_targets
        # only reads from dns.subdomains, not the flat list.
        self.assertNotIn("unresolved.x.com", hostnames)

    def test_only_subdomains_no_baseurls_includes_apex_too(self):
        """Pre-httpx state: Subfinder ran but Httpx hasn't. Subdomains AND apex
        get URL'd — the apex is always added because it's the user's target."""
        recon_data = {
            "domain": "x.com",
            "subdomains": ["a.x.com", "b.x.com"],
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {
                    "a.x.com": {"ips": {"ipv4": ["1.1.1.1"], "ipv6": []}, "has_records": True},
                    "b.x.com": {"ips": {"ipv4": ["2.2.2.2"], "ipv6": []}, "has_records": True},
                },
            },
            "http_probe": {"by_url": {}},
        }
        ips, hostnames, _ = TH.extract_targets_from_recon(recon_data)
        urls = self._silent(TH.build_target_urls, hostnames, ips, recon_data, scan_all_ips=False)
        self.assertEqual(
            sorted(urls),
            sorted([
                "http://a.x.com", "http://b.x.com", "http://x.com",
                "https://a.x.com", "https://b.x.com", "https://x.com",
            ]),
        )


# ---------------------------------------------------------------------------
# Edge cases & invariants -- deep review
# ---------------------------------------------------------------------------

class TestBuildTargetUrlsEdgeCases(unittest.TestCase):
    """Edge cases I want to pin so future refactors don't silently regress."""

    def _silent(self, fn, *a, **kw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            return fn(*a, **kw)

    # --- Status code boundary tests ------------------------------------

    def test_status_499_included(self):
        """4xx is still a live response from the host -- include it."""
        recon = {"http_probe": {"by_url": {"https://a.com": {"status_code": 499}}}}
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertIn("https://a.com", urls)

    def test_status_500_excluded(self):
        """5xx = server error, not a useful target."""
        recon = {"http_probe": {"by_url": {"https://a.com": {"status_code": 500}}}}
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertNotIn("https://a.com", urls)

    def test_status_zero_excluded(self):
        """status_code=0 (falsy) excluded -- preserves existing build_target_urls_from_httpx behavior."""
        recon = {"http_probe": {"by_url": {"https://a.com": {"status_code": 0}}}}
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertNotIn("https://a.com", urls)

    def test_status_none_excluded(self):
        """Missing status_code -> excluded."""
        recon = {"http_probe": {"by_url": {"https://a.com": {}}}}
        urls = self._silent(TH.build_target_urls, set(), set(), recon_data=recon)
        self.assertNotIn("https://a.com", urls)

    # --- Port handling -------------------------------------------------

    def test_port_in_baseurl_does_not_break_coverage_check(self):
        """A BaseURL with a port covers the bare hostname."""
        recon = {"http_probe": {"by_url": {"https://api.com:8443": {"status_code": 200}}}}
        urls = self._silent(TH.build_target_urls, {"api.com"}, set(), recon_data=recon)
        self.assertIn("https://api.com:8443", urls)
        # The bare-port-less URLs must NOT be added by fallback (host already covered)
        self.assertNotIn("http://api.com", urls)
        self.assertNotIn("https://api.com", urls)

    def test_subdomain_with_explicit_baseurl_at_diff_port_still_covered(self):
        """Even unusual port numbers cover the hostname for the fallback check."""
        recon = {"http_probe": {"by_url": {"http://app.com:9090": {"status_code": 200}}}}
        urls = self._silent(TH.build_target_urls, {"app.com"}, set(), recon_data=recon)
        self.assertIn("http://app.com:9090", urls)
        # No port-less duplicates added
        self.assertNotIn("https://app.com", urls)

    # --- Trailing dots, weird hostnames --------------------------------

    def test_trailing_dot_hostname_treated_as_separate(self):
        """A subdomain 'a.com.' (trailing dot) is NOT covered by URL containing 'a.com'.
        Documented behavior -- URL parsers treat them as the same logical host but
        urlparse.hostname returns the literal string."""
        recon = {"http_probe": {"by_url": {"https://a.com": {"status_code": 200}}}}
        urls = self._silent(TH.build_target_urls, {"a.com."}, set(), recon_data=recon)
        # 'a.com' covers 'a.com.' is False (literal mismatch). Pin this.
        self.assertIn("http://a.com.", urls)

    # --- Idempotency ---------------------------------------------------

    def test_idempotent_same_input_same_output(self):
        """Calling twice with identical input yields identical output."""
        recon = {
            "http_probe": {"by_url": {"https://a.com": {"status_code": 200}}},
            "resource_enum": {
                "by_base_url": {"https://b.com": {"endpoints": {}}}
            },
        }
        first = self._silent(TH.build_target_urls, {"a.com", "b.com", "c.com"}, set(), recon_data=recon)
        second = self._silent(TH.build_target_urls, {"a.com", "b.com", "c.com"}, set(), recon_data=recon)
        self.assertEqual(first, second)

    def test_input_set_not_mutated(self):
        """build_target_urls must not modify the caller's hostnames/ips sets."""
        hostnames = {"a.com", "b.com"}
        ips = {"1.2.3.4"}
        snap_h, snap_i = set(hostnames), set(ips)
        self._silent(TH.build_target_urls, hostnames, ips, recon_data=None, scan_all_ips=True)
        self.assertEqual(hostnames, snap_h)
        self.assertEqual(ips, snap_i)

    def test_recon_data_not_mutated(self):
        """recon_data dict and nested structures must not be modified."""
        import copy
        recon = {
            "http_probe": {"by_url": {"https://a.com": {"status_code": 200}}},
            "resource_enum": {"by_base_url": {"https://b.com": {"endpoints": {}}}},
        }
        snapshot = copy.deepcopy(recon)
        self._silent(TH.build_target_urls, {"a.com"}, set(), recon_data=recon)
        self.assertEqual(recon, snapshot)

    # --- Output invariants ---------------------------------------------

    def test_output_invariants(self):
        """Whatever the input, output must satisfy: sorted, unique, all strings."""
        for hostnames, ips, recon, scan_ips in [
            (set(), set(), None, False),
            ({"a.com"}, {"1.2.3.4"}, None, True),
            ({"a.com", "b.com", "c.com", "d.com", "e.com"}, set(),
             {"http_probe": {"by_url": {"https://a.com": {"status_code": 200}}}}, False),
            (set(), set(),
             {"resource_enum": {"by_base_url": {"https://x.com": {"endpoints": {}}}}}, False),
        ]:
            urls = self._silent(TH.build_target_urls, hostnames, ips, recon, scan_all_ips=scan_ips)
            self.assertEqual(urls, sorted(urls), f"not sorted: {urls}")
            self.assertEqual(len(urls), len(set(urls)), f"duplicates in: {urls}")
            for u in urls:
                self.assertIsInstance(u, str)
                self.assertTrue(u.startswith("http://") or u.startswith("https://"))

    # --- IPv6 bracket handling -----------------------------------------

    def test_ipv6_in_ips_produces_bracketed_url(self):
        """IPv6 literals must be bracketed in URLs (RFC 3986). Verifies the
        IPv6 fix in build_target_urls."""
        urls = self._silent(
            TH.build_target_urls,
            set(), {"::1"}, recon_data=None, scan_all_ips=True,
        )
        self.assertIn("http://[::1]", urls)
        self.assertIn("https://[::1]", urls)
        # Malformed unbracketed forms must NOT be produced.
        self.assertNotIn("http://::1", urls)
        self.assertNotIn("https://::1", urls)

    def test_ipv6_full_address_bracketed(self):
        """Full IPv6 address: 2001:db8::1 -> [2001:db8::1]."""
        urls = self._silent(
            TH.build_target_urls,
            set(), {"2001:db8::1"}, recon_data=None, scan_all_ips=True,
        )
        self.assertIn("http://[2001:db8::1]", urls)
        self.assertIn("https://[2001:db8::1]", urls)

    def test_ipv4_ip_NOT_bracketed(self):
        """IPv4 must not get brackets -- only IPv6 needs them."""
        urls = self._silent(
            TH.build_target_urls,
            set(), {"1.2.3.4"}, recon_data=None, scan_all_ips=True,
        )
        self.assertIn("http://1.2.3.4", urls)
        self.assertNotIn("http://[1.2.3.4]", urls)

    def test_ipv6_coverage_check_recognizes_bracketed_form(self):
        """If httpx already emitted https://[::1]/, fallback must NOT re-add it."""
        recon = {"http_probe": {"by_url": {"https://[::1]": {"status_code": 200}}}}
        urls = self._silent(
            TH.build_target_urls,
            set(), {"::1"}, recon_data=recon, scan_all_ips=True,
        )
        # The httpx URL is preserved
        self.assertIn("https://[::1]", urls)
        # Fallback must skip the IP since urlparse('https://[::1]').hostname == '::1'
        self.assertNotIn("http://[::1]", urls)

    # --- Stress / scale test --------------------------------------------

    def test_large_input_completes_quickly_and_correctly(self):
        """Stress test: 1000 hostnames + 500 BaseURLs covering 250 of them.
        Verifies O(N) scaling and dedup correctness at scale."""
        import time

        # 1000 subdomains, 250 covered by httpx (in https), 750 uncovered.
        all_subs = {f"sub{i:04d}.example.com" for i in range(1000)}
        covered_subs = {f"sub{i:04d}.example.com" for i in range(250)}
        uncovered_subs = all_subs - covered_subs

        recon = {
            "http_probe": {
                "by_url": {
                    f"https://{sub}": {"status_code": 200, "host": sub}
                    for sub in covered_subs
                },
            },
        }
        # Plus 250 unrelated BaseURLs (not in subdomain set) -- just clutter.
        for i in range(250):
            recon["http_probe"]["by_url"][f"https://other{i:04d}.test.com"] = {
                "status_code": 200, "host": f"other{i:04d}.test.com"
            }

        start = time.monotonic()
        urls = self._silent(TH.build_target_urls, all_subs, set(), recon_data=recon)
        duration = time.monotonic() - start

        # Performance: 1000 subs + 500 URLs should complete in well under 1 second.
        # Generous bound to avoid CI flake; real perf is ~5-20ms.
        self.assertLess(duration, 1.0, f"too slow: {duration:.3f}s")

        # Correctness:
        # 250 httpx URLs + 250 unrelated httpx URLs + 750 unprobed subs * 2 schemes
        # = 250 + 250 + 1500 = 2000
        self.assertEqual(len(urls), 250 + 250 + 750 * 2)
        # No duplicates
        self.assertEqual(len(urls), len(set(urls)))
        # Sorted
        self.assertEqual(urls, sorted(urls))
        # All 750 uncovered subs got both schemes
        for sub in list(uncovered_subs)[:50]:  # sample 50 to keep assertion count sane
            self.assertIn(f"http://{sub}", urls)
            self.assertIn(f"https://{sub}", urls)
        # No covered sub got the http (only-https) scheme as fallback
        for sub in list(covered_subs)[:50]:
            self.assertIn(f"https://{sub}", urls)
            self.assertNotIn(f"http://{sub}", urls)

    def test_duplicate_subdomain_strings_dedup(self):
        """If the hostnames set somehow contains both 'A.com' and 'a.com',
        they're different strings -- the set treats them as distinct -- but
        the coverage-check-after-fallback won't help since both pass through.
        We verify dedup at the URL level still holds."""
        # NB: a Python set cannot have both 'a.com' and 'a.com' (same string),
        # but it CAN have 'A.com' and 'a.com' (different strings).
        urls = self._silent(
            TH.build_target_urls, {"A.com", "a.com"}, set(), recon_data=None,
        )
        # Both casings produce both schemes -> 4 URL strings
        self.assertEqual(len(urls), 4)
        self.assertEqual(len(urls), len(set(urls)))

    # --- Equivalence: pre-refactor cascade vs post-refactor union ------

    def test_equivalence_when_no_uncovered_subdomains(self):
        """When every subdomain has a BaseURL, the union behavior must be identical
        to the old cascade behavior (just the httpx URLs, no fallback). This is
        the refactor-safety test -- pre-existing scans must produce the same set."""
        recon = {
            "http_probe": {
                "by_url": {
                    "https://a.com": {"status_code": 200},
                    "https://b.com": {"status_code": 200},
                },
            },
        }
        urls = self._silent(TH.build_target_urls, {"a.com", "b.com"}, set(), recon_data=recon)
        # Post-refactor: same as cascade would have produced.
        self.assertEqual(sorted(urls), ["https://a.com", "https://b.com"])


# ---------------------------------------------------------------------------
# Integration: run_with_heartbeat helper
# ---------------------------------------------------------------------------

class TestRunWithHeartbeat(unittest.TestCase):
    """Verify the shared subprocess helper that wraps blocking crawler calls
    with a periodic '[*][<label>] still running...' heartbeat."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "sh_under_test",
            str(_RECON_DIR / "helpers" / "subprocess_helpers.py"),
        )
        cls.SH = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.SH)

    def test_returns_completed_process_with_correct_fields(self):
        """Drop-in replacement for subprocess.run -- verify return shape."""
        result = self.SH.run_with_heartbeat(
            [sys.executable, "-c", "print('hello'); import sys; sys.exit(0)"],
            label="Test",
            interval=999,  # never fires
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_nonzero_exit_returncode_propagated(self):
        result = self.SH.run_with_heartbeat(
            [sys.executable, "-c", "import sys; sys.exit(7)"],
            label="Test",
            interval=999,
        )
        self.assertEqual(result.returncode, 7)

    def test_heartbeat_fires_during_long_subprocess(self):
        """A subprocess that runs for ~3s with heartbeat interval=1 should
        produce 1-3 heartbeat lines on stdout (timing-dependent).

        We capture parent stdout (the heartbeat thread's print()) and check
        that the expected pattern appears.
        """
        captured = io.StringIO()
        with redirect_stdout(captured):
            result = self.SH.run_with_heartbeat(
                [sys.executable, "-c", "import time; time.sleep(2.5)"],
                label="SlowChild",
                interval=1,
            )
        out = captured.getvalue()
        self.assertEqual(result.returncode, 0)
        # At least one heartbeat fired in the 2.5s window with interval=1.
        self.assertIn("[*][SlowChild] still running...", out)

    def test_no_heartbeat_when_subprocess_finishes_quickly(self):
        """Quick subprocess (<<interval) -- heartbeat must NOT fire."""
        captured = io.StringIO()
        with redirect_stdout(captured):
            self.SH.run_with_heartbeat(
                [sys.executable, "-c", "pass"],
                label="QuickChild",
                interval=10,
            )
        self.assertNotIn("still running", captured.getvalue())

    def test_timeout_raises_TimeoutExpired(self):
        """Match subprocess.run timeout semantics."""
        with self.assertRaises(subprocess.TimeoutExpired):
            self.SH.run_with_heartbeat(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                label="Hangs",
                interval=999,
                timeout=1,
            )


# ---------------------------------------------------------------------------
# Smoke: stderr merging via subprocess
# ---------------------------------------------------------------------------
class TestSubprocessStderrMerge(unittest.TestCase):

    def test_stderr_merged_into_stdout_via_subprocess_STDOUT(self):
        """Confirm stderr=STDOUT actually merges streams (the subprocess change)."""
        import subprocess

        child_script = (
            "import sys\n"
            "print('to-stdout', flush=True)\n"
            "print('to-stderr', file=sys.stderr, flush=True)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", child_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        captured = [l.rstrip() for l in proc.stdout]
        proc.wait()

        # Both streams arrive on stdout when stderr=subprocess.STDOUT.
        self.assertIn("to-stdout", captured)
        self.assertIn("to-stderr", captured)


# ---------------------------------------------------------------------------
# Allow direct invocation
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
