"""
Regression test for the Docker-in-Docker `--net=host` fix across the recon
pipeline.

Symptom (2026-05-23): Katana, hakrawler, jsluice/httpx-verifier,
kiterunner/httpx-verifier, gau/httpx-verifier, nuclei, and graphql-cop sat at
0% CPU for the full crawl-duration window when scanning loopback / local-lab
targets (127.0.0.1 — our guinea pigs at agentic/labs/* and guinea_pigs/*).

Root cause: a sibling Docker container spawned by `docker run` does NOT
inherit the recon container's `network_mode: host`. It lands on a fresh
bridge network where `localhost` == the sibling container itself, so every
fetch silently failed with ECONNREFUSED.

Fix: every target-reaching docker invocation must pass `--net=host`
unconditionally — equivalent to bridge for external targets, mandatory for
loopback. This test statically guards that invariant by source-reading each
helper file and asserting the literal `--net=host` flag is present alongside
`"docker", "run"`.

Source-reading is intentional: it's simpler than mocking every helper, and
catches future regressions where a refactor accidentally drops the flag (or
re-introduces conditional gating like `if use_proxy: cmd.append("--net=host")`).

Run with: python -m unittest recon.tests.test_net_host_target_reaching -v
"""
import os
import re
import unittest

_RECON_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Helper files that spawn docker containers which reach the scan target
# (HTTP/HTTPS, ports, GraphQL endpoints). Every `docker run` literal in these
# files must carry `--net=host`.
TARGET_REACHING_HELPERS = [
    "helpers/katana_helpers.py",
    "helpers/nuclei_helpers.py",
    "helpers/resource_enum/katana_helpers.py",
    "helpers/resource_enum/hakrawler_helpers.py",
    "helpers/resource_enum/jsluice_helpers.py",
    "helpers/resource_enum/kiterunner_helpers.py",
    "helpers/resource_enum/gau_helpers.py",
    "graphql_scan/misconfig.py",
    "main_recon_modules/http_probe.py",
    "main_recon_modules/port_scan.py",
]


# Files where `docker run` is allowed WITHOUT `--net=host` because the
# invocation doesn't reach the target (alpine cleanup, third-party API
# queries, DNS resolvers). Listed here so future readers know they were
# deliberately excluded, not forgotten.
NON_TARGET_REACHING_ALLOWED = [
    # Cleanup: alpine `rm -f` to delete root-owned tmp files
    ("main_recon_modules/vuln_scan.py", "alpine"),
    ("main_recon_modules/domain_recon.py", "alpine"),
    # Third-party APIs (Shodan/Censys/Wayback/etc): the docker container
    # queries external services, not the target
    ("main_recon_modules/uncover_enrich.py", "uncover"),
    # GAU itself queries Wayback/OTX, not the target. Its httpx verifier
    # invocations (3 sites in the same file) DO need --net=host and are
    # covered by the main test below via `helpers/resource_enum/gau_helpers.py`.
    # Subfinder/Amass/Puredns: passive DNS/3rd-party APIs
    ("main_recon_modules/domain_recon.py", "subfinder"),
    ("main_recon_modules/domain_recon.py", "amass"),
    ("main_recon_modules/domain_recon.py", "puredns"),
    # BadDNS: DNS-based subdomain takeover checks
    ("helpers/takeover_helpers.py", "baddns"),
    # Docker volume management
    ("helpers/docker_helpers.py", "templates"),
]


def _extract_docker_run_blocks(source: str) -> list:
    """Find every `"docker", "run"` argv literal and return its surrounding
    block (up to the closing bracket). We tolerate multi-line argv lists."""
    blocks = []
    # Match `cmd = [...]` or `["docker", "run", ...]` style invocations
    pattern = re.compile(
        r'\[[^\[\]]*?["\']docker["\']\s*,\s*["\']run["\'][^\[\]]*?\]',
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        blocks.append(match.group(0))
    return blocks


class TestNetHostInTargetReachingHelpers(unittest.TestCase):
    """Every target-reaching `docker run` must carry `--net=host`."""

    def test_every_target_reaching_docker_run_has_net_host(self):
        missing = []
        for rel_path in TARGET_REACHING_HELPERS:
            full_path = os.path.join(_RECON_DIR, rel_path)
            self.assertTrue(
                os.path.isfile(full_path),
                f"target-reaching helper not found: {rel_path}",
            )
            with open(full_path, "r") as f:
                source = f.read()

            blocks = _extract_docker_run_blocks(source)
            self.assertGreater(
                len(blocks), 0,
                f"{rel_path}: expected at least one `docker run` invocation",
            )

            for i, block in enumerate(blocks):
                # Accept either `--net=host` or `"--net=host"` or
                # `"--network", "host"` — but the chosen form must be
                # UNCONDITIONAL (i.e. inside the argv literal itself, not
                # appended via `if use_proxy: cmd.extend(...)`).
                has_flag = (
                    "--net=host" in block
                    or re.search(r'["\']--network["\']\s*,\s*["\']host["\']', block)
                )
                if not has_flag:
                    missing.append(f"{rel_path} block#{i}: {block[:200]}...")

        self.assertFalse(
            missing,
            "Target-reaching `docker run` invocations missing --net=host. "
            "Without it, the spawned container cannot reach loopback "
            "targets (127.0.0.1) — see "
            "recon/helpers/resource_enum/katana_helpers.py for the long "
            "comment.\n\nOffenders:\n" + "\n".join(missing),
        )

    def test_no_conditional_use_proxy_gating_on_network_host(self):
        """Forbid the historical bug pattern `if use_proxy: cmd.extend(["--network", "host"])`.

        This pattern was the bug we fixed across 7 files on 2026-05-23: it
        conditionally added --network host only when Tor was on, leaving
        loopback scans broken for the default non-Tor case.
        """
        offenders = []
        # Pattern matches both `cmd.extend([...])` and `cmd.append(...)`
        # forms gated by `if use_proxy:` followed by network/net=host args.
        bad_pattern = re.compile(
            r'if\s+use_proxy\s*:\s*\n\s*cmd\.(?:extend|append)\([^)]*'
            r'(?:["\']--network["\']\s*,\s*["\']host["\']|"--net=host")',
            re.MULTILINE,
        )
        for rel_path in TARGET_REACHING_HELPERS:
            full_path = os.path.join(_RECON_DIR, rel_path)
            with open(full_path, "r") as f:
                source = f.read()
            if bad_pattern.search(source):
                offenders.append(rel_path)

        self.assertFalse(
            offenders,
            "Found the historical bug pattern `if use_proxy: cmd.extend([\"--network\", \"host\"])`. "
            "This gating broke loopback scans whenever Tor was off. "
            "Make `--net=host` unconditional instead.\n\nOffenders:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
