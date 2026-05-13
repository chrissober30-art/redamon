"""
Regression test for the Katana Docker-in-Docker path-mount bug.

Symptom: Katana spawned by partial-recon exited in <2s with 0 URLs because
the targets list file was written to the recon container's local /tmp,
while the spawned katana container's `-v /tmp:/tmp` resolved against the
host daemon's /tmp (where the file did not exist).

Fix: write targets to /tmp/redamon (same path host<->recon container per
docker-compose.yml) and mount /tmp/redamon:/tmp/redamon into katana.

Run with: python -m unittest recon.tests.test_katana_dind_paths -v
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

from recon.helpers.resource_enum import katana_helpers


class TestKatanaDinDPaths(unittest.TestCase):
    """Verify Katana writes its target list and mounts the volume in a path
    that is shared between the recon container and the host docker daemon."""

    def _run_with_fake_subprocess(self):
        """Run run_katana_crawler with subprocess.Popen mocked. Returns the
        captured docker command argv and the url_file path that was opened."""
        captured = {"cmd": None, "url_file": None}

        real_open = open

        def spy_open(path, *args, **kwargs):
            if isinstance(path, str) and "katana_targets_" in path:
                captured["url_file"] = path
            return real_open(path, *args, **kwargs)

        # Fake Popen: capture argv, expose stdout that yields no lines (EOF)
        def fake_popen(cmd, *args, **kwargs):
            captured["cmd"] = cmd
            proc = MagicMock()
            proc.stdout = MagicMock()
            proc.stdout.readline.return_value = ""
            proc.stderr = MagicMock()
            proc.stderr.read.return_value = ""
            proc.poll.return_value = 0
            proc.returncode = 0
            proc.wait.return_value = 0
            proc.kill.return_value = None
            return proc

        # select.select returns (ready, [], []) — empty ready triggers EOF path
        def fake_select(rlist, _wlist, _xlist, _timeout):
            return (rlist, [], [])

        with patch.object(katana_helpers.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(katana_helpers.select, "select", side_effect=fake_select), \
             patch("builtins.open", side_effect=spy_open):
            urls, meta = katana_helpers.run_katana_crawler(
                target_urls=["https://example.com", "https://api.example.com"],
                docker_image="projectdiscovery/katana:latest",
                depth=2,
                max_urls=100,
                rate_limit=10,
                timeout=30,
                js_crawl=False,
                params_only=False,
                allowed_hosts={"example.com", "api.example.com"},
                custom_headers=[],
                exclude_patterns=[],
            )

        return captured, urls, meta

    def test_url_file_written_under_tmp_redamon(self):
        """Targets file must live under /tmp/redamon (host-shared), not /tmp."""
        captured, _, _ = self._run_with_fake_subprocess()
        self.assertIsNotNone(captured["url_file"], "url_file was never opened")
        self.assertTrue(
            captured["url_file"].startswith("/tmp/redamon/"),
            f"url_file must be under /tmp/redamon/ for DinD; got {captured['url_file']}",
        )
        self.assertNotEqual(
            os.path.dirname(captured["url_file"]), "/tmp",
            "url_file must NOT be in plain /tmp (host/container /tmp diverge under DinD)",
        )

    def test_docker_volume_mount_is_tmp_redamon(self):
        """Spawned katana container must bind-mount /tmp/redamon, not /tmp."""
        captured, _, _ = self._run_with_fake_subprocess()
        cmd = captured["cmd"]
        self.assertIsNotNone(cmd, "docker command was never built")
        # Find the -v argument
        v_indices = [i for i, a in enumerate(cmd) if a == "-v"]
        self.assertTrue(v_indices, "no -v flag in docker command")
        mounts = [cmd[i + 1] for i in v_indices]
        self.assertIn(
            "/tmp/redamon:/tmp/redamon", mounts,
            f"katana must mount /tmp/redamon:/tmp/redamon (DinD shared path); got mounts: {mounts}",
        )
        self.assertNotIn(
            "/tmp:/tmp", mounts,
            "plain /tmp:/tmp mount is the bug we fixed: container /tmp != host /tmp under DinD",
        )

    def test_list_arg_points_at_shared_path(self):
        """The -list argument passed to katana must point at the same path the
        targets file was written to, and that path must be under /tmp/redamon."""
        captured, _, _ = self._run_with_fake_subprocess()
        cmd = captured["cmd"]
        self.assertIn("-list", cmd, "-list flag missing from katana invocation")
        list_path = cmd[cmd.index("-list") + 1]
        self.assertEqual(
            list_path, captured["url_file"],
            "-list path must match the actual file we wrote",
        )
        self.assertTrue(
            list_path.startswith("/tmp/redamon/"),
            f"-list path must be under /tmp/redamon/; got {list_path}",
        )


if __name__ == "__main__":
    unittest.main()
