"""
Regression test for the partial-recon "Include Root Domain" scope bug.

Bug: partial-recon flows ignored the project's include_root_domain toggle.
The apex hostname was added to scan/crawl targets even when scope excluded
it, producing apex BaseURL + Endpoint nodes that violated the user's stated
scope. See bug history for full context.

Fix: graph builders accept include_root_domain and stamp metadata on
recon_data; extract_targets_from_recon honors metadata.include_root_domain.
Mirrors the full-pipeline scope rule in recon/main.py:parse_target.

Run with: python -m unittest recon.tests.test_include_root_domain_scope -v
"""
import os
import sys
import unittest

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

from recon.partial_recon_modules.helpers import _should_include_root_domain
from recon.helpers.target_helpers import extract_targets_from_recon


class TestShouldIncludeRootDomain(unittest.TestCase):
    """The helper must mirror recon/main.py:parse_target exactly."""

    def test_empty_list_excludes_apex(self):
        self.assertFalse(_should_include_root_domain({"SUBDOMAIN_LIST": []}))

    def test_missing_key_excludes_apex(self):
        self.assertFalse(_should_include_root_domain({}))

    def test_none_excludes_apex(self):
        self.assertFalse(_should_include_root_domain({"SUBDOMAIN_LIST": None}))

    def test_dot_includes_apex(self):
        self.assertTrue(_should_include_root_domain({"SUBDOMAIN_LIST": ["."]}))

    def test_dot_with_other_prefixes_includes_apex(self):
        self.assertTrue(_should_include_root_domain({"SUBDOMAIN_LIST": ["www.", ".", "api."]}))

    def test_subdomain_only_excludes_apex(self):
        self.assertFalse(_should_include_root_domain({"SUBDOMAIN_LIST": ["www.", "api."]}))

    def test_dotted_blank_treated_as_dot(self):
        # parse_target treats prefix that strips to empty as ".": "..".rstrip(".")=="" -> True.
        self.assertTrue(_should_include_root_domain({"SUBDOMAIN_LIST": [".."]}))


class TestExtractTargetsHonorsMetadata(unittest.TestCase):
    """extract_targets_from_recon must honor metadata.include_root_domain."""

    def _recon(self, include_root):
        return {
            "domain": "example.com",
            "dns": {
                "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}, "has_records": True},
                "subdomains": {
                    "www.example.com": {"ips": {"ipv4": ["1.2.3.5"], "ipv6": []}, "has_records": True},
                },
            },
            "metadata": {"include_root_domain": include_root},
        }

    def test_apex_excluded_when_metadata_false(self):
        ips, hostnames, _ = extract_targets_from_recon(self._recon(include_root=False))
        self.assertNotIn("example.com", hostnames)
        self.assertIn("www.example.com", hostnames)
        # Apex IPs still flow through (user-explicit IPs aren't filtered)
        self.assertIn("1.2.3.4", ips)

    def test_apex_included_when_metadata_true(self):
        ips, hostnames, _ = extract_targets_from_recon(self._recon(include_root=True))
        self.assertIn("example.com", hostnames)
        self.assertIn("www.example.com", hostnames)

    def test_apex_included_when_metadata_missing(self):
        # Backward compat: no metadata.include_root_domain → default True.
        # This is what existing tests assume (test_apex_domain_alone_produces_two_urls).
        recon_data = {
            "domain": "example.com",
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }
        _, hostnames, _ = extract_targets_from_recon(recon_data)
        self.assertIn("example.com", hostnames)


class TestGraphBuilderStampsMetadata(unittest.TestCase):
    """All 4 partial-recon graph builders must stamp metadata.include_root_domain."""

    def _patch_neo4j(self):
        """Return a context manager that mocks the Neo4j client to fail-closed
        (verify_connection -> False). The graph builders return early with
        the recon_data shell, which is enough to inspect metadata."""
        from unittest.mock import MagicMock, patch
        mock_client = MagicMock()
        mock_client.verify_connection.return_value = False
        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls
        return patch.dict(sys.modules, {"graph_db": mock_graph_db})

    def test_recon_data_builder_stamps_false(self):
        from recon.partial_recon_modules.graph_builders import _build_recon_data_from_graph
        with self._patch_neo4j():
            data = _build_recon_data_from_graph("example.com", "u1", "p1", include_root_domain=False)
        self.assertEqual(data["metadata"]["include_root_domain"], False)

    def test_recon_data_builder_stamps_true(self):
        from recon.partial_recon_modules.graph_builders import _build_recon_data_from_graph
        with self._patch_neo4j():
            data = _build_recon_data_from_graph("example.com", "u1", "p1", include_root_domain=True)
        self.assertEqual(data["metadata"]["include_root_domain"], True)

    def test_port_scan_builder_stamps_metadata(self):
        from recon.partial_recon_modules.graph_builders import _build_port_scan_data_from_graph
        with self._patch_neo4j():
            data = _build_port_scan_data_from_graph("example.com", "u1", "p1", include_root_domain=False)
        self.assertEqual(data["metadata"]["include_root_domain"], False)

    def test_http_probe_builder_stamps_metadata(self):
        from recon.partial_recon_modules.graph_builders import _build_http_probe_data_from_graph
        with self._patch_neo4j():
            data = _build_http_probe_data_from_graph("example.com", "u1", "p1", include_root_domain=False)
        self.assertEqual(data["metadata"]["include_root_domain"], False)

    def test_vuln_scan_builder_stamps_metadata(self):
        from recon.partial_recon_modules.graph_builders import _build_vuln_scan_data_from_graph
        with self._patch_neo4j():
            data = _build_vuln_scan_data_from_graph("example.com", "u1", "p1", include_root_domain=False)
        self.assertEqual(data["metadata"]["include_root_domain"], False)

    def test_default_excludes_apex(self):
        """Safe default: when called without the parameter, scope excludes apex.
        Prevents future call sites from accidentally re-introducing the bug."""
        from recon.partial_recon_modules.graph_builders import (
            _build_recon_data_from_graph, _build_port_scan_data_from_graph,
            _build_http_probe_data_from_graph, _build_vuln_scan_data_from_graph,
        )
        for fn in [_build_recon_data_from_graph, _build_port_scan_data_from_graph,
                   _build_http_probe_data_from_graph, _build_vuln_scan_data_from_graph]:
            with self._patch_neo4j():
                data = fn("example.com", "u1", "p1")
            self.assertEqual(
                data["metadata"]["include_root_domain"], False,
                f"{fn.__name__} default should exclude apex (safe default)",
            )


if __name__ == "__main__":
    unittest.main()
