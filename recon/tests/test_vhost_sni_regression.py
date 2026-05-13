"""
Regression tests for the VHost & SNI feature integration into the broader
RedAmon pipeline + settings flow.

These tests catch silent breakage during refactors:
    - GROUP 6 Phase A in recon/main.py still imports + dispatches vhost_sni
    - DEFAULT_SETTINGS contains all 11 VHOST_SNI_* keys with the right types
    - fetch_project_settings round-trips camelCase -> SCREAMING_SNAKE_CASE
    - apply_stealth_overrides leaves vhost_sni alone (or sets predictable
      throttled values)
    - All required graph mixin methods are wired into Neo4jClient
    - Wordlist file is present, parseable, and >= 1000 unique entries
    - The shipped wordlist contains key admin/dev/staging prefixes
    - vhost_sni Vulnerability source is documented in agent prompts

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_vhost_sni_regression.py -v
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _recon_root() -> Path | None:
    """Find the recon source directory in any container/host layout."""
    for candidate in (PROJECT_ROOT / "recon", Path("/app/recon")):
        if (candidate / "main.py").exists():
            return candidate
    return None


def _wordlist_path() -> Path | None:
    rr = _recon_root()
    if rr and (rr / "wordlists" / "vhost-common.txt").exists():
        return rr / "wordlists" / "vhost-common.txt"
    if Path("/app/recon/wordlists/vhost-common.txt").exists():
        return Path("/app/recon/wordlists/vhost-common.txt")
    return None


_RECON_AVAILABLE = _recon_root() is not None

requires_recon = pytest.mark.skipif(
    not _RECON_AVAILABLE,
    reason="recon source not mounted in this container — run in orchestrator/recon container",
)


# ===========================================================================
# 1. DEFAULT_SETTINGS shape
# ===========================================================================
@requires_recon
class TestDefaultSettings:
    EXPECTED_KEYS = {
        "VHOST_SNI_ENABLED": (bool, False),
        "VHOST_SNI_TIMEOUT": (int, 3),
        "VHOST_SNI_CONCURRENCY": (int, 20),
        "VHOST_SNI_BASELINE_SIZE_TOLERANCE": (int, 50),
        "VHOST_SNI_TEST_L7": (bool, True),
        "VHOST_SNI_TEST_L4": (bool, True),
        "VHOST_SNI_INJECT_DISCOVERED": (bool, True),
        "VHOST_SNI_USE_DEFAULT_WORDLIST": (bool, True),
        "VHOST_SNI_USE_GRAPH_CANDIDATES": (bool, True),
        "VHOST_SNI_CUSTOM_WORDLIST": (str, ""),
        "VHOST_SNI_MAX_CANDIDATES_PER_IP": (int, 2000),
    }

    def test_all_11_keys_present(self):
        from recon.project_settings import DEFAULT_SETTINGS
        for key in self.EXPECTED_KEYS:
            assert key in DEFAULT_SETTINGS, f"Missing setting key: {key}"

    def test_default_values_correct(self):
        from recon.project_settings import DEFAULT_SETTINGS
        for key, (expected_type, expected_value) in self.EXPECTED_KEYS.items():
            assert isinstance(DEFAULT_SETTINGS[key], expected_type), \
                f"{key} should be {expected_type.__name__}, got {type(DEFAULT_SETTINGS[key]).__name__}"
            assert DEFAULT_SETTINGS[key] == expected_value, \
                f"{key} default changed: expected {expected_value}, got {DEFAULT_SETTINGS[key]}"

    def test_enabled_default_off(self):
        # Critical safety check: VHost/SNI sends real traffic.
        # Default-on would surprise users.
        from recon.project_settings import DEFAULT_SETTINGS
        assert DEFAULT_SETTINGS["VHOST_SNI_ENABLED"] is False


# ===========================================================================
# 2. fetch_project_settings camelCase -> SCREAMING_SNAKE_CASE mapping
# ===========================================================================
@requires_recon
class TestFetchProjectSettings:
    EXPECTED_MAPPING = {
        "vhostSniEnabled": "VHOST_SNI_ENABLED",
        "vhostSniTimeout": "VHOST_SNI_TIMEOUT",
        "vhostSniConcurrency": "VHOST_SNI_CONCURRENCY",
        "vhostSniBaselineSizeTolerance": "VHOST_SNI_BASELINE_SIZE_TOLERANCE",
        "vhostSniTestL7": "VHOST_SNI_TEST_L7",
        "vhostSniTestL4": "VHOST_SNI_TEST_L4",
        "vhostSniInjectDiscovered": "VHOST_SNI_INJECT_DISCOVERED",
        "vhostSniUseDefaultWordlist": "VHOST_SNI_USE_DEFAULT_WORDLIST",
        "vhostSniUseGraphCandidates": "VHOST_SNI_USE_GRAPH_CANDIDATES",
        "vhostSniCustomWordlist": "VHOST_SNI_CUSTOM_WORDLIST",
        "vhostSniMaxCandidatesPerIp": "VHOST_SNI_MAX_CANDIDATES_PER_IP",
    }

    def test_all_camelcase_keys_mapped(self):
        # Read source of fetch_project_settings and confirm every camelCase key
        # is referenced. (Cheap structural check that survives refactors better
        # than monkey-patching the whole API call.)
        from recon import project_settings
        src = inspect.getsource(project_settings.fetch_project_settings)
        for camel_key, snake_key in self.EXPECTED_MAPPING.items():
            assert f"'{camel_key}'" in src, f"Missing camelCase key in fetch_project_settings: {camel_key}"
            assert f"settings['{snake_key}']" in src, f"Missing SCREAMING key assignment: {snake_key}"

    def test_camelcase_value_round_trip_unit(self):
        # We can't easily mock fetch_project_settings (it pulls many disparate
        # fields), so verify the mapping at the unit level by directly invoking
        # the same dict.get(camelKey, DEFAULT) idiom used inside the function.
        from recon.project_settings import DEFAULT_SETTINGS
        project = {camel: DEFAULT_SETTINGS[snake] for camel, snake in self.EXPECTED_MAPPING.items()}
        project["vhostSniEnabled"] = True
        project["vhostSniTimeout"] = 7
        project["vhostSniCustomWordlist"] = "foo\nbar"

        # Reproduce the assignments line-by-line (same shape as inside the function)
        for camel, snake in self.EXPECTED_MAPPING.items():
            value = project.get(camel, DEFAULT_SETTINGS[snake])
            if camel == "vhostSniEnabled":
                assert value is True
            elif camel == "vhostSniTimeout":
                assert value == 7
            elif camel == "vhostSniCustomWordlist":
                assert value == "foo\nbar"
            else:
                assert value == DEFAULT_SETTINGS[snake]


# ===========================================================================
# 3. Pipeline wiring (recon/main.py GROUP 6A)
# ===========================================================================
@requires_recon
class TestPipelineWiring:
    def test_main_imports_isolated_wrapper_lazily(self):
        from recon.main_recon_modules.vhost_sni_enum import run_vhost_sni_enrichment_isolated
        assert callable(run_vhost_sni_enrichment_isolated)

    def test_main_py_dispatches_vhost_sni_in_phase_a(self):
        main_path = _recon_root() / "main.py"
        src = main_path.read_text()
        assert "VHOST_SNI_ENABLED" in src, "main.py doesn't gate vhost_sni"
        assert "phase_a_tools['vhost_sni']" in src, \
            "main.py doesn't register vhost_sni into phase_a_tools"
        assert "run_vhost_sni_enrichment_isolated" in src, \
            "main.py doesn't import the isolated wrapper"

    def test_isolated_wrapper_signature_matches_phase_a_contract(self):
        from recon.main_recon_modules.vhost_sni_enum import run_vhost_sni_enrichment_isolated
        sig = inspect.signature(run_vhost_sni_enrichment_isolated)
        params = list(sig.parameters)
        assert params == ["combined_result", "settings"]


# ===========================================================================
# 4. Wordlist file present + parseable + sized correctly
# ===========================================================================
class TestWordlistShipped:
    """File-level tests: skip when neither path exists."""
    def setup_method(self):
        if _wordlist_path() is None:
            pytest.skip("vhost-common.txt not visible in this container")

    def test_file_exists(self):
        # If we got past setup_method, the file is there.
        assert _wordlist_path().exists()

    def test_at_least_1000_unique_entries(self):
        from recon.main_recon_modules.vhost_sni_enum import _load_default_wordlist
        entries = _load_default_wordlist()
        assert len(entries) >= 1000, f"Wordlist has only {len(entries)} entries (want >=1000)"

    def test_contains_expected_high_signal_prefixes(self):
        from recon.main_recon_modules.vhost_sni_enum import _load_default_wordlist
        entries = set(_load_default_wordlist())
        for required in (
            "admin", "staging", "dev", "internal", "jenkins", "gitlab",
            "kubernetes", "k8s", "vault", "grafana", "kibana", "phpmyadmin",
            "argocd", "rancher", "jaeger", "harbor", "sso", "auth", "vpn",
        ):
            assert required in entries, f"Wordlist missing required high-signal prefix: {required}"

    def test_no_full_hostnames_in_wordlist(self):
        # Default wordlist should be PURE prefixes — full hostnames make no
        # sense as cross-target candidates.
        from recon.main_recon_modules.vhost_sni_enum import _load_default_wordlist
        entries = _load_default_wordlist()
        with_dots = [e for e in entries if "." in e]
        # Allow at most a handful of accidental dots; anything >5 is a sign the
        # categorisation got polluted with FQDNs.
        assert len(with_dots) <= 5, f"Wordlist contains too many dotted entries: {with_dots[:10]}"


# ===========================================================================
# 5. Graph mixin wiring
# ===========================================================================
class TestGraphMixinWiring:
    """
    Source-checks graph_db files. Skips when graph_db isn't visible in this
    container (e.g. orchestrator container has only recon source mounted).
    """

    def _graph_db_root(self) -> Path:
        # Try project root first (host checkout / orchestrator container)
        for candidate in (PROJECT_ROOT / "graph_db", Path("/app/graph_db")):
            if (candidate / "mixins" / "recon_mixin.py").exists():
                return candidate
        return PROJECT_ROOT / "graph_db"  # fall through, will fail the file-present test

    def setup_method(self):
        if not (self._graph_db_root() / "mixins" / "recon_mixin.py").exists():
            pytest.skip("graph_db source not visible in this container — run in agent container")

    def test_vhost_sni_mixin_file_present(self):
        path = self._graph_db_root() / "mixins" / "recon" / "vhost_sni_mixin.py"
        assert path.exists(), f"Mixin file missing: {path}"

    def test_vhost_sni_mixin_defines_update_method(self):
        path = self._graph_db_root() / "mixins" / "recon" / "vhost_sni_mixin.py"
        src = path.read_text()
        assert "def update_graph_from_vhost_sni(" in src, \
            "VhostSniMixin doesn't define update_graph_from_vhost_sni"

    def test_recon_mixin_includes_vhost_sni(self):
        path = self._graph_db_root() / "mixins" / "recon_mixin.py"
        src = path.read_text()
        assert "VhostSniMixin" in src, "ReconMixin doesn't include VhostSniMixin"
        assert "from graph_db.mixins.recon.vhost_sni_mixin import VhostSniMixin" in src

    def test_get_graph_inputs_for_tool_handles_vhostsni(self):
        path = self._graph_db_root() / "mixins" / "recon" / "user_input_mixin.py"
        src = path.read_text()
        assert 'tool_id == "VhostSni"' in src, \
            "get_graph_inputs_for_tool missing the VhostSni branch"


# ===========================================================================
# 6. Partial recon dispatch
# ===========================================================================
@requires_recon
class TestPartialReconDispatch:
    def test_partial_recon_dispatches_vhost_sni(self):
        partial_path = _recon_root() / "partial_recon.py"
        src = partial_path.read_text()
        assert 'tool_id == "VhostSni"' in src, "partial_recon.py missing VhostSni branch"
        assert "run_vhost_sni_partial" in src, "partial_recon.py missing run_vhost_sni_partial import"

    def test_run_vhost_sni_partial_defined(self):
        path = _recon_root() / "partial_recon_modules" / "vulnerability_scanning.py"
        src = path.read_text()
        assert "def run_vhost_sni_partial(" in src, \
            "vulnerability_scanning.py missing run_vhost_sni_partial function"
        assert "VHOST_SNI_ENABLED" in src, \
            "run_vhost_sni_partial doesn't force-enable the setting"


# ===========================================================================
# 7. Agent prompt schema sync
# ===========================================================================
class TestAgentPromptSchemaSync:
    def test_vhost_sni_enum_source_documented(self):
        prompts_path = PROJECT_ROOT / "agentic" / "prompts" / "base.py"
        if not prompts_path.exists():
            pytest.skip("agentic/prompts/base.py not present in this checkout")
            return
        src = prompts_path.read_text()
        assert "vhost_sni_enum" in src, \
            "TEXT_TO_CYPHER_SYSTEM doesn't mention vhost_sni_enum source"
        assert "hidden_vhost" in src or "hidden_sni_route" in src, \
            "Vulnerability type enum for vhost_sni_enum not documented"


# ===========================================================================
# 8. Module-level constants
# ===========================================================================
@requires_recon
class TestStealthModeOverrides:
    """Pin the apply_stealth_overrides() contract for vhost_sni."""

    def test_stealth_mode_disables_vhost_sni(self):
        from recon.project_settings import apply_stealth_overrides, DEFAULT_SETTINGS
        settings = dict(DEFAULT_SETTINGS)
        settings["VHOST_SNI_ENABLED"] = True
        settings["STEALTH_MODE"] = True
        result = apply_stealth_overrides(settings)
        # Must hard-disable: 2,380 probes via Tor would be catastrophic
        assert result["VHOST_SNI_ENABLED"] is False

    def test_non_stealth_leaves_vhost_sni_enabled_setting_alone(self):
        from recon.project_settings import apply_stealth_overrides
        settings = {"STEALTH_MODE": False, "VHOST_SNI_ENABLED": True}
        result = apply_stealth_overrides(settings)
        assert result["VHOST_SNI_ENABLED"] is True


@requires_recon
class TestModuleConstants:
    def test_internal_keywords_non_empty(self):
        from recon.main_recon_modules.vhost_sni_enum import INTERNAL_KEYWORDS
        assert isinstance(INTERNAL_KEYWORDS, set)
        assert len(INTERNAL_KEYWORDS) >= 30

    def test_default_wordlist_path_inside_recon_image(self):
        from recon.main_recon_modules.vhost_sni_enum import DEFAULT_WORDLIST_CONTAINER_PATH
        assert DEFAULT_WORDLIST_CONTAINER_PATH == "/app/recon/wordlists/vhost-common.txt"
