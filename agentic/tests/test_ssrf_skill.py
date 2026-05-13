"""
Tests for the SSRF (Server-Side Request Forgery) built-in attack skill.

Covers state registration, classification wiring, project settings defaults,
prompt template formatting (with all 11 parametric knobs), conditional
sub-section injection in get_phase_tools, custom-targets free-text injection,
cloud-provider filter logic, and tool-registry presence.

Run with: python -m pytest tests/test_ssrf_skill.py -v
"""

import os
import re
import sys
import unittest
from unittest.mock import patch, MagicMock

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# ===========================================================================
# Test fixtures: stub heavy LangChain/LangGraph imports
# ===========================================================================

class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"


class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"


def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right


_stubs = {}
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint',
    'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic',
    'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]

sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

# Now safe to import agentic modules
from state import KNOWN_ATTACK_PATHS, is_unclassified_path, AttackPathClassification
from project_settings import DEFAULT_AGENT_SETTINGS
from prompts.ssrf_prompts import (
    SSRF_TOOLS,
    SSRF_OOB_WORKFLOW,
    SSRF_GOPHER_CHAINS,
    SSRF_DNS_REBINDING,
    SSRF_PAYLOAD_REFERENCE,
    SSRF_CLOUD_PROVIDER_BLOCKS,
    SSRF_CLOUD_DISABLED_STUB,
    SSRF_CLOUD_AWS,
    SSRF_CLOUD_GCP,
    SSRF_CLOUD_AZURE,
    SSRF_CLOUD_DIGITALOCEAN,
    SSRF_CLOUD_ALIBABA,
)
from prompts.classification import (
    _SSRF_SECTION,
    _BUILTIN_SKILL_MAP,
    _CLASSIFICATION_INSTRUCTIONS,
    build_classification_prompt,
)


# ===========================================================================
# 1. State — KNOWN_ATTACK_PATHS, AttackPathClassification accept "ssrf"
# ===========================================================================

class TestStateRegistration(unittest.TestCase):
    """Verify ssrf is registered as a known attack path so the Pydantic
    validator accepts classifier output."""

    def test_ssrf_in_known_paths(self):
        self.assertIn("ssrf", KNOWN_ATTACK_PATHS)

    def test_ssrf_is_not_unclassified(self):
        self.assertFalse(is_unclassified_path("ssrf"))

    def test_ssrf_unclassified_pattern_still_valid(self):
        """The legacy ssrf-unclassified path should still pass regex validation
        for backwards-compat with old projects."""
        self.assertTrue(is_unclassified_path("ssrf-unclassified"))

    def test_attack_path_classification_accepts_ssrf(self):
        """Pydantic model should accept ssrf as valid type — without this fix
        the classifier output crashes the agent."""
        apc = AttackPathClassification(
            attack_path_type="ssrf",
            required_phase="exploitation",
            confidence=0.95,
            reasoning="SSRF test",
        )
        self.assertEqual(apc.attack_path_type, "ssrf")

    def test_attack_path_classification_still_accepts_unclassified(self):
        apc = AttackPathClassification(
            attack_path_type="ssrf-unclassified",
            required_phase="exploitation",
            confidence=0.6,
            reasoning="Legacy path",
        )
        self.assertEqual(apc.attack_path_type, "ssrf-unclassified")


# ===========================================================================
# 2. Classification — section text, map entry, instructions
# ===========================================================================

class TestClassificationRegistration(unittest.TestCase):
    """Verify ssrf is wired into the dynamic classification prompt."""

    def test_ssrf_section_defined(self):
        self.assertIn("ssrf", _SSRF_SECTION)
        self.assertIn("Server-Side Request Forgery", _SSRF_SECTION)
        self.assertIn("cloud metadata", _SSRF_SECTION.lower())
        self.assertIn("IMDS", _SSRF_SECTION)

    def test_ssrf_section_disambiguates_from_neighbours(self):
        """Section should explicitly distinguish from sql_injection / xss / phishing
        to keep classifier precision high."""
        text = _SSRF_SECTION.lower()
        self.assertIn("sql_injection", text)
        self.assertIn("xss", text)
        self.assertIn("phishing", text)

    def test_ssrf_in_builtin_skill_map(self):
        self.assertIn("ssrf", _BUILTIN_SKILL_MAP)
        section, _letter, skill_id = _BUILTIN_SKILL_MAP["ssrf"]
        self.assertEqual(skill_id, "ssrf")
        self.assertEqual(section, _SSRF_SECTION)

    def test_ssrf_in_classification_instructions(self):
        self.assertIn("ssrf", _CLASSIFICATION_INSTRUCTIONS)
        instruction = _CLASSIFICATION_INSTRUCTIONS["ssrf"]
        self.assertIn("SSRF", instruction)
        self.assertIn("server-side request forgery", instruction.lower())

    def test_build_classification_prompt_includes_ssrf_when_enabled(self):
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'ssrf', 'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt(
                "Test for SSRF on the URL preview endpoint")
            self.assertIn("ssrf", prompt)
            self.assertIn("Server-Side Request Forgery", prompt)

    def test_build_classification_prompt_excludes_ssrf_when_disabled(self):
        """Disabling SSRF in project config must remove it from the classifier menu."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for SSRF")
            self.assertNotIn("### ssrf — Server-Side Request Forgery", prompt)
            self.assertIn("unclassified", prompt)


# ===========================================================================
# 3. Project settings — 11 SSRF defaults + master toggle default OFF
# ===========================================================================

class TestProjectSettings(unittest.TestCase):
    """Verify all 11 SSRF tunables and the master toggle have correct defaults."""

    def test_ssrf_in_attack_skill_config(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertIn('ssrf', config['builtIn'])

    def test_ssrf_master_toggle_default_off(self):
        """Per project decision: SSRF master toggle ships disabled-by-default
        even though the individual sub-sections default to enabled."""
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertFalse(config['builtIn']['ssrf'])

    def test_all_sub_workflow_toggles_default_on(self):
        """When the master is flipped on, every sub-workflow should be enabled."""
        for key in ('SSRF_OOB_CALLBACK_ENABLED',
                    'SSRF_CLOUD_METADATA_ENABLED',
                    'SSRF_GOPHER_ENABLED',
                    'SSRF_DNS_REBINDING_ENABLED',
                    'SSRF_PAYLOAD_REFERENCE_ENABLED'):
            self.assertTrue(DEFAULT_AGENT_SETTINGS[key],
                            f"{key} should default to True")

    def test_request_timeout_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['SSRF_REQUEST_TIMEOUT'], 10)

    def test_port_scan_ports_default(self):
        ports = DEFAULT_AGENT_SETTINGS['SSRF_PORT_SCAN_PORTS']
        # Common high-value internal ports must be present
        for needle in ('22', '80', '443', '6379', '8080', '9200', '27017'):
            self.assertIn(needle, ports)

    def test_internal_ranges_default(self):
        ranges = DEFAULT_AGENT_SETTINGS['SSRF_INTERNAL_RANGES']
        for cidr in ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                     '192.168.0.0/16', '169.254.0.0/16'):
            self.assertIn(cidr, ranges)

    def test_oob_provider_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['SSRF_OOB_PROVIDER'], 'oast.fun')

    def test_cloud_providers_default(self):
        providers = DEFAULT_AGENT_SETTINGS['SSRF_CLOUD_PROVIDERS']
        for cloud in ('aws', 'gcp', 'azure', 'digitalocean', 'alibaba'):
            self.assertIn(cloud, providers)

    def test_custom_targets_default_empty(self):
        """Free-text power-user knob defaults to empty so it adds nothing
        to the prompt unless explicitly populated."""
        self.assertEqual(
            DEFAULT_AGENT_SETTINGS['SSRF_CUSTOM_INTERNAL_TARGETS'], '')


# ===========================================================================
# 4. Prompt template — SSRF_TOOLS format-string substitution
# ===========================================================================

class TestSSRFToolsTemplate(unittest.TestCase):
    """Verify the main SSRF_TOOLS prompt formats cleanly with all 12 placeholders
    (10 tunables + 2 Python-built sections)."""

    def _format(self, **overrides):
        defaults = dict(
            ssrf_oob_callback_enabled=True,
            ssrf_cloud_metadata_enabled=True,
            ssrf_gopher_enabled=True,
            ssrf_dns_rebinding_enabled=True,
            ssrf_payload_reference_enabled=True,
            ssrf_request_timeout=10,
            ssrf_port_scan_ports='22,80,443',
            ssrf_internal_ranges='127.0.0.0/8',
            ssrf_oob_provider='oast.fun',
            ssrf_cloud_providers='aws,gcp',
            ssrf_cloud_section='STUB CLOUD',
            ssrf_custom_targets_section='',
        )
        defaults.update(overrides)
        return SSRF_TOOLS.format(**defaults)

    def test_formats_with_all_defaults(self):
        result = self._format()
        self.assertIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)
        # No leftover {ssrf_*} placeholders
        self.assertEqual(re.findall(r'\{ssrf_[a-z_]+\}', result), [])

    def test_no_em_dashes_in_main_prompt(self):
        """User-feedback rule: never emit em dashes in agent text."""
        result = self._format()
        self.assertNotIn("\u2014", result)

    def test_settings_block_reflects_values(self):
        result = self._format(ssrf_request_timeout=42, ssrf_oob_provider='self.local')
        self.assertIn("Request timeout:               42s", result)
        self.assertIn("OOB provider:                  self.local", result)

    def test_port_scan_command_uses_configured_ports(self):
        result = self._format(ssrf_port_scan_ports='1234,5678')
        self.assertIn("'1234,5678'", result)

    def test_oob_provider_substituted_in_interactsh_command(self):
        result = self._format(ssrf_oob_provider='internal-oast.example.com')
        self.assertIn("-server internal-oast.example.com", result)

    def test_internal_ranges_substituted(self):
        result = self._format(ssrf_internal_ranges='100.64.0.0/10,fd00::/8')
        self.assertIn("100.64.0.0/10,fd00::/8", result)

    def test_workflow_steps_present(self):
        result = self._format()
        for step in (
            "Step 1: Surface inventory",
            "Step 2: Establish OAST oracle",
            "Step 3: Internal address probing",
            "Step 4: Cloud metadata pivots",
            "Step 5: Header/method control",
            "Step 6: Defense fingerprints",
            "Step 7: Confidence scoring",
            "Step 8: Cleanup",
        ):
            self.assertIn(step, result)

    def test_transition_phase_instruction_present(self):
        result = self._format()
        self.assertIn("transition_phase", result)

    def test_hard_rules_block_present(self):
        result = self._format()
        self.assertIn("Hard rules", result)
        self.assertIn("Blind spraying", result)

    def test_output_schema_present(self):
        result = self._format()
        self.assertIn('"id": "SSRF-NN"', result)
        self.assertIn('"confidence"', result)

    def test_cloud_section_injected_verbatim(self):
        result = self._format(ssrf_cloud_section='### MY CLOUD STUB ###')
        self.assertIn('### MY CLOUD STUB ###', result)

    def test_custom_targets_section_injected_verbatim(self):
        result = self._format(ssrf_custom_targets_section='## MY CUSTOM ##')
        self.assertIn('## MY CUSTOM ##', result)


# ===========================================================================
# 5. Sub-section content — appended raw, no rogue placeholders
# ===========================================================================

class TestSubSectionContent(unittest.TestCase):
    """Each sub-section is appended raw (no .format() call), so any {ssrf_*}
    placeholder inside would leak into the agent prompt as literal text."""

    SUB_SECTIONS = {
        'SSRF_OOB_WORKFLOW': SSRF_OOB_WORKFLOW,
        'SSRF_GOPHER_CHAINS': SSRF_GOPHER_CHAINS,
        'SSRF_DNS_REBINDING': SSRF_DNS_REBINDING,
        'SSRF_PAYLOAD_REFERENCE': SSRF_PAYLOAD_REFERENCE,
    }

    def test_no_unsubstituted_ssrf_placeholders(self):
        for name, body in self.SUB_SECTIONS.items():
            stray = re.findall(r'\{ssrf_[a-z_]+\}', body)
            self.assertEqual(stray, [], f"{name} has unsubstituted placeholders: {stray}")

    def test_no_em_dashes_in_subsections(self):
        for name, body in self.SUB_SECTIONS.items():
            self.assertNotIn("\u2014", body, f"{name} contains em dash")

    def test_oob_workflow_describes_interactsh(self):
        self.assertIn("interactsh", SSRF_OOB_WORKFLOW)
        self.assertIn("OAST", SSRF_OOB_WORKFLOW)
        self.assertIn("Timing-based", SSRF_OOB_WORKFLOW)

    def test_gopher_chains_cover_redis_and_docker(self):
        self.assertIn("gopher://", SSRF_GOPHER_CHAINS)
        self.assertIn("Redis", SSRF_GOPHER_CHAINS)
        self.assertIn("Docker API", SSRF_GOPHER_CHAINS)
        self.assertIn("FastCGI", SSRF_GOPHER_CHAINS)

    def test_gopher_chains_cover_file_protocol(self):
        self.assertIn("file://", SSRF_GOPHER_CHAINS)
        self.assertIn("/etc/passwd", SSRF_GOPHER_CHAINS)

    def test_dns_rebinding_lists_free_services(self):
        self.assertIn("1u.ms", SSRF_DNS_REBINDING)
        self.assertIn("nip.io", SSRF_DNS_REBINDING)
        self.assertIn("rbndr.us", SSRF_DNS_REBINDING)

    def test_payload_reference_includes_parser_confusion(self):
        self.assertIn("URL Parser Confusion", SSRF_PAYLOAD_REFERENCE)
        self.assertIn("@169.254.169.254", SSRF_PAYLOAD_REFERENCE)

    def test_payload_reference_includes_address_encoding_table(self):
        self.assertIn("2130706433", SSRF_PAYLOAD_REFERENCE)
        self.assertIn("0x7f000001", SSRF_PAYLOAD_REFERENCE)

    def test_payload_reference_cites_real_world_precedents(self):
        """RedAmon's HackerOne grounding is a key differentiator; keep it."""
        self.assertIn("Capital One", SSRF_PAYLOAD_REFERENCE)
        self.assertIn("HackerOne", SSRF_PAYLOAD_REFERENCE)


# ===========================================================================
# 6. Cloud provider blocks — registry shape
# ===========================================================================

class TestCloudProviderBlocks(unittest.TestCase):
    """The cloud providers are looked up from SSRF_CLOUD_PROVIDER_BLOCKS by the
    inject function. The keys MUST match the lowercase names used in
    SSRF_CLOUD_PROVIDERS setting parsing."""

    def test_registry_keys(self):
        self.assertEqual(
            set(SSRF_CLOUD_PROVIDER_BLOCKS.keys()),
            {'aws', 'gcp', 'azure', 'digitalocean', 'alibaba'},
        )

    def test_registry_values_are_strings(self):
        for k, v in SSRF_CLOUD_PROVIDER_BLOCKS.items():
            self.assertIsInstance(v, str, f"{k} block is not a string")
            self.assertGreater(len(v), 50, f"{k} block suspiciously short")

    def test_aws_block_includes_imds_endpoints(self):
        self.assertIn("169.254.169.254", SSRF_CLOUD_AWS)
        self.assertIn("iam/security-credentials", SSRF_CLOUD_AWS)
        self.assertIn("IMDSv1", SSRF_CLOUD_AWS)
        self.assertIn("IMDSv2", SSRF_CLOUD_AWS)

    def test_gcp_block_requires_metadata_flavor_header(self):
        self.assertIn("Metadata-Flavor: Google", SSRF_CLOUD_GCP)
        self.assertIn("metadata.google.internal", SSRF_CLOUD_GCP)

    def test_azure_block_requires_metadata_true_header(self):
        self.assertIn("Metadata: true", SSRF_CLOUD_AZURE)

    def test_digitalocean_block_uses_correct_path(self):
        self.assertIn("/metadata/v1/", SSRF_CLOUD_DIGITALOCEAN)

    def test_alibaba_block_uses_distinct_ip(self):
        """Alibaba uses 100.100.100.200, NOT 169.254.169.254."""
        self.assertIn("100.100.100.200", SSRF_CLOUD_ALIBABA)

    def test_disabled_stub_signals_skip(self):
        self.assertIn("DISABLED", SSRF_CLOUD_DISABLED_STUB)
        self.assertIn("Skip", SSRF_CLOUD_DISABLED_STUB)


# ===========================================================================
# 7. get_phase_tools — end-to-end injection with the 10 knobs
# ===========================================================================

class TestGetPhaseToolsActivation(unittest.TestCase):
    """End-to-end: simulate the inject branch with various setting permutations."""

    def _get_phase_tools(self, attack_path_type, enabled_skills,
                          phase="exploitation", allowed_tools=None,
                          settings_override=None):
        if allowed_tools is None:
            allowed_tools = ['kali_shell', 'execute_curl', 'execute_code',
                             'execute_playwright', 'query_graph']
        defaults = {
            'STEALTH_MODE': False,
            'INFORMATIONAL_SYSTEM_PROMPT': '',
            'EXPL_SYSTEM_PROMPT': '',
            'POST_EXPL_SYSTEM_PROMPT': '',
            'ROE_ENABLED': False,
            'HYDRA_MAX_WORDLIST_ATTEMPTS': 3,
            'DOS_ASSESSMENT_ONLY': False,
            'PHISHING_SMTP_CONFIG': '',
            'ACTIVATE_POST_EXPL_PHASE': True,
            # SSRF defaults
            'SSRF_OOB_CALLBACK_ENABLED': True,
            'SSRF_CLOUD_METADATA_ENABLED': True,
            'SSRF_GOPHER_ENABLED': True,
            'SSRF_DNS_REBINDING_ENABLED': True,
            'SSRF_PAYLOAD_REFERENCE_ENABLED': True,
            'SSRF_REQUEST_TIMEOUT': 10,
            'SSRF_PORT_SCAN_PORTS': '22,80,443',
            'SSRF_INTERNAL_RANGES': '127.0.0.0/8',
            'SSRF_OOB_PROVIDER': 'oast.fun',
            'SSRF_CLOUD_PROVIDERS': 'aws,gcp,azure,digitalocean,alibaba',
            'SSRF_CUSTOM_INTERNAL_TARGETS': '',
        }
        if settings_override:
            defaults.update(settings_override)

        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase', return_value=allowed_tools), \
             patch('project_settings.get_enabled_builtin_skills', return_value=enabled_skills), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value="## Tools\n"), \
             patch('prompts.get_hydra_flags_from_settings', return_value="-t 16 -f"), \
             patch('prompts.get_dos_settings_dict', return_value={}), \
             patch('prompts.get_session_config_prompt', return_value=""), \
             patch('prompts.build_informational_tool_descriptions', return_value="info tools"):

            mock_setting.side_effect = lambda k, d=None: defaults.get(k, d)

            from prompts import get_phase_tools
            return get_phase_tools(
                phase=phase, activate_post_expl=True,
                post_expl_type="stateless",
                attack_path_type=attack_path_type,
                execution_trace=[],
            )

    # ----- skill matching -----

    def test_ssrf_classified_injects_workflow(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        self.assertIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)

    def test_ssrf_disabled_in_settings_falls_through(self):
        """Even with attack_path_type=ssrf, if the skill is disabled in
        ATTACK_SKILL_CONFIG, the workflow must NOT inject."""
        result = self._get_phase_tools("ssrf", {"cve_exploit"})
        self.assertNotIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)

    def test_ssrf_without_execute_curl_falls_through(self):
        """Phase guard: no execute_curl -> no SSRF workflow injected."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            allowed_tools=['kali_shell', 'execute_code'])
        self.assertNotIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)

    def test_other_skill_classified_doesnt_inject_ssrf(self):
        result = self._get_phase_tools("cve_exploit", {"ssrf", "cve_exploit"})
        self.assertNotIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)

    # ----- conditional sub-section gating -----

    def test_oob_subsection_present_when_enabled(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        self.assertIn("OOB / Blind SSRF Workflow", result)

    def test_oob_subsection_absent_when_disabled(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_OOB_CALLBACK_ENABLED': False})
        self.assertNotIn("## OOB / Blind SSRF Workflow", result)

    def test_oob_subsection_requires_kali_shell(self):
        """Even with OOB enabled, no kali_shell -> no OOB sub-section."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            allowed_tools=['execute_curl', 'execute_code', 'query_graph'])
        self.assertNotIn("## OOB / Blind SSRF Workflow", result)

    def test_gopher_chains_present_when_enabled(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        self.assertIn("Protocol Smuggling + RCE Chains", result)

    def test_gopher_chains_absent_when_disabled(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_GOPHER_ENABLED': False})
        self.assertNotIn("Protocol Smuggling + RCE Chains", result)

    def test_dns_rebinding_present_when_enabled(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        self.assertIn("DNS Rebinding Bypasses", result)

    def test_dns_rebinding_absent_when_disabled(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_DNS_REBINDING_ENABLED': False})
        self.assertNotIn("DNS Rebinding Bypasses", result)

    def test_payload_reference_present_when_enabled(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        self.assertIn("SSRF Payload Reference", result)

    def test_payload_reference_absent_when_disabled(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_PAYLOAD_REFERENCE_ENABLED': False})
        self.assertNotIn("SSRF Payload Reference", result)

    def test_lean_mode_strips_all_subsections(self):
        """All boolean toggles OFF -> only the main workflow remains."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={
                'SSRF_OOB_CALLBACK_ENABLED': False,
                'SSRF_CLOUD_METADATA_ENABLED': False,
                'SSRF_GOPHER_ENABLED': False,
                'SSRF_DNS_REBINDING_ENABLED': False,
                'SSRF_PAYLOAD_REFERENCE_ENABLED': False,
            })
        self.assertIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)
        self.assertNotIn("## OOB / Blind SSRF Workflow", result)
        self.assertNotIn("Protocol Smuggling + RCE Chains", result)
        self.assertNotIn("DNS Rebinding Bypasses", result)
        self.assertNotIn("SSRF Payload Reference", result)
        # Cloud-disabled stub should have replaced the cloud section
        self.assertIn("Cloud metadata pivots are DISABLED", result)

    # ----- cloud provider filter -----

    def test_cloud_section_includes_all_providers_by_default(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        for needle in ("AWS (IMDSv1)",
                       "GCP** (requires `Metadata-Flavor: Google`",
                       "Azure** (requires `Metadata: true`",
                       "DigitalOcean",
                       "Alibaba Cloud"):
            self.assertIn(needle, result, f"missing: {needle}")

    def test_cloud_filter_aws_only(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_CLOUD_PROVIDERS': 'aws'})
        self.assertIn("AWS (IMDSv1)", result)
        self.assertNotIn("GCP** (requires `Metadata-Flavor: Google`", result)
        self.assertNotIn("Azure** (requires `Metadata: true`", result)

    def test_cloud_filter_handles_whitespace_and_case(self):
        """Comma list parsing should tolerate ' AWS , GCP ' etc."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_CLOUD_PROVIDERS': '  AWS , GCP '})
        self.assertIn("AWS (IMDSv1)", result)
        self.assertIn("GCP**", result)
        self.assertNotIn("Azure**", result)

    def test_cloud_filter_unknown_provider_skipped(self):
        """Unknown providers in the list should not crash; just be skipped."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_CLOUD_PROVIDERS': 'aws,oracle,bogus'})
        self.assertIn("AWS (IMDSv1)", result)
        self.assertNotIn("Oracle", result)

    def test_cloud_filter_empty_string_falls_back_to_disabled_stub(self):
        """If the providers list is empty AND cloud is enabled, the stub
        should appear (no provider blocks to inject)."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_CLOUD_PROVIDERS': ''})
        self.assertIn("Cloud metadata pivots are DISABLED", result)

    def test_cloud_metadata_disabled_overrides_provider_list(self):
        """SSRF_CLOUD_METADATA_ENABLED=False forces the disabled stub even
        when SSRF_CLOUD_PROVIDERS is fully populated."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={
                'SSRF_CLOUD_METADATA_ENABLED': False,
                'SSRF_CLOUD_PROVIDERS': 'aws,gcp,azure',
            })
        self.assertIn("Cloud metadata pivots are DISABLED", result)
        self.assertNotIn("AWS (IMDSv1)", result)

    # ----- custom targets injection -----

    def test_custom_targets_block_absent_when_empty(self):
        result = self._get_phase_tools("ssrf", {"ssrf"})
        self.assertNotIn("SITE-SPECIFIC INTERNAL TARGETS", result)

    def test_custom_targets_block_injected_when_populated(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={
                'SSRF_CUSTOM_INTERNAL_TARGETS':
                    'admin.internal.example.com\n10.20.30.40:8500\njumphost.corp.local',
            })
        self.assertIn("SITE-SPECIFIC INTERNAL TARGETS", result)
        self.assertIn("admin.internal.example.com", result)
        self.assertIn("10.20.30.40:8500", result)
        self.assertIn("jumphost.corp.local", result)

    def test_custom_targets_whitespace_only_treated_as_empty(self):
        """A whitespace-only setting should NOT inject the block (avoids
        empty-section leak in the prompt)."""
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_CUSTOM_INTERNAL_TARGETS': '   \n  \n  '})
        self.assertNotIn("SITE-SPECIFIC INTERNAL TARGETS", result)

    # ----- format-string substitution end-to-end -----

    def test_request_timeout_propagates_to_prompt(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_REQUEST_TIMEOUT': 99})
        self.assertIn("Request timeout:               99s", result)

    def test_oob_provider_propagates_to_interactsh_command(self):
        result = self._get_phase_tools(
            "ssrf", {"ssrf"},
            settings_override={'SSRF_OOB_PROVIDER': 'self-hosted-oast.example.com'})
        self.assertIn("-server self-hosted-oast.example.com", result)


# ===========================================================================
# 8. Informational phase — workflow injects in informational too
# ===========================================================================

class TestInformationalPhase(unittest.TestCase):
    """SSRF surface inventory should be available in the informational phase
    so the agent can request transition to exploitation."""

    def test_ssrf_workflow_injects_in_informational(self):
        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase',
                   return_value=['kali_shell', 'execute_curl', 'query_graph']), \
             patch('project_settings.get_enabled_builtin_skills', return_value={'ssrf'}), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value=""), \
             patch('prompts.get_hydra_flags_from_settings', return_value=""), \
             patch('prompts.get_dos_settings_dict', return_value={}), \
             patch('prompts.get_session_config_prompt', return_value=""), \
             patch('prompts.build_informational_tool_descriptions', return_value=""):

            settings = {
                'SSRF_OOB_CALLBACK_ENABLED': True,
                'SSRF_CLOUD_METADATA_ENABLED': True,
                'SSRF_GOPHER_ENABLED': True,
                'SSRF_DNS_REBINDING_ENABLED': True,
                'SSRF_PAYLOAD_REFERENCE_ENABLED': True,
                'SSRF_REQUEST_TIMEOUT': 10,
                'SSRF_PORT_SCAN_PORTS': '22,80',
                'SSRF_INTERNAL_RANGES': '127.0.0.0/8',
                'SSRF_OOB_PROVIDER': 'oast.fun',
                'SSRF_CLOUD_PROVIDERS': 'aws',
                'SSRF_CUSTOM_INTERNAL_TARGETS': '',
                'STEALTH_MODE': False,
                'INFORMATIONAL_SYSTEM_PROMPT': '',
                'ROE_ENABLED': False,
            }
            mock_setting.side_effect = lambda k, d=None: settings.get(k, d)

            from prompts import get_phase_tools
            result = get_phase_tools(
                phase="informational", activate_post_expl=True,
                post_expl_type="stateless", attack_path_type="ssrf",
                execution_trace=[])
            self.assertIn("ATTACK SKILL: SERVER-SIDE REQUEST FORGERY", result)


# ===========================================================================
# 9. Tool registry — required tools documented
# ===========================================================================

class TestToolRegistry(unittest.TestCase):
    """The SSRF prompt references interactsh-client (via kali_shell), execute_curl,
    query_graph, and execute_code. They must exist in the registry."""

    def test_execute_curl_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_curl", TOOL_REGISTRY)

    def test_query_graph_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("query_graph", TOOL_REGISTRY)

    def test_kali_shell_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("kali_shell", TOOL_REGISTRY)

    def test_interactsh_in_kali_shell_description(self):
        """The blind-SSRF workflow relies on interactsh-client being available
        inside the Kali sandbox image."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("interactsh", kali_desc.lower())


# ===========================================================================
# 10. Regression — existing skills still classify and inject correctly
# ===========================================================================

class TestRegressionExistingSkills(unittest.TestCase):
    """Adding SSRF must not break any other built-in skill."""

    def test_xss_still_in_classification_map(self):
        self.assertIn("xss", _BUILTIN_SKILL_MAP)

    def test_sql_injection_still_in_classification_map(self):
        self.assertIn("sql_injection", _BUILTIN_SKILL_MAP)

    def test_cve_exploit_still_in_classification_map(self):
        self.assertIn("cve_exploit", _BUILTIN_SKILL_MAP)

    def test_existing_skills_in_known_paths(self):
        for path in ("cve_exploit", "brute_force_credential_guess",
                     "phishing_social_engineering", "denial_of_service",
                     "sql_injection", "xss"):
            self.assertIn(path, KNOWN_ATTACK_PATHS, f"{path} missing")

    def test_xss_classification_unaffected(self):
        """When XSS is enabled and SSRF isn't, classifier prompt should still
        cleanly include XSS without SSRF leakage."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'xss'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for XSS")
            self.assertIn("Cross-Site Scripting", prompt)
            self.assertNotIn("### ssrf — Server-Side Request Forgery", prompt)


if __name__ == "__main__":
    unittest.main()
