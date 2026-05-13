"""
Tests for the Path Traversal / LFI / RFI built-in attack skill.

Covers state registration, classification wiring, project settings defaults,
prompt template formatting (with all 6 parametric knobs), conditional
sub-section injection in get_phase_tools, sub-section content invariants,
tool-registry presence, and regression on existing built-ins.

Run with: python -m pytest tests/test_path_traversal_skill.py -v
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
from prompts.path_traversal_prompts import (
    PATH_TRAVERSAL_TOOLS,
    PATH_TRAVERSAL_PHP_WRAPPERS,
    PATH_TRAVERSAL_OOB_WORKFLOW,
    PATH_TRAVERSAL_ARCHIVE_EXTRACTION,
    PATH_TRAVERSAL_PAYLOAD_REFERENCE,
)
from prompts.classification import (
    _PATH_TRAVERSAL_SECTION,
    _BUILTIN_SKILL_MAP,
    _CLASSIFICATION_INSTRUCTIONS,
    build_classification_prompt,
)


# ===========================================================================
# 1. State -- KNOWN_ATTACK_PATHS, AttackPathClassification accept "path_traversal"
# ===========================================================================

class TestStateRegistration(unittest.TestCase):
    """Verify path_traversal is registered as a known attack path so the
    Pydantic validator accepts classifier output."""

    def test_path_traversal_in_known_paths(self):
        self.assertIn("path_traversal", KNOWN_ATTACK_PATHS)

    def test_path_traversal_is_not_unclassified(self):
        self.assertFalse(is_unclassified_path("path_traversal"))

    def test_legacy_directory_traversal_unclassified_still_valid(self):
        """Legacy `directory_traversal-unclassified` ids must keep passing
        regex validation for back-compat with old projects."""
        self.assertTrue(is_unclassified_path("directory_traversal-unclassified"))

    def test_attack_path_classification_accepts_path_traversal(self):
        """Pydantic model must accept path_traversal as a valid type."""
        apc = AttackPathClassification(
            attack_path_type="path_traversal",
            required_phase="exploitation",
            confidence=0.95,
            reasoning="Path traversal test",
        )
        self.assertEqual(apc.attack_path_type, "path_traversal")

    def test_attack_path_classification_still_accepts_unclassified(self):
        apc = AttackPathClassification(
            attack_path_type="path_traversal-unclassified",
            required_phase="exploitation",
            confidence=0.6,
            reasoning="Legacy path",
        )
        self.assertEqual(apc.attack_path_type, "path_traversal-unclassified")


# ===========================================================================
# 2. Classification -- section text, map entry, instructions
# ===========================================================================

class TestClassificationRegistration(unittest.TestCase):
    """Verify path_traversal is wired into the dynamic classification prompt."""

    def test_section_defined(self):
        self.assertIn("path_traversal", _PATH_TRAVERSAL_SECTION)
        self.assertIn("Path Traversal", _PATH_TRAVERSAL_SECTION)
        self.assertIn("LFI", _PATH_TRAVERSAL_SECTION)
        self.assertIn("RFI", _PATH_TRAVERSAL_SECTION)
        self.assertIn("php://filter", _PATH_TRAVERSAL_SECTION)
        self.assertIn("Zip Slip", _PATH_TRAVERSAL_SECTION)

    def test_section_disambiguates_from_neighbours(self):
        """Section must explicitly distinguish from rce / sql_injection / xss /
        ssrf to keep classifier precision high. The brief flagged classifier
        overlap with `rce` (LFI -> RCE chains) as the chief risk."""
        text = _PATH_TRAVERSAL_SECTION.lower()
        for neighbour in ("sql_injection", "xss", "ssrf", "rce", "cve_exploit"):
            self.assertIn(neighbour, text, f"missing disambiguation vs {neighbour}")

    def test_in_builtin_skill_map(self):
        self.assertIn("path_traversal", _BUILTIN_SKILL_MAP)
        section, _letter, skill_id = _BUILTIN_SKILL_MAP["path_traversal"]
        self.assertEqual(skill_id, "path_traversal")
        self.assertEqual(section, _PATH_TRAVERSAL_SECTION)

    def test_classification_instruction_present(self):
        self.assertIn("path_traversal", _CLASSIFICATION_INSTRUCTIONS)
        instruction = _CLASSIFICATION_INSTRUCTIONS["path_traversal"]
        self.assertIn("path traversal", instruction.lower())
        self.assertIn("LFI", instruction)
        self.assertIn("RFI", instruction)
        # Must explicitly mark the boundary against rce (the main overlap risk)
        self.assertIn("rce", instruction.lower())

    def test_classification_instruction_lists_php_wrappers(self):
        instruction = _CLASSIFICATION_INSTRUCTIONS["path_traversal"]
        for wrapper in ("php://filter", "data://", "expect://", "zip://"):
            self.assertIn(wrapper, instruction, f"missing wrapper {wrapper}")

    def test_build_classification_prompt_includes_when_enabled(self):
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'path_traversal', 'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt(
                "Test for LFI on the download endpoint")
            self.assertIn("path_traversal", prompt)
            self.assertIn("Path Traversal", prompt)

    def test_build_classification_prompt_excludes_when_disabled(self):
        """Disabling path_traversal must remove it from the classifier menu."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for path traversal")
            self.assertNotIn("### path_traversal", prompt)
            self.assertIn("unclassified", prompt)


# ===========================================================================
# 3. Project settings -- 6 tunables + master toggle default ON
# ===========================================================================

class TestProjectSettings(unittest.TestCase):
    """Verify all 6 path-traversal tunables and the master toggle defaults."""

    def test_path_traversal_in_attack_skill_config(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertIn('path_traversal', config['builtIn'])

    def test_master_toggle_default_on(self):
        """Read-only file-disclosure is non-destructive, mirrors SQLi / XSS /
        SSRF / RCE which all default ON."""
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertTrue(config['builtIn']['path_traversal'])

    def test_oob_callback_default_on(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_OOB_CALLBACK_ENABLED'])

    def test_php_wrappers_default_on(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED'])

    def test_archive_extraction_default_off(self):
        """Zip Slip writes files to the target. Operator must opt in."""
        self.assertFalse(DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED'])

    def test_payload_reference_default_on(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED'])

    def test_request_timeout_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_REQUEST_TIMEOUT'], 10)

    def test_oob_provider_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_OOB_PROVIDER'], 'oast.fun')


# ===========================================================================
# 4. Prompt template -- PATH_TRAVERSAL_TOOLS format-string substitution
# ===========================================================================

class TestPromptTemplate(unittest.TestCase):
    """Verify the main prompt formats cleanly with all 6 placeholders."""

    def _format(self, **overrides):
        defaults = dict(
            path_traversal_oob_callback_enabled=True,
            path_traversal_php_wrappers_enabled=True,
            path_traversal_archive_extraction_enabled=False,
            path_traversal_payload_reference_enabled=True,
            path_traversal_request_timeout=10,
            path_traversal_oob_provider='oast.fun',
        )
        defaults.update(overrides)
        return PATH_TRAVERSAL_TOOLS.format(**defaults)

    def test_formats_with_all_defaults(self):
        result = self._format()
        self.assertIn("ATTACK SKILL: PATH TRAVERSAL", result)
        # No leftover {path_traversal_*} placeholders
        self.assertEqual(re.findall(r'\{path_traversal_[a-z_]+\}', result), [])

    def test_curl_format_string_preserved(self):
        """`%{time_total}` is a literal curl format string; doubled braces in
        the source must collapse to single braces in the rendered prompt."""
        result = self._format()
        self.assertIn("%{time_total}", result)

    def test_no_em_dashes_in_main_prompt(self):
        """User-feedback rule: never emit em dashes in agent text."""
        result = self._format()
        self.assertNotIn("\u2014", result)

    def test_settings_block_reflects_values(self):
        result = self._format(path_traversal_request_timeout=42,
                               path_traversal_oob_provider='self.local')
        self.assertIn("Request timeout:                             42s", result)
        self.assertIn("OOB provider:                                self.local", result)

    def test_request_timeout_propagates_to_curl_commands(self):
        result = self._format(path_traversal_request_timeout=99)
        self.assertIn("--max-time 99", result)

    def test_workflow_steps_present(self):
        result = self._format()
        for step in (
            "Step 1: Reuse recon",
            "Step 2: Surface candidate sinks",
            "Step 3: Establish a deterministic oracle",
            "Step 4: Confirm exactly ONE primitive",
            "Step 5: Fingerprint the disclosure context",
            "Step 6: Targeted exfiltration",
            "Step 7: Long-running automation",
            "Step 8: Reporting requirements",
        ):
            self.assertIn(step, result)

    def test_transition_phase_instruction_present(self):
        result = self._format()
        self.assertIn("transition_phase", result)

    def test_hard_rules_block_present(self):
        result = self._format()
        self.assertIn("Hard rules", result)
        self.assertIn("Read-only proofs", result)

    def test_proof_levels_present(self):
        result = self._format()
        self.assertIn("Proof Levels", result)
        for level in ("Level 1", "Level 2", "Level 3", "Level 4"):
            # Level numbers appear in the table rows
            self.assertIn(level.split()[1], result)

    def test_false_positive_gate_present(self):
        result = self._format()
        self.assertIn("False positive gate", result)

    def test_primitives_enumerated(self):
        """All 4 primitives must appear in the intro so the agent picks one."""
        result = self._format()
        for primitive in (
            "Classic path traversal",
            "Local File Inclusion (LFI)",
            "Remote File Inclusion (RFI)",
            "Archive-extraction",
        ):
            self.assertIn(primitive, result)


# ===========================================================================
# 5. Sub-section content -- appended raw, no rogue placeholders
# ===========================================================================

class TestSubSectionContent(unittest.TestCase):
    """Each sub-section is appended raw (no .format() call), so any
    {path_traversal_*} placeholder inside would leak into the agent prompt
    as literal text."""

    SUB_SECTIONS = {
        'PATH_TRAVERSAL_PHP_WRAPPERS': PATH_TRAVERSAL_PHP_WRAPPERS,
        'PATH_TRAVERSAL_OOB_WORKFLOW': PATH_TRAVERSAL_OOB_WORKFLOW,
        'PATH_TRAVERSAL_ARCHIVE_EXTRACTION': PATH_TRAVERSAL_ARCHIVE_EXTRACTION,
        'PATH_TRAVERSAL_PAYLOAD_REFERENCE': PATH_TRAVERSAL_PAYLOAD_REFERENCE,
    }

    def test_no_unsubstituted_placeholders(self):
        for name, body in self.SUB_SECTIONS.items():
            stray = re.findall(r'\{path_traversal_[a-z_]+\}', body)
            self.assertEqual(stray, [],
                             f"{name} has unsubstituted placeholders: {stray}")

    def test_no_em_dashes_in_subsections(self):
        for name, body in self.SUB_SECTIONS.items():
            self.assertNotIn("\u2014", body, f"{name} contains em dash")

    def test_php_wrappers_covers_all_four(self):
        for wrapper in ("php://filter", "data://", "expect://", "zip://"):
            self.assertIn(wrapper, PATH_TRAVERSAL_PHP_WRAPPERS,
                          f"missing wrapper {wrapper}")

    def test_php_wrappers_documents_log_poisoning(self):
        self.assertIn("Log poisoning", PATH_TRAVERSAL_PHP_WRAPPERS)
        self.assertIn("/var/log/apache2/access.log", PATH_TRAVERSAL_PHP_WRAPPERS)
        self.assertIn("User-Agent", PATH_TRAVERSAL_PHP_WRAPPERS)

    def test_php_wrappers_documents_iconv_filter_chain(self):
        """The iconv filter chain is the modern blind-LFI escalation when
        convert.base64-encode is blacklisted."""
        self.assertIn("convert.iconv", PATH_TRAVERSAL_PHP_WRAPPERS)

    def test_oob_workflow_describes_interactsh(self):
        self.assertIn("interactsh", PATH_TRAVERSAL_OOB_WORKFLOW)
        self.assertIn("REGISTERED_DOMAIN", PATH_TRAVERSAL_OOB_WORKFLOW)
        self.assertIn("RFI", PATH_TRAVERSAL_OOB_WORKFLOW)

    def test_oob_workflow_includes_per_language_streams(self):
        """RFI is rare on hardened PHP; the language-specific stream handlers
        (Java JarURLConnection, netdoc) keep the skill productive on JVM apps."""
        self.assertIn("jar:", PATH_TRAVERSAL_OOB_WORKFLOW)
        self.assertIn("netdoc://", PATH_TRAVERSAL_OOB_WORKFLOW)

    def test_archive_extraction_covers_zip_and_tar(self):
        self.assertIn("zipfile", PATH_TRAVERSAL_ARCHIVE_EXTRACTION)
        self.assertIn("tarfile", PATH_TRAVERSAL_ARCHIVE_EXTRACTION)
        self.assertIn("Zip Slip", PATH_TRAVERSAL_ARCHIVE_EXTRACTION)

    def test_archive_extraction_warns_on_cleanup(self):
        """Archive workflow writes files. Cleanup obligation must be visible."""
        self.assertIn("Cleanup", PATH_TRAVERSAL_ARCHIVE_EXTRACTION)
        self.assertIn("MANDATORY", PATH_TRAVERSAL_ARCHIVE_EXTRACTION)

    def test_payload_reference_includes_encoding_table(self):
        self.assertIn("Encoding variants", PATH_TRAVERSAL_PAYLOAD_REFERENCE)
        self.assertIn("%2e%2e%2f", PATH_TRAVERSAL_PAYLOAD_REFERENCE)
        self.assertIn("..%252f", PATH_TRAVERSAL_PAYLOAD_REFERENCE)

    def test_payload_reference_includes_dot_tricks(self):
        self.assertIn("....//", PATH_TRAVERSAL_PAYLOAD_REFERENCE)

    def test_payload_reference_high_value_targets(self):
        for target in ("/etc/passwd", "/etc/hosts", "wp-config.php",
                       "/proc/self/environ", "win.ini"):
            self.assertIn(target, PATH_TRAVERSAL_PAYLOAD_REFERENCE,
                          f"missing high-value target {target}")

    def test_payload_reference_cites_real_world_precedents(self):
        """RedAmon's CVE / HackerOne grounding is a key differentiator; keep it."""
        self.assertIn("CVE-2021-41773", PATH_TRAVERSAL_PAYLOAD_REFERENCE)
        self.assertIn("Zip Slip", PATH_TRAVERSAL_PAYLOAD_REFERENCE)


# ===========================================================================
# 6. get_phase_tools -- end-to-end injection with the 6 knobs
# ===========================================================================

class TestGetPhaseToolsActivation(unittest.TestCase):
    """End-to-end: simulate the inject branch with various setting permutations."""

    def _get_phase_tools(self, attack_path_type, enabled_skills,
                          phase="exploitation", allowed_tools=None,
                          settings_override=None):
        if allowed_tools is None:
            allowed_tools = ['kali_shell', 'execute_curl', 'execute_code',
                             'execute_playwright', 'execute_ffuf',
                             'execute_nuclei', 'query_graph']
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
            # Path Traversal defaults
            'PATH_TRAVERSAL_OOB_CALLBACK_ENABLED': True,
            'PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED': True,
            'PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED': False,
            'PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED': True,
            'PATH_TRAVERSAL_REQUEST_TIMEOUT': 10,
            'PATH_TRAVERSAL_OOB_PROVIDER': 'oast.fun',
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

    def test_classified_injects_workflow(self):
        result = self._get_phase_tools("path_traversal", {"path_traversal"})
        self.assertIn("ATTACK SKILL: PATH TRAVERSAL", result)

    def test_disabled_in_settings_falls_through(self):
        """Even when classified, if the skill is disabled in
        ATTACK_SKILL_CONFIG, the workflow must NOT inject."""
        result = self._get_phase_tools("path_traversal", {"cve_exploit"})
        self.assertNotIn("ATTACK SKILL: PATH TRAVERSAL", result)

    def test_without_execute_curl_falls_through(self):
        """Phase guard: no execute_curl -> no path_traversal workflow."""
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            allowed_tools=['kali_shell', 'execute_code'])
        self.assertNotIn("ATTACK SKILL: PATH TRAVERSAL", result)

    def test_other_skill_classified_doesnt_inject_path_traversal(self):
        result = self._get_phase_tools(
            "cve_exploit", {"path_traversal", "cve_exploit"})
        self.assertNotIn("ATTACK SKILL: PATH TRAVERSAL", result)

    # ----- conditional sub-section gating -----

    # Sub-section presence checks use the `## ` heading prefix, since the main
    # workflow body legitimately mentions the sub-section names as
    # cross-references in Step 4 (e.g. "see the **PHP Wrappers + Log Poisoning
    # Workflow** section below"). Only the `## <name>` heading appears once,
    # at the top of the rendered sub-section.

    def test_php_wrappers_present_when_enabled(self):
        result = self._get_phase_tools("path_traversal", {"path_traversal"})
        self.assertIn("## PHP Wrappers + Log Poisoning Workflow", result)

    def test_php_wrappers_absent_when_disabled(self):
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={'PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED': False})
        self.assertNotIn("## PHP Wrappers + Log Poisoning Workflow", result)

    def test_oob_workflow_present_when_enabled(self):
        result = self._get_phase_tools("path_traversal", {"path_traversal"})
        self.assertIn("## OOB / RFI Workflow", result)

    def test_oob_workflow_absent_when_disabled(self):
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={'PATH_TRAVERSAL_OOB_CALLBACK_ENABLED': False})
        self.assertNotIn("## OOB / RFI Workflow", result)

    def test_oob_workflow_requires_kali_shell(self):
        """interactsh-client lives in kali_shell; without it, no OOB sub-section."""
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            allowed_tools=['execute_curl', 'execute_code', 'query_graph'])
        self.assertNotIn("## OOB / RFI Workflow", result)

    def test_archive_extraction_default_off(self):
        """Default is OFF -- the section must not appear with default settings."""
        result = self._get_phase_tools("path_traversal", {"path_traversal"})
        self.assertNotIn("## Archive Extraction Workflow", result)

    def test_archive_extraction_present_when_enabled(self):
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={'PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED': True})
        self.assertIn("## Archive Extraction Workflow", result)

    def test_archive_extraction_requires_execute_code(self):
        """Crafting Zip Slip archives uses execute_code (Python zipfile)."""
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            allowed_tools=['execute_curl', 'kali_shell', 'query_graph'],
            settings_override={'PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED': True})
        self.assertNotIn("## Archive Extraction Workflow", result)

    def test_payload_reference_present_when_enabled(self):
        result = self._get_phase_tools("path_traversal", {"path_traversal"})
        self.assertIn("## Path Traversal Payload Reference", result)

    def test_payload_reference_absent_when_disabled(self):
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={'PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED': False})
        self.assertNotIn("## Path Traversal Payload Reference", result)

    def test_lean_mode_strips_all_subsections(self):
        """All boolean toggles OFF -> only the main workflow remains."""
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={
                'PATH_TRAVERSAL_OOB_CALLBACK_ENABLED': False,
                'PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED': False,
                'PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED': False,
                'PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED': False,
            })
        self.assertIn("ATTACK SKILL: PATH TRAVERSAL", result)
        self.assertNotIn("## PHP Wrappers + Log Poisoning Workflow", result)
        self.assertNotIn("## OOB / RFI Workflow", result)
        self.assertNotIn("## Archive Extraction Workflow", result)
        self.assertNotIn("## Path Traversal Payload Reference", result)

    # ----- format-string substitution end-to-end -----

    def test_request_timeout_propagates_to_prompt(self):
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={'PATH_TRAVERSAL_REQUEST_TIMEOUT': 99})
        self.assertIn("Request timeout:                             99s", result)
        self.assertIn("--max-time 99", result)

    def test_oob_provider_propagates_to_settings_block(self):
        result = self._get_phase_tools(
            "path_traversal", {"path_traversal"},
            settings_override={'PATH_TRAVERSAL_OOB_PROVIDER': 'self-hosted-oast.example.com'})
        self.assertIn("self-hosted-oast.example.com", result)


# ===========================================================================
# 7. Informational phase -- workflow injects in informational too
# ===========================================================================

class TestInformationalPhase(unittest.TestCase):
    """Surface inventory should be available in the informational phase so
    the agent can request transition to exploitation."""

    def test_workflow_injects_in_informational(self):
        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase',
                   return_value=['kali_shell', 'execute_curl', 'execute_code',
                                 'query_graph']), \
             patch('project_settings.get_enabled_builtin_skills',
                   return_value={'path_traversal'}), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value=""), \
             patch('prompts.get_hydra_flags_from_settings', return_value=""), \
             patch('prompts.get_dos_settings_dict', return_value={}), \
             patch('prompts.get_session_config_prompt', return_value=""), \
             patch('prompts.build_informational_tool_descriptions', return_value=""):

            settings = {
                'PATH_TRAVERSAL_OOB_CALLBACK_ENABLED': True,
                'PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED': True,
                'PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED': False,
                'PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED': True,
                'PATH_TRAVERSAL_REQUEST_TIMEOUT': 10,
                'PATH_TRAVERSAL_OOB_PROVIDER': 'oast.fun',
                'STEALTH_MODE': False,
                'INFORMATIONAL_SYSTEM_PROMPT': '',
                'ROE_ENABLED': False,
            }
            mock_setting.side_effect = lambda k, d=None: settings.get(k, d)

            from prompts import get_phase_tools
            result = get_phase_tools(
                phase="informational", activate_post_expl=True,
                post_expl_type="stateless", attack_path_type="path_traversal",
                execution_trace=[])
            self.assertIn("ATTACK SKILL: PATH TRAVERSAL", result)


# ===========================================================================
# 8. Tool registry -- required tools documented
# ===========================================================================

class TestToolRegistry(unittest.TestCase):
    """The path-traversal prompt references execute_curl, execute_ffuf,
    execute_nuclei, kali_shell (interactsh-client), execute_code, query_graph.
    They must exist in the registry."""

    def test_execute_curl_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_curl", TOOL_REGISTRY)

    def test_execute_ffuf_documented(self):
        """Step 2 + Step 7 use ffuf for path / parameter fuzzing."""
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_ffuf", TOOL_REGISTRY)

    def test_execute_nuclei_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_nuclei", TOOL_REGISTRY)

    def test_query_graph_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("query_graph", TOOL_REGISTRY)

    def test_kali_shell_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("kali_shell", TOOL_REGISTRY)

    def test_interactsh_in_kali_shell_description(self):
        """The OOB / RFI sub-workflow relies on interactsh-client inside Kali."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("interactsh", kali_desc.lower())

    def test_seclists_path_in_kali_shell_description(self):
        """Step 7 references the SecLists raft-medium-directories wordlist."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("seclists", kali_desc.lower())


# ===========================================================================
# 9. Regression -- existing skills still classify and inject correctly
# ===========================================================================

class TestRegressionExistingSkills(unittest.TestCase):
    """Adding path_traversal must not break any other built-in skill."""

    def test_all_legacy_paths_in_known_paths(self):
        for path in ("cve_exploit", "brute_force_credential_guess",
                     "phishing_social_engineering", "denial_of_service",
                     "sql_injection", "xss", "ssrf", "rce"):
            self.assertIn(path, KNOWN_ATTACK_PATHS, f"{path} missing")

    def test_xss_still_in_classification_map(self):
        self.assertIn("xss", _BUILTIN_SKILL_MAP)

    def test_sql_injection_still_in_classification_map(self):
        self.assertIn("sql_injection", _BUILTIN_SKILL_MAP)

    def test_ssrf_still_in_classification_map(self):
        self.assertIn("ssrf", _BUILTIN_SKILL_MAP)

    def test_rce_still_in_classification_map(self):
        self.assertIn("rce", _BUILTIN_SKILL_MAP)

    def test_ssrf_classification_unaffected(self):
        """When SSRF is enabled and path_traversal isn't, classifier prompt
        should still cleanly include SSRF without path_traversal leakage."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'ssrf'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for SSRF")
            self.assertIn("Server-Side Request Forgery", prompt)
            self.assertNotIn("### path_traversal", prompt)

    def test_rce_classification_unaffected(self):
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'rce'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for command injection")
            self.assertIn("Remote Code Execution", prompt)
            self.assertNotIn("### path_traversal", prompt)

    def test_ssrf_skill_does_not_match_path_traversal_keyword(self):
        """Adding the path_traversal section must not hijack the SSRF classifier
        by accident -- both skills coexist when both are enabled."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'ssrf', 'path_traversal'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for SSRF")
            self.assertIn("ssrf", prompt)
            self.assertIn("path_traversal", prompt)


# ===========================================================================
# 10. Frontend artifacts -- API tooltip + suggestion data + Prisma schema
# ===========================================================================

class TestFrontendArtifacts(unittest.TestCase):
    """Smoke checks against the webapp source to catch missing wiring on
    the layers that don't crash the agent but break the UX."""

    REPO_ROOT = os.path.dirname(_agentic_dir)

    def _read(self, rel):
        with open(os.path.join(self.REPO_ROOT, rel), encoding='utf-8') as f:
            return f.read()

    def test_drawer_tooltip_api_lists_path_traversal(self):
        body = self._read('webapp/src/app/api/users/[id]/attack-skills/available/route.ts')
        self.assertIn("'path_traversal'", body)

    def test_attack_skills_section_lists_path_traversal(self):
        body = self._read(
            'webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx')
        self.assertIn("'path_traversal'", body)
        self.assertIn("PathTraversalSection", body)

    def test_path_traversal_section_component_exists(self):
        body = self._read(
            'webapp/src/components/projects/ProjectForm/sections/PathTraversalSection.tsx')
        # All 6 tunables must be wired to camelCase Prisma fields
        for camel in (
            'pathTraversalOobCallbackEnabled',
            'pathTraversalPhpWrappersEnabled',
            'pathTraversalArchiveExtractionEnabled',
            'pathTraversalPayloadReferenceEnabled',
            'pathTraversalRequestTimeout',
            'pathTraversalOobProvider',
        ):
            self.assertIn(camel, body, f"missing field wiring: {camel}")

    def test_phase_config_has_badge(self):
        body = self._read(
            'webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts')
        self.assertIn("path_traversal:", body)
        self.assertIn("'PATH'", body)

    def test_suggestion_data_has_block(self):
        body = self._read(
            'webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts')
        self.assertIn("id: 'path_traversal'", body)
        self.assertIn("Path Traversal", body)

    def test_prisma_schema_has_columns(self):
        body = self._read('webapp/prisma/schema.prisma')
        for column in (
            'pathTraversalOobCallbackEnabled',
            'pathTraversalPhpWrappersEnabled',
            'pathTraversalArchiveExtractionEnabled',
            'pathTraversalPayloadReferenceEnabled',
            'pathTraversalRequestTimeout',
            'pathTraversalOobProvider',
        ):
            self.assertIn(column, body, f"missing prisma column: {column}")

    def test_prisma_attack_skill_config_default_includes_path_traversal(self):
        body = self._read('webapp/prisma/schema.prisma')
        # The escaped JSON default must list the new id with a value
        self.assertIn('\\"path_traversal\\":true', body)


# ===========================================================================
# 11. Cross-file consistency -- snake_case <-> camelCase symmetry
# ===========================================================================

class TestCrossFileNamingConsistency(unittest.TestCase):
    """Catch silent drift between Prisma columns, Python settings keys, and
    the React form bindings. Each tunable must appear in exactly THREE places:
    Prisma column, Python `fetch_agent_settings` mapping, and the React
    component that writes the field via updateField()."""

    REPO_ROOT = os.path.dirname(_agentic_dir)

    @classmethod
    def setUpClass(cls):
        # webapp source: lives at <repo>/webapp/... whether agentic is at /app
        # or at <repo>/agentic. Locate it relative to REPO_ROOT.
        with open(os.path.join(cls.REPO_ROOT, 'webapp/prisma/schema.prisma')) as f:
            cls.prisma = f.read()
        # Python settings: read the module's own source file (always reachable)
        import project_settings as _ps
        with open(_ps.__file__) as f:
            cls.py = f.read()
        with open(os.path.join(
            cls.REPO_ROOT,
            'webapp/src/components/projects/ProjectForm/sections/PathTraversalSection.tsx'
        )) as f:
            cls.ts_section = f.read()

    @staticmethod
    def _snake_to_camel(s):
        parts = s.replace('PATH_TRAVERSAL_', '').lower().split('_')
        return 'pathTraversal' + ''.join(w.capitalize() for w in parts)

    def test_six_prisma_columns(self):
        prisma_fields = re.findall(
            r'(pathTraversal[A-Za-z]+)\s+\S+.*?@map\("(path_traversal_[a-z_]+)"\)',
            self.prisma)
        self.assertEqual(len(prisma_fields), 6,
                          f'expected 6 prisma columns, got {len(prisma_fields)}')

    def test_python_settings_camel_round_trip(self):
        """Every fetch_agent_settings mapping turns SCREAMING_SNAKE -> camelCase
        in the conventional way. A typo here would silently fall back to the
        default and the operator's saved value would never reach the agent."""
        mappings = re.findall(
            r"settings\['(PATH_TRAVERSAL_[A-Z_]+)'\]\s*=\s*project\.get\('([a-zA-Z]+)'",
            self.py)
        self.assertEqual(len(mappings), 6, f'expected 6 mappings, got {len(mappings)}')
        for snake, camel in mappings:
            self.assertEqual(camel, self._snake_to_camel(snake),
                              f'{snake} maps to {camel} (expected {self._snake_to_camel(snake)})')

    def test_prisma_columns_match_python_mappings(self):
        prisma_camels = set(re.findall(
            r'(pathTraversal[A-Za-z]+)\s+\S+.*?@map\("path_traversal_[a-z_]+"\)',
            self.prisma))
        py_camels = set(re.findall(
            r"project\.get\('(pathTraversal[A-Za-z]+)'", self.py))
        self.assertEqual(prisma_camels, py_camels,
                          f'prisma-only={prisma_camels - py_camels}, '
                          f'python-only={py_camels - prisma_camels}')

    def test_react_section_binds_every_prisma_field(self):
        """Each Prisma camelCase column must appear in the React section so
        the user can set it. A missing binding leaves a UI hole."""
        prisma_camels = set(re.findall(
            r'(pathTraversal[A-Za-z]+)\s+\S+.*?@map\("path_traversal_[a-z_]+"\)',
            self.prisma))
        for camel in prisma_camels:
            self.assertIn(camel, self.ts_section,
                           f'PathTraversalSection.tsx does not bind {camel}')

    def test_prisma_map_names_match_python_screaming_snake(self):
        """The Prisma @map snake_case must round-trip to a Python key.
        e.g. @map("path_traversal_oob_provider") <-> PATH_TRAVERSAL_OOB_PROVIDER."""
        prisma_pairs = re.findall(
            r'pathTraversal[A-Za-z]+\s+\S+.*?@map\("(path_traversal_[a-z_]+)"\)',
            self.prisma)
        for snake in prisma_pairs:
            screaming = snake.upper()
            self.assertIn(screaming, self.py,
                           f'Prisma @map({snake!r}) has no Python key {screaming!r}')

    def test_ui_skill_order_matches_drawer_tooltip_order(self):
        """The order of built-in skills in the project-settings card and the
        drawer-tooltip API must match -- otherwise the operator sees one order
        in settings and a different one in the chat-drawer hover panel."""
        with open(os.path.join(
            self.REPO_ROOT,
            'webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx'
        )) as f:
            attack = f.read()
        with open(os.path.join(
            self.REPO_ROOT,
            'webapp/src/app/api/users/[id]/attack-skills/available/route.ts'
        )) as f:
            api = f.read()
        known = {'cve_exploit', 'sql_injection', 'xss', 'ssrf', 'rce',
                 'path_traversal', 'brute_force_credential_guess',
                 'phishing_social_engineering', 'denial_of_service'}
        attack_order = [i for i in re.findall(r"id:\s*'([a-z_]+)'", attack) if i in known]
        api_order = [i for i in re.findall(r"id:\s*'([a-z_]+)'", api) if i in known]
        self.assertEqual(attack_order, api_order,
                          'AttackSkillsSection and route.ts disagree on skill order')


# ===========================================================================
# 12. Classifier-overlap regression -- the new section must not corrupt the
#      classification prompt for other built-in skills
# ===========================================================================

class TestClassifierOverlapRegression(unittest.TestCase):
    """When all skills are enabled, the path_traversal section must coexist
    with every other built-in: no duplicate sections, no missing sections,
    no instruction-block collisions."""

    def _build_full(self):
        all_skills = {'cve_exploit', 'brute_force_credential_guess',
                      'phishing_social_engineering', 'denial_of_service',
                      'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal'}
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value=all_skills), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            return all_skills, build_classification_prompt(
                'Test for LFI on the download endpoint')

    def test_all_nine_skills_present_exactly_once(self):
        all_skills, prompt = self._build_full()
        # Section headers end either with em dash or newline after the id
        headers = re.findall(r'^### ([a-z_]+)(?=[\s\u2014\n])', prompt, re.M)
        counts = {s: headers.count(s) for s in set(headers) if s in all_skills}
        self.assertEqual(set(counts.keys()), all_skills,
                          f'missing sections: {all_skills - set(counts.keys())}')
        for s, c in counts.items():
            self.assertEqual(c, 1, f'{s} appears {c} times (expected 1)')

    def test_all_nine_skills_have_instruction_blocks(self):
        all_skills, prompt = self._build_full()
        for skill in all_skills:
            self.assertIn(f'**{skill}**', prompt,
                           f'missing instruction block for {skill}')

    def test_path_traversal_keyword_density(self):
        """High keyword density on the new skill is what keeps classifier
        accuracy up vs the unclassified fallback. Drop below 10 and the LLM
        will start dumping ambiguous LFI requests into -unclassified."""
        all_skills, prompt = self._build_full()
        section_idx = prompt.find('### path_traversal')
        next_idx = prompt.find('###', section_idx + 5)
        section = prompt[section_idx:next_idx]
        kw_line = next(
            (l for l in section.split('\n') if l.lower().startswith('- keywords:')),
            '')
        keywords = [k.strip() for k in kw_line.split(':', 1)[-1].split(',') if k.strip()]
        self.assertGreaterEqual(len(keywords), 10,
                                 f'too few keywords on path_traversal: {len(keywords)}')

    def test_unclassified_fallback_redirects_to_path_traversal(self):
        """Before this skill landed, LFI/RFI/path-traversal queries fell into
        -unclassified. The unclassified section MUST now redirect those
        queries to path_traversal so the classifier sees the boundary."""
        from prompts.classification import _UNCLASSIFIED_SECTION
        self.assertIn('path_traversal', _UNCLASSIFIED_SECTION)
        self.assertIn('path traversal', _UNCLASSIFIED_SECTION.lower())


# ===========================================================================
# 13. Settings permutation matrix -- 16 boolean combos all render cleanly
# ===========================================================================

class TestSettingsPermutationMatrix(unittest.TestCase):
    """Render PATH_TRAVERSAL_TOOLS under every combination of the 4 booleans
    plus boundary numeric/string values. A leaked {placeholder} on any
    permutation would crash the agent at prompt-render time."""

    def _format(self, **overrides):
        defaults = dict(
            path_traversal_oob_callback_enabled=True,
            path_traversal_php_wrappers_enabled=True,
            path_traversal_archive_extraction_enabled=False,
            path_traversal_payload_reference_enabled=True,
            path_traversal_request_timeout=10,
            path_traversal_oob_provider='oast.fun',
        )
        defaults.update(overrides)
        return PATH_TRAVERSAL_TOOLS.format(**defaults)

    def test_sixteen_boolean_permutations_all_render(self):
        """4 booleans => 2^4 = 16 permutations. None should leak placeholders."""
        import itertools
        for a, b, c, d in itertools.product([True, False], repeat=4):
            out = self._format(
                path_traversal_oob_callback_enabled=a,
                path_traversal_php_wrappers_enabled=b,
                path_traversal_archive_extraction_enabled=c,
                path_traversal_payload_reference_enabled=d,
            )
            stray = [s for s in re.findall(r'\{[a-z_][a-z0-9_]*\}', out)
                     if s != '{time_total}']
            self.assertEqual(stray, [],
                              f'permutation a={a} b={b} c={c} d={d}: stray={stray}')
            self.assertIn('ATTACK SKILL: PATH TRAVERSAL', out)

    def test_extreme_timeout_values(self):
        for t in (1, 5, 30, 60, 999):
            out = self._format(path_traversal_request_timeout=t)
            self.assertIn(f'--max-time {t}', out)
            # Pre-rendered settings block reflects the new value
            self.assertIn(f'{t}s', out)

    def test_unusual_oob_provider_strings(self):
        """OOB provider is operator-set free text. Unusual values should not
        crash render; the agent will simply use whatever string."""
        for provider in ('oast.fun', 'a.b.c.example.com',
                          'self-hosted-oast.lab.internal',
                          'oast-fun-host', '127.0.0.1:8443'):
            out = self._format(path_traversal_oob_provider=provider)
            self.assertIn(provider, out)


# ===========================================================================
# 14. Tool-reference safety -- every tool the prompt instructs the agent to
#      call must exist in TOOL_REGISTRY (otherwise the agent emits unknown
#      tool_name and the orchestrator drops the call)
# ===========================================================================

class TestToolReferenceSafety(unittest.TestCase):
    """Hunt for prompt drift: a payload reference or a copy-paste from another
    skill could introduce a `tool_name(...)` reference for a tool that doesn't
    exist in TOOL_REGISTRY. This test catches that at CI time."""

    def test_every_referenced_tool_is_registered(self):
        from prompts.tool_registry import TOOL_REGISTRY
        all_text = ''.join([
            PATH_TRAVERSAL_TOOLS.format(
                path_traversal_oob_callback_enabled=True,
                path_traversal_php_wrappers_enabled=True,
                path_traversal_archive_extraction_enabled=True,
                path_traversal_payload_reference_enabled=True,
                path_traversal_request_timeout=10,
                path_traversal_oob_provider='oast.fun',
            ),
            PATH_TRAVERSAL_PHP_WRAPPERS,
            PATH_TRAVERSAL_OOB_WORKFLOW,
            PATH_TRAVERSAL_ARCHIVE_EXTRACTION,
            PATH_TRAVERSAL_PAYLOAD_REFERENCE,
        ])
        # Match calls of the form 'tool_name({' or 'tool_name(' that look like
        # the canonical agent tool names
        called = set(re.findall(
            r'\b(execute_[a-z_]+|kali_shell|query_graph|metasploit_console|web_search|shodan|google_dork)\(',
            all_text))
        missing = called - set(TOOL_REGISTRY.keys())
        self.assertFalse(missing,
                          f'prompt references tools not in TOOL_REGISTRY: {missing}')

    def test_no_format_braces_leak_through_subsections(self):
        """Sub-sections are appended raw (no .format() call). Any literal
        {bareword} inside would reach the LLM as a leaked placeholder unless
        it's a known curl / template format string the agent must keep."""
        legit = {'time_total', 'http_code', 'cmd', 'c'}
        for name, body in (
            ('PHP_WRAPPERS', PATH_TRAVERSAL_PHP_WRAPPERS),
            ('OOB_WORKFLOW', PATH_TRAVERSAL_OOB_WORKFLOW),
            ('ARCHIVE_EXTRACTION', PATH_TRAVERSAL_ARCHIVE_EXTRACTION),
            ('PAYLOAD_REFERENCE', PATH_TRAVERSAL_PAYLOAD_REFERENCE),
        ):
            # Sub-sections must not have Python-format-escaped {{ }} either
            # (would leak as literal {{ to the LLM)
            self.assertNotIn('{{', body, f'{name}: has Python-escaped braces')
            self.assertNotIn('}}', body, f'{name}: has Python-escaped braces')
            suspicious = re.findall(r'\{([a-z_][a-z0-9_]*)\}', body)
            leaks = [s for s in suspicious if s not in legit]
            self.assertFalse(leaks,
                              f'{name}: suspicious {{placeholder}} tokens: {leaks}')


if __name__ == "__main__":
    unittest.main()
