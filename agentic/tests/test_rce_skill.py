"""
Tests for the RCE (Remote Code Execution) built-in attack skill.

Layers:
- Unit: prompt-template formatting, brace escaping, conditional swap blocks
- Integration: classification, _inject_builtin_skill_workflow plumbing,
  phase guard, settings-driven sub-section toggling
- Smoke: end-to-end get_phase_tools rendering for both phases
- Regression: existing skills (sqli, xss, ssrf, cve_exploit) still wire
  correctly after the rce additions; KNOWN_ATTACK_PATHS includes rce + ssrf;
  Prisma JSON default parses; tool_registry exposes ysoserial

Run with: python -m pytest tests/test_rce_skill.py -v
"""

import json
import os
import re
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Repo root is one level above _agentic_dir on the host, but the agent
# Docker image only contains /app/. Filesystem-level tests (Prisma schema,
# Kali Dockerfile, frontend TSX) skip when paths are not reachable from
# the current working directory -- they only make sense from the host.
_repo_root = os.path.abspath(os.path.join(_agentic_dir, ".."))
_HAS_WEBAPP = os.path.isdir(os.path.join(_repo_root, "webapp"))
_HAS_MCP = os.path.isdir(os.path.join(_repo_root, "mcp"))
_skip_no_webapp = unittest.skipUnless(_HAS_WEBAPP, "webapp/ not present (running in agent container)")
_skip_no_mcp = unittest.skipUnless(_HAS_MCP, "mcp/ not present (running in agent container)")

# Stub out heavy dependencies not available outside Docker
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

from state import KNOWN_ATTACK_PATHS, is_unclassified_path, AttackPathClassification
from project_settings import DEFAULT_AGENT_SETTINGS
from prompts.rce_prompts import (
    RCE_TOOLS,
    RCE_AGGRESSIVE_DISABLED,
    RCE_AGGRESSIVE_ENABLED,
    RCE_OOB_WORKFLOW,
    RCE_DESERIALIZATION_WORKFLOW,
    RCE_PAYLOAD_REFERENCE,
)
from prompts.classification import (
    _RCE_SECTION, _BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
    build_classification_prompt,
)


# =============================================================================
# Helpers
# =============================================================================

def _format_rce_tools(**overrides):
    """Format RCE_TOOLS with sane defaults; allow per-test overrides."""
    defaults = dict(
        rce_oob_callback_enabled=True,
        rce_deserialization_enabled=True,
        rce_aggressive_payloads=False,
        rce_aggressive_block=RCE_AGGRESSIVE_DISABLED,
    )
    defaults.update(overrides)
    return RCE_TOOLS.format(**defaults)


def _call_get_phase_tools(attack_path_type, enabled_skills, *,
                           phase="exploitation",
                           allowed_tools=None,
                           rce_oob=True,
                           rce_deser=True,
                           rce_aggressive=False):
    """Invoke get_phase_tools with mocked settings + skill enablement.

    Returns the rendered prompt string the agent would see.
    """
    if allowed_tools is None:
        allowed_tools = ['kali_shell', 'execute_curl', 'execute_code',
                         'execute_playwright', 'query_graph', 'execute_nuclei',
                         'metasploit_console']

    with patch('prompts.get_setting') as mock_setting, \
         patch('prompts.get_allowed_tools_for_phase', return_value=allowed_tools), \
         patch('project_settings.get_enabled_builtin_skills', return_value=enabled_skills), \
         patch('prompts.build_kali_install_prompt', return_value=""), \
         patch('prompts.build_tool_availability_table', return_value="## Tools\n"), \
         patch('prompts.get_hydra_flags_from_settings', return_value="-t 16 -f"), \
         patch('prompts.get_dos_settings_dict', return_value={}), \
         patch('prompts.get_session_config_prompt', return_value=""), \
         patch('prompts.build_informational_tool_descriptions', return_value="info tools"):

        def setting_side_effect(key, default=None):
            settings = {
                'STEALTH_MODE': False,
                'INFORMATIONAL_SYSTEM_PROMPT': '',
                'EXPL_SYSTEM_PROMPT': '',
                'POST_EXPL_SYSTEM_PROMPT': '',
                'RCE_OOB_CALLBACK_ENABLED': rce_oob,
                'RCE_DESERIALIZATION_ENABLED': rce_deser,
                'RCE_AGGRESSIVE_PAYLOADS': rce_aggressive,
                'XSS_DALFOX_ENABLED': True,
                'XSS_BLIND_CALLBACK_ENABLED': False,
                'XSS_CSP_BYPASS_ENABLED': True,
                'SQLI_LEVEL': 1,
                'SQLI_RISK': 1,
                'SQLI_TAMPER_SCRIPTS': '',
                'ROE_ENABLED': False,
                'HYDRA_MAX_WORDLIST_ATTEMPTS': 3,
                'DOS_ASSESSMENT_ONLY': False,
                'PHISHING_SMTP_CONFIG': '',
                'ACTIVATE_POST_EXPL_PHASE': True,
                # SSRF settings (used by _inject_builtin_skill_workflow when ssrf is the active path)
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
            return settings.get(key, default)

        mock_setting.side_effect = setting_side_effect

        from prompts import get_phase_tools
        return get_phase_tools(
            phase=phase,
            activate_post_expl=True,
            post_expl_type="stateless",
            attack_path_type=attack_path_type,
            execution_trace=[],
        )


# =============================================================================
# 1. UNIT — RCE_TOOLS template formatting
# =============================================================================

class TestRceToolsFormatting(unittest.TestCase):
    """RCE_TOOLS is a .format() template with 4 placeholders. Verify it
    renders cleanly with valid inputs and rejects missing placeholders."""

    def test_format_with_defaults_renders(self):
        out = _format_rce_tools()
        self.assertIn("ATTACK SKILL: REMOTE CODE EXECUTION", out)
        self.assertIn("OOB blind-RCE callbacks (interactsh):    True", out)
        self.assertIn("Deserialization gadgets (ysoserial):     True", out)
        self.assertIn("Aggressive payloads (file write / shell):False", out)

    def test_format_no_unprocessed_placeholders(self):
        """No leftover {rce_*} placeholders after format."""
        out = _format_rce_tools()
        self.assertEqual(re.findall(r'\{rce_[a-z_]+\}', out), [])

    def test_format_no_placeholder_artifacts(self):
        """After format(), no `{rce_*}` placeholder remnants should remain.
        Note: literal `{{ }}` in the rendered output is FINE -- those are Jinja2
        / Twig SSTI payload examples (e.g. `{{7*7}}`). We only ban placeholder-
        shaped survivors that would mean .format() didn't substitute them."""
        out = _format_rce_tools()
        leftover = re.findall(r'\{rce_[a-z_]+\}', out)
        self.assertEqual(leftover, [],
                         f"Unprocessed format placeholders survived: {leftover}")

    def test_format_missing_placeholder_raises(self):
        """Calling .format() without all required keys must KeyError."""
        with self.assertRaises(KeyError):
            RCE_TOOLS.format(rce_oob_callback_enabled=True)

    def test_format_aggressive_disabled_value(self):
        out = _format_rce_tools(
            rce_aggressive_payloads=False,
            rce_aggressive_block=RCE_AGGRESSIVE_DISABLED,
        )
        self.assertIn("**DISABLED** by project setting", out)
        self.assertNotIn("**ENABLED** by project setting", out)

    def test_format_aggressive_enabled_value(self):
        out = _format_rce_tools(
            rce_aggressive_payloads=True,
            rce_aggressive_block=RCE_AGGRESSIVE_ENABLED,
        )
        self.assertIn("**ENABLED** by project setting", out)
        self.assertIn("Critical-impact proofs (Level 4)", out)

    def test_setting_values_are_visible_to_agent(self):
        """When OOB / Deser / aggressive flip, the rendered settings block
        reflects the change (so the LLM sees the right state)."""
        out = _format_rce_tools(
            rce_oob_callback_enabled=False,
            rce_deserialization_enabled=False,
            rce_aggressive_payloads=True,
            rce_aggressive_block=RCE_AGGRESSIVE_ENABLED,
        )
        self.assertIn("OOB blind-RCE callbacks (interactsh):    False", out)
        self.assertIn("Deserialization gadgets (ysoserial):     False", out)
        self.assertIn("Aggressive payloads (file write / shell):True", out)


# =============================================================================
# 2. UNIT — RCE_TOOLS content (steps, primitives, oracles, proof framework)
# =============================================================================

class TestRceToolsContent(unittest.TestCase):
    """The prompt must cover the six RCE primitives, oracles, OWASP stages,
    proof levels, and the false-positive gate. Each is a load-bearing
    contract Strix+Shannon were chosen for."""

    def setUp(self):
        self.out = _format_rce_tools()

    def test_six_primitives_listed(self):
        for primitive in ["command injection", "Server-side template injection",
                          "deserialization", "expression languages",
                          "Media + document pipelines", "SSRF-to-RCE"]:
            self.assertIn(primitive.lower(), self.out.lower(),
                          f"missing primitive: {primitive}")

    def test_all_steps_present(self):
        for step in ["Step 1: Reuse recon", "Step 2: Surface candidate sinks",
                     "Step 3: Establish a quiet oracle",
                     "Step 4: Confirm exactly ONE primitive",
                     "Step 5: Fingerprint the execution context",
                     "Step 6: Demonstrate impact",
                     "Step 7: Critical impact",
                     "Step 8: Long-running exploitation",
                     "Step 9: Reporting requirements"]:
            self.assertIn(step, self.out)

    def test_oracle_options_documented(self):
        """Three oracle options (timing, OOB, output-based) all documented."""
        self.assertIn("Time-based gate", self.out)
        self.assertIn("OOB DNS oracle", self.out)
        self.assertIn("Output-based", self.out)

    def test_step4_subsections_for_each_primitive(self):
        for sub in ["4A. Command injection", "4B. SSTI",
                    "4C. Insecure deserialization",
                    "4D. Eval / expression",
                    "4E. Media-pipeline RCE",
                    "4F. SSRF to RCE"]:
            self.assertIn(sub, self.out)

    def test_proof_levels_table(self):
        for level in ["Level 1", "Level 2", "Level 3", "Level 4"]:
            self.assertIn(level, self.out)
        # Specific Shannon-derived classifications
        self.assertIn("EXPLOITED (CRITICAL)", self.out)
        self.assertIn("FALSE POSITIVE", self.out)

    def test_false_positive_gate_present(self):
        self.assertIn("False positive gate", self.out)
        self.assertIn(">= 800ms", self.out)

    def test_transition_phase_instruction(self):
        """Step 1 must instruct the agent to transition to exploitation."""
        self.assertIn("transition_phase", self.out)

    def test_owasp_stage_mapping(self):
        """Step labels must align with the 4 OWASP exploitation stages."""
        self.assertIn("OWASP Stage 1: Confirmation", self.out)
        self.assertIn("OWASP Stage 2", self.out)
        self.assertIn("OWASP Stage 3", self.out)
        self.assertIn("OWASP Stage 4", self.out)

    def test_no_white_box_methodology_leaks(self):
        """Memory / project rule: white-box (source code analysis, deliverable
        files, save-deliverable CLI, Task Agent for code review) must NOT
        appear because RedAmon agents have no source-code access."""
        # Phrases that would indicate Shannon white-box bleed
        forbidden = [
            "save-deliverable",
            "Task Agent (Code Analysis)",
            "source code analysis",
            "white-box",
            ".shannon/deliverables/",
            "exploitation_queue.json",
            "TodoWrite tool",
        ]
        for needle in forbidden:
            self.assertNotIn(needle.lower(), self.out.lower(),
                             f"white-box bleed detected: {needle}")

    def test_no_em_dashes(self):
        """User feedback: no em dashes (—) in prompts; use hyphens."""
        self.assertNotIn("\u2014", self.out)

    def test_aggressive_disabled_block_exists_when_off(self):
        """Default: RCE_AGGRESSIVE_PAYLOADS=False -> DISABLED block in output."""
        # Already covered above but explicit semantic expectation here:
        self.assertIn("Stop at Step 6 (read-only proofs)", self.out)
        self.assertNotIn("Reverse shell (only if explicitly requested", self.out)


# =============================================================================
# 3. UNIT — Sub-prompts (OOB / Deserialization / Payload ref) brace correctness
# =============================================================================

class TestSubPromptsBraceCorrectness(unittest.TestCase):
    """The 3 appended-raw constants must use SINGLE braces for tool-call JSON
    (they are not .format()'d). SSTI payloads inside them legitimately use
    literal `{{ }}` (Jinja2/Twig syntax) -- those are fine.

    The bug we're guarding against: writing `kali_shell({{"command": ...}})`
    in a non-format constant would surface to the LLM as that exact string
    with double braces. The check: tool calls must be single-brace, AND no
    placeholder-shaped `{rce_*}` patterns must survive."""

    NON_FORMAT_CONSTANTS = [
        ("RCE_OOB_WORKFLOW", RCE_OOB_WORKFLOW),
        ("RCE_DESERIALIZATION_WORKFLOW", RCE_DESERIALIZATION_WORKFLOW),
        ("RCE_PAYLOAD_REFERENCE", RCE_PAYLOAD_REFERENCE),
        ("RCE_AGGRESSIVE_DISABLED", RCE_AGGRESSIVE_DISABLED),
        ("RCE_AGGRESSIVE_ENABLED", RCE_AGGRESSIVE_ENABLED),
    ]

    def test_no_unsubstituted_rce_placeholders(self):
        """No constant should contain `{rce_<name>}` -- those are format-
        template placeholders that only RCE_TOOLS resolves. Their presence
        in an appended-raw constant means it was incorrectly written as a
        format string."""
        for name, content in self.NON_FORMAT_CONSTANTS:
            leftover = re.findall(r'\{rce_[a-z_]+\}', content)
            self.assertEqual(leftover, [],
                             f"{name} contains unprocessable format placeholders: {leftover}")

    def test_tool_calls_use_single_brace_json(self):
        """`kali_shell({"command": ...})` (single brace) must appear in OOB +
        Deser sections; `kali_shell({{"command":` (double brace) is the bug."""
        self.assertIn('kali_shell({"command":', RCE_OOB_WORKFLOW)
        self.assertNotIn('kali_shell({{"command":', RCE_OOB_WORKFLOW)
        self.assertIn('kali_shell({"command":', RCE_DESERIALIZATION_WORKFLOW)
        self.assertNotIn('kali_shell({{"command":', RCE_DESERIALIZATION_WORKFLOW)
        self.assertIn('execute_nuclei({"args":', RCE_PAYLOAD_REFERENCE)
        self.assertNotIn('execute_nuclei({{"args":', RCE_PAYLOAD_REFERENCE)

    def test_payload_reference_has_legit_single_brace_literals(self):
        """Sanity: single-brace shell expressions like `{IFS}` and
        `{cat,/etc/passwd}` are documented payloads -- their absence would
        suggest the file was over-escaped."""
        self.assertIn("{IFS}", RCE_PAYLOAD_REFERENCE)
        self.assertIn("{cat,/etc/passwd}", RCE_PAYLOAD_REFERENCE)

    def test_oob_jinja2_payload_renders_correctly(self):
        """Legitimate Jinja2 SSTI example must use literal `{{...}}`."""
        self.assertIn(
            "{{config.update(__import__('os').popen",
            RCE_OOB_WORKFLOW,
        )


class TestSubPromptsContent(unittest.TestCase):
    """Sub-prompt content sanity (each section covers what its name claims)."""

    def test_oob_workflow_lifecycle(self):
        for section in ["interactsh-client", "REGISTERED_DOMAIN",
                        ".oast.fun", "kill SAVED_PID"]:
            self.assertIn(section, RCE_OOB_WORKFLOW)

    def test_oob_warns_random_subdomains_dont_route(self):
        """The OOB workflow must warn that a random domain won't work."""
        self.assertIn("cryptographically tied", RCE_OOB_WORKFLOW)
        self.assertIn("will NOT route back", RCE_OOB_WORKFLOW)

    def test_deser_covers_five_languages(self):
        for lang in ["Java", "PHP", "Python", "Ruby", ".NET"]:
            self.assertIn(lang, RCE_DESERIALIZATION_WORKFLOW)

    def test_deser_lists_ysoserial_chains(self):
        for chain in ["URLDNS", "CommonsCollections6", "Spring1"]:
            self.assertIn(chain, RCE_DESERIALIZATION_WORKFLOW)

    def test_deser_magic_byte_table(self):
        """Format-detection table is the practical entry point for black-box
        deser testing — must be present."""
        for marker in ["aced 0005", "Java serialized", "PHP serialized",
                       "Python pickle", "Ruby Marshal"]:
            self.assertIn(marker, RCE_DESERIALIZATION_WORKFLOW)

    def test_payload_reference_has_unix_separators(self):
        for sep in [";id", "|id", "&&id", "||id", "$(id)"]:
            self.assertIn(sep, RCE_PAYLOAD_REFERENCE)

    def test_payload_reference_ssti_engines(self):
        for engine in ["Jinja2", "Twig", "Freemarker", "Velocity", "EJS",
                       "Handlebars", "Thymeleaf", "Pug", "ERB"]:
            self.assertIn(engine, RCE_PAYLOAD_REFERENCE)

    def test_payload_reference_log4shell_pattern(self):
        self.assertIn("CVE-2021-44228", RCE_PAYLOAD_REFERENCE)
        self.assertIn("${jndi:ldap://", RCE_PAYLOAD_REFERENCE)

    def test_payload_reference_container_pivots(self):
        self.assertIn("/.dockerenv", RCE_PAYLOAD_REFERENCE)
        self.assertIn("/var/run/secrets/kubernetes.io/serviceaccount/token",
                      RCE_PAYLOAD_REFERENCE)

    def test_aggressive_enabled_has_cleanup_obligation(self):
        """The aggressive block must REQUIRE cleanup (no leftover artifacts)."""
        self.assertIn("Cleanup obligation (MANDATORY)", RCE_AGGRESSIVE_ENABLED)


# =============================================================================
# 4. UNIT — Classification: section, map, instructions, keyword disjointness
# =============================================================================

class TestRceClassificationRegistration(unittest.TestCase):
    def test_rce_section_defined(self):
        self.assertIn("rce", _RCE_SECTION)
        self.assertIn("Remote Code Execution", _RCE_SECTION)

    def test_rce_in_builtin_skill_map(self):
        self.assertIn("rce", _BUILTIN_SKILL_MAP)
        section, _, skill_id = _BUILTIN_SKILL_MAP["rce"]
        self.assertEqual(skill_id, "rce")
        self.assertEqual(section, _RCE_SECTION)

    def test_rce_in_classification_instructions(self):
        self.assertIn("rce", _CLASSIFICATION_INSTRUCTIONS)
        instruction = _CLASSIFICATION_INSTRUCTIONS["rce"]
        self.assertIn("RCE", instruction)
        self.assertIn("command injection", instruction.lower())
        self.assertIn("ssti", instruction.lower())
        self.assertIn("deserialization", instruction.lower())

    def test_rce_keywords_distinguish_from_neighboring_skills(self):
        """The RCE classification must explicitly distinguish itself from xss,
        sql_injection, ssrf, and cve_exploit so the classifier doesn't drift."""
        section = _RCE_SECTION.lower()
        # Boundaries
        self.assertIn("vs xss", section)
        self.assertIn("vs sql_injection", section)
        self.assertIn("vs ssrf", section)
        self.assertIn("vs cve_exploit", section)


# =============================================================================
# 5. UNIT — state.py: AttackPathClassification accepts rce
# =============================================================================

class TestStateRegistration(unittest.TestCase):
    """KNOWN_ATTACK_PATHS / Pydantic validator must accept 'rce' (and 'ssrf')
    or the LLM's classification will crash with ValidationError."""

    def test_rce_in_known_paths(self):
        self.assertIn("rce", KNOWN_ATTACK_PATHS)

    def test_ssrf_in_known_paths(self):
        """Regression: ssrf was wired as a built-in but missing from
        KNOWN_ATTACK_PATHS — the classifier output crashed. Pin it here."""
        self.assertIn("ssrf", KNOWN_ATTACK_PATHS)

    def test_rce_is_not_unclassified(self):
        self.assertFalse(is_unclassified_path("rce"))

    def test_pydantic_accepts_rce(self):
        apc = AttackPathClassification(
            attack_path_type="rce",
            required_phase="exploitation",
            confidence=0.9,
            reasoning="command injection request",
        )
        self.assertEqual(apc.attack_path_type, "rce")

    def test_pydantic_rejects_unknown_path(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            AttackPathClassification(
                attack_path_type="not_a_real_skill",
                required_phase="exploitation",
                confidence=0.5,
                reasoning="bogus",
            )

    def test_pydantic_still_accepts_unclassified(self):
        apc = AttackPathClassification(
            attack_path_type="xxe-unclassified",
            required_phase="exploitation",
            confidence=0.5,
            reasoning="XXE",
        )
        self.assertEqual(apc.attack_path_type, "xxe-unclassified")


# =============================================================================
# 6. UNIT — DEFAULT_AGENT_SETTINGS
# =============================================================================

class TestDefaultSettings(unittest.TestCase):
    def test_rce_in_attack_skill_config(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertIn('rce', config['builtIn'])

    def test_rce_enabled_by_default(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertTrue(config['builtIn']['rce'])

    def test_rce_oob_enabled_default(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['RCE_OOB_CALLBACK_ENABLED'])

    def test_rce_deser_enabled_default(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['RCE_DESERIALIZATION_ENABLED'])

    def test_rce_aggressive_disabled_by_default(self):
        """Hard rule: aggressive payloads are off by default. Read-only proofs
        already satisfy a Level 3 finding."""
        self.assertFalse(DEFAULT_AGENT_SETTINGS['RCE_AGGRESSIVE_PAYLOADS'])


# =============================================================================
# 7. INTEGRATION — build_classification_prompt
# =============================================================================

class TestBuildClassificationPrompt(unittest.TestCase):
    """Verify the dynamic classifier prompt picks up rce when enabled and
    omits it when disabled."""

    def _build(self, enabled):
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value=enabled), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            return build_classification_prompt("Test for command injection on /api/ping")

    def test_rce_section_included_when_enabled(self):
        prompt = self._build({'rce', 'cve_exploit'})
        self.assertIn("### rce", prompt)
        self.assertIn("Remote Code Execution", prompt)

    def test_rce_excluded_when_disabled(self):
        prompt = self._build({'cve_exploit'})
        self.assertNotIn("### rce", prompt)

    def test_rce_in_valid_types_when_enabled(self):
        prompt = self._build({'rce', 'cve_exploit'})
        self.assertIn('"rce"', prompt)

    def test_rce_classification_instruction_emitted(self):
        prompt = self._build({'rce'})
        # The instructions block has bullets specific to RCE primitives.
        self.assertIn("Does it mention server-side template injection", prompt)

    def test_rce_unclassified_examples_no_longer_listed(self):
        """When rce is enabled, command_injection / deserialization should NOT
        appear in the unclassified example list — they should route to rce."""
        prompt = self._build({'rce', 'cve_exploit'})
        self.assertNotIn("command_injection-unclassified", prompt)
        self.assertNotIn("deserialization-unclassified", prompt)


# =============================================================================
# 8. INTEGRATION — get_phase_tools branch + phase guard + sub-section toggles
# =============================================================================

class TestGetPhaseToolsRceBranch(unittest.TestCase):

    def test_rce_skill_injects_workflow(self):
        out = _call_get_phase_tools("rce", {"rce", "cve_exploit"})
        self.assertIn("ATTACK SKILL: REMOTE CODE EXECUTION", out)

    def test_rce_skill_injects_payload_reference(self):
        out = _call_get_phase_tools("rce", {"rce"})
        self.assertIn("## RCE Payload Reference", out)

    def test_rce_oob_only_when_setting_on(self):
        on = _call_get_phase_tools("rce", {"rce"}, rce_oob=True)
        self.assertIn("## OOB / Blind RCE Workflow (interactsh DNS+HTTP callbacks)", on)

        off = _call_get_phase_tools("rce", {"rce"}, rce_oob=False)
        self.assertNotIn("## OOB / Blind RCE Workflow (interactsh DNS+HTTP callbacks)", off)

    def test_rce_deser_only_when_setting_on(self):
        on = _call_get_phase_tools("rce", {"rce"}, rce_deser=True)
        self.assertIn("## Deserialization Workflow", on)

        off = _call_get_phase_tools("rce", {"rce"}, rce_deser=False)
        self.assertNotIn("## Deserialization Workflow", off)

    def test_rce_aggressive_block_swaps_with_setting(self):
        off = _call_get_phase_tools("rce", {"rce"}, rce_aggressive=False)
        self.assertIn("**DISABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=False`", off)
        self.assertNotIn("**ENABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=True`", off)

        on = _call_get_phase_tools("rce", {"rce"}, rce_aggressive=True)
        self.assertIn("**ENABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=True`", on)
        self.assertNotIn("**DISABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=False`", on)

    def test_phase_guard_blocks_when_kali_shell_missing(self):
        """No kali_shell in allowed_tools -> rce branch must NOT activate.
        The agent should see the unclassified fallback instead."""
        out = _call_get_phase_tools(
            "rce", {"rce"},
            allowed_tools=['execute_curl', 'execute_code'],
        )
        self.assertNotIn("ATTACK SKILL: REMOTE CODE EXECUTION", out)

    def test_skill_disabled_falls_through_to_unclassified(self):
        """rce path classified but rce skill disabled -> falls through.
        Since 'rce' is not -unclassified suffixed, it falls to
        build_informational_tool_descriptions as documented."""
        out = _call_get_phase_tools("rce", {"cve_exploit"})  # rce NOT enabled
        self.assertNotIn("ATTACK SKILL: REMOTE CODE EXECUTION", out)

    def test_other_path_does_not_trigger_rce_workflow(self):
        out = _call_get_phase_tools("cve_exploit", {"rce", "cve_exploit"})
        self.assertNotIn("ATTACK SKILL: REMOTE CODE EXECUTION", out)

    def test_informational_phase_also_injects_workflow(self):
        """get_phase_tools injects the skill workflow in the informational
        phase too — the workflow itself contains the recon Step 1."""
        out = _call_get_phase_tools(
            "rce", {"rce"}, phase="informational",
        )
        self.assertIn("ATTACK SKILL: REMOTE CODE EXECUTION", out)
        self.assertIn("Step 1: Reuse recon", out)


# =============================================================================
# 9. SMOKE — Full prompts package import + clean rendering
# =============================================================================

class TestSmokeImports(unittest.TestCase):
    def test_prompts_package_imports(self):
        import prompts as pkg
        # All RCE constants exposed via the package
        self.assertTrue(hasattr(pkg, 'RCE_TOOLS'))
        self.assertTrue(hasattr(pkg, 'RCE_OOB_WORKFLOW'))
        self.assertTrue(hasattr(pkg, 'RCE_DESERIALIZATION_WORKFLOW'))
        self.assertTrue(hasattr(pkg, 'RCE_PAYLOAD_REFERENCE'))
        self.assertTrue(hasattr(pkg, 'RCE_AGGRESSIVE_DISABLED'))
        self.assertTrue(hasattr(pkg, 'RCE_AGGRESSIVE_ENABLED'))

    def test_rce_constants_in_all(self):
        import prompts as pkg
        for name in ['RCE_TOOLS', 'RCE_OOB_WORKFLOW',
                     'RCE_DESERIALIZATION_WORKFLOW', 'RCE_PAYLOAD_REFERENCE']:
            self.assertIn(name, pkg.__all__, f"{name} missing from __all__")


# =============================================================================
# 10. REGRESSION — existing skills still work
# =============================================================================

class TestRegressionExistingSkills(unittest.TestCase):
    """Adding rce must not break sqli, xss, ssrf, cve_exploit."""

    def test_sqli_still_injects(self):
        out = _call_get_phase_tools("sql_injection", {"sql_injection"})
        self.assertIn("ATTACK SKILL: SQL INJECTION", out)

    def test_xss_still_injects(self):
        out = _call_get_phase_tools("xss", {"xss"})
        self.assertIn("ATTACK SKILL: CROSS-SITE SCRIPTING", out)

    def test_ssrf_still_injects(self):
        out = _call_get_phase_tools("ssrf", {"ssrf"})
        # SSRF skill heading
        self.assertIn("SERVER-SIDE REQUEST FORGERY", out.upper())

    def test_cve_exploit_still_injects(self):
        out = _call_get_phase_tools("cve_exploit", {"cve_exploit"})
        # CVE exploit prompt is the catch-all branch
        self.assertTrue(
            "CVE" in out or "Metasploit" in out or "metasploit" in out,
            "cve_exploit branch did not produce its prompt"
        )

    def test_classification_prompt_includes_all_six_when_all_enabled(self):
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'cve_exploit', 'sql_injection', 'xss', 'ssrf',
                                 'rce', 'brute_force_credential_guess',
                                 'phishing_social_engineering',
                                 'denial_of_service'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("test")
            for skill in ['cve_exploit', 'sql_injection', 'xss', 'ssrf', 'rce',
                          'brute_force_credential_guess',
                          'phishing_social_engineering', 'denial_of_service']:
                self.assertIn(f"### {skill}", prompt, f"{skill} missing from prompt")


# =============================================================================
# 11. REGRESSION — Prisma JSON default parses + key set is consistent
# =============================================================================

@_skip_no_webapp
class TestPrismaSchemaDefault(unittest.TestCase):
    """The Prisma schema's attackSkillConfig JSON default must parse and
    contain rce alongside the existing skills. Drift here means new projects
    won't get rce enabled."""

    def setUp(self):
        path = os.path.join(_agentic_dir, "..", "webapp", "prisma", "schema.prisma")
        path = os.path.abspath(path)
        with open(path) as f:
            self.schema = f.read()

    def test_attack_skill_config_default_parses(self):
        # Match the @default("...") capture, accounting for `\"` escape sequences
        match = re.search(
            r'attackSkillConfig\s+Json\s+@default\("((?:\\"|[^"])+)"\)',
            self.schema,
        )
        self.assertIsNotNone(match, "Could not locate attackSkillConfig default")
        # Prisma escapes inner quotes as \" -- unescape and parse
        raw = match.group(1).replace('\\"', '"')
        parsed = json.loads(raw)
        self.assertIn("builtIn", parsed)
        self.assertIn("user", parsed)
        self.assertIn("rce", parsed["builtIn"])
        self.assertTrue(parsed["builtIn"]["rce"])
        # Pre-existing keys still present
        for skill in ["cve_exploit", "sql_injection", "xss", "ssrf"]:
            self.assertIn(skill, parsed["builtIn"], f"{skill} missing from default")

    def test_rce_columns_present(self):
        for col in ["rceOobCallbackEnabled", "rceDeserializationEnabled",
                    "rceAggressivePayloads"]:
            self.assertIn(col, self.schema, f"{col} column missing from schema")


# =============================================================================
# 12. REGRESSION — tool_registry exposes ysoserial
# =============================================================================

class TestToolRegistryRce(unittest.TestCase):
    def test_ysoserial_in_kali_shell_description(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("ysoserial", kali_desc)
        # Chain names referenced in the deser workflow must also appear here
        self.assertIn("CommonsCollections", kali_desc)
        self.assertIn("URLDNS", kali_desc)

    def test_commix_still_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("commix", kali_desc)

    def test_sstimap_still_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("sstimap", kali_desc)


# =============================================================================
# 13. REGRESSION — Kali Dockerfile installs Java + ysoserial.jar
# =============================================================================

@_skip_no_mcp
class TestKaliDockerfile(unittest.TestCase):
    """The RCE prompt assumes ysoserial is in PATH. Pin the install commands
    so a future Dockerfile cleanup can't quietly drop them."""

    def setUp(self):
        path = os.path.join(_agentic_dir, "..", "mcp", "kali-sandbox", "Dockerfile")
        path = os.path.abspath(path)
        with open(path) as f:
            self.dockerfile = f.read()

    def test_jre_installed(self):
        self.assertIn("default-jre-headless", self.dockerfile)

    def test_ysoserial_jar_or_apt_install(self):
        """Either the apt package OR the upstream JAR download must be present.
        The wrapper script lands in /usr/local/bin/ysoserial in either case."""
        has_apt = re.search(r'^\s*ysoserial\s+\\', self.dockerfile, re.MULTILINE)
        has_jar = "ysoserial-all.jar" in self.dockerfile
        self.assertTrue(has_apt or has_jar,
                        "Neither apt ysoserial nor upstream jar present")

    def test_ysoserial_wrapper_or_path_resolved(self):
        """ysoserial must be invocable as a bare command. Either:
        - apt package installs `ysoserial` to /usr/bin (fine), OR
        - the upstream JAR install creates a wrapper at /usr/local/bin/ysoserial.
        """
        if "ysoserial-all.jar" in self.dockerfile:
            self.assertIn("/usr/local/bin/ysoserial", self.dockerfile,
                          "Upstream JAR install missing wrapper script")


# =============================================================================
# 14. REGRESSION — frontend artifacts are syntactically present
# =============================================================================

@_skip_no_webapp
class TestFrontendArtifacts(unittest.TestCase):
    """Lightweight sanity checks on TS files (no full TS compile here).
    These guard against accidental deletion / typo on the wiring."""

    def setUp(self):
        webapp = os.path.join(_agentic_dir, "..", "webapp", "src")
        self.attack_skills_section = os.path.abspath(os.path.join(
            webapp, "components/projects/ProjectForm/sections/AttackSkillsSection.tsx"
        ))
        self.rce_section = os.path.abspath(os.path.join(
            webapp, "components/projects/ProjectForm/sections/RceSection.tsx"
        ))
        self.phase_config = os.path.abspath(os.path.join(
            webapp, "app/graph/components/AIAssistantDrawer/phaseConfig.ts"
        ))

    def _read(self, path):
        with open(path) as f:
            return f.read()

    def test_rce_section_file_exists(self):
        self.assertTrue(os.path.exists(self.rce_section))
        content = self._read(self.rce_section)
        self.assertIn("export function RceSection", content)
        self.assertIn("rceOobCallbackEnabled", content)
        self.assertIn("rceDeserializationEnabled", content)
        self.assertIn("rceAggressivePayloads", content)

    def test_attack_skills_section_imports_rce(self):
        content = self._read(self.attack_skills_section)
        self.assertIn("import { RceSection }", content)
        # BUILT_IN_SKILLS array entry
        self.assertIn("id: 'rce'", content)
        # DEFAULT_CONFIG entry
        self.assertIn("rce: true", content)
        # Conditional render
        self.assertIn("skill.id === 'rce'", content)

    def test_phase_config_has_rce_badge(self):
        content = self._read(self.phase_config)
        self.assertIn("rce:", content)
        self.assertIn("'RCE'", content)


if __name__ == "__main__":
    unittest.main()
