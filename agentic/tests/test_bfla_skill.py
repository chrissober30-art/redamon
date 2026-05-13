"""
Tests for the BFLA (Broken Function-Level Authorization) Community Agent Skill.

The skill is a single .md file dropped into agentic/community-skills/. There is no
Python wiring, no Prisma schema, no per-project setting. The contract is therefore:

  Unit            -> markdown structure + content rules from the integration brief
  Integration     -> /community-skills catalog + /community-skills/<id> content endpoints
  Regression      -> the other community skills are still discoverable and parseable
  Classification  -> when imported as a UserAttackSkill and enabled, the classification
                     prompt builds correctly and the BFLA preview is rendered

Run with: python -m pytest tests/test_bfla_skill.py -v
"""

import json
import os
import re
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib import request as urlrequest


# ---------------------------------------------------------------------------
# Path bootstrap mirroring the existing skill-test files
# ---------------------------------------------------------------------------

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


SKILL_ID = "bfla_exploitation"
SKILL_PATH = _AGENTIC_DIR / "community-skills" / f"{SKILL_ID}.md"
COMMUNITY_DIR = _AGENTIC_DIR / "community-skills"

# Hard caps from the import surface
MAX_CONTENT_BYTES = 50 * 1024            # webapp/src/app/api/users/[id]/attack-skills/route.ts
MAX_DESCRIPTION_CHARS = 200              # agentic/api.py list_community_skills slice

# Real agent tool names per the integration brief
KNOWN_AGENT_TOOLS = {
    "query_graph", "kali_shell", "execute_curl", "execute_code",
    "execute_playwright", "execute_nuclei", "execute_hydra",
    "metasploit_console", "execute_ffuf", "execute_arjun",
    "execute_gau", "execute_httpx",
}


# Helper: read the file once, share across tests
def _read_skill() -> str:
    return SKILL_PATH.read_text(encoding="utf-8")


# ===========================================================================
# 1. UNIT - file presence and size
# ===========================================================================

class TestFilePresence(unittest.TestCase):
    def test_skill_file_exists(self):
        self.assertTrue(SKILL_PATH.exists(),
                        f"Expected community skill file at {SKILL_PATH}")
        self.assertTrue(SKILL_PATH.is_file())

    def test_skill_file_under_50kb_cap(self):
        size = SKILL_PATH.stat().st_size
        self.assertLess(size, MAX_CONTENT_BYTES,
                        f"File size {size} exceeds 50 KB import cap "
                        f"(POST /api/users/.../attack-skills validates this)")

    def test_skill_file_not_trivially_small(self):
        # Mirror the "200-800 lines" hint in PROMPT.ADD_COMMUNITY_AGENT_SKILL.md
        line_count = _read_skill().count("\n")
        self.assertGreater(line_count, 150,
                           f"Skill is only {line_count} lines, looks underbaked")
        self.assertLess(line_count, 1000,
                        f"Skill is {line_count} lines, way over the 200-800 target")


# ===========================================================================
# 2. UNIT - canonical markdown structure
# ===========================================================================

class TestCanonicalStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = _read_skill()

    def test_starts_with_h1(self):
        first_nonblank = next(line for line in self.content.splitlines() if line.strip())
        self.assertTrue(first_nonblank.startswith("# "),
                        f"First line should be H1 heading, got: {first_nonblank!r}")

    def test_overview_or_description_paragraph_present(self):
        # The classifier consumes either the explicit description or the first
        # 500 chars of content; either way we need a meaningful paragraph early
        body = self.content
        # First non-heading non-blank line
        for line in body.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                self.assertGreater(len(stripped), 60,
                                   f"Auto-description line is too short: {stripped!r}")
                return
        self.fail("No non-heading paragraph found before any heading")

    def test_when_to_classify_section_present(self):
        self.assertRegex(self.content, r"##\s+When to Classify Here",
                         "Required section 'When to Classify Here' missing")

    def test_phase_1_present(self):
        self.assertRegex(self.content, r"##\s+Phase\s*1",
                         "Phase 1 section missing")

    def test_phase_2_present(self):
        self.assertRegex(self.content, r"##\s+Phase\s*2",
                         "Phase 2 section missing")

    def test_phase_transition_cue_at_end_of_phase_1(self):
        # The agent reads this literal cue to decide on action="request_phase_transition"
        self.assertIn("request transition to exploitation phase", self.content,
                      "Required Phase 1 transition cue is missing")

    def test_reporting_section_present(self):
        self.assertRegex(self.content, r"##\s+Reporting",
                         "Reporting Guidelines section missing")

    def test_important_notes_present(self):
        self.assertRegex(self.content, r"##\s+Important Notes",
                         "Important Notes section missing")


# ===========================================================================
# 3. UNIT - content rules from the brief
# ===========================================================================

class TestContentRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = _read_skill()

    def test_no_em_dashes(self):
        em_dashes = [(i, line) for i, line in enumerate(self.content.splitlines(), 1)
                     if "\u2014" in line]
        self.assertEqual(em_dashes, [],
                         f"Em dashes found at lines: {[i for i, _ in em_dashes]}")

    def test_no_invented_agent_tools(self):
        # Catch any token that LOOKS like an agent tool (execute_*, kali_shell,
        # query_graph, metasploit_console) anywhere in the file (backticked,
        # in fenced code blocks, in prose). Cross-reference against the known
        # allowlist so an invented `execute_magic` would fail.
        # Word boundary on both sides; case-sensitive (real agent tools are snake_case).
        candidates = re.findall(
            r"\b(execute_[a-z][a-z_]*|query_graph|kali_shell|metasploit_console)\b",
            self.content,
        )
        # `execute_code` blocks and similar sometimes get repeated; dedupe before checking
        unknowns = sorted({c for c in candidates if c not in KNOWN_AGENT_TOOLS})
        self.assertEqual(unknowns, [],
                         f"Skill references unknown agent tools: {unknowns}. "
                         f"Add them to KNOWN_AGENT_TOOLS if real, or fix the skill.")

    def test_no_unbacked_missing_kali_tools(self):
        # The brief said missing tools are "None". The Kali image does NOT bundle
        # grpcurl, websocat, wscat, or clairvoyance. If the skill mentions them,
        # there must be an explicit fallback note nearby.
        for tool in ("grpcurl", "websocat", "wscat", "clairvoyance"):
            if tool in self.content:
                # Look for a fallback note in the same file
                self.assertRegex(
                    self.content,
                    rf"(?is)does not bundle\s+`?{tool}`?|emulate\s+it|fallback|drive .*from python|drive .*from `execute_code`",
                    f"Skill references {tool!r} but no fallback note explains it"
                    " (Kali image does not bundle this tool)",
                )

    def test_disjoint_from_neighboring_skills(self):
        # The brief requires the disjointness section to name the neighboring skills
        # so the classifier can route correctly.
        body = self.content
        for neighbor in ("sql_injection", "xss", "cve_exploit",
                         "brute_force_credential_guess", "api_testing",
                         "idor_bola_exploitation"):
            self.assertIn(neighbor, body,
                          f"Disjointness section missing reference to {neighbor!r}")

    def test_first_500_chars_carry_bfla_signal(self):
        # The classifier slices the first 500 chars when no explicit description is set
        preview = self.content[:500]
        # Must mention the headline term
        self.assertRegex(preview, r"(?i)broken function.level|bfla|function.level authorization",
                         "First-500 preview must carry the BFLA headline term")
        # Must signal vertical / privilege escalation
        self.assertRegex(preview, r"(?i)privileged|admin|escalat|authorization",
                         "First-500 preview must signal authz / privilege escalation")
        # Disambiguator vs SQLi, XSS, RCE
        for forbidden in ("SQL injection payload", "alert(1)", "/etc/passwd"):
            self.assertNotIn(forbidden, preview)


# ===========================================================================
# 4. UNIT - simulate the agent /community-skills auto-description extractor
# ===========================================================================

def _extract_auto_description(content: str) -> str:
    """Replica of agentic/api.py:list_community_skills description extractor."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:200]
    return ""


class TestAutoDescriptionExtractor(unittest.TestCase):
    def test_description_extracted_is_nonempty(self):
        desc = _extract_auto_description(_read_skill())
        self.assertTrue(desc, "Auto-description extraction returned empty")

    def test_description_within_200_chars(self):
        desc = _extract_auto_description(_read_skill())
        self.assertLessEqual(len(desc), MAX_DESCRIPTION_CHARS)

    def test_description_starts_with_meaningful_word(self):
        desc = _extract_auto_description(_read_skill())
        self.assertNotIn("Tools Available", desc)
        self.assertFalse(desc.startswith("-"),
                         "Description should not start with a list bullet")
        self.assertFalse(desc.startswith("|"),
                         "Description should not start with a table delimiter")

    def test_description_carries_classification_signal(self):
        desc = _extract_auto_description(_read_skill())
        self.assertRegex(desc, r"(?i)authorization|privilege|admin|function",
                         "Description must carry classification keywords")


# ===========================================================================
# 5. INTEGRATION - /community-skills catalog endpoint (live agent container)
# ===========================================================================

def _agent_endpoint_reachable() -> bool:
    """Probe the agent on the host-mapped port 8090 (mapping in docker-compose.yml)."""
    try:
        with socket.create_connection(("127.0.0.1", 8090), timeout=2):
            return True
    except OSError:
        return False


class TestCatalogEndpointIntegration(unittest.TestCase):
    """Hits the live agent container's /community-skills endpoint via host port."""

    @classmethod
    def setUpClass(cls):
        if not _agent_endpoint_reachable():
            raise unittest.SkipTest("Agent container not reachable at 127.0.0.1:8090")

    def _get(self, path: str):
        with urlrequest.urlopen(f"http://127.0.0.1:8090{path}", timeout=5) as resp:
            return json.loads(resp.read())

    def test_bfla_in_catalog(self):
        catalog = self._get("/community-skills")
        ids = {s["id"] for s in catalog["skills"]}
        self.assertIn(SKILL_ID, ids,
                      f"Skill {SKILL_ID!r} missing from /community-skills")

    def test_bfla_catalog_entry_shape(self):
        catalog = self._get("/community-skills")
        entry = next(s for s in catalog["skills"] if s["id"] == SKILL_ID)
        self.assertEqual(entry["id"], SKILL_ID)
        self.assertTrue(entry["name"])
        self.assertTrue(entry["description"])
        self.assertLessEqual(len(entry["description"]), MAX_DESCRIPTION_CHARS)
        self.assertTrue(entry["file"].endswith(f"{SKILL_ID}.md"))

    def test_bfla_content_endpoint(self):
        body = self._get(f"/community-skills/{SKILL_ID}")
        self.assertEqual(body["id"], SKILL_ID)
        self.assertIn("BROKEN FUNCTION-LEVEL AUTHORIZATION", body["content"].upper())
        # Match the live-served content against what's on disk
        self.assertEqual(body["content"], _read_skill())

    def test_readme_excluded_from_catalog(self):
        catalog = self._get("/community-skills")
        ids = {s["id"] for s in catalog["skills"]}
        self.assertNotIn("README", ids)
        self.assertNotIn("readme", ids)


# ===========================================================================
# 6. REGRESSION - other community skills still load
# ===========================================================================

class TestCommunitySkillsRegression(unittest.TestCase):
    """Adding bfla must not break the discoverability of other community skills."""

    @classmethod
    def setUpClass(cls):
        cls.expected_companions = {
            f.stem for f in COMMUNITY_DIR.glob("*.md")
            if f.name != "README.md"
        }

    def test_companion_skills_present_on_disk(self):
        # Sanity: at least the well-known siblings should ship
        well_known_subset = {
            "api_testing", "sqli_exploitation", "xss_exploitation",
        }
        on_disk = self.expected_companions
        missing = well_known_subset - on_disk
        self.assertEqual(missing, set(),
                         f"Expected sibling skills missing on disk: {missing}")

    def test_companion_skills_parseable(self):
        # Apply the same auto-description extractor used by /community-skills.
        # Every sibling must yield a non-empty description, otherwise the import
        # dialog would show a blank row.
        for stem in self.expected_companions:
            content = (COMMUNITY_DIR / f"{stem}.md").read_text(encoding="utf-8")
            desc = _extract_auto_description(content)
            self.assertTrue(desc,
                            f"Community skill {stem!r} has no auto-description; "
                            "would render blank in import dialog")
            self.assertLessEqual(len(desc), MAX_DESCRIPTION_CHARS)

    def test_no_duplicate_skill_ids(self):
        ids = [f.stem for f in COMMUNITY_DIR.glob("*.md") if f.name != "README.md"]
        self.assertEqual(len(ids), len(set(ids)),
                         f"Duplicate community-skill IDs: {ids}")

    def test_bfla_listed_in_readme_index(self):
        readme = (COMMUNITY_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("bfla_exploitation.md", readme,
                      "bfla_exploitation row missing from README.md index")


# ===========================================================================
# 7. INTEGRATION - classification-prompt rendering (offline, no agent needed)
# ===========================================================================

# Stub heavyweight imports the same way the existing built-in tests do
class _FakeMsg:
    def __init__(self, content="", **kwargs):
        self.content = content


_stub_modules = [
    "langchain_core", "langchain_core.tools", "langchain_core.messages",
    "langchain_core.language_models", "langchain_core.runnables",
    "langchain_mcp_adapters", "langchain_mcp_adapters.client",
    "langchain_neo4j",
    "langgraph", "langgraph.graph", "langgraph.graph.message",
    "langgraph.graph.state", "langgraph.checkpoint",
    "langgraph.checkpoint.memory",
    "langchain_openai", "langchain_openai.chat_models",
    "langchain_openai.chat_models.azure", "langchain_openai.chat_models.base",
    "langchain_anthropic",
    "langchain_core.language_models.chat_models",
    "langchain_core.callbacks", "langchain_core.outputs",
]
for mod in _stub_modules:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()
sys.modules["langchain_core.messages"].AIMessage = _FakeMsg
sys.modules["langchain_core.messages"].HumanMessage = _FakeMsg
sys.modules["langgraph.graph.message"].add_messages = lambda l, r: (l or []) + r


class TestClassificationPromptRendering(unittest.TestCase):
    """When the user has imported BFLA and toggled it ON for the project, the
    classification prompt must render a user_skill:bfla_exploitation section
    with a meaningful preview."""

    def _bfla_skill_record(self, with_description=True):
        # Replica of the rows produced by the import-community route
        content = _read_skill()
        record = {
            "id": SKILL_ID,
            "name": "Bfla Exploitation",
            "content": content,
        }
        if with_description:
            record["description"] = _extract_auto_description(content)
        return record

    def test_prompt_contains_bfla_section_when_enabled_with_description(self):
        from prompts.classification import build_classification_prompt
        with patch("prompts.classification.get_enabled_builtin_skills",
                   return_value=set()), \
             patch("prompts.classification.get_enabled_user_skills",
                   return_value=[self._bfla_skill_record(with_description=True)]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt(
                "Promote my user to admin via the staff API.")
        self.assertIn(f"user_skill:{SKILL_ID}", prompt)
        self.assertIn("Bfla Exploitation", prompt)
        # The auto-description should be the preview, not 500 chars of content
        self.assertNotIn("# ATTACK SKILL", prompt)
        self.assertRegex(prompt, r"(?i)authorization|privilege|admin|function")

    def test_prompt_falls_back_to_500_char_preview_without_description(self):
        from prompts.classification import build_classification_prompt
        with patch("prompts.classification.get_enabled_builtin_skills",
                   return_value=set()), \
             patch("prompts.classification.get_enabled_user_skills",
                   return_value=[self._bfla_skill_record(with_description=False)]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("anything")
        self.assertIn(f"user_skill:{SKILL_ID}", prompt)
        # When no description is supplied, the prompt builder slices the first
        # 500 chars of content. The H1 lives in those 500 chars.
        self.assertIn("ATTACK SKILL: BROKEN FUNCTION-LEVEL AUTHORIZATION", prompt)
        # And appends an ellipsis to signal truncation
        self.assertIn("...", prompt)

    def test_prompt_excludes_bfla_when_user_disables_it(self):
        from prompts.classification import build_classification_prompt
        with patch("prompts.classification.get_enabled_builtin_skills",
                   return_value=set()), \
             patch("prompts.classification.get_enabled_user_skills",
                   return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("BFLA test request")
        self.assertNotIn(f"user_skill:{SKILL_ID}", prompt)
        # Unclassified must always remain
        self.assertIn("unclassified", prompt)

    def test_prompt_disjoint_keywords_present_with_neighbor(self):
        """When BFLA and the IDOR/BOLA sibling are both enabled, the BFLA preview
        must still carry tokens that disambiguate it (otherwise the classifier
        cannot route correctly)."""
        from prompts.classification import build_classification_prompt
        bfla = self._bfla_skill_record(with_description=False)  # use full content preview
        idor_path = COMMUNITY_DIR / "idor_bola_exploitation.md"
        if not idor_path.exists():
            self.skipTest("idor_bola_exploitation skill not present yet")
        idor = {
            "id": "idor_bola_exploitation",
            "name": "Idor Bola Exploitation",
            "content": idor_path.read_text(encoding="utf-8"),
        }
        with patch("prompts.classification.get_enabled_builtin_skills",
                   return_value=set()), \
             patch("prompts.classification.get_enabled_user_skills",
                   return_value=[bfla, idor]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt(
                "Promote my user to admin via the staff API.")
        self.assertIn("user_skill:bfla_exploitation", prompt)
        self.assertIn("user_skill:idor_bola_exploitation", prompt)


if __name__ == "__main__":
    unittest.main()
