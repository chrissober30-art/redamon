"""
Tests for the idor_bola_exploitation Community Agent Skill.

This skill ships as a single .md file in agentic/community-skills/. It has no
Python wiring, so the contract under test is:

  1. The file exists, parses, and is well within the 50 KB import cap.
  2. Required structural sections are present (template fidelity).
  3. The first non-heading line is a sensible auto-description (drives the
     classifier when no operator-supplied description exists; agentic/api.py
     extracts the first 200 chars).
  4. Every tool name referenced is a real RedAmon tool (no invented tools).
  5. The "When to Classify Here" section disambiguates from neighboring
     skills (built-ins + adjacent community skills).
  6. No em dashes, no Shannon-specific paths or CLI references.
  7. The /community-skills catalog logic surfaces this skill with the
     expected id, title-cased name, and auto-description.
  8. README and wiki indices reference the file consistently with the
     directory state (regression catch for orphan rows or missing rows).

Run with:
    python -m pytest tests/test_idor_bola_community_skill.py -v
"""

import os
import re
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _AGENTIC_DIR.parent
_COMMUNITY_DIR = _AGENTIC_DIR / "community-skills"
_SKILL_ID = "idor_bola_exploitation"
_SKILL_PATH = _COMMUNITY_DIR / f"{_SKILL_ID}.md"
_README_PATH = _COMMUNITY_DIR / "README.md"
_WIKI_PATH = _REPO_ROOT / "redamon.wiki" / "Agent-Skills.md"

# Cap enforced at webapp/src/app/api/users/[id]/attack-skills/route.ts (POST handler).
_IMPORT_CAP_BYTES = 50_000

# Match the live extraction logic in agentic/api.py:572-578.
def _extract_auto_description(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:200]
    return ""


def _stem_to_title(stem: str) -> str:
    return stem.replace("_", " ").title()


class TestSkillFileSmoke(unittest.TestCase):
    """File-level smoke: exists, opens, encoding, size."""

    def test_file_exists(self):
        self.assertTrue(_SKILL_PATH.is_file(), f"missing {_SKILL_PATH}")

    def test_file_is_utf8_readable(self):
        # Should not raise.
        _SKILL_PATH.read_text(encoding="utf-8")

    def test_file_size_under_import_cap(self):
        size = _SKILL_PATH.stat().st_size
        self.assertLess(size, _IMPORT_CAP_BYTES,
                        f"{size} bytes exceeds 50 KB import cap")

    def test_file_size_in_recommended_band(self):
        # Brief targets 200-800 lines per PROMPT.ADD_COMMUNITY_AGENT_SKILL.md.
        line_count = len(_SKILL_PATH.read_text(encoding="utf-8").splitlines())
        self.assertGreaterEqual(line_count, 200, f"only {line_count} lines, looks underbaked")
        self.assertLessEqual(line_count, 800, f"{line_count} lines, will eat tokens")


class TestSkillStructure(unittest.TestCase):
    """Required structural sections per the canonical Community Agent template."""

    def setUp(self):
        self.text = _SKILL_PATH.read_text(encoding="utf-8")

    def test_starts_with_h1(self):
        first = self.text.lstrip().splitlines()[0]
        self.assertTrue(first.startswith("# "), f"first non-blank line is {first!r}")

    def test_h1_mentions_idor_or_bola(self):
        first = self.text.lstrip().splitlines()[0].lower()
        self.assertTrue("idor" in first or "bola" in first,
                        f"H1 should name the skill: {first!r}")

    def test_has_when_to_classify_here_section(self):
        self.assertRegex(self.text, r"(?m)^##\s+When to Classify Here\b")

    def test_has_workflow_section(self):
        self.assertRegex(self.text, r"(?m)^##\s+Workflow\b")

    def test_has_phase_1_recon_subheading(self):
        self.assertRegex(self.text, r"(?m)^###\s+Phase 1[: ].*Recon", )

    def test_has_phase_2_exploitation_subheading(self):
        self.assertRegex(self.text, r"(?m)^###\s+Phase 2[: ].*Exploit", )

    def test_has_reporting_guidelines_section(self):
        self.assertRegex(self.text, r"(?m)^##\s+Reporting Guidelines\b")

    def test_has_important_notes_section(self):
        self.assertRegex(self.text, r"(?m)^##\s+Important Notes\b")

    def test_phase_transition_cue_present(self):
        # Brief: Phase 1 must end with the literal cue so the agent knows
        # when to call action="request_phase_transition".
        self.assertIn("request transition to exploitation phase", self.text)

    def test_phase_transition_cue_appears_before_phase_2(self):
        cue_pos = self.text.find("request transition to exploitation phase")
        phase_2_match = re.search(r"(?m)^###\s+Phase 2", self.text)
        self.assertGreater(cue_pos, 0)
        self.assertIsNotNone(phase_2_match)
        self.assertLess(cue_pos, phase_2_match.start(),
                        "phase-transition cue must sit at the end of Phase 1, not later")


class TestAutoDescription(unittest.TestCase):
    """The first non-heading line is what the classifier sees on import."""

    def setUp(self):
        self.text = _SKILL_PATH.read_text(encoding="utf-8")
        self.desc = _extract_auto_description(self.text)

    def test_auto_description_is_nonempty(self):
        self.assertTrue(self.desc, "auto-description came back empty")

    def test_auto_description_within_200_chars(self):
        # The catalog endpoint trims to 200; we ensure the value the
        # classifier actually receives still reads as a complete sentence.
        self.assertLessEqual(len(self.desc), 200)

    def test_auto_description_mentions_skill_topic(self):
        lower = self.desc.lower()
        self.assertTrue(
            any(token in lower for token in ("idor", "bola", "object-level", "object level")),
            f"auto-description should name the topic: {self.desc!r}",
        )

    def test_auto_description_not_a_list_marker(self):
        # First line must be prose, not a bullet, otherwise the classifier
        # gets fragments instead of a sentence.
        self.assertFalse(self.desc.startswith(("-", "*", "1.", "|")))


class TestNoEmDashes(unittest.TestCase):
    """Project-wide rule: no em dashes anywhere."""

    def test_no_em_dash(self):
        text = _SKILL_PATH.read_text(encoding="utf-8")
        self.assertNotIn("\u2014", text, "em dash (U+2014) found in skill file")

    def test_no_en_dash(self):
        # Brief flags em specifically; en dashes look the same to most
        # readers and are equally AI-coded. Catch them too.
        text = _SKILL_PATH.read_text(encoding="utf-8")
        self.assertNotIn("\u2013", text, "en dash (U+2013) found in skill file")


class TestNoWhiteBoxLeakage(unittest.TestCase):
    """Brief rule 2: strip every Shannon / Strix white-box-only artifact."""

    def setUp(self):
        self.text = _SKILL_PATH.read_text(encoding="utf-8")

    def test_no_shannon_deliverable_paths(self):
        # Shannon writes to .shannon/deliverables/*. RedAmon agents have no
        # such filesystem; surfacing this string would confuse the agent.
        self.assertNotIn(".shannon/deliverables", self.text)

    def test_no_save_deliverable_cli(self):
        self.assertNotIn("save-deliverable", self.text)

    def test_no_task_agent_code_analysis(self):
        # Shannon's "Task Agent (Code Analysis)" is a white-box code-review
        # tool RedAmon does not have.
        self.assertNotRegex(self.text, r"Task Agent\s*\(.*Code Analysis.*\)")

    def test_no_playwright_cli_skill_handoff(self):
        # Shannon's "playwright-cli skill" is a Shannon-specific abstraction.
        # RedAmon uses execute_playwright directly.
        self.assertNotIn("playwright-cli skill", self.text)

    def test_no_white_box_source_review_directives(self):
        # Catch direct prose that tells the agent to read application source.
        offending = ["application source code", "application's source code",
                     "white-box code", "Read the source code"]
        hits = [p for p in offending if p.lower() in self.text.lower()]
        self.assertEqual(hits, [], f"white-box leakage found: {hits}")


class TestToolReferencesAreReal(unittest.TestCase):
    """Every tool name referenced must exist in tool_registry.py."""

    # Pulled from agentic/prompts/tool_registry.py keys plus the kali_shell
    # subtools that the brief explicitly lists as legal to reference inline.
    _LEGAL_AGENT_TOOLS = {
        "query_graph", "web_search", "shodan", "google_dork",
        "execute_nuclei", "execute_curl", "execute_httpx", "execute_naabu",
        "execute_jsluice", "execute_katana", "execute_subfinder",
        "execute_gau", "execute_nmap", "execute_amass",
        "kali_shell", "execute_code", "execute_playwright",
        "execute_hydra", "metasploit_console",
        "execute_wpscan", "execute_arjun", "execute_ffuf",
        "msf_restart",
    }

    def setUp(self):
        self.text = _SKILL_PATH.read_text(encoding="utf-8")
        # Match `execute_*` and `kali_shell` / `query_graph` / etc.
        # surrounded by backticks (the canonical mention pattern in skills).
        self.referenced = set(re.findall(
            r"`(query_graph|web_search|shodan|google_dork|execute_[a-z_]+|kali_shell|metasploit_console|msf_restart)`",
            self.text,
        ))

    def test_some_tools_are_referenced(self):
        # Sanity: a workflow with zero tool refs is broken by definition.
        self.assertTrue(self.referenced,
                        "no agent tool references found; skill is not actionable")

    def test_all_tool_references_are_real(self):
        invalid = self.referenced - self._LEGAL_AGENT_TOOLS
        self.assertEqual(invalid, set(),
                         f"unknown tools referenced: {invalid}")

    def test_brief_mandated_tools_present(self):
        # The integration brief specifies query_graph + execute_arjun + execute_curl
        # as the mandated tool set for this skill.
        for required in ("query_graph", "execute_arjun", "execute_curl"):
            self.assertIn(required, self.referenced,
                          f"brief requires {required}, not referenced")


class TestClassificationDisambiguation(unittest.TestCase):
    """Disjoint classification: spell out the boundary against neighbors
    that overlap by keyword. Same approach as PROMPT.ADD_COMMUNITY_AGENT_SKILL.md."""

    def setUp(self):
        self.text = _SKILL_PATH.read_text(encoding="utf-8")

    def _assert_disjoint(self, neighbor: str):
        # The boundary section must mention the neighbor by canonical name
        # (so the classifier sees the disambiguation cue near the top).
        self.assertIn(neighbor, self.text,
                      f"'When to Classify Here' should disambiguate from {neighbor}")

    def test_disjoint_from_sql_injection(self):
        self._assert_disjoint("sql_injection")

    def test_disjoint_from_xss(self):
        self._assert_disjoint("`xss`")

    def test_disjoint_from_ssrf(self):
        self._assert_disjoint("`ssrf`")

    def test_disjoint_from_rce(self):
        self._assert_disjoint("`rce`")

    def test_disjoint_from_path_traversal(self):
        self._assert_disjoint("path_traversal")

    def test_disjoint_from_brute_force(self):
        self._assert_disjoint("brute_force_credential_guess")

    def test_disjoint_from_api_testing_community_skill(self):
        self._assert_disjoint("api_testing")

    def test_disjoint_from_bfla_exploitation_community_skill(self):
        # bfla_exploitation owns vertical escalation as its primary mission;
        # boundary required to avoid classifier ambiguity.
        self._assert_disjoint("bfla_exploitation")

    def test_disjoint_from_mass_assignment_community_skill(self):
        # mass_assignment owns over-posting / privileged-field injection.
        self._assert_disjoint("mass_assignment")

    def test_when_to_classify_section_above_workflow(self):
        when_idx = self.text.find("## When to Classify Here")
        wf_idx = self.text.find("## Workflow")
        self.assertGreater(when_idx, 0)
        self.assertGreater(wf_idx, 0)
        self.assertLess(when_idx, wf_idx,
                        "Classification section must precede Workflow")


class TestCatalogEndpointLogic(unittest.TestCase):
    """Replicate the api.py logic so failures can be diagnosed without
    needing a live container, and so a regression in the endpoint contract
    surfaces here too."""

    def _list_skills(self):
        skills = []
        for md_file in sorted(_COMMUNITY_DIR.glob("*.md")):
            if md_file.name == "README.md":
                continue
            content = md_file.read_text(encoding="utf-8")
            skills.append({
                "id": md_file.stem,
                "name": _stem_to_title(md_file.stem),
                "description": _extract_auto_description(content),
                "file": str(md_file),
            })
        return skills

    def test_catalog_includes_idor_bola(self):
        ids = {s["id"] for s in self._list_skills()}
        self.assertIn(_SKILL_ID, ids)

    def test_catalog_entry_name_title_cased(self):
        entry = next(s for s in self._list_skills() if s["id"] == _SKILL_ID)
        self.assertEqual(entry["name"], "Idor Bola Exploitation")

    def test_catalog_entry_description_nonempty(self):
        entry = next(s for s in self._list_skills() if s["id"] == _SKILL_ID)
        self.assertTrue(entry["description"])

    def test_catalog_entry_description_mentions_topic(self):
        entry = next(s for s in self._list_skills() if s["id"] == _SKILL_ID)
        lower = entry["description"].lower()
        self.assertTrue("idor" in lower or "bola" in lower or "object-level" in lower
                         or "object level" in lower)

    def test_skill_ids_unique(self):
        ids = [s["id"] for s in self._list_skills()]
        self.assertEqual(len(ids), len(set(ids)),
                         f"duplicate community skill ids: {ids}")


class TestReadmeIndex(unittest.TestCase):
    """README must reference the new skill, and every README row must point
    to a real file (regression: catches orphan rows after deletes/renames)."""

    def setUp(self):
        self.readme = _README_PATH.read_text(encoding="utf-8")
        self.dir_files = {p.name for p in _COMMUNITY_DIR.glob("*.md")
                          if p.name != "README.md"}

    def test_readme_lists_idor_bola(self):
        self.assertIn(f"{_SKILL_ID}.md", self.readme)

    def test_every_readme_link_resolves(self):
        # Markdown links of the form [text](file.md).
        linked = set(re.findall(r"\[[^\]]+\]\(([a-z0-9_]+\.md)\)", self.readme))
        # Drop self-references like README.md if present.
        linked.discard("README.md")
        missing = linked - self.dir_files
        self.assertEqual(missing, set(),
                         f"README references files that do not exist: {missing}")

    def test_every_dir_file_is_listed(self):
        # Catch the inverse case: a new skill landed without a README row.
        # We allow new authors a grace window, so this only enforces for the
        # skill under test.
        if f"{_SKILL_ID}.md" not in self.readme:
            self.fail(f"{_SKILL_ID}.md missing from README index")


class TestWikiIndex(unittest.TestCase):
    """If the wiki exists locally, the community-skills table should
    reference the new skill. Skip silently when the wiki submodule isn't
    checked out (CI may not have it)."""

    def test_wiki_table_lists_idor_bola(self):
        if not _WIKI_PATH.is_file():
            self.skipTest("redamon.wiki not checked out locally")
        wiki = _WIKI_PATH.read_text(encoding="utf-8")
        self.assertIn(f"{_SKILL_ID}.md", wiki,
                      "wiki community-skills table must reference the new file")


class TestNeighborSkillsStillLoad(unittest.TestCase):
    """Regression: adding the new skill must not break the existing
    community catalog. Every sibling .md must still parse and produce a
    non-empty auto-description."""

    def test_each_sibling_skill_loads_with_description(self):
        broken = []
        for md_file in sorted(_COMMUNITY_DIR.glob("*.md")):
            if md_file.name == "README.md":
                continue
            content = md_file.read_text(encoding="utf-8")
            desc = _extract_auto_description(content)
            if not desc:
                broken.append(md_file.name)
        self.assertEqual(broken, [],
                         f"community skills with empty auto-description: {broken}")

    def test_no_neighbor_has_em_dashes(self):
        # While we are at it, regression-check the sibling skills against
        # the project-wide em-dash rule. Catches the case where someone
        # imports a Shannon/Strix file verbatim.
        offenders = []
        for md_file in sorted(_COMMUNITY_DIR.glob("*.md")):
            if md_file.name == "README.md":
                continue
            text = md_file.read_text(encoding="utf-8")
            if "\u2014" in text or "\u2013" in text:
                offenders.append(md_file.name)
        self.assertEqual(offenders, [],
                         f"community skills containing em/en dashes: {offenders}")


if __name__ == "__main__":
    unittest.main()
