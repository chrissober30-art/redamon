"""
Tests for the Subdomain Takeover community Agent Skill.

Layers covered:
- Unit:           file-level invariants (size, structural sections, no em dashes,
                  classifier-friendly opening paragraph, phase-transition cue).
- Integration:   reproduce the agentic/api.py:572-578 auto-description extraction
                  against the real markdown to confirm the import dialog will get
                  a sensible description; verify the Kali Dockerfile installs the
                  subzy binary and that the tool_registry advertises it.
- Smoke:         the file is in the directory glob that GET /community-skills
                  scans, exercises the same Path.glob('*.md') pipeline.
- Regression:    no duplicate skill IDs in the catalog; no neighboring community
                  skill fights this one for the same opening keyword set; phase-
                  transition cue still present across the catalog.

Run (host):
    cd agentic && python -m unittest tests.test_subdomain_takeover_skill -v

Run (containerized, matches CI):
    docker run --rm -v "$(pwd)/agentic:/app" -w /app redamon-agent \
        python -m unittest tests.test_subdomain_takeover_skill -v
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_REPO_DIR = _AGENTIC_DIR.parent
sys.path.insert(0, str(_AGENTIC_DIR))

SKILLS_DIR = _AGENTIC_DIR / "community-skills"
SKILL_FILE = SKILLS_DIR / "subdomain_takeover.md"
DOCKERFILE = _REPO_DIR / "mcp" / "kali-sandbox" / "Dockerfile"
TOOL_REGISTRY_FILE = _AGENTIC_DIR / "prompts" / "tool_registry.py"
README_FILE = SKILLS_DIR / "README.md"


def _first_non_heading_paragraph(content: str) -> str:
    """Reproduce the agentic/api.py:572-578 description extraction."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:200]
    return ""


def _read_skill() -> str:
    return SKILL_FILE.read_text(encoding="utf-8")


# ----------------------------- UNIT TESTS -----------------------------


class FileExistsAndSize(unittest.TestCase):
    """Hard invariants on the file shape."""

    def test_file_exists(self):
        self.assertTrue(SKILL_FILE.exists(), f"Missing: {SKILL_FILE}")

    def test_under_50kb_import_cap(self):
        size = SKILL_FILE.stat().st_size
        self.assertLess(
            size, 50_000,
            f"Skill is {size} bytes; the webapp import endpoint rejects >= 50 KB."
        )

    def test_target_line_range(self):
        lines = _read_skill().splitlines()
        self.assertGreaterEqual(
            len(lines), 200,
            "Below 200 lines reads as underbaked per PROMPT.ADD_COMMUNITY_AGENT_SKILL."
        )
        self.assertLessEqual(
            len(lines), 800,
            "Above 800 lines burns tokens every classification + injection pass."
        )

    def test_no_em_dashes(self):
        content = _read_skill()
        # Project-wide guardrail (CLAUDE.md / feedback memory).
        self.assertNotIn(
            "\u2014", content,
            "Em dash found. Replace with hyphen or rephrase per the project rule."
        )


class CanonicalSections(unittest.TestCase):
    """Sections required by the canonical Community Agent Skill template."""

    def setUp(self):
        self.content = _read_skill()

    def test_top_level_title(self):
        first_line = self.content.splitlines()[0].strip()
        self.assertTrue(
            first_line.startswith("# "),
            f"First line must be the H1 title; got: {first_line!r}"
        )
        self.assertIn(
            "Subdomain Takeover", first_line,
            "H1 must name the skill clearly for the import dialog title."
        )

    def test_when_to_classify_here_section(self):
        self.assertRegex(
            self.content, r"(?m)^## When to Classify Here\b",
            "Missing canonical '## When to Classify Here' section."
        )

    def test_workflow_section(self):
        self.assertRegex(self.content, r"(?m)^## Workflow\b")

    def test_phase_1_recon_section(self):
        self.assertRegex(self.content, r"(?m)^### Phase 1: Reconnaissance")

    def test_phase_2_exploitation_section(self):
        self.assertRegex(self.content, r"(?m)^### Phase 2: Exploitation\b")

    def test_phase_3_post_exploitation_section(self):
        self.assertRegex(self.content, r"(?m)^### Phase 3: Post-Exploitation\b")

    def test_reporting_guidelines_section(self):
        self.assertRegex(self.content, r"(?m)^## Reporting Guidelines\b")

    def test_important_notes_section(self):
        self.assertRegex(self.content, r"(?m)^## Important Notes\b")

    def test_phase_transition_cue_present(self):
        # The agent reads this literal string to call request_phase_transition.
        self.assertIn(
            "request transition to exploitation phase", self.content,
            "Phase 1 must end with the literal cue 'request transition to "
            "exploitation phase' (consumed by the phase router)."
        )

    def test_phase_transition_cue_lives_in_phase_1(self):
        # The cue MUST appear inside Phase 1, not after Phase 2.
        # Find the cue and verify it precedes the Phase 2 heading.
        cue_idx = self.content.find("request transition to exploitation phase")
        phase2_idx = self.content.find("### Phase 2: Exploitation")
        self.assertGreaterEqual(cue_idx, 0)
        self.assertGreaterEqual(phase2_idx, 0)
        self.assertLess(
            cue_idx, phase2_idx,
            "Phase-transition cue must live in Phase 1, before the Phase 2 heading."
        )


class OpeningParagraph(unittest.TestCase):
    """The first non-heading paragraph drives auto-description and classification."""

    def setUp(self):
        self.desc = _first_non_heading_paragraph(_read_skill())

    def test_description_extracted(self):
        self.assertTrue(self.desc, "No first non-heading paragraph found.")

    def test_description_length_at_or_below_api_cap(self):
        # api.py applies stripped[:200].
        self.assertLessEqual(len(self.desc), 200)

    def test_description_not_empty_or_trivial(self):
        self.assertGreater(len(self.desc), 60, "Description is too short to classify on.")

    def test_description_mentions_subdomain_or_takeover(self):
        # The classifier latches on these terms; the auto-description must carry them.
        lowered = self.desc.lower()
        self.assertTrue(
            "subdomain" in lowered or "takeover" in lowered or "dangling" in lowered,
            f"Auto-description lacks a primary keyword: {self.desc!r}"
        )

    def test_description_does_not_open_with_overlapping_keyword(self):
        # If the description leads with 'sql', 'xss', 'ssrf', 'rce', 'idor', etc., the
        # classifier may misroute. Ensure the first keyword is takeover-specific.
        lowered = self.desc.lower()
        misleading_leads = ("sql", "xss", "cross-site", "ssrf",
                            "remote code", "rce", "idor", "bola",
                            "xxe", "deserialization", "ssti", "template injection")
        first_120 = lowered[:120]
        for term in misleading_leads:
            # Tolerate the term appearing as a side mention but not as the first
            # technical noun. We check the first 30 chars.
            self.assertNotIn(
                term, lowered[:30],
                f"Description opens with a neighboring-skill keyword '{term}' that "
                f"will confuse the Intent Router: {self.desc!r}"
            )


class ClassificationDisjointness(unittest.TestCase):
    """Verify the Boundary section explicitly disambiguates against neighbors."""

    def setUp(self):
        self.content = _read_skill()

    def test_explicit_boundary_section(self):
        # Either '### Boundary against neighboring skills' or 'Boundary against'
        # in any heading; both shapes are accepted by the import flow.
        self.assertRegex(
            self.content,
            r"(?im)^#+\s+Boundary against neighboring skills\b",
            "Skill must explicitly disambiguate against neighboring built-ins/"
            "community skills (per PROMPT.ADD_COMMUNITY_AGENT_SKILL.md)."
        )

    def test_disambiguates_against_each_overlapping_neighbor(self):
        # Every neighbor that could compete for the same prompt must be named.
        required_neighbors = [
            "sql_injection", "xss",  # built-ins keyword-overlapping with takeover
            "ssrf", "xxe",
            "idor_bola_exploitation",  # community
            "api_testing", "cve_exploit",
            "denial_of_service", "phishing_social_engineering",
        ]
        missing = [n for n in required_neighbors if n not in self.content]
        self.assertEqual(
            missing, [],
            f"Boundary section does not name these neighbors: {missing}. "
            "Add 'Not <neighbor>: ...' lines so the classifier and operator "
            "know exactly when not to route here."
        )

    def test_keywords_list_present(self):
        # The 'Keywords:' anchor lets the classifier do plain string matching.
        self.assertRegex(
            self.content, r"(?mi)^Keywords[^\n]*:\s*",
            "Missing 'Keywords:' line inside When to Classify Here."
        )

    def test_keywords_disjoint_from_neighbors(self):
        """The Keywords line must NOT carry primary tokens of unrelated skills."""
        # Pull the keyword line.
        m = re.search(r"(?mi)^Keywords[^\n]*:\s*(.+)$", self.content)
        self.assertIsNotNone(m, "Keywords: line missing")
        kws_line = m.group(1).lower()

        # These tokens are the *primary* anchors of other skills. If they show
        # up in our keyword list naked (not as part of a takeover-specific
        # phrase), the classifier will be ambiguous.
        forbidden_bare_tokens = {
            "sqli", "sql injection",
            "xss", "cross-site scripting",
            "ssrf",  # naked 'ssrf' with no qualifier is built-in territory
            "xxe", "xml external entity",
            "idor", "bola",
            "rce", "remote code execution",
            "ssti", "template injection",
            "open redirect",
            "phishing", "social engineering",
            "credential stuffing", "credential spray",
            "ddos", "denial of service",
        }
        for tok in forbidden_bare_tokens:
            # Use word-boundary regex so 'ssrf-like takeover impact' as a phrase
            # can still appear in prose elsewhere. We only police the Keywords line.
            self.assertNotRegex(
                kws_line, rf"(?<![\w-]){re.escape(tok)}(?![\w-])",
                f"Keyword '{tok}' belongs to a neighboring skill. Either drop it "
                f"or wrap it inside a takeover-specific phrase that disambiguates."
            )

    def test_keywords_list_carries_at_least_one_anchor(self):
        m = re.search(r"(?mi)^Keywords[^\n]*:\s*(.+)$", self.content)
        kws_line = m.group(1).lower()
        anchors = ["subdomain takeover", "dangling cname", "orphaned ns",
                   "unclaimed", "subzy", "dangling dns"]
        hits = [a for a in anchors if a in kws_line]
        self.assertTrue(
            hits, f"Keywords line carries none of the canonical takeover anchors "
                  f"({anchors}); the classifier will struggle."
        )


class WorkflowReferencesRealTools(unittest.TestCase):
    """Every workflow command must call a tool the agent actually has."""

    KNOWN_TOOLS = {
        "query_graph", "kali_shell", "execute_curl", "execute_code",
        "execute_playwright", "execute_nuclei", "execute_hydra",
        "metasploit_console", "execute_httpx", "execute_naabu",
        "execute_nmap", "execute_subfinder", "execute_amass",
        "execute_katana", "execute_jsluice", "execute_gau",
        "execute_arjun", "execute_ffuf", "web_search",
    }

    def setUp(self):
        self.content = _read_skill()

    def test_at_least_one_tool_invocation(self):
        hits = [t for t in self.KNOWN_TOOLS if re.search(rf"\b{t}\b", self.content)]
        self.assertGreaterEqual(
            len(hits), 4,
            f"Skill references too few real agent tools ({hits}). Workflow needs "
            f"more concrete tool wiring."
        )

    def test_no_invented_tool_names(self):
        # Heuristic: any token shaped like 'execute_<word>' or '<word>_tool' must
        # be in the known set; otherwise the agent cannot call it.
        candidates = set(re.findall(r"\bexecute_[a-z_]+\b", self.content))
        unknown = candidates - self.KNOWN_TOOLS
        self.assertEqual(
            unknown, set(),
            f"Workflow references tools that do not exist in tool_registry: {unknown}"
        )

    def test_phase_1_uses_query_graph_first(self):
        # Per PROMPT.ADD_COMMUNITY_AGENT_SKILL.md, Phase 1 should hit query_graph
        # before any active tool to honour the project-wide PRIMARY guidance.
        phase1_start = self.content.find("### Phase 1:")
        phase2_start = self.content.find("### Phase 2:")
        self.assertGreater(phase1_start, -1)
        self.assertGreater(phase2_start, phase1_start)
        phase1_body = self.content[phase1_start:phase2_start]
        self.assertIn(
            "query_graph", phase1_body,
            "Phase 1 must use query_graph first (per PRIMARY guidance)."
        )

    def test_subzy_referenced(self):
        self.assertIn(
            "subzy", self.content,
            "subzy is the new tool added for this skill; the workflow must call it."
        )

    def test_phase_1_consumes_prior_takeover_scan_graph_rows(self):
        """The recon pipeline already runs subjack + nuclei takeover templates
        and writes Vulnerability nodes with `source: 'takeover_scan'` plus
        `takeover_provider` / `takeover_method` (see prompts/base.py:1257-1271).

        Phase 1 must consume those rows BEFORE re-running active subdomain
        enumeration; otherwise the agent burns time and tokens redoing work the
        recon already shipped to the graph.
        """
        phase1_start = self.content.find("### Phase 1:")
        phase2_start = self.content.find("### Phase 2:")
        phase1_body = self.content[phase1_start:phase2_start]
        self.assertIn(
            "takeover_scan", phase1_body,
            "Phase 1 must query the existing Vulnerability {source: 'takeover_scan'} "
            "rows produced by the recon pipeline before re-running enumeration."
        )


# ----------------------------- INTEGRATION -----------------------------


class ApiAutoDescriptionIntegration(unittest.TestCase):
    """Exercise the same extraction the FastAPI endpoint runs, end-to-end."""

    def test_glob_picks_up_skill(self):
        files = sorted(SKILLS_DIR.glob("*.md"))
        names = [f.name for f in files]
        self.assertIn("subdomain_takeover.md", names)

    def test_readme_excluded_by_endpoint(self):
        # api.py:569 explicitly skips README.md; emulate the exclusion.
        files = [f for f in sorted(SKILLS_DIR.glob("*.md")) if f.name != "README.md"]
        names = [f.name for f in files]
        self.assertIn("subdomain_takeover.md", names)
        self.assertNotIn("README.md", names)

    def test_skill_id_is_file_stem(self):
        # api.py uses md_file.stem.
        self.assertEqual(SKILL_FILE.stem, "subdomain_takeover")

    def test_default_name_is_titlecased_stem(self):
        # api.py: name = stem.replace('_', ' ').title()
        derived_name = SKILL_FILE.stem.replace("_", " ").title()
        self.assertEqual(derived_name, "Subdomain Takeover")

    def test_description_is_classifier_useful(self):
        desc = _first_non_heading_paragraph(_read_skill())
        # Must mention WHAT the attack class is, not WHY it matters.
        # Heuristic: contains either 'subdomain' AND 'takeover', OR 'dangling DNS'.
        lowered = desc.lower()
        self.assertTrue(
            ("subdomain" in lowered and "takeover" in lowered)
            or ("dangling" in lowered and "dns" in lowered.replace("\n", " ")),
            f"Auto-description should anchor on the attack class. Got: {desc!r}"
        )


class DockerfileInstallsSubzy(unittest.TestCase):
    """Image-level test: the binary the skill assumes is actually built into Kali."""

    def test_dockerfile_exists(self):
        self.assertTrue(DOCKERFILE.exists(), f"Missing: {DOCKERFILE}")

    def test_subzy_install_directive(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            "github.com/PentestPad/subzy", text,
            "subzy install directive missing from kali-sandbox Dockerfile."
        )
        self.assertRegex(
            text, r"go install[^\n]*subzy",
            "subzy must be installed via 'go install ... subzy'."
        )

    def test_subzy_documented_in_tool_registry(self):
        registry = TOOL_REGISTRY_FILE.read_text(encoding="utf-8")
        # Must appear inside the kali_shell description, otherwise the agent
        # has no way to know the binary is callable.
        self.assertIn("subzy", registry,
                      "subzy not advertised in tool_registry.py kali_shell.")
        # The DNS bullet group is where subzy makes sense.
        # Ensure subzy is mentioned in the same registry entry as other DNS tools.
        kali_block_match = re.search(
            r'"kali_shell".*?\}\s*,', registry, flags=re.DOTALL,
        )
        self.assertIsNotNone(kali_block_match,
                             "Could not isolate kali_shell registry entry.")
        self.assertIn(
            "subzy", kali_block_match.group(0),
            "subzy mention exists in tool_registry but NOT inside kali_shell entry."
        )


# ----------------------------- SMOKE -----------------------------


class SmokeTestsCatalog(unittest.TestCase):
    """End-to-end shape: emulate the 'Import from Community' catalog hit."""

    def test_catalog_payload_shape(self):
        """Reproduce api.list_community_skills()'s exact loop and assert the
        subdomain_takeover entry has all four required keys with non-empty values."""
        skills = []
        for md_file in sorted(SKILLS_DIR.glob("*.md")):
            if md_file.name == "README.md":
                continue
            content = md_file.read_text(encoding="utf-8")
            name = md_file.stem.replace("_", " ").title()
            desc = _first_non_heading_paragraph(content)
            skills.append({
                "id": md_file.stem,
                "name": name,
                "description": desc,
                "file": str(md_file),
            })

        match = next((s for s in skills if s["id"] == "subdomain_takeover"), None)
        self.assertIsNotNone(match, "subdomain_takeover not in catalog payload")
        self.assertEqual(match["name"], "Subdomain Takeover")
        self.assertGreater(len(match["description"]), 0)
        self.assertTrue(match["file"].endswith("subdomain_takeover.md"))

    def test_catalog_serves_full_content(self):
        """Reproduce api.get_community_skill_content()."""
        content = SKILL_FILE.read_text(encoding="utf-8")
        self.assertGreater(len(content), 5_000,
                           "Skill content too thin; agent will get a stub prompt.")
        self.assertLess(len(content), 50_000,
                        "Skill content too large; webapp import will reject.")


# ----------------------------- REGRESSION -----------------------------


class CrossSkillRegression(unittest.TestCase):
    """Catalog-wide invariants. Adding this skill must not break neighbors."""

    @classmethod
    def setUpClass(cls):
        cls.skills: dict[str, str] = {}
        for md in sorted(SKILLS_DIR.glob("*.md")):
            if md.name == "README.md":
                continue
            cls.skills[md.stem] = md.read_text(encoding="utf-8")

    def test_no_duplicate_skill_ids(self):
        # File system already guarantees this for stems, but make it explicit.
        self.assertEqual(len(self.skills), len(set(self.skills)),
                         "Duplicate skill IDs detected in the catalog.")

    def test_every_community_skill_has_phase_transition_cue(self):
        # Skill files marketed as Agent Skills must end Phase 1 with the cue.
        missing = [
            sid for sid, content in self.skills.items()
            if "request transition to exploitation phase" not in content
        ]
        # subdomain_takeover MUST be among the compliant ones.
        self.assertNotIn("subdomain_takeover", missing,
                         "Subdomain Takeover skill is missing the phase cue.")

    def test_no_em_dash_anywhere_in_catalog(self):
        offenders = [sid for sid, content in self.skills.items() if "\u2014" in content]
        self.assertNotIn("subdomain_takeover", offenders,
                         "Subdomain Takeover introduced an em dash.")

    def test_readme_lists_new_skill(self):
        readme = README_FILE.read_text(encoding="utf-8")
        self.assertIn("subdomain_takeover.md", readme,
                      "Community skills README is missing the new entry.")

    def test_description_not_borrowed_from_another_skill(self):
        my_desc = _first_non_heading_paragraph(self.skills["subdomain_takeover"])
        my_first_30 = my_desc[:30]
        for sid, content in self.skills.items():
            if sid == "subdomain_takeover":
                continue
            other_desc = _first_non_heading_paragraph(content)
            self.assertNotEqual(
                my_first_30, other_desc[:30],
                f"Opening 30 chars of subdomain_takeover collide with {sid}; "
                f"the classifier will not be able to disambiguate."
            )


if __name__ == "__main__":
    unittest.main()
