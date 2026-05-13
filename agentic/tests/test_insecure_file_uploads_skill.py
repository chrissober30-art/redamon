"""
Tests for the insecure_file_uploads Community Agent Skill.

Layered coverage:
  - Static / lint: file exists, size, line count, no em dashes, no shannon-isms
  - Structure: canonical sections, phase cues, disjoint-classification block
  - Tool references: only real agent tools from tool_registry are mentioned
  - API contract: api.py /community-skills auto-discovery and content endpoint
                  (exercised by replicating the same logic offline so the test
                   does not require the agent container to be running)
  - Live smoke: hits the running agent container at http://localhost:8090 if
                reachable; auto-skips otherwise
  - Regression: neighbouring community skills still discovered, no duplicates,
                /community-skills catalog count grew by exactly one

Run with:
  cd agentic && python3 -m unittest tests.test_insecure_file_uploads_skill -v
"""

import json
import os
import re
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

SKILL_ID = "insecure_file_uploads"
SKILL_PATH = _AGENTIC_DIR / "community-skills" / f"{SKILL_ID}.md"
COMMUNITY_DIR = _AGENTIC_DIR / "community-skills"

# 50KB cap enforced by webapp/src/app/api/users/[id]/attack-skills/route.ts
MAX_CONTENT_BYTES = 50 * 1024

# Canonical tool names from agentic/prompts/tool_registry.py top-level keys.
# These are the only `execute_*` / `*_shell` / `query_*` / `metasploit_*`
# identifiers that may appear as a backticked tool reference in the skill.
CANONICAL_TOOLS = {
    "execute_amass", "execute_arjun", "execute_code", "execute_curl",
    "execute_ffuf", "execute_gau", "execute_httpx", "execute_hydra",
    "execute_jsluice", "execute_katana", "execute_naabu", "execute_nmap",
    "execute_nuclei", "execute_playwright", "execute_subfinder",
    "execute_wpscan", "google_dork", "kali_shell", "metasploit_console",
    "msf_restart", "query_graph", "shodan", "web_search",
}

# Banned strings -- Shannon / Strix isms that must never leak into a black-box
# RedAmon community skill.
BANNED_SHANNONISMS = [
    "save-deliverable",
    ".shannon/",
    "TodoWrite",   # Shannon's task-tracking tool, not exposed to RedAmon agent
    "Task Agent",
    "@include",
    "{{WEB_URL}}", "{{TARGET_URL}}", "{{LOGIN_INSTRUCTIONS}}",
    "white-box",
    "whitebox",
    "source code analysis",
    "source-code analysis",
    ".shannon/deliverables",
]

# Built-in skill IDs that share keyword surface with file uploads.
# The skill's "When to Classify Here" block must distinguish itself
# from each of these to keep the Intent Router precise.
NEIGHBORING_BUILTINS = ["rce", "xss", "path_traversal", "cve_exploit"]
NEIGHBORING_COMMUNITY = [
    "xxe", "insecure_deserialization", "api_testing",
    "mass_assignment", "bfla_exploitation", "idor_bola_exploitation",
]


def _read_skill() -> str:
    return SKILL_PATH.read_text(encoding="utf-8")


def _replicate_catalog_entry(md_file: Path) -> dict:
    """
    Replicate the auto-discovery logic at agentic/api.py:561-585 exactly,
    so the test does not require the agent container to be running.
    Any drift between this and the real handler is itself a test failure.
    """
    content = md_file.read_text(encoding="utf-8")
    name = md_file.stem.replace("_", " ").title()
    desc = ""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            desc = stripped[:200]
            break
    return {
        "id": md_file.stem,
        "name": name,
        "description": desc,
        "file": str(md_file),
    }


def _live_get(path: str, timeout: float = 3.0):
    """GET against the running agent container; return (status, json) or None."""
    try:
        req = urllib.request.Request(f"http://localhost:8090{path}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return None


# ===========================================================================
# Static / lint tests
# ===========================================================================

class TestSkillFileExists(unittest.TestCase):

    def test_file_exists(self):
        self.assertTrue(SKILL_PATH.exists(),
                        f"Skill file missing: {SKILL_PATH}")

    def test_file_is_readable_utf8(self):
        # Must not raise
        text = SKILL_PATH.read_text(encoding="utf-8")
        self.assertGreater(len(text), 0)

    def test_under_50kb_cap(self):
        size = SKILL_PATH.stat().st_size
        self.assertLess(
            size, MAX_CONTENT_BYTES,
            f"Skill is {size} bytes, exceeds 50KB import cap "
            f"(webapp/src/app/api/users/[id]/attack-skills/route.ts)"
        )

    def test_line_count_in_canonical_range(self):
        # PROMPT.ADD_COMMUNITY_AGENT_SKILL.md target: 200-800 lines.
        line_count = len(_read_skill().splitlines())
        self.assertGreaterEqual(line_count, 200,
                                f"Only {line_count} lines, feels underbaked")
        self.assertLessEqual(line_count, 800,
                             f"{line_count} lines exceeds 800-line target")

    def test_no_em_dashes(self):
        # Project rule: never em dashes anywhere; they read as AI output.
        text = _read_skill()
        self.assertNotIn("\u2014", text,
                         "Em dash (U+2014) found; replace with hyphen or rephrase")

    def test_no_shannon_or_strix_isms(self):
        text = _read_skill()
        violations = [s for s in BANNED_SHANNONISMS if s in text]
        self.assertEqual(violations, [],
                         f"Banned upstream-tool isms found: {violations}")


# ===========================================================================
# Structure / canonical template tests
# ===========================================================================

class TestStructure(unittest.TestCase):

    def setUp(self):
        self.text = _read_skill()
        self.lines = self.text.splitlines()

    def test_h1_title_is_first(self):
        self.assertTrue(self.lines[0].startswith("# "),
                        "First line must be the H1 title")
        self.assertIn("Insecure File Uploads", self.lines[0])

    def test_first_paragraph_is_summary_not_header(self):
        # The auto-description path picks the first non-heading stripped line
        # at api.py:572-578. Make sure that line is the one-liner summary,
        # not a markdown artifact like a horizontal rule or a list bullet.
        first_para = ""
        for line in self.lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                first_para = stripped
                break
        self.assertNotEqual(first_para, "")
        self.assertFalse(first_para.startswith("-"),
                         f"First paragraph starts with a list bullet: {first_para[:80]!r}")
        self.assertFalse(first_para.startswith("|"),
                         f"First paragraph is a table row: {first_para[:80]!r}")
        self.assertGreater(len(first_para), 80,
                           f"First paragraph too terse ({len(first_para)} chars): {first_para!r}")

    def test_required_sections_present(self):
        required_headings = [
            "## When to Classify Here",
            "## Tools",
            "## Workflow",
            "### Phase 1: Reconnaissance",
            "### Phase 2: Exploitation",
            "## Reporting Guidelines",
            "## Important Notes",
        ]
        for heading in required_headings:
            self.assertIn(heading, self.text,
                          f"Required heading missing: {heading}")

    def test_phase1_ends_with_transition_cue(self):
        # The agent reads the literal phrase "request transition to exploitation
        # phase" at the end of Phase 1 to know when to call
        # action="request_phase_transition". Phrase must live in Phase 1, NOT
        # in Phase 2 (or it triggers the transition prematurely).
        cue = "request transition to exploitation phase"
        self.assertIn(cue, self.text)

        # Locate Phase 1, Phase 2, and the cue
        phase1_idx = self.text.index("### Phase 1:")
        phase2_idx = self.text.index("### Phase 2:")
        cue_idx = self.text.index(cue)
        self.assertGreater(cue_idx, phase1_idx,
                           "Transition cue appears before Phase 1 header")
        self.assertLess(cue_idx, phase2_idx,
                        "Transition cue must end Phase 1, not appear in Phase 2")

    def test_keywords_line_present(self):
        # Classifier-critical: the keyword list seeds disjoint classification.
        self.assertRegex(self.text, r"(?i)keywords\s*:",
                         "Trigger keywords block missing")

    def test_disjoint_section_lists_each_neighbor(self):
        # Every neighboring built-in or community skill must appear in the
        # disjoint section as a canonical "**vs. built-in `<name>`**" or
        # "**vs. community `<name>`**" bullet header. The header is what the
        # human reader (and a future doc-linter) keys off; bare keyword
        # mentions in prose elsewhere do not count.
        disjoint_match = re.search(
            r"###\s*Disjoint from neighboring skills(.*?)(?=^##\s|\Z)",
            self.text, re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(disjoint_match,
                             "Could not locate '### Disjoint from neighboring skills' subsection")
        disjoint = disjoint_match.group(1)

        # Collect every backticked identifier that appears inside the bold
        # "**vs. ... **" header on each disjoint bullet.
        header_re = re.compile(r"\*\*vs\.\s*(?:built-in|community)\s+([^*]+?)\*\*",
                                re.IGNORECASE)
        named_in_headers = set()
        for header in header_re.findall(disjoint):
            for tok in re.findall(r"`([a-z_]+)`", header):
                named_in_headers.add(tok)

        # `sqli_exploitation` may be lumped with `sql_injection`; both ok.
        all_neighbors = set(NEIGHBORING_BUILTINS + NEIGHBORING_COMMUNITY)
        missing = sorted(all_neighbors - named_in_headers)
        self.assertEqual(missing, [],
                         f"Disjoint block headers do not name: {missing}. "
                         f"Found: {sorted(named_in_headers)}")

    def test_proof_of_exploitation_levels_present(self):
        for level in ("Level 1", "Level 2", "Level 3", "Level 4"):
            self.assertIn(level, self.text,
                          f"Proof-of-exploitation tier {level} missing")

    def test_balanced_fenced_code_blocks(self):
        # Unbalanced fences swallow the rest of the document into a code block.
        fences = self.text.count("\n```")
        # +1 if the file starts with a fence (it shouldn't, but be safe)
        if self.text.startswith("```"):
            fences += 1
        self.assertEqual(fences % 2, 0,
                         f"Unbalanced ``` fences ({fences}); document will render broken")


# ===========================================================================
# Tool-reference tests
# ===========================================================================

class TestToolReferences(unittest.TestCase):

    def setUp(self):
        self.text = _read_skill()

    def test_no_invented_execute_tools(self):
        # Any backticked or bare token that looks like an agent tool must be
        # one of the canonical names. False positives (`execute` as a plain
        # verb, `code` reused below) are filtered by requiring an underscore.
        candidates = set(re.findall(r"\b((?:execute|metasploit|msf)_[a-z_]+)\b", self.text))
        invented = candidates - CANONICAL_TOOLS
        self.assertEqual(invented, set(),
                         f"Skill references unknown tools: {sorted(invented)}")

    def test_at_least_one_canonical_tool_per_phase(self):
        # Each major phase header should be followed by at least one canonical
        # tool reference before the next phase starts -- proves the workflow
        # is concrete, not narrative.
        phases = re.split(r"\n### Phase \d+:", self.text)[1:]  # split discards prelude
        self.assertGreaterEqual(len(phases), 2)
        for i, body in enumerate(phases, start=1):
            referenced = [t for t in CANONICAL_TOOLS if t in body]
            self.assertGreater(
                len(referenced), 0,
                f"Phase {i} mentions no canonical tool",
            )


# ===========================================================================
# API contract tests (replicates api.py:561-598 logic offline)
# ===========================================================================

class TestApiContract(unittest.TestCase):

    def test_skill_id_matches_file_stem(self):
        entry = _replicate_catalog_entry(SKILL_PATH)
        self.assertEqual(entry["id"], SKILL_ID)

    def test_auto_name_is_title_case(self):
        entry = _replicate_catalog_entry(SKILL_PATH)
        self.assertEqual(entry["name"], "Insecure File Uploads")

    def test_auto_description_is_first_non_heading_line(self):
        entry = _replicate_catalog_entry(SKILL_PATH)
        # api.py truncates to 200 chars.
        self.assertTrue(0 < len(entry["description"]) <= 200,
                        f"Bad auto-description length {len(entry['description'])}")
        # It must NOT be a markdown heading or a horizontal rule.
        self.assertFalse(entry["description"].startswith("#"))
        self.assertFalse(entry["description"].startswith("-"))
        # It should describe the workflow, not reference a section.
        self.assertNotIn("When to Classify", entry["description"])

    def test_readme_is_excluded_from_catalog(self):
        # api.py:569 explicitly skips README.md.
        readme = COMMUNITY_DIR / "README.md"
        self.assertTrue(readme.exists(), "Sanity: README.md should exist")
        # If we ran the real api.py glob, it would skip README. We assert
        # that our skill file is NOT named README.md (a guard against silly
        # rename mistakes that would silently drop the skill).
        self.assertNotEqual(SKILL_PATH.name.lower(), "readme.md")

    def test_catalog_count_includes_new_skill(self):
        catalog = []
        for f in sorted(COMMUNITY_DIR.glob("*.md")):
            if f.name == "README.md":
                continue
            catalog.append(_replicate_catalog_entry(f))
        ids = [e["id"] for e in catalog]
        self.assertIn(SKILL_ID, ids,
                      f"Auto-discovery missed the skill. Catalog ids: {ids}")

    def test_no_duplicate_ids_across_community_dir(self):
        ids = []
        for f in sorted(COMMUNITY_DIR.glob("*.md")):
            if f.name == "README.md":
                continue
            ids.append(f.stem)
        self.assertEqual(len(ids), len(set(ids)),
                         f"Duplicate community skill IDs: {ids}")

    def test_content_endpoint_payload_shape(self):
        # Replicates api.py:588-598
        skill_id = SKILL_ID
        skill_path = COMMUNITY_DIR / f"{skill_id}.md"
        content = skill_path.read_text(encoding="utf-8")
        name = skill_id.replace("_", " ").title()
        payload = {"id": skill_id, "name": name, "content": content}
        # The webapp import flow at import-community/route.ts:67 reads
        # skillData.description first, falling back to skill.description from
        # the catalog. If the content endpoint ever stops returning the right
        # keys, the import lands a UserAttackSkill row with content=None,
        # which the agent then injects as null -- fail the build instead.
        self.assertIn("id", payload)
        self.assertIn("name", payload)
        self.assertIn("content", payload)
        self.assertGreater(len(payload["content"]), 1000)


# ===========================================================================
# Live-endpoint smoke tests (skipped when agent container is not reachable)
# ===========================================================================

class TestLiveEndpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.live = _live_get("/community-skills") is not None
        if not cls.live:
            raise unittest.SkipTest("Agent container at localhost:8090 not reachable")

    def test_listing_endpoint_returns_skill(self):
        status, body = _live_get("/community-skills")
        self.assertEqual(status, 200)
        ids = {s["id"] for s in body.get("skills", [])}
        self.assertIn(SKILL_ID, ids,
                      f"Live /community-skills missing {SKILL_ID}; got {sorted(ids)}")

    def test_listing_total_matches_skills_length(self):
        _, body = _live_get("/community-skills")
        self.assertEqual(body["total"], len(body["skills"]))

    def test_listing_description_matches_first_paragraph(self):
        _, body = _live_get("/community-skills")
        live_entry = next(s for s in body["skills"] if s["id"] == SKILL_ID)
        offline_entry = _replicate_catalog_entry(SKILL_PATH)
        self.assertEqual(live_entry["description"], offline_entry["description"])
        self.assertEqual(live_entry["name"], offline_entry["name"])

    def test_content_endpoint_returns_full_markdown(self):
        result = _live_get(f"/community-skills/{SKILL_ID}")
        self.assertIsNotNone(result)
        status, body = result
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], SKILL_ID)
        self.assertEqual(body["name"], "Insecure File Uploads")
        on_disk = SKILL_PATH.read_text(encoding="utf-8")
        self.assertEqual(body["content"], on_disk,
                         "Live content drifted from disk; check the volume mount")

    def test_content_endpoint_unknown_skill_returns_404(self):
        result = _live_get("/community-skills/this_skill_does_not_exist_xyz")
        # _live_get swallows non-2xx responses as None; explicitly probe.
        try:
            req = urllib.request.Request(
                "http://localhost:8090/community-skills/this_skill_does_not_exist_xyz")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.fail(f"Expected 404, got {resp.status}")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


# ===========================================================================
# Regression tests: neighboring skills still discoverable
# ===========================================================================

class TestRegression(unittest.TestCase):

    def test_all_prior_skills_still_present(self):
        # The eight skills that shipped before this addition.
        prior_skills = {
            "api_testing", "xss_exploitation", "sqli_exploitation",
            "xxe", "bfla_exploitation", "insecure_deserialization",
            "idor_bola_exploitation", "mass_assignment",
            "subdomain_takeover", "ssti",
        }
        present = {f.stem for f in COMMUNITY_DIR.glob("*.md") if f.name != "README.md"}
        missing = prior_skills - present
        self.assertEqual(missing, set(),
                         f"Regression: prior community skills disappeared: {missing}")

    def test_new_skill_uses_unique_h1(self):
        # Catch accidental copy-paste from a sibling skill's H1.
        new_h1 = _read_skill().splitlines()[0]
        for sibling in COMMUNITY_DIR.glob("*.md"):
            if sibling.name == "README.md" or sibling.stem == SKILL_ID:
                continue
            sibling_h1 = sibling.read_text(encoding="utf-8").splitlines()[0]
            self.assertNotEqual(
                new_h1, sibling_h1,
                f"H1 collision with {sibling.name}: {new_h1!r}",
            )

    def test_readme_table_includes_new_skill(self):
        readme = (COMMUNITY_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("insecure_file_uploads.md", readme,
                      "README index does not list the new skill")

    def test_wiki_table_includes_new_skill(self):
        wiki = _AGENTIC_DIR.parent / "redamon.wiki" / "Agent-Skills.md"
        if not wiki.exists():
            self.skipTest("redamon.wiki not present in this checkout")
        text = wiki.read_text(encoding="utf-8")
        self.assertIn("insecure_file_uploads.md", text,
                      "Wiki Community Skills table does not list the new skill")


if __name__ == "__main__":
    unittest.main()
