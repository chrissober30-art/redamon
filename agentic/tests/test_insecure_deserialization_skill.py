"""
Tests for the Insecure Deserialization community Agent Skill.

Layers:
  - Unit:        file-on-disk shape (canonical sections, line/byte limits, no em dashes,
                 description-extraction simulation that mirrors agentic/api.py:572-578),
                 tool_registry source loads cleanly and references phpggc.
  - Integration: live agent container serves the skill via /community-skills and
                 /community-skills/<id>.
  - Regression:  pre-existing community skills are still served and the disjointness
                 against the rce built-in is explicit in the opening blob.

Run on host:
    python3 -m pytest agentic/tests/test_insecure_deserialization_skill.py -v
or, against the live container endpoints, just:
    python3 agentic/tests/test_insecure_deserialization_skill.py

The integration tests degrade to skip when the agent container is unreachable
(useful when iterating on the .md without docker running).
"""

import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = _REPO_ROOT / "agentic" / "community-skills"
_SKILL_ID = "insecure_deserialization"
_SKILL_FILE = _SKILLS_DIR / f"{_SKILL_ID}.md"
_REGISTRY_FILE = _REPO_ROOT / "agentic" / "prompts" / "tool_registry.py"
_DOCKERFILE = _REPO_ROOT / "mcp" / "kali-sandbox" / "Dockerfile"
_README = _SKILLS_DIR / "README.md"
_WIKI = _REPO_ROOT / "redamon.wiki" / "Agent-Skills.md"

# These are the 7 real community-skill .md files at time of writing. Used by
# the regression test to make sure adding insecure_deserialization didn't
# break catalog discovery for any sibling.
_EXPECTED_SIBLING_IDS = {
    "api_testing",
    "sqli_exploitation",
    "xss_exploitation",
    "xxe",
    "bfla_exploitation",
    "idor_bola_exploitation",
    _SKILL_ID,
}


def _agent_endpoint() -> str:
    """
    Pick the agent endpoint. From inside the docker network the service is
    `agent:8080`; from the host it is exposed on `${AGENT_PORT:-8090}` per
    docker-compose.yml. AGENT_API_URL beats both if explicitly set.
    """
    if os.environ.get("AGENT_API_URL"):
        return os.environ["AGENT_API_URL"]
    return f"http://localhost:{os.environ.get('AGENT_PORT', '8090')}"


def _fetch_json(url: str, timeout: float = 5.0):
    """
    GET + parse JSON. Returns the decoded body even on 4xx/5xx so tests can
    inspect FastAPI error envelopes (api.py:594 returns JSONResponse(..., 404)).
    Returns None only when the server is unreachable / wire-level fails / body
    is non-JSON.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        # FastAPI 4xx still ships a JSON body; surface it.
        try:
            body = e.read().decode("utf-8")
        except Exception:
            return None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def _agent_reachable() -> bool:
    return _fetch_json(f"{_agent_endpoint()}/health") is not None or \
        _fetch_json(f"{_agent_endpoint()}/community-skills") is not None


class TestSkillFileShape(unittest.TestCase):
    """Pure-disk checks. No docker, no network."""

    @classmethod
    def setUpClass(cls):
        if not _SKILL_FILE.exists():
            raise unittest.SkipTest(f"{_SKILL_FILE} missing")
        cls.text = _SKILL_FILE.read_text(encoding="utf-8")
        cls.lines = cls.text.splitlines()

    def test_size_under_import_cap(self):
        """
        webapp import caps content at MAX_CONTENT_SIZE = 50 * 1024 = 51200
        bytes (webapp/.../attack-skills/route.ts line 29 + line 65). Validate
        against the real constant, not an approximation.
        """
        cap = 50 * 1024
        self.assertLess(len(self.text), cap,
                        f"Skill is {len(self.text)} bytes; webapp import caps at {cap}")

    def test_target_line_band(self):
        """Brief asks for 200-800 lines."""
        self.assertGreaterEqual(len(self.lines), 200,
                                f"Only {len(self.lines)} lines; under-baked vs. brief target")
        self.assertLessEqual(len(self.lines), 800,
                             f"{len(self.lines)} lines; over the 800-line target")

    def test_no_em_dashes(self):
        """Project-wide rule: em dashes look AI-generated."""
        offenders = [(i + 1, ln) for i, ln in enumerate(self.lines) if "\u2014" in ln]
        self.assertEqual(offenders, [],
                         f"Em dashes found: {offenders}")

    def test_canonical_sections_present(self):
        for header in (
            "## When to Classify Here",
            "## Workflow",
            "### Phase 1: Reconnaissance (Informational)",
            "### Phase 2: Exploitation",
            "### Phase 3: Post-Exploitation",
            "## Reporting Guidelines",
            "## Important Notes",
        ):
            self.assertIn(header, self.text, f"Missing canonical section: {header!r}")

    def test_phase_transition_cue_present(self):
        """Exact-string the agent looks for to call request_phase_transition."""
        self.assertIn("request transition to exploitation phase", self.text,
                      "Phase 1 must end with the literal 'request transition to "
                      "exploitation phase' cue or the agent will not advance phases")

    def test_phase_transition_cue_in_phase_1(self):
        """The cue must sit inside Phase 1, not buried later."""
        phase1_start = self.text.index("### Phase 1:")
        phase2_start = self.text.index("### Phase 2:")
        phase1_block = self.text[phase1_start:phase2_start]
        self.assertIn("request transition to exploitation phase", phase1_block,
                      "Cue must live inside Phase 1 (before Phase 2 header)")

    def test_real_agent_tools_only(self):
        """Every tool-name reference must be one the agent actually has."""
        valid = {
            "query_graph", "kali_shell", "execute_curl", "execute_code",
            "execute_playwright", "execute_nuclei", "execute_hydra",
            "metasploit_console", "execute_httpx", "execute_naabu",
            "execute_jsluice",
        }
        # Match `xxx_yyy` identifiers that look like tool names (snake_case starting w/ verb).
        candidates = set(re.findall(r"`(execute_[a-z_]+|kali_shell|query_graph|metasploit_console)`", self.text))
        bogus = candidates - valid
        self.assertEqual(bogus, set(),
                         f"Workflow references non-existent tool names: {bogus}")

    def test_description_extraction_mirror(self):
        """
        Mirror agentic/api.py:572-578 exactly: take the first stripped non-'#'
        line, slice to 200 chars, and verify the result is informative.
        """
        desc = ""
        for line in self.lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                desc = stripped[:200]
                break
        self.assertGreater(len(desc), 80, "Description too short for the classifier")
        self.assertLessEqual(len(desc), 200, "Should be exactly the api.py slice")
        # The description has to make the deserialization angle obvious in the first 200 chars.
        self.assertRegex(desc.lower(), r"deserial",
                         f"Auto-description must surface 'deserial...': {desc!r}")

    def test_classifier_first_500_chars_carry_distinction(self):
        """
        When no description is provided in the import dialog, the classifier
        falls back to content[:500] (classification.py:222-224). Verify that
        slice contains both the rce-disjoint hint AND the language coverage
        signal so neighbour overlap is resolved.
        """
        first_500 = self.text[:500]
        self.assertRegex(first_500.lower(), r"\brce\b",
                         "First 500 chars must reference 'rce' to disambiguate from rce built-in")
        # At least 3 of the 5 language tracks should be visible early
        languages = ("java", "php", "python", ".net", "ruby")
        hits = sum(1 for lang in languages if lang in first_500.lower())
        self.assertGreaterEqual(hits, 3,
                                f"Only {hits}/5 language tracks visible in first 500 chars: {first_500!r}")

    def test_disjointness_section_names_neighbors(self):
        """The classification section must explicitly distinguish from key neighbours."""
        when_idx = self.text.index("## When to Classify Here")
        workflow_idx = self.text.index("## Workflow")
        block = self.text[when_idx:workflow_idx].lower()
        for neighbour in ("rce", "sql_injection", "path_traversal", "ssrf", "cve_exploit"):
            self.assertIn(neighbour, block,
                          f"Disjointness against '{neighbour}' must be spelled out in 'When to Classify Here'")

    def test_keyword_block_present(self):
        when_idx = self.text.index("## When to Classify Here")
        workflow_idx = self.text.index("## Workflow")
        block = self.text[when_idx:workflow_idx].lower()
        self.assertIn("keywords", block, "Need an explicit 'Keywords' line")
        # Must surface the most discriminative tokens
        for kw in ("ysoserial", "phpggc", "pickle", "viewstate", "marshal"):
            self.assertIn(kw, block, f"Discriminative keyword missing: {kw}")


class TestToolRegistry(unittest.TestCase):
    """tool_registry.py is plain dicts; load it directly and validate."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("_tr", _REGISTRY_FILE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.registry = mod.TOOL_REGISTRY

    def test_kali_shell_documents_phpggc(self):
        desc = self.registry["kali_shell"]["description"]
        self.assertIn("phpggc", desc,
                      "tool_registry kali_shell must document phpggc since it ships in the image")

    def test_phpggc_doc_includes_chain_examples(self):
        desc = self.registry["kali_shell"]["description"]
        self.assertIn("Monolog/RCE1", desc, "Doc should give a representative chain example")
        self.assertIn("Laravel", desc, "Doc should mention Laravel framework chains")
        self.assertIn("phar", desc.lower(), "Doc should mention PHAR mode")

    def test_ysoserial_still_documented(self):
        """Regression: previous integration must remain."""
        self.assertIn("ysoserial", self.registry["kali_shell"]["description"])


class TestIndexUpdates(unittest.TestCase):

    def test_community_readme_lists_skill(self):
        text = _README.read_text(encoding="utf-8")
        self.assertIn(f"({_SKILL_ID}.md)", text,
                      "agentic/community-skills/README.md must link to the new file")

    def test_wiki_lists_skill(self):
        if not _WIKI.exists():
            self.skipTest("redamon.wiki/ not checked out (sub-repo)")
        text = _WIKI.read_text(encoding="utf-8")
        self.assertIn(f"{_SKILL_ID}.md", text,
                      "wiki Agent-Skills.md Community Skills table must include the new entry")


class TestDockerfileWiring(unittest.TestCase):
    """Pure text checks against the Kali Dockerfile -- no docker exec required."""

    @classmethod
    def setUpClass(cls):
        cls.text = _DOCKERFILE.read_text(encoding="utf-8")

    def test_phpggc_install_present(self):
        self.assertIn("phpggc.git", self.text,
                      "Kali Dockerfile must clone phpggc")
        self.assertIn("/usr/local/bin/phpggc", self.text,
                      "phpggc binary must end up on PATH")

    def test_php_cli_dependency_pulled(self):
        self.assertIn("php-cli", self.text,
                      "phpggc requires php-cli; the install must include it")

    def test_ysoserial_install_still_present(self):
        """Regression: previous addition must not have been displaced."""
        self.assertIn("ysoserial.jar", self.text)
        self.assertIn("/usr/local/bin/ysoserial", self.text)


@unittest.skipUnless(_agent_reachable(), "agent container not reachable")
class TestAgentEndpointIntegration(unittest.TestCase):
    """Exercises the live FastAPI endpoints in the agent container."""

    def test_skill_appears_in_catalog(self):
        catalog = _fetch_json(f"{_agent_endpoint()}/community-skills")
        self.assertIsNotNone(catalog, "GET /community-skills failed")
        ids = {s["id"] for s in catalog["skills"]}
        self.assertIn(_SKILL_ID, ids,
                      f"Catalog missing {_SKILL_ID!r}; got {sorted(ids)}")

    def test_catalog_description_is_informative(self):
        catalog = _fetch_json(f"{_agent_endpoint()}/community-skills")
        entry = next(s for s in catalog["skills"] if s["id"] == _SKILL_ID)
        self.assertGreater(len(entry["description"]), 80,
                           f"Auto-description too short: {entry['description']!r}")
        self.assertLessEqual(len(entry["description"]), 200,
                             "API truncates at 200; we should be at the cap")
        self.assertIn("deserial", entry["description"].lower())

    def test_skill_content_endpoint_serves_full_file(self):
        payload = _fetch_json(f"{_agent_endpoint()}/community-skills/{_SKILL_ID}")
        self.assertIsNotNone(payload, "GET /community-skills/<id> failed")
        self.assertEqual(payload["id"], _SKILL_ID)
        self.assertIn("Insecure Deserialization Attack Skill", payload["content"])
        # Must match disk byte-for-byte (volume mount is read-only).
        on_disk = _SKILL_FILE.read_text(encoding="utf-8")
        self.assertEqual(payload["content"], on_disk,
                         "Endpoint content drifted from on-disk file")

    def test_unknown_skill_id_returns_404_payload(self):
        # Mirrors api.py:594-595 behaviour (returns 404 with error JSON).
        catalog = _fetch_json(f"{_agent_endpoint()}/community-skills/insecure_deserialization_xyz_nope")
        self.assertIsNotNone(catalog)
        self.assertIn("error", catalog)


@unittest.skipUnless(_agent_reachable(), "agent container not reachable")
class TestCommunityCatalogRegression(unittest.TestCase):
    """Sibling community skills must still be discoverable after our addition."""

    def test_all_expected_community_skills_listed(self):
        catalog = _fetch_json(f"{_agent_endpoint()}/community-skills")
        ids = {s["id"] for s in catalog["skills"]}
        missing = _EXPECTED_SIBLING_IDS - ids
        self.assertEqual(missing, set(),
                         f"Expected community skills missing from catalog: {missing}; full catalog: {sorted(ids)}")

    def test_no_readme_pollution(self):
        """README.md must NOT show up as a skill (excluded at api.py:569)."""
        catalog = _fetch_json(f"{_agent_endpoint()}/community-skills")
        ids = {s["id"] for s in catalog["skills"]}
        self.assertNotIn("README", ids)
        self.assertNotIn("readme", ids)


def _docker_exec_phpggc_present() -> bool:
    """Check the live kali-sandbox container for phpggc. Used by the smoke test."""
    try:
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "kali-sandbox", "which", "phpggc"],
            cwd=str(_REPO_ROOT), capture_output=True, text=True, timeout=15,
        )
        return proc.returncode == 0 and "/phpggc" in proc.stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False


class TestKaliSandboxSmoke(unittest.TestCase):
    """
    Smoke check: phpggc should be on PATH inside kali-sandbox AFTER the image
    is rebuilt. If the user has not yet run `docker compose --profile tools
    build kali-sandbox`, this test is informational rather than failing -- the
    Dockerfile change is the deliverable, not a runtime guarantee on a stale
    image.
    """

    def test_phpggc_on_path_after_rebuild(self):
        if not _docker_exec_phpggc_present():
            self.skipTest("phpggc not yet in running kali-sandbox image -- "
                          "rebuild required: `docker compose --profile tools "
                          "build kali-sandbox && docker compose up -d kali-sandbox`")
        # If it IS present, also confirm it executes:
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "kali-sandbox", "phpggc", "-l"],
            cwd=str(_REPO_ROOT), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0,
                         f"phpggc -l failed: stderr={proc.stderr!r}")
        self.assertIn("Monolog", proc.stdout, "phpggc -l should list Monolog chains")


if __name__ == "__main__":
    unittest.main(verbosity=2)
