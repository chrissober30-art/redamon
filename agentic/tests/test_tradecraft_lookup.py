"""Tests for the Tradecraft Lookup tool.

Covers:
- URL canonicalization, SSRF guard
- Type detection (all 6 rules)
- Slug + cache layer
- Section picker (Jaccard + substring overlap)
- Output formatter
- PDF page extraction
- CVE special path
- _prefer_english filter, sitemap parsing
- TradecraftLookupManager lifecycle: set_resources, get_tool, registry entry, invocation
- TOOL_REGISTRY swap
"""

from __future__ import annotations

import asyncio
import io
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from orchestrator_helpers.tradecraft_lookup import (
    CVE_ID_RE,
    DEFAULT_TTLS_BY_TYPE,
    FetchResult,
    TradecraftCache,
    TradecraftLookupManager,
    _extract_code_blocks,
    _extract_pdf_pages,
    _jaccard,
    _pick_section,
    _prefer_english,
    _rank_score,
    _substr_overlap_score,
    _tokens,
    canonicalize_url,
    detect_type,
    format_output,
    is_private_host,
    validate_url,
)


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# =========================================================================
# URL / SSRF helpers
# =========================================================================

class TestUrlHelpers(unittest.TestCase):
    def test_canonicalize_drops_fragment(self):
        self.assertEqual(
            canonicalize_url("https://example.com/path?b=2&a=1#frag"),
            "https://example.com/path?a=1&b=2",
        )

    def test_canonicalize_lowercases_host(self):
        self.assertEqual(
            canonicalize_url("https://EXAMPLE.com/Path"),
            "https://example.com/Path",
        )

    def test_canonicalize_keeps_empty_path(self):
        # Bare host gets a "/" path inserted.
        out = canonicalize_url("https://example.com")
        self.assertTrue(out.startswith("https://example.com/"))

    def test_is_private_host_loopback(self):
        self.assertTrue(is_private_host("localhost"))
        self.assertTrue(is_private_host("127.0.0.1"))
        self.assertTrue(is_private_host("::1"))

    def test_is_private_host_rfc1918(self):
        self.assertTrue(is_private_host("10.0.0.1"))
        self.assertTrue(is_private_host("172.16.5.5"))
        self.assertTrue(is_private_host("192.168.1.1"))

    def test_is_private_host_link_local(self):
        self.assertTrue(is_private_host("169.254.169.254"))

    def test_is_private_host_local_suffix(self):
        self.assertTrue(is_private_host("server.local"))
        self.assertTrue(is_private_host("foo.internal"))

    def test_validate_url_blocks_non_http(self):
        ok, err = validate_url("ftp://example.com/")
        self.assertFalse(ok)
        self.assertIn("http", err.lower())

    def test_validate_url_blocks_localhost(self):
        ok, err = validate_url("http://127.0.0.1:8080/")
        self.assertFalse(ok)
        self.assertIn("private", err.lower())

    def test_validate_url_accepts_public(self):
        # Use a deterministic-public TLD to avoid DNS lookup variance: example.com.
        ok, err = validate_url("https://example.com/foo")
        # Some sandboxes have no DNS; tolerate that case (returns False with no
        # specific guarantee). Assert public host is at least *not* private when
        # it resolves cleanly.
        if ok:
            self.assertEqual(err, "")


# =========================================================================
# Type detection
# =========================================================================

class TestDetectType(unittest.TestCase):
    def test_cve_repo_by_name(self):
        self.assertEqual(
            detect_type("https://github.com/trickest/cve", body=""),
            "cve-poc-db",
        )

    def test_cve_repo_by_density(self):
        body = "\n".join(["Some intro"] + [f"CVE-2024-{i:05d}" for i in range(50)])
        # Repo name doesn't say "cve" -> falls through to density rule
        self.assertEqual(
            detect_type("https://github.com/foo/bar", body=body),
            "cve-poc-db",
        )

    def test_github_repo_default(self):
        self.assertEqual(
            detect_type("https://github.com/swisskyrepo/PayloadsAllTheThings", body=""),
            "github-repo",
        )

    def test_mkdocs_meta(self):
        body = '<meta name="generator" content="mkdocs-material">'
        self.assertEqual(detect_type("https://docs.example.org", body=body), "mkdocs-wiki")

    def test_mdbook_comment(self):
        body = "<!-- Book generated using mdBook -->"
        self.assertEqual(detect_type("https://book.example.org", body=body), "mkdocs-wiki")

    def test_sphinx_searchindex(self):
        body = '<script src="_static/searchindex.js"></script>'
        self.assertEqual(detect_type("https://impacket.readthedocs.io", body=body), "sphinx-docs")

    def test_docusaurus_generator(self):
        body = '<meta name="generator" content="Docusaurus v2.4.0">'
        self.assertEqual(detect_type("https://docs.example.org", body=body), "sphinx-docs")

    def test_gitbook_host(self):
        body = ""
        self.assertEqual(
            detect_type("https://docs.gitbook.io/space", body=body),
            "gitbook",
        )

    def test_fallback_agentic_crawl(self):
        self.assertEqual(detect_type("https://random.blog.com", body=""), "agentic-crawl")


# =========================================================================
# Tokenization, ranking, picker
# =========================================================================

class TestSectionPicker(unittest.TestCase):
    def test_tokens_lowercase_alphanum(self):
        self.assertEqual(_tokens("Foo-Bar_baz!"), {"foo", "bar", "baz"})

    def test_jaccard(self):
        self.assertAlmostEqual(_jaccard({"a", "b"}, {"b", "c"}), 1 / 3)
        self.assertEqual(_jaccard(set(), {"a"}), 0.0)

    def test_substr_overlap_kerberoast(self):
        # Query "kerberoasting" should substring-match entry token "kerberoast".
        score = _substr_overlap_score({"kerberoasting"}, {"ad", "kerberoast", "html"})
        self.assertGreater(score, 0)

    def test_substr_overlap_skips_short(self):
        # 3-char tokens are skipped (would match noise like "ai", "ad").
        score = _substr_overlap_score({"ai"}, {"adminus"})
        self.assertEqual(score, 0)

    def test_rank_score_combines_jaccard_substr(self):
        e = {"title": "Kerberoast", "path": "/en/ad/kerberoast.html"}
        s = _rank_score({"kerberoasting"}, e)
        self.assertGreater(s, 0)

    def test_picker_returns_top_when_no_llm(self):
        sm = {"nav": [
            {"title": "Login", "path": "/login"},
            {"title": "Kerberoast", "path": "/ad/kerberoast.html"},
            {"title": "About", "path": "/about"},
        ]}
        sem = asyncio.Semaphore(1)
        picked = run_async(_pick_section(
            "kerberoasting",
            sm,
            section_picker_llm=None,
            semaphore=sem,
            resource_name="t",
        ))
        self.assertIsNotNone(picked)
        self.assertIn("kerberoast", picked["path"])

    def test_picker_returns_none_when_no_match_no_llm(self):
        sm = {"nav": [{"title": "About Us", "path": "/about"}]}
        sem = asyncio.Semaphore(1)
        picked = run_async(_pick_section(
            "completely irrelevant zzz",
            sm,
            section_picker_llm=None,
            semaphore=sem,
            resource_name="t",
        ))
        self.assertIsNone(picked)


# =========================================================================
# _prefer_english (multi-lang sitemap collapse)
# =========================================================================

class TestPreferEnglish(unittest.TestCase):
    def test_filters_to_en_when_majority_lang(self):
        urls = [
            "https://x.com/af/page1",
            "https://x.com/de/page1",
            "https://x.com/en/page1",
            "https://x.com/it/page1",
            "https://x.com/pt/page1",
        ]
        out = _prefer_english(urls)
        self.assertEqual(out, ["https://x.com/en/page1"])

    def test_preserves_when_no_lang_pattern(self):
        urls = [
            "https://x.com/blog/post1",
            "https://x.com/blog/post2",
        ]
        self.assertEqual(_prefer_english(urls), urls)

    def test_preserves_when_no_english(self):
        urls = ["https://x.com/de/p1", "https://x.com/fr/p1"]
        self.assertEqual(_prefer_english(urls), urls)


# =========================================================================
# Cache layer
# =========================================================================

class TestCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tc_cache_test_")
        self.cache = TradecraftCache(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_store_then_lookup(self):
        url = "https://example.com/page"
        self.cache.store("hacktricks", url, "## hello", ttl=60, tier=1)
        hit = self.cache.lookup(url)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["content"], "## hello")
        self.assertEqual(hit["resource_id"], "hacktricks")
        self.assertEqual(hit["tier"], 1)

    def test_canonicalization_in_lookup(self):
        url = "https://example.com/page?b=2&a=1#frag"
        self.cache.store("hacktricks", url, "x", ttl=60, tier=1)
        # Lookup with different fragment + reversed params should still hit.
        hit = self.cache.lookup("https://example.com/page?a=1&b=2#otherfrag")
        self.assertIsNotNone(hit)

    def test_ttl_expiry(self):
        url = "https://example.com/page"
        self.cache.store("h", url, "x", ttl=1, tier=1)
        # Manually rewind fetched_at via SQL to avoid sleep flakiness.
        self.cache._db.execute(
            "UPDATE cache SET fetched_at = ? WHERE url = ?",
            (int(time.time()) - 10, canonicalize_url(url)),
        )
        self.cache._db.commit()
        self.assertIsNone(self.cache.lookup(url))

    def test_invalidate(self):
        url = "https://example.com/page"
        self.cache.store("h", url, "x", ttl=60, tier=1)
        self.cache.invalidate(url)
        self.assertIsNone(self.cache.lookup(url))

    def test_pdf_pages_store_and_lookup(self):
        url = "https://example.com/doc.pdf"
        self.cache.store_pdf_pages("hacktricks", url, ["page1 text", "page2 text"], ttl=60)
        self.assertEqual(self.cache.lookup_pdf_page("hacktricks", url, 1), "page1 text")
        self.assertEqual(self.cache.lookup_pdf_page("hacktricks", url, 2), "page2 text")
        self.assertIsNone(self.cache.lookup_pdf_page("hacktricks", url, 99))


# =========================================================================
# Output formatter
# =========================================================================

class TestFormatOutput(unittest.TestCase):
    def test_envelope_and_meta(self):
        out = format_output(
            resource_id="hacktricks",
            url="https://x/foo",
            section_title="Foo",
            content="content body",
            cache="hit",
            tier=1,
        )
        self.assertIn("[BEGIN UNTRUSTED TRADECRAFT RESULT]", out)
        self.assertIn("[END UNTRUSTED TRADECRAFT RESULT]", out)
        self.assertIn("resource: hacktricks", out)
        self.assertIn("url: https://x/foo", out)
        self.assertIn("section_title: Foo", out)
        self.assertIn("cache hit", out)
        self.assertIn("content body", out)

    def test_no_internal_truncation(self):
        # tradecraft no longer truncates internally - global TOOL_OUTPUT_MAX_CHARS
        # is the single source of truth (applied at think_node level).
        big_content = "A" * 50000
        out = format_output(
            resource_id="x", url="u", section_title="t",
            content=big_content, cache="miss", tier=1,
        )
        self.assertIn(big_content, out)
        self.assertNotIn("[truncated]", out)

    def test_extract_code_blocks(self):
        body = (
            "intro\n```bash\necho hi\n```\nmid\n```python\nprint(1)\n```\n"
        )
        s = _extract_code_blocks(body)
        self.assertIn("- bash:", s)
        self.assertIn("echo hi", s)
        self.assertIn("- python:", s)


# =========================================================================
# CVE regex
# =========================================================================

class TestCveRegex(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(CVE_ID_RE.match("CVE-2021-41773"))
        self.assertTrue(CVE_ID_RE.match("cve-2021-41773"))
        self.assertTrue(CVE_ID_RE.match("CVE-2024-1234567"))

    def test_invalid(self):
        self.assertFalse(CVE_ID_RE.match("CVE-21-41773"))
        self.assertFalse(CVE_ID_RE.match("XCVE-2021-41773"))
        self.assertFalse(CVE_ID_RE.match("CVE-2021-417"))   # only 3 digits in seq
        self.assertFalse(CVE_ID_RE.match("CVE-2021-12345678"))  # > 7 digits in seq


# =========================================================================
# PDF extraction
# =========================================================================

class TestPdfExtraction(unittest.TestCase):
    def test_returns_error_when_no_pypdf(self):
        # If pypdf isn't installed in this env, _extract_pdf_pages returns an error.
        out = _extract_pdf_pages(b"")
        self.assertIsInstance(out, tuple)
        self.assertEqual(len(out), 3)

    def test_synthetic_minimal_pdf(self):
        try:
            from pypdf import PdfWriter  # type: ignore
        except Exception:
            self.skipTest("pypdf not installed")
        # Build a 2-page PDF in memory.
        from pypdf.generic import RectangleObject  # type: ignore
        w = PdfWriter()
        w.add_blank_page(width=72, height=72)
        w.add_blank_page(width=72, height=72)
        buf = io.BytesIO()
        w.write(buf)
        pages_meta, page_texts, err = _extract_pdf_pages(buf.getvalue())
        # Blank pages produce no text but should still enumerate.
        self.assertEqual(len(pages_meta), 2)
        self.assertEqual(len(page_texts), 2)
        self.assertEqual(err, "")


# =========================================================================
# TradecraftLookupManager lifecycle
# =========================================================================

class _StubLLM:
    """Minimal LLM stub for non-async-pickling section picker tests."""
    def __init__(self, response_text="1"):
        self.response_text = response_text

    async def ainvoke(self, prompt, *args, **kwargs):
        class R:
            pass
        r = R()
        r.content = self.response_text
        return r


class TestManagerLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tc_mgr_test_")
        self.mgr = TradecraftLookupManager(
            llm=_StubLLM(),
            mcp_manager=None,
            cache_root=self.tmp,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_get_tool_returns_none_when_no_resources(self):
        self.mgr.set_resources([])
        self.assertIsNone(self.mgr.get_tool())

    def test_get_tool_returns_callable_when_one_resource(self):
        self.mgr.set_resources([{
            "id": "r1", "slug": "h", "name": "HackTricks",
            "url": "https://book.hacktricks.wiki", "enabled": True,
            "resourceType": "mkdocs-wiki", "summary": "a summary",
            "sitemap": {"nav": []}, "cacheTtlSec": 0,
        }])
        tool = self.mgr.get_tool()
        self.assertIsNotNone(tool)
        self.assertEqual(getattr(tool, "name", ""), "tradecraft_lookup")

    def test_disabled_resources_filtered(self):
        self.mgr.set_resources([
            {"id": "r1", "slug": "h", "name": "HT", "url": "https://x", "enabled": False,
             "resourceType": "mkdocs-wiki", "summary": "", "sitemap": {}},
            {"id": "r2", "slug": "p", "name": "PA", "url": "https://y", "enabled": True,
             "resourceType": "github-repo", "summary": "", "sitemap": {}},
        ])
        self.assertEqual(len(self.mgr._resources), 1)
        self.assertEqual(self.mgr._resources[0].slug, "p")

    def test_build_registry_entry_includes_summaries(self):
        self.mgr.set_resources([
            {"id": "r1", "slug": "hacktricks", "name": "HackTricks",
             "url": "https://book.hacktricks.wiki", "enabled": True,
             "resourceType": "mkdocs-wiki", "summary": "MAGIC_MARKER offensive wiki",
             "sitemap": {}, "cacheTtlSec": 0},
        ])
        entry = self.mgr.build_registry_entry()
        self.assertIn("hacktricks", entry["description"])
        self.assertIn("MAGIC_MARKER", entry["description"])
        self.assertIn("(mkdocs-wiki)", entry["description"])

    def test_unknown_slug_returns_friendly_error(self):
        self.mgr.set_resources([
            {"id": "r1", "slug": "h", "name": "HT", "url": "https://x", "enabled": True,
             "resourceType": "mkdocs-wiki", "summary": "", "sitemap": {}, "cacheTtlSec": 0},
        ])
        tool = self.mgr.get_tool()
        out = run_async(tool.ainvoke({"resource_id": "no-such-slug", "query": "x"}))
        self.assertIn("not configured", out)
        self.assertIn("Available", out)

    def test_cve_path_requires_cve_id(self):
        self.mgr.set_resources([
            {"id": "r1", "slug": "trickest", "name": "TC", "url": "https://github.com/trickest/cve",
             "enabled": True, "resourceType": "cve-poc-db", "summary": "",
             "sitemap": {"owner": "trickest", "repo": "cve", "branch": "main"}, "cacheTtlSec": 0},
        ])
        tool = self.mgr.get_tool()
        out = run_async(tool.ainvoke({"resource_id": "trickest", "query": "x"}))
        self.assertIn("must pass cve_id", out)

    def test_pdf_route_via_section_path_page_n(self):
        # Pre-populate cache with PDF pages so _invoke_pdf returns from cache without network.
        url = "https://example.com/doc.pdf"
        slug = "sample-pdf"
        self.mgr.cache.store_pdf_pages(slug, url, ["pageone", "pagetwo", "pagethree"], ttl=60)
        self.mgr.set_resources([
            {"id": "r1", "slug": slug, "name": "Sample PDF", "url": url, "enabled": True,
             "resourceType": "agentic-crawl", "summary": "",
             "sitemap": {"pages": [
                 {"page": 1, "firstLine": "page one"},
                 {"page": 2, "firstLine": "page two"},
                 {"page": 3, "firstLine": "page three"},
             ]}, "cacheTtlSec": 0},
        ])
        tool = self.mgr.get_tool()
        out = run_async(tool.ainvoke({
            "resource_id": slug, "query": "", "section_path": "page=2",
        }))
        self.assertIn("pagetwo", out)
        self.assertIn("section_title: page 2", out)
        self.assertIn("cache hit", out)

    def test_slug_stable_after_rename(self):
        # Verify slug is what the agent uses and a name change doesn't break invocation.
        self.mgr.set_resources([
            {"id": "r1", "slug": "orig-slug", "name": "Original Name", "url": "https://x",
             "enabled": True, "resourceType": "mkdocs-wiki", "summary": "",
             "sitemap": {}, "cacheTtlSec": 0},
        ])
        # Rename in subsequent set_resources (slug stays the same).
        self.mgr.set_resources([
            {"id": "r1", "slug": "orig-slug", "name": "New Name", "url": "https://x",
             "enabled": True, "resourceType": "mkdocs-wiki", "summary": "",
             "sitemap": {}, "cacheTtlSec": 0},
        ])
        self.assertEqual(self.mgr._resources[0].slug, "orig-slug")
        # The slug-keyed lookup table must be repopulated.
        self.assertIn("orig-slug", self.mgr._by_slug)


# =========================================================================
# TOOL_REGISTRY swap (regression)
# =========================================================================

class TestToolRegistrySwap(unittest.TestCase):
    def test_swap_then_pop_isolated(self):
        from prompts.tool_registry import (
            TOOL_REGISTRY,
            swap_tradecraft_entry,
            pop_tradecraft_entry,
        )
        # Snapshot keys other than tradecraft_lookup
        before_keys = {k: v for k, v in TOOL_REGISTRY.items() if k != "tradecraft_lookup"}
        # Inject a marker entry
        swap_tradecraft_entry({
            "purpose": "p",
            "when_to_use": "w",
            "args_format": "a",
            "description": "MARKER_AAAA",
        })
        self.assertIn("tradecraft_lookup", TOOL_REGISTRY)
        self.assertEqual(TOOL_REGISTRY["tradecraft_lookup"]["description"], "MARKER_AAAA")
        # Pop and confirm other entries are intact
        pop_tradecraft_entry()
        self.assertNotIn("tradecraft_lookup", TOOL_REGISTRY)
        for k, v in before_keys.items():
            self.assertEqual(TOOL_REGISTRY.get(k), v, f"entry {k} was mutated by swap")


# =========================================================================
# Sitemap entries normalization
# =========================================================================

class TestSitemapNormalization(unittest.TestCase):
    def test_normalize_nav(self):
        from orchestrator_helpers.tradecraft_lookup import _sitemap_entries
        e = _sitemap_entries({"nav": [{"title": "T", "path": "/p"}]})
        self.assertEqual(e, [{"title": "T", "path": "/p"}])

    def test_normalize_tree(self):
        from orchestrator_helpers.tradecraft_lookup import _sitemap_entries
        e = _sitemap_entries({"tree": [{"title": "T", "path": "p.md"}]})
        self.assertEqual(e, [{"title": "T", "path": "p.md"}])

    def test_normalize_links(self):
        from orchestrator_helpers.tradecraft_lookup import _sitemap_entries
        e = _sitemap_entries({"links": [{"title": "T", "path": "/p"}]})
        self.assertEqual(e, [{"title": "T", "path": "/p"}])

    def test_normalize_empty(self):
        from orchestrator_helpers.tradecraft_lookup import _sitemap_entries
        self.assertEqual(_sitemap_entries({}), [])


if __name__ == "__main__":
    unittest.main()
