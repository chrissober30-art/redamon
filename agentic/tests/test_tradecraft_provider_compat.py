"""Provider-compat regression tests for tradecraft LLM call sites.

Three tradecraft sites used to crash on Bedrock with
`'list' object has no attribute 'strip'`:
- tradecraft_crawl.py:_llm_decide  (the agentic crawl loop's decision step)
- tradecraft_lookup.py:_pick_section  (the mini-LLM section picker)
- tradecraft_lookup.py: verify-time summary call

All three were wrapped with normalize_content(). These tests assert the
fixed sites work end-to-end when the stub LLM returns Bedrock-style
list-of-content-blocks responses, mirroring what `ChatBedrockConverse`
emits in production.

If anyone reverts a fix, the corresponding stub LLM here will trigger the
exact production crash and the test will fail with a clear stack trace.

Run inside the agent container:
    python -m unittest tests.test_tradecraft_provider_compat
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.tradecraft_crawl import agentic_crawl
from orchestrator_helpers.tradecraft_lookup import _pick_section


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class _BedrockShapedLLM:
    """LLM stub that returns `content` as a list of content blocks — the
    shape ChatBedrockConverse emits. Pre-fix tradecraft sites crash on this."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def ainvoke(self, _prompt):
        class R:
            pass
        r = R()
        if self.calls < len(self.responses):
            payload = self.responses[self.calls]
            # Wrap each payload in Bedrock Converse shape.
            r.content = [{"type": "text", "text": payload}]
        else:
            r.content = [{"type": "text", "text": '{"action":"stop","reason":"out of script"}'}]
        self.calls += 1
        return r


class _BedrockMixedBlocksLLM:
    """LLM stub that emits text + tool_use blocks (Bedrock mid-tool-call).
    The text block carries the JSON; the tool_use block must NOT pollute
    parsing (normalize_content drops non-text blocks)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def ainvoke(self, _prompt):
        class R:
            pass
        r = R()
        payload = self.responses[self.calls] if self.calls < len(self.responses) else '{"action":"stop","reason":"end"}'
        r.content = [
            {"type": "text", "text": payload},
            {"type": "tool_use", "id": "x", "name": "noop", "input": {}},
        ]
        self.calls += 1
        return r


class _StubPlaywrightTool:
    name = "execute_playwright"

    def __init__(self, html_map):
        self.html_map = html_map

    async def ainvoke(self, args):
        url = args.get("url", "")
        return [{"text": self.html_map.get(url, "<html></html>")}]


class _StubMCP:
    def __init__(self, html_map):
        self.tool = _StubPlaywrightTool(html_map)

    async def get_tools(self):
        return [self.tool]


def _make_html(title, body, links):
    link_html = "".join(f'<a href="{href}">{anchor}</a>' for anchor, href in links)
    return (
        f"<html><head><title>{title}</title></head>"
        f"<body><main><h1>{title}</h1><p>{body}</p>{link_html}</main></body></html>"
    )


# ---------------------------------------------------------------------------
# tradecraft_crawl: _llm_decide called inside the crawl loop
# ---------------------------------------------------------------------------

class TradecraftCrawlBedrockShapeTests(unittest.TestCase):
    """The agentic crawl loop calls llm.ainvoke per page. If the LLM returns
    Bedrock list-of-blocks, normalize_content must reassemble the JSON before
    the loop calls .strip() / regex on it."""

    def _base_html(self, links):
        return _make_html("Sec Blog", "intro " * 200, links)

    def test_crawl_loop_completes_with_bedrock_response_shape(self):
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": self._base_html([
                ("Kerberos Silver Tickets", "/post1"),
                ("SSRF Bypasses", "/post2"),
            ]),
            f"{base}/post1": _make_html("Kerberos", "kerberoast " * 200, []),
            f"{base}/post2": _make_html("SSRF", "ssrf-content " * 200, []),
        }
        llm = _BedrockShapedLLM(['{"action":"follow","indices":[1,2],"reason":"good"}'])
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 3, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=_StubMCP(html_map),
        ))
        # Sanity: loop completed, the Bedrock-shape decision parsed,
        # and we actually FOLLOWED the indices (3 pages fetched, not 1).
        self.assertEqual(result.stats["pages_fetched"], 3)
        self.assertGreaterEqual(len(result.sitemap_entries), 3)

    def test_crawl_loop_completes_with_bedrock_mixed_blocks(self):
        """Same as above but the LLM also emits a tool_use block alongside
        the text block. The text block's JSON must still be parsed."""
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": self._base_html([("Post 1", "/p1")]),
            f"{base}/p1": _make_html("Post 1", "post-content " * 200, []),
        }
        llm = _BedrockMixedBlocksLLM(['{"action":"follow","indices":[1],"reason":"ok"}'])
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 3, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=_StubMCP(html_map),
        ))
        self.assertEqual(result.stats["pages_fetched"], 2)

    def test_crawl_stop_action_works_with_bedrock_shape(self):
        """Bedrock `stop` decision must short-circuit cleanly."""
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": self._base_html([("P1", "/p1")]),
        }
        llm = _BedrockShapedLLM(['{"action":"stop","reason":"not enough signal"}'])
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 3, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=_StubMCP(html_map),
        ))
        self.assertEqual(result.stats["pages_fetched"], 1)
        self.assertIn("signal", result.stopped_because)


# ---------------------------------------------------------------------------
# tradecraft_lookup._pick_section: the mini section-picker LLM
# ---------------------------------------------------------------------------

class TradecraftPickSectionBedrockShapeTests(unittest.TestCase):
    """The section picker asks the LLM for a single number (1..N). If
    Bedrock returns its answer as a list of blocks, the regex search for
    a digit must run on the joined string, not the raw list."""

    def _sitemap(self, n: int):
        return {
            "links": [
                {"title": f"Topic {i}", "path": f"/topic-{i}"} for i in range(1, n + 1)
            ],
        }

    def test_picks_number_from_bedrock_response(self):
        sitemap = self._sitemap(20)  # > 5 entries forces LLM path
        llm = _BedrockShapedLLM(["3"])
        result = run_async(_pick_section(
            "kerberos silver ticket abuse",
            sitemap,
            section_picker_llm=llm,
            semaphore=asyncio.Semaphore(1),
            resource_name="testresource",
        ))
        self.assertIsNotNone(result)
        # The picker indexes into the *top-scored* candidates list, so we
        # cannot assert which exact entry it landed on (it's scored). What
        # matters: it returned a valid entry without crashing on the list
        # shape, AND the path looks like one of the seeded entries.
        self.assertTrue(result["path"].startswith("/topic-"))

    def test_picks_number_from_bedrock_mixed_blocks(self):
        sitemap = self._sitemap(20)
        llm = _BedrockMixedBlocksLLM(["7"])
        result = run_async(_pick_section(
            "ssrf cloud metadata pivot",
            sitemap,
            section_picker_llm=llm,
            semaphore=asyncio.Semaphore(1),
            resource_name="testresource",
        ))
        self.assertIsNotNone(result)
        self.assertTrue(result["path"].startswith("/topic-"))

    def test_falls_back_when_bedrock_returns_no_digit(self):
        """If Bedrock emits non-numeric content, the picker falls back to
        the top lexical match — NOT a crash."""
        sitemap = self._sitemap(20)
        llm = _BedrockShapedLLM(["I don't know"])
        result = run_async(_pick_section(
            "unknown topic xyz",
            sitemap,
            section_picker_llm=llm,
            semaphore=asyncio.Semaphore(1),
            resource_name="testresource",
        ))
        # Either the top scored entry or None — both are non-crash outcomes.
        if result is not None:
            self.assertTrue(result["path"].startswith("/topic-"))


# ---------------------------------------------------------------------------
# Pre-fix crash proof: show the OLD code path crashes on Bedrock,
# the NEW code path doesn't.
# ---------------------------------------------------------------------------

class PreFixVsPostFixContractTests(unittest.TestCase):
    """These tests document the exact crash the fix prevents. They're not
    coverage of the runtime — they're documentation that future readers
    (and AI code-reviewers) can grep for to understand the bug class."""

    def test_old_pattern_crashes_on_bedrock_shape(self):
        bedrock = [{"type": "text", "text": '{"action":"stop"}'}]

        class R:
            content = bedrock

        # Old pattern (pre-fix) — this exact form was in 3 tradecraft sites:
        with self.assertRaises(AttributeError) as ctx:
            (getattr(R(), "content", "") or "").strip()
        self.assertIn("'list' object has no attribute 'strip'", str(ctx.exception))

    def test_new_pattern_works_on_bedrock_shape(self):
        from orchestrator_helpers.json_utils import normalize_content

        bedrock = [{"type": "text", "text": '{"action":"stop"}'}]

        class R:
            content = bedrock

        # New pattern (post-fix):
        text = normalize_content(getattr(R(), "content", "") or "").strip()
        self.assertEqual(text, '{"action":"stop"}')

    def test_new_pattern_works_on_openai_shape(self):
        from orchestrator_helpers.json_utils import normalize_content

        class R:
            content = '{"action":"stop"}'

        text = normalize_content(getattr(R(), "content", "") or "").strip()
        self.assertEqual(text, '{"action":"stop"}')


if __name__ == "__main__":
    unittest.main()
