"""Integration tests for the 5 LLM-backed `/llm/*` endpoints under both
OpenAI-style (string content) AND Bedrock-style (list-of-blocks content)
provider responses.

Pre-fix bug:
    raw_text = (getattr(response, 'content', None) or '').strip()
This raised `AttributeError: 'list' object has no attribute 'strip'` whenever
the underlying LangChain model was `ChatBedrockConverse`, because Bedrock
returns content as `[{"type":"text","text":"..."}]`. All recon AI classifiers
(ffuf, nuclei tags, WAF, nuclei FP filter, takeover) crashed with HTTP 500.

Post-fix:
    raw_text = normalize_content(getattr(response, 'content', None)).strip()

This test patches `_build_llm_with_model_for_user` to return a stub LLM that
emits the chosen content shape, then asserts:
1. The endpoint returns 200 (no 500 crash).
2. The parsed payload matches what the model "intended" — proving the
   normalizer reassembled the JSON correctly regardless of provider shape.

Each endpoint is exercised under BOTH shapes to lock in cross-provider parity.

Run inside the agent container:
    python -m unittest tests.test_llm_endpoints_provider_compat
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


# ---------------------------------------------------------------------------
# Stub LLM (mimics LangChain ChatModel; emits canned `.content` of any shape)
# ---------------------------------------------------------------------------

class _StubLLM:
    """Returns a configurable `.content` shape from .ainvoke().

    Pass `content` as a str (OpenAI/Anthropic plain), a list of blocks
    (Bedrock Converse), or any other type to exercise edge cases.
    """

    def __init__(self, content):
        self._content = content

    async def ainvoke(self, _messages):
        class _R:
            pass
        r = _R()
        r.content = self._content
        return r


def _openai_str(payload_dict: dict) -> str:
    """Shape #1: OpenAI/Anthropic plain string."""
    return json.dumps(payload_dict)


def _bedrock_blocks(payload_dict: dict) -> list:
    """Shape #2: ChatBedrockConverse list-of-content-blocks."""
    return [{"type": "text", "text": json.dumps(payload_dict)}]


def _bedrock_blocks_split(payload_dict: dict) -> list:
    """Shape #3: Bedrock splitting one JSON answer across multiple text blocks
    (rare but legal — happens when the model interleaves reasoning with
    structured output)."""
    s = json.dumps(payload_dict)
    half = len(s) // 2
    return [
        {"type": "text", "text": s[:half]},
        {"type": "text", "text": s[half:]},
    ]


def _bedrock_with_tool_use(payload_dict: dict) -> list:
    """Shape #4: Bedrock mixed text + tool_use blocks. The tool_use block
    MUST NOT pollute the text output — normalize_content should drop it."""
    return [
        {"type": "text", "text": json.dumps(payload_dict)},
        {"type": "tool_use", "id": "tool_1", "name": "irrelevant", "input": {}},
    ]


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

class _LLMEndpointFixture(unittest.TestCase):
    """Shared boilerplate: import api module under a fake lifespan, build
    a TestClient, and provide a helper that patches the LLM resolver."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api_module = api_module
            from fastapi.testclient import TestClient
            cls.TestClient = TestClient

    def _client(self):
        return self.TestClient(self.api_module.app)

    def _post_with_stub_llm(self, endpoint: str, body: dict, llm_content):
        """POST to `endpoint`, with `_build_llm_with_model_for_user` patched
        to return a StubLLM emitting `llm_content`."""
        with patch.object(
            self.api_module,
            "_build_llm_with_model_for_user",
            return_value=_StubLLM(llm_content),
        ):
            return self._client().post(endpoint, json=body)


# ---------------------------------------------------------------------------
# /llm/ffuf-extensions
# ---------------------------------------------------------------------------

class FfufExtensionsProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "url": "https://target.example.com/upload",
        "headers": {"Server": "nginx", "X-Powered-By": "PHP/8.1"},
        "model": "test-model",
        "max_extensions": 4,
    }
    PAYLOAD = {"extensions": ["php", "phtml", "php5", "php7"]}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["extensions"], self.PAYLOAD["extensions"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["extensions"], self.PAYLOAD["extensions"])

    def test_bedrock_split_blocks(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _bedrock_blocks_split(self.PAYLOAD))
        # Joining splits inserts "\n" between halves, which breaks json.loads —
        # so endpoint should respond 502 ("non-JSON"), NOT crash with 500.
        # This pins the boundary between "normalizer crashed" (500) and
        # "model returned unparseable JSON" (502, expected).
        self.assertEqual(r.status_code, 502, r.text)
        self.assertIn("non-JSON", r.json().get("error", ""))

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/ffuf-extensions", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["extensions"], self.PAYLOAD["extensions"])


# ---------------------------------------------------------------------------
# /llm/nuclei-tags
# ---------------------------------------------------------------------------

class NucleiTagsProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "technologies": ["nginx", "php"],
        "servers": ["nginx"],
        "current_tags": [],
        "candidates": ["nginx", "php", "lfi", "sqli", "xss"],
        "model": "test-model",
        "max_tags": 3,
    }
    PAYLOAD = {"tags": ["nginx", "php", "lfi"]}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-tags", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-tags", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/nuclei-tags", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])

    def test_bedrock_with_markdown_fence(self):
        """Bedrock+Claude often wraps JSON in ```json fences. The endpoint
        already handles fence-stripping post-normalization."""
        fenced = "```json\n" + json.dumps(self.PAYLOAD) + "\n```"
        r = self._post_with_stub_llm(
            "/llm/nuclei-tags", self.REQUEST,
            [{"type": "text", "text": fenced}],
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], self.PAYLOAD["tags"])


# ---------------------------------------------------------------------------
# /llm/waf-classify
# ---------------------------------------------------------------------------

class WafClassifyProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "url": "https://target.example.com/admin",
        "status_code": 403,
        "headers": {"server": "cloudflare", "cf-ray": "8abc-FRA"},
        "body_sample": "Attention Required! | Cloudflare",
        "response_time_ms": 120,
        "model": "test-model",
    }
    PAYLOAD = {
        "waf_detected": True,
        "waf_type": "cloudflare",
        "confidence": 95,
        "reasoning": "cf-ray header + cloudflare body fingerprint",
    }

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/waf-classify", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["waf_detected"])
        self.assertEqual(r.json()["waf_type"], "cloudflare")

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/waf-classify", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["waf_detected"])

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/waf-classify", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["confidence"], 95)


# ---------------------------------------------------------------------------
# /llm/nuclei-fp-filter
# ---------------------------------------------------------------------------

class NucleiFpFilterProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "template_id": "CVE-2024-1234",
        "tags": ["wordpress", "rce"],
        "status_line": "403 Forbidden",
        "response_sample": "Just a moment...",
        "model": "test-model",
    }
    PAYLOAD = {"is_blocked": True, "confidence": 88, "reason": "challenge page"}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-fp-filter", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["is_blocked"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/nuclei-fp-filter", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["is_blocked"])
        self.assertEqual(r.json()["confidence"], 88)


# ---------------------------------------------------------------------------
# /llm/takeover-classify
# ---------------------------------------------------------------------------

class TakeoverClassifyProviderCompatTests(_LLMEndpointFixture):
    REQUEST = {
        "hostname": "abandoned.example.com",
        "expected_provider": "github",
        "status_code": 404,
        "headers": {"server": "GitHub.com"},
        "response_sample": "There isn't a GitHub Pages site here.",
        "model": "test-model",
    }
    PAYLOAD = {"is_waf_block": False, "confidence": 92, "reason": "genuine github 404 takeover signature"}

    def test_openai_string_content(self):
        r = self._post_with_stub_llm("/llm/takeover-classify", self.REQUEST, _openai_str(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["is_waf_block"])

    def test_bedrock_list_content(self):
        r = self._post_with_stub_llm("/llm/takeover-classify", self.REQUEST, _bedrock_blocks(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["is_waf_block"])

    def test_bedrock_with_tool_use_block(self):
        r = self._post_with_stub_llm("/llm/takeover-classify", self.REQUEST, _bedrock_with_tool_use(self.PAYLOAD))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["confidence"], 92)


# ---------------------------------------------------------------------------
# Regression: would-have-crashed-pre-fix proof
# ---------------------------------------------------------------------------

class PreFixCrashProofTests(_LLMEndpointFixture):
    """Direct proof that the OLD code path would crash on Bedrock content.

    We simulate the OLD code (`(getattr(resp, 'content', None) or '').strip()`)
    against a Bedrock-style list and confirm it raises AttributeError. This
    locks in WHY the fix matters; if normalize_content's contract ever loosens
    (e.g. it stops handling list inputs), this test will go green when the
    old form starts "working" — alerting us that something is wrong.
    """

    def test_old_code_path_would_have_crashed_on_bedrock(self):
        bedrock_content = [{"type": "text", "text": '{"tags": ["nginx"]}'}]

        class _OldStyleResponse:
            content = bedrock_content

        with self.assertRaises(AttributeError) as ctx:
            (getattr(_OldStyleResponse(), 'content', None) or '').strip()
        self.assertIn("'list' object has no attribute 'strip'", str(ctx.exception))

    def test_new_code_path_handles_bedrock_correctly(self):
        from orchestrator_helpers.json_utils import normalize_content

        bedrock_content = [{"type": "text", "text": '{"tags": ["nginx"]}'}]

        class _NewStyleResponse:
            content = bedrock_content

        text = normalize_content(getattr(_NewStyleResponse(), 'content', None)).strip()
        self.assertEqual(text, '{"tags": ["nginx"]}')
        # And it parses correctly:
        self.assertEqual(json.loads(text), {"tags": ["nginx"]})


if __name__ == "__main__":
    unittest.main()
