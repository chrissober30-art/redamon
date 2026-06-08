"""Extra coverage for the Phase 6 AI SDK catalogue beyond the smoke tests.

Adds:

  - Per-vendor positive cases (each SDK import family that we ship)
  - Real-world minified-bundle shapes (no whitespace, ESM + CommonJS mixed)
  - Byte-offset accuracy (so dedup hashes are stable across re-scans)
  - ``captured_value`` field contract (the new field the mixin uses as a
    dedup needle — without it, the v1 mixin enrichment was unsafe)
  - Provider-URL escalation when paired with a key match
  - Browser-flag truthy alternates (!!1, terser variants)
  - No-FP guards for non-AI JS files
  - Negative cases that previously confused the prefix patterns
"""
from __future__ import annotations

import importlib.util
import os
import re
import unittest


_HERE = os.path.dirname(os.path.abspath(__file__))
_CATALOG_PATH = os.path.normpath(
    os.path.join(_HERE, "..", "helpers", "ai_signal_catalog.py")
)


def _load():
    spec = importlib.util.spec_from_file_location("ai_signal_catalog", _CATALOG_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class VendorImportCoverage(unittest.TestCase):
    """Every shipped SDK family produces at least one detection on a canonical
    import line. Catches accidental regex breakage during catalogue edits."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()

    def _detect(self, blob: str, expected_substring: str):
        findings = self.cat.match_ai_sdk(blob)
        names = [f["sdk_name"] for f in findings
                 if f["category"] == "ai-sdk-client"]
        self.assertTrue(
            any(expected_substring.lower() in n.lower() for n in names),
            f"Expected {expected_substring!r} in detected SDK names; got {names}"
        )

    def test_openai(self):
        self._detect('import OpenAI from "openai/resources";', "OpenAI")

    def test_anthropic(self):
        self._detect('require("@anthropic-ai/sdk")', "Anthropic")

    def test_google_genai_new(self):
        self._detect('import { GoogleGenAI } from "@google/genai";', "Google")

    def test_cohere(self):
        self._detect('require("cohere-ai/client")', "Cohere")

    def test_mistral(self):
        self._detect('import { Mistral } from "@mistralai/mistralai";', "Mistral")

    def test_groq(self):
        self._detect('require("groq-sdk")', "Groq")

    def test_huggingface(self):
        self._detect('import { HfInference } from "@huggingface/inference"',
                     "HuggingFace Inference")

    def test_aws_bedrock(self):
        self._detect('require("@aws-sdk/client-bedrock-runtime")', "Bedrock")

    def test_langchain_core(self):
        self._detect('import { ChatModel } from "@langchain/core/language_models";',
                     "LangChain Core")

    def test_langchain_openai(self):
        self._detect('import { ChatOpenAI } from "@langchain/openai";',
                     "LangChain OpenAI")

    def test_llamaindex(self):
        self._detect('import { SimpleDirectoryReader } from "llamaindex";', "LlamaIndex")

    def test_vercel_ai_sub(self):
        self._detect('import { useChat } from "ai/react";', "Vercel AI SDK")

    def test_mcp_sdk(self):
        self._detect('import { Server } from "@modelcontextprotocol/sdk/server";',
                     "MCP SDK")

    def test_pinecone(self):
        self._detect('require("@pinecone-database/pinecone")', "Pinecone")

    def test_qdrant(self):
        self._detect('import { QdrantClient } from "@qdrant/js-client-rest";',
                     "Qdrant")

    def test_chroma(self):
        self._detect('require("chromadb")', "Chroma")

    def test_ollama(self):
        self._detect('import { Ollama } from "ollama/browser";', "Ollama")


class MinifiedBundleShapes(unittest.TestCase):
    """Real minified bundles strip whitespace and use mixed quote styles.
    The catalogue patterns must match these compressed forms."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()

    def test_no_whitespace_constructor(self):
        # Terser output: no spaces around colons or commas.
        blob = (
            'var a=new OpenAI({apiKey:"sk-proj-'
            + "a" * 40 + "T3BlbkFJ" + "b" * 40
            + '",dangerouslyAllowBrowser:!0});'
        )
        findings = self.cat.match_ai_sdk(blob)
        cats = {f["category"] for f in findings}
        self.assertIn("ai-sdk-key-literal", cats)
        self.assertIn("ai-sdk-browser-allowed", cats)

    def test_single_quotes(self):
        blob = "import OpenAI from 'openai';"
        findings = self.cat.match_ai_sdk(blob)
        self.assertTrue(any(f["sdk_name"] == "OpenAI" for f in findings))

    def test_mixed_quotes_in_same_line(self):
        # SDK import with single quotes, key literal with double.
        blob = (
            "import { Anthropic } from '@anthropic-ai/sdk';"
            'var x=new Anthropic({apiKey:"sk-ant-api03-' + "x" * 93 + 'AA"});'
        )
        findings = self.cat.match_ai_sdk(blob)
        sdks = {f["sdk_name"] for f in findings}
        self.assertIn("Anthropic", sdks)
        self.assertIn("Anthropic SDK constructor", sdks)


class CapturedValueContract(unittest.TestCase):
    """The ``captured_value`` field is what the mixin uses as a dedup needle.
    The contract is: present for every ai-sdk-key-literal finding, equal to
    the captured group (full secret, NOT redacted), absent for other categories."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()

    def test_captured_value_present_on_key_literal(self):
        blob = ('const c = new OpenAI({ apiKey: '
                '"sk-proj-' + "a" * 40 + "T3BlbkFJ" + "b" * 40 + '" });')
        keys = [f for f in self.cat.match_ai_sdk(blob)
                if f["category"] == "ai-sdk-key-literal"]
        self.assertTrue(keys)
        for k in keys:
            self.assertIn("captured_value", k)
            self.assertTrue(k["captured_value"].startswith("sk-proj-"))
            self.assertGreater(len(k["captured_value"]), 30)

    def test_captured_value_empty_on_sdk_import(self):
        blob = 'import OpenAI from "openai";'
        imports = [f for f in self.cat.match_ai_sdk(blob)
                   if f["category"] == "ai-sdk-client"]
        self.assertTrue(imports)
        for f in imports:
            # captured_value is the third arg in _record, defaults to "" when
            # no value is captured. Either absent OR empty string is OK.
            self.assertIn(f.get("captured_value", ""), ("", None))

    def test_sample_is_redacted_form_of_captured_value(self):
        blob = ('const c = new Anthropic({ apiKey: '
                '"sk-ant-api03-' + "x" * 93 + 'AA" });')
        for f in self.cat.match_ai_sdk(blob):
            if f["category"] == "ai-sdk-key-literal":
                cv = f["captured_value"]
                sample = f["sample"]
                # Sample format: first6 + "..." + last4
                self.assertEqual(sample[:6], cv[:6])
                self.assertEqual(sample[-4:], cv[-4:])
                self.assertIn("...", sample)


class ByteOffsetStability(unittest.TestCase):
    """Byte offsets must be reproducible across runs — the js_recon.py caller
    uses them in a deterministic id hash. A drifting offset breaks idempotency
    of the Neo4j MERGE."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()
        cls.blob = (
            '// big banner comment\n' * 5
            + 'import OpenAI from "openai";\n'  # offset known
            + 'const x = new OpenAI({ apiKey: "sk-proj-'
            + "a" * 40 + "T3BlbkFJ" + "b" * 40 + '" });\n'
        )

    def test_offsets_match_actual_positions(self):
        findings = self.cat.match_ai_sdk(self.blob)
        for f in findings:
            offset = f["byte_offset"]
            matched = f["matched_text"]
            # The matched_text must appear AT the recorded offset.
            self.assertEqual(
                self.blob[offset:offset + len(matched)],
                matched,
                f"Offset {offset} does not point at {matched!r}"
            )

    def test_offsets_are_stable_across_calls(self):
        run1 = self.cat.match_ai_sdk(self.blob)
        run2 = self.cat.match_ai_sdk(self.blob)
        sig1 = sorted([(f["category"], f["sdk_name"], f["byte_offset"]) for f in run1])
        sig2 = sorted([(f["category"], f["sdk_name"], f["byte_offset"]) for f in run2])
        self.assertEqual(sig1, sig2)


class BrowserFlagAlternates(unittest.TestCase):
    """Terser, esbuild, and webpack/swc all rewrite boolean literals
    differently. The catalogue covers ``true`` and ``!0``; verify both still."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()

    def test_quoted_true_still_matches(self):
        # Edge: some props get JSON-stringified during dehydration.
        blob = '{"dangerouslyAllowBrowser":true}'
        findings = self.cat.match_ai_sdk(blob)
        self.assertTrue(any(f["category"] == "ai-sdk-browser-allowed"
                            for f in findings))

    def test_allow_browser_variant(self):
        blob = 'fetch.config({ allowBrowser: true })'
        findings = self.cat.match_ai_sdk(blob)
        self.assertTrue(any(f["category"] == "ai-sdk-browser-allowed"
                            for f in findings))


class FalsePositiveGuards(unittest.TestCase):
    """Non-AI JS must produce zero findings. Catches catalogue patterns that
    are too greedy."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()

    def test_jquery_bundle_clean(self):
        blob = (
            "/*! jQuery v3.7.0 */\n"
            "(function(global, factory) { ... })(typeof window !== 'undefined' ? window : this, "
            "function(window, noGlobal) { var jQuery = function(selector) {...}; "
            "jQuery.fn = jQuery.prototype = {...}; });"
        )
        findings = self.cat.match_ai_sdk(blob)
        self.assertEqual(findings, [],
            f"jQuery bundle should produce zero findings, got: {findings}")

    def test_stripe_only_not_misdetected_as_openai(self):
        # Stripe keys start with sk_live_ / sk_test_ — must NOT trip the
        # OpenAI sk-* prefix.
        blob = (
            'const stripe = new Stripe("sk_live_' + "a" * 99 + '");\n'
            'const tk = "sk_test_' + "b" * 24 + '";'
        )
        findings = self.cat.match_ai_sdk(blob)
        ai_keys = [f for f in findings if f["category"] == "ai-sdk-key-literal"]
        self.assertEqual(ai_keys, [],
            f"Stripe keys must not match AI patterns, got: {ai_keys}")

    def test_react_app_with_no_ai_clean(self):
        blob = (
            'import React, { useState } from "react";\n'
            'import { Router } from "react-router-dom";\n'
            'function App() { const [c, sc] = useState(0); return <div>{c}</div>; }\n'
            'export default App;'
        )
        findings = self.cat.match_ai_sdk(blob)
        self.assertEqual(findings, [],
            f"Plain React app should produce zero findings, got: {findings}")


class HardCodedSdkKeyEnrichment(unittest.TestCase):
    """The constructor pattern + import + URL all firing on the same file
    is the realistic ‘smoking gun’ scenario — verify it produces a complete
    picture (key + import + url) without duplicating the key finding."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load()

    def test_smoking_gun_full_picture(self):
        blob = (
            'import OpenAI from "openai/resources";\n'
            'fetch("https://api.openai.com/v1/chat/completions");\n'
            'var c = new OpenAI({ apiKey: "sk-proj-'
            + "a" * 40 + "T3BlbkFJ" + "b" * 40
            + '", dangerouslyAllowBrowser: !0 });'
        )
        findings = self.cat.match_ai_sdk(blob)
        cats = {f["category"] for f in findings}
        self.assertIn("ai-sdk-client", cats)
        self.assertIn("ai-sdk-key-literal", cats)
        self.assertIn("ai-sdk-browser-allowed", cats)
        self.assertIn("ai-provider-url", cats)
        # Exactly one key literal — constructor must suppress prefix duplicate.
        keys = [f for f in findings if f["category"] == "ai-sdk-key-literal"]
        self.assertEqual(len(keys), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
