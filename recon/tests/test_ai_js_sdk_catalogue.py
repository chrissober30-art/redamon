"""Unit tests for the js_recon AI SDK catalogue (Adversarial AI Phase 6).

Covers:

  1. Catalogue shape — all five pattern families are non-empty and well-typed
  2. ``match_ai_sdk`` channel coverage — at least one match per family on a
     synthetic JS blob that exercises every channel
  3. Constructor-context suppression — a ``new OpenAI({apiKey:'sk-proj-...'})``
     line yields ONE finding (constructor wins), not two (constructor + prefix)
  4. AIzaSy disambiguation — Gemini-context tokens escalate the Google key to
     critical; absence keeps it at medium with the Maps/Firebase wording
  5. Backwards-compat — the legacy ``AI_SDK_IMPORT_REGEX`` tuple-of-3 export is
     still populated so any future caller using the old name keeps working
  6. Terser truthy-rewrite — both ``true`` and ``!0`` trigger the browser-flag
     pattern, since minified bundles use either form
  7. Frontend marker dedup — repeated Gradio markers in one file produce a
     single finding (the helper caps at one per product per file)

These tests run in the local Python environment (stdlib ``re`` only) and need
no external services or Docker containers.
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


def _load_catalogue():
    """Import ``ai_signal_catalog`` directly from its file path.

    The module is normally imported via ``recon.helpers.ai_signal_catalog``,
    which pulls in DNS / Docker / orchestration helpers that aren't present
    in a slim test environment. Loading the file by spec sidesteps the
    package ``__init__`` entirely.
    """
    spec = importlib.util.spec_from_file_location(
        "ai_signal_catalog", _CATALOG_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CatalogueShape(unittest.TestCase):
    """Every pattern family is populated, every entry is well-formed."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load_catalogue()

    def test_all_families_non_empty(self):
        self.assertGreater(len(self.cat.AI_KEY_PREFIX_PATTERNS), 20)
        self.assertGreater(len(self.cat.AI_KEY_CONSTRUCTOR_PATTERNS), 10)
        self.assertGreater(len(self.cat.AI_SDK_IMPORT_PATTERNS), 40)
        self.assertGreater(len(self.cat.AI_BROWSER_FLAG_PATTERNS), 0)
        self.assertGreater(len(self.cat.AI_FRONTEND_JS_PATTERNS), 15)
        self.assertGreater(len(self.cat.AI_PROVIDER_URL_PATTERNS), 15)

    def test_entry_tuple_shape(self):
        for family in (self.cat.AI_KEY_PREFIX_PATTERNS,
                        self.cat.AI_KEY_CONSTRUCTOR_PATTERNS,
                        self.cat.AI_SDK_IMPORT_PATTERNS,
                        self.cat.AI_BROWSER_FLAG_PATTERNS,
                        self.cat.AI_FRONTEND_JS_PATTERNS,
                        self.cat.AI_PROVIDER_URL_PATTERNS):
            for entry in family:
                self.assertEqual(len(entry), 4,
                    f"All entries must be (pattern, label, severity, confidence). Got {entry!r}")
                pattern, label, severity, confidence = entry
                self.assertIsInstance(pattern, re.Pattern)
                self.assertIsInstance(label, str)
                self.assertIn(severity, {"info", "low", "medium", "high", "critical"})
                self.assertIn(confidence, {"low", "medium", "high"})

    def test_legacy_export_populated(self):
        """``AI_SDK_IMPORT_REGEX`` (tuple-of-3) is the legacy export. It must
        stay populated so any future import path keeps working — the new
        catalogue derives it from AI_SDK_IMPORT_PATTERNS."""
        self.assertGreater(len(self.cat.AI_SDK_IMPORT_REGEX), 40)
        for entry in self.cat.AI_SDK_IMPORT_REGEX:
            self.assertEqual(len(entry), 3)
            self.assertEqual(entry[2], "ai-sdk-client")


class MatchAiSdkChannels(unittest.TestCase):
    """``match_ai_sdk`` exercises all five output categories on one blob."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load_catalogue()
        cls.sample = (
            'import { OpenAI } from "openai";\n'
            'import Anthropic from "@anthropic-ai/sdk";\n'
            'const c = new OpenAI({ apiKey: '
            '"sk-proj-' + 'a' * 40 + 'T3BlbkFJ' + 'b' * 40 + '", '
            'dangerouslyAllowBrowser: !0 });\n'
            'fetch("https://api.openai.com/v1/chat/completions");\n'
            'window.gradio_config = {};\n'
        )

    def test_all_categories_present(self):
        findings = self.cat.match_ai_sdk(self.sample)
        categories = {f["category"] for f in findings}
        self.assertIn("ai-sdk-client", categories)
        self.assertIn("ai-sdk-key-literal", categories)
        self.assertIn("ai-sdk-browser-allowed", categories)
        self.assertIn("ai-frontend-detected", categories)
        self.assertIn("ai-provider-url", categories)

    def test_key_literal_is_redacted(self):
        findings = self.cat.match_ai_sdk(self.sample)
        keys = [f for f in findings if f["category"] == "ai-sdk-key-literal"]
        self.assertTrue(keys, "Expected at least one key literal finding")
        for f in keys:
            sample = f["sample"]
            # The redact helper exposes the first 6 + last 4; the middle
            # must be masked so we never persist the full secret.
            self.assertTrue("..." in sample or "*" in sample,
                f"Key sample must be redacted, got {sample!r}")
            self.assertLessEqual(len(sample), 30)

    def test_constructor_suppresses_prefix_match(self):
        """A single ``new OpenAI({apiKey:'sk-proj-...'})`` must yield exactly
        ONE ai-sdk-key-literal finding (constructor wins over prefix-anchored
        on the same byte range)."""
        blob = (
            'const x = new OpenAI({ apiKey: '
            '"sk-proj-' + 'a' * 40 + 'T3BlbkFJ' + 'b' * 40 + '" });'
        )
        findings = self.cat.match_ai_sdk(blob)
        key_findings = [f for f in findings if f["category"] == "ai-sdk-key-literal"]
        self.assertEqual(len(key_findings), 1,
            f"Expected exactly one key finding, got {len(key_findings)}: "
            f"{[f['sdk_name'] for f in key_findings]}")
        self.assertEqual(key_findings[0]["sdk_name"], "OpenAI SDK constructor")


class GoogleKeyDisambiguation(unittest.TestCase):
    """The AIzaSy* format collides with Maps/Firebase; the helper resolves it
    by scanning ±2KB for Gemini SDK / endpoint tokens."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load_catalogue()
        cls.key = "AIzaSyA" + "b" * 32  # AIzaSy + 33 chars

    def test_gemini_context_escalates_to_critical(self):
        blob = (
            'import { GoogleGenerativeAI } from "@google/generative-ai";\n'
            f'const g = new GoogleGenerativeAI("{self.key}");'
        )
        findings = self.cat.match_ai_sdk(blob)
        google_keys = [f for f in findings
                        if f["category"] == "ai-sdk-key-literal"
                        and "Google" in f["sdk_name"]]
        self.assertTrue(google_keys, "Expected at least one Google key finding")
        # The constructor-context pattern fires first and is critical/high.
        # Either it wins outright or the prefix path with disambiguation
        # also escalates because @google/generative-ai is in context.
        self.assertTrue(any(f["severity"] == "critical" for f in google_keys),
            f"Expected at least one critical Google key, got: "
            f"{[(f['sdk_name'], f['severity']) for f in google_keys]}")

    def test_no_gemini_context_keeps_medium(self):
        # No Gemini tokens anywhere in the blob — the bare AIzaSy key
        # should be tagged as the Maps/Firebase variant at medium severity.
        blob = (
            f'const mapsKey = "{self.key}";\n'
            'const map = new google.maps.Map(div, opts);'
        )
        findings = self.cat.match_ai_sdk(blob)
        google_keys = [f for f in findings
                        if f["category"] == "ai-sdk-key-literal"
                        and "Google" in f["sdk_name"]]
        self.assertTrue(google_keys)
        for f in google_keys:
            self.assertEqual(f["severity"], "medium")
            self.assertIn("Maps/Firebase", f["sdk_name"])


class BrowserFlagTerser(unittest.TestCase):
    """Terser rewrites ``true`` → ``!0``; both must match the browser flag."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load_catalogue()

    def test_true_literal(self):
        findings = self.cat.match_ai_sdk(
            'const c = new OpenAI({ apiKey: "x", dangerouslyAllowBrowser: true })'
        )
        self.assertTrue(any(f["category"] == "ai-sdk-browser-allowed" for f in findings))

    def test_terser_truthy(self):
        findings = self.cat.match_ai_sdk(
            'const c = new OpenAI({ apiKey: "x", dangerouslyAllowBrowser: !0 })'
        )
        self.assertTrue(any(f["category"] == "ai-sdk-browser-allowed" for f in findings))


class FrontendMarkerDedup(unittest.TestCase):
    """Repeated frontend markers in one file produce a single finding."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load_catalogue()

    def test_one_finding_per_product(self):
        blob = (
            'window.gradio_config = {};\n'
            'window.gradio_config = {};\n'
            'customElements.define("gradio-app", X);\n'
            'window.__gradio_mode__ = "stable";\n'
        )
        findings = self.cat.match_ai_sdk(blob)
        gradio = [f for f in findings
                   if f["category"] == "ai-frontend-detected"
                   and f["sdk_name"] == "Gradio"]
        self.assertEqual(len(gradio), 1,
            f"Expected exactly one Gradio finding, got {len(gradio)}")


class EmptyInput(unittest.TestCase):
    """Edge cases that previously crashed regex-pattern scanners."""

    @classmethod
    def setUpClass(cls):
        cls.cat = _load_catalogue()

    def test_empty_string(self):
        self.assertEqual(self.cat.match_ai_sdk(""), [])

    def test_none(self):
        self.assertEqual(self.cat.match_ai_sdk(None), [])  # type: ignore[arg-type]

    def test_huge_blob_is_truncated(self):
        # 1 MB blob should be capped to 512 KB by the helper. Place a
        # tell-tale marker past the cap so we can verify it's NOT detected.
        blob = "x" * (600 * 1024) + 'import "openai";'
        findings = self.cat.match_ai_sdk(blob)
        self.assertEqual(len(findings), 0,
            "Markers past max_bytes must not be matched")


if __name__ == "__main__":
    unittest.main(verbosity=2)
