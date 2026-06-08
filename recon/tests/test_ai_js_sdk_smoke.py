"""Smoke test for Phase 6 — every file we touched imports cleanly.

The cheapest way to catch typos, missing imports, or broken module-load
side-effects is to ask Python to actually import every file we modified.
This catches:

  - Syntax errors after a merge
  - Missing imports (``from x import y`` where y was renamed)
  - Module-load-time crashes (catalogue tuples shaped wrong)
  - Test-runner-vs-prod path drift

The tricky part is the recon helpers package: its ``__init__.py`` pulls in
DNS / Docker / subprocess helpers that aren't always available in a test
environment. We import the catalogue file BY PATH (sidesteps the package)
and the rest by package name when their deps are present.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest


_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))


def _import_by_path(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_REPO_ROOT, rel_path)
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot resolve spec for {rel_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SmokeImports(unittest.TestCase):
    """Each modified Python file imports without crashing."""

    def test_ai_signal_catalog_module_loads(self):
        mod = _import_by_path(
            "ai_signal_catalog_smoke",
            "recon/helpers/ai_signal_catalog.py"
        )
        # Spot-check the new public surface.
        self.assertTrue(hasattr(mod, "match_ai_sdk"))
        self.assertTrue(hasattr(mod, "AI_KEY_PREFIX_PATTERNS"))
        self.assertTrue(hasattr(mod, "AI_KEY_CONSTRUCTOR_PATTERNS"))
        self.assertTrue(hasattr(mod, "AI_SDK_IMPORT_PATTERNS"))
        self.assertTrue(hasattr(mod, "AI_BROWSER_FLAG_PATTERNS"))
        self.assertTrue(hasattr(mod, "AI_FRONTEND_JS_PATTERNS"))
        self.assertTrue(hasattr(mod, "AI_PROVIDER_URL_PATTERNS"))
        # Legacy backwards-compat export.
        self.assertTrue(hasattr(mod, "AI_SDK_IMPORT_REGEX"))
        # Private helpers we depend on through match_ai_sdk.
        self.assertTrue(hasattr(mod, "_disambiguate_google_key"))
        self.assertTrue(hasattr(mod, "_redact_secret"))

    def test_match_ai_sdk_is_callable_on_empty(self):
        mod = _import_by_path(
            "ai_signal_catalog_smoke2",
            "recon/helpers/ai_signal_catalog.py"
        )
        # Doesn't crash, returns list.
        self.assertEqual(mod.match_ai_sdk(""), [])
        self.assertEqual(mod.match_ai_sdk(None), [])
        # Returns list shape on real input.
        out = mod.match_ai_sdk('import "openai";')
        self.assertIsInstance(out, list)
        if out:
            self.assertIsInstance(out[0], dict)

    def test_project_settings_loads_and_has_new_key(self):
        # project_settings.py only depends on stdlib at import-time.
        mod = _import_by_path(
            "project_settings_smoke",
            "recon/project_settings.py"
        )
        self.assertIn("JS_RECON_AI_SDK_DETECTION_ENABLED", mod.DEFAULT_SETTINGS)
        self.assertIs(mod.DEFAULT_SETTINGS["JS_RECON_AI_SDK_DETECTION_ENABLED"], True)


class SmokeMixinShape(unittest.TestCase):
    """The mixin file is more complex (Neo4j driver) but at minimum we
    verify it parses to Python AST without syntax errors."""

    def test_mixin_compiles(self):
        path = os.path.join(_REPO_ROOT, "graph_db", "mixins", "recon", "js_recon_mixin.py")
        with open(path) as f:
            source = f.read()
        # Will raise SyntaxError if the new write block has any issue.
        compile(source, path, "exec")

    def test_mixin_has_ai_sdk_block(self):
        path = os.path.join(_REPO_ROOT, "graph_db", "mixins", "recon", "js_recon_mixin.py")
        with open(path) as f:
            source = f.read()
        # Markers from the new block — protects against accidental revert.
        self.assertIn("ai_sdk_findings_created", source)
        self.assertIn("ai_sdk_secrets_enriched", source)
        self.assertIn("ai_provider", source)
        self.assertIn("captured_value", source)
        # The prefix-anchored Cypher guard we added in the bug fix.
        self.assertIn("STARTS WITH 'sk-'", source)
        self.assertIn("STARTS WITH 'AIzaSy'", source)


class SmokeJsReconAnalysisShape(unittest.TestCase):
    """js_recon.py only needs to syntax-check + have the new pass wired."""

    def test_js_recon_compiles(self):
        path = os.path.join(_REPO_ROOT, "recon", "main_recon_modules", "js_recon.py")
        with open(path) as f:
            source = f.read()
        compile(source, path, "exec")

    def test_js_recon_references_new_pass(self):
        path = os.path.join(_REPO_ROOT, "recon", "main_recon_modules", "js_recon.py")
        with open(path) as f:
            source = f.read()
        self.assertIn("JS_RECON_AI_SDK_DETECTION_ENABLED", source)
        self.assertIn("match_ai_sdk", source)
        self.assertIn("ai_sdk_findings", source)
        # The 6th-pass wiring marker.
        self.assertIn("run_ai_sdk_detection", source)


class SmokeWebappArtifacts(unittest.TestCase):
    """Webapp-side files are checked by file content rather than imports."""

    def test_prisma_schema_has_new_field(self):
        path = os.path.join(_REPO_ROOT, "webapp", "prisma", "schema.prisma")
        with open(path) as f:
            schema = f.read()
        self.assertIn("jsReconAiSdkDetectionEnabled", schema)
        self.assertIn("js_recon_ai_sdk_detection_enabled", schema)
        self.assertIn('@default(true)', schema)

    def test_zod_schema_has_new_field(self):
        path = os.path.join(_REPO_ROOT, "webapp", "src", "lib", "recon-preset-schema.ts")
        with open(path) as f:
            zod = f.read()
        self.assertIn("jsReconAiSdkDetectionEnabled: bool", zod)
        # Agent's parameter catalogue description.
        self.assertIn("Adversarial AI Phase 6", zod)

    def test_jsrecon_section_has_toggle(self):
        path = os.path.join(_REPO_ROOT, "webapp", "src", "components", "projects",
                            "ProjectForm", "sections", "JsReconSection.tsx")
        with open(path) as f:
            section = f.read()
        self.assertIn("jsReconAiSdkDetectionEnabled", section)
        self.assertIn("AI SDK Detection", section)


if __name__ == "__main__":
    unittest.main(verbosity=2)
