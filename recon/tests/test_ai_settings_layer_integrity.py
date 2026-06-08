"""Cross-layer integrity tests for the AI surface recon settings scaffold.

The integration plan's 9-layer flow is only worth what the operator can
actually see and control. If even one layer drifts — Prisma column missing,
Zod entry forgotten, section component renders the wrong camelCase, etc. —
the toggle becomes inert in some path. These tests assert the same 9 toggle
identifiers appear in every layer's source file.

This file complements ``test_ai_settings_scaffold.py``:

  * ``test_ai_settings_scaffold.py`` — runtime behaviour of the recon-side
    settings stack (DEFAULT_SETTINGS, fetch_project_settings, /defaults).
  * ``test_ai_settings_layer_integrity.py`` (this file) — structural
    presence of each toggle in every source file across the 9-layer flow.

Run:
    docker run --rm --network host --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_settings_layer_integrity.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# Single source of truth for the 9 lap-1 toggles. Every layer's source
# must contain both forms (the snake_case Python key and the camelCase
# Prisma/TS mirror).
AI_TOGGLES: list[tuple[str, str, str]] = [
    # (SCREAMING_SNAKE, camelCase, snake_case Postgres column)
    ("DOMAIN_RECON_AI_TXT_HINT_ENABLED",       "domainReconAiTxtHintEnabled",       "domain_recon_ai_txt_hint_enabled"),
    ("DOMAIN_RECON_AI_NS_HINT_ENABLED",        "domainReconAiNsHintEnabled",        "domain_recon_ai_ns_hint_enabled"),
    ("PORT_SCAN_AI_PORT_CATALOG_ENABLED",      "portScanAiPortCatalogEnabled",      "port_scan_ai_port_catalog_enabled"),
    ("MASSCAN_AI_PORT_CATALOG_ENABLED",        "masscanAiPortCatalogEnabled",       "masscan_ai_port_catalog_enabled"),
    ("NMAP_AI_VERSION_REGEX_ENABLED",          "nmapAiVersionRegexEnabled",         "nmap_ai_version_regex_enabled"),
    ("HTTP_PROBE_AI_HEADER_SCAN_ENABLED",      "httpProbeAiHeaderScanEnabled",      "http_probe_ai_header_scan_enabled"),
    ("HTTP_PROBE_AI_FAVICON_HASH_ENABLED",     "httpProbeAiFaviconHashEnabled",     "http_probe_ai_favicon_hash_enabled"),
    ("HTTP_PROBE_AI_TITLE_DETECTION_ENABLED",  "httpProbeAiTitleDetectionEnabled",  "http_probe_ai_title_detection_enabled"),
    ("HTTP_PROBE_AI_WAPPALYZER_ENABLED",       "httpProbeAiWappalyzerEnabled",      "http_probe_ai_wappalyzer_enabled"),
    # Phase 6 (js_recon AI SDK detection).
    ("JS_RECON_AI_SDK_DETECTION_ENABLED",      "jsReconAiSdkDetectionEnabled",      "js_recon_ai_sdk_detection_enabled"),
]


def _read(rel_path: str) -> str:
    path = PROJECT_ROOT / rel_path
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Layer 1 — Prisma schema  (webapp/prisma/schema.prisma)
# ---------------------------------------------------------------------------

def test_prisma_schema_has_each_field_with_default_true():
    content = _read("webapp/prisma/schema.prisma")
    for snake, camel, sql_col in AI_TOGGLES:
        # field declaration: camelCase Boolean @default(true) @map("snake_case")
        assert camel in content, f"Prisma schema missing field {camel}"
        assert f'@map("{sql_col}")' in content, f"Prisma @map missing for {camel} (expected {sql_col!r})"
        # Crude but effective: the line carrying the camelCase identifier must
        # carry both @default(true) and the @map.
        line = next((ln for ln in content.splitlines() if camel in ln), "")
        assert "@default(true)" in line, f"Prisma field {camel} is not @default(true) on {line!r}"


# ---------------------------------------------------------------------------
# Layer 2 — Postgres columns (verified live)
# ---------------------------------------------------------------------------

def _query_postgres_ai_columns() -> dict[str, tuple[str, str]] | None:
    """Return {column_name: (data_type, column_default)} for our 9 AI columns,
    or None if the postgres container isn't reachable from this test host."""
    if shutil.which("docker") is None:
        return None
    sql = (
        "SELECT column_name, data_type, column_default "
        "FROM information_schema.columns "
        "WHERE table_name='projects' "
        "AND (column_name LIKE 'domain_recon_ai_%' "
        "OR column_name LIKE 'port_scan_ai_%' "
        "OR column_name LIKE 'masscan_ai_%' "
        "OR column_name LIKE 'nmap_ai_%' "
        "OR column_name LIKE 'http_probe_ai_%') "
        "ORDER BY column_name;"
    )
    proc = subprocess.run(
        ["docker", "exec", "-i", "redamon-postgres",
         "psql", "-U", "redamon", "-d", "redamon", "-t", "-A", "-F|", "-c", sql],
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        return None
    rows: dict[str, tuple[str, str]] = {}
    for line in proc.stdout.strip().splitlines():
        if "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) >= 3:
            rows[parts[0].strip()] = (parts[1].strip(), parts[2].strip())
    return rows


def test_postgres_has_all_nine_columns_as_boolean_default_true():
    rows = _query_postgres_ai_columns()
    if rows is None:
        print("SKIP: test_postgres_has_all_nine_columns_as_boolean_default_true (postgres container unreachable)")
        return
    for _snake, _camel, sql_col in AI_TOGGLES:
        assert sql_col in rows, f"Postgres column {sql_col} missing — prisma db push didn't apply?"
        data_type, default = rows[sql_col]
        assert data_type == "boolean", f"{sql_col} is {data_type!r}, expected boolean"
        assert default == "true", f"{sql_col} default is {default!r}, expected 'true'"


# ---------------------------------------------------------------------------
# Layer 3 — recon DEFAULT_SETTINGS  (recon/project_settings.py)
# ---------------------------------------------------------------------------

def test_default_settings_present_in_python_source():
    """Source-file regex (no import) so this test catches drift even when
    the module has unrelated import errors."""
    content = _read("recon/project_settings.py")
    for snake, _camel, _sql in AI_TOGGLES:
        # Look for the key in DEFAULT_SETTINGS dict-literal style:  'KEY': True,
        needle = f"'{snake}': True"
        assert needle in content, (
            f"recon/project_settings.py DEFAULT_SETTINGS missing {snake!r} as True "
            f"(searched for {needle!r})"
        )


# ---------------------------------------------------------------------------
# Layer 4 — recon fetch_project_settings  (recon/project_settings.py)
# ---------------------------------------------------------------------------

def test_fetch_project_settings_mapping_present_in_python_source():
    content = _read("recon/project_settings.py")
    for snake, camel, _sql in AI_TOGGLES:
        # Mapping form: settings['KEY'] = project.get('camelCase', DEFAULT_SETTINGS['KEY'])
        needle_left = f"settings['{snake}']"
        needle_right = f"project.get('{camel}', DEFAULT_SETTINGS['{snake}'])"
        assert needle_left in content, f"fetch_project_settings missing assignment for {snake!r}"
        assert needle_right in content, (
            f"fetch_project_settings has assignment for {snake!r} but the camelCase "
            f"mirror is wrong; expected {needle_right!r}"
        )


# ---------------------------------------------------------------------------
# Layer 5 — recon-orchestrator /defaults  (snake→camel conversion sanity)
# ---------------------------------------------------------------------------

def test_recon_orchestrator_runtime_only_keys_excludes_ai_toggles():
    """RUNTIME_ONLY_KEYS is the gate that strips a key out of /defaults.
    Our 9 AI toggles MUST NOT appear in it — otherwise the operator never
    sees them in the project form."""
    content = _read("recon_orchestrator/api.py")
    # Locate the RUNTIME_ONLY_KEYS literal block. It's bounded by '{' and the
    # closing '}' that immediately precedes the camel_case_defaults dict.
    start = content.find("RUNTIME_ONLY_KEYS = {")
    assert start != -1, "RUNTIME_ONLY_KEYS literal not found in recon_orchestrator/api.py"
    end = content.find("}", start)
    block = content[start:end]
    for snake, _camel, _sql in AI_TOGGLES:
        assert snake not in block, (
            f"{snake!r} accidentally landed in RUNTIME_ONLY_KEYS — it will be stripped "
            f"from /defaults and the operator won't see the toggle."
        )


# ---------------------------------------------------------------------------
# Layer 6 — Frontend section components
# ---------------------------------------------------------------------------

# Map camelCase identifier to the section file that owns it. Verified against
# the integration plan.
SECTION_OWNERS: dict[str, str] = {
    "domainReconAiTxtHintEnabled":       "webapp/src/components/projects/ProjectForm/sections/SubdomainDiscoverySection.tsx",
    "domainReconAiNsHintEnabled":        "webapp/src/components/projects/ProjectForm/sections/SubdomainDiscoverySection.tsx",
    "portScanAiPortCatalogEnabled":      "webapp/src/components/projects/ProjectForm/sections/NaabuSection.tsx",
    "masscanAiPortCatalogEnabled":       "webapp/src/components/projects/ProjectForm/sections/MasscanSection.tsx",
    "nmapAiVersionRegexEnabled":         "webapp/src/components/projects/ProjectForm/sections/NmapSection.tsx",
    "httpProbeAiHeaderScanEnabled":      "webapp/src/components/projects/ProjectForm/sections/HttpxSection.tsx",
    "httpProbeAiFaviconHashEnabled":     "webapp/src/components/projects/ProjectForm/sections/HttpxSection.tsx",
    "httpProbeAiTitleDetectionEnabled":  "webapp/src/components/projects/ProjectForm/sections/HttpxSection.tsx",
    "httpProbeAiWappalyzerEnabled":      "webapp/src/components/projects/ProjectForm/sections/HttpxSection.tsx",
}


def test_each_toggle_has_toggle_row_in_owning_section_file():
    """The section component must (a) reference the camelCase identifier
    twice — once in `checked=` and once in `updateField(...)` — and (b)
    fall back to `?? true` so a project row missing the column still gets
    the right default."""
    for camel, rel_path in SECTION_OWNERS.items():
        content = _read(rel_path)
        # checked={data.<camel> ?? true}  — the safety fallback
        checked_pattern = f"data.{camel} ?? true"
        update_pattern = f"updateField('{camel}',"
        assert checked_pattern in content, (
            f"Section {rel_path} should have `data.{camel} ?? true` "
            f"so old project rows still default the toggle to ON."
        )
        assert update_pattern in content, (
            f"Section {rel_path} missing updateField('{camel}', …) — the toggle is "
            f"rendered but doesn't write back to the project."
        )


# ---------------------------------------------------------------------------
# Layer 7 — Zod schema in recon-preset-schema.ts
# ---------------------------------------------------------------------------

def test_zod_schema_lists_every_ai_toggle_as_bool():
    """The Zod schema is what validates AI-generated presets. Missing a key
    here means the LLM-produced preset gets silently stripped."""
    content = _read("webapp/src/lib/recon-preset-schema.ts")
    # Find the reconPresetSchema z.object literal body.
    obj_start = content.find("export const reconPresetSchema = z.object({")
    assert obj_start != -1, "reconPresetSchema literal not found"
    obj_end = content.find("})", obj_start)
    block = content[obj_start:obj_end]
    for _snake, camel, _sql in AI_TOGGLES:
        # The entry shape is:   camelCase: bool,
        needle = f"{camel}: bool,"
        assert needle in block, (
            f"reconPresetSchema is missing `{needle}` — the AI-preset Zod parser "
            f"will silently strip this key."
        )


# ---------------------------------------------------------------------------
# Layer 8 — RECON_PARAMETER_CATALOG in recon-preset-schema.ts
# ---------------------------------------------------------------------------

def test_recon_parameter_catalog_documents_every_ai_toggle():
    """RECON_PARAMETER_CATALOG is embedded in the LLM system prompt. Missing
    a key means the preset-generation LLM will never propose setting it."""
    content = _read("webapp/src/lib/recon-preset-schema.ts")
    cat_start = content.find("export const RECON_PARAMETER_CATALOG = `")
    assert cat_start != -1, "RECON_PARAMETER_CATALOG literal not found"
    cat_end = content.find("`", cat_start + len("export const RECON_PARAMETER_CATALOG = `"))
    block = content[cat_start:cat_end]
    for _snake, camel, _sql in AI_TOGGLES:
        needle = f"- {camel}: boolean -"
        assert needle in block, (
            f"RECON_PARAMETER_CATALOG missing description for {camel}. "
            f"Expected a line starting with `- {camel}: boolean -`."
        )


# ---------------------------------------------------------------------------
# Layer 9 — Workflow-view tooltips
# ---------------------------------------------------------------------------

def test_workflow_tooltips_mention_ai_hooks_in_relevant_tools():
    """Each host tool's tooltip text should at least reference the AI hook
    behaviour so operators discover it from the workflow view."""
    content = _read("webapp/src/components/projects/ProjectForm/WorkflowView/inputLogicTooltips.tsx")
    # A coarse check — the tooltip file is one big TSX. We just verify each
    # AI-aware tool's section in the file contains an "AI" keyword reference.
    # The granular per-property assertion is too brittle for tooltip prose.
    for tool in ("SubdomainDiscovery", "Naabu", "Masscan", "Nmap", "Httpx"):
        marker = f"const {tool} = ("
        tool_start = content.find(marker)
        assert tool_start != -1, f"tooltip block for {tool} not found"
        # Find the closing ')' of the JSX expression — heuristic: the next
        # blank-line + const declaration. Use the next `const ` after a `)` as a
        # rough boundary, falling back to end-of-file.
        end_marker_idx = content.find("\nconst ", tool_start + len(marker))
        block = content[tool_start:end_marker_idx if end_marker_idx != -1 else len(content)]
        assert "AI" in block, (
            f"tooltip block for {tool} mentions no AI hook — operators won't discover "
            f"the lap-1 AI annotations from the workflow view."
        )


# ---------------------------------------------------------------------------
# Cross-layer parity — every layer carries exactly the same 9 keys
# ---------------------------------------------------------------------------

def test_no_extra_lap1_ai_toggles_leaked_into_default_settings():
    """Guard against accidentally landing a 10th AI toggle that doesn't make
    it through all 9 layers. If you want a 10th, add it to AI_TOGGLES first."""
    from recon.project_settings import DEFAULT_SETTINGS
    ai_keys = {
        k for k in DEFAULT_SETTINGS
        if "AI" in k and any(
            k.startswith(prefix) for prefix in (
                "DOMAIN_RECON_AI_", "PORT_SCAN_AI_", "MASSCAN_AI_",
                "NMAP_AI_", "HTTP_PROBE_AI_", "JS_RECON_AI_",
            )
        )
    }
    expected = {snake for snake, _, _ in AI_TOGGLES}
    extra = ai_keys - expected
    missing = expected - ai_keys
    assert not extra, f"DEFAULT_SETTINGS has extra lap-1 AI keys not in AI_TOGGLES: {extra}"
    assert not missing, f"AI_TOGGLES expected keys missing from DEFAULT_SETTINGS: {missing}"


# ---------------------------------------------------------------------------
# Standalone runner (no pytest dependency)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    failures: list[tuple[str, str]] = []
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append((name, str(exc)))
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append((name, f"{type(exc).__name__}: {exc}"))
    print()
    print(f"{passed} passed, {len(failures)} failed")
    if failures:
        print()
        print("Failures:")
        for n, err in failures:
            print(f"  - {n}: {err}")
        sys.exit(1)
    sys.exit(0)
