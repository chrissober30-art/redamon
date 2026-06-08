"""Smoke + regression + settings-integrity tests for AI Surface Recon.

- smoke: every new module imports; the runner survives an empty graph.
- settings integrity: every AI_SURFACE_RECON_* DEFAULT key has a fetch mapping
  AND a Prisma field (9-layer chain not silently broken).
- regression: the 3 main.py call sites, partial-recon dispatch, phase pattern,
  graph-inputs case, mixin registration, stealth overrides.

Run inside the recon image:
    docker run --rm --entrypoint python3 \
        -v "$PWD/recon:/app/recon:ro" -v "$PWD/graph_db:/app/graph_db:ro" \
        -v "$PWD/recon_orchestrator:/app/recon_orchestrator:ro" \
        -v "$PWD/webapp:/app/webapp:ro" -w /app \
        redamon-recon:latest recon/tests/test_ai_surface_recon_smoke.py
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _read(rel):
    return (PROJECT_ROOT / rel).read_text(encoding="utf-8")


def _camel(snake: str) -> str:
    parts = snake.lower().split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# --- smoke -------------------------------------------------------------------
def test_modules_import():
    import importlib
    for mod in ("recon.helpers.ai_signal_catalog",
                "recon.helpers.probe_pack_engine",
                "recon.main_recon_modules.ai_surface_recon",
                "recon.partial_recon_modules.ai_surface_recon",
                "graph_db.mixins.recon.ai_surface_recon_mixin"):
        importlib.import_module(mod)


def test_runner_survives_empty_graph():
    from recon.main_recon_modules import ai_surface_recon as m
    out = m.run_ai_surface_recon(
        {"metadata": {"project_id": "p"}, "resource_enum": {"by_base_url": {}},
         "http_probe": {"by_url": {}}, "port_scan": {}},
        settings={"AI_SURFACE_RECON_ENABLED": True,
                  "AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED": False})
    assert "ai_surface_recon" in out


def test_mixin_registered_in_recon_mixin():
    src = _read("graph_db/mixins/recon_mixin.py")
    assert "AiSurfaceReconMixin" in src
    from graph_db.mixins.recon_mixin import ReconMixin
    assert any(b.__name__ == "AiSurfaceReconMixin" for b in ReconMixin.__mro__)


# --- settings 9-layer integrity ---------------------------------------------
def test_settings_default_fetch_prisma_consistency():
    ps = _read("recon/project_settings.py")
    prisma = _read("webapp/prisma/schema.prisma")

    default_keys = set(re.findall(r"'(AI_SURFACE_RECON_[A-Z_]+)':", ps))
    fetch_keys = set(re.findall(r"settings\['(AI_SURFACE_RECON_[A-Z_]+)'\]", ps))

    assert default_keys, "no AI_SURFACE_RECON_* keys found in DEFAULT_SETTINGS"
    assert default_keys == fetch_keys, (
        f"DEFAULT vs fetch mismatch: only-default={default_keys - fetch_keys}, "
        f"only-fetch={fetch_keys - default_keys}")

    missing_fetch_camel = []
    missing_prisma = []
    for key in sorted(default_keys):
        camel = _camel(key)
        if f"project.get('{camel}'" not in ps:
            missing_fetch_camel.append(camel)
        if camel not in prisma:
            missing_prisma.append(camel)
    assert not missing_fetch_camel, f"fetch camelCase missing: {missing_fetch_camel}"
    assert not missing_prisma, f"Prisma fields missing: {missing_prisma}"


def test_master_toggle_exists():
    ps = _read("recon/project_settings.py")
    assert "'AI_SURFACE_RECON_ENABLED': True" in ps


# --- stealth -----------------------------------------------------------------
def test_stealth_overrides_present():
    ps = _read("recon/project_settings.py")
    assert "settings['AI_SURFACE_RECON_MAX_WORKERS'] = 2" in ps
    assert "settings['AI_SURFACE_RECON_MCP_LIST_TOOLS_ENABLED'] = False" in ps
    assert "settings['AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED'] = False" in ps


# --- pipeline wiring regression ---------------------------------------------
def test_main_py_three_call_sites_and_import():
    main = _read("recon/main.py")
    assert "from recon.main_recon_modules.ai_surface_recon import run_ai_surface_recon" in main
    assert "def _maybe_run_ai_surface(" in main
    assert main.count("_maybe_run_ai_surface(") >= 4  # 1 def + 3 call sites


def test_partial_recon_dispatch():
    pr = _read("recon/partial_recon.py")
    assert 'elif tool_id == "AiSurfaceRecon":' in pr
    assert "run_ai_surface_partial(config)" in pr


def test_phase_pattern_added():
    cm = _read("recon_orchestrator/container_manager.py")
    assert "AI Surface Recon" in cm
    assert "4.5" in cm


def test_graph_inputs_case():
    src = _read("graph_db/mixins/recon/user_input_mixin.py")
    assert 'elif tool_id == "AiSurfaceRecon":' in src
    assert "existing_mcp_endpoints_count" in src


def test_text_to_cypher_synced():
    base = _read("agentic/prompts/base.py")
    assert "ai_surface_recon" in base  # vuln source documented
    assert "ai_mcp_server_name" in base


if __name__ == "__main__":
    failures = []
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"  PASS  {name}"); passed += 1
            except AssertionError as e:
                print(f"  FAIL  {name}: {e}"); failures.append((name, str(e)))
            except Exception as e:
                print(f"  ERROR {name}: {type(e).__name__}: {e}")
                failures.append((name, f"{type(e).__name__}: {e}"))
    print(f"\n{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)
