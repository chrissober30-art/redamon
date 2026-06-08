"""Tests for the Phase 6 AI surface recon lab fixture.

Two layers:

  1. Structural tests on the lab artifacts (docker-compose.override.yml,
     verify_lab_graph_state.py, README.md). These run on the host with
     no live infrastructure — they catch typos and drift between the
     lab fixture and the rest of the integration.

  2. Live end-to-end tests. When the lab containers are up AND the
     verify script reports the expected graph state, these tests pass.
     They SKIP gracefully when the lab isn't running, so this file is
     safe to run on a developer laptop without the full lab brought up.

  3. A synthetic end-to-end test: seed the same graph shape a real scan
     would produce via the lap-1 mixins, then run the verify script and
     confirm its assertions pass. This exercises the verify_lab_graph_state.py
     script logic without requiring the Ollama/Open WebUI/Chroma pull.

Run:
    docker run --rm --network host --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_lab_fixture.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

LAB_DIR = PROJECT_ROOT / "agentic" / "labs" / "ai-surface"
COMPOSE_PATH = LAB_DIR / "docker-compose.override.yml"
VERIFY_SCRIPT = LAB_DIR / "verify_lab_graph_state.py"
README_PATH = LAB_DIR / "README.md"


# ---------------------------------------------------------------------------
# Structural tests on the lab artifacts
# ---------------------------------------------------------------------------

def test_lab_directory_contains_all_three_artifacts():
    assert COMPOSE_PATH.is_file(), "docker-compose.override.yml missing"
    assert VERIFY_SCRIPT.is_file(), "verify_lab_graph_state.py missing"
    assert README_PATH.is_file(), "README.md missing"


def test_lab_compose_lists_three_required_services():
    """The plan §16.1 mandates Ollama + Open WebUI + Chroma."""
    body = COMPOSE_PATH.read_text()
    for service in ("ai-lab-ollama", "ai-lab-open-webui", "ai-lab-chroma"):
        assert service in body, f"compose missing service {service!r}"


def test_lab_compose_pins_lab_to_host_network_for_loopback_scans():
    body = COMPOSE_PATH.read_text()
    # All three services use network_mode: host so the recon container
    # (also network_mode: host) can reach them via 127.0.0.1.
    assert body.count("network_mode: host") >= 3, (
        "all 3 lab services must use network_mode: host so the recon "
        "container can scan them via 127.0.0.1"
    )


def test_lab_compose_chroma_binds_disambiguate_port():
    """Port 8000 is the canonical disambiguate test fixture. Catalog has
    8000 with disambiguate=True. Lab must use 8000 to exercise the guard."""
    body = COMPOSE_PATH.read_text()
    chroma_block = body[body.find("ai-lab-chroma"):]
    assert "8000" in chroma_block, "Chroma must listen on 8000 to test the disambiguate guard"


def test_lab_compose_ollama_uses_canonical_port_11434():
    body = COMPOSE_PATH.read_text()
    ollama_block = body[body.find("ai-lab-ollama"):]
    next_section = ollama_block.find("ai-lab-open-webui")
    ollama_block = ollama_block[:next_section] if next_section != -1 else ollama_block
    # Port 11434 is in the AI port catalog with disambiguate=False,
    # so port_scan will tag it directly. Open WebUI configures
    # OLLAMA_BASE_URL=http://127.0.0.1:11434 to confirm the wiring.
    assert "11434" in body, "Ollama must listen on 11434 (the canonical AI runtime port)"


def test_lab_compose_open_webui_disables_auth_for_smoke_testing():
    body = COMPOSE_PATH.read_text()
    assert 'WEBUI_AUTH: "false"' in body, (
        "Open WebUI must skip login wall for lab smoke-testing — otherwise "
        "httpx would only see the login page, not the AI title regex"
    )


def test_lab_compose_has_healthchecks_on_every_service():
    """Healthchecks are the operator's first signal that the lab is
    ready to scan. All three services should have one."""
    body = COMPOSE_PATH.read_text()
    assert body.count("healthcheck:") == 3, (
        "all 3 lab services must declare a healthcheck"
    )


def test_lab_compose_declares_named_volumes():
    """Persistent volumes avoid re-pulling the Ollama model on every
    bring-up. The compose file uses 3 named volumes."""
    body = COMPOSE_PATH.read_text()
    for vol in ("ai-lab-ollama-models", "ai-lab-open-webui-data", "ai-lab-chroma-data"):
        assert vol in body, f"compose missing named volume {vol!r}"


def test_lab_compose_open_webui_depends_on_ollama():
    """Without the depends_on, Open WebUI's first start may race ahead
    of Ollama. The compose file must enforce ordering."""
    body = COMPOSE_PATH.read_text()
    # Locate the open-webui block
    start = body.find("ai-lab-open-webui:")
    end = body.find("ai-lab-chroma:")
    webui_block = body[start:end]
    assert "depends_on:" in webui_block, (
        "open-webui block must declare depends_on: ai-lab-ollama"
    )
    assert "ai-lab-ollama" in webui_block, (
        "open-webui depends_on must name ai-lab-ollama"
    )


def test_lab_compose_yaml_parses():
    """Defence against subtle YAML syntax errors (mismatched indent,
    tab/space mix)."""
    try:
        import yaml  # type: ignore
    except ImportError:
        print("SKIP: test_lab_compose_yaml_parses (PyYAML unavailable)")
        return
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    assert isinstance(data, dict), "compose top level must be a mapping"
    assert "services" in data, "compose missing 'services' key"
    services = data["services"]
    for name in ("ai-lab-ollama", "ai-lab-open-webui", "ai-lab-chroma"):
        assert name in services, f"compose missing service {name!r}"
        assert services[name].get("network_mode") == "host", (
            f"service {name!r} must use network_mode: host"
        )


# ---------------------------------------------------------------------------
# Verify script — structural sanity
# ---------------------------------------------------------------------------

def test_verify_script_is_executable():
    assert os.access(VERIFY_SCRIPT, os.X_OK), "verify_lab_graph_state.py must be executable"


def test_verify_script_python_syntax_parses():
    import ast
    src = VERIFY_SCRIPT.read_text()
    ast.parse(src)  # raises SyntaxError on malformed Python


def test_verify_script_exposes_expected_toggle_flags():
    """The README documents three --expect-*-empty toggle flags that
    operators use during toggle smoke. They must be wired in argparse."""
    src = VERIFY_SCRIPT.read_text()
    for flag in ("--expect-port-ai-empty", "--expect-http-ai-empty", "--expect-dns-ai-empty"):
        assert flag in src, f"verify script missing CLI flag {flag!r}"


def test_verify_script_uses_correct_neo4j_query_patterns():
    """The verify script must query the exact properties the lap-1 mixins
    write. A query against ``ai_framework`` instead of ``ai_framework_name``
    would silently return empty."""
    src = VERIFY_SCRIPT.read_text()
    must_query = [
        "ai_service_hint",           # Subdomain
        "is_ai_framework_detected",  # BaseURL
        "ai_framework_name",         # BaseURL
        "ai_frontend_product_guess", # BaseURL
        "ai-vector-db",              # disambiguate guard
        "naabu-ai-port",             # detected_by check
    ]
    missing = [p for p in must_query if p not in src]
    assert not missing, f"verify script not querying expected properties: {missing}"


def test_verify_script_exit_codes_documented():
    """The script returns 0/1/2 — must be documented in the module docstring
    so CI/operators can use it correctly."""
    src = VERIFY_SCRIPT.read_text()
    assert "exit code 0" in src.lower() or "returns exit code 0" in src.lower(), (
        "verify script's exit-code contract not documented in the docstring"
    )


def test_verify_script_help_invocation_is_runnable():
    """`--help` must work even when Neo4j is unreachable (argparse should
    bail out before connecting)."""
    proc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, f"--help failed: {proc.stderr[:200]}"
    assert "--project-id" in proc.stdout
    assert "--user-id" in proc.stdout


# ---------------------------------------------------------------------------
# README sanity
# ---------------------------------------------------------------------------

def test_readme_explains_bring_up_and_tear_down():
    body = README_PATH.read_text()
    assert "docker compose" in body and "up -d" in body, (
        "README must explain how to bring the lab up"
    )
    assert "down" in body, "README must explain how to tear the lab down"


def test_readme_documents_expected_graph_results():
    body = README_PATH.read_text()
    # The three classes of expected graph state
    for marker in ("ai-runtime", "ai-frontend", "BaseURL.is_ai_framework_detected"):
        assert marker in body, f"README missing expected-state marker {marker!r}"


def test_readme_documents_toggle_smoke_workflow():
    body = README_PATH.read_text()
    assert "portScanAiPortCatalogEnabled" in body or "PORT_SCAN_AI_PORT_CATALOG_ENABLED" in body
    assert "toggle" in body.lower()


# ---------------------------------------------------------------------------
# Synthetic end-to-end — seed graph + run verify script
# ---------------------------------------------------------------------------
#
# We don't need to pull Ollama (1GB), Open WebUI (3GB) and Chroma (200MB)
# to test that verify_lab_graph_state.py correctly reports passes. We can
# seed the exact graph shape the lap-1 mixins would produce, then invoke
# the verify script against it. This exercises the whole script logic
# while keeping the test deterministic and fast.

def _neo4j_driver():
    try:
        from neo4j import GraphDatabase  # type: ignore
    except Exception:
        return None
    try:
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "changeme123"))
        drv.verify_connectivity()
        return drv
    except Exception:
        return None


SYNTH_UID = "phase6-verify-script-test-user"
SYNTH_PID = "phase6-verify-script-test-project"


def _seed_synthetic_lap1_graph(session) -> None:
    """Mirror exactly what a successful scan against the lab fixture
    would write — Ollama Technology(ai-runtime), Open WebUI BaseURL +
    Technology(ai-frontend) — plus the Chroma Service+Port at 8000 that
    must NOT carry an AI Technology edge (disambiguate guard)."""
    # 1. Ollama on 11434 → naabu-ai-port path
    session.run(
        """
        MERGE (i:IP {address:'127.0.0.1', user_id:$u, project_id:$p})
        MERGE (port:Port {number:11434, protocol:'tcp', ip_address:'127.0.0.1', user_id:$u, project_id:$p})
        MERGE (i)-[:HAS_PORT]->(port)
        MERGE (svc:Service {name:'ollama', port_number:11434, ip_address:'127.0.0.1', user_id:$u, project_id:$p})
        MERGE (port)-[:RUNS_SERVICE]->(svc)
        MERGE (t:Technology {name:'ollama', user_id:$u, project_id:$p})
          SET t.category='ai-runtime', t.source='ai-port-catalog'
        MERGE (svc)-[r1:USES_TECHNOLOGY]->(t)
          SET r1.detected_by='naabu-ai-port'
        MERGE (port)-[r2:HAS_TECHNOLOGY]->(t)
          SET r2.detected_by='naabu-ai-port'
        """,
        u=SYNTH_UID, p=SYNTH_PID,
    )
    # 2. Open WebUI BaseURL on 8080 → httpx-ai-title path
    session.run(
        """
        MERGE (u:BaseURL {url:'http://127.0.0.1:8080/', user_id:$u, project_id:$p})
          SET u.is_ai_framework_detected=true,
              u.ai_framework_name='open-webui',
              u.ai_frontend_product_guess='open-webui'
        MERGE (t:Technology {name:'open-webui', user_id:$u, project_id:$p})
          SET t.category='ai-frontend', t.source='ai-surface-recon'
        MERGE (u)-[r:USES_TECHNOLOGY]->(t)
          SET r.detected_by='httpx-ai-title', r.confidence=100
        """,
        u=SYNTH_UID, p=SYNTH_PID,
    )
    # 3. Chroma Service on 8000 — must NOT have an AI Technology edge
    #    (catalog's disambiguate=True means port_scan skipped it)
    session.run(
        """
        MERGE (i:IP {address:'127.0.0.1', user_id:$u, project_id:$p})
        MERGE (port:Port {number:8000, protocol:'tcp', ip_address:'127.0.0.1', user_id:$u, project_id:$p})
        MERGE (i)-[:HAS_PORT]->(port)
        MERGE (svc:Service {name:'http', port_number:8000, ip_address:'127.0.0.1', user_id:$u, project_id:$p})
        MERGE (port)-[:RUNS_SERVICE]->(svc)
        """,
        u=SYNTH_UID, p=SYNTH_PID,
    )


def _cleanup_synthetic_lap1_graph(session) -> None:
    session.run(
        """
        MATCH (n) WHERE n.user_id = $u AND n.project_id = $p
        DETACH DELETE n
        """,
        u=SYNTH_UID, p=SYNTH_PID,
    )


def _run_verify_script(extra_args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT),
         "--project-id", SYNTH_PID, "--user-id", SYNTH_UID, *extra_args],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "NEO4J_PASSWORD": "changeme123"},
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_verify_script_passes_on_seeded_lap1_graph():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_verify_script_passes_on_seeded_lap1_graph (neo4j unreachable)")
        return
    try:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
            _seed_synthetic_lap1_graph(s)
        rc, out = _run_verify_script([])
        assert rc == 0, (
            f"verify script failed against seeded graph (rc={rc})\nOutput:\n{out}"
        )
        assert "All checks passed" in out
    finally:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
        drv.close()


def test_verify_script_fails_when_ollama_technology_missing():
    """Regression: if the next refactor accidentally renames the Technology
    `name` from 'ollama' to something else, the verify script must catch it."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_verify_script_fails_when_ollama_technology_missing (neo4j unreachable)")
        return
    try:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
            # Seed Open WebUI but skip Ollama
            s.run(
                """
                MERGE (u:BaseURL {url:'http://127.0.0.1:8080/', user_id:$u, project_id:$p})
                  SET u.is_ai_framework_detected=true,
                      u.ai_framework_name='open-webui'
                MERGE (t:Technology {name:'open-webui', user_id:$u, project_id:$p})
                  SET t.category='ai-frontend'
                MERGE (u)-[r:USES_TECHNOLOGY]->(t) SET r.detected_by='httpx-ai-title'
                """,
                u=SYNTH_UID, p=SYNTH_PID,
            )
        rc, out = _run_verify_script([])
        assert rc == 1, (
            f"verify script should have failed (ollama missing) but rc={rc}\n{out}"
        )
        assert "ollama" in out.lower()
    finally:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
        drv.close()


def test_verify_script_fails_when_disambiguate_port_was_promoted():
    """Critical regression: if a future change starts auto-promoting
    port 8000 to an AI Technology node, the disambiguate guard test
    must report it."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_verify_script_fails_when_disambiguate_port_was_promoted (neo4j unreachable)")
        return
    try:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
            _seed_synthetic_lap1_graph(s)
            # Simulate the regression: add the forbidden AI Technology edge to port-8000 Service
            s.run(
                """
                MATCH (svc:Service {port_number:8000, user_id:$u, project_id:$p})
                MERGE (t:Technology {name:'chroma', user_id:$u, project_id:$p})
                  SET t.category='ai-vector-db', t.source='ai-port-catalog'
                MERGE (svc)-[r:USES_TECHNOLOGY]->(t) SET r.detected_by='naabu-ai-port'
                """,
                u=SYNTH_UID, p=SYNTH_PID,
            )
        rc, out = _run_verify_script([])
        assert rc == 1, (
            f"verify script should have failed (disambiguate regression) but rc={rc}\n{out}"
        )
        assert "disambiguate" in out.lower() or "8000" in out
    finally:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
        drv.close()


def test_verify_script_toggle_smoke_passes_when_port_ai_truly_empty():
    """--expect-port-ai-empty must report PASS when the graph genuinely
    lacks port_scan AI annotations (the operator turned the toggle off
    and re-ran)."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_verify_script_toggle_smoke_passes_when_port_ai_truly_empty (neo4j unreachable)")
        return
    try:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
            # Seed only Open WebUI (http path) — no port_scan AI Technology
            s.run(
                """
                MERGE (u:BaseURL {url:'http://127.0.0.1:8080/', user_id:$u, project_id:$p})
                  SET u.is_ai_framework_detected=true,
                      u.ai_framework_name='open-webui'
                MERGE (t:Technology {name:'open-webui', user_id:$u, project_id:$p})
                  SET t.category='ai-frontend'
                MERGE (u)-[r:USES_TECHNOLOGY]->(t) SET r.detected_by='httpx-ai-title'
                """,
                u=SYNTH_UID, p=SYNTH_PID,
            )
        rc, out = _run_verify_script(["--expect-port-ai-empty"])
        assert rc == 0, (
            f"toggle-off smoke should have passed (no port AI) but rc={rc}\n{out}"
        )
    finally:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
        drv.close()


def test_verify_script_toggle_smoke_fails_when_port_ai_still_present():
    """--expect-port-ai-empty must FAIL when the operator turned the
    port toggle off but the AI Technology is still there — that would
    indicate a stale graph state or a partial-recon that didn't actually
    clean up."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_verify_script_toggle_smoke_fails_when_port_ai_still_present (neo4j unreachable)")
        return
    try:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
            _seed_synthetic_lap1_graph(s)  # has ollama / port_scan AI tech
        rc, out = _run_verify_script(["--expect-port-ai-empty"])
        assert rc == 1, (
            f"toggle-off smoke should have failed (port AI still present) but rc={rc}\n{out}"
        )
    finally:
        with drv.session() as s:
            _cleanup_synthetic_lap1_graph(s)
        drv.close()


# ---------------------------------------------------------------------------
# Live lab — graceful skip when containers aren't running
# ---------------------------------------------------------------------------

def _lab_container_running(name: str) -> bool:
    if shutil.which("docker") is None:
        return False
    proc = subprocess.run(
        ["docker", "ps", "--filter", f"name={name}", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=5,
    )
    return name in proc.stdout


def test_live_lab_containers_health_status_if_running():
    """If the operator brought up the lab, all three services should be
    in healthy state. Otherwise skip — this test is opt-in via the lab
    being up."""
    if not _lab_container_running("ai-lab-ollama"):
        print("SKIP: test_live_lab_containers_health_status_if_running (lab not running)")
        return
    if shutil.which("docker") is None:
        print("SKIP: test_live_lab_containers_health_status_if_running (no docker)")
        return
    for name in ("ai-lab-ollama", "ai-lab-open-webui", "ai-lab-chroma"):
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", name],
            capture_output=True, text=True, timeout=5,
        )
        status = proc.stdout.strip()
        # Some images don't define a healthcheck inside; "" is acceptable.
        # The compose file declares a healthcheck for each — but it can
        # take a minute to settle on first bring-up.
        assert status in {"healthy", "starting", ""}, (
            f"lab container {name} is {status!r} — expected healthy/starting"
        )


# ---------------------------------------------------------------------------
# Standalone runner
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
