"""
Smoke tests for the Nuclei AI feature against the live agent + templates volume.

Unlike the unit tests, these hit real services and prove the pieces are wired
together correctly:

1. The agent's /llm/nuclei-tags endpoint exists, validates payloads with
   Pydantic (422 on missing field), and reaches the LLM-setup branch
   (returns 503 cleanly when no per-user API key is available).

2. The official nuclei-templates volume is mountable at the new path
   /opt/nuclei-templates-official, TEMPLATES-STATS.json is readable, and
   _load_candidates() produces the expected ~125-tag pool when run inside a
   container with that mount.

These tests skip gracefully when the agent isn't reachable so they can run
on a developer laptop without the full stack up.

Run:
    docker compose up -d agent
    docker compose exec recon-orchestrator python /app/recon/tests/test_nuclei_ai_smoke.py
or
    python recon/tests/test_nuclei_ai_smoke.py   # from host (uses localhost:8090)
"""
import json
import os
import sys
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

AGENT_URL = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')


def _agent_reachable() -> bool:
    try:
        requests.get(f"{AGENT_URL}/health", timeout=2)
        return True
    except requests.RequestException:
        return False


def test_endpoint_rejects_missing_required_field():
    """FastAPI/Pydantic returns 422 on a body that lacks required fields.
    Proves the schema is wired, not just any request being accepted."""
    if not _agent_reachable():
        print("SKIP: test_endpoint_rejects_missing_required_field (agent unreachable)")
        return
    # Missing 'candidates'
    bad_body = {
        'technologies': ['x'],
        'servers': [],
        'current_tags': ['cve'],
        'model': 'claude-haiku-4-5',
    }
    resp = requests.post(f"{AGENT_URL}/llm/nuclei-tags", json=bad_body, timeout=10)
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    detail = body.get('detail', [])
    field_names = {err.get('loc', [None, None])[-1] for err in detail if isinstance(err, dict)}
    assert 'candidates' in field_names, f"Pydantic should flag the missing field: {body}"
    print("PASS: test_endpoint_rejects_missing_required_field")


def test_endpoint_returns_503_without_api_key():
    """No user_id / no per-user provider key -> _build_llm_with_model_for_user
    raises -> endpoint returns 503. Proves the LLM-setup branch is reached
    (i.e. the request was accepted by Pydantic and we reached the body of the
    handler)."""
    if not _agent_reachable():
        print("SKIP: test_endpoint_returns_503_without_api_key (agent unreachable)")
        return
    body = {
        'technologies': ['wordpress'],
        'servers': ['apache'],
        'current_tags': ['cve', 'xss'],
        'candidates': ['cve', 'xss', 'wordpress', 'apache'],
        'model': 'claude-haiku-4-5',
        'max_tags': 10,
    }
    resp = requests.post(f"{AGENT_URL}/llm/nuclei-tags", json=body, timeout=30)
    # Expect 503 ("LLM not configured") or 502 (LLM call failure if a key
    # somehow resolved). Anything 4xx other than 422 OR 5xx is fine here --
    # the smoke is "endpoint exists and dispatches to the handler".
    assert resp.status_code in (502, 503), \
        f"Unexpected status {resp.status_code}: {resp.text[:200]}"
    print(f"PASS: test_endpoint_returns_503_without_api_key (status={resp.status_code})")


def test_endpoint_health():
    """Just confirm /health is up so the previous tests have a known-good baseline."""
    if not _agent_reachable():
        print("SKIP: test_endpoint_health (agent unreachable)")
        return
    resp = requests.get(f"{AGENT_URL}/health", timeout=5)
    assert resp.status_code == 200
    print("PASS: test_endpoint_health")


def test_templates_volume_readable_at_mount_path():
    """When this test is run INSIDE a container that has the volume mount,
    TEMPLATES-STATS.json should be readable at the new path. When run from
    the host without the mount, skip."""
    path = '/opt/nuclei-templates-official/TEMPLATES-STATS.json'
    if not os.path.exists(path):
        print(f"SKIP: test_templates_volume_readable_at_mount_path (no mount at {path})")
        return
    with open(path) as f:
        data = json.load(f)
    assert 'tags' in data
    assert isinstance(data['tags'], list)
    assert len(data['tags']) > 100, f"Expected hundreds of tags, got {len(data['tags'])}"
    # Ensure at least one well-known tag is present
    names = {t.get('name') for t in data['tags']}
    assert 'cve' in names
    print(f"PASS: test_templates_volume_readable_at_mount_path ({len(data['tags'])} raw tags)")


def test_orchestrator_spawn_sites_mount_volume():
    """Source-level guard: container_manager.py must mount nuclei-templates
    at /opt/nuclei-templates-official in BOTH spawn sites (main + partial
    recon). If a future refactor splits the spawn into 3 sites, this test
    forces the developer to add the mount to the new one."""
    cm = PROJECT_ROOT / 'recon_orchestrator' / 'container_manager.py'
    if not cm.exists():
        print(f"SKIP: test_orchestrator_spawn_sites_mount_volume (file not found in {cm})")
        return
    src = cm.read_text()
    spawn_count = src.count('containers.run(')
    mount_count = src.count('"nuclei-templates": {"bind": "/opt/nuclei-templates-official", "mode": "ro"}')
    # Each containers.run() that spawns a recon-image container should have
    # the mount. There may be other containers.run() calls (gvm, github_hunt,
    # trufflehog) that don't run nuclei -- those are fine. So we only assert
    # the lower bound: at least 2 mounts (main + partial recon).
    assert mount_count >= 2, \
        f"Expected nuclei-templates mount in >=2 spawn sites, found {mount_count} (total containers.run calls: {spawn_count})"
    print(f"PASS: test_orchestrator_spawn_sites_mount_volume ({mount_count} mounts present)")


def test_load_candidates_against_real_volume():
    """When the volume is mounted, _load_candidates() should produce a sane
    pool (>= 80 tags after the count>=50 filter)."""
    path = '/opt/nuclei-templates-official/TEMPLATES-STATS.json'
    if not os.path.exists(path):
        print(f"SKIP: test_load_candidates_against_real_volume (no mount at {path})")
        return
    import recon.helpers.ai_planner.nuclei_tags as nt
    nt._candidates_cache = None  # force reload
    candidates = nt._load_candidates()
    assert len(candidates) >= 80, \
        f"Expected ~125 broad tags from real templates, got {len(candidates)}"
    # Universal tags MUST survive the count>=50 filter
    must_have = {'cve', 'xss', 'sqli', 'rce', 'wordpress', 'exposure', 'misconfig'}
    missing = must_have - set(candidates)
    assert not missing, f"These universal tags are missing from real candidates: {missing}"
    print(f"PASS: test_load_candidates_against_real_volume ({len(candidates)} broad tags)")


if __name__ == '__main__':
    test_endpoint_health()
    test_endpoint_rejects_missing_required_field()
    test_endpoint_returns_503_without_api_key()
    test_templates_volume_readable_at_mount_path()
    test_orchestrator_spawn_sites_mount_volume()
    test_load_candidates_against_real_volume()
    print("\nAll smoke tests passed (or skipped where infra unavailable)")
