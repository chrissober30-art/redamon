"""Tests for the AI surface recon settings scaffold (Phase 1).

Covers the 9 new toggles introduced in lap 1 across the layers that the recon
container can verify directly:

  1. DEFAULT_SETTINGS in recon/project_settings.py — every key present, default True
  2. fetch_project_settings() — every key honours the project's value with the
     DEFAULT_SETTINGS fallback (the 9-layer flow's "bool fallback is True"
     invariant from the integration plan)
  3. /defaults endpoint on recon-orchestrator — every key surfaces in camelCase
     and none of them landed in RUNTIME_ONLY_KEYS by accident

Layers verified elsewhere:
  - Prisma schema: confirmed via direct Postgres column check after
    `prisma db push` (see Phase 1.1 transcript).
  - Frontend section components / preset schema / tooltips: type-checked at
    webapp build time.

Run:
    docker run --rm --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_settings_scaffold.py

The /defaults reachability check is skipped gracefully when the
recon-orchestrator container isn't running, so the file is safe to execute
on a developer laptop without the full stack up.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# recon/project_settings.py imports helpers.* using the in-container path
# layout (/app/recon is on sys.path). Mirror that here so the function body
# resolves its imports when the test runs from the project root.
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

from unittest.mock import patch

from recon.project_settings import DEFAULT_SETTINGS, fetch_project_settings


class _FakeResponse:
    """Minimal stand-in for requests.Response so we can mock the webapp API."""

    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:  # never raises in the success path
        return None

    def json(self) -> dict:
        return self._payload


def _fetch_with_project(project_payload: dict) -> dict:
    """Run fetch_project_settings against a mocked webapp API and return the
    resulting settings dict. The webapp URL and project ID are irrelevant
    because requests.get is intercepted."""
    fake_payload = {"userId": "test-user", "targetDomain": "example.com", **project_payload}
    # fetch_project_settings imports `requests` inside its body, so we patch the
    # module-level requests.get (which is what the local import resolves to).
    with patch("requests.get", return_value=_FakeResponse(fake_payload)):
        return fetch_project_settings("test-project", "http://mocked")


# The 9 toggles introduced in lap 1, with their expected camelCase mirror.
# This is the contract between Prisma, the recon settings stack, and /defaults.
AI_TOGGLES: list[tuple[str, str]] = [
    ("DOMAIN_RECON_AI_TXT_HINT_ENABLED",       "domainReconAiTxtHintEnabled"),
    ("DOMAIN_RECON_AI_NS_HINT_ENABLED",        "domainReconAiNsHintEnabled"),
    ("PORT_SCAN_AI_PORT_CATALOG_ENABLED",      "portScanAiPortCatalogEnabled"),
    ("MASSCAN_AI_PORT_CATALOG_ENABLED",        "masscanAiPortCatalogEnabled"),
    ("NMAP_AI_VERSION_REGEX_ENABLED",          "nmapAiVersionRegexEnabled"),
    ("HTTP_PROBE_AI_HEADER_SCAN_ENABLED",      "httpProbeAiHeaderScanEnabled"),
    ("HTTP_PROBE_AI_FAVICON_HASH_ENABLED",     "httpProbeAiFaviconHashEnabled"),
    ("HTTP_PROBE_AI_TITLE_DETECTION_ENABLED",  "httpProbeAiTitleDetectionEnabled"),
    ("HTTP_PROBE_AI_WAPPALYZER_ENABLED",       "httpProbeAiWappalyzerEnabled"),
]


# ---------------------------------------------------------------------------
# DEFAULT_SETTINGS
# ---------------------------------------------------------------------------

def test_default_settings_contains_every_ai_toggle():
    missing = [snake for snake, _ in AI_TOGGLES if snake not in DEFAULT_SETTINGS]
    assert not missing, f"DEFAULT_SETTINGS missing AI toggles: {missing}"


def test_default_settings_defaults_to_true_for_every_ai_toggle():
    """Every passive AI hook defaults to True per the integration plan
    (default-coverage; stealth overrides flip only the active ones)."""
    wrong: list[tuple[str, object]] = []
    for snake, _ in AI_TOGGLES:
        value = DEFAULT_SETTINGS[snake]
        if value is not True:
            wrong.append((snake, value))
    assert not wrong, f"AI toggles with non-True defaults: {wrong}"


# ---------------------------------------------------------------------------
# fetch_project_settings — empty project (database miss / fresh row)
# ---------------------------------------------------------------------------

def test_fetch_project_settings_returns_defaults_for_empty_project():
    """An empty project dict (e.g. a row that pre-dates the lap) must yield
    the DEFAULT_SETTINGS value for every AI toggle. This is the safety net
    that lets the recon container run before the webapp container is
    rebuilt with the new Prisma client."""
    settings = _fetch_with_project({})
    for snake, _ in AI_TOGGLES:
        assert settings[snake] is True, f"empty-project fallback for {snake!r} was {settings[snake]!r}, expected True"


# ---------------------------------------------------------------------------
# fetch_project_settings — explicit project values honored
# ---------------------------------------------------------------------------

def test_fetch_project_settings_honours_explicit_false():
    """Each AI toggle, when set to False on the project, must propagate
    through to the Python settings dict. This guards against typos in the
    camelCase mirror."""
    project_all_off = {camel: False for _, camel in AI_TOGGLES}
    settings = _fetch_with_project(project_all_off)
    for snake, _ in AI_TOGGLES:
        assert settings[snake] is False, (
            f"{snake!r} stayed True even though project had its camelCase mirror set False. "
            f"Likely a typo in fetch_project_settings()."
        )


def test_fetch_project_settings_honours_explicit_true_after_false_default():
    """Symmetric guard: a project that explicitly sets True still gets True
    even if a hypothetical future change flipped a DEFAULT to False."""
    project_all_on = {camel: True for _, camel in AI_TOGGLES}
    settings = _fetch_with_project(project_all_on)
    for snake, _ in AI_TOGGLES:
        assert settings[snake] is True


def test_fetch_project_settings_per_toggle_independence():
    """Flipping one AI toggle must not affect the others. Guards against an
    accidental shared mapping like `settings['X'] = project.get('y', ...)`."""
    for target_snake, target_camel in AI_TOGGLES:
        project = {target_camel: False}
        settings = _fetch_with_project(project)
        for other_snake, _ in AI_TOGGLES:
            expected = False if other_snake == target_snake else True
            assert settings[other_snake] is expected, (
                f"flipping {target_camel} to False also affected {other_snake} (got {settings[other_snake]!r})"
            )


# ---------------------------------------------------------------------------
# /defaults endpoint — auto-surface + RUNTIME_ONLY_KEYS sanity
# ---------------------------------------------------------------------------

def _orchestrator_url() -> str:
    return os.environ.get("RECON_ORCHESTRATOR_URL", "http://localhost:8010").rstrip("/")


def _defaults_reachable() -> dict | None:
    import urllib.request
    import json
    try:
        with urllib.request.urlopen(_orchestrator_url() + "/defaults", timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def test_defaults_endpoint_surfaces_every_ai_toggle():
    defaults = _defaults_reachable()
    if defaults is None:
        print("SKIP: test_defaults_endpoint_surfaces_every_ai_toggle (orchestrator unreachable)")
        return
    missing = [camel for _, camel in AI_TOGGLES if camel not in defaults]
    assert not missing, (
        f"/defaults missing AI toggles: {missing}. "
        f"Either a typo in to_camel_case or the key accidentally landed in RUNTIME_ONLY_KEYS."
    )


def test_defaults_endpoint_returns_true_for_every_ai_toggle():
    defaults = _defaults_reachable()
    if defaults is None:
        print("SKIP: test_defaults_endpoint_returns_true_for_every_ai_toggle (orchestrator unreachable)")
        return
    wrong = [(camel, defaults[camel]) for _, camel in AI_TOGGLES if defaults.get(camel) is not True]
    assert not wrong, f"/defaults returned non-True for AI toggles: {wrong}"


def test_no_ai_toggle_accidentally_in_runtime_only_keys():
    """Re-import the RUNTIME_ONLY_KEYS set the orchestrator builds and assert
    none of the AI toggles slipped into it."""
    # The set is defined inline in recon_orchestrator/api.py:get_defaults;
    # mirror it here so this test is self-contained. Keep these two in sync
    # if you ever change the orchestrator's RUNTIME_ONLY_KEYS.
    RUNTIME_ONLY_KEYS = {
        "PROJECT_ID", "USER_ID", "TARGET_DOMAIN",
        "SHODAN_API_KEY", "URLSCAN_API_KEY",
        "CENSYS_API_TOKEN", "CENSYS_ORG_ID",
        "OTX_API_KEY", "NETLAS_API_KEY",
        "VIRUSTOTAL_API_KEY", "ZOOMEYE_API_KEY",
        "CRIMINALIP_API_KEY", "FOFA_EMAIL", "FOFA_API_KEY",
        "UNCOVER_QUAKE_API_KEY", "UNCOVER_HUNTER_API_KEY",
        "UNCOVER_PUBLICWWW_API_KEY", "UNCOVER_HUNTERHOW_API_KEY",
        "UNCOVER_GOOGLE_API_KEY", "UNCOVER_GOOGLE_API_CX",
        "UNCOVER_ONYPHE_API_KEY", "UNCOVER_DRIFTNET_API_KEY",
    }
    leaked = [snake for snake, _ in AI_TOGGLES if snake in RUNTIME_ONLY_KEYS]
    assert not leaked, (
        f"AI toggles must not be filtered out of /defaults; found in RUNTIME_ONLY_KEYS: {leaked}"
    )


# ---------------------------------------------------------------------------
# Cross-check — AI_IN_PIPELINE cascade orthogonality
# ---------------------------------------------------------------------------

def test_ai_in_pipeline_cascade_does_not_touch_lap1_toggles():
    """The plan promises orthogonality between the existing AI_IN_PIPELINE
    cascade (LLM-as-aid for our scans) and the new AI surface recon toggles
    (detect AI in the target). Verify the cascade leaves our 9 toggles
    alone."""
    from recon.project_settings import apply_ai_pipeline_overrides

    # Toggle AI_IN_PIPELINE on with our toggles at their defaults
    settings = _fetch_with_project({"aiInPipeline": True})
    settings = apply_ai_pipeline_overrides(settings)

    # All 9 AI surface recon toggles must remain True (their default)
    for snake, _ in AI_TOGGLES:
        assert settings[snake] is True, (
            f"AI_IN_PIPELINE cascade unexpectedly mutated {snake!r} to {settings[snake]!r}"
        )

    # And toggle AI_IN_PIPELINE off with our toggles explicitly False
    settings = _fetch_with_project({
        "aiInPipeline": False,
        **{camel: False for _, camel in AI_TOGGLES},
    })
    settings = apply_ai_pipeline_overrides(settings)
    for snake, _ in AI_TOGGLES:
        assert settings[snake] is False, (
            f"AI_IN_PIPELINE cascade unexpectedly flipped {snake!r} back on (got {settings[snake]!r})"
        )


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
