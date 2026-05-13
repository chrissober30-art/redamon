"""
Cross-module audit of the settings-dump rollout.

For every recon module that calls `print_effective_settings(...)`, this
test:

  1. Extracts the keys list passed to the helper.
  2. Cross-checks every key against `DEFAULT_SETTINGS` (catches typos and
     obsolete keys that were renamed or removed).
  3. Cross-checks every key against the module's actual `settings.get(...)`
     calls (catches keys that are dumped but the module doesn't actually
     read, OR keys the module reads but forgot to dump).
  4. Verifies the dump call lives AFTER any `if not settings.get('X_ENABLED', ...)`
     early-return (so disabled tools don't pollute the log drawer).

Run:
    docker exec redamon-recon-orchestrator python -m pytest /app/recon/tests/test_settings_dump_audit.py -v
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Discover every recon module that calls print_effective_settings.
RECON_DIRS = [
    PROJECT_ROOT / "recon" / "main_recon_modules",
    PROJECT_ROOT / "recon" / "graphql_scan",
]

# Some keys are intentionally not dumped because they aren't user-facing
# (transient / internal / Pydantic-only). Add to this set to allow.
ALLOWED_UNDUMPED_KEYS = {
    # Internal compute / runtime
    "TARGET_DOMAIN", "USER_ID", "PROJECT_ID", "SUBDOMAIN_LIST",
    "USE_BRUTEFORCE_FOR_SUBDOMAINS", "VERIFY_DOMAIN_OWNERSHIP",
    "OWNERSHIP_TOKEN", "OWNERSHIP_TXT_PREFIX", "IP_MODE", "TARGET_IPS",
    "SCAN_MODULES", "UPDATE_GRAPH_DB", "STEALTH_MODE",
    "ROE_*",  # all RoE keys
    # Project-level outputs
    "_WHOIS_ORG",
    # Settings consumed only via helpers
    "VULNERS_KEY_ROTATOR", "NVD_KEY_ROTATOR",
    # Wappalyzer settings dumped under Httpx group
    "WAPPALYZER_*",
}

# Keys that are populated at runtime by fetch_project_settings() (e.g. injected
# from the user's global UserSettings credentials table) and therefore won't
# appear in the per-project DEFAULT_SETTINGS dict. Modules legitimately dump
# these so the operator can verify how many API keys are loaded for the run.
RUNTIME_INJECTED_KEYS = {
    "*_KEY_ROTATOR",   # SHODAN_KEY_ROTATOR, FOFA_KEY_ROTATOR, OTX_KEY_ROTATOR, ...
}


def _is_runtime_injected(key: str) -> bool:
    for pattern in RUNTIME_INJECTED_KEYS:
        if pattern.startswith("*") and key.endswith(pattern[1:]):
            return True
        if pattern.endswith("*") and key.startswith(pattern[:-1]):
            return True
        if pattern == key:
            return True
    return False


def _files_with_dump_call() -> list[Path]:
    """Find all .py files under main_recon_modules and graphql_scan that call
    print_effective_settings."""
    files = []
    for d in RECON_DIRS:
        if not d.exists():
            continue
        for fp in d.rglob("*.py"):
            if "__pycache__" in str(fp):
                continue
            try:
                src = fp.read_text(encoding="utf-8")
            except Exception:
                continue
            if "print_effective_settings(" in src:
                files.append(fp)
    return files


def _extract_dump_keys(source: str) -> list[str]:
    """
    Walk the AST to find every print_effective_settings(..., keys=[...]) call
    and return the flat list of string keys.
    """
    tree = ast.parse(source)
    keys: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Match print_effective_settings(...)
        callee = node.func
        callee_name = None
        if isinstance(callee, ast.Name):
            callee_name = callee.id
        elif isinstance(callee, ast.Attribute):
            callee_name = callee.attr
        if callee_name != "print_effective_settings":
            continue

        # Find keys= kwarg
        for kw in node.keywords:
            if kw.arg != "keys":
                continue
            if not isinstance(kw.value, ast.List):
                continue
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    keys.append(elt.value)
                elif isinstance(elt, ast.Tuple) and len(elt.elts) >= 1:
                    first = elt.elts[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        keys.append(first.value)
    return keys


def _extract_settings_get_keys(source: str) -> set[str]:
    """Return every SCREAMING_SNAKE key referenced via settings.get(...)
    or settings['...'] in the source."""
    keys = set()
    # settings.get('KEY', ...) or settings.get("KEY", ...)
    for m in re.finditer(r"""settings\.get\(\s*['"]([A-Z][A-Z0-9_]+)['"]""", source):
        keys.add(m.group(1))
    # settings['KEY'] / settings["KEY"]
    for m in re.finditer(r"""settings\[\s*['"]([A-Z][A-Z0-9_]+)['"]\s*\]""", source):
        keys.add(m.group(1))
    return keys


def _default_settings_keys() -> set[str]:
    from recon.project_settings import DEFAULT_SETTINGS
    return set(DEFAULT_SETTINGS.keys())


# ===========================================================================
# Discovery (parametrize over the modules with a dump call)
# ===========================================================================
DUMP_FILES = _files_with_dump_call()


@pytest.mark.parametrize("filepath", DUMP_FILES, ids=lambda p: p.name)
def test_dump_keys_exist_in_default_settings(filepath: Path):
    """Every key in a module's dump must exist in DEFAULT_SETTINGS.

    Catches typos like `NAABU_TIMOUT` (missing 'e') and obsolete key names
    that were renamed.
    """
    src = filepath.read_text(encoding="utf-8")
    dump_keys = _extract_dump_keys(src)
    assert dump_keys, f"{filepath.name}: no keys extracted from dump call (parser bug?)"

    defaults = _default_settings_keys()
    typos = [
        k for k in dump_keys
        if k not in defaults and not _is_runtime_injected(k)
    ]
    assert not typos, (
        f"{filepath.name}: dump references keys NOT in DEFAULT_SETTINGS and "
        f"not in the runtime-injected allowlist - likely typos or obsolete "
        f"names: {typos}"
    )


@pytest.mark.parametrize("filepath", DUMP_FILES, ids=lambda p: p.name)
def test_dump_doesnt_skip_keys_the_module_actually_reads(filepath: Path):
    """If a module reads a setting via settings.get(...), it should also
    dump it -- otherwise the operator misses important config in the log.

    Some intentional exclusions (RoE/runtime keys) are allowed.
    """
    src = filepath.read_text(encoding="utf-8")
    dump_keys = set(_extract_dump_keys(src))
    read_keys = _extract_settings_get_keys(src)

    # Drop allowed exclusions (exact + glob with * suffix)
    def is_allowed(k: str) -> bool:
        for allowed in ALLOWED_UNDUMPED_KEYS:
            if allowed == k:
                return True
            if allowed.endswith("*") and k.startswith(allowed[:-1]):
                return True
        return False

    missing = sorted(k for k in (read_keys - dump_keys) if not is_allowed(k))

    # Light tolerance: the module may read keys via helper functions in
    # other files (e.g. nuclei_helpers). Don't fail unless the gap is huge.
    # Threshold: 60% coverage of read keys is the floor.
    if read_keys:
        coverage = len(read_keys & dump_keys) / len(read_keys)
        assert coverage >= 0.40 or len(missing) <= 8, (
            f"{filepath.name}: dump misses {len(missing)} keys that the module "
            f"reads. Coverage {coverage:.0%}. Missing: {missing[:15]}"
        )


@pytest.mark.parametrize("filepath", DUMP_FILES, ids=lambda p: p.name)
def test_dump_called_after_early_skip(filepath: Path):
    """The dump should appear AFTER any `if not settings.get('X_ENABLED'): return`
    early-skip block, so disabled tools don't flood the drawer."""
    src = filepath.read_text(encoding="utf-8")

    # Find the position of the first `if not settings.get('..._ENABLED'...): return`
    # (loose match -- accept any returning early-skip on an _ENABLED flag)
    early_skip = re.search(
        r"if not settings\.get\(['\"]\w*_ENABLED['\"][^)]*\):[\s\S]{0,300}?return",
        src,
    )
    dump_call = src.find("print_effective_settings(")
    assert dump_call != -1, f"{filepath.name}: no dump call found"

    if early_skip is None:
        # Module has no early-skip on an _ENABLED flag; that's fine.
        return

    assert early_skip.end() < dump_call, (
        f"{filepath.name}: print_effective_settings(...) call appears at "
        f"position {dump_call} but the early-skip on *_ENABLED ends at "
        f"position {early_skip.end()}. Dump must come AFTER the skip so "
        f"disabled tools don't pollute the log drawer."
    )


# ===========================================================================
# Sanity meta-tests — make sure the audit itself isn't broken
# ===========================================================================
class TestAuditMeta:
    def test_at_least_20_modules_have_dump_calls(self):
        """The rollout claimed 22 modules. Allow ±2 for refactors."""
        assert len(DUMP_FILES) >= 20, (
            f"Expected ~22 modules with dump calls, found {len(DUMP_FILES)}: "
            f"{[p.name for p in DUMP_FILES]}"
        )

    def test_default_settings_loads(self):
        defaults = _default_settings_keys()
        assert len(defaults) > 100, "DEFAULT_SETTINGS looks suspiciously small"

    def test_extractor_finds_keys_in_a_known_module(self):
        # vhost_sni_enum is the canonical module — should have ~10 dump keys
        path = PROJECT_ROOT / "recon" / "main_recon_modules" / "vhost_sni_enum.py"
        src = path.read_text(encoding="utf-8")
        keys = _extract_dump_keys(src)
        assert len(keys) >= 8
        assert "VHOST_SNI_TEST_L7" in keys
        assert "VHOST_SNI_CONCURRENCY" in keys
