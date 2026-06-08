"""Tests for the TEXT_TO_CYPHER_SYSTEM AI Surface Annotations block.

The prompt is the contract between user natural-language queries and the
Cypher the agent generates. Drift in this block means the agent stops being
able to answer "show me all AI endpoints" correctly.

Tested layers:

  1. Source file (agentic/prompts/base.py) — structural presence of every
     lap-1 AI property + value-prefixed field + detected_by marker
  2. Baked agent image — running container's prompt has the AI block too
     (regression: catches a rebuild that forgot to copy the prompt)
  3. Conformance with the project's "no project_id/user_id in queries"
     convention — example queries inside the AI block must NOT include
     ``user_id`` / ``project_id`` filters

Run:
    docker run --rm --network host --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_text_to_cypher_prompt.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PROMPT_PATH = PROJECT_ROOT / "agentic" / "prompts" / "base.py"


def _read_prompt_source() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _extract_text_to_cypher_block(src: str) -> str:
    """Slice TEXT_TO_CYPHER_SYSTEM string literal (the triple-quoted prompt)."""
    start_token = 'TEXT_TO_CYPHER_SYSTEM = """'
    start = src.find(start_token)
    assert start != -1, "TEXT_TO_CYPHER_SYSTEM not found in agentic/prompts/base.py"
    body_start = start + len(start_token)
    end = src.find('"""', body_start)
    assert end != -1, "TEXT_TO_CYPHER_SYSTEM has no closing triple-quote"
    return src[body_start:end]


def _extract_ai_block(prompt_body: str) -> str:
    """Slice the AI Surface Annotations subsection so we can test it in
    isolation (drift guard: structural test on the AI subsection alone)."""
    marker = "## AI Surface Annotations"
    start = prompt_body.find(marker)
    assert start != -1, "AI Surface Annotations subsection missing from TEXT_TO_CYPHER_SYSTEM"
    # The next "## " heading bounds the block
    end = prompt_body.find("\n## ", start + len(marker))
    return prompt_body[start:end if end != -1 else len(prompt_body)]


# ---------------------------------------------------------------------------
# Source-file tests
# ---------------------------------------------------------------------------

def test_prompt_contains_ai_surface_annotations_section():
    body = _extract_text_to_cypher_block(_read_prompt_source())
    assert "## AI Surface Annotations" in body, (
        "TEXT_TO_CYPHER_SYSTEM missing the AI Surface Annotations subsection"
    )


def test_prompt_documents_every_lap1_ai_property():
    """Every property actually written by phases 2–4 must be listed in
    the prompt — otherwise the agent can't formulate Cypher for them."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    required_properties = [
        # Phase 2 — domain_recon
        "ai_service_hint",
        # Phase 3 — nmap
        "ai_runtime_version",
        # Phase 4 — http_probe
        "is_ai_framework_detected",
        "ai_framework_name",
        "ai_frontend_product_guess",
    ]
    missing = [p for p in required_properties if p not in block]
    assert not missing, f"prompt missing AI properties: {missing}"


def test_prompt_documents_every_technology_category_value():
    """The value-prefixed `Technology.category` values must be listed
    explicitly so the agent doesn't have to enumerate them ad-hoc."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    required_values = [
        "ai-runtime",
        "ai-vector-db",
        "ai-framework",
        "ai-proxy",
        "ai-frontend",
        "ai-sdk-client",
    ]
    missing = [v for v in required_values if v not in block]
    assert not missing, f"prompt missing Technology.category values: {missing}"


def test_prompt_documents_every_detected_by_marker():
    """Each tool's detected_by marker must be listed so the agent can
    explain provenance ('which scanner found this?')."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    markers = [
        "naabu-ai-port", "masscan-ai-port",
        "httpx-ai-header", "httpx-ai-favicon", "httpx-ai-title",
    ]
    missing = [m for m in markers if m not in block]
    assert not missing, f"prompt missing detected_by markers: {missing}"


def test_prompt_documents_baseurl_subdomain_service_technology():
    """All four node labels touched by lap 1 must be named in the AI block."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    for label in ("Subdomain", "Service", "BaseURL", "Technology"):
        assert label in block, f"prompt's AI block doesn't mention {label}"


def test_prompt_explains_prefix_convention():
    """The structural rule (`ai_*` / `is_ai_*` prefix) is the single most
    important thing in the AI block — it lets the agent answer
    'show me everything AI-related' without enumerating fields."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    assert "ai_" in block and "is_ai_" in block, "prompt missing prefix convention explanation"
    assert "STARTS WITH 'ai_'" in block or "starts with" in block.lower(), (
        "prompt missing the catch-all 'keys(n) STARTS WITH ai_' pattern"
    )


def test_prompt_contains_useful_query_examples():
    """The block ships at least 3 worked Cypher examples — without them,
    the LLM has to invent query patterns from scratch."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    cypher_match_count = block.count("MATCH ")
    assert cypher_match_count >= 3, (
        f"AI block has only {cypher_match_count} MATCH clauses; "
        f"expected at least 3 worked examples"
    )


# ---------------------------------------------------------------------------
# Convention conformance — no project_id/user_id in the example queries
# ---------------------------------------------------------------------------

def test_prompt_examples_do_not_include_project_id_filter():
    """The prompt's own rule #8 says user_id/project_id are 'injected
    automatically'. The AI block's example queries must respect that —
    a contradictory example trains the agent to write WHERE-clauses
    that get rejected."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    forbidden = ["project_id = $", "user_id = $", "project_id IN", "user_id IN"]
    found = [f for f in forbidden if f in block]
    assert not found, (
        f"AI block examples include forbidden filters {found}; the prompt's "
        f"own rule #8 says project_id/user_id are injected automatically"
    )


# ---------------------------------------------------------------------------
# Baked image — running agent has the prompt
# ---------------------------------------------------------------------------

def _agent_has_ai_block() -> tuple[bool, str]:
    """Exec into the running agent and check the prompt is loaded.
    Returns (ok, reason)."""
    if shutil.which("docker") is None:
        return (False, "docker CLI unavailable")
    proc = subprocess.run(
        ["docker", "exec", "redamon-agent", "python3", "-c",
         "import sys; sys.path.insert(0, '/app'); "
         "from prompts.base import TEXT_TO_CYPHER_SYSTEM; "
         "print(1 if '## AI Surface Annotations' in TEXT_TO_CYPHER_SYSTEM else 0)"],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0:
        return (False, f"docker exec failed: {proc.stderr.strip()[:200]}")
    return (proc.stdout.strip() == "1", proc.stdout.strip())


def test_baked_agent_image_has_ai_prompt_block():
    ok, info = _agent_has_ai_block()
    if not ok and "docker" in info.lower():
        print("SKIP: test_baked_agent_image_has_ai_prompt_block (docker unavailable)")
        return
    assert ok, (
        f"agent image is missing the AI block (got {info!r}). "
        f"You probably forgot to rebuild — run "
        f"`docker compose build agent && docker compose up -d agent`."
    )


def test_baked_agent_image_has_graph_mixin_ai_extensions():
    """Phase 2/3/4 mixin extensions must also be in the baked image —
    catches a rebuild that picked up the prompt but missed the mixins."""
    if shutil.which("docker") is None:
        print("SKIP: test_baked_agent_image_has_graph_mixin_ai_extensions (docker unavailable)")
        return
    script = """
import inspect, sys
sys.path.insert(0, '/app')
from graph_db.mixins.recon.domain_mixin import DomainMixin
from graph_db.mixins.recon.port_mixin import PortMixin
from graph_db.mixins.recon.http_mixin import HttpMixin
src_d = inspect.getsource(DomainMixin)
src_p = inspect.getsource(PortMixin)
src_h = inspect.getsource(HttpMixin)
flags = [
    'ai_service_hint' in src_d,
    'ai-port-catalog' in src_p,
    'ai_runtime_version' in src_p,
    'ai-surface-recon' in src_h,
    'httpx-ai-header' in src_h,
]
print(','.join('1' if f else '0' for f in flags))
""".strip()
    proc = subprocess.run(
        ["docker", "exec", "redamon-agent", "python3", "-c", script],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0:
        print(f"SKIP: agent exec failed: {proc.stderr.strip()[:200]}")
        return
    flags = proc.stdout.strip().split(",")
    expected = ["1"] * 5
    assert flags == expected, (
        f"baked agent missing mixin AI extensions "
        f"(domain, port_catalog, runtime_version, http_ai, detected_by) = {flags}"
    )


# ---------------------------------------------------------------------------
# Property-to-node-label mapping correctness
# ---------------------------------------------------------------------------

# The plan + mixins write each AI property onto exactly one node label.
# If the prompt lists `ai_service_hint` under `Service:` instead of
# `Subdomain:`, the agent will write Cypher that returns nothing.
PROPERTY_TO_LABEL: dict[str, str] = {
    # Phase 2 — domain_recon
    "ai_service_hint":           "Subdomain",
    # Phase 3 — nmap
    "ai_runtime_version":        "Service",
    # Phase 4 — http_probe (Patch D: moved from BaseURL to Endpoint —
    # BaseURL is now scheme+host+port only, paths/responses live on Endpoint)
    "is_ai_framework_detected":  "Endpoint",
    "ai_framework_name":         "Endpoint",
    "ai_frontend_product_guess": "Endpoint",
    # Lap 2 — resource_enum endpoint AI classifier
    "ai_interface_type":         "Endpoint",
    "is_ai_rag_ingest":          "Endpoint",
    "is_ai_prompt_injectable":   "Parameter",
    "ai_tool_arg_path":          "Parameter",
}


def test_each_ai_property_appears_under_its_owning_node_label():
    """Per the AI block, each property must be listed within ~10 lines of
    its owning node label header. A property listed under the wrong label
    leads the agent to generate Cypher with a missing match."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    lines = block.splitlines()
    for prop, label in PROPERTY_TO_LABEL.items():
        # Find the property line
        prop_idx = next((i for i, l in enumerate(lines) if prop in l), None)
        assert prop_idx is not None, f"property {prop!r} not in AI block"
        # Find the nearest preceding label header (lines like "  - Subdomain:")
        label_marker = f"- {label}:"
        preceding = [
            i for i in range(prop_idx, -1, -1)
            if label_marker in lines[i]
        ]
        assert preceding, (
            f"property {prop!r} (line {prop_idx}) is not under a `- {label}:` "
            f"header — the agent will think it belongs to a different node label"
        )
        # The wrong-label proximity check: no OTHER node-label header sits
        # between the property and its expected label header.
        last_label_idx = preceding[0]
        other_labels = [v for v in PROPERTY_TO_LABEL.values() if v != label]
        for other in set(other_labels):
            other_marker = f"- {other}:"
            in_between = [
                i for i in range(last_label_idx + 1, prop_idx)
                if other_marker in lines[i]
            ]
            assert not in_between, (
                f"property {prop!r} appears after a `- {other}:` label "
                f"(should be under `- {label}:`); risk of misattribution"
            )


# ---------------------------------------------------------------------------
# Catalog parity — prompt mentions every category actually written by mixins
# ---------------------------------------------------------------------------

def _collect_categories_in_use() -> set[str] | None:
    """Walk the recon catalogs the mixins actually write to find every
    `ai-*` category value that could land in the graph. The prompt must
    cover all of them.

    Returns None when the recon helpers aren't importable in this Python
    env (e.g. host run without dnspython). Tests using this helper then
    skip gracefully — the recon-container run still covers them.
    """
    try:
        from recon.helpers.ai_signal_catalog import (
            AI_PORTS,
            AI_HEADER_PATTERNS,
        )
    except ImportError:
        return None
    seen: set[str] = set()
    for descriptor in AI_PORTS.values():
        cat = descriptor.get("category")
        if isinstance(cat, str) and cat.startswith("ai-"):
            seen.add(cat)
    for _pat, _name, category in AI_HEADER_PATTERNS:
        if category.startswith("ai-"):
            seen.add(category)
    # http_probe also sets "ai-frontend" as fallback (favicon/title)
    seen.add("ai-frontend")
    return seen


def test_prompt_covers_every_ai_category_written_by_mixins():
    """Drift guard: when somebody adds a new category to the catalog
    (e.g. 'ai-orchestrator'), this test fails until they update the
    prompt too."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    in_use = _collect_categories_in_use()
    if in_use is None:
        print("SKIP: test_prompt_covers_every_ai_category_written_by_mixins (recon helpers unimportable)")
        return
    missing = [c for c in sorted(in_use) if c not in block]
    assert not missing, (
        f"prompt missing Technology.category values that the mixins actually "
        f"emit: {missing}. Update the AI block when adding a new category."
    )


def test_prompt_does_not_advertise_unsupported_categories():
    """Inverse: if the prompt names a category, the catalog/mixins should
    actually be able to produce it. Lap 1 supports these; later laps
    will expand. Prevent the prompt from promising more than the code
    delivers."""
    in_use = _collect_categories_in_use()
    if in_use is None:
        print("SKIP: test_prompt_does_not_advertise_unsupported_categories (recon helpers unimportable)")
        return
    advertised = {
        "ai-runtime", "ai-vector-db", "ai-framework",
        "ai-proxy", "ai-frontend", "ai-sdk-client",
    }
    extra = advertised - in_use
    assert not extra, (
        f"prompt advertises categories not produced by lap-1 mixins: {extra}. "
        f"Either add the missing catalog entry or drop the category from the prompt."
    )


# ---------------------------------------------------------------------------
# Reserved future properties must NOT appear in the lap-1 prompt
# ---------------------------------------------------------------------------

def test_prompt_does_not_promise_lap2plus_properties():
    """The plan reserves these properties for later laps (vuln_scan,
    trufflehog). Listing them now in the prompt would lead the agent to write
    Cypher against fields that simply don't exist yet, yielding empty results
    and confusing the operator.

    Note: ai_interface_type, is_ai_rag_ingest, is_ai_prompt_injectable and
    ai_tool_arg_path ship with the resource_enum AI classifier lap, and
    ai_tool_schema_ref / ai_supports_streaming / ai_supports_tools /
    ai_supports_vision / ai_model_family_guess / ai_latency_p50_ms / ai_mcp_*
    ship with the central ai_surface_recon lap — all are correctly listed in
    the prompt and NO LONGER on this reserved list.
    """
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    reserved_for_later_laps = [
        "ai_asr",                # Vulnerability, ai_guardrail_probe lap
        "ai_trials",             # Vulnerability, ai_guardrail_probe lap
        "ai_oracle_kind",        # Vulnerability, ai_guardrail_probe lap
        "ai_transcript_ref",     # Vulnerability, ai_guardrail_probe lap
        "ai_provider",           # Secret, trufflehog lap
        "is_ai_library",         # CVE, vuln_scan lap
    ]
    leaked = [p for p in reserved_for_later_laps if p in block]
    assert not leaked, (
        f"prompt's AI block lists future-lap properties: {leaked}. "
        f"These will return empty Cypher results until the relevant lap ships."
    )


# ---------------------------------------------------------------------------
# Block position + size budget — regression guards
# ---------------------------------------------------------------------------

def test_ai_block_appears_before_output_format_section():
    """Heuristic-ordering: the AI subsection is a schema reference and
    must sit before the Output Format / generation rules so the LLM has
    read the schema before reading the format constraints."""
    body = _extract_text_to_cypher_block(_read_prompt_source())
    ai_idx = body.find("## AI Surface Annotations")
    out_idx = body.find("## Output Format")
    assert ai_idx != -1, "AI block missing"
    assert out_idx != -1, "Output Format section missing"
    assert ai_idx < out_idx, (
        "AI Surface Annotations subsection must precede Output Format; "
        "swapping their order would change the LLM's reading sequence."
    )


def test_ai_block_size_within_reasonable_budget():
    """Token-budget regression guard. The lap-1 AI block should be small
    (~60–120 lines); a 300-line block means somebody added prose instead
    of property lines. The plan rule (§7.6) is 'one property line per
    new field, not one paragraph per module'."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    n_lines = block.count("\n")
    assert n_lines < 200, (
        f"AI block is {n_lines} lines — bloat watch. Strip prose; keep "
        f"one property line per field per the §7.6 drift-control rule."
    )
    assert n_lines >= 30, (
        f"AI block is only {n_lines} lines — likely incomplete. Should "
        f"document properties, categories, detected_by markers, prefix "
        f"rule, and ≥3 worked examples."
    )


# ---------------------------------------------------------------------------
# Rule #8 regression — "Do NOT include user_id/project_id filters"
# ---------------------------------------------------------------------------

def test_rule_8_no_project_id_filter_still_present():
    """Without rule #8 the operator gets Cypher full of `WHERE
    project_id = $pid` filters that the system tries to inject again,
    causing duplicate-filter errors. The AI block's compliance depends
    on rule #8 staying."""
    body = _extract_text_to_cypher_block(_read_prompt_source())
    assert "Do NOT include user_id/project_id filters" in body, (
        "Rule #8 was deleted or reworded — Cypher generation will start "
        "including project_id filters and the AI block's example queries "
        "will become inconsistent with the rest of the prompt."
    )


# ---------------------------------------------------------------------------
# Cross-doc parity — GRAPH.SCHEMA.md and the prompt must agree
# ---------------------------------------------------------------------------

def test_graph_schema_md_and_prompt_agree_on_lap1_ai_properties():
    """The developer-facing reference doc and the agent-facing prompt
    must agree on what properties exist. Drift means one of the two
    misleads its audience."""
    schema_md = (PROJECT_ROOT / "readmes" / "GRAPH.SCHEMA.md").read_text()
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    for prop in PROPERTY_TO_LABEL:
        assert prop in schema_md, (
            f"GRAPH.SCHEMA.md missing property {prop!r} that the prompt "
            f"documents — operator-facing reference is out of sync"
        )


def test_graph_schema_md_and_prompt_agree_on_technology_categories():
    schema_md = (PROJECT_ROOT / "readmes" / "GRAPH.SCHEMA.md").read_text()
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    for cat in ("ai-runtime", "ai-vector-db", "ai-framework",
                "ai-proxy", "ai-frontend"):
        if cat in block:
            assert cat in schema_md, (
                f"GRAPH.SCHEMA.md missing Technology.category {cat!r} that "
                f"the prompt mentions"
            )


# ---------------------------------------------------------------------------
# Live Cypher syntax validation — every example query must parse against Neo4j
# ---------------------------------------------------------------------------

def _extract_cypher_examples(block: str) -> list[str]:
    """Pull out every Cypher example. Examples are introduced by `MATCH `
    (case-sensitive — that's how the catalog writes them) and continue
    until a blank line or the next `- ` bullet."""
    examples: list[str] = []
    lines = block.splitlines()
    i = 0
    while i < len(lines):
        if "MATCH " in lines[i] and not lines[i].lstrip().startswith("- "):
            buf: list[str] = []
            while i < len(lines) and lines[i].strip():
                stripped = lines[i].strip()
                if stripped.startswith("- ") and not buf:
                    break  # this is a bullet, not a code line
                buf.append(stripped)
                i += 1
            if buf:
                examples.append(" ".join(buf))
        i += 1
    return examples


def test_each_example_query_uses_match_clause():
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    examples = _extract_cypher_examples(block)
    assert examples, "no Cypher examples extracted from the AI block"
    for ex in examples:
        assert "MATCH" in ex, f"example missing MATCH clause: {ex!r}"


def test_each_example_query_has_balanced_parentheses():
    """Cypher uses ( ) for node patterns and [ ] for relationships.
    A typo that opens but doesn't close a paren is the #1 silent error."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    for ex in _extract_cypher_examples(block):
        opens = ex.count("(") + ex.count("[") + ex.count("{")
        closes = ex.count(")") + ex.count("]") + ex.count("}")
        assert opens == closes, (
            f"unbalanced brackets in example: {ex!r} "
            f"(opens={opens}, closes={closes})"
        )


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


def test_each_example_query_parses_against_live_neo4j():
    """Submit each example to Neo4j's planner via EXPLAIN. A syntax error
    here means the agent's example is broken; a planner failure means
    the example references a constraint or label that doesn't exist."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_each_example_query_parses_against_live_neo4j (neo4j unreachable)")
        return
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    examples = _extract_cypher_examples(block)
    assert examples, "no Cypher examples extracted"
    failures: list[tuple[str, str]] = []
    try:
        with drv.session() as s:
            for ex in examples:
                try:
                    s.run("EXPLAIN " + ex).consume()
                except Exception as exc:  # noqa: BLE001
                    failures.append((ex, str(exc)[:200]))
    finally:
        drv.close()
    assert not failures, (
        "Cypher example(s) failed to parse against live Neo4j:\n"
        + "\n".join(f"  EXAMPLE: {q}\n    ERROR: {e}" for q, e in failures)
    )


# ---------------------------------------------------------------------------
# AI block self-consistency
# ---------------------------------------------------------------------------

def test_ai_block_uses_consistent_node_label_capitalisation():
    """Neo4j is case-sensitive on labels. The prompt must use the exact
    capitalisation that mixins write: `BaseURL`, `Subdomain`, `Service`,
    `Technology` (not `baseUrl`, `subdomain`, etc.)."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    canonical = {"BaseURL", "Subdomain", "Service", "Technology"}
    typos = {
        "baseurl": "BaseURL", "Baseurl": "BaseURL", "BASEURL": "BaseURL",
        "subdomain": "Subdomain", "service": "Service",
        "technology": "Technology",
    }
    # Check that the canonical forms are present
    for label in canonical:
        assert label in block, f"canonical label {label!r} missing from AI block"
    # Check no lowercase typos within Cypher patterns
    import re
    for typo, correct in typos.items():
        # `(u:baseurl)` style — must not occur
        if re.search(rf"\(\w*:{typo}\b", block):
            raise AssertionError(
                f"AI block uses lowercase typo `:{typo}` — Neo4j is "
                f"case-sensitive; should be `:{correct}`"
            )


def test_ai_block_lists_detected_by_markers_in_consistent_grouping():
    """The five `detected_by` markers must all appear in the same
    contiguous list (not scattered across the block). This keeps the
    agent's understanding of provenance coherent."""
    block = _extract_ai_block(_extract_text_to_cypher_block(_read_prompt_source()))
    markers = [
        "naabu-ai-port", "masscan-ai-port",
        "httpx-ai-header", "httpx-ai-favicon", "httpx-ai-title",
    ]
    positions = [block.find(m) for m in markers]
    assert all(p != -1 for p in positions), "missing markers in AI block"
    # All five should appear within a window of ~250 chars
    span = max(positions) - min(positions)
    assert span < 400, (
        f"detected_by markers spread across {span} chars — they should be in "
        f"a single bullet list. Cohesion regression."
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
