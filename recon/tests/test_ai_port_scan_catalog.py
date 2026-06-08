"""Unit + integration + live-Neo4j tests for the Phase 3 AI port catalog hook.

Covers:

  1. ``_annotate_ai_port_catalog`` — naabu/masscan port-details annotation
  2. ``parse_naabu_output`` integration with a synthetic naabu JSONL file
  3. ``parse_masscan_output`` integration with a synthetic masscan NDJSON file
  4. ``parse_nmap_xml`` integration — AI runtime version regex against XML
  5. Live Neo4j: ``update_graph_from_port_scan`` + ``update_graph_from_nmap``
     write Technology(category=ai-*) nodes and Service.ai_runtime_version,
     reusing existing USES_TECHNOLOGY / HAS_TECHNOLOGY edges
  6. Regression: parser shapes preserved when settings is None / toggles off

Run:
    docker run --rm --network host --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_port_scan_catalog.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

from recon.helpers.ai_signal_catalog import AI_PORTS, lookup_ai_port
from recon.main_recon_modules.port_scan import (
    _annotate_ai_port_catalog,
    parse_naabu_output,
)
from recon.main_recon_modules.masscan_scan import parse_masscan_output
from recon.main_recon_modules.nmap_scan import parse_nmap_xml


# ---------------------------------------------------------------------------
# _annotate_ai_port_catalog — direct helper
# ---------------------------------------------------------------------------

def _by_host(host: str, ports: list[int]) -> dict:
    return {
        host: {
            "host": host,
            "ports": ports,
            "port_details": [{"port": p, "protocol": "tcp", "service": ""} for p in ports],
        }
    }


def test_annotator_tags_known_unambiguous_ai_port():
    by_host = _by_host("ai-host.example", [22, 11434, 443])
    n = _annotate_ai_port_catalog(by_host, {"PORT_SCAN_AI_PORT_CATALOG_ENABLED": True}, "naabu-ai-port")
    assert n == 1
    entries = by_host["ai-host.example"]["port_details"]
    by_port = {e["port"]: e for e in entries}
    assert by_port[11434]["ai_service"] == {
        "name": "ollama",
        "category": "ai-runtime",
        "detected_by": "naabu-ai-port",
    }
    assert "ai_service" not in by_port[22]
    assert "ai_service" not in by_port[443]


def test_annotator_skips_disambiguate_ports():
    """8000 and 8080 are shared with many non-AI services. Port-scan alone
    cannot claim them — the central ai_surface_recon module (Phase 15)
    confirms via chat-shape probes. Lap-1 must skip them here."""
    by_host = _by_host("host.example", [8000, 8080])
    n = _annotate_ai_port_catalog(by_host, {"PORT_SCAN_AI_PORT_CATALOG_ENABLED": True}, "naabu-ai-port")
    assert n == 0
    for entry in by_host["host.example"]["port_details"]:
        assert "ai_service" not in entry


def test_annotator_returns_zero_when_toggle_off():
    by_host = _by_host("host.example", [11434, 6333, 19530])
    n = _annotate_ai_port_catalog(by_host, {"PORT_SCAN_AI_PORT_CATALOG_ENABLED": False}, "naabu-ai-port")
    assert n == 0
    for entry in by_host["host.example"]["port_details"]:
        assert "ai_service" not in entry


def test_annotator_returns_zero_when_settings_is_none():
    by_host = _by_host("host.example", [11434])
    n = _annotate_ai_port_catalog(by_host, None, "naabu-ai-port")
    assert n == 0
    assert "ai_service" not in by_host["host.example"]["port_details"][0]


def test_annotator_picks_correct_toggle_for_masscan():
    """masscan-ai-port detected_by reads MASSCAN_AI_PORT_CATALOG_ENABLED,
    NOT PORT_SCAN_AI_PORT_CATALOG_ENABLED. Confirms the toggle map."""
    by_host = _by_host("host.example", [11434])

    # masscan toggle off, naabu toggle on => masscan path should still annotate 0
    n_masscan_off = _annotate_ai_port_catalog(
        by_host, {"MASSCAN_AI_PORT_CATALOG_ENABLED": False,
                  "PORT_SCAN_AI_PORT_CATALOG_ENABLED": True}, "masscan-ai-port",
    )
    assert n_masscan_off == 0

    # masscan toggle on, naabu toggle off => masscan should annotate
    n_masscan_on = _annotate_ai_port_catalog(
        by_host, {"MASSCAN_AI_PORT_CATALOG_ENABLED": True,
                  "PORT_SCAN_AI_PORT_CATALOG_ENABLED": False}, "masscan-ai-port",
    )
    assert n_masscan_on == 1
    assert by_host["host.example"]["port_details"][0]["ai_service"]["detected_by"] == "masscan-ai-port"


def test_annotator_rejects_unknown_detected_by():
    """Defensive: an unknown detected_by string must not crash and must not
    accidentally fall through to a True default."""
    by_host = _by_host("host.example", [11434])
    n = _annotate_ai_port_catalog(by_host, {}, "totally-fake-source")
    assert n == 0
    assert "ai_service" not in by_host["host.example"]["port_details"][0]


def test_annotator_handles_missing_port_field():
    """A malformed port_details entry without a 'port' key must be skipped,
    not crash."""
    by_host = {
        "host.example": {
            "port_details": [
                {"protocol": "tcp", "service": "ollama"},     # no port
                {"port": 11434, "protocol": "tcp"},           # match
                {"port": None, "service": "junk"},            # invalid
            ]
        }
    }
    n = _annotate_ai_port_catalog(by_host, {}, "naabu-ai-port")
    assert n == 1
    assert by_host["host.example"]["port_details"][1]["ai_service"]["name"] == "ollama"


def test_annotator_is_idempotent_on_repeat_runs():
    by_host = _by_host("host.example", [11434])
    n1 = _annotate_ai_port_catalog(by_host, {}, "naabu-ai-port")
    n2 = _annotate_ai_port_catalog(by_host, {}, "naabu-ai-port")
    assert n1 == 1 and n2 == 1
    # Annotation stays stable, not duplicated
    assert by_host["host.example"]["port_details"][0]["ai_service"]["name"] == "ollama"


def test_annotator_covers_every_unambiguous_ai_port_in_catalog():
    """Parity guard: every non-disambiguate entry in AI_PORTS must be
    reachable through the annotator. If somebody adds a port but forgets
    to update parsing logic, this fails."""
    unambiguous_ports = [p for p, d in AI_PORTS.items() if not d.get("disambiguate")]
    assert unambiguous_ports, "AI_PORTS must contain at least some unambiguous entries"

    by_host = _by_host("host.example", unambiguous_ports + [22, 443])
    n = _annotate_ai_port_catalog(by_host, {}, "naabu-ai-port")
    assert n == len(unambiguous_ports), (
        f"annotated {n} but catalog has {len(unambiguous_ports)} unambiguous AI ports"
    )


# ---------------------------------------------------------------------------
# parse_naabu_output — file-based integration
# ---------------------------------------------------------------------------

def _write_naabu_jsonl(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_parse_naabu_emits_ai_annotation_on_known_port():
    jsonl = "\n".join([
        json.dumps({"host": "ai.example", "ip": "10.0.0.1", "port": 11434}),
        json.dumps({"host": "ai.example", "ip": "10.0.0.1", "port": 443}),
    ]) + "\n"
    path = _write_naabu_jsonl(jsonl)
    try:
        result = parse_naabu_output(path, settings={"PORT_SCAN_AI_PORT_CATALOG_ENABLED": True})
    finally:
        Path(path).unlink(missing_ok=True)
    assert result["summary"]["ai_ports_annotated"] == 1
    details = {pd["port"]: pd for pd in result["by_host"]["ai.example"]["port_details"]}
    assert details[11434]["ai_service"]["name"] == "ollama"
    assert "ai_service" not in details[443]


def test_parse_naabu_legacy_callsite_without_settings_keeps_old_shape():
    """An existing caller that didn't pass settings (e.g. a script doing
    only summary aggregation) must continue to work — old shape preserved,
    no AI fields injected."""
    jsonl = json.dumps({"host": "x.example", "ip": "10.0.0.2", "port": 11434}) + "\n"
    path = _write_naabu_jsonl(jsonl)
    try:
        result = parse_naabu_output(path)
    finally:
        Path(path).unlink(missing_ok=True)
    # ai_ports_annotated defaults to 0 (helper returns 0 when settings is None)
    assert result["summary"]["ai_ports_annotated"] == 0
    assert "ai_service" not in result["by_host"]["x.example"]["port_details"][0]


def test_parse_naabu_with_empty_input_file_still_returns_summary_shape():
    path = _write_naabu_jsonl("")
    try:
        result = parse_naabu_output(path, settings={})
    finally:
        Path(path).unlink(missing_ok=True)
    assert result["summary"]["hosts_scanned"] == 0
    # Empty output goes through the early-return path (no ai_ports_annotated key)
    # so just verify the rest of the summary shape is intact.
    assert result["summary"]["total_open_ports"] == 0


def test_parse_naabu_does_not_annotate_disambiguate_ports():
    jsonl = "\n".join([
        json.dumps({"host": "x.example", "ip": "10.0.0.3", "port": 8000}),
        json.dumps({"host": "x.example", "ip": "10.0.0.3", "port": 8080}),
    ]) + "\n"
    path = _write_naabu_jsonl(jsonl)
    try:
        result = parse_naabu_output(path, settings={})
    finally:
        Path(path).unlink(missing_ok=True)
    assert result["summary"]["ai_ports_annotated"] == 0


# ---------------------------------------------------------------------------
# parse_masscan_output — file-based integration
# ---------------------------------------------------------------------------

def _write_masscan_ndjson(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_parse_masscan_emits_ai_annotation_via_shared_helper():
    """Masscan output runs the same annotator as naabu, but writes
    detected_by='masscan-ai-port'. Confirms cross-module reuse."""
    rec = json.dumps({
        "ip": "10.0.0.4", "timestamp": "0", "port": 11434, "proto": "tcp",
        "rec_type": "status", "data": {"status": "open", "reason": "syn-ack", "ttl": 48},
    })
    path = _write_masscan_ndjson(rec + "\n")
    try:
        result = parse_masscan_output(
            path, ip_to_hostnames={"10.0.0.4": ["llm.example"]},
            settings={"MASSCAN_AI_PORT_CATALOG_ENABLED": True},
        )
    finally:
        Path(path).unlink(missing_ok=True)
    assert result["summary"]["ai_ports_annotated"] == 1
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert pd["ai_service"]["name"] == "ollama"
    assert pd["ai_service"]["detected_by"] == "masscan-ai-port"


def test_parse_masscan_respects_its_own_toggle_not_naabus():
    """Cross-module sanity: setting PORT_SCAN_*=False must NOT silence
    masscan annotation, and vice versa. Each tool reads its own toggle."""
    rec = json.dumps({
        "ip": "10.0.0.5", "timestamp": "0", "port": 11434, "proto": "tcp",
        "rec_type": "status", "data": {"status": "open"},
    })
    path = _write_masscan_ndjson(rec + "\n")
    try:
        # naabu off, masscan on => masscan still annotates
        result = parse_masscan_output(
            path, ip_to_hostnames={"10.0.0.5": []},
            settings={"PORT_SCAN_AI_PORT_CATALOG_ENABLED": False,
                      "MASSCAN_AI_PORT_CATALOG_ENABLED": True},
        )
        assert result["summary"]["ai_ports_annotated"] == 1
    finally:
        Path(path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# parse_nmap_xml — AI runtime version regex
# ---------------------------------------------------------------------------

def _write_nmap_xml(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


_NMAP_XML_TEMPLATE = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <hostnames><hostname name="llm.example" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open"/>
        <service name="http" product="{product}" version="{version}" extrainfo="{extra}"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_sets_ai_runtime_version_from_product():
    xml = _NMAP_XML_TEMPLATE.format(port=11434, product="Ollama/0.1.32", version="", extra="")
    path = _write_nmap_xml(xml)
    try:
        result = parse_nmap_xml(path, ip_to_hostnames={"10.0.0.6": ["llm.example"]})
    finally:
        Path(path).unlink(missing_ok=True)
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert pd["ai_runtime_version"] == "ollama"


def test_parse_nmap_sets_ai_runtime_version_from_version_field():
    """Some nmap probes put the AI marker in 'version' rather than 'product'."""
    xml = _NMAP_XML_TEMPLATE.format(port=8000, product="HTTP", version="vllm/0.4.1", extra="")
    path = _write_nmap_xml(xml)
    try:
        result = parse_nmap_xml(path, ip_to_hostnames={"10.0.0.6": ["llm.example"]})
    finally:
        Path(path).unlink(missing_ok=True)
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert pd["ai_runtime_version"] == "vllm"


def test_parse_nmap_sets_ai_runtime_version_from_extrainfo():
    xml = _NMAP_XML_TEMPLATE.format(
        port=8001, product="HTTP", version="", extra="triton-server/24.05 inference platform"
    )
    path = _write_nmap_xml(xml)
    try:
        result = parse_nmap_xml(path, ip_to_hostnames={"10.0.0.6": ["llm.example"]})
    finally:
        Path(path).unlink(missing_ok=True)
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert pd["ai_runtime_version"] == "triton"


def test_parse_nmap_does_not_set_ai_runtime_version_on_unrelated_service():
    xml = _NMAP_XML_TEMPLATE.format(port=80, product="nginx", version="1.18.0", extra="")
    path = _write_nmap_xml(xml)
    try:
        result = parse_nmap_xml(path, ip_to_hostnames={"10.0.0.6": ["llm.example"]})
    finally:
        Path(path).unlink(missing_ok=True)
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert "ai_runtime_version" not in pd


def test_parse_nmap_respects_disabled_toggle():
    xml = _NMAP_XML_TEMPLATE.format(port=11434, product="Ollama/0.1.32", version="", extra="")
    path = _write_nmap_xml(xml)
    try:
        result = parse_nmap_xml(
            path, ip_to_hostnames={"10.0.0.6": ["llm.example"]},
            settings={"NMAP_AI_VERSION_REGEX_ENABLED": False},
        )
    finally:
        Path(path).unlink(missing_ok=True)
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert "ai_runtime_version" not in pd


def test_parse_nmap_legacy_callsite_without_settings_defaults_to_on():
    """Calling parse_nmap_xml without settings (legacy callers) must still
    populate ai_runtime_version — the default is True, matching the
    integration plan's default-coverage rule."""
    xml = _NMAP_XML_TEMPLATE.format(port=11434, product="Ollama/0.1.32", version="", extra="")
    path = _write_nmap_xml(xml)
    try:
        result = parse_nmap_xml(path, ip_to_hostnames={"10.0.0.6": ["llm.example"]})
    finally:
        Path(path).unlink(missing_ok=True)
    pd = result["by_host"]["llm.example"]["port_details"][0]
    assert pd["ai_runtime_version"] == "ollama"


# ---------------------------------------------------------------------------
# Callsite verification — settings actually flows through
# ---------------------------------------------------------------------------

def _extract_call(source: str, opener: str) -> str:
    """Return the full `opener(...)` substring with balanced parentheses.

    `src.find(")", idx)` is wrong when the call has nested parens — it returns
    the first inner close. This walks the string with a paren counter to
    return the call site verbatim, so settings= kwarg checks are accurate.
    """
    idx = source.find(opener)
    if idx == -1:
        return ""
    open_paren = source.find("(", idx)
    depth = 0
    i = open_paren
    while i < len(source):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return source[idx:i + 1]
        i += 1
    return source[idx:]


def test_callsite_run_port_scan_passes_settings_to_parser():
    src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "port_scan.py").read_text()
    call = _extract_call(src, "parse_naabu_output(str(naabu_output)")
    assert call, "could not locate parse_naabu_output callsite"
    assert "settings=settings" in call, f"settings kwarg missing from call: {call!r}"


def test_callsite_run_masscan_scan_passes_settings_to_parser():
    src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "masscan_scan.py").read_text()
    call = _extract_call(src, "parse_masscan_output(str(masscan_output)")
    assert call, "could not locate parse_masscan_output callsite"
    assert "settings=settings" in call, f"settings kwarg missing from call: {call!r}"


def test_callsite_run_nmap_scan_passes_settings_to_parser():
    src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "nmap_scan.py").read_text()
    call = _extract_call(src, "parse_nmap_xml(xml_output")
    assert call, "could not locate parse_nmap_xml callsite"
    assert "settings=settings" in call, f"settings kwarg missing from call: {call!r}"


# ---------------------------------------------------------------------------
# Patch B regression guard — IP-mode pipeline must invoke Nmap
# ---------------------------------------------------------------------------

def test_ip_mode_pipeline_invokes_nmap_scan():
    """Regression guard for the Patch B fix.

    Before lap-1, ``run_ip_recon`` in recon/main.py jumped straight from
    Naabu → OSINT → HTTP probe, skipping Nmap entirely. That meant the
    Phase 3 AI nmap-runtime-regex hook (sets ``Service.ai_runtime_version``
    when nmap reports ``Ollama/0.1.32`` etc.) could never fire in IP mode.

    The fix copies the Group 3.5 block from ``run_domain_recon`` verbatim.
    This test ensures someone doesn't remove it later, restoring the bug.
    """
    src = (PROJECT_ROOT / "recon" / "main.py").read_text()
    # Slice run_ip_recon's body (from its def line to the next top-level def)
    body = src.split("def run_ip_recon")[1].split("\ndef ")[0]
    # All four landmarks of the Group 3.5 block must be present
    assert "run_nmap_scan" in body, (
        "run_ip_recon is missing a call to run_nmap_scan — "
        "IP-mode scans will skip Nmap and Service.ai_runtime_version "
        "will never be populated. Re-apply the lap-1 Patch B fix."
    )
    assert "merge_nmap_into_port_scan" in body, (
        "run_ip_recon calls Nmap but doesn't merge its output into "
        "port_scan.port_details — downstream graph mixin won't see "
        "ai_runtime_version."
    )
    assert "update_graph_from_nmap" in body, (
        "run_ip_recon doesn't schedule the graph update for Nmap output — "
        "Service.ai_runtime_version won't reach Neo4j."
    )
    assert "NMAP_ENABLED" in body, (
        "Nmap invocation in run_ip_recon must be gated on the NMAP_ENABLED "
        "setting so operators can disable it."
    )


def test_ip_mode_nmap_block_runs_between_port_scan_and_osint():
    """Order matters: Nmap must run AFTER port_scan (it consumes the ports)
    AND BEFORE OSINT (so OSINT enrichers see the enriched Service nodes)."""
    src = (PROJECT_ROOT / "recon" / "main.py").read_text()
    body = src.split("def run_ip_recon")[1].split("\ndef ")[0]

    port_scan_graph_idx = body.find("update_graph_from_port_scan")
    nmap_call_idx = body.find("run_nmap_scan")
    osint_block_idx = body.find("_ip_osint_tools")

    assert port_scan_graph_idx != -1
    assert nmap_call_idx != -1
    assert osint_block_idx != -1
    assert port_scan_graph_idx < nmap_call_idx < osint_block_idx, (
        f"Nmap block is out of order — expected port_scan → nmap → osint, "
        f"got positions port_scan_graph={port_scan_graph_idx}, "
        f"nmap={nmap_call_idx}, osint={osint_block_idx}"
    )


# ---------------------------------------------------------------------------
# Cross-layer: masscan re-uses port_scan annotator (no duplication)
# ---------------------------------------------------------------------------

def test_masscan_imports_annotator_from_port_scan_no_duplication():
    """Source-level check: masscan_scan must not redeclare its own annotator.
    The plan calls for single-source-of-truth on the catalog rule."""
    src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "masscan_scan.py").read_text()
    assert "from main_recon_modules.port_scan import _annotate_ai_port_catalog" in src, (
        "masscan_scan.py must import _annotate_ai_port_catalog from port_scan"
    )
    # And must NOT redeclare it locally
    assert "def _annotate_ai_port_catalog" not in src, (
        "masscan_scan.py redeclared _annotate_ai_port_catalog — should reuse port_scan's"
    )


# ---------------------------------------------------------------------------
# Live Neo4j — port_mixin writes Technology(category=ai-*)
# ---------------------------------------------------------------------------

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


def _cleanup_port_test_data(session, uid: str, pid: str):
    session.run(
        """
        MATCH (n)
        WHERE (n:IP OR n:Port OR n:Service OR n:Technology)
          AND n.user_id = $u AND n.project_id = $p
        DETACH DELETE n
        """,
        u=uid, p=pid,
    )


def _make_recon_data_for_port_scan(ai_port: int = 11434, ai_name: str = "ollama", ai_category: str = "ai-runtime"):
    """Build a minimal recon_data dict that update_graph_from_port_scan accepts."""
    return {
        "port_scan": {
            "by_host": {
                "llm.example.invalid": {
                    "host": "llm.example.invalid",
                    "ip": "10.99.99.1",
                    "ports": [ai_port],
                    "port_details": [
                        {
                            "port": ai_port,
                            "protocol": "tcp",
                            "service": "ollama",
                            "ai_service": {
                                "name": ai_name,
                                "category": ai_category,
                                "detected_by": "naabu-ai-port",
                            },
                        }
                    ],
                    "is_cdn": False,
                }
            },
            "by_ip": {
                "10.99.99.1": {"ip": "10.99.99.1", "hostnames": ["llm.example.invalid"], "ports": [ai_port]}
            },
        }
    }


def _get_port_mixin_instance(driver):
    """Build a lightweight class that combines just the port mixin so we can
    call update_graph_from_port_scan directly."""
    from graph_db.mixins.recon.port_mixin import PortMixin

    class _ScratchGraph(PortMixin):
        def __init__(self, drv):
            self.driver = drv

    return _ScratchGraph(driver)


def test_neo4j_port_mixin_creates_ai_technology_with_category():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_port_mixin_creates_ai_technology_with_category (neo4j unreachable)")
        return
    uid, pid = "phase3-test-user", "phase3-test-project-tech"
    try:
        with drv.session() as s:
            _cleanup_port_test_data(s, uid, pid)
        mixin = _get_port_mixin_instance(drv)
        mixin.update_graph_from_port_scan(_make_recon_data_for_port_scan(), uid, pid)
        with drv.session() as s:
            row = s.run(
                """
                MATCH (t:Technology {name: $n, user_id: $u, project_id: $p})
                RETURN t.category AS category, t.source AS source
                """,
                n="ollama", u=uid, p=pid,
            ).single()
            assert row is not None, "AI Technology node not created"
            assert row["category"] == "ai-runtime"
            assert row["source"] == "ai-port-catalog"
            _cleanup_port_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_port_mixin_links_port_and_service_to_technology():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_port_mixin_links_port_and_service_to_technology (neo4j unreachable)")
        return
    uid, pid = "phase3-test-user", "phase3-test-project-links"
    try:
        with drv.session() as s:
            _cleanup_port_test_data(s, uid, pid)
        mixin = _get_port_mixin_instance(drv)
        mixin.update_graph_from_port_scan(_make_recon_data_for_port_scan(), uid, pid)
        with drv.session() as s:
            # Both HAS_TECHNOLOGY (Port→Tech) and USES_TECHNOLOGY (Service→Tech)
            # must exist, both carrying detected_by='naabu-ai-port'.
            port_tech = s.run(
                """
                MATCH (p:Port {number: 11434, user_id: $u, project_id: $p})
                      -[r:HAS_TECHNOLOGY]->(t:Technology {name: 'ollama'})
                RETURN r.detected_by AS detected_by
                """,
                u=uid, p=pid,
            ).single()
            assert port_tech is not None, "Port-[:HAS_TECHNOLOGY]->Technology edge missing"
            assert port_tech["detected_by"] == "naabu-ai-port"

            svc_tech = s.run(
                """
                MATCH (svc:Service {port_number: 11434, user_id: $u, project_id: $p})
                      -[r:USES_TECHNOLOGY]->(t:Technology {name: 'ollama'})
                RETURN r.detected_by AS detected_by
                """,
                u=uid, p=pid,
            ).single()
            assert svc_tech is not None, "Service-[:USES_TECHNOLOGY]->Technology edge missing"
            assert svc_tech["detected_by"] == "naabu-ai-port"
            _cleanup_port_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_port_mixin_disambiguate_port_does_not_get_ai_tech_node():
    """Annotator never tags 8080 (disambiguate). Even if a malformed
    upstream snuck in an ai_service for 8080, the mixin should still
    create the Technology — the gate is upstream — so this test instead
    verifies the realistic flow: no ai_service => no Technology."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_port_mixin_disambiguate_port_does_not_get_ai_tech_node (neo4j unreachable)")
        return
    uid, pid = "phase3-test-user", "phase3-test-project-disamb"
    try:
        with drv.session() as s:
            _cleanup_port_test_data(s, uid, pid)
        recon_data = {
            "port_scan": {
                "by_host": {
                    "x.example.invalid": {
                        "host": "x.example.invalid", "ip": "10.99.99.2",
                        "ports": [8080], "is_cdn": False,
                        "port_details": [{"port": 8080, "protocol": "tcp", "service": "http"}],
                    }
                },
                "by_ip": {"10.99.99.2": {"ip": "10.99.99.2", "hostnames": ["x.example.invalid"], "ports": [8080]}},
            }
        }
        mixin = _get_port_mixin_instance(drv)
        mixin.update_graph_from_port_scan(recon_data, uid, pid)
        with drv.session() as s:
            row = s.run(
                "MATCH (t:Technology {user_id:$u, project_id:$p}) WHERE t.category STARTS WITH 'ai-' RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()
            assert row["n"] == 0, "disambiguate port 8080 produced an AI Technology node (should be deferred to Phase 15)"
            _cleanup_port_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_nmap_mixin_writes_ai_runtime_version_on_service():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_nmap_mixin_writes_ai_runtime_version_on_service (neo4j unreachable)")
        return
    uid, pid = "phase3-test-user", "phase3-test-project-nmap"
    try:
        from graph_db.mixins.recon.port_mixin import PortMixin

        class _ScratchGraph(PortMixin):
            def __init__(self, drv):
                self.driver = drv

        graph = _ScratchGraph(drv)

        with drv.session() as s:
            _cleanup_port_test_data(s, uid, pid)
            # Seed a Service node that nmap will enrich. Mirrors what port_scan
            # would have created.
            s.run(
                """
                MERGE (i:IP {address:'10.99.99.3', user_id:$u, project_id:$p})
                MERGE (p:Port {number:11434, protocol:'tcp', ip_address:'10.99.99.3', user_id:$u, project_id:$p})
                MERGE (svc:Service {name:'ollama', port_number:11434, ip_address:'10.99.99.3', user_id:$u, project_id:$p})
                """,
                u=uid, p=pid,
            )

        recon_data = {
            "nmap_scan": {
                "by_host": {
                    "llm.example.invalid": {
                        "ip": "10.99.99.3",
                        "port_details": [{
                            "port": 11434, "protocol": "tcp", "state": "open",
                            "service": "ollama", "product": "Ollama/0.1.32",
                            "version": "", "extrainfo": "", "cpe": "",
                            "scripts": {},
                            "ai_runtime_version": "ollama",
                        }],
                    }
                },
                "services_detected": [],
                "nse_vulns": [],
            }
        }
        graph.update_graph_from_nmap(recon_data, uid, pid)

        with drv.session() as s:
            row = s.run(
                """
                MATCH (svc:Service {port_number:11434, ip_address:'10.99.99.3', user_id:$u, project_id:$p})
                RETURN svc.ai_runtime_version AS v
                """,
                u=uid, p=pid,
            ).single()
            assert row is not None and row["v"] == "ollama", (
                f"Service.ai_runtime_version not set; got {row}"
            )
            _cleanup_port_test_data(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_port_mixin_repeat_runs_keep_single_tech_edge():
    """Re-running the port scan must not duplicate edges. MERGE semantics
    plus the SET on r.detected_by keep the relationship a single instance."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_port_mixin_repeat_runs_keep_single_tech_edge (neo4j unreachable)")
        return
    uid, pid = "phase3-test-user", "phase3-test-project-rerun"
    try:
        with drv.session() as s:
            _cleanup_port_test_data(s, uid, pid)
        mixin = _get_port_mixin_instance(drv)
        mixin.update_graph_from_port_scan(_make_recon_data_for_port_scan(), uid, pid)
        mixin.update_graph_from_port_scan(_make_recon_data_for_port_scan(), uid, pid)
        with drv.session() as s:
            n_rels = s.run(
                """
                MATCH (svc:Service {port_number:11434, user_id:$u, project_id:$p})
                      -[r:USES_TECHNOLOGY]->(t:Technology {name:'ollama'})
                RETURN count(r) AS n
                """,
                u=uid, p=pid,
            ).single()["n"]
            assert n_rels == 1, f"expected 1 USES_TECHNOLOGY edge, got {n_rels}"
            n_techs = s.run(
                "MATCH (t:Technology {name:'ollama', user_id:$u, project_id:$p}) RETURN count(t) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n_techs == 1, f"expected 1 Technology node, got {n_techs}"
            _cleanup_port_test_data(s, uid, pid)
    finally:
        drv.close()


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
