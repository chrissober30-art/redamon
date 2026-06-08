"""Unit + integration tests for the domain_recon AI TXT/NS hint hook (Phase 2).

Covers ``_annotate_ai_service_hint`` directly and the integration path through
``resolve_all_dns`` with a mocked ``dns_lookup`` so the test stays offline.

Run standalone (no pytest required):

    docker run --rm --entrypoint python3 \\
        -v "$PWD:/work:ro" -w /work redamon-recon:latest \\
        recon/tests/test_ai_domain_recon_hint.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# domain_recon.py imports `from helpers.ai_signal_catalog import ...` with the
# in-container layout (recon/ on sys.path).
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

from recon.helpers.ai_signal_catalog import AI_NS_HINT_PATTERNS, AI_TXT_PATTERNS
from recon.main_recon_modules.domain_recon import (
    _annotate_ai_service_hint,
    resolve_all_dns,
)


# Shorthand for the toggle settings dict
ON = {
    "DOMAIN_RECON_AI_TXT_HINT_ENABLED": True,
    "DOMAIN_RECON_AI_NS_HINT_ENABLED": True,
}


def _make_dns_entry(txt=None, ns=None, ips=None):
    """Build a minimal dns_lookup-shaped dict for the annotator."""
    return {
        "records": {
            "A": [] if ips is None else ips,
            "TXT": txt or [],
            "NS": ns or [],
        },
        "ips": {"ipv4": ips or [], "ipv6": []},
        "has_records": bool(txt or ns or ips),
    }


# ---------------------------------------------------------------------------
# _annotate_ai_service_hint — TXT matching
# ---------------------------------------------------------------------------

def test_annotate_returns_vendor_name_on_known_txt_vendor():
    entry = _make_dns_entry(txt=["v=spf1 include:_spf.anthropic.com ~all"])
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "anthropic"


def test_annotate_handles_multiple_txt_records_first_match_wins():
    """Patterns are ordered by strength inside AI_TXT_PATTERNS; first hit wins."""
    entry = _make_dns_entry(txt=[
        "v=spf1 include:_spf.google.com ~all",  # no match
        "verification=replicate.com",            # match
        "another-anthropic.com-style-record",    # also matches, but later
    ])
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] in {"replicate", "anthropic"}, (
        "expected one of replicate/anthropic, got " + repr(entry.get("ai_service_hint"))
    )


def test_annotate_does_not_set_hint_when_no_match():
    entry = _make_dns_entry(txt=["v=DMARC1; p=reject", "stripe-verify=abc"])
    _annotate_ai_service_hint(entry, ON)
    assert "ai_service_hint" not in entry


# ---------------------------------------------------------------------------
# _annotate_ai_service_hint — NS matching (weakest signal)
# ---------------------------------------------------------------------------

def test_annotate_uses_ns_hint_when_no_txt_match():
    entry = _make_dns_entry(ns=["ns1.vercel-dns.com.", "ns2.vercel-dns.com."])
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "ai-hosting-candidate"


def test_annotate_txt_overrides_ns_in_same_pass():
    """If both TXT and NS would match, the TXT hint (a concrete provider)
    wins — NS hint never overrides a stronger signal."""
    entry = _make_dns_entry(
        txt=["openai.com domain verification"],
        ns=["ns1.vercel-dns.com."],
    )
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "openai", (
        f"NS hint stomped TXT hint: got {entry.get('ai_service_hint')!r}"
    )


# ---------------------------------------------------------------------------
# _annotate_ai_service_hint — toggle gating
# ---------------------------------------------------------------------------

def test_annotate_no_op_when_settings_is_none():
    """Legacy callers (tests, partial recon paths that don't have settings)
    must remain unaffected."""
    entry = _make_dns_entry(txt=["openai.com verify"])
    _annotate_ai_service_hint(entry, None)
    assert "ai_service_hint" not in entry


def test_annotate_no_op_when_settings_is_empty_dict():
    entry = _make_dns_entry(txt=["openai.com verify"])
    _annotate_ai_service_hint(entry, {})
    # Both toggles default True via .get(_, True) so this should still fire.
    assert entry.get("ai_service_hint") == "openai"


def test_annotate_skips_txt_when_txt_toggle_off_only():
    """With only NS allowed, a TXT-matching record must not set the hint."""
    entry = _make_dns_entry(txt=["openai.com verify"])
    settings = {"DOMAIN_RECON_AI_TXT_HINT_ENABLED": False, "DOMAIN_RECON_AI_NS_HINT_ENABLED": True}
    _annotate_ai_service_hint(entry, settings)
    assert "ai_service_hint" not in entry


def test_annotate_skips_ns_when_ns_toggle_off_only():
    entry = _make_dns_entry(ns=["ns1.vercel-dns.com."])
    settings = {"DOMAIN_RECON_AI_TXT_HINT_ENABLED": True, "DOMAIN_RECON_AI_NS_HINT_ENABLED": False}
    _annotate_ai_service_hint(entry, settings)
    assert "ai_service_hint" not in entry


def test_annotate_no_op_when_both_toggles_off():
    entry = _make_dns_entry(txt=["openai.com verify"], ns=["ns1.vercel-dns.com."])
    settings = {"DOMAIN_RECON_AI_TXT_HINT_ENABLED": False, "DOMAIN_RECON_AI_NS_HINT_ENABLED": False}
    _annotate_ai_service_hint(entry, settings)
    assert "ai_service_hint" not in entry


# ---------------------------------------------------------------------------
# _annotate_ai_service_hint — defensive shape handling
# ---------------------------------------------------------------------------

def test_annotate_tolerates_missing_records_field():
    """A DNS lookup that errored may return a partial dict."""
    entry = {"has_records": False}
    _annotate_ai_service_hint(entry, ON)
    assert "ai_service_hint" not in entry


def test_annotate_tolerates_none_for_record_lists():
    """dns_lookup_single returns None when a record type doesn't exist."""
    entry = {"records": {"TXT": None, "NS": None}, "has_records": False, "ips": {"ipv4": [], "ipv6": []}}
    _annotate_ai_service_hint(entry, ON)
    assert "ai_service_hint" not in entry


def test_annotate_is_idempotent_on_repeat_runs():
    entry = _make_dns_entry(txt=["anthropic.com verify"])
    _annotate_ai_service_hint(entry, ON)
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "anthropic"


# ---------------------------------------------------------------------------
# Integration — resolve_all_dns end-to-end with mocked dns_lookup
# ---------------------------------------------------------------------------

def _fake_dns_lookup(per_host: dict) -> "callable":
    """Build a fake dns_lookup that returns the supplied per-host result."""
    def _fn(hostname, max_retries=3, parallel=True):
        return per_host.get(hostname, _make_dns_entry())
    return _fn


def test_resolve_all_dns_propagates_hint_to_root_and_subdomains():
    per_host = {
        "example.com": _make_dns_entry(txt=["v=spf1 include:_spf.anthropic.com ~all"]),
        "ai.example.com": _make_dns_entry(txt=["replicate.com verify"]),
        "blog.example.com": _make_dns_entry(ns=["ns1.vercel-dns.com."]),
        "plain.example.com": _make_dns_entry(txt=["unrelated"]),
    }
    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=_fake_dns_lookup(per_host)):
        result = resolve_all_dns(
            "example.com",
            ["ai.example.com", "blog.example.com", "plain.example.com"],
            max_workers=4, record_parallelism=False, settings=ON,
        )

    assert result["domain"]["ai_service_hint"] == "anthropic"
    assert result["subdomains"]["ai.example.com"]["ai_service_hint"] == "replicate"
    assert result["subdomains"]["blog.example.com"]["ai_service_hint"] == "ai-hosting-candidate"
    assert "ai_service_hint" not in result["subdomains"]["plain.example.com"]


def test_resolve_all_dns_does_nothing_without_settings():
    """The pre-Phase-2 signature (no settings kwarg) must keep working — the
    parallelization test and any other legacy caller relies on this."""
    per_host = {
        "example.com": _make_dns_entry(txt=["v=spf1 include:_spf.anthropic.com ~all"]),
    }
    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=_fake_dns_lookup(per_host)):
        result = resolve_all_dns("example.com", [], max_workers=2, record_parallelism=False)
    assert "ai_service_hint" not in result["domain"]


def test_resolve_all_dns_respects_disabled_toggles_globally():
    per_host = {
        "example.com": _make_dns_entry(txt=["anthropic.com verify"]),
        "x.example.com": _make_dns_entry(ns=["ns1.vercel-dns.com."]),
    }
    settings_off = {"DOMAIN_RECON_AI_TXT_HINT_ENABLED": False, "DOMAIN_RECON_AI_NS_HINT_ENABLED": False}
    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=_fake_dns_lookup(per_host)):
        result = resolve_all_dns(
            "example.com", ["x.example.com"], max_workers=2,
            record_parallelism=False, settings=settings_off,
        )
    assert "ai_service_hint" not in result["domain"]
    assert "ai_service_hint" not in result["subdomains"]["x.example.com"]


# ---------------------------------------------------------------------------
# Regression — DNS shape preserved (other consumers must keep working)
# ---------------------------------------------------------------------------

def test_resolve_all_dns_preserves_existing_shape():
    """The annotator only adds an optional key. All existing keys (records,
    ips, has_records) and the (domain, subdomains) split must survive."""
    per_host = {
        "example.com": _make_dns_entry(txt=["anthropic.com verify"], ips=["1.2.3.4"]),
        "x.example.com": _make_dns_entry(),
    }
    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=_fake_dns_lookup(per_host)):
        result = resolve_all_dns(
            "example.com", ["x.example.com"], max_workers=2,
            record_parallelism=False, settings=ON,
        )
    assert set(result.keys()) == {"domain", "subdomains"}
    assert set(result["domain"].keys()) >= {"records", "ips", "has_records"}
    assert set(result["subdomains"]["x.example.com"].keys()) >= {"records", "ips", "has_records"}


# ---------------------------------------------------------------------------
# Pattern coverage — every vendor in the catalogue actually fires
# ---------------------------------------------------------------------------

def test_every_ai_txt_pattern_fires_against_a_synthetic_record():
    """The catalog is only valuable if every entry is reachable. Build a
    synthetic TXT record from each pattern's source regex and assert the
    annotator returns the matching provider hint."""
    # Curated TXT samples that satisfy each AI_TXT_PATTERNS entry. The
    # catalogue's pattern source uses `\b<token>\b`, so any sentence
    # containing the token will match.
    samples_by_hint = {
        "anthropic":   "v=spf1 include:_spf.anthropic.com ~all",
        "openai":      "v=spf1 include:openai.com -all",
        "huggingface": "huggingface.co domain verification",
        "cohere":      "cohere.com=verify",
        "replicate":   "verification=replicate.com",
        "langchain":   "langchain.com api key",
        "langfuse":    "langfuse.com tenant=abc",
        "langsmith":   "langsmith.com workspace=xyz",
        "together":    "verify=together.ai",
        "groq":        "groq.com=verified",
        "mistral":     "mistral.ai=verified",
    }
    expected_hints = {hint for _pat, hint in AI_TXT_PATTERNS}
    missing = expected_hints - set(samples_by_hint)
    assert not missing, (
        f"test fixture out of sync with AI_TXT_PATTERNS — missing samples for: {missing}"
    )
    extra = set(samples_by_hint) - expected_hints
    assert not extra, f"test fixture has stale entries no longer in AI_TXT_PATTERNS: {extra}"

    for hint, record in samples_by_hint.items():
        entry = _make_dns_entry(txt=[record])
        _annotate_ai_service_hint(entry, ON)
        assert entry.get("ai_service_hint") == hint, (
            f"AI_TXT_PATTERNS entry for {hint!r} did not fire on {record!r}; "
            f"got {entry.get('ai_service_hint')!r}"
        )


def test_every_ai_ns_hint_pattern_fires_against_a_synthetic_record():
    samples_by_hint = {
        "vercel":             "ns1.vercel-dns.com.",
        "netlify":            "dns3.nsone.net.",
        "replit":             "replit.com.",
        "modal":              "ns1.modal-dns.example.",
        "huggingface-spaces": "ns1.huggingface.co.",
    }
    expected_hints = {hint for _pat, hint in AI_NS_HINT_PATTERNS}
    missing = expected_hints - set(samples_by_hint)
    assert not missing, f"NS test fixture missing samples for: {missing}"
    extra = set(samples_by_hint) - expected_hints
    assert not extra, f"NS test fixture has stale entries: {extra}"

    for _hint, ns_record in samples_by_hint.items():
        entry = _make_dns_entry(ns=[ns_record])
        _annotate_ai_service_hint(entry, ON)
        # NS matches always normalise to the weakest signal — the provider
        # name itself is not stored; "ai-hosting-candidate" is.
        assert entry.get("ai_service_hint") == "ai-hosting-candidate", (
            f"NS pattern did not fire on {ns_record!r}; got {entry.get('ai_service_hint')!r}"
        )


# ---------------------------------------------------------------------------
# Real-world DNS output shape — dnspython rr.to_text() formats
# ---------------------------------------------------------------------------

def test_txt_record_with_surrounding_quotes_still_matches():
    """dns.resolver returns TXT values via rr.to_text() which wraps them in
    double-quotes. The annotator must still match through the quotes."""
    entry = _make_dns_entry(txt=['"v=spf1 include:_spf.anthropic.com ~all"'])
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "anthropic"


def test_txt_record_with_concatenated_quoted_chunks_matches():
    """dnspython joins long TXT records as multiple quoted chunks, e.g.
    `"chunk1" "chunk2"`. The annotator must still find the vendor token."""
    entry = _make_dns_entry(txt=['"v=spf1 ip4:10.0.0.0/8 " "include:openai.com ~all"'])
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "openai"


def test_ns_record_with_trailing_dot_still_matches():
    """rr.to_text() on an NS record yields a hostname with a trailing dot."""
    entry = _make_dns_entry(ns=["ns1.vercel-dns.com."])
    _annotate_ai_service_hint(entry, ON)
    assert entry["ai_service_hint"] == "ai-hosting-candidate"


def test_multi_vendor_txt_uses_pattern_catalog_priority():
    """When a single TXT contains tokens for multiple vendors, the catalog
    order determines which fires (anthropic > openai > … per the file).
    Specifically: AI_TXT_PATTERNS lists anthropic before openai, so a TXT
    naming both should resolve to anthropic."""
    entry = _make_dns_entry(txt=["v=spf1 include:anthropic.com include:openai.com ~all"])
    _annotate_ai_service_hint(entry, ON)
    # Look up actual catalog order to avoid hard-coding "anthropic"
    order = [hint for _pat, hint in AI_TXT_PATTERNS]
    anthropic_idx = order.index("anthropic")
    openai_idx = order.index("openai")
    expected = "anthropic" if anthropic_idx < openai_idx else "openai"
    assert entry["ai_service_hint"] == expected, (
        f"catalog priority broken: AI_TXT_PATTERNS order says {expected!r} should win "
        f"but annotator chose {entry.get('ai_service_hint')!r}"
    )


def test_txt_record_case_insensitive():
    """SPF and DKIM headers commonly use mixed case; the regex must be CI."""
    for variant in [
        "v=SPF1 INCLUDE:_SPF.ANTHROPIC.COM ~ALL",
        "OpenAI.com domain verification",
        "REPLICATE.com=token123",
    ]:
        entry = _make_dns_entry(txt=[variant])
        _annotate_ai_service_hint(entry, ON)
        assert entry.get("ai_service_hint") is not None, (
            f"case-insensitive match failed on {variant!r}"
        )


# ---------------------------------------------------------------------------
# resolve_all_dns — edge cases and error paths
# ---------------------------------------------------------------------------

def test_resolve_all_dns_with_empty_subdomain_list():
    """Pre-Phase-2 invariant: empty list resolves only the root domain.
    The AI annotator must not crash on the empty case."""
    per_host = {"example.com": _make_dns_entry(txt=["anthropic.com verify"])}
    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=_fake_dns_lookup(per_host)):
        result = resolve_all_dns("example.com", [], max_workers=2, record_parallelism=False, settings=ON)
    assert result["subdomains"] == {}
    assert result["domain"]["ai_service_hint"] == "anthropic"


def test_resolve_all_dns_dns_lookup_exception_does_not_crash_annotator():
    """If dns_lookup raises mid-flight, resolve_all_dns substitutes an
    empty-records dict (see the except branch). The annotator must
    tolerate that shape — no hint, no crash."""
    def bomb(hostname, max_retries=3, parallel=True):
        if hostname == "broken.example.com":
            raise RuntimeError("simulated DNS lookup failure")
        return _make_dns_entry(txt=["anthropic.com verify"])

    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=bomb):
        result = resolve_all_dns(
            "example.com",
            ["ok.example.com", "broken.example.com"],
            max_workers=2, record_parallelism=False, settings=ON,
        )
    # The failed host got the fallback dict; the annotator must leave it alone
    assert result["subdomains"]["broken.example.com"]["has_records"] is False
    assert "ai_service_hint" not in result["subdomains"]["broken.example.com"]
    # The healthy host still gets its hint
    assert result["subdomains"]["ok.example.com"]["ai_service_hint"] == "anthropic"


def test_resolve_all_dns_subdomain_with_no_records_gets_no_hint():
    """Subdomains where every record type was None (NXDOMAIN-style) must
    not get an AI hint by accident."""
    per_host = {
        "example.com": _make_dns_entry(txt=["anthropic.com verify"]),
        "ghost.example.com": {
            "records": {"A": None, "TXT": None, "NS": None},
            "ips": {"ipv4": [], "ipv6": []},
            "has_records": False,
        },
    }
    with patch("recon.main_recon_modules.domain_recon.dns_lookup", side_effect=_fake_dns_lookup(per_host)):
        result = resolve_all_dns(
            "example.com", ["ghost.example.com"], max_workers=2,
            record_parallelism=False, settings=ON,
        )
    assert result["domain"]["ai_service_hint"] == "anthropic"
    assert "ai_service_hint" not in result["subdomains"]["ghost.example.com"]


# ---------------------------------------------------------------------------
# Callsite verification — settings actually flows through
# ---------------------------------------------------------------------------

def test_callsite_main_py_passes_settings_kwarg():
    main_src = (PROJECT_ROOT / "recon" / "main.py").read_text()
    # Find the resolve_all_dns call inside main.py (filtered subdomain path)
    needle = "resolve_all_dns(root_domain, full_subdomains"
    idx = main_src.find(needle)
    assert idx != -1, "couldn't locate resolve_all_dns callsite in main.py"
    # The call must include `settings=` as kwarg
    end = main_src.find(")", idx)
    call_block = main_src[idx:end]
    assert "settings=_settings" in call_block, (
        "main.py callsite to resolve_all_dns is missing settings=_settings — "
        "AI hints will never fire in production scans."
    )


def test_callsite_partial_recon_subdomain_discovery_passes_settings_kwarg():
    src = (PROJECT_ROOT / "recon" / "partial_recon_modules" / "subdomain_discovery.py").read_text()
    needle = "resolve_all_dns(domain, all_subs"
    idx = src.find(needle)
    assert idx != -1, "couldn't locate resolve_all_dns callsite in subdomain_discovery.py"
    end = src.find(")", idx)
    call_block = src[idx:end]
    assert "settings=settings" in call_block, (
        "partial recon subdomain_discovery is missing settings= — "
        "partial-recon runs won't get AI hints."
    )


def test_callsite_domain_recon_discover_subdomains_passes_settings_kwarg():
    """discover_subdomains() itself calls resolve_all_dns when resolve=True
    (line ~875). That call must thread settings too."""
    src = (PROJECT_ROOT / "recon" / "main_recon_modules" / "domain_recon.py").read_text()
    # Locate the call inside discover_subdomains (the one wrapped in `if resolve:`)
    in_func = src.split("def discover_subdomains")[1]  # everything from that def onwards
    needle = 'resolve_all_dns(domain, all_subs'
    idx = in_func.find(needle)
    assert idx != -1, "couldn't locate resolve_all_dns callsite inside discover_subdomains"
    end = in_func.find(")", idx)
    call_block = in_func[idx:end]
    assert "settings=settings" in call_block, (
        "discover_subdomains' internal resolve_all_dns call is missing settings="
    )


# ---------------------------------------------------------------------------
# Graph mixin — Cypher preservation logic (live Neo4j)
# ---------------------------------------------------------------------------

def _neo4j_driver():
    """Return a Neo4j driver if the container is reachable, else None."""
    try:
        from neo4j import GraphDatabase  # type: ignore
    except Exception:
        return None
    uri = "bolt://localhost:7687"
    pwd = "changeme123"  # from docker-compose default
    try:
        drv = GraphDatabase.driver(uri, auth=("neo4j", pwd))
        # Probe — verify_connectivity() raises if unreachable
        drv.verify_connectivity()
        return drv
    except Exception:
        return None


def _cleanup_test_subdomain(session, name: str, uid: str, pid: str) -> None:
    session.run(
        "MATCH (s:Subdomain {name:$n, user_id:$u, project_id:$p}) DETACH DELETE s",
        n=name, u=uid, p=pid,
    )


def _run_subdomain_upsert(session, name: str, uid: str, pid: str, ai_hint: str | None) -> None:
    """Mirror the Cypher in domain_mixin.update_graph_from_domain_discovery()."""
    session.run(
        """
        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
        SET s.has_dns_records = $has_records,
            s.status = coalesce(s.status, $status),
            s.discovered_at = coalesce(s.discovered_at, datetime()),
            s.updated_at = datetime(),
            s.ai_service_hint = CASE
                WHEN $ai_service_hint IS NULL THEN s.ai_service_hint
                WHEN s.ai_service_hint IS NULL THEN $ai_service_hint
                WHEN $ai_service_hint = 'ai-hosting-candidate' AND s.ai_service_hint <> 'ai-hosting-candidate' THEN s.ai_service_hint
                ELSE $ai_service_hint
            END
        """,
        name=name, user_id=uid, project_id=pid,
        has_records=True, status="resolved",
        ai_service_hint=ai_hint,
    )


def _read_hint(session, name: str, uid: str, pid: str) -> str | None:
    rec = session.run(
        "MATCH (s:Subdomain {name:$n, user_id:$u, project_id:$p}) RETURN s.ai_service_hint AS h",
        n=name, u=uid, p=pid,
    ).single()
    return None if rec is None else rec["h"]


def test_neo4j_mixin_writes_ai_service_hint_on_fresh_subdomain():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_writes_ai_service_hint_on_fresh_subdomain (neo4j unreachable)")
        return
    name, uid, pid = "ai-hint-test-fresh.example.invalid", "test-user", "test-project-phase2"
    try:
        with drv.session() as s:
            _cleanup_test_subdomain(s, name, uid, pid)
            _run_subdomain_upsert(s, name, uid, pid, "anthropic")
            assert _read_hint(s, name, uid, pid) == "anthropic"
            _cleanup_test_subdomain(s, name, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_does_not_downgrade_strong_hint_with_ai_hosting_candidate():
    """The CASE expression preserves the stronger TXT hint even when a later
    NS pass would set the weak 'ai-hosting-candidate'."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_does_not_downgrade_strong_hint_with_ai_hosting_candidate (neo4j unreachable)")
        return
    name, uid, pid = "ai-hint-test-no-downgrade.example.invalid", "test-user", "test-project-phase2"
    try:
        with drv.session() as s:
            _cleanup_test_subdomain(s, name, uid, pid)
            _run_subdomain_upsert(s, name, uid, pid, "anthropic")
            assert _read_hint(s, name, uid, pid) == "anthropic"
            # Now a re-scan that only sees an NS hint must not stomp anthropic
            _run_subdomain_upsert(s, name, uid, pid, "ai-hosting-candidate")
            assert _read_hint(s, name, uid, pid) == "anthropic"
            _cleanup_test_subdomain(s, name, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_upgrades_weak_hint_when_strong_one_arrives():
    """Inverse: a previous 'ai-hosting-candidate' MUST be replaced when a
    real vendor hint (e.g. 'anthropic') arrives on the next scan."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_upgrades_weak_hint_when_strong_one_arrives (neo4j unreachable)")
        return
    name, uid, pid = "ai-hint-test-upgrade.example.invalid", "test-user", "test-project-phase2"
    try:
        with drv.session() as s:
            _cleanup_test_subdomain(s, name, uid, pid)
            _run_subdomain_upsert(s, name, uid, pid, "ai-hosting-candidate")
            assert _read_hint(s, name, uid, pid) == "ai-hosting-candidate"
            _run_subdomain_upsert(s, name, uid, pid, "anthropic")
            assert _read_hint(s, name, uid, pid) == "anthropic"
            _cleanup_test_subdomain(s, name, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_null_hint_does_not_overwrite_existing_hint():
    """Running domain_recon with the AI toggles off must not erase an
    ai_service_hint set during a previous (toggle-on) scan."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_null_hint_does_not_overwrite_existing_hint (neo4j unreachable)")
        return
    name, uid, pid = "ai-hint-test-null-preserve.example.invalid", "test-user", "test-project-phase2"
    try:
        with drv.session() as s:
            _cleanup_test_subdomain(s, name, uid, pid)
            _run_subdomain_upsert(s, name, uid, pid, "replicate")
            assert _read_hint(s, name, uid, pid) == "replicate"
            _run_subdomain_upsert(s, name, uid, pid, None)
            assert _read_hint(s, name, uid, pid) == "replicate"
            _cleanup_test_subdomain(s, name, uid, pid)
    finally:
        drv.close()


def test_neo4j_mixin_strong_hint_replaced_with_different_strong_hint():
    """A previous 'anthropic' should be updated to 'openai' if the next
    scan returns a different vendor — the CASE expression overwrites for
    strong-vs-strong since neither side is 'ai-hosting-candidate'."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_mixin_strong_hint_replaced_with_different_strong_hint (neo4j unreachable)")
        return
    name, uid, pid = "ai-hint-test-vendor-swap.example.invalid", "test-user", "test-project-phase2"
    try:
        with drv.session() as s:
            _cleanup_test_subdomain(s, name, uid, pid)
            _run_subdomain_upsert(s, name, uid, pid, "anthropic")
            _run_subdomain_upsert(s, name, uid, pid, "openai")
            assert _read_hint(s, name, uid, pid) == "openai"
            _cleanup_test_subdomain(s, name, uid, pid)
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
