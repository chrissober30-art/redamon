"""Unit + integration tests for the Julius probe-pack engine.

Verifies the matcher semantics reproduced from the Julius Go source:
rules AND within a request; `require` any/all; specificity ranking; per-rule
case sensitivity; negation; missing-header + not:true = pass. Also loads the
vendored julius packs and runs them against a fake session.

Run inside the recon image (needs PyYAML; jq is optional/lazy):
    docker run --rm --entrypoint python3 -v "$PWD/recon:/app/recon:ro" -w /app \
        redamon-recon:latest recon/tests/test_probe_pack_engine.py
"""
from __future__ import annotations
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import probe_pack_engine as eng


# --- fakes -------------------------------------------------------------------
class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    def json(self):
        import json
        return json.loads(self.text)


class FakeSession:
    """Maps (method, path) -> FakeResp. Path = request path only."""
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.calls = []

    def request(self, method, url, headers=None, data=None, timeout=None,
                allow_redirects=False, verify=True):
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        self.calls.append((method, path))
        resp = self.routes.get((method, path))
        if resp is None:
            raise eng.requests.RequestException("no route")
        return resp


# --- _match_rule -------------------------------------------------------------
def test_rule_status():
    r = eng.MatchRule(type="status", value=200)
    assert eng._match_rule(r, 200, "", {}) is True
    assert eng._match_rule(r, 404, "", {}) is False


def test_rule_body_contains_case_sensitive():
    r = eng.MatchRule(type="body.contains", value="Ollama is running")
    assert eng._match_rule(r, 200, "Ollama is running", {}) is True
    # case-sensitive: lowercased body must NOT match
    assert eng._match_rule(r, 200, "ollama is running", {}) is False


def test_rule_body_prefix():
    r = eng.MatchRule(type="body.prefix", value="{")
    assert eng._match_rule(r, 200, '{"a":1}', {}) is True
    assert eng._match_rule(r, 200, ' {"a":1}', {}) is False


def test_rule_content_type_case_insensitive():
    r = eng.MatchRule(type="content-type", value="application/json")
    assert eng._match_rule(r, 200, "", {"Content-Type": "application/json; charset=utf-8"}) is True
    assert eng._match_rule(r, 200, "", {"content-type": "APPLICATION/JSON"}) is True
    assert eng._match_rule(r, 200, "", {"Content-Type": "text/html"}) is False


def test_rule_header_contains_and_missing_negation():
    r = eng.MatchRule(type="header.contains", value="nginx", header="Server")
    assert eng._match_rule(r, 200, "", {"Server": "nginx/1.19"}) is True
    # missing header + not:true -> PASS (Julius semantics)
    rn = eng.MatchRule(type="header.contains", value="x", header="X-Absent", negate=True)
    assert eng._match_rule(rn, 200, "", {}) is True
    # present header + not:true + match -> fail
    rn2 = eng.MatchRule(type="header.contains", value="nginx", header="Server", negate=True)
    assert eng._match_rule(rn2, 200, "", {"Server": "nginx"}) is False


def test_rule_unknown_type_is_false():
    r = eng.MatchRule(type="totally-bogus", value="x")
    assert eng._match_rule(r, 200, "x", {}) is False


# --- evaluate_probe: require any/all -----------------------------------------
def _probe(require, reqs):
    return eng.Probe(name="t", require=require, requests=reqs)


def test_require_all_needs_every_request():
    reqs = [
        eng.ProbeRequest(path="/a", match=[eng.MatchRule("status", 200)]),
        eng.ProbeRequest(path="/b", match=[eng.MatchRule("status", 200)]),
    ]
    sess = FakeSession({("GET", "/a"): FakeResp(200), ("GET", "/b"): FakeResp(200)})
    assert eng.evaluate_probe(sess, "http://h", _probe("all", reqs), 1) == "/a"
    sess2 = FakeSession({("GET", "/a"): FakeResp(200), ("GET", "/b"): FakeResp(500)})
    assert eng.evaluate_probe(sess2, "http://h", _probe("all", reqs), 1) is None


def test_require_any_first_match_wins():
    reqs = [
        eng.ProbeRequest(path="/a", match=[eng.MatchRule("status", 200)]),
        eng.ProbeRequest(path="/b", match=[eng.MatchRule("status", 200)]),
    ]
    sess = FakeSession({("GET", "/a"): FakeResp(500), ("GET", "/b"): FakeResp(200)})
    assert eng.evaluate_probe(sess, "http://h", _probe("any", reqs), 1) == "/b"


def test_rules_within_request_are_anded():
    req = eng.ProbeRequest(path="/x", match=[
        eng.MatchRule("status", 200),
        eng.MatchRule("body.contains", "models"),
    ])
    ok = FakeSession({("GET", "/x"): FakeResp(200, '{"models":[]}')})
    bad = FakeSession({("GET", "/x"): FakeResp(200, "no match")})
    assert eng.evaluate_probe(ok, "http://h", _probe("any", [req]), 1) == "/x"
    assert eng.evaluate_probe(bad, "http://h", _probe("any", [req]), 1) is None


# --- ranking by specificity --------------------------------------------------
def test_run_probe_packs_ranks_by_specificity():
    low = eng.Probe(name="generic", specificity=1, require="any",
                    requests=[eng.ProbeRequest(path="/x", match=[eng.MatchRule("status", 200)])])
    high = eng.Probe(name="ollama", specificity=100, require="any",
                     requests=[eng.ProbeRequest(path="/x", match=[eng.MatchRule("status", 200)])])
    sess = FakeSession({("GET", "/x"): FakeResp(200)})

    # monkeypatch requests.Session to our fake within run_probe_packs
    orig = eng.requests.Session
    eng.requests.Session = lambda: sess
    try:
        results = eng.run_probe_packs("http://h", [low, high], timeout=1, extract_models=False)
    finally:
        eng.requests.Session = orig
    assert [r.name for r in results] == ["ollama", "generic"]
    assert results[0].specificity == 100


# --- _parse_probe + load_probe_packs (vendored) ------------------------------
def test_parse_probe_defaults_require_any():
    p = eng._parse_probe({"name": "x", "requests": [{"path": "/", "match": [{"type": "status", "value": 200}]}]})
    assert p is not None and p.require == "any"
    assert p.requests[0].match[0].type == "status"


def test_parse_probe_rejects_nameless():
    assert eng._parse_probe({"description": "no name"}) is None
    assert eng._parse_probe("not a dict") is None


def test_load_vendored_julius_packs():
    julius_dir = PROJECT_ROOT / "recon" / "main_recon_modules" / "ai_surface_probes" / "julius"
    probes = eng.load_probe_packs(julius_dir)
    names = {p.name for p in probes}
    assert "ollama" in names, f"expected ollama pack, got {names}"
    assert "openai-compatible" in names
    ollama = next(p for p in probes if p.name == "ollama")
    assert ollama.require == "all" and ollama.specificity == 100
    assert ollama.port_hint == 11434


def test_load_missing_dir_is_softfail():
    assert eng.load_probe_packs("/nonexistent/dir/xyz") == []


def test_vendored_ollama_matches_fake_server():
    julius_dir = PROJECT_ROOT / "recon" / "main_recon_modules" / "ai_surface_probes" / "julius"
    probes = eng.load_probe_packs(julius_dir)
    ollama = next(p for p in probes if p.name == "ollama")
    sess = FakeSession({
        ("GET", "/"): FakeResp(200, "Ollama is running"),
        ("GET", "/api/tags"): FakeResp(200, '{"models":[{"name":"llama3"}]}',
                                       {"Content-Type": "application/json"}),
    })
    assert eng.evaluate_probe(sess, "http://h", ollama, 1) == "/"


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
