"""
Tests for the redagraph CLI and its tenant-scoping helpers.

Covers:
- graph_db.tenant_filter (unit)
- mcp/servers/redagraph.py helpers + parser (unit)
- mcp/servers/terminal_server.py _read_init_frame (integration with mock WS)
"""
import asyncio
import importlib.util
import io
import json
import os
import sys
import types
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_module(dotted_name: str, file_path: str):
    """Load a module from an absolute file path, registering it in sys.modules."""
    spec = importlib.util.spec_from_file_location(dotted_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[dotted_name] = module
    spec.loader.exec_module(module)
    return module


# Stub `graph_db` package so the host-side import does not pull in neo4j_client
# (which requires the `neo4j` driver, only present in the container).
_graph_db_stub = types.ModuleType("graph_db")
_graph_db_stub.__path__ = [os.path.join(REPO_ROOT, "graph_db")]
sys.modules["graph_db"] = _graph_db_stub

tf = _load_module("graph_db.tenant_filter", os.path.join(REPO_ROOT, "graph_db", "tenant_filter.py"))
rg = _load_module("redagraph", os.path.join(REPO_ROOT, "mcp", "servers", "redagraph.py"))
ts = _load_module("terminal_server", os.path.join(REPO_ROOT, "mcp", "servers", "terminal_server.py"))


# =============================================================================
# graph_db.tenant_filter
# =============================================================================
class TestInjectTenantFilter(unittest.TestCase):
    def test_simple_label_no_props(self):
        out = tf.inject_tenant_filter("MATCH (d:Domain) RETURN d", "U", "P")
        self.assertEqual(
            out,
            "MATCH (d:Domain {user_id: $tenant_user_id, project_id: $tenant_project_id}) RETURN d",
        )

    def test_label_with_existing_props(self):
        out = tf.inject_tenant_filter('MATCH (d:Domain {name: "x.com"}) RETURN d', "U", "P")
        self.assertIn("name:", out)
        self.assertIn("user_id: $tenant_user_id", out)
        self.assertIn("project_id: $tenant_project_id", out)

    def test_label_with_empty_braces(self):
        out = tf.inject_tenant_filter("MATCH (d:Domain {}) RETURN d", "U", "P")
        self.assertIn("user_id: $tenant_user_id", out)
        self.assertNotIn(", ,", out)

    def test_multiple_nodes_in_path(self):
        q = "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, s"
        out = tf.inject_tenant_filter(q, "U", "P")
        self.assertEqual(out.count("user_id: $tenant_user_id"), 2)
        self.assertEqual(out.count("project_id: $tenant_project_id"), 2)

    def test_anonymous_node_is_NOT_filtered(self):
        # Documents the known behaviour: unlabelled (n) is left alone.
        # Callers must add explicit WHERE filters for queries that use them.
        q = "MATCH (n) RETURN n"
        out = tf.inject_tenant_filter(q, "U", "P")
        self.assertEqual(q, out)

    def test_anonymous_with_label_only(self):
        # `(:Subdomain)` (no var) is also not picked up — same caveat.
        q = "MATCH (:Subdomain) RETURN count(*)"
        out = tf.inject_tenant_filter(q, "U", "P")
        self.assertEqual(q, out)

    def test_relationship_brackets_are_not_touched(self):
        q = "MATCH (d:Domain)-[r:HAS_PORT]->(p:Port) RETURN r"
        out = tf.inject_tenant_filter(q, "U", "P")
        self.assertNotIn("r:HAS_PORT {", out)
        self.assertIn("(p:Port {user_id: $tenant_user_id", out)


class TestFindDisallowedWriteOperation(unittest.TestCase):
    READ_OK = [
        "MATCH (n:Foo) RETURN n",
        "OPTIONAL MATCH (n:Foo)-[r]->(m) RETURN n, m",
        "CALL db.labels()",
        "CALL db.schema.visualization()",
        "WITH 1 AS x RETURN x",
        "UNWIND [1,2,3] AS i RETURN i",
    ]
    WRITES = {
        "CREATE (n:Foo)": "CREATE",
        "MATCH (n:Foo) SET n.x = 1": "SET",
        "MATCH (n:Foo) DELETE n": "DELETE",
        "MATCH (n:Foo) DETACH DELETE n": "DETACH DELETE",
        "MATCH (n:Foo) REMOVE n.x": "REMOVE",
        "MERGE (n:Foo {id: 1})": "MERGE",
        "DROP INDEX foo": "DROP",
        "GRANT TRAVERSE ON GRAPH * TO role": "GRANT",
        "LOAD CSV FROM 'x.csv' AS r RETURN r": "LOAD CSV",
        "CALL apoc.create.node([], {})": "apoc.create",
        "CALL apoc.cypher.runWrite('CREATE ()')": "apoc.cypher",
        "CALL dbms.security.createUser('a','b')": "dbms.",
    }

    def test_read_only_returns_none(self):
        for q in self.READ_OK:
            with self.subTest(q=q):
                self.assertIsNone(tf.find_disallowed_write_operation(q))

    def test_writes_detected(self):
        for q, expected_substring in self.WRITES.items():
            with self.subTest(q=q):
                hit = tf.find_disallowed_write_operation(q)
                self.assertIsNotNone(hit, f"Should reject: {q}")
                self.assertIn(expected_substring.split()[0].lower(), hit.lower())

    def test_case_insensitive(self):
        self.assertIsNotNone(tf.find_disallowed_write_operation("create (n:Foo)"))
        self.assertIsNotNone(tf.find_disallowed_write_operation("MaTcH (n) SeT n.x = 1"))

    def test_word_boundary_no_false_positive_on_property_name(self):
        # `set_value` should NOT trigger SET (regex \b prevents it because _ is a word char)
        self.assertIsNone(tf.find_disallowed_write_operation("MATCH (n:Foo) RETURN n.set_value"))
        self.assertIsNone(tf.find_disallowed_write_operation("MATCH (n:Foo) RETURN n.create_time"))

    def test_known_limitation_property_name_equals_keyword(self):
        # Pre-existing behaviour: if a property is literally named SET/CREATE
        # the word-boundary regex fires. Documented, not fixed in this CLI.
        self.assertIsNotNone(tf.find_disallowed_write_operation("MATCH (n:Foo) RETURN n.SET"))


# =============================================================================
# redagraph helpers
# =============================================================================
class TestToPlain(unittest.TestCase):
    def test_none(self):
        self.assertEqual(rg._to_plain(None), "")

    def test_str(self):
        self.assertEqual(rg._to_plain("hello"), "hello")

    def test_int(self):
        self.assertEqual(rg._to_plain(42), "42")

    def test_dict_serialises(self):
        out = rg._to_plain({"a": 1, "b": "x"})
        self.assertIn('"a"', out)
        self.assertIn('"b"', out)

    def test_list_serialises(self):
        self.assertEqual(rg._to_plain([1, 2]), "[1, 2]")


class _FakeRecord:
    """Minimal stand-in for neo4j.Record.

    Supports .keys() and __getitem__ which is all _emit / _record_to_dict use.
    """
    def __init__(self, mapping):
        self._mapping = dict(mapping)

    def keys(self):
        return list(self._mapping.keys())

    def __getitem__(self, key):
        return self._mapping[key]


class _FakeNode:
    """Duck-type stand-in for neo4j.graph.Node."""
    def __init__(self, labels, props):
        self.labels = frozenset(labels)
        self._props = dict(props)
    def items(self):
        return self._props.items()


class _FakeRelationship:
    def __init__(self, rel_type, props, nodes=("a", "b")):
        self.type = rel_type
        self._props = dict(props)
        self.nodes = nodes
    def items(self):
        return self._props.items()


class TestCoerce(unittest.TestCase):
    def test_primitives_passthrough(self):
        for v in (None, True, 1, 2.5, "x"):
            self.assertEqual(rg._coerce(v), v)

    def test_node_serialises(self):
        n = _FakeNode(["Subdomain"], {"name": "x.com", "user_id": "U"})
        out = rg._coerce(n)
        self.assertEqual(out["_kind"], "node")
        self.assertEqual(out["labels"], ["Subdomain"])
        self.assertEqual(out["properties"]["name"], "x.com")

    def test_relationship_serialises(self):
        r = _FakeRelationship("HAS_SUBDOMAIN", {"since": "2026"})
        out = rg._coerce(r)
        self.assertEqual(out["_kind"], "relationship")
        self.assertEqual(out["type"], "HAS_SUBDOMAIN")
        self.assertEqual(out["properties"]["since"], "2026")

    def test_list_of_nodes(self):
        out = rg._coerce([_FakeNode(["A"], {}), _FakeNode(["B"], {})])
        self.assertEqual([n["labels"] for n in out], [["A"], ["B"]])

    def test_nested_dict(self):
        out = rg._coerce({"k": _FakeNode(["A"], {"x": 1})})
        self.assertEqual(out["k"]["properties"]["x"], 1)

    def test_record_to_dict_uses_coerce(self):
        rec = _FakeRecord({"n": _FakeNode(["Domain"], {"name": "x.com"})})
        out = rg._record_to_dict(rec)
        self.assertEqual(out["n"]["_kind"], "node")
        self.assertEqual(out["n"]["properties"]["name"], "x.com")


class TestEmit(unittest.TestCase):
    def test_plain_single_column(self):
        recs = [_FakeRecord({"name": "a.com"}), _FakeRecord({"name": "b.com"})]
        buf = io.StringIO()
        rg._emit(recs, "plain", buf)
        self.assertEqual(buf.getvalue(), "a.com\nb.com\n")

    def test_plain_multi_column_uses_tsv_to_stdout_header_to_stderr(self):
        recs = [_FakeRecord({"k": "a", "v": 1})]
        buf = io.StringIO()
        with mock.patch("sys.stderr", new_callable=io.StringIO) as fake_err:
            rg._emit(recs, "plain", buf)
        self.assertEqual(buf.getvalue(), "a\t1\n")
        self.assertIn("k\tv", fake_err.getvalue())

    def test_json_ndjson(self):
        recs = [_FakeRecord({"name": "a"}), _FakeRecord({"name": "b"})]
        buf = io.StringIO()
        rg._emit(recs, "json", buf)
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), {"name": "a"})

    def test_tsv_with_header(self):
        recs = [_FakeRecord({"k": "a", "v": "b"})]
        buf = io.StringIO()
        rg._emit(recs, "tsv", buf)
        self.assertEqual(buf.getvalue(), "k\tv\na\tb\n")

    def test_empty_records(self):
        buf = io.StringIO()
        rg._emit([], "plain", buf)
        self.assertEqual(buf.getvalue(), "")

    def test_plain_single_column_of_nodes_emits_all_props(self):
        # Output must reflect what the LLM was asked to RETURN. Whole nodes
        # render as `key=value key=value ...` — all attributes survive.
        recs = [
            _FakeRecord({"s": _FakeNode(["Subdomain"], {"name": "a.com", "status": "200"})}),
        ]
        buf = io.StringIO()
        rg._emit(recs, "plain", buf)
        line = buf.getvalue().rstrip("\n")
        self.assertIn("name=a.com", line)
        self.assertIn("status=200", line)

    def test_plain_scalar_is_unchanged(self):
        recs = [_FakeRecord({"name": "a.com"})]
        buf = io.StringIO()
        rg._emit(recs, "plain", buf)
        self.assertEqual(buf.getvalue(), "a.com\n")


class TestRequireTenant(unittest.TestCase):
    def test_exits_when_missing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as cm:
                rg._require_tenant()
            self.assertEqual(cm.exception.code, 2)

    def test_returns_pair_when_set(self):
        env = {"REDAMON_USER_ID": "U", "REDAMON_PROJECT_ID": "P"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(rg._require_tenant(), ("U", "P"))

    def test_blank_strings_treated_as_missing(self):
        env = {"REDAMON_USER_ID": "  ", "REDAMON_PROJECT_ID": "P"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit):
                rg._require_tenant()


class TestParser(unittest.TestCase):
    def setUp(self):
        self.p = rg.build_parser()

    def test_whoami(self):
        ns = self.p.parse_args(["whoami"])
        self.assertEqual(ns.cmd, "whoami")

    def test_ls_defaults(self):
        ns = self.p.parse_args(["ls", "Subdomain"])
        self.assertEqual(ns.node_type, "Subdomain")
        self.assertEqual(ns.attr, "name")
        self.assertEqual(ns.limit, 0)

    def test_ls_with_attr_and_limit(self):
        ns = self.p.parse_args(["ls", "Endpoint", "-a", "baseurl", "--limit", "50"])
        self.assertEqual(ns.attr, "baseurl")
        self.assertEqual(ns.limit, 50)

    def test_cypher(self):
        ns = self.p.parse_args(["cypher", "MATCH (n:Foo) RETURN n"])
        self.assertEqual(ns.query, "MATCH (n:Foo) RETURN n")

    def test_ask_with_show(self):
        ns = self.p.parse_args(["ask", "how many subs", "--show"])
        self.assertEqual(ns.question, ["how many subs"])
        self.assertTrue(ns.show)

    def test_ask_unquoted_multi_word(self):
        # Regression: `redagraph ask domain list` must not error.
        ns = self.p.parse_args(["ask", "domain", "list"])
        self.assertEqual(ns.question, ["domain", "list"])

    def test_format_choices(self):
        ns = self.p.parse_args(["--format", "json", "whoami"])
        self.assertEqual(ns.format, "json")
        with self.assertRaises(SystemExit):
            self.p.parse_args(["--format", "yaml", "whoami"])

    def test_output_flag(self):
        ns = self.p.parse_args(["-o", "/tmp/x.txt", "whoami"])
        self.assertEqual(ns.output, "/tmp/x.txt")


class TestExecuteGuards(unittest.TestCase):
    """_execute should reject writes and queries without labelled patterns."""

    def test_rejects_write(self):
        with self.assertRaises(SystemExit) as cm:
            rg._execute("CREATE (n:Foo)", "U", "P")
        self.assertEqual(cm.exception.code, 3)

    def test_rejects_unlabelled_query(self):
        with self.assertRaises(SystemExit) as cm:
            rg._execute("MATCH (n) RETURN n", "U", "P")
        self.assertEqual(cm.exception.code, 3)

    def test_unlabelled_allowed_when_require_labels_false(self):
        # When the caller takes responsibility for tenant scoping (e.g. cmd_types
        # builds an explicit WHERE), require_labels=False bypasses the guard.
        # Stop before the actual driver call.
        with mock.patch.object(rg, "_connect") as fake_connect:
            fake_session = mock.MagicMock()
            fake_session.__enter__.return_value.run.return_value = []
            fake_connect.return_value.session.return_value = fake_session
            rg._execute(
                "MATCH (n) WHERE n.user_id=$tenant_user_id RETURN n",
                "U", "P", require_labels=False,
            )
            # confirm the driver was actually opened (i.e. we got past guards)
            fake_connect.assert_called_once()


class TestCmdTypesIsTenantScoped(unittest.TestCase):
    """Regression: cmd_types must filter on user_id/project_id. Earlier draft did not."""

    def test_query_contains_explicit_tenant_where(self):
        captured = {}

        def fake_run(query, params=None):
            captured["q"] = query
            captured["p"] = params
            return []

        fake_session = mock.MagicMock()
        fake_session.__enter__.return_value.run.side_effect = fake_run

        with mock.patch.object(rg, "_connect") as fake_connect:
            fake_connect.return_value.session.return_value = fake_session
            args = types.SimpleNamespace(format="plain")
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                rg.cmd_types(args, "U", "P")

        self.assertIn("$tenant_user_id", captured["q"])
        self.assertIn("$tenant_project_id", captured["q"])
        self.assertEqual(captured["p"]["tenant_user_id"], "U")
        self.assertEqual(captured["p"]["tenant_project_id"], "P")


# =============================================================================
# terminal_server._read_init_frame
# =============================================================================
class _FakeWS:
    """Minimal websocket stub for _read_init_frame: queue of messages to recv()."""
    def __init__(self, messages, raise_timeout_after=False):
        self._messages = list(messages)
        self._raise_timeout_after = raise_timeout_after

    async def recv(self):
        if not self._messages:
            if self._raise_timeout_after:
                # Simulate hanging — wait_for will time out.
                await asyncio.sleep(10)
            raise RuntimeError("no more messages")
        return self._messages.pop(0)


class TestReadInitFrame(unittest.TestCase):
    def _run(self, ws, timeout=0.5):
        return asyncio.run(ts._read_init_frame(ws, timeout=timeout))

    def test_init_frame_parsed(self):
        ws = _FakeWS([json.dumps({"type": "init", "user_id": "U", "project_id": "P"})])
        env, replay = self._run(ws)
        self.assertEqual(env, {"REDAMON_USER_ID": "U", "REDAMON_PROJECT_ID": "P"})
        self.assertEqual(replay, b"")

    def test_init_with_blank_user_is_skipped(self):
        ws = _FakeWS([json.dumps({"type": "init", "user_id": "", "project_id": "P"})])
        env, replay = self._run(ws)
        self.assertNotIn("REDAMON_USER_ID", env)
        self.assertEqual(env.get("REDAMON_PROJECT_ID"), "P")
        self.assertEqual(replay, b"")

    def test_non_init_json_is_replayed(self):
        msg = json.dumps({"type": "resize", "rows": 24, "cols": 80})
        ws = _FakeWS([msg])
        env, replay = self._run(ws)
        self.assertEqual(env, {})
        self.assertEqual(replay, msg.encode("utf-8"))

    def test_raw_keystroke_is_replayed(self):
        ws = _FakeWS([b"ls\n"])
        env, replay = self._run(ws)
        self.assertEqual(env, {})
        self.assertEqual(replay, b"ls\n")

    def test_invalid_json_is_replayed_as_bytes(self):
        ws = _FakeWS(["not json at all"])
        env, replay = self._run(ws)
        self.assertEqual(env, {})
        self.assertEqual(replay, b"not json at all")

    def test_timeout_returns_empty(self):
        ws = _FakeWS([], raise_timeout_after=True)
        env, replay = self._run(ws, timeout=0.05)
        self.assertEqual(env, {})
        self.assertEqual(replay, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
