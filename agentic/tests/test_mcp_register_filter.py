"""
Tests for PhaseAwareToolExecutor.register_mcp_tools(declared_tool_names=...)
filter behaviour: undeclared user-MCP tools are dropped, system MCP tools
always pass through, declared-but-not-live tools surface a warning.

Run with: python tests/test_mcp_register_filter.py
"""

import logging
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


def _make_tool(name, description="d"):
    t = MagicMock()
    t.name = name
    t.description = description
    return t


def _make_executor():
    """Build a PhaseAwareToolExecutor with stub deps."""
    from tools import PhaseAwareToolExecutor, MCPToolsManager
    mgr = MCPToolsManager({"fake": {"url": "http://x", "transport": "sse",
                                     "timeout": 60, "sse_read_timeout": 60}})
    return PhaseAwareToolExecutor(mgr, graph_tool=None)


class DeclaredToolNameFilterTests(unittest.TestCase):

    def test_no_filter_registers_all_tools(self):
        ex = _make_executor()
        tools = [_make_tool("tool_a"), _make_tool("tool_b")]
        ex.register_mcp_tools(tools)  # declared_tool_names not given
        self.assertIn("tool_a", ex._all_tools)
        self.assertIn("tool_b", ex._all_tools)
        self.assertEqual(ex._mcp_tool_names, {"tool_a", "tool_b"})

    def test_filter_drops_undeclared_user_tools(self):
        ex = _make_executor()
        tools = [_make_tool("declared_user"), _make_tool("undeclared_user")]
        ex.register_mcp_tools(tools, declared_tool_names={"declared_user"})
        self.assertIn("declared_user", ex._all_tools)
        self.assertNotIn("undeclared_user", ex._all_tools)

    def test_system_tools_always_pass_through_filter(self):
        from tools import SYSTEM_MCP_TOOL_NAMES
        any_system = next(iter(SYSTEM_MCP_TOOL_NAMES))

        ex = _make_executor()
        tools = [
            _make_tool(any_system),       # system, always allowed
            _make_tool("nonsense_user"),  # not declared, not system → dropped
        ]
        ex.register_mcp_tools(tools, declared_tool_names=set())  # empty user set
        self.assertIn(any_system, ex._all_tools)
        self.assertNotIn("nonsense_user", ex._all_tools)

    def test_subsequent_register_clears_previous_mcp_set(self):
        ex = _make_executor()
        ex.register_mcp_tools([_make_tool("x"), _make_tool("y")])
        self.assertEqual(ex._mcp_tool_names, {"x", "y"})

        ex.register_mcp_tools([_make_tool("z")])
        self.assertEqual(ex._mcp_tool_names, {"z"})
        self.assertNotIn("x", ex._all_tools)
        self.assertNotIn("y", ex._all_tools)

    def test_unnamed_tools_skipped(self):
        ex = _make_executor()
        unnamed = MagicMock()
        unnamed.name = None
        ex.register_mcp_tools([unnamed, _make_tool("named")])
        self.assertIn("named", ex._all_tools)
        self.assertEqual(len(ex._mcp_tool_names), 1)

    def test_declared_but_missing_logs_warning(self):
        ex = _make_executor()
        with self.assertLogs("tools", level="WARNING") as logs:
            ex.register_mcp_tools(
                [_make_tool("present")],
                declared_tool_names={"present", "absent"},
            )
        joined = "\n".join(logs.output)
        self.assertIn("absent", joined)
        self.assertIn("did not expose", joined)

    def test_no_warning_when_all_declared_present(self):
        ex = _make_executor()
        # No "did not expose" warning should fire when the set matches.
        # Capture WARNING logs but tolerate other unrelated warnings.
        logger_name = "tools"
        captured = []

        class _Capture(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())

        handler = _Capture(level=logging.WARNING)
        logging.getLogger(logger_name).addHandler(handler)
        try:
            ex.register_mcp_tools(
                [_make_tool("a"), _make_tool("b")],
                declared_tool_names={"a", "b"},
            )
        finally:
            logging.getLogger(logger_name).removeHandler(handler)

        self.assertFalse(
            any("did not expose" in m for m in captured),
            f"Unexpected 'did not expose' warning: {captured}",
        )


if __name__ == "__main__":
    unittest.main()
