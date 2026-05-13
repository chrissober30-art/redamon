"""
Tests for the project_settings.py read-time MCP phase fallback added by the
MCP plugin feature: is_tool_allowed_in_phase() and get_allowed_tools_for_phase()
must consult the manifest when a tool isn't in TOOL_PHASE_MAP.

Run with: python tests/test_mcp_project_settings.py
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

import mcp_registry as reg  # noqa: E402
from project_settings import (  # noqa: E402
    is_tool_allowed_in_phase,
    get_allowed_tools_for_phase,
)


def _fake_get_setting(phase_map):
    """Return a fake get_setting that returns phase_map for TOOL_PHASE_MAP."""
    def _impl(key, default=None):
        if key == 'TOOL_PHASE_MAP':
            return phase_map
        return default
    return _impl


def _user_server(tool_name, tool_phases=None, server_phases=None):
    return reg.MCPServer.model_validate({
        "id": "user_test",
        "name": "user test",
        "transport": "streamable_http",
        "url": "http://x/mcp",
        "default_phases": server_phases or list(reg.ALL_PHASES),
        "tools": [{
            "name": tool_name,
            "purpose": "x",
            "when_to_use": "y",
            "args_format": '"a":"b"',
            "description": "z",
            **({"default_phases": tool_phases} if tool_phases else {}),
        }],
    })


class IsToolAllowedInPhaseFallbackTests(unittest.TestCase):

    def setUp(self):
        reg.set_current([])

    def tearDown(self):
        reg.set_current([])

    def test_explicit_map_entry_wins_over_manifest(self):
        # User MCP tool 'foo' — manifest says only [informational].
        # Project map says [exploitation]. Project should win.
        reg.set_current([_user_server("foo", tool_phases=["informational"])])

        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({"foo": ["exploitation"]})):
            self.assertTrue(is_tool_allowed_in_phase("foo", "exploitation"))
            self.assertFalse(is_tool_allowed_in_phase("foo", "informational"))

    def test_manifest_used_when_no_map_entry(self):
        reg.set_current([_user_server("foo", tool_phases=["informational"])])

        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({})):
            self.assertTrue(is_tool_allowed_in_phase("foo", "informational"))
            self.assertFalse(is_tool_allowed_in_phase("foo", "exploitation"))

    def test_unknown_tool_returns_false(self):
        reg.set_current([])
        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({})):
            self.assertFalse(is_tool_allowed_in_phase("unknown_tool", "informational"))

    def test_disabled_server_tools_treated_as_unknown(self):
        # A user MCP that's been disabled should not provide phase fallbacks.
        srv = reg.MCPServer.model_validate({
            "id": "off",
            "name": "off",
            "enabled": False,
            "transport": "streamable_http",
            "url": "http://x/mcp",
            "tools": [{
                "name": "off_tool", "purpose": "x", "when_to_use": "y",
                "args_format": '"a":"b"', "description": "z",
            }],
        })
        reg.set_current([srv])
        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({})):
            # Tool isn't in manifest_tool_names() because the server is disabled.
            self.assertFalse(is_tool_allowed_in_phase("off_tool", "informational"))

    def test_explicit_empty_phase_list_blocks_tool(self):
        # User uncheck-all-phases on a manifest tool: project map says [].
        # Should return False (project override wins, even when empty).
        reg.set_current([_user_server("foo", server_phases=list(reg.ALL_PHASES))])

        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({"foo": []})):
            self.assertFalse(is_tool_allowed_in_phase("foo", "informational"))
            self.assertFalse(is_tool_allowed_in_phase("foo", "exploitation"))


class GetAllowedToolsForPhaseTests(unittest.TestCase):

    def setUp(self):
        reg.set_current([])

    def tearDown(self):
        reg.set_current([])

    def test_unions_map_and_manifest(self):
        reg.set_current([_user_server("manifest_tool", tool_phases=["informational"])])
        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({
                       "builtin_tool": ["informational", "exploitation"],
                   })):
            allowed = set(get_allowed_tools_for_phase("informational"))
            self.assertIn("builtin_tool", allowed)
            self.assertIn("manifest_tool", allowed)

    def test_excludes_manifest_tool_when_phase_does_not_match(self):
        reg.set_current([_user_server("manifest_tool", tool_phases=["informational"])])
        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({})):
            allowed = set(get_allowed_tools_for_phase("exploitation"))
            self.assertNotIn("manifest_tool", allowed)

    def test_project_override_for_manifest_tool_takes_precedence(self):
        # Manifest says informational, project override says exploitation.
        # In phase=exploitation, tool should appear; in phase=informational, it should NOT.
        reg.set_current([_user_server("manifest_tool", tool_phases=["informational"])])
        with patch("project_settings.get_setting",
                   side_effect=_fake_get_setting({"manifest_tool": ["exploitation"]})):
            self.assertIn("manifest_tool", get_allowed_tools_for_phase("exploitation"))
            self.assertNotIn("manifest_tool", get_allowed_tools_for_phase("informational"))


if __name__ == "__main__":
    unittest.main()
