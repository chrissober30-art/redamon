"""Tests for build_kali_install_prompt() in prompts/base.py."""

from unittest.mock import patch

import pytest


# The function under test imports `get_setting` at call time via
# `from project_settings import get_setting`, so we patch at that path.
SETTING_PATH = "project_settings.get_setting"


def _mock_settings(overrides: dict):
    """Return a side_effect for get_setting that uses *overrides* with defaults."""
    defaults = {
        "KALI_INSTALL_ENABLED": False,
        "KALI_INSTALL_ALLOWED_PACKAGES": "",
        "KALI_INSTALL_FORBIDDEN_PACKAGES": "",
    }

    def _get(key, default=None):
        if key in overrides:
            return overrides[key]
        if key in defaults:
            return defaults[key]
        return default

    return _get


# ---------------------------------------------------------------------------
# Toggle OFF (disabled)
# ---------------------------------------------------------------------------

class TestKaliInstallDisabled:
    """When KALI_INSTALL_ENABLED is False the prompt must forbid installation."""

    @patch(SETTING_PATH)
    def test_disabled_contains_disabled_header(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": False})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "DISABLED" in result

    @patch(SETTING_PATH)
    def test_disabled_forbids_pip(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": False})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "DO NOT install any packages" in result

    @patch(SETTING_PATH)
    def test_disabled_forbids_apt(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": False})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "apt install" in result

    @patch(SETTING_PATH)
    def test_disabled_no_whitelist_or_blacklist(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": False})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "whitelist" not in result
        assert "blacklist" not in result


# ---------------------------------------------------------------------------
# Toggle ON — no lists
# ---------------------------------------------------------------------------

class TestKaliInstallEnabledNoLists:
    """Enabled with empty whitelist/blacklist → unrestricted installation."""

    @patch(SETTING_PATH)
    def test_enabled_contains_allowed_header(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": True})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "ALLOWED" in result

    @patch(SETTING_PATH)
    def test_enabled_mentions_pip(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": True})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "pip install" in result

    @patch(SETTING_PATH)
    def test_enabled_mentions_ephemeral(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": True})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "ephemeral" in result

    @patch(SETTING_PATH)
    def test_enabled_no_whitelist_blacklist_sections(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": True})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "whitelist" not in result
        assert "blacklist" not in result


# ---------------------------------------------------------------------------
# Toggle ON + whitelist only
# ---------------------------------------------------------------------------

class TestKaliInstallWhitelist:
    """Enabled with authorized packages whitelist."""

    @patch(SETTING_PATH)
    def test_whitelist_packages_appear(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_ALLOWED_PACKAGES": "exploit-db, nikto, wpscan",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "exploit-db, nikto, wpscan" in result

    @patch(SETTING_PATH)
    def test_whitelist_has_restriction_note(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_ALLOWED_PACKAGES": "exploit-db",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "Do NOT install any package not in this list" in result

    @patch(SETTING_PATH)
    def test_whitelist_no_blacklist_section(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_ALLOWED_PACKAGES": "exploit-db",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "blacklist" not in result


# ---------------------------------------------------------------------------
# Toggle ON + blacklist only
# ---------------------------------------------------------------------------

class TestKaliInstallBlacklist:
    """Enabled with forbidden packages blacklist."""

    @patch(SETTING_PATH)
    def test_blacklist_packages_appear(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_FORBIDDEN_PACKAGES": "metasploit-framework, cobalt-strike",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "metasploit-framework, cobalt-strike" in result

    @patch(SETTING_PATH)
    def test_blacklist_has_never_install_note(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_FORBIDDEN_PACKAGES": "metasploit-framework",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "NEVER install these" in result

    @patch(SETTING_PATH)
    def test_blacklist_no_whitelist_section(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_FORBIDDEN_PACKAGES": "metasploit-framework",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "whitelist" not in result


# ---------------------------------------------------------------------------
# Toggle ON + both lists
# ---------------------------------------------------------------------------

class TestKaliInstallBothLists:
    """Enabled with both whitelist and blacklist."""

    @patch(SETTING_PATH)
    def test_both_lists_present(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_ALLOWED_PACKAGES": "nikto, wpscan",
            "KALI_INSTALL_FORBIDDEN_PACKAGES": "cobalt-strike",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "whitelist" in result
        assert "blacklist" in result
        assert "nikto, wpscan" in result
        assert "cobalt-strike" in result


# ---------------------------------------------------------------------------
# Edge cases — whitespace handling
# ---------------------------------------------------------------------------

class TestKaliInstallEdgeCases:
    """Whitespace-only lists should be treated as empty."""

    @patch(SETTING_PATH)
    def test_whitespace_only_allowed_treated_as_empty(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_ALLOWED_PACKAGES": "   ",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "whitelist" not in result

    @patch(SETTING_PATH)
    def test_whitespace_only_forbidden_treated_as_empty(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_FORBIDDEN_PACKAGES": "  \t  ",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "blacklist" not in result

    @patch(SETTING_PATH)
    def test_allowed_packages_are_stripped(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_ALLOWED_PACKAGES": "  nikto, wpscan  ",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "`nikto, wpscan`" in result  # stripped, no leading/trailing spaces

    @patch(SETTING_PATH)
    def test_forbidden_packages_are_stripped(self, mock_get):
        mock_get.side_effect = _mock_settings({
            "KALI_INSTALL_ENABLED": True,
            "KALI_INSTALL_FORBIDDEN_PACKAGES": "  cobalt-strike  ",
        })
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert "`cobalt-strike`" in result


# ---------------------------------------------------------------------------
# Return type consistency
# ---------------------------------------------------------------------------

class TestKaliInstallReturnType:
    """build_kali_install_prompt must always return a non-empty string."""

    @patch(SETTING_PATH)
    def test_disabled_returns_string(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": False})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert isinstance(result, str)
        assert len(result) > 0

    @patch(SETTING_PATH)
    def test_enabled_returns_string(self, mock_get):
        mock_get.side_effect = _mock_settings({"KALI_INSTALL_ENABLED": True})
        from prompts.base import build_kali_install_prompt

        result = build_kali_install_prompt()
        assert isinstance(result, str)
        assert len(result) > 0
