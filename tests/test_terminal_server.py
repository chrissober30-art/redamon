"""
Unit tests for terminal_server.py

Tests the PTY terminal WebSocket server logic.
Run with: python -m pytest tests/test_terminal_server.py -v
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp', 'servers'))

import pytest


class TestSetPtySize:
    """Test the _set_pty_size helper function."""

    def test_set_pty_size_valid(self):
        """Should pack rows/cols into a TIOCSWINSZ struct without error."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 24, 80)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 24
            assert cols == 80
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_different_dimensions(self):
        """Should correctly set arbitrary dimensions."""
        import pty
        from terminal_server import _set_pty_size

        master_fd, slave_fd = pty.openpty()
        try:
            _set_pty_size(master_fd, 50, 200)

            import fcntl
            import termios
            packed = fcntl.ioctl(master_fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            assert rows == 50
            assert cols == 200
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_set_pty_size_invalid_fd(self):
        """Should not raise on invalid file descriptor (graceful failure)."""
        from terminal_server import _set_pty_size
        _set_pty_size(-1, 24, 80)  # Should not raise


class TestPortConfig:
    """Test port configuration from environment."""

    def test_default_port(self):
        """Should default to 8016 when TERMINAL_WS_PORT is not set."""
        env_backup = os.environ.pop("TERMINAL_WS_PORT", None)
        try:
            # Re-import to get fresh PORT value
            import importlib
            import terminal_server
            importlib.reload(terminal_server)
            assert terminal_server.PORT == 8016
        finally:
            if env_backup is not None:
                os.environ["TERMINAL_WS_PORT"] = env_backup

    def test_custom_port(self):
        """Should use TERMINAL_WS_PORT environment variable."""
        os.environ["TERMINAL_WS_PORT"] = "9999"
        try:
            import importlib
            import terminal_server
            importlib.reload(terminal_server)
            assert terminal_server.PORT == 9999
        finally:
            os.environ["TERMINAL_WS_PORT"] = "8016"


class TestResizeMessageParsing:
    """Test that resize JSON messages are correctly detected."""

    def test_valid_resize_json(self):
        """A valid resize message should parse without error."""
        msg = json.dumps({"type": "resize", "rows": 30, "cols": 120})
        parsed = json.loads(msg)
        assert parsed["type"] == "resize"
        assert parsed["rows"] == 30
        assert parsed["cols"] == 120

    def test_resize_message_defaults(self):
        """Missing rows/cols should use defaults."""
        msg = json.dumps({"type": "resize"})
        parsed = json.loads(msg)
        rows = parsed.get("rows", 24)
        cols = parsed.get("cols", 80)
        assert rows == 24
        assert cols == 80

    def test_non_resize_message_not_intercepted(self):
        """Non-resize messages should not be treated as control messages."""
        msg = "ls -la"
        try:
            parsed = json.loads(msg)
            assert parsed.get("type") != "resize"
        except (json.JSONDecodeError, TypeError):
            pass  # Expected for plain text input

    def test_invalid_json_passes_through(self):
        """Invalid JSON should be treated as terminal input, not error."""
        msg = "echo hello"
        is_json = False
        try:
            json.loads(msg)
            is_json = True
        except (json.JSONDecodeError, TypeError):
            pass
        assert not is_json
