"""Tests for the agent startup guard.

Pins the contract: agent refuses to start if any worker-count env var
declares more than one worker, because the fireteam confirmation registry
is in-process and silently breaks under multi-worker deployments.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from startup_guard import check_single_worker, _WORKER_ENV_VARS  # noqa: E402


class StartupGuardTests(unittest.TestCase):

    def _clear_worker_env(self):
        """Return a dict that overrides all worker env vars to None (unset)."""
        return {var: "" for var in _WORKER_ENV_VARS}

    def test_no_env_vars_set_does_not_raise(self):
        # Clear by setting to empty string; os.environ.get returns "" which is
        # not None, so we also have to delete. Use a clean dict via clear=True.
        with patch.dict(os.environ, {}, clear=True):
            check_single_worker()  # should not raise

    def test_workers_eq_1_does_not_raise(self):
        with patch.dict(os.environ, {"WORKERS": "1"}, clear=True):
            check_single_worker()

    def test_workers_eq_4_raises_runtime_error(self):
        with patch.dict(os.environ, {"WORKERS": "4"}, clear=True):
            with self.assertRaises(RuntimeError) as cm:
                check_single_worker()
            msg = str(cm.exception)
            self.assertIn("FATAL", msg)
            self.assertIn("refusing to start", msg)
            self.assertIn("WORKERS=4", msg)
            self.assertIn("fireteam_confirmation_registry", msg)

    def test_each_worker_env_var_triggers_guard(self):
        """All four documented env var names should trip the guard."""
        for var in _WORKER_ENV_VARS:
            with self.subTest(var=var):
                with patch.dict(os.environ, {var: "2"}, clear=True):
                    with self.assertRaises(RuntimeError) as cm:
                        check_single_worker()
                    self.assertIn(f"{var}=2", str(cm.exception))

    def test_malformed_env_value_is_tolerated(self):
        """A typo like WORKERS=foo should NOT crash startup — treat as unset."""
        with patch.dict(os.environ, {"WORKERS": "not-a-number"}, clear=True):
            check_single_worker()  # should not raise

    def test_workers_eq_0_does_not_raise(self):
        """Edge case: 0 workers is nonsensical but not "more than one"."""
        with patch.dict(os.environ, {"WORKERS": "0"}, clear=True):
            check_single_worker()

    def test_workers_eq_minus_1_does_not_raise(self):
        """Negative values shouldn't trigger the >1 check (they're invalid in
        a different way, not our problem to surface)."""
        with patch.dict(os.environ, {"WORKERS": "-1"}, clear=True):
            check_single_worker()

    def test_first_offending_var_is_named_in_error(self):
        """When multiple offending vars are set, the error names the one
        that tripped the guard (deterministic by iteration order)."""
        with patch.dict(
            os.environ,
            {"UVICORN_WORKERS": "2", "WEB_CONCURRENCY": "3"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError) as cm:
                check_single_worker()
            # WORKERS is checked first, then UVICORN_WORKERS, then
            # WEB_CONCURRENCY — so UVICORN_WORKERS wins here.
            self.assertIn("UVICORN_WORKERS=2", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
