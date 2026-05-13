"""
Integration tests for the AI in Pipeline cascade end-to-end.

These tests exercise the full settings load path -- not just the
apply_ai_pipeline_overrides() function in isolation. They mock the webapp
API and ensure that get_settings() correctly applies stealth and AI cascade
overrides in the right order.
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
# Also add the recon dir so `from helpers.key_rotation import KeyRotator`
# (used inside fetch_project_settings) resolves. This mirrors how the recon
# container runs scripts with cwd=/app/recon.
sys.path.insert(0, str(PROJECT_ROOT / 'recon'))


def _mock_project(**overrides):
    """Build a minimal fake project dict that satisfies fetch_project_settings."""
    base = {
        "ffufEnabled": True,
        "ffufAiExtensions": False,
        "stealthMode": False,
        "aiInPipeline": False,
        "aiPipelineModel": "claude-opus-4-6",
    }
    base.update(overrides)
    return base


def _mock_response(project_dict):
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.json.return_value = project_dict
    resp.raise_for_status = mock.MagicMock()
    return resp


def test_get_settings_applies_ai_cascade_when_master_on():
    """get_settings() with aiInPipeline=true must end with FFUF_AI_EXTENSIONS=true,
    even if the DB row had ffufAiExtensions=false (drift defense)."""
    import os
    from recon import project_settings

    fake_project = _mock_project(aiInPipeline=True, ffufAiExtensions=False)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 'test', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake_project)):
        settings = project_settings.get_settings()

    assert settings['AI_IN_PIPELINE'] is True
    assert settings['FFUF_AI_EXTENSIONS'] is True, \
        "Cascade should force per-tool flag ON when master is ON"
    assert settings['AI_PIPELINE_MODEL'] == 'claude-opus-4-6'
    print("PASS: test_get_settings_applies_ai_cascade_when_master_on")


def test_get_settings_strips_per_tool_when_master_off():
    """get_settings() with aiInPipeline=false must end with FFUF_AI_EXTENSIONS=false,
    even if the DB has ffufAiExtensions=true (drift defense)."""
    import os
    from recon import project_settings

    fake_project = _mock_project(aiInPipeline=False, ffufAiExtensions=True)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 'test', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake_project)):
        settings = project_settings.get_settings()

    assert settings['AI_IN_PIPELINE'] is False
    assert settings['FFUF_AI_EXTENSIONS'] is False, \
        "Cascade should force per-tool flag OFF when master is OFF"
    print("PASS: test_get_settings_strips_per_tool_when_master_off")


def test_stealth_runs_before_ai_cascade():
    """When stealth and AI are both on, stealth wins on FFUF_ENABLED.
    AI cascade still runs and would set FFUF_AI_EXTENSIONS=true, but FFuf
    is disabled so AI extensions are moot. No crash, no contradiction."""
    import os
    from recon import project_settings

    fake_project = _mock_project(stealthMode=True, aiInPipeline=True, ffufEnabled=True)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 'test', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake_project)):
        settings = project_settings.get_settings()

    # Stealth wins: FFuf entirely disabled
    assert settings['FFUF_ENABLED'] is False
    # AI cascade still ran (master flag is true)
    assert settings['AI_IN_PIPELINE'] is True
    assert settings['FFUF_AI_EXTENSIONS'] is True
    # The combination is harmless: AI flag is set but FFuf will not run
    print("PASS: test_stealth_runs_before_ai_cascade")


def test_get_settings_cli_mode_applies_cascade():
    """When no PROJECT_ID/WEBAPP_API_URL env vars (CLI mode), get_settings()
    falls back to DEFAULT_SETTINGS but still applies the cascade."""
    import os
    from recon import project_settings

    # Clear env so CLI fallback path runs; cascade should still execute
    with mock.patch.dict(os.environ, {}, clear=True):
        settings = project_settings.get_settings()

    # Defaults: AI off, so per-tool flag must be OFF too
    assert settings['AI_IN_PIPELINE'] is False
    assert settings['FFUF_AI_EXTENSIONS'] is False
    assert settings['STEALTH_MODE'] is False
    print("PASS: test_get_settings_cli_mode_applies_cascade")


def test_ai_off_path_makes_no_llm_calls():
    """Regression: when FFUF_AI_EXTENSIONS=False, the ai_planner module
    is never imported and no HTTP calls are made. We can't observe that
    directly here without spinning the full pipeline, but we can prove the
    settings cascade leaves the per-tool flag OFF for a default project."""
    import os
    from recon import project_settings

    fake_project = _mock_project()  # all defaults, AI off
    with mock.patch.dict(os.environ, {'PROJECT_ID': 'test', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake_project)):
        settings = project_settings.get_settings()

    assert settings['FFUF_AI_EXTENSIONS'] is False
    print("PASS: test_ai_off_path_makes_no_llm_calls")


if __name__ == '__main__':
    test_get_settings_applies_ai_cascade_when_master_on()
    test_get_settings_strips_per_tool_when_master_off()
    test_stealth_runs_before_ai_cascade()
    test_get_settings_cli_mode_applies_cascade()
    test_ai_off_path_makes_no_llm_calls()
    print("\nAll integration tests passed")
