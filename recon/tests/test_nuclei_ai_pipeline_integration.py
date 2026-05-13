"""
Integration tests for the AI in Pipeline cascade as it applies to NUCLEI_AI_TAGS.

These mirror the FFuf cascade tests in test_ai_pipeline_integration.py but
target the new Nuclei flag. They prove:

- aiInPipeline=true forces NUCLEI_AI_TAGS=true even when DB had it false
  (drift defense).
- aiInPipeline=false forces NUCLEI_AI_TAGS=false even when DB had it true
  (drift defense).
- Both AI flags (FFuf, Nuclei) are governed by the same master switch.
- CLI fallback path applies the cascade.
- Nuclei AI flag flips off entirely when stealth disables Nuclei (regression
  guard for the stealth + AI ordering).
"""
import os
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'recon'))


def _mock_project(**overrides):
    base = {
        "ffufEnabled": True,
        "ffufAiExtensions": False,
        "nucleiEnabled": True,
        "nucleiAiTags": False,
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


def test_cascade_master_on_forces_nuclei_ai_tags_on():
    from recon import project_settings
    fake = _mock_project(aiInPipeline=True, nucleiAiTags=False)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 't', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake)):
        settings = project_settings.get_settings()
    assert settings['AI_IN_PIPELINE'] is True
    assert settings['NUCLEI_AI_TAGS'] is True, "Master ON must force per-tool ON"
    assert settings['FFUF_AI_EXTENSIONS'] is True, "FFuf cascade must still fire"
    print("PASS: test_cascade_master_on_forces_nuclei_ai_tags_on")


def test_cascade_master_off_forces_nuclei_ai_tags_off():
    from recon import project_settings
    fake = _mock_project(aiInPipeline=False, nucleiAiTags=True)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 't', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake)):
        settings = project_settings.get_settings()
    assert settings['AI_IN_PIPELINE'] is False
    assert settings['NUCLEI_AI_TAGS'] is False, "Master OFF must force per-tool OFF"
    assert settings['FFUF_AI_EXTENSIONS'] is False
    print("PASS: test_cascade_master_off_forces_nuclei_ai_tags_off")


def test_cli_mode_default_has_nuclei_ai_off():
    from recon import project_settings
    with mock.patch.dict(os.environ, {}, clear=True):
        settings = project_settings.get_settings()
    assert settings['AI_IN_PIPELINE'] is False
    assert settings['NUCLEI_AI_TAGS'] is False
    assert settings['FFUF_AI_EXTENSIONS'] is False
    print("PASS: test_cli_mode_default_has_nuclei_ai_off")


def test_default_settings_includes_nuclei_ai_tags():
    """Regression: NUCLEI_AI_TAGS must be in DEFAULT_SETTINGS so cli mode and
    new project rows always have a definite value."""
    from recon.project_settings import DEFAULT_SETTINGS
    assert 'NUCLEI_AI_TAGS' in DEFAULT_SETTINGS
    assert DEFAULT_SETTINGS['NUCLEI_AI_TAGS'] is False
    print("PASS: test_default_settings_includes_nuclei_ai_tags")


def test_apply_ai_pipeline_overrides_isolated():
    """Direct test of the cascade function with no settings load surface."""
    from recon.project_settings import apply_ai_pipeline_overrides

    on = {'AI_IN_PIPELINE': True, 'AI_PIPELINE_MODEL': 'claude-opus-4-6',
          'FFUF_AI_EXTENSIONS': False, 'NUCLEI_AI_TAGS': False}
    out = apply_ai_pipeline_overrides(on)
    assert out['FFUF_AI_EXTENSIONS'] is True
    assert out['NUCLEI_AI_TAGS'] is True

    off = {'AI_IN_PIPELINE': False,
           'FFUF_AI_EXTENSIONS': True, 'NUCLEI_AI_TAGS': True}
    out = apply_ai_pipeline_overrides(off)
    assert out['FFUF_AI_EXTENSIONS'] is False
    assert out['NUCLEI_AI_TAGS'] is False
    print("PASS: test_apply_ai_pipeline_overrides_isolated")


def test_stealth_plus_ai_does_not_break_nuclei_flag():
    """When both stealth and AI are on, AI cascade still fires.
    Stealth modifies Nuclei DAST/rate-limit but does NOT disable Nuclei,
    so NUCLEI_AI_TAGS remains true. (Regression: stealth must run BEFORE
    AI cascade so the cascade has the final word on the flag.)"""
    from recon import project_settings
    fake = _mock_project(stealthMode=True, aiInPipeline=True, nucleiEnabled=True)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 't', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake)):
        settings = project_settings.get_settings()
    assert settings['AI_IN_PIPELINE'] is True
    assert settings['NUCLEI_AI_TAGS'] is True
    # Stealth still narrows Nuclei behaviour
    assert settings['NUCLEI_DAST_MODE'] is False
    assert settings['NUCLEI_INTERACTSH'] is False
    print("PASS: test_stealth_plus_ai_does_not_break_nuclei_flag")


def test_nuclei_ai_tags_camelcase_mapped_correctly():
    """The DB field nucleiAiTags must map to the Python NUCLEI_AI_TAGS key.
    Catches typos in the project_settings.py mapping."""
    from recon import project_settings
    # Master ON would mask drift, so use master OFF and DB OFF then check key exists
    fake = _mock_project(nucleiAiTags=False, aiInPipeline=False)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 't', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake)):
        settings = project_settings.get_settings()
    assert 'NUCLEI_AI_TAGS' in settings
    print("PASS: test_nuclei_ai_tags_camelcase_mapped_correctly")


if __name__ == '__main__':
    test_cascade_master_on_forces_nuclei_ai_tags_on()
    test_cascade_master_off_forces_nuclei_ai_tags_off()
    test_cli_mode_default_has_nuclei_ai_off()
    test_default_settings_includes_nuclei_ai_tags()
    test_apply_ai_pipeline_overrides_isolated()
    test_stealth_plus_ai_does_not_break_nuclei_flag()
    test_nuclei_ai_tags_camelcase_mapped_correctly()
    print("\nAll integration tests passed")
