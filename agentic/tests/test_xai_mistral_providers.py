"""
Tests for xAI (Grok) and Mistral AI provider integration.

Covers:
  - parse_model_provider() prefix routing for xai/<model> and mistral/<model>
  - setup_llm() xAI + Mistral branches (kwarg validation + ChatOpenAI wiring)
  - fetch_xai_models() / fetch_mistral_models() success path, filter, fallback
  - fetch_all_models() aggregator wires "xai" and "mistral" providerTypes
  - Existing providers unaffected

Run with: python -m pytest tests/test_xai_mistral_providers.py -v
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from orchestrator_helpers.llm_setup import parse_model_provider, setup_llm
from orchestrator_helpers.model_providers import (
    fetch_xai_models,
    fetch_mistral_models,
    fetch_all_models,
    _XAI_FALLBACK_MODELS,
    _MISTRAL_FALLBACK_MODELS,
)


# ---------------------------------------------------------------------------
# Unit: parse_model_provider
# ---------------------------------------------------------------------------
class TestParseModelProviderXaiMistral(unittest.TestCase):
    def test_xai_prefix(self):
        self.assertEqual(
            parse_model_provider("xai/grok-3"),
            ("xai", "grok-3"),
        )
        self.assertEqual(
            parse_model_provider("xai/grok-3-fast"),
            ("xai", "grok-3-fast"),
        )
        self.assertEqual(
            parse_model_provider("xai/grok-3-mini"),
            ("xai", "grok-3-mini"),
        )
        self.assertEqual(
            parse_model_provider("xai/grok-2"),
            ("xai", "grok-2"),
        )

    def test_mistral_prefix(self):
        self.assertEqual(
            parse_model_provider("mistral/mistral-large-2411"),
            ("mistral", "mistral-large-2411"),
        )
        self.assertEqual(
            parse_model_provider("mistral/mistral-small-2501"),
            ("mistral", "mistral-small-2501"),
        )
        self.assertEqual(
            parse_model_provider("mistral/open-mistral-nemo"),
            ("mistral", "open-mistral-nemo"),
        )

    def test_xai_prefix_with_unknown_id_passes_through(self):
        self.assertEqual(
            parse_model_provider("xai/grok-9000-ultra"),
            ("xai", "grok-9000-ultra"),
        )

    def test_mistral_prefix_with_unknown_id_passes_through(self):
        self.assertEqual(
            parse_model_provider("mistral/mistral-future-3000"),
            ("mistral", "mistral-future-3000"),
        )

    def test_existing_prefixes_still_route(self):
        """Regression: ensure adding xai/mistral didn't break other prefixes."""
        self.assertEqual(
            parse_model_provider("custom/abc"),
            ("custom", "abc"),
        )
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-chat"),
            ("deepseek", "deepseek-chat"),
        )
        self.assertEqual(
            parse_model_provider("gemini/gemini-2.0-flash"),
            ("gemini", "gemini-2.0-flash"),
        )
        self.assertEqual(
            parse_model_provider("glm/glm-4"),
            ("glm", "glm-4"),
        )
        self.assertEqual(
            parse_model_provider("kimi/kimi-k1.5"),
            ("kimi", "kimi-k1.5"),
        )
        self.assertEqual(
            parse_model_provider("qwen/qwen-72b"),
            ("qwen", "qwen-72b"),
        )
        self.assertEqual(
            parse_model_provider("claude-opus-4-7"),
            ("anthropic", "claude-opus-4-7"),
        )
        self.assertEqual(
            parse_model_provider("gpt-4o"),
            ("openai", "gpt-4o"),
        )
        self.assertEqual(
            parse_model_provider("openrouter/anthropic/claude-sonnet-4"),
            ("openrouter", "anthropic/claude-sonnet-4"),
        )
        self.assertEqual(
            parse_model_provider("bedrock/anthropic.claude-v2"),
            ("bedrock", "anthropic.claude-v2"),
        )

    def test_bare_xai_id_routes_to_openai(self):
        """Without the xai/ prefix, the contract treats it as OpenAI."""
        self.assertEqual(
            parse_model_provider("grok-3"),
            ("openai", "grok-3"),
        )

    def test_bare_mistral_id_routes_to_openai(self):
        """Without the mistral/ prefix, the contract treats it as OpenAI."""
        self.assertEqual(
            parse_model_provider("mistral-large-2411"),
            ("openai", "mistral-large-2411"),
        )


# ---------------------------------------------------------------------------
# Unit: setup_llm (xAI branch)
# ---------------------------------------------------------------------------
class TestSetupLlmXai(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(ValueError) as ctx:
            setup_llm("xai/grok-3")
        self.assertIn("xAI (Grok) API key", str(ctx.exception))

    def test_empty_string_key_raises(self):
        with self.assertRaises(ValueError):
            setup_llm("xai/grok-3", xai_api_key="")

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_builds_chatopenai_with_correct_base_url(self, mock_chat):
        mock_chat.return_value = MagicMock()
        llm = setup_llm(
            "xai/grok-3-fast",
            xai_api_key="sk-xai-test",
        )
        mock_chat.assert_called_once()
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("model"), "grok-3-fast")
        self.assertEqual(kwargs.get("api_key"), "sk-xai-test")
        self.assertEqual(kwargs.get("base_url"), "https://api.x.ai/v1")
        self.assertEqual(kwargs.get("temperature"), 0)
        self.assertIs(llm, mock_chat.return_value)

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_other_provider_unaffected_when_xai_key_passed(self, mock_chat):
        """Regression: providing xai_api_key while resolving OpenAI should not pollute kwargs."""
        mock_chat.return_value = MagicMock()
        setup_llm(
            "gpt-4o-mini",
            openai_api_key="sk-openai",
            xai_api_key="sk-xai-unused",
        )
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("api_key"), "sk-openai")
        self.assertNotIn("base_url", kwargs)


# ---------------------------------------------------------------------------
# Unit: setup_llm (Mistral branch)
# ---------------------------------------------------------------------------
class TestSetupLlmMistral(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(ValueError) as ctx:
            setup_llm("mistral/mistral-large-2411")
        self.assertIn("Mistral AI API key", str(ctx.exception))

    def test_empty_string_key_raises(self):
        with self.assertRaises(ValueError):
            setup_llm("mistral/mistral-large-2411", mistral_api_key="")

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_builds_chatopenai_with_correct_base_url(self, mock_chat):
        mock_chat.return_value = MagicMock()
        llm = setup_llm(
            "mistral/mistral-large-2411",
            mistral_api_key="sk-mistral-test",
        )
        mock_chat.assert_called_once()
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("model"), "mistral-large-2411")
        self.assertEqual(kwargs.get("api_key"), "sk-mistral-test")
        self.assertEqual(kwargs.get("base_url"), "https://api.mistral.ai/v1")
        self.assertEqual(kwargs.get("temperature"), 0)
        self.assertIs(llm, mock_chat.return_value)

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_other_provider_unaffected_when_mistral_key_passed(self, mock_chat):
        """Regression: providing mistral_api_key while resolving OpenAI should not pollute kwargs."""
        mock_chat.return_value = MagicMock()
        setup_llm(
            "gpt-4o-mini",
            openai_api_key="sk-openai",
            mistral_api_key="sk-mistral-unused",
        )
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("api_key"), "sk-openai")
        self.assertNotIn("base_url", kwargs)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Unit: fetch_xai_models
# ---------------------------------------------------------------------------
class TestFetchXaiModels(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    def test_empty_key_returns_empty(self):
        result = _run(fetch_xai_models(api_key=""))
        self.assertEqual(result, [])

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_success_path_filters_and_prefixes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "data": [
                {"id": "grok-3"},
                {"id": "grok-3-fast"},
                {"id": "grok-3-mini"},
                {"id": "grok-2"},
                # Non-chat models should be included (generic passthrough)
                {"id": "grok-2-image"},
            ]
        })

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_xai_models(api_key="sk-test"))

        ids = [m["id"] for m in result]
        # All ids prefixed with xai/ for routing.
        self.assertTrue(all(i.startswith("xai/") for i in ids))
        # Expected models present.
        self.assertIn("xai/grok-3", ids)
        self.assertIn("xai/grok-3-fast", ids)
        self.assertIn("xai/grok-3-mini", ids)
        self.assertIn("xai/grok-2", ids)
        self.assertIn("xai/grok-2-image", ids)
        # Sort order is reverse-lexical (newest first).
        self.assertEqual(ids, sorted(ids, reverse=True))
        # Description tags every entry as xAI Grok.
        self.assertTrue(all(m["description"] == "xAI Grok" for m in result))

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_http_error_falls_back_to_hardcoded_list(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_xai_models(api_key="sk-test"))

        ids = [m["id"] for m in result]
        for mid, _name in _XAI_FALLBACK_MODELS:
            self.assertIn(f"xai/{mid}", ids)

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_empty_data_falls_back_to_hardcoded_list(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"data": []})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_xai_models(api_key="sk-test"))
        self.assertGreater(len(result), 0, "fallback list should populate")


# ---------------------------------------------------------------------------
# Unit: fetch_mistral_models
# ---------------------------------------------------------------------------
class TestFetchMistralModels(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    def test_empty_key_returns_empty(self):
        result = _run(fetch_mistral_models(api_key=""))
        self.assertEqual(result, [])

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_success_path_filters_and_prefixes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "data": [
                {"id": "mistral-large-2411"},
                {"id": "mistral-small-2501"},
                {"id": "open-mistral-nemo"},
                {"id": "open-codestral-mamba"},
                {"id": "mistral-moderation-2411"},
                # Non-chat embedding model — still included by generic passthrough
                {"id": "mistral-embed"},
            ]
        })

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_mistral_models(api_key="sk-test"))

        ids = [m["id"] for m in result]
        # All ids prefixed with mistral/ for routing.
        self.assertTrue(all(i.startswith("mistral/") for i in ids))
        # Expected models present.
        self.assertIn("mistral/mistral-large-2411", ids)
        self.assertIn("mistral/mistral-small-2501", ids)
        self.assertIn("mistral/open-mistral-nemo", ids)
        self.assertIn("mistral/open-codestral-mamba", ids)
        self.assertIn("mistral/mistral-moderation-2411", ids)
        self.assertIn("mistral/mistral-embed", ids)
        # Sort order is reverse-lexical.
        self.assertEqual(ids, sorted(ids, reverse=True))
        # Description tags every entry as Mistral AI.
        self.assertTrue(all(m["description"] == "Mistral AI" for m in result))

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_http_error_falls_back_to_hardcoded_list(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_mistral_models(api_key="sk-test"))

        ids = [m["id"] for m in result]
        for mid, _name in _MISTRAL_FALLBACK_MODELS:
            self.assertIn(f"mistral/{mid}", ids)

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_empty_data_falls_back_to_hardcoded_list(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"data": []})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_mistral_models(api_key="sk-test"))
        self.assertGreater(len(result), 0, "fallback list should populate")


# ---------------------------------------------------------------------------
# Integration: fetch_all_models aggregator wiring
# ---------------------------------------------------------------------------
class TestFetchAllModelsWiringXaiMistral(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    @patch("orchestrator_helpers.model_providers.fetch_xai_models", new_callable=AsyncMock)
    def test_xai_provider_type_is_dispatched(self, mock_fetch):
        mock_fetch.return_value = [
            {"id": "xai/grok-3", "name": "Grok 3",
             "context_length": None, "description": "xAI Grok"}
        ]

        providers = [{
            "id": "abc",
            "providerType": "xai",
            "name": "Sam's xAI",
            "apiKey": "sk-test",
        }]
        result = _run(fetch_all_models(providers=providers))

        self.assertIn("xAI Grok (Sam's xAI)", result)
        models = result["xAI Grok (Sam's xAI)"]
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "xai/grok-3")
        mock_fetch.assert_called_once_with(api_key="sk-test")

    @patch("orchestrator_helpers.model_providers.fetch_mistral_models", new_callable=AsyncMock)
    def test_mistral_provider_type_is_dispatched(self, mock_fetch):
        mock_fetch.return_value = [
            {"id": "mistral/mistral-large-2411", "name": "Mistral Large (2411)",
             "context_length": None, "description": "Mistral AI"}
        ]

        providers = [{
            "id": "def",
            "providerType": "mistral",
            "name": "Team Mistral",
            "apiKey": "sk-test",
        }]
        result = _run(fetch_all_models(providers=providers))

        self.assertIn("Mistral AI (Team Mistral)", result)
        models = result["Mistral AI (Team Mistral)"]
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "mistral/mistral-large-2411")
        mock_fetch.assert_called_once_with(api_key="sk-test")

    @patch("orchestrator_helpers.model_providers.fetch_xai_models", new_callable=AsyncMock)
    @patch("orchestrator_helpers.model_providers.fetch_mistral_models", new_callable=AsyncMock)
    def test_both_providers_can_coexist(self, mock_mistral, mock_xai):
        """Regression: xAI and Mistral dispatch should work simultaneously."""
        mock_xai.return_value = [
            {"id": "xai/grok-3", "name": "Grok 3",
             "context_length": None, "description": "xAI Grok"}
        ]
        mock_mistral.return_value = [
            {"id": "mistral/mistral-large-2411", "name": "Mistral Large (2411)",
             "context_length": None, "description": "Mistral AI"}
        ]

        providers = [
            {"id": "p1", "providerType": "xai", "name": "My xAI", "apiKey": "k1"},
            {"id": "p2", "providerType": "mistral", "name": "My Mistral", "apiKey": "k2"},
        ]
        result = _run(fetch_all_models(providers=providers))

        self.assertIn("xAI Grok (My xAI)", result)
        self.assertIn("Mistral AI (My Mistral)", result)
        self.assertEqual(len(result["xAI Grok (My xAI)"]), 1)
        self.assertEqual(len(result["Mistral AI (My Mistral)"]), 1)

    def test_unknown_provider_type_is_ignored(self):
        result = _run(fetch_all_models(providers=[{
            "providerType": "xai_typo",
            "id": "x",
            "name": "y",
        }]))
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
