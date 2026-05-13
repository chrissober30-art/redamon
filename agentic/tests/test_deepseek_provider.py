"""
Tests for DeepSeek provider integration.

Covers:
  - parse_model_provider() prefix routing for deepseek/<model>
  - setup_llm() deepseek branch (kwarg validation + ChatOpenAI wiring)
  - fetch_deepseek_models() success path, filter, fallback
  - fetch_all_models() aggregator wires "deepseek" providerType
  - Existing providers (openai/anthropic/openrouter/bedrock/custom) unaffected

Run with: python -m pytest tests/test_deepseek_provider.py -v
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
    fetch_deepseek_models,
    fetch_all_models,
    _DEEPSEEK_FALLBACK_MODELS,
)


# ---------------------------------------------------------------------------
# Unit: parse_model_provider
# ---------------------------------------------------------------------------
class TestParseModelProvider(unittest.TestCase):
    def test_deepseek_prefix(self):
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-v4-pro"),
            ("deepseek", "deepseek-v4-pro"),
        )
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-v4-flash"),
            ("deepseek", "deepseek-v4-flash"),
        )
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-chat"),
            ("deepseek", "deepseek-chat"),
        )
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-reasoner"),
            ("deepseek", "deepseek-reasoner"),
        )

    def test_deepseek_prefix_with_unknown_id_passes_through(self):
        # Whatever follows the prefix is forwarded to the upstream API verbatim.
        self.assertEqual(
            parse_model_provider("deepseek/deepseek-future-9000"),
            ("deepseek", "deepseek-future-9000"),
        )

    def test_existing_prefixes_still_route(self):
        # Regression: ensure adding deepseek didn't break other prefixes.
        self.assertEqual(
            parse_model_provider("custom/abc"),
            ("custom", "abc"),
        )
        self.assertEqual(
            parse_model_provider("openrouter/x/y"),
            ("openrouter", "x/y"),
        )
        self.assertEqual(
            parse_model_provider("bedrock/anthropic.claude-v2"),
            ("bedrock", "anthropic.claude-v2"),
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
            parse_model_provider("openai_compat/foo"),
            ("openai_compat", "foo"),
        )

    def test_bare_deepseek_id_routes_to_openai(self):
        # Without the deepseek/ prefix the contract treats it as OpenAI.
        # This is the documented behavior — DeepSeek always needs the prefix.
        self.assertEqual(
            parse_model_provider("deepseek-chat"),
            ("openai", "deepseek-chat"),
        )


# ---------------------------------------------------------------------------
# Unit: setup_llm (deepseek branch)
# ---------------------------------------------------------------------------
class TestSetupLlmDeepseek(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(ValueError) as ctx:
            setup_llm("deepseek/deepseek-v4-pro")
        self.assertIn("DeepSeek API key", str(ctx.exception))

    def test_empty_string_key_raises(self):
        with self.assertRaises(ValueError):
            setup_llm("deepseek/deepseek-v4-pro", deepseek_api_key="")

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_builds_chatopenai_with_correct_base_url(self, mock_chat):
        mock_chat.return_value = MagicMock()
        llm = setup_llm(
            "deepseek/deepseek-v4-flash",
            deepseek_api_key="sk-test-key",
        )
        # Verify ChatOpenAI was instantiated with deepseek base_url and the
        # api_model (without prefix) — not the full prefixed name.
        mock_chat.assert_called_once()
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("model"), "deepseek-v4-flash")
        self.assertEqual(kwargs.get("api_key"), "sk-test-key")
        self.assertEqual(kwargs.get("base_url"), "https://api.deepseek.com/v1")
        self.assertEqual(kwargs.get("temperature"), 0)
        self.assertIs(llm, mock_chat.return_value)

    @patch("orchestrator_helpers.llm_setup.ChatOpenAI")
    def test_other_provider_unaffected_when_deepseek_key_passed(self, mock_chat):
        # Regression: providing deepseek_api_key while resolving an OpenAI
        # model should not divert routing or pollute kwargs.
        mock_chat.return_value = MagicMock()
        setup_llm(
            "gpt-4o-mini",
            openai_api_key="sk-openai",
            deepseek_api_key="sk-deepseek-unused",
        )
        kwargs = mock_chat.call_args.kwargs
        self.assertEqual(kwargs.get("api_key"), "sk-openai")
        # No base_url override for plain openai (OpenAI default endpoint).
        self.assertNotIn("base_url", kwargs)


# ---------------------------------------------------------------------------
# Unit: fetch_deepseek_models
# ---------------------------------------------------------------------------
def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestFetchDeepseekModels(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    def test_empty_key_returns_empty(self):
        result = _run(fetch_deepseek_models(api_key=""))
        self.assertEqual(result, [])

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_success_path_filters_and_prefixes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "data": [
                {"id": "deepseek-v4-pro"},
                {"id": "deepseek-v4-flash"},
                {"id": "deepseek-chat"},
                # Non-deepseek IDs must be filtered out.
                {"id": "embedding-large"},
                {"id": "whisper-large"},
            ]
        })

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_deepseek_models(api_key="sk-test"))

        ids = [m["id"] for m in result]
        # All ids prefixed with deepseek/ for routing.
        self.assertTrue(all(i.startswith("deepseek/") for i in ids))
        # Non-deepseek-* ids excluded.
        self.assertNotIn("deepseek/embedding-large", ids)
        self.assertNotIn("deepseek/whisper-large", ids)
        # Expected models present.
        self.assertIn("deepseek/deepseek-v4-pro", ids)
        self.assertIn("deepseek/deepseek-v4-flash", ids)
        self.assertIn("deepseek/deepseek-chat", ids)
        # Sort order is reverse-lexical (newest first by version string).
        self.assertEqual(ids, sorted(ids, reverse=True))
        # Description tags every entry as DeepSeek.
        self.assertTrue(all(m["description"] == "DeepSeek" for m in result))

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_http_error_falls_back_to_hardcoded_list(self, mock_client_cls):
        # When /v1/models is unreachable, return curated fallback rather than [].
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_deepseek_models(api_key="sk-test"))

        ids = [m["id"] for m in result]
        # Every fallback model must appear in the result.
        for mid, _name in _DEEPSEEK_FALLBACK_MODELS:
            self.assertIn(f"deepseek/{mid}", ids)

    @patch("orchestrator_helpers.model_providers.httpx.AsyncClient")
    def test_empty_data_falls_back_to_hardcoded_list(self, mock_client_cls):
        # If /v1/models returns successfully but with no data field → fallback.
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"data": []})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client_cls.return_value.__aexit__.return_value = None

        result = _run(fetch_deepseek_models(api_key="sk-test"))
        self.assertGreater(len(result), 0, "fallback list should populate")


# ---------------------------------------------------------------------------
# Integration: fetch_all_models aggregator wiring
# ---------------------------------------------------------------------------
class TestFetchAllModelsWiring(unittest.TestCase):
    def setUp(self):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

    @patch("orchestrator_helpers.model_providers.fetch_deepseek_models", new_callable=AsyncMock)
    def test_deepseek_provider_type_is_dispatched(self, mock_fetch):
        mock_fetch.return_value = [
            {"id": "deepseek/deepseek-v4-pro", "name": "v4 pro",
             "context_length": None, "description": "DeepSeek"}
        ]

        providers = [{
            "id": "abc",
            "providerType": "deepseek",
            "name": "Sam's DeepSeek",
            "apiKey": "sk-test",
        }]
        result = _run(fetch_all_models(providers=providers))

        # Aggregator key follows existing convention: "<Friendly> (<name>)".
        self.assertIn("DeepSeek (Sam's DeepSeek)", result)
        models = result["DeepSeek (Sam's DeepSeek)"]
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "deepseek/deepseek-v4-pro")
        mock_fetch.assert_called_once_with(api_key="sk-test")

    def test_unknown_provider_type_is_ignored(self):
        # Regression: an unknown providerType (e.g. typo) returns empty,
        # not a crash.
        result = _run(fetch_all_models(providers=[{
            "providerType": "openai_compatible_typo",
            "id": "x",
            "name": "y",
        }]))
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
