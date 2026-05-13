"""End-to-end smoke proof for GLM / Kimi / Qwen providers using a mocked
upstream. Run inside the agent container:

    python /app/tests/test_new_providers_e2e.py

Mocks both /models (used by the model-list aggregator) and /chat/completions
(used by ChatOpenAI.ainvoke) so we exercise the full pipeline:
parse_model_provider → fetch_<provider>_models → setup_llm → ainvoke
without touching any real vendor.
"""
from __future__ import annotations

import asyncio
import sys

import httpx

# ---------------------------------------------------------------------------
# Mock httpx.AsyncClient — intercepts ALL outbound calls
# ---------------------------------------------------------------------------
_OriginalAsyncClient = httpx.AsyncClient

CALL_LOG: list[tuple[str, str, str]] = []  # (method, url, auth_header)


def _canned_body(method: str, url: str) -> tuple[int, dict]:
    if method == "GET" and url.endswith("/models"):
        return 200, {
            "data": [
                {"id": "mock-flash", "object": "model"},
                {"id": "mock-pro-8k", "object": "model"},
                {"id": "mock-turbo", "object": "model"},
            ],
        }
    if method == "POST" and url.endswith("/chat/completions"):
        return 200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": 0,
            "model": "mock-flash",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "MOCK_REPLY_OK"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
    return 404, {"error": "not_found"}


class MockedAsyncClient(_OriginalAsyncClient):
    async def get(self, url, *args, **kwargs):
        headers = kwargs.get("headers", {}) or {}
        url_s = str(url)
        CALL_LOG.append(("GET", url_s, headers.get("Authorization", "")))
        request = httpx.Request("GET", url_s, headers=headers)
        status, body = _canned_body("GET", url_s)
        return httpx.Response(status, request=request,
                              headers={"content-type": "application/json"}, json=body)

    async def post(self, url, *args, **kwargs):
        headers = kwargs.get("headers", {}) or {}
        url_s = str(url)
        CALL_LOG.append(("POST", url_s, headers.get("Authorization", "")))
        request = httpx.Request("POST", url_s, headers=headers, json=kwargs.get("json"))
        status, body = _canned_body("POST", url_s)
        return httpx.Response(status, request=request,
                              headers={"content-type": "application/json"}, json=body)

    async def send(self, request, *args, **kwargs):
        url_s = str(request.url)
        CALL_LOG.append((request.method, url_s, request.headers.get("authorization", "")))
        status, body = _canned_body(request.method, url_s)
        # Attach the ORIGINAL request — openai SDK reads back X-Stainless-Raw-Response
        return httpx.Response(status, request=request,
                              headers={"content-type": "application/json"}, json=body)


httpx.AsyncClient = MockedAsyncClient  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Now the proof
# ---------------------------------------------------------------------------
sys.path.insert(0, "/app")

from orchestrator_helpers.llm_setup import parse_model_provider, setup_llm  # noqa: E402
from orchestrator_helpers.model_providers import (  # noqa: E402
    fetch_glm_models,
    fetch_kimi_models,
    fetch_qwen_models,
    fetch_xai_models,
    fetch_mistral_models,
)


PROVIDERS = [
    {
        "label": "GLM (Zhipu AI)",
        "fetcher": fetch_glm_models,
        "id_prefix": "glm",
        "expected_host": "open.bigmodel.cn",
        "setup_kwarg": "glm_api_key",
    },
    {
        "label": "Kimi (Moonshot)",
        "fetcher": fetch_kimi_models,
        "id_prefix": "kimi",
        "expected_host": "api.moonshot.ai",
        "setup_kwarg": "kimi_api_key",
    },
    {
        "label": "Qwen (Alibaba)",
        "fetcher": fetch_qwen_models,
        "id_prefix": "qwen",
        "expected_host": "dashscope-intl.aliyuncs.com",
        "setup_kwarg": "qwen_api_key",
    },
    {
        "label": "xAI (Grok)",
        "fetcher": fetch_xai_models,
        "id_prefix": "xai",
        "expected_host": "api.x.ai",
        "setup_kwarg": "xai_api_key",
    },
    {
        "label": "Mistral AI",
        "fetcher": fetch_mistral_models,
        "id_prefix": "mistral",
        "expected_host": "api.mistral.ai",
        "setup_kwarg": "mistral_api_key",
    },
]


async def main() -> int:
    failures: list[str] = []

    for p in PROVIDERS:
        print(f"\n=== {p['label']} ===")
        CALL_LOG.clear()

        # 1) Discovery — fetch_<provider>_models
        models = await p["fetcher"](api_key="fake-key-abc")
        ids = [m["id"] for m in models]
        print(f"  models discovered: {ids}")
        if not ids or not all(i.startswith(f"{p['id_prefix']}/") for i in ids):
            failures.append(f"{p['label']}: bad model id prefixes: {ids}")

        get_calls = [c for c in CALL_LOG if c[0] == "GET"]
        if not get_calls:
            failures.append(f"{p['label']}: no GET issued")
            continue
        method, url, auth = get_calls[0]
        if p["expected_host"] not in url:
            failures.append(f"{p['label']}: GET hit wrong host: {url}")
        if not auth.startswith("Bearer "):
            failures.append(f"{p['label']}: missing/bad Authorization header: {auth!r}")
        print(f"  GET  {url}  (Authorization: {auth[:25]}...)")

        # 2) Routing — parse_model_provider
        first_id = ids[0]  # whatever the fetcher returned first
        expected_model = first_id[len(p["id_prefix"]) + 1:]
        prov, model = parse_model_provider(first_id)
        print(f"  parse_model_provider({first_id!r}) -> ({prov!r}, {model!r})")
        if prov != p["id_prefix"] or model != expected_model:
            failures.append(f"{p['label']}: parse_model_provider returned ({prov}, {model})")

        # 3) End-to-end invoke — ChatOpenAI.ainvoke through our mock
        CALL_LOG.clear()
        llm = setup_llm(first_id, **{p["setup_kwarg"]: "fake-key-abc"})
        result = await llm.ainvoke("ping")
        print(f"  invoke('ping') -> {result.content!r}")
        if result.content != "MOCK_REPLY_OK":
            failures.append(f"{p['label']}: unexpected reply: {result.content!r}")

        post_calls = [c for c in CALL_LOG if c[0] == "POST"]
        if not post_calls:
            failures.append(f"{p['label']}: no POST issued by invoke()")
        else:
            method, url, auth = post_calls[0]
            if p["expected_host"] not in url or "/chat/completions" not in url:
                failures.append(f"{p['label']}: POST hit wrong URL: {url}")
            if not auth.startswith("Bearer fake-key-abc"):
                failures.append(f"{p['label']}: POST missing/bad auth: {auth!r}")
            print(f"  POST {url}  (Authorization: {auth[:25]}...)")

    # ---------------------------------------------------------------------
    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED — {len(failures)} issue(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL PROVIDERS PROVEN END-TO-END (mocked upstream)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
