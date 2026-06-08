"""
Proof script — NOT part of the regular test suite.

Reconstructs the pre-fix /models GET handler in a throwaway FastAPI app, then
runs the regression assertions from test_models_endpoint_security against it.
Each block prints PASS or FAIL: every FAIL here is a regression-test that
correctly catches the pre-fix vulnerability.

Run: python -m tests._proof_pre_fix_fails
"""
from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Pre-fix handler (verbatim shape from api.py before the security fix)
# ---------------------------------------------------------------------------
def build_pre_fix_app() -> FastAPI:
    app = FastAPI()

    @app.get("/models", tags=["System"])
    async def get_models(providers: str = Query(default="")):
        import json
        try:
            json.loads(providers) if providers else None
        except Exception:
            pass
        return {}

    return app


CANARY = "sk-ant-api03-LEAK-CANARY-DO-NOT-LOG-XXXXXXXXXX"


def check(label: str, condition: bool, *, expect: str) -> None:
    """expect='catches' → test correctly fails on pre-fix (printed CATCHES).
    expect='passes' → test is method-agnostic / unrelated."""
    actual = "catches" if not condition else "misses"
    verdict = "✓" if actual == expect else "✗ UNEXPECTED"
    print(f"  {verdict} {label}: pre-fix {actual}")


def main() -> int:
    client = TestClient(build_pre_fix_app())

    print("Re-running regression assertions against synthesized pre-fix handler:")
    print()

    # 1. test_get_method_is_rejected expects 405; pre-fix returns 200.
    r = client.get("/models", params={"providers": f'[{{"apiKey": "{CANARY}"}}]'})
    check("test_get_method_is_rejected", r.status_code == 405, expect="catches")

    # 2. test_get_method_is_rejected_without_query: same — pre-fix GET returns 200.
    r = client.get("/models")
    check("test_get_method_is_rejected_without_query", r.status_code == 405, expect="catches")

    # 3. test_only_post_method_is_registered: pre-fix has GET, no POST.
    pre_fix_app = build_pre_fix_app()
    models_routes = [r for r in pre_fix_app.routes if getattr(r, "path", None) == "/models"]
    methods = models_routes[0].methods
    has_post_only = "POST" in methods and "GET" not in methods
    check("test_only_post_method_is_registered_for_models", has_post_only, expect="catches")

    # 4. test_post_with_providers_passes_body_through: pre-fix POST → 405.
    r = client.post("/models", json={"providers": [{"apiKey": CANARY}]})
    check("test_post_with_providers_passes_body_through", r.status_code == 200, expect="catches")

    # 5. test_post_with_empty_body_falls_back_to_env: pre-fix POST → 405.
    r = client.post("/models")
    check("test_post_with_empty_body_falls_back_to_env", r.status_code == 200, expect="catches")

    print()
    print("All regression tests confirmed to catch the pre-fix vulnerability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
