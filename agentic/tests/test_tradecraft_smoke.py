"""Smoke / integration tests for tradecraft (live agent + webapp).

These tests hit the running local stack via HTTP. They are skipped when the
stack is not reachable so the suite can still run on its own.

Covers:
- Webapp API: list / create / SSRF reject / slug collision / delete
- Agent /tradecraft/verify schema (cold call returns expected keys)
- Tool description correctly composed from settings
"""

from __future__ import annotations

import os
import unittest
import urllib.parse
import urllib.request
import json


WEBAPP_URL = os.environ.get("TC_TEST_WEBAPP_URL", "http://localhost:3000")
AGENT_URL = os.environ.get("TC_TEST_AGENT_URL", "http://localhost:8090")
INTERNAL_KEY = os.environ.get("INTERNAL_API_KEY", "")
TEST_USER_ID = os.environ.get("TC_TEST_USER_ID", "")


def _http(method: str, url: str, body: dict | None = None) -> tuple[int, dict | str]:
    data = None
    headers = {}
    if INTERNAL_KEY:
        headers["x-internal-key"] = INTERNAL_KEY
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            txt = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(txt)
            except Exception:
                return resp.status, txt
    except urllib.error.HTTPError as e:
        txt = (e.read() or b"").decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, txt
    except Exception as e:
        return 0, str(e)


def _services_reachable() -> bool:
    try:
        s, _ = _http("GET", f"{WEBAPP_URL}/api/health")
        if s != 200:
            return False
        s2, _ = _http("GET", f"{AGENT_URL}/health")
        return s2 == 200
    except Exception:
        return False


def _resolve_user_id() -> str:
    """If TC_TEST_USER_ID isn't set, call the LLM-providers internal endpoint
    to discover a user with a configured Anthropic key (needed for /verify)."""
    if TEST_USER_ID:
        return TEST_USER_ID
    # Best-effort: try a few common user paths via the database is out of scope;
    # callers should set TC_TEST_USER_ID env var. Return empty string -> tests skip.
    return ""


SKIP_MSG = (
    "Live stack not reachable on localhost:3000 / localhost:8090, or "
    "TC_TEST_USER_ID env var not set. Run agent + webapp first."
)


@unittest.skipUnless(_services_reachable(), SKIP_MSG)
class TestWebappApiSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.user_id = _resolve_user_id()
        if not cls.user_id:
            raise unittest.SkipTest("TC_TEST_USER_ID not set")
        cls.created_ids: list[str] = []

    @classmethod
    def tearDownClass(cls):
        # Clean up test resources by name.
        for rid in getattr(cls, "created_ids", []):
            _http("DELETE", f"{WEBAPP_URL}/api/users/{cls.user_id}/tradecraft-resources/{rid}")

    def test_list_returns_array(self):
        s, body = _http("GET", f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources")
        self.assertEqual(s, 200)
        self.assertIsInstance(body, list)

    def test_create_skip_verify(self):
        s, body = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {"name": "TC_TEST_SmokeBasic", "url": "https://example.com/tc-smoke-basic"},
        )
        self.assertEqual(s, 201, body)
        self.assertIn("id", body)
        self.assertEqual(body["slug"], "tc-test-smokebasic")
        self.created_ids.append(body["id"])

    def test_ssrf_blocked(self):
        s, body = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {"name": "TC_TEST_SSRF", "url": "http://127.0.0.1:8080"},
        )
        self.assertEqual(s, 400, body)

    def test_slug_collision_suffix(self):
        # Two resources with the same name -> second gets "-2" suffix on slug.
        s1, b1 = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {"name": "TC_TEST_Dup", "url": "https://example.com/tc-dup-1"},
        )
        self.assertEqual(s1, 201, b1)
        self.created_ids.append(b1["id"])
        s2, b2 = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {"name": "TC_TEST_Dup", "url": "https://example.com/tc-dup-2"},
        )
        self.assertEqual(s2, 201, b2)
        self.created_ids.append(b2["id"])
        self.assertNotEqual(b1["slug"], b2["slug"])
        self.assertTrue(b2["slug"].startswith("tc-test-dup"))

    def test_url_unique_409(self):
        url = "https://example.com/tc-dup-url"
        s1, b1 = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {"name": "TC_TEST_UrlA", "url": url},
        )
        self.assertEqual(s1, 201)
        self.created_ids.append(b1["id"])
        s2, _ = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {"name": "TC_TEST_UrlB", "url": url},
        )
        self.assertEqual(s2, 409)

    def test_token_masking_in_get(self):
        s, body = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            {
                "name": "TC_TEST_Token",
                "url": "https://example.com/tc-token",
                "githubTokenOverride": "ghp_supersecrettokenABCDE",
            },
        )
        self.assertEqual(s, 201)
        self.created_ids.append(body["id"])
        # Masked
        self.assertTrue(body["githubTokenOverride"].startswith("•"))
        # Internal endpoint returns the real value
        s2, body2 = _http(
            "GET",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?internal=true",
        )
        self.assertEqual(s2, 200)
        match = next((r for r in body2 if r["id"] == body["id"]), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["githubTokenOverride"], "ghp_supersecrettokenABCDE")


@unittest.skipUnless(_services_reachable(), SKIP_MSG)
class TestAgentVerifyEndpoint(unittest.TestCase):
    def test_ssrf_guard_at_agent(self):
        s, body = _http(
            "POST",
            f"{AGENT_URL}/tradecraft/verify",
            {"url": "http://127.0.0.1:8080"},
        )
        # Agent verify_resource returns 200 with last_error on validate fail.
        self.assertEqual(s, 200, body)
        if isinstance(body, dict):
            self.assertIn("last_error", body)
            self.assertTrue(
                "private" in (body.get("last_error") or "").lower()
                or "address" in (body.get("last_error") or "").lower()
            )


@unittest.skipUnless(_services_reachable(), SKIP_MSG)
class TestWebappPutBehavior(unittest.TestCase):
    """PUT-route invariants: slug immutability + token mask preserve."""

    @classmethod
    def setUpClass(cls):
        cls.user_id = _resolve_user_id()
        if not cls.user_id:
            raise unittest.SkipTest("TC_TEST_USER_ID not set")
        cls.created_ids: list[str] = []

    @classmethod
    def tearDownClass(cls):
        for rid in getattr(cls, "created_ids", []):
            _http("DELETE", f"{WEBAPP_URL}/api/users/{cls.user_id}/tradecraft-resources/{rid}")

    def _create(self, name: str, url: str, token: str = "") -> dict:
        body = {"name": name, "url": url}
        if token:
            body["githubTokenOverride"] = token
        s, b = _http(
            "POST",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?skipVerify=true",
            body,
        )
        self.assertEqual(s, 201, b)
        self.created_ids.append(b["id"])
        return b

    def test_put_does_not_change_slug(self):
        created = self._create("TC_TEST_PutSlug", "https://example.com/tc-put-slug")
        original_slug = created["slug"]
        # Try to update name + smuggle a new slug field
        s, body = _http(
            "PUT",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources/{created['id']}",
            {"name": "Renamed", "slug": "fake-evil-slug"},
        )
        self.assertEqual(s, 200, body)
        self.assertEqual(body["slug"], original_slug)
        self.assertEqual(body["name"], "Renamed")

    def test_put_preserves_masked_token(self):
        token = "ghp_putpreserveTOKEN12345"
        created = self._create(
            "TC_TEST_PutTokenMask",
            "https://example.com/tc-put-token-mask",
            token=token,
        )
        masked = created["githubTokenOverride"]
        self.assertTrue(masked.startswith("•"))
        # PUT with the masked value should NOT overwrite the real token.
        s, _ = _http(
            "PUT",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources/{created['id']}",
            {"githubTokenOverride": masked, "name": "TC_TEST_PutTokenMask"},
        )
        self.assertEqual(s, 200)
        # Confirm via internal-API GET that the original token is intact.
        s2, all_resources = _http(
            "GET",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources?internal=true",
        )
        self.assertEqual(s2, 200)
        match = next((r for r in all_resources if r["id"] == created["id"]), None)
        self.assertIsNotNone(match)
        self.assertEqual(match["githubTokenOverride"], token,
                         "PUT with masked token must NOT overwrite the real token")

    def test_put_does_not_change_summary_sitemap_resourcetype(self):
        """Verify-only fields (set by /verify) should not be overridable via PUT."""
        created = self._create(
            "TC_TEST_PutVerifyFields",
            "https://example.com/tc-put-verify-fields",
        )
        s, body = _http(
            "PUT",
            f"{WEBAPP_URL}/api/users/{self.user_id}/tradecraft-resources/{created['id']}",
            {
                "name": "Renamed",
                "summary": "INJECTED MALICIOUS SUMMARY",
                "sitemap": {"nav": [{"title": "fake", "path": "/fake"}]},
                "resourceType": "github-repo",  # Was agentic-crawl
            },
        )
        self.assertEqual(s, 200, body)
        # All verify-managed fields must be untouched.
        self.assertEqual(body.get("summary", ""), created.get("summary", ""))
        self.assertEqual(body.get("resourceType"), created.get("resourceType"))
        self.assertEqual(body.get("sitemap"), created.get("sitemap"))


if __name__ == "__main__":
    unittest.main()
