"""
AI Surface Recon — Guinea Pig HTTP target.

Listens on every port + path the lap-1 catalog cares about, returns
deterministic responses that fire each detection. No LLM, no model
weights, no GPU — just a Python aiohttp process producing surface signals.

Layout:
    16 per-port listeners (one aiohttp app per AI product port)
    +  1 header showroom on port 9100 (20 framework variants)
    +  1 title  showroom on port 9101 (18 product variants)
    = 18 ports bound to 0.0.0.0

The recon container reaches this via `network_mode: host` → 127.0.0.1:*.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys

from aiohttp import web

import ai_surface_recon_endpoints as _aiep  # validated central-module response shapes

from ai_signals import (
    ENDPOINT_AI_CLASSIFIER_PORT,
    HEADER_SHOWROOM_PORT,
    HEADER_VARIANTS,
    JS_RECON_AI_SDK_FIXTURES,
    JS_RECON_AI_SDK_PORT,
    PORT_LISTENERS,
    RESOURCE_ENUM_AI_PATHS,
    RESOURCE_ENUM_AI_RAG_PATHS,
    TITLE_SHOWROOM_PORT,
    TITLE_VARIANTS,
    ZAP_AJAX_SHOWROOM_PORT,
    ZAP_AJAX_TEST_ENDPOINTS,
)


# Port for the jsluice URL-verification end-to-end target. Independent of the
# AI surface ports above so the AI lap-1 catalog tests stay untouched.
JSLUICE_TARGET_PORT = 9102

# Central ai_surface_recon module target: serves the REAL response shapes the
# active probes confirm (chat / OpenAPI / models / Julius). AI header so
# http_probe tags it -> it becomes an ai_surface_recon candidate host.
AI_SURFACE_RECON_TARGET_PORT = 9106

# Real MCP (Streamable HTTP) server, run as a subprocess by run_target.py.
MCP_TARGET_PORT = 9107


# ---------------------------------------------------------------------------
# Logging — concise, single-line per request
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("guinea-pig")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _html(title: str, body: str = "") -> str:
    return (
        "<!DOCTYPE html><html><head>"
        f"<title>{title}</title>"
        "<meta charset='utf-8'></head><body>"
        f"<h1>{title}</h1><pre>{body}</pre>"
        "<p>RedAmon AI surface guinea pig — deterministic stub.</p>"
        "</body></html>"
    )


def _empty_favicon() -> web.Response:
    # Tiny PNG-style placeholder so httpx -favicon doesn't 404.
    # Hash is irrelevant for lap-1 (catalog is empty); Phase 15 will use a
    # known mmh3 hash here.
    return web.Response(body=b"\x00", content_type="image/x-icon")


# ---------------------------------------------------------------------------
# Per-product port handler factory
# ---------------------------------------------------------------------------

def make_port_app(descriptor: dict) -> web.Application:
    app = web.Application()
    app["descriptor"] = descriptor

    @web.middleware
    async def server_header_mw(request: web.Request, handler) -> web.Response:
        response = await handler(request)
        response.headers["Server"] = descriptor.get("server_header", "ai-test-target")
        return response

    app.middlewares.append(server_header_mw)

    async def root(request: web.Request) -> web.Response:
        body = (
            f"product       = {descriptor['name']}\n"
            f"port          = {descriptor['port']}\n"
            f"server_banner = {descriptor.get('server_header', '')}\n"
        )
        return web.Response(
            text=_html(descriptor.get("html_title", descriptor["name"]), body),
            content_type="text/html",
        )

    async def favicon(_request: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_request: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", root)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)

    # Vector-DB confirmation read: the ai_surface_recon module probes known
    # vector-DB ports (Qdrant 6333, etc.) and confirms with a benign read.
    # Serve the matching response so the confirmation actually fires.
    name = descriptor.get("name", "")
    if name.startswith("qdrant"):
        async def qdrant_collections(_r: web.Request) -> web.Response:
            return web.json_response({"result": {"collections": [{"name": "docs"}]},
                                      "status": "ok", "time": 0.0})
        app.router.add_get("/collections", qdrant_collections)
    if name.startswith("milvus"):
        async def milvus_collections(_r: web.Request) -> web.Response:
            return web.json_response({"collections": []})
        app.router.add_get("/v1/vector/collections", milvus_collections)
    return app


# ---------------------------------------------------------------------------
# Header showroom (port 9100) — emit AI headers per /header/<framework>
# ---------------------------------------------------------------------------

def make_header_showroom_app() -> web.Application:
    app = web.Application()

    async def index(_request: web.Request) -> web.Response:
        links = "\n".join(
            f"  <li><a href='/header/{k}'>/header/{k}</a> &mdash; "
            f"{', '.join(v['headers'].keys())} → {v['expected_framework']}/{v['expected_category']}</li>"
            for k, v in HEADER_VARIANTS.items()
        )
        body = _html(
            "AI Header Showroom",
            f"GET /header/&lt;framework&gt; returns response carrying that AI header.\n\n<ul>\n{links}\n</ul>",
        )
        return web.Response(text=body, content_type="text/html")

    async def emit(request: web.Request) -> web.Response:
        framework = request.match_info["framework"]
        info = HEADER_VARIANTS.get(framework)
        if not info:
            return web.Response(
                text=f"unknown framework: {framework}",
                status=404,
                content_type="text/plain",
            )
        body = _html(
            f"AI Header: {framework}",
            "\n".join(f"{k}: {v}" for k, v in info["headers"].items()),
        )
        response = web.Response(text=body, content_type="text/html")
        for h_name, h_value in info["headers"].items():
            response.headers[h_name] = h_value
        response.headers["Server"] = "ai-test-target/header-showroom"
        return response

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/header/{framework}", emit)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Title showroom (port 9101) — emit AI titles per /title/<product>
# ---------------------------------------------------------------------------

def make_title_showroom_app() -> web.Application:
    app = web.Application()

    async def index(_request: web.Request) -> web.Response:
        links = "\n".join(
            f"  <li><a href='/title/{k}'>/title/{k}</a> &mdash; "
            f"&lt;title&gt;{v['title']}&lt;/title&gt; → {v['expected_product']}</li>"
            for k, v in TITLE_VARIANTS.items()
        )
        body = _html(
            "AI Title Showroom",
            f"GET /title/&lt;product&gt; returns HTML with the matching &lt;title&gt;.\n\n<ul>\n{links}\n</ul>",
        )
        return web.Response(text=body, content_type="text/html")

    async def emit(request: web.Request) -> web.Response:
        product = request.match_info["product"]
        info = TITLE_VARIANTS.get(product)
        if not info:
            return web.Response(
                text=f"unknown product: {product}",
                status=404,
                content_type="text/plain",
            )
        body = _html(info["title"], f"product = {product}")
        response = web.Response(text=body, content_type="text/html")
        response.headers["Server"] = "ai-test-target/title-showroom"
        return response

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/title/{product}", emit)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# jsluice URL-verification target (port 9102)
#
# Serves a tiny HTML entry point that links to an application JS file. The JS
# file embeds a deliberately mixed bag of URL strings that exercise every
# branch of the jsluice deny-list + httpx verifier:
#
#   live  + .json  → /api/v1/users.json   (proves B1: .json survives .js rule)
#   live  + path   → /api/products
#   live  + 403    → /admin                (proves accept_status default 403)
#   dead  + 404    → /api/deprecated       (proves fail-closed for dead URL)
#   noise + lib    → /node_modules/...     (deny-list drops before httpx)
#   noise + lib    → /rxjs/static-5.10     (deny-list drops before httpx)
#   noise + asset  → /assets/logo.png      (deny-list drops before httpx)
#
# Noise paths are intentionally NOT served — if the deny-list ever stops
# filtering them, httpx would 404 the path and they still wouldn't reach the
# graph. The deny-list is the guard we care about.
# ---------------------------------------------------------------------------

JSLUICE_APP_JS = b"""
// Mixed-signal JS for end-to-end jsluice verification testing.
// Each fetch / string literal below should exercise a specific branch of the
// jsluice deny-list + httpx verifier.

const USERS_API = '/api/v1/users.json';      // live + .json (B1 regression)
fetch('/api/products');                       // live + path
fetch('/admin');                              // live + 403 (accept_status)
fetch('/api/deprecated');                    // dead + 404 (fail-closed)

// Noise that the deny-list MUST drop before httpx ever probes it.
const LIB    = '/node_modules/lodash/index.js';
const BUNDLE = '/rxjs/static-5.10';
const LOGO   = '/assets/logo.png';

export { USERS_API, LIB, BUNDLE, LOGO };
"""


def make_endpoint_ai_classifier_app() -> web.Application:
    """Lap-2 — resource_enum AI classifier showroom.

    Serves an HTML index linking to every catalogued AI path. Each link
    carries query-string params (some prompt-injectable, some control) so
    Katana picks them up as Endpoint + Parameter nodes. The resource_enum
    AI classifier then tags each endpoint with `ai_interface_type` /
    `is_ai_rag_ingest` and each prompt-named param with
    `is_ai_prompt_injectable=true`.

    Every linked URL serves a trivial 200 OK — the goal is discovery, not
    realism. The classifier reads from the graph, not from the response.
    """
    app = web.Application()

    all_entries = RESOURCE_ENUM_AI_PATHS + RESOURCE_ENUM_AI_RAG_PATHS

    def _qs(entry: dict) -> str:
        params = entry.get("prompt_params", []) + entry.get("control_params", [])
        return "&".join(f"{p}=demo" for p in params)

    async def index(_request: web.Request) -> web.Response:
        rows = []
        for entry in RESOURCE_ENUM_AI_PATHS:
            params = entry.get("prompt_params", []) + entry.get("control_params", [])
            href = entry["path"] + (("?" + _qs(entry)) if params else "")
            rows.append(
                f"  <li><a href='{href}'>{entry['path']}</a> &mdash; "
                f"<code>{entry['enum']}</code>"
                + (f" (params: {', '.join(params)})" if params else "")
                + "</li>"
            )
        rag_rows = []
        for entry in RESOURCE_ENUM_AI_RAG_PATHS:
            params = entry.get("prompt_params", []) + entry.get("control_params", [])
            href = entry["path"] + (("?" + _qs(entry)) if params else "")
            rag_rows.append(
                f"  <li><a href='{href}'>{entry['path']}</a> &mdash; RAG"
                + (f" (params: {', '.join(params)})" if params else "")
                + "</li>"
            )
        body = (
            "<!DOCTYPE html><html><head>"
            "<title>RedAmon Endpoint AI Classifier Showroom</title>"
            "</head><body>"
            "<h1>Endpoint AI Classifier Showroom</h1>"
            "<p>Katana discovers these links. The resource_enum AI classifier "
            "stamps <code>Endpoint.ai_interface_type</code> and "
            "<code>is_ai_rag_ingest</code> based on path; "
            "<code>Parameter.is_ai_prompt_injectable=true</code> on the prompt-named params.</p>"
            f"<h2>AI Interface Type paths ({len(RESOURCE_ENUM_AI_PATHS)})</h2>"
            "<ul>\n" + "\n".join(rows) + "\n</ul>"
            f"<h2>RAG ingestion / retrieval paths ({len(RESOURCE_ENUM_AI_RAG_PATHS)})</h2>"
            "<ul>\n" + "\n".join(rag_rows) + "\n</ul>"
            "</body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def catch_all(request: web.Request) -> web.Response:
        # Echo the path and parsed query string. 200 OK is enough — the
        # classifier reads from the graph, not from the response body.
        path = request.path
        return web.Response(
            text=f"OK — guinea pig endpoint: {path}\nquery: {dict(request.query)}\n",
            content_type="text/plain",
        )

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    # Register every catalogued path as a no-op 200 OK.
    seen: set[str] = set()
    for entry in all_entries:
        p = entry["path"]
        if p in seen:
            continue
        seen.add(p)
        app.router.add_get(p, catch_all)
    return app


# ---------------------------------------------------------------------------
# Lap-3 (Phase 6) — js_recon AI SDK showroom (port 9104)
#
# Serves an HTML index that links to every fixture JS file via <script>
# tags. Katana follows the script tags; js_recon downloads each .js, runs
# match_ai_sdk() against the content, and writes JsReconFinding nodes with
# finding_type ai-sdk-*. The mixin then enriches matching Secret nodes
# with ai_provider.
#
# Each fixture is engineered to exercise one or more detection branches:
#   - SDK imports (single + sub-path + multi-vendor)
#   - constructor-context key literals (suppresses prefix duplicate)
#   - prefix-anchored key literals (for SDK-less fetch calls)
#   - dangerouslyAllowBrowser opt-in (bareword + terser !0 + JSON form)
#   - Gemini disambiguation BOTH WAYS (with and without context)
#   - frontend product markers (Open WebUI, Gradio, Flowise, SillyTavern)
#   - provider base URLs (OpenAI, Anthropic, Groq, OpenRouter, etc.)
#   - Bearer + x-api-key header literals
#   - env-var hydration leak (NEXT_PUBLIC_*)
#   - negative cases (jQuery, Stripe) for false-positive regression
# ---------------------------------------------------------------------------

def make_js_recon_ai_sdk_app() -> web.Application:
    app = web.Application()

    # Index of {filename: bytes} so the JS handler is O(1) per request.
    fixtures_by_name = {f["filename"]: f for f in JS_RECON_AI_SDK_FIXTURES}

    async def index(_request: web.Request) -> web.Response:
        # Generate <script> tags so Katana picks up every JS file as a JS
        # discovery edge. Also list them in a human-readable table.
        script_tags = "\n".join(
            f"  <script src='/static/{f['filename']}'></script>"
            for f in JS_RECON_AI_SDK_FIXTURES
        )
        rows = []
        for f in JS_RECON_AI_SDK_FIXTURES:
            expected = ", ".join(
                f"{e['category']}" + (f"({e.get('sdk_name', '?')})"
                                       if 'sdk_name' in e else "")
                for e in f["expected_findings"]
            ) or "(none — negative case)"
            rows.append(
                f"  <tr>"
                f"<td><a href='/static/{f['filename']}'><code>{f['filename']}</code></a></td>"
                f"<td>{f['description']}</td>"
                f"<td><code>{expected}</code></td>"
                f"</tr>"
            )
        body = (
            "<!DOCTYPE html><html><head>"
            "<title>RedAmon JS Recon AI SDK Showroom</title>"
            "<meta charset='utf-8'>"
            "<style>table{border-collapse:collapse;font-family:monospace;}"
            "th,td{border:1px solid #444;padding:6px;text-align:left;vertical-align:top;}"
            "code{background:#eee;padding:1px 4px;}</style>"
            f"{script_tags}\n"
            "</head><body>"
            "<h1>JS Recon AI SDK Showroom (Phase 6)</h1>"
            f"<p>Serves {len(JS_RECON_AI_SDK_FIXTURES)} fixture JS files that "
            "exercise every detection branch in <code>match_ai_sdk()</code>. "
            "Katana follows the <code>&lt;script&gt;</code> tags above; "
            "js_recon downloads each file and the catalogue emits "
            "JsReconFinding nodes with finding_type <code>ai-sdk-*</code>.</p>"
            "<table>"
            "<thead><tr><th>Fixture</th><th>Purpose</th>"
            "<th>Expected match_ai_sdk findings</th></tr></thead>"
            "<tbody>" + "\n".join(rows) + "</tbody></table>"
            "</body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def serve_js(request: web.Request) -> web.Response:
        filename = request.match_info["filename"]
        fixture = fixtures_by_name.get(filename)
        if not fixture:
            return web.Response(text=f"unknown fixture: {filename}",
                                status=404, content_type="text/plain")
        # NB: served as application/javascript so httpx/katana treat it as
        # JS and js_recon downloads it. The content itself is what the AI
        # SDK detection catalogue scans.
        return web.Response(text=fixture["content"],
                            content_type="application/javascript")

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/static/{filename}", serve_js)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


def make_zap_ajax_showroom_app() -> web.Application:
    """
    SPA-like surface for testing ZAP Ajax Spider end-to-end.

    The root HTML carries minimal static markup. The interactive surface is
    built at runtime by inline JavaScript:
    - JS-only XHR endpoints triggered by onclick handlers
    - Runtime-templated URL (template literal with computed id)
    - SPA route changes via history.pushState (no real HTTP for the route, but the
      subsequent data fetch IS a real HTTP request)
    - Click cascade: button A reveals button B; B's onclick fetches /api/secret-page
    - GraphQL POST from a button
    - Form submission via onsubmit
    - Auth-aware flow: on load, fetch /api/me. If the server returns
      `x-redamon-authed: true` (which it does only when an Authorization header
      arrives via ZAP's Replacer), inject an admin link and fetch /api/admin/audit-log

    Logout link and a static-asset img are included to verify:
    - logoutAvoidance=true skips the /api/auth/logout anchor
    - excludePatterns=[\\.png$] filters out the logo
    """
    app = web.Application()

    INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <title>ZAP Ajax Spider Test Target</title>
  <meta charset="utf-8" />
  <style>
    body { font-family: sans-serif; margin: 2em; }
    button, a { display: inline-block; margin: 4px 8px 4px 0; }
    #secret-area, #auth-area { margin-top: 1em; padding: 8px; border: 1px dashed #888; min-height: 24px; }
    code { background: #eee; padding: 1px 4px; }
  </style>
</head>
<body>
  <h1>ZAP Ajax Spider Test Surface</h1>
  <p>Every link/button below exercises a discovery branch that static
  crawlers (Katana, Hakrawler) cannot reach without a real browser.</p>

  <h2>Static (baseline)</h2>
  <a href="/about">About (plain anchor — every crawler finds this)</a>
  <br/>
  <a id="logout-link" href="/api/auth/logout">Sign out (logoutAvoidance should SKIP this)</a>
  <br/>
  <img src="/static/logo.png" alt="logo" width="32" height="32" />
  <span>&larr; static asset noise (filter via excludePatterns)</span>

  <h2>JS-driven XHR</h2>
  <button id="load-users" onclick="loadUsers()">Load Users</button>
  <button id="reveal" onclick="revealSecret()">Show Secret Area</button>
  <button id="goto-dashboard" onclick="gotoDashboard()">Dashboard (SPA route)</button>
  <button id="graphql-btn" onclick="callGraphql()">Run GraphQL Query</button>

  <h2>Form (test randomInputs)</h2>
  <form id="search-form" onsubmit="return submitSearch(event)">
    <input name="q" id="search-q" placeholder="search…" />
    <button type="submit">Search</button>
  </form>

  <h2>Click-cascade reveal</h2>
  <div id="secret-area"><em>(click "Show Secret Area" first)</em></div>

  <h2>Auth-aware area (only populated when Authorization header is present)</h2>
  <div id="auth-area"><em>(no auth detected yet)</em></div>

  <script>
    // 1. Plain XHR + runtime-templated URL — discoverable only via browser click
    async function loadUsers() {
      await fetch('/api/users/list');
      const id = 42;
      await fetch(`/api/projects/${id}`);
    }

    // 2. Cascade: reveal a second button, whose onclick fires another XHR
    function revealSecret() {
      const div = document.getElementById('secret-area');
      div.innerHTML = '<button id="secret-btn" onclick="loadSecretPage()">Open Secret Page</button>';
    }
    async function loadSecretPage() {
      await fetch('/api/secret-page');
    }

    // 3. SPA route change via history.pushState, followed by data fetch
    async function gotoDashboard() {
      history.pushState({}, '', '/spa/dashboard');
      await fetch('/api/dashboard-data');
    }

    // 4. GraphQL POST
    async function callGraphql() {
      await fetch('/graphql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: '{ me { id email } }' })
      });
    }

    // 5. Form submission triggers an XHR with query param
    function submitSearch(e) {
      e.preventDefault();
      const q = document.getElementById('search-q').value || '';
      fetch('/api/search?q=' + encodeURIComponent(q));
      return false;
    }

    // 6. Auth-aware probe — runs on load. Server only returns the
    // x-redamon-authed header when an Authorization request header was
    // present (ZAP injects this via Replacer; a static crawler does not).
    (async () => {
      const r = await fetch('/api/me');
      const authed = r.headers.get('x-redamon-authed') === 'true';
      const area = document.getElementById('auth-area');
      if (authed) {
        area.innerHTML = '<a id="admin-link" href="/api/admin/users">Admin Users (auth-only)</a>';
        await fetch('/api/admin/audit-log');
      }
    })();
  </script>
</body>
</html>
"""

    async def index(_r: web.Request) -> web.Response:
        return web.Response(text=INDEX_HTML, content_type="text/html")

    async def about(_r: web.Request) -> web.Response:
        return web.Response(text=_html("About — plain page"),
                            content_type="text/html")

    async def users_list(_r: web.Request) -> web.Response:
        return web.json_response({"users": [{"id": 42, "name": "alice"}]})

    async def project_by_id(request: web.Request) -> web.Response:
        return web.json_response({
            "project_id": request.match_info["pid"],
            "items": [],
        })

    async def dashboard_data(_r: web.Request) -> web.Response:
        return web.json_response({"widgets": []})

    async def secret_page(_r: web.Request) -> web.Response:
        return web.json_response({"secret": "discovered-via-cascade"})

    async def graphql_endpoint(_r: web.Request) -> web.Response:
        return web.json_response({"data": {"me": {"id": 1, "email": "stub@example.test"}}})

    async def search(_r: web.Request) -> web.Response:
        return web.json_response({"results": []})

    async def auth_logout(_r: web.Request) -> web.Response:
        # If ZAP follows this, the session would end. Returning 200 is fine for
        # the guinea pig; the test is whether logoutAvoidance prevented the click.
        return web.Response(text="logged out", content_type="text/plain")

    async def me(request: web.Request) -> web.Response:
        # Tell the JS whether the request carried an Authorization header.
        # The JS uses this signal to decide whether to render the admin link.
        # ZAP's Replacer injects Authorization on every request when
        # zapAjaxSpiderCustomHeaders is configured.
        has_auth = bool(request.headers.get("Authorization"))
        headers = {"x-redamon-authed": "true" if has_auth else "false"}
        return web.json_response(
            {"user_id": 1 if has_auth else None},
            headers=headers,
        )

    async def admin_users(request: web.Request) -> web.Response:
        if not request.headers.get("Authorization"):
            return web.Response(text="forbidden", status=403, content_type="text/plain")
        return web.json_response({"users": [{"id": 1, "role": "admin"}]})

    async def admin_audit_log(request: web.Request) -> web.Response:
        if not request.headers.get("Authorization"):
            return web.Response(text="forbidden", status=403, content_type="text/plain")
        return web.json_response({"events": []})

    async def logo_png(_r: web.Request) -> web.Response:
        # Tiny 1x1 png stub. Hashed identical across runs.
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xfa\xcf"
            b"\x00\x00\x00\x02\x00\x01\xe5'\xde\xfc\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return web.Response(body=png, content_type="image/png")

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    # Routes
    app.router.add_get("/", index)
    app.router.add_get("/about", about)
    app.router.add_get("/api/users/list", users_list)
    app.router.add_get("/api/projects/{pid}", project_by_id)
    app.router.add_get("/api/dashboard-data", dashboard_data)
    app.router.add_get("/api/secret-page", secret_page)
    app.router.add_post("/graphql", graphql_endpoint)
    app.router.add_get("/api/search", search)
    app.router.add_get("/api/auth/logout", auth_logout)
    app.router.add_get("/api/me", me)
    app.router.add_get("/api/admin/users", admin_users)
    app.router.add_get("/api/admin/audit-log", admin_audit_log)
    app.router.add_get("/static/logo.png", logo_png)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


def make_jsluice_target_app() -> web.Application:
    app = web.Application()

    async def index(_r: web.Request) -> web.Response:
        body = (
            "<!DOCTYPE html><html><head>"
            "<title>RedAmon jsluice verifier target</title>"
            "<script src='/static/app.js'></script>"
            "</head><body><h1>jsluice target</h1>"
            "<p>Katana follows the script tag; jsluice extracts the URLs.</p>"
            "</body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def app_js(_r: web.Request) -> web.Response:
        return web.Response(body=JSLUICE_APP_JS, content_type="application/javascript")

    async def users_json(_r: web.Request) -> web.Response:
        return web.json_response({"users": []})

    async def products(_r: web.Request) -> web.Response:
        return web.json_response({"products": []})

    async def admin(_r: web.Request) -> web.Response:
        return web.Response(text="forbidden", status=403)

    async def deprecated(_r: web.Request) -> web.Response:
        return web.Response(text="gone", status=404)

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/static/app.js", app_js)
    app.router.add_get("/api/v1/users.json", users_json)
    app.router.add_get("/api/products", products)
    app.router.add_get("/admin", admin)
    app.router.add_get("/api/deprecated", deprecated)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def _start_site(app: web.Application, port: int, label: str) -> web.AppRunner:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info(f"+ listening :{port:<5d}  {label}")
    return runner


def make_ai_surface_recon_app() -> web.Application:
    """Central ai_surface_recon module target (port 9106).

    Serves the REAL response shapes the module's active probes confirm, so a
    full scan with the AI preset actually fires chat-shape detection, OpenAPI /
    manifest parsing, model-family guessing, and Julius fingerprinting against
    this host. An AI header (`x-vllm-version`) makes http_probe tag the port as
    an AI surface, which makes it an ai_surface_recon candidate; the HTML index
    links every AI path so Katana also discovers + classifies them. Reuses the
    response bodies validated by validate_ai_surface_recon.py.
    """
    app = web.Application()

    @web.middleware
    async def ai_header_mw(request: web.Request, handler) -> web.Response:
        resp = await handler(request)
        # AI-stack header signatures so http_probe flags this as an AI surface.
        resp.headers["x-vllm-version"] = "0.6.0"
        resp.headers["openai-version"] = "2020-10-01"
        return resp

    app.middlewares.append(ai_header_mw)

    chat_paths = [
        "/v1/chat/completions", "/v1/messages", "/api/generate", "/api/chat",
        "/v1beta/models/gemini-pro:generateContent", "/invoke", "/stream",
    ]

    async def index(_r: web.Request) -> web.Response:
        links = "".join(f"<li><a href='{p}'>{p}</a></li>" for p in chat_paths)
        # Body contains "Ollama is running" so the Julius ollama pack also matches.
        body = ("<!DOCTYPE html><html><head><title>AI Surface Recon Target</title>"
                "</head><body><h1>AI Surface Recon Target</h1>"
                "<p>Ollama is running</p><ul>" + links +
                "<li><a href='/v1/models'>/v1/models</a></li>"
                "<li><a href='/openapi.json'>/openapi.json</a></li>"
                "<li><a href='/.well-known/ai-plugin.json'>ai-plugin.json</a></li>"
                "</ul></body></html>")
        return web.Response(text=body, content_type="text/html")

    async def api_tags(_r): return web.json_response(_aiep._API_TAGS)
    async def api_version(_r): return web.json_response({"version": "0.3.0"})
    async def v1_models(_r): return web.json_response(_aiep._V1_MODELS)
    async def openapi(_r): return web.json_response(_aiep._OPENAPI)
    async def ai_plugin(_r): return web.json_response(_aiep._AI_PLUGIN)

    async def openai_chat(_r): return web.json_response(_aiep._OPENAI_CHAT)
    async def anthropic(_r): return web.json_response(_aiep._ANTHROPIC)
    async def ollama_gen(_r): return web.json_response(_aiep._OLLAMA_GEN)
    async def ollama_chat(_r): return web.json_response(_aiep._OLLAMA_CHAT)
    async def gemini(_r): return web.json_response(_aiep._GEMINI)
    async def langserve(_r): return web.json_response(_aiep._LANGSERVE)

    async def stream(_r):
        sse = "data: " + json_dumps(_aiep._OPENAI_CHAT) + "\n\ndata: [DONE]\n\n"
        return web.Response(text=sse, content_type="text/event-stream")

    async def favicon(_r): return _empty_favicon()
    async def healthz(_r): return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/api/tags", api_tags)
    app.router.add_get("/api/version", api_version)
    app.router.add_get("/v1/models", v1_models)
    app.router.add_get("/models", v1_models)
    app.router.add_get("/openapi.json", openapi)
    app.router.add_get("/swagger.json", openapi)
    app.router.add_get("/v3/api-docs", openapi)
    app.router.add_get("/.well-known/ai-plugin.json", ai_plugin)
    for p in ("/v1/chat/completions", "/v1/completions", "/v1/responses"):
        app.router.add_post(p, openai_chat)
    app.router.add_post("/v1/messages", anthropic)
    app.router.add_post("/api/generate", ollama_gen)
    app.router.add_post("/api/chat", ollama_chat)
    app.router.add_post("/v1beta/models/{model}:generateContent", gemini)
    app.router.add_post("/invoke", langserve)
    app.router.add_post("/stream", stream)
    return app


def json_dumps(d) -> str:
    import json as _json
    return _json.dumps(d)


async def main() -> None:
    runners: list[web.AppRunner] = []

    log.info("=" * 60)
    log.info("RedAmon AI surface guinea pig starting")
    log.info("=" * 60)

    # 1. Per-product ports
    for descriptor in PORT_LISTENERS:
        app = make_port_app(descriptor)
        runner = await _start_site(
            app,
            descriptor["port"],
            f"{descriptor['name']:<22s}  banner={descriptor.get('server_header', '')!r}",
        )
        runners.append(runner)

    # 2. Header showroom
    runners.append(
        await _start_site(
            make_header_showroom_app(),
            HEADER_SHOWROOM_PORT,
            f"header showroom — {len(HEADER_VARIANTS)} variants on /header/<framework>",
        )
    )

    # 3. Title showroom
    runners.append(
        await _start_site(
            make_title_showroom_app(),
            TITLE_SHOWROOM_PORT,
            f"title  showroom — {len(TITLE_VARIANTS)} variants on /title/<product>",
        )
    )

    # 4. jsluice URL-verification target (additive — does not affect AI surface tests)
    runners.append(
        await _start_site(
            make_jsluice_target_app(),
            JSLUICE_TARGET_PORT,
            "jsluice verifier target — /static/app.js with mixed live/dead/noise URLs",
        )
    )

    # 5. Lap-2 — resource_enum AI classifier showroom
    runners.append(
        await _start_site(
            make_endpoint_ai_classifier_app(),
            ENDPOINT_AI_CLASSIFIER_PORT,
            f"endpoint-ai-classifier showroom — "
            f"{len(RESOURCE_ENUM_AI_PATHS)} interface-type paths + "
            f"{len(RESOURCE_ENUM_AI_RAG_PATHS)} RAG paths",
        )
    )

    # 6. Lap-3 (Phase 6) — js_recon AI SDK showroom
    runners.append(
        await _start_site(
            make_js_recon_ai_sdk_app(),
            JS_RECON_AI_SDK_PORT,
            f"js-recon-ai-sdk showroom — {len(JS_RECON_AI_SDK_FIXTURES)} "
            f"fixture JS files exercising match_ai_sdk() across all 5 channels",
        )
    )

    # 7. ZAP Ajax Spider showroom — exercises browser-driven discovery
    runners.append(
        await _start_site(
            make_zap_ajax_showroom_app(),
            ZAP_AJAX_SHOWROOM_PORT,
            f"zap-ajax-spider showroom — {len(ZAP_AJAX_TEST_ENDPOINTS)} "
            f"discovery branches (XHR, pushState, cascade, GraphQL, auth-only)",
        )
    )

    # 8. Central ai_surface_recon module target — real chat/OpenAPI/models/Julius shapes
    runners.append(
        await _start_site(
            make_ai_surface_recon_app(),
            AI_SURFACE_RECON_TARGET_PORT,
            "ai-surface-recon target — chat shapes / OpenAPI / /v1/models / Julius "
            "(MCP runs separately on port "
            f"{MCP_TARGET_PORT})",
        )
    )

    log.info("=" * 60)
    log.info(f"Ready. {len(runners)} ports bound. Ctrl-C / SIGTERM to stop.")
    log.info("=" * 60)

    # Block until cancelled / signal
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            # No signal support (e.g. on Windows) — fall back to forever loop
            pass
    await stop.wait()

    log.info("Shutting down…")
    for runner in runners:
        await runner.cleanup()
    log.info("Bye.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
