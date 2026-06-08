# `ai_surface_target` — RedAmon guinea pig for AI surface recon

A purpose-built, **non-AI**, deterministic HTTP target that emits **every** surface signal the lap-1 AI recon catalogue (`recon/helpers/ai_signal_catalog.py`) tries to detect. Used to drive end-to-end tests that exercise:

- `port_scan` → AI port catalog (Phase 3)
- `nmap_scan` → AI runtime version regex (Phase 3)
- `http_probe` → AI header signature (Phase 4)
- `http_probe` → AI title regex (Phase 4)
- `http_probe` → disambiguate guard (Phase 4, regression)
- `domain_mixin` / `port_mixin` / `http_mixin` → Neo4j writes (Phases 2-4)
- `agentic/prompts/base.py` → text-to-cypher correctness (Phase 5)

## Purpose

A single Python `aiohttp` process binds to **18 ports** on `127.0.0.1` and serves deterministic responses that fire one specific recon detection per port (or per path on the showroom ports). The recon container scans the target via `network_mode: host`, the lap-1 hooks light up exactly the annotations we expect, and the e2e driver diffs the resulting Neo4j state against [expected_results.yaml](expected_results.yaml).

**No LLM, no model weights, no GPU**. The recon hooks are black-box fingerprints — they only look at ports, HTTP banners, headers, titles. The guinea pig just produces those signals; nothing intelligent happens inside the container.

Why this matters for the test suite:

- **Granular** — every signal in the catalogue gets its own endpoint, so a failure tells you exactly which detection broke.
- **Deterministic** — no real AI products, no model versions, no CDN drift. The catalogue maps 1:1 to fixed bytes the server returns.
- **Fast** — Python image (~80 MB) brings up in 2-3 seconds; full e2e scan finishes in under 2 minutes.
- **CI-friendly** — no GPU, no Internet egress, no auth flows, exit codes are pure data-driven.

## Architecture

```
                ┌─────────────────────────────────────────┐
                │  ai_surface_target  (Python asyncio)    │
                │                                         │
                │   ┌───────────────────────────────┐     │
                │   │ 16 AI-product port listeners  │     │
                │   │   :11434  ollama              │     │
                │   │   :6333   qdrant              │     │
                │   │   :19530  milvus              │     │
                │   │   :8080   open-webui (disamb) │     │
                │   │   ... 12 more ...             │     │
                │   └───────────────────────────────┘     │
                │                                         │
                │   ┌───────────────────────────────┐     │
                │   │ :9100 — header showroom       │     │
                │   │   /header/vllm                │     │
                │   │   /header/langchain           │     │
                │   │   /header/openai              │     │
                │   │   ... 20 framework variants   │     │
                │   └───────────────────────────────┘     │
                │                                         │
                │   ┌───────────────────────────────┐     │
                │   │ :9101 — title showroom        │     │
                │   │   /title/open-webui           │     │
                │   │   /title/flowise              │     │
                │   │   ... 18 product variants     │     │
                │   └───────────────────────────────┘     │
                │                                         │
                └─────────────────────────────────────────┘
                          ▲  network_mode: host
                          │  (recon container reaches 127.0.0.1:*)
                          │
                ┌─────────────────────────────────────────┐
                │  RedAmon recon (naabu + nmap + httpx)   │
                │  Writes annotations to Neo4j            │
                └─────────────────────────────────────────┘
                          │
                          ▼
                ┌─────────────────────────────────────────┐
                │  e2e driver  (next step, not in this    │
                │  artifact): scan + diff vs              │
                │  expected_results.yaml                  │
                └─────────────────────────────────────────┘
```

## File layout

```
ai_surface_target/
├── README.md               # this file
├── docker-compose.yml      # bring it up
├── Dockerfile              # python:3.11-slim + aiohttp
├── requirements.txt        # aiohttp pin
├── server.py               # asyncio multi-port server
├── ai_signals.py           # the catalogue of port/header/title variants
└── expected_results.yaml   # what Neo4j should look like after a scan
```

## What it serves

### Ports — bound for `port_scan` AI catalog (and `nmap` runtime regex)

Each port runs an `aiohttp` app that returns an HTML page on `/`. The `Server:` header is shaped so `nmap -sV` picks up the AI runtime regex.

**Unambiguous AI ports (11)** — `port_scan` MUST emit `Technology(category=ai-*)` with `detected_by='naabu-ai-port'`.

| Port  | Product       | Server banner       | Title in HTML       | Catalog → Tech    | nmap runtime |
|-------|---------------|---------------------|---------------------|-------------------|--------------|
| 11434 | ollama        | `Ollama/0.1.32`     | `Ollama`            | ai-runtime        | ollama       |
| 1234  | lm-studio     | `lm-studio/0.2.10`  | `LM Studio`         | ai-runtime        | —            |
| 4000  | litellm       | `LiteLLM/1.30`      | `LiteLLM`           | ai-proxy          | litellm      |
| 6333  | qdrant        | `qdrant/1.7.0`      | `Qdrant`            | ai-vector-db      | —            |
| 6334  | qdrant-grpc   | `qdrant/1.7.0`      | `Qdrant gRPC`       | ai-vector-db      | —            |
| 19530 | milvus        | `milvus/2.3.0`      | `Milvus`            | ai-vector-db      | —            |
| 9091  | milvus-metrics| `milvus/2.3.0`      | `Milvus Metrics`    | ai-vector-db      | —            |
| 7860  | gradio        | `gradio/4.0`        | `Gradio Demo`       | ai-frontend       | —            |
| 8188  | comfyui       | `ComfyUI/0.1.0`     | `ComfyUI`           | ai-frontend       | —            |
| 8501  | streamlit     | `Streamlit/1.30`    | `Streamlit App`     | ai-frontend       | —            |
| 3001  | anythingllm   | `AnythingLLM/0.2.0` | `AnythingLLM`       | ai-frontend       | —            |

**Disambiguate ports (2)** — `port_scan` MUST skip auto-promotion (`disambiguate: True` in the catalog). Phase 15 will promote them later via chat-shape probes. **One of them (8080) carries `<title>Open WebUI</title>` to prove `http_probe` can still promote a disambiguate port via the title regex.**

| Port  | Product           | Server banner          | Title in HTML  | Expected port catalog | nmap runtime |
|-------|-------------------|------------------------|----------------|-----------------------|--------------|
| 8001  | triton-or-vllm    | `triton-server/24.05`  | `Triton API`   | — (disambiguate)      | triton       |
| 8080  | open-webui        | `nginx/1.18`           | `Open WebUI`   | — (disambiguate);  http_probe title regex DOES fire | — |

**Catalog ports owned by Redamon services** — three catalog disambiguate ports are NOT bound here because Redamon services already publish them on the host:

| Catalog port | Catalog name              | Redamon owner                 |
|-------------:|---------------------------|-------------------------------|
| 8000         | vllm-or-chroma-or-langserve | kali-sandbox (MCP network-recon) |
| 8002         | triton-metrics            | kali-sandbox (MCP nuclei)     |
| 3000         | bentoml-or-langflow       | webapp (the UI itself)        |

We lose the explicit disambiguate-skipped test for these three ports, but the disambiguate logic is identical for every catalog entry — it's still validated end-to-end by 8001 and 8080.

**Off-catalog vllm banner port (1)** — to preserve the `vllm` nmap-regex test (otherwise tied to port 8000), the vllm `Server:` banner moves to **port 18000** (outside the AI port catalog). `port_scan` doesn't tag it (not in catalog) but `nmap -sV` still reads `Server: vllm/0.4.1` and sets `Service.ai_runtime_version='vllm'`.

| Port  | Product           | Server banner          | Title in HTML  | Expected port catalog | nmap runtime |
|-------|-------------------|------------------------|----------------|-----------------------|--------------|
| 18000 | vllm-banner-only  | `vllm/0.4.1`           | `vLLM API`     | — (off-catalog)       | vllm         |

### Port 9100 — header showroom (20 variants)

`GET /header/<framework>` on port 9100 returns an HTML page **plus** the AI header for that framework. The recon project's `httpxPaths` is configured to probe every `/header/<framework>` path, so `http_probe`'s AI header scan should annotate each one as `BaseURL(is_ai_framework_detected=true, ai_framework_name=<framework>)`.

| Path                | Header sent                         | Expected framework             | Category          |
|---------------------|-------------------------------------|--------------------------------|-------------------|
| /header/vllm        | `x-vllm-cache-hit: 1`               | vllm                           | ai-runtime        |
| /header/tgi         | `x-tgi-request-id: stub`            | tgi                            | ai-runtime        |
| /header/tei         | `x-tei-version: 1.2`                | text-embeddings-inference      | ai-runtime        |
| /header/bentoml     | `x-bentoml-version: 1.1.0`          | bentoml                        | ai-runtime        |
| /header/baseten     | `x-baseten-deployment: dep-abc`     | baseten                        | ai-runtime        |
| /header/modal       | `x-modal-task-id: task-xyz`         | modal                          | ai-runtime        |
| /header/replicate   | `x-replicate-prediction: pred-123`  | replicate                      | ai-runtime        |
| /header/runpod      | `x-runpod-pod-id: pod-456`          | runpod                         | ai-runtime        |
| /header/langchain   | `x-langchain-run-id: run-789`       | langchain                      | ai-framework      |
| /header/llamaindex  | `x-llamaindex-trace-id: trace-abc`  | llamaindex                     | ai-framework      |
| /header/langfuse    | `langfuse-trace-id: lf-trace-1`     | langfuse                       | ai-framework      |
| /header/mcp         | `x-mcp-server-name: stub`           | mcp                            | ai-framework      |
| /header/litellm     | `x-litellm-model-id: gpt-4`         | litellm                        | ai-proxy          |
| /header/helicone    | `x-helicone-cache: HIT`             | helicone                       | ai-proxy          |
| /header/portkey     | `x-portkey-cache: x`                | portkey                        | ai-proxy          |
| /header/omniroute   | `x-omniroute-trace: x`              | omniroute                      | ai-proxy          |
| /header/cloudflare  | `cf-aig-cache-status: hit`          | cloudflare-ai-gateway          | ai-proxy          |
| /header/together    | `together-request-id: req-1`        | together                       | ai-proxy          |
| /header/openai      | `openai-organization: org-abc`      | openai                         | ai-sdk-client     |
| /header/anthropic   | `anthropic-version: 2023-06-01`     | anthropic                      | ai-sdk-client     |

### Port 9101 — title showroom (18 variants)

`GET /title/<product>` returns HTML with `<title>{product display name}</title>`. Configured via `httpxPaths` so `http_probe`'s AI title regex fires on each.

`open-webui`, `librechat`, `anythingllm`, `flowise`, `langflow`, `dify`, `comfyui`, `gradio`, `streamlit`, `chatgpt-clone`, `hf-chat-ui`, `lobechat`, `nextchat`, `sillytavern`, `jan`, `h2ogpt`, `privategpt`, `quivr`.

### Port 9103 — endpoint AI classifier showroom (Lap-2)

Serves an HTML index at `/` linking to **21 catalogued AI paths** plus **8 unambiguous RAG paths**. Each link carries query-string params: one or two prompt-named (`messages`, `prompt`, `system`, `contents`, `input`, `inputs`, `instructions`, `suffix`, `arguments`, `query`) and one control name (`model`, `temperature`, `max_tokens`, `assistant_id`, `method`, etc.). This exercises the **resource_enum AI classifier** end-to-end:

| Catalogued path | `ai_interface_type` stamped |
|---|---|
| `/v1/chat/completions`, `/v1/messages`, `/api/chat`, `/v1beta/models/*:generateContent`, `/v2/chat`, `/v1/sonar` | `llm-chat` |
| `/v1/completions`, `/v1/fim/completions`, `/api/generate` | `llm-completion` |
| `/v1/embeddings`, `/api/embed`, `/v2/embed` | `llm-embedding` |
| `/v1/threads/<id>/runs`, `/v1/responses/<id>/input_items` | `llm-tool-call` |
| `/generate_stream`, `/agents/<id>/stream` | `sse-stream` |
| `/mcp`, `/api/mcp`, `/sse`, `/tools/list` | `mcp` |
| `/graphql` | `llm-graphql` |
| `/v1/files`, `/v1/uploads`, `/v1/vector_stores(/<id>(/search)?)?`, `/v1/assistants`, `/vectors/upsert`, `/v1/objects`, `/collections/<name>/points/search` | RAG ingest (`is_ai_rag_ingest=true`) |

The classifier reads existing Endpoint + Parameter nodes from the graph after Katana finishes — no probe traffic of its own. Required project settings: `katanaEnabled=true`, `resourceEnumAiClassifierEnabled=true` (default on).

### Port 9105 — ZAP Ajax Spider showroom

Serves a deliberately SPA-shaped page where every endpoint exists behind a
different runtime discovery branch — none are reachable from static HTML
alone. Lets you verify, end-to-end, that ZAP Ajax Spider can:

- Click buttons that fire JS `fetch()` calls (`/api/users/list`)
- Resolve runtime-templated URLs (`` `/api/projects/${id}` ``)
- Follow `history.pushState` SPA route changes (`/spa/dashboard` → `/api/dashboard-data`)
- Cascade-discover: click button A → reveals button B → B fetches `/api/secret-page`
- POST to GraphQL (`/graphql`)
- Submit forms with generated inputs (`/api/search?q=...`)
- Honor `logoutAvoidance` — must NOT click `/api/auth/logout` (anchor text "Sign out")
- Filter static-asset noise via `excludePatterns` (`/static/logo.png`)
- Inject custom headers via Replacer — auth-gated endpoints (`/api/admin/users`,
  `/api/admin/audit-log`) only appear when an `Authorization` header arrives

| Endpoint                  | Method | How it's discovered                                       | Static crawlers (Katana/Hakrawler) | ZAP Ajax Spider |
|---------------------------|--------|-----------------------------------------------------------|------------------------------------|-----------------|
| `/about`                  | GET    | Plain `<a href>` anchor                                   | ✓                                  | ✓               |
| `/api/users/list`         | GET    | `fetch()` inside button `onclick`                         | ✗                                  | ✓               |
| `/api/projects/42`        | GET    | Template literal `` `/api/projects/${id}` ``              | ✗                                  | ✓               |
| `/spa/dashboard`          | GET    | `history.pushState` route change                          | ✗                                  | ✓               |
| `/api/dashboard-data`     | GET    | XHR after pushState                                       | ✗                                  | ✓               |
| `/api/secret-page`        | GET    | Cascade — second button revealed after first click        | ✗                                  | ✓               |
| `/graphql`                | POST   | `fetch` with POST body from onclick                       | ✗                                  | ✓               |
| `/api/search`             | GET    | `form.onsubmit` triggers XHR with query string            | ✗                                  | ✓               |
| `/api/auth/logout`        | GET    | `<a href>` with text "Sign out"                           | ✓                                  | ✗ (avoided)     |
| `/static/logo.png`        | GET    | `<img src>` static asset                                  | ✓                                  | ✓ (filter it)   |
| `/api/me`                 | GET    | Always fetched on load — returns `x-redamon-authed` header if `Authorization` was injected | ✗ | ✓ |
| `/api/admin/users`        | GET    | JS-injected `<a>` rendered ONLY when `/api/me` reported authed | ✗                             | ✓ (auth-only)   |
| `/api/admin/audit-log`    | GET    | Cascade fetch after `/api/me` returned authed             | ✗                                  | ✓ (auth-only)   |

Manual smoke-check:
```bash
curl -s http://127.0.0.1:9105/ | head -20            # HTML index with buttons
curl -s http://127.0.0.1:9105/api/me -i | grep -i x-redamon-authed   # → "false" (no Authorization)
curl -s http://127.0.0.1:9105/api/me -H "Authorization: Bearer test" -i | grep -i x-redamon-authed  # → "true"
curl -s http://127.0.0.1:9105/api/admin/users -H "Authorization: Bearer test"  # → JSON 200
curl -s http://127.0.0.1:9105/api/admin/users -i | head -1            # → 403 without auth
```

End-to-end recon test:
1. Create a RedAmon project, set target URL `http://127.0.0.1:9105`
2. Run HTTP Probing — confirms the BaseURL node
3. Enable ZAP Ajax Spider, leave seed mode = `base_urls`
4. Run partial recon
5. Open the graph — you should see Endpoints for every row in the table marked ✓ under "ZAP Ajax Spider"
6. **Auth test**: paste `Authorization: Bearer testtoken` into the ZAP Custom Headers field, re-run
7. The graph should now also contain `/api/me`, `/api/admin/users`, `/api/admin/audit-log` — endpoints invisible to the unauthenticated crawl

Compare with Katana on the same target — it will find only `/about`, `/api/auth/logout`, and `/static/logo.png` (the three things visible in static HTML).

### Port 9104 — JS Recon AI SDK showroom (Lap-3 / Phase 6)

Serves an HTML index at `/` whose `<head>` carries `<script src='/static/...'>` tags for **23 fixture JS files**. Katana follows the script tags; js_recon downloads each file; `match_ai_sdk()` in [recon/helpers/ai_signal_catalog.py](../../recon/helpers/ai_signal_catalog.py) scans the content and emits `JsReconFinding` nodes with `finding_type` ∈ `{ai-sdk-client, ai-sdk-key-literal, ai-sdk-browser-allowed, ai-frontend-detected, ai-provider-url}`. The Phase 6 mixin then enriches matching `Secret` nodes (from the legacy `JS_SECRET_PATTERNS` pass) with the `ai_provider` property.

Every fixture is engineered to exercise one specific detection branch. Together they cover every code path in `match_ai_sdk()`:

| Fixture | Detection branch exercised |
|---|---|
| `openai-leaked.js` | OpenAI SDK import + constructor-context key (suppresses prefix duplicate) + dangerouslyAllowBrowser + base URL |
| `anthropic-direct.js` | Anthropic SDK + Anthropic-format key + terser `!0` truthy form + base URL |
| `gemini-with-context.js` | **Gemini disambiguation ESCALATES** (AIzaSy* + `@google/generative-ai` import + Gemini base URL → critical) |
| `google-maps-key.js` | **Gemini disambiguation DOWNGRADES** (AIzaSy* without any Gemini context → medium, "likely Maps/Firebase") |
| `langchain-stack.js` | Multi-vendor LangChain ecosystem imports (core, openai, anthropic, langgraph) |
| `vercel-ai-multi.js` | Vercel AI SDK sub-imports + multiple provider packages |
| `vector-dbs.js` | Pinecone + Qdrant + Chroma + Weaviate SDK clients + Pinecone constructor key |
| `mcp-client.js` | MCP SDK + reference server imports |
| `next-public-leak.js` | `NEXT_PUBLIC_OPENAI_API_KEY` env-var hydration (framework-public leak pattern) |
| `bearer-fetch.js` | Hand-written `Authorization: Bearer <gsk_...>` header (bypasses SDK entirely) |
| `anthropic-header.js` | Anthropic `x-api-key` header literal (Anthropic-specific, not Bearer) |
| `openwebui-frontend.js` | Open WebUI markers (WEBUI_NAME, WEBUI_VERSION) — http_probe Wappalyzer pass cannot see these in async-loaded chunks |
| `gradio-frontend.js` | Gradio markers (customElements.define + window.gradio_config + window.__gradio_mode__). Single-finding dedup test |
| `flowise-frontend.js` | Flowise (chatflowid + /api/v1/prediction route) |
| `sillytavern-frontend.js` | SillyTavern markers |
| `next-data-blob.js` | JSON-stringified `"dangerouslyAllowBrowser":true` (the loosened browser-flag regex catches the quoted-key form found in `__NEXT_DATA__`) |
| `minified-vendor.js` | Real minified shape — no whitespace, `!0`, comma-fused, mixed quotes |
| `huggingface-inference.js` | HfInference positional-arg constructor + hf_ token + Inference API base URL |
| `langfuse-tracing.js` | Langfuse client + secretKey constructor |
| `openrouter-bearer.js` | OpenRouter Bearer (multi-provider router credit drain) |
| `secret-dup-test.js` | **Mixin dedup/enrichment test** — the legacy JS_SECRET_PATTERNS scan AND our AI SDK scan both catch the same key. The mixin enriches the Secret with `ai_provider` rather than emit a parallel taxonomy |
| `negative-jquery.js` | **Negative case** — clean jQuery stub. Must produce ZERO ai-sdk-* findings (regex over-reach regression) |
| `negative-stripe.js` | **Negative case** — Stripe `sk_live_` + AWS `AKIA...` literals. Must NOT trip the OpenAI `sk-` prefix patterns |

Required project settings: `jsReconEnabled=true`, `jsReconRegexPatterns=true` (for the dedup-enrichment test), `jsReconAiSdkDetectionEnabled=true` (default on), `katanaEnabled=true` (to discover the script tags).

Manual smoke-check:
```bash
curl -s http://127.0.0.1:9104/ | head -20          # HTML index
curl -s http://127.0.0.1:9104/static/openai-leaked.js | head -10
curl -s http://127.0.0.1:9104/static/gemini-with-context.js
```

End-to-end validation (against the live recon image, no Neo4j required):
```bash
docker run --rm --entrypoint python3 \
  -v "$(pwd)/../../:/work:ro" -w /work \
  redamon-recon:latest -c "
from recon.helpers.ai_signal_catalog import match_ai_sdk
import urllib.request
for f in ['openai-leaked', 'gemini-with-context', 'negative-jquery']:
    js = urllib.request.urlopen(f'http://host.docker.internal:9104/static/{f}.js').read().decode()
    findings = match_ai_sdk(js)
    print(f'{f}: {len(findings)} findings')
    for x in findings: print(' ', x['category'], x['sdk_name'])
"
```

## How to bring up

```bash
cd guinea_pigs/ai_surface_target
docker compose up -d --build
# Wait ~3 seconds; healthcheck probes :11434
docker compose ps
# STATUS should be "Up (healthy)" within ~15 s
```

Smoke-check from the host:

```bash
curl -sI http://127.0.0.1:11434/ | head -3              # Server: Ollama/0.1.32
curl -s  http://127.0.0.1:8080/ | grep -i title         # <title>Open WebUI</title>
curl -sI http://127.0.0.1:9100/header/vllm | grep -i vllm  # x-vllm-cache-hit: 1
curl -s  http://127.0.0.1:9101/title/flowise | grep -i flowise  # <title>Flowise</title>
```

## How to tear down

```bash
docker compose down
```

The container holds no state — restart anytime.

## Conflict with the Phase 6 lab fixture

[`agentic/labs/ai-surface/`](../../agentic/labs/ai-surface/) (the realism-smoke lab with real Ollama + Open WebUI + Chroma) binds to several of the same ports as this guinea pig (11434, 8080, 8000). **Bring up one at a time.** The two fixtures serve different purposes:

| Fixture | Purpose | Pull size | Bring-up |
|---|---|---|---|
| `ai_surface_target/` (this) | Granular correctness — every catalog signal | ~80 MB | ~3 s |
| `agentic/labs/ai-surface/` | Realism smoke — real product surfaces | ~4 GB | ~5 min |

Both stay in the tree because they answer different questions: the guinea pig answers "does the catalog logic work?", the lab answers "does it work against the real wire?".

## Why no real LLM

The lap-1 recon hooks never invoke an LLM. They only look at:
- TCP port numbers
- HTTP response headers (just the names)
- HTML `<title>` text
- nmap `Server:` banner text
- DNS record values (TXT/NS) — *not exercised by this guinea pig; see caveats*

A Python aiohttp process producing the right bytes is indistinguishable from a real Ollama for these checks. Skipping the LLM saves several GB of disk, eliminates GPU requirements, and makes the test deterministic.

The Phase 6 lab fixture keeps a real Ollama around for the times we need to verify the actual wire (httpx CLI flag drift, real product fingerprint changes). The guinea pig is for **correctness**, the lab is for **realism** — different questions, both worth answering.

## Caveats / limits

- **No DNS hint coverage**. Phase 2 (`Subdomain.ai_service_hint` via TXT/NS records) needs a DNS server, not an HTTP server. The Phase 2 hooks already have parameterised unit tests over the full catalogue; e2e DNS coverage would need a `dnsmasq` sidecar and a `.lab.invalid` zone, which is a v1 extension.
- **No favicon-hash coverage**. `AI_FAVICON_HASHES` is empty until Phase 15 vendors the Julius catalogue. The guinea pig serves a stub favicon but no AI hash match fires.
- **No `Wappalyzer` fingerprint coverage**. The `HTTP_PROBE_AI_WAPPALYZER_ENABLED` toggle is wired but no AI fingerprints ship this lap. Tested via toggle-state only.

## Next step

Build the e2e driver (separate artifact at `recon/tests/test_ai_e2e_against_guinea_pig.py` or `guinea_pigs/ai_surface_target/scripts/e2e_driver.py`) that:

1. Brings up the target via `docker compose up -d`.
2. Creates a RedAmon project with `ipMode=true`, `targetIps=['127.0.0.1']`, the 18 ports in `naabuCustomPorts`, and the 38 paths in `httpxPaths`.
3. Triggers a full recon scan.
4. Polls until completion.
5. Queries Neo4j; diffs against [expected_results.yaml](expected_results.yaml).
6. Reports per-signal PASS/FAIL.

The expected-results YAML is committed alongside this README and is the **contract** the driver tests against.

---

## Central `ai_surface_recon` module — live 100% validation

The files above validate the **distributed** AI hooks via a full recon scan. The
**central** `ai_surface_recon` module (active chat/MCP/OpenAPI/Julius/vector-DB
probing) is validated by a self-contained harness that runs the module's real
functions against real servers — no mocks. This closes the gaps unit tests
cannot: live HTTP, the official `mcp` SDK handshake + `tools/list`, real YARA on
real tool manifests, real `prance`/`jq` parsing, the real Julius matcher against
the vendored packs, and the vector-DB confirmation read.

Files:
- [`ai_surface_recon_endpoints.py`](ai_surface_recon_endpoints.py) — stdlib HTTP
  target: every chat shape (OpenAI / Anthropic / Ollama / Gemini / LangServe /
  SSE), `/openapi.json` + `/.well-known/ai-plugin.json` + `/swagger.json`,
  `/v1/models` + `/api/tags`, Julius signals (`GET /` "Ollama is running"),
  Qdrant `/collections`, and the MCP `401`/version-mismatch branches.
- [`mcp_poison_server.py`](mcp_poison_server.py) — a **real** MCP Streamable-HTTP
  server (FastMCP) with a benign tool plus a tool-poisoning tool, a
  data-exfiltration tool, and an annotation-mismatch tool, so the static YARA
  analysis and heuristics have genuine targets.
- [`validate_ai_surface_recon.py`](validate_ai_surface_recon.py) — the harness:
  starts the HTTP target (+ Qdrant port 6333), launches the MCP server as a
  subprocess, then exercises every workload and asserts. Exit 0 == 100%.

Run it inside the recon image:

```bash
docker run --rm --entrypoint sh \
  -v "$PWD/recon:/app/recon:ro" -v "$PWD/graph_db:/app/graph_db:ro" \
  -v "$PWD/guinea_pigs:/app/guinea_pigs:ro" -w /app redamon-recon:latest -c '
  pip install -q pyyaml yara-python jq prance "openapi-spec-validator>=0.7.1,<0.8" "mcp>=1.27" uvicorn &&
  python3 guinea_pigs/ai_surface_target/validate_ai_surface_recon.py'
```

(The `pip install` is only needed until the recon image is rebuilt with the new
`recon/requirements.txt` deps; after `docker compose --profile tools build recon`
the harness runs with no install step.)

Current status: **36/36 checks pass** — every chat family + streaming + latency,
OpenAPI tools/vision/schema-ref/model-family, Julius service detection +
specificity ranking, Qdrant read confirmation, the full MCP path (real SDK
handshake, 4-tool enumeration, rug-pull hash, tool-poisoning + exfiltration +
annotation-mismatch findings with OWASP-LLM/ATLAS mapping, auth-required and
version-mismatch branches), and the integrated `run_ai_surface_recon` assembly.
The only path not covered here is the Neo4j Cypher in the graph mixin (needs a
live database); the harness validates everything up to the graph write.

---

## Full-scan coverage of the central `ai_surface_recon` module (ports 9106 + 9107)

Earlier laps' showrooms only feed the *distributed* AI hooks (http_probe / port
catalogue / resource_enum classifier / js_recon) — they serve no-op/banner
responses, so the **central ai_surface_recon module's active probes would
confirm nothing** against them. To make a full scan with the **AI / LLM Surface
Recon** preset trigger every check end-to-end, the dockerized target now also
runs the real central-module surfaces (started by [`run_target.py`](run_target.py)):

- **Port 9106 — central AI surface** ([`make_ai_surface_recon_app`](server.py),
  reusing the validated bodies in
  [`ai_surface_recon_endpoints.py`](ai_surface_recon_endpoints.py)): real chat
  shapes (OpenAI / Anthropic / Ollama / Gemini / LangServe / SSE), `/openapi.json`
  + `/.well-known/ai-plugin.json` + `/v3/api-docs`, `/v1/models` + `/api/tags`,
  and a Julius-matching `/` ("Ollama is running" + linked AI paths). Emits an
  `x-vllm-version` header so http_probe flags it as an AI surface, which makes it
  an ai_surface_recon candidate.
- **Port 9107 — real MCP server** ([`mcp_poison_server.py`](mcp_poison_server.py),
  FastMCP Streamable-HTTP): a benign tool plus a tool-poisoning, a
  data-exfiltration, and an annotation-mismatch tool, so the MCP handshake,
  `tools/list` enumeration, and static YARA analysis all fire. A discoverable
  `x-mcp-version`-headed `GET /` makes it an ai_surface_recon candidate; the
  protocol lives at `/mcp`.
- **Port 6333 — Qdrant** (existing listener, now serves `/collections`): the
  vector-DB confirmation read fires.

So a full scan against this target with the AI preset triggers the complete
chain: distributed AI hooks **and** the central module's chat-shape probes, MCP
handshake + tool-poisoning, OpenAPI/manifest parsing, model-family guess, Julius
fingerprint, and vector-DB confirmation.

**Verified end-to-end (8/8):** running the real `ai_surface_recon` module
against this target confirms 1 chat endpoint, 1 MCP server (4 tools, 3
tool-poisoning findings), 1 vector DB, the model family, the OpenAPI tool-schema
ref, and the Julius service. (`requirements.txt` now includes `mcp` + `uvicorn`
for the MCP server; rebuild the image with `docker compose up -d --build`.)
