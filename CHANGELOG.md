# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.9.1] - 2026-04-13

### Added

- **Partial Recon** -- run any single tool from the recon pipeline independently without re-running the entire scan. Every tool section header and Workflow View node has a play button that opens a dedicated modal. The modal shows existing graph data counts (subdomains, IPs, ports, BaseURLs, endpoints), accepts custom targets (subdomains, IPs, ports, URLs, JS file uploads depending on the tool), and launches the tool in isolation. Results are merged back into the Neo4j graph via `MERGE` operations -- duplicates are updated, not recreated. All 20 pipeline tools are supported. Key features:
  - **Graph-aware targeting** -- the modal queries Neo4j for existing data relevant to each tool and displays counts in the Input panel
  - **Custom target injection** -- add subdomains, IPs (IPv4/IPv6/CIDR), ports, or URLs with real-time validation (scope checks, format validation, CIDR range restrictions)
  - **Include graph targets toggle** -- choose whether to scan existing graph data alongside custom inputs, or only scan custom targets
  - **Attach-to dropdowns** -- link custom IPs to a specific subdomain or custom URLs to a specific BaseURL for correct graph relationships
  - **Nuclei settings overrides** -- toggle CVE Lookup, MITRE ATT&CK, and Security Checks independently from project settings
  - **API key warnings** -- the modal checks user settings and warns about missing API keys with impact descriptions per tool
  - **UserInput node tracking** -- custom inputs create UserInput nodes in the graph linked to results via PRODUCED relationships for traceability
  - **Project settings inheritance** -- partial recon runs use the project's saved settings (timeouts, wordlists, thread counts, API keys, proxy, Tor) automatically

---

## [3.9.0] - 2026-04-11

### Added

- **Workflow data node count badges** -- each data node in the Workflow View (Subdomain, Port, BaseURL, etc.) now shows a small badge with the total number of graph nodes of that type. Clicking the badge opens an overlay listing all node names. Uses the graph page's React Query cache for zero extra API calls

---

## [3.8.0] - 2026-04-10

### Added

- **9 new AI agent tools** -- major expansion of the agent's offensive toolkit, all exposed as dedicated MCP tools with full CLI argument passthrough:
  - **execute_httpx** -- HTTP probing and fingerprinting (status codes, titles, server headers, tech detection, redirect following)
  - **execute_subfinder** -- passive subdomain enumeration via OSINT sources (certificate transparency, DNS datasets, search engines). No traffic to target
  - **execute_gau** -- passive URL discovery from Wayback Machine, Common Crawl, AlienVault OTX, and URLScan archives. No traffic to target
  - **execute_jsluice** -- JavaScript static analysis for hidden API endpoints, URL paths, query parameters, and secrets (AWS keys, API tokens). Local file analysis only
  - **execute_katana** -- web crawling and endpoint/URL discovery with JavaScript parsing and known-file enumeration (robots.txt, sitemap.xml)
  - **execute_amass** -- OWASP Amass subdomain enumeration and network mapping (passive + active modes, ASN intel)
  - **execute_arjun** -- HTTP parameter discovery by brute-forcing ~25,000 common parameter names (GET, POST, JSON, XML)
  - **execute_ffuf** -- web fuzzing for hidden directories, files, virtual hosts, and parameters using FUZZ keyword injection
  - **execute_subfinder** -- passive subdomain discovery from third-party OSINT sources

- **URLScan API key integration** -- optional API key for enriching `execute_gau` results with URLScan archived data. Configured in Settings, auto-injected into GAU's `~/.gau.toml` config at runtime

- **Tool Phase Matrix expansion** -- all 9 new tools added to the agent's tool-phase permission matrix with default phase assignments (informational + exploitation). Configurable per-project in the Tool Matrix UI

- **Stealth mode rules for all new tools** -- each new tool has calibrated stealth-mode restrictions:
  - No restrictions: `execute_subfinder`, `execute_gau`, `execute_jsluice` (passive/local only)
  - Heavily restricted: `execute_httpx` (single target, rate-limited), `execute_katana` (depth 1, rate-limited), `execute_amass` (passive mode only)
  - Forbidden: `execute_arjun`, `execute_ffuf` (inherently noisy brute-force tools)

- **Tool registry documentation** -- detailed usage guides for all 9 tools in the agent's tool registry, including argument formats, examples, and when-to-use guidance

- **Graph empty state component** -- new `GraphEmptyState` component replaces the plain text "No data found" message on the graph canvas

### Changed

- **15 new pentesting tools in kali-sandbox** -- major expansion of the agent's kali_shell toolkit, all accessible as Type A tools (no dedicated MCP wrapper needed):
  - **Web/infra scanning:** nikto (web server misconfiguration scanner), whatweb (1800+ plugin tech fingerprinter), testssl.sh (SSL/TLS audit), commix (command injection detection/exploitation), SSTImap (server-side template injection)
  - **DNS:** dnsrecon (zone transfers, SRV records, DNSSEC walk), dnsx (fast bulk DNS resolution, ProjectDiscovery pipeline)
  - **Windows/AD:** enum4linux-ng (SMB/RPC enumeration with JSON output), netexec/nxc (multi-protocol exploitation -- SMB, WinRM, LDAP, MSSQL, RDP), bloodhound-python (AD relationship collection), certipy-ad (AD-CS ESC1-ESC13 attacks), ldapdomaindump (quick LDAP dumps)
  - **Secrets/passwords:** gitleaks (git repo secret scanning), hashid (hash type identification), cewl (custom wordlist generation from target websites)

- **kali_shell timeout increased** -- from 120s to 300s (5 min), enabling tools like nikto, testssl.sh, and bloodhound-python that need more than 2 minutes. Updated across MCP server, tool registry, dev docs, and wiki

- **Kali sandbox Dockerfile** -- installs subfinder, katana, jsluice (with CGO for tree-sitter), amass, gau, and paramspider. Adds arjun to Python requirements

- **kali_shell tool description** -- restructured into categorized sections (Exploitation, Password cracking, Web/infra, DNS, Windows/AD, API/GraphQL, Secrets, Tunneling) with usage examples for every tool. Added all 15 new tools, restored missing entries (dig, nslookup, smbclient, ngrok, chisel), and expanded the "Do NOT use" list to cover all 17 dedicated MCP tools

- **Rules of Engagement (ROE)** -- `execute_ffuf` added to brute_force category for ROE blocking

- **redamon.sh update logic** -- agent container now always rebuilds (not just restarts) when any `agentic/` file changes, since source code is baked into the image without volume mount

- **Settings page** -- removed "AI Agent" badge from Censys, FOFA, AlienVault OTX, Netlas, VirusTotal, ZoomEye, and Criminal IP API key fields (these keys are used by Recon Pipeline only, not the agent)

---

## [3.7.0] - 2026-04-09

### Added

- **RAG-Enhanced Knowledge Base** -- the `web_search` tool now queries a local vector index (FAISS) and graph database (Neo4j) before falling back to Tavily. Curated security datasets are embedded, indexed, and searched locally with a 6-stage hybrid retrieval pipeline (vector search + keyword search, RRF fusion, cross-encoder reranking, MMR diversity filtering). When the KB produces high-confidence results, Tavily is skipped entirely. When confidence is low, KB and Tavily results are merged automatically

- **Seven security data sources** -- tool_docs (agent skill playbooks), GTFOBins (Unix priv-esc), LOLBAS (Windows LOLBins), OWASP WSTG (web testing methodology), ExploitDB (exploit database), NVD (CVEs via REST API), and Nuclei templates. Organized in four ingestion profiles: `cpu-lite` (~900 chunks, ~15 min on CPU), `lite` (~47k chunks), `standard` (+ NVD), `full` (+ Nuclei)

- **Smart ingestion on install** -- `./redamon.sh install` detects GPU and API key availability. On CPU without an API key, shows an interactive prompt with estimated times per source and lets the user choose quick start (~15 min) or full ingestion (~4 hours). With GPU or API key, ingests all sources automatically

- **API embedding support** -- configure `KB_EMBEDDING_USE_API=true` in `.env` to use any OpenAI-compatible embedding API (OpenAI, Ollama, Together AI, Azure, vLLM, LiteLLM) instead of local sentence-transformers. Speeds up ingestion from hours to minutes on CPU-only machines. See `.env.example` for configuration

- **Incremental updates** -- two-layer content-hash dedup (file-level + chunk-level) makes re-runs near-instant. Only new or modified content is re-embedded. NVD uses `lastModStartDate` for incremental delta fetches

- **Prompt injection defense** -- KB content is untrusted (sourced from public repos). Three-layer protection: content sanitization (strips role/boundary markers), length capping, and untrusted content framing with explicit LLM instructions

- **Dimension mismatch guard** -- switching embedding models (local vs API) produces different vector dimensions. The ingestion pipeline detects mismatches and requires `--rebuild` to prevent silent corruption

- **Makefile for KB management** -- `knowledge_base/Makefile` with targets for build, update, rebuild, stats, and cleanup. All `redamon.sh` KB commands use `MODE=docker` to run inside the agent container

### Changed

- **Agent Dockerfile** -- pre-downloads embedding model (`intfloat/e5-large-v2`, ~1.3 GB) and cross-encoder reranker (`BAAI/bge-reranker-base`, ~568 MB) at build time. KB source code set to read-only via `chmod`

- **docker-compose.yml** -- agent service now loads `.env` via `env_file` (optional). KB data volume mounted read-write for ingestion. Added opt-in `kb-refresh` sidecar for automated daily/weekly/monthly updates

- **Bash compatibility fix** -- replaced `${confirm,,}` (Bash 4+ only) with `=~ ^[Yy]$` regex in `cmd_clean()` for compatibility with older Bash versions and macOS

---

## [3.6.2] - 2026-04-06

### Fixed

- **Pipeline crash resilience** -- wrapped all recon pipeline phase calls (`run_http_probe`, `run_resource_enum`, `run_vuln_scan`, `run_mitre_enrichment`) in try/except in both domain and IP mode. A failing phase now logs the error, records it in `metadata.phase_errors`, and continues to the next phase instead of killing the entire pipeline
- **JS Recon analyzer crash isolation** -- added per-file try/except in all JS Recon analyzer loops (`run_patterns`, `run_framework_analysis`, `discover_and_analyze_sourcemaps`, `detect_dependency_confusion`, `extract_endpoints`, `detect_frameworks`, `detect_dom_sinks`). One malformed JS file no longer crashes the entire analyzer batch
- **Docker API 500 crash** -- added `APIError` handling alongside existing `NotFound` catches in all four container status functions (`get_status`, `get_gvm_status`, `get_github_hunt_status`, `get_trufflehog_status`) and all four SSE log streaming functions. A Docker daemon 500 error during container inspection no longer crashes the SSE stream with an unhandled `ExceptionGroup`

### Added

- **Crash resilience test suite** -- new `recon/tests/test_crash_resilience.py` with 17 tests (12 local + 5 Docker-dependent) verifying that poisoned/malformed input in any analyzer batch is caught, logged, and skipped without affecting other items in the batch

---

## [3.6.1] - 2026-04-05

### Fixed

- **WorkflowView build failure** -- aligned `onSave` prop type from `() => void` to `() => Promise<void>` to match `WorkflowNodeModal`'s expected signature

---

## [3.6.0] - 2026-04-05

### Added

- **Recon Pipeline Workflow View** -- interactive visual diagram of the entire reconnaissance pipeline, available as an alternative to the tabbed settings interface. Toggle between Tab View and Workflow View using the icons at the left edge of the Recon Pipeline tab group:
  - **Three-band layout** -- tools in the center horizontal row, consumed data nodes above, produced data nodes below, with dashed animated edges showing data flow direction
  - **22 tool nodes** covering all pipeline stages: Discovery (Subdomain Discovery, URLScan, Uncover), OSINT (Shodan, OSINT Enrichment), Port Scanning (Naabu, Masscan, Nmap), HTTP Probing (Httpx), Resource Enumeration (Katana, Hakrawler, jsluice, FFuf, GAU, ParamSpider, Kiterunner, Arjun), JS Recon, Vulnerability Scanning (Nuclei), CVE & MITRE (CVE Lookup, MITRE), Security Checks
  - **18 data node types** as visible convergence points (Domain, Subdomain, IP, DNSRecord, Port, Service, BaseURL, Endpoint, Parameter, Header, Certificate, Technology, Vulnerability, CVE, MitreData, Capec, Secret, ExternalDomain), colored by category (identity, network, web, technology, security, external)
  - **Chain-breaking detection** -- when a tool is enabled but its required input data has no active producer, the data node turns red (starved) and the tool shows an amber warning with a detailed tooltip. Uses "true source" algorithm that excludes tools recycling their own output (e.g., Katana consumes and produces BaseURL)
  - **Click highlighting** -- click any tool or data node to highlight it and all directly connected elements; non-connected edges dim for visual clarity
  - **Inline enable/disable toggles** on each tool node, with changes immediately reflected in both views
  - **Settings modal** -- click the gear icon on any tool to open the full settings panel (identical to Tab View) in a modal overlay
  - **Shared state** -- both views read and write the same form data with zero re-fetching; React Query cache untouched
  - **Code-split** -- Workflow View loaded via `next/dynamic` so React Flow only loads when the workflow toggle is activated

- **Verified node mapping** -- deep-audited every tool's consumes/produces against the actual recon pipeline code. Fixed 15+ inaccuracies in the node mapping (added missing ExternalDomain outputs to 8 tools, corrected Shodan/Masscan/Nmap/Httpx input dependencies, added Technology output to Shodan/OSINT Enrichment/JsRecon, removed incorrect Service/Domain consumption from multiple tools)

### Changed

- **Node mapping corrections** -- updated `nodeMapping.ts` with verified produces/consumes for all 22 recon tools. Affects both the workflow diagram edges and the NodeInfoTooltip in tab mode

---

## [3.5.1] - 2026-04-05

### Added

- **WPScan WordPress scanner** -- new `execute_wpscan` agentic tool (Type B MCP) for WordPress vulnerability scanning. Detects vulnerable plugins, themes, users, config backups, and misconfigurations. 600s timeout, HEAVILY RESTRICTED in stealth mode, added to brute_force RoE category. Available in informational and exploitation phases.

### Fixed

- **Graph 3D rendering** -- removed LOD (Level-of-Detail) system that was causing disconnected edges and low-quality nodes during live recon. 3D now always renders at full quality (16-segment spheres, glow, wireframes, labels, particles)
- **Graph 3D labels** -- labels now hide/show based on camera distance (300 unit threshold), improving readability when zoomed out

### Changed

- **Auto-switch to 2D** -- graphs with more than 1,000 nodes automatically switch to 2D rendering. The 3D toggle is disabled with a tooltip explaining the reason
- **2D progressive quality reduction** -- 2D canvas progressively disables glow and particles above 1,000 nodes to maintain performance
- **2D force layout** -- increased link distance (80) and capped charge repulsion range (250) so clusters are more spread internally and closer to each other
- **Polling auto-stop** -- graph polling (5s interval during recon/agent) stops when graph exceeds 2,000 nodes to prevent performance degradation
- **2D performance tiers** -- adjusted thresholds: full (0-1000), reduced (1001-2000), minimal (2001-5000), ultra-minimal (5000+)

---

## [3.5.0] - 2026-04-04

### Added

- **Recon Preset System** -- one-click recon configuration with 21 built-in presets covering common scanning scenarios. Each preset configures 328+ recon pipeline parameters (tool toggles, thresholds, rate limits, OSINT flags, etc.) in a single click:
  - **Built-in Presets**: Full Pipeline Active/Passive/Maximum, Bug Bounty Quick Wins, Bug Bounty Deep Dive, API Security Audit, Infrastructure Mapper, OSINT Investigator, Web App Pentester, JS Secret Miner, Subdomain Takeover Hunter, Stealth Recon, CVE Hunter, Red Team Operator, Directory & Content Discovery, Cloud & External Exposure, Compliance & Header Audit, Secret & Credential Hunter, Parameter & Injection Surface, DNS & Email Security, Network Perimeter Large Scale
  - **Recon Preset tab** in Recon Pipeline tab group (lightning bolt icon) opens a modal with card grid UI, expandable detail descriptions, and "Applied" badge tracking
  - **Zod-validated schema** with 328 parameters covering all recon tools. Uses `.strip()` to prevent unknown key injection

- **My Project Presets** -- save, load, and delete user project presets that capture the entire project configuration (recon pipeline, agent behavior, tool matrix, agent skills, CypherFix, and all other settings). Target-specific fields (domain, subdomains, IPs, RoE document, uploaded files) are automatically stripped for portability:
  - **Save as Preset** button in project form header saves current config with name + description
  - **Load Preset** button opens side drawer listing saved presets with merge-over-defaults loading
  - Per-user storage in PostgreSQL (`UserProjectPreset` model)

- **AI-Generated Presets** -- describe scanning goals in natural language and an LLM generates a validated recon preset. Two-step wizard (Describe -> Review) with enabled/disabled/tuned parameter summary:
  - Supports all configured LLM providers (Anthropic, OpenAI, OpenRouter, OpenAI-compatible, Bedrock)
  - System prompt with full recon parameter catalog guides the LLM
  - Zod validation + JSON extraction pipeline with error details on failure
  - Generated presets saved to My Project Presets collection

- **Wiki documentation** -- new [Recon & Project Presets](https://github.com/samugit83/redamon/wiki/Recon-Presets) wiki page with full guide, 21-preset reference table, and AI generation walkthrough. Updated Creating a Project (16 tabs), Project Settings Reference, Running Reconnaissance, Home, and Sidebar

---

## [3.4.0] - 2026-04-03

### Added

- **JS Recon Scanner** -- comprehensive JavaScript reconnaissance module that runs as GROUP 5b in the recon pipeline (post-resource_enum, pre-vuln_scan). Analyzes JS files discovered by Katana/Hakrawler/GAU for secrets, hidden endpoints, dependency confusion vulnerabilities, source maps, DOM sinks, and framework fingerprints:
  - **Secret Detection**: 100 hardcoded regex patterns covering cloud credentials (AWS, GCP, Azure, Firebase, DigitalOcean, Cloudflare), payment keys (Stripe, PayPal, Square, Razorpay), auth tokens (GitHub, GitLab, Slack, Discord, Twilio, SendGrid, Telegram, 20+ services), JS-specific services (Sentry, Algolia, Mapbox, Pusher, Supabase, OpenAI, Vercel), database URIs, JWTs, private keys, and infrastructure URLs
  - **Key Validation**: 21 service-specific validators that make live API calls to confirm if discovered keys are active (AWS STS, GitHub /user, Stripe /v1/account, etc.). Rate-limited at 1 req/sec per service. Disabled in stealth mode
  - **Source Map Discovery**: probes for `.map` files via sourceMappingURL comments, SourceMap HTTP headers, and 8 common path patterns. Parses discovered maps to extract original source filenames and scan sourcesContent for embedded secrets
  - **Dependency Confusion Detection**: extracts scoped npm packages from import/require/export statements and webpack chunk names, checks each against public npm registry. Missing packages flagged as CRITICAL (attacker could register and execute arbitrary code)
  - **Deep Endpoint Extraction**: extracts REST API calls (fetch, axios, $.ajax, XMLHttpRequest), GraphQL queries/mutations/introspection, WebSocket connections, React/Vue/Angular router definitions, admin/debug/auth endpoints, API documentation paths (/swagger, /openapi.json, /graphiql)
  - **Framework Fingerprinting**: detects 12 frameworks with version extraction (React, Next.js, Vue.js, Nuxt.js, Angular, jQuery, Svelte, Ember, Backbone, Lodash, Moment.js, Bootstrap)
  - **DOM Sink Detection**: 17 patterns for XSS vectors (innerHTML, eval, document.write, dangerouslySetInnerHTML), prototype pollution (__proto__, constructor.prototype), URL manipulation (location.href, window.open), and cross-origin messaging (postMessage)
  - **Developer Comment Mining**: extracts TODO/FIXME/HACK/BUG/XXX markers and comments containing sensitive keywords (password, secret, token, credential, bypass)
  - **Custom Extension Files**: upload JSON/TXT files to extend built-in patterns (custom secret regexes, source map probe paths, internal package names, endpoint keywords, framework signatures). Help guide modal with format docs + examples for each upload type. Client-side validation before upload
  - **Manual JS File Upload**: upload .js/.mjs/.map/.json files from Burp Suite, mobile APKs, DevTools, or authenticated areas for analysis without crawling
  - **25 project settings** across all 4 layers (Prisma schema, Python DEFAULT_SETTINGS, fetch_project_settings mapping, /defaults auto-serve). Includes enable toggle, max files, timeout, concurrency, 7 module toggles, 3 coverage expansion flags, min confidence filter, and 6 custom file upload paths
  - **New "JS Recon" tab** in Recon Pipeline settings group (between Resource Enum and Vulnerability Scanning) with collapsible sub-sections for analysis scope, JS file sources, detection modules, key validation, custom extension files, and manual JS upload
  - **Graph DB integration**: new `JsReconFinding` node type (fuchsia-600 color) with `(BaseURL)-[:HAS_JS_FINDING]->(JsReconFinding)` for pipeline discoveries and `(Domain)-[:HAS_JS_FINDING]->(JsReconFinding)` for uploaded file findings. Secret nodes extended with `source='js_recon'`, `validation_status`, `validation_info`, `confidence`, `detection_method` properties. Endpoint nodes with `source='js_recon'`
  - **Neo4j schema**: unique constraint + tenant index for JsReconFinding. ON CREATE/ON MATCH pattern for Endpoints to avoid overwriting resource_enum source
  - **AI Agent integration**: TEXT_TO_CYPHER_SYSTEM updated with JsReconFinding node schema, HAS_JS_FINDING relationship, example Cypher queries, and combined "all secrets" query including Domain-linked uploads. Tool registry updated with JsReconFinding in node list
  - **Subdomain feedback loop**: JS-discovered in-scope subdomains merged back into combined_result for downstream modules
  - **Security**: matched_text (raw secrets) redacted before writing to disk. Short secrets (<=12 chars) also redacted. Path traversal protection on all upload API routes via PROJECT_ID_RE regex validation. Upload file size limits (10MB JS, 2MB custom). JSON validation before accepting .json uploads
  - **Stealth mode overrides**: JS_RECON_MAX_FILES=50, VALIDATE_KEYS=False, INCLUDE_CHUNKS=False, INCLUDE_FRAMEWORK_JS=False
  - **72 unit tests** covering all 6 analysis modules + integration tests

- **JS Recon DataTable view** -- new "JS Recon" option in the Graph page DataTable dropdown (alongside "All Nodes"). Specialized table with 6 sub-tabs (Secrets, Endpoints, Dependencies, Source Maps, Security Patterns, Attack Surface) displaying JS Recon findings with purpose-built columns. Universal search across all text fields. XLSX export with 13 sheets. Fetches data from `/api/js-recon/{projectId}/download`

- **DataTable view mode dropdown** -- the "Data Table" tab on the Graph page now has a dropdown arrow to switch between "All Nodes" (generic node table) and "JS Recon" (specialized findings table). Bottom bar node filters hidden for JS Recon view

- **View Mode + Labels toggles moved** -- 2D/3D toggle and Labels toggle moved from GraphToolbar to ViewTabs right section (visible only when Graph Map is active). Tunnel badges moved from ViewTabs to GraphToolbar next to PAUSE ALL button

### Changed

- **Report generation** -- added Secret, TruffleHog, JS Recon, OTX threat intelligence sections to HTML/PDF report generation (reportData.ts + reportTemplate.ts). Risk score now includes secrets, TruffleHog findings, JS Recon findings, and OTX threat data

- **Bottom bar visibility** -- PageBottomBar (node type filters, session controls, stats) now hidden for Reverse Shell, RedAmon Terminal, RoE, and JS Recon views. Only visible for Graph Map, Graph Views, and All Nodes

---

## [3.3.0] - 2026-04-01

### Added

- **Chat Skills (`/skill` command)** -- on-demand reference injection system for the AI agent chat. Chat Skills are tactical reference docs (tool playbooks, vulnerability guides, framework notes) that you inject into the agent's context exactly when you need them, without affecting classification or phase routing:
  - **`/skill` command**: type `/skill ssrf` to activate a skill, `/skill ssrf test the API` to activate and send a message in one shot, `/skill list` to browse all skills, `/skill remove` to deactivate
  - **Skill picker button**: lightning bolt button next to send -- click to browse all skills grouped by category, click a skill to activate instantly. Includes "Import from Community" and "Upload .md" buttons directly in the dropdown
  - **Slash autocomplete**: typing `/s` anywhere in the input triggers a floating dropdown with filtered skills -- arrow keys to navigate, Enter to select, works mid-sentence
  - **Active skill badge**: shows the active skill name and category above the input with an X button to remove. Persists across messages until changed or removed
  - **Persistent activation**: once activated, skill context is included with every subsequent message (prepended for new queries, injected via guidance queue for running agents)
  - **Global Settings tab**: new "Chat Skills" tab between Agent Skills and API Keys with upload, edit description, download, delete, and category filtering
  - **Import from Community**: bulk-import all 36 shipped reference skills (or community Agent Skills) with one click -- available in both Global Settings and the chat skill picker
  - **WebSocket integration**: `SKILL_INJECT` / `SKILL_INJECT_ACK` message types push skill content through the existing guidance queue pipeline
  - **Database**: `UserChatSkill` Prisma model with per-user storage, category field, and full CRUD API routes
  - **36 community Chat Skills** by [@blackkhawkk](https://github.com/blackkhawkk) covering 7 categories: vulnerabilities (17), tooling (9), scan modes (3), frameworks (3), technologies (2), protocols (1), coordination (1)
  - **15 skill categories**: general, vulnerabilities, tooling, scan_modes, frameworks, technologies, protocols, coordination, cloud, mobile, api_security, wireless, network, active_directory, social_engineering, reporting
  - **Security**: path traversal protection in `load_skill_content()` via `.resolve().is_relative_to()` containment check

- **Amass Brute Force Wordlist Selector** -- configurable wordlist selection for Amass DNS brute forcing:
  - **Wordlist selector UI**: checkbox list under the Amass Bruteforce toggle in project settings. Amass Default (~8K entries) is always active and cannot be unchecked. jhaddix all.txt (~2.18M entries) is optional with time estimate badge
  - **jhaddix all.txt**: Jason Haddix's comprehensive subdomain wordlist (~2.18M entries compiled from certificate transparency, bug bounty findings, DNS datasets) baked into the `redamon-recon` Docker image
  - **Prisma schema**: `amassBruteWordlists` JSON field on Project model (default: `["default"]`)
  - **Future extensibility**: adding more wordlists is just a `.txt` file in `recon/wordlists/` + a checkbox entry in the UI

- **Import from Community for Agent Skills** -- new "Import from Community" button in Global Settings > Agent Skills tab. Bulk-imports all `.md` workflow files from `agentic/community-skills/` into the user's personal Agent Skills library with duplicate-by-name skipping

### Fixed

- **Amass wordlist mount bug** -- `os.path.isfile()` was checking a host filesystem path from inside the recon container, always returning `False`. The jhaddix wordlist was never mounted into the Amass container. Fixed to check the container-local path (`/app/recon/wordlists/jhaddix-all.txt`) and use the host path only for the Docker `-v` bind mount

### Removed

- **Claude Code proxy and provider** -- removed the host-side FastAPI proxy (`claude_proxy/server.py`), the `claude_code` LLM provider type, `ClaudeCodeToolManager`, auto-fallback logic, Docker credential mounts, and all related frontend/settings code. The OAuth token used by Claude Code is scoped to `user:sessions:claude_code` -- using it outside Claude Code is against Anthropic's Terms of Service. Users should use the existing Anthropic provider with a standard API key from console.anthropic.com

- **OSINT agent tools** -- removed 7 incomplete tool manager classes (Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP) from the agent. Missing 7 of 13 required integration steps (no TOOL_REGISTRY entries, no Tool Matrix UI, no stealth rules, no execute() dispatch). The recon pipeline integration for these services is unaffected. See `PROMPT.ADD_AGENTIC_TOOL.md` for the full integration checklist if re-adding later

- **Always-on specialist skills injection** -- removed the `AGENT_SKILLS` project setting, `agentSkills` Prisma column, `build_skills_prompt_section()`, and the AgentBehaviourSection skill pills UI. Replaced by the on-demand Chat Skills system above

---

## [3.2.0] - 2026-03-31

### Added

- **Uncover Multi-Engine Target Expansion** -- ProjectDiscovery's [uncover](https://github.com/projectdiscovery/uncover) integrated as GROUP 2b in the recon pipeline, running before Shodan and port scanning to expand the target surface. Queries up to 13 search engines simultaneously to discover exposed hosts, IPs, and endpoints associated with the target domain:
  - **Engines:** Shodan, Censys, FOFA, ZoomEye, Netlas, CriminalIP (reuses existing pipeline keys) + Quake, Hunter, PublicWWW, HunterHow, Google Custom Search, Onyphe, Driftnet (uncover-specific keys)
  - **Smart key reuse:** automatically picks up API keys already configured for standalone OSINT enrichment modules -- no extra configuration needed if you already have Shodan/Censys/FOFA/etc. keys
  - **Docker-in-Docker:** runs `projectdiscovery/uncover:latest` container with a dynamically generated `provider-config.yaml` containing only engines with valid credentials
  - **Engine-aware parsing:** handles per-engine quirks -- Google's URL-in-IP field, PublicWWW's host-only results (no IP), Censys URL endpoints. All three previously produced silent data loss
  - **URL discovery:** captures in-scope URLs from engines that populate the `url` field (Censys, PublicWWW, Google), stored as Endpoint nodes in Neo4j
  - **Pipeline merge:** discovered subdomains are injected into `dns.subdomains` so all downstream modules (port scan, HTTP probe, OSINT enrichment) process them automatically. New IPs are added to `metadata.expanded_ips`
  - **Neo4j graph:** `update_graph_from_uncover()` in `osint_mixin.py` creates Subdomain, IP, Port, and Endpoint nodes with source tracking (`uncover_sources`, `uncover_source_counts`, `uncover_total_raw`, `uncover_total_deduped`)
  - **Frontend:** embedded in OsintEnrichmentSection with enable/disable toggle and max results (1-10,000). Settings page groups uncover-specific keys under "Uncover (Multi-Engine Search)" with `Standalone + Uncover` badges on shared keys
  - **Prisma schema:** `uncoverEnabled`, `uncoverMaxResults`, `uncoverDockerImage` fields + 8 API key fields in UserGlobalSettings (Quake, Hunter, PublicWWW, HunterHow, Google key+CX, Onyphe, Driftnet)
  - **Tests:** 42 unit tests covering provider config, deduplication, host/IP extraction, Google/PublicWWW quirks, URL collection, merge logic, isolated wrapper

- **Centralized IP Filtering (`ip_filter.py`)** -- shared module replacing duplicate inline filtering across all OSINT enrichment modules:
  - `is_non_routable_ip()` -- filters RFC 1918 private, loopback, link-local, CGNAT (100.64.0.0/10), multicast, reserved ranges
  - `collect_cdn_ips()` -- gathers IPs flagged as CDN by Naabu/httpx from port scan and HTTP probe data
  - `filter_ips_for_enrichment()` -- single entry point used by all 9 enrichment modules (Shodan, Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP, Uncover) to skip non-routable and CDN IPs before making external API calls
  - 22 unit tests covering all IP classification categories, CDN collection, and filtering combinations

- **Censys Platform API v3 Migration** -- migrated from deprecated Basic Auth (`API_ID:API_SECRET`) to Bearer token auth (`CENSYS_API_TOKEN` + `CENSYS_ORG_ID`). Both the recon pipeline enrichment module and the AI agent's `censys_lookup` tool now use the Platform API v3 (`api.platform.censys.io/v3/global`). Old credentials are consolidated via database migration

- **CriminalIP Agent Tool** -- added `criminalip_lookup` to the AI agent's tool registry for interactive IP threat intelligence queries

- **Playwright Browser Automation (MCP Tool)** -- headless Chromium browser automation exposed as an MCP tool (`execute_playwright`) on port 8005 inside the Kali sandbox. Enables the AI agent to interact with JavaScript-rendered pages, SPAs, and dynamic web applications that curl cannot handle:
  - **Two modes:** Content extraction (navigate URL, extract rendered text/HTML with optional CSS selector) and Script mode (run multi-step Playwright Python code with pre-initialized `browser`, `context`, `page` variables)
  - **Backend:** `mcp/servers/playwright_server.py` MCP server using FastMCP, subprocess-based script execution with ANSI stripping, 45s timeout for content mode, 60s for scripts
  - **Docker:** Playwright + Chromium installed in kali-sandbox Dockerfile, headless with `--no-sandbox` and Chrome 120 user-agent. Server registered in `run_servers.py` on port 8005
  - **Agent integration:** configured in `agentic/tools.py` as MCP server (SSE transport, 60s connection / 120s read timeout), documented in `tool_registry.py` with both modes and examples
  - **Phase restrictions:** allowed in all phases (informational, exploitation, post_exploitation). Marked as a **dangerous tool** requiring manual confirmation before execution
  - **Stealth mode:** restricted to single-URL operations only -- no crawling, bulk scraping, or credential spraying. Maximum 2 form submissions per target
  - **Output:** max 15,000 chars per extraction, truncated with notice. Script mode captures stdout with filtered Playwright verbose logging

### Fixed

- **Silent data loss in uncover** -- Google engine results (URL in IP field) and PublicWWW results (no IP, host-only) were silently dropped by deduplication. Fixed with engine-aware parsing that extracts hostnames from URLs and uses `(host, port)` fallback dedup key
- **Graph data loss in uncover** -- `sources`, `source_counts`, `total_raw`, `total_deduped` metadata fields were collected but never written to Neo4j nodes. All fields now stored on Subdomain and IP nodes
- **Logging format violations in uncover** -- replaced `logger.info()`/`logger.error()` calls with standard `print("[symbol][Uncover]")` format per pipeline conventions
- **Missing Prisma schema field** -- `uncoverDockerImage` was in Python settings but missing from Prisma schema, causing frontend/DB desync
- **Missing nodeMapping entries** -- Uncover was not listed in `SECTION_INPUT_MAP` / `SECTION_NODE_MAP`, breaking the graph visualization node info tooltips

---

## [3.1.4] - 2026-03-29

### Added

- **Nmap Service Detection & NSE Vulnerability Scripts** -- deep service version detection (`-sV`) and NSE vulnerability scripts (`--script vuln`) integrated into the recon pipeline as GROUP 3.5, running after port discovery and before HTTP probing. Only scans ports already discovered as open by Masscan/Naabu. Full multi-layer integration:
  - **Backend**: `recon/nmap_scan.py` module with `run_nmap_scan()` orchestration, XML output parsing, CVE extraction from NSE script output (regex `CVE-\d{4}-\d+`), and thread-safe `run_nmap_scan_isolated()` wrapper
  - **Pipeline**: runs after port_scan merge, enriches `port_scan.port_details` with product/version/CPE/scripts via `merge_nmap_into_port_scan()`, updates `port_scan.scan_metadata.scanners` to include "nmap"
  - **Neo4j graph**: `update_graph_from_nmap()` enriches Port nodes (product, version, CPE, nmap_scanned flag), creates Technology nodes (`(Service)-[:USES_TECHNOLOGY]->(Technology)`, `(Port)-[:HAS_TECHNOLOGY]->(Technology)`), creates Vulnerability nodes from NSE findings (`(Vulnerability)-[:AFFECTS]->(Port)`, `(Vulnerability)-[:FOUND_ON]->(Technology)`), and creates CVE nodes from NSE-detected CVEs (`(Vulnerability)-[:HAS_CVE]->(CVE)`, `(Technology)-[:HAS_KNOWN_CVE]->(CVE)`)
  - **CVE lookup**: Nmap-detected service versions (product/version from `services_detected[]`) feed into the CVE lookup pipeline for NVD/Vulners enrichment
  - **Docker**: nmap installed via `apt-get` in recon Dockerfile, NSE scripts included
  - **Frontend**: `NmapSection.tsx` with enable/disable toggle, version detection (-sV) toggle, NSE vulnerability scripts toggle, timing template dropdown (T1-T5), total timeout, and per-host timeout settings
  - **Prisma schema**: 6 new fields -- `nmapEnabled`, `nmapVersionDetection`, `nmapScriptScan`, `nmapTimingTemplate`, `nmapTimeout`, `nmapHostTimeout`
  - **Settings**: 6 configurable parameters with stealth mode overrides (timing T2, scripts disabled)
  - **Output structure**: `nmap_scan` key with `scan_metadata`, `by_host` (port details with service/version/CPE/scripts), `services_detected[]`, `nse_vulns[]`, and `summary`
  - **Tests**: comprehensive test suite in `recon/tests/test_nmap_scan.py` covering target extraction, command construction, XML parsing, CVE extraction, and edge cases

---

## [3.1.3] - 2026-03-29

### Fixed

- **GVM scan stuck at 0%** -- `ospd-openvas` tried to connect to an MQTT broker (`[Errno 111] Connection refused`) because it was missing the `--notus-feed-dir` flag. Without it, the container defaults to MQTT-based notus communication which requires a Mosquitto broker we don't run. Added the official Greenbone `command` with `--notus-feed-dir /var/lib/notus/advisories` so ospd-openvas handles notus locally, matching the upstream community edition compose ([#78](https://github.com/user/redamon/issues/78))
- **GVM button enabled without GVM installed** -- users who installed without `--gvm` still saw an active GVM Scan button. Added a `/health` availability check (`gvm_available`) from the recon orchestrator that detects whether `gvmd` is running, exposed via `/api/gvm/available`, and wired into the toolbar to disable the button with a descriptive tooltip when GVM is not installed

---

## [3.1.2] - 2026-03-29

### Added

- **Surface Shaper** -- natural language attack surface scoping. Describe a subgraph in plain English and the AI generates a read-only Cypher query that carves out a focused slice of the reconnaissance graph. Active surfaces scope Graph Map, Data Table, bottom bar stats, and the AI agent's `query_graph` tool:
  - Split-panel creation page with form on left and live graph preview on right
  - 20 example queries organized by category (Infrastructure, Vulnerabilities, Web Application, Threat Intelligence, Attack Chains) via dropdown menu
  - Save & Select button to instantly activate a surface and switch to Graph Map
  - Unified filter group control in tab bar (create + select as segmented element)
  - Write operation guard (CREATE, MERGE, DELETE blocked) on both webapp execute endpoint and agent tools
  - Bottom bar dynamically reflects active surface (node types, counts, sessions, stats)

- **API Security Testing Tools in Kali Sandbox** -- 6 new tools available via `kali_shell` for API and web security testing:
  - **ffuf** v2.1.0 -- fast web fuzzer for API endpoint/parameter discovery ([MIT](https://github.com/ffuf/ffuf))
  - **httpx** v1.9.0 (ProjectDiscovery) -- HTTP probing, tech detection, header analysis ([MIT](https://github.com/projectdiscovery/httpx))
  - **jwt_tool** v2.3.0 -- JWT exploitation: alg:none, key confusion, secret cracking ([GPL-3.0](https://github.com/ticarpi/jwt_tool))
  - **graphql-cop** -- GraphQL security auditor ([BSD-3-Clause](https://github.com/dolevf/graphql-cop))
  - **graphqlmap** -- GraphQL exploitation scripting engine ([MIT](https://github.com/swisskyrepo/GraphQLmap))
  - **dalfox** -- XSS vulnerability scanner with WAF bypass, DOM-based and blind XSS support ([MIT](https://github.com/hahwul/dalfox))

---

## [3.1.1] - 2026-03-27

### Added

- **Community Skills** -- new section in wiki and Global Settings UI linking to community-contributed attack skill templates (API testing, XSS, SQLi, SSRF)

### Fixed

- **httpx PATH shadowing** -- ProjectDiscovery Go httpx was shadowed by Python httpx CLI wrapper in the Kali sandbox PATH; fixed via symlink override
- **Python httpx removal** -- removed incorrect `pip uninstall httpx` from Dockerfile that would have broken MCP server SSE transport

---

## [3.1.0] - 2026-03-25

### Added

- **Masscan High-Speed Port Scanner** — integrated Masscan as a parallel port scanner alongside Naabu, with NDJSON output parsing, result merging/deduplication, and full multi-layer integration:
  - **Backend**: `recon/masscan_scan.py` module with `run_masscan_scan()` and thread-safe `run_masscan_scan_isolated()` for parallel execution
  - **Pipeline**: Masscan and Naabu run concurrently in the same `ThreadPoolExecutor` fan-out group, results merged via `merge_port_scan_results()` into the unified `port_scan` key for downstream consumers (HTTP probe, graph DB, vuln scan)
  - **Docker**: Masscan built from source in a multi-stage `recon/Dockerfile` build; installed via apt in `kali-sandbox/Dockerfile` for AI agent use
  - **Frontend**: `MasscanSection.tsx` with header enable/disable toggle (Katana pattern), rate, ports, wait, retries, banners, and exclude targets controls
  - **Naabu enable/disable toggle**: added `naabuEnabled` setting across all layers (Prisma, project_settings, frontend header toggle) — both scanners enabled by default
  - **Both-disabled warning**: frontend alert + pipeline log warning when both port scanners are toggled off
  - **AI agent**: `execute_masscan` MCP tool registered in `network_recon_server.py` and `tool_registry.py`
  - **Stealth mode**: Masscan disabled, Naabu switches to passive mode
  - **53 unit tests** covering NDJSON parsing, command construction, result merging, IP/domain mode, mock hostname normalization, and mocked subprocess lifecycle

- **TruffleHog Secret Scanner** — deep credential scanning with 700+ detectors and automatic credential verification via the TruffleHog Docker container (`trufflesecurity/trufflehog`). Scans GitHub repositories for leaked secrets (API keys, passwords, tokens, certificates) and verifies whether discovered credentials are still active. Full multi-layer integration:
  - **Backend**: `trufflehog_scan/` service with SSE streaming progress, Docker-in-Docker execution, and JSON output parsing
  - **Neo4j graph**: new node types `TrufflehogScan`, `TrufflehogRepository`, and `TrufflehogFinding` with relationships `(:TrufflehogScan)-[:SCANNED_REPO]->(:TrufflehogRepository)-[:HAS_FINDING]->(:TrufflehogFinding)`
  - **Frontend**: real-time SSE progress via `useTrufflehogSSE` hook, scan status polling via `useTrufflehogStatus` hook, results displayed in the graph dashboard
  - **API**: `/api/trufflehog` routes for triggering scans, streaming progress, and retrieving results

- **"Other Scans" Modal** — new modal in the graph toolbar (`OtherScansModal`) that consolidates GitHub Hunt and TruffleHog scanning into a single launch point accessible from the graph page toolbar.

- **GitHub Access Token moved to Global Settings** — the GitHub access token is now configured once in Global Settings and shared by both GitHub Secret Hunt and TruffleHog, eliminating duplicate token configuration per scan type.

- **SQL Injection Agent Skill** (`sql_injection`) — new built-in agent skill for SQL injection testing, replacing the previous `sql_injection-unclassified` fallback with a structured 7-step workflow.

- **Agent skill workflows injected from informational phase** — all built-in skill prompts (CVE, SQLi, Credential Testing, DoS, Social Engineering) are now injected from the start of a session, matching user skill behavior. Previously, skill workflows only appeared after transitioning to exploitation phase, causing the agent to improvise without guidance during recon.

- **Phase transition guidance in skill prompts** — each built-in skill now includes an explicit instruction to request `transition_phase` to exploitation after initial recon, ensuring the agent moves through the phase model correctly.

- **Improved classification for informational requests** — the LLM classifier now always determines the best-matching agent skill regardless of phase. Pure recon requests (e.g., "show attack surface") classify as `recon-unclassified` instead of defaulting to `cve_exploit`.

- **AI-Assisted Development wiki page** — new contributor guide with two structured integration prompts (`ADD_AGENTIC_TOOL`, `ADD_RECON_TOOL`) and a 7-step iterative workflow for shipping zero-bug PRs using Claude Code. See [Wiki: AI-Assisted Development](https://github.com/samugit83/redamon/wiki/AI-Assisted-Development).

- **7 OSINT Threat Intelligence Enrichment Tools** — passive enrichment phase (GROUP 3b) running in parallel with port scanning. All 7 modules use a fan-out `ThreadPoolExecutor` pattern, support rate-limit detection (HTTP 429), optional API key rotation, and write results to `recon_domain.json` + Neo4j graph:
  - **Censys** (`censys_enrich.py`) — queries the Censys Search API v2 (`/v2/hosts/{ip}`) for each discovered IP. Returns open ports, services, banners, TLS certificate chains, geolocation, ASN, and OS. Requires `CENSYS_API_ID` + `CENSYS_API_SECRET` (Basic Auth). Both keys stored in Global Settings.
  - **FOFA** (`fofa_enrich.py`) — queries the FOFA Search API using base64-encoded query syntax (`domain="<domain>"` or per-IP). Returns IP:port pairs, HTTP titles, server headers, geolocation, certificate info, and protocol details. Supports legacy (`email:key`) and modern (`key`-only) authentication formats. Max 10,000 results per query. Supports key rotation via `FOFA_KEY_ROTATOR`.
  - **OTX / AlienVault Open Threat Exchange** (`otx_enrich.py`) — queries the OTX Indicators API v1 for IPs and domains. Returns threat reputation, associated malware families, MITRE ATT&CK attack IDs, passive DNS history, pulse data (adversaries, tags, TLP). Supports anonymous requests (1,000 req/hr) or with API key (10,000 req/hr). **Enabled by default** — the only OSINT tool active without an API key. Supports key rotation.
  - **Netlas** (`netlas_enrich.py`) — queries the Netlas Responses API (`host:{domain}` or `host:{ip}`) for internet-connected asset intelligence. Returns port/service data, HTTP response metadata, geolocation (lat/lon, timezone), TLS certificate details, DNS records, and WHOIS data. Max 1,000 results. Supports key rotation.
  - **VirusTotal** (`virustotal_enrich.py`) — queries the VirusTotal API v3 for domain and IP reputation. Returns reputation scores, last analysis stats (malicious/suspicious/undetected counts), categories, tags, JARM fingerprint, registrar, and last analysis date. Free-tier rate limit: 4 requests/minute (configurable via `VIRUSTOTAL_RATE_LIMIT`). On 429, automatically sleeps 65 seconds and retries once. Configurable `VIRUSTOTAL_MAX_TARGETS` (default 20) caps API usage per scan.
  - **ZoomEye** (`zoomeye_enrich.py`) — queries the ZoomEye API for hostname and IP searches. Returns open ports, service banners, device type/OS, web application fingerprints, geolocation (country, city, lat/lon, timezone), ASN, ISP, and SSL certificate info. Max 1,000 results. Supports key rotation.
  - **CriminalIP** (`criminalip_enrich.py`) — queries the Criminal IP API v1 (`/v1/ip/data?full=true`, `/v1/domain/data`) for IP and domain intelligence. Returns risk score, threat tags (VPN, cloud, Tor, proxy, hosting, mobile, darkweb, scanner, Snort IDS), geolocation, ISP, hosted services, and abuse history. On 429, sleeps 2 seconds and retries once.
  - **API Keys**: all 7 tool API keys are stored in **Global Settings > API Keys** (user-scoped). Project settings contain only enable/disable toggles and optional limits (max results, rate limits, max targets).
  - **Key Rotation**: FOFA, OTX, Netlas, VirusTotal, ZoomEye, and CriminalIP support automatic round-robin key rotation via the Global Settings key rotation UI.
  - **Unit tests**: 7 test files in `tests/` covering all enrichment modules (mocked HTTP, rate limit handling, key rotation, graph update functions).

### Fixed

- **Duplicate tool widget replacement** — fixed a bug where the second call to the same tool (e.g., two `execute_curl` calls) would overwrite the first widget in the chat timeline. Root cause: streaming event dedup key only used `tool_name`, causing the second `tool_start` to be deduplicated away. Fix: include `tool_args` in the dedup key.

- **Tool completion ordering** — fixed a race condition where `TOOL_CONFIRMATION_REQUEST` for the next tool arrived before `TOOL_COMPLETE` for the previous tool, causing the confirmation handler to overwrite the previous tool's widget. Fix: reordered streaming events so `tool_complete` always fires before `tool_confirmation`.

---

## [3.0.0] - 2026-03-15

### Added

- **Custom Nuclei Templates Integration** — custom nuclei templates (`mcp/nuclei-templates/`) are now manageable via the UI with per-project selection, dynamically discovered by the agent, and included in automated recon scans:
  - **Template Upload UI**: upload, view, and delete custom `.yaml`/`.yml` nuclei templates directly from Project Settings → Nuclei → Template Options. Templates are global (shared across all projects). Upload validates nuclei template format (requires `id:` and `info:` with `name:` and `severity:`). API: `GET/POST/DELETE /api/nuclei-templates`
  - **Per-project template selection**: each template has a checkbox — only checked templates are included in that project's automated scans. Stored as `nucleiSelectedCustomTemplates` String[] per project (default: `[]`). Different projects can enable different templates from the same global pool
  - **Agent discovery**: at startup, the nuclei MCP server scans `/opt/nuclei-templates/` and dynamically appends all template paths (id, severity, name) to the `execute_nuclei` tool description, so the agent automatically knows what custom templates are available
  - **Recon pipeline**: selected templates are individually passed as `-t /custom-templates/{path}` flags to nuclei. Recon logs list each selected template by name
  - **Spring Boot Actuator templates** (community PR #69): 7 detection templates with 200+ WAF bypass paths for `/actuator`, `/heapdump`, `/env`, `/jolokia`, `/gateway` endpoints — URL encoding, semicolon injection, path traversal, and alternate base path evasion techniques

- **SSL Verify Toggle for OpenAI-compatible LLM Providers** (community PR #70) — `sslVerify` boolean (default: `true`) lets users skip SSL certificate verification when connecting to internal/self-hosted LLM endpoints with self-signed certificates. Full stack: Prisma schema, API route, frontend checkbox, agent `httpx.Client(verify=False)` injection.

- **Dockerfile `DEBIAN_FRONTEND=noninteractive`** (community PR #63) — added to `agentic`, `recon_orchestrator`, and `guinea_pigs` Dockerfiles to suppress interactive `apt-get` prompts during builds.

- **ParamSpider Passive Parameter Discovery** — mines the Wayback Machine CDX API for historically-documented URLs containing query parameters. Only returns parameterized URLs (with `?key=value`), with values replaced by a configurable placeholder (default `FUZZ`), making results directly usable for fuzzing. Runs in Phase 4 (Resource Enumeration) in parallel with Katana, Hakrawler, and GAU. Passive — no traffic to target. No API keys required. Disabled by default; stealth mode auto-enables it. Full stack integration:
  - **Backend**: `paramspider_helpers.py` with `run_paramspider_discovery()` (subprocess per domain, stdout + file output parsing, scope filtering, temp dir cleanup) and `merge_paramspider_into_by_base_url()` (sources array merge, parameter enrichment, deduplication)
  - **Settings**: 3 user-configurable `PARAMSPIDER_*` settings (enabled, placeholder, timeout)
  - **Frontend**: `ParamSpiderSection.tsx` with enable toggle, placeholder input, timeout setting
  - **Stealth mode**: auto-enabled (passive tool, queries Wayback Machine only)
  - **Tests**: 22 unit tests covering merge logic, subprocess mocking, scope filtering, method merging, legacy field migration, settings, stealth overrides

- **Arjun Parameter Discovery** — discovers hidden HTTP query and body parameters on endpoints by testing ~25,000 common parameter names. Runs in Phase 4 (Resource Enumeration) after FFuf, testing discovered endpoints from crawlers/fuzzers rather than just base URLs. Disabled by default; stealth mode forces passive-only; RoE caps rate. Full stack integration:
  - **Backend**: `arjun_helpers.py` with multi-method parallel execution via `ThreadPoolExecutor` — each selected method (GET/POST/JSON/XML) runs as a separate Arjun subprocess simultaneously
  - **Discovered endpoint feeding**: collects full endpoint URLs from Katana + Hakrawler + jsluice + FFuf results, prioritizes API and dynamic endpoints, caps to configurable max (default 50)
  - **Settings**: 12 user-configurable `ARJUN_*` settings (methods, max endpoints, threads, timeout, chunk size, rate limit, stable mode, passive mode, disable redirects, custom headers)
  - **Frontend**: `ArjunSection.tsx` with multi-select method checkboxes, max endpoints field, scan parameters, stable/passive/redirect toggles, custom headers textarea
  - **Stealth mode**: forces `ARJUN_PASSIVE=True` (CommonCrawl/OTX/WaybackMachine only, no active requests to target)
  - **Tests**: 29 unit tests covering merge logic, multi-method parallel execution, scope filtering, command building, settings consistency, stealth/RoE overrides

- **FFuf Directory Fuzzer** — brute-force directory/endpoint discovery using wordlists, complementing crawlers (Katana, Hakrawler, GAU) by finding hidden content (admin panels, backup files, configs, undocumented APIs). Runs in Phase 4 (Resource Enumeration) after jsluice and before Kiterunner. Disabled by default; stealth mode disables it; RoE caps rate. Full stack integration:
  - **Backend**: `ffuf_helpers.py` with `run_ffuf_discovery()`, JSON output parsing, scope filtering, deduplication, and smart fuzzing under crawler-discovered base paths
  - **Dockerfile**: multi-stage Go 1.22 build compiles FFuf from source, installs 3 SecLists wordlists (`common.txt`, `raft-medium-directories.txt`, `directory-list-2.3-small.txt`)
  - **Settings**: 16 user-configurable `FFUF_*` settings (threads, rate, timeout, wordlist, match/filter codes, extensions, recursion, auto-calibrate, smart fuzz, custom headers)
  - **Frontend**: `FfufSection.tsx` with full settings UI, wordlist dropdown (built-in SecLists + custom uploads), custom wordlist upload/delete via API
  - **Custom wordlists**: upload `.txt` wordlists per-project via `/api/projects/[id]/wordlists` (GET/POST/DELETE), shared between webapp and recon containers via Docker volume mount
  - **Validation**: frontend form validation for FFuf status codes (100-599), header format, numeric ranges, extensions format, recursion depth (1-5)
  - **Tests**: 43 unit tests covering helpers, settings, stealth/RoE overrides, sanitization, and CRUD operations

- **RedAmon Terminal** — interactive PTY shell access to the kali-sandbox container directly from the graph page via xterm.js. Provides full Kali Linux terminal with all pre-installed pentesting tools (Metasploit, Nmap, Nuclei, Hydra, sqlmap, etc.) without leaving the browser. Architecture: Browser (xterm.js) → WebSocket → Agent FastAPI proxy (`/ws/kali-terminal`) → kali-sandbox terminal server (PTY `/bin/bash` on port 8016):
  - **Terminal server**: `terminal_server.py` — WebSocket PTY server using `os.fork` + `pty` module with async I/O via `loop.add_reader()`, connection limits (max 5 sessions), resize validation (clamped 1-500), process group cleanup, and `asyncio.Event` for clean shutdown
  - **Agent proxy**: `/ws/kali-terminal` WebSocket endpoint in `api.py` — bidirectional relay with proper task cancellation (`asyncio.gather` with `return_exceptions`)
  - **Frontend**: `KaliTerminal.tsx` — React component with dark Ayu theme, connection status indicator, auto-reconnect with exponential backoff (5 attempts), fullscreen toggle, browser-side keepalive ping (30s), proper xterm.js teardown, ARIA accessibility attributes
  - **Docker**: port 8016 bound to localhost only (`127.0.0.1:8016:8016`), `TERMINAL_WS_PORT` and `KALI_TERMINAL_WS_URL` env vars
  - **Tests**: 18 Python + TypeScript unit tests covering resize clamping, connection limits, URL derivation, reconnect logic

- **"Remote Shells" renamed to "Reverse Shell"** — tab renamed for clarity to distinguish from the new RedAmon Terminal tab. The Reverse Shell tab manages agent-opened sessions (meterpreter, netcat, etc.), while RedAmon Terminal provides direct interactive sandbox access.

- **Hakrawler Integration** — DOM-aware web crawler running as Docker container (`jauderho/hakrawler`). Runs in parallel with Katana, GAU, and Kiterunner during resource enumeration. Configurable depth, threads, subdomain inclusion, and scope filtering. Disabled automatically in stealth mode.
- **jsluice JavaScript Analysis** — JS analysis tool that downloads and extracts URLs, API endpoints, and embedded secrets (AWS keys, GitHub tokens, GCP credentials, etc.) from discovered JavaScript files. Runs sequentially after the parallel crawling phase.
- **Secret Node in Neo4j** — Generic `Secret` node type linked to `BaseURL` via `[:HAS_SECRET]`. Source-agnostic design supports jsluice now and future secret discovery tools. Includes deduplication, severity classification, and redacted samples.
- **Hakrawler enabled by default** — New projects have Hakrawler and Include Subdomains enabled by default.
- **Tool Confirmation Gate** — per-tool human-in-the-loop safety gate that pauses the agent before executing dangerous tools (`execute_nmap`, `execute_naabu`, `execute_nuclei`, `execute_curl`, `metasploit_console`, `msf_restart`, `kali_shell`, `execute_code`, `execute_hydra`). Full multi-layer integration:
  - **Backend**: `DANGEROUS_TOOLS` frozenset in `project_settings.py`, `ToolConfirmationRequest` Pydantic model in `state.py`, two new LangGraph nodes (`await_tool_confirmation`, `process_tool_confirmation`) in `tool_confirmation_nodes.py`
  - **Orchestrator**: think node detects dangerous tools in both single-tool and plan-wave decisions, sets `awaiting_tool_confirmation` and `tool_confirmation_pending` state, graph pauses at `await_tool_confirmation` (END) and resumes via `process_tool_confirmation` routing to execute_tool/execute_plan (approve), think (reject), or patching tool_args (modify)
  - **WebSocket**: `tool_confirmation` (client→server) and `tool_confirmation_request` (server→client) message types, `ToolConfirmationMessage` model, `handle_tool_confirmation()` handler with streaming resumption
  - **Frontend**: inline **Allow / Deny** buttons on `ToolExecutionCard` (single mode) and `PlanWaveCard` (plan mode) with `pending_approval` status, `awaitingToolConfirmation` state disables chat input, warning badge in chat header when disabled
  - **Settings**: `REQUIRE_TOOL_CONFIRMATION` (default: `true`) toggle in Project Settings → Agent Behaviour → Approval Gates, with autonomous operation risk warning when disabled
  - **Conversation restore**: tool confirmation requests and responses persisted to DB, correctly restored on conversation reload with Allow/Deny buttons re-activated if no subsequent agent work occurred
  - **Prisma schema**: `agentRequireToolConfirmation` Boolean field (default: true)
- **Hard Guardrail** — deterministic, non-disableable domain blocklist for government, military, educational, and international organization domains. Cannot be toggled off regardless of project settings. Implemented identically in Python (`agentic/hard_guardrail.py`) and TypeScript (`webapp/src/lib/hard-guardrail.ts`):
  - Blocks TLD suffix patterns: `.gov`, `.mil`, `.edu`, `.int`, and country-code variants (`.gov.uk`, `.ac.jp`, `.gob.mx`, `.gouv.fr`, etc.)
  - Blocks 300+ exact intergovernmental organization domains on generic TLDs (UN system, EU institutions, development banks, arms control bodies, international courts, etc.)
  - Subdomain matching: blocks all subdomains of exact-blocked domains
  - Provides defense-in-depth alongside the soft LLM-based guardrail

- **Zero-config setup — `.env` file completely removed** — all user-configurable settings (NVD API key, ngrok auth token, chisel server URL/auth) are now managed from the Global Settings UI page and stored in PostgreSQL. No `.env` or `.env.example` file is needed.
  - **Global Settings → API Keys**: NVD, Vulners, and URLScan API keys added alongside Tavily, Shodan, SerpAPI (all user-scoped)
  - **Global Settings → Tunneling**: new section for ngrok and chisel tunnel configuration with live push to kali-sandbox (no container restart needed)
  - **Tunnel Manager API**: lightweight HTTP server on port 8015 inside kali-sandbox that receives tunnel config pushes from the webapp and manages ngrok/chisel processes
  - **Boot-time config fetch**: kali-sandbox fetches tunnel credentials from webapp DB on startup
  - **Bug fix**: NVD API key was never actually passed to CVE lookup function — now correctly wired through

- **Availability Testing Attack Skill** — new built-in attack skill for disrupting service availability. Includes LLM prompt templates for DoS vector selection, resource exhaustion, flooding, and crash exploits. Full integration across the stack:
  - **Backend**: `denial_of_service_prompts.py` with DoS-specific workflow guidance, vector classification, and impact assessment prompts
  - **Orchestrator**: DoS attack path type (`denial_of_service`) integrated into classification, phase transitions, and tool registry
  - **Database**: Prisma schema updated with DoS configuration fields and project-level toggle
  - **Frontend**: `DosSection.tsx` configuration component in the project form for enabling/disabling and tuning DoS parameters
  - **API**: agent skills endpoint updated to expose DoS as a built-in skill

- **Expanded Finding Types** — 8 new goal/outcome `finding_type` values for ChainFinding nodes, covering real-world pentesting outcomes beyond the original 10 types:
  - `data_exfiltration` — data successfully stolen/exfiltrated
  - `lateral_movement` — pivot to another system in the network
  - `persistence_established` — backdoor, cron job, or persistent access installed
  - `denial_of_service_success` — service confirmed down after DoS attack
  - `social_engineering_success` — phishing or social engineering succeeded
  - `remote_code_execution` — arbitrary code execution achieved
  - `session_hijacked` — existing user session taken over
  - `information_disclosure` — sensitive info leaked (source code, API keys, error messages)
  - LLM prompts updated to guide the agent in emitting the correct goal type
  - Analytics and report queries expanded to include all goal types

- **Goal Finding Visualization** — ChainFinding diamond nodes on the attack surface graph now visually distinguish goal/outcome findings from informational ones:
  - **Active chain**: goal diamonds are bright green (`#4ade80`), non-goal diamonds remain amber
  - **Inactive chain**: goal diamonds are dark green (`#276d43`), non-goal diamonds are dark yellow (`#3d3107`), other chain nodes remain dark grey
  - Inactive chain edges and particles darkened for better contrast
  - Active chain particles brighter (`#9ca3af`) for clear visual distinction
  - Applied consistently to both 2D and 3D graph renderers

- **Inline Model Picker** — the model badge in the AI assistant drawer is now clickable, opening a searchable modal to switch LLM model on the fly. Models are grouped by provider with context-length badges and descriptions. Includes a manual-input fallback when the models API is unreachable. Shared model utilities (`ModelOption` type, `formatContextLength`, `getDisplayName`) extracted into `modelUtils.ts` and reused across the drawer and project form.

- **Animated Loading Indicator** — replaced static "Processing..." text in the AI assistant chat with a dynamic loading experience:
  - **RedAmon eye logo** with randomized heartbeat animation (2–6s random intervals)
  - **Color-shifting pupil** cycling through 13 bright colors (yellow, cyan, orange, purple, green, pink, etc.)
  - **60 rotating hacker-themed phrases** displayed in random order every 5 seconds with fade-in animation (e.g., "Unmasking the hidden...", "Piercing the veil...", "Becoming root...")

- **URLScan.io OSINT Integration** — new passive enrichment module that queries URLScan.io's Search API to discover subdomains, IPs, TLS metadata, server technologies, domain age, and screenshots from historical scans. Runs in the recon pipeline after domain discovery, before port scanning. Full integration across the stack:
  - **New module**: `recon/urlscan_enrich.py` — fetches historical scan data from URLScan.io for each discovered domain. Works without API key (public results) or with API key (higher rate limits and access to private scans)
  - **Passive OSINT data**: discovers in-scope subdomains, IP addresses, URL paths for endpoint creation, TLS validity, ASN information, and external domains from historical scans
  - **GAU provider deduplication**: when URLScan enrichment has already run, the `urlscan` provider is automatically removed from GAU's data sources to avoid redundant API calls to the same underlying data
  - **Pipeline placement**: runs after domain discovery and before port scanning, alongside Shodan enrichment
  - **Project settings**: `urlscanEnabled` toggle and `urlscanMaxResults` (default: 500) configurable per project. Optional API key in Global Settings → API Keys
  - **Frontend**: new `UrlscanSection.tsx` in the Discovery & OSINT tab with passive badge, API key status indicator, and max results configuration

- **ExternalDomain Node** — new graph node type for tracking out-of-scope domains encountered during reconnaissance. Provides situational awareness about the target's external dependencies without scanning them:
  - **Schema**: `(:ExternalDomain { domain, sources[], redirect_from_urls[], redirect_to_urls[], status_codes_seen[], titles_seen[], servers_seen[], ips_seen[], countries_seen[], times_seen, first_seen_at, updated_at })`
  - **Relationship**: `(d:Domain)-[:HAS_EXTERNAL_DOMAIN]->(ed:ExternalDomain)`
  - **Multi-source aggregation**: external domains are collected from HTTP probe redirects, URLScan historical data, GAU passive archives, Katana crawling, and certificate transparency — then merged and deduplicated
  - **Neo4j constraints**: unique constraint on `(domain, user_id, project_id)` with tenant-scoped index
  - **Neo4j client**: new `update_graph_from_external_domains()` method for creating ExternalDomain nodes and HAS_EXTERNAL_DOMAIN relationships
  - **Graph schema docs**: `GRAPH.SCHEMA.md` updated with full ExternalDomain documentation

- **Subfinder Integration** — new passive subdomain discovery source in the recon pipeline. Queries 50+ online sources (certificate transparency, DNS databases, web archives, threat intelligence feeds) via ProjectDiscovery's Subfinder Docker image. No API keys required for basic operation (20+ free sources). Full multi-layer integration:
  - **Backend**: `run_subfinder()` in `domain_recon.py` using Docker-in-Docker pattern, JSONL parsing, max results capping
  - **Settings**: `subfinderEnabled` (default: true), `subfinderMaxResults` (default: 5000), `subfinderDockerImage` across Prisma schema, project settings, and defaults
  - **Frontend**: compact inline toggle with max results input in the Subdomain Discovery passive sources section
  - **Stealth mode**: max results capped to 100 (consistent with other passive sources)
  - **Entrypoint**: `projectdiscovery/subfinder:latest` added to Docker image pre-pull list
  - Results merge into existing subdomain flow — no graph schema changes needed

- **Puredns Wildcard Filtering** — new post-discovery validation step that removes wildcard DNS entries and DNS-poisoned subdomains before they reach the rest of the pipeline. Runs after the 5 discovery tools merge their results and before DNS resolution. Full multi-layer integration:
  - **Backend**: `run_puredns_resolve()` in `domain_recon.py` using Docker-in-Docker pattern with configurable threads, rate limiting, wildcard batch size, and skip-validation option
  - **Settings**: `purednsEnabled` (default: true), `purednsThreads` (default: 0 = auto), `purednsRateLimit` (default: 0 = unlimited), `purednsDockerImage` across Prisma schema, project settings, and defaults
  - **Frontend**: new "Wildcard Filtering" subsection with Active badge in the Subdomain Discovery section, with toggle and conditional thread/rate-limit inputs
  - **Stealth mode**: forced off (active DNS queries)
  - **RoE**: rate limit capped by global RoE max when enabled
  - **Entrypoint**: `frost19k/puredns:latest` added to Docker image pre-pull list, DNS resolver list auto-downloaded from trickest/resolvers (refreshed every 7 days)
  - **Graceful degradation**: on any error or timeout, returns the unfiltered subdomain list unchanged
  - **Orphan cleanup**: puredns image added to `SUB_CONTAINER_IMAGES` for force-stop container cleanup

- **Amass Integration** — OWASP Amass subdomain enumeration added to the recon pipeline as a new passive/active discovery source. Queries 50+ data sources (certificate transparency logs, DNS databases, web archives, WHOIS records) via the official Amass Docker image. Full multi-layer integration:
  - **Backend**: `run_amass()` in `domain_recon.py` using Docker-in-Docker pattern with configurable active mode, brute force, timeout, and max results capping
  - **Settings**: `amassEnabled` (default: false), `amassMaxResults` (default: 5000), `amassTimeout` (default: 10 min), `amassActive` (default: false), `amassBrute` (default: false), `amassDockerImage` across Prisma schema, project settings, and defaults
  - **Frontend**: compact inline toggle with max results input in the passive sources section, plus dedicated Amass Active Mode and Amass Bruteforce toggles in the active discovery section with time estimate warning
  - **Stealth mode**: active and brute force forced off, max results capped to 100
  - **Entrypoint**: `caffix/amass:latest` added to Docker image pre-pull list
  - Results merge into existing subdomain flow with per-source attribution — no graph schema changes needed

- **Parallelized Recon Pipeline (Fan-Out / Fan-In)** — the reconnaissance pipeline now uses `concurrent.futures.ThreadPoolExecutor` to run independent modules concurrently, significantly reducing total scan time while respecting data dependencies between groups:
  - **GROUP 1**: WHOIS + Subdomain Discovery + URLScan run in parallel (3 concurrent tasks). Within subdomain discovery, all 5 tools (crt.sh, HackerTarget, Subfinder, Amass, Knockpy) run concurrently via `ThreadPoolExecutor(max_workers=5)`. Each tool refactored into a thread-safe function with its own `requests.Session`
  - **GROUP 3**: Shodan Enrichment + Port Scan (Naabu) run in parallel (2 concurrent tasks). New `_isolated` function variants (`run_port_scan_isolated`, `run_shodan_enrichment_isolated`) accept a read-only snapshot and return only their data section
  - **DNS Resolution**: parallelized with 20 concurrent workers via `ThreadPoolExecutor(max_workers=20)` in `resolve_all_dns()`
  - **Background Graph DB Updates**: all Neo4j graph writes now run in a dedicated single-writer background thread (`_graph_update_bg`). The main pipeline submits deep-copy snapshots and continues immediately. `_graph_wait_all()` ensures completion before pipeline exit
  - **Structured Logging**: all log messages standardized to `[level][Module]` prefix format (e.g., `[+][crt.sh] Found 42 subdomains`) for clarity in concurrent output
  - Resource Enumeration (Katana, GAU, Kiterunner) was already internally parallel; Groups 4 (HTTP Probe) and 6 (Vuln Scan + MITRE) remain sequential as they depend on prior group results

- **Per-source Subdomain Attribution** — subdomain discovery now tracks which tool found each subdomain (crt.sh, hackertarget, subfinder, amass, knockpy). External domain entries carry accurate per-source labels instead of generic `cert_discovery`. `get_passive_subdomains()` returns `dict{subdomain: set_of_sources}` instead of a flat set

- **Compact Subdomain Discovery UI** — passive subdomain source toggles (crt.sh, HackerTarget, Subfinder, Amass, Knockpy) now display the tool name, max results input, and toggle on a single row instead of separate expandable sections

- **Discovery & OSINT Tab** — new unified tab in the project form replacing the previous scattered tool placement. Groups all passive and active discovery tools in a single section:
  - **Subdomain Discovery** — passive sources (crt.sh, HackerTarget, Subfinder, Amass, Knockpy Recon) and active discovery (Knockpy Bruteforce, Amass Active/Brute), plus DNS settings (WHOIS/DNS retries)
  - **Shodan OSINT Enrichment** — moved from the Integrations tab into Discovery & OSINT, reflecting its role as a core discovery tool rather than an external integration. All four toggles (Host Lookup, Reverse DNS, Domain DNS, Passive CVEs) remain unchanged
  - **URLScan.io Enrichment** — new section with passive badge, max results config, and API key status
  - **Node Info Tooltips** — each section header now has a waypoints icon that shows which graph node types the tool **consumes** (input, blue pills) and **produces** (output, purple pills) via `NodeInfoTooltip` component, `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` in `nodeMapping.ts`
  - Recon toggle switches moved to section headers for cleaner layout

- **Agent Guardrail Toggle** — the scope guardrail (LLM-based target verification) can now be enabled or disabled per project:
  - **New setting**: `agentGuardrailEnabled` (default: `true`) — when disabled, the agent skips the scope verification check on session start
  - **Initialize node**: guardrail check is now conditional, skipped when setting is false or on retries to avoid redundant LLM calls
  - **Think node**: scope guardrail reminder in the system prompt only injected when enabled
  - **Guardrail LLM bootstrapping**: the guardrail API endpoint now fetches the user's configured LLM providers from the database to properly initialize the LLM with the correct API keys (OpenAI, Anthropic, or OpenRouter)
  - **Frontend**: checkbox in Agent Behaviour section
  - **Fail-closed**: if the guardrail check itself fails (API error, LLM error), the agent is blocked by default (security-first)

- **Multi-source CVE Attribution** — CVE nodes created from Shodan data now track their source (`source` property) instead of hardcoding "shodan", enabling future enrichment from multiple CVE databases (NVD, Vulners, etc.)

- **API Key Rotation** — configure multiple API keys per tool with automatic round-robin rotation to avoid rate limits. Each key in Global Settings now has a "Key Rotation" button that opens a modal to add extra keys and set the rotation interval (default: every 10 API calls). All keys (main + extras) are treated equally in the rotation pool. Full multi-layer integration:
  - **Database**: new `ApiKeyRotationConfig` model with `userId + toolName` unique constraint, `extraKeys` (newline-separated), and `rotateEveryN` (default 10)
  - **Settings API**: `GET /api/users/[id]/settings` returns `rotationConfigs` with key counts (frontend) or full keys (`?internal=true`); `PUT` accepts rotation config upserts with masked-value preservation
  - **Frontend**: "Key Rotation" button next to each API key field; modal with textarea for extra keys (one per line) and rotation interval input; info badge showing total key count and rotation interval when configured
  - **Python KeyRotator**: pure-Python round-robin class (`key_rotation.py`) in both `agentic/` and `recon/` containers — no new dependencies, no Docker image rebuild needed
  - **Agent integration**: orchestrator builds `KeyRotator` per tool manager; `web_search`, `shodan`, and `google_dork` tools use `rotator.current_key` + `tick()` on each API call
  - **Recon integration**: single `_fetch_user_settings_full()` call replaces individual key fetches; rotators built for Shodan, URLScan, NVD, and Vulners; threaded through `_shodan_get`, `_urlscan_search`, `lookup_cves_nvd`, and `lookup_cves_vulners`
  - **Backward compatible**: with no extra keys configured, behavior is identical to before
  - **Tests**: 26 unit tests covering KeyRotator logic, rotation mechanics, integration with Shodan/URLScan/NVD/Vulners enrichment modules

- **NVD/Vulners API Keys moved to Global Settings** — NVD and Vulners API keys removed from the Project model and the project-level fallback chain. All 6 tool API keys (Tavily, Shodan, SerpAPI, NVD, Vulners, URLScan) are now exclusively user-scoped in Global Settings, consistent with the other keys.

### Fixed

- **Banner grabbing data loss** — fixed falsy value filtering in `neo4j_client.py` banner property handling. Changed `if v` to `if v is not None` to preserve empty strings and zero values that are valid banner data

### Changed

- Kali sandbox Dockerfile updated
- Shodan OSINT Enrichment moved from the Integrations tab to the new Discovery & OSINT tab in the project form
- Integrations tab now contains only GitHub Secret Hunting (Shodan removed)
- Recon pipeline toggle switches moved from section bodies to section headers for a cleaner UI
- Documentation and wiki updates

---

## [2.3.0] - 2026-03-14

### Added

- **Global Settings Page** — new `/settings` page (gear icon in header) for managing all user-level configuration through the UI. AI provider keys and Tavily API key are configured exclusively here — no `.env` file needed. Two sections:
  - **LLM Providers** — add, edit, delete, and test LLM provider configurations stored per-user in the database. Supports five provider types:
    - **OpenAI, Anthropic, OpenRouter** — enter API key, all models auto-discovered
    - **AWS Bedrock** — enter AWS credentials + region, foundation models auto-discovered
    - **OpenAI-Compatible** — single endpoint+model configuration with presets for Ollama, vLLM, LM Studio, Groq, Together AI, Fireworks AI, Mistral AI, and Deepinfra. Supports custom base URL, headers, timeout, temperature, and max tokens
  - **API Keys** — Tavily API key (web search), Shodan API key (internet-wide OSINT), and SerpAPI key (Google dorking)
- **Test Connection** — each LLM provider can be tested before saving with a "Test Connection" button that sends a simple message and shows the response
- **DB-only settings** — AI provider keys and Tavily API key are stored exclusively in the database (per-user). No env-var fallback — `.env` is reserved for infrastructure variables only (NVD, tunneling, database credentials, ports)
- **Prisma schema** — added `UserLlmProvider` and `UserSettings` models with relations to `User`
- **Centralized LLM setup** — CypherFix triage and codefix orchestrators now use the shared `setup_llm()` function instead of duplicating provider routing logic

- **Pentest Report Generation** — generate professional, client-ready penetration testing reports as self-contained HTML files from the `/reports` page. Reports compile all reconnaissance data, vulnerability findings, CVE intelligence, attack chain results, and remediation recommendations into an 11-section document (Cover, Executive Summary, Scope & Methodology, Risk Summary, Findings, Other Vulnerability Details, Attack Surface, CVE Intelligence, GitHub Secrets, Attack Chains, Recommendations, Appendix). Features include:
  - **LLM-generated narratives** — when an AI model is configured, six report sections receive detailed prose: executive summary (8–12 paragraphs), scope, risk analysis, findings context, attack surface analysis, and exhaustive prioritized remediation triage. Falls back gracefully to data-only reports when no LLM is available
  - **Security Posture Radar** — inline SVG 6-axis radar chart in the Risk Summary section showing Attack Surface, Vulnerability Density, Exploitability, Certificate Health, Injectable Parameters, and Security Header coverage using logarithmic normalization
  - **Security Headers Gap Analysis** — per-header weighted coverage bars (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy) with color-coded thresholds
  - **CISA KEV Callout** — prominent alert box highlighting Known Exploited Vulnerabilities when present
  - **Injectable Parameters Breakdown** — summary and per-position injection risk analysis with visual bars
  - **Attack Flow Chains** — Technology → CVE → CWE → CAPEC flow table showing complete attack paths
  - **CDN Coverage visualization** — ratio of CDN-fronted vs directly exposed IPs in the Attack Surface section
  - **Project-specific generation** — dedicated project selector dropdown on the reports page (independent of the top bar selection)
  - **Download and Open** — separate buttons to save the HTML file locally or open in a new browser tab
  - **Print/PDF optimized** — page breaks, print-friendly CSS, and clean SVG/CSS bar rendering for `Ctrl+P` export
  - **Export/Import support** — reports (metadata + HTML files) are included in project export ZIP archives and fully restored on import
  - **Wiki documentation** — new [Pentest Reports](redamon.wiki/20.-Pentest-Reports) wiki page with example report download

- **Target Guardrail** — LLM-based safety check that prevents targeting unauthorized domains and IPs. Blocks government sites (`.gov`, `.mil`), major tech companies, financial institutions, social media platforms, and other well-known public services. Two layers: project creation (fail-open) and agent initialization (fail-closed). For IP mode, public IPs are resolved via reverse DNS before evaluation; private/RFC1918 IPs are auto-allowed. Blocked targets show a centered modal with the reason.

- **Expanded CPE Technology Mappings** — CPE_MAPPINGS table in `recon/helpers/cve_helpers.py` expanded from 82 to 133 entries, significantly improving CVE lookup accuracy for Wappalyzer-detected technologies. New coverage includes:
  - **CMS**: Magento, Ghost, TYPO3, Concrete CMS, Craft CMS, Strapi, Umbraco, Adobe Experience Manager, Sitecore, DNN, Kentico
  - **Web Frameworks**: CodeIgniter, Symfony, CakePHP, Yii, Nuxt.js, Apache Struts, Adobe ColdFusion
  - **JavaScript Libraries**: Moment.js, Lodash, Handlebars, Ember.js, Backbone.js, Dojo, CKEditor, TinyMCE, Prototype
  - **E-commerce**: PrestaShop, OpenCart, osCommerce, Zen Cart, WooCommerce
  - **Message Boards / Community**: Discourse, phpBB, vBulletin, MyBB, Flarum, NodeBB, Mastodon, Mattermost
  - **Wikis**: MediaWiki, Atlassian Confluence, DokuWiki, XWiki
  - **Issue Trackers / DevOps**: Atlassian Jira, Atlassian Bitbucket, Bugzilla, Redmine, Gitea, TeamCity, Artifactory
  - **Hosting Panels**: cPanel, Plesk, DirectAdmin
  - **Web Servers**: OpenResty, Deno, Tengine
  - **Databases**: SQLite, Apache Solr, Adminer
  - **Security / Network**: Kong, F5 BIG-IP, Pulse Secure
  - **Webmail**: Zimbra, SquirrelMail
  - 29 new `normalize_product_name()` aliases for Wappalyzer output variations (e.g., "Atlassian Jira" → "jira", "Moment" → "moment.js", "Concrete5" → "concrete cms")
  - 6 new `skip_list` entries (Cloudflare, Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Google Font API) to avoid wasting NVD API calls on SaaS/CDN technologies

- **Insights Dashboard** — Real-time analytics page (`/insights`) with interactive charts and tables covering attack chains, exploit successes, finding severity, targets attacked, strategic decisions, vulnerability distributions, attack surface composition, and agent activity. All data is pulled directly from the Neo4j graph and organized into sections: Attack Chains & Exploits, Attack Surface, Vulnerabilities & CVE Intelligence, Graph Overview, and Activity & Timeline.

- **Rules of Engagement (RoE)** — upload a RoE document (PDF, TXT, MD, DOCX) at project creation and an LLM auto-parses it into structured settings enforced across the entire platform:
  - **Document upload & parsing** — file upload area in the RoE tab of the project form (create mode only). The agent extracts client info, scope, exclusions, time windows, testing permissions, rate limits, data handling policies, compliance frameworks, and more into 30+ structured fields
  - **Three enforcement layers** — (1) agent prompt injection: structured `RULES OF ENGAGEMENT (MANDATORY)` section injected into every reasoning step with excluded hosts, permissions, and constraints; (2) hard gate in `execute_tool_node`: deterministic code blocks forbidden tools, forbidden categories, permission flags, and phase cap violations regardless of LLM output; (3) recon pipeline: excluded hosts filtered from target lists, rate limits capped via `min(tool_rate, global_max)`, time window blocks scan starts outside allowed hours
  - **30+ RoE project fields** — client & engagement info, excluded hosts with reasons, time windows (days/hours/timezone), 6 testing permission toggles (DoS, social engineering, physical access, data exfiltration, account lockout, production testing), forbidden tool/category lists, max severity phase cap, global rate limit, sensitive data handling policy, data retention, encryption requirements, status update frequency, critical finding notification, incident procedure, compliance frameworks, third-party providers, and free-text notes
  - **RoE Viewer tab** on the graph dashboard — formatted read-only view with cards for engagement, scope, exclusions, time window (live ACTIVE/OUTSIDE WINDOW status), testing permissions (green/red badge grid), constraints, data handling, communication, compliance, and notes. Download button for the original uploaded document
  - **RoE toolbar badge** — blue "RoE" badge on the graph toolbar when engagement guardrails are active
  - **Smart tool restriction parsing** — only explicitly banned tools (e.g., "do not use Hydra") are disabled; "discouraged" or "use with caution" language is noted in the prompt but does not disable tools. Phase restrictions use `roeMaxSeverityPhase` instead of stripping phases from individual tools
  - **Export/import support** — RoE document binary is base64-encoded in project exports and restored on import. All RoE fields are included in the export ZIP
  - **Cascade deletion** — all RoE data (fields + document binary) deleted with the project via Prisma cascade
  - One-way at creation only — RoE settings become read-only after project creation to prevent mid-engagement modification
  - Based on industry standards: PTES, SANS, NIST SP 800-115, Microsoft RoE, HackerOne, Red Team Guide

- **Emergency PAUSE ALL button** — red/yellow danger-styled button on the Graph toolbar that instantly freezes every running pipeline (Recon, GVM, GitHub Hunt) and stops all AI agent conversations in one click. Shows "PAUSING..." with spinner during operation. Always visible on the toolbar, disabled when nothing is running. New `POST /emergency-stop-all` endpoint on the agent service cancels all active agent tasks via the WebSocket manager

- **Wave Runner (Parallel Tool Plans)** — when the LLM identifies two or more independent tools that don't depend on each other's outputs, it groups them into a **wave** and executes them concurrently via `asyncio.gather()` instead of sequentially. Key components:
  - **New LLM action**: `plan_tools` alongside `use_tool` — the LLM emits a `ToolPlan` with multiple `ToolPlanStep` entries and a plan rationale
  - **New LangGraph node**: `execute_plan` runs all steps in parallel, each with its own RoE gate check, tool_start/tool_complete streaming, and progress updates
  - **Combined wave analysis**: after all tools finish, the think node analyzes all outputs together in a single LLM call, producing consolidated findings and next steps
  - **Three new WebSocket events**: `plan_start` (wave begins with tool list), `plan_complete` (success/failure counts), `plan_analysis` (LLM interpretation). Existing `tool_start`, `tool_output_chunk`, and `tool_complete` events carry an optional `wave_id` to group tools within a wave
  - **Frontend PlanWaveCard**: grouped card in AgentTimeline showing all wave tools nested together with status badge (Running/Success/Partial/Error), plan rationale, combined analysis, actionable findings, and recommended next steps
  - **State management**: new `ToolPlan` and `ToolPlanStep` Pydantic models, `_current_plan` field in `AgentState`
  - **Graceful fallback**: empty `tool_plan` objects or plans with no steps are automatically downgraded to sequential `use_tool` execution

- **Agent Skills System** — modular attack path management with built-in and user-uploaded skills:
  - **Built-in Agent Skills** — four core skills (CVE (MSF), Credential Testing, Social Engineering Simulation, Availability Testing) can now be individually enabled or disabled per project via toggles in the new Agent Skills section of Project Settings. Disabling a skill prevents the agent from classifying requests into that attack type and removes its prompts from the system prompt. Sub-settings (Hydra config, SMTP config, DoS parameters) are shown inline when the corresponding skill is enabled
  - **User Agent Skills** — upload custom `.md` files defining attack workflows from Global Settings. Each skill file contains a full workflow description that the agent follows across all three phases (informational, exploitation, post-exploitation). User skills are stored per-user in the database (`UserAttackSkill` model) and become available as toggles in all project settings
  - **Skill Management in Global Settings** — dedicated "Agent Skills" section with upload button (accepts `.md` files, max 50KB), skill list with download and delete actions, and a name-entry modal on upload
  - **Per-project skill toggles** — `attackSkillConfig` JSON field in the project stores `{ builtIn: { skill_id: bool }, user: { skill_id: bool } }` controlling which skills are active. Built-in skills default to enabled; user skills default to enabled when present
  - **Agent integration** — LLM classifier routes requests to user skills via `user_skill:<id>` attack path type. Skill `.md` content is injected into the system prompt for all three phases with phase-appropriate guidance. Falls back to unclassified workflow if skill content is missing
  - **API endpoints** — `GET/POST /api/users/[id]/attack-skills` (list/create), `GET/DELETE /api/users/[id]/attack-skills/[skillId]` (read/delete), `GET /api/users/[id]/attack-skills/available` (with content for agent consumption)
  - Max 20 skills per user, 50KB per skill file

- **Kali Shell — Library Installation Control** — new prompt-based setting in Agent Behaviour to control whether the agent can install packages via `pip install` or `apt install` in `kali_shell` during a pentest:
  - **Toggle**: "Allow Library Installation" — when disabled (default), the system prompt instructs the agent to only use pre-installed tools and libraries. When enabled, the agent may install packages as needed for specific attacks
  - **Authorized Packages (whitelist)** — comma-separated list. When non-empty, only these packages may be installed; the agent is instructed not to install anything outside the list
  - **Forbidden Packages (blacklist)** — comma-separated list. These packages must never be installed, regardless of the whitelist
  - Installed packages are ephemeral — lost on container restart. Prompt-based control only (no server-side enforcement)
  - Conditional UI: whitelist and blacklist textareas only appear when the toggle is enabled
  - `build_kali_install_prompt()` dynamically generates the installation rules section, injected into the system prompt whenever `kali_shell` is in the allowed tools for the current phase

- **Shodan OSINT Integration** — full Shodan integration at two levels: automated recon pipeline and interactive AI agent tool:
  - **Pipeline enrichment** — new `recon/shodan_enrich.py` module runs after domain/IP discovery, before port scanning. Four independently toggled features: Host Lookup (IP geolocation, OS, ISP, open ports, services, banners), Reverse DNS (hostname discovery), Domain DNS (subdomain enumeration + DNS records, paid plan), and Passive CVEs (extract known CVEs from host data)
  - **InternetDB fallback** — when the Shodan API returns 403 (free key), host lookup and reverse DNS automatically fall back to Shodan's free InternetDB API (`internetdb.shodan.io`) which provides ports, hostnames, CPEs, CVEs, and tags without requiring a paid plan
  - **Graph database ingestion** — `update_graph_from_shodan()` in `neo4j_client.py` creates/updates IP nodes (os, isp, org, country, city), Port + Service nodes, Subdomain nodes from reverse DNS, DNSRecord nodes from domain DNS, and Vulnerability + CVE nodes from passive CVEs — all using MERGE for deduplication with existing pipeline data
  - **Agent tool** — unified `shodan` tool with 5 actions: `search` (device search, paid key), `host` (detailed IP info), `dns_reverse` (reverse DNS), `dns_domain` (DNS records + subdomains, paid key), and `count` (host count without search credits). Available in all agent phases
  - **Project settings** — 4 pipeline toggles in the Integrations tab (`ShodanSection.tsx`): Host Lookup, Reverse DNS, Domain DNS, Passive CVEs. Toggles are disabled with a warning banner when no Shodan API key is configured in Global Settings
  - **Graceful error handling** — `ShodanApiKeyError` exception for immediate abort on invalid keys (401); per-function 403 handling with InternetDB fallback; pipeline continues even if Shodan enrichment fails entirely

- **Google Dork Tool (SerpAPI)** — new `google_dork` agent tool for passive OSINT via Google advanced search operators. Uses the SerpAPI Google engine to find exposed files (`filetype:sql`, `filetype:env`), admin panels (`inurl:admin`), directory listings (`intitle:"index of"`), and sensitive data leaks (`intext:password`). Returns up to 10 results with titles, URLs, snippets, and total result count. SerpAPI key configured in Global Settings. No packets are sent to the target — purely passive reconnaissance

- **Deep Think (Strategic Reasoning)** — automatic strategic analysis at key decision points during agent operation. Triggers on: first iteration (initial strategy), phase transitions (re-evaluation), failure loops (3+ consecutive failures trigger pivot), and agent self-request (when stuck or going in circles). Produces structured JSON analysis with situation assessment, identified attack vectors, recommended approach with rationale, priority-ordered action steps, and risk mitigations. The analysis is injected into subsequent reasoning steps to guide the agent's strategy:
  - **Toggle**: `DEEP_THINK_ENABLED` in Agent Behaviour settings (default: off)
  - **Self-request**: agent can set `"need_deep_think": true` in its output to trigger a strategic re-evaluation on the next iteration
  - **Frontend card**: `DeepThinkCard` in the Agent Timeline displays the analysis with trigger reason, situation assessment, attack vectors, recommended approach, priority steps, and risks — collapsible with a lightbulb icon
  - **WebSocket event**: `deep_think` event streams the analysis result to the frontend in real-time

- **Inline Agent Settings** — Agent Behaviour, Tool Matrix, and Agent Skills sections are now accessible directly from the AI Assistant drawer via a gear icon in the toolbar. Opens a modal overlay for quick configuration changes without navigating away from the graph page. Changes are saved to the project and take effect on the next agent iteration

- **Inline API Key Configuration** — when an agent tool is unavailable due to a missing API key (web_search, shodan, google_dork), the AI Assistant drawer shows a warning badge with a one-click modal to enter the key directly. No need to navigate to Global Settings

- **Tool Registry Overhaul** — compressed and restructured the agent's tool registry descriptions for all tools (query_graph, web_search, shodan, google_dork, curl, nmap, kali_shell, hydra, metasploit_command). Descriptions are more concise with inline argument formats and usage examples, reducing prompt token usage while maintaining clarity

### Fixed

- **Project export/import missing Remediations** — The `Remediation` table (CypherFix vulnerability remediations, code fixes, GitHub PR integrations, file changes) was not included in project export/import. Exports now include `remediations/remediations.json` in the ZIP archive, and imports restore all remediation records under the new project. Backward-compatible with older exports that lack the remediations file.

### Changed

- **Docker CLI upgrade in recon container** — Replaced Debian's `docker.io` package with `docker-ce-cli` from Docker's official APT repository. Fixes compatibility issues with newer host Docker daemons (closes #30, based on #35). Only the CLI is installed — no full engine, containerd, or compose plugins.

---

## [2.2.0] - 2026-03-05

### Added

- **Pipeline Pause / Resume / Stop Controls** — full lifecycle management for all three pipelines (Recon, GVM Scan, GitHub Secret Hunt):
  - **Pause** — freezes the running container via Docker cgroups (`container.pause()`). Zero changes to scan scripts; processes resume exactly where they left off
  - **Resume** — unfreezes the container (`container.unpause()`), logs resume streaming instantly
  - **Stop** — kills the container permanently. Paused containers are unpaused before stopping to avoid cgroup issues. Sub-containers (naabu, httpx, nuclei, etc.) are also cleaned up
  - **Toolbar UI** — when running: spinner + Pause button + Stop button. When paused: Resume button + Stop button. When stopping: "Stopping..." with disabled controls
  - **Logs drawer controls** — pause/resume and stop buttons in the status bar, with `Paused` status indicator and spinner during stopping
  - **Optimistic UI** — stop button immediately shows "Stopping..." before the API responds
  - **SSE stays alive** during pause and stopping states so logs resume/complete without reconnection
  - 6 new backend endpoints (`POST /{recon,gvm,github-hunt}/{projectId}/{pause,resume}`) and 9 new webapp API proxy routes (pause/resume/stop × 3 pipelines)
  - Removed the auto-scroll play/pause toggle from logs drawer (redundant with "Scroll to bottom" button)
- **IP/CIDR Targeting Mode** — start reconnaissance from IP addresses or CIDR ranges instead of a domain:
  - **"Start from IP" toggle** in the Target & Modules tab — switches the project from domain-based to IP-based targeting. Locked after creation (cannot switch modes on existing projects)
  - **Target IPs / CIDRs textarea** — accepts individual IPs (`192.168.1.1`), IPv6 (`2001:db8::1`), and CIDR ranges (`10.0.0.0/24`, `192.168.1.0/28`) with a max /24 (256 hosts) limit per CIDR
  - **Reverse DNS (PTR) resolution** — each IP is resolved to its hostname via PTR records. When no PTR exists, a mock hostname is generated from the IP (e.g., `192-168-1-1`)
  - **CIDR expansion** — CIDR ranges are automatically expanded into individual host IPs (network and broadcast addresses excluded). Original CIDRs are passed to naabu for efficient native scanning
  - **Full pipeline support** — IP-mode projects run the complete 6-phase pipeline: reverse DNS + IP WHOIS → port scan → HTTP probe → resource enumeration (Katana, Kiterunner) → vulnerability scan (Nuclei) → CVE/MITRE enrichment
  - **Neo4j graph integration** — mock Domain node (`ip-targets.{project_id}`) with `ip_mode: true`, Subdomain nodes (real PTR hostnames or IP-based mocks), IP nodes with WHOIS data, and all downstream relationships
  - **Tenant-scoped Neo4j constraints** — IP, Subdomain, BaseURL, Port, Service, and Technology uniqueness constraints are now scoped to `(key, user_id, project_id)`, allowing the same IP/subdomain to exist in different projects without conflicts
  - **Input validation** — new `webapp/src/lib/validation.ts` module with regex validators for IPs, CIDRs, domains, ports, status codes, HTTP headers, GitHub tokens, and more. Validation runs on form submit
  - `ipMode` and `targetIps` fields added to Prisma schema with database migration
- **Chisel TCP Tunnel Integration** — multi-port reverse tunnel alternative to ngrok for full attack path support:
  - chisel (v1.11.4) installed alongside ngrok in kali-sandbox Dockerfile — single binary, supports amd64 and arm64
  - Reverse tunnels both port 4444 (handler) and port 8080 (web delivery/HTA) through a single connection to a VPS
  - Enables **Web Delivery** (Method C) and **HTA Delivery** (Method D) phishing attacks that require two ports — previously blocked with ngrok's single-port limitation
  - **Stageless** Meterpreter payloads required through chisel (staged payloads fail through tunnels — same as ngrok)
  - Deterministic endpoint discovery — LHOST derived from `CHISEL_SERVER_URL` hostname (no API polling needed)
  - Auto-reconnect with exponential backoff if VPS connection drops
  - `CHISEL_SERVER_URL` and `CHISEL_AUTH` env vars added to `.env.example` and `docker-compose.yml`
  - `_query_chisel_tunnel()` utility in `agentic/utils.py` with `get_session_config_prompt()` integration
  - `agentChiselTunnelEnabled` Prisma field with database migration
- **Social Engineering Simulation Attack Path** (`phishing_social_engineering`) — third classified attack path with a mandatory 6-step workflow: target platform selection, handler setup, payload generation, verification, delivery, and session callback:
  - **Standalone Payloads** (Method A): msfvenom-based payload generation for Windows (exe, psh, psh-reflection, vba, hta-psh), Linux (elf, bash, python), macOS (macho), Android (apk), Java (war), and cross-platform (python) — with optional AV evasion via shikata_ga_nai encoding
  - **Malicious Documents** (Method B): Metasploit fileformat modules for weaponized Word macro (.docm), Excel macro (.xlsm), PDF (Adobe Reader exploit), RTF (CVE-2017-0199 HTA handler), and LNK shortcut files
  - **Web Delivery** (Method C): fileless one-liner delivery via `exploit/multi/script/web_delivery` supporting Python, PHP, PowerShell, Regsvr32 (AppLocker bypass), pubprn, SyncAppvPublishingServer, and PSH Binary targets
  - **HTA Delivery** (Method D): HTML Application server via `exploit/windows/misc/hta_server` for browser-based payload delivery
  - **Email Delivery**: Python smtplib-based email sending via `execute_code` with per-project SMTP configuration (host, port, user, password, sender, TLS) — agent asks at runtime if no SMTP settings are configured
  - **Chat Download**: default delivery via `docker cp` command reported in chat
  - New prompt module `phishing_social_engineering_prompts.py` with `PHISHING_SOCIAL_ENGINEERING_TOOLS` (full workflow) and `PHISHING_PAYLOAD_FORMAT_GUIDANCE` (OS-specific format decision tree and msfvenom quick reference)
  - LLM classifier updated with phishing keywords and 10 example requests for accurate routing
  - `phishing_social_engineering` added to `KNOWN_ATTACK_PATHS` set and `AttackPathClassification` validator
- **ngrok TCP Tunnel Integration** — automatic reverse shell tunneling through ngrok for NAT/cloud environments:
  - ngrok installed in kali-sandbox Dockerfile and auto-started in `entrypoint.sh` when `NGROK_AUTHTOKEN` env var is set
  - TCP tunnel on port 4444 with ngrok API exposed on port 4040
  - `_query_ngrok_tunnel()` utility in `agentic/utils.py` that queries ngrok API, discovers the public TCP endpoint, and resolves the hostname to an IP for targets with limited DNS
  - `get_session_config_prompt()` auto-detects LHOST/LPORT from ngrok when enabled — injects a status banner, dual LHOST/LPORT table (handler vs payload), and enforces REVERSE-only payloads through ngrok
  - `is_session_config_complete()` short-circuits to complete when ngrok tunnel is active
  - `NGROK_AUTHTOKEN` added to `.env.example` and `docker-compose.yml` (kali-sandbox env + port 4040 exposed)
- **Phishing Section in Project Settings** — new `PhishingSection` component with SMTP configuration textarea for per-project email delivery settings
- **Tunnel Provider Dropdown** — replaced the single "Enable ngrok TCP Tunnel" toggle in Agent Behaviour settings with a **Tunnel Provider** dropdown (None / ngrok / chisel). Mutually exclusive — selecting one automatically disables the other
- **Social Engineering Suggestion Templates** — 15 new suggestion buttons in AI Assistant drawer under a pink "Social Engineering" template group (Mail icon), covering payload generation, malicious documents, web delivery, HTA, email phishing, AV evasion, and more
- **Phishing Attack Path Badge** — pink "PHISH" badge with `#ec4899` accent color for phishing sessions in the AI Assistant drawer
- **Prisma Migrations** — `20260228120000_add_ngrok_tunnel` (agentNgrokTunnelEnabled), `20260228130000_add_phishing_smtp_config` (phishingSmtpConfig), and `20260305145750_add_ip_mode` (ipMode, targetIps) database migrations
- **Remote Shells Tab** — new "Remote Shells" tab on the graph dashboard for real-time session management:
  - Unified view of all active Metasploit sessions (meterpreter, shell), background handlers/jobs, and non-MSF listeners (netcat, socat)
  - Sessions auto-detected from the Kali sandbox with 3-second polling and background cache refresh
  - Built-in interactive terminal with command history (arrow keys), session-aware prompts, and auto-scroll
  - Session actions: kill, upgrade shell to meterpreter, stop background jobs
  - Agent busy detection with lock-timeout strategy — session listing always works from cache, interaction retries when lock is available
  - Session-to-chat mapping — each session card shows which AI agent chat session created it
  - Non-MSF session registration when agent creates netcat/socat listeners via `kali_shell`
- **Command Whisperer** — AI-powered NLP-to-command translator in the Remote Shells terminal:
  - Natural language input bar (purple accent) above the terminal command line
  - Describe what you want in plain English → LLM generates the correct command for the current session type (meterpreter vs shell)
  - Uses the project's configured LLM (same model as the AI agent) via a new `/command-whisperer` API endpoint
  - Generated commands auto-fill the terminal input for review — no auto-execution
- **Metasploit Session Persistence** — removed automatic Metasploit restart on new conversations:
  - Removed `start_msf_prewarm` call from WebSocket initialization
  - Removed `sessions -K` soft-reset on first `metasploit_console` use
  - `msf_restart` tool now visible to the AI agent for manual use when a clean state is needed

### Changed

- **Model selector** — now passes `userId` to `/api/models` to fetch models from user-specific DB-stored providers
- **Agent orchestrator** — removed all env-var reads for AI provider keys; keys come exclusively from DB-stored user providers
- **`.env.example`** — stripped of all AI provider keys; now contains only infrastructure variables (NVD, tunneling, database)
- **Conflict detection** — IP-mode projects skip domain conflict checks entirely (tenant-scoped Neo4j constraints make IP overlap safe across projects). Domain-mode conflict detection unchanged
- **HTTP probe scope filtering** — `is_host_in_scope()` reordered to check `allowed_hosts` before `root_domain` scope, fixing IP-mode where the fake root domain caused all real hostnames to be filtered out. Added `input` URL fallback for redirect chains
- **GAU disabled in IP mode** — passive URL archives index by domain, not IP; GAU is automatically skipped when `ip_mode` is active
- **Domain ownership verification** skipped in IP mode — not applicable to IP-based targets
- **Session Config Prompt** — refactored to inject pre-configured payload settings (LHOST/LPORT/ngrok) BEFORE the attack chain workflow, so all attack paths (not just CVE exploit) see payload direction — previously injected only after CVE fallback
- **Agent prompts updated** — phishing, CVE exploit, and post-exploitation prompts now conditionally guide the agent based on which tunnel provider is active (ngrok limitations vs chisel capabilities)
- **Recon: HTTP Probe DNS Fallback** — now probes common non-standard HTTP ports (8080, 8000, 8888, 3000, 5000, 9000) and HTTPS ports (8443, 4443, 9443) when falling back to DNS-only target building, improving coverage when naabu port scan results are empty
- **Recon: Port Scanner SYN→CONNECT Retry** — when SYN scan completes but finds 0 open ports (firewall silently dropping SYN probes), automatically retries with CONNECT scan (full TCP handshake) which works through most firewalls
- **Wiki and documentation** — updated AI Agent Guide, Project Settings Reference, Attack Paths guide, and README with dual tunnel provider documentation

### Fixed

- **Duplicate port in https_ports set** — removed duplicate `443` and stale `8080` from `https_ports` in `build_targets_from_naabu()`

---

## [2.1.0] - 2026-02-27

### Added

- **CypherFix — Automated Vulnerability Remediation Pipeline** — end-to-end system that takes offensive findings from the Neo4j graph and turns them into merged code fixes:
  - **Triage Agent** (`cypherfix_triage/`): AI agent that queries the Neo4j knowledge graph, correlates hundreds of reconnaissance and exploitation findings, deduplicates them, ranks by exploitability and severity, and produces a prioritized remediation plan
  - **CodeFix Agent** (`cypherfix_codefix/`): autonomous code-repair agent that clones the target repository, navigates the codebase with 11 code-aware tools, implements targeted fixes for each triaged vulnerability, and opens a GitHub pull request ready for review and merge
  - Real-time WebSocket streaming for both Triage and CodeFix agents with dedicated hooks (`useCypherFixTriageWS`, `useCypherFixCodeFixWS`)
  - Remediations API (`/api/remediations/`) and hook (`useRemediations`) for persisting and retrieving remediation results
  - CypherFix API routes (`/api/cypherfix/`) for triggering and managing triage and codefix sessions
  - Agent-side API endpoints and orchestrator integration in `api.py` and `orchestrator.py`
- **CypherFix Tab on Graph Page** — new tab (`CypherFixTab/`) in the Graph dashboard providing a dedicated interface to launch triage, review prioritized findings, trigger code fixes, and monitor remediation progress
- **CypherFix Settings Section** — new `CypherFixSettingsSection` in Project Settings for configuring CypherFix parameters (GitHub repo, branch, AI model, triage/codefix behavior)
- **CypherFix Type System** (`cypherfix-types.ts`) — shared TypeScript types for triage results, codefix sessions, remediation records, and WebSocket message protocols
- **Agentic README Documentation** (`readmes/`) — internal documentation for the agentic module

### Changed

- **Global Header** — updated navigation to include CypherFix access point
- **View Tabs** — styling updates to accommodate the new CypherFix tab
- **Project Form** — expanded with CypherFix settings section and updated section exports
- **Hooks barrel export** — updated `hooks/index.ts` with new CypherFix and remediation hooks
- **Prisma Schema** — new fields for CypherFix configuration in the project model
- **Agent Requirements** — new Python dependencies for CypherFix agents
- **Docker Compose** — updated service configuration for CypherFix support
- **README** — version bump to v2.1.0, CypherFix badge added, pipeline description updated

---

## [2.0.0] - 2026-02-22

### Added

- **Project Export & Import** — full project portability via ZIP archives:
  - Export (`GET /api/projects/{id}/export`): streams a ZIP containing project settings, conversation history, Neo4j graph data (nodes + relationships with stable `_exportId` UUIDs), and recon/GVM/GitHub Hunt artifact files
  - Import (`POST /api/projects/import`): restores a project from ZIP under a specified user with domain/subdomain conflict validation, constraint-aware Neo4j import (MERGE for unique-constrained labels, CREATE for unconstrained via APOC), and conversation session ID deduplication
  - Import modal with drag-to-select file picker on the Projects page; Export button on Project Settings page
- **EvoGraph — Dynamic Attack Chain Visualization** — real-time evolutionary graph that updates as agent sessions progress with attack chains:
  - New `chain_graph_writer.py` module replacing the legacy `exploit_writer.py`
  - Five new Neo4j node types: `AttackChain` (session root), `ChainStep` (tool execution), `ChainFinding` (discovered vulnerability/credential/info), `ChainDecision` (phase transition), `ChainFailure` (error/dead-end)
  - Rich relationship model: `CHAIN_TARGETS`, `HAS_STEP`, `NEXT_STEP`, `LED_TO`, `DECISION_PRECEDED`, `PRODUCED`, `FAILED_WITH`, plus bridge relationships to the recon graph (`STEP_TARGETED`, `STEP_EXPLOITED`, `STEP_IDENTIFIED`, `FOUND_ON`, `FINDING_RELATES_CVE`)
  - Visual differentiation on the graph canvas: inactive session chains render grey (orange when selected), active session ring pulses yellow, chain flow particles are static grey
  - Cross-session awareness via `query_prior_chains()`: the agent knows what has already been tried in previous sessions
  - All graph writes are async fire-and-forget (never block the orchestrator loop)
- **Multi-Session System** — parallel attack sessions with full concurrency support:
  - Multiple independent agent sessions per project, each with its own WebSocket connection keyed by `user_id:project_id:session_id`
  - Per-session guidance queues and streaming callbacks (dicts keyed by `session_id`) preventing cross-session interference
  - Central task registry (`_active_tasks`) that survives WebSocket reconnection — agents keep running in the background when users disconnect or switch conversations
  - Connection replacement on reconnect: transfers running task, stop state, and guidance queue seamlessly
  - Metasploit prewarm per session key
- **Chat Persistence & Conversation History** — full message durability and session management:
  - Ordered `asyncio.Queue` + single background worker replacing fire-and-forget `asyncio.create_task()`, ensuring messages are saved with correct `sequenceNum`
  - All message types persisted: thinking, tool_start/complete (with raw output), phase updates, approval/question requests, responses, errors, todos
  - Conversation CRUD API routes: list, get with messages, lookup by session, update, delete
  - ConversationHistory panel in AI Assistant drawer with session title, status badge, phase indicator, iteration count, relative timestamps, and live "agent running" pulsing dot
  - Full state restoration when loading a conversation: chat items, todo lists, pending approval/question state, phase, iteration count
- **Per-Session Graph Controls** — granular visibility management for attack chains on the graph:
  - "Show only this session in graph" toggle button in AI drawer header
  - Sessions popup in the bottom bar with per-chain ON/OFF toggles, plus "All" / "None" bulk controls
  - Session badge showing `visible/total` count
  - Session title display (user's initial message truncated to 30 chars) instead of session ID codes
- **Data Table View** — alternative tabular visualization of the attack surface graph:
  - Graph Map / Data Table view tabs with Lucide icons
  - `@tanstack/react-table` powered table with columns: Type (color-coded), Name, Properties count, In/Out connections, L2/L3 hop counts
  - Global text filter, client-side sorting on all columns, row expansion with full property display
  - Pagination (10/25/50/100 per page) and XLSX Excel export
- **User Selector in Global Header** — switch between users directly from the top bar without navigating away, with two-letter avatar initials, dropdown user list, and "Manage Users" link
- **OpenAI-Compatible Provider** — fifth AI provider supporting any OpenAI API-compatible endpoint (Ollama, LM Studio, vLLM, local proxies) via `OPENAI_COMPAT_BASE_URL` and `OPENAI_COMPAT_API_KEY` env vars, with `openai_compat/` prefix convention for model detection
- **Hydra Credential Testing Attack Path** — dedicated credential testing attack path powered by THC Hydra, replacing Metasploit for credential-guessing operations with significantly higher performance. Supports 50+ protocols (SSH, FTP, RDP, SMB, MySQL, HTTP forms, and more) with configurable threads, timeouts, extra checks, and wordlist strategies. After credentials are discovered, the agent establishes access via `sshpass`, database clients, or protocol-specific tools
- **Unclassified Attack Paths** — agent orchestrator now supports attack paths that don't fit the CVE (MSF) or Hydra Credential Testing categories, with dedicated prompts in `unclassified_prompts.py`
- **GitHub Wiki** — 13-page documentation wiki covering getting started, user management, project creation, graph dashboard, reconnaissance, GVM scanning, GitHub secret hunting, AI agent guide, project settings reference, AI model providers, attack surface graph, data export/import, and troubleshooting

### Changed

- **Agent Orchestrator** — major refactoring: per-session dictionaries for guidance queues and streaming callbacks, central task registry for connection-resilient background tasks, dynamic connection resolution via `ws_manager`
- **Graph Canvas** — new node types (ChainFinding, ChainDecision, ChainFailure) with distinct visual styling, session-aware coloring and particle rendering
- **Graph API** — expanded to return attack chain data with session-level grouping
- **PageBottomBar** — redesigned with session visibility controls, view-mode awareness, and session title display
- **UI Theme Hierarchy** — light mode background layers reorganized (white → gray-50 → gray-100 → gray-200 → gray-300), added `--bg-quaternary` token
- **Global Header** — navigation tabs (Projects/Red Zone) moved to right side, Graph Map/Data Table view tabs added, AI Agent button restyled to crimson, user selector added
- **Node Drawer** — styling improvements, new chain node type support
- **Target Section** — domain, subdomains, and root domain toggle locked in edit mode to prevent graph data inconsistency
- **README** — comprehensive rewrite reflecting v2.0 features

### Removed

- **`exploit_writer.py`** — replaced by `chain_graph_writer.py` with full EvoGraph support
- **`README.METASPLOIT.GUIDE.md`** — removed from agentic module

### Fixed

- **Race condition in chat message persistence** — fire-and-forget `asyncio.create_task()` caused messages to be saved with incorrect `sequenceNum`; replaced with ordered queue + single background worker
- **Race condition in concurrent sessions** — `_guidance_queue` and `_streaming_callback` were single instance variables overwritten by each new session; changed to per-session dictionaries keyed by `session_id`

---

## [1.3.0] - 2026-02-19

### Added

- **Multi-Provider LLM Support** — the agent now supports **4 AI providers** (OpenAI, Anthropic, OpenRouter, AWS Bedrock) with 400+ selectable models. Models are dynamically fetched from each provider's API and cached for 1 hour. Provider is auto-detected via a prefix convention (`openrouter/`, `bedrock/`, `claude-*`, or plain OpenAI)
- **Dynamic Model Selector** — replaced the hardcoded 11-model dropdown with a searchable, provider-grouped model picker in Project Settings. Type to filter across all providers instantly; each model shows name, context window, and pricing info
- **`GET /models` API Endpoint** — new agent endpoint that fetches available models from all configured providers in parallel. Proxied through the webapp at `/api/models`
- **`model_providers.py`** — new provider discovery module with async fetchers for OpenAI, Anthropic, OpenRouter, and AWS Bedrock APIs, with in-memory caching (1h TTL)
- **Stealth Mode** — new per-project toggle that forces the entire pipeline to use only passive and low-noise techniques:
  - Recon: disables Kiterunner and banner grabbing, switches Naabu to CONNECT scan with rate limiting, throttles httpx/Katana/Nuclei, disables DAST and interactsh callbacks
  - Agent: injects stealth rules into the system prompt — only passive/stealthy methods allowed, agent must refuse if stealth is impossible
  - GVM scanning disabled in stealth mode (generates ~50K active probes per target)
- **Stealth Mode UI** — toggle in Target section of Project Settings with description of what it does
- **Kali Sandbox Tooling Expansion** — 15+ new packages installed in the Kali container: `netcat`, `socat`, `rlwrap`, `exploitdb`, `john`, `smbclient`, `sqlmap`, `jq`, `gcc`, `g++`, `make`, `perl`, `go`
- **`kali_shell` MCP Tool** — direct Kali Linux shell command execution, available in all phases
- **`execute_code` MCP Tool** — run custom Python/Bash exploit scripts on the Kali sandbox
- **`msf_restart` MCP Tool** — restart Metasploit RPC daemon when it becomes unresponsive
- **`execute_nmap` MCP Tool** — deep service analysis, OS fingerprinting, NSE scripts (consolidated from previous naabu-only setup)
- **MCP Server Consolidation** — merged curl and naabu servers into a unified `network_recon_server.py`, added dedicated `nmap_server.py`, fixed tool loading race condition
- **Failure Loop Detection** — agent detects 3+ consecutive similar failures and injects a pivot warning to break out of unproductive loops
- **Prompt Token Optimization** — lazy no-module fallback injection (saves ~1.1K tokens), compact formatting for older execution trace steps (full output only for last 5), trimmed rarely-used wordlist tables
- **Metasploit Prewarm** — pre-initializes Metasploit console on agent startup to reduce first-use latency
- **Markdown Report Export** — download the full agent conversation as a formatted Markdown file
- **Hydra Credential Testing & CVE (MSF) Settings** — new Project Settings sections for configuring Hydra credential testing (threads, timeouts, extra checks, wordlist limits) and CVE exploit attack path parameters
- **Node.js Deserialization Guinea Pig** — new test environment for CVE-2017-5941 (node-serialize RCE)
- **Phase Tools Tooltip** — hover on phase badges to see which MCP tools are available in that phase
- **GitHub Secrets Suggestion** — new suggestion button in AI Assistant to leverage discovered GitHub secrets during exploitation

### Changed

- **Agent Orchestrator** — rewritten `_setup_llm()` with 4-way provider detection (OpenAI, Anthropic, OpenRouter via ChatOpenAI + custom base_url, Bedrock via ChatBedrockConverse with lazy import)
- **Model Display** — `formatModelDisplay()` helper cleans up prefixed model names in the AI Assistant badge and markdown export (e.g., `openrouter/meta-llama/llama-4-maverick` → `llama-4-maverick (OR)`)
- **Prompt Architecture** — tool registry extracted into dedicated `tool_registry.py`, attack path prompts (CVE exploit, credential testing, post-exploitation) significantly reworked for better token efficiency and exploitation success rates
- **curl-based Exploitation** — expanded curl-based vulnerability probing and no-module fallback workflows for when Metasploit modules aren't available
- **kali_shell & execute_nuclei** — expanded to all phases (previously restricted)
- **GVM Button** — disabled in stealth mode with tooltip explaining why
- **README** — extensive updates: 4-provider documentation, AI Model Providers section, Kali sandbox tooling tables, new badges (400+ AI Models, Stealth Mode, Full Kill Chain, 30+ Security Tools, 9000+ Vuln Templates, 170K+ NVTs, 180+ Settings), version bump to v1.3.0

---

## [1.2.0] - 2026-02-13

### Added

- **GVM Vulnerability Scanning** — full end-to-end integration of Greenbone Vulnerability Management (GVM/OpenVAS) into the RedAmon pipeline:
  - Python scanner module (`gvm_scan/`) with `GVMScanner` class wrapping the GMP protocol for headless API-based scanning
  - Orchestrator endpoints (`/gvm/{id}/start`, `/gvm/{id}/status`, `/gvm/{id}/stop`, `/gvm/{id}/logs`) with SSE log streaming
  - Webapp API routes, `useGvmStatus` polling hook, `useGvmSSE` streaming hook, toolbar buttons, and log drawer on the Graph page
  - Neo4j graph integration — GVM findings stored as `Vulnerability` nodes (source="gvm") linked to IP/Subdomain via `HAS_VULNERABILITY`, with associated `CVE` nodes
  - JSON result download from the Graph page toolbar
- **GitHub Secret Hunt** — automated secret and credential detection across GitHub organizations and user repositories:
  - Python scanner module (`github_secret_hunt/`) with `GitHubSecretHunter` class supporting 40+ regex patterns for AWS, Azure, GCP, GitHub, Slack, Stripe, database connection strings, CI/CD tokens, cryptographic keys, JWT/Bearer tokens, and more
  - High-entropy string detection via Shannon entropy to catch unknown secret formats
  - Sensitive filename detection (`.env`, `.pem`, `.key`, credentials files, Kubernetes kubeconfig, Terraform tfvars, etc.)
  - Commit history scanning (configurable depth, default 100 commits) and gist scanning
  - Organization member repository enumeration with rate-limit handling and exponential backoff
  - Orchestrator endpoints (`/github-hunt/{id}/start`, `/github-hunt/{id}/status`, `/github-hunt/{id}/stop`, `/github-hunt/{id}/logs`) with SSE log streaming
  - Webapp API routes for start, status, stop, log streaming, and JSON result download
  - `useGithubHuntStatus` polling hook and `useGithubHuntSSE` streaming hook for real-time UI updates
  - Graph page toolbar integration with start/stop button, log drawer, and result download
  - JSON output with statistics (repos scanned, files scanned, commits scanned, gists scanned, secrets found, sensitive files, high-entropy findings)
- **GitHub Hunt Per-Project Settings** — GitHub scan configuration is now configurable per-project via the webapp UI:
  - New "GitHub" section in Project Settings with token, target org/user, and scan options
  - 7 configurable fields: Access Token, Target Organization, Scan Members, Scan Gists, Scan Commits, Max Commits, Output JSON
  - `github_secret_hunt/project_settings.py` mirrors the recon/GVM settings pattern (fetch from webapp API, fallback to defaults)
  - 7 new Prisma schema fields (`github_access_token`, `github_target_org`, `github_scan_members`, `github_scan_gists`, `github_scan_commits`, `github_max_commits`, `github_output_json`)
- **GVM Per-Project Settings** — GVM scan configuration is now configurable per-project via the webapp UI:
  - New "GVM Scan" tab in Project Settings (between Integrations and Agent Behaviour)
  - 5 configurable fields: Scan Profile, Scan Targets Strategy, Task Timeout, Poll Interval, Cleanup After Scan
  - `gvm_scan/project_settings.py` mirrors the recon/agentic settings pattern (fetch from webapp API, fallback to defaults)
  - Defaults served via orchestrator `/defaults` endpoint using `importlib` to avoid module name collision
  - 5 new Prisma schema fields (`gvm_scan_config`, `gvm_scan_targets`, `gvm_task_timeout`, `gvm_poll_interval`, `gvm_cleanup_after_scan`)

### Changed

- **Webapp Dockerfile** — embedded Prisma CLI in the production image; entrypoint now runs `prisma db push` automatically on startup, eliminating the separate `webapp-init` container
- **Dev Compose** — `docker-compose.dev.yml` now runs `prisma db push` before `npm run dev` to ensure schema is always in sync
- **Docker Compose** — removed `webapp-init` service and `webapp_prisma_cache` volume; webapp handles its own schema migration

### Removed

- **`webapp-init` service** — replaced by automatic migration in the webapp entrypoint (both production and dev modes)
- **`gvm_scan/params.py`** — hardcoded GVM settings replaced by per-project `project_settings.py`

---

## [1.1.0] - 2026-02-08

### Added

- **Attack Path System** — agent now supports dynamic attack path selection with two built-in paths:
  - **CVE (MSF)** — automated Metasploit module search, payload configuration, and exploit execution
  - **Hydra Credential Testing** — THC Hydra-based credential guessing with configurable threads, timeouts, extra checks, and wordlist retry strategies
- **Agent Guidance** — send real-time steering messages to the agent while it works, injected into the system prompt before the next reasoning step
- **Agent Stop & Resume** — stop the agent at any point and resume from the last LangGraph checkpoint with full context preserved
- **Project Creation UI** — full frontend project form with all configurable settings sections:
  - Naabu (port scanner), Httpx (HTTP prober), Katana (web crawler), GAU (passive URLs), Kiterunner (API discovery), Nuclei (vulnerability scanner), and agent behavior settings
- **Agent Settings in Frontend** — transferred agent configuration parameters from hardcoded `params.py` to PostgreSQL, editable via webapp UI
- **Metasploit Progress Streaming** — HTTP progress endpoint (port 8013) for real-time MSF command tracking with ANSI escape code cleaning
- **Metasploit Session Auto-Reset** — `msf_restart()` MCP tool for clean msfconsole state; auto-reset on first use per chat session
- **WebSocket Integration** — real-time bidirectional communication between frontend and agent orchestrator
- **Markdown Chat UI** — react-markdown with syntax highlighting for agent chat messages
- **Smart Auto-Scroll** — chat only auto-scrolls when user is at the bottom of the conversation
- **Connection Status Indicator** — color-coded WebSocket connection status (green/red) in the chat interface

### Changed

- **Unified Docker Compose** — replaced per-module `.env` files and `start.sh`/`stop.sh` scripts with a single root `docker-compose.yml` and `docker-compose.dev.yml` for full-stack orchestration
- **Settings Source of Truth** — migrated all recon and agent settings from hardcoded `params.py` to PostgreSQL via Prisma ORM, fetched at runtime via webapp API
- **Recon Pipeline Improvements** — multi-level improvements across all recon modules for reliability and accuracy
- **Orchestrator Model Selection** — fixed model selection logic in the agent orchestrator
- **Frontend Usability** — unified RedAmon primary crimson color (#d32f2f), styled message containers with ghost icons and gradient backgrounds, improved markdown heading and list spacing
- **Environment Configuration** — added root `.env.example` with all required keys; forwarded NVD_API_KEY and Neo4j credentials from recon-orchestrator to spawned containers
- **Webapp Header** — replaced Crosshair icon with custom logo.png image, bumped logo text size

### Fixed

- **Double Approval Dialog** — fixed duplicate approval confirmation with ref-based state tracking
- **Orchestrator Model Selection** — corrected model selection logic when switching between AI providers

---

## [1.0.0] - Initial Release

### Added

- Automated reconnaissance pipeline (6-phase: domain discovery, port scanning, HTTP probing, resource enumeration, vulnerability scanning, MITRE mapping)
- Neo4j graph database with 17 node types and 20+ relationship types
- MCP tool servers (Naabu, Curl, Nuclei, Metasploit)
- LangGraph-based AI agent with ReAct pattern
- Next.js webapp with graph visualization (2D/3D)
- Recon orchestrator with SSE log streaming
- GVM scanner integration (under development)
- Test environments (Apache CVE containers)
