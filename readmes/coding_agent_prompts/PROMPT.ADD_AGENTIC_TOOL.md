# NEW TOOL IN AGENTIC SYSTEM

Integrate **[TOOL_NAME]** into the RedAmon agentic system.

> **Scope**: This prompt covers tools used by the AI agent during interactive pentesting sessions (chat-based). It does NOT cover the recon pipeline.

### Critical Rules

- **Python import safety**: The `agent` container volume-mounts source code (`./agentic:/app`). Adding a new Python `import` that isn't already installed in the container image will **crash-loop** the agent. Before importing any package, verify it exists in `agentic/requirements.txt` or the `agentic/Dockerfile`. If it's missing, add it and rebuild: `docker compose build agent`.
- **Don't break existing tools**: Adding a new tool must NOT modify the behavior, arguments, or output format of any existing tool. If you change a shared file (e.g., `tools.py`, `project_settings.py`), verify that all existing tools still work after your changes.
- **Container restart rules**: MCP server code in `mcp/servers/` is volume-mounted and **hot-reloads** — changes are live immediately. But agent Python code in `agentic/` is cached at import time — you MUST run `docker compose restart agent` after any change there. Frontend changes require `docker compose build webapp`.
- **Build/restart quick reference**:
  - Changed `mcp/kali-sandbox/Dockerfile` → `docker compose build kali-sandbox && docker compose up -d kali-sandbox`
  - Changed `mcp/servers/*.py` → `docker compose restart kali-sandbox`
  - Changed `agentic/*.py` → `docker compose restart agent`
  - Changed `webapp/prisma/schema.prisma` → `docker compose exec webapp npx prisma db push`
  - Changed `webapp/src/**` → `docker compose build webapp && docker compose up -d webapp`

---

### Phase 0: Pre-flight — Does the tool already exist?

Before doing ANY work, check whether the tool is already available:

1. **Check `agentic/prompts/tool_registry.py`** — Is the tool (or a functional equivalent) already registered? The `TOOL_REGISTRY` dict is the single source of truth for all agentic tools. If found, STOP and tell the user.
2. **Check `kali_shell` availability** — Is the tool already installed in the Kali sandbox? Read `mcp/kali-sandbox/Dockerfile` and search for its binary/package. If it's already in Kali, the agent can already use it via `kali_shell` or `execute_code`. Consider whether a dedicated tool wrapper adds enough value vs simply using `kali_shell`.
3. **Check MCP servers** — Read `mcp/servers/network_recon_server.py`, `mcp/servers/nmap_server.py`, `mcp/servers/nuclei_server.py`, `mcp/servers/metasploit_server.py`. Is the tool already exposed as an MCP function?

If the tool already exists in any form, explain what's already available and ask whether a dedicated integration is still wanted.

---

### Phase 1: Research (do NOT write code yet)

#### Step 1 — Tool research

Search the tool's official docs, GitHub repo, and README online. Determine:
- **What it does**: One-line purpose
- **CLI interface**: Key flags, input format, output format
- **Output format**: Does it support JSON output? What fields does it return?
- **Dependencies**: External binaries, config files, wordlists, API keys?
- **Installation method**: apt, pip, go install, binary download, Docker image?
- **Timeout profile**: Fast (<30s), medium (30s-5min), or long-running (5min+)?
- **Is it interactive or batch?**: Does it require interactive input (like `msfconsole`) or is it fire-and-forget (like `nmap`)?

#### Step 2 — Choose the integration type

There are **4 integration types**, ordered from simplest to most complex. Choose the SIMPLEST that meets the tool's requirements:

---

**Type A: Kali Shell Tool (SIMPLEST — no new tool registration needed)**

The tool works well via `kali_shell` / `execute_code`. No dedicated MCP tool or tool registry entry is needed.

**When to use:**
- Tool is already in Kali or trivially installable
- CLI is simple enough that the agent can use it via `kali_shell` without a wrapper
- 120s `kali_shell` timeout is sufficient
- No progress streaming needed

**What to change:**
1. `mcp/kali-sandbox/Dockerfile` — Install tool if not already present
2. `agentic/prompts/tool_registry.py` — Update `kali_shell` entry's `description` field to mention the new tool in the CLI tools list
3. Rebuild kali-sandbox: `docker compose build kali-sandbox`

**Examples:** searchsploit, john, smbclient, sqlmap

---

**Type B: New MCP Tool on Existing Server (RECOMMENDED for most CLI tools)**

Add a new `@mcp.tool()` function to an existing MCP server (usually `network_recon_server.py`). The tool gets its own name, custom timeout, output parsing, and rich docstring.

**When to use:**
- Tool needs a custom timeout different from `kali_shell`'s 120s
- Tool output benefits from dedicated parsing/cleaning
- The agent should see a dedicated tool name in the tool list
- Tool is fire-and-forget (not interactive/stateful)

**What to change (full list in Phase 2 checklist):**
1. MCP server file — Add `@mcp.tool()` function (follow `execute_nmap` in `nmap_server.py` as reference)
2. `agentic/prompts/tool_registry.py` — Add entry to `TOOL_REGISTRY` dict
3. `agentic/project_settings.py` — Add to `TOOL_PHASE_MAP` + optionally to `DANGEROUS_TOOLS`
4. Frontend `ToolMatrixSection.tsx` — Add tool row to the phase matrix grid
5. Prisma schema — Default `agentToolPhaseMap` value must include the new tool
6. If tool binary not in Kali: `mcp/kali-sandbox/Dockerfile`

**Examples:** `execute_naabu`, `execute_curl`, `execute_hydra`, `execute_nmap`, `execute_nuclei`

---

**Type C: New Dedicated MCP Server (for complex/stateful tools)**

Create a new MCP server file with its own port, process, and optionally a progress streaming endpoint.

**When to use:**
- Tool is interactive or stateful (needs persistent process)
- Tool needs its own progress streaming endpoint
- Tool has complex lifecycle management
- Isolation from other tools is important

**What to change (full list in Phase 2 checklist):**
1. `mcp/servers/[tool]_server.py` — New server file (follow `nmap_server.py` for simple, `metasploit_server.py` for stateful)
2. `mcp/servers/run_servers.py` — Register in `SERVERS` dict with port
3. `agentic/tools.py` — Add MCP server URL to `MCPToolsManager.get_tools()` server dict
4. Both `docker-compose.yml` files — Add `MCP_[TOOL]_URL` env var + expose port on kali-sandbox
5. Everything from Type B (registry, settings, frontend, etc.)

**Already-taken ports:** 8000 (network_recon), 8002 (nuclei), 8003 (metasploit), 8004 (nmap), 8013 (msf progress), 8014 (hydra progress), 8015 (tunnel manager), 8016 (terminal). Next available: **8005+**.

**Examples:** `metasploit_server.py`

---

**Type D: API/HTTP-Based Tool (for external services)**

A Python wrapper around an external API. It runs inside the `agent` container, not `kali-sandbox`. The tool is **conditionally available** — it only appears if the user has configured the API key in Global Settings. Without the key, the tool is not registered and the agent cannot see it.

**When to use:**
- Tool is an external API service (like Shodan, Tavily, SerpAPI)
- Tool needs API keys stored in user settings
- No CLI binary needed — pure Python HTTP calls
- Tool availability depends on whether the user has an API key

**Architecture pattern — 3-layer design (read existing implementations to follow exactly):**

1. **`[Tool]ToolManager` class** in `agentic/tools.py` — Holds the API key and creates the tool function. `get_tool()` returns `None` if no API key is set (tool conditionally unavailable). Read `ShodanToolManager` or `GoogleDorkToolManager` as reference.

2. **`PhaseAwareToolExecutor`** in `agentic/tools.py` — Accepts the tool in `__init__()`, provides an `update_[tool]_tool()` method for hot-swapping at runtime, and has a dispatch branch in `execute()` (~line 1097). Read how `shodan` and `google_dork` are handled.

3. **Orchestrator** in `agentic/orchestrator.py` — Creates the manager in `_init_tools()` (no key initially), then in `_apply_project_settings()` reads the API key from user settings, updates the manager, and hot-reloads the tool on the executor. Supports key rotation via `KeyRotator`. Read the Shodan block (~line 186-198) as reference.

**CRITICAL**: The `PhaseAwareToolExecutor.execute()` method (~line 1097) has hardcoded if/elif dispatch for non-MCP tools (query_graph, web_search, shodan, google_dork). Each extracts arguments differently. For Type D, you MUST add a new `elif` branch. For Types B/C, the `else` branch (MCP tools) handles dispatch automatically — no change needed.

**What to change (full list in Phase 2 checklist):**
1. `agentic/tools.py` — New ToolManager class + update method on PhaseAwareToolExecutor + dispatch branch in `execute()`
2. `agentic/orchestrator.py` — Init manager in `_init_tools()` + key refresh in `_apply_project_settings()`
3. API key storage across Prisma, settings API, Global Settings page, ToolMatrix warnings
4. Everything from Type B (registry, phase map, frontend matrix, Prisma default, etc.)

**Examples:** `shodan`, `web_search`, `google_dork`

---

#### Step 3 — Determine phase restrictions

Decide which phases the tool should be available in. The 3 phases are:

| Phase | Purpose | Typical tools |
|-------|---------|---------------|
| **informational** | Passive/active recon, scanning, OSINT | query_graph, web_search, shodan, google_dork, execute_curl, execute_naabu, execute_nmap, execute_nuclei, kali_shell |
| **exploitation** | Active exploitation, credential attacks | All informational tools + execute_code, execute_hydra, metasploit_console, msf_restart |
| **post_exploitation** | Post-exploit activities, lateral movement, persistence | query_graph, web_search, execute_curl, execute_nmap, kali_shell, execute_code, execute_hydra, metasploit_console, msf_restart |

Guidelines:
- **Passive/reconnaissance** → all 3 phases
- **Active scanning** → informational + exploitation
- **Exploitation-focused** → exploitation + post_exploitation
- **Post-exploitation only** → post_exploitation

#### Step 4 — Determine if tool is dangerous

A tool is "dangerous" if it actively modifies the target, sends attack traffic, or could cause unintended impact. If yes, add to `DANGEROUS_TOOLS` frozenset — this requires user confirmation before each execution.

**Dangerous** (add): active scanners, exploits, brute force, shell execution, code execution
**Not dangerous** (skip): passive OSINT, graph queries, web searches, read-only API calls

#### Step 5 — Determine RoE category mapping

Read `agentic/orchestrator_helpers/nodes/execute_plan_node.py` — the `_check_roe_blocked()` function has a `CATEGORY_TOOL_MAP` dict that maps RoE categories to tools (brute_force, dos, social_engineering, exploitation). If the new tool fits any category, add it to the appropriate list so RoE category-based blocking works.

#### Step 5b — Determine stealth mode constraints

Read `agentic/prompts/stealth_rules.py` — this file defines **per-tool stealth constraints** injected into the system prompt when `STEALTH_MODE` is enabled. Every active tool has a dedicated section under "Per-Tool Stealth Constraints" specifying what is allowed and forbidden.

If the new tool sends any traffic to a target, you MUST add a stealth constraint section for it. Determine the restriction level:
- **FORBIDDEN**: Tool is inherently noisy and cannot be used stealthily (e.g., brute force, DoS)
- **HEAVILY RESTRICTED**: Tool can be used in very limited ways only (e.g., nmap only `-sV` on known ports)
- **RESTRICTED**: Tool can be used with rate/scope limits (e.g., curl for single targeted requests)
- **NO RESTRICTIONS**: Tool is passive and doesn't touch the target (e.g., query_graph, web_search)

Read existing tool sections in `stealth_rules.py` as reference for the format and level of detail expected.

#### Step 6 — Check if tool needs API keys

If the tool uses external API keys, RedAmon has a well-established pattern where tools are **conditionally available** — present only when the user has configured the key. Without a key, the tool simply doesn't appear.

**The full API key lifecycle:**
1. **Storage**: Keys stored per-user (NOT per-project) in `UserSettings` Prisma model
2. **Frontend input**: Global Settings page (`/settings`) with `SecretField` component — masked display, toggle visibility, key rotation
3. **Frontend warning**: Tool Matrix (`ToolMatrixSection.tsx`) shows yellow warning icon next to tools with missing keys, with inline modal to set the key
4. **Runtime fetch**: Orchestrator fetches keys via `GET /api/users/{userId}/settings?internal=true` on every session init
5. **Hot-reload**: `_apply_project_settings()` in orchestrator compares current key with stored key, recreates tool if changed via `ToolManager.get_tool()` + `update_[tool]_tool()`
6. **No key = tool unavailable**: `ToolManager.get_tool()` returns `None` → tool not registered → agent can't see it. Graceful degradation by design.
7. **Key rotation** (optional): For tools with rate limits, multiple keys cycled every N calls via `KeyRotator`

**Key files for API key integration:**
- `webapp/prisma/schema.prisma` → `UserSettings` model
- `webapp/src/app/api/users/[id]/settings/route.ts` → GET masking + PUT whitelist
- `webapp/src/app/settings/page.tsx` → `UserSettings` interface, `EMPTY_SETTINGS`, `TOOL_NAME_MAP`, `SecretField` rendering
- `webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx` → `TOOL_KEY_INFO` + `fetchKeyStatus()`
- `webapp/src/app/graph/components/AIAssistantDrawer/hooks/useApiKeyModal.ts` → `API_KEY_INFO` dict (top of file) + `fetchApiKeyStatus()` — **duplicate** of ToolMatrix key check, used to show missing-key warnings in the chat UI
- `webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx` → `TOOL_KEY_LABEL` dict (line 15-19) — maps tool name to human-readable API key label for chat tool cards
- `agentic/tools.py` → `[Tool]ToolManager` class
- `agentic/orchestrator.py` → `_apply_project_settings()` + `_init_tools()`

#### Step 7 — Check if tool needs progress streaming

Long-running tools (>60s typical) benefit from progress streaming. If needed, **TWO files** must be updated (they have duplicated logic):

1. `agentic/orchestrator_helpers/nodes/execute_tool_node.py` (~line 97) — hardcoded `is_long_running_*` checks per tool
2. `agentic/orchestrator_helpers/nodes/execute_plan_node.py` (~line 108) — **same duplicated logic** for parallel plan execution

Both files need a new long-running detection check with the progress URL. Also:
3. Create an HTTP progress endpoint in the MCP server (follow Hydra pattern in `network_recon_server.py`)
4. Add `MCP_[TOOL]_PROGRESS_URL` env var in docker-compose files

#### Step 8 — Check if tool manages sessions or listeners

Read `agentic/orchestrator_helpers/nodes/execute_tool_node.py` lines 155-180. There are hardcoded post-execution handlers for `metasploit_console` (session detection) and `kali_shell` (listener detection). The **same code is duplicated** in `execute_plan_node.py` (~line 176-201).

If the new tool creates reverse shells, listeners, or sessions, add similar detection logic in **BOTH** files.

---

### Phase 2: Implementation Checklist

The exact set of files depends on the integration type chosen in Phase 1.

#### Core: Tool Registration & Execution (ALL types except A)

- [ ] **`agentic/prompts/tool_registry.py`** — Add entry to `TOOL_REGISTRY` dict with `purpose`, `when_to_use`, `args_format`, and `description`. Position matters: dict insertion order = tool priority. Read existing entries as reference.

- [ ] **`agentic/project_settings.py`** — Up to 3 changes:
  1. Add tool to `TOOL_PHASE_MAP` in `DEFAULT_AGENT_SETTINGS` (~line 81-95)
  2. If dangerous: add to `DANGEROUS_TOOLS` frozenset (~line 19-23)
  3. If tool has configurable settings: add defaults to `DEFAULT_AGENT_SETTINGS` + mapping in `fetch_agent_settings()`

- [ ] **`agentic/orchestrator_helpers/nodes/execute_plan_node.py`** — If tool fits an RoE category: add to `CATEGORY_TOOL_MAP` in `_check_roe_blocked()` (~line 30-35)

- [ ] **`agentic/prompts/stealth_rules.py`** — If tool sends any traffic to a target: add a per-tool stealth constraint section under "Per-Tool Stealth Constraints". Specify what is ALLOWED and FORBIDDEN when stealth mode is active. Read existing tool sections as reference for format.

#### MCP Server (Types B and C only)

- [ ] **Type B**: Add `@mcp.tool()` function to `mcp/servers/network_recon_server.py` (or whichever server fits). Read `execute_nmap` in `nmap_server.py` as the simplest reference. Include: rich docstring with examples (LLM reads this), `shlex.split` for arg parsing, `subprocess.run` with appropriate timeout, ANSI escape stripping, error handling.

- [ ] **Type C**: Create `mcp/servers/[tool]_server.py`. Read `nmap_server.py` for simple tools or `metasploit_server.py` for stateful tools. Then:
  - Register in `mcp/servers/run_servers.py` `SERVERS` dict with module name and port (next available: 8005+)
  - Add MCP server URL to `agentic/tools.py` `MCPToolsManager.get_tools()` server dict — read existing entries for the exact format
  - Add `MCP_[TOOL]_URL` env var to **BOTH** `docker-compose.yml` (root: `http://kali-sandbox:PORT/sse`) and `agentic/docker-compose.yml` (`http://host.docker.internal:PORT/sse`)
  - Expose port on kali-sandbox in root `docker-compose.yml`

#### API-Based Tool (Type D only)

- [ ] **`agentic/tools.py`** — Read `ShodanToolManager` or `GoogleDorkToolManager` as reference. Create:
  1. `[Tool]ToolManager` class — with `get_tool()` returning `None` if no API key
  2. `update_[tool]_tool()` method on `PhaseAwareToolExecutor` — for hot-swapping (read existing `update_shodan_tool` as reference)
  3. Registration in `PhaseAwareToolExecutor.__init__()` — accept tool param, add to `self._all_tools` if not None
  4. Dispatch branch in `PhaseAwareToolExecutor.execute()` (~line 1097) — add `elif` for the new tool with correct arg extraction

- [ ] **`agentic/orchestrator.py`** — Read the Shodan block (~line 186-198) as reference. Add:
  1. Manager creation in `_init_tools()` (no key initially)
  2. Key refresh block in `_apply_project_settings()` — read key from user settings, update manager, hot-reload tool on executor, setup key rotation

#### Kali Sandbox (if tool binary is not already installed)

- [ ] **`mcp/kali-sandbox/Dockerfile`** — Install the tool. Read existing installation patterns in the Dockerfile (apt, pip, go install, wget binary). Rebuild: `docker compose build kali-sandbox`

#### Frontend: Tool Matrix (ALL types except A)

- [ ] **`webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx`** — Add tool to the tools array in the `.map()` call (~line 129-143). Place it logically among existing tools.

- [ ] If tool needs API key: add entry to `TOOL_KEY_INFO` constant at top of file, and add missing-key check in `fetchKeyStatus()` callback. Read existing entries (web_search, shodan, google_dork) as reference.

#### Frontend: Prisma Schema & Database

- [ ] **`webapp/prisma/schema.prisma`** — Update the default JSON value of `agentToolPhaseMap` in the `Project` model (~line 414) to include the new tool's phase array.

- [ ] Run schema push: `docker compose exec webapp npx prisma db push` (NEVER use `prisma migrate`)

- [ ] **Update existing DB rows** — Existing projects won't have the new tool in their `agentToolPhaseMap`. Run a SQL UPDATE via `docker compose exec postgres psql -U redamon -d redamon` to add the new tool entry where it doesn't already exist.

#### Frontend: API Key in UserSettings (Type D or any tool needing API keys)

- [ ] **`webapp/prisma/schema.prisma`** — Add `[tool]ApiKey` field to `UserSettings` model (read existing key fields as reference)
- [ ] **`webapp/src/app/api/users/[id]/settings/route.ts`** — Add to GET masking logic + PUT whitelist (read how existing keys are handled)
- [ ] **`webapp/src/app/settings/page.tsx`** — Add to `UserSettings` interface, `EMPTY_SETTINGS`, `TOOL_NAME_MAP`, add `SecretField` component in JSX (read Shodan ~line 505-515 as reference), add to both `fetchSettings()` response handlers (~lines 243, 313)
- [ ] **`webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx`** — Add to `TOOL_KEY_INFO` + `fetchKeyStatus()` (if not already done above)
- [ ] **`webapp/src/app/graph/components/AIAssistantDrawer/hooks/useApiKeyModal.ts`** — Add to `API_KEY_INFO` dict (top of file) and missing key detection in `fetchApiKeyStatus()`. This is a **duplicate** of the ToolMatrix key check — the chat drawer also warns users about missing API keys.
- [ ] **`webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx`** — Add to `TOOL_KEY_LABEL` dict (line 15-19) — maps tool name to human-readable label shown on tool cards in chat when key is missing.

#### Progress Streaming (if long-running tool, >60s typical)

- [ ] **MCP server** — Add progress tracking (read Hydra pattern in `network_recon_server.py`: thread-safe state, background subprocess, HTTP progress endpoint)
- [ ] **`agentic/orchestrator_helpers/nodes/execute_tool_node.py`** (~line 97-121) — Add long-running detection and progress execution branch (read existing MSF and Hydra checks as reference)
- [ ] **`agentic/orchestrator_helpers/nodes/execute_plan_node.py`** (~line 108-131) — **DUPLICATE the same logic** (this file has copy-pasted tool execution for parallel plan mode)
- [ ] **docker-compose files** — Add `MCP_[TOOL]_PROGRESS_URL` env var to agent service in both files

#### Session/Listener Registration (if tool creates reverse shells or listeners)

- [ ] **`agentic/orchestrator_helpers/nodes/execute_tool_node.py`** (~line 155-180) — Add post-execution handler (read existing metasploit_console and kali_shell handlers as reference)
- [ ] **`agentic/orchestrator_helpers/nodes/execute_plan_node.py`** (~line 176-201) — **DUPLICATE the same handler**

#### Agent Defaults Endpoint

- [ ] **`agentic/api.py`** — If the tool has configurable settings, add them to the `/defaults` endpoint response

#### Optional: Tool-Specific Project Settings

If the tool has configurable parameters (like Hydra's threads, SQLMap's level/risk):

- [ ] **`webapp/prisma/schema.prisma`** — Add fields to `Project` model with `@default()` and `@map()`
- [ ] **`agentic/project_settings.py`** — Add to `DEFAULT_AGENT_SETTINGS` + mapping in `fetch_agent_settings()` (camelCase → SCREAMING_SNAKE_CASE)
- [ ] **Frontend section component** — Create `[Tool]Section.tsx` in `webapp/src/components/projects/ProjectForm/sections/` (read `BruteForceSection.tsx` or `SqliSection.tsx` as reference). Export from `sections/index.ts`.
- [ ] **`webapp/src/components/projects/ProjectForm/ProjectForm.tsx`** — Import and render section in appropriate tab
- [ ] Run `docker compose exec webapp npx prisma db push`

#### Optional: Attack Skill Integration

If the tool is the PRIMARY tool for a new built-in attack skill (like Hydra is for brute_force, or SQLMap is for sql_injection):

- [ ] **`agentic/prompts/[skill]_prompts.py`** — Create new prompt file with tool workflow guidance and step-by-step methodology (read `sql_injection_prompts.py` or `brute_force_credential_guess_prompts.py` as reference)
- [ ] **`agentic/prompts/__init__.py`** — Add new `elif` branch in `_inject_builtin_skill_workflow()` (~line 206-284) — read existing branches as reference
- [ ] **`agentic/project_settings.py`** — Add skill to `ATTACK_SKILL_CONFIG` > `builtIn` defaults (~line 130-138)
- [ ] **`webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx`** — Add to `BUILT_IN_SKILLS` array (~line 36-67)
- [ ] **`webapp/src/app/api/users/[id]/attack-skills/available/route.ts`** — Add to `BUILT_IN_SKILLS` array
- [ ] **`webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts`** — Add to `KNOWN_ATTACK_PATH_CONFIG` for chat UI badge
- [ ] **`agentic/prompts/classification.py`** — Add the new skill to the attack path classification prompt

---

### Phase 3: Verification

1. **Build containers**: `docker compose build kali-sandbox` and/or `docker compose build webapp`
2. **Push schema**: `docker compose exec webapp npx prisma db push`
3. **Restart services**: `docker compose restart agent kali-sandbox` (agent caches Python modules — restart is mandatory)
4. **Check Tool Matrix**: Project settings > AI Agent > Tool Matrix — new tool should appear with phase checkboxes
5. **Check MCP server**: `docker compose logs kali-sandbox` — tool's server should start without errors
6. **Test execution**: In agent chat, ask it to use the tool. Verify: correct phase availability, confirmation dialog if dangerous, output returned and truncated to `TOOL_OUTPUT_MAX_CHARS`
7. **Test phase restrictions**: Use tool in a disabled phase — agent should refuse
8. **Test RoE blocking** (if applicable): Enable RoE with the tool's category forbidden — verify blocked

---

### Architecture Reference

#### File Map

| File | Purpose | When to modify |
|------|---------|---------------|
| `agentic/prompts/tool_registry.py` | **TOOL_REGISTRY** — single source of truth for tool metadata and LLM descriptions | All types except A |
| `agentic/project_settings.py` | **TOOL_PHASE_MAP**, **DANGEROUS_TOOLS**, default settings, `fetch_agent_settings()` | All types except A |
| `agentic/tools.py` | **MCPToolsManager**, **PhaseAwareToolExecutor** (dispatch + phase enforcement), API tool managers | Type C (MCP URLs), Type D (manager + dispatch) |
| `agentic/orchestrator.py` | Orchestrator — `_init_tools()`, `_apply_project_settings()` key hot-reload | Type D only |
| `agentic/prompts/base.py` | Dynamic prompt builders — **auto-reads TOOL_REGISTRY, no change needed** | Never |
| `agentic/orchestrator_helpers/nodes/execute_tool_node.py` | Tool execution — progress streaming, session detection, RoE | If long-running or session-creating |
| `agentic/orchestrator_helpers/nodes/execute_plan_node.py` | **Duplicate** of above for parallel plans + `CATEGORY_TOOL_MAP` for RoE | If long-running, session-creating, or RoE-categorized |
| `agentic/orchestrator_helpers/nodes/tool_confirmation_nodes.py` | Dangerous tool confirmation — **auto-reads DANGEROUS_TOOLS** | Never |
| `agentic/orchestrator_helpers/nodes/think_node.py` | ReAct reasoning — **auto-reads TOOL_PHASE_MAP + TOOL_REGISTRY** | Never |
| `agentic/prompts/stealth_rules.py` | Per-tool stealth constraints (FORBIDDEN/RESTRICTED/allowed) | If tool sends traffic to target |
| `agentic/prompts/__init__.py` | `_inject_builtin_skill_workflow()` | If tool is part of an attack skill |
| `agentic/prompts/classification.py` | Attack path classification prompt | If tool is part of a new attack skill |
| `mcp/servers/run_servers.py` | **SERVERS** dict — MCP server registry with ports | Type C only |
| `mcp/servers/network_recon_server.py` | MCP tools: curl, naabu, kali_shell, execute_code, hydra | Type B (add tool here) |
| `mcp/servers/nmap_server.py` | MCP tool: nmap — reference for simple Type C | — |
| `mcp/servers/metasploit_server.py` | MCP tool: metasploit — reference for stateful Type C | — |
| `mcp/kali-sandbox/Dockerfile` | Kali sandbox — tool binary installation | If tool not already in Kali |
| `mcp/kali-sandbox/entrypoint.sh` | Container startup sequence | Rarely |
| `webapp/prisma/schema.prisma` | `Project.agentToolPhaseMap` default, `UserSettings` API keys | All types except A |
| `webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx` | Tool × phase grid + API key warnings/modals | All types except A |
| `webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx` | Built-in attack skill toggles | If part of attack skill |
| `webapp/src/components/projects/ProjectForm/ProjectForm.tsx` | Tab layout, section rendering | If adding settings section |
| `webapp/src/components/projects/ProjectForm/sections/index.ts` | Section exports | If adding settings section |
| `webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts` | `KNOWN_ATTACK_PATH_CONFIG` — chat UI badges | If part of new attack skill |
| `webapp/src/app/graph/components/AIAssistantDrawer/hooks/useApiKeyModal.ts` | `API_KEY_INFO` + `fetchApiKeyStatus()` — missing key detection in chat drawer | If tool needs API keys |
| `webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx` | `TOOL_KEY_LABEL` — human label on tool cards when key missing | If tool needs API keys |
| `webapp/src/app/api/users/[id]/settings/route.ts` | API key storage, masking, PUT whitelist | If tool needs API keys |
| `webapp/src/app/api/users/[id]/attack-skills/available/route.ts` | Built-in skills list | If part of new attack skill |
| `webapp/src/app/settings/page.tsx` | Global Settings — API key inputs with `SecretField` | If tool needs API keys |
| `docker-compose.yml` | Root compose — agent env vars, kali-sandbox ports | Type C |
| `agentic/docker-compose.yml` | Dev compose — agent env vars | Type C |
| `agentic/api.py` | Agent `/defaults` endpoint | If tool has configurable settings |

#### Tool Execution Flow

```
User message → WebSocket → Agent Orchestrator
    ↓
Think Node (auto-reads TOOL_REGISTRY + TOOL_PHASE_MAP)
    ↓ decides: action=use_tool, tool_name="execute_[tool]"
    ↓
Phase Check: is_tool_allowed_in_phase() → blocked if not in TOOL_PHASE_MAP
RoE Check: _check_roe_blocked() → blocked if CATEGORY_TOOL_MAP forbids it
Dangerous Check: in DANGEROUS_TOOLS? → pause for user confirmation
    ↓
Long-running check (hardcoded per tool) → execute_with_progress() or execute()
    ↓
PhaseAwareToolExecutor.execute() dispatch:
    - Non-MCP tools: hardcoded elif branches (query_graph, web_search, shodan, google_dork)
    - MCP tools (Types B/C): automatic via else branch
    ↓
Output: _extract_text_from_output() → truncate to TOOL_OUTPUT_MAX_CHARS
    ↓
Post-execution handlers (hardcoded): session detection, listener registration
    ↓
Execution trace updated → Think Node loops back
```

#### MCP Auto-Discovery (key insight for Types B/C)

For Type B, adding a new `@mcp.tool()` to an existing server means it gets **auto-discovered** by `MCPToolsManager.get_tools()` — no changes needed in `tools.py`. The tool name in `_tools_cache` matches the Python function name. This is why Type B requires fewer files than Type D.

#### Naming Conventions

| Layer | Convention | Example |
|-------|-----------|---------|
| MCP function name | `execute_[tool]` | `execute_nikto` |
| Tool Registry key | Same as MCP function name | `"execute_nikto"` |
| TOOL_PHASE_MAP key | Same | `'execute_nikto'` |
| DANGEROUS_TOOLS entry | Same | `'execute_nikto'` |
| CATEGORY_TOOL_MAP | Same | `'exploitation': [..., 'execute_nikto']` |
| Tool Matrix ID | Same | `{ id: 'execute_nikto', label: 'execute_nikto' }` |
| Prisma setting field | camelCase | `niktoTimeout` |
| Python setting key | SCREAMING_SNAKE_CASE | `'NIKTO_TIMEOUT'` |
| DB column name | snake_case via `@map()` | `nikto_timeout` |
| MCP URL env var | `MCP_[TOOL]_URL` | `MCP_NIKTO_URL` |
| Progress URL env var | `MCP_[TOOL]_PROGRESS_URL` | `MCP_NIKTO_PROGRESS_URL` |

---

### Decision Tree: Which Integration Type?

```
Is the tool already in Kali or trivially installable?
├─ YES → Is kali_shell (120s timeout, no custom parsing) sufficient?
│   ├─ YES → Type A (Dockerfile + update kali_shell description)
│   └─ NO → Is it fire-and-forget (not stateful)?
│       ├─ YES → Type B (new @mcp.tool() on existing server)
│       └─ NO → Type C (new dedicated MCP server)
└─ NO → Is it an external API/service?
    ├─ YES → Type D (API tool in agent container)
    └─ NO → Can the binary be installed in Kali?
        ├─ YES → Add to Dockerfile → then Type B or C
        └─ NO → Investigate alternative or skip
```
