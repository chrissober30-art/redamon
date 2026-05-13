# PROMPT — Add an AI hook to a recon tool

Wire an LLM into a recon tool's decision-making (e.g. "let AI pick {FEATURE}
for {TOOL}"). Mirror an existing implementation; do not invent a new pattern.

## Before you start

**Study how the recon pipeline works first.** Read the relevant entry points
and trace how the tool you're touching is invoked:
- Full pipeline: `recon/main.py` → `recon/main_recon_modules/*.py`.
- Partial recon: `recon/partial_recon.py` → `recon/partial_recon_modules/*.py`.
- Settings flow: `recon/project_settings.py` (`get_settings`, cascades).
- Container spawn: `recon_orchestrator/container_manager.py` (main and
  partial recon are spawned separately).

The feature **MUST work in both the full pipeline AND partial recon.** Do
not ship until you've confirmed both paths.

## Reference

Pick the closer template and copy its structure end-to-end:

- **Per-target** (the AI is called once per URL/host): FFuf —
  `recon/helpers/ai_planner/ffuf_extensions.py`. **MUST use a cache** keyed
  by tech fingerprint (Server, X-Powered-By, ...) so N targets behind one
  stack collapse to one LLM call. Without the cache you spend N× the budget.
- **Per-scan** (the AI is called once per scan from an aggregated fingerprint):
  Nuclei — `recon/helpers/ai_planner/nuclei_tags.py`. **No cache needed** —
  there's only one call. (Module-level memoization of the candidate pool is
  a separate concern; not the same thing.)

Rule of thumb: if your hook runs inside a per-target loop, cache. If it runs
once before the tool's main command is built, don't.

## What to do

1. **Helper** in `recon/helpers/ai_planner/{tool}_{feature}.py`. POSTs to the
   agent's `/llm/{tool}-{feature}` endpoint. Reads `AGENT_API_URL` from env.
   **Never raises** — every failure path returns the user's current value.
   All log lines must be `print(...)` (stdout) and prefixed `[*][{Tool}-AI]`
   for normal events, `[!][{Tool}-AI]` for warnings/fallbacks. The recon
   container's stdout is what the webapp tails into the recon drawer SSE
   stream — anything not on stdout is invisible to the user.
2. **Agent endpoint** in `agentic/api.py`. New Pydantic request model + system
   prompt. Reuse `_build_llm_with_model_for_user(model, user_id)`.
3. **Settings** in `recon/project_settings.py`: add `{TOOL}_AI_{FEATURE}` to
   `DEFAULT_SETTINGS`, map `{tool}Ai{Feature}` → `{TOOL}_AI_{FEATURE}` in
   `fetch_project_settings`, and add it to **both branches** of
   `apply_ai_pipeline_overrides` (the `aiInPipeline` master cascade).
4. **Hook the AI block** into the tool's main entry function. The feature
   MUST cover **both full pipeline and partial recon**. Most tools share a
   single entry function (e.g. `run_vuln_scan` is called by both
   `main_recon_modules/vuln_scan.py` and `partial_recon_modules/vulnerability_scanning.py`)
   — hook there once and both paths inherit. If the tool has separate
   entry functions, hook both. Verify by `grep`-ing the function name.
5. **Prisma**: add `{tool}Ai{Feature} Boolean @default(false) @map("{tool}_ai_{feature}")`
   to `Project`. Apply via `prisma db push` (or `ALTER TABLE` + `prisma generate`
   if push wants to drop unrelated tables — never use `--accept-data-loss`).
6. **Zod**: add the field to `webapp/src/lib/recon-preset-schema.ts` (and a
   one-line note in the catalog comment) so AI-generated presets see it.
7. **UI: the toggle MUST exist in TWO places, BOUND to the same form field
   so they stay in sync automatically (bidirectional).**

   - **Place A — `TargetSection.tsx` (master "AI in Pipeline" panel)**: add
     a per-tool toggle row next to the existing FFuf one, visible only when
     `data.aiInPipeline` is on. Also extend the master `aiInPipeline`
     `onChange` handler so it cascades to `{tool}Ai{Feature}`.
   - **Place B — tool's own module section** (e.g. `NucleiSection.tsx`): a
     toggle inside the tool's settings panel, `disabled={!data.aiInPipeline}`,
     and dim/disable the static input it replaces (e.g. tags list) when on.

   **Both toggles must be bound to the same form field** `data.{tool}Ai{Feature}`
   (read AND write). Do **not** copy values between them on flip. Because
   they share the same field, flipping either toggle is automatically
   reflected in the other. If you find yourself writing copy-on-flip logic,
   you've got it wrong — fix the binding.
8. **Tests**: copy the four Nuclei test files (`test_nuclei_ai_planner.py`,
   `test_nuclei_ai_pipeline_integration.py`, `test_nuclei_ai_vuln_scan_wiring.py`,
   `test_nuclei_ai_smoke.py`) and adapt names. Run inside the recon image.
9. **Wiki**: extend `redamon.wiki/Recon-Pipeline-Workflow.md`, section **"AI
   in Pipeline"**:
   - Add a row to the "three current AI hooks" table (Tool / Pattern /
     Replaces).
   - Add a `#### {Tool}: {Feature}` subsection mirroring the existing FFuf,
     Nuclei, and WAF entries: one paragraph on what it does, then a bullet
     list with helper path, agent endpoint, setting key, and typical impact.
   - Update the screenshot if the Target-tab AI panel layout changes (drop
     a refreshed `ai-in-pipeline-target-tab.png` into `redamon.wiki/images/`).

## Do NOT

- **Touch any file under `webapp/src/lib/recon-presets/presets/`.** The
  cascade is the single source of truth; presets must not hard-code per-tool
  AI flags. Updating the Zod schema (step 6) is enough.
- **Return an empty list/string as the fallback.** For tools where empty
  means "skip the work" (Nuclei tags, FFuf extensions), that silently turns
  detection off. Always fall back to the user's current value.
- **Skip the AI when there's no signal.** Empty fingerprint → return current
  value, don't call the LLM with an empty prompt.
- **Hook the AI separately in partial recon.** Find the shared entry point
  (`run_vuln_scan`, `run_ffuf_discovery`, ...) and hook it once.

## Rebuild

- `agentic/api.py` → rebuild **agent**.
- `recon_orchestrator/*.py` → rebuild **recon-orchestrator**.
- `recon/*.py` → nothing (volume-mounted).
- Prisma schema → `prisma db push` + `prisma generate -u root`.
- `webapp/src/*` → rebuild **webapp** (prod mode) or nothing (dev mode).

## Verify

1. Tests green.
2. `curl -X POST http://localhost:8090/llm/{tool}-{feature}` with a minimal
   body returns 422 (bad body) or 503 (no API key), never 500.
3. Master toggle in Target panel flips the per-tool toggle and vice versa.
4. Live scan logs show `[*][{Tool}-AI] ...` lines in **both** a full pipeline
   run AND a partial recon run for the same tool.
5. Stop the agent → scan still completes using the user's static value.
