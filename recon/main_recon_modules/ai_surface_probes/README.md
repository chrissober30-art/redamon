# AI Surface Recon — vendored probe data

Data consumed by [`ai_surface_recon.py`](../ai_surface_recon.py) and the Julius
engine in [`probe_pack_engine.py`](../../helpers/probe_pack_engine.py). Both
loaders are **failure-soft**: an empty/missing dir degrades that one workload
instead of crashing the module.

(Lives here rather than under the sibling `data/` dir because that directory is
a root-owned Docker runtime cache.)

## `yara_rules/` — MCP tool-poisoning static analysis (Apache-2.0)
Vendor the full set from **Cisco AI Defense MCP Scanner**
(`github.com/cisco-ai-defense/mcp-scanner`, `mcpscanner/data/yara_rules/`) — 10
rules: `tool_poisoning`, `prompt_injection`, `data_exfiltration`,
`command_injection`, `code_execution`, `credential_harvesting`,
`coercive_injection`, `script_injection`, `sql_injection`,
`system_manipulation`. Keep the SPDX/Apache-2.0 headers. This repo ships a small
starter subset so the workload works before full vendoring.

Each rule `meta:` must carry `threat_type` (mapped to OWASP-LLM/ATLAS in
`ai_surface_recon._MCP_THREAT_MAP`) and `severity`.

## `julius/` — AI service fingerprint probe packs (Apache-2.0)
Vendor the full set from **Julius** (`github.com/praetorian-inc/julius`,
`probes/*.yaml`) — ~63 service packs + the `openai-compatible.yaml` fallback.
This repo ships `ollama.yaml` + `openai-compatible.yaml` as starters. The Python
engine reproduces the Go matcher exactly (AND-within-request, `require` any/all,
specificity ranking, case rules).
