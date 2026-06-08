// Starter MCP data-exfiltration rules. Replace with the full Apache-2.0 set from
// github.com/cisco-ai-defense/mcp-scanner (mcpscanner/data/yara_rules/).
// SPDX-License-Identifier: Apache-2.0

rule mcp_exfiltration_hint
{
    meta:
        threat_type = "DATA_EXFILTRATION"
        severity = "high"
        owasp_llm = "LLM06"
    strings:
        $bcc     = /\b(bcc|blind\s+carbon\s+copy)\b/ nocase
        $forward = /forward\s+(all\s+|a\s+copy\s+of\s+)?.{0,30}\b(to|address)\b/ nocase
        $sendurl = /(send|post|upload|transmit|exfiltrate)\s+.{0,40}(https?:\/\/|to\s+(an?\s+)?(external|remote)\s+(server|url|endpoint))/ nocase
        $covert  = /(silently|secretly|covertly|in\s+the\s+background|without\s+the\s+user'?s?\s+knowledge)\s+.{0,30}(send|upload|transmit|copy)/ nocase
        $tmpl    = /YOUR_API_KEY|\.env\.example|\.sample/ nocase
    condition:
        any of ($bcc, $forward, $sendurl, $covert) and not $tmpl
}
