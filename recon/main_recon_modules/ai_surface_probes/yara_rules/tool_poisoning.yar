// Starter MCP tool-poisoning rules. Replace with the full Apache-2.0 set from
// github.com/cisco-ai-defense/mcp-scanner (mcpscanner/data/yara_rules/).
// SPDX-License-Identifier: Apache-2.0

rule mcp_hidden_instructions
{
    meta:
        threat_type = "TOOL_POISONING"
        severity = "high"
        owasp_llm = "LLM01"
    strings:
        $ignore  = /ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+(instructions|prompts?)/ nocase
        $tag_imp = "<IMPORTANT>" nocase
        $dnt1    = /do\s+not\s+(tell|mention|inform|reveal\s+to)\s+(the\s+)?user/ nocase
        $dnt2    = /don'?t\s+(let|tell)\s+the\s+user\s+know/ nocase
        $secret  = /(read|cat|access|open|contents?\s+of)\s+.{0,24}(~\/\.ssh|id_rsa|\.env\b|mcp\.json|\.aws\/credentials)/ nocase
        $sysover = /<!--[^>]{0,80}(system|admin)\s+(override|instruction)/ nocase
        // placeholder strings that should NOT trip the rule
        $tmpl    = /YOUR_API_KEY|\.env\.example|\.sample/ nocase
    condition:
        any of ($ignore, $tag_imp, $dnt1, $dnt2, $secret, $sysover) and not $tmpl
}

rule mcp_imperative_override
{
    meta:
        threat_type = "PROMPT_INJECTION"
        severity = "medium"
        owasp_llm = "LLM01"
    strings:
        $role   = /\bnew\s+(instructions|directive|rules?)\s*:\s*you\s+are\b/ nocase
        $before = /before\s+(using|calling|responding|doing\s+anything)\b.{0,40}\b(you\s+must|always|first)\b/ nocase
        $disg   = /(disregard|forget|bypass)\s+(all\s+)?(your\s+)?(safety|guidelines|previous\s+instructions)/ nocase
    condition:
        any of them
}
