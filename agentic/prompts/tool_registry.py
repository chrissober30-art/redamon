"""
RedAmon Tool Registry

Single source of truth for tool metadata used by dynamic prompt builders.
Dict insertion order defines tool priority (first = highest).
"""

TOOL_REGISTRY = {
    "query_graph": {
        "purpose": "Neo4j database queries",
        "when_to_use": "PRIMARY - Check graph first for recon data",
        "args_format": '"question": "natural language question about the graph data"',
        "description": (
            '**query_graph** (PRIMARY — start here)\n'
            '   - Query Neo4j graph via natural language — your source of truth for recon data\n'
            '   - **Nodes:** Domains, Subdomains, IPs, Ports, Services, BaseURLs, DNSRecords, '
            'Endpoints, Parameters, Certificates, Headers, Technologies, Vulnerabilities, '
            'CVEs, MitreData (CWE), CAPEC, Traceroute hops, Exploits, ExploitGvm, '
            'GithubHunt, Repositories, Paths, Secrets, SensitiveFiles, '
            'JsReconFinding, TrufflehogScan, TrufflehogRepository, TrufflehogFinding\n'
            '   - Skip if you already know which specific tool to use'
        ),
    },
    "web_search": {
        "purpose": "Knowledge base + web search",
        "when_to_use": "Research CVEs, exploits, tool flags, methodology, priv-esc",
        "args_format": (
            '"query": "search query", '
            '"include_sources": ["tool_docs"|"gtfobins"|"lolbas"|"owasp"|"nvd"|"exploitdb"|"nuclei"] (optional), '
            '"exclude_sources": [...] (optional), '
            '"top_k": 1-20 (optional, default 5), '
            '"min_cvss": 0.0-10.0 (optional, NVD only)'
        ),
        "description": (
            '**web_search** (SECONDARY — KB + external research)\n'
            '   - Checks the local Knowledge Base first (curated, ~50ms), then falls back to '
            'Tavily web search if no strong local match.\n'
            '   - **KB sources** (pass via `include_sources` arg to scope your query — significantly improves relevance):\n'
            '     - `tool_docs`: sqlmap/nmap/hydra/nuclei/ffuf/httpx flags + framework guides '
            '(FastAPI, NestJS, Next.js, GraphQL, Supabase) + vuln testing methodology '
            '(XSS, SQLi, IDOR, SSRF, RCE, XXE, CSRF, JWT, race conditions, mass assignment)\n'
            '     - `gtfobins`: Linux priv-esc one-liners (python, vim, find, awk, tar...)\n'
            '     - `lolbas`: Windows LOLBin abuse (certutil, mshta, regsvr32...) with MITRE IDs\n'
            '     - `owasp`: OWASP WSTG test cases by category and WSTG ID\n'
            '     - `nvd`: CVE descriptions with CVSS, severity, affected products\n'
            '     - `exploitdb`: Public exploit titles + descriptions (use `searchsploit` via '
            'kali_shell for exploit code)\n'
            '     - `nuclei`: Nuclei template metadata (use `execute_nuclei` for actual scanning)\n'
            '   - **Args**:\n'
            '     - `include_sources` (list[str], optional): Allowlist — restrict to these KB '
            'sources. Use when you KNOW the right source. Omit to search everything.\n'
            '     - `exclude_sources` (list[str], optional): Blocklist — drop these sources '
            'after the include filter. Use to remove high-volume noise on broad queries. '
            'ExploitDB has ~46k chunks vs LOLBAS\'s 451 — excluding it on concept queries '
            'stops exploit titles from drowning out methodology hits.\n'
            '     - `top_k` (int, optional, default 5, max 20): Number of results to return. '
            'Keep at 5 for targeted lookups (single CVE, specific flag). Bump to 10–15 for '
            'broad/exploratory queries or when a narrow first call returned partial results.\n'
            '     - `min_cvss` (float, optional, 0.0–10.0): Minimum CVSS for NVD chunks. '
            '9.0 = critical only, 7.0 = high+critical. Other sources unaffected.\n'
            '   - **Scoping patterns**:\n'
            '     - Targeted (existing pattern, just renamed):\n'
            '         `web_search("nuclei -rl flag", include_sources=["tool_docs"])`\n'
            '     - Broad with noise removal:\n'
            '         `web_search("SSRF cloud metadata", exclude_sources=["exploitdb", "nvd"], top_k=15)`\n'
            '     - Critical CVEs only:\n'
            '         `web_search("Apache RCE", include_sources=["nvd"], min_cvss=9.0)`\n'
            '     - Broad sweep across operational sources:\n'
            '         `web_search("kubernetes priv esc", include_sources=["tool_docs", "lolbas", "gtfobins"], top_k=12)`\n'
            '     - Re-query strategy: first call narrow, second call wider if needed:\n'
            '         `web_search("Cisco IOS auth bypass")`           # default top_k=5\n'
            '         `web_search("Cisco IOS auth bypass", top_k=15)` # if first call missed it\n'
            '   - **Single-source shortcuts**:\n'
            '     - sqlmap/nmap flag question → `include_sources=["tool_docs"]`\n'
            '     - Linux priv-esc → `include_sources=["gtfobins"]`\n'
            '     - Windows LOLBin abuse → `include_sources=["lolbas"]`\n'
            '     - OWASP methodology → `include_sources=["owasp"]`\n'
            '     - CVE lookup → `include_sources=["nvd", "exploitdb"]`\n'
            '     - Open-ended research → omit both source args\n'
            '   - Use AFTER query_graph when you need context not in the graph'
        ),
    },
    "shodan": {
        "purpose": "Shodan internet intelligence (OSINT)",
        "when_to_use": "Search for exposed IPs, get host details, reverse DNS, domain DNS",
        "args_format": '"action": "search|host|dns_reverse|dns_domain|count", "query": "...", "ip": "...", "domain": "..."',
        "description": (
            '**shodan** (Internet-wide OSINT)\n'
            '   - **action="search"** — Search devices (requires `query`, PAID key). '
            'Filters: port:, hostname:, org:, country:, product:, version:, net:, vuln:, has_vuln:true\n'
            '   - **action="host"** — Detailed IP info: ports, services, banners, CVEs, SSL, OS (requires `ip`, FREE key)\n'
            '   - **action="dns_reverse"** — Reverse DNS for IP (requires `ip`, FREE key)\n'
            '   - **action="dns_domain"** — DNS records & subdomains (requires `domain`, PAID key)\n'
            '   - **action="count"** — Count matching hosts without search credits (requires `query`, FREE key)'
        ),
    },
    "google_dork": {
        "purpose": "Google dorking (OSINT)",
        "when_to_use": "Find exposed files, admin panels, directory listings via Google",
        "args_format": '"query": "Google dork query string with advanced operators"',
        "description": (
            '**google_dork** (Passive OSINT via SerpAPI)\n'
            '   - Google advanced search — no packets to target\n'
            '   - Operators: site:, inurl:, intitle:, filetype:, intext:, ext:, cache:\n'
            '   - Rate limit: 250 queries/month, 50/hour'
        ),
    },
    "execute_nuclei": {
        "purpose": "CVE verification & exploitation",
        "when_to_use": "Verify/exploit CVEs using nuclei templates",
        "args_format": '"args": "nuclei arguments without \'nuclei\' prefix"',
        "description": (
            '**execute_nuclei** (CVE verification & exploitation)\n'
            '   - 8000+ YAML templates — verify and exploit CVEs in one step\n'
            '   - Custom templates at `/opt/nuclei-templates/` are listed in the tool description (check it for available paths)\n'
            '   - Examples: `-u URL -id CVE-2021-41773 -jsonl` | `-u URL -tags cve,rce -severity critical,high -jsonl`\n'
            '   - Custom: `-u URL -t /opt/nuclei-templates/http/misconfiguration/springboot/ -jsonl`'
        ),
    },
    "execute_curl": {
        "purpose": "HTTP requests",
        "when_to_use": "Reachability checks, headers, status codes",
        "args_format": '"args": "curl command arguments without \'curl\' prefix"',
        "description": (
            '**execute_curl** (HTTP requests)\n'
            '   - Make HTTP requests for reachability, headers, banners\n'
            '   - Do NOT use for vuln probing — use execute_nuclei instead'
        ),
    },
    "execute_naabu": {
        "purpose": "Port scanning",
        "when_to_use": "ONLY to verify ports or scan new targets",
        "args_format": '"args": "naabu arguments without \'naabu\' prefix"',
        "description": (
            '**execute_naabu** (Fast port scanning)\n'
            '   - Verify open ports or scan targets not yet in graph\n'
            '   - Example: `-host 10.0.0.5 -p 80,443,8080 -json`'
        ),
    },
    "execute_nmap": {
        "purpose": "Deep network scanning",
        "when_to_use": "Service detection, OS fingerprint, NSE scripts",
        "args_format": '"args": "nmap arguments without \'nmap\' prefix"',
        "description": (
            '**execute_nmap** (Deep scanning)\n'
            '   - Version detection (-sV), OS fingerprint (-O), NSE scripts (-sC/--script)\n'
            '   - Slower than naabu but far more detailed'
        ),
    },
    "kali_shell": {
        "purpose": "General shell execution in Kali sandbox",
        "when_to_use": "Run shell commands, download PoCs, use Kali tools (NOT for writing code — use execute_code)",
        "args_format": '"command": "full shell command to execute"',
        "description": (
            '**kali_shell** (Kali Linux shell — bash -c)\n'
            '   - Full Kali toolset. Timeout: 120s.\n'
            '   - **CLI tools:** netcat, socat, rlwrap, msfvenom, searchsploit, sqlmap, '
            'john, smbclient, sshpass, jq, git, wget, gcc/g++/make, perl, hping3, slowhttptest, interactsh-client, '
            'ffuf, httpx, jwt_tool, graphql-cop, graphqlmap, dalfox, masscan\n'
            '   - **Wordlists (SecLists):** pre-installed at `/usr/share/seclists/Discovery/Web-Content/`:\n'
            '     - `common.txt` (4750 entries) — standard web content discovery\n'
            '     - `big.txt` (20481 entries) — comprehensive directory list\n'
            '     - `raft-medium-directories.txt` (29999 entries) — raft-based directory enumeration\n'
            '   - **Python libs** (for one-liners via `python3 -c`): '
            'requests, beautifulsoup4, pycryptodome, PyJWT, paramiko, impacket, pwntools\n'
            '   - For multi-line scripts use **execute_code** instead (avoids shell escaping)\n'
            '   - Do NOT use for: curl, nmap, naabu, nuclei, msfconsole — use their dedicated tools'
        ),
    },
    "execute_code": {
        "purpose": "Execute code files (Python, bash, C, etc.)",
        "when_to_use": "Multi-line exploit scripts without shell escaping issues",
        "args_format": '"code": "source code", "language": "python", "filename": "exploit"',
        "description": (
            '**execute_code** (Code execution — no shell escaping)\n'
            '   - Writes code to file and runs with appropriate interpreter\n'
            '   - **Languages:** python (default), bash, ruby, perl, c, cpp\n'
            '   - **Timeout:** 120s (compiled: 60s compile + 120s run). Files persist at /tmp/{filename}.{ext}\n'
            '   - **Python libs** (import directly): '
            'requests, beautifulsoup4, pycryptodome, PyJWT, paramiko, impacket, pwntools\n'
            '   - Do NOT use for shell commands — use kali_shell instead'
        ),
    },
    "execute_playwright": {
        "purpose": "Browser automation -- rendered content extraction or custom scripting",
        "when_to_use": "Get JS-rendered page content (SPAs, dynamic pages), fill forms, test XSS inputs, login testing, multi-step browser flows",
        "args_format": '"url": "http://target:port/path", "selector": "CSS selector", "format": "text|html", "script": "Playwright Python code"',
        "description": (
            '**execute_playwright** (Browser automation -- Playwright)\n'
            '   - **Content mode** (url): renders page with real browser, extracts text/HTML\n'
            '     Unlike curl, this executes JavaScript -- perfect for SPAs and dynamic pages\n'
            '     Optional: selector="form" to target elements, format="html" for innerHTML\n'
            '   - **Script mode** (script): run multi-step Playwright Python code\n'
            '     Pre-initialized `browser`, `context`, `page` variables. Use print() for output.\n'
            '     Example: page.goto("url"); page.fill("#user","admin"); print(page.title())'
        ),
    },
    "execute_hydra": {
        "purpose": "Brute force password cracking (50+ protocols)",
        "when_to_use": "Credential brute force attacks (SSH, FTP, SMB, RDP, HTTP, MySQL, etc.)",
        "args_format": '"args": "hydra arguments without \'hydra\' prefix"',
        "description": (
            '**execute_hydra** (THC Hydra — brute force)\n'
            '   - 50+ protocols: ssh, ftp, rdp, smb, vnc, mysql, mssql, postgres, redis, telnet, http-post-form, etc.\n'
            '   - Key flags: `-l/-L` user(s), `-p/-P` pass(es), `-C` combo file, '
            '`-e nsr` (null/login-as-pass/reverse), `-t` threads, `-f` stop on first hit, `-s` port, `-S` SSL\n'
            '   - Syntax: `[flags] protocol://target[:port]`\n'
            '   - HTTP form: `[flags] target http-post-form "/path:user=^USER^&pass=^PASS^:F=failure_string"`'
        ),
    },
    "metasploit_console": {
        "purpose": "Exploit execution",
        "when_to_use": "Execute exploits, manage sessions",
        "args_format": '"command": "msfconsole command to execute"',
        "description": (
            '**metasploit_console** (Primary exploitation tool)\n'
            '   - Persistent msfconsole — module context and sessions survive between calls\n'
            '   - **Chain commands with `;`** (semicolons). Do NOT use `&&` or `||`\n'
            '   - **Shell limitations:** no variable assignment `$()`, no heredocs, no subshell expansion. '
            'For complex scripts: write to file via `echo`, then run with `python3`'
        ),
    },
    "execute_wpscan": {
        "purpose": "WordPress vulnerability scanning",
        "when_to_use": "Scan WordPress sites for vulnerable plugins, themes, users, and misconfigurations",
        "args_format": '"args": "wpscan arguments without \'wpscan\' prefix"',
        "description": (
            '**execute_wpscan** (WordPress security scanner)\n'
            '   - Detects vulnerable plugins, themes, and WordPress core versions\n'
            '   - Enumerates users, config backups, database exports\n'
            '   - Requires WPScan API token for vulnerability data (free: 25 requests/day)\n'
            '   - Key flags: --url TARGET, --enumerate p,t,u,cb, --format json, --api-token TOKEN\n'
            '   - Example: "--url http://example.com --enumerate p,t --format json --no-banner"'
        ),
    },
    "msf_restart": {
        "purpose": "Restart msfconsole",
        "when_to_use": "Reset Metasploit to a clean state (kills ALL sessions)",
        "args_format": '(no arguments)',
        "description": (
            '**msf_restart** (Full Metasploit reset)\n'
            '   - Kills ALL active sessions and clears module config. Takes 60-120s.\n'
            '   - Use only when you need a completely clean state'
        ),
    },
}

# Simplified web_search entry used when Knowledge Base is not available
# (--skipkbase install or missing KB dependencies). Replaces the full
# KB-centric entry in TOOL_REGISTRY at runtime via orchestrator.py.
WEB_SEARCH_TAVILY_ONLY = {
    "purpose": "Web search via Tavily",
    "when_to_use": "Research CVEs, exploits, tool usage, security advisories, version info",
    "args_format": '"query": "search query"',
    "description": (
        '**web_search** (SECONDARY -- external web research via Tavily)\n'
        '   - Searches the internet for security research information.\n'
        '   - Use for: CVE details, exploit techniques, tool documentation, '
        'security advisories, version info, methodology references.\n'
        '   - **Args**: `query` (str, required) -- the search query.\n'
        '   - Use AFTER query_graph when you need context not in the graph'
    ),
}
