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
            'GithubHunt, Repositories, Paths, Secrets, SensitiveFiles\n'
            '   - Skip if you already know which specific tool to use'
        ),
    },
    "web_search": {
        "purpose": "Web search (Tavily)",
        "when_to_use": "Research CVEs, exploits, service vulns",
        "args_format": '"query": "search query for CVE details, exploit techniques, etc."',
        "description": (
            '**web_search** (SECONDARY — external research)\n'
            '   - Search the internet via Tavily for CVE details, exploit PoCs, advisories, '
            'Metasploit module docs, version-specific vulns\n'
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
            'ffuf, httpx, jwt_tool, graphql-cop, graphqlmap, dalfox\n'
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
    "execute_masscan": {
        "purpose": "High-speed port scanning for IP ranges/CIDRs",
        "when_to_use": "Scan large networks, subnets, or IP ranges for open ports at high speed",
        "args_format": '"args": "complete masscan CLI arguments"',
        "description": (
            '**execute_masscan** (Fastest port scanner for large networks)\n'
            '   - Asynchronous SYN scanning — scans millions of IPs quickly\n'
            '   - ONLY accepts IP addresses and CIDR ranges (NOT hostnames)\n'
            '   - Resolve hostnames to IPs first using dig/nslookup\n'
            '   - Requires root or CAP_NET_RAW capability\n'
            '   - Key flags:\n'
            '     - `-p PORTS` — port list or range (e.g., `-p 80,443` or `-p 0-65535`)\n'
            '     - `--top-ports N` — scan top N most common ports\n'
            '     - `--rate N` — packets per second (default 100, can go to 10M+)\n'
            '     - `--banners` — grab service banners after port discovery\n'
            '     - `-iL FILE` — read targets from file\n'
            '     - `--excludefile FILE` — exclude targets from file\n'
            '   - Example: "10.0.0.0/24 -p 80,443,8080 --rate 1000"\n'
            '   - Example: "192.168.1.0/24 --top-ports 100 --rate 5000"\n'
            '   - Example: "10.0.0.1-10.0.0.254 -p 0-65535 --rate 10000 --banners"'
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
    "censys": {
        "purpose": "Censys internet search (hosts/services)",
        "when_to_use": "Search for hosts by banner, cert, or get detailed host info",
        "args_format": '"action": "search|host", "query": "...", "ip": "..."',
        "description": (
            '**censys** (Internet-wide host/service search)\n'
            '   - **action="search"** — Search hosts by query (e.g. "services.port=443 AND location.country=US")\n'
            '   - **action="host"** — Detailed IP info: services, TLS certs, OS, ASN\n'
            '   - Paid API — requires Censys API ID + Secret'
        ),
    },
    "fofa": {
        "purpose": "FOFA cyberspace search (asset discovery)",
        "when_to_use": "Search for assets by banner, certificate, domain, header, protocol",
        "args_format": '"query": "FOFA query string"',
        "description": (
            '**fofa** (FOFA cyberspace search)\n'
            '   - Query syntax: domain="example.com", ip="1.2.3.4", header="Apache", cert="example.com"\n'
            '   - Returns IP, port, host, title, server, protocol, geo'
        ),
    },
    "otx": {
        "purpose": "AlienVault OTX threat intelligence",
        "when_to_use": "Check IPs/domains against threat feeds, get pulse counts, adversary attribution, malware samples, and historical infrastructure",
        "args_format": '"action": "ip_report|domain_report", "ip": "...", "domain": "..."',
        "description": (
            '**otx** (AlienVault Open Threat Exchange)\n'
            '   - **action="ip_report"** — Threat pulses, adversary attribution, malware samples, reputation, geo for an IP\n'
            '   - **action="domain_report"** — Threat pulses, adversary, malware samples, WHOIS, historical IPs for a domain\n'
            '   - Works without API key (reduced rate); key provides private pulses and higher limits'
        ),
    },
    "netlas": {
        "purpose": "Netlas.io internet intelligence search",
        "when_to_use": "Search for services by banner, certificate; get host details",
        "args_format": '"action": "search|host", "query": "...", "ip": "..."',
        "description": (
            '**netlas** (Internet intelligence)\n'
            '   - **action="search"** — Search responses index (e.g. "host:example.com", "port:443")\n'
            '   - **action="host"** — Aggregated host info for an IP'
        ),
    },
    "virustotal": {
        "purpose": "VirusTotal reputation lookup",
        "when_to_use": "Check IP/domain reputation against 70+ security vendors",
        "args_format": '"action": "ip_report|domain_report", "ip": "...", "domain": "..."',
        "description": (
            '**virustotal** (Multi-engine reputation)\n'
            '   - **action="ip_report"** — Detections, ASN, country for an IP\n'
            '   - **action="domain_report"** — Detections, categories, popularity, registrar for a domain\n'
            '   - Free tier: 4 lookups/min, 500/day — use sparingly'
        ),
    },
    "zoomeye": {
        "purpose": "ZoomEye cyberspace search",
        "when_to_use": "Search for hosts/devices by port, app, banner, OS, country",
        "args_format": '"query": "ZoomEye search query"',
        "description": (
            '**zoomeye** (Cyberspace search)\n'
            '   - Query syntax: ip:"1.2.3.4", hostname:"example.com", port:8080, app:"Apache"\n'
            '   - Returns ports, banners, OS, geo info'
        ),
    },
    "criminalip": {
        "purpose": "Criminal IP threat intelligence",
        "when_to_use": "Get IP/domain risk scores, detect VPN/proxy/Tor, find vulnerabilities",
        "args_format": '"action": "ip_report|domain_report", "ip": "...", "domain": "..."',
        "description": (
            '**criminalip** (AI threat intelligence)\n'
            '   - **action="ip_report"** — Risk score, open ports, issues (VPN/proxy/Tor/hosting), vulnerabilities\n'
            '   - **action="domain_report"** — Risk assessment, technologies, domain intel'
        ),
    },
}
