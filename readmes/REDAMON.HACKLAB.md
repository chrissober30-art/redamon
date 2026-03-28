# RedAmon HackLab
### 50 Agentic Attack Prompts — Powered by RedAmon AI Agent
### Target: AltoroJ — intentionally vulnerable banking app deployed on your own EC2 instance

> **How it works:**
> Each prompt is intentionally short and generic — no hardcoded URLs, no specific parameters.
> The agent starts every session by querying the Neo4j graph database to retrieve everything
> discovered during the recon pipeline (endpoints, technologies, CVEs, injectable parameters, services).
> From there it reasons autonomously, selects the right tools, chains them across phases,
> and executes the full attack — just like a real human operator would.
>
> **Prerequisites:**
> - AltoroJ deployed and running on your EC2 instance
> - Full recon pipeline executed and stored in the graph database
> - RedAmon agent configured with your EC2 IP as the target

---

## CATEGORY 1 — SQL INJECTION (1–5)

### #1 — SQL Injection Login Bypass → Full Database Dump
```
Query the graph to find all login forms and injectable parameters discovered on the target.
Test each login form for SQL injection using classic auth bypass payloads.
If bypass is confirmed, use sqlmap to enumerate all databases and dump the users table.
```

### #2 — SQLi → File Read → OS Shell
```
Query the graph to identify injectable parameters on the target.
Use sqlmap to confirm SQL injection, then escalate:
attempt file read (/etc/passwd), then file write (drop a web shell),
then attempt OS shell access. Transition to post-exploitation if shell is obtained.
```

### #3 — Blind SQLi + Out-of-Band DNS Exfiltration
```
Query the graph for injectable parameters and response-time anomalies noted during recon.
Set up an interactsh OOB callback domain, then use sqlmap with --dns-domain to
perform blind SQL injection with DNS-based data exfiltration.
Show what data arrives via DNS callbacks.
```

### #4 — Time-Based Blind SQLi with WAF Bypass Tamper Scripts
```
Query the graph to check if any WAF or security headers were detected on the target.
Test for time-based blind SQL injection and apply appropriate sqlmap tamper scripts
(space2comment, randomcase, charencode) to bypass filtering.
Explain which tamper was chosen and why based on the detected technology stack.
```

### #5 — SQLi → Web Shell Upload → Remote Code Execution
```
Query the graph to identify the web root path and writable directories on the target.
Use sqlmap file-write to upload a JSP web shell to the web root,
then trigger it via HTTP request to confirm remote code execution.
Transition to post-exploitation after shell access is confirmed.
```

---

## CATEGORY 2 — XSS & CLIENT-SIDE ATTACKS (6–8)

### #6 — Reflected XSS → Stored XSS → Cookie Theft Simulation
```
Query the graph to find all user-input endpoints and parameters on the target.
Test each for reflected XSS, then attempt stored XSS via feedback or comment forms.
Build a cookie-theft payload and explain the real-world session hijacking impact.
```

### #7 — HTTP Response Header Injection + XSS via HTTP Headers
```
Query the graph to identify which HTTP headers are reflected or logged by the target application.
Test for CRLF injection in URL parameters and XSS via User-Agent and Referer headers.
Document all injection points found with full HTTP request/response evidence.
```

### #8 — DOM-Based XSS + JavaScript Sink Analysis
```
Query the graph for discovered JavaScript files and client-side endpoints on the target.
Retrieve and analyze JavaScript source files for dangerous sinks (innerHTML, eval, document.write).
Test URL fragment and parameter injection to confirm DOM-based XSS.
Explain why DOM XSS evades server-side WAFs.
```

---

## CATEGORY 3 — AUTHENTICATION & SESSION ATTACKS (9–12)

### #9 — Hydra Brute Force Login → Session Takeover
```
Query the graph to find login endpoints and any credential hints discovered during recon.
Analyze the login form structure, then brute force it with Hydra using common wordlists.
On success, use the discovered credentials to authenticate and capture a valid session cookie.
```

### #10 — Session Fixation + Cookie Security Audit
```
Query the graph for cookie names and session management findings from recon.
Capture a pre-authentication session token, authenticate, and compare the before/after session IDs.
Check all cookie security flags (HttpOnly, Secure, SameSite) and test if logout properly invalidates sessions.
```

### #11 — IDOR + Horizontal Privilege Escalation
```
Query the graph for account-related endpoints and numeric ID parameters discovered on the target.
Authenticate as a low-privilege user and attempt to access other users' data
by manipulating account ID parameters. Test for admin panel access as a regular user.
```

### #12 — Forced Browsing + Admin Panel Exposure + Config File Disclosure
```
Query the graph for all paths and directories discovered during resource enumeration.
Attempt direct unauthenticated access to admin panels, management interfaces,
and sensitive configuration files. Report anything accessible without authentication.
```

---

## CATEGORY 4 — CVE EXPLOITATION WITH METASPLOIT (13–17)

### #13 — Nuclei CVE Scan → Auto-Select → Metasploit Exploitation
```
Query the graph for CVEs already identified during recon on the target.
Run Nuclei to confirm and discover additional critical/high vulnerabilities.
Search for a Metasploit module for the top CVE found, configure it, and exploit.
Transition to post-exploitation on session open.
```

### #14 — Tomcat Manager Brute Force → WAR Deployment → Meterpreter
```
Query the graph to check if a Tomcat Manager interface was discovered and what version is running.
Brute force the manager credentials with Hydra using Tomcat default wordlists.
Deploy a malicious WAR file via the tomcat_mgr_upload Metasploit module to open a Meterpreter session.
```

### #15 — Java Deserialization RCE — No MSF Module Fallback via execute_code
```
Query the graph for any Java deserialization endpoints or related CVEs on the target.
If no Metasploit module exists for the CVE, use the no-module fallback:
set up a reverse handler, write a Python exploit with execute_code, and deliver the payload manually.
```

### #16 — Log4Shell (CVE-2021-44228) → JNDI Callback → Reverse Shell
```
Query the graph to confirm Log4j version and any Log4Shell findings stored during recon.
Set up an interactsh listener, inject JNDI payloads into HTTP headers (User-Agent, X-Forwarded-For, X-Api-Version).
Confirm the DNS callback, then deliver a reverse shell through the JNDI vector.
```

### #17 — Metasploit Auxiliary Chain → Exploit → Post Module
```
Query the graph for confirmed services and versions on the target.
Run Metasploit auxiliary scanners (http_version, brute_dirs) to enrich the attack surface,
then search for and execute the best-ranked exploit module for the detected technology.
Run post-exploitation modules on the opened session.
```

---

## CATEGORY 5 — REVERSE SHELL & RCE (18–20)

### #18 — Command Injection → Reverse Bash Shell
```
Query the graph for endpoints flagged as potentially injectable during recon.
Test for OS command injection by sending payloads like ;id and |whoami via HTTP parameters.
If confirmed, set up a Metasploit handler and deliver a reverse bash shell through the injection point.
```

### #19 — SSTI Detection → Template Engine Fingerprint → RCE
```
Query the graph for the web framework and template engine detected on the target.
Test input fields with detection payloads ({{7*7}}, ${7*7}, #{7*7}) to confirm SSTI.
Fingerprint the template engine from the response, then escalate to remote code execution.
```

### #20 — File Upload Bypass → Web Shell → Reverse Shell
```
Query the graph for any file upload endpoints discovered during recon.
Test content-type bypass to upload a JSP reverse shell.
Trigger the uploaded shell and catch the session in a Metasploit handler.
```

---

## CATEGORY 6 — POST-EXPLOITATION (21–24)

### #21 — Meterpreter Full Enumeration: System + Credentials + File Exfil
```
Starting from an active Meterpreter session on the target.
Query the graph for the entry point used to establish context.
Run post-exploitation modules: system info, network enumeration, credential harvesting, hashdump.
Search for and download sensitive configuration files containing credentials.
```

### #22 — Privilege Escalation: SUID + Sudo Abuse → Root
```
Starting from a low-privilege shell on the target (tomcat/www-data user).
Query the graph for OS version and any privilege escalation CVEs stored from recon.
Check sudo permissions, enumerate SUID binaries, and identify writable cron jobs.
Use the first viable vector to escalate to root. Dump /etc/shadow after root is obtained.
```

### #23 — Persistence: Backdoor User + Crontab Reverse Shell
```
Starting from a root shell on the target.
Demonstrate persistence by creating a backdoor user with sudo access,
installing an SSH authorized key, and adding a crontab-based reverse shell that fires every minute.
Verify persistence by catching the callback in a fresh Metasploit handler.
```

### #24 — Network Pivoting: MSF Route + Internal Subnet Scan
```
Starting from an active Meterpreter session on the target.
Query the graph for network interfaces and internal IP ranges discovered during recon.
Add an MSF route through the session, scan the internal network for live hosts and services,
then probe discovered internal services through the pivot.
```

---

## CATEGORY 7 — DENIAL OF SERVICE (25–27)

### #25 — Slowloris HTTP DoS → Service Disruption + Recovery Check
```
Query the graph for the HTTP server version and any DoS-related findings on the target.
Launch a Slowloris attack with slowhttptest against the web application.
Verify service impact during the attack with periodic HTTP probes, then check recovery after.
```

### #26 — TCP SYN Flood + UDP Flood with hping3
```
Query the graph for open TCP ports and network configuration of the target.
Execute TCP SYN flood, UDP flood, and ICMP flood attacks using hping3 against the target.
Verify port availability before and after each attack vector using Nmap.
Explain the difference between L4 and L7 DoS and which defenses mitigate each.
```

### #27 — Application Logic DoS: XML Bomb + Concurrent Request Exhaustion
```
Query the graph for XML-processing or API endpoints on the target.
Use execute_code to craft and send a Billion Laughs XML bomb payload.
Follow up with a concurrent request flood (500 parallel threads) to exhaust the server thread pool.
Monitor response time degradation as evidence of impact.
```

---

## CATEGORY 8 — PHISHING & PAYLOAD GENERATION (28–29)

### #28 — msfvenom Linux ELF Payload → Handler → Meterpreter
```
Query the graph to confirm the target OS and architecture.
Generate a stageless Linux Meterpreter ELF payload with msfvenom.
Set up the multi/handler, simulate delivery to the target, and catch the Meterpreter session.
Demonstrate the difference between staged and stageless payloads.
```

### #29 — Fileless Web Delivery → Python Meterpreter (No Binary on Disk)
```
Query the graph to confirm Python availability on the target.
Use Metasploit web_delivery to generate a Python one-liner payload that runs entirely in memory.
Simulate social engineering delivery, catch the session, then prove no file was written to disk.
Explain why fileless execution bypasses traditional AV and disk forensics.
```

---

## CATEGORY 9 — FULL AUTONOMOUS KILL CHAIN (30)

### #30 — Full Pentest: Recon → Exploit → Root → Persist → Report
```
Perform a complete autonomous penetration test against the target.
Start by querying the graph to understand the full attack surface.
Select and execute the highest-confidence attack vector to gain initial access.
Escalate privileges to root, establish persistence, and harvest credentials.
At the end, generate a structured pentest report with: executive summary,
attack path, vulnerabilities found (with CVSS scores), data accessed,
remediation recommendations, and MITRE ATT&CK technique mapping.
```

---

## CATEGORY 10 — ADVANCED & BONUS (31–40)

### #31 — SSL/TLS Misconfiguration Audit
```
Query the graph for TLS certificate and protocol data captured during recon on the target.
Use Nmap ssl-enum-ciphers and sslscan to identify weak ciphers, outdated protocols (TLS 1.0/1.1),
expired certificates, and self-signed certificates.
Rate each finding by exploitability and explain the man-in-the-middle risk.
```

### #32 — SSH Brute Force → Shell Access → sudo Escalation
```
Query the graph for any SSH service discovered on the target and OS hints from banners.
Brute force SSH credentials with Hydra using OS-aware wordlists (ubuntu, ec2-user, root).
On success, connect via sshpass and immediately check sudo -l for privilege escalation paths.
```

### #33 — Information Disclosure via Error Messages + Stack Trace Harvesting
```
Query the graph for all discovered endpoints and parameters on the target.
Send malformed, oversized, and type-mismatched inputs to every parameter via execute_curl.
Collect all stack traces, database error messages, internal paths, and framework version leaks.
Build a target profile from the disclosed information alone.
```

### #34 — CSRF Token Bypass + Unauthorized State-Changing Request
```
Query the graph for POST endpoints and form parameters discovered during recon.
Analyze CSRF protection mechanisms: check if tokens are present, validated, or reusable.
Craft a state-changing request (fund transfer, password change) that succeeds without a valid CSRF token.
Document the impact and explain how a malicious page would deliver this in the real world.
```

### #35 — Password Reset Flow Abuse + Account Takeover
```
Query the graph for authentication-related endpoints discovered on the target.
Analyze the password reset flow: test for predictable tokens, token reuse, host header injection,
and whether the reset link reveals the token in the HTTP response.
Demonstrate account takeover via the weakest link in the reset chain.
```

### #36 — Malicious Word Document (VBA Macro) → Meterpreter
```
Query the graph to confirm the target OS is Windows or that Windows clients are in scope.
Use Metasploit office_word_macro fileformat module to generate a weaponized .docm file.
Set up the reverse handler, verify the document was generated, and simulate delivery.
Explain how the macro fires on document open and catches the Meterpreter callback.
```

### #37 — Credential Reuse Attack: Dump → SSH → Database → Lateral Move
```
Starting from credentials or hashes harvested during a prior exploitation step.
Query the graph for all services running on the target and any related hosts.
Test the harvested credentials against SSH, database services (MySQL, PostgreSQL), and admin panels.
For each successful reuse, enumerate accessible data and attempt further lateral movement.
```

### #38 — CVE Research → OSINT Correlation → Exploit Prioritization Report
```
Query the graph for all CVEs and technologies stored from the recon pipeline.
Use web_search to enrich each CVE with CVSS score, public exploit availability, and patch status.
Cross-reference with Shodan and VirusTotal data from the graph to assess real-world exposure.
Produce a prioritized exploitation roadmap ranked by impact and ease of exploitation.
```

### #39 — Stealth Mode Attack: Slow Scan + Minimal Footprint + Log Evasion
```
Query the graph for the full attack surface discovered during recon.
Enable stealth mode and perform the same SQL injection and CVE exploitation chain as a normal run,
but with rate limiting, randomized user agents, and delays between requests.
Compare the noise level between normal and stealth execution and explain what a SIEM would see.
```

### #40 — Strategic Planning: Agent Self-Designs the Full Attack
> 💡 **Enable Deep Think before running this prompt**
```
Query the graph for the complete recon dataset on the target: all ports, services,
technologies, CVEs, endpoints, parameters, and OSINT findings.
Before executing any tool, autonomously design the optimal full attack strategy —
choose attack vectors, order of operations, fallback paths, and post-exploitation goals.
Present the plan, then execute it and report any deviations.
```

---

## CATEGORY 11 — ALTOROJ-SPECIFIC ATTACKS (41–50)

### #41 — REST API Weak Token Decode → Credential Extraction
```
Query the graph for any REST API endpoints and authentication tokens discovered on the target.
Authenticate via the REST API login endpoint and capture the returned auth token.
Decode the token (it uses weak Base64 encoding of username:password) and extract plaintext credentials.
Use the decoded credentials to authenticate to other services on the target.
```

### #42 — REST API IDOR: Access Any Account Without Authorization
```
Query the graph for REST API endpoints and account-related paths on the target.
Authenticate as a low-privilege user via the REST API and retrieve your own account ID.
Then iterate through other account IDs via the account balance endpoint without any authorization check.
Document every account balance accessible and explain the broken access control root cause.
```

### #43 — XPath Injection → Authentication Bypass + Data Extraction
```
Query the graph for search or query endpoints that may process XML or XPath expressions on the target.
Test the news/article search endpoint for XPath injection using payloads like ' or '1'='1.
Attempt authentication bypass and data extraction by manipulating the XPath query logic.
Compare XPath injection to SQL injection and explain the unique detection challenges.
```

### #44 — Open Redirect → Phishing Landing Page Delivery
```
Query the graph for redirect parameters and URL-handling endpoints discovered on the target.
Identify the open redirect vulnerability and confirm it accepts arbitrary external URLs.
Craft a redirect URL that points to a simulated phishing page and demonstrate
how a trusted domain can be abused to legitimize a phishing link.
```

### #45 — REST API SQL Injection in Transaction Date Filter → Full Data Dump
```
Query the graph for REST API endpoints that accept date or range parameters on the target.
Test the transaction query endpoint for SQL injection via the date filter parameters.
Use sqlmap against the REST API endpoint to enumerate the database and dump the accounts and users tables.
Show how REST APIs are equally vulnerable to SQLi as traditional web forms.
```

### #46 — Swagger UI Discovery → Full API Surface Mapping → Targeted Attack
```
Query the graph for any API documentation or Swagger/OpenAPI endpoints discovered on the target.
Access the Swagger UI to enumerate all REST API endpoints, parameters, and authentication requirements.
Identify the most dangerous endpoint (unauthenticated or broken auth), then attack it directly.
Demonstrate how exposed API documentation accelerates an attacker's reconnaissance phase.
```

### #47 — Plaintext Password Extraction via SQLi → Credential Spray
```
Query the graph for injectable parameters and database type detected on the target.
Use SQL injection to dump the users table and extract plaintext passwords stored without hashing.
Test the extracted credentials against SSH, the admin panel, and the REST API.
Explain the compounding risk of SQLi + plaintext storage + credential reuse.
```

### #48 — CSRF: Unauthorized Fund Transfer Without Token
```
Query the graph for state-changing POST endpoints and any CSRF protection mechanisms detected on the target.
Authenticate as a valid user and analyze the fund transfer request for CSRF tokens.
Craft a forged cross-origin fund transfer request that the server accepts without validation.
Generate a proof-of-concept HTML page that would silently trigger the transfer when visited by a victim.
```

### #49 — OS Command Injection via Static Page Processing → RCE
```
Query the graph for any file-serving or content-processing endpoints on the target.
Test parameters that accept file names or paths for OS command injection using semicolons and pipes.
If the application processes static content via shell commands, inject a reverse shell payload.
Set up a Metasploit handler and transition to post-exploitation on shell access.
```

### #50 — Log4j 1.x Deserialization (CVE-2019-17571) → Remote Code Execution
> 💡 **Enable Deep Think before running this prompt**
```
Query the graph to confirm the Log4j version and any related CVEs stored during recon on the target.
Research CVE-2019-17571 (Log4j 1.x SocketServer deserialization) via web_search.
Set up a Metasploit handler, then craft and deliver a malicious serialized Java object
to the Log4j SocketServer listener port to trigger remote code execution.
Transition to post-exploitation on session open.
```

---

## Quick Reference

| Category | Demos | Key Tools |
|----------|-------|-----------|
| SQL Injection | #1–5 | `kali_shell` (sqlmap), `execute_curl` |
| XSS & Client-Side | #6–8 | `execute_curl` |
| Auth & Sessions | #9–12 | `execute_hydra`, `execute_curl` |
| CVE with Metasploit | #13–17 | `execute_nuclei`, `metasploit_console` |
| Reverse Shell & RCE | #18–20 | `execute_curl`, `execute_code`, `metasploit_console` |
| Post-Exploitation | #21–24 | `metasploit_console`, `kali_shell` |
| Denial of Service | #25–27 | `kali_shell` (slowhttptest, hping3), `execute_code` |
| Phishing & Payloads | #28–29 | `kali_shell` (msfvenom), `metasploit_console` |
| Full Kill Chain | #30 | ALL |
| Advanced & Bonus | #31–40 | Mixed |
| AltoroJ-Specific | #41–50 | Mixed |

> 💡 = Enable Deep Think in agent settings before running
