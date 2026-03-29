# RedAmon HackLab
### 50 Agentic Attack Prompts -- Powered by RedAmon AI Agent
### Target: DVWS-Node + CVE Lab -- Vulnerable Web Services + Metasploit-Exploitable CVEs

> **How it works:**
> Each prompt is intentionally short and generic -- no hardcoded URLs, no specific parameters.
> The agent autonomously searches the recon data, selects the right tools, chains them across phases,
> and executes the full attack -- just like a real human operator would.
>
> **Prerequisites:**
> - DVWS-Node + CVE Lab deployed on your EC2 instance
> - Full recon pipeline executed and stored in the graph database
> - RedAmon agent configured with your EC2 IP as the target

---

## Target Overview

### DVWS-Node (application-level vulnerabilities)

| Service | Port | Technology |
|---------|------|-----------|
| REST API + SOAP + Swagger | 80 | Node.js, Express |
| GraphQL Playground | 4000 | Apollo Server |
| XML-RPC | 9090 | xmlrpc module |
| MySQL | 3306 | MySQL 8.4 (exposed) |
| MongoDB | 27017 | MongoDB 4.0.4 (exposed, no auth) |

### CVE Lab (Metasploit-exploitable CVEs)

| Service | Port | CVE | Metasploit Module |
|---------|------|-----|-------------------|
| Apache Tomcat 8.5.19 | 8080 | CVE-2017-12617 | `exploit/multi/http/tomcat_jsp_upload_bypass` |
| Log4Shell (Spring Boot) | 8888 | CVE-2021-44228 | `exploit/multi/http/log4shell_header_injection` |
| vsftpd 2.3.4 | 21, 6200 | CVE-2011-2523 | `exploit/unix/ftp/vsftpd_234_backdoor` |

**Default credentials:** `admin` / `letmein` (admin), `test` / `test` (regular), `root` / `mysecretpassword` (MySQL)

---

## Vulnerability Map

### Application-Level (DVWS-Node)

| Category | Count | Key Endpoints |
|----------|-------|---------------|
| SQL Injection | 2 | `/api/v2/passphrase`, GraphQL `getPassphrase` |
| NoSQL Injection | 2 | `/api/v2/notesearch` |
| OS Command Injection | 1 | `/api/v2/sysinfo/:command` |
| XXE Injection | 3 | `/dvwsuserservice`, `/api/v2/notes/import/xml`, profile XML |
| SSRF | 2 | XML-RPC `dvws.CheckUptime`, `/api/download` |
| JWT/Auth Bypass | 3 | `alg:none`, weak secret, expired tokens accepted |
| IDOR / Broken Access Control | 4 | Notes API, GraphQL queries, admin endpoints |
| Insecure Deserialization | 1 | `/api/v2/export` (node-serialize RCE) |
| XPath Injection | 1 | `/api/v2/release/:release` |
| LDAP Injection | 1 | `/api/v2/users/ldap-search` |
| Prototype Pollution | 1 | `/api/upload` metadata merge |
| Path Traversal | 2 | `/api/download`, GraphQL `updateUserUploadFile` |
| Open Redirect | 1 | `/api/v2/users/logout/:redirect` |
| CORS Misconfiguration | 1 | Global wildcard with credentials |
| Info Disclosure | 2 | `/api/v1/info` (env vars + JWT secret), GraphQL introspection |
| Privilege Escalation | 1 | `/api/v2/users/profile/import/xml` (mass assignment) |

### CVE-Based (CVE Lab)

| CVE | CVSS | Service | Type | Impact |
|-----|------|---------|------|--------|
| CVE-2017-12617 | 8.1 | Tomcat 8.5.19 :8080 | PUT method RCE | Upload JSP shell via HTTP PUT |
| CVE-2021-44228 | 10.0 | Log4j 2.14.1 :8888 | JNDI injection RCE | Remote code execution via HTTP headers |
| CVE-2011-2523 | 10.0 | vsftpd 2.3.4 :21 | Backdoor | Root shell on port 6200 |
| Log Injection | 1 | `/api/v2/login` username field |
| Rate Limit Bypass | 1 | X-Forwarded-For spoofing on login |
| GraphQL Abuse | 3 | Introspection, batching, password hash exposure |
| Unrestricted File Upload | 1 | `/api/upload` |

---

## CATEGORY 1 -- SQL INJECTION (1-5)

### #1 -- Unauthenticated SQL Injection -> Full Database Dump
```
Find endpoints on the target that accept username parameters without authentication.
Test for SQL injection using UNION-based techniques to enumerate
all databases, tables, and dump the passphrases table.
```

### #2 -- SQL Injection via POST Parameters -> Data Exfiltration
```
Authenticate to the target and find endpoints that accept passphrase or reminder inputs.
Test for SQL injection in POST parameters and use sqlmap to enumerate
the MySQL database schema and dump all tables including credentials.
```

### #3 -- GraphQL SQL Injection -> Database Dump
```
Find the GraphQL endpoint on the target and enumerate the schema via introspection.
Identify queries that accept string parameters and test each for SQL injection.
Use sqlmap to exploit any confirmed injection point and dump the database.
```

### #4 -- Blind SQL Injection with Time-Based Extraction
```
Find injectable parameters on the target's REST API and confirm blind SQL injection
using time-based payloads (SLEEP). Extract the MySQL version, database names,
and user credentials character by character. Compare extraction speed
between time-based and UNION-based techniques.
```

### #5 -- SQL Injection -> File Read -> Web Shell Upload
```
Exploit SQL injection on the target to read server files via LOAD_FILE().
Identify the web root path, then use INTO OUTFILE to write a web shell.
Confirm remote code execution through the uploaded shell.
```

---

## CATEGORY 2 -- NoSQL INJECTION (6-8)

### #6 -- NoSQL Injection -> Dump All Notes From All Users
```
Find search endpoints on the target that query MongoDB.
Test for NoSQL injection using JavaScript evaluation in $where clauses.
Extract all notes including private notes from all users.
```

### #7 -- NoSQL Injection -> Authentication Bypass via Operator Injection
```
Find login or search endpoints on the target that use MongoDB.
Test for operator injection using $gt, $ne, and $regex operators
to bypass authentication or extract data without valid credentials.
```

### #8 -- NoSQL Injection -> Time-Based Data Extraction
```
Find MongoDB-backed search endpoints on the target.
Use JavaScript sleep-based payloads in $where clauses
to extract data character by character via timing side-channels.
Document the extraction technique and all data recovered.
```

---

## CATEGORY 3 -- OS COMMAND INJECTION & RCE (9-12)

### #9 -- Command Injection -> Reverse Shell -> Post-Exploitation
```
Find endpoints on the target that interact with the operating system.
Test for command injection using shell metacharacters (;, |, &&).
Establish a reverse shell and perform post-exploitation:
enumerate users, network, running processes, and sensitive files.
```

### #10 -- Insecure Deserialization (node-serialize) -> Remote Code Execution
```
Find endpoints on the target that accept serialized or encoded data.
Test for insecure deserialization by crafting a node-serialize IIFE payload.
Achieve remote code execution and establish a Meterpreter session.
```

### #11 -- Command Injection -> Credential Harvesting -> Lateral Movement
```
Exploit command injection on the target to read environment variables,
configuration files, and database connection strings.
Use harvested database credentials to connect directly to MySQL and MongoDB
and dump all data. Test if credentials are reused on SSH.
```

### #12 -- Chained RCE: JWT Bypass -> Command Injection -> Persistence
```
Bypass authentication on the target using JWT algorithm confusion.
Use the forged token to access command injection endpoints.
Establish persistence via a crontab reverse shell and an SSH authorized key.
Verify persistence by catching callbacks after container restart.
```

---

## CATEGORY 4 -- XXE INJECTION (13-16)

### #13 -- XXE via SOAP Service -> File Exfiltration
```
Find SOAP endpoints on the target and retrieve the WSDL definition.
Craft an XXE payload in the SOAP envelope to read /etc/passwd.
Escalate to exfiltrate application source code, environment files,
and database configuration. No authentication should be needed.
```

### #14 -- XXE via Notes XML Import -> SSRF to Cloud Metadata
```
Find XML import endpoints on the target and test for XXE.
Use an external entity pointing to the AWS metadata endpoint
(169.254.169.254) to extract instance credentials, IAM role,
and security tokens. Explain the cloud privilege escalation risk.
```

### #15 -- XML Bomb (Billion Laughs) -> Denial of Service
```
Find XML processing endpoints on the target.
Craft a Billion Laughs (entity expansion) payload and send it.
Monitor server response time and memory consumption during the attack.
Verify service degradation and check recovery after stopping.
```

### #16 -- XXE -> Out-of-Band Data Exfiltration via DNS/HTTP
```
Find XXE-vulnerable endpoints on the target where the response
does not reflect entity content (blind XXE).
Set up an out-of-band channel (interactsh or a controlled server)
and use parameter entities to exfiltrate file contents via HTTP callbacks.
```

---

## CATEGORY 5 -- SSRF (17-19)

### #17 -- SSRF via XML-RPC -> AWS Metadata Theft
```
Find XML-RPC endpoints on the target and enumerate available methods.
Exploit SSRF to reach the AWS metadata service at 169.254.169.254.
Extract the instance IAM credentials, security token, and account ID.
Explain how stolen IAM credentials can be used for cloud lateral movement.
```

### #18 -- SSRF -> Internal Port Scanning -> Service Discovery
```
Exploit SSRF on the target to scan internal network ranges.
Probe common ports (3306, 27017, 6379, 8080, 9200) on internal IPs.
Map all discovered internal services and their versions.
Demonstrate accessing the internal MySQL and MongoDB directly via SSRF.
```

### #19 -- SSRF + Path Traversal -> Server File Read -> Source Code Theft
```
Find endpoints on the target that fetch files or URLs server-side.
Test for SSRF with file:// protocol to read local files.
Chain with path traversal to read application source code,
package.json, .env files, and database configuration.
```

---

## CATEGORY 6 -- JWT & AUTHENTICATION ATTACKS (20-23)

### #20 -- JWT Algorithm None Attack -> Full Admin Access
```
Authenticate to the target as a regular user and capture the JWT token.
Analyze the token structure and test for algorithm confusion (alg:none).
Forge an admin token without any signature and access all admin endpoints.
Document every admin-only endpoint that becomes accessible.
```

### #21 -- JWT Secret Extraction -> Token Forgery for All Users
```
Find information disclosure endpoints on the target that leak
server environment variables. Extract the JWT signing secret.
Forge valid tokens for every known user and demonstrate full impersonation.
If the secret is not directly leaked, brute force it with hashcat or jwt_tool.
```

### #22 -- Brute Force Login with Rate Limit Bypass
```
Find the login endpoint on the target and analyze rate limiting.
Bypass the rate limit using X-Forwarded-For header rotation.
Brute force credentials with Hydra using common wordlists.
Document all valid credential pairs discovered.
```

### #23 -- Session Analysis: Token Reuse + Expiration Bypass
```
Analyze the target's JWT implementation for security weaknesses.
Test if expired tokens are still accepted. Test if tokens remain valid
after logout. Test if the same token works across different sessions.
Document every session management flaw found.
```

---

## CATEGORY 7 -- IDOR & BROKEN ACCESS CONTROL (24-27)

### #24 -- IDOR on Notes API -> Read All Users' Private Data
```
Authenticate to the target and create some notes.
Enumerate note IDs and access notes belonging to other users.
Read, modify, and delete other users' private notes.
Document the total number of accessible records and their contents.
```

### #25 -- GraphQL IDOR -> User Enumeration + Password Hash Extraction
```
Find the GraphQL endpoint on the target and run introspection.
Use ID-based queries to enumerate all users in the database.
Extract usernames, admin status, and password hashes.
Attempt to crack the bcrypt hashes offline with hashcat.
```

### #26 -- Privilege Escalation via Mass Assignment -> Admin Takeover
```
Find user profile endpoints on the target that accept XML or JSON input.
Test for mass assignment by injecting an admin field into the update request.
Escalate a regular user to admin and verify access to admin-only endpoints.
```

### #27 -- Forced Browsing -> Admin Logs + Hidden API Endpoints
```
Enumerate all API endpoints on the target using Swagger/OpenAPI docs.
Attempt unauthenticated access to admin endpoints (logs, user management).
Discover and access any hidden or undocumented endpoints.
Test every endpoint with both regular and admin-forged tokens.
```

---

## CATEGORY 8 -- XPath & LDAP INJECTION (28-30)

### #28 -- XPath Injection -> Configuration Data Extraction
```
Find endpoints on the target that query XML documents.
Test for XPath injection using boolean-based and union-based techniques.
Extract all data from the underlying XML configuration file
including any secrets, API keys, or internal paths.
```

### #29 -- LDAP Injection -> User Enumeration + Credential Extraction
```
Find LDAP search endpoints on the target.
Test for LDAP filter injection using wildcard and boolean payloads.
Enumerate all users in the directory and extract their attributes
including passwords. Test extracted credentials against all services.
```

### #30 -- XPath + LDAP Injection Combined -> Full Directory Dump
```
Chain XPath injection and LDAP injection on the target
to extract all data from both XML config files and LDAP directories.
Cross-reference discovered credentials across SQL, NoSQL, and LDAP.
Build a complete credential map for the target.
```

---

## CATEGORY 9 -- FILE OPERATIONS & PATH TRAVERSAL (31-33)

### #31 -- Unrestricted File Upload -> Web Shell -> Reverse Shell
```
Find file upload endpoints on the target and test upload restrictions.
Upload a Node.js or reverse shell script bypassing any content-type checks.
Trigger the uploaded shell to confirm code execution, then establish
a reverse shell via Metasploit handler.
```

### #32 -- Path Traversal (Read) -> Application Source Code Theft
```
Find file download endpoints on the target and test for path traversal.
Use ../ sequences to read files outside the upload directory.
Download app.js, package.json, .env, and all route handler source files.
Extract hardcoded secrets, database credentials, and JWT signing keys.
```

### #33 -- GraphQL Arbitrary File Write -> Code Injection -> RCE
```
Find GraphQL mutations on the target that write files to the server.
Exploit path traversal in the file path parameter to write outside
the uploads directory. Overwrite a server-side JavaScript file
with malicious code and trigger it to achieve remote code execution.
```

---

## CATEGORY 10 -- PROTOTYPE POLLUTION (34-35)

### #34 -- Prototype Pollution via File Upload Metadata
```
Find file upload endpoints on the target that accept metadata.
Test for prototype pollution by injecting __proto__ in the metadata JSON.
Verify pollution by checking if new properties appear on empty objects.
Demonstrate how prototype pollution chains to authentication bypass.
```

### #35 -- Prototype Pollution -> Denial of Service + Auth Bypass
```
Exploit prototype pollution on the target to inject properties
that break application logic. Pollute properties used in
authorization checks to escalate privileges.
Demonstrate both DoS and privilege escalation via prototype pollution.
```

---

## CATEGORY 11 -- INFORMATION DISCLOSURE & RECON (36-38)

### #36 -- Environment Variable Leak -> JWT Secret -> Token Forgery
```
Find information disclosure endpoints on the target that expose
server internals. Extract environment variables including database
credentials and the JWT signing secret. Use the secret to forge
admin tokens and access all protected endpoints.
```

### #37 -- GraphQL Introspection -> Full API Mapping -> Targeted Attack
```
Run GraphQL introspection on the target to enumerate all queries,
mutations, and types. Map the complete API surface including
hidden fields and deprecated operations. Select the most dangerous
operation and exploit it directly.
```

### #38 -- OpenAPI/Swagger Discovery -> Full Attack Surface Enumeration
```
Find API documentation endpoints on the target (Swagger UI, OpenAPI spec).
Parse the specification to extract all endpoints, parameters, and auth requirements.
Identify the most vulnerable endpoints and test each one systematically.
Produce a prioritized vulnerability report from the discovered attack surface.
```

---

## CATEGORY 12 -- CORS, REDIRECTS & CLIENT-SIDE (39-41)

### #39 -- CORS Misconfiguration -> Cross-Origin Data Theft PoC
```
Analyze the target's CORS headers by sending requests with
various Origin values. Confirm that arbitrary origins are reflected
with credentials allowed. Build a proof-of-concept HTML page
that steals authenticated API data from a victim's session.
```

### #40 -- Open Redirect -> Phishing Chain -> Credential Theft
```
Find redirect endpoints on the target that accept URL parameters.
Confirm open redirect by redirecting to an external domain.
Build a phishing chain: craft a URL on the trusted target domain
that redirects to a fake login page. Explain the social engineering impact.
```

### #41 -- Log Injection -> Fake Log Entries -> Forensic Evasion
```
Find endpoints on the target where user input is written to logs.
Inject newline characters and fake log entries into the username field.
Create false entries showing successful logins from different IPs.
View the admin logs to confirm the injected entries are indistinguishable.
```

---

## CATEGORY 13 -- CVE EXPLOITATION WITH METASPLOIT (42-46)

### #42 -- CVE-2011-2523: vsftpd Backdoor -> Instant Root Shell
```
Find the FTP service on the target and identify its version.
Use Metasploit to exploit the vsftpd 2.3.4 backdoor vulnerability.
Obtain a root shell and perform post-exploitation: dump /etc/shadow,
enumerate the system, and check for network pivoting opportunities.
```

### #43 -- CVE-2017-12617: Tomcat PUT RCE -> JSP Web Shell -> Meterpreter
```
Find the Tomcat service on the target and confirm the version.
Exploit CVE-2017-12617 by uploading a JSP shell via HTTP PUT method.
Escalate from web shell to a full Meterpreter session using Metasploit.
Run post-exploitation modules: sysinfo, hashdump, network enumeration.
```

### #44 -- CVE-2021-44228: Log4Shell -> JNDI RCE -> Reverse Shell
```
Find Java web applications on the target and test for Log4Shell.
Inject JNDI lookup payloads via HTTP headers (User-Agent, X-Api-Version).
Set up the Metasploit Log4Shell module to deliver a reverse shell payload.
Transition to post-exploitation after session is established.
```

### #45 -- Nuclei CVE Scan -> Auto-Select -> Metasploit Exploitation
```
Run a full Nuclei CVE scan against all ports on the target.
Identify the highest-severity CVE found and search for a matching
Metasploit module. Configure and exploit it to gain a shell.
If no module exists, write a custom exploit using execute_code.
```

### #46 -- CVE Chain: Scan All Services -> Exploit Three CVEs -> Pivot
```
Scan all ports on the target for version-specific CVEs.
Exploit three different CVEs across three different services
to establish three independent shells on the target.
Demonstrate lateral movement between the compromised containers.
```

---

## CATEGORY 14 -- FULL ATTACK CHAINS (47-49)

### #47 -- Info Disclosure -> JWT Forge -> SQLi -> Command Injection -> Root
```
Chain vulnerabilities on the target for maximum impact:
1. Extract the JWT secret from the info disclosure endpoint
2. Forge an admin token
3. Exploit SQL injection to read server files
4. Use command injection to establish a reverse shell
5. Perform post-exploitation and persist access
Document the complete kill chain with evidence at each step.
```

### #48 -- Multi-Protocol Attack: REST + GraphQL + SOAP + XML-RPC + FTP
```
Attack all protocols on the target in a single session:
1. REST: SQL injection and command injection
2. GraphQL: IDOR and arbitrary file write
3. SOAP: XXE and file exfiltration
4. XML-RPC: SSRF to cloud metadata
5. FTP: vsftpd backdoor to root shell
Demonstrate that every protocol on the target is exploitable.
Generate a comparative vulnerability report across all protocols.
```

### #49 -- XXE -> SSRF -> Cloud Metadata + CVE RCE -> Full Compromise
```
Chain server-side vulnerabilities and CVEs on the target:
1. Exploit XXE in the SOAP service to confirm file read
2. Use XXE to reach AWS metadata via SSRF
3. Exploit Log4Shell on port 8888 for a second entry point
4. Use Tomcat PUT RCE on port 8080 for a third entry point
5. Cross-reference access across all three compromised services
Document the full multi-vector kill chain.
```

---

## CATEGORY 15 -- FULL AUTONOMOUS KILL CHAIN (50)

### #50 -- Strategic Planning: Agent Self-Designs the Full Attack
> Enable Deep Think before running this prompt
```
Analyze the complete recon dataset on the target: all ports, services,
technologies, CVEs, endpoints, parameters, and OSINT findings.
The target has both application-level vulnerabilities (DVWS-Node on ports
80/4000/9090) and CVE-vulnerable services (Tomcat 8080, Log4Shell 8888,
vsftpd 21, exposed MongoDB 27017 and MySQL 3306).
Before executing any tool, design the optimal full attack strategy --
choose attack vectors, order of operations, fallback paths, and post-exploitation goals.
Present the plan, then execute it and report any deviations.
```

---

## Quick Reference

| Category | Prompts | Key Tools |
|----------|---------|-----------|
| SQL Injection | #1-5 | `kali_shell` (sqlmap), `execute_curl` |
| NoSQL Injection | #6-8 | `execute_curl`, `execute_code` |
| Command Injection & RCE | #9-12 | `execute_curl`, `metasploit_console` |
| XXE Injection | #13-16 | `execute_curl`, `kali_shell` |
| SSRF | #17-19 | `execute_curl`, XML-RPC |
| JWT & Auth | #20-23 | `execute_curl`, `execute_code`, `execute_hydra` |
| IDOR & Access Control | #24-27 | `execute_curl`, GraphQL |
| XPath & LDAP | #28-30 | `execute_curl` |
| File Ops & Path Traversal | #31-33 | `execute_curl`, GraphQL mutations |
| Prototype Pollution | #34-35 | `execute_curl`, `execute_code` |
| Info Disclosure & Recon | #36-38 | `execute_curl`, `execute_nuclei` |
| CORS & Client-Side | #39-41 | `execute_curl`, `execute_code` |
| **CVE Exploitation** | **#42-46** | **`metasploit_console`, `execute_nuclei`** |
| Full Attack Chains | #47-49 | ALL |
| Autonomous Kill Chain | #50 | ALL |

> Enable Deep Think in agent settings before running #50
