# RedAmon HackLab
### Agentic Attack Prompts -- Powered by RedAmon AI Agent
### Target: DVWS-Node + CVE Lab on EC2

> **How it works:**
> Each prompt points the agent at a specific service and port, then lets it
> autonomously discover endpoints, select tools, and chain the full attack.
>
> **Prerequisites:**
> - DVWS-Node + CVE Lab deployed on your EC2 instance
> - Full recon pipeline executed and stored in the graph database
> - RedAmon agent configured with the target project
>
> **Service Map:**
> | Port | Service | Attack Surface |
> |------|---------|---------------|
> | **80** | **Express/Node.js (DVWS-Node)** | REST API, SOAP, Swagger -- all app-level vulns |
> | **4000** | **Apollo GraphQL** | Introspection, IDOR, SQLi, file write |
> | **3306** | **MySQL 8.4.8** | Direct DB access (exposed, no firewall) |
> | **21** | **vsftpd 2.3.4** | CVE-2011-2523 backdoor |
> | **8080** | **Tomcat 8.5.19** | CVE-2017-12617 PUT RCE, Ghostcat |
> | **8888** | **Spring Boot (Log4j)** | Log4Shell (CVE-2021-44228) |
> | **9090** | **XML-RPC** | SSRF via method calls |

---

## Target Overview (from Recon Pipeline)

### Infrastructure

| Asset | Value |
|-------|-------|
| Domain | devergolabs.com |
| Subdomain | gpigs.devergolabs.com |
| IP | 15.160.68.117 (AWS eu-south-1, ASN AS16509) |

### Open Ports & Services (Nmap + HTTP Probe)

| Port | Protocol | Service | Product/Version | Notes |
|------|----------|---------|-----------------|-------|
| 21 | tcp | ftp | vsftpd 2.3.4 | Known backdoor CVE-2011-2523 |
| 22 | tcp | ssh | OpenSSH 9.6p1 | Ubuntu, multiple CVEs in graph |
| 80 | tcp | http | Node.js Express | DVWS-Node main app (REST + SOAP + Swagger) |
| 3306 | tcp | mysql | MySQL 8.4.8 | Exposed to internet |
| 4000 | tcp | http | Apollo Server | GraphQL Playground (CORS: *) |
| 8080 | tcp | http-proxy | Apache Tomcat 8.5.19 | CVE Lab -- manager panel exposed |
| 8888 | tcp | http-alt | -- | CVE Lab -- Spring Boot / Log4j target |
| 9090 | tcp | http | -- | CVE Lab -- XML-RPC service |

### Technologies Detected (11)

AngularJS, Bootstrap, jQuery, Node.js, Express, MySQL 8.4.8, Apache Tomcat 8.5.19, vsftpd 2.3.4, OpenSSH 9.6p1, Nagios NSCA

### Web Entry Points (BaseURLs)

| URL | Status | Stack |
|-----|--------|-------|
| http://gpigs.devergolabs.com | 200 | Express (AngularJS/Bootstrap/jQuery) |
| http://gpigs.devergolabs.com:4000 | 200 | Apollo Server (GraphQL) |
| http://gpigs.devergolabs.com:8080 | 200 | Apache Tomcat 8.5.19 |
| http://gpigs.devergolabs.com:8888 | 400 | Spring Boot (Log4j) |
| http://gpigs.devergolabs.com:9090 | 404 | XML-RPC |

### Key Endpoints Discovered by Recon

**Express App (:80):** `/api/v2/login`, `/api/v2/users`, `/api/v2/notes`, `/api/v2/info`, `/api/upload`, `/index.html`
**GraphQL (:4000):** `/` (playground)
**Tomcat (:8080):** `/manager/html`, `/manager/status`, `/examples/`, `/docs/`, 130+ doc/example pages

### Parameters Found

| Endpoint | Parameter | Type |
|----------|-----------|------|
| /api/v2/login | username | body (string) |
| /api/v2/users | id, username, password, admin | body |

### CVEs in Graph (31 total)

**Critical:**
- CVE-2011-2523 (9.8) -- vsftpd 2.3.4 backdoor
- CVE-2020-1938 (9.8) -- Apache Tomcat AJP Ghostcat

**High:**
- CVE-2017-12617 (8.1) -- Tomcat PUT method RCE
- CVE-2024-6387 (8.1) -- OpenSSH regreSSHion
- CVE-2019-0232 (9.3) -- Tomcat CGI RCE
- CVE-2020-9484 (7.0) -- Tomcat deserialization
- CVE-2020-11996 (7.5) -- Tomcat HTTP/2 DoS
- Plus 20+ medium-severity Tomcat and SSH CVEs

### Vulnerabilities Flagged by Scanners

| Finding | Severity | Service | Notes |
|---------|----------|---------|-------|
| http-vuln-cve2011-3192 | HIGH | :80 | Apache byterange DoS -- CONFIRMED |
| http-slowloris-check | HIGH | :8080 | Slowloris DoS -- LIKELY VULNERABLE |
| DMARC Record Missing | MEDIUM | DNS | Email spoofing risk |
| SPF Record Missing | MEDIUM | DNS | Email spoofing risk |
| Direct IP HTTP Access | MEDIUM | :80 | Host header not validated |

**Default credentials:** `admin` / `letmein` (admin), `test` / `test` (regular), `root` / `mysecretpassword` (MySQL)

---

## Vulnerability Map (DVWS-Node on :80)

> Known vulnerabilities in the DVWS-Node codebase on port 80.
> Most endpoints were NOT discovered by automated recon -- the agent must explore.

| Category | Port(s) | Recon Found? |
|----------|---------|--------------|
| SQL Injection | :80, :4000 | No |
| NoSQL Injection | :80 | No |
| OS Command Injection | :80 | No |
| XXE Injection | :80 (SOAP + XML import) | No |
| SSRF | :80, :9090 | No |
| JWT/Auth Bypass | :80 | Partial -- login found |
| IDOR | :80, :4000 | Partial -- notes found |
| Insecure Deserialization | :80 | No |
| XPath Injection | :80 | No |
| Prototype Pollution | :80 | Yes -- upload found |
| Path Traversal | :80, :4000 | No |
| Open Redirect | :80 | No |
| CORS Misconfiguration | :4000 | Yes -- CORS * |
| Info Disclosure | :80, :4000 | Partial |
| Unrestricted File Upload | :80 | Yes -- upload found |

---

## MISLEADING INTEL (MSL)

> These prompts intentionally give the agent wrong or incomplete assumptions.
> The goal is to demonstrate the agent's ability to recognize when something
> doesn't match reality, pivot its strategy, and find the real attack surface.

### --------------DONE #MSL-XAJI0 -- Wrong Database Assumption
```
Target the Express REST API on port 80. Discover endpoints that accept
user input for database lookups. Test for SQL injection using UNION-based
techniques and dump the MySQL database including all credentials.
```

### #MSL-Y6DPB -- Wrong Port for the Vulnerability
```
Target Apache Tomcat on port 8080. Find REST API endpoints that accept
user input. Test for command injection, SQL injection, and authentication
bypass on the Tomcat application. Dump all user credentials.
```

### #MSL-HSAHX -- Wrong Protocol Assumption
```
Target port 9090. The service is running a REST API with JSON endpoints.
Authenticate and explore for IDOR vulnerabilities. Enumerate all users
and extract their private data.
```

### #MSL-THV3A -- Wrong Technology Stack
```
Target the web application on port 80. The backend uses PostgreSQL
and Django. Find the admin panel and exploit SQL injection in the
search functionality. Extract all user records from the database.
```

---

## SQL INJECTION (SQL)

### #SQL-3ZMF8 -- SQL Injection via POST Parameters
```
Target the Express REST API on port 80. Authenticate with default credentials.
Not all endpoints use the same database -- explore beyond authentication
to find endpoints backed by MySQL. Detect and exploit SQL injection,
enumerate the MySQL schema, and dump all tables.
```

### #SQL-MDD4V -- GraphQL SQL Injection
```
Target the GraphQL service on port 4000. Enumerate the schema via introspection.
Identify queries that accept string parameters and test for SQL injection.
Exploit any confirmed injection and dump the database.
```

### #SQL-30T9N -- Blind SQL Injection with Time-Based Extraction
```
Target the Express REST API on port 80. The application uses both MongoDB
and MySQL for different features. Find the MySQL-backed endpoints
and confirm blind SQL injection using time-based payloads (SLEEP).
Extract the MySQL version, database names, and user credentials.
Compare extraction speed between time-based and UNION-based techniques.
```

---

## NoSQL INJECTION (NQL)

### #NQL-T3W5U -- NoSQL Injection via MongoDB Search Endpoints
```
Target the Express REST API on port 80. The application uses MongoDB
internally for some features. Authenticate and explore the API for
search or note-related endpoints. Test for NoSQL injection using
$where clauses and operator injection ($gt, $ne, $regex).
Extract all stored documents including other users' private data.
```

### #NQL-ZBIKC -- NoSQL Operator Injection for Authentication Bypass
```
Target the Express REST API on port 80. Find endpoints that query MongoDB.
Test for operator injection in JSON body parameters to bypass filters
or extract data without valid credentials.
```

---

## OS COMMAND INJECTION & RCE (RCE)

### #RCE-IDKWN -- Command Injection Discovery and Reverse Shell
```
Target the Express REST API on port 80. Explore for endpoints that
interact with the operating system. Test for command injection using
shell metacharacters (;, |, &&). Establish a reverse shell and enumerate
the container: users, network, processes, environment variables.
```

### #RCE-NHJ7X -- Insecure Deserialization (node-serialize) RCE
```
Target the Express REST API on port 80. Authenticate and explore for
endpoints that accept serialized or encoded data. The target runs Node.js --
test for node-serialize deserialization and achieve remote code execution.
```

### #RCE-VG0FN -- Command Injection to Credential Harvesting
```
Target the Express REST API on port 80. Exploit command injection to read
environment variables, config files, and database connection strings.
Use harvested credentials to connect directly to MySQL on port 3306
and dump all data.
```

### #RCE-9XUY4 -- Chained RCE: JWT Bypass then Command Injection then Persistence
```
Target the Express REST API on port 80. Bypass authentication using
JWT algorithm confusion. Use the forged admin token to reach
command injection endpoints. Establish persistence via a crontab reverse shell.
```

---

## XXE INJECTION (XXE)

### --------------DONE #XXE-1IBLJ -- XXE via XML Import for File Exfiltration
```
Target port 80. Discover SOAP/WSDL endpoints on the Express application.
Craft an XXE payload in the SOAP XML envelope to read /etc/passwd.
Escalate to exfiltrate application source code and environment files.
```

### #XXE-O6QJI -- Blind XXE with Out-of-Band Data Exfiltration
```
Target the XML processing endpoints on port 80 (SOAP and XML import).
Find XXE-vulnerable endpoints where entity content is not reflected
in the response. Use parameter entities to exfiltrate file contents
via HTTP callbacks. Extract database credentials and JWT secrets.
```

### #XXE-UJV6O -- XML Bomb (Billion Laughs) Denial of Service
```
Target the XML processing endpoints on port 80 (SOAP and XML import).
Craft a Billion Laughs entity expansion payload and send it.
Monitor server response time and verify service degradation.
```

---

## SSRF (SRF)

### #SRF-H9SDB -- SSRF via Download Endpoint and XML-RPC
```
Target port 80 and port 9090. Find endpoints on port 80 that fetch URLs
server-side. On port 9090, explore the XML-RPC service for methods
that accept URL arguments. Test for SSRF with internal URLs and
the AWS metadata endpoint. Map the internal network topology.
```

### #SRF-DW2PC -- SSRF with file:// Protocol for Local File Read
```
Target the SSRF-capable endpoints on port 80 and the XML-RPC service
on port 9090. Test with file:// protocol to read local files from the server.
Chain with path traversal to read application source code and secrets.
```

---

## JWT & AUTHENTICATION ATTACKS (JWT)

### #JWT-N9T84 -- JWT Algorithm None Attack for Admin Access
```
Target the Express REST API on port 80. Authenticate as a regular user,
capture the JWT token, and analyze its structure.
Test for algorithm confusion (alg:none), forge an admin token,
and access all admin-only endpoints.
```

### #JWT-AZYTJ -- JWT Secret Extraction and Token Forgery
```
Target the Express REST API on port 80. Find information disclosure
endpoints that leak environment variables or server internals.
Extract the JWT signing secret and forge valid tokens for every known user.
Demonstrate full impersonation of admin and regular users.
```

### #JWT-XEPQ8 -- Brute Force Login with Rate Limit Bypass
```
Target the login endpoint on port 80. Analyze rate limiting behavior.
Bypass the rate limit using X-Forwarded-For header rotation.
Brute force credentials with common wordlists.
Document all valid credential pairs discovered.
```

### #JWT-5JSG6 -- Session Analysis: Token Reuse and Expiration Bypass
```
Target the Express REST API on port 80. Analyze the JWT implementation
for security weaknesses: expired token acceptance, post-logout validity,
cross-session reuse. Document every session management flaw found.
```

---

## IDOR & BROKEN ACCESS CONTROL (IDR)

### #IDR-5KXVF -- IDOR on Notes API to Read All Users' Data
```
Target the Express REST API on port 80. Authenticate and find resource
endpoints with numeric IDs. Enumerate IDs to access other users' data.
Test read, modify, and delete operations on other users' resources.
```

### #IDR-1T2TA -- GraphQL IDOR for User Enumeration and Password Hash Extraction
```
Target the GraphQL service on port 4000. Run introspection to discover
all queries. Use ID-based queries to enumerate all users.
Extract usernames, admin status, and password hashes.
Attempt offline cracking of any exposed hashes.
```

### #IDR-LA753 -- Privilege Escalation via Mass Assignment
```
Target the Express REST API on port 80. Find user creation or profile
update endpoints. Test for mass assignment by injecting extra fields
(admin, role) into requests. Escalate a regular user to admin
and verify access to admin-only endpoints.
```

### #IDR-LC58D -- Forced Browsing and Hidden Endpoint Discovery
```
Target the Express REST API on port 80. Find API documentation or
specification files. Attempt unauthenticated access to admin endpoints.
Discover hidden or undocumented endpoints and test each with different
authorization levels.
```

---

## XPath INJECTION (XPT)

### #XPT-RC11E -- XPath Injection for Configuration Data Extraction
```
Target the Express REST API on port 80. Find endpoints that query
XML data (release info, configuration lookups).
Test for XPath injection and extract all data from the underlying
XML configuration including secrets and internal paths.
```

---

## FILE OPERATIONS & PATH TRAVERSAL (FIL)

### #FIL-RTJ5P -- Unrestricted File Upload to Web Shell
```
Target the Express REST API on port 80. Find file upload endpoints
and test restrictions: content-type checks, extension filtering, size limits.
Upload a web shell or reverse shell bypassing any checks.
Trigger the uploaded file to confirm code execution.
```

### #FIL-HT0HL -- Path Traversal for Application Source Code Theft
```
Target the Express REST API on port 80. Find file download or file serving
endpoints. Test for path traversal using ../ sequences to escape directories.
Download application source code, config files, and environment files.
Extract hardcoded secrets, database credentials, and JWT keys.
```

### #FIL-9XPSE -- GraphQL Arbitrary File Write to RCE
```
Target the GraphQL service on port 4000. Run introspection to find
mutations that write files to the server. Exploit path traversal
in file path parameters to write outside the uploads directory.
Overwrite a server-side file with malicious code to achieve RCE.
```

---

## PROTOTYPE POLLUTION (PPL)

### #PPL-IMVIH -- Prototype Pollution via File Upload Metadata
```
Target the Express REST API on port 80. Find the file upload endpoint
and test for prototype pollution by injecting __proto__ properties
in the upload metadata. Verify pollution propagation and demonstrate
how it chains to authentication bypass.
```

### #PPL-CWI64 -- Prototype Pollution to Denial of Service and Auth Bypass
```
Target the Express REST API on port 80. Exploit prototype pollution
to inject properties that break application logic. Pollute properties
used in authorization checks to escalate privileges.
Demonstrate both DoS and privilege escalation.
```

---

## INFORMATION DISCLOSURE & RECON (INF)

### #INF-CIYHE -- Environment Variable Leak to JWT Secret to Token Forgery
```
Target the Express REST API on port 80. Explore for endpoints that
expose server internals or environment variables. Extract database
credentials and the JWT secret. Use the secret to forge admin tokens
and access all protected endpoints. Use DB credentials to connect
directly to MySQL on port 3306.
```

### #INF-7UR23 -- GraphQL Introspection for Full API Mapping
```
Target the GraphQL service on port 4000. Run full introspection to
enumerate all queries, mutations, types, and fields. Map the complete
API surface. Select the most dangerous operation and exploit it.
```

### #INF-GDPPQ -- OpenAPI/Swagger Discovery and Attack Surface Mapping
```
Target the Express REST API on port 80. Find API documentation or
specification files. Parse the spec to extract all endpoints, parameters,
and auth requirements. Identify the most vulnerable endpoints and test
each systematically. Produce a prioritized vulnerability report.
```

---

## CORS, REDIRECTS & CLIENT-SIDE (CLS)

### #CLS-0Y9DO -- CORS Misconfiguration Analysis
```
Target all web services: port 80 (Express), port 4000 (GraphQL),
port 8080 (Tomcat). Send requests with various Origin headers.
Confirm if arbitrary origins are reflected with credentials allowed.
Build a proof-of-concept showing cross-origin data theft.
```

### #CLS-M5IGQ -- Open Redirect to Phishing Chain
```
Target the Express REST API on port 80. Explore for redirect endpoints
(logout, callback, return URL parameters). Confirm open redirect
by redirecting to an external domain. Explain the phishing attack chain.
```

### #CLS-PKI7P -- Log Injection for Forensic Evasion
```
Target the Express REST API on port 80. Find endpoints where user input
is written to server logs. Inject newline characters and fake log entries.
Verify the injected entries appear in admin logs and are indistinguishable
from real entries.
```

---

## CVE EXPLOITATION (CVE)

### #CVE-5TB94 -- CVE-2011-2523: vsftpd 2.3.4 Backdoor to Root Shell
```
Target the FTP service on port 21 (vsftpd 2.3.4).
The recon graph shows CVE-2011-2523 (CRITICAL 9.8).
Exploit the backdoor vulnerability to obtain a root shell.
Perform post-exploitation:
dump /etc/shadow, enumerate the system, check for pivoting opportunities.
```

### #CVE-874FR -- CVE-2017-12617: Tomcat PUT RCE to JSP Web Shell
```
Target Apache Tomcat 8.5.19 on port 8080.
The recon graph shows CVE-2017-12617 (HIGH 8.1).
Exploit the PUT method bypass to upload a JSP shell.
Escalate to a full remote session and run post-exploitation.
```

### #CVE-HOCN9 -- CVE-2020-1938: Tomcat Ghostcat AJP File Read
```
Target Apache Tomcat 8.5.19 on port 8080.
The recon graph shows CVE-2020-1938 (CRITICAL 9.8) -- Ghostcat.
Test if AJP is exposed or reachable from the application network.
Attempt to read protected web application files through the AJP connector.
```

### #CVE-J2QP8 -- CVE Scan then Exploitation
```
Run a vulnerability scan against all open ports: 21 (vsftpd), 80 (Express),
8080 (Tomcat), 8888 (Spring Boot). Cross-reference with the 31 CVEs
in the recon graph. Identify the highest-severity exploitable CVE
and exploit it to gain a shell.
```

---

## BROWSER-BASED ATTACKS (BRW)

> These prompts require the Playwright headless browser tool (`execute_playwright`).
> The agent uses a real Chromium browser to render JavaScript, interact with forms,
> read DOM content, and test client-side vulnerabilities that curl cannot reach.

### #BRW-V8NML -- Stored XSS via Notes to Session Hijacking
```
Target the Express web application on port 80. Use Playwright to log in
as a regular user and create notes containing XSS payloads. Then log in
as a different user and navigate to shared or public notes. Use Playwright
to verify if the stored payload executes in the victim's browser context.
Extract cookies, localStorage, and session tokens from the rendered page.
Demonstrate the full stored XSS to session hijacking chain.
```

### #BRW-PJRL6 -- Authenticated Multi-Step Exploitation via Browser
```
Target the Express web application on port 80. Use Playwright to perform
the full attack through the browser like a real user: log in via the
login form, navigate the dashboard, discover hidden features by reading
the rendered HTML and JavaScript, find file upload or import pages,
and exploit them. The agent must NOT use curl or direct API calls --
everything goes through the browser. Report what the browser-only
attack surface looks like compared to API-only testing.
```

### #BRW-Y9AZK -- JavaScript Source Analysis for Hidden Endpoints and Secrets
```
Target the Express web application on port 80. Use Playwright to render
the application and extract all JavaScript files, inline scripts, and
dynamically loaded modules. Parse the JS source for hardcoded API keys,
tokens, hidden API endpoints, debug flags, and commented-out features.
Use any discovered hidden endpoints or credentials to escalate access.
```

---

## FULL ATTACK CHAINS (CHN)

### #CHN-9UZFK -- Info Disclosure to JWT Forge to SQLi to Command Injection
```
Chain vulnerabilities on the Express app (port 80) for maximum impact:
find info disclosure to extract the JWT secret, forge an admin token,
exploit SQL injection to dump the database, then use command injection
to establish a reverse shell. Document the complete kill chain.
```

### #CHN-8UT0C -- Multi-Protocol Attack: REST + GraphQL + SOAP
```
Attack all application protocols in a single session:
REST API on port 80, GraphQL on port 4000, and SOAP on port 80.
Find and exploit at least one vulnerability per protocol.
Generate a comparative vulnerability report across all three.
```

### #CHN-VS4F8 -- Application Vulns + CVE Exploitation Combined
```
Chain application-level and CVE-based attacks across multiple ports:
exploit an app vuln on port 80 to extract credentials,
exploit CVE-2011-2523 on port 21 for a root shell,
exploit CVE-2017-12617 on port 8080 for a second shell.
Cross-reference access across all compromised services.
```

### #CHN-CGVYI -- Exposed MySQL: Direct Database Exploitation
```
Target MySQL 8.4.8 exposed on port 3306. Attempt to connect directly
using default or discovered credentials. Enumerate all databases,
tables, and users. Test for FILE and SUPER privileges.
Attempt to read and write files on the server via SQL.
```

---

## FULL AUTONOMOUS KILL CHAIN (AUT)

### #AUT-E6IVW -- Strategic Planning: Agent Self-Designs the Full Attack
> Enable Deep Think before running this prompt
```
Query the recon graph for the complete dataset on the target.

The target has 8 open ports with different services:
- Port 80: Express/Node.js (main vulnerable web app)
- Port 4000: Apollo GraphQL
- Port 3306: MySQL 8.4.8 (exposed)
- Port 21: vsftpd 2.3.4 (known backdoor CVE)
- Port 8080: Apache Tomcat 8.5.19 (multiple CVEs)
- Port 8888: Spring Boot (potential Log4Shell)
- Port 9090: XML-RPC
- Port 22: OpenSSH 9.6p1

The automated recon missed many application-level endpoints on port 80.
Design the optimal full attack strategy: prioritize by impact,
plan endpoint discovery, choose attack vectors and fallback paths.
Present the plan, then execute it end-to-end and report deviations.
```

---

## Quick Reference

| Category | Prompts | Primary Port(s) |
|----------|---------|-----------------|
| Misleading Intel | MSL-XAJI0, MSL-Y6DPB, MSL-HSAHX, MSL-THV3A | varies |
| SQL Injection | SQL-3ZMF8, SQL-MDD4V, SQL-30T9N | :80, :4000 |
| NoSQL Injection | NQL-T3W5U, NQL-ZBIKC | :80 |
| Command Injection & RCE | RCE-IDKWN, RCE-NHJ7X, RCE-VG0FN, RCE-9XUY4 | :80 |
| XXE Injection | XXE-1IBLJ, XXE-O6QJI, XXE-UJV6O | :80 |
| SSRF | SRF-H9SDB, SRF-DW2PC | :80, :9090 |
| JWT & Auth | JWT-N9T84, JWT-AZYTJ, JWT-XEPQ8, JWT-5JSG6 | :80 |
| IDOR & Access Control | IDR-5KXVF, IDR-1T2TA, IDR-LA753, IDR-LC58D | :80, :4000 |
| XPath | XPT-RC11E | :80 |
| File Ops & Path Traversal | FIL-RTJ5P, FIL-HT0HL, FIL-9XPSE | :80, :4000 |
| Prototype Pollution | PPL-IMVIH, PPL-CWI64 | :80 |
| Info Disclosure & Recon | INF-CIYHE, INF-7UR23, INF-GDPPQ | :80, :4000 |
| CORS & Client-Side | CLS-0Y9DO, CLS-M5IGQ, CLS-PKI7P | :80, :4000, :8080 |
| Browser-Based (Playwright) | BRW-V8NML, BRW-PJRL6, BRW-Y9AZK | :80 |
| CVE Exploitation | CVE-5TB94, CVE-874FR, CVE-HOCN9, CVE-J2QP8 | :21, :8080, :8888 |
| Full Attack Chains | CHN-9UZFK, CHN-8UT0C, CHN-VS4F8, CHN-CGVYI | ALL |
| Autonomous Kill Chain | AUT-E6IVW | ALL |

> Enable Deep Think in agent settings before running AUT-E6IVW
