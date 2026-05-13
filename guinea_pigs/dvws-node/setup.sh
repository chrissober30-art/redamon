#!/bin/bash
# Install Docker and deploy RedAmon HackLab target environment
set -e

echo "=== Installing Docker ==="

# Detect OS and install Docker
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose git
elif [ "$OS" = "amzn" ] || [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ]; then
    sudo dnf install -y docker git
    sudo curl -sL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

sudo systemctl start docker
sudo systemctl enable docker

echo "=== Cleaning up Docker space ==="
cd ~
if [ -d dvws-node ]; then
    cd dvws-node
    sudo docker-compose down --volumes --remove-orphans 2>/dev/null || true
    cd ~
fi
# Stop and remove any other running containers (previous guinea pigs, etc.)
sudo docker stop $(sudo docker ps -aq) 2>/dev/null || true
sudo docker system prune -a -f --volumes

echo "=== Cloning DVWS-Node ==="
rm -rf ~/dvws-node
git clone https://github.com/snoopysecurity/dvws-node.git ~/dvws-node
cd ~/dvws-node

# If the operator scp'd the xss-lab directory alongside setup.sh, move it in.
if [ -d ~/xss-lab ]; then
    echo "=== Importing Argentum site (xss-lab) ==="
    rm -rf ~/dvws-node/xss-lab
    mv ~/xss-lab ~/dvws-node/xss-lab
fi

echo "=== Creating additional containers ==="

# Tomcat container
mkdir -p ~/dvws-node/tomcat-rce
cat > ~/dvws-node/tomcat-rce/Dockerfile << 'DOCKERFILE'
FROM vulhub/tomcat:8.5.19
RUN cd /usr/local/tomcat/conf \
    && LINE=$(nl -ba web.xml | grep '<load-on-startup>1' | awk '{print $1}') \
    && ADDON="<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>" \
    && sed -i "$LINE i $ADDON" web.xml
EXPOSE 8080
DOCKERFILE

# vsftpd container
mkdir -p ~/dvws-node/vsftpd-backdoor
cat > ~/dvws-node/vsftpd-backdoor/Dockerfile << 'DOCKERFILE'
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y build-essential wget libcap-dev \
    && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/nikdubois/vsftpd-2.3.4-infected/archive/refs/heads/vsftpd_original.tar.gz -O /tmp/vsftpd.tar.gz \
    && tar xzf /tmp/vsftpd.tar.gz -C /tmp \
    && cd /tmp/vsftpd-2.3.4-infected-vsftpd_original \
    && chmod +x vsf_findlibs.sh \
    && sed -i 's|`./vsf_findlibs.sh`|-lcrypt -lcap|' Makefile \
    && make \
    && cp vsftpd /usr/local/sbin/vsftpd \
    && chmod 755 /usr/local/sbin/vsftpd \
    && rm -rf /tmp/vsftpd*
RUN mkdir -p /var/ftp /etc/vsftpd /var/run/vsftpd/empty \
    && useradd -r -d /var/ftp -s /usr/sbin/nologin ftp 2>/dev/null; true
RUN printf "listen=YES\nanonymous_enable=YES\nlocal_enable=YES\nwrite_enable=YES\nsecure_chroot_dir=/var/run/vsftpd/empty\n" > /etc/vsftpd.conf
EXPOSE 21 6200
CMD ["/usr/local/sbin/vsftpd", "/etc/vsftpd.conf"]
DOCKERFILE

# --- Self-signed TLS cert with multi-SAN for the VHost & SNI hidden vhost demo ---
# The cert SANs include 7 hidden vhost hostnames so RedAmon's httpx scrapes them
# from the certificate during the HTTP probe phase, seeding them as candidates
# for the VHost & SNI module's L7 + L4 probes.
echo "=== Generating self-signed TLS cert with multi-SAN for hidden vhost demo ==="
mkdir -p ~/dvws-node/landing/certs
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ~/dvws-node/landing/certs/privkey.pem \
    -out ~/dvws-node/landing/certs/fullchain.pem \
    -days 365 \
    -subj "/CN=gpigs.devergolabs.com" \
    -addext "subjectAltName=DNS:gpigs.devergolabs.com,DNS:admin.gpigs.devergolabs.com,DNS:internal.gpigs.devergolabs.com,DNS:k8s.gpigs.devergolabs.com,DNS:staging.gpigs.devergolabs.com,DNS:jenkins.gpigs.devergolabs.com,DNS:marketing.gpigs.devergolabs.com,DNS:news.gpigs.devergolabs.com" \
    2>/dev/null
chmod 644 ~/dvws-node/landing/certs/*.pem

# Landing page with legal terms (served by nginx at / and /legal)
echo "=== Creating legal landing page ==="
mkdir -p ~/dvws-node/landing
cat > ~/dvws-node/landing/index.html << 'LANDING_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedAmon HackLab -- Research Target</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
  .container { max-width: 860px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { color: #ff4444; font-size: 1.8rem; margin-bottom: 0.3rem; }
  .subtitle { color: #888; font-size: 1rem; margin-bottom: 2rem; }
  .warning-box { background: #1a0000; border: 1px solid #ff4444; border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 2rem; }
  .warning-box strong { color: #ff6666; }
  h2 { color: #ff6666; font-size: 1.2rem; margin: 1.8rem 0 0.8rem; border-bottom: 1px solid #222; padding-bottom: 0.4rem; }
  .info-box { background: #111; border: 1px solid #222; border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; font-size: 0.95rem; }
  ol { padding-left: 1.5rem; }
  ol li { margin-bottom: 0.6rem; }
  ol li strong { color: #ffaaaa; }
  .consequences { background: #1a0000; border-left: 3px solid #ff4444; padding: 0.8rem 1rem; margin: 1.2rem 0; font-size: 0.9rem; }
  .footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #222; color: #555; font-size: 0.8rem; text-align: center; }
  a { color: #ff8888; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; background: #2a0000; border: 1px solid #ff4444; color: #ff6666; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 0.4rem; }
</style>
</head>
<body>
<div class="container">

<h1>RedAmon HackLab</h1>
<p class="subtitle">Research Target Server -- gpigs.devergolabs.com</p>

<div class="warning-box">
  <strong>WARNING:</strong> This server is a dedicated research target for authorized security testing with <a href="https://github.com/samugit83/redamon">RedAmon</a> only. All traffic is logged and monitored. By accessing any service on this server, you accept the Rules of Engagement below.
</div>

<div class="info-box">
  This server hosts multiple services as part of the <a href="https://github.com/samugit83/redamon">RedAmon</a> HackLab research environment. The RedAmon AI agent is designed to autonomously discover and map the attack surface. No additional information about the target is provided here intentionally -- the agent must perform its own reconnaissance.
</div>

<h2>Rules of Engagement</h2>
<ol>
  <li><strong>RedAmon-only testing.</strong> This server is provided exclusively for testing with the <a href="https://github.com/samugit83/redamon">RedAmon</a> framework. Manual exploitation, third-party scanners, and automated tools other than RedAmon are not authorized.</li>
  <li><strong>Scope.</strong> Only interact with services hosted on this server. All other IPs and infrastructure behind this server are out of scope.</li>
  <li><strong>No lateral movement.</strong> Do not attempt to pivot from this server to other systems, networks, or cloud infrastructure.</li>
  <li><strong>No denial of service.</strong> Do not perform load testing, resource exhaustion, or any action intended to degrade availability.</li>
  <li><strong>No data exfiltration beyond the server.</strong> Do not exfiltrate data to external servers, set up reverse shells to your own infrastructure, or establish persistent backdoors.</li>
  <li><strong>No modification of the environment.</strong> Do not delete databases, drop tables, modify other users' data, or alter running services in ways that affect other testers.</li>
  <li><strong>Responsible disclosure.</strong> If you discover a vulnerability in RedAmon itself (not in the target), report it via <a href="https://github.com/samugit83/redamon/issues">GitHub Issues</a>.</li>
  <li><strong>Legal compliance.</strong> You are solely responsible for ensuring your testing complies with all applicable laws in your jurisdiction. Unauthorized access to computer systems is illegal in most countries.</li>
  <li><strong>No warranty / liability.</strong> This server is provided "as is" for educational and research purposes. Devergolabs assumes no liability for any damages arising from your use. Access may be revoked at any time without notice.</li>
  <li><strong>Logging and monitoring.</strong> All traffic to this server is logged. IP addresses and request data are recorded for security monitoring and abuse prevention.</li>
</ol>

<div class="consequences">
  <strong>Violations</strong> will result in immediate IP ban and may be reported to the relevant ISP or law enforcement authority.
</div>

<h2>Get Started</h2>
<p style="margin-top:0.5rem;">
  <span class="badge">1</span> Install <a href="https://github.com/samugit83/redamon">RedAmon</a> &nbsp;
  <span class="badge">2</span> Create a project targeting this server &nbsp;
  <span class="badge">3</span> Run the recon pipeline &nbsp;
  <span class="badge">4</span> Let the AI agent attack &nbsp;
  <span class="badge">5</span> Record and <a href="https://github.com/samugit83/redamon/wiki/RedAmon-HackLab#community-sessions">submit your session</a>
</p>

<div class="footer">
  <a href="https://github.com/samugit83/redamon">RedAmon</a> &middot;
  <a href="https://github.com/samugit83/redamon/wiki/RedAmon-HackLab">HackLab Wiki</a> &middot;
  <a href="https://devergolabs.com">Devergolabs</a>
  <br/>Last updated: 2026-04-04
</div>

</div>
</body>
</html>
LANDING_HTML

# Nginx config -- serves landing page at / and /legal, proxies API traffic to dvws-node
# Plus VHost & SNI hidden virtual host demo (5 vhosts on port 80, 3 SNI-routed on port 443)
cat > ~/dvws-node/landing/nginx.conf << 'NGINX_CONF'
# ===========================================================================
# Default server (port 80) -- landing page + dvws-node proxy + Argentum
# This is the BASELINE response when RedAmon's VHost & SNI module probes the
# bare IP with no Host override. The full landing HTML is served (~5KB).
# ===========================================================================
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 16M;

    # Landing page with legal terms
    location = / {
        root /usr/share/nginx/html;
        try_files /index.html =404;
    }
    location = /legal {
        root /usr/share/nginx/html;
        try_files /index.html =404;
    }

    # Argentum Digital site (Node.js sidecar on port 3001)
    location /argentum/ {
        proxy_pass http://argentum:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
    }

    # Proxy everything else to DVWS-Node
    location / {
        proxy_pass http://web:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

# ===========================================================================
# Hidden VHost #1: admin.gpigs.devergolabs.com (port 80 / L7)
# Internal-keyword "admin" -> RedAmon flags as MEDIUM severity
# ===========================================================================
server {
    listen 80;
    server_name admin.gpigs.devergolabs.com;
    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><title>Admin Console - INTERNAL</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:2rem;max-width:760px;margin:0 auto}h1{color:#ff4444}h2{color:#ffaa44;font-size:1rem;margin-top:1.5rem}.warn{background:#1a0000;border:1px solid #ff4444;padding:1rem;margin:1rem 0}.dim{color:#666;font-size:.85rem}</style></head>
<body><h1>Internal Admin Console</h1>
<div class="warn"><strong>RESTRICTED:</strong> This system is for authorized personnel only. All actions are logged and audited.</div>
<h2>Active Sessions</h2><pre>uid=1001 (alice@corp)   192.168.4.21   active 14m
uid=1002 (bob@corp)     192.168.4.43   idle   2h
uid=1009 (carol@corp)   10.0.0.55      active 3m
uid=1015 (dave@corp)    10.0.0.71      idle   45m</pre>
<h2>System Health</h2><pre>db-primary    ONLINE   load=0.42  conn=87
db-replica-1  ONLINE   lag=180ms  conn=12
db-replica-2  ONLINE   lag=210ms  conn=15
cache-redis   ONLINE   mem=44%
queue-rabbit  DEGRADED 2 nodes down</pre>
<h2>Recent Audit Log</h2><pre>2026-04-25 18:42:11  INFO   alice@corp    user.update    uid=1031
2026-04-25 18:38:54  WARN   bob@corp      acl.bypass     resource=/api/v2/admin/secrets
2026-04-25 18:31:02  INFO   system        backup.start   target=db-primary
2026-04-25 18:15:20  ERROR  carol@corp    auth.fail      attempts=4
2026-04-25 18:14:17  INFO   carol@corp    login.success  ip=10.0.0.55</pre>
<h2>Quick Actions</h2><a href="/users">Users</a> | <a href="/secrets">Secrets vault</a> | <a href="/backup">Backup now</a> | <a href="/maintenance">Maintenance mode</a>
<p class="dim">Build: admin-console-7.4.2 -- Last deploy: 2026-04-22T11:18:00Z</p>
</body></html>';
    }
}

# ===========================================================================
# Hidden VHost #2: staging.gpigs.devergolabs.com (port 80 / L7)
# Internal-keyword "staging" -> RedAmon flags as MEDIUM severity
# ===========================================================================
server {
    listen 80;
    server_name staging.gpigs.devergolabs.com;
    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><title>STAGING - DVWS Pre-prod</title>
<style>body{background:#1a1a00;color:#ffffaa;font-family:sans-serif;padding:2rem;max-width:680px;margin:0 auto}h1{color:#ffff44}.banner{background:#332200;border:2px solid #ffaa00;padding:1rem;text-align:center;font-weight:bold;margin-bottom:1.5rem}pre{background:#000;padding:.8rem;border-left:3px solid #ffaa00}</style></head>
<body><div class="banner">YOU ARE ON STAGING -- DO NOT USE PRODUCTION CREDENTIALS</div>
<h1>DVWS Staging Environment</h1>
<p>Pre-production mirror of the DVWS application stack. Database is reset every 24 hours.</p>
<pre>Branch:        feat/auth-rewrite
Commit:        7a3f9c2 (2026-04-25)
Deploy time:   2026-04-25T16:11:09Z
DB:            staging-db-postgres-replica  (last reset: 04:00 UTC)
Cache:         staging-redis  (TTL=60s)
Feature flags: jwt_v2=true, oauth_pkce=true, debug_logs=true</pre>
<h2>Test Accounts</h2><pre>admin/letmein     (admin role)
test/test         (regular user)
qauser/qa-456     (regression suite)</pre>
<p>Stack: Node.js 18 / Express / Postgres 14 / Redis 7</p>
</body></html>';
    }
}

# ===========================================================================
# Hidden VHost #3: jenkins.gpigs.devergolabs.com (port 80 / L7)
# Internal-keyword "jenkins" -> RedAmon flags as MEDIUM severity
# ===========================================================================
server {
    listen 80;
    server_name jenkins.gpigs.devergolabs.com;
    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title>
<style>body{background:#fff;font-family:Arial,sans-serif;color:#333}.container{max-width:380px;margin:60px auto;padding:30px;border:1px solid #ccc}h1{color:#335061;font-size:1.4rem}.logo{color:#d33833;font-weight:bold;font-size:1.6rem;margin-bottom:1.5rem}label{display:block;margin-top:1rem}input{width:100%;padding:.5rem;margin-top:.3rem;border:1px solid #ccc}button{background:#335061;color:#fff;padding:.6rem 1.2rem;border:0;margin-top:1rem;cursor:pointer;font-size:1rem}.foot{color:#888;font-size:.8rem;margin-top:2rem;text-align:center}</style></head>
<body><div class="container">
<div class="logo">Jenkins</div>
<h1>Sign in to Jenkins</h1>
<form action="/j_spring_security_check" method="post">
<label>Username<input name="j_username" type="text"></label>
<label>Password<input name="j_password" type="password"></label>
<label><input name="remember_me" type="checkbox"> Keep me signed in</label>
<button type="submit">Sign in</button>
</form>
<p style="margin-top:1.5rem"><a href="/signup">Create an account</a></p>
<div class="foot">Jenkins 2.387.3 LTS<br>Page generated: 2026-04-25T17:33:21Z</div>
</div></body></html>';
    }
}

# ===========================================================================
# Hidden VHost #4: marketing.gpigs.devergolabs.com (port 80 / L7)
# NO internal-keyword match BUT returns 403 (different status from baseline 200)
# -> RedAmon flags as LOW severity (status mismatch is the trigger)
# ===========================================================================
server {
    listen 80;
    server_name marketing.gpigs.devergolabs.com;
    location / {
        default_type text/html;
        return 403 '<!DOCTYPE html><html><head><title>Devergolabs - Marketing Microsite (Authorisation Required)</title>
<style>body{background:#f5f5f0;font-family:Georgia,serif;color:#222;text-align:center;padding:4rem 2rem}h1{color:#c0392b;font-size:1.8rem}p{max-width:540px;margin:1rem auto;line-height:1.6}.btn{background:#2c3e50;color:#fff;padding:.6rem 1.2rem;text-decoration:none;border-radius:4px;display:inline-block;margin-top:1rem}</style></head>
<body><h1>403 Forbidden</h1>
<p>The Devergolabs marketing microsite is restricted to authenticated partners and registered prospects. This page is not part of the public website.</p>
<p>If you believe you should have access, please contact your account manager or open a ticket through the partner portal.</p>
<p><a class="btn" href="https://devergolabs.com">Visit the public site</a></p>
<p style="color:#888;font-size:.8rem;margin-top:2rem">Reference: marketing-microsite v2.1.4 -- Build 2026-04-21T09:14:00Z</p>
</body></html>';
    }
}

# ===========================================================================
# Hidden VHost #5: news.gpigs.devergolabs.com (port 80 / L7)
# Same status as baseline + slight body size delta -> RedAmon flags as INFO severity
# ===========================================================================
server {
    listen 80;
    server_name news.gpigs.devergolabs.com;
    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><title>RedAmon HackLab - News</title></head>
<body><h1>RedAmon HackLab News</h1><p>Latest research updates from the Devergolabs security team.</p><ul><li>2026-04-22: New attack-skill library released</li><li>2026-04-15: Improved Cypher query generation</li><li>2026-04-08: VHost & SNI Enumeration module added</li></ul></body></html>';
    }
}

# ===========================================================================
# HTTPS default server (port 443 / TLS) -- baseline TLS response
# Returns a small fixed string regardless of Host header. This is the L4
# baseline RedAmon compares against when probing the IP with random SNI.
# ===========================================================================
server {
    listen 443 ssl default_server;
    server_name _;
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        default_type text/plain;
        return 200 'RedAmon HackLab -- TLS endpoint. See / on port 80 for terms.\n';
    }
}

# ===========================================================================
# Hidden VHost #6: internal.gpigs.devergolabs.com (port 443 / SNI-routed L4)
# Internal-keyword "internal" -> RedAmon flags as MEDIUM severity via L4 path
# Reachable only when SNI matches (curl --resolve trick)
# ===========================================================================
server {
    listen 443 ssl;
    server_name internal.gpigs.devergolabs.com;
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><title>Internal Cluster Dashboard</title>
<style>body{background:#0a1628;color:#a8c8e8;font-family:monospace;padding:2rem;max-width:780px;margin:0 auto}h1{color:#5fa8d3}h2{color:#82c0e0;font-size:1rem;margin-top:1.5rem;border-bottom:1px solid #1f3a5f;padding-bottom:.3rem}pre{background:#050d18;padding:1rem;border-left:3px solid #5fa8d3;font-size:.85rem;overflow-x:auto}.warn{background:#2a0a0a;border:1px solid #ff4444;padding:.8rem;margin:1rem 0;color:#ffaaaa}</style></head>
<body><h1>Internal Cluster Dashboard</h1>
<div class="warn">RESTRICTED -- This dashboard is reachable only via SNI <code>internal.gpigs.devergolabs.com</code>. Bare-IP requests over HTTPS receive the public landing baseline.</div>
<h2>Cluster Overview</h2><pre>Region:           eu-west-1
Nodes:            12 (control-plane: 3, worker: 9)
Pods:             247 running, 4 pending, 0 crashloop
Services:         63 ClusterIP, 8 LoadBalancer, 2 NodePort
Ingress:          nginx-ingress 1.8.1 (12 routes)
Cert manager:     v1.13.2 (84 certificates managed)</pre>
<h2>Active Workloads</h2><pre>backend-api          (default)         Running   3/3
frontend-app         (default)         Running   4/4
redis-cluster        (default)         Running   3/3
postgres-primary     (data)            Running   1/1
postgres-replicas    (data)            Running   2/2
prometheus-stack     (monitoring)      Running   1/1
grafana              (monitoring)      Running   1/1
argo-workflows       (cicd)            Running   2/2
vault                (security)        Running   3/3</pre>
<h2>Active Alerts (3)</h2><pre>WARN  postgres-primary disk usage > 75%
WARN  prometheus retention nearing limit (28 of 30 days)
INFO  vault leader election in 2h (rotation policy)</pre>
<p style="color:#5a7a9a;font-size:.8rem">Internal Dashboard v3.4.1 -- Build 7a8b9c2 -- Updated 2026-04-25T17:41:22Z</p>
</body></html>';
    }
}

# ===========================================================================
# Hidden VHost #7: k8s.gpigs.devergolabs.com (port 443 / host_header_bypass)
# Internal-keyword "k8s" -> normally MEDIUM, but escalated to HIGH because
# the response differs based on whether the SNI matched (L4) or only the
# Host header matched via fallthrough (L7). RedAmon flags this as
# host_header_bypass -- the highest-severity finding from this module.
#
# How the divergence works:
#   L4 probe: curl --resolve k8s.gpigs:443:IP   -> SNI = k8s -> $ssl_server_name = "k8s..."
#                                                -> returns the K8S_VIA_SNI body (~2 KB)
#   L7 probe: curl -H "Host: k8s.gpigs" IP:443  -> SNI = IP -> default cert -> Host header
#                                                   matches this server_name during HTTP
#                                                   routing, but $ssl_server_name = ""
#                                                -> returns the K8S_VIA_HOST body (~1 KB)
# ===========================================================================
server {
    listen 443 ssl;
    server_name k8s.gpigs.devergolabs.com;
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        default_type application/json;
        if ($ssl_server_name = "k8s.gpigs.devergolabs.com") {
            return 200 '{"backend":"k8s-via-sni","apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7842913"},"items":[{"metadata":{"name":"backend-api-7d9f5b8c6f-mqx4n","namespace":"default","uid":"a1b2c3d4-1111-2222-3333-444455556666"},"status":{"phase":"Running","podIP":"10.244.1.42","hostIP":"10.0.1.5","containerStatuses":[{"name":"backend-api","ready":true,"restartCount":0,"image":"corp/backend-api:7.4.2"}]}},{"metadata":{"name":"frontend-app-66cf4d9b8d-t2p8j","namespace":"default","uid":"a1b2c3d4-aaaa-bbbb-cccc-ddddeeeeffff"},"status":{"phase":"Running","podIP":"10.244.2.71","hostIP":"10.0.1.6","containerStatuses":[{"name":"frontend-app","ready":true,"restartCount":1,"image":"corp/frontend-app:3.1.0"}]}},{"metadata":{"name":"vault-active-0","namespace":"security","uid":"a1b2c3d4-9999-8888-7777-666655554444"},"status":{"phase":"Running","podIP":"10.244.3.11","hostIP":"10.0.1.7","containerStatuses":[{"name":"vault","ready":true,"restartCount":0,"image":"hashicorp/vault:1.15.4"}]}}],"_meta":{"served_via":"sni-routing","note":"Production k8s API surrogate. SNI-only access enforced at the ingress layer."}}\n';
        }
        return 200 '{"error":"sni_mismatch","reason":"This endpoint refuses requests whose TLS SNI does not match the requested Host header.","detail":"Use a TLS client that sends Server Name Indication matching the Host header (e.g. curl --resolve).","l4_required":true}\n';
    }
}
NGINX_CONF

# docker-compose.override.yml -- expose databases + add extra containers + nginx landing
# All services use restart: unless-stopped so they come back after EC2 reboot
cat > ~/dvws-node/docker-compose.override.yml << 'OVERRIDE'
version: '3'
services:

  # Nginx landing page + reverse proxy + VHost & SNI hidden vhost demo
  landing:
    image: nginx:alpine
    container_name: gpigs-landing
    ports:
      - "80:80"
      - "443:443"      # NEW -- TLS / SNI-routed hidden vhost demo
    volumes:
      - ./landing/index.html:/usr/share/nginx/html/index.html:ro
      - ./landing/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./landing/certs:/etc/nginx/certs:ro     # NEW -- multi-SAN self-signed cert
    depends_on:
      - web
      - argentum
    restart: unless-stopped

  # Argentum Digital sidecar (Node.js + headless Chromium for the moderation queue)
  argentum:
    build: ./xss-lab
    container_name: gpigs-argentum
    expose:
      - "3001"
    restart: unless-stopped

  # Base DVWS services -- add restart policy
  web:
    restart: unless-stopped

  dvws-mongo:
    ports:
      - "27017:27017"
    restart: unless-stopped

  dvws-mysql:
    ports:
      - "3306:3306"
    restart: unless-stopped

  tomcat-rce:
    build: ./tomcat-rce
    container_name: gpigs-tomcat
    ports:
      - "8080:8080"
    restart: unless-stopped

  log4shell:
    image: ghcr.io/christophetd/log4shell-vulnerable-app:latest
    container_name: gpigs-log4shell
    ports:
      - "8888:8080"
    restart: unless-stopped

  vsftpd:
    build: ./vsftpd-backdoor
    container_name: gpigs-vsftpd
    ports:
      - "21:21"
      - "6200:6200"
    restart: unless-stopped
OVERRIDE

# Move web app off port 80 (nginx landing takes over)
# App is reachable via nginx proxy and directly on host port 8081
sed -i 's/"80:80"/"8081:80"/' ~/dvws-node/docker-compose.yml

echo "=== Building and starting all containers ==="
sudo docker-compose up -d --build

PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo '<IP>')

echo ""
echo "=== DONE ==="
echo ""
echo "RedAmon HackLab deployed successfully."
echo "  Landing page:  http://${PUBLIC_IP}/"
echo "  All containers set to restart: unless-stopped"
echo ""
echo "All services will auto-restart after EC2 reboot."
