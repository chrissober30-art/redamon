#!/bin/bash
# Install Docker and deploy DVWS-Node + CVE Lab (vulnerable services)
# DVWS-Node:  port 80 (REST/SOAP), 4000 (GraphQL), 9090 (XML-RPC)
# Databases:  port 3306 (MySQL), 27017 (MongoDB) -- exposed for scanning
# CVE Lab:    port 8080 (Tomcat RCE), 8888 (Log4Shell), 21/6200 (vsftpd backdoor)
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

echo "=== Creating CVE Lab overlay ==="

# Dockerfile for Tomcat CVE-2017-12617 (PUT method RCE)
mkdir -p ~/dvws-node/tomcat-rce
cat > ~/dvws-node/tomcat-rce/Dockerfile << 'DOCKERFILE'
FROM vulhub/tomcat:8.5.19
# Enable PUT method (readonly=false) to trigger CVE-2017-12617
RUN cd /usr/local/tomcat/conf \
    && LINE=$(nl -ba web.xml | grep '<load-on-startup>1' | awk '{print $1}') \
    && ADDON="<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>" \
    && sed -i "$LINE i $ADDON" web.xml
EXPOSE 8080
DOCKERFILE

# Dockerfile for vsftpd 2.3.4 backdoor (CVE-2011-2523)
# Built from source -- the original GPL-licensed code with the known backdoor
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

# Landing page with legal terms (served by nginx at / and /legal)
echo "=== Creating legal landing page ==="
mkdir -p ~/dvws-node/landing
cat > ~/dvws-node/landing/index.html << 'LANDING_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedAmon HackLab -- Vulnerable Test Server</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
  .container { max-width: 860px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { color: #ff4444; font-size: 1.8rem; margin-bottom: 0.3rem; }
  .subtitle { color: #888; font-size: 1rem; margin-bottom: 2rem; }
  .warning-box { background: #1a0000; border: 1px solid #ff4444; border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 2rem; }
  .warning-box strong { color: #ff6666; }
  h2 { color: #ff6666; font-size: 1.2rem; margin: 1.8rem 0 0.8rem; border-bottom: 1px solid #222; padding-bottom: 0.4rem; }
  .services-table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
  .services-table th { background: #1a1a1a; color: #ff8888; text-align: left; padding: 0.5rem 0.8rem; border: 1px solid #222; }
  .services-table td { padding: 0.5rem 0.8rem; border: 1px solid #222; }
  .services-table tr:hover { background: #111; }
  .port { color: #ff8888; font-family: monospace; font-weight: bold; }
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
<p class="subtitle">Intentionally Vulnerable Test Server -- gpigs.devergolabs.com</p>

<div class="warning-box">
  <strong>WARNING:</strong> This is a deliberately vulnerable server provided for authorized security testing with <a href="https://github.com/samugit83/redamon">RedAmon</a> only. All traffic is logged and monitored. By accessing any service on this server, you accept the Rules of Engagement below.
</div>

<h2>Target Services</h2>
<table class="services-table">
<tr><th>Port</th><th>Service</th><th>Vulnerabilities</th></tr>
<tr><td class="port">80</td><td>Express / Node.js</td><td>REST API, SOAP, Swagger -- SQLi, XXE, CMDi, IDOR, SSRF, JWT bypass, file upload, NoSQLi</td></tr>
<tr><td class="port">4000</td><td>Apollo GraphQL</td><td>Introspection, IDOR, SQLi, arbitrary file write</td></tr>
<tr><td class="port">9090</td><td>XML-RPC</td><td>SSRF via method calls</td></tr>
<tr><td class="port">3306</td><td>MySQL 8.4</td><td>Exposed database, no firewall</td></tr>
<tr><td class="port">27017</td><td>MongoDB 4.0.4</td><td>No authentication, known CVEs</td></tr>
<tr><td class="port">8080</td><td>Tomcat 8.5.19</td><td>CVE-2017-12617 (PUT RCE), Ghostcat</td></tr>
<tr><td class="port">8888</td><td>Spring Boot + Log4j</td><td>CVE-2021-44228 (Log4Shell JNDI RCE)</td></tr>
<tr><td class="port">21 / 6200</td><td>vsftpd 2.3.4</td><td>CVE-2011-2523 (backdoor root shell)</td></tr>
</table>

<h2>Rules of Engagement</h2>
<ol>
  <li><strong>RedAmon-only testing.</strong> This server is provided exclusively for testing with the <a href="https://github.com/samugit83/redamon">RedAmon</a> framework. Manual exploitation, third-party scanners, and automated tools other than RedAmon are not authorized.</li>
  <li><strong>Scope.</strong> You may only interact with the services listed above (ports 80, 4000, 9090, 3306, 27017, 8080, 8888, 21/6200). All other ports, IPs, and infrastructure behind this server are out of scope.</li>
  <li><strong>No lateral movement.</strong> Do not attempt to pivot from this server to other systems, networks, or AWS infrastructure (including the EC2 metadata service at 169.254.169.254).</li>
  <li><strong>No denial of service.</strong> Do not perform load testing, resource exhaustion, or any action intended to degrade availability. This includes XML bombs, fork bombs, and excessive concurrent connections.</li>
  <li><strong>No data exfiltration beyond the server.</strong> You may read intentionally planted vulnerable data. Do not exfiltrate data to external servers, set up reverse shells to your own infrastructure, or establish persistent backdoors.</li>
  <li><strong>No modification of the environment.</strong> Do not delete databases, drop tables, modify other users' data, or alter running services in ways that affect other testers.</li>
  <li><strong>Responsible disclosure.</strong> If you discover a vulnerability in RedAmon itself (not in the intentionally vulnerable target), report it via <a href="https://github.com/samugit83/redamon/issues">GitHub Issues</a>.</li>
  <li><strong>Legal compliance.</strong> You are solely responsible for ensuring your testing complies with all applicable laws in your jurisdiction. Unauthorized access to computer systems is illegal in most countries.</li>
  <li><strong>No warranty / liability.</strong> This server is provided "as is" for educational purposes. Devergolabs assumes no liability for any damages arising from your use. Access may be revoked at any time without notice.</li>
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
  <br/>Last updated: 2026-03-31
</div>

</div>
</body>
</html>
LANDING_HTML

# Nginx config -- serves landing page at / and /legal, proxies API traffic to dvws-node
cat > ~/dvws-node/landing/nginx.conf << 'NGINX_CONF'
server {
    listen 80;

    # Landing page with legal terms
    location = / {
        root /usr/share/nginx/html;
        try_files /index.html =404;
    }
    location = /legal {
        root /usr/share/nginx/html;
        try_files /index.html =404;
    }

    # Proxy everything else to DVWS-Node
    location / {
        proxy_pass http://web:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX_CONF

# docker-compose.override.yml -- expose databases + add CVE containers + nginx landing
cat > ~/dvws-node/docker-compose.override.yml << 'OVERRIDE'
version: '3'
services:

  # Nginx landing page + reverse proxy to DVWS-Node
  landing:
    image: nginx:alpine
    container_name: gpigs-landing
    ports:
      - "80:80"
    volumes:
      - ./landing/index.html:/usr/share/nginx/html/index.html:ro
      - ./landing/nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - web
    restart: unless-stopped

  # Expose MongoDB 4.0.4 (2018) -- has known CVEs
  dvws-mongo:
    ports:
      - "27017:27017"

  # Expose MySQL 8 -- detectable by scanners
  dvws-mysql:
    ports:
      - "3306:3306"

  # CVE-2017-12617: Apache Tomcat PUT method RCE
  # Metasploit: exploit/multi/http/tomcat_jsp_upload_bypass
  tomcat-rce:
    build: ./tomcat-rce
    container_name: vulnerable-tomcat-8.5.19
    ports:
      - "8080:8080"
    restart: unless-stopped

  # CVE-2021-44228: Log4Shell JNDI RCE
  # Metasploit: exploit/multi/http/log4shell_header_injection
  log4shell:
    image: ghcr.io/christophetd/log4shell-vulnerable-app:latest
    container_name: vulnerable-log4shell
    ports:
      - "8888:8080"
    restart: unless-stopped

  # CVE-2011-2523: vsftpd 2.3.4 backdoor (root shell on port 6200)
  # Metasploit: exploit/unix/ftp/vsftpd_234_backdoor
  # Built from source (GPL-licensed) -- no third-party image dependency
  vsftpd:
    build: ./vsftpd-backdoor
    container_name: vulnerable-vsftpd-2.3.4
    ports:
      - "21:21"
      - "6200:6200"
    restart: unless-stopped
OVERRIDE

# Patch: move DVWS-Node web service off public port 80 (nginx landing takes over)
# Host port 80 is now owned by nginx; DVWS-Node API is still reachable via nginx proxy
# and directly on host port 8081 for scanners/recon
sed -i 's/"80:80"/"8081:80"/' ~/dvws-node/docker-compose.yml

echo "=== Building and starting all containers ==="
sudo docker-compose up -d --build

PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo '<IP>')

echo ""
echo "=== DONE ==="
echo ""
echo "Landing page (legal terms):"
echo "  Homepage:            http://${PUBLIC_IP}/"
echo "  Legal / RoE:         http://${PUBLIC_IP}/legal"
echo ""
echo "DVWS-Node (application-level vulns):"
echo "  REST API + Swagger:  http://${PUBLIC_IP}:8081/"
echo "  via nginx proxy:     http://${PUBLIC_IP}/api/"
echo "  Swagger UI:          http://${PUBLIC_IP}:8081/api-docs"
echo "  GraphQL Playground:  http://${PUBLIC_IP}:4000/"
echo "  XML-RPC:             http://${PUBLIC_IP}:9090/xmlrpc"
echo "  SOAP WSDL:           http://${PUBLIC_IP}/dvwsuserservice?wsdl"
echo ""
echo "Exposed Databases:"
echo "  MySQL 8:             ${PUBLIC_IP}:3306  (root / mysecretpassword)"
echo "  MongoDB 4.0.4:       ${PUBLIC_IP}:27017 (no auth)"
echo ""
echo "CVE Lab (Metasploit-exploitable):"
echo "  Tomcat 8.5.19 RCE:   http://${PUBLIC_IP}:8080/  (CVE-2017-12617)"
echo "  Log4Shell:            http://${PUBLIC_IP}:8888/  (CVE-2021-44228)"
echo "  vsftpd 2.3.4:        ftp://${PUBLIC_IP}:21      (CVE-2011-2523, backdoor on 6200)"
echo ""
echo "Default credentials:"
echo "  DVWS-Node:  admin / letmein  (admin) | test / test (regular)"
echo "  MySQL:      root / mysecretpassword"
echo "  MongoDB:    no authentication required"
