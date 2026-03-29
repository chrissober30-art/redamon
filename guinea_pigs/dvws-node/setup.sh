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

# docker-compose.override.yml -- expose databases + add CVE containers
cat > ~/dvws-node/docker-compose.override.yml << 'OVERRIDE'
version: '3'
services:

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

echo "=== Building and starting all containers ==="
sudo docker-compose up -d --build

PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo '<IP>')

echo ""
echo "=== DONE ==="
echo ""
echo "DVWS-Node (application-level vulns):"
echo "  REST API + Swagger:  http://${PUBLIC_IP}/"
echo "  Swagger UI:          http://${PUBLIC_IP}/api-docs"
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
