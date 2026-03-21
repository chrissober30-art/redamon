# Third-Party Licenses

RedAmon integrates, bundles, or dynamically invokes the following third-party open-source software. Each component is governed by its own license. **The authors of RedAmon do not own, maintain, or provide warranty for any of these tools.** This file documents all third-party components, their licenses, and where to obtain their source code.

> **AGPL-3.0 Notice**: Several tools bundled in RedAmon's Docker images are licensed under the GNU Affero General Public License v3.0. Under AGPL-3.0, the complete corresponding source code for these tools must be made available to any user who interacts with them. Source code for all AGPL-licensed components is available at their respective repositories listed below.

---

## ProjectDiscovery Tools (AGPL-3.0)

These tools are either installed in Docker images or pulled as Docker containers at runtime.

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Naabu** | Port scanning | AGPL-3.0 | https://github.com/projectdiscovery/naabu | Installed via `go install` in `mcp/kali-sandbox/Dockerfile`; also pulled as Docker image `projectdiscovery/naabu:latest` at runtime |
| **Nuclei** | Template-based vulnerability scanning (9,000+ templates) | AGPL-3.0 | https://github.com/projectdiscovery/nuclei | Installed via `go install` in `mcp/kali-sandbox/Dockerfile`; also pulled as Docker image `projectdiscovery/nuclei:latest` at runtime |
| **Katana** | Web crawling and endpoint discovery | AGPL-3.0 | https://github.com/projectdiscovery/katana | Pulled as Docker image `projectdiscovery/katana:latest` at runtime |
| **HTTPx** | HTTP probing and technology detection | AGPL-3.0 | https://github.com/projectdiscovery/httpx | Pulled as Docker image `projectdiscovery/httpx:latest` at runtime |
| **Subfinder** | Subdomain enumeration via passive sources | AGPL-3.0 | https://github.com/projectdiscovery/subfinder | Pulled as Docker image `projectdiscovery/subfinder:latest` at runtime |

---

## Exploitation & Post-Exploitation Tools

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Metasploit Framework** | Exploitation, post-exploitation, and payload generation | BSD-3-Clause (Rapid7) | https://github.com/rapid7/metasploit-framework | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **Hydra** | Network login brute-force (50+ protocols) | AGPL-3.0 | https://github.com/vanhauser-thc/thc-hydra | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **SQLMap** | Automated SQL injection detection and exploitation | GPL-2.0 | https://github.com/sqlmapproject/sqlmap | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **John the Ripper** | Password cracking | GPL-2.0 | https://github.com/openwall/john | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **ExploitDB** | Public exploit archive and search | GPL-2.0 | https://gitlab.com/exploit-database/exploitdb | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |

---

## Network Scanning & Reconnaissance Tools

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Nmap** | Network scanning and service detection | NPSL (Nmap Public Source License) | https://github.com/nmap/nmap | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **Amass** | In-depth subdomain enumeration | Apache-2.0 | https://github.com/owasp-amass/amass | Pulled as Docker image `caffix/amass:latest` at runtime |
| **Knockpy** | Subdomain enumeration via wordlist | GPL-3.0 | https://github.com/guelfoweb/knock | Installed via `pip` in `recon/Dockerfile` |
| **puredns** | DNS wildcard filtering and resolution | GPL-3.0 | https://github.com/d3mondev/puredns | Pulled as Docker image `frost19k/puredns:latest` at runtime |
| **Hakrawler** | Web crawling and link discovery | MIT | https://github.com/hakluke/hakrawler | Pulled as Docker image `jauderho/hakrawler:latest` at runtime |
| **GAU (GetAllUrls)** | Passive URL discovery from web archives | MIT | https://github.com/lc/gau | Pulled as Docker image `sxcurity/gau:latest` at runtime |
| **Kiterunner** | API endpoint discovery | AGPL-3.0 | https://github.com/assetnote/kiterunner | Binary downloaded from GitHub releases at runtime |
| **jsluice** | JavaScript file analysis for endpoints and secrets | MIT | https://github.com/BishopFox/jsluice | Built from source via `go install` in `recon/Dockerfile` (multi-stage) |

---

## Vulnerability Assessment (GVM/OpenVAS)

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **GVM (Greenbone Vulnerability Management)** | Network vulnerability scanning (170,000+ NVTs) | AGPL-3.0 | https://github.com/greenbone | Multiple Docker images from `registry.community.greenbone.net` in `docker-compose.yml` |
| **gvmd** | GVM management daemon | AGPL-3.0 | https://github.com/greenbone/gvmd | Docker image: `registry.community.greenbone.net/community/gvmd:stable` |
| **ospd-openvas** | OpenVAS scanner daemon | AGPL-3.0 | https://github.com/greenbone/ospd-openvas | Docker image: `registry.community.greenbone.net/community/ospd-openvas:stable` |
| **pg-gvm** | GVM PostgreSQL database | AGPL-3.0 | https://github.com/greenbone/pg-gvm | Docker image: `registry.community.greenbone.net/community/pg-gvm:stable` |

---

## Anonymity & Tunneling

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Tor** | Anonymous network routing (optional) | BSD-3-Clause | https://gitlab.torproject.org/tpo/core/tor | Installed via `apt-get` in `recon/Dockerfile` |
| **Proxychains4** | SOCKS proxy chaining | LGPL-2.1+ | https://github.com/rofl0r/proxychains-ng | Installed via `apt-get` in `recon/Dockerfile` |
| **Ngrok** | TCP tunneling for reverse shells (optional) | Proprietary (free tier) | https://ngrok.com/ | Binary downloaded in `mcp/kali-sandbox/Dockerfile` |
| **Chisel** | Multi-port TCP tunneling | MIT | https://github.com/jpillora/chisel | Binary downloaded in `mcp/kali-sandbox/Dockerfile` |

---

## DoS / Stress Testing

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **hping3** | Packet crafting and stress testing | GPL-2.0 | https://github.com/antirez/hping | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **slowhttptest** | Slow HTTP attack testing | Apache-2.0 | https://github.com/shekyan/slowhttptest | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |

---

## Technology Fingerprinting

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **python-Wappalyzer** | Technology detection on web targets | GPL-3.0 | https://github.com/chorsley/python-Wappalyzer | Installed via `pip` in `recon/Dockerfile` |

---

## Databases

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Neo4j Community** | Graph database for attack surface mapping | GPL-3.0 (Neo4j Community) | https://github.com/neo4j/neo4j | Docker image: `neo4j:5.26-community` in `docker-compose.yml` |
| **PostgreSQL** | Relational database for project settings | PostgreSQL License (BSD-like) | https://github.com/postgres/postgres | Docker image: `postgres:16-alpine` in `docker-compose.yml` |

---

## AGPL-3.0 Source Code Availability

In compliance with the AGPL-3.0 license, the complete corresponding source code for all AGPL-licensed components is available at the repositories listed above. If you have received a RedAmon Docker image containing any of these tools and cannot access their source code at the listed repositories, please contact the maintainers at devergo.sam@gmail.com and we will provide the source code.

## License Compatibility Note

RedAmon's own source code is released under the **MIT License**. Third-party tools run as **separate processes** in Docker containers and are invoked via CLI commands or network APIs. This constitutes "mere aggregation" under the GPL/AGPL and does not require RedAmon's own code to adopt a copyleft license. However, the AGPL-licensed tools themselves remain under AGPL-3.0, and any modifications to those tools must comply with their respective licenses.

---

*Last updated: March 2026*
