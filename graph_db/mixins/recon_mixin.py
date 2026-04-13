"""
ReconMixin: Core reconnaissance pipeline graph operations.

Provides methods to ingest data from:
- domain_discovery (Domain, Subdomain, IP, DNSRecord nodes)
- ip_recon (mock Domain, Subdomain, IP nodes for IP-mode scans)
- port_scan (Port, Service nodes)
- http_probe (BaseURL, Technology, Header, Certificate nodes)
- vuln_scan (Vulnerability, CVE, Exploit, MitreData, Capec nodes)
- resource_enum (Endpoint, Parameter nodes)
- js_recon (JsReconFinding, Secret nodes with js_recon source)
"""

import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address


class ReconMixin:
    def update_graph_from_domain_discovery(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Initialize the Neo4j graph database with reconnaissance data after domain_discovery.

        This function creates:
        - Domain node (root) with WHOIS data
        - Subdomain nodes
        - IP nodes
        - DNSRecord nodes
        - All relationships between them

        Args:
            recon_data: The recon JSON data from domain_discovery module
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "domain_created": False,
            "subdomains_created": 0,
            "ips_created": 0,
            "dns_records_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        with self.driver.session() as session:
            # Initialize schema first

            # Extract data from recon_data
            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns") or {}

            root_domain = metadata.get("root_domain", "")
            target = metadata.get("target", "")
            filtered_mode = metadata.get("filtered_mode", False)
            subdomain_filter = metadata.get("subdomain_filter", [])

            if not root_domain:
                stats["errors"].append("No root_domain found in metadata")
                return stats

            # 1. Create Domain node with WHOIS data
            try:
                domain_props = {
                    "name": root_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "scan_timestamp": metadata.get("scan_timestamp"),
                    "scan_type": metadata.get("scan_type"),
                    "target": target,
                    "filtered_mode": filtered_mode,
                    "subdomain_filter": subdomain_filter,
                    "modules_executed": metadata.get("modules_executed", []),
                    "anonymous_mode": metadata.get("anonymous_mode", False),
                    "bruteforce_mode": metadata.get("bruteforce_mode", False),
                    # WHOIS data
                    "registrar": whois_data.get("registrar"),
                    "registrar_url": whois_data.get("registrar_url"),
                    "whois_server": whois_data.get("whois_server"),
                    "dnssec": whois_data.get("dnssec"),
                    "organization": whois_data.get("org"),
                    "country": whois_data.get("country"),
                    "city": whois_data.get("city"),
                    "state": whois_data.get("state"),
                    "address": whois_data.get("address"),
                    "registrant_postal_code": whois_data.get("registrant_postal_code"),
                    "registrant_name": whois_data.get("name"),
                    "admin_name": whois_data.get("admin_name"),
                    "admin_org": whois_data.get("admin_org"),
                    "tech_name": whois_data.get("tech_name"),
                    "tech_org": whois_data.get("tech_org"),
                    "domain_name": whois_data.get("domain_name"),
                    "referral_url": whois_data.get("referral_url"),
                    "reseller": whois_data.get("reseller"),
                    "name_servers": whois_data.get("name_servers", []),
                    "whois_emails": whois_data.get("emails", []),
                    "updated_at": datetime.now().isoformat()
                }

                # Handle date fields (can be list or single value)
                for date_field in ["creation_date", "expiration_date", "updated_date"]:
                    date_val = whois_data.get(date_field)
                    if isinstance(date_val, list) and date_val:
                        domain_props[date_field] = date_val[0]
                    elif date_val:
                        domain_props[date_field] = date_val

                # Handle status (can be list)
                status = whois_data.get("status", [])
                if isinstance(status, list):
                    # Clean status strings (remove URL part)
                    domain_props["status"] = [s.split()[0] if " " in s else s for s in status]
                elif status:
                    domain_props["status"] = [status.split()[0] if " " in status else status]

                # Remove None values
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props
                    """,
                    name=root_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+][graph-db] Created Domain node: {root_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes and relationships
            subdomain_dns = dns_data.get("subdomains", {})
            domain_dns = dns_data.get("domain", {})  # DNS data for root domain
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # Get DNS info: use domain_dns if subdomain equals root_domain, else use subdomain_dns
                    if subdomain == root_domain:
                        subdomain_info = domain_dns  # Root domain DNS is in dns.domain
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)

                    # Create Subdomain node
                    status = subdomain_status_map.get(subdomain)  # None for unresolved subs
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=status
                    )
                    stats["subdomains_created"] += 1

                    # Create relationships: Subdomain -[:BELONGS_TO]-> Domain and Domain -[:HAS_SUBDOMAIN]-> Subdomain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        domain=root_domain, subdomain=subdomain,
                        user_id=user_id, project_id=project_id
                    )
                    stats["relationships_created"] += 1

                    # 3. Create DNS records and IP addresses
                    records = subdomain_info.get("records", {})
                    ips_data = subdomain_info.get("ips", {})

                    # Create IP nodes from resolved IPs
                    for ip_version in ["ipv4", "ipv6"]:
                        ip_list = ips_data.get(ip_version, [])
                        for ip_addr in ip_list:
                            if ip_addr:
                                try:
                                    # Create IP node
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                        SET i.version = $version,
                                            i.updated_at = datetime()
                                        """,
                                        address=ip_addr, user_id=user_id, project_id=project_id,
                                        version=ip_version
                                    )
                                    stats["ips_created"] += 1

                                    # Create relationship: Subdomain -[:RESOLVES_TO]-> IP
                                    record_type = "A" if ip_version == "ipv4" else "AAAA"
                                    session.run(
                                        """
                                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: $record_type}]->(i)
                                        """,
                                        subdomain=subdomain, ip=ip_addr, record_type=record_type,
                                        user_id=user_id, project_id=project_id
                                    )
                                    stats["relationships_created"] += 1
                                except Exception as e:
                                    stats["errors"].append(f"IP {ip_addr} creation failed: {e}")

                    # Create DNSRecord nodes for other record types
                    for record_type, record_values in records.items():
                        if record_values and record_type not in ["A", "AAAA"]:  # A/AAAA handled via IP nodes
                            if not isinstance(record_values, list):
                                record_values = [record_values]

                            for value in record_values:
                                if value:
                                    try:
                                        # Create DNSRecord node
                                        session.run(
                                            """
                                            MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain, user_id: $user_id, project_id: $project_id})
                                            SET dns.user_id = $user_id,
                                                dns.project_id = $project_id,
                                                dns.updated_at = datetime()
                                            """,
                                            type=record_type, value=str(value), subdomain=subdomain,
                                            user_id=user_id, project_id=project_id
                                        )
                                        stats["dns_records_created"] += 1

                                        # Create relationship: Subdomain -[:HAS_DNS_RECORD]-> DNSRecord
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                            MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain, user_id: $user_id, project_id: $project_id})
                                            MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                            """,
                                            subdomain=subdomain, type=record_type, value=str(value),
                                            user_id=user_id, project_id=project_id
                                        )
                                        stats["relationships_created"] += 1
                                    except Exception as e:
                                        stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!][graph-db] Subdomain {subdomain} processing failed: {e}")

            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['ips_created']} IP nodes")
            print(f"[+][graph-db] Created {stats['dns_records_created']} DNSRecord nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_ip_recon(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Initialize the Neo4j graph for IP-based reconnaissance.

        Creates:
        - Mock Domain node (ip-targets.{project_id}) with ip_mode: True
        - Subdomain nodes (real hostnames from PTR or mock IP-based names)
        - IP nodes and RESOLVES_TO relationships
        - BELONGS_TO relationships from subdomains to mock domain
        - Per-IP WHOIS data on IP nodes
        """
        stats = {
            "domain_created": False,
            "subdomains_created": 0,
            "ips_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        with self.driver.session() as session:

            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns") or {}
            ip_to_hostname = metadata.get("ip_to_hostname", {})
            ip_whois = whois_data.get("ip_whois", {})

            mock_domain = metadata.get("root_domain", f"ip-targets.{project_id}")

            # 1. Create mock Domain node
            try:
                domain_props = {
                    "name": mock_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "ip_mode": True,
                    "is_mock": True,
                    "scan_timestamp": metadata.get("scan_timestamp"),
                    "scan_type": metadata.get("scan_type"),
                    "target_ips": metadata.get("target_ips", []),
                    "expanded_ips": metadata.get("expanded_ips", []),
                    "modules_executed": metadata.get("modules_executed", []),
                    "updated_at": datetime.now().isoformat()
                }
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props
                    """,
                    name=mock_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+][graph-db] Created mock Domain node: {mock_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes, IP nodes, and relationships
            subdomains_dns = dns_data.get("subdomains", {})

            for subdomain_name in subdomains:
                try:
                    sub_dns = subdomains_dns.get(subdomain_name, {})
                    is_mock = sub_dns.get("is_mock", False)
                    actual_ip = sub_dns.get("actual_ip", "")

                    # Create Subdomain node
                    sub_props = {
                        "name": subdomain_name,
                        "user_id": user_id,
                        "project_id": project_id,
                        "has_records": sub_dns.get("has_records", False),
                        "is_mock": is_mock,
                        "ip_mode": True,
                        "updated_at": datetime.now().isoformat()
                    }
                    if actual_ip:
                        sub_props["actual_ip"] = actual_ip

                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET s += $props, s.status = 'resolved'
                        ON MATCH SET s += $props
                        WITH s
                        WHERE s.status IS NULL
                        SET s.status = 'resolved'
                        """,
                        name=subdomain_name, user_id=user_id, project_id=project_id, props=sub_props
                    )
                    stats["subdomains_created"] += 1

                    # Create BELONGS_TO and HAS_SUBDOMAIN relationships to mock domain
                    session.run(
                        """
                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        sub=subdomain_name, domain=mock_domain, uid=user_id, pid=project_id
                    )
                    stats["relationships_created"] += 1

                    # Create IP nodes and RESOLVES_TO relationships
                    ips = sub_dns.get("ips", {})
                    all_ips = (ips.get("ipv4", []) or []) + (ips.get("ipv6", []) or [])

                    for ip in all_ips:
                        # Get WHOIS info for this IP if available
                        whois_info = ip_whois.get(ip, {})

                        ip_props = {
                            "address": ip,
                            "user_id": user_id,
                            "project_id": project_id,
                            "version": "v6" if ":" in ip else "v4",
                            "ip_mode": True,
                            "updated_at": datetime.now().isoformat()
                        }
                        if whois_info:
                            ip_props["organization"] = whois_info.get("org", "")
                            ip_props["country"] = whois_info.get("country", "")

                        session.run(
                            """
                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            SET i += $props
                            """,
                            addr=ip, uid=user_id, pid=project_id, props=ip_props
                        )
                        stats["ips_created"] += 1

                        # RESOLVES_TO
                        session.run(
                            """
                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                            MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:RESOLVES_TO]->(i)
                            """,
                            sub=subdomain_name, ip=ip, uid=user_id, pid=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain_name}: {e}")
                    print(f"[!][graph-db] Error processing {subdomain_name}: {e}")

            print(f"[+][graph-db] IP Recon graph update complete:")
            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['ips_created']} IP nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_port_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with port scan data.

        This function creates/updates:
        - Port nodes with open ports
        - Service nodes for detected services
        - Updates IP nodes with CDN information
        - Relationships: IP -[:HAS_PORT]-> Port, Port -[:RUNS_SERVICE]-> Service

        Args:
            recon_data: The recon JSON data containing port_scan results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "ports_created": 0,
            "services_created": 0,
            "ips_updated": 0,
            "relationships_created": 0,
            "errors": []
        }

        port_scan_data = recon_data.get("port_scan", {})
        if not port_scan_data:
            stats["errors"].append("No port_scan data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = port_scan_data.get("scan_metadata", {})
            by_ip = port_scan_data.get("by_ip", {})
            by_host = port_scan_data.get("by_host", {})

            # Process by_ip data - this gives us IP -> ports mapping
            # Only update IPs that already exist in the graph (from DNS) or have open ports.
            # Skip IPs with no ports and no hostnames to avoid orphaned nodes.
            for ip_addr, ip_info in by_ip.items():
                try:
                    ports = ip_info.get("ports", [])
                    hostnames = ip_info.get("hostnames", [])

                    # Skip IPs that have no open ports and no hostname associations
                    if not ports and not hostnames:
                        continue

                    # Update IP node with CDN info if available
                    cdn_name = ip_info.get("cdn")
                    is_cdn = ip_info.get("is_cdn", False)

                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        SET i.is_cdn = $is_cdn,
                            i.cdn_name = $cdn_name,
                            i.updated_at = datetime()
                        """,
                        address=ip_addr, user_id=user_id, project_id=project_id,
                        is_cdn=is_cdn, cdn_name=cdn_name
                    )
                    stats["ips_updated"] += 1

                except Exception as e:
                    stats["errors"].append(f"IP {ip_addr} update failed: {e}")

            # Process by_host data - this gives us hostname -> port details with services
            for hostname, host_info in by_host.items():
                ip_addr = host_info.get("ip")
                port_details = host_info.get("port_details", [])
                cdn_name = host_info.get("cdn")
                is_cdn = host_info.get("is_cdn", False)

                # Update IP node with CDN info (if not already done)
                if ip_addr:
                    try:
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            SET i.is_cdn = $is_cdn,
                                i.cdn_name = $cdn_name,
                                i.updated_at = datetime()
                            """,
                            address=ip_addr, user_id=user_id, project_id=project_id,
                            is_cdn=is_cdn, cdn_name=cdn_name
                        )
                    except Exception as e:
                        stats["errors"].append(f"IP {ip_addr} update failed: {e}")

                # Create Port and Service nodes
                for port_info in port_details:
                    port_number = port_info.get("port")
                    protocol = port_info.get("protocol", "tcp")
                    service_name = port_info.get("service")

                    if not port_number:
                        continue

                    try:
                        # Create Port node linked to IP
                        # Port uniqueness is per IP + port + protocol + tenant
                        session.run(
                            """
                            MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.state = 'open',
                                p.updated_at = datetime()
                            """,
                            port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_created"] += 1

                        # Create relationship: IP -[:HAS_PORT]-> Port
                        if ip_addr:
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=ip_addr, port_number=port_number, protocol=protocol,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create Service node if service detected
                        if service_name:
                            session.run(
                                """
                                MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.updated_at = datetime()
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                user_id=user_id, project_id=project_id
                            )
                            stats["services_created"] += 1

                            # Create relationship: Port -[:RUNS_SERVICE]-> Service
                            session.run(
                                """
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                                service_name=service_name, user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Port {port_number}/{protocol} on {ip_addr} failed: {e}")

            # Update Domain node with port scan metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.port_scan_timestamp = $scan_timestamp,
                            d.port_scan_type = $scan_type,
                            d.port_scan_ports_config = $ports_config,
                            d.port_scan_total_open_ports = $total_open_ports,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        scan_type=scan_metadata.get("scan_type"),
                        ports_config=scan_metadata.get("ports_config"),
                        total_open_ports=port_scan_data.get("summary", {}).get("total_open_ports", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Updated {stats['ips_updated']} IP nodes with CDN info")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes")
            print(f"[+][graph-db] Created {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_nmap(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with Nmap service detection and NSE vuln data.

        This function:
        - Enriches existing Port nodes with product, version, CPE from Nmap -sV
        - Updates existing Service nodes with version info
        - Creates Vulnerability nodes from NSE script findings
        - Creates CVE nodes if NSE scripts report specific CVEs
        - Creates Technology nodes for detected services (for CVE lookup linkage)
        """
        import re

        stats = {
            "ports_enriched": 0,
            "services_enriched": 0,
            "technologies_created": 0,
            "nse_vulns_created": 0,
            "cves_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        nmap_data = recon_data.get("nmap_scan", {})
        if not nmap_data:
            return stats

        with self.driver.session() as session:

            # 1. Enrich Port and Service nodes with Nmap version data
            for host, host_info in nmap_data.get("by_host", {}).items():
                ip_addr = host_info.get("ip", "")
                for pd in host_info.get("port_details", []):
                    port_number = pd.get("port")
                    product = pd.get("product")
                    version = pd.get("version")
                    cpe = pd.get("cpe")

                    if not port_number or not ip_addr:
                        continue

                    try:
                        # Enrich Port node
                        session.run(
                            """
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.product = $product,
                                p.version = $version,
                                p.cpe = $cpe,
                                p.nmap_scanned = true,
                                p.updated_at = datetime()
                            """,
                            port_number=port_number, ip_addr=ip_addr,
                            product=product, version=version, cpe=cpe,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_enriched"] += 1

                        # Enrich Service node
                        if product:
                            session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.product = $product,
                                    svc.version = $version,
                                    svc.cpe = $cpe,
                                    svc.updated_at = datetime()
                                """,
                                port_number=port_number, ip_addr=ip_addr,
                                product=product, version=version, cpe=cpe,
                                user_id=user_id, project_id=project_id
                            )
                            stats["services_enriched"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Port {port_number} enrich failed: {e}")

            # 2. Create Technology nodes for Nmap-detected services (for CVE lookup linkage)
            #    Link: (Service)-[:USES_TECHNOLOGY]->(Technology)
            #    Link: (Port)-[:HAS_TECHNOLOGY]->(Technology)
            for svc in nmap_data.get("services_detected", []):
                product = svc.get("product", "")
                version = svc.get("version", "")
                port_number = svc.get("port")
                if not product:
                    continue
                tech_name = f"{product}/{version}" if version else product

                # Find the IP for this service from by_host data
                svc_ip = ""
                for host_info in nmap_data.get("by_host", {}).values():
                    if any(pd.get("port") == port_number for pd in host_info.get("port_details", [])):
                        svc_ip = host_info.get("ip", "")
                        break

                try:
                    session.run(
                        """
                        MERGE (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                        SET t.version = $version,
                            t.source = 'nmap',
                            t.cpe = $cpe,
                            t.updated_at = datetime()
                        """,
                        name=tech_name, version=version or "",
                        cpe=svc.get("cpe", ""),
                        user_id=user_id, project_id=project_id
                    )
                    stats["technologies_created"] += 1

                    # Link Service -> Technology
                    if svc_ip and port_number:
                        session.run(
                            """
                            MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                            MERGE (svc)-[:USES_TECHNOLOGY]->(t)
                            """,
                            port_number=port_number, ip_addr=svc_ip,
                            tech_name=tech_name,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Link Port -> Technology
                        session.run(
                            """
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                            MERGE (p)-[:HAS_TECHNOLOGY]->(t)
                            """,
                            port_number=port_number, ip_addr=svc_ip,
                            tech_name=tech_name,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Technology {tech_name} failed: {e}")

            # 3. Create Vulnerability nodes from NSE script findings
            for vuln in nmap_data.get("nse_vulns", []):
                script_id = vuln.get("script_id", "")
                ip_addr = vuln.get("host", "")
                port_number = vuln.get("port")
                output = vuln.get("output", "")
                state = vuln.get("state", "")
                cve_id = vuln.get("cve")

                if not script_id or not ip_addr:
                    continue

                try:
                    # Determine severity from NSE state
                    severity = "high" if "VULNERABLE" in state.upper() else "medium"

                    # Create Vulnerability node
                    session.run(
                        """
                        MERGE (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                        SET v.severity = $severity,
                            v.type = 'nmap_nse',
                            v.source = 'nmap_nse',
                            v.output = $output,
                            v.state = $state,
                            v.cve_id = $cve_id,
                            v.updated_at = datetime()
                        """,
                        name=script_id, ip_addr=ip_addr, port_number=port_number,
                        severity=severity, output=output[:2000], state=state,
                        cve_id=cve_id,
                        user_id=user_id, project_id=project_id
                    )
                    stats["nse_vulns_created"] += 1

                    # Link Vulnerability to Port
                    if port_number:
                        session.run(
                            """
                            MATCH (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:AFFECTS]->(p)
                            """,
                            name=script_id, ip_addr=ip_addr, port_number=port_number,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                    # Link Vulnerability to the Technology on that port
                    if port_number:
                        # Find the technology name for this port from services_detected
                        for svc in nmap_data.get("services_detected", []):
                            if svc.get("port") == port_number and svc.get("product"):
                                svc_product = svc["product"]
                                svc_version = svc.get("version", "")
                                svc_tech_name = f"{svc_product}/{svc_version}" if svc_version else svc_product
                                session.run(
                                    """
                                    MATCH (v:Vulnerability {name: $vuln_name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (v)-[:FOUND_ON]->(t)
                                    """,
                                    vuln_name=script_id, ip_addr=ip_addr, port_number=port_number,
                                    tech_name=svc_tech_name,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1
                                break

                    # Create CVE node if NSE reported a specific CVE
                    if cve_id:
                        session.run(
                            """
                            MERGE (c:CVE {id: $cve_id, user_id: $user_id, project_id: $project_id})
                            SET c.cve_id = $cve_id,
                                c.name = $cve_id,
                                c.source = 'nmap_nse',
                                c.updated_at = datetime()
                            """,
                            cve_id=cve_id, user_id=user_id, project_id=project_id
                        )
                        stats["cves_created"] += 1

                        # Link CVE to Vulnerability
                        session.run(
                            """
                            MATCH (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                            MATCH (c:CVE {id: $cve_id, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:HAS_CVE]->(c)
                            """,
                            name=script_id, ip_addr=ip_addr, port_number=port_number,
                            cve_id=cve_id, user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Link Technology to CVE (so agent can traverse Service -> Tech -> CVE)
                        if port_number:
                            for svc in nmap_data.get("services_detected", []):
                                if svc.get("port") == port_number and svc.get("product"):
                                    svc_product = svc["product"]
                                    svc_version = svc.get("version", "")
                                    svc_tech_name = f"{svc_product}/{svc_version}" if svc_version else svc_product
                                    session.run(
                                        """
                                        MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                                        MATCH (c:CVE {id: $cve_id, user_id: $user_id, project_id: $project_id})
                                        MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                        """,
                                        tech_name=svc_tech_name, cve_id=cve_id,
                                        user_id=user_id, project_id=project_id
                                    )
                                    stats["relationships_created"] += 1
                                    break

                except Exception as e:
                    stats["errors"].append(f"NSE vuln {script_id} failed: {e}")

        print(f"[+][graph-db] Nmap Graph Update Summary:")
        print(f"[+][graph-db] Enriched {stats['ports_enriched']} Port nodes with version data")
        print(f"[+][graph-db] Enriched {stats['services_enriched']} Service nodes")
        print(f"[+][graph-db] Created {stats['technologies_created']} Technology nodes")
        print(f"[+][graph-db] Created {stats['nse_vulns_created']} NSE Vulnerability nodes")
        print(f"[+][graph-db] Created {stats['cves_created']} CVE nodes")
        print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

        if stats["errors"]:
            print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_http_probe(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with HTTP probe data.

        This function creates/updates:
        - BaseURL nodes with HTTP response data (root/base URLs discovered by httpx)
        - Technology nodes for detected technologies
        - Header nodes for HTTP response headers
        - Service nodes (if not existing) for the HTTP/HTTPS service
        - Relationships: Service -[:SERVES_URL]-> BaseURL, BaseURL -[:USES_TECHNOLOGY]-> Technology, BaseURL -[:HAS_HEADER]-> Header

        Args:
            recon_data: The recon JSON data containing http_probe results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "baseurls_created": 0,
            "certificates_created": 0,
            "services_created": 0,
            "technologies_created": 0,
            "headers_created": 0,
            "relationships_created": 0,
            "subdomains_updated": 0,
            "errors": []
        }

        http_probe_data = recon_data.get("http_probe", {})
        if not http_probe_data:
            stats["errors"].append("No http_probe data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = http_probe_data.get("scan_metadata", {})
            by_url = http_probe_data.get("by_url", {})
            wappalyzer = http_probe_data.get("wappalyzer", {})
            all_technologies = wappalyzer.get("all_technologies", {})

            # Process each URL
            for url, url_info in by_url.items():
                try:
                    # Extract URL components
                    host = url_info.get("host", "")
                    scheme = "https" if url.startswith("https://") else "http"

                    # Create BaseURL node (root/base URL discovered by http_probe)
                    baseurl_props = {
                        "url": url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "scheme": scheme,
                        "host": host,
                        "status_code": url_info.get("status_code"),
                        "content_length": url_info.get("content_length"),
                        "content_type": url_info.get("content_type"),
                        "title": url_info.get("title"),
                        "server": url_info.get("server"),
                        "response_time_ms": url_info.get("response_time_ms"),
                        "word_count": url_info.get("word_count"),
                        "line_count": url_info.get("line_count"),
                        "resolved_ip": url_info.get("ip"),
                        "cname": url_info.get("cname"),
                        "cdn": url_info.get("cdn"),
                        "is_cdn": url_info.get("is_cdn", False),
                        "asn": url_info.get("asn"),
                        "favicon_hash": url_info.get("favicon_hash"),
                        "is_live": url_info.get("status_code") is not None,
                        "source": "http_probe"
                    }

                    # Add body hash info if available
                    body_hash = url_info.get("body_hash", {})
                    if body_hash:
                        baseurl_props["body_sha256"] = body_hash.get("body_sha256")
                        baseurl_props["header_sha256"] = body_hash.get("header_sha256")

                    # Add TLS cipher if available (store on BaseURL for quick reference)
                    tls_data = url_info.get("tls", {})
                    if tls_data:
                        baseurl_props["tls_cipher"] = tls_data.get("cipher")
                        baseurl_props["tls_version"] = tls_data.get("version")

                    # Remove None values
                    baseurl_props = {k: v for k, v in baseurl_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                        SET u += $props,
                            u.updated_at = datetime()
                        """,
                        url=url, user_id=user_id, project_id=project_id, props=baseurl_props
                    )
                    stats["baseurls_created"] += 1

                    # Create Certificate node from TLS data if available
                    if tls_data and tls_data.get("certificate"):
                        cert_data = tls_data.get("certificate", {})
                        subject_cn = cert_data.get("subject_cn", "")
                        
                        if subject_cn:
                            # Build certificate properties
                            cert_props = {
                                "subject_cn": subject_cn,
                                "user_id": user_id,
                                "project_id": project_id,
                                "issuer": ", ".join(cert_data.get("issuer", [])) if isinstance(cert_data.get("issuer"), list) else cert_data.get("issuer"),
                                "not_before": cert_data.get("not_before"),
                                "not_after": cert_data.get("not_after"),
                                "san": cert_data.get("san", []),  # Subject Alternative Names as list
                                "cipher": tls_data.get("cipher"),
                                "tls_version": tls_data.get("version"),
                                "source": "http_probe"
                            }
                            
                            # Remove None values
                            cert_props = {k: v for k, v in cert_props.items() if v is not None}
                            
                            # Create Certificate node (unique by subject_cn + project_id)
                            session.run(
                                """
                                MERGE (c:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                SET c += $props,
                                    c.updated_at = datetime()
                                """,
                                subject_cn=subject_cn, user_id=user_id, project_id=project_id, props=cert_props
                            )
                            stats["certificates_created"] += 1
                            
                            # Create relationship: BaseURL -[:HAS_CERTIFICATE]-> Certificate
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                MATCH (c:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                MERGE (u)-[:HAS_CERTIFICATE]->(c)
                                """,
                                url=url, subject_cn=subject_cn, project_id=project_id, user_id=user_id
                            )
                            stats["relationships_created"] += 1

                    # Create relationship: Service -[:SERVES_URL]-> BaseURL
                    # BaseURLs are served by HTTP/HTTPS services running on ports
                    if host:
                        resolved_ip = url_info.get("ip")
                        # Extract actual port from URL (e.g., http://example.com:8080)
                        # Only use default ports (80/443) if no explicit port in URL
                        parsed_url = urlparse(url)
                        port_number = parsed_url.port or (443 if scheme == "https" else 80)
                        default_service_name = "https" if scheme == "https" else "http"

                        if resolved_ip:
                            # Check if a service already exists for this port/IP (from port scan)
                            # If so, reuse it instead of creating a duplicate with different name
                            existing_service = session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                RETURN svc.name as name LIMIT 1
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                user_id=user_id, project_id=project_id
                            ).single()

                            if existing_service:
                                # Use the existing service name (e.g., http-proxy from port scan)
                                service_name = existing_service["name"]
                            else:
                                # No existing service, create one with default name (http/https)
                                service_name = default_service_name
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                    SET svc.updated_at = datetime()
                                    """,
                                    service_name=service_name, port_number=port_number, ip_addr=resolved_ip,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["services_created"] += 1

                            # Create relationship: Service -[:SERVES_URL]-> BaseURL
                            session.run(
                                """
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                MERGE (svc)-[:SERVES_URL]->(u)
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=resolved_ip, url=url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                            # Also ensure Port node exists and is connected to Service
                            session.run(
                                """
                                MERGE (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET p.state = 'open',
                                    p.updated_at = datetime()
                                WITH p
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                service_name=service_name,
                                user_id=user_id, project_id=project_id
                            )

                            # Also ensure IP -[:HAS_PORT]-> Port relationship exists
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=resolved_ip, port_number=port_number,
                                user_id=user_id, project_id=project_id
                            )

                    # Process technologies from both httpx and wappalyzer
                    # Track processed tech names to avoid duplicates
                    processed_techs = set()

                    # 1. Process technologies from httpx first
                    httpx_technologies = url_info.get("technologies", [])
                    for tech_str in httpx_technologies:
                        try:
                            # Parse technology string (e.g., "Nginx:1.19.0" or "Ubuntu")
                            if ":" in tech_str:
                                tech_name, tech_version = tech_str.split(":", 1)
                            else:
                                tech_name = tech_str
                                tech_version = None

                            # Get additional info from wappalyzer if available
                            wap_info = all_technologies.get(tech_name, {})
                            categories = wap_info.get("categories", [])
                            confidence = wap_info.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                                "detected_by": "httpx"
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Create Technology node (unique by name + version + tenant)
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """,
                                    name=tech_name, version=tech_version, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                                processed_techs.add((tech_name, tech_version))
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """,
                                    name=tech_name, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                                processed_techs.add((tech_name, None))
                            stats["technologies_created"] += 1

                            # Create relationship: BaseURL -[:USES_TECHNOLOGY]-> Technology
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Technology {tech_str} failed: {e}")

                    # 2. Process wappalyzer technologies not found by httpx
                    # wappalyzer.by_url contains complete tech list per URL
                    # (plugins, analytics, security_tools, frameworks are just filtered subsets by category)
                    wappalyzer_by_url = wappalyzer.get("by_url", {})
                    wap_techs_for_url = wappalyzer_by_url.get(url, [])

                    for wap_tech in wap_techs_for_url:
                        try:
                            tech_name = wap_tech.get("name", "")
                            tech_version = wap_tech.get("version")  # Can be None

                            # Skip if already processed from httpx
                            if (tech_name, tech_version) in processed_techs:
                                continue
                            # Also skip if httpx found it without version but wappalyzer has version
                            if (tech_name, None) in processed_techs:
                                continue

                            categories = wap_tech.get("categories", [])
                            confidence = wap_tech.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                                "detected_by": "wappalyzer"
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Create Technology node
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """,
                                    name=tech_name, version=tech_version, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """,
                                    name=tech_name, props=tech_props,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["technologies_created"] += 1

                            # Create relationship: BaseURL -[:USES_TECHNOLOGY]-> Technology
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version, user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, tech_version=tech_version, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, version: '', user_id: $user_id, project_id: $project_id})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, confidence=confidence,
                                    user_id=user_id, project_id=project_id
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Wappalyzer technology {tech_name} failed: {e}")

                    # Process headers
                    headers = url_info.get("headers", {})
                    security_headers = ["x-frame-options", "x-xss-protection", "content-security-policy",
                                        "strict-transport-security", "x-content-type-options"]
                    tech_revealing_headers = ["server", "x-powered-by", "x-aspnet-version"]

                    for header_name, header_value in headers.items():
                        try:
                            is_security = header_name.lower() in security_headers
                            reveals_tech = header_name.lower() in tech_revealing_headers

                            session.run(
                                """
                                MERGE (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                SET h.user_id = $user_id,
                                    h.project_id = $project_id,
                                    h.is_security_header = $is_security,
                                    h.reveals_technology = $reveals_tech,
                                    h.updated_at = datetime()
                                """,
                                name=header_name, value=str(header_value), url=url,
                                user_id=user_id, project_id=project_id,
                                is_security=is_security, reveals_tech=reveals_tech
                            )
                            stats["headers_created"] += 1

                            # Create relationship: BaseURL -[:HAS_HEADER]-> Header
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $url, user_id: $user_id, project_id: $project_id})
                                MATCH (h:Header {name: $name, value: $value, baseurl: $url, user_id: $user_id, project_id: $project_id})
                                MERGE (u)-[:HAS_HEADER]->(h)
                                """,
                                url=url, name=header_name, value=str(header_value),
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Header {header_name} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"URL {url} processing failed: {e}")

            # Update Domain node with http probe metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = http_probe_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.http_probe_timestamp = $scan_timestamp,
                            d.http_probe_live_urls = $live_urls,
                            d.http_probe_technology_count = $tech_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        live_urls=summary.get("live_urls", 0),
                        tech_count=summary.get("technology_count", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            # --- Update Subdomain nodes with HTTP probe status ---
            by_host = http_probe_data.get("by_host", {})
            for hostname, host_info in by_host.items():
                try:
                    status_codes = host_info.get("status_codes", [])  # already sorted int list
                    live_urls = host_info.get("live_urls", [])

                    # Determine status as the primary HTTP status code (string)
                    # Priority: lowest non-5xx code, then lowest overall
                    if status_codes:
                        non_error = [c for c in status_codes if c < 500]
                        primary = min(non_error) if non_error else min(status_codes)
                        http_status = str(primary)
                    else:
                        http_status = "no_http"

                    session.run(
                        """
                        MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                        SET s.status = $status,
                            s.status_codes = $status_codes,
                            s.http_live_url_count = $live_count,
                            s.http_probed_at = datetime(),
                            s.updated_at = datetime()
                        """,
                        hostname=hostname, user_id=user_id, project_id=project_id,
                        status=http_status, status_codes=status_codes,
                        live_count=len(live_urls)
                    )
                    stats["subdomains_updated"] += 1
                except Exception as e:
                    stats["errors"].append(f"Subdomain status update for {hostname}: {e}")

            # Mark resolved subdomains that got no HTTP response at all as "no_http"
            all_probed_hosts = set(by_host.keys())
            all_target_subs = set(recon_data.get("subdomains", []))
            no_response_hosts = all_target_subs - all_probed_hosts
            if no_response_hosts:
                session.run(
                    """
                    UNWIND $hosts AS hostname
                    MATCH (s:Subdomain {name: hostname, user_id: $user_id, project_id: $project_id})
                    WHERE s.status = 'resolved'
                    SET s.status = 'no_http',
                        s.http_probed_at = datetime(),
                        s.updated_at = datetime()
                    """,
                    hosts=list(no_response_hosts), user_id=user_id, project_id=project_id
                )

            print(f"[+][graph-db] Created {stats['baseurls_created']} BaseURL nodes")
            print(f"[+][graph-db] Created/Updated {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['technologies_created']} Technology nodes")
            print(f"[+][graph-db] Created {stats['headers_created']} Header nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Updated {stats['subdomains_updated']} Subdomain statuses")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def _find_cwes_with_capec(self, cwe_node: dict, results: list):
        """
        Recursively traverse CWE hierarchy and collect only CWEs that have non-empty related_capec.

        Args:
            cwe_node: CWE hierarchy node
            results: List to collect CWEs with CAPEC (passed by reference)
        """
        if not cwe_node:
            return

        # Check if this CWE has related_capec
        related_capec = cwe_node.get("related_capec", [])
        if related_capec:
            results.append(cwe_node)

        # Recursively check child
        child = cwe_node.get("child")
        if child:
            self._find_cwes_with_capec(child, results)

    def _process_cwe_with_capec(self, session, cwe_node: dict, cve_id: str, user_id: str,
                                 project_id: str, stats_mitre: dict):
        """
        Create MitreData (CWE) node and its related Capec nodes, directly connected to CVE.

        Args:
            session: Neo4j session
            cwe_node: CWE node that has related_capec
            cve_id: The CVE ID to connect to
            user_id: User identifier
            project_id: Project identifier
            stats_mitre: Dictionary to track created nodes
        """

        # Get CWE ID (support both "cwe_id" and "id" keys)
        cwe_id = cwe_node.get("cwe_id") or cwe_node.get("id")
        if not cwe_id:
            return

        # Generate unique MitreData node ID (per CVE + CWE combination)
        mitre_id = f"{cve_id}-{cwe_id}"

        # Create MitreData node with CWE properties
        mitre_props = {
            "id": mitre_id,
            "user_id": user_id,
            "project_id": project_id,
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "cwe_name": cwe_node.get("name"),
            "cwe_description": cwe_node.get("description"),
            "cwe_url": cwe_node.get("url"),
            "abstraction": cwe_node.get("abstraction"),
        }

        # Add additional fields if available
        if cwe_node.get("mapping"):
            mitre_props["mapping"] = cwe_node.get("mapping")
        if cwe_node.get("structure"):
            mitre_props["structure"] = cwe_node.get("structure")
        if cwe_node.get("consequences"):
            mitre_props["consequences"] = json.dumps(cwe_node.get("consequences"))
        if cwe_node.get("mitigations"):
            mitre_props["mitigations"] = json.dumps(cwe_node.get("mitigations"))
        if cwe_node.get("detection_methods"):
            mitre_props["detection_methods"] = json.dumps(cwe_node.get("detection_methods"))

        # Remove None values
        mitre_props = {k: v for k, v in mitre_props.items() if v is not None}

        session.run(
            """
            MERGE (m:MitreData {id: $id})
            SET m += $props,
                m.updated_at = datetime()
            """,
            id=mitre_id, props=mitre_props
        )
        stats_mitre["nodes"] += 1

        # Create relationship: CVE -[:HAS_CWE]-> MitreData (directly connected)
        session.run(
            """
            MATCH (c:CVE {id: $cve_id})
            MATCH (m:MitreData {id: $mitre_id})
            MERGE (c)-[:HAS_CWE]->(m)
            """,
            cve_id=cve_id, mitre_id=mitre_id
        )
        stats_mitre["rels"] += 1

        # Process related CAPEC entries
        related_capec = cwe_node.get("related_capec", [])
        for capec in related_capec:
            capec_id_raw = capec.get("id")
            if not capec_id_raw:
                continue

            # Handle both formats: "CAPEC-475" (string) or 475 (numeric)
            if isinstance(capec_id_raw, str) and capec_id_raw.startswith("CAPEC-"):
                capec_node_id = capec_id_raw
                try:
                    numeric_id = int(capec_id_raw.replace("CAPEC-", ""))
                except ValueError:
                    numeric_id = None
            else:
                capec_node_id = f"CAPEC-{capec_id_raw}"
                numeric_id = capec_id_raw if isinstance(capec_id_raw, int) else None

            # Create Capec node with all properties
            capec_props = {
                "capec_id": capec_node_id,
                "user_id": user_id,
                "project_id": project_id,
                "numeric_id": numeric_id,
                "name": capec.get("name"),
                "description": capec.get("description"),
                "url": capec.get("url"),
                "likelihood": capec.get("likelihood"),
                "severity": capec.get("severity"),
                "prerequisites": capec.get("prerequisites"),
                "examples": capec.get("examples"),
            }

            # Add execution flow if available
            execution_flow = capec.get("execution_flow", [])
            if execution_flow:
                capec_props["execution_flow"] = json.dumps(execution_flow)

            # Add related CWEs
            related_cwes = capec.get("related_cwes", [])
            if related_cwes:
                capec_props["related_cwes"] = related_cwes

            # Remove None values
            capec_props = {k: v for k, v in capec_props.items() if v is not None}

            session.run(
                """
                MERGE (cap:Capec {capec_id: $capec_id})
                SET cap += $props,
                    cap.updated_at = datetime()
                """,
                capec_id=capec_node_id, props=capec_props
            )
            stats_mitre["capec"] += 1

            # Create relationship: MitreData -[:HAS_CAPEC]-> Capec
            session.run(
                """
                MATCH (m:MitreData {id: $mitre_id})
                MATCH (cap:Capec {capec_id: $capec_id})
                MERGE (m)-[:HAS_CAPEC]->(cap)
                """,
                mitre_id=mitre_id, capec_id=capec_node_id
            )
            stats_mitre["rels"] += 1

    def update_graph_from_vuln_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with vulnerability scan data.

        This function creates/updates:
        - Endpoint nodes (discovered paths/URLs with parameters from Katana crawling)
        - Parameter nodes (query/body parameters discovered and tested)
        - Vulnerability nodes (DAST findings from Nuclei scanning)
        - Relationships: BaseURL -[:HAS_ENDPOINT]-> Endpoint -[:HAS_PARAMETER]-> Parameter
        - Relationships: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter, Vulnerability -[:FOUND_AT]-> Endpoint
        - Relationships: BaseURL -[:HAS_VULNERABILITY]-> Vulnerability

        Args:
            recon_data: The recon JSON data containing vuln_scan results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "endpoints_created": 0,
            "parameters_created": 0,
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        vuln_scan_data = recon_data.get("vuln_scan", {})
        if not vuln_scan_data:
            stats["errors"].append("No vuln_scan data found in recon_data")
            return stats

        # Get target subdomains from scan scope - only create nodes for these
        target_subdomains = set(recon_data.get("subdomains", []))
        target_domain = recon_data.get("domain", "")

        # Also include the main domain if no subdomains specified
        if target_domain and not target_subdomains:
            target_subdomains.add(target_domain)

        def is_in_scope(hostname: str) -> bool:
            """Check if a hostname is within the scan scope (target subdomains)."""
            if not target_subdomains:
                return True  # No filter if no subdomains defined
            # Remove port if present
            host_only = hostname.split(":")[0] if ":" in hostname else hostname
            return host_only in target_subdomains

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = vuln_scan_data.get("scan_metadata", {})
            discovered_urls = vuln_scan_data.get("discovered_urls", {})
            by_target = vuln_scan_data.get("by_target", {})

            # Track created endpoints and parameters for deduplication
            created_endpoints = set()  # (baseurl, path, method)
            created_parameters = set()  # (endpoint_path, param_name, param_position)
            skipped_out_of_scope = 0  # Track skipped URLs

            # Process discovered URLs with parameters (from Katana crawling)
            dast_urls = discovered_urls.get("dast_urls_with_params", [])
            base_urls = discovered_urls.get("base_urls", [])

            for dast_url in dast_urls:
                try:
                    # Parse the URL to extract components
                    parsed = urlparse(dast_url)

                    # Determine scheme, host, path
                    scheme = parsed.scheme or "http"
                    host = parsed.netloc
                    path = parsed.path or "/"
                    query_string = parsed.query

                    # Skip URLs that are not in scan scope (discovered subdomains only)
                    if not is_in_scope(host):
                        skipped_out_of_scope += 1
                        continue

                    # Construct base URL (scheme://host)
                    base_url = f"{scheme}://{host}"

                    # Determine HTTP method (default to GET for URLs with query params)
                    method = "GET"

                    # Create Endpoint node
                    endpoint_key = (base_url, path, method)
                    if endpoint_key not in created_endpoints:
                        has_parameters = bool(query_string)

                        session.run(
                            """
                            MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            SET e.user_id = $user_id,
                                e.project_id = $project_id,
                                e.has_parameters = $has_parameters,
                                e.full_url = $full_url,
                                e.source = 'katana_crawl',
                                e.updated_at = datetime()
                            """,
                            path=path, method=method, baseurl=base_url,
                            user_id=user_id, project_id=project_id,
                            has_parameters=has_parameters,
                            full_url=dast_url.split('?')[0]  # URL without query params
                        )
                        stats["endpoints_created"] += 1
                        created_endpoints.add(endpoint_key)

                        # Create BaseURL node if it doesn't exist and relationship
                        # BaseURL may not exist if endpoint was discovered by crawling a different subdomain
                        session.run(
                            """
                            MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET bu.source = 'resource_enum',
                                          bu.updated_at = datetime()
                            WITH bu
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (bu)-[:HAS_ENDPOINT]->(e)
                            """,
                            baseurl=base_url, path=path, method=method,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1


                    # Parse and create Parameter nodes from query string
                    if query_string:
                        params = parse_qs(query_string, keep_blank_values=True)
                        for param_name, param_values in params.items():
                            param_key = (path, param_name, "query")
                            if param_key not in created_parameters:
                                sample_value = param_values[0] if param_values else ""

                                session.run(
                                    """
                                    MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    SET p.user_id = $user_id,
                                        p.project_id = $project_id,
                                        p.sample_value = $sample_value,
                                        p.is_injectable = false,
                                        p.updated_at = datetime()
                                    """,
                                    name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                    user_id=user_id, project_id=project_id,
                                    sample_value=sample_value
                                )
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="query",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"DAST URL {dast_url} processing failed: {e}")

            # Process vulnerability findings by target
            for target_host, target_data in by_target.items():
                # Skip targets that are not in scan scope
                target_host_only = target_host.split(":")[0] if ":" in target_host else target_host
                if not is_in_scope(target_host_only):
                    skipped_out_of_scope += 1
                    continue

                findings = target_data.get("findings", [])

                for finding in findings:
                    try:
                        # Extract raw data for detailed information
                        raw = finding.get("raw", {})
                        raw_info = raw.get("info", {})
                        raw_metadata = raw_info.get("metadata", {})

                        # Generate unique vulnerability ID
                        template_id = finding.get("template_id", "unknown")
                        matched_at = finding.get("matched_at", "")
                        fuzzing_param = raw.get("fuzzing_parameter", "")
                        vuln_id = f"{template_id}-{target_host}-{fuzzing_param}-{hash(matched_at) % 10000}"

                        # Extract path from matched_at URL
                        matched_parsed = urlparse(matched_at)
                        vuln_path = matched_parsed.path or "/"
                        vuln_scheme = matched_parsed.scheme or "http"
                        vuln_host = matched_parsed.netloc or target_host

                        # Also check if matched_at URL host is in scope
                        vuln_host_only = vuln_host.split(":")[0] if ":" in vuln_host else vuln_host
                        if not is_in_scope(vuln_host_only):
                            skipped_out_of_scope += 1
                            continue

                        vuln_base_url = f"{vuln_scheme}://{vuln_host}"

                        # Create Vulnerability node with all fields
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "nuclei",
                            "template_id": template_id,
                            "template_path": finding.get("template_path"),
                            "template_url": raw.get("template-url"),
                            "name": finding.get("name"),
                            "description": finding.get("description"),
                            "severity": finding.get("severity"),
                            "category": finding.get("category"),
                            "tags": finding.get("tags", []),
                            "authors": raw_info.get("author", []),
                            "references": finding.get("reference", []),

                            # Classification
                            "cwe_ids": finding.get("cwe_id", []),
                            "cves": finding.get("cves", []),
                            "cvss_score": finding.get("cvss_score"),
                            "cvss_metrics": finding.get("cvss_metrics"),

                            # Attack details
                            "matched_at": matched_at,
                            "matcher_name": finding.get("matcher_name"),
                            "matcher_status": raw.get("matcher-status", False),
                            "extractor_name": raw.get("extractor-name"),
                            "extracted_results": finding.get("extracted_results", []),

                            # Request/Response details
                            "request_type": raw.get("type"),
                            "scheme": raw.get("scheme"),
                            "host": raw.get("host"),
                            "port": raw.get("port"),
                            "path": vuln_path,
                            "matched_ip": raw.get("ip"),

                            # DAST specific
                            "is_dast_finding": raw.get("is_fuzzing_result", False),
                            "fuzzing_method": raw.get("fuzzing_method"),
                            "fuzzing_parameter": raw.get("fuzzing_parameter"),
                            "fuzzing_position": raw.get("fuzzing_position"),

                            # Template metadata
                            "max_requests": raw_metadata.get("max-request"),

                            # Reproduction
                            "curl_command": finding.get("curl_command"),

                            # Raw request/response (for evidence)
                            "raw_request": finding.get("request"),
                            "raw_response": finding.get("response", "")[:5000] if finding.get("response") else None,  # Truncate long responses

                            # Timestamp
                            "timestamp": finding.get("timestamp"),
                            "discovered_at": finding.get("timestamp")
                        }

                        # Remove None values
                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        stats["vulnerabilities_created"] += 1

                        # Note: We don't create BaseURL -[:HAS_VULNERABILITY]-> Vulnerability
                        # because the vulnerability is connected via:
                        # BaseURL -> Endpoint <- Vulnerability (FOUND_AT)
                        # and optionally: Endpoint -> Parameter <- Vulnerability (AFFECTS_PARAMETER)
                        # This avoids redundant connections in the graph.

                        # Create Endpoint node for the vulnerability path if not exists
                        fuzzing_method = raw.get("fuzzing_method", "GET")
                        endpoint_key = (vuln_base_url, vuln_path, fuzzing_method)

                        if endpoint_key not in created_endpoints:
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    e.has_parameters = true,
                                    e.source = 'vuln_scan',
                                    e.updated_at = datetime()
                                """,
                                path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["endpoints_created"] += 1
                            created_endpoints.add(endpoint_key)

                            # Create BaseURL node if it doesn't exist and relationship
                            session.run(
                                """
                                MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET bu.source = 'vuln_scan',
                                              bu.updated_at = datetime()
                                WITH bu
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=vuln_base_url, path=vuln_path, method=fuzzing_method,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create relationship: Vulnerability -[:FOUND_AT]-> Endpoint
                        session.run(
                            """
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:FOUND_AT]->(e)
                            """,
                            vuln_id=vuln_id, path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Create Parameter node and mark as injectable if this is a DAST finding
                        fuzzing_param = raw.get("fuzzing_parameter")
                        fuzzing_position = raw.get("fuzzing_position", "query")

                        if fuzzing_param:
                            param_key = (vuln_path, fuzzing_param, fuzzing_position)

                            # Create or update Parameter node (mark as injectable)
                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.is_injectable = true,
                                    p.updated_at = datetime()
                                """,
                                name=fuzzing_param, position=fuzzing_position, endpoint_path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )

                            if param_key not in created_parameters:
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                    param_name=fuzzing_param, position=fuzzing_position,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                            # Create relationship: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter
                            session.run(
                                """
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (v)-[:AFFECTS_PARAMETER]->(p)
                                """,
                                vuln_id=vuln_id, param_name=fuzzing_param, position=fuzzing_position,
                                path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Finding {finding.get('template_id', 'unknown')} processing failed: {e}")

            # =========================================================================
            # Process technology_cves - CVE, MitreData, and Capec nodes
            # =========================================================================
            technology_cves = recon_data.get("technology_cves", {})
            by_technology = technology_cves.get("by_technology", {})

            cves_created = 0
            mitre_stats = {"nodes": 0, "capec": 0, "rels": 0}  # Shared stats for MITRE processing
            cve_relationships_created = 0

            for tech_name, tech_data in by_technology.items():
                tech_product = tech_data.get("product", tech_name)
                tech_version = tech_data.get("version")  # Version from CVE lookup
                cves = tech_data.get("cves", [])

                # Extract clean technology name from key by stripping version suffix
                # e.g. "Apache HTTP Server:2.4.49" → "Apache HTTP Server"
                # e.g. "Apache/2.4.49" → "Apache"
                tech_name_clean = tech_name
                if tech_version:
                    for sep in [":", "/"]:
                        suffix = f"{sep}{tech_version}"
                        if tech_name_clean.endswith(suffix):
                            tech_name_clean = tech_name_clean[:-len(suffix)]
                            break

                for cve in cves:
                    try:
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue

                        # Create CVE node with all properties
                        cve_props = {
                            "id": cve_id,
                            "cve_id": cve_id,
                            "name": cve_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "cvss": cve.get("cvss"),
                            "severity": cve.get("severity"),
                            "description": cve.get("description"),
                            "published": cve.get("published"),
                            "source": cve.get("source"),
                            "url": cve.get("url"),
                        }

                        # Handle references (can be a list)
                        references = cve.get("references", [])
                        if references:
                            cve_props["references"] = references

                        # Remove None values
                        cve_props = {k: v for k, v in cve_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (c:CVE {id: $id})
                            SET c += $props,
                                c.updated_at = datetime()
                            """,
                            id=cve_id, props=cve_props
                        )
                        cves_created += 1

                        # Create relationship: Technology -[:HAS_KNOWN_CVE]-> CVE
                        # Match Technology node by name (case-insensitive)
                        # Matching strategies (in order):
                        # 1. Exact match by clean name (key without version suffix)
                        # 2. Exact match by NVD product name or raw key
                        # 3. CONTAINS fallback (product name within technology name)
                        # Version matching:
                        # - First try exact version match
                        # - Then fallback to version-less match (handles httpx detecting
                        #   "Apache Tomcat" without version while NVD uses "Apache-Coyote/1.1")
                        name_where = """
                            (toLower(t.name) = toLower($tech_name_clean)
                             OR toLower(t.name) = toLower($tech_product)
                             OR toLower(t.name) = toLower($tech_key)
                             OR toLower(t.name) CONTAINS toLower($tech_product))
                        """

                        matched = 0

                        if tech_version:
                            # Try 1: exact name + exact version
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where} AND t.version = $tech_version
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, tech_name_clean=tech_name_clean,
                                tech_product=tech_product, tech_key=tech_name,
                                tech_version=tech_version, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched == 0:
                            # Try 2: name match ignoring version (fallback for version mismatch)
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where}
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, tech_name_clean=tech_name_clean,
                                tech_product=tech_product, tech_key=tech_name, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched > 0:
                            cve_relationships_created += 1

                        # Process MITRE data if available
                        mitre_attack = cve.get("mitre_attack", {})
                        if mitre_attack.get("enriched"):
                            cwe_hierarchy = mitre_attack.get("cwe_hierarchy")

                            if cwe_hierarchy:
                                # Find all CWEs that have related_capec (traverse hierarchy)
                                cwes_with_capec = []
                                self._find_cwes_with_capec(cwe_hierarchy, cwes_with_capec)

                                # Create MitreData and Capec nodes for each CWE with CAPEC
                                for cwe_node in cwes_with_capec:
                                    self._process_cwe_with_capec(
                                        session, cwe_node, cve_id, user_id, project_id,
                                        stats_mitre=mitre_stats
                                    )

                            # Process additional CWE hierarchies if present
                            additional_hierarchies = mitre_attack.get("additional_cwe_hierarchies", [])
                            for add_hierarchy in additional_hierarchies:
                                cwes_with_capec = []
                                self._find_cwes_with_capec(add_hierarchy, cwes_with_capec)

                                for cwe_node in cwes_with_capec:
                                    self._process_cwe_with_capec(
                                        session, cwe_node, cve_id, user_id, project_id,
                                        stats_mitre=mitre_stats
                                    )

                    except Exception as e:
                        stats["errors"].append(f"CVE {cve.get('id', 'unknown')} processing failed: {e}")

            if cves_created > 0:
                print(f"[+][graph-db] Created {cves_created} CVE nodes")
                print(f"[+][graph-db] Created {cve_relationships_created} Technology-CVE relationships")
            if mitre_stats["nodes"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['nodes']} MitreData (CWE) nodes")
            if mitre_stats["capec"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['capec']} Capec nodes")

            # =========================================================================
            # Process security_checks - Direct IP access, WAF bypass, etc.
            # =========================================================================
            security_checks_created = 0
            waf_bypass_rels = 0

            for target_host, target_data in by_target.items():
                security_checks = target_data.get("security_checks", {})

                if not security_checks:
                    continue

                # Process direct_ip_access checks
                direct_ip_access = security_checks.get("direct_ip_access", {})
                ip_address = direct_ip_access.get("ip")
                checks = direct_ip_access.get("checks", [])

                for check in checks:
                    try:
                        check_type = check.get("check_type", "unknown")
                        severity = check.get("severity", "info")
                        url = check.get("url", "")
                        finding = check.get("finding", "")
                        evidence = check.get("evidence")
                        status_code = check.get("status_code")
                        content_length = check.get("content_length")

                        # Generate unique vulnerability ID
                        vuln_id = f"sec_{check_type}_{ip_address}_{hash(url) % 10000}"

                        # Human-readable names for check types
                        check_names = {
                            "direct_ip_http": "HTTP accessible directly via IP",
                            "direct_ip_https": "HTTPS accessible directly via IP",
                            "ip_api_exposed": "API endpoint exposed on IP without TLS",
                            "waf_bypass": "WAF bypass via direct IP access",
                            "tls_mismatch": "TLS certificate mismatch",
                            "http_on_ip": "HTTP service on direct IP",
                        }

                        # Create Vulnerability node (source='security_check')
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "security_check",
                            "type": check_type,
                            "severity": severity,
                            "name": check_names.get(check_type, f"Security check: {check_type}"),
                            "description": finding,
                            "url": url,
                            "matched_at": url,
                            "host": target_host,
                            "matched_ip": ip_address,
                            "template_id": None,
                            "is_dast_finding": False,
                        }

                        if evidence:
                            vuln_props["evidence"] = evidence
                        if status_code:
                            vuln_props["status_code"] = status_code
                        if content_length:
                            vuln_props["content_length"] = content_length

                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        security_checks_created += 1
                        stats["vulnerabilities_created"] += 1

                        # Create relationship: IP -[:HAS_VULNERABILITY]-> Vulnerability
                        # These are IP-level findings (direct IP access), so IP relationship is correct
                        if ip_address:
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
                                """,
                                address=ip_address, user_id=user_id, project_id=project_id
                            )

                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                """,
                                ip_addr=ip_address, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # For WAF bypass: create WAF_BYPASS_VIA relationship (not HAS_VULNERABILITY)
                        # The vulnerability is already connected to IP; WAF_BYPASS_VIA shows the bypass path
                        if check_type == "waf_bypass" and target_host:
                            # Subdomain -[:WAF_BYPASS_VIA]-> IP (shows which subdomain can bypass WAF via IP)
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:WAF_BYPASS_VIA {
                                    discovered_at: datetime(),
                                    evidence: $evidence
                                }]->(i)
                                """,
                                subdomain=target_host, ip_addr=ip_address,
                                evidence=evidence or "",
                                user_id=user_id, project_id=project_id
                            )
                            waf_bypass_rels += 1

                    except Exception as e:
                        stats["errors"].append(f"Security check {check_type} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} security check Vulnerability nodes")
            if waf_bypass_rels > 0:
                print(f"[+][graph-db] Created {waf_bypass_rels} WAF_BYPASS_VIA relationships")

            # =========================================================================
            # Process top-level security_checks.findings (new structure)
            # =========================================================================
            top_level_security_checks = vuln_scan_data.get("security_checks", {})
            security_findings = top_level_security_checks.get("findings", [])

            for finding in security_findings:
                try:
                    finding_type = finding.get("type", "unknown")
                    severity = finding.get("severity", "info")
                    name = finding.get("name", f"Security Issue: {finding_type}")
                    description = finding.get("description", "")
                    url = finding.get("url", "")
                    matched_ip = finding.get("matched_ip")
                    hostname = finding.get("hostname")
                    evidence = finding.get("evidence")
                    status_code = finding.get("status_code")
                    server = finding.get("server")
                    recommendation = finding.get("recommendation")
                    missing_header = finding.get("missing_header")
                    port = finding.get("port")

                    # Generate unique vulnerability ID
                    unique_key = f"{finding_type}_{url}_{matched_ip or hostname or ''}"
                    vuln_id = f"seccheck_{finding_type}_{hash(unique_key) % 100000}"

                    # Create Vulnerability node
                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "security_check",
                        "type": finding_type,
                        "severity": severity,
                        "name": name,
                        "description": description,
                        "url": url,
                        "matched_at": url,
                        "is_dast_finding": False,
                    }

                    if matched_ip:
                        vuln_props["matched_ip"] = matched_ip
                    if hostname:
                        vuln_props["hostname"] = hostname
                    if evidence:
                        vuln_props["evidence"] = evidence
                    if status_code:
                        vuln_props["status_code"] = status_code
                    if server:
                        vuln_props["server"] = server
                    if recommendation:
                        vuln_props["recommendation"] = recommendation
                    if missing_header:
                        vuln_props["missing_header"] = missing_header
                    if port:
                        vuln_props["port"] = port

                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        SET v += $props,
                            v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props
                    )
                    security_checks_created += 1
                    stats["vulnerabilities_created"] += 1

                    # Create relationships based on finding type
                    # Priority: IP (for IP-based URLs) > BaseURL (for hostname URLs) > Subdomain/Domain > IP
                    # Only ONE relationship is created per vulnerability to avoid redundancy
                    # (You can always traverse: BaseURL <- Service <- Port <- IP <- Subdomain <- Domain)
                    
                    relationship_created = False
                    
                    # For URL-based findings
                    if url and (url.startswith("http://") or url.startswith("https://")):
                        parsed = urlparse(url)
                        url_host = parsed.netloc.split(':')[0]  # Remove port if present
                        
                        # If URL host is an IP address, connect to IP node (not BaseURL)
                        # This keeps the vulnerability connected to the existing IP node in the graph
                        if _is_ip_address(url_host):
                            result = session.run(
                                """
                                MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                address=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                        else:
                            # URL host is a hostname - connect to existing BaseURL if it exists
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            result = session.run(
                                """
                                MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (bu)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                baseurl=base_url, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                            else:
                                # BaseURL doesn't exist, try Subdomain/Domain
                                result = session.run(
                                    """
                                    MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                    MATCH (v:Vulnerability {id: $vuln_id})
                                    MERGE (s)-[:HAS_VULNERABILITY]->(v)
                                    RETURN count(*) as matched
                                    """,
                                    hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                )
                                if result.single()["matched"] > 0:
                                    stats["relationships_created"] += 1
                                    relationship_created = True
                                else:
                                    # Try Domain
                                    session.run(
                                        """
                                        MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                        """,
                                        hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                    )
                                    stats["relationships_created"] += 1
                                    relationship_created = True

                    # For hostname-only findings (no URL): connect to Subdomain/Domain
                    elif hostname and not relationship_created:
                        # Try to link to Subdomain node
                        result = session.run(
                            """
                            MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            RETURN count(*) as matched
                            """,
                            hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        if result.single()["matched"] > 0:
                            stats["relationships_created"] += 1
                            relationship_created = True
                        else:
                            # Try Domain node if not a subdomain
                            session.run(
                                """
                                MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                """,
                                hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            stats["relationships_created"] += 1
                            relationship_created = True

                    # For IP-only findings (no URL, no hostname): connect to IP
                    elif matched_ip and not relationship_created:
                        session.run(
                            """
                            MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            """,
                            address=matched_ip, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        stats["relationships_created"] += 1
                        relationship_created = True

                    # For domain-only findings (e.g., SPF/DMARC missing): connect to Domain
                    if not relationship_created:
                        finding_domain = finding.get("domain")
                        if finding_domain:
                            result = session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                domain=finding_domain, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True

                except Exception as e:
                    stats["errors"].append(f"Security finding {finding.get('type', 'unknown')} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} SecurityCheck Vulnerability nodes")

            # Update Domain node with vuln_scan metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = vuln_scan_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.vuln_scan_timestamp = $scan_timestamp,
                            d.vuln_scan_dast_mode = $dast_mode,
                            d.vuln_scan_total_urls_scanned = $total_urls,
                            d.vuln_scan_dast_urls_discovered = $dast_urls,
                            d.vuln_scan_critical_count = $critical_count,
                            d.vuln_scan_high_count = $high_count,
                            d.vuln_scan_medium_count = $medium_count,
                            d.vuln_scan_low_count = $low_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        dast_mode=scan_metadata.get("dast_mode", False),
                        total_urls=scan_metadata.get("total_urls_scanned", 0),
                        dast_urls=scan_metadata.get("dast_urls_discovered", 0),
                        critical_count=summary.get("critical", 0),
                        high_count=summary.get("high", 0),
                        medium_count=summary.get("medium", 0),
                        low_count=summary.get("low", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} items out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_resource_enum(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with resource enumeration data.

        This function creates/updates:
        - Endpoint nodes (discovered paths with their HTTP methods)
        - Parameter nodes (query/body parameters)
        - Form nodes (POST forms discovered)
        - Relationships: BaseURL -[:HAS_ENDPOINT]-> Endpoint -[:HAS_PARAMETER]-> Parameter

        Args:
            recon_data: The recon JSON data containing resource_enum results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "endpoints_created": 0,
            "parameters_created": 0,
            "forms_created": 0,
            "secrets_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        resource_enum_data = recon_data.get("resource_enum", {})
        if not resource_enum_data:
            stats["errors"].append("No resource_enum data found in recon_data")
            return stats

        # Get target subdomains from scan scope - only create nodes for these
        target_subdomains = set(recon_data.get("subdomains", []))
        target_domain = recon_data.get("domain", "")

        # Also include the main domain if no subdomains specified
        if target_domain and not target_subdomains:
            target_subdomains.add(target_domain)

        def is_in_scope(base_url: str) -> bool:
            """Check if a base URL's hostname is within the scan scope."""
            if not target_subdomains:
                return True  # No filter if no subdomains defined
            parsed = urlparse(base_url)
            host = parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
            return host in target_subdomains

        with self.driver.session() as session:
            # Ensure schema is initialized

            by_base_url = resource_enum_data.get("by_base_url", {})
            forms = resource_enum_data.get("forms", [])

            # Track created items to avoid duplicates
            created_endpoints = set()
            created_parameters = set()
            skipped_out_of_scope = 0

            # Process endpoints by base URL
            for base_url, base_data in by_base_url.items():
                # Skip base URLs that are not in scan scope
                if not is_in_scope(base_url):
                    skipped_out_of_scope += 1
                    continue
                endpoints = base_data.get("endpoints", {})

                for path, endpoint_info in endpoints.items():
                    try:
                        methods = endpoint_info.get("methods", ["GET"])
                        category = endpoint_info.get("category", "other")
                        param_count = endpoint_info.get("parameter_count", {})

                        for method in methods:
                            endpoint_key = (base_url, path, method)
                            if endpoint_key in created_endpoints:
                                continue

                            # Create Endpoint node
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    e.category = $category,
                                    e.has_parameters = $has_params,
                                    e.query_param_count = $query_count,
                                    e.body_param_count = $body_count,
                                    e.path_param_count = $path_count,
                                    e.urls_found = $urls_found,
                                    e.source = 'resource_enum',
                                    e.updated_at = datetime()
                                """,
                                path=path, method=method, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                category=category,
                                has_params=param_count.get('total', 0) > 0,
                                query_count=param_count.get('query', 0),
                                body_count=param_count.get('body', 0),
                                path_count=param_count.get('path', 0),
                                urls_found=endpoint_info.get('urls_found', 1)
                            )
                            stats["endpoints_created"] += 1
                            created_endpoints.add(endpoint_key)

                            # Create BaseURL node if it doesn't exist and relationship
                            session.run(
                                """
                                MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET bu.source = 'resource_enum',
                                              bu.updated_at = datetime()
                                WITH bu
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=base_url, path=path, method=method,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create Parameter nodes
                        parameters = endpoint_info.get("parameters", {})

                        # Process query parameters
                        for param in parameters.get("query", []):
                            param_name = param.get("name")
                            if not param_name:
                                continue

                            param_key = (base_url, path, param_name, "query")
                            if param_key in created_parameters:
                                continue

                            sample_values = param.get("sample_values", [])

                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.type = $param_type,
                                    p.category = $category,
                                    p.sample_values = $sample_values,
                                    p.is_injectable = false,
                                    p.source = 'resource_enum',
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                sample_values=sample_values[:5]  # Limit sample values
                            )
                            stats["parameters_created"] += 1
                            created_parameters.add(param_key)

                            # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                            for method in methods:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="query",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                        # Process body parameters
                        for param in parameters.get("body", []):
                            param_name = param.get("name")
                            if not param_name:
                                continue

                            param_key = (base_url, path, param_name, "body")
                            if param_key in created_parameters:
                                continue

                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.type = $param_type,
                                    p.category = $category,
                                    p.input_type = $input_type,
                                    p.required = $required,
                                    p.is_injectable = false,
                                    p.source = 'resource_enum',
                                    p.updated_at = datetime()
                                """,
                                name=param_name, position="body", endpoint_path=path, baseurl=base_url,
                                user_id=user_id, project_id=project_id,
                                param_type=param.get("type", "string"),
                                category=param.get("category", "other"),
                                input_type=param.get("input_type", "text"),
                                required=param.get("required", False)
                            )
                            stats["parameters_created"] += 1
                            created_parameters.add(param_key)

                            # Create relationship for POST method (body params are only relevant for POST)
                            # First ensure the POST endpoint exists (in case it wasn't in methods list)
                            if 'POST' in methods:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'POST', baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, baseurl=base_url,
                                    param_name=param_name, position="body",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Endpoint {path} processing failed: {e}")

            # Process forms - aggregate by endpoint to collect all found_at locations
            form_data_by_endpoint = {}  # key: (baseurl, path, method) -> {found_at_pages, enctype, input_names}

            for form in forms:
                try:
                    action = form.get("action", "")
                    method = form.get("method", "POST").upper()
                    found_at = form.get("found_at", "")

                    if not action:
                        continue

                    # Parse action URL
                    parsed = urlparse(action)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""

                    if not baseurl and found_at:
                        # Extract baseurl from found_at
                        found_parsed = urlparse(found_at)
                        baseurl = f"{found_parsed.scheme}://{found_parsed.netloc}"

                    endpoint_key = (baseurl, path, method)

                    if endpoint_key not in form_data_by_endpoint:
                        form_data_by_endpoint[endpoint_key] = {
                            "found_at_pages": set(),
                            "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
                            "input_names": set(),
                            "input_types": {}  # name -> type mapping
                        }

                    # Collect found_at page
                    if found_at:
                        form_data_by_endpoint[endpoint_key]["found_at_pages"].add(found_at)

                    # Collect input names and types
                    for inp in form.get("inputs", []):
                        inp_name = inp.get("name", "")
                        inp_type = inp.get("type", "text")
                        if inp_name and inp_type != "submit":  # Skip submit buttons
                            form_data_by_endpoint[endpoint_key]["input_names"].add(inp_name)
                            form_data_by_endpoint[endpoint_key]["input_types"][inp_name] = inp_type

                except Exception as e:
                    stats["errors"].append(f"Form data collection failed: {e}")

            # Now update endpoints with aggregated form data
            for (baseurl, path, method), form_info in form_data_by_endpoint.items():
                try:
                    session.run(
                        """
                        MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                        SET e.is_form = true,
                            e.form_enctype = $enctype,
                            e.form_found_at_pages = $found_at_pages,
                            e.form_input_names = $input_names,
                            e.form_count = $form_count
                        """,
                        path=path, method=method, baseurl=baseurl,
                        user_id=user_id, project_id=project_id,
                        enctype=form_info["enctype"],
                        found_at_pages=list(form_info["found_at_pages"]),
                        input_names=list(form_info["input_names"]),
                        form_count=len(form_info["found_at_pages"])
                    )
                    stats["forms_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Form endpoint update failed: {e}")

            # ── Secret nodes from jsluice ──────────────────────────────
            jsluice_secrets = resource_enum_data.get("jsluice_secrets", [])
            created_secrets = set()

            for secret in jsluice_secrets:
                try:
                    base_url = secret.get("base_url", "")
                    if not base_url or not is_in_scope(base_url):
                        continue

                    secret_type = secret.get("kind", "unknown")
                    severity = secret.get("severity", "info")
                    source_url = secret.get("source_url", "")

                    # Extract the matched data for dedup and sample
                    data_field = secret.get("data", {})
                    if isinstance(data_field, dict):
                        data_str = json.dumps(data_field, sort_keys=True)
                    else:
                        data_str = str(data_field)

                    # Dedup hash: type + source_url + data + tenant
                    dedup_input = f"{secret_type}|{source_url}|{data_str}|{user_id}|{project_id}"
                    dedup_hash = hashlib.sha256(dedup_input.encode()).hexdigest()[:16]
                    node_id = f"secret-{user_id}-{project_id}-{dedup_hash}"

                    if node_id in created_secrets:
                        continue

                    # Redacted sample: first 6 chars + ...
                    matched = data_field.get("match", "") if isinstance(data_field, dict) else str(data_field)
                    sample = (matched[:6] + "...") if len(matched) > 6 else matched

                    scan_ts = resource_enum_data.get("scan_metadata", {}).get("scan_timestamp", "")

                    session.run(
                        """
                        MERGE (s:Secret {id: $id})
                        SET s.user_id = $user_id,
                            s.project_id = $project_id,
                            s.secret_type = $secret_type,
                            s.severity = $severity,
                            s.source = 'jsluice',
                            s.source_url = $source_url,
                            s.base_url = $base_url,
                            s.sample = $sample,
                            s.discovered_at = $discovered_at,
                            s.updated_at = datetime()
                        WITH s
                        MATCH (bu:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                        MERGE (bu)-[:HAS_SECRET]->(s)
                        """,
                        id=node_id, user_id=user_id, project_id=project_id,
                        secret_type=secret_type, severity=severity,
                        source_url=source_url, base_url=base_url,
                        sample=sample, discovered_at=scan_ts
                    )
                    created_secrets.add(node_id)
                    stats["secrets_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Secret node creation failed: {e}")

            if stats["secrets_created"] > 0:
                print(f"[+][graph-db] Created {stats['secrets_created']} Secret nodes")

            # Update Domain node with resource_enum metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = resource_enum_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.resource_enum_timestamp = $scan_timestamp,
                            d.resource_enum_total_endpoints = $total_endpoints,
                            d.resource_enum_total_parameters = $total_parameters,
                            d.resource_enum_total_forms = $total_forms,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=resource_enum_data.get("scan_metadata", {}).get("scan_timestamp"),
                        total_endpoints=summary.get("total_endpoints", 0),
                        total_parameters=summary.get("total_parameters", 0),
                        total_forms=summary.get("total_forms", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            # Connect orphaned BaseURLs to their Subdomain node
            # BaseURLs created by resource_enum may not have a Service -[:SERVES_URL]-> link
            # if httpx didn't probe that URL (e.g., port 80 redirected to HTTPS).
            # Link them to the Subdomain to prevent disconnected graph clusters.
            orphan_result = session.run(
                """
                MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})
                WHERE NOT (bu)<-[:SERVES_URL]-()
                MATCH (sub:Subdomain {user_id: $user_id, project_id: $project_id})
                WHERE bu.url CONTAINS sub.name
                MERGE (sub)-[:HAS_BASE_URL]->(bu)
                RETURN count(*) AS linked
                """,
                user_id=user_id, project_id=project_id
            )
            orphans_linked = orphan_result.single()["linked"]
            if orphans_linked > 0:
                print(f"[+][graph-db] Linked {orphans_linked} orphaned BaseURL(s) to Subdomain")
                stats["relationships_created"] += orphans_linked

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Processed {stats['forms_created']} form endpoints")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} base URLs out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    # ========== JS RECON SCANNER ==========

    def update_graph_from_js_recon(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Ingest JS Recon Scanner results into the graph.

        Graph structure:
        - Domain/BaseURL -[:HAS_JS_FILE]-> JsReconFinding(finding_type='js_file')
        - JsReconFinding(js_file) -[:HAS_JS_FINDING]-> JsReconFinding (findings)
        - JsReconFinding(js_file) -[:HAS_SECRET]-> Secret
        - JsReconFinding(js_file) -[:HAS_ENDPOINT]-> Endpoint

        Each analyzed JS file becomes a JsReconFinding node with finding_type='js_file'.
        All findings discovered in that file are linked to the file node, not directly
        to Domain/BaseURL.
        """
        js_recon_data = recon_data.get("js_recon", {})
        if not js_recon_data:
            return {"status": "skipped", "reason": "no js_recon data"}

        stats = {
            "file_nodes_created": 0,
            "findings_created": 0,
            "secrets_created": 0,
            "endpoints_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        scan_ts = js_recon_data.get("scan_metadata", {}).get("scan_timestamp", "")
        domain_name = recon_data.get('domain', '')

        def _is_uploaded(source_url: str) -> bool:
            return source_url.startswith('upload://')

        def _derive_base_url(source_url: str) -> str:
            if not source_url or _is_uploaded(source_url):
                return ''
            try:
                parsed = urlparse(source_url)
                if parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
            except Exception:
                pass
            return ''

        def _filename_from_url(url: str) -> str:
            if _is_uploaded(url):
                return url.replace('upload://', '')
            try:
                return urlparse(url).path.split('/')[-1] or url
            except Exception:
                return url

        with self.driver.session() as session:
            # --- 0. Collect all unique source JS files and create file nodes ---
            all_source_urls = set()
            for data_key in ("dependencies", "source_maps", "dom_sinks", "dev_comments"):
                for f in js_recon_data.get(data_key, []):
                    url = f.get("source_url", f.get("js_url", ""))
                    if url:
                        all_source_urls.add(url)
            for f in js_recon_data.get("frameworks", []):
                url = f.get("source_url", "")
                if url:
                    all_source_urls.add(url)
            for s in js_recon_data.get("secrets", []):
                url = s.get("source_url", "")
                if url:
                    all_source_urls.add(url)
            for ep in js_recon_data.get("endpoints", []):
                url = ep.get("source_js", "")
                if url:
                    all_source_urls.add(url)

            # Map source_url -> file node id
            file_node_ids = {}
            for source_url in all_source_urls:
                try:
                    url_hash = hashlib.sha256(source_url.encode()).hexdigest()[:16]
                    file_node_id = f"jsrf-{user_id}-{project_id}-file-{url_hash}"
                    base_url = _derive_base_url(source_url)
                    filename = _filename_from_url(source_url)

                    props = {
                        "id": file_node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "js_file",
                        "severity": "info",
                        "confidence": "high",
                        "title": filename,
                        "detail": source_url,
                        "evidence": "",
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "is_uploaded": _is_uploaded(source_url),
                        "discovered_at": scan_ts,
                    }

                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
                        id=file_node_id, props=props
                    )
                    file_node_ids[source_url] = file_node_id
                    stats["file_nodes_created"] += 1

                    # Link file node to BaseURL (pipeline) or Domain (uploaded)
                    if base_url:
                        session.run(
                            """
                            MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                            MATCH (jf:JsReconFinding {id: $fid})
                            MERGE (bu)-[:HAS_JS_FILE]->(jf)
                            """,
                            base_url=base_url, uid=user_id, pid=project_id, fid=file_node_id
                        )
                    else:
                        # Uploaded file or no base URL -- link to Domain
                        if domain_name:
                            session.run(
                                """
                                MATCH (d:Domain {name: $dname, user_id: $uid, project_id: $pid})
                                MATCH (jf:JsReconFinding {id: $fid})
                                MERGE (d)-[:HAS_JS_FILE]->(jf)
                                """,
                                dname=domain_name, uid=user_id, pid=project_id, fid=file_node_id
                            )
                        else:
                            session.run(
                                """
                                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                                WITH d LIMIT 1
                                MATCH (jf:JsReconFinding {id: $fid})
                                MERGE (d)-[:HAS_JS_FILE]->(jf)
                                """,
                                uid=user_id, pid=project_id, fid=file_node_id
                            )
                    stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS file node creation failed ({source_url}): {e}")

            def _link_to_file(session, node_id: str, node_label: str, rel_type: str, source_url: str) -> bool:
                """Link a finding/secret/endpoint to its parent JS file node."""
                file_node_id = file_node_ids.get(source_url)
                if not file_node_id:
                    return False
                if node_label not in ('JsReconFinding', 'Secret', 'Endpoint'):
                    return False
                if rel_type not in ('HAS_JS_FINDING', 'HAS_SECRET', 'HAS_ENDPOINT'):
                    return False
                session.run(
                    f"""
                    MATCH (file:JsReconFinding {{id: $fid, finding_type: 'js_file'}})
                    MATCH (n:{node_label} {{id: $nid}})
                    MERGE (file)-[:{rel_type}]->(n)
                    """,
                    fid=file_node_id, nid=node_id
                )
                return True

            # --- 1. JsReconFinding nodes (non-secret findings) ---
            finding_types = [
                ("dependencies", "dependency_confusion"),
                ("source_maps", "source_map_exposure"),
                ("dom_sinks", "dom_sink"),
                ("dev_comments", "dev_comment"),
            ]

            for data_key, finding_type in finding_types:
                for finding in js_recon_data.get(data_key, []):
                    try:
                        finding_id = finding.get("id")
                        if not finding_id:
                            continue

                        node_id = f"jsrf-{user_id}-{project_id}-{finding_id}"
                        source_url = finding.get("source_url", finding.get("js_url", ""))
                        base_url = _derive_base_url(source_url)

                        props = {
                            "id": node_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "finding_type": finding.get("finding_type", finding_type),
                            "severity": finding.get("severity", "info"),
                            "confidence": finding.get("confidence", "medium"),
                            "title": finding.get("title", finding.get("type", finding_type)),
                            "detail": finding.get("detail", finding.get("content", finding.get("description", ""))),
                            "evidence": finding.get("evidence", finding.get("pattern", finding.get("content", "")))[:500],
                            "source_url": source_url,
                            "base_url": base_url or 'upload',
                            "source": "js_recon",
                            "discovered_at": scan_ts,
                        }

                        session.run(
                            "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
                            id=node_id, props=props
                        )
                        stats["findings_created"] += 1

                        if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"JsReconFinding creation failed: {e}")

            # Framework findings
            for fw in js_recon_data.get("frameworks", []):
                try:
                    fw_id = fw.get("id")
                    if not fw_id:
                        continue
                    node_id = f"jsrf-{user_id}-{project_id}-{fw_id}"
                    source_url = fw.get("source_url", "")
                    base_url = _derive_base_url(source_url)

                    version_str = f" {fw['version']}" if fw.get('version') else ""
                    props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "finding_type": "framework",
                        "severity": "info",
                        "confidence": fw.get("confidence", "medium"),
                        "title": f"{fw['name']}{version_str}",
                        "detail": f"Framework detected: {fw['name']}{version_str}",
                        "evidence": fw.get("name", ""),
                        "source_url": source_url,
                        "base_url": base_url or 'upload',
                        "source": "js_recon",
                        "discovered_at": scan_ts,
                    }
                    session.run(
                        "MERGE (jf:JsReconFinding {id: $id}) SET jf += $props, jf.updated_at = datetime()",
                        id=node_id, props=props
                    )
                    stats["findings_created"] += 1

                    if _link_to_file(session, node_id, 'JsReconFinding', 'HAS_JS_FINDING', source_url):
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Framework finding failed: {e}")

            # --- 2. Secret nodes (source='js_recon') ---
            created_secrets = set()
            for secret in js_recon_data.get("secrets", []):
                try:
                    secret_id = secret.get("id")
                    if not secret_id:
                        continue

                    node_id = f"secret-{user_id}-{project_id}-{secret_id}"
                    if node_id in created_secrets:
                        continue

                    source_url = secret.get("source_url", "")
                    base_url = _derive_base_url(source_url)
                    validation = secret.get("validation", {})

                    session.run(
                        """
                        MERGE (s:Secret {id: $id})
                        SET s.user_id = $user_id,
                            s.project_id = $project_id,
                            s.secret_type = $secret_type,
                            s.severity = $severity,
                            s.source = 'js_recon',
                            s.source_url = $source_url,
                            s.base_url = $base_url,
                            s.sample = $sample,
                            s.confidence = $confidence,
                            s.detection_method = $detection_method,
                            s.key_type = $key_type,
                            s.validation_status = $validation_status,
                            s.matched_text = $matched_text,
                            s.validation_info = $validation_info,
                            s.discovered_at = $discovered_at,
                            s.updated_at = datetime()
                        """,
                        id=node_id, user_id=user_id, project_id=project_id,
                        secret_type=secret.get("name", "unknown"),
                        severity=secret.get("severity", "info"),
                        source_url=source_url,
                        base_url=base_url or 'upload',
                        sample=secret.get("redacted_value", ""),
                        matched_text=secret.get("matched_text", ""),
                        confidence=secret.get("confidence", "medium"),
                        detection_method=secret.get("detection_method", "regex"),
                        key_type=secret.get("category", ""),
                        validation_status=validation.get("status", "unvalidated"),
                        validation_info=json.dumps(validation) if validation else "",
                        discovered_at=scan_ts,
                    )
                    created_secrets.add(node_id)
                    stats["secrets_created"] += 1

                    if _link_to_file(session, node_id, 'Secret', 'HAS_SECRET', source_url):
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS Recon Secret node failed: {e}")

            # --- 3. Endpoint nodes (source='js_recon') ---
            created_endpoints = set()
            for ep in js_recon_data.get("endpoints", []):
                try:
                    path = ep.get("path", "")
                    method = ep.get("method", "GET")
                    source_js = ep.get("source_js", "")
                    base_url = ep.get("base_url", "")
                    is_upload = _is_uploaded(source_js)

                    if not base_url and source_js and not is_upload:
                        base_url = _derive_base_url(source_js)

                    if not path:
                        continue
                    if not base_url and not is_upload:
                        continue

                    ep_key = f"{method}:{path}:{base_url or 'upload'}"
                    if ep_key in created_endpoints:
                        continue
                    created_endpoints.add(ep_key)

                    effective_baseurl = base_url or 'upload'

                    session.run(
                        """
                        MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $uid, project_id: $pid})
                        ON CREATE SET e.source = 'js_recon',
                            e.category = $category,
                            e.full_url = $full_url,
                            e.endpoint_type = $ep_type,
                            e.updated_at = datetime()
                        ON MATCH SET e.js_recon_source = true,
                            e.endpoint_type = COALESCE(e.endpoint_type, $ep_type),
                            e.full_url = COALESCE(e.full_url, $full_url),
                            e.updated_at = datetime()
                        """,
                        path=path, method=method, baseurl=effective_baseurl,
                        uid=user_id, pid=project_id,
                        category=ep.get("category", "endpoint"),
                        full_url=ep.get("full_url", ""),
                        ep_type=ep.get("type", "rest"),
                    )
                    stats["endpoints_created"] += 1

                    if _link_to_file(session, node_id, 'Endpoint', 'HAS_ENDPOINT', source_js):
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"JS Recon Endpoint node failed: {e}")

        print(f"[+][graph-db] JS Recon: {stats['file_nodes_created']} files, "
              f"{stats['findings_created']} findings, {stats['secrets_created']} secrets, "
              f"{stats['endpoints_created']} endpoints, {stats['relationships_created']} relationships")
        if stats["errors"]:
            print(f"[!][graph-db] JS Recon: {len(stats['errors'])} errors")

        return stats

    # ---- Partial Recon Methods ----

    def create_user_input_node(self, domain: str, user_input_data: dict, user_id: str, project_id: str) -> str:
        """
        Create a UserInput node for partial recon user-provided values.

        Args:
            domain: Root domain to attach the UserInput to
            user_input_data: Dict with keys: id, input_type, values, tool_id
            user_id: Tenant user ID
            project_id: Tenant project ID

        Returns:
            The UserInput node ID
        """
        node_id = user_input_data["id"]

        with self.driver.session() as session:
            # Create UserInput node
            session.run(
                """
                MERGE (ui:UserInput {id: $id})
                SET ui.input_type = $input_type,
                    ui.values = $values,
                    ui.tool_id = $tool_id,
                    ui.source = 'user',
                    ui.status = 'running',
                    ui.created_at = datetime(),
                    ui.user_id = $user_id,
                    ui.project_id = $project_id
                """,
                id=node_id,
                input_type=user_input_data.get("input_type", "subdomains"),
                values=user_input_data.get("values", []),
                tool_id=user_input_data.get("tool_id", ""),
                user_id=user_id,
                project_id=project_id,
            )

            # Connect to Domain node (create Domain if needed via MERGE)
            session.run(
                """
                MERGE (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                ON CREATE SET d.updated_at = datetime()
                WITH d
                MATCH (ui:UserInput {id: $ui_id})
                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                """,
                domain=domain, user_id=user_id, project_id=project_id, ui_id=node_id,
            )

            print(f"[+][graph-db] Created UserInput node {node_id} for {domain}")

        return node_id

    def update_user_input_status(self, user_input_id: str, status: str, stats: dict = None) -> None:
        """Update the status and stats of a UserInput node."""
        with self.driver.session() as session:
            props = {"status": status, "updated_at": datetime.now().isoformat()}
            if status == "completed":
                props["completed_at"] = datetime.now().isoformat()
            if stats:
                props["stats"] = json.dumps(stats)

            session.run(
                """
                MATCH (ui:UserInput {id: $id})
                SET ui += $props
                """,
                id=user_input_id, props=props,
            )

    def update_graph_from_partial_discovery(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
        user_input_id: str = None,
    ) -> dict:
        """
        Update Neo4j graph with results from a partial subdomain discovery run.

        Creates Subdomain, IP, DNSRecord nodes and relationships using the same
        MERGE patterns as update_graph_from_domain_discovery(). Optionally links
        all produced nodes to a UserInput node via PRODUCED relationships.

        Args:
            recon_data: Discovery result dict (same format as domain_recon output)
            user_id: Tenant user ID
            project_id: Tenant project ID
            user_input_id: Optional UserInput node ID to link produced nodes

        Returns:
            Stats dict with counts
        """

        stats = {
            "subdomains_total": 0,
            "subdomains_new": 0,
            "subdomains_existing": 0,
            "ips_total": 0,
            "ips_new": 0,
            "dns_records_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        subdomains = recon_data.get("subdomains", [])
        dns_data = recon_data.get("dns") or {}
        domain = recon_data.get("domain", "")

        if not domain:
            stats["errors"].append("No domain found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure Domain node exists
            session.run(
                """
                MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                ON CREATE SET d.updated_at = datetime()
                ON MATCH SET d.updated_at = datetime()
                """,
                name=domain, user_id=user_id, project_id=project_id,
            )

            subdomain_dns = dns_data.get("subdomains", {}) if dns_data else {}
            domain_dns = dns_data.get("domain", {}) if dns_data else {}
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # Get DNS info
                    if subdomain == domain:
                        subdomain_info = domain_dns
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)
                    sub_status = subdomain_status_map.get(subdomain)

                    # Check if subdomain already exists (for stats tracking)
                    result = session.run(
                        """
                        OPTIONAL MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        RETURN s IS NOT NULL AS exists
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                    )
                    existed = result.single()["exists"]

                    # MERGE subdomain node (same pattern as full recon)
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=sub_status,
                    )
                    stats["subdomains_total"] += 1
                    if existed:
                        stats["subdomains_existing"] += 1
                    else:
                        stats["subdomains_new"] += 1

                    # Relationships: Subdomain <-> Domain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        domain=domain, sub=subdomain, uid=user_id, pid=project_id,
                    )
                    stats["relationships_created"] += 1

                    # Link to UserInput via PRODUCED
                    if user_input_id:
                        session.run(
                            """
                            MATCH (ui:UserInput {id: $ui_id})
                            MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                            MERGE (ui)-[:PRODUCED]->(s)
                            """,
                            ui_id=user_input_id, name=subdomain, uid=user_id, pid=project_id,
                        )

                    # Create IP nodes from resolved IPs
                    records = subdomain_info.get("records", {})
                    ips_data = subdomain_info.get("ips", {})

                    for ip_version in ["ipv4", "ipv6"]:
                        for ip_addr in ips_data.get(ip_version, []):
                            if not ip_addr:
                                continue
                            try:
                                # Check if IP already exists
                                ip_exists = session.run(
                                    """
                                    OPTIONAL MATCH (i:IP {address: $address, user_id: $uid, project_id: $pid})
                                    RETURN i IS NOT NULL AS exists
                                    """,
                                    address=ip_addr, uid=user_id, pid=project_id,
                                ).single()["exists"]

                                session.run(
                                    """
                                    MERGE (i:IP {address: $address, user_id: $uid, project_id: $pid})
                                    SET i.version = $version,
                                        i.updated_at = datetime()
                                    """,
                                    address=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version,
                                )
                                stats["ips_total"] += 1
                                if not ip_exists:
                                    stats["ips_new"] += 1

                                # Subdomain -[:RESOLVES_TO]-> IP
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rt}]->(i)
                                    """,
                                    sub=subdomain, ip=ip_addr, rt=record_type,
                                    uid=user_id, pid=project_id,
                                )
                                stats["relationships_created"] += 1

                                # Link IP to UserInput
                                if user_input_id:
                                    session.run(
                                        """
                                        MATCH (ui:UserInput {id: $ui_id})
                                        MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (ui)-[:PRODUCED]->(i)
                                        """,
                                        ui_id=user_input_id, addr=ip_addr,
                                        uid=user_id, pid=project_id,
                                    )
                            except Exception as e:
                                stats["errors"].append(f"IP {ip_addr} failed: {e}")

                    # Create DNSRecord nodes (non-A/AAAA)
                    for record_type, record_values in records.items():
                        if not record_values or record_type in ["A", "AAAA"]:
                            continue
                        if not isinstance(record_values, list):
                            record_values = [record_values]
                        for value in record_values:
                            if not value:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $sub, user_id: $uid, project_id: $pid})
                                    SET dns.updated_at = datetime()
                                    """,
                                    type=record_type, value=str(value), sub=subdomain,
                                    uid=user_id, pid=project_id,
                                )
                                stats["dns_records_created"] += 1

                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                    """,
                                    sub=subdomain, type=record_type, value=str(value),
                                    uid=user_id, pid=project_id,
                                )
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!][graph-db] Partial discovery: {subdomain} failed: {e}")

            # Count new IPs (approximate -- count those without prior discovered_at)
            # For simplicity, ips_new tracking is done at MERGE time above

            print(f"[+][graph-db] Partial discovery: {stats['subdomains_total']} subdomains "
                  f"({stats['subdomains_new']} new, {stats['subdomains_existing']} existing)")
            print(f"[+][graph-db] Partial discovery: {stats['ips_total']} IPs, "
                  f"{stats['dns_records_created']} DNS records")
            if stats["errors"]:
                print(f"[!][graph-db] Partial discovery: {len(stats['errors'])} errors")

        return stats

    def get_graph_inputs_for_tool(self, tool_id: str, user_id: str, project_id: str) -> dict:
        """
        Query existing graph data to provide inputs for a partial recon tool.

        Args:
            tool_id: Tool identifier (e.g., "SubdomainDiscovery")
            user_id: Tenant user ID
            project_id: Tenant project ID

        Returns:
            Dict with tool-specific inputs from the existing graph
        """
        with self.driver.session() as session:
            if tool_id == "SubdomainDiscovery":
                # Get the domain and count existing subdomains
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN d.name AS domain, count(s) AS subdomain_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["subdomain_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id in ("Naabu", "Masscan"):
                # Get domain, subdomain count, and IP count for port scanning
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
                    WITH d, count(DISTINCT s) AS sub_count,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count
                    RETURN d.name AS domain, sub_count, ip_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Nmap":
                # Get domain, IPs with ports, and port count for Nmap service detection
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
                    WITH d, count(DISTINCT s) AS sub_count,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count,
                         count(DISTINCT p) + count(DISTINCT dp) AS port_count
                    RETURN d.name AS domain, sub_count, ip_count, port_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "existing_ports_count": record["port_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Httpx":
                # Get domain, subdomains, IPs, ports, and existing BaseURLs for HTTP probing
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
                    OPTIONAL MATCH (p)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
                    OPTIONAL MATCH (dp)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(dbu:BaseURL)
                    WITH d, count(DISTINCT s) AS sub_count,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count,
                         count(DISTINCT p) + count(DISTINCT dp) AS port_count,
                         count(DISTINCT bu) + count(DISTINCT dbu) AS baseurl_count
                    RETURN d.name AS domain, sub_count, ip_count, port_count, baseurl_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "existing_ports_count": record["port_count"] or 0,
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id in ("Gau", "ParamSpider"):
                # Get domain and subdomain count for passive URL discovery tools
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    WITH d, collect(DISTINCT s.name) AS subdomains
                    RETURN d.name AS domain, subdomains, size(subdomains) AS sub_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "JsRecon":
                # Get domain, BaseURL count/list, and Endpoint count for JS Recon
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    WITH d
                    OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WITH d, collect(DISTINCT b.url) AS baseurls
                    OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                    WITH d, baseurls, count(DISTINCT e) AS endpoint_count
                    RETURN d.name AS domain, baseurls, size(baseurls) AS baseurl_count, endpoint_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": 0,
                    "existing_baseurls": record["baseurls"] or [],
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "existing_endpoints_count": record["endpoint_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Nuclei":
                # Get domain, BaseURL count/list, and Endpoint count for Nuclei vuln scanning
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    WITH d
                    OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WITH d, collect(DISTINCT b.url) AS baseurls
                    OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                    WITH d, baseurls, count(DISTINCT e) AS endpoint_count
                    RETURN d.name AS domain, baseurls, size(baseurls) AS baseurl_count, endpoint_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": 0,
                    "existing_baseurls": record["baseurls"] or [],
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "existing_endpoints_count": record["endpoint_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Shodan":
                # Get domain, subdomain names (for IP attach-to dropdown), and IP count
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
                    WITH d, collect(DISTINCT s.name) AS subdomains,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count
                    RETURN d.name AS domain, subdomains, size(subdomains) AS sub_count, ip_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Urlscan":
                # Get domain and subdomain count for URLScan passive enrichment
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN d.name AS domain, count(s) AS subdomain_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["subdomain_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Uncover":
                # Get domain and subdomain count for Uncover multi-engine expansion
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN d.name AS domain, count(s) AS subdomain_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["subdomain_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "OsintEnrichment":
                # Get domain, subdomain names (for dropdown), and IP count for OSINT enrichment
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
                    WITH d, collect(DISTINCT s.name) AS subdomains,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count
                    RETURN d.name AS domain, subdomains, size(subdomains) AS sub_count, ip_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            return {"error": f"Unknown tool_id: {tool_id}"}

