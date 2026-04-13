"""
Partial Recon - Entry point for per-tool partial reconnaissance runs.

This script is invoked by the orchestrator as a container command
(instead of main.py) for running individual recon phases on demand.

Configuration is passed via a JSON file whose path is in the
PARTIAL_RECON_CONFIG environment variable.

Currently supported tool_ids:
  - SubdomainDiscovery: runs discover_subdomains() from domain_recon.py
  - Naabu: runs run_port_scan() from port_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Nmap: runs run_nmap_scan() from nmap_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Httpx: runs run_http_probe() from http_probe.py
  - Katana: runs run_katana_crawler() from helpers/resource_enum
  - Hakrawler: runs run_hakrawler_crawler() from helpers
  - Ffuf: runs run_ffuf_discovery() from helpers/resource_enum
  - JsRecon: runs run_js_recon() from js_recon.py
  - Shodan: runs run_shodan_enrichment() from shodan_enrich.py
  - Urlscan: runs run_urlscan_discovery_only() from urlscan_enrich.py
  - OsintEnrichment: runs OSINT sub-tools (Censys, FOFA, OTX, etc.) in parallel
"""

import os
import sys
import json
import uuid
from pathlib import Path
from datetime import datetime

# Add project root to path (same pattern as main.py)
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_config() -> dict:
    """Load partial recon configuration from JSON file."""
    config_path = os.environ.get("PARTIAL_RECON_CONFIG")
    if not config_path:
        print("[!][Partial] PARTIAL_RECON_CONFIG not set")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!][Partial] Failed to load config from {config_path}: {e}")
        sys.exit(1)


def run_subdomain_discovery(config: dict) -> None:
    """
    Run partial subdomain discovery using the exact same functions
    as the full pipeline in domain_recon.py.
    """
    from recon.domain_recon import discover_subdomains, resolve_all_dns, run_puredns_resolve
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    # Fetch settings via the same API conversion as main.py (camelCase -> UPPER_SNAKE_CASE)
    # This ensures tool toggles and parameters are in the correct format
    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Subdomain Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    if user_inputs:
        print(f"[*][Partial Recon] User inputs: {len(user_inputs)} custom subdomains")
    print(f"{'=' * 50}\n")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    user_input_id = None
    needs_user_input = bool(user_inputs)

    # Run the standard subdomain discovery (same function as full pipeline)
    print(f"[*][Partial Recon] Running subdomain discovery tools...")
    result = discover_subdomains(
        domain=domain,
        anonymous=settings.get("USE_TOR_FOR_RECON", False),
        bruteforce=settings.get("USE_BRUTEFORCE_FOR_SUBDOMAINS", False),
        resolve=True,
        save_output=False,  # Don't save intermediate JSON
        project_id=project_id,
        settings=settings,
    )

    discovered_subs = result.get("subdomains", [])
    print(f"[+][Partial Recon] Discovery found {len(discovered_subs)} subdomains")

    # Merge user-added subdomains into the result
    if user_inputs:
        # Filter user inputs: must be valid subdomains of the target domain
        valid_user_subs = []
        for sub in user_inputs:
            sub = sub.strip().lower()
            if sub and (sub == domain or sub.endswith("." + domain)):
                valid_user_subs.append(sub)
            elif sub:
                print(f"[!][Partial Recon] Skipping invalid user input: {sub} (not a subdomain of {domain})")

        # Add user subdomains not already in the discovered list
        new_user_subs = [s for s in valid_user_subs if s not in discovered_subs]
        if new_user_subs:
            print(f"[*][Partial Recon] Adding {len(new_user_subs)} user-provided subdomains")
            all_subs = sorted(set(discovered_subs + new_user_subs))

            # Run puredns wildcard filtering on the new combined list
            all_subs = run_puredns_resolve(all_subs, domain, settings)

            # Re-resolve DNS for the full combined list
            print(f"[*][Partial Recon] Resolving DNS for {len(all_subs)} subdomains...")
            result["subdomains"] = all_subs
            result["subdomain_count"] = len(all_subs)
            result["dns"] = resolve_all_dns(domain, all_subs)

            # Rebuild subdomain status map
            subdomain_status_map = {}
            if result["dns"]:
                dns_subs = result["dns"].get("subdomains", {})
                for s in all_subs:
                    info = result["dns"].get("domain", {}) if s == domain else dns_subs.get(s, {})
                    if info.get("has_records", False):
                        subdomain_status_map[s] = "resolved"
            result["subdomain_status_map"] = subdomain_status_map

    final_count = len(result.get("subdomains", []))
    print(f"[+][Partial Recon] Final subdomain count: {final_count}")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # Create UserInput node NOW (after scan succeeded) if needed
                if needs_user_input:
                    user_input_id = str(uuid.uuid4())
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "subdomains",
                            "values": user_inputs,
                            "tool_id": "SubdomainDiscovery",
                        },
                        user_id=user_id,
                        project_id=project_id,
                    )

                stats = graph_client.update_graph_from_partial_discovery(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                    user_input_id=user_input_id,
                )

                if user_input_id:
                    graph_client.update_user_input_status(
                        user_input_id, "completed", stats
                    )
                    print(f"[+][Partial Recon] Created UserInput + linked to discovery results")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Subdomain discovery completed successfully")


def _classify_ip(address: str, version: str = None) -> str:
    """Return 'ipv4' or 'ipv6' for an IP address."""
    if version:
        v = version.lower()
        if "4" in v:
            return "ipv4"
        if "6" in v:
            return "ipv6"
    import ipaddress as _ipaddress
    try:
        return "ipv4" if _ipaddress.ip_address(address).version == 4 else "ipv6"
    except ValueError:
        return "ipv4"


def _build_recon_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_port_scan expects.

    Returns a dict with 'domain' and 'dns' keys matching the structure
    produced by domain_recon.py (domain IPs + subdomain IPs).
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query domain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                RETURN i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                recon_data["dns"]["domain"]["ips"][bucket].append(addr)

            if (recon_data["dns"]["domain"]["ips"]["ipv4"]
                    or recon_data["dns"]["domain"]["ips"]["ipv6"]):
                recon_data["dns"]["domain"]["has_records"] = True

            # Query subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                RETURN s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                sub = record["subdomain"]
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])

                if sub not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][sub] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                recon_data["dns"]["subdomains"][sub]["ips"][bucket].append(addr)

    return recon_data


def _resolve_hostname(hostname: str) -> dict:
    """
    Resolve a hostname to IPs via socket.getaddrinfo.

    Returns {"ipv4": [...], "ipv6": [...]}.
    """
    import socket
    ips = {"ipv4": [], "ipv6": []}
    try:
        results = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in results:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in ips["ipv4"]:
                ips["ipv4"].append(addr)
            elif family == socket.AF_INET6 and addr not in ips["ipv6"]:
                ips["ipv6"].append(addr)
    except socket.gaierror:
        pass
    return ips


def _is_ip_or_cidr(value: str) -> bool:
    """Check if value is an IP address or CIDR range."""
    import ipaddress as _ipaddress
    try:
        if "/" in value:
            _ipaddress.ip_network(value, strict=False)
        else:
            _ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_HOSTNAME_RE = None

def _is_valid_hostname(value: str) -> bool:
    """Check if value looks like a valid hostname/subdomain."""
    global _HOSTNAME_RE
    if _HOSTNAME_RE is None:
        import re
        _HOSTNAME_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(_HOSTNAME_RE.match(value))


def _run_port_scanner(config: dict, tool_id: str, scan_fn, label: str,
                      pre_settings: dict = None, normalize_fn=None) -> None:
    """
    Shared logic for port-scanner partial recon (Naabu, Masscan, etc.).

    Args:
        config: Partial recon config dict from orchestrator.
        tool_id: Tool identifier for UserInput nodes (e.g. "Naabu", "Masscan").
        scan_fn: The scan function to call (e.g. run_port_scan, run_masscan_scan).
        label: Display label for log messages.
        pre_settings: Settings to force before calling scan_fn (e.g. MASSCAN_ENABLED).
        normalize_fn: Optional post-scan normalizer -- receives recon_data, mutates in place.
    """
    import ipaddress as _ipaddress
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    if pre_settings:
        settings.update(pre_settings)

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Port Scanning ({label})")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets (structured format from new modal, or legacy flat list)
    user_targets = config.get("user_targets") or {}
    user_ips = []
    user_hostnames = []
    ip_attach_to = None
    user_input_id = None

    if user_targets:
        # New structured format: {subdomains: [...], ips: [...], ip_attach_to: "..." | null}
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                user_hostnames.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid subdomain: {entry}")

        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

    elif user_inputs:
        # Legacy flat list fallback: classify each entry
        for entry in user_inputs:
            entry = entry.strip().lower()
            if not entry:
                continue
            if _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif _is_valid_hostname(entry):
                user_hostnames.append(entry)
            else:
                print(f"[!][Partial Recon] Skipping invalid target: {entry}")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_hostnames:
        print(f"[+][Partial Recon] Validated {len(user_hostnames)} custom hostnames")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_ips and not ip_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs and subdomains)...")
        recon_data = _build_recon_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # STEP 1: Resolve user-provided hostnames FIRST (before IP injection)
    resolved_hostnames = {}
    if user_hostnames:
        print(f"[*][Partial Recon] Resolving {len(user_hostnames)} user-provided hostnames...")
        for hostname in user_hostnames:
            if hostname in recon_data["dns"]["subdomains"]:
                print(f"[*][Partial Recon] {hostname} already in graph, skipping")
                continue
            ips = _resolve_hostname(hostname)
            if ips["ipv4"] or ips["ipv6"]:
                recon_data["dns"]["subdomains"][hostname] = {
                    "ips": ips,
                    "has_records": True,
                }
                resolved_hostnames[hostname] = ips
                print(f"[+][Partial Recon] Resolved {hostname} -> {ips['ipv4'] + ips['ipv6']}")
            else:
                print(f"[!][Partial Recon] Could not resolve {hostname}, skipping")

        # Create Subdomain + IP + relationships in Neo4j for newly resolved hostnames
        if resolved_hostnames:
            print(f"[*][Partial Recon] Creating graph nodes for {len(resolved_hostnames)} user hostnames...")
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        driver = graph_client.driver
                        with driver.session() as session:
                            for hostname, ips in resolved_hostnames.items():
                                # MERGE Subdomain node
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                                    SET s.has_dns_records = true,
                                        s.status = coalesce(s.status, 'resolved'),
                                        s.discovered_at = coalesce(s.discovered_at, datetime()),
                                        s.updated_at = datetime(),
                                        s.source = 'partial_recon_user_input'
                                    """,
                                    name=hostname, uid=user_id, pid=project_id,
                                )
                                # MERGE Domain <-> Subdomain relationships
                                session.run(
                                    """
                                    MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    domain=domain, sub=hostname, uid=user_id, pid=project_id,
                                )
                                # MERGE IP nodes + RESOLVES_TO relationships
                                for ip_version in ("ipv4", "ipv6"):
                                    for ip_addr in ips.get(ip_version, []):
                                        session.run(
                                            """
                                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            SET i.version = $version, i.updated_at = datetime()
                                            """,
                                            addr=ip_addr, uid=user_id, pid=project_id, version=ip_version,
                                        )
                                        record_type = "A" if ip_version == "ipv4" else "AAAA"
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                            """,
                                            sub=hostname, addr=ip_addr, uid=user_id, pid=project_id, rtype=record_type,
                                        )
                                print(f"[+][Partial Recon] Created graph nodes for {hostname}")
                    else:
                        print("[!][Partial Recon] Neo4j not reachable, skipping subdomain node creation")
            except Exception as e:
                print(f"[!][Partial Recon] Failed to create subdomain nodes: {e}")

    # STEP 2: Inject user-provided IPs/CIDRs into recon_data (AFTER hostname resolution)
    # If ip_attach_to is set, inject into that subdomain's entry; otherwise into domain IPs
    # Safety: if ip_attach_to points to a subdomain that failed resolution, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        # Check if the subdomain exists in Neo4j graph already
        _sub_exists = False
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as _gc:
                if _gc.verify_connection():
                    with _gc.driver.session() as _s:
                        _res = _s.run(
                            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s LIMIT 1",
                            name=ip_attach_to, uid=user_id, pid=project_id,
                        )
                        _sub_exists = _res.single() is not None
        except Exception:
            pass
        if not _sub_exists:
            print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found in graph, falling back to generic UserInput for IPs")
            ip_attach_to = None
            needs_user_input = bool(user_ips)

    user_ip_addrs = []
    if user_ips:
        if ip_attach_to:
            # Ensure the target subdomain entry exists (may have been created by hostname resolution above)
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
            print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs -> {ip_attach_to}")
        else:
            target_ips = recon_data["dns"]["domain"]["ips"]
            print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs -> domain (generic)")

        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        bucket = _classify_ip(addr)
                        if addr not in target_ips[bucket]:
                            target_ips[bucket].append(addr)
                        user_ip_addrs.append(addr)
                    if not ip_attach_to:
                        recon_data["dns"]["domain"]["has_records"] = True
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                bucket = _classify_ip(ip_str)
                if ip_str not in target_ips[bucket]:
                    target_ips[bucket].append(ip_str)
                    if not ip_attach_to:
                        recon_data["dns"]["domain"]["has_records"] = True
                user_ip_addrs.append(ip_str)

    # Check we have targets
    domain_ips = recon_data["dns"]["domain"]["ips"]
    sub_count = len(recon_data["dns"]["subdomains"])
    ip_count = len(domain_ips["ipv4"]) + len(domain_ips["ipv6"])
    for sub_data in recon_data["dns"]["subdomains"].values():
        ip_count += len(sub_data["ips"]["ipv4"]) + len(sub_data["ips"]["ipv6"])

    if ip_count == 0:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets resolved).")
        print("[!][Partial Recon] Run Subdomain Discovery first, or provide IPs/subdomains manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {ip_count} IPs across {sub_count} subdomains + domain")

    # Run scan (same function as full pipeline)
    print(f"[*][Partial Recon] Running {label} port scan...")
    result = scan_fn(recon_data, output_file=None, settings=settings)

    # Normalize scan results if needed (e.g. masscan_scan -> port_scan)
    if normalize_fn:
        normalize_fn(result)

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_port_scan(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            # IPs attached to a subdomain: create RESOLVES_TO relationships
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif needs_user_input:
                            # Generic IPs: create UserInput node NOW (after scan succeeded) and link
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": tool_id,
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for ip_addr in user_ip_addrs:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    ui_id=user_input_id, addr=ip_addr, uid=user_id, pid=project_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked {len(user_ip_addrs)} IPs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] {label} port scanning completed successfully")


def _normalize_masscan_result(result: dict) -> None:
    """Copy masscan_scan data into port_scan key for update_graph_from_port_scan()."""
    masscan_data = result.get("masscan_scan", {})
    if masscan_data:
        result["port_scan"] = {
            "scan_metadata": masscan_data.get("scan_metadata", {}),
            "by_host": dict(masscan_data.get("by_host", {})),
            "by_ip": dict(masscan_data.get("by_ip", {})),
            "all_ports": list(masscan_data.get("all_ports", [])),
            "ip_to_hostnames": dict(masscan_data.get("ip_to_hostnames", {})),
            "summary": dict(masscan_data.get("summary", {})),
        }


def run_naabu(config: dict) -> None:
    """Run partial port scanning using Naabu (run_port_scan from port_scan.py)."""
    from recon.port_scan import run_port_scan
    _run_port_scanner(config, tool_id="Naabu", scan_fn=run_port_scan, label="Naabu")


def run_masscan(config: dict) -> None:
    """Run partial port scanning using Masscan (run_masscan_scan from masscan_scan.py)."""
    from recon.masscan_scan import run_masscan_scan
    _run_port_scanner(
        config, tool_id="Masscan", scan_fn=run_masscan_scan, label="Masscan",
        pre_settings={"MASSCAN_ENABLED": True},
        normalize_fn=_normalize_masscan_result,
    )


def _build_port_scan_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_nmap_scan expects.

    Returns a dict with 'port_scan' key containing by_ip, by_host, and
    ip_to_hostnames structures matching what build_nmap_targets() consumes.
    Also populates a 'dns' section for user-IP linking logic.
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "port_scan": {
            "by_ip": {},
            "by_host": {},
            "ip_to_hostnames": {},
            "all_ports": [],
            "scan_metadata": {"scanners": ["naabu"]},
            "summary": {},
        },
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
    }

    all_ports_set = set()

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query domain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                ip_addr = record["ip"]
                ip_version = record["version"]
                ports_data = record["ports"]

                # Populate dns section
                bucket = _classify_ip(ip_addr, ip_version)
                if ip_addr not in recon_data["dns"]["domain"]["ips"][bucket]:
                    recon_data["dns"]["domain"]["ips"][bucket].append(ip_addr)
                    recon_data["dns"]["domain"]["has_records"] = True

                # Filter out null ports (from OPTIONAL MATCH when no ports exist)
                port_numbers = []
                port_details = []
                for p in ports_data:
                    if p["number"] is not None:
                        pnum = int(p["number"])
                        port_numbers.append(pnum)
                        all_ports_set.add(pnum)
                        port_details.append({
                            "port": pnum,
                            "protocol": p["protocol"] or "tcp",
                            "service": "",
                        })

                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr,
                        "hostnames": [domain],
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if domain not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(domain)

                # Populate by_host for domain IPs (build_nmap_targets reads by_host too)
                if domain not in recon_data["port_scan"]["by_host"]:
                    recon_data["port_scan"]["by_host"][domain] = {
                        "host": domain,
                        "ip": ip_addr,
                        "ports": list(port_numbers),
                        "port_details": list(port_details),
                    }
                else:
                    existing = recon_data["port_scan"]["by_host"][domain]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

            # Query subdomain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN s.name AS subdomain, i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                subdomain = record["subdomain"]
                ip_addr = record["ip"]
                ip_version = record["version"]
                ports_data = record["ports"]

                # Populate dns section
                bucket = _classify_ip(ip_addr, ip_version)
                if subdomain not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][subdomain] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                sub_ips = recon_data["dns"]["subdomains"][subdomain]["ips"]
                if ip_addr not in sub_ips[bucket]:
                    sub_ips[bucket].append(ip_addr)

                # Filter out null ports
                port_numbers = []
                port_details = []
                for p in ports_data:
                    if p["number"] is not None:
                        pnum = int(p["number"])
                        port_numbers.append(pnum)
                        all_ports_set.add(pnum)
                        port_details.append({
                            "port": pnum,
                            "protocol": p["protocol"] or "tcp",
                            "service": "",
                        })

                # Populate by_ip
                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr,
                        "hostnames": [subdomain],
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    if subdomain not in existing["hostnames"]:
                        existing["hostnames"].append(subdomain)
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                # Populate by_host
                if subdomain not in recon_data["port_scan"]["by_host"]:
                    recon_data["port_scan"]["by_host"][subdomain] = {
                        "host": subdomain,
                        "ip": ip_addr,
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_host"][subdomain]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                # Populate ip_to_hostnames
                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if subdomain not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(subdomain)

    recon_data["port_scan"]["all_ports"] = sorted(all_ports_set)
    return recon_data


def run_nmap(config: dict) -> None:
    """
    Run partial Nmap service detection + NSE vulnerability scanning
    using the exact same function as the full pipeline in nmap_scan.py.

    Nmap runs on IPs+Ports already in the graph (from prior port scanning).
    It enriches existing Port nodes with product/version/CPE and creates
    Technology, Vulnerability, and CVE nodes from NSE script findings.
    """
    import ipaddress as _ipaddress
    from recon.nmap_scan import run_nmap_scan
    from recon.main import merge_nmap_into_port_scan
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Nmap since the user explicitly chose to run it
    settings['NMAP_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Nmap Service Detection + NSE Vuln Scripts")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Nmap accepts IPs and Ports
    user_targets = config.get("user_targets") or {}
    user_ips = []           # validated IPs and CIDRs
    user_ports = []         # validated port numbers
    ip_attach_to = None     # subdomain to attach IPs to (None = UserInput)
    user_input_id = None    # only created when IPs are generic (no subdomain attachment)

    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        for entry in user_targets.get("ports", []):
            try:
                port = int(entry)
                if 1 <= port <= 65535:
                    user_ports.append(port)
                else:
                    print(f"[!][Partial Recon] Skipping out-of-range port: {entry}")
            except (ValueError, TypeError):
                print(f"[!][Partial Recon] Skipping invalid port: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

    elif user_inputs:
        # Legacy flat list fallback: only accept IPs
        for entry in user_inputs:
            entry = entry.strip()
            if not entry:
                continue
            if _is_ip_or_cidr(entry):
                user_ips.append(entry)
            else:
                print(f"[!][Partial Recon] Skipping non-IP target (Nmap only accepts IPs): {entry}")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_ports:
        print(f"[+][Partial Recon] Validated {len(user_ports)} custom ports: {user_ports}")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_ips and not ip_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs, ports, subdomains)...")
        recon_data = _build_port_scan_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "port_scan": {
                "by_ip": {}, "by_host": {}, "ip_to_hostnames": {},
                "all_ports": [], "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
            },
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Inject user-provided IPs/CIDRs into port_scan structure
    # Safety: if ip_attach_to points to a subdomain that failed resolution, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        # Check if the subdomain exists in Neo4j graph already
        _sub_exists = False
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as _gc:
                if _gc.verify_connection():
                    with _gc.driver.session() as _s:
                        _res = _s.run(
                            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s LIMIT 1",
                            name=ip_attach_to, uid=user_id, pid=project_id,
                        )
                        _sub_exists = _res.single() is not None
        except Exception:
            pass
        if not _sub_exists:
            print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found in graph, falling back to generic UserInput for IPs")
            ip_attach_to = None
            needs_user_input = bool(user_ips)

    user_ip_addrs = []  # flat list of individual IPs from user (after CIDR expansion)
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs to scan targets")
        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        user_ip_addrs.append(addr)
                        if addr not in recon_data["port_scan"]["by_ip"]:
                            recon_data["port_scan"]["by_ip"][addr] = {
                                "ip": addr,
                                "hostnames": [ip_attach_to] if ip_attach_to else [],
                                "ports": [],
                                "port_details": [],
                            }
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                user_ip_addrs.append(ip_str)
                if ip_str not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_str] = {
                        "ip": ip_str,
                        "hostnames": [ip_attach_to] if ip_attach_to else [],
                        "ports": [],
                        "port_details": [],
                    }

        # Also populate dns section for user IPs (needed for post-scan IP linking)
        if ip_attach_to:
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_dns_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
        else:
            target_dns_ips = recon_data["dns"]["domain"]["ips"]

        for addr in user_ip_addrs:
            bucket = _classify_ip(addr)
            if addr not in target_dns_ips[bucket]:
                target_dns_ips[bucket].append(addr)
                if not ip_attach_to:
                    recon_data["dns"]["domain"]["has_records"] = True

    # Inject user-provided ports into port_scan (global -- applies to all IPs)
    if user_ports:
        for port in user_ports:
            if port not in recon_data["port_scan"]["all_ports"]:
                recon_data["port_scan"]["all_ports"].append(port)
            # Add to each IP's port list so build_nmap_targets picks them up
            for ip_data in recon_data["port_scan"]["by_ip"].values():
                if port not in ip_data["ports"]:
                    ip_data["ports"].append(port)
                    ip_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
            for host_data in recon_data["port_scan"]["by_host"].values():
                if port not in host_data["ports"]:
                    host_data["ports"].append(port)
                    host_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
        recon_data["port_scan"]["all_ports"].sort()
        print(f"[+][Partial Recon] Injected {len(user_ports)} custom ports into scan targets")

    # Check we have scannable targets
    port_count = len(recon_data["port_scan"]["all_ports"])
    ip_count = len(recon_data["port_scan"]["by_ip"])

    if ip_count == 0:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets provided).")
        print("[!][Partial Recon] Run Subdomain Discovery + Naabu first, or provide IPs manually.")
        sys.exit(1)

    if port_count == 0:
        print("[!][Partial Recon] No ports to scan. Provide custom ports or run Naabu first to discover open ports.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {ip_count} IPs with {port_count} unique ports to scan")

    # Run Nmap scan (same function as full pipeline)
    print(f"[*][Partial Recon] Running Nmap service detection + NSE vuln scripts...")
    result = run_nmap_scan(recon_data, output_file=None, settings=settings)

    # Merge Nmap service versions into port_scan.port_details
    if "nmap_scan" in result:
        merge_nmap_into_port_scan(result)
        print(f"[+][Partial Recon] Merged Nmap results into port_scan data")
    else:
        print("[!][Partial Recon] Nmap scan produced no results (nmap_scan key missing)")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = {}

                # If user provided custom ports, create Port nodes first
                # (update_graph_from_nmap uses MATCH, so Port nodes must exist)
                if user_ports and "port_scan" in result:
                    ps_stats = graph_client.update_graph_from_port_scan(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created Port nodes for custom ports: {json.dumps(ps_stats, default=str)}")

                if "nmap_scan" in result:
                    stats = graph_client.update_graph_from_nmap(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            # IPs attached to a subdomain: create RESOLVES_TO relationships
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif needs_user_input:
                            # Generic IPs: create UserInput NOW (after scan succeeded) and link
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": "Nmap",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for ip_addr in user_ip_addrs:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    ui_id=user_input_id, addr=ip_addr, uid=user_id, pid=project_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked {len(user_ip_addrs)} IPs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Nmap service detection completed successfully")


def run_httpx(config: dict) -> None:
    """
    Run partial HTTP probing using httpx (run_http_probe from http_probe.py).

    Httpx probes URLs built from port_scan data (IPs + ports) and DNS data
    (subdomains). User can provide custom subdomains, IPs, and ports.
    IPs+ports are injected into the port_scan structure (same as Nmap).
    Subdomains are resolved and added to the DNS section.
    """
    import ipaddress as _ipaddress
    from recon.http_probe import run_http_probe as _run_http_probe
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable httpx since the user explicitly chose to run it
    settings['HTTPX_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] HTTP Probing (Httpx)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Httpx accepts subdomains, IPs, and ports
    user_targets = config.get("user_targets") or {}
    user_hostnames = []
    user_ips = []
    user_ports = []
    ip_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                user_hostnames.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid subdomain: {entry}")

        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        for entry in user_targets.get("ports", []):
            try:
                port = int(entry)
                if 1 <= port <= 65535:
                    user_ports.append(port)
                else:
                    print(f"[!][Partial Recon] Skipping out-of-range port: {entry}")
            except (ValueError, TypeError):
                print(f"[!][Partial Recon] Skipping invalid port: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")

    if user_hostnames:
        print(f"[+][Partial Recon] Validated {len(user_hostnames)} custom hostnames")
    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_ports:
        print(f"[+][Partial Recon] Validated {len(user_ports)} custom ports: {user_ports}")

    # Create UserInput node only when IPs are generic (no subdomain attachment)
    if user_ips and not ip_attach_to:
        user_input_id = str(uuid.uuid4())
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "ips",
                            "values": user_ips,
                            "tool_id": "Httpx",
                        },
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created UserInput node for IPs: {user_input_id}")
                else:
                    print("[!][Partial Recon] Neo4j not reachable, skipping UserInput node")
                    user_input_id = None
        except Exception as e:
            print(f"[!][Partial Recon] Failed to create UserInput node: {e}")
            user_input_id = None

    # Build recon_data from Neo4j graph (port_scan + DNS, same structure as Nmap)
    # httpx uses port_scan data if available, falls back to DNS for default ports
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs, ports, subdomains)...")
        recon_data = _build_port_scan_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "port_scan": {
                "by_ip": {}, "by_host": {}, "ip_to_hostnames": {},
                "all_ports": [], "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
            },
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # STEP 1: Resolve user-provided hostnames and add to recon_data DNS section
    resolved_hostnames = {}
    if user_hostnames:
        print(f"[*][Partial Recon] Resolving {len(user_hostnames)} user-provided hostnames...")
        for hostname in user_hostnames:
            if hostname in recon_data["dns"]["subdomains"]:
                print(f"[*][Partial Recon] {hostname} already in graph, skipping")
                continue
            ips = _resolve_hostname(hostname)
            if ips["ipv4"] or ips["ipv6"]:
                recon_data["dns"]["subdomains"][hostname] = {
                    "ips": ips,
                    "has_records": True,
                }
                resolved_hostnames[hostname] = ips
                print(f"[+][Partial Recon] Resolved {hostname} -> {ips['ipv4'] + ips['ipv6']}")
            else:
                print(f"[!][Partial Recon] Could not resolve {hostname}, skipping")

        # Create Subdomain + IP + relationships in Neo4j for newly resolved hostnames
        if resolved_hostnames:
            print(f"[*][Partial Recon] Creating graph nodes for {len(resolved_hostnames)} user hostnames...")
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        driver = graph_client.driver
                        with driver.session() as session:
                            for hostname, ips in resolved_hostnames.items():
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                                    SET s.has_dns_records = true,
                                        s.status = coalesce(s.status, 'resolved'),
                                        s.discovered_at = coalesce(s.discovered_at, datetime()),
                                        s.updated_at = datetime(),
                                        s.source = 'partial_recon_user_input'
                                    """,
                                    name=hostname, uid=user_id, pid=project_id,
                                )
                                session.run(
                                    """
                                    MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    domain=domain, sub=hostname, uid=user_id, pid=project_id,
                                )
                                for ip_version in ("ipv4", "ipv6"):
                                    for ip_addr in ips.get(ip_version, []):
                                        session.run(
                                            """
                                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            SET i.version = $version, i.updated_at = datetime()
                                            """,
                                            addr=ip_addr, uid=user_id, pid=project_id, version=ip_version,
                                        )
                                        record_type = "A" if ip_version == "ipv4" else "AAAA"
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                            """,
                                            sub=hostname, addr=ip_addr, uid=user_id, pid=project_id, rtype=record_type,
                                        )
                                print(f"[+][Partial Recon] Created graph nodes for {hostname}")
                    else:
                        print("[!][Partial Recon] Neo4j not reachable, skipping subdomain node creation")
            except Exception as e:
                print(f"[!][Partial Recon] Failed to create subdomain nodes: {e}")

    # STEP 2: Inject user-provided IPs into port_scan structure
    # Safety: if ip_attach_to points to a subdomain not in graph, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        _sub_exists = False
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as _gc:
                if _gc.verify_connection():
                    with _gc.driver.session() as _s:
                        _res = _s.run(
                            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s LIMIT 1",
                            name=ip_attach_to, uid=user_id, pid=project_id,
                        )
                        _sub_exists = _res.single() is not None
        except Exception:
            pass
        if not _sub_exists:
            print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found in graph, falling back to generic UserInput for IPs")
            ip_attach_to = None
            if user_ips and not user_input_id:
                user_input_id = str(uuid.uuid4())
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": "Httpx",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            print(f"[+][Partial Recon] Created fallback UserInput node: {user_input_id}")
                except Exception:
                    user_input_id = None

    user_ip_addrs = []
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs to scan targets")
        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        user_ip_addrs.append(addr)
                        if addr not in recon_data["port_scan"]["by_ip"]:
                            recon_data["port_scan"]["by_ip"][addr] = {
                                "ip": addr,
                                "hostnames": [ip_attach_to] if ip_attach_to else [],
                                "ports": [],
                                "port_details": [],
                            }
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                user_ip_addrs.append(ip_str)
                if ip_str not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_str] = {
                        "ip": ip_str,
                        "hostnames": [ip_attach_to] if ip_attach_to else [],
                        "ports": [],
                        "port_details": [],
                    }

        # Also populate dns section for user IPs
        if ip_attach_to:
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_dns_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
        else:
            target_dns_ips = recon_data["dns"]["domain"]["ips"]

        for addr in user_ip_addrs:
            bucket = _classify_ip(addr)
            if addr not in target_dns_ips[bucket]:
                target_dns_ips[bucket].append(addr)
                if not ip_attach_to:
                    recon_data["dns"]["domain"]["has_records"] = True

    # STEP 3: Inject user-provided ports into port_scan (global -- applies to all IPs)
    if user_ports:
        for port in user_ports:
            if port not in recon_data["port_scan"]["all_ports"]:
                recon_data["port_scan"]["all_ports"].append(port)
            for ip_data in recon_data["port_scan"]["by_ip"].values():
                if port not in ip_data["ports"]:
                    ip_data["ports"].append(port)
                    ip_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
            for host_data in recon_data["port_scan"]["by_host"].values():
                if port not in host_data["ports"]:
                    host_data["ports"].append(port)
                    host_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
        recon_data["port_scan"]["all_ports"].sort()
        print(f"[+][Partial Recon] Injected {len(user_ports)} custom ports into scan targets")

    # STEP 4: Ensure all user targets are in port_scan.by_host so httpx builds URLs.
    # build_targets_from_naabu() only reads by_host -- anything not there is invisible.
    # Use custom ports if provided, otherwise default to 80+443.
    probe_ports = user_ports if user_ports else [80, 443]
    probe_port_details = [{"port": p, "protocol": "tcp", "service": ""} for p in probe_ports]
    injected_hosts = 0

    # Inject resolved user subdomains
    for hostname, ips in resolved_hostnames.items():
        if hostname not in recon_data["port_scan"]["by_host"]:
            all_ips = ips.get("ipv4", []) + ips.get("ipv6", [])
            recon_data["port_scan"]["by_host"][hostname] = {
                "host": hostname,
                "ip": all_ips[0] if all_ips else "",
                "ports": list(probe_ports),
                "port_details": list(probe_port_details),
            }
            injected_hosts += 1
            # Also register in ip_to_hostnames
            for ip_addr in all_ips:
                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if hostname not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(hostname)
                # Ensure IP is in by_ip with ports
                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr, "hostnames": [hostname],
                        "ports": list(probe_ports), "port_details": list(probe_port_details),
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    if hostname not in existing.get("hostnames", []):
                        existing.setdefault("hostnames", []).append(hostname)

    # Inject user IPs as direct hosts (httpx can probe http://1.2.3.4:port)
    for ip_addr in user_ip_addrs:
        if ip_addr not in recon_data["port_scan"]["by_host"]:
            recon_data["port_scan"]["by_host"][ip_addr] = {
                "host": ip_addr,
                "ip": ip_addr,
                "ports": list(probe_ports),
                "port_details": list(probe_port_details),
            }
            injected_hosts += 1

    # Ensure probe ports are in all_ports
    for p in probe_ports:
        if p not in recon_data["port_scan"]["all_ports"]:
            recon_data["port_scan"]["all_ports"].append(p)
    recon_data["port_scan"]["all_ports"].sort()

    if injected_hosts:
        if user_ports:
            print(f"[+][Partial Recon] Injected {injected_hosts} user targets into httpx probe list with custom ports {user_ports}")
        else:
            print(f"[+][Partial Recon] Injected {injected_hosts} user targets into httpx probe list with default ports [80, 443]")

    # Check we have targets
    has_port_scan = bool(recon_data.get("port_scan", {}).get("by_host"))
    sub_count = len(recon_data["dns"]["subdomains"])
    domain_has_ips = recon_data["dns"]["domain"]["has_records"]

    if not has_port_scan and sub_count == 0 and not domain_has_ips:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets resolved).")
        print("[!][Partial Recon] Run Subdomain Discovery + Port Scanning first, or provide targets manually.")
        sys.exit(1)

    if has_port_scan:
        ip_count = len(recon_data["port_scan"]["by_ip"])
        port_count = len(recon_data["port_scan"]["all_ports"])
        print(f"[+][Partial Recon] Found {ip_count} IPs with {port_count} ports + {sub_count} subdomains")
    else:
        print(f"[+][Partial Recon] Found {sub_count} subdomains (no port scan data, httpx will use default ports)")

    # Run httpx probe (same function as full pipeline)
    print(f"[*][Partial Recon] Running httpx HTTP probing...")
    result = _run_http_probe(recon_data, output_file=None, settings=settings)

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # Create Port nodes for user-injected targets (subdomains + IPs)
                # so the full chain IP -> Port -> Service -> BaseURL connects
                if (resolved_hostnames or user_ip_addrs) and "port_scan" in result:
                    ps_stats = graph_client.update_graph_from_port_scan(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created Port nodes for user targets: {json.dumps(ps_stats, default=str)}")

                stats = graph_client.update_graph_from_http_probe(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif user_input_id:
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, ui_id=user_input_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs via UserInput PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        if user_input_id:
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as gc:
                    if gc.verify_connection():
                        gc.update_user_input_status(user_input_id, "error", {"error": str(e)})
            except Exception:
                pass
        raise

    print(f"\n[+][Partial Recon] HTTP probing completed successfully")


def _build_http_probe_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict for Katana/Hakrawler partial recon.

    Returns a dict with 'http_probe' key containing by_url structure
    (BaseURL -> metadata). Also populates 'domain' and 'subdomains' for
    scope filtering in update_graph_from_resource_enum.
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "subdomains": [],
        "http_probe": {
            "by_url": {},
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query all BaseURL nodes for this project
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                RETURN b.url AS url, b.status_code AS status_code,
                       b.host AS host, b.content_type AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                # Skip URLs with server errors (same filter as resource_enum)
                if status_code is not None and int(status_code) >= 500:
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                }

            # Get subdomains for scope filtering
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = record["subdomains"] or []

    return recon_data


def _is_valid_url(value: str) -> bool:
    """Check if value looks like a valid HTTP/HTTPS URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def run_katana(config: dict) -> None:
    """
    Run partial resource enumeration using only Katana (not the full
    resource_enum pipeline). Katana crawls BaseURLs to discover endpoints.

    Unlike run_resource_enum() which runs ALL sub-tools (Katana + Hakrawler +
    GAU + jsluice + FFuf + etc.), this runs only the Katana crawler +
    organize_endpoints, then updates the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        run_katana_crawler,
        pull_katana_docker_image,
        organize_endpoints,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Katana since the user explicitly chose to run it
    settings['KATANA_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Katana Crawling (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Katana accepts URLs
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")  # BaseURL or None

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs)...")
        recon_data = _build_http_probe_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "http_probe": {
                "by_url": {},
            },
        }

    # Inject user-provided URLs into the target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to crawl targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }

    # Build target_urls list from http_probe.by_url (same logic as resource_enum.py)
    target_urls = []
    target_domains = set()
    for url, url_data in recon_data["http_probe"]["by_url"].items():
        status_code = url_data.get("status_code")
        if status_code and int(status_code) < 500:
            target_urls.append(url)
            host = url_data.get("host", "")
            if host:
                target_domains.add(host)

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    if not target_urls:
        print("[!][Partial Recon] No URLs to crawl (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to crawl")

    # Extract Katana settings
    KATANA_DOCKER_IMAGE = settings.get('KATANA_DOCKER_IMAGE', 'projectdiscovery/katana:latest')
    KATANA_DEPTH = settings.get('KATANA_DEPTH', 2)
    KATANA_MAX_URLS = settings.get('KATANA_MAX_URLS', 300)
    KATANA_RATE_LIMIT = settings.get('KATANA_RATE_LIMIT', 50)
    KATANA_TIMEOUT = settings.get('KATANA_TIMEOUT', 3600)
    KATANA_JS_CRAWL = settings.get('KATANA_JS_CRAWL', True)
    KATANA_PARAMS_ONLY = settings.get('KATANA_PARAMS_ONLY', False)
    KATANA_CUSTOM_HEADERS = settings.get('KATANA_CUSTOM_HEADERS', [])
    KATANA_EXCLUDE_PATTERNS = settings.get('KATANA_EXCLUDE_PATTERNS', [])

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Pull Docker image
    print(f"[*][Partial Recon] Pulling Katana Docker image: {KATANA_DOCKER_IMAGE}")
    pull_katana_docker_image(KATANA_DOCKER_IMAGE)

    # Run Katana crawler (ONLY Katana -- not the full resource_enum pipeline)
    print(f"[*][Partial Recon] Running Katana crawler on {len(target_urls)} URLs...")
    katana_urls, katana_meta = run_katana_crawler(
        target_urls,
        KATANA_DOCKER_IMAGE,
        KATANA_DEPTH,
        KATANA_MAX_URLS,
        KATANA_RATE_LIMIT,
        KATANA_TIMEOUT,
        KATANA_JS_CRAWL,
        KATANA_PARAMS_ONLY,
        target_domains,
        KATANA_CUSTOM_HEADERS,
        KATANA_EXCLUDE_PATTERNS,
        use_proxy,
    )
    print(f"[+][Partial Recon] Katana found {len(katana_urls)} URLs")

    # Organize discovered URLs into by_base_url structure
    organized_data = organize_endpoints(katana_urls, use_proxy=use_proxy)

    # Mark all endpoints with sources=['katana']
    for base_url, base_data in organized_data['by_base_url'].items():
        for path, endpoint in base_data['endpoints'].items():
            endpoint['sources'] = ['katana']

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": organized_data['by_base_url'],
        "forms": organized_data.get('forms', []),
        "jsluice_secrets": [],
        "scan_metadata": {
            "katana_total": len(katana_urls),
            "external_domains": katana_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in organized_data['by_base_url'].values()
            ),
            "total_base_urls": len(organized_data['by_base_url']),
        },
        "external_domains": katana_meta.get("external_domains", []),
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            # Attached: link crawled BaseURLs to selected BaseURL via DISCOVERED_FROM
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            # Generic: create UserInput -> PRODUCED -> BaseURL
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Katana",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Katana crawling completed successfully")


def run_hakrawler(config: dict) -> None:
    """
    Run partial resource enumeration using only Hakrawler (not the full
    resource_enum pipeline). Hakrawler crawls BaseURLs to discover endpoints.

    Same pattern as run_katana() -- runs just the hakrawler crawler +
    organize_endpoints, then updates the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        run_hakrawler_crawler,
        pull_hakrawler_docker_image,
        organize_endpoints,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Hakrawler since the user explicitly chose to run it
    settings['HAKRAWLER_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Resource Enumeration (Hakrawler)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Hakrawler accepts URLs
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs)...")
        recon_data = _build_http_probe_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "http_probe": {
                "by_url": {},
            },
        }

    # Inject user-provided URLs into the target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to crawl targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }

    # Build target_urls list from http_probe.by_url (same logic as resource_enum.py)
    target_urls = []
    target_domains = set()
    for url, url_data in recon_data["http_probe"]["by_url"].items():
        status_code = url_data.get("status_code")
        if status_code and int(status_code) < 500:
            target_urls.append(url)
            host = url_data.get("host", "")
            if host:
                target_domains.add(host)

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    if not target_urls:
        print("[!][Partial Recon] No URLs to crawl (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to crawl")

    # Extract Hakrawler settings
    HAKRAWLER_DOCKER_IMAGE = settings.get('HAKRAWLER_DOCKER_IMAGE', 'jauderho/hakrawler:latest')
    HAKRAWLER_DEPTH = settings.get('HAKRAWLER_DEPTH', 2)
    HAKRAWLER_THREADS = settings.get('HAKRAWLER_THREADS', 5)
    HAKRAWLER_TIMEOUT = settings.get('HAKRAWLER_TIMEOUT', 30)
    HAKRAWLER_MAX_URLS = settings.get('HAKRAWLER_MAX_URLS', 500)
    HAKRAWLER_INCLUDE_SUBS = settings.get('HAKRAWLER_INCLUDE_SUBS', False)
    HAKRAWLER_INSECURE = settings.get('HAKRAWLER_INSECURE', True)
    HAKRAWLER_CUSTOM_HEADERS = settings.get('HAKRAWLER_CUSTOM_HEADERS', [])

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Pull Docker image
    print(f"[*][Partial Recon] Pulling Hakrawler Docker image: {HAKRAWLER_DOCKER_IMAGE}")
    pull_hakrawler_docker_image(HAKRAWLER_DOCKER_IMAGE)

    # Run Hakrawler crawler
    print(f"[*][Partial Recon] Running Hakrawler crawler on {len(target_urls)} URLs...")
    hakrawler_urls, hakrawler_meta = run_hakrawler_crawler(
        target_urls,
        HAKRAWLER_DOCKER_IMAGE,
        HAKRAWLER_DEPTH,
        HAKRAWLER_THREADS,
        HAKRAWLER_TIMEOUT,
        HAKRAWLER_MAX_URLS,
        HAKRAWLER_INCLUDE_SUBS,
        HAKRAWLER_INSECURE,
        target_domains,
        HAKRAWLER_CUSTOM_HEADERS,
        [],  # no exclude patterns for Hakrawler
        use_proxy,
    )
    print(f"[+][Partial Recon] Hakrawler found {len(hakrawler_urls)} URLs")

    # Organize discovered URLs into by_base_url structure
    organized_data = organize_endpoints(hakrawler_urls, use_proxy=use_proxy)

    # Mark all endpoints with sources=['hakrawler']
    for base_url, base_data in organized_data['by_base_url'].items():
        for path, endpoint in base_data['endpoints'].items():
            endpoint['sources'] = ['hakrawler']

    # Build resource_enum result structure (same as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": organized_data['by_base_url'],
        "forms": organized_data.get('forms', []),
        "jsluice_secrets": [],
        "scan_metadata": {
            "hakrawler_total": len(hakrawler_urls),
            "external_domains": hakrawler_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in organized_data['by_base_url'].values()
            ),
            "total_base_urls": len(organized_data['by_base_url']),
        },
        "external_domains": hakrawler_meta.get("external_domains", []),
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            # Attached: link crawled BaseURLs to selected BaseURL via DISCOVERED_FROM
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            # Generic: create UserInput -> PRODUCED -> BaseURL
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Hakrawler",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Resource enumeration (Hakrawler) completed successfully")


def run_ffuf(config: dict) -> None:
    """
    Run partial resource enumeration using only FFuf directory fuzzer.
    FFuf fuzzes BaseURLs to discover hidden endpoints, directories, and files.

    Same pattern as run_hakrawler() -- takes BaseURL inputs, runs the fuzzer,
    then updates the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        run_ffuf_discovery,
        pull_ffuf_binary_check,
        merge_ffuf_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable FFuf since the user explicitly chose to run it
    settings['FFUF_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Directory Fuzzing (FFuf)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- FFuf accepts URLs
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs)...")
        recon_data = _build_http_probe_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "http_probe": {
                "by_url": {},
            },
        }

    # Inject user-provided URLs into the target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to fuzz targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }

    # Build target_urls list from http_probe.by_url (same logic as resource_enum.py)
    target_urls = []
    target_domains = set()
    for url, url_data in recon_data["http_probe"]["by_url"].items():
        status_code = url_data.get("status_code")
        if status_code and int(status_code) < 500:
            target_urls.append(url)
            host = url_data.get("host", "")
            if host:
                target_domains.add(host)

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    # (update_graph_from_resource_enum skips BaseURLs whose host is not in subdomains)
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    if not target_urls:
        print("[!][Partial Recon] No URLs to fuzz (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to fuzz")

    # Extract FFuf settings
    FFUF_WORDLIST = settings.get('FFUF_WORDLIST', '/usr/share/seclists/Discovery/Web-Content/common.txt')
    FFUF_THREADS = settings.get('FFUF_THREADS', 40)
    FFUF_RATE = settings.get('FFUF_RATE', 0)
    FFUF_TIMEOUT = settings.get('FFUF_TIMEOUT', 10)
    FFUF_MAX_TIME = settings.get('FFUF_MAX_TIME', 600)
    FFUF_MATCH_CODES = settings.get('FFUF_MATCH_CODES', [200, 201, 204, 301, 302, 307, 308, 401, 403, 405])
    FFUF_FILTER_CODES = settings.get('FFUF_FILTER_CODES', [])
    FFUF_FILTER_SIZE = settings.get('FFUF_FILTER_SIZE', '')
    FFUF_EXTENSIONS = settings.get('FFUF_EXTENSIONS', [])
    FFUF_RECURSION = settings.get('FFUF_RECURSION', False)
    FFUF_RECURSION_DEPTH = settings.get('FFUF_RECURSION_DEPTH', 2)
    FFUF_AUTO_CALIBRATE = settings.get('FFUF_AUTO_CALIBRATE', True)
    FFUF_FOLLOW_REDIRECTS = settings.get('FFUF_FOLLOW_REDIRECTS', False)
    FFUF_CUSTOM_HEADERS = settings.get('FFUF_CUSTOM_HEADERS', [])
    FFUF_SMART_FUZZ = settings.get('FFUF_SMART_FUZZ', True)

    print(f"[*][Partial Recon] FFuf wordlist: {FFUF_WORDLIST}")
    print(f"[*][Partial Recon] FFuf threads: {FFUF_THREADS}")
    print(f"[*][Partial Recon] FFuf rate limit: {FFUF_RATE} req/s" if FFUF_RATE > 0 else "[*][Partial Recon] FFuf rate limit: unlimited")
    print(f"[*][Partial Recon] FFuf timeout: {FFUF_TIMEOUT}s per request, {FFUF_MAX_TIME}s max")

    # Check Tor proxy
    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Check ffuf binary
    if not pull_ffuf_binary_check():
        print("[!][Partial Recon] ffuf binary not found in PATH")
        sys.exit(1)

    # Smart fuzz: query existing endpoints from graph for discovered base paths
    discovered_base_paths = None
    if FFUF_SMART_FUZZ and include_graph:
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as gc:
                if gc.verify_connection():
                    with gc.driver.session() as session:
                        result = session.run(
                            """
                            MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                            RETURN collect(DISTINCT e.path) AS paths
                            """,
                            uid=user_id, pid=project_id,
                        )
                        record = result.single()
                        if record:
                            paths = record["paths"] or []
                            base_paths = set()
                            for path in paths:
                                if not path:
                                    continue
                                parts = path.strip('/').split('/')
                                if len(parts) >= 2:
                                    base_paths.add('/'.join(parts[:2]))
                                if len(parts) >= 1 and parts[0]:
                                    base_paths.add(parts[0])
                            if base_paths:
                                discovered_base_paths = sorted(base_paths)[:20]
                                print(f"[*][Partial Recon] Smart fuzz: targeting {len(discovered_base_paths)} discovered base paths")
        except Exception as e:
            print(f"[!][Partial Recon] Smart fuzz query failed: {e}")

    # Run FFuf discovery
    print(f"[*][Partial Recon] Running FFuf directory fuzzing on {len(target_urls)} URLs...")
    ffuf_results, ffuf_meta = run_ffuf_discovery(
        target_urls,
        FFUF_WORDLIST,
        FFUF_THREADS,
        FFUF_RATE,
        FFUF_TIMEOUT,
        FFUF_MAX_TIME,
        FFUF_MATCH_CODES,
        FFUF_FILTER_CODES,
        FFUF_FILTER_SIZE,
        FFUF_EXTENSIONS,
        FFUF_RECURSION,
        FFUF_RECURSION_DEPTH,
        FFUF_AUTO_CALIBRATE,
        FFUF_CUSTOM_HEADERS,
        FFUF_FOLLOW_REDIRECTS,
        target_domains,
        discovered_base_paths,
        use_proxy,
    )
    print(f"[+][Partial Recon] FFuf discovered {len(ffuf_results)} endpoints")

    # Merge FFuf results into by_base_url structure
    by_base_url = {}
    ffuf_stats = {"ffuf_total": 0, "ffuf_new": 0, "ffuf_overlap": 0}
    if ffuf_results:
        by_base_url, ffuf_stats = merge_ffuf_into_by_base_url(ffuf_results, by_base_url)
        print(f"[+][Partial Recon] FFuf total: {ffuf_stats['ffuf_total']} endpoints")
        print(f"[+][Partial Recon] FFuf new: {ffuf_stats['ffuf_new']}")

    # Build resource_enum result structure (same as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": [],
        "scan_metadata": {
            "ffuf_total": len(ffuf_results),
            "external_domains": ffuf_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": ffuf_meta.get("external_domains", []),
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Ffuf",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] FFuf directory fuzzing completed successfully")


def run_gau(config: dict) -> None:
    """
    Run partial GAU (GetAllUrls) passive URL discovery.

    GAU queries web archives (Wayback Machine, Common Crawl, OTX, URLScan)
    for historical URLs associated with target domains/subdomains.
    Results are organized into Endpoint/Parameter/BaseURL nodes and merged
    into the graph via update_graph_from_resource_enum().
    """
    from recon.helpers.resource_enum import (
        pull_gau_docker_image,
        run_gau_discovery,
        verify_gau_urls,
        detect_gau_methods,
        merge_gau_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable GAU since the user explicitly chose to run it
    settings['GAU_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] GAU Passive URL Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- GAU accepts subdomains
    user_targets = config.get("user_targets") or {}
    user_subdomains = []

    if user_targets:
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                if entry == domain or entry.endswith("." + domain):
                    user_subdomains.append(entry)
                else:
                    print(f"[!][Partial Recon] Skipping subdomain outside scope: {entry}")
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid hostname: {entry}")

    if user_subdomains:
        print(f"[+][Partial Recon] Validated {len(user_subdomains)} custom subdomains")

    # Build target_domains from graph subdomains + user subdomains
    include_graph = config.get("include_graph_targets", True)
    target_domains = set()

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for target subdomains...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                driver = graph_client.driver
                with driver.session() as session:
                    # Get all subdomains from graph
                    result = session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                              -[:HAS_SUBDOMAIN]->(s:Subdomain)
                        RETURN collect(DISTINCT s.name) AS subdomains
                        """,
                        domain=domain, uid=user_id, pid=project_id,
                    )
                    record = result.single()
                    if record and record["subdomains"]:
                        target_domains.update(record["subdomains"])
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph subdomains")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Always include the root domain
    target_domains.add(domain)

    # Add user-provided subdomains
    for sub in user_subdomains:
        target_domains.add(sub)

    print(f"[+][Partial Recon] Total target domains for GAU: {len(target_domains)}")

    # Also get subdomains list for scope filtering later
    all_subdomains = list(target_domains)

    # GAU settings
    GAU_DOCKER_IMAGE = settings.get('GAU_DOCKER_IMAGE', 'sxcurity/gau:latest')
    GAU_PROVIDERS = list(settings.get('GAU_PROVIDERS', ['wayback', 'commoncrawl', 'otx', 'urlscan']))
    GAU_THREADS = settings.get('GAU_THREADS', 2)
    GAU_TIMEOUT = settings.get('GAU_TIMEOUT', 60)
    GAU_BLACKLIST_EXTENSIONS = settings.get('GAU_BLACKLIST_EXTENSIONS', ['png', 'jpg', 'jpeg', 'gif', 'css', 'woff', 'woff2', 'ttf', 'svg', 'ico', 'eot'])
    GAU_MAX_URLS = settings.get('GAU_MAX_URLS', 10000)
    GAU_YEAR_RANGE = settings.get('GAU_YEAR_RANGE', None)
    GAU_VERBOSE = settings.get('GAU_VERBOSE', False)
    GAU_VERIFY_URLS = settings.get('GAU_VERIFY_URLS', True)
    GAU_VERIFY_DOCKER_IMAGE = settings.get('GAU_VERIFY_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')
    GAU_VERIFY_TIMEOUT = settings.get('GAU_VERIFY_TIMEOUT', 5)
    GAU_VERIFY_RATE_LIMIT = settings.get('GAU_VERIFY_RATE_LIMIT', 50)
    GAU_VERIFY_THREADS = settings.get('GAU_VERIFY_THREADS', 50)
    GAU_VERIFY_ACCEPT_STATUS = settings.get('GAU_VERIFY_ACCEPT_STATUS', ['200', '201', '301', '302', '307', '308', '401', '403'])
    GAU_DETECT_METHODS = settings.get('GAU_DETECT_METHODS', True)
    GAU_METHOD_DETECT_THREADS = settings.get('GAU_METHOD_DETECT_THREADS', 20)
    GAU_METHOD_DETECT_TIMEOUT = settings.get('GAU_METHOD_DETECT_TIMEOUT', 5)
    GAU_METHOD_DETECT_RATE_LIMIT = settings.get('GAU_METHOD_DETECT_RATE_LIMIT', 30)
    GAU_FILTER_DEAD_ENDPOINTS = settings.get('GAU_FILTER_DEAD_ENDPOINTS', True)

    URLSCAN_API_KEY = settings.get('URLSCAN_API_KEY', '')

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Pull Docker image
    print(f"[*][Partial Recon] Pulling GAU Docker image: {GAU_DOCKER_IMAGE}")
    pull_gau_docker_image(GAU_DOCKER_IMAGE)

    # Run GAU discovery
    print(f"[*][Partial Recon] Running GAU on {len(target_domains)} domains...")
    gau_urls, gau_urls_by_domain = run_gau_discovery(
        target_domains,
        GAU_DOCKER_IMAGE,
        GAU_PROVIDERS,
        GAU_THREADS,
        GAU_TIMEOUT,
        GAU_BLACKLIST_EXTENSIONS,
        GAU_MAX_URLS,
        GAU_YEAR_RANGE,
        GAU_VERBOSE,
        use_proxy,
        URLSCAN_API_KEY,
    )
    print(f"[+][Partial Recon] GAU discovered {len(gau_urls)} total URLs")

    if not gau_urls:
        print("[!][Partial Recon] GAU found no URLs. No archives available for these domains.")
        # Still update graph with user subdomains if provided
        if user_subdomains:
            _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)
        print(f"\n[+][Partial Recon] GAU completed (no results)")
        return

    # Filter to in-scope URLs only
    from urllib.parse import urlparse as _urlparse
    in_scope_gau_urls = []
    gau_external_domains = []
    out_of_scope_count = 0
    for url in gau_urls:
        parsed = _urlparse(url)
        host = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
        if host in target_domains:
            in_scope_gau_urls.append(url)
        else:
            out_of_scope_count += 1
            if host:
                gau_external_domains.append({"domain": host, "source": "gau", "url": url})

    if out_of_scope_count > 0:
        print(f"[*][Partial Recon] Filtered {out_of_scope_count} out-of-scope URLs")
    print(f"[+][Partial Recon] In-scope URLs: {len(in_scope_gau_urls)}")

    gau_urls_to_process = in_scope_gau_urls

    # Verify GAU URLs if enabled
    verified_urls = None
    if GAU_VERIFY_URLS and gau_urls_to_process:
        verified_urls = verify_gau_urls(
            gau_urls_to_process,
            GAU_VERIFY_DOCKER_IMAGE,
            GAU_VERIFY_TIMEOUT,
            GAU_VERIFY_RATE_LIMIT,
            GAU_VERIFY_THREADS,
            GAU_VERIFY_ACCEPT_STATUS,
            use_proxy,
        )

    # Detect HTTP methods
    url_methods = None
    urls_to_probe = list(verified_urls) if verified_urls else gau_urls_to_process
    if GAU_DETECT_METHODS and urls_to_probe:
        url_methods = detect_gau_methods(
            urls_to_probe,
            GAU_VERIFY_DOCKER_IMAGE,
            GAU_METHOD_DETECT_THREADS,
            GAU_METHOD_DETECT_TIMEOUT,
            GAU_METHOD_DETECT_RATE_LIMIT,
            GAU_FILTER_DEAD_ENDPOINTS,
            use_proxy,
        )

    # Merge GAU URLs into by_base_url structure
    print(f"[*][Partial Recon] Merging GAU endpoints...")
    by_base_url = {}
    by_base_url, gau_stats = merge_gau_into_by_base_url(
        gau_urls_to_process,
        by_base_url,
        verified_urls,
        url_methods,
    )

    print(f"[+][Partial Recon] GAU stats:")
    print(f"[+][Partial Recon]   Parsed: {gau_stats['gau_parsed']}")
    print(f"[+][Partial Recon]   New endpoints: {gau_stats['gau_new']}")
    if GAU_VERIFY_URLS:
        print(f"[+][Partial Recon]   Skipped (unverified): {gau_stats.get('gau_skipped_unverified', 0)}")
    if GAU_DETECT_METHODS:
        print(f"[+][Partial Recon]   With POST: {gau_stats.get('gau_with_post', 0)}")
    if GAU_FILTER_DEAD_ENDPOINTS:
        print(f"[+][Partial Recon]   Dead filtered: {gau_stats.get('gau_skipped_dead', 0)}")

    # Build resource_enum result structure (same shape as full pipeline)
    recon_data = {
        "domain": domain,
        "subdomains": all_subdomains,
        "resource_enum": {
            "by_base_url": by_base_url,
            "forms": [],
            "jsluice_secrets": [],
            "scan_metadata": {
                "gau_urls_found_total": len(gau_urls),
                "gau_urls_in_scope": len(in_scope_gau_urls),
                "gau_stats": gau_stats,
                "external_domains": gau_external_domains,
            },
            "summary": {
                "total_endpoints": sum(
                    len(bd['endpoints']) for bd in by_base_url.values()
                ),
                "total_base_urls": len(by_base_url),
            },
            "external_domains": gau_external_domains,
        },
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=recon_data,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Create Subdomain nodes for user-provided subdomains
                if user_subdomains:
                    _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] GAU passive URL discovery completed successfully")


def run_paramspider(config: dict) -> None:
    """
    Run partial ParamSpider passive parameter discovery.

    ParamSpider queries the Wayback Machine for historical URLs containing
    query parameters for target domains/subdomains.
    Results are organized into Endpoint/Parameter/BaseURL nodes and merged
    into the graph via update_graph_from_resource_enum().
    """
    from recon.helpers.resource_enum.paramspider_helpers import (
        run_paramspider_discovery,
        merge_paramspider_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable ParamSpider since the user explicitly chose to run it
    settings['PARAMSPIDER_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] ParamSpider Passive Parameter Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- ParamSpider accepts subdomains
    user_targets = config.get("user_targets") or {}
    user_subdomains = []

    if user_targets:
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                if entry == domain or entry.endswith("." + domain):
                    user_subdomains.append(entry)
                else:
                    print(f"[!][Partial Recon] Skipping subdomain outside scope: {entry}")
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid hostname: {entry}")

    if user_subdomains:
        print(f"[+][Partial Recon] Validated {len(user_subdomains)} custom subdomains")

    # Build target_domains from graph subdomains + user subdomains
    include_graph = config.get("include_graph_targets", True)
    target_domains = set()

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for target subdomains...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                driver = graph_client.driver
                with driver.session() as session:
                    result = session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                              -[:HAS_SUBDOMAIN]->(s:Subdomain)
                        RETURN collect(DISTINCT s.name) AS subdomains
                        """,
                        domain=domain, uid=user_id, pid=project_id,
                    )
                    record = result.single()
                    if record and record["subdomains"]:
                        target_domains.update(record["subdomains"])
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph subdomains")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Always include the root domain
    target_domains.add(domain)

    # Add user-provided subdomains
    for sub in user_subdomains:
        target_domains.add(sub)

    print(f"[+][Partial Recon] Total target domains for ParamSpider: {len(target_domains)}")

    # ParamSpider settings
    PARAMSPIDER_PLACEHOLDER = settings.get('PARAMSPIDER_PLACEHOLDER', 'FUZZ')
    PARAMSPIDER_TIMEOUT = settings.get('PARAMSPIDER_TIMEOUT', 120)

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Run ParamSpider discovery
    print(f"[*][Partial Recon] Running ParamSpider on {len(target_domains)} domains...")
    paramspider_urls, paramspider_urls_by_domain = run_paramspider_discovery(
        target_domains,
        PARAMSPIDER_PLACEHOLDER,
        PARAMSPIDER_TIMEOUT,
        use_proxy,
    )
    print(f"[+][Partial Recon] ParamSpider discovered {len(paramspider_urls)} parameterized URLs")

    if not paramspider_urls:
        print("[!][Partial Recon] ParamSpider found no URLs. No archived parameters for these domains.")
        if user_subdomains:
            _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)
        print(f"\n[+][Partial Recon] ParamSpider completed (no results)")
        return

    # Merge ParamSpider URLs into by_base_url structure
    print(f"[*][Partial Recon] Merging ParamSpider endpoints...")
    by_base_url = {}
    by_base_url, paramspider_stats = merge_paramspider_into_by_base_url(
        paramspider_urls,
        by_base_url,
        target_domains,
    )

    print(f"[+][Partial Recon] ParamSpider stats:")
    print(f"[+][Partial Recon]   Total: {paramspider_stats.get('paramspider_total', 0)}")
    print(f"[+][Partial Recon]   Parsed: {paramspider_stats.get('paramspider_parsed', 0)}")
    print(f"[+][Partial Recon]   New endpoints: {paramspider_stats.get('paramspider_new', 0)}")
    print(f"[+][Partial Recon]   Overlap: {paramspider_stats.get('paramspider_overlap', 0)}")
    print(f"[+][Partial Recon]   Out of scope: {paramspider_stats.get('paramspider_out_of_scope', 0)}")

    # Build resource_enum result structure (same shape as full pipeline)
    recon_data = {
        "domain": domain,
        "subdomains": list(target_domains),
        "resource_enum": {
            "by_base_url": by_base_url,
            "forms": [],
            "jsluice_secrets": [],
            "scan_metadata": {
                "paramspider_stats": paramspider_stats,
            },
            "summary": {
                "total_endpoints": sum(
                    len(bd['endpoints']) for bd in by_base_url.values()
                ),
                "total_base_urls": len(by_base_url),
            },
            "external_domains": [],
        },
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=recon_data,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Create Subdomain nodes for user-provided subdomains
                if user_subdomains:
                    _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] ParamSpider passive parameter discovery completed successfully")


def _create_user_subdomains_in_graph(domain: str, subdomains: list, user_id: str, project_id: str) -> None:
    """Create Subdomain nodes in the graph for user-provided subdomains (MERGE, no duplicates)."""
    from graph_db import Neo4jClient
    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            return
        driver = graph_client.driver
        with driver.session() as session:
            for sub in subdomains:
                # Resolve the subdomain to get IPs
                ips = _resolve_hostname(sub)
                # Create Subdomain node attached to Domain
                session.run(
                    """
                    MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                    MERGE (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                    ON CREATE SET s.source = 'partial_recon_user_input',
                                  s.updated_at = datetime()
                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                    """,
                    domain=domain, sub=sub, uid=user_id, pid=project_id,
                )
                # Create IP nodes and RESOLVES_TO relationships
                for bucket in ("ipv4", "ipv6"):
                    for addr in ips.get(bucket, []):
                        session.run(
                            """
                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            ON CREATE SET i.version = $version,
                                          i.source = 'partial_recon_user_input',
                                          i.updated_at = datetime()
                            WITH i
                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:RESOLVES_TO]->(i)
                            """,
                            addr=addr, uid=user_id, pid=project_id,
                            version=bucket, sub=sub,
                        )
            if subdomains:
                print(f"[+][Partial Recon] Created/merged {len(subdomains)} user subdomain nodes in graph")


def run_jsluice(config: dict) -> None:
    """
    Run partial resource enumeration using only jsluice (not the full
    resource_enum pipeline). jsluice analyzes JavaScript files to extract
    hidden API endpoints, parameters, and secrets.

    Unlike the full pipeline where jsluice runs after Katana/Hakrawler,
    this queries the graph for existing Endpoint URLs (from prior crawling)
    and/or accepts user-provided URLs, then runs jsluice analysis on them.
    """
    from recon.helpers.resource_enum import (
        run_jsluice_analysis,
        merge_jsluice_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable jsluice since the user explicitly chose to run it
    settings['JSLUICE_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] jsluice JS Analysis (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- jsluice accepts URLs (same as Katana/Hakrawler)
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")  # BaseURL or None

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    target_urls = []
    target_domains = set()

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (Endpoints from prior crawling)...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                driver = graph_client.driver
                with driver.session() as session:
                    # Get all endpoint full URLs (baseurl + path) from the graph
                    result = session.run(
                        """
                        MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT e.baseurl + e.path AS url
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        if url:
                            target_urls.append(url)

                    # Also add BaseURLs themselves (some may host JS directly)
                    result = session.run(
                        """
                        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT b.url AS url, b.host AS host
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        host = record["host"] or ""
                        if url and url not in target_urls:
                            target_urls.append(url)
                        if host:
                            target_domains.add(host)

                print(f"[+][Partial Recon] Found {len(target_urls)} URLs from graph")
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Add user-provided URLs to target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs")
        for url in user_urls:
            if url not in target_urls:
                target_urls.append(url)
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0]
            if host:
                target_domains.add(host)

    # Also add domain itself to target_domains for scope filtering
    if domain:
        target_domains.add(domain)

    if not target_urls:
        print("[!][Partial Recon] No URLs to analyze (graph has no Endpoints/BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run Katana or Hakrawler first to discover URLs, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Total {len(target_urls)} URLs to analyze with jsluice")

    # Extract jsluice settings
    JSLUICE_MAX_FILES = settings.get('JSLUICE_MAX_FILES', 100)
    JSLUICE_TIMEOUT = settings.get('JSLUICE_TIMEOUT', 300)
    JSLUICE_EXTRACT_URLS = settings.get('JSLUICE_EXTRACT_URLS', True)
    JSLUICE_EXTRACT_SECRETS = settings.get('JSLUICE_EXTRACT_SECRETS', True)
    JSLUICE_CONCURRENCY = settings.get('JSLUICE_CONCURRENCY', 5)

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Run jsluice analysis (filters to .js files internally, downloads and analyzes)
    print(f"[*][Partial Recon] Running jsluice analysis...")
    jsluice_result = run_jsluice_analysis(
        target_urls,
        JSLUICE_MAX_FILES,
        JSLUICE_TIMEOUT,
        JSLUICE_EXTRACT_URLS,
        JSLUICE_EXTRACT_SECRETS,
        JSLUICE_CONCURRENCY,
        target_domains,
        use_proxy,
    )

    jsluice_urls = jsluice_result.get("urls", [])
    jsluice_secrets = jsluice_result.get("secrets", [])
    external_domains = jsluice_result.get("external_domains", [])

    print(f"[+][Partial Recon] jsluice found {len(jsluice_urls)} URLs, {len(jsluice_secrets)} secrets, {len(external_domains)} external domains")

    # Organize extracted URLs into by_base_url structure
    by_base_url = {}
    jsluice_stats = {
        "jsluice_total": 0,
        "jsluice_parsed": 0,
        "jsluice_new": 0,
        "jsluice_overlap": 0,
    }

    if jsluice_urls:
        by_base_url, jsluice_stats = merge_jsluice_into_by_base_url(
            jsluice_urls,
            {},  # Start with empty -- jsluice is the only source
        )
        print(f"[+][Partial Recon] Organized {jsluice_stats['jsluice_new']} new endpoints across {len(by_base_url)} base URLs")

    # Build recon_data for graph update (needs domain + subdomains for scope)
    recon_data = {
        "domain": domain,
        "subdomains": [],
    }

    # Get subdomains for scope filtering
    if include_graph:
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    driver = graph_client.driver
                    with driver.session() as session:
                        result = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                  -[:HAS_SUBDOMAIN]->(s:Subdomain)
                            RETURN collect(DISTINCT s.name) AS subdomains
                            """,
                            domain=domain, uid=user_id, pid=project_id,
                        )
                        record = result.single()
                        if record:
                            recon_data["subdomains"] = record["subdomains"] or []
        except Exception:
            pass

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": jsluice_secrets,
        "scan_metadata": {
            "jsluice_total": jsluice_stats.get("jsluice_total", 0),
            "jsluice_new": jsluice_stats.get("jsluice_new", 0),
            "external_domains": external_domains,
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": external_domains,
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Jsluice",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] jsluice analysis completed successfully")


def run_kiterunner(config: dict) -> None:
    """
    Run partial resource enumeration using only Kiterunner (not the full
    resource_enum pipeline). Kiterunner bruteforces API endpoints using
    Assetnote wordlists derived from real-world Swagger/OpenAPI specs.

    Same URL-input pattern as run_katana()/run_hakrawler() -- reads BaseURLs
    from graph and/or user-provided URLs, runs Kiterunner discovery, merges
    results into the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        ensure_kiterunner_binary,
        run_kiterunner_discovery,
        merge_kiterunner_into_by_base_url,
        detect_kiterunner_methods,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Kiterunner since the user explicitly chose to run it
    settings['KITERUNNER_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Kiterunner API Discovery (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Kiterunner accepts URLs
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs)...")
        recon_data = _build_http_probe_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "http_probe": {
                "by_url": {},
            },
        }

    # Inject user-provided URLs into the target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to scan targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }

    # Build target_urls list from http_probe.by_url (same logic as resource_enum.py)
    target_urls = []
    target_domains = set()
    for url, url_data in recon_data["http_probe"]["by_url"].items():
        status_code = url_data.get("status_code")
        if status_code and int(status_code) < 500:
            target_urls.append(url)
            host = url_data.get("host", "")
            if host:
                target_domains.add(host)

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    if not target_urls:
        print("[!][Partial Recon] No URLs to scan (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to scan")

    # Extract Kiterunner settings
    KITERUNNER_WORDLISTS = settings.get('KITERUNNER_WORDLISTS', ['apiroutes-210228'])
    KITERUNNER_RATE_LIMIT = settings.get('KITERUNNER_RATE_LIMIT', 100)
    KITERUNNER_CONNECTIONS = settings.get('KITERUNNER_CONNECTIONS', 50)
    KITERUNNER_TIMEOUT = settings.get('KITERUNNER_TIMEOUT', 3)
    KITERUNNER_SCAN_TIMEOUT = settings.get('KITERUNNER_SCAN_TIMEOUT', 300)
    KITERUNNER_THREADS = settings.get('KITERUNNER_THREADS', 10)
    KITERUNNER_IGNORE_STATUS = settings.get('KITERUNNER_IGNORE_STATUS', ['404', '429', '503'])
    KITERUNNER_MATCH_STATUS = settings.get('KITERUNNER_MATCH_STATUS', [])
    KITERUNNER_MIN_CONTENT_LENGTH = settings.get('KITERUNNER_MIN_CONTENT_LENGTH', 0)
    KITERUNNER_HEADERS = settings.get('KITERUNNER_HEADERS', [])
    KITERUNNER_DETECT_METHODS = settings.get('KITERUNNER_DETECT_METHODS', True)
    KITERUNNER_METHOD_DETECTION_MODE = settings.get('KITERUNNER_METHOD_DETECTION_MODE', 'options')
    KITERUNNER_BRUTEFORCE_METHODS = settings.get('KITERUNNER_BRUTEFORCE_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    KITERUNNER_METHOD_DETECT_TIMEOUT = settings.get('KITERUNNER_METHOD_DETECT_TIMEOUT', 3)
    KITERUNNER_METHOD_DETECT_RATE_LIMIT = settings.get('KITERUNNER_METHOD_DETECT_RATE_LIMIT', 50)
    KITERUNNER_METHOD_DETECT_THREADS = settings.get('KITERUNNER_METHOD_DETECT_THREADS', 20)
    GAU_VERIFY_DOCKER_IMAGE = settings.get('GAU_VERIFY_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Ensure Kiterunner binary and run discovery for each wordlist
    kr_results = []
    for wordlist_name in KITERUNNER_WORDLISTS:
        print(f"\n[*][Partial Recon] Processing wordlist: {wordlist_name}")
        try:
            kr_binary_path, wordlist_path = ensure_kiterunner_binary(wordlist_name)
            if not kr_binary_path or not wordlist_path:
                print(f"[!][Partial Recon] Could not get binary/wordlist: {wordlist_name}")
                continue
            wordlist_results = run_kiterunner_discovery(
                target_urls,
                kr_binary_path,
                wordlist_path,
                wordlist_name,
                KITERUNNER_RATE_LIMIT,
                KITERUNNER_CONNECTIONS,
                KITERUNNER_TIMEOUT,
                KITERUNNER_SCAN_TIMEOUT,
                KITERUNNER_THREADS,
                KITERUNNER_IGNORE_STATUS,
                KITERUNNER_MATCH_STATUS,
                KITERUNNER_MIN_CONTENT_LENGTH,
                KITERUNNER_HEADERS,
                use_proxy,
            )
            # Merge results, avoiding duplicates
            existing_urls = {(r['url'], r['method']) for r in kr_results}
            for result in wordlist_results:
                if (result['url'], result['method']) not in existing_urls:
                    kr_results.append(result)
                    existing_urls.add((result['url'], result['method']))
            print(f"[+][Partial Recon] {wordlist_name}: {len(wordlist_results)} endpoints found, {len(kr_results)} total unique")
        except Exception as e:
            print(f"[!][Partial Recon] Failed for {wordlist_name}: {e}")

    print(f"[+][Partial Recon] Kiterunner found {len(kr_results)} total API endpoints")

    # Detect additional HTTP methods if enabled
    kr_url_methods = None
    if kr_results and KITERUNNER_DETECT_METHODS:
        kr_url_methods = detect_kiterunner_methods(
            kr_results,
            GAU_VERIFY_DOCKER_IMAGE,
            KITERUNNER_DETECT_METHODS,
            KITERUNNER_METHOD_DETECTION_MODE,
            KITERUNNER_BRUTEFORCE_METHODS,
            KITERUNNER_METHOD_DETECT_TIMEOUT,
            KITERUNNER_METHOD_DETECT_RATE_LIMIT,
            KITERUNNER_METHOD_DETECT_THREADS,
            use_proxy,
        )

    # Merge Kiterunner results into by_base_url structure
    by_base_url = {}
    kr_stats = {
        "kr_total": 0,
        "kr_parsed": 0,
        "kr_new": 0,
        "kr_overlap": 0,
        "kr_methods": {},
        "kr_with_multiple_methods": 0,
    }

    if kr_results:
        by_base_url, kr_stats = merge_kiterunner_into_by_base_url(
            kr_results,
            {},  # Start with empty -- Kiterunner is the only source
            kr_url_methods,
        )
        print(f"[+][Partial Recon] Organized {kr_stats['kr_new']} new endpoints across {len(by_base_url)} base URLs")
        if kr_stats.get('kr_methods'):
            print(f"[+][Partial Recon] Methods found: {kr_stats['kr_methods']}")
        if kr_stats.get('kr_with_multiple_methods', 0) > 0:
            print(f"[+][Partial Recon] Endpoints with multiple methods: {kr_stats['kr_with_multiple_methods']}")

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": [],
        "scan_metadata": {
            "kiterunner_total": kr_stats.get("kr_total", 0),
            "kiterunner_new": kr_stats.get("kr_new", 0),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": [],
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Kiterunner",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Kiterunner API discovery completed successfully")


def run_arjun(config: dict) -> None:
    """
    Run partial parameter discovery using Arjun. Tests common parameter names
    against discovered endpoints to find hidden query/body parameters.

    Targets come from graph (BaseURLs + Endpoints from prior crawling) and/or
    user-provided URLs. Results are merged into the graph via
    update_graph_from_resource_enum() (same as full pipeline).
    """
    from recon.helpers.resource_enum.arjun_helpers import (
        arjun_binary_check,
        run_arjun_discovery,
        merge_arjun_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Arjun since the user explicitly chose to run it
    settings['ARJUN_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Arjun Parameter Discovery (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Check binary availability
    if not arjun_binary_check():
        print("[!][Partial Recon] arjun binary not found in PATH, cannot proceed")
        sys.exit(1)

    # Parse user targets -- Arjun accepts URLs
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    arjun_target_urls = []
    target_domains = set()

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs + Endpoints)...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                driver = graph_client.driver
                with driver.session() as session:
                    # Get all endpoint full URLs (baseurl + path) from the graph
                    result = session.run(
                        """
                        MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT e.baseurl + e.path AS url
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        if url:
                            arjun_target_urls.append(url)

                    # Also add BaseURLs themselves (fallback if no endpoints)
                    result = session.run(
                        """
                        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT b.url AS url, b.host AS host
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        host = record["host"] or ""
                        if url and url not in arjun_target_urls:
                            arjun_target_urls.append(url)
                        if host:
                            target_domains.add(host)

                print(f"[+][Partial Recon] Found {len(arjun_target_urls)} URLs from graph")
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Add user-provided URLs to target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs")
        for url in user_urls:
            if url not in arjun_target_urls:
                arjun_target_urls.append(url)
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0]
            if host:
                target_domains.add(host)

    # Also add domain itself to target_domains for scope filtering
    if domain:
        target_domains.add(domain)

    if not arjun_target_urls:
        print("[!][Partial Recon] No URLs to test (graph has no BaseURLs/Endpoints and no valid user URLs provided).")
        print("[!][Partial Recon] Run Katana or Hakrawler first to discover endpoints, or provide URLs manually.")
        sys.exit(1)

    # Cap to max endpoints (most interesting first -- API/dynamic endpoints)
    ARJUN_MAX_ENDPOINTS = settings.get('ARJUN_MAX_ENDPOINTS', 50)
    if len(arjun_target_urls) > ARJUN_MAX_ENDPOINTS:
        api_urls = [u for u in arjun_target_urls if any(p in u.lower() for p in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/'])]
        dynamic_urls = [u for u in arjun_target_urls if u not in api_urls and any(u.lower().endswith(e) for e in ['.php', '.asp', '.aspx', '.jsp'])]
        other_urls = [u for u in arjun_target_urls if u not in api_urls and u not in dynamic_urls]
        arjun_target_urls = (api_urls + dynamic_urls + other_urls)[:ARJUN_MAX_ENDPOINTS]
        print(f"[*][Partial Recon] Capped to {ARJUN_MAX_ENDPOINTS} endpoints (API: {len(api_urls)}, dynamic: {len(dynamic_urls)}, other: {len(other_urls)})")

    print(f"[+][Partial Recon] Total {len(arjun_target_urls)} URLs to test with Arjun")

    # Extract Arjun settings
    ARJUN_METHODS = settings.get('ARJUN_METHODS', ['GET', 'POST'])
    ARJUN_THREADS = settings.get('ARJUN_THREADS', 2)
    ARJUN_TIMEOUT = settings.get('ARJUN_TIMEOUT', 15)
    ARJUN_SCAN_TIMEOUT = settings.get('ARJUN_SCAN_TIMEOUT', 600)
    ARJUN_CHUNK_SIZE = settings.get('ARJUN_CHUNK_SIZE', 500)
    ARJUN_RATE_LIMIT = settings.get('ARJUN_RATE_LIMIT', 0)
    ARJUN_STABLE = settings.get('ARJUN_STABLE', False)
    ARJUN_PASSIVE = settings.get('ARJUN_PASSIVE', False)
    ARJUN_DISABLE_REDIRECTS = settings.get('ARJUN_DISABLE_REDIRECTS', False)
    ARJUN_CUSTOM_HEADERS = settings.get('ARJUN_CUSTOM_HEADERS', [])

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Run Arjun parameter discovery
    print(f"[*][Partial Recon] Running Arjun parameter discovery on {len(arjun_target_urls)} URLs...")
    arjun_results, arjun_meta = run_arjun_discovery(
        arjun_target_urls,
        ARJUN_METHODS,
        ARJUN_THREADS,
        ARJUN_TIMEOUT,
        ARJUN_SCAN_TIMEOUT,
        ARJUN_CHUNK_SIZE,
        ARJUN_RATE_LIMIT,
        ARJUN_STABLE,
        ARJUN_PASSIVE,
        ARJUN_DISABLE_REDIRECTS,
        ARJUN_CUSTOM_HEADERS,
        target_domains,
        use_proxy,
    )

    # Merge Arjun results into by_base_url structure
    by_base_url = {}
    arjun_stats = {
        "arjun_total": 0,
        "arjun_new_endpoints": 0,
        "arjun_existing_enriched": 0,
        "arjun_params_discovered": 0,
    }

    if arjun_results:
        print(f"[*][Partial Recon] Merging discovered parameters into results...")
        by_base_url, arjun_stats = merge_arjun_into_by_base_url(
            arjun_results,
            {},  # Start with empty -- Arjun is the only source for this partial run
        )
        print(f"[+][Partial Recon] URLs with params: {arjun_stats['arjun_total']}")
        print(f"[+][Partial Recon] New endpoints: {arjun_stats['arjun_new_endpoints']}")
        print(f"[+][Partial Recon] Existing enriched: {arjun_stats['arjun_existing_enriched']}")
        print(f"[+][Partial Recon] Parameters discovered: {arjun_stats['arjun_params_discovered']}")
    else:
        print("[!][Partial Recon] Arjun found no parameters on any tested endpoint.")

    # Build recon_data for graph update (needs domain + subdomains for scope)
    recon_data = {
        "domain": domain,
        "subdomains": [],
    }

    # Get subdomains for scope filtering
    if include_graph:
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    driver = graph_client.driver
                    with driver.session() as session:
                        result = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                  -[:HAS_SUBDOMAIN]->(s:Subdomain)
                            RETURN collect(DISTINCT s.name) AS subdomains
                            """,
                            domain=domain, uid=user_id, pid=project_id,
                        )
                        record = result.single()
                        if record:
                            recon_data["subdomains"] = record["subdomains"] or []
        except Exception:
            pass

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": [],
        "scan_metadata": {
            "arjun_stats": arjun_stats,
            "external_domains": arjun_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": arjun_meta.get("external_domains", []),
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Arjun",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Arjun parameter discovery completed successfully")


def run_jsrecon(config: dict) -> None:
    """
    Run partial JS Recon analysis. Downloads and analyzes JavaScript files
    from graph-discovered URLs and/or user-provided URLs to find secrets,
    endpoints, source maps, dependencies, DOM sinks, and frameworks.

    Input nodes: BaseURL, Endpoint (from graph)
    Output nodes: Secret, Endpoint (merged into graph)

    Same URL-input pattern as run_jsluice() -- reads BaseURLs + Endpoints
    from graph and/or user-provided URLs, runs JS Recon analysis, merges
    results into the graph via update_graph_from_js_recon.
    """
    from recon.js_recon import run_js_recon
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable JS Recon since the user explicitly chose to run it
    settings['JS_RECON_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] JS Recon Scanner")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- JS Recon accepts URLs (same as Jsluice/Katana)
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")  # BaseURL or None

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    target_urls = []

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs + Endpoints)...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                driver = graph_client.driver
                with driver.session() as session:
                    # Get all endpoint full URLs (baseurl + path) from the graph
                    result = session.run(
                        """
                        MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT e.baseurl + e.path AS url
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        if url:
                            target_urls.append(url)

                    # Also add BaseURLs themselves
                    result = session.run(
                        """
                        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT b.url AS url
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        if url and url not in target_urls:
                            target_urls.append(url)

                print(f"[+][Partial Recon] Found {len(target_urls)} URLs from graph")
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Add user-provided URLs to target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs")
        for url in user_urls:
            if url not in target_urls:
                target_urls.append(url)

    # Check for uploaded JS files (they're loaded by run_js_recon internally)
    has_uploaded_files = False
    upload_dir = Path(f'/data/js-recon-uploads/{project_id}')
    if upload_dir.exists():
        uploaded = [f for f in upload_dir.iterdir() if f.is_file()]
        if uploaded:
            has_uploaded_files = True
            print(f"[+][Partial Recon] Found {len(uploaded)} uploaded JS file(s) in {upload_dir}")

    if not target_urls and not has_uploaded_files:
        print("[!][Partial Recon] No URLs to analyze and no uploaded JS files found.")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) and Resource Enumeration (Katana/Hakrawler) first, provide URLs manually, or upload JS files.")
        sys.exit(1)

    print(f"[+][Partial Recon] Total {len(target_urls)} URLs for JS Recon analysis{f' + {len(uploaded)} uploaded files' if has_uploaded_files else ''}")

    # Build a combined_result structure that run_js_recon expects
    # It reads from resource_enum.discovered_urls and http_probe.by_url
    # We populate discovered_urls with all our target URLs
    # and http_probe.by_url as an empty dict (no live probe data in partial mode)
    subdomains = []
    if include_graph:
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    driver = graph_client.driver
                    with driver.session() as session:
                        result = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                  -[:HAS_SUBDOMAIN]->(s:Subdomain)
                            RETURN collect(DISTINCT s.name) AS subdomains
                            """,
                            domain=domain, uid=user_id, pid=project_id,
                        )
                        record = result.single()
                        if record:
                            subdomains = record["subdomains"] or []
        except Exception:
            pass

    combined_result = {
        "domain": domain,
        "dns": {
            "subdomains": [{"subdomain": s, "source": "graph"} for s in subdomains],
        },
        "resource_enum": {
            "discovered_urls": target_urls,
        },
        "http_probe": {
            "by_url": {},
        },
        "metadata": {
            "project_id": project_id,
        },
    }

    # Run JS Recon analysis (same function as the full pipeline)
    print(f"[*][Partial Recon] Running JS Recon analysis...")
    combined_result = run_js_recon(combined_result, settings=settings)

    js_recon_data = combined_result.get("js_recon", {})
    secrets_count = len(js_recon_data.get("secrets", []))
    endpoints_count = len(js_recon_data.get("endpoints", []))
    print(f"[+][Partial Recon] JS Recon found {secrets_count} secrets, {endpoints_count} endpoints")

    if not js_recon_data or (not secrets_count and not endpoints_count):
        print("[*][Partial Recon] No JS Recon findings to update in graph")
        if not js_recon_data.get("scan_metadata", {}).get("js_files_analyzed", 0):
            print("[*][Partial Recon] No JS files were found/analyzed. Ensure target URLs contain .js files.")
        return

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_js_recon(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "JsRecon",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] JS Recon analysis completed successfully")


def _build_vuln_scan_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_vuln_scan expects.

    Returns a dict with 'domain', 'dns', 'subdomains', 'http_probe', and
    'resource_enum' keys. The vuln_scan module uses extract_targets_from_recon()
    (needs dns) and build_target_urls() (prefers resource_enum > http_probe).
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "http_probe": {
            "by_url": {},
        },
        "resource_enum": {
            "by_base_url": {},
            "discovered_urls": [],
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) Domain -> IP relationships (for extract_targets_from_recon)
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                RETURN i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                recon_data["dns"]["domain"]["ips"][bucket].append(addr)

            if (recon_data["dns"]["domain"]["ips"]["ipv4"]
                    or recon_data["dns"]["domain"]["ips"]["ipv6"]):
                recon_data["dns"]["domain"]["has_records"] = True

            # 2) Subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                RETURN s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            subdomain_set = set()
            for record in result:
                sub = record["subdomain"]
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                subdomain_set.add(sub)

                if sub not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][sub] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                recon_data["dns"]["subdomains"][sub]["ips"][bucket].append(addr)

            # Also get subdomains without IPs for the subdomains list
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = record["subdomains"] or []

            # 3) BaseURL nodes (for build_target_urls http_probe fallback)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                RETURN b.url AS url, b.status_code AS status_code,
                       b.host AS host, b.content_type AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                if status_code is not None and int(status_code) >= 500:
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                }

            # 4) Endpoints with parameters (for DAST mode)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.full_url IS NOT NULL
                RETURN e.full_url AS url
                """,
                uid=user_id, pid=project_id,
            )
            discovered_urls = []
            for record in result:
                url = record["url"]
                if url:
                    discovered_urls.append(url)
            recon_data["resource_enum"]["discovered_urls"] = discovered_urls

    return recon_data


def run_nuclei(config: dict) -> None:
    """
    Run partial vulnerability scanning using Nuclei.

    Scans BaseURLs and endpoints from the graph (and/or user-provided URLs)
    with the Nuclei vulnerability scanner. Results are merged into the graph
    via update_graph_from_vuln_scan.
    """
    from recon.vuln_scan import run_vuln_scan
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Nuclei since the user explicitly chose to run it
    settings['NUCLEI_ENABLED'] = True

    # Apply settings_overrides from modal checkboxes (bypass DB settings)
    settings_overrides = config.get("settings_overrides") or {}
    for key, value in settings_overrides.items():
        settings[key] = value

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Nuclei Vulnerability Scanning")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Nuclei accepts URLs
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")  # BaseURL or None

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs, Endpoints, DNS)...")
        recon_data = _build_vuln_scan_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
            "http_probe": {
                "by_url": {},
            },
            "resource_enum": {
                "by_base_url": {},
                "discovered_urls": [],
            },
        }

    # Inject user-provided URLs into http_probe targets
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to scan targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }
            # Also add user URLs with parameters to DAST list
            if "?" in url and "=" in url:
                if url not in recon_data["resource_enum"]["discovered_urls"]:
                    recon_data["resource_enum"]["discovered_urls"].append(url)

    # Ensure all target hostnames are in subdomains list for scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for url_key, url_data in recon_data["http_probe"]["by_url"].items():
        host = url_data.get("host", "")
        if host and host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    # Check we have something to scan
    has_http_targets = bool(recon_data["http_probe"]["by_url"])
    has_dns_targets = bool(recon_data["dns"]["domain"]["has_records"] or recon_data["dns"]["subdomains"])
    if not has_http_targets and not has_dns_targets:
        print("[!][Partial Recon] No targets to scan (no BaseURLs, endpoints, or DNS data in graph).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) or Subdomain Discovery first, or provide URLs manually.")
        sys.exit(1)

    # Run vuln_scan (same function as the full pipeline)
    print(f"[*][Partial Recon] Running Nuclei vulnerability scan...")
    result = run_vuln_scan(recon_data, settings=settings)

    # Also run MITRE enrichment if enabled
    if settings.get('MITRE_ENABLED', True):
        try:
            from recon.add_mitre import run_mitre_enrichment
            print(f"[*][Partial Recon] Running MITRE ATT&CK enrichment...")
            result = run_mitre_enrichment(result, settings=settings)
        except Exception as e:
            print(f"[!][Partial Recon] MITRE enrichment failed: {e}")

    # Pre-create BaseURL + UserInput BEFORE graph update so vuln_scan can find and attach to them
    if user_urls:
        print(f"[*][Partial Recon] Pre-creating BaseURL nodes for user-provided URLs...")
        try:
            from graph_db import Neo4jClient
            from urllib.parse import urlparse as _urlparse
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            # Verify the attachment BaseURL still exists
                            check = session.run(
                                """
                                MATCH (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                RETURN b.url AS url
                                """,
                                url=url_attach_to, uid=user_id, pid=project_id,
                            )
                            if check.single():
                                print(f"[+][Partial Recon] BaseURL {url_attach_to} exists, linking user URLs")
                            else:
                                print(f"[!][Partial Recon] BaseURL {url_attach_to} not found, falling back to UserInput")
                                needs_user_input = True
                                url_attach_to = None

                        if needs_user_input:
                            import uuid
                            user_input_id = str(uuid.uuid4())
                            session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.type = 'url',
                                              ui.values = $urls,
                                              ui.created_at = datetime(),
                                              ui.tool = 'Nuclei'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                domain=domain, uid=user_id, pid=project_id,
                                ui_id=user_input_id, urls=user_urls,
                            )

                        # Create BaseURL nodes for each user URL (so vuln_scan attaches findings here)
                        for url in user_urls:
                            parsed = _urlparse(url)
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            if needs_user_input:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.host = $host,
                                                  b.source = 'partial_recon_user_input',
                                                  b.updated_at = datetime()
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, uid=user_id, pid=project_id,
                                    url=base_url, host=parsed.netloc.split(":")[0],
                                )
                            else:
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.host = $host,
                                                  b.source = 'partial_recon_user_input',
                                                  b.updated_at = datetime()
                                    """,
                                    uid=user_id, pid=project_id,
                                    url=base_url, host=parsed.netloc.split(":")[0],
                                )
                        print(f"[+][Partial Recon] Pre-created BaseURL + UserInput nodes for user URLs")
        except Exception as e:
            print(f"[!][Partial Recon] Failed to pre-create BaseURL nodes: {e}")

    # Update the graph database (vuln_scan will find the BaseURLs and attach findings to them)
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_vuln_scan(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Nuclei vulnerability scanning completed successfully")


def run_security_checks_partial(config: dict) -> None:
    """
    Run partial security checks (Direct IP Access, TLS/SSL, Security Headers, DNS, etc.)

    Uses the same run_security_checks() function from the full pipeline.
    Targets are loaded from the graph (IPs, subdomains, BaseURLs) and/or
    user-provided custom subdomains, IPs, and URLs.
    Results are stored as Vulnerability nodes via update_graph_from_vuln_scan.
    """
    from recon.helpers import run_security_checks
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable security checks since the user explicitly chose to run them
    settings['SECURITY_CHECK_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Security Checks")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets
    user_targets = config.get("user_targets") or {}
    user_subdomains = []
    user_ips = []
    user_urls = []
    ip_attach_to = None
    url_attach_to = None

    if user_targets:
        # Validate subdomains
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                if entry.endswith("." + domain) or entry == domain:
                    user_subdomains.append(entry)
                else:
                    print(f"[!][Partial Recon] Skipping out-of-scope subdomain: {entry}")
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid hostname: {entry}")

        # Validate IPs
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")

        # Validate URLs
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")

    if user_subdomains:
        print(f"[+][Partial Recon] Validated {len(user_subdomains)} custom subdomains")
    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")

    # Track whether we need UserInput nodes
    needs_ip_user_input = bool(user_ips and not ip_attach_to)
    needs_url_user_input = bool(user_urls and not url_attach_to)

    # Build recon_data from Neo4j graph
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs, Subdomains, BaseURLs, DNS)...")
        recon_data = _build_vuln_scan_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
            "http_probe": {
                "by_url": {},
            },
            "resource_enum": {
                "by_base_url": {},
                "discovered_urls": [],
            },
        }

    # STEP 1: Resolve user subdomains and inject into recon_data DNS
    resolved_sub_ips = {}
    if user_subdomains:
        print(f"[*][Partial Recon] Resolving {len(user_subdomains)} custom subdomains...")
        for sub in user_subdomains:
            ips = _resolve_hostname(sub)
            all_ips = ips.get("ipv4", []) + ips.get("ipv6", [])
            if all_ips:
                resolved_sub_ips[sub] = ips
                if sub not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][sub] = {
                        "ips": ips,
                        "has_records": True,
                    }
                else:
                    for bucket in ("ipv4", "ipv6"):
                        for addr in ips.get(bucket, []):
                            if addr not in recon_data["dns"]["subdomains"][sub]["ips"][bucket]:
                                recon_data["dns"]["subdomains"][sub]["ips"][bucket].append(addr)
                if sub not in recon_data.get("subdomains", []):
                    recon_data.setdefault("subdomains", []).append(sub)
                print(f"[+][Partial Recon] Resolved {sub} -> {all_ips}")
            else:
                print(f"[!][Partial Recon] Could not resolve {sub}")

    # STEP 2: Inject user IPs into recon_data DNS
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs to DNS data")
        for ip_str in user_ips:
            bucket = _classify_ip(ip_str)
            if ip_attach_to:
                # Inject into subdomain's IP list
                if ip_attach_to not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][ip_attach_to] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                if ip_str not in recon_data["dns"]["subdomains"][ip_attach_to]["ips"][bucket]:
                    recon_data["dns"]["subdomains"][ip_attach_to]["ips"][bucket].append(ip_str)
            else:
                # Inject into domain's IP list
                if ip_str not in recon_data["dns"]["domain"]["ips"][bucket]:
                    recon_data["dns"]["domain"]["ips"][bucket].append(ip_str)
                    recon_data["dns"]["domain"]["has_records"] = True

    # STEP 3: Inject user URLs into http_probe targets
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to scan targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }

    # Check we have something to scan
    has_http_targets = bool(recon_data["http_probe"]["by_url"])
    has_dns_targets = bool(recon_data["dns"]["domain"]["has_records"] or recon_data["dns"]["subdomains"])
    if not has_http_targets and not has_dns_targets:
        print("[!][Partial Recon] No targets to scan (no IPs, subdomains, or BaseURLs in graph).")
        print("[!][Partial Recon] Run Subdomain Discovery and HTTP Probing first, or provide custom targets.")
        sys.exit(1)

    # Build enabled checks dict from settings
    security_checks_enabled = {
        "direct_ip_http": settings.get('SECURITY_CHECK_DIRECT_IP_HTTP', True),
        "direct_ip_https": settings.get('SECURITY_CHECK_DIRECT_IP_HTTPS', True),
        "ip_api_exposed": settings.get('SECURITY_CHECK_IP_API_EXPOSED', True),
        "waf_bypass": settings.get('SECURITY_CHECK_WAF_BYPASS', True),
        "tls_expiring_soon": settings.get('SECURITY_CHECK_TLS_EXPIRING_SOON', True),
        "missing_referrer_policy": settings.get('SECURITY_CHECK_MISSING_REFERRER_POLICY', True),
        "missing_permissions_policy": settings.get('SECURITY_CHECK_MISSING_PERMISSIONS_POLICY', True),
        "missing_coop": settings.get('SECURITY_CHECK_MISSING_COOP', True),
        "missing_corp": settings.get('SECURITY_CHECK_MISSING_CORP', True),
        "missing_coep": settings.get('SECURITY_CHECK_MISSING_COEP', True),
        "cache_control_missing": settings.get('SECURITY_CHECK_CACHE_CONTROL_MISSING', True),
        "login_no_https": settings.get('SECURITY_CHECK_LOGIN_NO_HTTPS', True),
        "session_no_secure": settings.get('SECURITY_CHECK_SESSION_NO_SECURE', True),
        "session_no_httponly": settings.get('SECURITY_CHECK_SESSION_NO_HTTPONLY', True),
        "basic_auth_no_tls": settings.get('SECURITY_CHECK_BASIC_AUTH_NO_TLS', True),
        "spf_missing": settings.get('SECURITY_CHECK_SPF_MISSING', True),
        "dmarc_missing": settings.get('SECURITY_CHECK_DMARC_MISSING', True),
        "dnssec_missing": settings.get('SECURITY_CHECK_DNSSEC_MISSING', True),
        "zone_transfer": settings.get('SECURITY_CHECK_ZONE_TRANSFER', True),
        "admin_port_exposed": settings.get('SECURITY_CHECK_ADMIN_PORT_EXPOSED', True),
        "database_exposed": settings.get('SECURITY_CHECK_DATABASE_EXPOSED', True),
        "redis_no_auth": settings.get('SECURITY_CHECK_REDIS_NO_AUTH', True),
        "kubernetes_api_exposed": settings.get('SECURITY_CHECK_KUBERNETES_API_EXPOSED', True),
        "smtp_open_relay": settings.get('SECURITY_CHECK_SMTP_OPEN_RELAY', True),
        "csp_unsafe_inline": settings.get('SECURITY_CHECK_CSP_UNSAFE_INLINE', True),
        "insecure_form_action": settings.get('SECURITY_CHECK_INSECURE_FORM_ACTION', True),
        "no_rate_limiting": settings.get('SECURITY_CHECK_NO_RATE_LIMITING', True),
    }

    enabled_count = sum(1 for v in security_checks_enabled.values() if v)
    print(f"[*][Partial Recon] {enabled_count}/{len(security_checks_enabled)} security checks enabled")

    if not any(security_checks_enabled.values()):
        print("[!][Partial Recon] All individual security checks are disabled in settings.")
        print("[!][Partial Recon] Enable at least one check category to run security checks.")
        sys.exit(1)

    # Run security checks (same function as the full pipeline)
    print(f"[*][Partial Recon] Running security checks...")
    security_results = run_security_checks(
        recon_data=recon_data,
        enabled_checks=security_checks_enabled,
        timeout=settings.get('SECURITY_CHECK_TIMEOUT', 10),
        tls_expiry_days=settings.get('SECURITY_CHECK_TLS_EXPIRY_DAYS', 30),
        max_workers=settings.get('SECURITY_CHECK_MAX_WORKERS', 10),
    )

    # Merge security checks into recon_data for graph update
    if "vuln_scan" in recon_data:
        recon_data["vuln_scan"]["security_checks"] = security_results.get("security_checks", {})
    else:
        recon_data["vuln_scan"] = {"security_checks": security_results.get("security_checks", {})}

    findings = security_results.get("security_checks", {}).get("findings", [])
    print(f"[+][Partial Recon] Security checks completed: {len(findings)} findings")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_vuln_scan(
                    recon_data=recon_data,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided subdomains to graph
                if user_subdomains and resolved_sub_ips:
                    driver = graph_client.driver
                    with driver.session() as session:
                        for sub, ips in resolved_sub_ips.items():
                            session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                ON CREATE SET s.source = 'partial_recon_user_input',
                                              s.created_at = datetime()
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                domain=domain, uid=user_id, pid=project_id, sub=sub,
                            )
                            for bucket in ("ipv4", "ipv6"):
                                for addr in ips.get(bucket, []):
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        ON CREATE SET i.version = $version,
                                                      i.source = 'partial_recon_user_input',
                                                      i.created_at = datetime()
                                        WITH i
                                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                        MERGE (s)-[:RESOLVES_TO]->(i)
                                        """,
                                        addr=addr, uid=user_id, pid=project_id,
                                        version=bucket, sub=sub,
                                    )
                    print(f"[+][Partial Recon] Linked {len(resolved_sub_ips)} user subdomains to graph")

                # Link user-provided IPs to graph
                if user_ips:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to:
                            # Check if subdomain exists
                            check = session.run(
                                """
                                MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                RETURN s.name AS name
                                """,
                                sub=ip_attach_to, uid=user_id, pid=project_id,
                            )
                            if check.single():
                                for ip_str in user_ips:
                                    version = _classify_ip(ip_str)
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        ON CREATE SET i.version = $version,
                                                      i.source = 'partial_recon_user_input',
                                                      i.created_at = datetime()
                                        WITH i
                                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                        MERGE (s)-[:RESOLVES_TO]->(i)
                                        """,
                                        addr=ip_str, uid=user_id, pid=project_id,
                                        version=version, sub=ip_attach_to,
                                    )
                                print(f"[+][Partial Recon] Linked {len(user_ips)} IPs to {ip_attach_to}")
                            else:
                                print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found, falling back to UserInput")
                                needs_ip_user_input = True

                        if needs_ip_user_input:
                            user_input_id = str(uuid.uuid4())
                            session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.type = 'ip',
                                              ui.values = $ips,
                                              ui.created_at = datetime(),
                                              ui.tool = 'SecurityChecks'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                domain=domain, uid=user_id, pid=project_id,
                                ui_id=user_input_id, ips=user_ips,
                            )
                            for ip_str in user_ips:
                                version = _classify_ip(ip_str)
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    ON CREATE SET i.version = $version,
                                                  i.source = 'partial_recon_user_input',
                                                  i.created_at = datetime()
                                    WITH i
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    addr=ip_str, uid=user_id, pid=project_id,
                                    version=version, ui_id=user_input_id,
                                )
                            print(f"[+][Partial Recon] Created UserInput + linked {len(user_ips)} IPs via PRODUCED")

                # Link user-provided URLs to graph
                if user_urls:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            check = session.run(
                                """
                                MATCH (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                RETURN b.url AS url
                                """,
                                url=url_attach_to, uid=user_id, pid=project_id,
                            )
                            if check.single():
                                print(f"[+][Partial Recon] BaseURL {url_attach_to} exists, linking user URLs")
                            else:
                                print(f"[!][Partial Recon] BaseURL {url_attach_to} not found, falling back to UserInput")
                                needs_url_user_input = True
                                url_attach_to = None

                        if needs_url_user_input:
                            user_input_id = str(uuid.uuid4())
                            session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.type = 'url',
                                              ui.values = $urls,
                                              ui.created_at = datetime(),
                                              ui.tool = 'SecurityChecks'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                domain=domain, uid=user_id, pid=project_id,
                                ui_id=user_input_id, urls=user_urls,
                            )
                            for url in user_urls:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MATCH (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, uid=user_id, pid=project_id, url=url,
                                )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Security checks completed successfully")


def run_shodan(config: dict) -> None:
    """
    Run partial Shodan OSINT enrichment.

    Queries existing IPs from the graph and enriches them with Shodan data
    (host lookup, reverse DNS, domain DNS, passive CVEs).
    Users can also provide custom IPs to enrich.
    """
    from recon.shodan_enrich import run_shodan_enrichment
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    include_graph = config.get("include_graph_targets", True)

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Shodan OSINT Enrichment")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable Shodan for partial recon (user explicitly triggered it)
    settings["SHODAN_ENABLED"] = True

    # Parse user-provided IPs from structured targets
    user_targets = config.get("user_targets") or {}
    user_ips = []
    ip_attach_to = None

    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")
        ip_attach_to = user_targets.get("ip_attach_to")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")

    needs_user_input = bool(user_ips and not ip_attach_to)
    user_input_id = str(uuid.uuid4()) if needs_user_input else None

    # Build combined_result from graph (IPs + subdomains)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs and subdomains)...")
        combined_result = _build_recon_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        combined_result = {
            "domain": domain,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Inject user-provided IPs into combined_result DNS structure
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs to DNS data")
        for ip_str in user_ips:
            bucket = _classify_ip(ip_str)
            if ip_attach_to:
                if ip_attach_to not in combined_result["dns"]["subdomains"]:
                    combined_result["dns"]["subdomains"][ip_attach_to] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                if ip_str not in combined_result["dns"]["subdomains"][ip_attach_to]["ips"][bucket]:
                    combined_result["dns"]["subdomains"][ip_attach_to]["ips"][bucket].append(ip_str)
            else:
                if ip_str not in combined_result["dns"]["domain"]["ips"][bucket]:
                    combined_result["dns"]["domain"]["ips"][bucket].append(ip_str)
                    combined_result["dns"]["domain"]["has_records"] = True

    # Count IPs for logging
    ip_count = len(combined_result.get("dns", {}).get("domain", {}).get("ips", {}).get("ipv4", []))
    for _sub, info in combined_result.get("dns", {}).get("subdomains", {}).items():
        ip_count += len(info.get("ips", {}).get("ipv4", []))
    print(f"[+][Partial Recon] Total IPs for enrichment: {ip_count}")

    if ip_count == 0:
        print(f"[-][Partial Recon] No IPs to enrich. Run Subdomain Discovery first or provide custom IPs.")
        return

    # Run Shodan enrichment (same function as full pipeline)
    combined_result = run_shodan_enrichment(combined_result, settings)

    shodan_data = combined_result.get("shodan", {})
    if not shodan_data:
        print(f"[-][Partial Recon] Shodan returned no data")
        return

    print(f"[+][Partial Recon] Shodan hosts enriched: {len(shodan_data.get('hosts', []))}")
    print(f"[+][Partial Recon] Reverse DNS entries: {len(shodan_data.get('reverse_dns', {}))}")
    print(f"[+][Partial Recon] Domain DNS subdomains: {len(shodan_data.get('domain_dns', {}).get('subdomains', []))}")
    print(f"[+][Partial Recon] Passive CVEs: {len(shodan_data.get('cves', []))}")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_shodan(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")

                # Link user-provided IPs to graph
                if user_ips:
                    needs_ip_user_input = needs_user_input
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to:
                            check = session.run(
                                """
                                MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                RETURN s.name AS name
                                """,
                                sub=ip_attach_to, uid=user_id, pid=project_id,
                            )
                            if check.single():
                                for ip_str in user_ips:
                                    version = _classify_ip(ip_str)
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        ON CREATE SET i.version = $version,
                                                      i.source = 'partial_recon_user_input',
                                                      i.created_at = datetime()
                                        WITH i
                                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                        MERGE (s)-[:RESOLVES_TO]->(i)
                                        """,
                                        addr=ip_str, uid=user_id, pid=project_id,
                                        version=version, sub=ip_attach_to,
                                    )
                                print(f"[+][Partial Recon] Linked {len(user_ips)} IPs to {ip_attach_to}")
                            else:
                                print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found, falling back to UserInput")
                                needs_ip_user_input = True

                        if needs_ip_user_input:
                            session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.type = 'ip',
                                              ui.values = $ips,
                                              ui.created_at = datetime(),
                                              ui.tool = 'Shodan'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                domain=domain, uid=user_id, pid=project_id,
                                ui_id=user_input_id, ips=user_ips,
                            )
                            for ip_str in user_ips:
                                version = _classify_ip(ip_str)
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    ON CREATE SET i.version = $version,
                                                  i.source = 'partial_recon_user_input',
                                                  i.created_at = datetime()
                                    WITH i
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    addr=ip_str, uid=user_id, pid=project_id,
                                    version=version, ui_id=user_input_id,
                                )
                            print(f"[+][Partial Recon] Created UserInput node for {len(user_ips)} IPs")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Shodan enrichment completed successfully")


def run_urlscan(config: dict) -> None:
    """
    Run partial URLScan.io passive enrichment.

    Phase A (discovery): discovers subdomains, IPs, external domains, domain age.
    Phase B (enrichment): enriches existing BaseURLs with screenshots/endpoints/parameters.
    """
    from recon.urlscan_enrich import run_urlscan_discovery_only
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] URLScan.io Passive Enrichment")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable URLScan for partial recon (user explicitly triggered it)
    settings["URLSCAN_ENABLED"] = True

    # Run URLScan discovery (same function as full pipeline Phase A)
    urlscan_data = run_urlscan_discovery_only(domain, settings)

    if not urlscan_data or urlscan_data.get("results_count", 0) == 0:
        print(f"[-][Partial Recon] URLScan returned no results for {domain}")
        return

    print(f"[+][Partial Recon] URLScan returned {urlscan_data.get('results_count', 0)} results")
    print(f"[+][Partial Recon] Subdomains: {len(urlscan_data.get('subdomains_discovered', []))}")
    print(f"[+][Partial Recon] IPs: {len(urlscan_data.get('ips_discovered', []))}")
    print(f"[+][Partial Recon] URLs with paths: {len(urlscan_data.get('urls_with_paths', []))}")
    print(f"[+][Partial Recon] External domains: {len(urlscan_data.get('external_domains', []))}")

    # Build combined_result structure expected by graph update methods
    combined_result = {
        "domain": domain,
        "urlscan": urlscan_data,
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # Phase A: discovery (subdomains, IPs, external domains, domain age)
                discovery_stats = graph_client.update_graph_from_urlscan_discovery(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Discovery graph update: {json.dumps(discovery_stats, default=str)}")

                # Phase B: enrichment (BaseURL screenshots, endpoints, parameters)
                enrichment_stats = graph_client.update_graph_from_urlscan_enrichment(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Enrichment graph update: {json.dumps(enrichment_stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] URLScan enrichment completed successfully")


def run_uncover(config: dict) -> None:
    """
    Run partial Uncover multi-engine target expansion.

    Queries Shodan, Censys, FOFA, ZoomEye, Netlas, CriminalIP, and other
    search engines to discover additional IPs, subdomains, ports, and URLs
    associated with the target domain.
    """
    from recon.uncover_enrich import run_uncover_expansion
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Uncover Multi-Engine Expansion")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable Uncover for partial recon (user explicitly triggered it)
    settings["UNCOVER_ENABLED"] = True
    settings["OSINT_ENRICHMENT_ENABLED"] = True

    # API keys for Uncover engines are only loaded by get_settings() when
    # UNCOVER_ENABLED is True in the project config.  Since we force-enable it
    # after the fact, we must manually load the keys from user global settings.
    webapp_url = os.environ.get("WEBAPP_API_URL", "")
    if webapp_url and user_id:
        try:
            from recon.project_settings import _fetch_user_settings_full
            user_global = _fetch_user_settings_full(user_id, webapp_url)
            if user_global:
                # Shared OSINT keys (may already be set if the per-tool toggle was on)
                if not settings.get('SHODAN_API_KEY'):
                    settings['SHODAN_API_KEY'] = user_global.get('shodanApiKey', '')
                if not settings.get('FOFA_API_KEY'):
                    settings['FOFA_API_KEY'] = user_global.get('fofaApiKey', '')
                if not settings.get('ZOOMEYE_API_KEY'):
                    settings['ZOOMEYE_API_KEY'] = user_global.get('zoomEyeApiKey', '')
                if not settings.get('NETLAS_API_KEY'):
                    settings['NETLAS_API_KEY'] = user_global.get('netlasApiKey', '')
                if not settings.get('CRIMINALIP_API_KEY'):
                    settings['CRIMINALIP_API_KEY'] = user_global.get('criminalIpApiKey', '')
                if not settings.get('CENSYS_API_TOKEN'):
                    settings['CENSYS_API_TOKEN'] = user_global.get('censysApiToken', '')
                if not settings.get('CENSYS_ORG_ID'):
                    settings['CENSYS_ORG_ID'] = user_global.get('censysOrgId', '')
                # Uncover-specific keys
                settings['UNCOVER_QUAKE_API_KEY'] = user_global.get('quakeApiKey', '')
                settings['UNCOVER_HUNTER_API_KEY'] = user_global.get('hunterApiKey', '')
                settings['UNCOVER_PUBLICWWW_API_KEY'] = user_global.get('publicWwwApiKey', '')
                settings['UNCOVER_HUNTERHOW_API_KEY'] = user_global.get('hunterHowApiKey', '')
                settings['UNCOVER_GOOGLE_API_KEY'] = user_global.get('googleApiKey', '')
                settings['UNCOVER_GOOGLE_API_CX'] = user_global.get('googleApiCx', '')
                settings['UNCOVER_ONYPHE_API_KEY'] = user_global.get('onypheApiKey', '')
                settings['UNCOVER_DRIFTNET_API_KEY'] = user_global.get('driftnetApiKey', '')
                print(f"[+][Partial Recon] Loaded API keys from user settings")
        except Exception as e:
            print(f"[!][Partial Recon] Could not load user API keys: {e}")

    # Build minimal combined_result structure expected by run_uncover_expansion
    combined_result = {
        "domain": domain,
    }

    # Run Uncover expansion (same function as full pipeline)
    uncover_data = run_uncover_expansion(combined_result, settings)

    if not uncover_data:
        print(f"[-][Partial Recon] Uncover returned no results for {domain}")
        return

    print(f"[+][Partial Recon] Uncover returned {uncover_data.get('total_deduped', 0)} deduplicated results")
    print(f"[+][Partial Recon] Hosts: {len(uncover_data.get('hosts', []))}")
    print(f"[+][Partial Recon] IPs: {len(uncover_data.get('ips', []))}")
    print(f"[+][Partial Recon] URLs: {len(uncover_data.get('urls', []))}")

    # Build combined_result structure expected by graph update method
    combined_result["uncover"] = uncover_data

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_uncover(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Uncover expansion completed successfully")


def run_osint_enrichment(config: dict) -> None:
    """
    Run partial OSINT Enrichment (Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP).

    Queries existing IPs from the graph and enriches them with passive OSINT data.
    Enabled sub-tools run in parallel (same as the full pipeline GROUP 3b).
    Users can also provide custom IPs to enrich.
    """
    import importlib
    from concurrent.futures import ThreadPoolExecutor
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    include_graph = config.get("include_graph_targets", True)

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] OSINT Enrichment (multi-tool)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable OSINT enrichment for partial recon (user explicitly triggered it)
    settings["OSINT_ENRICHMENT_ENABLED"] = True

    # Build combined_result from graph (IPs + subdomains)
    if include_graph:
        combined_result = _build_recon_data_from_graph(domain, user_id, project_id)
    else:
        combined_result = {
            "domain": domain,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Parse user-provided IPs
    user_targets = config.get("user_targets") or {}
    user_ips = []
    ip_attach_to = None
    needs_user_input = False

    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")
        ip_attach_to = user_targets.get("ip_attach_to")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
        needs_user_input = bool(user_ips and not ip_attach_to)

        # Inject user IPs into combined_result so enrichment tools can see them
        import ipaddress as _ipaddress
        for raw_ip in user_ips:
            raw_ip = raw_ip.strip()
            # Expand CIDRs
            expanded = []
            if "/" in raw_ip:
                try:
                    net = _ipaddress.ip_network(raw_ip, strict=False)
                    expanded = [str(h) for h in net.hosts()]
                    if not expanded:
                        expanded = [str(net.network_address)]
                except ValueError:
                    expanded = [raw_ip]
            else:
                expanded = [raw_ip]

            for ip_addr in expanded:
                ip_type = _classify_ip(ip_addr)
                if ip_attach_to:
                    # Inject into subdomain bucket
                    sub_key = ip_attach_to
                    if sub_key not in combined_result["dns"]["subdomains"]:
                        combined_result["dns"]["subdomains"][sub_key] = {
                            "ips": {"ipv4": [], "ipv6": []}, "has_records": True,
                        }
                    sub_ips = combined_result["dns"]["subdomains"][sub_key]["ips"]
                    if ip_addr not in sub_ips.get(ip_type, []):
                        sub_ips.setdefault(ip_type, []).append(ip_addr)
                else:
                    # Inject into domain-level IPs
                    domain_ips = combined_result["dns"]["domain"]["ips"]
                    if ip_addr not in domain_ips.get(ip_type, []):
                        domain_ips.setdefault(ip_type, []).append(ip_addr)

    # Count IPs for logging
    ip_count = len(combined_result.get("dns", {}).get("domain", {}).get("ips", {}).get("ipv4", []))
    for _sub, info in combined_result.get("dns", {}).get("subdomains", {}).items():
        ip_count += len(info.get("ips", {}).get("ipv4", []))
    print(f"[+][Partial Recon] Total IPs for enrichment: {ip_count}")

    if ip_count == 0:
        print(f"[-][Partial Recon] No IPs to enrich. Provide custom IPs or run Subdomain Discovery first.")
        return

    # OSINT sub-tool registry (same as main.py GROUP 3b)
    _osint_tools = {
        'censys': ('CENSYS_ENABLED', 'recon.censys_enrich', 'run_censys_enrichment_isolated', 'update_graph_from_censys'),
        'fofa': ('FOFA_ENABLED', 'recon.fofa_enrich', 'run_fofa_enrichment_isolated', 'update_graph_from_fofa'),
        'otx': ('OTX_ENABLED', 'recon.otx_enrich', 'run_otx_enrichment_isolated', 'update_graph_from_otx'),
        'netlas': ('NETLAS_ENABLED', 'recon.netlas_enrich', 'run_netlas_enrichment_isolated', 'update_graph_from_netlas'),
        'virustotal': ('VIRUSTOTAL_ENABLED', 'recon.virustotal_enrich', 'run_virustotal_enrichment_isolated', 'update_graph_from_virustotal'),
        'zoomeye': ('ZOOMEYE_ENABLED', 'recon.zoomeye_enrich', 'run_zoomeye_enrichment_isolated', 'update_graph_from_zoomeye'),
        'criminalip': ('CRIMINALIP_ENABLED', 'recon.criminalip_enrich', 'run_criminalip_enrichment_isolated', 'update_graph_from_criminalip'),
    }

    # Filter to enabled sub-tools with valid API keys
    enabled_osint = {
        name: cfg for name, cfg in _osint_tools.items()
        if settings.get(cfg[0], False)
        and (
            settings.get(f'{name.upper()}_API_KEY', '')
            or (name == 'censys' and settings.get('CENSYS_API_TOKEN', ''))
            or name == 'otx'  # OTX supports anonymous requests without an API key
        )
    }

    if not enabled_osint:
        print(f"[-][Partial Recon] No OSINT sub-tools are enabled or have valid API keys.")
        print(f"[-][Partial Recon] Enable at least one OSINT tool in project settings and configure its API key.")
        return

    print(f"[+][Partial Recon] Enabled OSINT tools: {', '.join(enabled_osint.keys())}")

    # Run enabled sub-tools in parallel (same pattern as main.py)
    osint_workers = min(len(enabled_osint), 5)
    with ThreadPoolExecutor(max_workers=osint_workers, thread_name_prefix="osint") as osint_exec:
        osint_futures = {}
        for name, (_, module_path, func_name, _) in enabled_osint.items():
            mod = importlib.import_module(module_path)
            fn = getattr(mod, func_name)
            osint_futures[name] = osint_exec.submit(fn, combined_result, settings)

        for name, future in osint_futures.items():
            try:
                data = future.result()
                if data:
                    combined_result[name] = data
                    print(f"[+][{name.upper()}] Enrichment completed")
                else:
                    print(f"[-][{name.upper()}] No data returned")
            except Exception as e:
                print(f"[!][{name.upper()}] Enrichment failed: {e}")

    # Update the graph database for each completed tool
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                for name, (_, _, _, graph_method) in enabled_osint.items():
                    if name in combined_result:
                        try:
                            update_fn = getattr(graph_client, graph_method)
                            stats = update_fn(
                                recon_data=combined_result,
                                user_id=user_id,
                                project_id=project_id,
                            )
                            print(f"[+][{name.upper()}] Graph updated: {json.dumps(stats, default=str)}")
                        except Exception as e:
                            print(f"[!][{name.upper()}] Graph update failed: {e}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    # Link user-provided IPs to graph (RESOLVES_TO or UserInput PRODUCED)
    if user_ips:
        print(f"[*][Partial Recon] Linking {len(user_ips)} user-provided IPs to graph...")
        try:
            from graph_db import Neo4jClient as _Neo4jClient2
            with _Neo4jClient2() as gc:
                if gc.verify_connection():
                    with gc.driver.session() as sess:
                        if needs_user_input:
                            # Create UserInput node for generic IPs
                            user_input_id = str(uuid.uuid4())
                            sess.run(
                                """
                                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.source = 'OsintEnrichment',
                                              ui.created_at = datetime(),
                                              ui.label = 'Custom IPs for OSINT enrichment'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                uid=user_id, pid=project_id, ui_id=user_input_id,
                            )
                            # Link each IP to UserInput
                            for raw_ip in user_ips:
                                expanded = [raw_ip]
                                if "/" in raw_ip:
                                    import ipaddress as _ipa
                                    try:
                                        net = _ipa.ip_network(raw_ip, strict=False)
                                        expanded = [str(h) for h in net.hosts()] or [str(net.network_address)]
                                    except ValueError:
                                        pass
                                for ip_addr in expanded:
                                    sess.run(
                                        """
                                        MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                        MERGE (ip:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (ui)-[:PRODUCED]->(ip)
                                        """,
                                        uid=user_id, pid=project_id, ui_id=user_input_id, addr=ip_addr,
                                    )
                            print(f"[+][Partial Recon] Created UserInput -> PRODUCED -> IP links")
                        elif ip_attach_to:
                            # Attach IPs to existing subdomain via RESOLVES_TO
                            for raw_ip in user_ips:
                                expanded = [raw_ip]
                                if "/" in raw_ip:
                                    import ipaddress as _ipa
                                    try:
                                        net = _ipa.ip_network(raw_ip, strict=False)
                                        expanded = [str(h) for h in net.hosts()] or [str(net.network_address)]
                                    except ValueError:
                                        pass
                                for ip_addr in expanded:
                                    sess.run(
                                        """
                                        MERGE (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                        MERGE (ip:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (s)-[:RESOLVES_TO]->(ip)
                                        """,
                                        uid=user_id, pid=project_id, sub=ip_attach_to, addr=ip_addr,
                                    )
                            print(f"[+][Partial Recon] Created Subdomain -> RESOLVES_TO -> IP links")
        except Exception as e:
            print(f"[!][Partial Recon] User IP linking failed: {e}")

    print(f"\n[+][Partial Recon] OSINT enrichment completed successfully")


def _cleanup_orphan_user_inputs(user_id: str, project_id: str) -> int:
    """
    Delete UserInput nodes that have no outgoing relationships (except
    the incoming HAS_USER_INPUT from Domain).

    After a partial recon tool runs, a UserInput node may have been created
    for user-provided targets (generic IPs, URLs, etc.). If the scan produced
    no results for those targets, the UserInput sits orphaned -- connected to
    the Domain via HAS_USER_INPUT but with no outgoing children.

    Different tools create different outgoing relationships from UserInput:
      - PRODUCED (port scanners, resource enum tools)
      - HAS_VULNERABILITY (Nuclei via BaseURL)
      - etc.

    This function checks for ANY outgoing relationship from UserInput.
    If the node only has the incoming HAS_USER_INPUT and nothing going out,
    it's an orphan and gets deleted.

    Returns:
        Number of orphan UserInput nodes deleted.
    """
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return 0
            with graph_client.driver.session() as session:
                result = session.run(
                    """
                    MATCH (ui:UserInput {user_id: $uid, project_id: $pid})
                    WHERE NOT (ui)-->()
                    WITH ui, ui.id AS uid_id
                    DETACH DELETE ui
                    RETURN count(uid_id) AS deleted
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                deleted = record["deleted"] if record else 0
                if deleted:
                    print(f"[+][Partial Recon] Cleaned up {deleted} orphan UserInput node(s) (no outgoing relationships)")
                return deleted
    except Exception as e:
        print(f"[!][Partial Recon] UserInput cleanup failed: {e}")
        return 0


def main():
    config = load_config()
    tool_id = config.get("tool_id", "")

    print(f"[*][Partial Recon] Starting partial recon for tool: {tool_id}")
    print(f"[*][Partial Recon] Timestamp: {datetime.now().isoformat()}")

    if tool_id == "SubdomainDiscovery":
        run_subdomain_discovery(config)
    elif tool_id == "Naabu":
        run_naabu(config)
    elif tool_id == "Masscan":
        run_masscan(config)
    elif tool_id == "Nmap":
        run_nmap(config)
    elif tool_id == "Httpx":
        run_httpx(config)
    elif tool_id == "Katana":
        run_katana(config)
    elif tool_id == "Hakrawler":
        run_hakrawler(config)
    elif tool_id == "Gau":
        run_gau(config)
    elif tool_id == "Jsluice":
        run_jsluice(config)
    elif tool_id == "Kiterunner":
        run_kiterunner(config)
    elif tool_id == "ParamSpider":
        run_paramspider(config)
    elif tool_id == "Ffuf":
        run_ffuf(config)
    elif tool_id == "Arjun":
        run_arjun(config)
    elif tool_id == "JsRecon":
        run_jsrecon(config)
    elif tool_id == "Nuclei":
        run_nuclei(config)
    elif tool_id == "SecurityChecks":
        run_security_checks_partial(config)
    elif tool_id == "Shodan":
        run_shodan(config)
    elif tool_id == "Urlscan":
        run_urlscan(config)
    elif tool_id == "Uncover":
        run_uncover(config)
    elif tool_id == "OsintEnrichment":
        run_osint_enrichment(config)
    else:
        print(f"[!][Partial Recon] Unknown tool_id: {tool_id}")
        sys.exit(1)

    # Clean up orphan UserInput nodes (created but no PRODUCED children)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    if user_id and project_id:
        _cleanup_orphan_user_inputs(user_id, project_id)


if __name__ == "__main__":
    main()
