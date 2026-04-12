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
  - Katana: runs run_katana_crawler() from helpers/resource_enum
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
    else:
        print(f"[!][Partial Recon] Unknown tool_id: {tool_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
