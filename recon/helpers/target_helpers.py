"""
RedAmon - Target Extraction Helpers
====================================
Functions for extracting and building target URLs from reconnaissance data.
"""

from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# =============================================================================
# Target Extraction from Recon Data
# =============================================================================

def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract all unique IPs, hostnames, and build IP-to-hostname mapping.

    Honors recon_data["metadata"]["include_root_domain"]: when explicitly
    False, the apex/root domain is NOT added to the hostname set, even when
    dns.domain is populated. The full pipeline sets this flag in main.py
    (parse_target + GROUP-2/3 branches); partial-recon graph builders set
    it from project settings. Default (flag missing) is True, preserving
    legacy behavior where the apex is always included.

    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    ips = set()
    hostnames = set()
    ip_to_hostnames = {}

    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames, ip_to_hostnames

    metadata = recon_data.get("metadata") or {}
    include_root_domain = metadata.get("include_root_domain", True)

    # Extract from root domain
    domain = recon_data.get("domain", "") or metadata.get("target", "")
    domain_dns = dns_data.get("domain", {})
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])

        ips.update(ipv4_list)
        ips.update(ipv6_list)

        if domain and include_root_domain:
            hostnames.add(domain)
            for ip in ipv4_list + ipv6_list:
                if ip:
                    if ip not in ip_to_hostnames:
                        ip_to_hostnames[ip] = []
                    if domain not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(domain)
    
    # Extract from all subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, subdomain_data in subdomains_dns.items():
        if subdomain_data:
            if subdomain_data.get("has_records"):
                hostnames.add(subdomain)
            
            if subdomain_data.get("ips"):
                ipv4_list = subdomain_data["ips"].get("ipv4", [])
                ipv6_list = subdomain_data["ips"].get("ipv6", [])
                
                ips.update(ipv4_list)
                ips.update(ipv6_list)
                
                for ip in ipv4_list + ipv6_list:
                    if ip:
                        if ip not in ip_to_hostnames:
                            ip_to_hostnames[ip] = []
                        if subdomain not in ip_to_hostnames[ip]:
                            ip_to_hostnames[ip].append(subdomain)
    
    # Filter out empty strings
    ips = {ip for ip in ips if ip}
    hostnames = {h for h in hostnames if h}
    
    return ips, hostnames, ip_to_hostnames


# =============================================================================
# URL Building from httpx Data
# =============================================================================

def build_target_urls_from_httpx(httpx_data: Optional[dict]) -> List[str]:
    """
    Build list of target URLs from httpx scan results.
    Uses live URLs discovered by httpx for more accurate targeting.
    
    Args:
        httpx_data: httpx scan results containing live URLs
        
    Returns:
        List of live URLs to scan
    """
    urls = []
    
    if httpx_data:
        # Use live URLs from httpx (already verified to be responding)
        by_url = httpx_data.get("by_url", {})
        for url, url_data in by_url.items():
            status_code = url_data.get("status_code")
            # Include URLs with successful responses (not server errors)
            if status_code and status_code < 500:
                urls.append(url)
    
    return sorted(list(set(urls)))


# =============================================================================
# URL Building from Resource Enumeration Data
# =============================================================================

def build_target_urls_from_resource_enum(resource_enum_data: Optional[dict]) -> Tuple[List[str], List[str]]:
    """
    Build list of target URLs from resource_enum data.

    Args:
        resource_enum_data: Resource enumeration data with endpoints

    Returns:
        Tuple of (base_urls, endpoint_urls_with_params)
    """
    base_urls = []
    endpoint_urls = []

    if not resource_enum_data:
        return base_urls, endpoint_urls

    by_base_url = resource_enum_data.get("by_base_url", {})

    for base_url, base_data in by_base_url.items():
        base_urls.append(base_url)

        endpoints = base_data.get("endpoints", {})
        for path, endpoint_info in endpoints.items():
            # Build URLs with sample parameter values for GET endpoints
            parameters = endpoint_info.get("parameters", {})
            query_params = parameters.get("query", [])

            if query_params:
                # Build URL with parameters
                param_parts = []
                for param in query_params:
                    name = param.get("name")
                    sample_values = param.get("sample_values", [])
                    value = sample_values[0] if sample_values else "1"
                    param_parts.append(f"{name}={value}")

                if param_parts:
                    full_url = f"{base_url}{path}?{'&'.join(param_parts)}"
                    endpoint_urls.append(full_url)
            else:
                # Add path without params
                endpoint_urls.append(f"{base_url}{path}")

    return base_urls, endpoint_urls


# =============================================================================
# Combined URL Building
# =============================================================================

def _hosts_in_urls(urls: Set[str]) -> Set[str]:
    """Extract the set of lowercased hostnames present in a URL set."""
    hosts: Set[str] = set()
    for u in urls:
        try:
            host = urlparse(u).hostname
        except (ValueError, TypeError):
            continue
        if host:
            hosts.add(host.lower())
    return hosts


def build_target_urls(
    hostnames: Set[str],
    ips: Set[str],
    recon_data: Optional[dict] = None,
    scan_all_ips: bool = False,
) -> List[str]:
    """
    Build the list of target URLs for nuclei scanning as the UNION of every
    available source, deduplicated.

    Sources (all merged, none shadowed):
      1. Endpoint URLs from resource_enum (parameterized URLs, e.g. /api?q=1).
      2. BaseURL nodes from httpx (live URLs, e.g. https://A.com).
      3. http(s)://{hostname} for every hostname/subdomain whose host is NOT
         already represented by sources 1 or 2 (so newly-discovered subdomains
         that haven't been probed yet still get scanned).
      4. http(s)://{ip} for IPs not already covered, only if scan_all_ips=True.

    A hostname is "already covered" iff some URL in sources 1+2 has that exact
    hostname (httpx already picked the working scheme; re-scanning the other
    scheme would just waste rate-limit budget).

    Args:
        hostnames: Set of hostnames/subdomains discovered via DNS.
        ips: Set of IPs discovered via DNS.
        recon_data: Full recon data dict with optional 'resource_enum' and
                    'http_probe' keys.
        scan_all_ips: Whether to include IP addresses (default False).

    Returns:
        Sorted, deduplicated list of URLs to scan.
    """
    url_set: Set[str] = set()
    counts = {
        "resource_enum_base": 0,
        "resource_enum_endpoint": 0,
        "httpx": 0,
        "fallback_subdomain": 0,
        "fallback_ip": 0,
    }

    # Source 1: resource_enum (BaseURLs + parameterized endpoint URLs)
    resource_enum_data = recon_data.get("resource_enum") if recon_data else None
    if resource_enum_data:
        base_urls, endpoint_urls = build_target_urls_from_resource_enum(resource_enum_data)
        for u in base_urls:
            if u not in url_set:
                url_set.add(u)
                counts["resource_enum_base"] += 1
        for u in endpoint_urls:
            if u not in url_set:
                url_set.add(u)
                counts["resource_enum_endpoint"] += 1

    # Source 2: httpx live URLs (BaseURLs verified by httpx)
    httpx_data = recon_data.get("http_probe") if recon_data else None
    if httpx_data:
        for u in build_target_urls_from_httpx(httpx_data):
            if u not in url_set:
                url_set.add(u)
                counts["httpx"] += 1

    # Compute which hostnames sources 1+2 already cover (host-only match,
    # ignoring scheme/port/path) so we don't re-add them as fallback URLs.
    covered_hosts = _hosts_in_urls(url_set)

    # Source 3: hostnames not covered by httpx/resource_enum → both schemes.
    # This catches newly discovered subdomains that haven't been probed yet.
    for hostname in sorted(hostnames):
        if not hostname or hostname.lower() in covered_hosts:
            continue
        before = len(url_set)
        url_set.add(f"http://{hostname}")
        url_set.add(f"https://{hostname}")
        if len(url_set) > before:
            counts["fallback_subdomain"] += 1

    # Source 4: IPs not covered (opt-in)
    if scan_all_ips:
        for ip in sorted(ips):
            if not ip or ip in covered_hosts:
                continue
            # IPv6 literals need brackets in URLs: http://[::1]/ not http://::1/.
            # An IPv6 contains ':' (IPv4 does not).
            ip_for_url = f"[{ip}]" if ":" in ip else ip
            before = len(url_set)
            url_set.add(f"http://{ip_for_url}")
            url_set.add(f"https://{ip_for_url}")
            if len(url_set) > before:
                counts["fallback_ip"] += 1

    parts = []
    if counts["resource_enum_base"]:
        parts.append(f"{counts['resource_enum_base']} resource_enum base URLs")
    if counts["resource_enum_endpoint"]:
        parts.append(f"{counts['resource_enum_endpoint']} parameterized endpoints")
    if counts["httpx"]:
        parts.append(f"{counts['httpx']} additional httpx URLs")
    if counts["fallback_subdomain"]:
        parts.append(f"{counts['fallback_subdomain']} unprobed subdomains")
    if counts["fallback_ip"]:
        parts.append(f"{counts['fallback_ip']} unprobed IPs")

    if parts:
        print(f"[*][Targets] Merged {len(url_set)} URLs: " + " + ".join(parts))
    else:
        print(f"[*][Targets] No targets available")

    return sorted(url_set)

