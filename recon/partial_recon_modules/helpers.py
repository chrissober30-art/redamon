import os
import sys
from pathlib import Path

# Add project root to path (for lazy imports in other modules)
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


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


def _is_valid_url(value: str) -> bool:
    """Check if value looks like a valid HTTP/HTTPS URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _should_include_root_domain(settings: dict) -> bool:
    """
    Derive the "Include Root Domain" flag from project settings.

    Mirrors recon/main.py:parse_target() exactly: the apex is in scope if
    SUBDOMAIN_LIST contains "." (or any prefix that strips to empty). Used
    by partial-recon graph builders to honor the same scope rules as the
    full pipeline.
    """
    subdomain_list = settings.get("SUBDOMAIN_LIST") or []
    return any(p == "." or p.rstrip(".") == "" for p in subdomain_list)


def _is_host_in_scope(
    host: str,
    settings: dict,
    requested_domain: str = "",
    include_root_domain: bool = False,
) -> bool:
    """
    Decide whether a hostname is in scope for the current scan.

    Single source of truth for partial-recon scope checks. Two regimes:

    1. **IP mode** (settings["IP_MODE"] is True): the project targets raw
       IPs, not a domain. The synthetic ``ip-targets.<project_id>`` pseudo-
       domain used elsewhere in the pipeline is NOT a real scope rule, so
       we ignore it here:

       - If TARGET_IPS is configured, accept the host if it matches one of
         them literally, falls inside a configured CIDR, or is the
         loopback alias (``localhost`` / ``::1``) for an explicitly-listed
         ``127.0.0.1``.
       - If TARGET_IPS is empty, accept anything that's an IP, ``localhost``,
         or resolves to a private/loopback IP. The graph was already
         populated by HTTP probe which enforced RoE at probe time, so the
         partial-recon re-filter just acts as a defensive sanity check.

    2. **Domain mode** (default): accept the host if it equals
       ``requested_domain`` (gated by ``include_root_domain``) or is a
       subdomain of it (``host.endswith("." + requested_domain)``).

    Empty/None hosts are out of scope.
    """
    import ipaddress

    host = (host or "").strip().strip(".").lower()
    if not host:
        return False

    # Strip "[ipv6]:port" → "ipv6", or "host:port" → "host". Must not mangle
    # bare IPv6 addresses (where every colon is part of the address, e.g. "::1"
    # or "2001:db8::1"). Strategy:
    #   1. Bracketed form has unambiguous port boundary at "]"
    #   2. Otherwise, try to parse as an IP first — IPv6 wins
    #   3. Only then fall back to the host:port split for plain hostnames
    if host.startswith("["):
        end = host.find("]")
        if end > 0:
            host = host[1:end]
    else:
        try:
            ipaddress.ip_address(host)
            # Already a valid IP (v4 or v6) — leave intact
        except ValueError:
            if ":" in host:
                host = host.split(":", 1)[0]

    if settings.get("IP_MODE"):
        target_ips = {
            ip.strip().lower()
            for ip in (settings.get("TARGET_IPS") or [])
            if ip and ip.strip()
        }

        if target_ips:
            # Literal IP / CIDR match
            if host in target_ips:
                return True
            # CIDR membership for IP hosts
            try:
                host_ip = ipaddress.ip_address(host)
                for cidr in target_ips:
                    if "/" not in cidr:
                        continue
                    try:
                        if host_ip in ipaddress.ip_network(cidr, strict=False):
                            return True
                    except ValueError:
                        continue
            except ValueError:
                pass
            # Loopback aliases: accept "localhost" when 127.0.0.1 is in scope,
            # or "::1" when ::1 is in scope.
            if host == "localhost" and (
                "127.0.0.1" in target_ips or "::1" in target_ips
            ):
                return True
            return False

        # No specific target IPs configured — accept localhost + private/loopback
        # IPs. HTTP probe already enforced scope when populating the graph.
        if host == "localhost":
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False

    # Domain mode (default)
    requested = (requested_domain or "").strip(".").lower()
    if not requested:
        # No domain configured (degenerate case) — accept anything.
        return True
    if host == requested:
        return include_root_domain
    return host.endswith(f".{requested}")
