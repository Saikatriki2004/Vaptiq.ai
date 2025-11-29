import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_target(target: str) -> bool:
    """
    Validates if a target is safe to scan (publicly accessible).
    Blocks private IPs, loopback, link-local, and reserved ranges to prevent SSRF.
    """
    # 1. Parse URL if needed
    if "://" in target:
        parsed = urlparse(target)
        hostname = parsed.hostname
    else:
        hostname = target.split(":")[0]  # Remove port if present

    if not hostname:
        return False

    # 2. Check if it's an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        return _is_public_ip(ip)
    except ValueError:
        # It's a domain name
        pass

    # 3. Check for obvious localhost/internal domains
    if hostname.lower() in ["localhost", "ip6-localhost", "ip6-loopback"]:
        return False
    if hostname.endswith(".local") or hostname.endswith(".internal"):
        return False

    # 4. Resolve DNS (Basic SSRF Protection)
    try:
        # Use getaddrinfo to handle IPv4 and IPv6
        # This returns a list of tuples
        results = socket.getaddrinfo(hostname, None)
        for result in results:
            ip_str = result[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if not _is_public_ip(ip):
                    return False
            except ValueError:
                continue
    except socket.error:
        # If valid domain but cannot resolve, it might be internal DNS failure or invalid domain.
        # Fail closed for security.
        return False

    return True

def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Returns True if IP is public, False if private/reserved/loopback."""
    return not (
        ip.is_private or
        ip.is_loopback or
        ip.is_reserved or
        ip.is_link_local or
        ip.is_multicast
    )
