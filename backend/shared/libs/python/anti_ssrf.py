"""
Anti-SSRF Network Guard & Payload Caps (Python)
Prevents SSRF, DNS Rebinding, and parser DoS at the network layer.
"""
import socket
import ipaddress
import urllib.parse
from typing import List, Tuple, Optional

# Prohibited IPv4 and IPv6 CIDR Networks
PROHIBITED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-Grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark Testing
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 Networks
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

# Strict Security Caps
MAX_BODY_BYTES = 10 * 1024 * 1024        # 10 MB payload cap
MAX_REDIRECT_HOPS = 5                     # Max 5 redirects
MAX_CERT_CHAIN_BYTES = 64 * 1024          # 64 KB certificate chain limit
HARD_TIMEOUT_SECONDS = 15                 # 15s detonation limit

class AntiSSRFException(Exception):
    """Raised when an outbound connection targets a prohibited internal IP or metadata endpoint."""
    pass

class PayloadCapException(Exception):
    """Raised when a response body or redirect chain exceeds maximum security caps."""
    pass

def is_ip_prohibited(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP address belongs to RFC 1918, loopback, link-local, or cloud metadata."""
    # Check if IPv6 is an IPv4-mapped address (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    # Check against known cloud metadata literal IPs
    str_ip = str(ip_obj)
    if str_ip in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254"):
        return True

    for network in PROHIBITED_NETWORKS:
        if ip_obj in network:
            return True

    return False

def resolve_and_verify_host(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses and verifies every resolved IP against Anti-SSRF policies.
    Returns the list of verified public IP addresses.
    Raises AntiSSRFException if any resolved IP is prohibited.
    """
    try:
        # Resolve both IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise AntiSSRFException(f"DNS resolution failure for host '{hostname}': {e}")

    verified_ips = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_prohibited(ip_obj):
                raise AntiSSRFException(
                    f"Anti-SSRF violation: Host '{hostname}' resolved to prohibited internal IP '{ip_str}'"
                )
            verified_ips.append(ip_str)
        except ValueError:
            raise AntiSSRFException(f"Invalid IP address returned: '{ip_str}'")

    if not verified_ips:
        raise AntiSSRFException(f"No routable IP addresses discovered for '{hostname}'")

    return list(set(verified_ips))

def defang_url(url: str) -> str:
    """
    Converts active URLs into defanged strings to prevent Stored XSS and accidental clicks.
    e.g. https://evil.corp/login -> hxxps://evil[.]corp/login
    """
    res = url
    if res.startswith("https://"):
        res = "hxxps://" + res[8:]
    elif res.startswith("http://"):
        res = "hxxp://" + res[7:]

    parts = res.split("/", 3)
    if len(parts) >= 3:
        host_segment = parts[2]
        # Replace the last dot in the hostname with [.]
        last_dot_idx = host_segment.rfind(".")
        if last_dot_idx != -1:
            defanged_host = host_segment[:last_dot_idx] + "[.]" + host_segment[last_dot_idx + 1:]
            parts[2] = defanged_host
            res = "/".join(parts)

    return res

def validate_url_safe(target_url: str) -> Tuple[str, str]:
    """
    Validates URL syntax, ensures only HTTP/HTTPS schemes, and resolves target host to verify safe egress.
    Returns (normalized_url, verified_ip).
    """
    parsed = urllib.parse.urlparse(target_url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise AntiSSRFException(f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise AntiSSRFException("Missing valid hostname in target URL.")

    # Check if host is already an IP address
    try:
        literal_ip = ipaddress.ip_address(hostname)
        if is_ip_prohibited(literal_ip):
            raise AntiSSRFException(f"Anti-SSRF violation: Target hostname is a prohibited IP '{hostname}'")
        return target_url, str(literal_ip)
    except ValueError:
        # Hostname is a domain name, resolve and verify
        verified_ips = resolve_and_verify_host(hostname)
        return target_url, verified_ips[0]

