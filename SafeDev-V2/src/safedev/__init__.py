"""SafeDev V2 — Main Package Initialization with IPv4 socket optimization."""

import socket

# Force IPv4 socket resolution to prevent Windows dual-stack IPv6 20-30 second timeouts
_orig_getaddrinfo = socket.getaddrinfo

def _getaddrinfo_ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
    except Exception:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

socket.getaddrinfo = _getaddrinfo_ipv4_only
