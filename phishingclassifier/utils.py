"""Helper utilities."""

from __future__ import annotations

import ipaddress
from typing import Optional

# private IP ranges
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/29",
        "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fe80::/10", "fc00::/7", "ff00::/8",
    )
]


def is_internal_ip(ip_text: str) -> bool:
    """Check if IP is in private/internal range."""
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def extract_ip(text: str) -> Optional[str]:
    """Extract IPv4 address from text."""
    import re

    match = re.search(r"\(?(\b(?:\d{1,3}\.){3}\d{1,3})\b\)?", text)
    if not match:
        return None
    candidate = match.group(1)
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None
