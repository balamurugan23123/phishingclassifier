"""Helper utilities."""

from __future__ import annotations

import html as _html
import ipaddress
from typing import Dict, Optional

# File extensions that indicate a dangerous/executable attachment. Shared by
# the parser (which flags them on each attachment) and the heuristic
# attachment check so the two can never drift apart.
DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".lnk", ".hta",
    ".docm", ".xlsm", ".bat", ".cmd", ".ps1", ".jar",
}

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


def esc(value: object) -> str:
    """HTML-escape any value for safe rendering (None renders as empty)."""
    return _html.escape("" if value is None else str(value), quote=True)


def confusion_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Binary accuracy/precision/recall/f1 from a confusion matrix.

    Guards every denominator so an empty class yields 0.0 rather than a
    ZeroDivisionError. Kept dependency-free (no numpy/sklearn) so the CLI
    validation path stays usable in minimal installs.
    """
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    accuracy = (tp + tn) / total if total else 0.0
    return {
        "total": total,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }
