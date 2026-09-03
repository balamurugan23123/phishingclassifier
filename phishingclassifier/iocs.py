"""IOC extraction helpers."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .parser import ParsedEmail

# regex patterns
IPv4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IPv6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{0,4}:){2,7}(?:[0-9a-fA-F]{0,4}|(?:\d{1,3}\.){3}\d{1,3})\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:aero|biz|cat|com|coop|edu|gov|info|int|mil|museum|net|org|pro|xyz"
    r"|online|site|top|live|shop|store|app|dev|io|co|me|tv|cc|ru|cn|br|in|uk"
    r"|de|fr|jp|au|ca|nl|se|no|es|it|pl|cz|kr|tw|hk|sg|eu|us|biz|name|mobi"
    r"|asia|post|travel|jobs|tel|XXX)\b"
)
URL_HOST_RE = re.compile(
    r"\b(?:https?|ftp)://"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,24})"
    r"(?::\d{1,5})?(?:[/?#\s]|\b)",
    re.IGNORECASE,
)
URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s<>\"'()\[\]{}]+", re.IGNORECASE
)
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# benign domains to ignore
LEGIT_DOMAINS = {
    "w3.org", "www.w3.org", "schemas.xmlsoap.org",
    "example.com", "example.net", "example.org",
    "example.edu", "mail.example.com", "www.example.com",
}

# test fixture IP ranges
EXAMPLE_IP_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def extract_domains(text: str) -> List[str]:
    """Extract unique domains from text."""
    seen, out = set(), []
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0).lower().rstrip(".")
        if d in LEGIT_DOMAINS or d in seen:
            continue
        seen.add(d)
        out.append(d)
    return out


def _ips_from(text: str, skip_internal: bool = False) -> List[str]:
    from .utils import is_internal_ip

    out: List[str] = []
    for m in IPv4_RE.finditer(text):
        ip = m.group(0)
        if skip_internal and is_internal_ip(ip):
            continue
        if ip not in out:
            out.append(ip)
    return out


def extract_iocs(parsed: ParsedEmail) -> Dict[str, Any]:
    """Extract IOCs from parsed email headers and body."""
    header_blob = "\n".join(
        f"{k}: {v}" for k, v in parsed.headers.items()
    )
    body_blob = "\n".join([parsed.text_body, parsed.html_body])

    domains_header = extract_domains(header_blob)
    domains_body = extract_domains(body_blob)

    for host in URL_HOST_RE.findall(body_blob):
        host = host.lower().rstrip(".")
        if host and host not in domains_body:
            domains_body.append(host)
    for host in URL_HOST_RE.findall(header_blob):
        host = host.lower().rstrip(".")
        if host and host not in domains_header:
            domains_header.append(host)

    urls_header = [u for u in URL_RE.findall(header_blob)]
    urls_body = [u for u in URL_RE.findall(body_blob)]

    emails_header = sorted(set(EMAIL_RE.findall(header_blob)))
    emails_body = sorted(set(EMAIL_RE.findall(body_blob)))

    return {
        "ipv4": {
            "origin": parsed.origin_ip or "",
            "header": _ips_from(header_blob, skip_internal=True),
            "body": _ips_from(body_blob),
        },
        "domains": {
            "header": domains_header,
            "body": domains_body,
        },
        "urls": {
            "header": urls_header,
            "body": urls_body,
        },
        "emails": {
            "header": emails_header,
            "body": emails_body,
        },
        "attachment_hashes": [
            {"sha256": a["sha256"], "filename": a["filename"]}
            for a in parsed.attachments
        ],
    }


def all_domains(iocs: Dict[str, Any]) -> List[str]:
    """Return all unique domains."""
    seen: List[str] = []
    for bucket in (iocs["domains"]["header"], iocs["domains"]["body"]):
        for d in bucket:
            if d not in seen:
                seen.append(d)
    return seen


def all_urls(iocs: Dict[str, Any]) -> List[str]:
    """Return all unique URLs."""
    seen: List[str] = []
    for bucket in (iocs["urls"]["header"], iocs["urls"]["body"]):
        for u in bucket:
            if u not in seen:
                seen.append(u)
    return seen
