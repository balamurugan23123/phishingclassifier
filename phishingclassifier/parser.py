"""Email parser for .eml files."""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import re
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from .utils import extract_ip, is_internal_ip

_DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".lnk", ".hta",
    ".docm", ".xlsm", ".bat", ".cmd", ".ps1", ".jar",
}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar"}


class ParsedEmail:
    """Structured data from a parsed email."""

    def __init__(self, source_path: str) -> None:
        self.source_path: str = source_path
        self.warnings: List[str] = []
        self.headers: Dict[str, str] = {}
        self.subject: str = ""
        self.from_addr: str = ""
        self.from_display: str = ""
        self.from_domain: str = ""
        self.reply_to: str = ""
        self.return_path: str = ""
        self.message_id: str = ""
        self.date: Optional[email.utils.parsedate_to_datetime] = None
        self.received_chain: List[str] = []
        self.origin_ip: Optional[str] = None
        self.origin_ip_reserved: Optional[bool] = None
        self.auth_results: Dict[str, str] = {}
        self.text_body: str = ""
        self.html_body: str = ""
        self.attachments: List[Dict[str, Any]] = []
        self.body_charset: str = ""
        # skip header checks when parsed from CSV row
        self.from_csv: bool = False

    @property
    def has_auth_header(self) -> bool:
        return bool(self.auth_results)

    def auth(self, mechanism: str) -> str:
        """Return SPF, DKIM, or DMARC verdict."""
        return self.auth_results.get(mechanism.lower(), "")


def _decode_header(value: str) -> str:
    try:
        parts = email.header.decode_header(value)
        out = []
        for part, charset in parts:
            if isinstance(part, bytes):
                out.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                out.append(str(part))
        return " ".join(out).strip()
    except Exception:
        return value


def _header_addresses(header_value: str):
    """Extract (display_name, email) pairs from header."""
    try:
        return email.utils.getaddresses([header_value or ""])
    except Exception:
        return []


def _domain_of(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower().lstrip("[").rstrip("]")


def parse_eml_bytes(raw: bytes, source_path: str = "(pasted)") -> ParsedEmail:
    """Parse raw email bytes."""
    parsed = ParsedEmail(source_path=source_path)
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:
        parsed.warnings.append(f"Hard parse failure: {exc}")
        return parsed
    _populate(msg, parsed)
    return parsed


def _populate(msg: email.message.Message, parsed: ParsedEmail) -> None:
    # headers
    for key in msg.keys():
        try:
            if key.lower() in parsed.headers:
                continue
            parsed.headers[key.lower()] = _decode_header(str(msg.get(key, "")))
        except Exception as exc:
            parsed.warnings.append(f"Header '{key}' unreadable: {exc}")

    parsed.subject = parsed.headers.get("subject", "")
    parsed.message_id = parsed.headers.get("message-id", "")

    # sender addresses
    from_value = parsed.headers.get("from", "")
    addrs = _header_addresses(from_value)
    if addrs:
        parsed.from_display, parsed.from_addr = addrs[0]
        parsed.from_domain = _domain_of(parsed.from_addr)
    else:
        parsed.from_display = from_value

    reply = _header_addresses(parsed.headers.get("reply-to", ""))
    parsed.reply_to = reply[0][1] if reply else ""
    rpath = _header_addresses(parsed.headers.get("return-path", ""))
    parsed.return_path = rpath[0][1] if rpath else ""

    # date
    raw_date = parsed.headers.get("date", "")
    if raw_date:
        try:
            parsed.date = email.utils.parsedate_to_datetime(raw_date)
        except Exception as exc:
            parsed.warnings.append(f"Unparseable Date header: {exc}")

    # received chain
    parsed.received_chain = [str(v) for v in msg.get_all("Received", [])]
    for hop in parsed.received_chain:
        ip = extract_ip(hop)
        if ip and not is_internal_ip(ip):
            parsed.origin_ip = ip
            parsed.origin_ip_reserved = False
            break
    if parsed.origin_ip is None and parsed.received_chain:
        parsed.origin_ip_reserved = True

    # authentication results
    ar_raw = parsed.headers.get("authentication-results", "")
    if ar_raw:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mech}\s*=\s*([a-z]+)", ar_raw, re.IGNORECASE)
            if m:
                parsed.auth_results[mech] = m.group(1).lower()

    # body and attachments
    try:
        _walk_payload(msg, parsed)
    except Exception as exc:
        parsed.warnings.append(f"Body/attachment walk failed: {exc}")


def parse_eml(path: str) -> ParsedEmail:
    """Parse .eml file from disk."""
    parsed = ParsedEmail(source_path=path)

    with open(path, "rb") as fh:
        raw = fh.read()

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:
        parsed.warnings.append(f"Hard parse failure: {exc}")
        return parsed
    _populate(msg, parsed)
    return parsed


def _walk_payload(msg: email.message.Message, parsed: ParsedEmail) -> None:
    for part in msg.walk():
        try:
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "") or "")
            filename = part.get_filename()
            payload: Optional[bytes] = None
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
                parsed.warnings.append("Attachment/body part undecodable; skipped")
            if payload is None:
                payload = b""

            is_attachment = bool(filename) or "attachment" in disposition.lower()

            if is_attachment:
                name = filename or "(unnamed)"
                lower = name.lower()
                ext = lower[lower.rfind("."):] if "." in lower else ""
                digest = hashlib.sha256(payload).hexdigest()
                parsed.attachments.append({
                    "filename": name,
                    "mime": content_type,
                    "size": len(payload),
                    "sha256": digest,
                    "extension": ext,
                    "dangerous": ext in _DANGEROUS_EXT,
                    "archive": ext in _ARCHIVE_EXT,
                })
                continue

            if content_type == "text/plain" and not parsed.text_body:
                charset = part.get_content_charset() or "utf-8"
                parsed.body_charset = charset
                parsed.text_body = _safe_decode(payload, charset)
            elif content_type == "text/html" and not parsed.html_body:
                charset = part.get_content_charset() or "utf-8"
                parsed.html_body = _safe_decode(payload, charset)
        except Exception as exc:
            parsed.warnings.append(f"Part skipped due to error: {exc}")


def _safe_decode(payload: bytes, charset: str) -> str:
    try:
        return payload.decode(charset or "utf-8", errors="replace")
    except (LookupError, TypeError):
        try:
            return payload.decode("utf-8", errors="replace")
        except Exception:
            return payload.decode("latin-1", errors="replace")
