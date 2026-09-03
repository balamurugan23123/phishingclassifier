"""Heuristic detection rules for phishing signals."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from .iocs import all_urls, extract_iocs
from .ml import fuzzy_brand_hit, normalize_confusables
from .parser import ParsedEmail

# signal weights
W_HIGH = 20
W_MEDHIGH = 15
W_MED = 10
W_LOW = 5

# known brand domains
BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "login.microsoftonline.com"],
    "outlook": ["outlook.com", "office.com", "live.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citibank.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
}

# known lookalike domains
LOOKALIKES = {
    "paypa1", "paypai", "paypa1.com", "g00gle", "goog1e", "rnicrosoft",
    "rnicrosoft.com", "micros0ft", "arnazon", "amaz0n", "arnazon.com",
    "app1e", "faceb00k", "fac ebook.com", "netf1ix", "1inkedin",
    "lnstagram", "wel1sfargo", "chase-secure", "usps-secure",
    "dhl-express-secure", "microsofl", "outl00k", "0utlook",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".lnk", ".hta",
    ".docm", ".xlsm", ".bat", ".cmd", ".ps1", ".jar",
}

URGENCY_KEYWORDS = [
    "verify your account", "account has been suspended", "suspended",
    "unusual activity", "unusual sign-in", "click here", "limited time",
    "act now", "immediately", "urgent", "final notice", "last warning",
    "your account will be", "within 24 hours", "confirm your identity",
    "update your payment", "avoid closure", "unauthorized access",
]

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "mail.com", "protonmail.com", "gmx.com", "yandex.com",
    "icloud.com", "zoho.com", "inbox.lv", "rediffmail.com",
}

INSTITUTION_KEYWORDS = [
    "bank", "security", "support", "admin", "billing", "finance",
    "accounts", "treasury", "federal", "government", "ministry",
    "embassy", "courier", "lottery", "director", "official",
]

MONEY_SCAM_KEYWORDS = [
    "wire transfer", "inheritance", "next of kin", "beneficiary",
    "unclaimed fund", "depositor", "atm card", "dead client",
    "late customer", "god fearing", "strictly confidential",
    "business proposal", "sum of", "usd$", "million united state",
    "million dollars", "foreign partner", "transfer the sum",
    "died in", "plane crash", "capital flight", "orphanage",
]

SPAM_SALES_KEYWORDS = [
    "viagra", "cialis", "male enhancement", "pills", "casino",
    "lottery winner", "you have won", "congratulations! you",
    "cheap meds", "no prescription", "work from home",
    "earn extra income", "weight loss", "free trial",
    "click below to buy", "discount 80", "viagra",
    "unsold merchandise", "replica watches", "online pharmacy",
    "100% free", "risk-free", "guaranteed income", "act now and",
    "limited supply", "best price", "special offer",
]

GENERIC_GREETINGS = [
    "dear customer", "dear client", "dear user", "dear account holder",
    "dear sir/madam", "dear sir", "dear madam", "dear beneficiary",
    "dear friend", "dear partner", "dear winner", "dear esteemed",
]

LINK_COUNT_THRESHOLD = 6
CORRELATION_MIN_SIGNALS = 3
CORRELATION_BONUS = 15

ENTROPY_THRESHOLD = 3.5
MIN_DOMAIN_LEN_FOR_ENTROPY = 10


def _signal(sid: str, weight: int, reason: str, evidence: str) -> Dict[str, Any]:
    return {"id": sid, "weight": weight, "reason": reason, "evidence": evidence}


def _domain_of_addr(addr: str) -> str:
    return addr.rsplit("@", 1)[1].strip().lower() if "@" in addr else ""


def _check_auth(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    if not parsed.has_auth_header:
        signals.append(_signal(
            "auth_header_absent", W_LOW,
            "No Authentication-Results header: SPF/DKIM/DMARC could not be verified",
            "(header absent)",
        ))
        return
    for mech in ("spf", "dkim", "dmarc"):
        verdict = parsed.auth(mech)
        if verdict in ("fail", "softfail"):
            signals.append(_signal(
                f"{mech}_{verdict}", W_HIGH,
                f"{mech.upper()} {verdict}: sending server is not authorized for the sender domain",
                f"Authentication-Results: {mech}={verdict}",
            ))
    if parsed.auth("spf") == "none" and parsed.auth("dkim") == "none":
        signals.append(_signal(
            "auth_none", W_LOW,
            "Email carries no passing authentication at all",
            "Authentication-Results: spf=none dkim=none",
        ))


def _check_envelope_spoof(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    rp_dom = _domain_of_addr(parsed.return_path)
    if rp_dom and parsed.from_domain and rp_dom != parsed.from_domain:
        signals.append(_signal(
            "return_path_mismatch", W_HIGH,
            f"Return-Path domain ({rp_dom}) differs from From domain ({parsed.from_domain})",
            f"Return-Path: {parsed.return_path} vs From: {parsed.from_addr}",
        ))
    if parsed.reply_to:
        rt_dom = _domain_of_addr(parsed.reply_to)
        if rt_dom and parsed.from_domain and rt_dom != parsed.from_domain:
            signals.append(_signal(
                "reply_to_mismatch", W_MED,
                f"Reply-To domain ({rt_dom}) differs from From domain ({parsed.from_domain})",
                f"Reply-To: {parsed.reply_to} vs From: {parsed.from_addr}",
            ))


def _check_display_name(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    display = (parsed.from_display or "").lower()
    for brand, legit_domains in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", display):
            if parsed.from_domain not in legit_domains:
                signals.append(_signal(
                    "display_name_spoof", W_HIGH,
                    f"Display name mentions '{brand}' but domain '{parsed.from_domain}' is not official",
                    f"From: {parsed.from_display} <{parsed.from_addr}>",
                ))
            break


def _check_message_id_date(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    if not parsed.message_id or parsed.message_id in ("<>", "<>"):
        signals.append(_signal(
            "message_id_absent", W_LOW,
            "Message-ID is missing or malformed",
            f"Message-ID: {parsed.message_id or '(absent)'}",
        ))
    if parsed.date is not None:
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        try:
            when = parsed.date
            if when.tzinfo is None:
                when = when.replace(tzinfo=_dt.timezone.utc)
            delta_days = (now - when).days
            if delta_days < -2:
                signals.append(_signal(
                    "date_future", W_LOW,
                    f"Date header is {abs(delta_days)} days in the future",
                    f"Date: {parsed.headers.get('date', '')}",
                ))
            elif delta_days > 365:
                signals.append(_signal(
                    "date_stale", W_LOW,
                    f"Date header is {delta_days} days old",
                    f"Date: {parsed.headers.get('date', '')}",
                ))
        except Exception:
            pass


def _check_origin_ip(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    if parsed.origin_ip_reserved:
        signals.append(_signal(
            "origin_ip_internal", W_MED,
            "No public originating IP found in Received chain",
            f"Received hops: {len(parsed.received_chain)}",
        ))


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _check_urls(parsed: ParsedEmail, iocs: Dict[str, Any], signals: List[Dict[str, Any]]) -> None:
    for url in all_urls(iocs):
        host = _url_host(url)
        if not host:
            continue
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            signals.append(_signal(
                "url_ip_literal", W_HIGH,
                f"URL uses a raw IP address: {url}",
                url,
            ))
        if "xn--" in host:
            signals.append(_signal(
                "url_punycode", W_HIGH,
                f"URL host contains punycode: {url}",
                url,
            ))
        if host in URL_SHORTENERS or any(
            host.endswith("." + s) for s in URL_SHORTENERS
        ):
            signals.append(_signal(
                "url_shortener", W_MEDHIGH,
                f"URL uses a shortener service: {url}",
                url,
            ))
        port = urlparse(url).port
        if port is not None and port not in (80, 443):
            signals.append(_signal(
                "url_nonstandard_port", W_MED,
                f"URL uses non-standard port {port}: {url}",
                url,
            ))
        subdomain_depth = host.count(".")
        if subdomain_depth >= 5:
            signals.append(_signal(
                "url_deep_subdomains", W_LOW,
                f"URL host has high subdomain depth: {url}",
                url,
            ))
        for like in LOOKALIKES:
            if like in host:
                signals.append(_signal(
                    "lookalike_domain", W_HIGH,
                    f"Host resembles a brand domain: {url} (matched '{like}')",
                    url,
                ))
                break
        else:
            brand = fuzzy_brand_hit(host)
            if brand:
                signals.append(_signal(
                    "brand_lookalike_fuzzy", W_HIGH,
                    f"Host is a near-match of brand '{brand}': {url}",
                    url,
                ))


def _check_link_text_mismatch(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    html = parsed.html_body
    if not html:
        return
    for m in re.finditer(
        r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        href, text = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
        href_host = _url_host(href if "//" in href else "")
        text_domains = re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text
        )
        if href_host and text_domains:
            text_host = text_domains[0].lower()
            if text_host != href_host:
                signals.append(_signal(
                    "link_text_mismatch", W_HIGH,
                    f"Link text shows '{text_host}' but href goes to '{href_host}'",
                    f"text='{text}' href='{href}'",
                ))


def _check_forms(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    html = parsed.html_body
    if not html:
        return
    for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        body = m.group(0)
        action = re.search(r"action\s*=\s*[\"']([^\"']+)[\"']", body, re.IGNORECASE)
        has_password = re.search(
            r'type\s*=\s*["\']password["\']', body, re.IGNORECASE
        )
        if has_password:
            signals.append(_signal(
                "credential_form", W_HIGH,
                "HTML contains a form with a password field",
                f"<form action={action.group(1) if action else '(none)'}> with password input",
            ))
            break


def _check_attachments(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    for att in parsed.attachments:
        ext = att.get("extension", "")
        name = att.get("filename", "(unnamed)")
        if ext in DANGEROUS_EXT:
            signals.append(_signal(
                "dangerous_attachment", W_HIGH,
                f"Attachment '{name}' has dangerous extension '{ext}'",
                f"{name} ({att.get('mime')}, {att.get('size')} bytes)",
            ))
        if att.get("archive") and re.search(
            r"pass(word)?\s*[:=]", parsed.text_body + parsed.html_body, re.IGNORECASE
        ):
            signals.append(_signal(
                "passworded_archive", W_MEDHIGH,
                f"Archive attachment '{name}' with password hint in body",
                name,
            ))


def _check_urgency(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    haystack = (parsed.subject + "\n" + parsed.text_body + "\n" +
                re.sub(r"<[^>]+>", " ", parsed.html_body)).lower()
    fired, total_weight = [], 0
    for kw in URGENCY_KEYWORDS:
        if kw in haystack:
            fired.append(kw)
            total_weight += W_LOW
    if fired:
        capped = min(total_weight, W_MEDHIGH)
        signals.append(_signal(
            "urgency_keywords", capped,
            f"Urgency phrases detected ({len(fired)} phrase(s))",
            ", ".join(fired[:5]),
        ))


def _check_base64_blobs(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    html = parsed.html_body
    if not html:
        return
    for m in re.finditer(r"[A-Za-z0-9+/=]{200,}", html):
        signals.append(_signal(
            "base64_blob", W_MED,
            f"Large base64 blob ({len(m.group(0))} chars) in HTML",
            m.group(0)[:60] + "...",
        ))
        break


def _check_free_webmail_impersonation(parsed: ParsedEmail,
                                      signals: List[Dict[str, Any]]) -> None:
    if parsed.from_domain not in FREE_WEBMAIL_DOMAINS:
        return
    display = (parsed.from_display or "").lower()
    subject = (parsed.subject or "").lower()
    hit = next((kw for kw in INSTITUTION_KEYWORDS if kw in display or kw in subject), None)
    if hit:
        signals.append(_signal(
            "free_webmail_impersonation", W_MED,
            f"Sender claims '{hit}' from free webmail provider ({parsed.from_domain})",
            f"From: {parsed.from_display} <{parsed.from_addr}>; Subject: {parsed.subject}",
        ))


def _haystack(parsed: ParsedEmail) -> str:
    raw = (parsed.subject + "\n" + parsed.text_body + "\n" +
           re.sub(r"<[^>]+>", " ", parsed.html_body)).lower()
    return normalize_confusables(raw)


def _check_money_scam(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    text = _haystack(parsed)
    fired = [kw for kw in MONEY_SCAM_KEYWORDS if kw in text]
    if fired:
        weight = W_MEDHIGH if len(fired) <= 2 else W_HIGH
        signals.append(_signal(
            "money_scam_language", weight,
            f"Advance-fee scam language detected ({len(fired)} phrase(s))",
            ", ".join(fired[:5]),
        ))


def _check_spam_sales(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    text = _haystack(parsed)
    fired = [kw for kw in SPAM_SALES_KEYWORDS if kw in text]
    if fired:
        signals.append(_signal(
            "spam_sales_language", W_MED,
            f"Spam/sales language detected ({len(fired)} phrase(s))",
            ", ".join(fired[:5]),
        ))


def _check_generic_greeting(parsed: ParsedEmail, signals: List[Dict[str, Any]]) -> None:
    first_lines = (parsed.text_body or
                   re.sub(r"<[^>]+>", " ", parsed.html_body))
    head = "\n".join(first_lines.splitlines()[:6]).lower()
    hit = next((g for g in GENERIC_GREETINGS if g in head), None)
    if hit:
        signals.append(_signal(
            "generic_greeting", W_LOW,
            f"Generic greeting '{hit}' detected",
            hit,
        ))


def _check_link_count(parsed: ParsedEmail, iocs: Dict[str, Any],
                      signals: List[Dict[str, Any]]) -> None:
    urls = all_urls(iocs)
    if len(urls) > LINK_COUNT_THRESHOLD:
        signals.append(_signal(
            "link_count_high", W_LOW,
            f"High link count ({len(urls)} URLs)",
            f"{len(urls)} unique URLs",
        ))


def _shannon_entropy(text: str) -> float:
    from collections import Counter
    from math import log2

    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * log2(c / total) for c in counts.values())


def _check_domain_entropy(parsed: ParsedEmail, iocs: Dict[str, Any],
                          signals: List[Dict[str, Any]]) -> None:
    from .iocs import all_domains

    seen: set = set()
    for domain in all_domains(iocs):
        if domain in seen:
            continue
        seen.add(domain)
        parts = domain.split(".")
        if len(parts) < 2:
            continue
        sld = parts[-2]
        tld = parts[-1]
        if len(sld) < MIN_DOMAIN_LEN_FOR_ENTROPY:
            continue
        entropy = _shannon_entropy(sld)
        high_tld = tld in {"xyz", "top", "info", "online", "site", "click"}
        if entropy >= ENTROPY_THRESHOLD or (entropy >= 3.0 and high_tld):
            signals.append(_signal(
                "domain_high_entropy", W_MEDHIGH,
                f"Domain '{domain}' has high character entropy ({entropy:.2f})",
                f"domain={domain} sld_entropy={entropy:.2f} tld={tld}",
            ))


def analyze_signals(parsed: ParsedEmail) -> Dict[str, Any]:
    """Evaluate email and return fired signals and IOCs."""
    iocs = extract_iocs(parsed)
    signals: List[Dict[str, Any]] = []
    if not parsed.from_csv:
        _check_auth(parsed, signals)
        _check_envelope_spoof(parsed, signals)
        _check_display_name(parsed, signals)
        _check_message_id_date(parsed, signals)
        _check_origin_ip(parsed, signals)
    _check_urls(parsed, iocs, signals)
    _check_link_text_mismatch(parsed, signals)
    _check_domain_entropy(parsed, iocs, signals)
    _check_free_webmail_impersonation(parsed, signals)
    _check_money_scam(parsed, signals)
    _check_spam_sales(parsed, signals)
    _check_generic_greeting(parsed, signals)
    _check_link_count(parsed, iocs, signals)
    _check_forms(parsed, signals)
    _check_attachments(parsed, signals)
    _check_urgency(parsed, signals)
    _check_base64_blobs(parsed, signals)

    # deduplicate identical signals
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for s in signals:
        key = (s["id"], s["evidence"])
        if key not in seen:
            seen.add(key)
            unique.append(s)

    # correlation bonus for multiple distinct signals
    lure_ids = {s["id"] for s in unique}
    if len(lure_ids) >= CORRELATION_MIN_SIGNALS:
        unique.append(_signal(
            "lure_signal_correlation", CORRELATION_BONUS,
            f"{len(lure_ids)} distinct signals fired together",
            f"signals: {', '.join(sorted(lure_ids)[:6])}",
        ))
    return {"signals": unique, "iocs": iocs}
