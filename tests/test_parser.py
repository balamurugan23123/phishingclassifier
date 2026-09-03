"""Parser tests."""

from pathlib import Path

from phishingclassifier.parser import parse_eml

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_email_parses():
    parsed = parse_eml(str(FIXTURES / "clean.eml"))
    assert "New release published" in parsed.subject
    assert parsed.from_addr == "noreply@github.com"
    assert parsed.from_domain == "github.com"
    assert parsed.auth("spf") == "pass"
    assert parsed.auth("dkim") == "pass"
    assert parsed.auth("dmarc") == "pass"
    assert parsed.origin_ip == "140.82.112.3"
    assert parsed.warnings == []


def test_spoofed_email_parses():
    parsed = parse_eml(str(FIXTURES / "spoofed.eml"))
    assert parsed.from_display == "PayPal Support"
    assert parsed.from_domain == "paypa1-secure-alerts.com"
    assert parsed.reply_to.startswith("verify.acct.2026@")
    assert parsed.origin_ip == "198.51.100.77"
    assert not parsed.has_auth_header
    assert "verify" in parsed.html_body


def test_harvester_email_parses():
    parsed = parse_eml(str(FIXTURES / "harvester.eml"))
    assert parsed.auth("spf") == "fail"
    assert parsed.auth("dmarc") == "fail"
    assert parsed.origin_ip == "203.0.113.42"
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att["filename"] == "INV-2026-0842.zip"
    assert att["archive"] is True
    assert len(att["sha256"]) == 64
    assert att["size"] > 0
    assert "<form" in parsed.html_body


def test_origin_ip_filters_reserved():
    eml = FIXTURES / "chain.eml"
    eml.write_text(
        "Received: from internal.corp ([192.168.1.10]) by mail.corp\n"
        "Received: from external.biz ([203.0.113.99]) by mail.corp\n"
        "Subject: t\nFrom: a@b.com\n\nbody\n",
        encoding="utf-8",
    )
    parsed = parse_eml(str(eml))
    assert parsed.origin_ip == "203.0.113.99"
    eml.unlink()


def test_malformed_file_never_crashes():
    bad = FIXTURES / "broken.eml"
    bad.write_bytes(b"\x00\xff not an email at \x01\x02 all")
    parsed = parse_eml(str(bad))
    assert isinstance(parsed.warnings, list)
    bad.unlink()
