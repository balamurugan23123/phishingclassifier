"""Parser tests."""

from pathlib import Path

from phishingclassifier.parser import parse_eml, parse_eml_bytes

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


def test_email_without_body_parses_cleanly():
    raw = (b"Subject: subject only, no body\r\n"
           b"From: someone@example.com\r\n\r\n")
    parsed = parse_eml_bytes(raw, source_path="(no-body)")
    assert parsed.subject == "subject only, no body"
    assert parsed.from_domain == "example.com"
    assert parsed.text_body == "" and parsed.html_body == ""
    assert parsed.attachments == []


def test_rfc2047_encoded_unicode_subject_is_decoded():
    import email.header

    enc = email.header.Header("Verificación urgente", "utf-8").encode()
    raw = (f"Subject: {enc}\r\nFrom: a@b.com\r\n\r\ncuerpo\r\n").encode()
    parsed = parse_eml_bytes(raw, source_path="(unicode)")
    assert "Verificación" in parsed.subject


def test_nested_multipart_extracts_bodies_and_attachment():
    raw = (
        "From: sender@example.com\r\n"
        "Subject: nested\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="OUT"\r\n\r\n'
        "--OUT\r\n"
        'Content-Type: multipart/alternative; boundary="IN"\r\n\r\n'
        "--IN\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
        "plain text body\r\n"
        "--IN\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n\r\n'
        "<b>html body</b>\r\n"
        "--IN--\r\n"
        "--OUT\r\n"
        'Content-Type: application/octet-stream; name="payload.exe"\r\n'
        'Content-Disposition: attachment; filename="payload.exe"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "QUJDRA==\r\n"
        "--OUT--\r\n"
    ).encode()
    parsed = parse_eml_bytes(raw, source_path="(nested)")
    assert "plain text body" in parsed.text_body
    assert "html body" in parsed.html_body
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att["filename"] == "payload.exe"
    assert att["dangerous"] is True
    assert att["size"] == 4  # base64 'QUJDRA==' -> b'ABCD'
