"""IOC extraction tests."""

from pathlib import Path

from phishingclassifier.iocs import all_domains, all_urls, extract_iocs
from phishingclassifier.parser import parse_eml

FIXTURES = Path(__file__).parent / "fixtures"


def _iocs_for(name):
    return extract_iocs(parse_eml(str(FIXTURES / name)))


def test_domains_extracted_with_source_location():
    iocs = _iocs_for("spoofed.eml")
    header_d = iocs["domains"]["header"]
    body_d = iocs["domains"]["body"]
    assert "paypa1-secure-alerts.com" in header_d
    assert "paypa1-secure-alerts.com" in body_d
    assert "example.com" not in header_d + body_d


def test_urls_extracted_from_body():
    iocs = _iocs_for("spoofed.eml")
    urls = all_urls(iocs)
    assert any("paypa1-secure-alerts.com/verify" in u for u in urls)


def test_origin_ip_recorded():
    iocs = _iocs_for("harvester.eml")
    assert iocs["ipv4"]["origin"] == "203.0.113.42"


def test_attachment_hashes_present():
    iocs = _iocs_for("harvester.eml")
    hashes = iocs["attachment_hashes"]
    assert len(hashes) == 1
    assert len(hashes[0]["sha256"]) == 64
    assert hashes[0]["filename"] == "INV-2026-0842.zip"


def test_clean_email_has_few_iocs():
    iocs = _iocs_for("clean.eml")
    assert all_urls(iocs) == []
    assert "github.com" in all_domains(iocs)
