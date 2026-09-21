"""STIX / MISP export tests."""

import json
from pathlib import Path

from phishingclassifier.export import misp_events, stix_bundle
from phishingclassifier.heuristics import analyze_signals
from phishingclassifier.parser import parse_eml
from phishingclassifier.report import build_result

FIXTURES = Path(__file__).parent / "fixtures"


def _results():
    out = []
    for name in ("spoofed.eml", "harvester.eml", "clean.eml"):
        parsed = parse_eml(str(FIXTURES / name))
        out.append(build_result(parsed, analyze_signals(parsed)))
    return out


def _empty_iocs_result(**extra):
    r = {
        "subject": "x",
        "score": {"score": 10, "verdict": "Clean"},
        "iocs": {
            "ipv4": {},
            "domains": {"header": [], "body": []},
            "urls": {"header": [], "body": []},
            "emails": {"header": [], "body": []},
            "attachment_hashes": [],
        },
    }
    r.update(extra)
    return r


def test_stix_bundle_is_a_valid_deduped_bundle():
    bundle = json.loads(stix_bundle(_results()))
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert bundle["id"].startswith("bundle--")
    ids = {o["id"] for o in bundle["objects"]}
    assert len(ids) == len(bundle["objects"])  # no duplicate observables
    for o in bundle["objects"]:
        assert o["spec_version"] == "2.1"
        assert o["id"].startswith(o["type"] + "--")


def test_stix_bundle_is_deterministic():
    assert stix_bundle(_results()) == stix_bundle(_results())


def test_stix_bundle_empty_input():
    bundle = json.loads(stix_bundle([]))
    assert bundle["objects"] == []


def test_stix_bundle_carries_observables_from_phish():
    types = {o["type"] for o in json.loads(stix_bundle(_results()))["objects"]}
    assert "url" in types or "domain-name" in types


def test_stix_file_object_has_sha256():
    r = _empty_iocs_result()
    r["iocs"]["attachment_hashes"] = [{"filename": "invoice.docm", "sha256": "ab" * 32}]
    objs = json.loads(stix_bundle([r]))["objects"]
    files = [o for o in objs if o["type"] == "file"]
    assert files and files[0]["hashes"]["SHA-256"] == "ab" * 32


def test_misp_events_have_one_event_per_email():
    events = json.loads(misp_events(_results()))
    assert len(events) == 3
    for ev in events:
        e = ev["Event"]
        assert e["info"].startswith("PhishSleuth:")
        assert "Attribute" in e and "Tag" in e
        for a in e["Attribute"]:
            assert a["type"] and a["category"] and "value" in a


def test_misp_filename_and_sha_are_combined():
    r = _empty_iocs_result()
    r["iocs"]["attachment_hashes"] = [{"filename": "invoice.docm", "sha256": "cd" * 32}]
    event = json.loads(misp_events([r]))[0]["Event"]
    combined = [a for a in event["Attribute"] if a["type"] == "filename|sha256"]
    assert combined and combined[0]["value"] == "invoice.docm|" + "cd" * 32
