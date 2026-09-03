"""CSV adapter and validation tests."""

from pathlib import Path

from phishingclassifier.csv_adapter import (
    load_csv_dataset, row_label, row_to_parsed,
)
from phishingclassifier.heuristics import _shannon_entropy, analyze_signals
from phishingclassifier.iocs import extract_iocs
from phishingclassifier.report import build_result
from phishingclassifier.scoring import verdict_for

SAMPLES = Path(__file__).parent / ".." / "samples"


def _dataset():
    return load_csv_dataset(str(SAMPLES / "labeled_sample.csv"))


def test_loads_all_rows_with_labels():
    ds = _dataset()
    assert len(ds) == 20
    assert sum(1 for d in ds if d["label"] == 1) == 10
    assert sum(1 for d in ds if d["label"] == 0) == 10
    assert all(d["label"] is not None for d in ds)


def test_row_to_parsed_shape_matches_parser():
    row = {"sender": "a@gmail.com", "subject": "s", "body": "b", "label": "1"}
    parsed = row_to_parsed(row)
    assert parsed.from_addr == "a@gmail.com"
    assert parsed.from_domain == "gmail.com"
    assert parsed.subject == "s"
    assert parsed.text_body == "b"
    assert parsed.from_csv is True
    assert parsed.headers == {}
    assert parsed.auth_results == {}


def test_label_parsing_textual_and_numeric():
    assert row_label({"label": "1"}) == 1
    assert row_label({"label": "0"}) == 0
    assert row_label({"label": "phishing"}) == 1
    assert row_label({"label": "legitimate"}) == 0
    assert row_label({"label": "spam"}) == 1
    assert row_label({"label": "ham"}) == 0
    assert row_label({"label": ""}) is None
    assert row_label({}) is None


def test_header_signals_never_fire_for_csv_rows():
    ds = _dataset()
    header_ids = {"auth_header_absent", "message_id_absent",
                  "origin_ip_internal"}
    for d in ds:
        signals = analyze_signals(d["parsed"])["signals"]
        fired_ids = {s["id"] for s in signals}
        overlap = fired_ids & header_ids
        assert not overlap, f"Header signals fired for CSV row: {overlap}"


def test_validation_confusion_matrix():
    ds = _dataset()
    tp = fp = tn = fn = 0
    threshold = 50

    for d in ds:
        parsed = d["parsed"]
        label = d["label"]
        score = build_result(parsed, analyze_signals(parsed))["score"]["score"]
        pred = 1 if score >= threshold else 0
        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 0:
            tn += 1
        elif label == 0 and pred == 1:
            fp += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    assert total == 20
    assert fp == 0
    assert tp >= 8
    assert (tp + tn) / total >= 0.85


def test_free_webmail_impersonation_fires():
    row = {
        "sender": "paypal-support@gmail.com",
        "subject": "Security notice: bank transfer pending",
        "body": "Dear customer, verify your account immediately.",
        "label": "1",
    }
    signals = analyze_signals(row_to_parsed(row))["signals"]
    ids = {s["id"] for s in signals}
    assert "free_webmail_impersonation" in ids


def test_money_scam_language_fires():
    row = {
        "sender": "barrister.john@attorney.net",
        "subject": "BUSINESS PROPOSAL / INHERITANCE",
        "body": "I am the next of kin attorney for a late customer. "
                "The sum of 25.5 million dollars is in an unclaimed fund. "
                "Wire transfer to your account. Strictly confidential.",
        "label": "1",
    }
    signals = analyze_signals(row_to_parsed(row))["signals"]
    ids = {s["id"] for s in signals}
    assert "money_scam_language" in ids


def test_generic_greeting_fires():
    row = {
        "sender": "marketing@news.co",
        "subject": "Notice",
        "body": "Dear customer,\n\nPlease read our updated terms below.",
        "label": "0",
    }
    signals = analyze_signals(row_to_parsed(row))["signals"]
    ids = {s["id"] for s in signals}
    assert "generic_greeting" in ids


def test_dga_entropy_detects_random_domain():
    high_ent = "x7k2m9q4p1z3"
    low_ent = "paypal"
    assert _shannon_entropy(high_ent) > _shannon_entropy(low_ent)

    row = {
        "sender": "info@x7k2m9q4p1z3.info",
        "subject": "hi",
        "body": "click https://x7k2m9q4p1z3.info/login to update details",
        "label": "1",
    }
    signals = analyze_signals(row_to_parsed(row))["signals"]
    ids = {s["id"] for s in signals}
    assert "domain_high_entropy" in ids


def test_correlation_bonus_requires_three_lure_signals():
    row = {"sender": "a@b.example", "subject": "hi", "body": "dear customer", "label": "1"}
    signals = analyze_signals(row_to_parsed(row))["signals"]
    assert "lure_signal_correlation" not in {s["id"] for s in signals}

    row2 = {
        "sender": "a@b.example", "subject": "urgent",
        "body": "dear customer, this is urgent, verify your account "
                "immediately. unclaimed fund inheritance wire transfer.",
        "label": "1",
    }
    signals2 = analyze_signals(row_to_parsed(row2))["signals"]
    assert "lure_signal_correlation" in {s["id"] for s in signals2}


def test_validate_cli_reproduces_narrative(tmp_path, capsys):
    from phishingclassifier.cli import main
    code = main(["validate", str(SAMPLES / "labeled_sample.csv"),
                 "--json", str(tmp_path / "v.json")])
    assert code == 0
    out = capsys.readouterr().out
    assert "Rows evaluated: 20" in out
    assert "Accuracy:  90.0%" in out
    assert "Precision: 1.000" in out
    import json
    stats = json.loads((tmp_path / "v.json").read_text(encoding="utf-8"))
    assert stats["false_positives"] == 0
    assert stats["accuracy"] == 0.9
