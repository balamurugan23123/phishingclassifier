"""Heuristic scoring tests."""

from pathlib import Path

from phishingclassifier.heuristics import analyze_signals
from phishingclassifier.parser import parse_eml
from phishingclassifier.report import batch_json, build_result, markdown_report
from phishingclassifier.scoring import score_result, verdict_for

FIXTURES = Path(__file__).parent / "fixtures"


def _signals_for(name):
    parsed = parse_eml(str(FIXTURES / name))
    return analyze_signals(parsed)["signals"], parsed


def _result_for(name):
    signals, parsed = _signals_for(name)
    analysis = analyze_signals(parsed)
    return build_result(parsed, analysis), signals


def _ids(signals):
    return [s["id"] for s in signals]


def test_spoofed_fires_five_or_more_signals():
    signals, _ = _signals_for("spoofed.eml")
    ids = _ids(signals)
    assert len(signals) >= 5
    assert "display_name_spoof" in ids
    assert "lookalike_domain" in ids
    assert "link_text_mismatch" in ids
    assert "urgency_keywords" in ids
    assert "auth_header_absent" in ids


def test_harvester_fires_form_and_attachment_signals():
    signals, _ = _signals_for("harvester.eml")
    ids = _ids(signals)
    assert "credential_form" in ids
    assert "url_ip_literal" in ids
    assert "url_nonstandard_port" in ids
    assert "spf_fail" in ids
    assert "dmarc_fail" in ids


def test_clean_fires_at_most_one_low_signal():
    signals, _ = _signals_for("clean.eml")
    assert len(signals) <= 1
    if signals:
        assert signals[0]["weight"] <= 5


def test_every_signal_is_explainable():
    for name in ("clean.eml", "spoofed.eml", "harvester.eml"):
        signals, _ = _signals_for(name)
        for s in signals:
            assert set(s) == {"id", "weight", "reason", "evidence"}
            assert s["weight"] > 0 and isinstance(s["reason"], str)
            assert len(s["reason"]) > 10
            assert len(s["evidence"]) > 0


def test_verdict_bands():
    assert verdict_for(0) == "Clean"
    assert verdict_for(24) == "Clean"
    assert verdict_for(25) == "Suspicious"
    assert verdict_for(49) == "Suspicious"
    assert verdict_for(50) == "Likely Malicious"
    assert verdict_for(74) == "Likely Malicious"
    assert verdict_for(75) == "Malicious"
    assert verdict_for(100) == "Malicious"


def test_score_capped_at_100():
    signals = [{"id": "x", "weight": 60, "reason": "r", "evidence": "e"}] * 5
    score = score_result(signals)
    assert score["score"] == 100
    assert score["capped"] is True
    assert score["raw_weight_total"] == 300


def test_fixture_scores_match_verdicts():
    clean, _ = _signals_for("clean.eml")
    spoof, _ = _signals_for("spoofed.eml")
    harv, _ = _signals_for("harvester.eml")
    assert verdict_for(score_result(clean)["score"]) == "Clean"
    assert verdict_for(score_result(spoof)["score"]) == "Malicious"
    assert verdict_for(score_result(harv)["score"]) == "Malicious"


def test_markdown_report_is_escaped_and_non_clickable():
    result, _ = _result_for("spoofed.eml")
    md = markdown_report(result)
    assert "[http" not in md.replace("```text", "")
    assert "](http" not in md
    assert "```text" in md
    assert "paypa1-secure-alerts.com" in md
    assert "display-name" in md or "display" in md


def test_batch_json_sorts_by_score():
    results = []
    for name in ("clean.eml", "spoofed.eml", "harvester.eml"):
        parsed = parse_eml(str(FIXTURES / name))
        analysis = analyze_signals(parsed)
        results.append(build_result(parsed, analysis))
    payload = batch_json(results)
    assert '"count": 3' in payload
    import json
    data = json.loads(payload)
    scores = [r["score"]["score"] for r in data["results"]]
    assert scores == sorted(scores, reverse=True)
