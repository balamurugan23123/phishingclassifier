"""Heuristic scoring tests."""

from pathlib import Path
from types import SimpleNamespace

from phishingclassifier.heuristics import (
    _check_mailer,
    _check_received_chain,
    _check_reply_chain,
    _check_urgency,
    _haystack,
    analyze_signals,
)
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


def test_haystack_is_memoized_and_invalidates_on_change():
    parsed = parse_eml(str(FIXTURES / "spoofed.eml"))
    first = _haystack(parsed)
    # repeated calls return the identical cached object (no recompute)
    assert _haystack(parsed) is first
    # mutating a source field must invalidate the cache
    parsed.subject = "Totally Different Subject XYZZY"
    second = _haystack(parsed)
    assert second is not first
    assert "totally different subject" in second


def _mailer_signals(headers):
    signals = []
    _check_mailer(SimpleNamespace(headers=headers), signals)
    return signals


def test_mailer_flags_scripted_user_agent():
    s = _mailer_signals({"user-agent": "python-requests/2.31.0"})
    assert [x["id"] for x in s] == ["suspicious_mailer"]


def test_mailer_flags_bulk_xmailer():
    s = _mailer_signals({"x-mailer": "Mass Mailer Pro 3.0"})
    assert s and s[0]["id"] == "suspicious_mailer"


def test_mailer_ignores_normal_clients():
    assert (
        _mailer_signals(
            {
                "x-mailer": "Microsoft Outlook 16",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            }
        )
        == []
    )


def test_mailer_absent_header_is_not_flagged():
    assert _mailer_signals({}) == []


def _reply_signals(subject, headers):
    signals = []
    _check_reply_chain(SimpleNamespace(subject=subject, headers=headers), signals)
    return signals


def test_reply_chain_flags_fabricated_thread():
    s = _reply_signals("Re: your invoice", {})
    assert [x["id"] for x in s] == ["fake_reply_thread"]


def test_reply_chain_allows_genuine_reply():
    assert _reply_signals("Re: your invoice", {"in-reply-to": "<a@x.com>"}) == []
    assert _reply_signals("Re: your invoice", {"references": "<a@x.com>"}) == []


def test_reply_chain_ignores_non_reply_subject():
    assert _reply_signals("Your weekly summary", {}) == []


def _received_signals(hops):
    signals = []
    _check_received_chain(SimpleNamespace(received_chain=hops), signals)
    return signals


def test_received_absent_chain_flagged():
    s = _received_signals([])
    assert [x["id"] for x in s] == ["received_chain_absent"]


def test_received_monotonic_chain_is_clean():
    hops = [
        "from mta1 (x) by dest.example.com; Fri, 05 Jan 2024 12:00:00 +0000",
        "from origin (y) by relay.example.com; Fri, 05 Jan 2024 11:00:00 +0000",
    ]
    assert _received_signals(hops) == []


def test_received_backdated_chain_flagged():
    hops = [
        "from mta1 by dest.example.com; Mon, 01 Jan 2024 00:00:00 +0000",
        "from origin by relay.example.com; Fri, 05 Jan 2024 00:00:00 +0000",
    ]
    s = _received_signals(hops)
    assert [x["id"] for x in s] == ["received_timestamp_backdated"]


def test_received_unparseable_dates_are_ignored():
    assert _received_signals(["from a by b; nope", "from c by d; also nope"]) == []


def _urgency_signals(subject="", text="", html=""):
    parsed = SimpleNamespace(subject=subject, text_body=text, html_body=html)
    signals = []
    _check_urgency(parsed, signals)
    return signals


def test_urgency_matches_multilingual_phrases():
    s = _urgency_signals(
        subject="Acci\u00f3n requerida",
        text="Por favor verifique su cuenta de inmediato.",
    )
    assert [x["id"] for x in s] == ["urgency_keywords"]
    ev = s[0]["evidence"]
    assert "verifique su cuenta" in ev
    assert "[es]" in ev


def test_urgency_still_matches_english():
    s = _urgency_signals(text="Please verify your account immediately")
    assert any(x["id"] == "urgency_keywords" for x in s)


def test_urgency_clean_text_fires_nothing():
    assert _urgency_signals(text="Here is the quarterly report you asked for. Thanks!") == []
