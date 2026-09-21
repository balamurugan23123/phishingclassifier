"""Report-generation tests (Markdown, HTML, batch JSON, file writers)."""

import json
from pathlib import Path

from phishingclassifier.heuristics import analyze_signals
from phishingclassifier.parser import parse_eml_bytes
from phishingclassifier.report import (
    batch_json, build_result, html_summary, markdown_report,
    write_html, write_markdown,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _result(name):
    parsed = parse_eml_bytes((FIXTURES / name).read_bytes(), source_path=name)
    return build_result(parsed, analyze_signals(parsed))


def _result_from_bytes(raw, source="(test)"):
    parsed = parse_eml_bytes(raw, source_path=source)
    return build_result(parsed, analyze_signals(parsed))


def test_markdown_report_renders_all_sections():
    md = markdown_report(_result("spoofed.eml"))
    assert md.startswith("# Phishing Classifier Report")
    for heading in ("## Headers of interest", "## Fired signals",
                    "## IOCs", "## Enrichment"):
        assert heading in md
    assert "[LIKELY MALICIOUS]" in md or "[MALICIOUS]" in md


def test_markdown_report_no_signals_shows_placeholder():
    raw = (b"Subject: hello there friend\r\nFrom: nobody@example.com\r\n"
           b"\r\nNothing to see here.\r\n")
    result = _result_from_bytes(raw)
    result["signals"] = []
    result["score"] = {"score": 0, "verdict": "Clean", "capped": False,
                       "signal_count": 0, "top_signals": [],
                       "raw_weight_total": 0}
    md = markdown_report(result)
    assert "No detection signals fired." in md


def test_markdown_report_surfaces_enrichment_errors():
    result = _result("clean.eml")
    result["enrichment"] = {"mode": "live", "lookups": [],
                            "errors": ["network error: Timeout"]}
    md = markdown_report(result)
    assert "Errors:" in md
    assert "network error: Timeout" in md


def test_html_summary_is_opsec_safe_and_escaped():
    results = [_result("spoofed.eml"), _result("clean.eml")]
    html = html_summary(results)
    # Zero remote resources: no external links, scripts, or stylesheets.
    assert "<script" not in html.lower()
    assert 'href="http' not in html and 'src="http' not in html
    assert "<link" not in html.lower()
    # Verdict badge classes render.
    assert 'class="v-' in html
    assert "batch summary" in html


def test_html_summary_escapes_injected_markup():
    result = _result("clean.eml")
    result["subject"] = "<script>alert(1)</script>"
    html = html_summary([result])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_write_markdown_and_html_to_disk(tmp_path):
    results = [_result("spoofed.eml")]
    md_path = write_markdown(results[0], str(tmp_path / "md"))
    assert Path(md_path).is_file()
    assert Path(md_path).read_text(encoding="utf-8").startswith("#")
    html_path = write_html(results, str(tmp_path / "out" / "s.html"))
    assert Path(html_path).is_file()
    assert "<!DOCTYPE html>" in Path(html_path).read_text(encoding="utf-8")


def test_batch_json_includes_version_and_count():
    import phishingclassifier
    payload = json.loads(batch_json([_result("clean.eml")]))
    assert payload["tool"] == "phishingclassifier"
    assert payload["version"] == phishingclassifier.__version__
    assert payload["count"] == 1
