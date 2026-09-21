"""CLI tests: argument dispatch and the analyze/validate/stats commands.

Sentry is neutralized so these stay offline and deterministic regardless of
whether a real SENTRY_DSN happens to sit in the developer's .env.
"""

import json
from pathlib import Path

import pytest

from phishingclassifier import cli, observability

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.fixture(autouse=True)
def _no_sentry(monkeypatch):
    monkeypatch.setattr(observability, "init", lambda: False)
    monkeypatch.setattr(observability, "capture_exception",
                        lambda *a, **k: None)


def test_cli_analyze_offline_writes_all_outputs(tmp_path, capsys):
    rc = cli.main([
        "--log-level", "error", "analyze", str(FIXTURES), "--offline",
        "--md-dir", str(tmp_path / "md"),
        "--json", str(tmp_path / "results.json"),
        "--html", str(tmp_path / "summary.html"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "===" in out  # per-email summary printed
    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert data["count"] >= 3
    assert (tmp_path / "summary.html").is_file()
    md_files = list((tmp_path / "md").glob("*.md"))
    assert len(md_files) >= 3


def test_cli_analyze_single_file_offline(tmp_path):
    rc = cli.main([
        "analyze", str(FIXTURES / "spoofed.eml"), "--offline",
        "--md-dir", str(tmp_path / "md"),
    ])
    assert rc == 0
    assert list((tmp_path / "md").glob("*.md"))


def test_cli_analyze_missing_target_returns_two(tmp_path, capsys):
    rc = cli.main(["analyze", str(tmp_path / "nope.eml"), "--offline"])
    assert rc == 2


def test_cli_validate_on_labeled_sample(capsys):
    csv_path = SAMPLES / "labeled_sample.csv"
    if not csv_path.is_file():
        pytest.skip("labeled_sample.csv not present")
    rc = cli.main(["validate", str(csv_path), "--max-rows", "40"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Dataset Validation" in out
    assert "Accuracy:" in out


def test_cli_stats_overlaps_folders(capsys):
    rc = cli.main(["stats", str(FIXTURES), str(FIXTURES)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Detection Performance" in out


def test_cli_requires_subcommand():
    with pytest.raises(SystemExit):
        cli.main([])


def test_enrichment_feedback_signals_from_verdicts():
    enrichment = {
        "mode": "live",
        "lookups": [
            {"source": "virustotal", "ioc": "http://evil.test", "malicious": 5},
            {"source": "urlscan", "ioc": "http://evil.test",
             "verdicts_seen": ["malicious"]},
            {"source": "virustotal", "ioc": "http://clean.test", "malicious": 1},
        ],
    }
    signals = cli._enrichment_feedback_signals({}, enrichment)
    ids = {s["id"] for s in signals}
    assert "vt_malicious_verdict" in ids
    assert "urlscan_malicious_verdict" in ids
    # a single-engine VT hit (below the >=3 threshold) must not fire
    assert sum(1 for s in signals if s["id"] == "vt_malicious_verdict") == 1
