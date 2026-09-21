"""Enrichment tests."""

import json
from pathlib import Path

from phishingclassifier.enrich import (
    EnrichmentState,
    VT_MIN_INTERVAL,
    enrich_result,
)
from phishingclassifier.heuristics import analyze_signals
from phishingclassifier.parser import parse_eml
from phishingclassifier.report import build_result, html_summary

FIXTURES = Path(__file__).parent / "fixtures"


def test_offline_mode_when_no_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    # Plant an empty .env in the workdir: the loader takes the first
    # EXISTING .env it finds, so this isolates the test from the real
    # repo-root .env (which holds live keys on dev machines).
    (tmp_path / ".env").write_text("", encoding="utf-8")
    state = EnrichmentState(offline=False, workdir=str(tmp_path))
    assert state.enabled is False
    parsed = parse_eml(str(FIXTURES / "harvester.eml"))
    result = build_result(parsed, analyze_signals(parsed))
    block = enrich_result(result, state)
    assert block["mode"].startswith("offline")
    assert block["lookups"] == []


def test_offline_flag_forces_skip(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    state = EnrichmentState(offline=True)
    parsed = parse_eml(str(FIXTURES / "spoofed.eml"))
    result = build_result(parsed, analyze_signals(parsed))
    block = enrich_result(result, state)
    assert block["mode"] == "offline (--offline flag)"


def test_cache_written_atomically(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    state = EnrichmentState()
    state._put_cache("vt:/ip_addresses/1.2.3.4", {"data": {"ok": True}})
    cache_file = tmp_path / "cache" / "vt_cache.json"
    assert cache_file.is_file()
    data = json.loads(cache_file.read_text(encoding="utf-8"))
    entry = data["vt:/ip_addresses/1.2.3.4"]
    # envelope carries a timestamp + the cached value
    assert "at" in entry
    assert entry["value"]["data"]["ok"] is True
    leftovers = list((tmp_path / "cache").glob("*.tmp"))
    assert leftovers == []


def _state_with_key(tmp_path, monkeypatch, **kw):
    monkeypatch.setenv("VT_API_KEY", "dummy-key")
    monkeypatch.delenv("VT_CACHE_TTL", raising=False)
    monkeypatch.chdir(tmp_path)
    return EnrichmentState(workdir=str(tmp_path), **kw)


def test_cache_hit_within_ttl(tmp_path, monkeypatch):
    state = _state_with_key(tmp_path, monkeypatch, cache_ttl=3600)
    state._put_cache("vt:/domains/evil.com", {"malicious": 5})
    assert state._cached("vt:/domains/evil.com") == {"malicious": 5}
    assert state.cache_hits == 1


def test_cache_expires_after_ttl(tmp_path, monkeypatch):
    state = _state_with_key(tmp_path, monkeypatch, cache_ttl=100)
    state._put_cache("vt:/domains/evil.com", {"malicious": 5})
    # backdate the stored timestamp past the TTL
    state._cache["vt:/domains/evil.com"]["at"] -= 1000
    assert state._cached("vt:/domains/evil.com") is None
    assert state.cache_expired >= 1
    # stale entry is dropped from the cache and file
    assert "vt:/domains/evil.com" not in state._cache


def test_zero_ttl_disables_cache(tmp_path, monkeypatch):
    state = _state_with_key(tmp_path, monkeypatch, cache_ttl=0)
    state._put_cache("vt:/domains/evil.com", {"malicious": 5})
    assert state._cached("vt:/domains/evil.com") is None


def test_legacy_entry_without_envelope_is_stale(tmp_path, monkeypatch):
    state = _state_with_key(tmp_path, monkeypatch, cache_ttl=3600)
    # simulate a pre-TTL cache file: value stored with no envelope
    state._cache["vt:/domains/old.com"] = {"malicious": 9}
    assert state._cached("vt:/domains/old.com") is None


def test_ttl_read_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "dummy-key")
    monkeypatch.setenv("VT_CACHE_TTL", "60")
    monkeypatch.chdir(tmp_path)
    state = EnrichmentState(workdir=str(tmp_path))
    assert state.cache_ttl == 60


def test_vt_free_tier_pacing(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "dummy-key")
    monkeypatch.chdir(tmp_path)  # isolate from any real .env: no live calls
    state = EnrichmentState()
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    calls = []

    def fake_http(url, headers):
        calls.append(url)
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

    monkeypatch.setattr(state, "_http_get", fake_http)
    state.vt_ip("1.1.1.1")
    state.vt_ip("2.2.2.2")
    assert len(calls) == 2
    assert len(slept) >= 1
    assert slept[0] <= VT_MIN_INTERVAL


def test_urlscan_search_mode_only(monkeypatch, tmp_path):
    monkeypatch.setenv("URLSCAN_API_KEY", "dummy-key")
    monkeypatch.chdir(tmp_path)  # isolate from any real .env: no live calls
    state = EnrichmentState()
    called_urls = []

    class DummyResp:
        status_code = 200

        def json(self):
            return {"total": 3, "results": [{"verdicts": {"overall": "malicious"}}]}

    class DummyRequests:
        RequestException = Exception

        @staticmethod
        def get(url, params=None, headers=None, timeout=None):
            called_urls.append(url)
            return DummyResp()

    monkeypatch.setattr("requests.get", DummyRequests.get, raising=False)
    monkeypatch.setitem(__import__("sys").modules, "requests", DummyRequests)

    res = state.urlscan_search("bad.example.com")
    assert res is not None
    assert res["source"] == "urlscan"
    assert res["total_existing_scans"] == 3
    assert "malicious" in res["verdicts_seen"]
    assert any("/search/" in u for u in called_urls)
    assert not any("/scan/" in u for u in called_urls)


def test_enrich_result_overlaps_urlscan_with_vt_and_preserves_order(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "dummy")
    monkeypatch.setenv("URLSCAN_API_KEY", "dummy")
    monkeypatch.chdir(tmp_path)
    state = EnrichmentState(workdir=str(tmp_path))

    # No real network: replace the lookups with fast fakes. urlscan_search
    # runs on the thread pool while VT stays on the main thread; this asserts
    # the concurrent path yields the exact same ordered output as sequential.
    def fake_vt_ip(ip):
        return {"source": "virustotal", "type": "ip", "malicious": 1}

    def fake_vt_domain(d):
        return {"source": "virustotal", "type": "domain", "malicious": 2}

    def fake_urlscan(d):
        return {
            "source": "urlscan",
            "type": "domain_search",
            "total_existing_scans": 7,
            "verdicts_seen": ["malicious"],
        }

    monkeypatch.setattr(state, "vt_ip", fake_vt_ip)
    monkeypatch.setattr(state, "vt_domain", fake_vt_domain)
    monkeypatch.setattr(state, "urlscan_search", fake_urlscan)

    result = {
        "origin_ip": None,
        "iocs": {"domains": {"header": ["a.test", "b.test"], "body": []}, "attachment_hashes": []},
    }
    block = enrich_result(result, state, max_lookups=20)
    assert block["mode"] == "live"
    # each domain yields a VT result then its urlscan result, in order
    assert [(lk["ioc"], lk["source"]) for lk in block["lookups"]] == [
        ("a.test", "virustotal"),
        ("a.test", "urlscan"),
        ("b.test", "virustotal"),
        ("b.test", "urlscan"),
    ]


def test_enrichment_never_raises(monkeypatch):
    state = EnrichmentState()
    state.vt_key = "dummy"

    def blow_up(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(state, "vt_ip", blow_up)
    parsed = parse_eml(str(FIXTURES / "harvester.eml"))
    result = build_result(parsed, analyze_signals(parsed))
    block = enrich_result(result, state)
    assert block["mode"] == "live"
    assert any("RuntimeError" in e for e in block["errors"])


def test_html_summary_has_no_remote_resources_and_escapes():
    results = []
    for name in ("clean.eml", "spoofed.eml", "harvester.eml"):
        parsed = parse_eml(str(FIXTURES / name))
        analysis = analyze_signals(parsed)
        result = build_result(parsed, analysis)
        result["enrichment"] = {"mode": "offline", "lookups": []}
        results.append(result)
    page = html_summary(results)

    lower = page.lower()
    assert "<script" not in lower
    assert "src=" not in lower
    assert "link rel" not in lower
    assert "<a href" not in lower
    assert "PayPal Support" in page
    assert "&lt;" in page
    assert "phishing classifier" in page
