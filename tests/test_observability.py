"""Observability tests: evidence scrubbing and safe no-op behavior.

These must never require a real Sentry DSN or network: the whole point of the
module is that it is env-gated and evidence-safe.
"""

from phishingclassifier import observability


def test_scrub_replaces_known_evidence_keys():
    event = {
        "subject": "urgent verify your account",
        "text_body": "click http://evil.test/x now",
        "benign_field": "keep me",
    }
    out = observability._scrub(event)
    assert out["subject"] == "[scrubbed]"
    assert out["text_body"] == "[scrubbed]"
    assert out["benign_field"] == "keep me"


def test_scrub_neutralizes_urls_emails_ips_in_strings():
    s = "contact john@corp.example from 203.0.113.9 at https://paypa1.evil/x"
    out = observability._scrub(s)
    assert "[email]" in out
    assert "[ip]" in out
    assert "[url]" in out
    assert "john@corp.example" not in out
    assert "https://paypa1.evil" not in out


def test_scrub_caps_length_and_depth():
    long = observability._scrub("a" * 5000)
    assert len(long) <= 400
    deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": "x"}}}}}}}}
    assert observability._scrub(deep) is not None  # does not recurse forever


def test_before_send_scrubs_request_and_logentry():
    # 'meta'/'formatted' are NOT evidence keys, so scrubbing recurses into
    # them rather than replacing them wholesale -- lets us assert the actual
    # field-level and string-level scrubbing _before_send performs.
    event = {
        "request": {"meta": {"subject": "leak", "keep": "fine"}},
        "logentry": {"formatted": "ping me@corp.test now"},
    }
    out = observability._before_send(event)
    assert out is not None
    assert out["request"]["meta"]["subject"] == "[scrubbed]"
    assert out["request"]["meta"]["keep"] == "fine"
    assert "@corp.test" not in out["logentry"]["formatted"]


def test_before_send_drops_event_when_scrub_fails(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("scrub broke")

    monkeypatch.setattr(observability, "_scrub", boom)
    event = {"request": {"headers": {"subject": "x"}}}
    assert observability._before_send(event) is None


def test_init_is_noop_without_dsn(monkeypatch):
    monkeypatch.setattr(observability, "_dsn_from_env", lambda: "")
    monkeypatch.setattr(observability, "_dsn_from_dotenv", lambda: "")
    monkeypatch.setattr(observability, "_READY", False)
    assert observability.init() is False
    assert observability.enabled() is False


def test_capture_helpers_are_noops_when_disabled(monkeypatch):
    monkeypatch.setattr(observability, "_READY", False)
    # Must return cleanly without importing/using sentry.
    assert observability.capture_exception(ValueError("x"), surface="cli") is None
    assert observability.capture_message("hello", level="info") is None
