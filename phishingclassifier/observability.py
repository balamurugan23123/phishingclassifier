"""Sentry error monitoring — opt-in, evidence-safe.

Why this shape:
- This tool processes attacker-controlled content (subjects, bodies, URLs).
  Telemetry must never ship that: send_default_pii is OFF and a before_send
  scrub strips known evidence fields from events and breadcrumbs.
- Env-gated: no SENTRY_DSN configured -> init is skipped entirely and every
  helper below is a no-op. Local dev, tests, and CI never phone home.
- DSN resolution mirrors the rest of the tool: os.environ first, then .env
  (repo root), and on Streamlit Cloud the app bridges st.secrets into the
  environment before calling init().
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict

_READY = False

# Fields that may appear in event data or locals that could carry raw
# email evidence. Scrubbed from every outbound event.
_EVIDENCE_KEYS = (
    "subject",
    "body",
    "text_body",
    "html_body",
    "raw",
    "pasted",
    "content",
    "message",
    "evidence",
    "haystack",
    "value",
    "args",
    "headers",
    "received_chain",
    "from_display",
    "reply_to",
    "return_path",
    "urls",
    "domains",
    "ioc",
    "reason",
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_ADDR_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# generous IP v4/v6 matcher for Received-chain remnants
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}\b")


def _scrub(value: Any, depth: int = 0) -> Any:
    """Recursively strip evidence from a value before it leaves the process."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k).lower()
            if key in _EVIDENCE_KEYS or any(e in key for e in _EVIDENCE_KEYS):
                out[k] = "[scrubbed]"
            else:
                out[k] = _scrub(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_scrub(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        # strings: neutralize URLs, email addresses, and IPs
        s = _URL_RE.sub("[url]", value)
        s = _ADDR_RE.sub("[email]", s)
        s = _IP_RE.sub("[ip]", s)
        return s[:400]  # cap long blobs (bodies can end up in locals)
    return value


def _before_send(event: Dict[str, Any], _hint: Any = None) -> Any:
    """Sentry filter: scrub, or drop the event entirely on failure."""
    try:
        if "request" in event:
            event["request"] = _scrub(event["request"])
        for frame_list in ("breadcrumbs", "extra", "contexts"):
            if frame_list in event:
                event[frame_list] = _scrub(event[frame_list])
        if event.get("exception"):
            for exc in event["exception"].get("values", [])[:10]:
                for frame in exc.get("stacktrace", {}).get("frames", [])[:50]:
                    frame["vars"] = _scrub(frame.get("vars", {}))
        if event.get("logentry"):
            event["logentry"] = _scrub(event["logentry"])
        return event
    except Exception:
        return None  # if scrubbing itself fails, send nothing


def _dsn_from_env() -> str:
    return os.environ.get("SENTRY_DSN", "").strip()


def _dsn_from_dotenv() -> str:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return ""
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("SENTRY_DSN="):
                return line.partition("=")[2].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def init() -> bool:
    """Initialize Sentry if a DSN is configured. Returns whether it started.

    Idempotent; safe to call from both the dashboard and CLI entry points.
    """
    global _READY
    if _READY:
        return True
    dsn = _dsn_from_env() or _dsn_from_dotenv()
    if not dsn:
        return False
    try:
        import sentry_sdk

        sentry_sdk.init(
            dsn=dsn,
            # PII OFF: this tool handles evidence, never ship it.
            send_default_pii=False,
            # Sample a small share of transactions: this is a tool, not a
            # web service; full-rate tracing is noise + cost.
            traces_sample_rate=0.05,
            # Errors only by default; switch to logs when we need them.
            attach_stacktrace=False,
            before_send=_before_send,  # type: ignore[arg-type]
            environment=os.environ.get("SENTRY_ENV", "dev"),
        )
        _READY = True
        return True
    except Exception:
        # observability must never take the tool down
        _READY = False
        return False


def capture_exception(exc: BaseException, **tags: str) -> None:
    """Report an exception with tool-specific tags (no-op when disabled)."""
    if not _READY:
        return
    try:
        import sentry_sdk

        with sentry_sdk.new_scope() as scope:
            for k, v in tags.items():
                scope.set_tag(k, v)
            sentry_sdk.capture_exception(exc)
    except Exception:
        pass


def capture_message(text: str, level: str = "info", **tags: str) -> None:
    """Report a plain message (no-op when disabled). Text is scrubbed."""
    if not _READY:
        return
    try:
        import sentry_sdk

        clean = _scrub(text)
        with sentry_sdk.new_scope() as scope:
            for k, v in tags.items():
                scope.set_tag(k, v)
            sentry_sdk.capture_message(clean, level=level)  # type: ignore[arg-type]
    except Exception:
        pass


def enabled() -> bool:
    return _READY
