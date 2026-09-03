"""Phishing classifier triage dashboard."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

# Make the phishingclassifier package importable regardless of where the
# app runs from (repo root locally, /mount/src/<repo> on Streamlit Cloud).
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

st.set_page_config(
    page_title="Phishing Classifier — triage",
    page_icon="shark",
    layout="wide",
)

VERDICT_ORDER = ["Malicious", "Likely Malicious", "Suspicious", "Clean"]
RAIL_COLOR = {
    "Malicious": "#f87171",
    "Likely Malicious": "#fb923c",
    "Suspicious": "#fbbf24",
    "Clean": "#4ade80",
}
RAIL_INK = "#0b0f12"

CSS = """
<style>
.pc-lead{font-size:15px;font-weight:700;letter-spacing:.14em;
 color:#8fa1ad;text-transform:uppercase;margin:0 0 4px 0}
.pc-hero{font-size:44px;line-height:1.05;font-weight:800;color:#e6ebee;
 font-variant-numeric:tabular-nums}
.pc-sub{font-size:13px;font-weight:600;color:#8fa1ad;margin-top:6px;
 font-variant-numeric:tabular-nums}
.pc-distro-bar{display:flex;height:52px;margin:10px 0 4px 0;border-radius:4px;
 overflow:hidden;border:1px solid rgba(230,235,238,.14)}
.pc-distro-seg{display:flex;align-items:center;padding:0 10px;
 font-size:11px;font-weight:700;color:#0b0f12;white-space:nowrap}
.pc-distro-caption{font-size:11px;color:#8fa1ad;letter-spacing:.05em}
.pc-case{border:1px solid rgba(230,235,238,.12);border-radius:6px;
 background:#12181d;margin-bottom:10px;overflow:hidden}
.pc-case-inner{padding:12px 16px}
.pc-head{display:flex;align-items:baseline;gap:12px;margin-bottom:8px;
 border-bottom:1px solid rgba(230,235,238,.08);padding-bottom:8px}
.pc-rail{flex:none;width:86px;border-radius:4px;padding:6px 10px;
 color:#0b0f12;text-align:center}
.pc-rail-score{font-size:22px;font-weight:800;line-height:1;
 font-variant-numeric:tabular-nums}
.pc-rail-verdict{font-size:10px;font-weight:700;letter-spacing:.06em;
 text-transform:uppercase;margin-top:2px;white-space:nowrap}
.pc-head-file{font-size:14px;font-weight:700;color:#e6ebee;min-width:0;
 overflow-wrap:anywhere}
.pc-head-sub{font-size:12px;font-weight:500;color:#8fa1ad;margin-top:2px;
 overflow-wrap:anywhere}
.pc-meta{display:flex;flex-wrap:wrap;gap:8px 24px;
 font-size:12px;font-weight:500;color:#8fa1ad;margin:6px 0 10px 0;
 font-variant-numeric:tabular-nums}
.pc-meta b{color:#e6ebee;font-weight:700}
.pc-meta .bad{color:#f87171}
.pc-meta .warn{color:#fbbf24}
.pc-lead-sm{font-size:11px;font-weight:700;letter-spacing:.14em;
 color:#8fa1ad;text-transform:uppercase;margin:10px 0 4px 0}
.pc-dropzone{border:1px dashed rgba(230,235,238,.22);border-radius:6px;
 padding:24px;background:rgba(230,235,238,.02);text-align:center;
 color:#8fa1ad;font-size:13px;margin:8px 0}
section[data-testid="stExpander"]{border:none !important}
section[data-testid="stExpander"] details{background:transparent}
section[data-testid="stExpander"] summary{font-size:12px !important;
 font-weight:700;letter-spacing:.05em;color:#8fa1ad}
</style>
"""

DEMO_EMAILS = {
    "spoofed.eml": "PayPal display-name spoof + lookalike domain",
    "harvester.eml": "Credential form + IP-literal link + zip attachment",
    "clean.eml": "Legitimate GitHub notification (SPF/DKIM/DMARC pass)",
}


def _esc(value) -> str:
    """Escape text before inserting into HTML."""
    return html.escape(str(value or ""), quote=True)


def _load_results(path: str) -> list:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data.get("results", [])
    return sorted(results, key=lambda r: -r["score"]["score"])


def _analyze_bytes(raw: bytes, source: str) -> dict:
    """Parse and score email bytes."""
    from phishingclassifier.heuristics import analyze_signals
    from phishingclassifier.parser import parse_eml_bytes
    from phishingclassifier.report import build_result

    parsed = parse_eml_bytes(raw, source_path=source)
    analysis = analyze_signals(parsed)
    result = build_result(parsed, analysis)
    result["enrichment"] = {"mode": "offline (user input, no lookup)",
                            "lookups": [], "errors": []}
    return result


def _ioc_lines(result: dict) -> list:
    lines = []
    if result.get("origin_ip"):
        lines.append(f"origin-ip: {result['origin_ip']}")
    iocs = result.get("iocs") or {}
    for url in iocs.get("urls", {}).get("header", []) + \
            iocs.get("urls", {}).get("body", []):
        lines.append(f"url: {url}")
    for d in iocs.get("domains", {}).get("header", []) + \
            iocs.get("domains", {}).get("body", []):
        lines.append(f"domain: {d}")
    for a in iocs.get("attachment_hashes", []):
        lines.append(f"attachment: {a.get('filename')} "
                     f"sha256={a.get('sha256')}")
    return lines


def _distro_html(counts: dict, total: int) -> str:
    if not total:
        return ""
    segs = []
    for verdict in VERDICT_ORDER:
        n = counts.get(verdict, 0)
        if not n:
            continue
        segs.append(
            f"<div class='pc-distro-seg' style='flex:{n};"
            f"background:{RAIL_COLOR[verdict]}'>{verdict} {n}</div>"
        )
    return (
        f"<div class='pc-distro-bar'>{''.join(segs)}</div>"
        "<div class='pc-distro-caption'>verdict distribution</div>"
    )


def _auth_line(result: dict) -> str:
    auth = result.get("auth", {})
    return " &middot; ".join(
        f"<span class='{'bad' if auth.get(m) in ('fail', 'softfail') else ''}'>"
        f"{m.upper()} <b>{_esc(auth.get(m) or '—')}</b></span>"
        for m in ("spf", "dkim", "dmarc")
    )


def _render_cases(results: list) -> None:
    """Render distribution bar and case cards."""
    if not results:
        st.info("No results to show.")
        return
    counts = {v: 0 for v in VERDICT_ORDER}
    for r in results:
        counts[r["score"]["verdict"]] = counts.get(r["score"]["verdict"], 0) + 1
    st.markdown(_distro_html(counts, len(results)), unsafe_allow_html=True)

    for r in results:
        score = r["score"]
        verdict = score["verdict"]
        color = RAIL_COLOR[verdict]
        auth_html = _auth_line(r)
        subject = (r.get("subject") or "(no subject)")[:96]
        from_line = (f"{_esc(r.get('from_display', ''))} "
                     f"&lt;{_esc(r.get('from', ''))}&gt;")
        # ML second opinion: rendered only when a trained model exists.
        # pct >= 60 red-flagged, >= 30 amber, below stays neutral.
        ml = r.get("ml")
        if ml:
            pct = ml.get("probability_phishing", 0) * 100
            cls = "bad" if pct >= 60 else ("warn" if pct >= 30 else "")
            ml_html = (f"<span class='{cls}'>ML <b>{pct:.0f}%</b> "
                       f"phishing</span>")
        else:
            ml_html = ""
        head_html = f"""
<div class="pc-case">
 <div class="pc-case-inner">
  <div class="pc-head">
   <div class="pc-rail" style="background:{color}">
    <div class="pc-rail-score">{score['score']}</div>
    <div class="pc-rail-verdict">{_esc(verdict)}</div>
   </div>
   <div style="min-width:0">
    <div class="pc-head-file">{_esc(Path(r['file']).name)}</div>
    <div class="pc-head-sub">{_esc(subject)}</div>
   </div>
  </div>
  <div class="pc-meta">
   <span>From <b>{from_line}</b></span>
   {f"<span>Reply-To <b>{_esc(r['reply_to'])}</b></span>" if r.get("reply_to") else ""}
   {f"<span>Origin <b>{_esc(r['origin_ip'])}</b></span>" if r.get("origin_ip") else ""}
   <span>{auth_html}</span>
   <span>Hops <b>{r.get('received_hops', 0)}</b></span>
   {ml_html}
  </div>
"""
        st.markdown(head_html, unsafe_allow_html=True)

        with st.expander("Evidence", expanded=False):
            st.markdown("<p class='pc-lead-sm'>Fired signals</p>",
                        unsafe_allow_html=True)
            if r.get("signals"):
                for s in sorted(r["signals"], key=lambda x: -x["weight"]):
                    st.markdown(
                        f"- `[{s['weight']:>2}]` **{s['id']}** — {s['reason']}"
                    )
            else:
                st.markdown("_No signals fired._")

            st.markdown("<p class='pc-lead-sm'>IOCs (plain text)</p>", unsafe_allow_html=True)
            st.code("\n".join(_ioc_lines(r)) or "(none)", language="text")

            enrich = r.get("enrichment") or {}
            st.markdown("<p class='pc-lead-sm'>Enrichment — "
                        f"{enrich.get('mode', 'offline')}</p>",
                        unsafe_allow_html=True)
            for lk in enrich.get("lookups", []):
                st.markdown(
                    f"- `{lk.get('ioc', '')}` — {lk.get('source', '')}: "
                    f"malicious={lk.get('malicious', '')}, "
                    f"reputation={lk.get('reputation', '')}"
                )

            if r.get("parser_warnings"):
                st.markdown("<p class='pc-lead-sm'>Parser warnings</p>",
                            unsafe_allow_html=True)
                for w in r["parser_warnings"]:
                    st.markdown(f"- {w}")
        st.markdown("</div></div>", unsafe_allow_html=True)


def _bridge_cloud_secrets() -> None:
    """Streamlit Cloud secrets -> os.environ bridge.

    Cloud injects secrets via st.secrets (TOML), but the enrichment layer
    reads env vars / .env. Bridge them once per process so live lookups
    work on Cloud exactly as they do locally with .env. Never bridges
    anything that already exists in the environment (real env wins).
    """
    import os

    try:
        if not hasattr(st, "secrets"):
            return
        for name in ("VT_API_KEY", "URLSCAN_API_KEY"):
            if not os.environ.get(name):
                value = st.secrets.get(name)
                if value:
                    os.environ[name] = str(value)
    except Exception:
        pass  # secrets unavailable (local run) — nothing to bridge


def _sidebar_integrations() -> None:
    """Display threat intelligence integration status.

    Degrades gracefully: any failure (including the package being
    unavailable) shows offline status instead of crashing the dashboard.
    """
    st.header("Integrations")
    state_info: dict = {"mode": "offline"}

    _bridge_cloud_secrets()
    try:
        from phishingclassifier.enrich import EnrichmentState

        state = EnrichmentState(offline=False, workdir=str(_ROOT))
        state_info = {
            "mode": "live" if state.enabled else "offline",
            "vt": bool(state.vt_key),
            "urlscan": bool(state.urlscan_key),
        }
    except Exception:
        pass  # status panel only — never a crash vector

    if state_info.get("mode") == "live":
        st.markdown("● **live** — threat-intel lookups active")
        st.markdown(f"- VirusTotal: {'configured' if state_info.get('vt') else 'no key'}")
        st.markdown(f"- urlscan.io: {'configured' if state_info.get('urlscan') else 'no key'}")
    else:
        st.markdown("○ **offline** — no API keys configured")
        st.caption(
            "Keys come from .env locally, or the app's Secrets "
            "(VT_API_KEY / URLSCAN_API_KEY) on Streamlit Cloud."
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json",
                        default=str(_ROOT / "reports" / "output" / "results.json"),
                        help="batch results JSON from the phishingclassifier CLI")
    args, _ = parser.parse_known_args()

    st.markdown(CSS, unsafe_allow_html=True)

    left, right = st.columns([5, 2])
    with left:
        st.markdown(
            "<p class='pc-lead'>Phishing Classifier — triage bench</p>",
            unsafe_allow_html=True,
        )
        st.caption("Heuristic scores are analyst aids, not verdicts.")
    with right:
        st.markdown("<p class='pc-lead' style='text-align:right'>bench</p>",
                    unsafe_allow_html=True)

    mode = st.radio(
        "Input",
        ["Prebuilt demo", "Paste raw email", "Upload .eml", "Batch file"],
        horizontal=True,
    )

    results: list = []

    if mode == "Prebuilt demo":
        st.markdown(
            "<div class='pc-dropzone'>Bundled fixture emails — "
            "display-name spoof, credential harvester, and legitimate notification.</div>",
            unsafe_allow_html=True,
        )
        fixtures = _ROOT / "tests" / "fixtures"
        for name in DEMO_EMAILS:
            path = fixtures / name
            if not path.is_file():
                st.warning(f"Demo fixture missing: {path}")
                continue
            results.append(_analyze_bytes(path.read_bytes(), source=name))
        if results:
            st.caption(" · ".join(
                f"`{n}` {d}" for n, d in DEMO_EMAILS.items()))
        with st.sidebar:
            _sidebar_integrations()

    elif mode == "Paste raw email":
        st.markdown(
            "<div class='pc-dropzone'>Paste full raw email (headers and body). "
            "Parsed locally in memory.</div>",
            unsafe_allow_html=True,
        )
        pasted = st.text_area(
            "Raw email",
            height=240,
            placeholder=("From: \"PayPal Support\" <security@paypa1-alerts.com>\n"
                         "Subject: URGENT: verify your account\n"
                         "...\n\nDear Customer, click here to verify..."),
        )
        if st.button("Analyze pasted email", type="primary"):
            if not pasted.strip():
                st.error("Paste a raw email first.")
            else:
                results.append(_analyze_bytes(
                    pasted.encode("utf-8", errors="replace"),
                    source="(pasted email)"))
        with st.sidebar:
            _sidebar_integrations()

    elif mode == "Upload .eml":
        uploads = st.file_uploader(
            "Upload .eml file(s)",
            type=["eml", "txt"],
            accept_multiple_files=True,
        )
        if uploads:
            results = [
                _analyze_bytes(up.getvalue(), source=up.name) for up in uploads
            ]
        elif not uploads:
            st.markdown(
                "<div class='pc-dropzone'>Drop .eml files here to analyze locally.</div>",
                unsafe_allow_html=True,
            )
        with st.sidebar:
            _sidebar_integrations()

    else:
        try:
            results = _load_results(args.json)
        except FileNotFoundError:
            st.error(f"Results file not found: {args.json}\n\n"
                     "Generate one first, e.g.:\n\n"
                     "```\n"
                     "python -m phishingclassifier.cli analyze <folder> "
                     "--json reports/output/results.json\n"
                     "```")
            return
        except json.JSONDecodeError:
            st.error("Results file is not valid JSON.")
            return
        with st.sidebar:
            st.header("Batch filters")
            verdicts = st.multiselect("Verdict", VERDICT_ORDER,
                                      default=VERDICT_ORDER)
            min_score = st.slider("Min score", 0, 100, 0)
            max_score = st.slider("Max score", 0, 100, 100)
            search = st.text_input(
                "Subject/sender contains",
            ).lower()

            def _keep(r) -> bool:
                if r["score"]["verdict"] not in verdicts:
                    return False
                if not (min_score <= r["score"]["score"] <= max_score):
                    return False
                if search and search not in (
                    (r.get("subject", "") + " " + r.get("from", ""))
                ).lower():
                    return False
                return True

            results = [r for r in results if _keep(r)]
            st.write(f"Showing {len(results)} email(s)")
            _sidebar_integrations()

    if results:
        _render_cases(results)
    elif mode == "Batch file":
        st.info("No results in batch file.")


if __name__ == "__main__":
    main()
