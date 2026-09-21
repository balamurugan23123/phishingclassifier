"""Phishing classifier triage dashboard."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Make the phishingclassifier package importable regardless of where the
# app runs from (repo root locally, /mount/src/<repo> on Streamlit Cloud).
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from phishingclassifier import observability
from phishingclassifier.utils import esc as _esc

# Error monitoring: starts only when a DSN is present (env, .env, or
# Streamlit Cloud secrets — bridged below). Evidence-scrubbing is inside
# the module; the DSN lookup itself needs no secrets here.
observability.init()

# Surface library diagnostics (cache/model/API warnings) in the server log.
# Streamlit may already install root handlers, so basicConfig is a no-op guard:
# we only bump the level if nothing else has configured logging yet.
logging.basicConfig(
    level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
)

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

# Pasted/uploaded emails are parsed in memory; cap their size so a single
# giant input can't exhaust the server. Real raw emails are tens-to-hundreds
# of KB; 5 MiB leaves ample headroom while bounding worst-case memory.
MAX_INPUT_BYTES = 5 * 1024 * 1024

CSS = """
<style>
:root{
 --ink-0:#0b0f12; --ink-1:#12181d; --ink-2:#1a2228;
 --line:rgba(230,235,238,.10); --line-soft:rgba(230,235,238,.06);
 --txt:#e6ebee; --txt-mut:#8fa1ad; --txt-dim:#5c6b76;
 --acc:#22d3ee; --acc-dim:rgba(34,211,238,.12);
 --bad:#f87171; --warn:#fbbf24; --ok:#4ade80;
 /* Local system-font stacks only. The dashboard deliberately loads ZERO
    remote resources (same opsec rule as the HTML reports): no webfont is
    fetched, so an analyst's IP/user-agent is never leaked to a third party. */
 --font-display:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,
    Helvetica,Arial,sans-serif;
 --font-mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,
    "Liberation Mono","Courier New",monospace;
}
/* page shell */
.appview-container, .block-container, section[data-testid="stSidebar"],
.stApp, [data-testid="stHeader"]{background:var(--ink-0) !important;
 font-family:var(--font-mono) !important}
.block-container{padding-top:1.2rem !important;max-width:1200px}
section[data-testid="stSidebar"]{border-right:1px solid var(--line)}
/* type */
.pc-lead{font-family:var(--font-mono);font-size:11px;font-weight:500;
 letter-spacing:.18em;color:var(--txt-mut);text-transform:uppercase}
/* ---- hero band -------------------------------------------------------- */
.pc-hero{display:flex;flex-wrap:wrap;align-items:flex-end;gap:0 28px;
 padding:26px 0 18px 0;margin-bottom:14px;
 border-bottom:1px solid var(--line);
 background:
  radial-gradient(600px 160px at 12% 0%,rgba(34,211,238,.05),transparent 60%),
  var(--ink-0)}
.pc-title{font-family:var(--font-display);font-size:46px;line-height:1.02;
 font-weight:700;letter-spacing:-.02em;margin:2px 0 10px 0;
 background:linear-gradient(92deg,#e6ebee 30%,#22d3ee 130%);
 -webkit-background-clip:text;background-clip:text;color:transparent}
.pc-tag{font-size:14px;color:var(--txt-mut);font-weight:500;max-width:560px;
 line-height:1.5;text-wrap:balance}
.pc-chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.pc-chip{font-size:11px;font-weight:500;letter-spacing:.06em;color:var(--txt-mut);
 border:1px solid var(--line);border-radius:3px;padding:4px 10px;
 background:var(--ink-1)}
.pc-chip b{color:var(--txt);font-weight:600}
.pc-stat-strip{display:flex;gap:26px;margin-left:auto;align-items:flex-end;
 padding-bottom:2px}
.pc-stat{ text-align:right}
.pc-stat-n{font-family:var(--font-display);font-size:30px;font-weight:700;
 color:var(--txt);font-variant-numeric:tabular-nums;line-height:1}
.pc-stat-l{font-size:10px;letter-spacing:.14em;color:var(--txt-dim);
 text-transform:uppercase;margin-top:4px}
.pc-stat-foot{font-size:11px;color:var(--txt-dim);line-height:1.55;
 padding-bottom:16px;max-width:900px;margin-top:-6px}
/* ---- verdict distribution bar ----------------------------------------- */
.pc-distro-bar{display:flex;height:46px;margin:12px 0 4px 0;border-radius:4px;
 overflow:hidden;border:1px solid var(--line)}
.pc-distro-seg{display:flex;align-items:center;padding:0 10px;
 font-size:11px;font-weight:700;color:var(--ink-0);white-space:nowrap;
 overflow:hidden;text-overflow:ellipsis}
.pc-distro-seg:first-child{clip-path:inset(0 0 0 0)}
.pc-distro-caption{font-size:11px;color:var(--txt-dim);letter-spacing:.05em}
/* ---- mode tabs (segmented control) ------------------------------------ */
div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"]:first-child
 ~ div[data-testid="stColumn"]{padding:0 2px}
.stTabs [data-baseweb="tab-list"]{gap:4px;border-bottom:1px solid var(--line);
 background:var(--ink-1);border-radius:6px 6px 0 0;padding:4px 4px 0 4px}
.stTabs [data-baseweb="tab"]{font-family:var(--font-mono) !important;
 font-size:13px !important;font-weight:500 !important;color:var(--txt-mut) !important;
 background:transparent !important;border-radius:4px 4px 0 0 !important;
 padding:8px 22px !important;line-height:24px !important}
.stTabs [data-baseweb="tab"] svg{width:14px;height:14px;margin-right:6px;
 opacity:.7}
.stTabs [data-baseweb="tab-highlight"],.stTabs [data-baseweb="tab-border"]{
 display:none !important}
.stTabs [aria-selected="true"]{color:var(--txt) !important;
 background:var(--ink-2) !important;
 box-shadow:inset 0 -2px 0 0 var(--acc)}
.stTabs [data-baseweb="tab"]:hover{color:var(--txt) !important}
/* ---- case cards ------------------------------------------------------- */
.pc-case{border:1px solid var(--line);border-radius:6px;
 background:var(--ink-1);margin-bottom:10px;overflow:hidden;
 transition:transform .18s cubic-bezier(.23,1,.32,1),
 border-color .18s cubic-bezier(.23,1,.32,1)}
.pc-case:hover{transform:translateY(-1px);border-color:rgba(34,211,238,.25)}
.pc-case-inner{padding:12px 16px}
.pc-head{display:flex;align-items:baseline;gap:12px;margin-bottom:8px;
 border-bottom:1px solid var(--line-soft);padding-bottom:8px}
.pc-rail{flex:none;width:92px;border-radius:4px;padding:6px 10px;
 color:var(--ink-0);text-align:center;position:relative;overflow:hidden;
 display:flex;flex-direction:column;align-items:center;justify-content:center;
 min-height:52px}
.pc-rail::after{content:'';position:absolute;inset:0;
 background:linear-gradient(120deg,transparent 30%,rgba(11,15,18,.18) 50%,
 transparent 70%);transform:translateX(-100%);
 animation:pc-scan 2.8s cubic-bezier(.4,0,.2,1) infinite}
@keyframes pc-scan{0%{transform:translateX(-100%)}55%,100%{transform:translateX(100%)}}
.pc-rail-score{font-family:var(--font-display);font-size:22px;font-weight:700;
 line-height:1;font-variant-numeric:tabular-nums}
.pc-rail-verdict{font-size:9px;font-weight:700;letter-spacing:.05em;
 text-transform:uppercase;margin-top:3px;line-height:1.25;
 word-break:break-word;display:-webkit-box;-webkit-line-clamp:2;
 -webkit-box-orient:vertical;overflow:hidden;white-space:normal}
.pc-head-file{font-family:var(--font-mono);font-size:14px;font-weight:700;
 color:var(--txt);min-width:0;overflow-wrap:anywhere}
.pc-head-sub{font-size:12px;font-weight:500;color:var(--txt-mut);margin-top:2px;
 overflow-wrap:anywhere}
.pc-meta{display:flex;flex-wrap:wrap;gap:8px 24px;font-size:12px;
 font-weight:500;color:var(--txt-mut);margin:6px 0 10px 0;
 font-variant-numeric:tabular-nums}
.pc-meta b{color:var(--txt);font-weight:700}
.pc-meta .bad{color:var(--bad)}
.pc-meta .warn{color:var(--warn)}
.pc-lead-sm{font-size:11px;font-weight:700;letter-spacing:.14em;
 color:var(--txt-mut);text-transform:uppercase;margin:12px 0 6px 0}
/* ---- evidence internals: signal rows ---------------------------------- */
.pc-sig{display:flex;align-items:baseline;gap:10px;padding:7px 10px;
 border:1px solid var(--line-soft);border-left:2px solid var(--txt-dim);
 border-radius:4px;margin-bottom:4px;background:var(--ink-2)}
.pc-sig.w-hi{border-left-color:var(--bad)}
.pc-sig.w-md{border-left-color:var(--warn)}
.pc-sig.w-lo{border-left-color:var(--txt-dim)}
.pc-sig-w{flex:none;font-family:var(--font-mono);font-size:11px;font-weight:700;
 color:var(--ink-0);background:var(--txt-dim);border-radius:3px;
 padding:1px 6px;min-width:26px;text-align:center}
.pc-sig.w-hi .pc-sig-w{background:var(--bad);color:var(--ink-0)}
.pc-sig.w-md .pc-sig-w{background:var(--warn);color:var(--ink-0)}
.pc-sig-id{flex:none;font-size:12px;font-weight:700;color:var(--txt)}
.pc-sig-reason{font-size:11.5px;color:var(--txt-mut);line-height:1.45;
 overflow-wrap:anywhere}
.pc-sig-empty{font-size:12px;color:var(--txt-dim);padding:10px 12px;
 border:1px dashed var(--line);border-radius:4px}
/* ---- enrichment lookup rows -------------------------------------------- */
.pc-lk{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 18px;
 padding:6px 10px;border:1px solid var(--line-soft);border-radius:4px;
 margin-bottom:3px;background:var(--ink-2);font-size:11.5px;color:var(--txt-mut)}
.pc-lk-ioc{font-family:var(--font-mono);font-weight:700;color:var(--txt);
 overflow-wrap:anywhere}
.pc-lk-src{font-size:10px;letter-spacing:.08em;text-transform:uppercase;
 color:var(--txt-dim)}
.pc-lk .bad{color:var(--bad)}
/* ---- integrations status card (sidebar) -------------------------------- */
.pc-int-card{border:1px solid var(--line);border-radius:6px;
 background:var(--ink-1);padding:10px 12px;margin-top:2px}
.pc-int-mode{font-size:12px;font-weight:700;letter-spacing:.12em;
 color:var(--txt);text-transform:uppercase;display:flex;align-items:center;
 gap:8px;margin-bottom:8px;padding-bottom:8px;
 border-bottom:1px solid var(--line-soft)}
.pc-dot{width:8px;height:8px;border-radius:50%;background:var(--txt-dim);
 flex:none;display:inline-block}
.pc-dot.on{background:var(--ok);
 box-shadow:0 0 0 0 rgba(74,222,128,.5);animation:pc-pulse 2s infinite}
@keyframes pc-pulse{0%{box-shadow:0 0 0 0 rgba(74,222,128,.45)}
 70%{box-shadow:0 0 0 7px rgba(74,222,128,0)}100%{box-shadow:0 0 0 0 rgba(74,222,128,0)}}
.pc-int-row{display:flex;align-items:center;justify-content:space-between;
 gap:8px;margin:6px 0}
.pc-int-name{font-size:12px;font-weight:500;color:var(--txt)}
.pc-pill{font-size:10px;font-weight:600;letter-spacing:.04em;
 color:var(--txt-dim);border:1px solid var(--line);border-radius:3px;
 padding:2px 8px;text-transform:uppercase}
.pc-pill.ok{color:var(--ok);border-color:rgba(74,222,128,.35);
 background:rgba(74,222,128,.06)}
.pc-int-note{font-size:10.5px;color:var(--txt-dim);line-height:1.5;
 margin-top:8px;padding-top:8px;border-top:1px solid var(--line-soft)}
.pc-int-note b{color:var(--txt-mut)}
/* ---- dropzones / empty states ----------------------------------------- */
.pc-dropzone{border:1px dashed rgba(34,211,238,.28);border-radius:6px;
 padding:26px 24px;background:rgba(34,211,238,.03);text-align:center;
 color:var(--txt-mut);font-size:13px;margin:10px 0;position:relative;overflow:hidden}
.pc-dropzone::before{content:'';position:absolute;top:0;left:-60%;width:40%;
 height:1px;background:linear-gradient(90deg,transparent,var(--acc),transparent);
 animation:pc-sweep 3.2s ease-in-out infinite}
@keyframes pc-sweep{0%{left:-60%}100%{left:120%}}
/* ---- entrance --------------------------------------------------------- */
.pc-rise{animation:pc-rise .5s cubic-bezier(.23,1,.32,1) both}
@keyframes pc-rise{from{opacity:0;transform:translateY(10px)}
 to{opacity:1;transform:translateY(0)}}
@media (prefers-reduced-motion:reduce){
 .pc-case,.pc-case:hover{transform:none;transition:none}
 .pc-rail::after,.pc-dropzone::before{animation:none}
 .pc-rise{animation:none}
 .pc-dot.on{animation:none}
 .pc-title{background:none;-webkit-text-fill-color:var(--txt);color:var(--txt)}
}
/* ---- streamlit resets ------------------------------------------------- */
section[data-testid="stExpander"]{border:none !important}
section[data-testid="stExpander"] details{background:transparent}
section[data-testid="stExpander"] summary{font-size:12px !important;
 font-weight:600;letter-spacing:.05em;color:var(--txt-mut)}
div[data-testid="stCaptionContainer"]{color:var(--txt-dim) !important}
</style>
"""

DEMO_EMAILS = {
    "spoofed.eml": "PayPal display-name spoof + lookalike domain",
    "harvester.eml": "Credential form + IP-literal link + zip attachment",
    "clean.eml": "Legitimate GitHub notification (SPF/DKIM/DMARC pass)",
}


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
    result["enrichment"] = {"mode": "offline (user input, no lookup)", "lookups": [], "errors": []}
    return result


# Streamlit re-executes this whole script (every tab body included) on any
# widget interaction. Caching the pure analysis/loading work by input means a
# slider tweak in one tab does not re-parse and re-score emails elsewhere.
_analyze_bytes = st.cache_data(_analyze_bytes, show_spinner="Analyzing\u2026")
_load_results = st.cache_data(_load_results)


def _analyze_many(items: list) -> list:
    """Analyze a list of (raw_bytes, source) pairs defensively.

    User-supplied .eml files are untrusted and can be malformed in ways the
    parser's own guards don't cover. One bad file must not tear down the whole
    tab: analyze each in isolation, surface failures inline, and render only
    the ones that succeeded.
    """
    results, failures = [], []
    for raw, source in items:
        try:
            results.append(_analyze_bytes(raw, source))
        except Exception as exc:  # noqa: BLE001 - deliberate per-file guard
            failures.append((source, exc))
    for source, exc in failures:
        st.error(
            f"Could not analyze <b>{_esc(source)}</b>: "
            f"{_esc(type(exc).__name__)} \u2014 the rest of your files "
            "are shown below.",
            unsafe_allow_html=True,
        )
    return results


def _ioc_lines(result: dict) -> list:
    lines = []
    if result.get("origin_ip"):
        lines.append(f"origin-ip: {result['origin_ip']}")
    iocs = result.get("iocs") or {}
    for url in iocs.get("urls", {}).get("header", []) + iocs.get("urls", {}).get("body", []):
        lines.append(f"url: {url}")
    for d in iocs.get("domains", {}).get("header", []) + iocs.get("domains", {}).get("body", []):
        lines.append(f"domain: {d}")
    for a in iocs.get("attachment_hashes", []):
        lines.append(f"attachment: {a.get('filename')} sha256={a.get('sha256')}")
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


def _export_block(results: list, export_key: str) -> None:
    """Offer the analyzed results for download (JSON always, Markdown when
    a single email). Nothing leaves the page unless the analyst clicks."""
    from phishingclassifier.report import batch_json, markdown_report

    label = "Download results (JSON)" if len(results) != 1 else "Download this result (JSON)"
    st.download_button(
        label,
        data=batch_json(results),
        file_name="phishing_results.json",
        mime="application/json",
        key=f"dl_json_{export_key}",
    )
    if len(results) == 1:
        stem = Path(results[0]["file"]).stem or "email"
        st.download_button(
            "Download report (Markdown)",
            data=markdown_report(results[0]),
            file_name=f"{stem}.md",
            mime="text/markdown",
            key=f"dl_md_{export_key}",
        )


def _render_cases(results: list, export_key: str = "view") -> None:
    """Render distribution bar, export control, and case cards."""
    if not results:
        st.info("No results to show.")
        return
    counts = {v: 0 for v in VERDICT_ORDER}
    for r in results:
        counts[r["score"]["verdict"]] = counts.get(r["score"]["verdict"], 0) + 1
    st.markdown(_distro_html(counts, len(results)), unsafe_allow_html=True)
    _export_block(results, export_key)

    for r in results:
        score = r["score"]
        verdict = score["verdict"]
        color = RAIL_COLOR[verdict]
        auth_html = _auth_line(r)
        subject = (r.get("subject") or "(no subject)")[:96]
        from_line = f"{_esc(r.get('from_display', ''))} &lt;{_esc(r.get('from', ''))}&gt;"
        # ML second opinion: rendered only when a trained model exists.
        # pct >= 60 red-flagged, >= 30 amber, below stays neutral.
        ml = r.get("ml")
        if ml:
            pct = ml.get("probability_phishing", 0) * 100
            cls = "bad" if pct >= 60 else ("warn" if pct >= 30 else "")
            ml_html = f"<span class='{cls}'>ML <b>{pct:.0f}%</b> phishing</span>"
        else:
            ml_html = ""
        head_html = f"""
<div class="pc-case">
 <div class="pc-case-inner">
  <div class="pc-head">
   <div class="pc-rail" style="background:{color}">
    <div class="pc-rail-score">{score["score"]}</div>
    <div class="pc-rail-verdict">{_esc(verdict)}</div>
   </div>
   <div style="min-width:0">
    <div class="pc-head-file">{_esc(Path(r["file"]).name)}</div>
    <div class="pc-head-sub">{_esc(subject)}</div>
   </div>
  </div>
  <div class="pc-meta">
   <span>From <b>{from_line}</b></span>
   {f"<span>Reply-To <b>{_esc(r['reply_to'])}</b></span>" if r.get("reply_to") else ""}
   {f"<span>Origin <b>{_esc(r['origin_ip'])}</b></span>" if r.get("origin_ip") else ""}
   <span>{auth_html}</span>
   <span>Hops <b>{r.get("received_hops", 0)}</b></span>
   {ml_html}
  </div>
"""
        st.markdown(head_html, unsafe_allow_html=True)

        with st.expander("Evidence", expanded=False):
            # ---- fired signals: weight chip + id + reason -------------------
            st.markdown("<p class='pc-lead-sm'>Fired signals</p>", unsafe_allow_html=True)
            if r.get("signals"):
                rows = []
                for s in sorted(r["signals"], key=lambda x: (-x["weight"], x["id"])):
                    w = s["weight"]
                    if w >= 20:
                        wcls = "w-hi"
                    elif w >= 15:
                        wcls = "w-md"
                    else:
                        wcls = "w-lo"
                    rows.append(f"""
<div class='pc-sig {wcls}'>
 <span class='pc-sig-w'>{w}</span>
 <span class='pc-sig-id'>{_esc(s["id"])}</span>
 <span class='pc-sig-reason'>{_esc(s["reason"])}</span>
</div>""")
                st.markdown("".join(rows), unsafe_allow_html=True)
            else:
                st.markdown(
                    "<div class='pc-sig-empty'>No signals fired — "
                    "nothing in this email matched any rule.</div>",
                    unsafe_allow_html=True,
                )

            # ---- IOCs: plain text, never clickable -------------------------
            st.markdown(
                "<p class='pc-lead-sm'>IOCs — plain text, never click or scan</p>",
                unsafe_allow_html=True,
            )
            st.code("\n".join(_ioc_lines(r)) or "(none)", language="text")

            # ---- enrichment lookups ----------------------------------------
            enrich = r.get("enrichment") or {}
            st.markdown(
                f"<p class='pc-lead-sm'>Enrichment — {enrich.get('mode', 'offline')}</p>",
                unsafe_allow_html=True,
            )
            lookups = enrich.get("lookups", [])
            if lookups:
                lk_rows = []
                for lk in lookups:
                    mal = lk.get("malicious")
                    bad = "bad" if (isinstance(mal, (int, float)) and mal >= 3) else ""
                    lk_rows.append(f"""
<div class='pc-lk'>
 <span class='pc-lk-ioc'>{_esc(lk.get("ioc", ""))}</span>
 <span class='pc-lk-src'>{_esc(lk.get("source", ""))}</span>
 <span class='{bad}'>malicious <b>{_esc(mal if mal is not None else "—")}</b></span>
 <span>reputation <b>{_esc(lk.get("reputation", "—"))}</b></span>
</div>""")
                st.markdown("".join(lk_rows), unsafe_allow_html=True)
            elif enrich.get("mode", "").startswith("live"):
                st.markdown("_No lookups returned data._")

            if r.get("parser_warnings"):
                st.markdown("<p class='pc-lead-sm'>Parser warnings</p>", unsafe_allow_html=True)
                for w in r["parser_warnings"]:
                    st.markdown(f"- {_esc(w)}")
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
        for name in ("VT_API_KEY", "URLSCAN_API_KEY", "SENTRY_DSN"):
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
    st.markdown("<p class='pc-lead'>Integrations</p>", unsafe_allow_html=True)
    state_info: dict = {"mode": "offline", "vt": False, "urlscan": False}

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

    live = state_info.get("mode") == "live"
    dot = "<span class='pc-dot on'></span>" if live else "<span class='pc-dot'></span>"
    mode_word = "LIVE" if live else "OFFLINE"
    st.markdown(
        f"""
<div class='pc-int-card'>
 <div class='pc-int-mode'>{dot}{mode_word}</div>
 <div class='pc-int-row'>
  <span class='pc-int-name'>VirusTotal</span>
  <span class='pc-pill {"ok" if state_info["vt"] else ""}'>
   {"key configured" if state_info["vt"] else "no key"}</span>
 </div>
 <div class='pc-int-row'>
  <span class='pc-int-name'>urlscan.io</span>
  <span class='pc-pill {"ok" if state_info["urlscan"] else ""}'>
   {"key configured" if state_info["urlscan"] else "no key"}</span>
 </div>
 <div class='pc-int-note'>Link lookups are read-only: the tool checks
 what scanners already know about a link and never submits your email's
 links for new scans, so a scammer's site gets no alert that it's being
 investigated. Keys live in <b>.env</b> locally or <b>Secrets</b> when
 hosted.</div>
</div>""",
        unsafe_allow_html=True,
    )


def main() -> None:
    try:
        _main()
    except Exception as exc:  # crash page + telemetry; never a bare stack
        observability.capture_exception(exc, surface="dashboard")
        st.error(
            "Something broke while building this page. The error has been logged."
            if observability.enabled()
            else "Something broke while building this page."
        )
        raise


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json",
        default=str(_ROOT / "samples" / "demo_batch" / "results.json"),
        help="batch results JSON from the phishingclassifier CLI",
    )
    args, _ = parser.parse_known_args()

    st.markdown(CSS, unsafe_allow_html=True)

    # ---- hero band: the above-the-fold moment -----------------------------
    hero_html = """
<div class="pc-hero pc-rise">
 <div style="min-width:0;flex:1 1 420px">
  <p class="pc-lead">Phishing email investigation</p>
  <h1 class="pc-title">Phishing Classifier</h1>
  <p class="pc-tag">Paste in a suspicious email and see why it looks
  phishy — the rule check explains every point it scores, the ML model
  gives a second opinion, and any links or sender addresses it finds are
  listed as plain text.</p>
  <div class="pc-chips">
   <span class="pc-chip"><b>20+</b> explained signals</span>
   <span class="pc-chip"><b>ML</b> second opinion</span>
   <span class="pc-chip"><b>VirusTotal / urlscan</b> link lookups</span>
   <span class="pc-chip">analyzed on the server, nothing stored</span>
  </div>
 </div>
 <div class="pc-stat-strip">
  <div class="pc-stat"><div class="pc-stat-n">42<span style="font-size:16px">%</span></div>
   <div class="pc-stat-l">F1 on unseen corpora*</div></div>
  <div class="pc-stat"><div class="pc-stat-n">10k</div>
   <div class="pc-stat-l">emails trained on</div></div>
  <div class="pc-stat"><div class="pc-stat-n">95<span style="font-size:16px">%</span></div>
   <div class="pc-stat-l">F1 on advance-fee scams it knows</div></div>
 </div>
</div>
<div class="pc-stat-foot">* Leave-one-corpus-out average — each corpus was
scored by a model that never saw it. That is the real generalization
number; the 96% figure holds only inside the training corpora. The rule
engine, not the ML layer, is the primary verdict — see the README for the
full per-corpus breakdown and known blind spots.</div>
"""
    st.markdown(hero_html, unsafe_allow_html=True)
    st.caption(
        "Scores are decision support, not proof. Treat every link "
        "in a suspicious email as live: don't click, don't scan."
    )

    tab_demo, tab_paste, tab_upload, tab_batch = st.tabs(
        ["Try the demo", "Paste an email", "Upload files", "Earlier results"]
    )

    # sidebar is global: integrations render exactly once, not per-tab
    with st.sidebar:
        _sidebar_integrations()

    with tab_demo:
        st.markdown(
            "<div class='pc-dropzone'>New here? Start with three sample "
            "emails — a fake PayPal notice, a fake invoice with a "
            "credential-stealing link, and a real GitHub notification for "
            "comparison. You'll see how each one gets picked apart.</div>",
            unsafe_allow_html=True,
        )
        fixtures = _ROOT / "tests" / "fixtures"
        demo_results = []
        for name in DEMO_EMAILS:
            path = fixtures / name
            if not path.is_file():
                st.warning(f"Demo fixture missing: {path}")
                continue
            demo_results.append(_analyze_bytes(path.read_bytes(), source=name))
        if demo_results:
            st.caption(" · ".join(f"`{n}` {d}" for n, d in DEMO_EMAILS.items()))
            _render_cases(demo_results, export_key="demo")

    with tab_paste:
        st.markdown(
            "<div class='pc-dropzone'>Have a suspicious email in your "
            "inbox? In Gmail or Outlook, open it, choose <b>show "
            "original</b>, copy everything, and paste it here. The full "
            "raw email — headers included — gives the most accurate "
            "results.</div>",
            unsafe_allow_html=True,
        )
        pasted = st.text_area(
            "Raw email",
            height=240,
            placeholder=(
                'From: "PayPal Support" <security@paypa1-alerts.com>\n'
                "Subject: URGENT: verify your account\n"
                "...\n\nDear Customer, click here to verify..."
            ),
        )
        if st.button("Analyze pasted email", type="primary"):
            if not pasted.strip():
                st.error("Paste an email first — nothing to analyze.")
            elif len(pasted.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
                st.error(
                    f"That email is larger than the "
                    f"{MAX_INPUT_BYTES // (1024 * 1024)} MiB limit. "
                    "Trim it or analyze the file with the command-line tool."
                )
            else:
                _render_cases(
                    _analyze_many([(pasted.encode("utf-8", errors="replace"), "(pasted email)")]),
                    export_key="paste",
                )

    with tab_upload:
        st.markdown(
            "<div class='pc-dropzone'>Saved the email as a file? Drop "
            ".eml files here — they're read in memory, analyzed, and "
            "thrown away. Nothing is kept after you close the page.</div>",
            unsafe_allow_html=True,
        )
        uploads = st.file_uploader(
            "Upload .eml file(s)",
            type=["eml", "txt"],
            accept_multiple_files=True,
        )
        if uploads:
            oversized = [up.name for up in uploads if up.size > MAX_INPUT_BYTES]
            for name in oversized:
                st.warning(
                    f"Skipped {name}: larger than the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit."
                )
            accepted = [up for up in uploads if up.size <= MAX_INPUT_BYTES]
            if accepted:
                _render_cases(
                    _analyze_many([(up.getvalue(), up.name) for up in accepted]),
                    export_key="upload",
                )

    with tab_batch:
        st.markdown(
            "<div class='pc-dropzone'>Ran the command-line tool on a "
            "folder of emails? That analysis is saved as a results file. "
            "This tab loads it so you can browse and filter what was "
            "already analyzed — handy for going through a whole inbox at "
            "once.</div>",
            unsafe_allow_html=True,
        )
        try:
            batch_results = _load_results(args.json)
        except FileNotFoundError:
            st.info(
                f"No results file found at `{_esc(Path(args.json).name)}`.\n\n"
                "Run the CLI first: `python -m phishingclassifier.cli "
                "analyze <folder> --json results.json`, then point this "
                "tab at the file with `--json` when starting the app. A "
                "sample results file ships with the project at "
                "`samples/demo_batch/results.json`."
            )
        except json.JSONDecodeError:
            st.error("The results file isn't valid JSON — re-run the analysis that produced it.")
        else:
            c1, c2, c3 = st.columns([2, 2, 2])
            with c1:
                verdicts = st.multiselect(
                    "Verdict", VERDICT_ORDER, default=VERDICT_ORDER, key="batch_verdicts"
                )
            with c2:
                score_lo, score_hi = st.slider("Score range", 0, 100, (0, 100), key="batch_score")
            with c3:
                search = st.text_input(
                    "Subject/sender contains",
                    key="batch_search",
                ).lower()

            def _keep(r) -> bool:
                if r["score"]["verdict"] not in verdicts:
                    return False
                if not (score_lo <= r["score"]["score"] <= score_hi):
                    return False
                if (
                    search
                    and search not in (r.get("subject", "") + " " + r.get("from", "")).lower()
                ):
                    return False
                return True

            kept = [r for r in batch_results if _keep(r)]
            st.caption(f"Showing {len(kept)} of {len(batch_results)} email(s)")
            _render_cases(kept, export_key="batch")


if __name__ == "__main__":
    main()
