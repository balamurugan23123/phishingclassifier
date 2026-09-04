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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{
 --ink-0:#0b0f12; --ink-1:#12181d; --ink-2:#1a2228;
 --line:rgba(230,235,238,.10); --line-soft:rgba(230,235,238,.06);
 --txt:#e6ebee; --txt-mut:#8fa1ad; --txt-dim:#5c6b76;
 --acc:#22d3ee; --acc-dim:rgba(34,211,238,.12);
 --bad:#f87171; --warn:#fbbf24; --ok:#4ade80;
 --font-display:'Space Grotesk',sans-serif; --font-mono:'JetBrains Mono',monospace;
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
/* ---- verdict distribution bar ----------------------------------------- */
.pc-distro-bar{display:flex;height:46px;margin:12px 0 4px 0;border-radius:4px;
 overflow:hidden;border:1px solid var(--line)}
.pc-distro-seg{display:flex;align-items:center;padding:0 10px;
 font-size:11px;font-weight:700;color:var(--ink-0);white-space:nowrap}
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
 padding:8px 18px !important;line-height:24px !important}
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
.pc-rail{flex:none;width:86px;border-radius:4px;padding:6px 10px;
 color:var(--ink-0);text-align:center;position:relative;overflow:hidden}
.pc-rail::after{content:'';position:absolute;inset:0;
 background:linear-gradient(120deg,transparent 30%,rgba(11,15,18,.18) 50%,
 transparent 70%);transform:translateX(-100%);
 animation:pc-scan 2.8s cubic-bezier(.4,0,.2,1) infinite}
@keyframes pc-scan{0%{transform:translateX(-100%)}55%,100%{transform:translateX(100%)}}
.pc-rail-score{font-family:var(--font-display);font-size:22px;font-weight:700;
 line-height:1;font-variant-numeric:tabular-nums}
.pc-rail-verdict{font-size:9.5px;font-weight:700;letter-spacing:.06em;
 text-transform:uppercase;margin-top:2px;white-space:nowrap}
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
 color:var(--txt-mut);text-transform:uppercase;margin:10px 0 4px 0}
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
  <p class="pc-tag">Triage bench for suspicious mail — paste a raw email,
  and get rule-based scoring, a machine-learning second opinion, and
  IOC extraction with analyst-safe rendering.</p>
  <div class="pc-chips">
   <span class="pc-chip"><b>20+</b> explainable signals</span>
   <span class="pc-chip"><b>ML</b> second opinion · CV F1 0.96</span>
   <span class="pc-chip"><b>VT / urlscan</b> enrichment</span>
   <span class="pc-chip">runs <b>server-side</b> — nothing stored</span>
  </div>
 </div>
 <div class="pc-stat-strip">
  <div class="pc-stat"><div class="pc-stat-n">96<span style="font-size:16px">%</span></div>
   <div class="pc-stat-l">CV F1 macro</div></div>
  <div class="pc-stat"><div class="pc-stat-n">10k</div>
   <div class="pc-stat-l">training rows</div></div>
  <div class="pc-stat"><div class="pc-stat-n">0</div>
   <div class="pc-stat-l">false positives</div></div>
 </div>
</div>
"""
    st.markdown(hero_html, unsafe_allow_html=True)
    st.caption("Heuristic scores are analyst aids, not verdicts. "
               "IOC URLs render as plain text; never click or scan them.")

    tab_demo, tab_paste, tab_upload, tab_batch = st.tabs(
        ["Prebuilt demo", "Paste raw email", "Upload .eml", "Batch file"])

    # sidebar is global: integrations render exactly once, not per-tab
    with st.sidebar:
        _sidebar_integrations()

    with tab_demo:
        st.markdown(
            "<div class='pc-dropzone'>Bundled fixture emails — "
            "display-name spoof, credential harvester, and a legitimate "
            "notification. Same pipeline as real analysis.</div>",
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
            st.caption(" · ".join(
                f"`{n}` {d}" for n, d in DEMO_EMAILS.items()))
            _render_cases(demo_results)

    with tab_paste:
        st.markdown(
            "<div class='pc-dropzone'>Paste full raw email — headers and "
            "body, as exported by 'Show original'. Parsed in memory, "
            "never stored.</div>",
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
                _render_cases([_analyze_bytes(
                    pasted.encode("utf-8", errors="replace"),
                    source="(pasted email)")])

    with tab_upload:
        uploads = st.file_uploader(
            "Upload .eml file(s)",
            type=["eml", "txt"],
            accept_multiple_files=True,
        )
        if uploads:
            _render_cases([
                _analyze_bytes(up.getvalue(), source=up.name)
                for up in uploads
            ])
        else:
            st.markdown(
                "<div class='pc-dropzone'>Drop .eml files here — analyzed "
                "locally in memory, never stored or sent anywhere.</div>",
                unsafe_allow_html=True,
            )

    with tab_batch:
        try:
            batch_results = _load_results(args.json)
        except FileNotFoundError:
            st.info(
                "No batch results file at "
                f"`{_esc(Path(args.json).name)}`.\n\n"
                "This tab reads the JSON produced by the CLI "
                "(`analyze ... --json`). The committed demo file ships at "
                "`samples/demo_batch/results.json`; point `--json` at it "
                "or your own analysis output."
            )
        except json.JSONDecodeError:
            st.error("Results file is not valid JSON.")
        else:
            c1, c2, c3 = st.columns([2, 2, 2])
            with c1:
                verdicts = st.multiselect("Verdict", VERDICT_ORDER,
                                           default=VERDICT_ORDER,
                                           key="batch_verdicts")
            with c2:
                score_lo, score_hi = st.slider("Score range", 0, 100,
                                               (0, 100), key="batch_score")
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
                if search and search not in (
                    (r.get("subject", "") + " " + r.get("from", ""))
                ).lower():
                    return False
                return True

            kept = [r for r in batch_results if _keep(r)]
            st.caption(f"Showing {len(kept)} of {len(batch_results)} email(s)")
            _render_cases(kept)


if __name__ == "__main__":
    main()
