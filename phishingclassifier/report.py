"""Report generation for Markdown, HTML, and JSON."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List

from .scoring import score_result

_VERDICT_EMOJI = {
    "Clean": "[CLEAN]",
    "Suspicious": "[SUSPICIOUS]",
    "Likely Malicious": "[LIKELY MALICIOUS]",
    "Malicious": "[MALICIOUS]",
}


def _md_escape(text: str) -> str:
    """Escape text for safe Markdown rendering."""
    return (
        text.replace("\\", "\\\\")
        .replace("`", "'")
        .replace("[", "(")
        .replace("]", ")")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )


def _kv_line(key: str, value: Any) -> str:
    return f"| {_md_escape(key)} | {_md_escape(str(value))} |"


def build_result(parsed, analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build result dict for an email."""
    result = {
        "file": parsed.source_path,
        "subject": parsed.subject,
        "from": parsed.from_addr,
        "from_display": parsed.from_display,
        "from_domain": parsed.from_domain,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
        "origin_ip": parsed.origin_ip,
        "received_hops": len(parsed.received_chain),
        "auth": {
            "spf": parsed.auth("spf"),
            "dkim": parsed.auth("dkim"),
            "dmarc": parsed.auth("dmarc"),
        },
        "parser_warnings": parsed.warnings,
        "iocs": analysis["iocs"],
        "signals": analysis["signals"],
        "score": score_result(analysis["signals"]),
    }
    try:
        from .ml import classify, model_exists
        if model_exists():
            result["ml"] = classify(
                parsed, analysis["signals"], analysis["iocs"])
    except Exception:
        pass
    return result


def markdown_report(result: Dict[str, Any]) -> str:
    """Render per-email Markdown report."""
    score = result["score"]
    banner = _VERDICT_EMOJI[score["verdict"]]
    lines: List[str] = []
    lines.append(f"# Phishing Classifier Report — {banner}")
    lines.append("")
    lines.append(f"**File:** `{result['file']}`")
    lines.append(f"**Score:** {score['score']}/100 — **{score['verdict']}**"
                  + (" (capped)" if score["capped"] else ""))
    lines.append("")

    lines.append("## Headers of interest")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(_kv_line("Subject", result["subject"]))
    lines.append(_kv_line("From", f"{result['from_display']} <{result['from']}>"))
    if result["reply_to"]:
        lines.append(_kv_line("Reply-To", result["reply_to"]))
    if result["return_path"]:
        lines.append(_kv_line("Return-Path", result["return_path"]))
    lines.append(_kv_line("Origin IP", result["origin_ip"] or "(none)"))
    lines.append(_kv_line("SPF / DKIM / DMARC",
                          f"{result['auth']['spf'] or '-'} / "
                          f"{result['auth']['dkim'] or '-'} / "
                          f"{result['auth']['dmarc'] or '-'}"))
    lines.append("")

    lines.append("## Fired signals (explainable scoring)")
    lines.append("")
    if result["signals"]:
        lines.append("| Weight | Signal | Reason | Evidence |")
        lines.append("|---|---|---|---|")
        for s in sorted(result["signals"], key=lambda x: -x["weight"]):
            lines.append(
                f"| {s['weight']} | {_md_escape(s['id'])} "
                f"| {_md_escape(s['reason'])} "
                f"| {_md_escape(s['evidence'])} |"
            )
    else:
        lines.append("No detection signals fired.")
    lines.append("")

    lines.append("## IOCs")
    lines.append("")
    iocs = result["iocs"]
    lines.append("URLs and infrastructure below are shown as PLAIN TEXT only.")
    lines.append("Never click, copy-paste into a browser, or scan them.")
    lines.append("")
    lines.append("```text")
    if result["origin_ip"]:
        lines.append(f"origin-ip: {result['origin_ip']}")
    for url in iocs["urls"]["header"] + iocs["urls"]["body"]:
        lines.append(f"url: {url}")
    for d in iocs["domains"]["header"] + iocs["domains"]["body"]:
        lines.append(f"domain: {d}")
    for a in iocs["attachment_hashes"]:
        lines.append(f"attachment: {a['filename']} sha256={a['sha256']}")
    if not (iocs["urls"]["header"] or iocs["urls"]["body"]
            or iocs["domains"]["header"] or iocs["domains"]["body"]
            or iocs["attachment_hashes"]):
        lines.append("(none)")
    lines.append("```")
    lines.append("")

    enrichment = result.get("enrichment") or {"mode": "offline", "lookups": []}
    lines.append("## Enrichment")
    lines.append("")
    mode = enrichment.get("mode", "offline")
    if mode == "live":
        lines.append(f"Mode: live ({len(enrichment.get('lookups', []))} lookup(s))")
        lines.append("")
        if enrichment.get("lookups"):
            lines.append("| IOC | Source | Malicious | Reputation | Detail |")
            lines.append("|---|---|---|---|---|")
            for lk in enrichment["lookups"]:
                detail = lk.get("verdicts_seen") or lk.get("total_existing_scans")
                lines.append(
                    f"| {_md_escape(lk.get('ioc', ''))} "
                    f"| {_md_escape(lk.get('source', ''))} "
                    f"| {lk.get('malicious', '')} "
                    f"| {lk.get('reputation', '')} "
                    f"| {_md_escape(str(detail))} |"
                )
        else:
            lines.append("No lookups returned data.")
    else:
        lines.append(f"Skipped ({mode}).")
    if enrichment.get("errors"):
        lines.append("")
        lines.append("Errors:")
        for e in enrichment["errors"]:
            lines.append(f"- {_md_escape(e)}")
    lines.append("")

    if result["parser_warnings"]:
        lines.append("## Parser warnings")
        lines.append("")
        for w in result["parser_warnings"]:
            lines.append(f"- {_md_escape(w)}")
        lines.append("")

    lines.append("---")
    lines.append("Generated by phishing classifier. Scores are heuristic aids, not "
                 "verdicts; always validate with full manual analysis.")
    return "\n".join(lines) + "\n"


def write_markdown(result: Dict[str, Any], out_dir: str) -> str:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = Path(result["file"]).stem + ".md"
    target = out / name
    target.write_text(markdown_report(result), encoding="utf-8")
    return str(target)


def batch_json(results: List[Dict[str, Any]]) -> str:
    import phishingclassifier

    return json.dumps(
        {
            "tool": "phishingclassifier",
            "version": phishingclassifier.__version__,
            "count": len(results),
            "results": sorted(results, key=lambda r: -r["score"]["score"]),
        },
        indent=2,
        ensure_ascii=False,
    )


# inline CSS for report
_CSS = """
body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:24px auto;
padding:0 16px;background:#f6f7f9;color:#1c2430}
h1{font-size:1.5rem} .meta{color:#5a6675;font-size:.9rem}
table{border-collapse:collapse;width:100%;margin:12px 0;background:#fff}
th,td{border:1px solid #d5dbe3;padding:6px 10px;text-align:left;
vertical-align:top;font-size:.88rem}
th{background:#eef1f5}
.v-Clean{background:#e6f4ea;color:#1e6b34;font-weight:600;padding:2px 8px;
border-radius:3px;display:inline-block}
.v-Suspicious{background:#fdf3d7;color:#8a6d00;font-weight:600;padding:2px 8px;
border-radius:3px;display:inline-block}
.v-Likely-Malicious{background:#fde2e0;color:#a11c12;font-weight:600;
padding:2px 8px;border-radius:3px;display:inline-block}
.v-Malicious{background:#a11c12;color:#fff;font-weight:600;padding:2px 8px;
border-radius:3px;display:inline-block}
code,.ioc{font-family:Consolas,monospace;font-size:.82rem;word-break:break-all}
.note{background:#fff8e1;border:1px solid #e6c96b;padding:8px 12px;
border-radius:4px;font-size:.85rem}
details{margin:6px 0} summary{cursor:pointer;font-weight:600;font-size:.9rem}
"""


def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def html_summary(results: List[Dict[str, Any]]) -> str:
    """Render batch HTML summary."""
    import phishingclassifier

    rows: List[str] = []
    for i, r in enumerate(sorted(results, key=lambda x: -x["score"]["score"])):
        score = r["score"]
        verdict_cls = score["verdict"].replace(" ", "-")
        top = "<br>".join(
            f"{_esc(s['id'])} ({s['weight']})" for s in score["top_signals"]
        ) or "&mdash;"
        ioc_lines = []
        if r.get("origin_ip"):
            ioc_lines.append(f"origin-ip: {_esc(r['origin_ip'])}")
        iocs = r.get("iocs") or {}
        for u in iocs.get("urls", {}).get("header", []) + \
                iocs.get("urls", {}).get("body", []):
            ioc_lines.append(f"url: {_esc(u)}")
        for d in iocs.get("domains", {}).get("header", []) + \
                iocs.get("domains", {}).get("body", []):
            ioc_lines.append(f"domain: {_esc(d)}")
        ioc_block = "<br>".join(ioc_lines) or "&mdash;"

        full_signals = "<br>".join(
            f"[{_esc(s['weight'])}] {_esc(s['id'])}: {_esc(s['reason'])}"
            for s in sorted(r["signals"], key=lambda x: -x["weight"])
        ) or "No signals fired."

        enrich = r.get("enrichment") or {"mode": "offline", "lookups": []}
        enrich_text = f"mode: {_esc(enrich.get('mode', 'offline'))}"
        for lk in enrich.get("lookups", []):
            enrich_text += (
                f"<br>{_esc(lk.get('ioc', ''))} [{_esc(lk.get('source', ''))}]"
                f" malicious={_esc(lk.get('malicious', ''))}"
                f" reputation={_esc(lk.get('reputation', ''))}"
            )

        rows.append(f"""
<tr>
  <td>{_esc(Path(r['file']).name)}</td>
  <td>{_esc(r['subject'])}</td>
  <td>{_esc(r['from_display'])} &lt;{_esc(r['from'])}&gt;</td>
  <td>{score['score']}</td>
  <td><span class="v-{verdict_cls}">{_esc(score['verdict'])}</span></td>
  <td><details><summary>Top signals</summary><div>{top}</div></details>
      <details><summary>All signals ({len(r['signals'])})</summary>
        <div>{full_signals}</div></details>
      <details><summary>IOCs (plain text)</summary>
        <div class="ioc">{ioc_block}</div></details>
      <details><summary>Enrichment</summary><div>{enrich_text}</div></details>
  </td>
</tr>""")

    counts = {v: 0 for v in ("Clean", "Suspicious",
                             "Likely Malicious", "Malicious")}
    for r in results:
        counts[r["score"]["verdict"]] = counts.get(r["score"]["verdict"], 0) + 1

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>phishing classifier batch summary</title>
<style>{_CSS}</style></head>
<body>
<h1>Phishing Classifier &mdash; batch summary</h1>
<p class="meta">phishing classifier {_esc(phishingclassifier.__version__)} &middot;
{_esc(len(results))} email(s) &middot;
Clean {_esc(counts.get('Clean', 0))} / Suspicious {_esc(counts.get('Suspicious', 0))}
/ Likely Malicious {_esc(counts.get('Likely Malicious', 0))} /
Malicious {_esc(counts.get('Malicious', 0))}</p>
<p class="note"><strong>Opsec:</strong> this report loads zero remote
resources and renders IOC URLs as plain text only. Never click or scan
anything shown here.</p>
<table>
<tr><th>File</th><th>Subject</th><th>From</th><th>Score</th><th>Verdict</th><th>Details</th></tr>
{''.join(rows)}
</table>
<p class="meta">Scores are heuristic aids, not verdicts. Generated locally by
phishing classifier.</p>
</body></html>"""


def write_html(results: List[Dict[str, Any]], out_path: str) -> str:
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html_summary(results), encoding="utf-8")
    return str(target)
