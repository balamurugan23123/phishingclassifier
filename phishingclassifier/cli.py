"""Command-line interface for phishing classifier."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from .enrich import EnrichmentState, enrich_result
from .heuristics import analyze_signals
from .parser import parse_eml
from .report import batch_json, build_result, write_html, write_markdown


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="phishingclassifier",
        description="Phishing email investigation tool: parse, extract IOCs, score, and report.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze one .eml file or a folder")
    analyze.add_argument("target", help=".eml file or folder of .eml files")
    analyze.add_argument("--offline", action="store_true",
                         help="Skip live threat-intel enrichment")
    analyze.add_argument("--json", dest="json_out", metavar="PATH",
                         help="Write batch results JSON to this path")
    analyze.add_argument("--md-dir", metavar="DIR", default="reports/output",
                         help="Directory for per-email Markdown reports")
    analyze.add_argument("--html", dest="html_out", metavar="PATH",
                         help="Write batch HTML summary to this path")

    stats = sub.add_parser("stats", help="Detection stats vs labeled folders")
    stats.add_argument("phish_dir", help="Folder of known-phish .eml files")
    stats.add_argument("ham_dir", help="Folder of benign .eml files")

    validate = sub.add_parser(
        "validate", help="Validate heuristics against a labeled CSV dataset")
    validate.add_argument("csv_path", help="Labeled CSV file")
    validate.add_argument("--max-rows", type=int, default=0,
                          help="Only use first N rows (0 = all)")
    validate.add_argument("--show-misses", action="store_true",
                          help="Print misclassified rows")
    validate.add_argument("--json", dest="json_out", metavar="PATH",
                          help="Write validation stats JSON to this path")

    train = sub.add_parser(
        "train", help="Train the ML classifier on a labeled CSV dataset")
    train.add_argument("csv_path", help="Labeled CSV (sender,subject,body,label)")
    train.add_argument("--json", dest="json_out", metavar="PATH",
                       help="Write training metrics JSON to this path")

    return ap


def _collect_eml_paths(target: str) -> List[Path]:
    p = Path(target)
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(q for q in p.glob("*.eml"))
    return []


def _print_summary(result) -> None:
    score = result["score"]
    print(f"\n=== {result['file']} ===")
    print(f"Subject:  {result['subject']!r}")
    print(f"From:    {result['from']}")
    print(f"Score:   {score['score']}/100 -> {score['verdict']}")
    ml = result.get("ml")
    if ml:
        pct = ml["probability_phishing"] * 100
        print(f"ML:      {pct:.1f}% phishing probability (gradient boosting)")
    if score["signal_count"]:
        print(f"Signals: {score['signal_count']}")
        for s in score["top_signals"]:
            print(f"  [{s['weight']:>2}] {s['id']}")
    if result["parser_warnings"]:
        print(f"Warnings: {len(result['parser_warnings'])}")
    if result["origin_ip"]:
        print(f"Origin IP: {result['origin_ip']}")
    enrich = result.get("enrichment") or {}
    print(f"Enrichment: {enrich.get('mode', 'offline')}"
          + (f" ({len(enrich.get('lookups', []))} lookups)"
             if enrich.get("lookups") else ""))


def _enrichment_feedback_signals(result, enrichment: dict) -> list:
    """Convert threat-intel verdicts into scoring signals."""
    from .heuristics import W_HIGH, W_MEDHIGH, _signal

    sigs = []
    for lk in (enrichment or {}).get("lookups", []):
        source = lk.get("source", "")
        ioc = lk.get("ioc", "")
        if source == "virustotal":
            try:
                mal = int(lk.get("malicious") or 0)
            except (TypeError, ValueError):
                mal = 0
            if mal >= 3:
                sigs.append(_signal(
                    "vt_malicious_verdict", W_HIGH,
                    f"VirusTotal: {mal} engine(s) flag this IOC as malicious",
                    f"ioc={ioc} malicious={mal}",
                ))
        elif source == "urlscan":
            verdicts = lk.get("verdicts_seen") or []
            if any(v and v != "benign" and v not in ("unrated",)
                   for v in verdicts if isinstance(v, str)):
                sigs.append(_signal(
                    "urlscan_malicious_verdict", W_MEDHIGH,
                    "urlscan.io community verdict on existing scans: "
                    f"{', '.join(v for v in verdicts if v)}",
                    f"ioc={ioc} verdicts={verdicts}",
                ))
    return sigs


def cmd_analyze(args: argparse.Namespace) -> int:
    paths = _collect_eml_paths(args.target)
    if not paths:
        print(f"No .eml files found at: {args.target}", file=sys.stderr)
        return 2

    state = EnrichmentState(offline=args.offline)
    results = []
    md_written = []

    for path in paths:
        try:
            parsed = parse_eml(str(path))
            analysis = analyze_signals(parsed)
            result = build_result(parsed, analysis)
        except Exception as exc:
            print(f"[!] Failed {path.name}: {exc}", file=sys.stderr)
            continue
        result["enrichment"] = enrich_result(result, state)
        if result["enrichment"].get("mode") == "live":
            from .scoring import score_result
            extra = _enrichment_feedback_signals(result, result["enrichment"])
            if extra:
                result["signals"] = result["signals"] + extra
                result["score"] = score_result(result["signals"])
        _print_summary(result)
        results.append(result)
        md_written.append(write_markdown(result, args.md_dir))

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(batch_json(results), encoding="utf-8")
        print(f"\n[+] Batch JSON: {args.json_out}")

    if args.html_out:
        print(f"[+] HTML: {write_html(results, args.html_out)}")

    if md_written:
        print(f"[+] Markdown reports: {args.md_dir} ({len(md_written)} files)")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    def _score_folder(folder: str) -> List[int]:
        scores = []
        for path in _collect_eml_paths(folder):
            try:
                parsed = parse_eml(str(path))
                analysis = analyze_signals(parsed)
                result = build_result(parsed, analysis)
                scores.append(result["score"]["score"])
            except Exception as exc:
                print(f"[!] skip {path.name}: {exc}", file=sys.stderr)
        return scores

    p_scores = _score_folder(args.phish_dir)
    h_scores = _score_folder(args.ham_dir)

    tp = sum(1 for s in p_scores if s >= 50)
    fn = len(p_scores) - tp
    fp = sum(1 for s in h_scores if s >= 50)
    tn = len(h_scores) - fp

    print("\n=== Detection Performance (threshold = 50) ===")
    print(f"Phish samples: {len(p_scores):>4}  |  Ham samples: {len(h_scores):>4}")
    print(f"TP: {tp:>3}   FP: {fp:>3}")
    print(f"FN: {fn:>3}   TN: {tn:>3}")
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    print(f"Precision: {precision:.3f}   Recall: {recall:.3f}   F1: {f1:.3f}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    import json as json_mod

    from .csv_adapter import load_csv_dataset
    from .scoring import verdict_for

    dataset = load_csv_dataset(args.csv_path)
    if args.max_rows and args.max_rows > 0:
        dataset = dataset[:args.max_rows]

    labeled = [d for d in dataset if d["label"] is not None]
    if not labeled:
        print(f"No labeled rows found in: {args.csv_path}", file=sys.stderr)
        return 2

    tp = fp = tn = fn = 0
    misses: List[dict] = []
    threshold = 50

    for item in labeled:
        parsed = item["parsed"]
        label = item["label"]
        analysis = analyze_signals(parsed)
        result = build_result(parsed, analysis)
        score = result["score"]["score"]
        pred = 1 if score >= threshold else 0

        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 0:
            tn += 1
        elif label == 0 and pred == 1:
            fp += 1
            misses.append({
                "source": item["source"], "type": "false_positive",
                "score": score, "verdict": verdict_for(score),
                "subject": parsed.subject, "from": parsed.from_addr,
                "signals": [s["id"] for s in result["signals"]],
            })
        else:
            fn += 1
            misses.append({
                "source": item["source"], "type": "false_negative",
                "score": score, "verdict": verdict_for(score),
                "subject": parsed.subject, "from": parsed.from_addr,
                "signals": [s["id"] for s in result["signals"]],
            })

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"\n=== Dataset Validation: {args.csv_path} ===")
    print(f"Rows evaluated: {total} (from {len(dataset)} total)")
    print(f"Threshold: score >= {threshold} -> Phishing")
    print(f"TP: {tp:>4}   FP: {fp:>4}")
    print(f"FN: {fn:>4}   TN: {tn:>4}")
    print(f"Accuracy:  {accuracy * 100:.1f}%")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")

    if args.show_misses and misses:
        print(f"\n--- Misclassified Rows ({len(misses)}) ---")
        for m in misses:
            print(f"[{m['type'].upper()}] {m['source']} score={m['score']} ({m['verdict']})")
            print(f"  From:    {m['from']}")
            print(f"  Subject: {m['subject']!r}")
            print(f"  Signals: {', '.join(m['signals']) if m['signals'] else '(none)'}")

    if args.json_out:
        out = {
            "dataset": str(args.csv_path),
            "rows_evaluated": total,
            "threshold": threshold,
            "true_positives": tp, "false_positives": fp,
            "true_negatives": tn, "false_negatives": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "misses": misses,
        }
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json_mod.dumps(out, indent=2), encoding="utf-8")
        print(f"\n[+] Validation stats JSON: {args.json_out}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    """Train the ML classifier on a labeled CSV dataset."""
    import json as json_mod

    from .csv_adapter import load_csv_dataset
    from .ml import model_path, train_from_rows

    dataset = load_csv_dataset(args.csv_path)
    labeled = [d for d in dataset if d["label"] is not None]
    print(f"Rows loaded: {len(dataset)} "
          f"({len(dataset) - len(labeled)} skipped: no label)")
    if not labeled:
        print("No labeled rows found.", file=sys.stderr)
        return 2

    try:
        metrics = train_from_rows(labeled)
    except ValueError as exc:
        print(f"Cannot train: {exc}", file=sys.stderr)
        return 2

    print(f"Trained classifier on {metrics['rows']} rows")
    print(f"5-fold CV F1 (macro): {metrics['cv_f1_macro_mean']:.3f} "
          f"(+/- {metrics['cv_f1_macro_std']:.3f})")
    print(f"Train accuracy:       {metrics['train_accuracy']:.3f}")
    print(f"Model saved: {model_path()}")

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json_mod.dumps(metrics, indent=2), encoding="utf-8")
        print(f"[+] Training metrics JSON: {args.json_out}")
    return 0


def main(argv=None) -> int:
    args = _build_arg_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "stats":
        return cmd_stats(args)
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "train":
        return cmd_train(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
