"""Leave-one-source-out validation of the deployed ML pipeline.

For each Kaggle source S:
  1. Train a fresh model on the combined corpus EXCLUDING S.
  2. Evaluate that model on S (never seen during training).
  3. Report per-source real-world accuracy.

This is the honest generalization estimate — each source is scored by a
model that never saw it. Writes reports/output/holdout_report.json.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishingclassifier.csv_adapter import (
    iter_csv_rows, row_label, row_to_parsed,
)
from phishingclassifier.ml import train_from_rows

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
SOURCES = [
    "CEAS_08.csv", "Enron.csv", "Ling.csv", "Nazario.csv",
    "Nigerian_Fraud.csv", "SpamAssasin.csv",
]
# phishing_email.csv is a blended superset of the others — excluded from
# the leave-one-out set to avoid trivially overlapping train/eval.

PER_CLASS = 5000


def load_source(name: str, cap: int = 3000):
    """Load up to cap labeled rows from one CSV (balanced if needed)."""
    out = []
    for i, row in enumerate(iter_csv_rows(str(SAMPLES / name))):
        label = row_label(row)
        if label is None:
            continue
        body = (row.get("body") or row.get("text_combined") or "").strip()
        if not body or len(body) > 20000:
            continue
        out.append({
            "row": row,
            "parsed": row_to_parsed(row, source=f"{name}#row{i+1}"),
            "label": label,
            "source": f"{name}#row{i+1}",
        })
        if len(out) >= cap:
            break
    return out


def main() -> None:
    t0 = time.monotonic()
    report = {}
    for held_out in SOURCES:
        print(f"\n=== holdout: {held_out} " + "=" * 40)
        exclude = {held_out, "phishing_email.csv", "labeled_sample.csv"}
        files = [n for n in SOURCES if n not in exclude]
        # build combined training rows manually: load each, cap per class
        phish, legit = [], []
        for n in files:
            rows = load_source(n, cap=4000)
            for r in rows:
                (phish if r["label"] == 1 else legit).append(r)
        take = min(PER_CLASS, len(phish), len(legit))
        import random
        rng = random.Random(42)
        rng.shuffle(phish)
        rng.shuffle(legit)
        train_rows = phish[:take] + legit[:take]
        rng.shuffle(train_rows)
        print(f"train rows: {len(train_rows)} "
              f"(from {len(files)} sources, {held_out} excluded)")
        metrics = train_from_rows(train_rows)
        print(f"  train CV F1: {metrics['cv_f1_macro_mean']:.3f}")

        eval_rows = load_source(held_out, cap=3000)
        # evaluate_on_datasets takes paths; reuse the featurize+predict
        # path by writing rows through the same API used by classify()
        from phishingclassifier.ml import load_model
        import numpy as np
        import scipy.sparse as sp
        from sklearn.metrics import f1_score, precision_score, recall_score
        from phishingclassifier.heuristics import analyze_signals
        from phishingclassifier.ml import _featurize, _text_for_tfidf

        bundle = load_model()
        vec, tfidf, clf = bundle["vec"], bundle["tfidf"], bundle["clf"]
        y, p = [], []
        for r in eval_rows:
            a = analyze_signals(r["parsed"])
            F = vec.transform([_featurize(r["parsed"], a["signals"], a["iocs"])])
            T = tfidf.transform([_text_for_tfidf(r["parsed"])])
            X = sp.hstack([sp.csr_matrix(F), T]).toarray()
            proba = clf.predict_proba(X)[0]
            idx = list(clf.classes_).index(1)
            y.append(r["label"])
            p.append(1 if proba[idx] >= 0.5 else 0)
        y_arr, p_arr = np.array(y), np.array(p)
        s = {
            "eval_rows": len(y),
            "eval_label_split": f"{sum(y)}/{len(y) - sum(y)} phish/legit",
            "accuracy": round(float((p_arr == y_arr).mean()), 4),
            "precision": round(float(precision_score(
                y_arr, p_arr, zero_division=0)), 4),
            "recall": round(float(recall_score(
                y_arr, p_arr, zero_division=0)), 4),
            "f1": round(float(f1_score(y_arr, p_arr, zero_division=0)), 4),
            "train_cv_f1": round(metrics["cv_f1_macro_mean"], 4),
        }
        report[held_out] = s
        print(f"  HELD-OUT {held_out}: acc={s['accuracy']:.1%} "
              f"prec={s['precision']:.1%} rec={s['recall']:.1%} "
              f"f1={s['f1']:.1%} ({s['eval_rows']} rows)")

    Path("reports/output").mkdir(parents=True, exist_ok=True)
    out = Path("reports/output/holdout_report.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[+] report: {out}")
    print(f"total {time.monotonic() - t0:.0f}s")


if __name__ == "__main__":
    main()
