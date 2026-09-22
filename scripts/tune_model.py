"""Long-running ML tuner: honest group-CV search + FP-aware threshold.

Why this exists
---------------
The stock ``cli train`` path hardcodes HistGradientBoosting defaults and
scores itself with in-corpus StratifiedKFold, which is optimistic (the
README's 0.96 CV vs 0.42 leave-one-corpus-out gap is exactly this).  To
spend hours productively we need to (1) optimise the *honest* metric,
(2) explore a real hyperparameter space, and (3) choose the decision
threshold deliberately to trade false positives against recall.

This script does all three and is safe to leave running unattended:

* **Grouped CV by source** (``StratifiedGroupKFold``) so a fold is always
  scored by a model that never saw that corpus -- the search optimises the
  number we actually care about (generalisation), not memorisation.
* **Randomised search with a wall-clock budget and checkpoints.** Each
  sampled config is evaluated once; results append to a JSON checkpoint so
  re-running skips configs already tried.  Ctrl-C or a power blip costs
  nothing already done.  ``--max-seconds`` bounds the whole run.
* **Threshold selection from out-of-fold probabilities**, choosing the
  cut-off that maximises F1 while holding precision at/above
  ``--min-precision`` (this is where false positives get squeezed).
* **Drop-in artefact.** The saved bundle matches ``ml.load_model`` /
  ``ml.classify`` exactly (``vec``/``tfidf``/``clf``/``kind``) and adds
  ``threshold``, which those functions now honour.
* **Auto-discovers corpora.** Every ``*.csv`` in ``samples/`` is trained on
  except a small exclude set (the blended superset / hand sample). Drop a new
  labelled corpus into ``samples/`` and the next run folds it into the
  group-CV with no code edit; the checkpoint's data signature then forces a
  fresh search since old cached F1 scores no longer apply.

Hardware note: HistGradientBoosting is a CPU (OpenMP) learner -- the GPU
is unused here. The search loop is SERIAL (no sklearn n_jobs fan-out), so
let one HistGradientBoosting fit span every logical core: on a 14c/20t chip
set ``OMP_NUM_THREADS`` to ~18. Setting it low (e.g. 4) leaves most cores
idle and makes each config several times slower. Individual configs vary
widely in cost -- the slowest are the high ``max_iter`` x big-leaf draws.

Usage (see README "Training the model"):

    $env:PYTHONPATH = (Get-Location).Path
    $env:OMP_NUM_THREADS = "18"
    py -3 scripts/tune_model.py --per-class 15000 --max-seconds 21600
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from pathlib import Path

# Corpora always excluded from honest group-CV training: the blended Kaggle
# superset (phishing_email.csv) overlaps the per-source files and would leak
# train into eval, and the tiny hand sample (labeled_sample.csv) adds nothing.
EXCLUDE_FROM_TRAIN = {"phishing_email.csv", "labeled_sample.csv"}


def discover_sources(samples_dir: Path, exclude=EXCLUDE_FROM_TRAIN):
    """Every labelled corpus CSV in the samples dir, minus the excluded set.

    Drop a new subject/body/label CSV into ``samples/`` and it is picked up
    automatically with no code change. Add its name to EXCLUDE_FROM_TRAIN if
    it overlaps files already present (a blended superset), to keep the
    group-CV honest."""
    return sorted(p.name for p in Path(samples_dir).glob("*.csv") if p.name not in exclude)


def _sample_params(rng: random.Random) -> dict:
    """Draw one HistGradientBoosting config from the search space.

    Ranges bias toward regularisation (small leaves, high min_samples,
    l2, subsampling) because the failure mode we are fixing is
    overfitting to corpus-specific style, not underfitting.
    """
    return {
        "learning_rate": rng.choice([0.03, 0.05, 0.08, 0.12]),
        "max_iter": rng.choice([200, 300, 400, 600, 800]),
        "max_leaf_nodes": rng.choice([15, 31, 63]),
        "min_samples_leaf": rng.choice([10, 20, 40, 80]),
        "l2_regularization": rng.choice([0.0, 0.1, 1.0, 5.0]),
        "max_features": rng.choice([0.6, 0.7, 0.85, 1.0]),
        "early_stopping": True,
        "random_state": 42,
    }


def _build_matrix(rows, max_features: int, min_df: int):
    """Featurise identically to production (ml._featurize/_text_for_tfidf),
    then densify to float32. HistGradientBoosting in this sklearn build
    rejects sparse X (see ml.DENSE_MAX_ROWS), so we cannot dodge the dense
    cost -- but float32 halves it versus the stock float64 path, letting a
    wider TF-IDF space and more rows fit in 16 GB RAM."""
    import numpy as np
    import scipy.sparse as sp
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.feature_extraction.text import TfidfVectorizer

    from phishingclassifier.heuristics import analyze_signals
    from phishingclassifier.ml import _featurize, _text_for_tfidf

    feats, texts, y, groups = [], [], [], []
    for r in rows:
        parsed = r["parsed"]
        analysis = analyze_signals(parsed)
        feats.append(_featurize(parsed, analysis["signals"], analysis["iocs"]))
        texts.append(_text_for_tfidf(parsed))
        y.append(int(r["label"]))
        # source is like "Enron.csv#row123" -> group is the file stem
        groups.append(str(r["source"]).split("#")[0])
    vec = DictVectorizer(sparse=True)
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=max_features,
        sublinear_tf=True,
        strip_accents="unicode",
        min_df=min_df,
        lowercase=True,
    )
    F = vec.fit_transform(feats)
    T = tfidf.fit_transform(texts)
    X = sp.hstack([F, T]).tocsr()
    Xd = X.toarray().astype(np.float32, copy=False)
    return Xd, y, groups, vec, tfidf


def _grouped_cv_f1(X, y, groups, params, n_splits: int) -> float:
    """Honest f1_macro: mean over source-disjoint stratified folds."""
    import numpy as np
    import scipy.sparse as sp
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.metrics import f1_score

    if sp.issparse(X):
        X = X.toarray().astype(np.float32)
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = []
    for tr, te in sgkf.split(X, y, groups):
        clf = HistGradientBoostingClassifier(**params)
        clf.fit(X[tr], np.asarray(y)[tr])
        pred = clf.predict(X[te])
        scores.append(f1_score(np.asarray(y)[te], pred, average="macro"))
    return float(np.mean(scores))


def _tune_threshold(X, y, groups, params, n_splits: int, min_precision: float):
    """Out-of-fold probabilities -> pick a threshold that maximises F1
    subject to precision >= min_precision (this is the FP control)."""
    import numpy as np
    import scipy.sparse as sp
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.metrics import precision_score, recall_score, f1_score

    if sp.issparse(X):
        X = X.toarray().astype(np.float32)
    y_arr = np.asarray(y)
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
    oof = np.zeros(len(y_arr), dtype=float)
    for tr, te in sgkf.split(X, y, groups):
        clf = HistGradientBoostingClassifier(**params)
        clf.fit(X[tr], y_arr[tr])
        proba = clf.predict_proba(X[te])
        idx = list(clf.classes_).index(1)
        oof[te] = proba[:, idx]
    grid = np.round(np.arange(0.05, 0.951, 0.01), 2)
    best = (0.5, -1.0)
    fallback = (0.5, -1.0)
    for thr in grid:
        pred = (oof >= thr).astype(int)
        p = precision_score(y_arr, pred, zero_division=0)
        f = f1_score(y_arr, pred, zero_division=0)
        if f > fallback[1]:
            fallback = (float(thr), float(f))
        if p >= min_precision and f > best[1]:
            best = (float(thr), float(f))
    thr = best[0] if best[1] >= 0 else fallback[0]
    pred = (oof >= thr).astype(int)
    return thr, {
        "precision": round(float(precision_score(y_arr, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_arr, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_arr, pred, zero_division=0)), 4),
        "false_positive_rate": round(float((pred[y_arr == 0] == 1).mean()), 4),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Honest group-CV tuner for the ML second opinion")
    ap.add_argument("--per-class", type=int, default=15000, help="balanced rows per class")
    ap.add_argument("--n-iter", type=int, default=60, help="max random configs to try")
    ap.add_argument("--max-seconds", type=int, default=6 * 3600, help="wall-clock budget")
    ap.add_argument("--splits", type=int, default=6, help="StratifiedGroupKFold splits")
    ap.add_argument("--max-features", type=int, default=8000, help="TF-IDF vocab ceiling")
    ap.add_argument("--min-df", type=int, default=3, help="TF-IDF min documents")
    ap.add_argument("--min-precision", type=float, default=0.90, help="FP-control floor")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="models/phish_model_tuned.joblib", help="model path")
    ap.add_argument("--report", default="reports/output/tune_report.json")
    ap.add_argument("--checkpoint", default="reports/output/tune_checkpoint.json")
    ap.add_argument(
        "--deploy", action="store_true", help="also overwrite models/phish_model.joblib"
    )
    args = ap.parse_args()

    import joblib
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier

    from phishingclassifier.csv_adapter import load_combined_dataset
    from phishingclassifier.ml import MODEL_FILE

    t0 = time.monotonic()
    rng = random.Random(args.seed)
    root = Path(__file__).resolve().parent.parent
    samples = root / "samples"

    sources = discover_sources(samples)
    if not sources:
        print(f"No corpus CSVs found in {samples}", file=sys.stderr)
        return 2
    print(f"Training corpora (auto-discovered): {', '.join(sources)}")

    # The checkpoint is namespaced by a data signature: a cached F1 is only
    # valid for the exact corpus + featurisation it was computed on, so
    # dropping in new CSVs correctly invalidates a stale resume.
    data_sig = hashlib.sha256(
        json.dumps(
            {
                "sources": sorted(sources),
                "per_class": args.per_class,
                "max_features": args.max_features,
                "min_df": args.min_df,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()[:12]
    cp_path = Path(args.checkpoint)
    cp_path.parent.mkdir(parents=True, exist_ok=True)
    done: dict[str, float] = {}
    if cp_path.exists():
        try:
            loaded = json.loads(cp_path.read_text(encoding="utf-8"))
            if loaded.get("sig") == data_sig and isinstance(loaded.get("results"), dict):
                done = loaded["results"]
                print(f"resuming: {len(done)} configs already evaluated (corpus unchanged)")
            else:
                print("checkpoint is for a different corpus/config -- starting fresh")
        except Exception:
            done = {}

    print(f"Loading combined corpus (per-class={args.per_class})...")
    rows = load_combined_dataset(str(samples), per_class=args.per_class, files=sources)
    n_phish = sum(1 for r in rows if r["label"] == 1)
    print(
        f"  {len(rows)} rows ({n_phish} phish / {len(rows) - n_phish} legit) "
        f"in {time.monotonic() - t0:.0f}s"
    )

    print(f"Featurising (max_features={args.max_features}, min_df={args.min_df})...")
    X, y, groups, vec, tfidf = _build_matrix(rows, args.max_features, args.min_df)
    # StratifiedGroupKFold needs at least one held-out group per split.
    n_groups = len(set(groups))
    n_splits = max(2, min(args.splits, n_groups))
    print(
        f"  matrix {X.shape[0]} x {X.shape[1]} dense float32 (~{X.nbytes / 1e9:.1f} GB) "
        f"across {n_groups} sources, {n_splits}-fold group-CV "
        f"in {time.monotonic() - t0:.0f}s"
    )

    # ---- randomised search over honest group-CV F1 -----------------------
    best_cfg, best_f1 = None, -1.0
    tried = len(done)
    for i in range(args.n_iter):
        if time.monotonic() - t0 > args.max_seconds:
            print(f"[budget] {args.max_seconds}s elapsed, stopping search.")
            break
        params = _sample_params(rng)
        key = json.dumps(params, sort_keys=True)
        if key in done:
            continue
        tried += 1
        f1 = _grouped_cv_f1(X, y, groups, params, n_splits)
        done[key] = f1
        cp_path.write_text(
            json.dumps({"sig": data_sig, "results": done}, indent=2), encoding="utf-8"
        )
        mark = ""
        if f1 > best_f1:
            best_f1, best_cfg = f1, params
            mark = "  <- best"
        print(
            f"  [{tried:>3}] groupCV f1={f1:.4f}{mark}  "
            f"(lr={params['learning_rate']} it={params['max_iter']} "
            f"leaf={params['max_leaf_nodes']} msl={params['min_samples_leaf']} "
            f"l2={params['l2_regularization']} mf={params['max_features']}) "
            f"[{time.monotonic() - t0:.0f}s]{mark}"
        )

    if best_cfg is None:
        # resumed run where all sampled configs were already cached: rebuild
        # the best from the checkpoint keys.
        best_key = max(done, key=lambda k: done[k])
        best_cfg = json.loads(best_key)
        best_f1 = done[best_key]

    print(f"\nBest config group-CV F1 = {best_f1:.4f}: {best_cfg}")

    # ---- threshold selection on out-of-fold probabilities ----------------
    print("Tuning decision threshold (FP control)...")
    thr, thr_metrics = _tune_threshold(X, y, groups, best_cfg, n_splits, args.min_precision)
    print(f"  threshold={thr:.2f} -> {thr_metrics}")

    # ---- final fit on ALL rows, save drop-in bundle ----------------------
    print("Fitting final model on the full corpus...")
    clf = HistGradientBoostingClassifier(**best_cfg)
    clf.fit(X, np.asarray(y))
    bundle = {
        "vec": vec,
        "tfidf": tfidf,
        "clf": clf,
        "kind": "ml-gbdt-tuned",
        "threshold": thr,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    print(f"[+] tuned model: {out_path}")
    if args.deploy:
        joblib.dump(bundle, MODEL_FILE)
        print(f"[+] deployed over {MODEL_FILE}")

    report = {
        "rows": len(rows),
        "features": int(X.shape[1]),
        "sources": sources,
        "splits": n_splits,
        "configs_tried": len(done),
        "best_params": best_cfg,
        "best_group_cv_f1": round(best_f1, 4),
        "threshold": thr,
        "threshold_metrics": thr_metrics,
        "elapsed_s": round(time.monotonic() - t0, 1),
    }
    rp = Path(args.report)
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] report: {rp}")
    print(f"total {time.monotonic() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
