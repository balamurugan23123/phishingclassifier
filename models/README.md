# Models

`phish_model.joblib` is the ML second-opinion model.

- Trained by: `py -m phishingclassifier.cli train samples --per-class 5000`
- Trained on: combined public Kaggle corpora (6 datasets, 10,000 balanced rows)
- In-corpus 5-fold CV F1: **0.961** — fits the training distribution well
- Leave-one-corpus-out F1: **0.42 average** (95% on 419-style scams, 0% on
  unseen families) — the honest generalization number; see the project
  README section "ML model — honest performance numbers" for the full
  per-corpus breakdown before trusting this model on unfamiliar mail.
- Loaded by `phishingclassifier.ml.classify()`; when absent, analysis
  runs rule-only and the ML probability simply doesn't render.

Retraining overwrites this file — commit the new artifact and update the
numbers in this README in the same commit.
