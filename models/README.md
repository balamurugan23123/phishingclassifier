# Models

`phish_model.joblib` is the production ML second-opinion model.

- Trained by: `py -m phishingclassifier.cli train <dir> --per-class 5000`
- Trained on: the combined public Kaggle corpus (7 datasets, 10,000
  balanced rows)
- Last training metrics: 5-fold CV F1 0.961 (macro), train accuracy 0.996
- Loaded by `phishingclassifier.ml.classify()`; when absent, analysis
  runs rule-only and the ML probability column simply doesn't render.

Retraining overwrites this file — commit the new artifact with updated
metrics in this README.
