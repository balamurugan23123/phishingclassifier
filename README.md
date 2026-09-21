# phishing classifier

A phishing email investigation tool: parses raw `.eml` emails, extracts IOCs,
scores phishing risk with explainable heuristics, and produces analyst-ready
Markdown, HTML, and JSON reports — plus a Streamlit analyst dashboard. Also
validates heuristics against labeled CSV datasets.

## Quick start

```bash
# Install the package (editable) + its dependencies and dev tools.
pip install -e .[dev]

# Analyze .eml files (single file or folder). `phishsleuth` is the
# installed console command; `python -m phishingclassifier.cli` is equivalent.
phishsleuth analyze tests/fixtures \
    --json reports/output/results.json --html reports/output/summary.html

# Dashboard (Streamlit)
streamlit run dashboard/app.py -- --json reports/output/results.json

# Validate heuristics against a labeled CSV dataset
phishsleuth validate samples/labeled_sample.csv --show-misses

# Train the ML second-opinion model on a labeled corpus
phishsleuth train samples --per-class 5000

# Score the deployed model on datasets it has NEVER seen
phishsleuth evaluate <holdout1.csv> <holdout2.csv>
```

## Detection heuristics

- Header-based: SPF/DKIM/DMARC fail, Return-Path mismatch, Reply-To mismatch,
  display-name brand spoof, absent Message-ID, future/stale Date, internal origin IP.
- Content/URL-based: IP-literal URLs, punycode hosts, URL shorteners, non-standard
  ports, deep subdomains, lookalike domains, link-text/href mismatch, credential
  harvesting forms, dangerous attachments, passworded archives, base64 blobs,
  urgency language, domain entropy (DGA detection), free-webmail institution
  impersonation, money-scam language, spam/sales language, generic greetings,
  excessive link count, irreversible-payment requests, windfall claims,
  credential-lure phrasing, and composite lure-signal correlation bonus.

## ML model — honest performance numbers

The ML layer is a **second opinion** beside the rule engine, never the
primary verdict. Two numbers matter and they are very different:

- **In-corpus cross-validation: 96% F1** (macro, 5-fold, 10,000 balanced
  rows from six public corpora). This says the model fits the training
  distribution.
- **Leave-one-corpus-out: 42% average F1.** For each public corpus, we
  trained a fresh model on the *other five* and scored the held-out one.
  This is the honest generalization estimate — each corpus was scored by
  a model that never saw it.

Per-corpus held-out results:

| Held-out corpus | F1 | What it means |
|---|---|---|
| Nigerian_Fraud | 95% | advance-fee scams transfer well between corpora |
| Nazario | 69% | same family, slightly different era/style |
| CEAS_08 | 49% | commercial spam is a different beast from 419 |
| Ling spam | 41% | misses most, false-flags some |
| Enron phish | 0% | blind spot — this family never appears in training |
| SpamAssasin ham | 0% | flags nearly all legit mail as phish |

**Read this as:** the TF-IDF model learns corpus-specific vocabulary, not
universal phishing signals. It is genuinely useful on scam families it has
seen (419/advance-fee: 91–95% F1 held out) and untrustworthy on families it
hasn't. The rule engine carries the primary verdict for exactly this
reason — every point it scores is explained on screen.

Reproducing the held-out numbers:

```bash
py scripts/holdout_validation.py          # ~12 min, writes the report JSON
py -m phishingclassifier.cli evaluate ... # score any unseen CSV against
                                          # the deployed model, no retraining
```

**Improving real-world performance** (in order of expected payoff):
1. Diverse training corpora — add 2–3 modern corpora (2020s era BEC,
   credential phishing) so no family is unseen. The 0% rows above are
   missing families, not hard examples.
2. Character n-grams (`analyzer='char_wb'`) in the TF-IDF layer — less
   sensitive to era-specific word choice than word n-grams.
3. Source-aware cross-validation during training (group by corpus) so
   the in-train CV number itself becomes honest, rather than optimistic.

## Labeled dataset validation

CSV adapter (`phishingclassifier/csv_adapter.py`) normalizes labeled dataset
rows into the same `ParsedEmail` shape as the `.eml` parser.

Result on `samples/labeled_sample.csv` (20 handcrafted rows):
**90% accuracy, 1.000 precision, 0.800 recall** (rules only).

## Versions

- `v0.1` parser + CLI skeleton
- `v0.2` IOC extraction + offline detection heuristics
- `v0.3` scoring engine + Markdown/JSON reports + batch mode
- `v0.4` hybrid enrichment + HTML summary + validation stats
- `v0.5` Streamlit analyst dashboard
- `v0.5.1` dashboard redesign
- `v0.5.2` dashboard input modes + dark theme + integrations status
- `v0.6` CSV dataset adapter + labeled validation + DGA entropy detection
- `v0.7` ML second opinion + honest leave-one-corpus-out validation
- `v0.7.1` engineering hardening: editable-install packaging + console script,
  GitHub Actions CI (lint/format/type/test/secret-scan/dep-audit), test suite
  37→100, cache TTL + concurrent enrichment, `logging` diagnostics, DRY +
  input-size caps, dashboard opsec (no remote fonts) + per-file error handling
