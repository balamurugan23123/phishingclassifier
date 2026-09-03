# phishing classifier

A phishing email investigation tool: parses raw `.eml` emails, extracts IOCs,
scores phishing risk with explainable heuristics, and produces analyst-ready
Markdown, HTML, and JSON reports — plus a Streamlit analyst dashboard. Also
validates heuristics against labeled CSV datasets.

## Quick start

```bash
pip install -r requirements.txt -r requirements-dev.txt

# Analyze .eml files (single file or folder)
python -m phishingclassifier.cli analyze tests/fixtures \
    --json reports/output/results.json --html reports/output/summary.html

# Dashboard (Streamlit)
streamlit run dashboard/app.py -- --json reports/output/results.json

# Validate heuristics against a labeled CSV dataset
python -m phishingclassifier.cli validate samples/labeled_sample.csv --show-misses
```

## Detection heuristics

- Header-based: SPF/DKIM/DMARC fail, Return-Path mismatch, Reply-To mismatch,
  display-name brand spoof, absent Message-ID, future/stale Date, internal origin IP.
- Content/URL-based: IP-literal URLs, punycode hosts, URL shorteners, non-standard
  ports, deep subdomains, lookalike domains, link-text/href mismatch, credential
  harvesting forms, dangerous attachments, passworded archives, base64 blobs,
  urgency language, domain entropy (DGA detection), free-webmail institution
  impersonation, money-scam language, spam/sales language, generic greetings,
  excessive link count, and composite lure-signal correlation bonus.

## Labeled dataset validation

CSV adapter (`phishingclassifier/csv_adapter.py`) normalizes labeled dataset
rows into the same `ParsedEmail` shape as the `.eml` parser.

Result on `samples/labeled_sample.csv` (20 rows: 10 phish / 10 legitimate):
**90% accuracy, 1.000 precision (zero false positives), 0.800 recall**.

## Versions

- `v0.1` parser + CLI skeleton
- `v0.2` IOC extraction + offline detection heuristics
- `v0.3` scoring engine + Markdown/JSON reports + batch mode
- `v0.4` hybrid enrichment + HTML summary + validation stats
- `v0.5` Streamlit analyst dashboard
- `v0.6` CSV dataset adapter + labeled validation + DGA entropy detection
- `v0.5.1` dashboard redesign
- `v0.5.2` dashboard input modes + dark theme + integrations status
