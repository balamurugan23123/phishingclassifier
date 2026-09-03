"""CSV dataset adapter for labeled email rows."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .parser import ParsedEmail

# common column names across datasets
SUBJECT_KEYS = ["subject", "Subject", "email_subject", "title"]
BODY_KEYS = ["body", "Body", "text", "email_body", "content", "message",
             "text_combined", "combined_text"]
SENDER_KEYS = ["sender", "Sender", "from", "From", "email_from", "from_addr"]
LABEL_KEYS = ["label", "Label", "class", "Class", "type", "target",
              "label_num", "spam"]


def _pick(row: Dict[str, str], keys: List[str]) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip() not in ("", "nan"):
            return str(value)
    return ""


def _sender_domain(sender: str) -> str:
    if "@" not in sender:
        return ""
    return sender.rsplit("@", 1)[1].strip().lower().lstrip("[").rstrip("]")


def row_to_parsed(row: Dict[str, str], source: str = "csv") -> ParsedEmail:
    """Convert a CSV row into a ParsedEmail object."""
    parsed = ParsedEmail(source_path=source)
    parsed.subject = _pick(row, SUBJECT_KEYS)
    parsed.text_body = _pick(row, BODY_KEYS)
    parsed.from_addr = _pick(row, SENDER_KEYS)
    parsed.from_display = parsed.from_addr
    parsed.from_domain = _sender_domain(parsed.from_addr)
    parsed.received_chain = []
    parsed.origin_ip = None
    parsed.origin_ip_reserved = True
    parsed.auth_results = {}
    parsed.from_csv = True
    return parsed


def row_label(row: Dict[str, str]) -> Optional[int]:
    """Extract binary label: 1 = phishing, 0 = clean, None = unknown."""
    raw = _pick(row, LABEL_KEYS)
    if not raw:
        return None
    value = raw.strip().lower()
    if value in {"1", "phishing", "phish", "spam", "yes", "true", "malicious"}:
        return 1
    if value in {"0", "legitimate", "legit", "ham", "safe", "no", "false",
                 "benign", "normal"}:
        return 0
    try:
        return 1 if int(value) == 1 else 0
    except ValueError:
        return None


def iter_csv_rows(path: str) -> Iterable[Dict[str, str]]:
    """Yield rows from CSV file (handles very large fields)."""
    import sys

    csv.field_size_limit(sys.maxsize)
    p = Path(path)
    with open(p, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield row


def load_csv_dataset(path: str, max_rows: int = 0) -> List[Dict[str, Any]]:
    """Load dataset rows into parsed objects with labels.

    max_rows=0 loads all; otherwise the first N labeled rows.
    """
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(iter_csv_rows(path)):
        label = row_label(row)
        if max_rows and len(out) >= max_rows:
            break
        if label is None:
            continue
        out.append({
            "row": row,
            "parsed": row_to_parsed(row, source=f"{Path(path).name}#row{i + 1}"),
            "label": label,
            "source": f"{Path(path).name}#row{i + 1}",
        })
    return out


def load_combined_dataset(dir_path: str, per_class: int = 0,
                          files: Optional[List[str]] = None,
                          max_body: int = 20000) -> List[Dict[str, Any]]:
    """Load and merge labeled datasets from a directory.

    - Deduplicates exact subject+body pairs across files.
    - Drops rows with empty bodies or bodies over max_body chars
      (truncated forwards dominate corpora and add nothing).
    - per_class > 0: balanced random sample per class (deterministic seed).
    - Nazario/Nigerian_Fraud/SpamAssasin label semantics: Nazario and
      Nigerian_Fraud are all-phishing corpora; SpamAssasin rows are
      labeled spam=1 which this project counts as phishing-family only
      if the file says so — their 'label' column is respected as-is.
    """
    import random

    rng = random.Random(42)
    d = Path(dir_path)
    names = files or sorted(p.name for p in d.glob("*.csv"))
    merged: List[Dict[str, Any]] = []
    seen: set = set()
    for name in names:
        if name == "labeled_sample.csv":
            continue  # tiny hand sample, would be duplicated by the corpus
        for row in iter_csv_rows(str(d / name)):
            label = row_label(row)
            if label is None:
                continue
            subject = (row.get("subject") or row.get("Subject") or "").strip()
            body = (row.get("body") or row.get("Body")
                    or row.get("text_combined") or "").strip()
            if not body or len(body) > max_body:
                continue
            key = hash((subject.lower()[:200], body.lower()[:2000]))
            if key in seen:
                continue
            seen.add(key)
            merged.append({
                "row": row,
                "parsed": row_to_parsed(
                    row, source=f"{name}#{len(merged) + 1}"),
                "label": label,
                "source": f"{name}#{len(merged) + 1}",
            })

    if per_class and per_class > 0:
        phish = [m for m in merged if m["label"] == 1]
        legit = [m for m in merged if m["label"] == 0]
        rng.shuffle(phish)
        rng.shuffle(legit)
        take = min(per_class, len(phish), len(legit))
        merged = phish[:take] + legit[:take]
        rng.shuffle(merged)
    return merged
