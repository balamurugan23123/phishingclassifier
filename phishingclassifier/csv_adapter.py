"""CSV dataset adapter for labeled email rows."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .parser import ParsedEmail

# common column names across datasets
SUBJECT_KEYS = ["subject", "Subject", "email_subject", "title"]
BODY_KEYS = ["body", "Body", "text", "email_body", "content", "message"]
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
    """Yield rows from CSV file."""
    p = Path(path)
    with open(p, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield row


def load_csv_dataset(path: str) -> List[Dict[str, Any]]:
    """Load dataset rows into parsed objects with labels."""
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(iter_csv_rows(path)):
        out.append({
            "row": row,
            "parsed": row_to_parsed(row, source=f"{Path(path).name}#row{i + 1}"),
            "label": row_label(row),
            "source": f"{Path(path).name}#row{i + 1}",
        })
    return out
