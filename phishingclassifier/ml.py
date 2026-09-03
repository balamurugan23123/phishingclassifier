"""Machine learning classifier for phishing detection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_FILE = MODEL_DIR / "phish_model.joblib"
MAX_TFIDF_FEATURES = 300

KNOWN_SIGNAL_IDS = [
    "spf_fail", "dkim_fail", "dmarc_fail", "auth_header_absent",
    "auth_none", "return_path_mismatch", "reply_to_mismatch",
    "display_name_spoof", "message_id_absent", "date_future", "date_stale",
    "origin_ip_internal", "url_ip_literal", "url_punycode",
    "url_shortener", "url_nonstandard_port", "url_deep_subdomains",
    "lookalike_domain", "domain_high_entropy", "link_text_mismatch",
    "credential_form", "dangerous_attachment", "passworded_archive",
    "urgency_keywords", "money_scam_language", "spam_sales_language",
    "free_webmail_impersonation", "generic_greeting", "link_count_high",
    "base64_blob", "lure_signal_correlation", "brand_lookalike_fuzzy",
    "vt_malicious_verdict", "urlscan_malicious_verdict",
]

_MODEL_CACHE: Dict[str, Any] = {}
_NORM_TABLE: Dict[str, str] = {}

# character substitutions
_LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i",
    "|": "l", "€": "e", "£": "l",
}


def build_norm_table() -> Dict[str, str]:
    if _NORM_TABLE:
        return _NORM_TABLE
    table: Dict[str, str] = dict(_LEET_MAP)
    extra = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
        "у": "y", "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d",
        "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p",
        "ϲ": "c", "ν": "v", "τ": "t", "υ": "u",
    }
    table.update(extra)
    _NORM_TABLE.update(table)
    return _NORM_TABLE


def normalize_confusables(text: str) -> str:
    """Normalize homoglyphs and leet characters."""
    import unicodedata

    if not text:
        return text
    text = unicodedata.normalize("NFKC", text)
    table = build_norm_table()
    return "".join(table.get(ch, ch) for ch in text.lower())


def levenshtein(a: str, b: str, cap: int = 2) -> int:
    """Distance with early cutoff."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            if v < best:
                best = v
        if best > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def fuzzy_brand_hit(host: str, brands: Optional[Dict[str, list]] = None,
                    max_distance: int = 2) -> Optional[str]:
    """Check if host is a near-miss of a known brand."""
    from .heuristics import BRANDS as _B

    if brands is None:
        brands = _B
    if not host:
        return None
    parts = host.rstrip(".").split(".")
    if len(parts) < 2:
        return None
    sld = normalize_confusables("".join(parts[:-1]))
    for brand, legit in brands.items():
        if sld == brand or host.lower() in legit:
            continue
        for ref in {brand, normalize_confusables(legit[0].split(".")[0])}:
            if len(ref) >= 4 and levenshtein(sld, ref, max_distance) <= max_distance:
                return brand
    return None


def _text_for_tfidf(parsed) -> str:
    import re as _re

    html = _re.sub(r"<[^>]+>", " ", parsed.html_body or "")
    return " ".join([
        parsed.subject or "", parsed.text_body or "", html,
    ])


def _engineered_features(parsed, signals: List[Dict[str, Any]],
                         iocs: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    feats: Dict[str, float] = {}
    sig_counts: Dict[str, int] = {}
    weight_by_id: Dict[str, int] = {}
    for s in signals:
        sig_counts[s["id"]] = sig_counts.get(s["id"], 0) + 1
        weight_by_id[s["id"]] = weight_by_id.get(s["id"], 0) + s.get("weight", 0)
    for sid in KNOWN_SIGNAL_IDS:
        feats[f"sig_count::{sid}"] = float(sig_counts.get(sid, 0))
        feats[f"sig_weight::{sid}"] = float(weight_by_id.get(sid, 0))

    feats["rule_score"] = float(sum(s.get("weight", 0) for s in signals))
    feats["signal_total"] = float(len(signals))
    feats["url_count"] = float(len((iocs or {}).get("urls", {}).get("body", [])
                                   + (iocs or {}).get("urls", {}).get("header", [])))
    feats["domain_count"] = float(len((iocs or {}).get("domains", {}).get("body", [])
                                       + (iocs or {}).get("domains", {}).get("header", [])))
    feats["auth_spf_fail"] = 1.0 if (parsed.auth("spf") in ("fail", "softfail")) else 0.0
    feats["auth_dkim_fail"] = 1.0 if (parsed.auth("dkim") in ("fail", "softfail")) else 0.0
    feats["auth_dmarc_fail"] = 1.0 if (parsed.auth("dmarc") in ("fail", "softfail")) else 0.0
    feats["has_auth_header"] = 1.0 if parsed.has_auth_header else 0.0
    feats["body_len"] = float(len(parsed.text_body or "") + len(parsed.html_body or ""))
    feats["attachment_count"] = float(len(parsed.attachments))
    feats["from_csv_row"] = 1.0 if getattr(parsed, "from_csv", False) else 0.0
    sender_dom = (parsed.from_domain or "").lower()
    feats["sender_digits_ratio"] = (
        sum(c.isdigit() for c in sender_dom) / len(sender_dom)
        if sender_dom else 0.0
    )
    feats["sender_hyphens"] = float(sender_dom.count("-"))
    return feats


def _featurize(parsed, signals, iocs) -> Dict[str, float]:
    return _engineered_features(parsed, signals, iocs)


def model_path() -> Path:
    return MODEL_FILE


def model_exists() -> bool:
    return MODEL_FILE.is_file()


def load_model():
    """Load the trained pipeline."""
    if "pipeline" in _MODEL_CACHE:
        return _MODEL_CACHE["pipeline"]
    if not model_exists():
        return None
    try:
        import joblib

        pipe = joblib.load(MODEL_FILE)
        _MODEL_CACHE["pipeline"] = pipe
        return pipe
    except Exception:
        return None


def save_model(pipe) -> None:
    import joblib

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, MODEL_FILE)
    _MODEL_CACHE.pop("pipeline", None)


def train_from_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Train ML model on labeled rows."""
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import FeatureUnion, Pipeline

    labeled = [r for r in rows if r.get("label") in (0, 1)]
    if len(labeled) < 10:
        raise ValueError("Need >= 10 labeled rows to train")
    classes = {r["label"] for r in labeled}
    if classes != {0, 1}:
        raise ValueError("Both classes (0 and 1) required")

    from .heuristics import analyze_signals

    X_feats: List[Dict[str, float]] = []
    X_text: List[str] = []
    y: List[int] = []
    for r in labeled:
        parsed = r["parsed"]
        analysis = analyze_signals(parsed)
        X_feats.append(_featurize(parsed, analysis["signals"], analysis["iocs"]))
        X_text.append(_text_for_tfidf(parsed))
        y.append(r["label"])

    class _RowPicker:
        def __init__(self, which: str):
            self.which = which

        def transform(self, X, y=None):
            return X[self.which]

    pipe = Pipeline([
        ("features", FeatureUnion([
            ("engineered", Pipeline([
                ("pick", _RowPicker("feats")),
                ("vec", DictVectorizer(sparse=False)),
            ])),
            ("text", Pipeline([
                ("pick", _RowPicker("text")),
                ("tfidf", TfidfVectorizer(
                    ngram_range=(1, 2), max_features=MAX_TFIDF_FEATURES,
                    sublinear_tf=True, strip_accents="unicode",
                    stop_words="english", min_df=1,
                )),
            ])),
        ])),
        ("clf", HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.1, max_depth=None,
            random_state=42,
        )),
    ])

    X = {"feats": X_feats, "text": X_text}
    cv_scores = cross_val_score(pipe, X, np.array(y), cv=5, scoring="f1_macro")
    pipe.fit(X, np.array(y))
    save_model(pipe)

    train_pred = pipe.predict(X)
    train_acc = float((train_pred == np.array(y)).mean())
    return {
        "rows": len(labeled),
        "cv_f1_macro_mean": float(cv_scores.mean()),
        "cv_f1_macro_std": float(cv_scores.std()),
        "train_accuracy": train_acc,
    }


def classify(parsed, signals: List[Dict[str, Any]],
             iocs: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Get ML prediction for an email."""
    pipe = load_model()
    if pipe is None:
        return None
    feats = _featurize(parsed, signals, iocs)
    text = _text_for_tfidf(parsed)
    proba = pipe.predict_proba({"feats": [feats], "text": [text]})[0]
    idx = int(getattr(pipe, "classes_", [0, 1]).tolist().index(1)) \
        if hasattr(pipe, "classes_") else 1
    p_phish = float(proba[idx])
    return {
        "probability_phishing": round(p_phish, 4),
        "prediction": 1 if p_phish >= 0.5 else 0,
        "model": "ml-gbdt",
    }
