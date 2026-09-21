"""Tests for the ML classifier module (phishingclassifier.ml).

Focus on the deterministic, model-independent logic (normalization,
fuzzy brand matching, feature engineering, model IO) plus guarded
integration against the shipped model on disk.
"""

from pathlib import Path

import numpy as np
import pytest
import scipy.sparse as sp

from phishingclassifier import ml
from phishingclassifier.heuristics import analyze_signals
from phishingclassifier.parser import ParsedEmail, parse_eml

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------
# normalize_confusables / build_norm_table
# --------------------------------------------------------------------------
def test_normalize_confusables_lowercases_and_maps_leet():
    assert ml.normalize_confusables("PaYp4l") == "paypal"


def test_normalize_confusables_handles_cyrillic_homoglyphs():
    # 'раypal' with cyrillic р/а should fold toward latin
    out = ml.normalize_confusables("mypаypal.com")
    assert "paypal" in out


def test_normalize_confusables_empty_passthrough():
    assert ml.normalize_confusables("") == ""


def test_build_norm_table_is_populated_and_cached():
    table = ml.build_norm_table()
    assert table  # non-empty
    assert table["0"] == "o"
    # second call returns the same cached object
    assert ml.build_norm_table() is table


# --------------------------------------------------------------------------
# levenshtein
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "a, b, cap, expected",
    [
        ("paypal", "paypal", 2, 0),
        ("paypal", "paypa1", 2, 1),
        ("paypal", "paypa", 2, 1),
        ("kitten", "sitting", 2, 3),   # real distance 3 > cap -> cap+1
        ("abcdef", "xyz", 2, 3),        # length diff > cap -> cap+1
    ],
)
def test_levenshtein(a, b, cap, expected):
    assert ml.levenshtein(a, b, cap=cap) == expected


# --------------------------------------------------------------------------
# fuzzy_brand_hit
# --------------------------------------------------------------------------
def test_fuzzy_brand_hit_flags_near_miss():
    assert ml.fuzzy_brand_hit("paypa1-alerts.com") == "paypal"


def test_fuzzy_brand_hit_ignores_genuine_brand_domain():
    assert ml.fuzzy_brand_hit("paypal.com") is None
    assert ml.fuzzy_brand_hit("www.paypal.com") is None


def test_fuzzy_brand_hit_skips_generic_labels():
    # 'secure', 'login' etc are generic hosting vocab, never a lookalike
    assert ml.fuzzy_brand_hit("secure-login.example.org") is None


def test_fuzzy_brand_hit_empty_host():
    assert ml.fuzzy_brand_hit("") is None


def test_fuzzy_brand_hit_custom_brands_dict():
    brands = {"acme": ["acme.com"]}
    assert ml.fuzzy_brand_hit("acm3-verify.net", brands=brands) == "acme"
    assert ml.fuzzy_brand_hit("acme.com", brands=brands) is None


# --------------------------------------------------------------------------
# _text_for_tfidf
# --------------------------------------------------------------------------
def test_text_for_tfidf_strips_html_tags():
    p = ParsedEmail(source_path="mem")
    p.subject = "Hello"
    p.text_body = "plain part"
    p.html_body = "<p>rich <b>content</b></p>"
    text = ml._text_for_tfidf(p)
    assert "<p>" not in text and "<b>" not in text
    assert "Hello" in text and "plain part" in text and "rich" in text


# --------------------------------------------------------------------------
# _engineered_features / _featurize
# --------------------------------------------------------------------------
def _analysis(name):
    parsed = parse_eml(str(FIXTURES / name))
    return parsed, analyze_signals(parsed)


def test_engineered_features_have_expected_keys():
    parsed, analysis = _analysis("spoofed.eml")
    feats = ml._engineered_features(parsed, analysis["signals"], analysis["iocs"])
    # every known signal contributes a count and weight column
    for sid in ml.KNOWN_SIGNAL_IDS:
        assert f"sig_count::{sid}" in feats
        assert f"sig_weight::{sid}" in feats
    for key in ("rule_score", "signal_total", "url_count", "domain_count",
                "auth_spf_fail", "has_auth_header", "body_len",
                "attachment_count", "sender_digits_ratio"):
        assert key in feats
    assert all(isinstance(v, float) for v in feats.values())


def test_engineered_features_counts_match_signals():
    parsed, analysis = _analysis("spoofed.eml")
    feats = ml._engineered_features(parsed, analysis["signals"], analysis["iocs"])
    # rule_score equals the sum of signal weights
    assert feats["rule_score"] == float(
        sum(s.get("weight", 0) for s in analysis["signals"]))
    assert feats["signal_total"] == float(len(analysis["signals"]))
    assert feats["signal_total"] > 0


def test_engineered_features_spf_fail_flag():
    parsed, analysis = _analysis("harvester.eml")
    feats = ml._engineered_features(parsed, analysis["signals"], analysis["iocs"])
    assert feats["auth_spf_fail"] == 1.0


def test_featurize_delegates_to_engineered():
    parsed, analysis = _analysis("clean.eml")
    a = ml._featurize(parsed, analysis["signals"], analysis["iocs"])
    b = ml._engineered_features(parsed, analysis["signals"], analysis["iocs"])
    assert a == b


def test_engineered_features_handles_missing_iocs():
    parsed, analysis = _analysis("clean.eml")
    feats = ml._engineered_features(parsed, analysis["signals"], None)
    assert feats["url_count"] == 0.0
    assert feats["domain_count"] == 0.0


# --------------------------------------------------------------------------
# model path / existence / save-load roundtrip
# --------------------------------------------------------------------------
def test_model_path_and_exists():
    assert ml.model_path() == ml.MODEL_FILE
    assert ml.model_exists() == ml.MODEL_FILE.is_file()


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    target = tmp_path / "models" / "test_model.joblib"
    monkeypatch.setattr(ml, "MODEL_DIR", target.parent)
    monkeypatch.setattr(ml, "MODEL_FILE", target)
    ml._MODEL_CACHE.pop("pipeline", None)

    bundle = {"vec": "sentinel", "tfidf": 42, "clf": object(), "kind": "ml-test"}
    ml.save_model(bundle)
    assert target.is_file()

    ml._MODEL_CACHE.pop("pipeline", None)
    loaded = ml.load_model()
    assert isinstance(loaded, dict)
    assert loaded["kind"] == "ml-test"
    assert loaded["tfidf"] == 42
    ml._MODEL_CACHE.pop("pipeline", None)


def test_load_model_returns_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "MODEL_FILE", tmp_path / "nope.joblib")
    ml._MODEL_CACHE.pop("pipeline", None)
    assert ml.load_model() is None


def test_load_model_swallows_corrupt_file(tmp_path, monkeypatch):
    bad = tmp_path / "corrupt.joblib"
    bad.write_bytes(b"not a real joblib payload")
    monkeypatch.setattr(ml, "MODEL_FILE", bad)
    ml._MODEL_CACHE.pop("pipeline", None)
    assert ml.load_model() is None


# --------------------------------------------------------------------------
# classify
# --------------------------------------------------------------------------
def test_classify_returns_none_without_model(monkeypatch):
    monkeypatch.setattr(ml, "load_model", lambda: None)
    parsed, analysis = _analysis("clean.eml")
    assert ml.classify(parsed, analysis["signals"], analysis["iocs"]) is None


class _FakeVec:
    def transform(self, rows):
        return np.zeros((len(rows), 3))


class _FakeTfidf:
    def transform(self, rows):
        return sp.csr_matrix(np.zeros((len(rows), 2)))


class _FakeClf:
    classes_ = [0, 1]

    def __init__(self, prob_phish):
        self._p = prob_phish

    def predict_proba(self, X):
        return np.array([[1.0 - self._p, self._p]])


def _patch_bundle(monkeypatch, prob_phish, scaler=None):
    bundle = {"vec": _FakeVec(), "tfidf": _FakeTfidf(),
              "clf": _FakeClf(prob_phish), "kind": "ml-fake"}
    if scaler is not None:
        bundle["scaler"] = scaler
    monkeypatch.setattr(ml, "load_model", lambda: bundle)


def test_classify_phishing_side(monkeypatch):
    _patch_bundle(monkeypatch, 0.9)
    parsed, analysis = _analysis("spoofed.eml")
    out = ml.classify(parsed, analysis["signals"], analysis["iocs"])
    assert out["prediction"] == 1
    assert out["model"] == "ml-fake"
    assert 0.0 <= out["probability_phishing"] <= 1.0


def test_classify_clean_side_and_threshold(monkeypatch):
    _patch_bundle(monkeypatch, 0.5)  # boundary -> phishing (>= 0.5)
    parsed, analysis = _analysis("clean.eml")
    out = ml.classify(parsed, analysis["signals"], analysis["iocs"])
    assert out["prediction"] == 1

    _patch_bundle(monkeypatch, 0.49)
    out2 = ml.classify(parsed, analysis["signals"], analysis["iocs"])
    assert out2["prediction"] == 0


def test_classify_uses_scaler_when_present(monkeypatch):
    calls = {"n": 0}

    class _FakeScaler:
        def transform(self, X):
            calls["n"] += 1
            return X

    _patch_bundle(monkeypatch, 0.7, scaler=_FakeScaler())
    parsed, analysis = _analysis("clean.eml")
    out = ml.classify(parsed, analysis["signals"], analysis["iocs"])
    assert calls["n"] == 1
    assert out["prediction"] == 1


def test_classify_real_model_on_disk():
    if not ml.model_exists():
        pytest.skip("no shipped model on disk")
    ml._MODEL_CACHE.pop("pipeline", None)
    parsed, analysis = _analysis("spoofed.eml")
    out = ml.classify(parsed, analysis["signals"], analysis["iocs"])
    assert out is not None
    assert 0.0 <= out["probability_phishing"] <= 1.0
    assert out["prediction"] in (0, 1)


# --------------------------------------------------------------------------
# train_from_rows validation
# --------------------------------------------------------------------------
def _row(label):
    p = ParsedEmail(source_path="mem")
    p.subject = "hello"
    p.text_body = "body text"
    return {"parsed": p, "label": label}


def test_train_requires_min_rows():
    with pytest.raises(ValueError, match="Need >= 10"):
        ml.train_from_rows([_row(1)] * 5 + [_row(0)] * 2)


def test_train_requires_both_classes():
    with pytest.raises(ValueError, match="Both classes"):
        ml.train_from_rows([_row(1)] * 15)


# --------------------------------------------------------------------------
# evaluate_on_datasets
# --------------------------------------------------------------------------
def test_evaluate_raises_without_model(monkeypatch):
    monkeypatch.setattr(ml, "load_model", lambda: None)
    with pytest.raises(RuntimeError, match="No trained model"):
        ml.evaluate_on_datasets(["whatever.csv"])
