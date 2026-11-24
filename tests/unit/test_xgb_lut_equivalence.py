"""Real-data equivalence, invariance, and SQLI-006 regression tests (H4a, H4c, H2a)."""

from __future__ import annotations

import json
import logging
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

ROOT_DIR = Path(__file__).resolve().parents[2]
for extra_path in (ROOT_DIR, ROOT_DIR / "gateway", ROOT_DIR / "ml-engine"):
    extra_str = str(extra_path)
    if extra_str not in sys.path:
        sys.path.insert(0, extra_str)

from app.security.anomaly import AnomalyDetector  # noqa: E402
from app.security.engine import RuleEngine  # noqa: E402
from app.security.ml_detector import MLDetector  # noqa: E402
from app.security.scoring import RuleScorer  # noqa: E402
from features.extractor import extract_26_from_http  # noqa: E402

logger = logging.getLogger(__name__)

B1000_CSV = ROOT_DIR / "data" / "benchmark_1000_diverse.csv"
CSIC_CSV = ROOT_DIR / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv"
XGB_MODEL_PATH = ROOT_DIR / "ml-engine" / "artifacts" / "xgb_v2.ubj"

REST_API_BENIGN_ROWS = [
    {"method": "GET", "path": "/api/v1/vulnerable/books/search/", "query_params": "q=Clean+Code", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/books/search/", "query_params": "q=Design+Patterns&page=1", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/books/search/", "query_params": "", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/reviews/", "query_params": "book_id=1", "body": ""},
    {"method": "POST", "path": "/api/v1/vulnerable/reviews/", "query_params": "", "body": json.dumps({"book_id": 1, "author": "Alice", "comment": "Great book worth $45!"})},
    {"method": "POST", "path": "/api/v1/vulnerable/reviews/", "query_params": "", "body": json.dumps({"author": "Bob", "comment": "Helpful chapter 3", "rating": 5})},
    {"method": "POST", "path": "/api/v1/vulnerable/auth/login/", "query_params": "", "body": json.dumps({"username": "admin", "password": "SafePassword123!"})},
    {"method": "GET", "path": "/api/v1/vulnerable/orders/101/", "query_params": "", "body": ""},
    {"method": "POST", "path": "/api/v1/vulnerable/books/", "query_params": "", "body": json.dumps({"title": "Refactoring", "author": "Martin Fowler", "price": 49.99})},
    {"method": "GET", "path": "/api/v1/vulnerable/admin/health/", "query_params": "", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/categories/", "query_params": "category=software", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/inventory/", "query_params": "warehouse_id=1", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/shipping/status/", "query_params": "tracking_num=TRK123456", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/discounts/", "query_params": "code=SUMMER2026", "body": ""},
    {"method": "GET", "path": "/api/v1/vulnerable/recommendations/", "query_params": "user_id=42", "body": ""},
]


def _extract_http_parts(row: pd.Series) -> tuple[str, str | None, str | None, str]:
    path = str(row.get("path", "/")).strip() or "/"
    query = str(row.get("query_params", "")).strip() if pd.notna(row.get("query_params")) else None
    body = str(row.get("body", "")).strip() if pd.notna(row.get("body")) else None
    payload = f"{path} {query or ''} {body or ''}".strip()
    return path, query, body, payload


def _eval_lut_probs(lut: dict, feat: np.ndarray) -> np.ndarray:
    idx = lut["root_slots"]
    f_feat = lut["flat_feat"]
    f_thresh = lut["flat_thresh"]
    f_child = lut["flat_children"]
    for _ in range(lut["max_depth"]):
        idx = f_child[idx, (feat[f_feat[idx]] >= f_thresh[idx]).view(np.uint8)]
    logits = lut["base_logits"] + lut["flat_weights"][idx].reshape(-1, lut["num_class"]).sum(axis=0)
    logits = logits - logits.max()
    exp_l = np.exp(logits)
    return exp_l / exp_l.sum()


def _native_decision(
    proba_array: np.ndarray,
    classes: list[str],
    threshold: float,
) -> tuple[bool, str]:
    benign_idx = next((i for i, c in enumerate(classes) if c.upper() == "BENIGN"), -1)
    benign_prob = float(proba_array[benign_idx]) if benign_idx >= 0 else 0.0
    attack_prob = 1.0 - benign_prob
    if attack_prob >= threshold:
        best_idx = max((i for i in range(len(classes)) if i != benign_idx), key=lambda i: float(proba_array[i]))
        return True, classes[best_idx]
    return False, "BENIGN"


def test_xgb_lut_bit_exact_equivalence_on_b1000() -> None:
    """Verifies compiled branchless LUT matches native XGBoost Booster across all 1,000 B1000 rows."""
    df = pd.read_csv(B1000_CSV)
    assert len(df) == 1000

    detector = MLDetector(model_path=XGB_MODEL_PATH)
    assert detector.is_loaded is True
    assert detector._compiled_lut is not None

    booster = xgb.Booster({"nthread": 1})
    booster.load_model(str(XGB_MODEL_PATH))
    booster.set_param({"nthread": 1})

    lut = detector._compiled_lut
    classes = detector.classes
    threshold = detector._attack_threshold
    assert len(classes) == 5

    max_abs_prob_diff = 0.0
    class_mismatches = 0
    is_attack_mismatches = 0

    for _, row in df.iterrows():
        path, query, body, payload = _extract_http_parts(row)
        vec26 = extract_26_from_http(path=path, query_params=query, body=body)

        lut_probs = _eval_lut_probs(lut, vec26)
        native_probs = booster.inplace_predict(vec26.reshape(1, -1))[0]

        row_diff = float(np.max(np.abs(lut_probs - native_probs)))
        if row_diff > max_abs_prob_diff:
            max_abs_prob_diff = row_diff

        det_res = detector.predict(payload, feature_vector=vec26.tolist())
        native_is_attack, native_class = _native_decision(native_probs, classes, threshold)

        if det_res.attack_type != native_class:
            class_mismatches += 1
        if det_res.is_attack != native_is_attack:
            is_attack_mismatches += 1

    print(
        f"\n[XGB LUT B1000] max_abs_prob_diff={max_abs_prob_diff:.3e}, "
        f"class_mismatches={class_mismatches}, is_attack_mismatches={is_attack_mismatches}"
    )
    logger.info(
        "XGB LUT B1000 equivalence: max_abs_prob_diff=%.3e class_mismatches=%d is_attack_mismatches=%d",
        max_abs_prob_diff,
        class_mismatches,
        is_attack_mismatches,
    )

    assert max_abs_prob_diff < 1e-6
    assert class_mismatches == 0
    assert is_attack_mismatches == 0


def test_anomaly_detector_b1000_zero_fp_and_order_invariance() -> None:
    """Verifies AnomalyDetector achieves 0 FP on B1000 benign rows regardless of row order."""
    df = pd.read_csv(B1000_CSV)
    benign_df = df[df["attack_type"].astype(str).str.upper() == "BENIGN"].reset_index(drop=True)
    assert len(benign_df) == 200

    detector = AnomalyDetector()
    assert detector.is_loaded is True

    samples: list[tuple[int, str, str | None, str | None, str, list[float]]] = []
    bare_root_indices: list[int] = []
    for idx, row in benign_df.iterrows():
        path, query, body, payload = _extract_http_parts(row)
        vec26 = extract_26_from_http(path=path, query_params=query, body=body).tolist()
        samples.append((int(idx), path, query, body, payload, vec26))
        if path == "/" and not query and not body:
            bare_root_indices.append(int(idx))

    assert len(bare_root_indices) == 8

    def _score_order(ordered_items: list[tuple[int, str, str | None, str | None, str, list[float]]]) -> dict[int, float]:
        scores: dict[int, float] = {}
        for idx, _, _, _, payload, vec26 in ordered_items:
            res = detector.predict(payload, feature_vector=vec26)
            assert res.model_loaded is True
            assert res.anomaly_score is not None
            scores[idx] = float(res.anomaly_score)
        return scores

    orig_scores = _score_order(samples)
    rev_scores = _score_order(list(reversed(samples)))
    shuffled = list(samples)
    random.Random(42).shuffle(shuffled)
    shuf_scores = _score_order(shuffled)

    for scores in (orig_scores, rev_scores, shuf_scores):
        fp_at_60 = sum(1 for s in scores.values() if s >= 60.0)
        fp_at_80 = sum(1 for s in scores.values() if s >= 80.0)
        assert fp_at_60 == 0
        assert fp_at_80 == 0
        for root_idx in bare_root_indices:
            assert scores[root_idx] == 0.0

    assert orig_scores == rev_scores == shuf_scores


def test_sqli_006_between_tautology_and_zero_benign_fp() -> None:
    """Verifies SQLI-006 catches BETWEEN/NOT BETWEEN tautologies with 0 FP across all 1,715 benign samples."""
    engine = RuleEngine()

    attack_payloads = [
        "105 OR 17-7 BETWEEN 10 AND 10",
        "105 OR 17-7 BETWEEN 5 AND 15",
        "105 OR 17-7 NOT BETWEEN 20 AND 30",
        "105/**/OR/**/17-7 BETWEEN 10 AND 10",
    ]
    for payload in attack_payloads:
        det = engine.inspect_request(path="/api/v1/items", query_params=f"id={payload}")
        sqli_006 = [m for m in det.matches if m.rule_id == "SQLI-006"]
        assert sqli_006, f"Expected SQLI-006 match for {payload!r}"
        assert max(m.confidence for m in sqli_006) >= 0.98
        assert det.rule_risk_score >= 88.2
        assert RuleScorer.calculate_score(det.matches) >= 88.2

    benign_edge_phrases = [
        "delivery in 1 or 2 days",
        "orders between 10 and 20",
        "age >= 18 and age <= 65",
    ]
    for phrase in benign_edge_phrases:
        det = engine.inspect_request(path="/api/v1/orders", query_params=f"q={phrase}")
        sqli_006 = [m for m in det.matches if m.rule_id == "SQLI-006"]
        assert not sqli_006, f"Unexpected SQLI-006 match for benign phrase {phrase!r}: {sqli_006}"

    df_b1000 = pd.read_csv(B1000_CSV)
    b1000_benign = df_b1000[df_b1000["attack_type"].astype(str).str.upper() == "BENIGN"].reset_index(drop=True)
    assert len(b1000_benign) == 200

    df_csic = pd.read_csv(CSIC_CSV)
    csic_benign = df_csic[df_csic["label"].astype(int) == 0].reset_index(drop=True)
    assert len(csic_benign) == 1500

    df_rest_benign = pd.DataFrame(REST_API_BENIGN_ROWS)
    assert len(df_rest_benign) == 15

    sqli_006_fp_count = 0
    total_evaluated = 0
    for corpus_name, df_corpus in (
        ("b1000_benign", b1000_benign),
        ("csic_benign", csic_benign),
        ("rest_api_benign", df_rest_benign),
    ):
        for idx, row in df_corpus.iterrows():
            path, query, body, _ = _extract_http_parts(row)
            body_bytes = body.encode("utf-8") if body else None
            det = engine.inspect_request(path=path, query_params=query, body_bytes=body_bytes)
            total_evaluated += 1
            if any(m.rule_id == "SQLI-006" for m in det.matches):
                sqli_006_fp_count += 1
                logger.error("SQLI-006 FP in %s[%d]: path=%r query=%r body=%r", corpus_name, idx, path, query, body)

    print(f"\n[SQLI-006 Benign Check] total_evaluated={total_evaluated}, sqli_006_fp_count={sqli_006_fp_count}")
    assert total_evaluated == 1715
    assert sqli_006_fp_count == 0
