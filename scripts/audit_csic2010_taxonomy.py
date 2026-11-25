"""Audit and re-classify CSIC 2010 dataset taxonomy (Phase D2 & Phase E Two-Tier + Sub-Breakdown).

Investigates:
1. Reviewer finding: substring matching 'insert' in 'modo=insertar' falsely inflated SQLi labels.
2. Two-tier breakdown:
   - Group A (True Payload Attacks): SQLI, XSS, PATH_TRAVERSAL, COMMAND_INJECTION
     with detailed sub-categories: SQLI_CLASSIC_UNION, SQLI_BLIND_BOOLEAN,
     SQLI_TSQL_TIME_DELAY, XSS, COMMAND_SSI, PATH_TRAVERSAL.
   - Group B (Parameter Tampering): Business-logic/form deviations on 2010 JSP application.
3. Evaluates BOTH:
   - Loose monitoring criteria (rule >= 80 OR ml.is_attack OR anom >= 60 OR hybrid >= 50)
   - Operational DecisionEngine T=80 (ACTIVE_BLOCKING)
   across BOTH Overall 1,500 Attacks AND Group A True Payload Attacks, plus Benign FPR (N=1,500).
4. Supports `--save-before` to snapshot pre-Phase-E metrics to `docs/reports/csic2010_phase_e_before.json`,
   and compares against that snapshot on normal runs to emit `docs/reports/csic2010_phase_e_comparison.json`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "gateway"))
sys.path.insert(0, str(ROOT_DIR / "ml-engine"))

from app.security.anomaly import AnomalyDetector  # noqa: E402
from app.security.decision import DecisionEngine  # noqa: E402
from app.security.engine import RuleEngine  # noqa: E402
from app.security.ml_detector import MLDetector  # noqa: E402
from app.security.risk_engine import RiskEngine  # noqa: E402
from features.canonicalizer import canonicalize_http_request  # noqa: E402
from features.extractor import extract_26_from_http  # noqa: E402

try:
    from features.canonicalizer import normalize_http_for_ml  # type: ignore[attr-defined]
except ImportError:
    normalize_http_for_ml = None

BENCHMARK_CSV = ROOT_DIR / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv"
OUTPUT_JSON = ROOT_DIR / "docs" / "reports" / "csic2010_taxonomy_breakdown.json"
BEFORE_JSON = ROOT_DIR / "docs" / "reports" / "csic2010_phase_e_before.json"
COMPARISON_JSON = ROOT_DIR / "docs" / "reports" / "csic2010_phase_e_comparison.json"

GROUP_A_SUBCATEGORIES = (
    "SQLI_CLASSIC_UNION",
    "SQLI_BLIND_BOOLEAN",
    "SQLI_TSQL_TIME_DELAY",
    "XSS",
    "COMMAND_SSI",
    "PATH_TRAVERSAL",
)


def recursive_urldecode(s: str, max_depth: int = 3) -> str:
    """Recursively decodes URL-encoded strings (including '+' as space) up to max_depth levels."""
    curr = str(s)
    for _ in range(max_depth):
        dec = urllib.parse.unquote_plus(curr)
        if dec == curr:
            break
        curr = dec
    return curr


# Authentic Injection Patterns with strict word boundaries (\b)
_TRUE_SQLI_RE = re.compile(
    r"""(?i)(?:\b(?:union\s+(?:all\s+|distinct\s+)?select|select\b.+?\bfrom|insert\s+into\b|drop\s+table\b|drop\s+database\b|waitfor\s+(?:delay|time)\b|benchmark\s*\(|sleep\s*\(|load_file\s*\(|into\s+(?:outfile|dumpfile))\b|--|/\*|(?:\b(?:or|and)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?|\b(?:or|and)\s+\d+\s*=\s*\d+)|\b(?:or|and)\s+[0-9\s+\-*\/]+?\s*(=|!=|<>|\blike\b)\s*[0-9\s+\-*\/]+)""",
    re.IGNORECASE,
)

_SQLI_TIME_DELAY_RE = re.compile(
    r"""(?i)\b(?:waitfor\s+(?:delay|time)|benchmark\s*\(|sleep\s*\(|pg_sleep\s*\()""",
    re.IGNORECASE,
)

_SQLI_CLASSIC_UNION_RE = re.compile(
    r"""(?i)(?:\bunion\s+(?:all\s+|distinct\s+)?select\b|\bselect\b.+?\bfrom\b|\binsert\s+into\b|\bdrop\s+(?:table|database)\b|\bload_file\s*\(|\binto\s+(?:outfile|dumpfile)\b)""",
    re.IGNORECASE,
)

_TRUE_XSS_RE = re.compile(
    r"""(?i)(?:<script[^>]*>|javascript:|alert\s*\(|document\.cookie|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|eval\s*\(|<svg|<img[^>]*onerror|<iframe)""",
    re.IGNORECASE,
)

_TRUE_PATH_RE = re.compile(
    r"""(?i)(?:\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini)""",
    re.IGNORECASE,
)

_TRUE_CMD_RE = re.compile(
    r"""(?i)(?:;\s*(?:cat|whoami|id|ls|sh|bash|uname)\b|<!--#exec)""",
    re.IGNORECASE,
)


def classify_payload_taxonomy(raw_text: str) -> dict[str, Any]:
    """Classifies an attack request into Group A (True Payload + sub-category) or Group B."""
    decoded = recursive_urldecode(raw_text)

    is_sqli = bool(_TRUE_SQLI_RE.search(decoded))
    is_xss = bool(_TRUE_XSS_RE.search(decoded))
    is_path = bool(_TRUE_PATH_RE.search(decoded))
    is_cmd = bool(_TRUE_CMD_RE.search(decoded))

    has_insertar = "insertar" in decoded.lower()
    has_raw_insert = "insert" in decoded.lower()

    if is_sqli:
        detected_category = "SQLI"
        if _SQLI_TIME_DELAY_RE.search(decoded):
            detailed_subcategory = "SQLI_TSQL_TIME_DELAY"
        elif _SQLI_CLASSIC_UNION_RE.search(decoded):
            detailed_subcategory = "SQLI_CLASSIC_UNION"
        else:
            detailed_subcategory = "SQLI_BLIND_BOOLEAN"
    elif is_xss:
        detected_category = "XSS"
        detailed_subcategory = "XSS"
    elif is_path:
        detected_category = "PATH_TRAVERSAL"
        detailed_subcategory = "PATH_TRAVERSAL"
    elif is_cmd:
        detected_category = "COMMAND_INJECTION"
        detailed_subcategory = "COMMAND_SSI"
    else:
        detected_category = "PARAMETER_TAMPERING"
        detailed_subcategory = "PARAMETER_TAMPERING"

    is_group_a = detected_category in ("SQLI", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION")
    tier = "Group A (True Payload)" if is_group_a else "Group B (Parameter Tampering)"

    return {
        "tier": tier,
        "is_group_a": is_group_a,
        "true_category": detected_category,
        "detailed_subcategory": detailed_subcategory,
        "is_sqli": is_sqli,
        "is_xss": is_xss,
        "is_path": is_path,
        "is_cmd": is_cmd,
        "has_insertar": has_insertar,
        "has_raw_insert": has_raw_insert,
    }


def _run_ml_prediction(
    ml_detector: MLDetector,
    path: str,
    query: str,
    body: str,
) -> tuple[Any, list[float], str]:
    """Runs ML inference via predict_http (if present) or canonical extract_26_from_http."""
    if callable(getattr(ml_detector, "predict_http", None)):
        ml_out = ml_detector.predict_http(path=path, query_params=query, body=body)
        if isinstance(ml_out, tuple) and len(ml_out) == 2:
            ml_pred, vec26 = ml_out
        else:
            ml_pred = ml_out
            vec26 = ml_pred.feature_vector or extract_26_from_http(
                path=path, query_params=query, body=body
            ).tolist()
        if normalize_http_for_ml is not None:
            np_, nq_, nb_ = normalize_http_for_ml(path=path, query_params=query, body=body)
            canon_payload = canonicalize_http_request(path=np_, query_params=nq_, body=nb_)
        else:
            canon_payload = canonicalize_http_request(path=path, query_params=query, body=body)
        return ml_pred, vec26, canon_payload

    if normalize_http_for_ml is not None:
        np_, nq_, nb_ = normalize_http_for_ml(path=path, query_params=query, body=body)
    else:
        np_, nq_, nb_ = path, query, body
    vec26 = extract_26_from_http(path=np_, query_params=nq_, body=nb_).tolist()
    canon_payload = canonicalize_http_request(path=np_, query_params=nq_, body=nb_)
    ml_pred = ml_detector.predict(canon_payload, feature_vector=vec26)
    return ml_pred, vec26, canon_payload


def _summarize_subcategories(records: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for sub in (*GROUP_A_SUBCATEGORIES, "PARAMETER_TAMPERING"):
        sub_recs = [r for r in records if r["detailed_subcategory"] == sub]
        tot = len(sub_recs)
        blk = sum(1 for r in sub_recs if r[key])
        summary[sub] = {
            "total": tot,
            "blocked": blk,
            "recall_pct": round((blk / tot * 100.0), 2) if tot else 0.0,
        }
    return summary


def audit_csic2010(save_before: bool = False) -> dict[str, Any]:
    print("=" * 80)
    print("  CSIC 2010 TAXONOMY AUDIT & TWO-TIER BREAKDOWN (Phase D2 / Phase E)")
    print("=" * 80)
    print(f"Loading dataset from: {BENCHMARK_CSV}")

    df = pd.read_csv(BENCHMARK_CSV)
    attacks_df = df[df["label"].astype(int) == 1].copy()
    benign_df = df[df["label"].astype(int) == 0].copy()

    total_attacks = len(attacks_df)
    total_benign = len(benign_df)
    print(f"Loaded {len(df)} total samples ({total_benign} Benign, {total_attacks} Attacks).\n")

    sqli_labeled = attacks_df[attacks_df["attack_type"] == "SQLI"]
    print(f"Original CSIC labeled 'SQLI' samples: {len(sqli_labeled)}")

    sqli_true_count = 0
    sqli_mislabeled_insertar_count = 0
    sqli_mislabeled_other_count = 0

    records: list[dict[str, Any]] = []
    group_a_count = 0
    group_b_count = 0
    category_counts: dict[str, int] = {}

    rule_engine = RuleEngine()
    ml_detector = MLDetector()
    anomaly_detector = AnomalyDetector()
    risk_engine = RiskEngine()
    decision_engine = DecisionEngine()

    group_a_blocked_loose = 0
    group_b_blocked_loose = 0
    total_blocked_loose = 0

    group_a_blocked_op = 0
    group_b_blocked_op = 0
    total_blocked_op = 0

    group_a_blocked_ml = 0
    total_blocked_ml = 0

    for idx, row in attacks_df.iterrows():
        path = str(row.get("path", "")).strip()
        query = str(row.get("query_params", "")).strip() if pd.notna(row.get("query_params")) else ""
        body = str(row.get("body", "")).strip() if pd.notna(row.get("body")) else ""
        orig_type = str(row.get("attack_type", ""))

        raw_req = f"{path} {query} {body}"
        tax = classify_payload_taxonomy(raw_req)

        if orig_type == "SQLI":
            if tax["is_sqli"]:
                sqli_true_count += 1
            elif tax["has_insertar"]:
                sqli_mislabeled_insertar_count += 1
            else:
                sqli_mislabeled_other_count += 1

        cat = tax["true_category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

        if tax["is_group_a"]:
            group_a_count += 1
        else:
            group_b_count += 1

        ml_pred, vec26, canon_payload = _run_ml_prediction(ml_detector, path, query, body)
        anom_pred = anomaly_detector.predict(canon_payload, feature_vector=vec26)
        det = rule_engine.inspect_request(
            path=path,
            query_params=query,
            body_bytes=body.encode("utf-8") if body else None,
        )

        rule_score = det.rule_risk_score
        ml_score = ml_pred.risk_score or 0.0
        anom_score = anom_pred.anomaly_score or 0.0

        rb = risk_engine.calculate_weighted_score(
            rule_score=rule_score,
            ml_score=ml_pred.risk_score,
            anomaly_score=anom_pred.anomaly_score,
            ablation_mode="hybrid",
        )
        dec = decision_engine.evaluate(risk_breakdown=rb, waf_mode="ACTIVE_BLOCKING")
        is_detected_op = bool(dec.is_blocked or dec.is_rate_limited)

        hybrid_risk = 0.40 * rule_score + 0.35 * ml_score + 0.25 * anom_score
        is_detected_loose = bool(
            rule_score >= 80.0
            or ml_pred.is_attack
            or (anom_score >= 60.0)
            or (hybrid_risk >= 50.0)
        )
        is_detected_ml = bool(ml_pred.is_attack)

        if is_detected_loose:
            total_blocked_loose += 1
            if tax["is_group_a"]:
                group_a_blocked_loose += 1
            else:
                group_b_blocked_loose += 1

        if is_detected_op:
            total_blocked_op += 1
            if tax["is_group_a"]:
                group_a_blocked_op += 1
            else:
                group_b_blocked_op += 1

        if is_detected_ml:
            total_blocked_ml += 1
            if tax["is_group_a"]:
                group_a_blocked_ml += 1

        records.append(
            {
                "index": int(idx),
                "orig_type": orig_type,
                "audited_category": cat,
                "detailed_subcategory": tax["detailed_subcategory"],
                "tier": tax["tier"],
                "is_detected_loose": is_detected_loose,
                "is_detected_op": is_detected_op,
                "is_detected_ml": is_detected_ml,
            }
        )

    # Evaluate Benign FPR (N=1,500)
    benign_fp_loose = 0
    benign_fp_op = 0
    benign_fp_ml = 0
    for _, row in benign_df.iterrows():
        path = str(row.get("path", "")).strip()
        query = str(row.get("query_params", "")).strip() if pd.notna(row.get("query_params")) else ""
        body = str(row.get("body", "")).strip() if pd.notna(row.get("body")) else ""

        ml_pred, vec26, canon_payload = _run_ml_prediction(ml_detector, path, query, body)
        anom_pred = anomaly_detector.predict(canon_payload, feature_vector=vec26)
        det = rule_engine.inspect_request(
            path=path,
            query_params=query,
            body_bytes=body.encode("utf-8") if body else None,
        )
        rule_score = det.rule_risk_score
        ml_score = ml_pred.risk_score or 0.0
        anom_score = anom_pred.anomaly_score or 0.0

        rb = risk_engine.calculate_weighted_score(
            rule_score=rule_score,
            ml_score=ml_pred.risk_score,
            anomaly_score=anom_pred.anomaly_score,
            ablation_mode="hybrid",
        )
        dec = decision_engine.evaluate(risk_breakdown=rb, waf_mode="ACTIVE_BLOCKING")
        if dec.is_blocked or dec.is_rate_limited:
            benign_fp_op += 1
        hybrid_risk = 0.40 * rule_score + 0.35 * ml_score + 0.25 * anom_score
        if rule_score >= 80.0 or ml_pred.is_attack or anom_score >= 60.0 or hybrid_risk >= 50.0:
            benign_fp_loose += 1
        if ml_pred.is_attack:
            benign_fp_ml += 1

    sqli_mislabeled_total = sqli_mislabeled_insertar_count + sqli_mislabeled_other_count
    sqli_mislabeled_pct = (sqli_mislabeled_total / len(sqli_labeled)) * 100.0 if len(sqli_labeled) else 0.0

    group_a_recall_loose = (group_a_blocked_loose / group_a_count * 100.0) if group_a_count else 0.0
    group_b_recall_loose = (group_b_blocked_loose / group_b_count * 100.0) if group_b_count else 0.0
    total_recall_loose = (total_blocked_loose / total_attacks * 100.0) if total_attacks else 0.0

    group_a_recall_op = (group_a_blocked_op / group_a_count * 100.0) if group_a_count else 0.0
    group_b_recall_op = (group_b_blocked_op / group_b_count * 100.0) if group_b_count else 0.0
    total_recall_op = (total_blocked_op / total_attacks * 100.0) if total_attacks else 0.0

    group_a_recall_ml = (group_a_blocked_ml / group_a_count * 100.0) if group_a_count else 0.0
    total_recall_ml = (total_blocked_ml / total_attacks * 100.0) if total_attacks else 0.0

    fpr_loose = (benign_fp_loose / total_benign * 100.0) if total_benign else 0.0
    fpr_op = (benign_fp_op / total_benign * 100.0) if total_benign else 0.0
    fpr_ml = (benign_fp_ml / total_benign * 100.0) if total_benign else 0.0

    sub_loose = _summarize_subcategories(records, "is_detected_loose")
    sub_op = _summarize_subcategories(records, "is_detected_op")
    sub_ml = _summarize_subcategories(records, "is_detected_ml")

    print("\n--- AUDIT RESULTS: ORIGINAL 254 'SQLI' LABELS ---")
    print(f"Total labeled 'SQLI': {len(sqli_labeled)}")
    print(f"  - Verified True SQLi (word boundary): {sqli_true_count} ({sqli_true_count/len(sqli_labeled)*100:.1f}%)")
    print(f"  - Mislabeled via 'modo=insertar':      {sqli_mislabeled_insertar_count}")
    print(f"  - Mislabeled other (no SQLi pattern): {sqli_mislabeled_other_count}")
    print(f"  -> Total False SQLI Subtype Labels:   {sqli_mislabeled_total}/{len(sqli_labeled)} ({sqli_mislabeled_pct:.1f}%)")

    print("\n--- TWO-TIER BREAKDOWN (1,500 TOTAL ATTACKS) ---")
    print(f"Group A (True Payload Attacks):      {group_a_count} ({group_a_count/total_attacks*100:.1f}%)")
    for cat in ["SQLI", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION"]:
        print(f"    - {cat:<18}: {category_counts.get(cat, 0)}")
    print("  Detailed Group A Sub-Categories:")
    for sub in GROUP_A_SUBCATEGORIES:
        s_o = sub_op[sub]
        s_l = sub_loose[sub]
        print(
            f"    - {sub:<22}: {s_o['total']:<4} | Op T=80: {s_o['blocked']}/{s_o['total']} ({s_o['recall_pct']:.1f}%) "
            f"| Loose: {s_l['blocked']}/{s_l['total']} ({s_l['recall_pct']:.1f}%)"
        )
    print(f"Group B (Parameter Tampering):      {group_b_count} ({group_b_count/total_attacks*100:.1f}%)")

    print("\n--- PARALLEL METRICS (OVERALL 1,500 vs GROUP A TRUE PAYLOAD) ---")
    print(f"Operational DecisionEngine T=80 : Overall={total_recall_op:.2f}% ({total_blocked_op}/{total_attacks}) | GroupA={group_a_recall_op:.2f}% ({group_a_blocked_op}/{group_a_count}) | Benign FPR={fpr_op:.2f}%")
    print(f"Loose Monitoring Criteria       : Overall={total_recall_loose:.2f}% ({total_blocked_loose}/{total_attacks}) | GroupA={group_a_recall_loose:.2f}% ({group_a_blocked_loose}/{group_a_count}) | Benign FPR={fpr_loose:.2f}%")
    print(f"Standalone Supervised ML        : Overall={total_recall_ml:.2f}% ({total_blocked_ml}/{total_attacks}) | GroupA={group_a_recall_ml:.2f}% ({group_a_blocked_ml}/{group_a_count}) | Benign FPR={fpr_ml:.2f}%")

    report_data: dict[str, Any] = {
        "metadata": {
            "dataset": "CSIC 2010 HTTP Dataset (csic_2010_benchmark.csv)",
            "model_path": str(ml_detector.model_path),
            "total_attack_samples": total_attacks,
            "total_benign_samples": total_benign,
            "audit_methodology": "Recursive unquote_plus (depth=3) + regex with strict word boundary (\\b)",
            "recall_metric_note": (
                "Reports BOTH loose monitoring criteria (rule >= 80 OR ml.is_attack OR anom >= 60.0 "
                "OR hybrid_risk >= 50.0) AND operational DecisionEngine T=80 across Overall 1,500 and Group A."
            ),
            "taxonomy_audit_note": (
                "Group A expanded from 196 (Phase D2) to 221 (Phase E3) strictly because recursive_urldecode switched from "
                "urllib.parse.unquote to urllib.parse.unquote_plus: decoding URL form '+' spaces revealed 25 additional genuine "
                "CSIC SQLi payloads (118 -> 143 SQLi, e.g. '1%27+OR+%271%27%3D%271' -> \"1' OR '1'='1\") previously masked "
                "under Group B Parameter Tampering. In addition, the 75-row legacy SQLI_BLIND_BOOLEAN slice includes 50 HTML SSI "
                "directives (<!--#EXEC / <!--#include) matched by the '--' comment token and is preserved intact for apples-to-apples "
                "before/after regression accounting alongside csic2010_blind_boolean_per_case_diff.json."
            ),
        },
        "reviewer_sqli_finding_verification": {
            "total_original_sqli_labeled": len(sqli_labeled),
            "true_sqli_count": sqli_true_count,
            "mislabeled_insertar_count": sqli_mislabeled_insertar_count,
            "mislabeled_other_count": sqli_mislabeled_other_count,
            "total_mislabeled_sqli": sqli_mislabeled_total,
            "mislabeled_pct": round(sqli_mislabeled_pct, 2),
            "verified_reviewer_number": sqli_mislabeled_total,
        },
        "two_tier_breakdown": {
            "group_a_true_payload": {
                "count": group_a_count,
                "percentage": round(group_a_count / total_attacks * 100.0, 2),
                "categories": {
                    cat: category_counts.get(cat, 0)
                    for cat in ["SQLI", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION"]
                },
                "blocked": group_a_blocked_loose,
                "recall_pct": round(group_a_recall_loose, 2),
                "detection_recall_loose_pct": round(group_a_recall_loose, 2),
                "blocked_operational_t80": group_a_blocked_op,
                "operational_t80_recall_pct": round(group_a_recall_op, 2),
                "blocked_standalone_ml": group_a_blocked_ml,
                "standalone_ml_recall_pct": round(group_a_recall_ml, 2),
            },
            "group_b_parameter_tampering": {
                "count": group_b_count,
                "percentage": round(group_b_count / total_attacks * 100.0, 2),
                "categories": {
                    "PARAMETER_TAMPERING": category_counts.get("PARAMETER_TAMPERING", 0)
                },
                "blocked": group_b_blocked_loose,
                "recall_pct": round(group_b_recall_loose, 2),
                "blocked_operational_t80": group_b_blocked_op,
                "operational_t80_recall_pct": round(group_b_recall_op, 2),
            },
            "total_overall": {
                "count": total_attacks,
                "blocked": total_blocked_loose,
                "recall_pct": round(total_recall_loose, 2),
                "blocked_operational_t80": total_blocked_op,
                "operational_t80_recall_pct": round(total_recall_op, 2),
                "blocked_standalone_ml": total_blocked_ml,
                "standalone_ml_recall_pct": round(total_recall_ml, 2),
            },
        },
        "parallel_metrics": {
            "benign_fpr_target_pct": 0.5,
            "operational_decision_engine_t80": {
                "overall_1500_recall_pct": round(total_recall_op, 2),
                "overall_1500_blocked": total_blocked_op,
                "group_a_recall_pct": round(group_a_recall_op, 2),
                "group_a_blocked": group_a_blocked_op,
                "group_b_recall_pct": round(group_b_recall_op, 2),
                "benign_fpr_pct": round(fpr_op, 2),
                "benign_fp_count": benign_fp_op,
                "fpr_within_target": fpr_op <= 0.5,
            },
            "loose_monitoring": {
                "overall_1500_recall_pct": round(total_recall_loose, 2),
                "overall_1500_blocked": total_blocked_loose,
                "group_a_recall_pct": round(group_a_recall_loose, 2),
                "group_a_blocked": group_a_blocked_loose,
                "group_b_recall_pct": round(group_b_recall_loose, 2),
                "benign_fpr_pct": round(fpr_loose, 2),
                "benign_fp_count": benign_fp_loose,
                "fpr_within_target": fpr_loose <= 0.5,
            },
            "standalone_ml": {
                "overall_1500_recall_pct": round(total_recall_ml, 2),
                "overall_1500_blocked": total_blocked_ml,
                "group_a_recall_pct": round(group_a_recall_ml, 2),
                "group_a_blocked": group_a_blocked_ml,
                "benign_fpr_pct": round(fpr_ml, 2),
                "benign_fp_count": benign_fp_ml,
                "fpr_within_target": fpr_ml <= 0.5,
            },
        },
        "detailed_subcategory_breakdown": {
            "operational_t80": sub_op,
            "loose_monitoring": sub_loose,
            "standalone_ml": sub_ml,
        },
    }

    if save_before:
        BEFORE_JSON.parent.mkdir(parents=True, exist_ok=True)
        BEFORE_JSON.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[OK] Pre-Phase-E baseline saved to: {BEFORE_JSON}")
        return report_data

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[OK] Taxonomy breakdown saved to: {OUTPUT_JSON}")

    if BEFORE_JSON.is_file():
        before_data = json.loads(BEFORE_JSON.read_text(encoding="utf-8"))
        comparison = _build_phase_e_comparison(before_data, report_data)
        COMPARISON_JSON.write_text(json.dumps(comparison, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] Before vs After comparison saved to: {COMPARISON_JSON}")

    return report_data


def _build_phase_e_comparison(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Builds Before vs After comparison across Overall 1,500, Group A, and sub-categories."""
    b_pm = before.get("parallel_metrics", {})
    a_pm = after.get("parallel_metrics", {})

    def _delta_section(sec_key: str) -> dict[str, Any]:
        b_s = b_pm.get(sec_key, {})
        a_s = a_pm.get(sec_key, {})
        return {
            "before": b_s,
            "after": a_s,
            "delta_overall_1500_recall_pp": round(
                float(a_s.get("overall_1500_recall_pct", 0.0))
                - float(b_s.get("overall_1500_recall_pct", 0.0)),
                2,
            ),
            "delta_group_a_recall_pp": round(
                float(a_s.get("group_a_recall_pct", 0.0))
                - float(b_s.get("group_a_recall_pct", 0.0)),
                2,
            ),
            "delta_benign_fpr_pp": round(
                float(a_s.get("benign_fpr_pct", 0.0))
                - float(b_s.get("benign_fpr_pct", 0.0)),
                2,
            ),
        }

    sub_cmp: dict[str, Any] = {}
    for mode in ("operational_t80", "loose_monitoring", "standalone_ml"):
        b_sub = before.get("detailed_subcategory_breakdown", {}).get(mode, {})
        a_sub = after.get("detailed_subcategory_breakdown", {}).get(mode, {})
        sub_cmp[mode] = {}
        for sub in (*GROUP_A_SUBCATEGORIES, "PARAMETER_TAMPERING"):
            b_rec = float(b_sub.get(sub, {}).get("recall_pct", 0.0))
            a_rec = float(a_sub.get(sub, {}).get("recall_pct", 0.0))
            sub_cmp[mode][sub] = {
                "total": a_sub.get(sub, {}).get("total", 0),
                "before_blocked": b_sub.get(sub, {}).get("blocked", 0),
                "after_blocked": a_sub.get(sub, {}).get("blocked", 0),
                "before_recall_pct": b_rec,
                "after_recall_pct": a_rec,
                "delta_pp": round(a_rec - b_rec, 2),
            }

    return {
        "metadata": {
            "baseline_note": (
                "before = pre-Phase E baseline commit 2a3969f (NOT Phase E R1 fb2fe46); "
                "after = current post-fix measurement"
            ),
            "before_model_path": before.get("metadata", {}).get("model_path"),
            "after_model_path": after.get("metadata", {}).get("model_path"),
            "total_attack_samples": after.get("metadata", {}).get("total_attack_samples"),
            "group_a_total": after.get("two_tier_breakdown", {}).get("group_a_true_payload", {}).get("count"),
            "group_b_total": after.get("two_tier_breakdown", {}).get("group_b_parameter_tampering", {}).get("count"),
            "total_benign_samples": after.get("metadata", {}).get("total_benign_samples"),
        },
        "parallel_metrics_comparison": {
            "operational_decision_engine_t80": _delta_section("operational_decision_engine_t80"),
            "loose_monitoring": _delta_section("loose_monitoring"),
            "standalone_ml": _delta_section("standalone_ml"),
        },
        "per_subcategory_comparison": sub_cmp,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit CSIC 2010 taxonomy and parallel recall metrics")
    parser.add_argument(
        "--save-before",
        action="store_true",
        help="Save baseline metrics snapshot to docs/reports/csic2010_phase_e_before.json",
    )
    args = parser.parse_args()
    audit_csic2010(save_before=args.save_before)


if __name__ == "__main__":
    main()
