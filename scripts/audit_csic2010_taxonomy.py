"""Audit and re-classify CSIC 2010 dataset taxonomy (Phase D - D2 / SCI-PBL6-003).

Investigates:
1. Reviewer finding: substring matching 'insert' in 'modo=insertar' falsely inflated SQLi labels.
2. Two-tier breakdown:
   - Group A (True Payload Attacks): SQLi, XSS, Path Traversal, Command/SSI injection.
   - Group B (Parameter Tampering): Business-logic/form deviations on 2010 JSP application.
3. Does NOT modify the original frozen benchmark CSV (benchmark integrity preserved).
4. Outputs comprehensive audit report to docs/reports/csic2010_taxonomy_breakdown.json.
"""

from __future__ import annotations

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
from app.security.engine import RuleEngine  # noqa: E402
from app.security.ml_detector import MLDetector  # noqa: E402
from features.extractor import extract_26_from_http  # noqa: E402

BENCHMARK_CSV = ROOT_DIR / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv"
OUTPUT_JSON = ROOT_DIR / "docs" / "reports" / "csic2010_taxonomy_breakdown.json"


def recursive_urldecode(s: str, max_depth: int = 3) -> str:
    """Recursively decodes URL-encoded strings up to max_depth levels."""
    curr = str(s)
    for _ in range(max_depth):
        dec = urllib.parse.unquote(curr)
        if dec == curr:
            break
        curr = dec
    return curr


# Authentic Injection Patterns with strict word boundaries (\b)
_TRUE_SQLI_RE = re.compile(
    r"""(?i)(?:\b(?:union\s+(?:all\s+|distinct\s+)?select|select\b.+?\bfrom|insert\s+into\b|drop\s+table\b|drop\s+database\b|waitfor\s+(?:delay|time)\b|benchmark\s*\(|sleep\s*\(|load_file\s*\(|into\s+(?:outfile|dumpfile))\b|--|/\*|(?:\b(?:or|and)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?|\b(?:or|and)\s+\d+\s*=\s*\d+)|\b(?:or|and)\s+[0-9\s+\-*\/]+?\s*(=|!=|<>|\blike\b)\s*[0-9\s+\-*\/]+)""",
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
    """Classifies an attack request into Group A (True Payload) or Group B (Parameter Tampering)."""
    decoded = recursive_urldecode(raw_text)

    is_sqli = bool(_TRUE_SQLI_RE.search(decoded))
    is_xss = bool(_TRUE_XSS_RE.search(decoded))
    is_path = bool(_TRUE_PATH_RE.search(decoded))
    is_cmd = bool(_TRUE_CMD_RE.search(decoded))

    has_insertar = "insertar" in decoded.lower()
    has_raw_insert = "insert" in decoded.lower()

    if is_sqli:
        detected_category = "SQLI"
    elif is_xss:
        detected_category = "XSS"
    elif is_path:
        detected_category = "PATH_TRAVERSAL"
    elif is_cmd:
        detected_category = "COMMAND_INJECTION"
    else:
        detected_category = "PARAMETER_TAMPERING"

    is_group_a = detected_category in ("SQLI", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION")
    tier = "Group A (True Payload)" if is_group_a else "Group B (Parameter Tampering)"

    return {
        "tier": tier,
        "is_group_a": is_group_a,
        "true_category": detected_category,
        "is_sqli": is_sqli,
        "is_xss": is_xss,
        "is_path": is_path,
        "is_cmd": is_cmd,
        "has_insertar": has_insertar,
        "has_raw_insert": has_raw_insert,
    }


def audit_csic2010() -> dict[str, Any]:
    print("=" * 80)
    print("  CSIC 2010 TAXONOMY AUDIT & TWO-TIER BREAKDOWN (Task D2)")
    print("=" * 80)
    print(f"Loading dataset from: {BENCHMARK_CSV}")

    df = pd.read_csv(BENCHMARK_CSV)
    attacks_df = df[df["label"].astype(int) == 1].copy()
    benign_df = df[df["label"].astype(int) == 0].copy()

    total_attacks = len(attacks_df)
    total_benign = len(benign_df)
    print(f"Loaded {len(df)} total samples ({total_benign} Benign, {total_attacks} Attacks).\n")

    # Audit the legacy labeled SQLI rows
    sqli_labeled = attacks_df[attacks_df["attack_type"] == "SQLI"]
    print(f"Original CSIC labeled 'SQLI' samples: {len(sqli_labeled)}")

    sqli_true_count = 0
    sqli_mislabeled_insertar_count = 0
    sqli_mislabeled_other_count = 0

    records = []
    group_a_count = 0
    group_b_count = 0
    category_counts: dict[str, int] = {}

    # Initialize engines for detection evaluation
    rule_engine = RuleEngine()
    ml_detector = MLDetector()
    anomaly_detector = AnomalyDetector()

    group_a_blocked = 0
    group_b_blocked = 0
    total_blocked = 0

    for idx, row in attacks_df.iterrows():
        path = str(row.get("path", "")).strip()
        query = str(row.get("query_params", "")).strip() if pd.notna(row.get("query_params")) else ""
        body = str(row.get("body", "")).strip() if pd.notna(row.get("body")) else ""
        orig_type = str(row.get("attack_type", ""))

        raw_req = f"{path} {query} {body}"
        tax = classify_payload_taxonomy(raw_req)

        # Audit SQLI legacy label
        if orig_type == "SQLI":
            if tax["is_sqli"]:
                sqli_true_count += 1
            else:
                if tax["has_insertar"]:
                    sqli_mislabeled_insertar_count += 1
                else:
                    sqli_mislabeled_other_count += 1

        cat = tax["true_category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

        if tax["is_group_a"]:
            group_a_count += 1
        else:
            group_b_count += 1

        # Evaluate detection with current hybrid engine
        vec26 = extract_26_from_http(path=path, query_params=query, body=body).tolist()
        payload = f"{path} {query} {body}".strip()
        ml_pred = ml_detector.predict(payload, feature_vector=vec26)
        anom_pred = anomaly_detector.predict(payload, feature_vector=vec26)
        det = rule_engine.inspect_request(path=path, query_params=query, body_bytes=body.encode("utf-8") if body else None)

        rule_score = det.rule_risk_score
        ml_score = ml_pred.risk_score or 0.0
        anom_score = anom_pred.anomaly_score or 0.0

        hybrid_risk = 0.40 * rule_score + 0.35 * ml_score + 0.25 * anom_score
        is_detected_loose = bool(
            rule_score >= 80.0
            or ml_pred.is_attack
            or (anom_score >= 60.0)
            or (hybrid_risk >= 50.0)
        )

        if is_detected_loose:
            total_blocked += 1
            if tax["is_group_a"]:
                group_a_blocked += 1
            else:
                group_b_blocked += 1

        records.append({
            "index": int(idx),
            "orig_type": orig_type,
            "audited_category": cat,
            "tier": tax["tier"],
            "is_detected_loose": is_detected_loose,
        })

    sqli_mislabeled_total = sqli_mislabeled_insertar_count + sqli_mislabeled_other_count
    sqli_mislabeled_pct = (sqli_mislabeled_total / len(sqli_labeled)) * 100.0 if len(sqli_labeled) else 0.0

    group_a_recall = (group_a_blocked / group_a_count * 100.0) if group_a_count else 0.0
    group_b_recall = (group_b_blocked / group_b_count * 100.0) if group_b_count else 0.0
    total_recall = (total_blocked / total_attacks * 100.0) if total_attacks else 0.0

    print("\n--- AUDIT RESULTS: ORIGINAL 254 'SQLI' LABELS ---")
    print(f"Total labeled 'SQLI': {len(sqli_labeled)}")
    print(f"  - Verified True SQLi (word boundary): {sqli_true_count} ({sqli_true_count/len(sqli_labeled)*100:.1f}%)")
    print(f"  - Mislabeled via 'modo=insertar':      {sqli_mislabeled_insertar_count}")
    print(f"  - Mislabeled other (no SQLi pattern): {sqli_mislabeled_other_count}")
    print(f"  -> Total False SQLI Subtype Labels:   {sqli_mislabeled_total}/{len(sqli_labeled)} ({sqli_mislabeled_pct:.1f}%)")
    print(f"  -> Matches Reviewer Finding (~134/254): {sqli_mislabeled_total == 134 or abs(sqli_mislabeled_total - 134) <= 5} (Exact count: {sqli_mislabeled_total})")

    print("\n--- TWO-TIER BREAKDOWN (1,500 TOTAL ATTACKS) ---")
    print(f"Group A (True Payload Attacks):      {group_a_count} ({group_a_count/total_attacks*100:.1f}%)")
    for cat in ["SQLI", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION"]:
        cnt = category_counts.get(cat, 0)
        print(f"    - {cat:<18}: {cnt}")
    print(f"Group B (Parameter Tampering):      {group_b_count} ({group_b_count/total_attacks*100:.1f}%)")
    print(f"    - PARAMETER_TAMPERING: {category_counts.get('PARAMETER_TAMPERING', 0)}")

    print("\n--- DETECTION RECALL BREAKDOWN ---")
    print(f"Group A True Payload Recall:        {group_a_recall:.2f}% ({group_a_blocked}/{group_a_count})")
    print(f"Group B Parameter Tampering Recall: {group_b_recall:.2f}% ({group_b_blocked}/{group_b_count})")
    print(f"Total CSIC Overall Recall:          {total_recall:.2f}% ({total_blocked}/{total_attacks})")

    report_data = {
        "metadata": {
            "dataset": "CSIC 2010 HTTP Dataset (csic_2010_benchmark.csv)",
            "total_attack_samples": total_attacks,
            "total_benign_samples": total_benign,
            "audit_methodology": "Recursive URL-decode (depth=3) + regex with strict word boundary (\\b)",
            "recall_metric_note": (
                "detection_recall_loose uses broad security monitoring criteria "
                "(rule_score >= 80 OR ml.is_attack OR anom >= 60.0 OR hybrid_risk >= 50.0). "
                "This is distinct from operational block recall under DecisionEngine T=80 (85.71%, 168/196)."
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
                "blocked": group_a_blocked,
                "recall_pct": round(group_a_recall, 2),
                "detection_recall_loose_pct": round(group_a_recall, 2),
            },
            "group_b_parameter_tampering": {
                "count": group_b_count,
                "percentage": round(group_b_count / total_attacks * 100.0, 2),
                "categories": {
                    "PARAMETER_TAMPERING": category_counts.get("PARAMETER_TAMPERING", 0)
                },
                "blocked": group_b_blocked,
                "recall_pct": round(group_b_recall, 2),
            },
            "total_overall": {
                "count": total_attacks,
                "blocked": total_blocked,
                "recall_pct": round(total_recall, 2),
            },
        },
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[OK] Taxonomy breakdown saved to: {OUTPUT_JSON}")
    return report_data


if __name__ == "__main__":
    audit_csic2010()
