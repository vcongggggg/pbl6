"""E3 Secondary Experiment: CSIC 2010 /tienda1 Positive Security Schema Proof.

Generates (when --generate-schema is passed) `data/schemas/csic2010_tienda1_openapi.json`
STRICTLY from the 1,500 Benign (label == 0) CSIC 2010 rows (zero inspection of label == 1),
then evaluates all 3,000 CSIC 2010 rows comparing:
  - baseline_hybrid_schema_off
  - hybrid_plus_tienda1_schema_strict (SchemaValidator strict_all with /tienda1 OpenAPI spec)

Writes `docs/reports/csic2010_tienda1_schema_proof.json`.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
for _p in (str(ROOT_DIR / "gateway"), str(ROOT_DIR / "ml-engine"), str(ROOT_DIR / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app.security.anomaly import AnomalyDetector  # noqa: E402
from app.security.decision import DecisionEngine  # noqa: E402
from app.security.engine import RuleEngine  # noqa: E402
from app.security.ml_detector import MLDetector  # noqa: E402
from app.security.risk_engine import RiskEngine  # noqa: E402
from app.security.schema_validator import SchemaValidator  # noqa: E402
from audit_csic2010_taxonomy import classify_payload_taxonomy  # noqa: E402
from features.canonicalizer import canonicalize_http_request  # noqa: E402
from features.extractor import extract_26_from_http  # noqa: E402

try:
    from features.canonicalizer import normalize_http_for_ml  # type: ignore[attr-defined]
except ImportError:
    normalize_http_for_ml = None

BENCHMARK_CSV = ROOT_DIR / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv"
SCHEMA_JSON = ROOT_DIR / "data" / "schemas" / "csic2010_tienda1_openapi.json"
PROOF_JSON = ROOT_DIR / "docs" / "reports" / "csic2010_tienda1_schema_proof.json"

_INT_RE = re.compile(r"^-?\d+$")


def _infer_param_schema(values: list[str]) -> dict[str, Any]:
    """Infers OpenAPI scalar schema strictly from observed benign values."""
    non_empty = [v for v in values if v != ""]
    is_int = bool(non_empty) and all(bool(_INT_RE.match(v.strip())) for v in non_empty)
    max_len = max((len(v) for v in values), default=1)
    headroom_max_len = max(2, int(math.ceil(max_len * 1.5)))
    return {
        "type": "integer" if is_int else "string",
        "maxLength": headroom_max_len,
    }


def generate_tienda1_openapi_from_benign(
    csv_path: Path = BENCHMARK_CSV,
    out_path: Path = SCHEMA_JSON,
) -> dict[str, Any]:
    """Generates OpenAPI 3.0.3 schema for /tienda1 strictly from label == 0 (Benign) rows."""
    df = pd.read_csv(csv_path)
    # STRICT ZERO-LEAKAGE GUARD: ONLY label == 0 benign traffic may be inspected
    benign_df = df[df["label"].astype(int) == 0].copy()

    op_stats: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    for _, row in benign_df.iterrows():
        path = str(row["path"]).strip()
        method = str(row["method"]).strip().lower()
        query = str(row["query_params"]).strip() if pd.notna(row["query_params"]) else ""
        body = str(row["body"]).strip() if pd.notna(row["body"]) else ""

        if method not in op_stats[path]:
            op_stats[path][method] = {
                "count": 0,
                "query_values": defaultdict(list),
                "query_presence": Counter(),
                "form_values": defaultdict(list),
                "form_presence": Counter(),
                "has_body_count": 0,
            }

        entry = op_stats[path][method]
        entry["count"] += 1

        if query:
            parsed_q = parse_qs(query, keep_blank_values=True)
            for k, vs in parsed_q.items():
                entry["query_presence"][k] += 1
                entry["query_values"][k].extend(vs)

        if body:
            entry["has_body_count"] += 1
            parsed_f = parse_qs(body, keep_blank_values=True)
            for k, vs in parsed_f.items():
                entry["form_presence"][k] += 1
                entry["form_values"][k].extend(vs)

    paths_spec: dict[str, Any] = {}
    for path in sorted(op_stats):
        paths_spec[path] = {}
        for method in sorted(op_stats[path]):
            entry = op_stats[path][method]
            op_count = entry["count"]
            op_obj: dict[str, Any] = {
                "summary": f"CSIC 2010 Benign Endpoint ({method.upper()} {path})",
                "responses": {"200": {"description": "OK"}},
            }

            if entry["query_values"]:
                params = []
                for param_name in sorted(entry["query_values"]):
                    vals = entry["query_values"][param_name]
                    is_req = entry["query_presence"][param_name] == op_count
                    params.append(
                        {
                            "name": param_name,
                            "in": "query",
                            "required": is_req,
                            "schema": _infer_param_schema(vals),
                        }
                    )
                op_obj["parameters"] = params

            if entry["form_values"]:
                props: dict[str, Any] = {}
                required_fields: list[str] = []
                for field_name in sorted(entry["form_values"]):
                    vals = entry["form_values"][field_name]
                    props[field_name] = _infer_param_schema(vals)
                    if entry["form_presence"][field_name] == op_count:
                        required_fields.append(field_name)

                form_schema: dict[str, Any] = {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": props,
                }
                if required_fields:
                    form_schema["required"] = required_fields

                op_obj["requestBody"] = {
                    "required": entry["has_body_count"] == op_count,
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": form_schema,
                        }
                    },
                }

            paths_spec[path][method] = op_obj

    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "CSIC 2010 Tienda1 Web Application (Benign-Derived Positive Security Schema)",
            "version": "1.0.0",
            "x_derived_from": "csic_2010_benchmark.csv label==0 ONLY (1500 benign requests)",
            "x_max_length_headroom_multiplier": 1.5,
        },
        "paths": paths_spec,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    return spec


def _extract_content_type(raw_headers: Any) -> str | None:
    if pd.isna(raw_headers) or not raw_headers:
        return None
    try:
        hdrs = json.loads(str(raw_headers))
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if str(k).lower() == "content-type":
                    return str(v)
    except Exception:
        pass
    return None


def _compute_tier_metrics(records: list[dict[str, Any]], pred_key: str) -> dict[str, Any]:
    attacks = [r for r in records if r["true_label"] == 1]
    benign = [r for r in records if r["true_label"] == 0]
    group_a = [r for r in attacks if r["is_group_a"]]
    group_b = [r for r in attacks if not r["is_group_a"]]

    tp = sum(1 for r in attacks if r[pred_key])
    fn = len(attacks) - tp
    fp = sum(1 for r in benign if r[pred_key])
    tn = len(benign) - fp

    ga_tp = sum(1 for r in group_a if r[pred_key])
    gb_tp = sum(1 for r in group_b if r[pred_key])

    overall_rec = (tp / len(attacks) * 100.0) if attacks else 0.0
    ga_rec = (ga_tp / len(group_a) * 100.0) if group_a else 0.0
    gb_rec = (gb_tp / len(group_b) * 100.0) if group_b else 0.0
    fpr = (fp / len(benign) * 100.0) if benign else 0.0
    prec = (tp / (tp + fp) * 100.0) if (tp + fp) else 0.0
    f1 = (2 * prec * overall_rec / (prec + overall_rec)) if (prec + overall_rec) else 0.0
    acc = ((tp + tn) / len(records) * 100.0) if records else 0.0

    return {
        "overall_1500": {
            "tp": tp,
            "fn": fn,
            "recall_pct": round(overall_rec, 2),
        },
        "group_a_true_payload": {
            "tp": ga_tp,
            "total": len(group_a),
            "recall_pct": round(ga_rec, 2),
        },
        "group_b_parameter_tampering": {
            "tp": gb_tp,
            "total": len(group_b),
            "recall_pct": round(gb_rec, 2),
        },
        "benign_1500": {
            "tn": tn,
            "fp": fp,
            "fpr_pct": round(fpr, 2),
        },
        "precision_pct": round(prec, 2),
        "f1_score_pct": round(f1, 2),
        "accuracy_pct": round(acc, 2),
    }


def run_experiment() -> dict[str, Any]:
    if not SCHEMA_JSON.is_file():
        generate_tienda1_openapi_from_benign()

    spec = json.loads(SCHEMA_JSON.read_text(encoding="utf-8"))
    df = pd.read_csv(BENCHMARK_CSV)

    rule_engine = RuleEngine()
    ml_detector = MLDetector()
    anomaly_detector = AnomalyDetector()
    risk_engine = RiskEngine()
    decision_engine = DecisionEngine()
    schema_validator = SchemaValidator(
        spec=spec,
        enforcement_policy="strict_all",
        strict_route_prefixes=("/tienda1",),
    )

    records: list[dict[str, Any]] = []
    violation_counts: Counter[str] = Counter()
    benign_violation_counts: Counter[str] = Counter()

    t0 = time.perf_counter()
    for _, row in df.iterrows():
        method = str(row.get("method", "GET")).strip().upper()
        path = str(row.get("path", "")).strip()
        query = str(row.get("query_params", "")).strip() if pd.notna(row.get("query_params")) else ""
        body = str(row.get("body", "")).strip() if pd.notna(row.get("body")) else ""
        true_label = int(row["label"])
        content_type = _extract_content_type(row.get("headers"))

        is_group_a = False
        true_cat = "BENIGN"
        if true_label == 1:
            tax = classify_payload_taxonomy(f"{path} {query} {body}")
            is_group_a = bool(tax["is_group_a"])
            true_cat = str(tax["true_category"])

        # Hybrid inference (predict_http if available from Phase E, else canonical extract_26_from_http)
        if callable(getattr(ml_detector, "predict_http", None)):
            ml_out = ml_detector.predict_http(path=path, query_params=query, body=body)
            if isinstance(ml_out, tuple) and len(ml_out) == 2:
                ml_res, vec26 = ml_out
            else:
                ml_res = ml_out
                vec26 = ml_res.feature_vector or extract_26_from_http(
                    path=path, query_params=query, body=body
                ).tolist()
            if normalize_http_for_ml is not None:
                np_, nq_, nb_ = normalize_http_for_ml(path=path, query_params=query, body=body)
                canon_payload = canonicalize_http_request(path=np_, query_params=nq_, body=nb_)
            else:
                canon_payload = canonicalize_http_request(path=path, query_params=query, body=body)
        else:
            if normalize_http_for_ml is not None:
                np_, nq_, nb_ = normalize_http_for_ml(path=path, query_params=query, body=body)
            else:
                np_, nq_, nb_ = path, query, body
            vec26 = extract_26_from_http(path=np_, query_params=nq_, body=nb_).tolist()
            canon_payload = canonicalize_http_request(path=np_, query_params=nq_, body=nb_)
            ml_res = ml_detector.predict(canon_payload, feature_vector=vec26)

        anom_res = anomaly_detector.predict(canon_payload, feature_vector=vec26)
        rule_res = rule_engine.inspect_request(
            path=path,
            query_params=query,
            body_bytes=body.encode("utf-8") if body else None,
        )

        rb = risk_engine.calculate_weighted_score(
            rule_score=rule_res.rule_risk_score,
            ml_score=ml_res.risk_score,
            anomaly_score=anom_res.anomaly_score,
            ablation_mode="hybrid",
        )
        dec = decision_engine.evaluate(risk_breakdown=rb, waf_mode="ACTIVE_BLOCKING")

        is_base_op = bool(dec.is_blocked or dec.is_rate_limited)
        is_base_loose = bool(
            rule_res.rule_risk_score >= 80.0
            or ml_res.is_attack
            or (anom_res.anomaly_score is not None and anom_res.anomaly_score >= 60.0)
            or rb.weighted_score >= 50.0
        )

        # Positive Security SchemaValidator (/tienda1 strict_all)
        sv_violations = schema_validator.validate_request(
            method=method,
            path=path,
            query_params=query or None,
            body_bytes=body.encode("utf-8") if body else None,
            content_type=content_type,
        )
        schema_penalty = any(v.is_penalty for v in sv_violations)
        for v in sv_violations:
            if v.is_penalty:
                if true_label == 1:
                    violation_counts[v.violation_type] += 1
                else:
                    benign_violation_counts[v.violation_type] += 1

        records.append(
            {
                "true_label": true_label,
                "is_group_a": is_group_a,
                "true_cat": true_cat,
                "base_op": is_base_op,
                "base_loose": is_base_loose,
                "schema_op": is_base_op or schema_penalty,
                "schema_loose": is_base_loose or schema_penalty,
                "schema_only": schema_penalty,
            }
        )

    elapsed = time.perf_counter() - t0

    report = {
        "metadata": {
            "experiment": "E3 Secondary Experiment: CSIC 2010 /tienda1 Positive Security Schema Proof",
            "dataset": str(BENCHMARK_CSV.relative_to(ROOT_DIR)),
            "schema_path": str(SCHEMA_JSON.relative_to(ROOT_DIR)),
            "schema_derivation_policy": "Strictly label == 0 (1,500 benign requests) ONLY; zero label == 1 leakage.",
            "enforcement_policy": "strict_all",
            "strict_route_prefixes": list(schema_validator.strict_route_prefixes),
            "total_samples": len(records),
            "duration_seconds": round(elapsed, 2),
        },
        "operational_decision_engine_t80": {
            "baseline_hybrid_schema_off": _compute_tier_metrics(records, "base_op"),
            "hybrid_plus_tienda1_schema_strict": _compute_tier_metrics(records, "schema_op"),
        },
        "loose_monitoring_criteria": {
            "baseline_hybrid_schema_off": _compute_tier_metrics(records, "base_loose"),
            "hybrid_plus_tienda1_schema_strict": _compute_tier_metrics(records, "schema_loose"),
        },
        "schema_only_strict_all": _compute_tier_metrics(records, "schema_only"),
        "schema_violation_breakdown": {
            "attack_penalty_counts": dict(violation_counts.most_common()),
            "benign_penalty_counts": dict(benign_violation_counts.most_common()),
        },
    }

    PROOF_JSON.parent.mkdir(parents=True, exist_ok=True)
    PROOF_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="CSIC 2010 /tienda1 OpenAPI Schema Proof")
    parser.add_argument(
        "--generate-schema",
        action="store_true",
        help="Regenerate data/schemas/csic2010_tienda1_openapi.json strictly from benign CSIC rows",
    )
    parser.add_argument(
        "--schema-only",
        action="store_true",
        help="Only generate the OpenAPI schema without running the full benchmark",
    )
    args = parser.parse_args()

    if args.generate_schema or not SCHEMA_JSON.is_file():
        spec = generate_tienda1_openapi_from_benign()
        print(f"[OK] Generated {SCHEMA_JSON} with {len(spec['paths'])} /tienda1 paths (benign-only).")
        if args.schema_only:
            return

    rep = run_experiment()
    b_op = rep["operational_decision_engine_t80"]["baseline_hybrid_schema_off"]
    s_op = rep["operational_decision_engine_t80"]["hybrid_plus_tienda1_schema_strict"]
    print("=" * 80)
    print("  CSIC 2010 /tienda1 SCHEMA PROOF (Operational DecisionEngine T=80)")
    print("=" * 80)
    print(
        f"Baseline (Schema OFF): Overall={b_op['overall_1500']['recall_pct']}% | "
        f"GroupA={b_op['group_a_true_payload']['recall_pct']}% | "
        f"GroupB={b_op['group_b_parameter_tampering']['recall_pct']}% | "
        f"Benign FPR={b_op['benign_1500']['fpr_pct']}%"
    )
    print(
        f"+ /tienda1 Schema ON : Overall={s_op['overall_1500']['recall_pct']}% | "
        f"GroupA={s_op['group_a_true_payload']['recall_pct']}% | "
        f"GroupB={s_op['group_b_parameter_tampering']['recall_pct']}% | "
        f"Benign FPR={s_op['benign_1500']['fpr_pct']}%"
    )
    print(f"[OK] Saved proof report to: {PROOF_JSON}")


if __name__ == "__main__":
    main()
