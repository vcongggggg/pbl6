"""Train Defense ML Models v2.0 (Champion XGBoost UBJSON + Calibrated IsolationForest v2).

Conforms to:
- Task: pbl6-blueteam-v2-sprint2-ml-v2
- 26-Dimensional Unified Canonical Feature Extraction (f1-f26)
- 5-Model Benchmark: LogisticRegression, DecisionTree, RandomForest, XGBoost, LightGBM
- Champion Cost-Sensitive Regularized XGBoost exported to UBJSON (Zero Pickle Vulnerability)
- RobustScaler + IsolationForest v2 with Empirical Percentile Calibration
- Benchmark 1000 Diverse Anomaly Recall >= 50%
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import RobustScaler
from sklearn.tree import DecisionTreeClassifier

# Add ml-engine to sys.path
MODEL_DIR = Path(__file__).resolve().parent
ML_ENGINE_DIR = MODEL_DIR.parent
REPO_ROOT = ML_ENGINE_DIR.parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.extractor import (  # noqa: E402
    CANONICAL_FEATURE_NAMES_V2,
    extract_batch_26_vectors,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("waf.ml_engine.train_defense_v2")

CANONICAL_CLASSES = [
    "BENIGN",
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "SQL_INJECTION",
    "XSS",
]
CLASS_TO_INT = {name: idx for idx, name in enumerate(CANONICAL_CLASSES)}


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hex digest of file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def extract_features_and_labels(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Extracts 26-D feature matrix X and integer class labels y."""
    logger.info(f"Extracting 26-D features for {len(df)} samples...")
    t0 = time.perf_counter()
    records = df.to_dict(orient="records")
    X = extract_batch_26_vectors(records)
    elapsed = time.perf_counter() - t0
    logger.info(f"Feature extraction completed in {elapsed:.2f}s ({len(df)/max(1e-5, elapsed):.1f} req/s). Shape: {X.shape}")

    y = np.array([CLASS_TO_INT[str(row.get("attack_type", "BENIGN")).strip().upper()] for _, row in df.iterrows()], dtype=int)
    return X, y


def benchmark_candidate_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
) -> dict[str, dict[str, float]]:
    """Benchmarks 5 candidate classifiers on validation set."""
    logger.info(">>> Benchmarking 5 Candidate Classifiers on 26-D Canonical Features <<<")
    candidates: dict[str, Any] = {
        "LogisticRegression": LogisticRegression(max_iter=300, random_state=42),
        "DecisionTree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=14, random_state=42, n_jobs=-1),
        "XGBoost": xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.08,
            random_state=42,
            n_jobs=-1,
            eval_metric="mlogloss",
        ),
        "LightGBM": lgb.LGBMClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.08,
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        ),
    }

    results: dict[str, dict[str, float]] = {}
    for name, model in candidates.items():
        t_start = time.perf_counter()
        model.fit(X_train, y_train)
        fit_time = time.perf_counter() - t_start

        t_pred = time.perf_counter()
        y_pred = model.predict(X_val)
        pred_time = (time.perf_counter() - t_pred) * 1000 / len(X_val)  # ms per sample

        acc = accuracy_score(y_val, y_pred)
        prec = precision_score(y_val, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_val, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_val, y_pred, average="macro", zero_division=0)

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision_macro": round(float(prec), 4),
            "recall_macro": round(float(rec), 4),
            "f1_macro": round(float(f1), 4),
            "fit_time_s": round(float(fit_time), 2),
            "latency_ms_per_req": round(float(pred_time), 4),
        }
        logger.info(f"  [{name:18s}] Acc={acc:.4f} | Prec={prec:.4f} | Rec={rec:.4f} | F1={f1:.4f} | Latency={pred_time:.4f}ms")

    return results


def train_champion_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    artifacts_dir: Path,
) -> tuple[xgb.Booster, dict[str, Any]]:
    """Trains Champion Cost-Sensitive Regularized XGBoost and exports to UBJSON."""
    logger.info(">>> Training Champion Cost-Sensitive Regularized XGBoost v2.0 <<<")

    # Cost-sensitive weighting to handle class distributions
    classes, counts = np.unique(y_train, return_counts=True)
    total_samples = len(y_train)
    class_weights = {c: total_samples / (len(classes) * cnt) for c, cnt in zip(classes, counts)}
    sample_weights = np.array([class_weights[y] for y in y_train], dtype=np.float32)

    # Initialize XGBClassifier with Sprint 2 specifications
    clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_lambda=2.0,
        objective="multi:softprob",
        num_class=len(CANONICAL_CLASSES),
        eval_metric="mlogloss",
        random_state=42,
        nthread=1,
    )

    clf.fit(
        X_train,
        y_train,
        sample_weight=sample_weights,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    # Evaluate on Test Set
    y_test_pred = clf.predict(X_test)

    test_acc = accuracy_score(y_test, y_test_pred)
    test_prec = precision_score(y_test, y_test_pred, average="macro", zero_division=0)
    test_rec = recall_score(y_test, y_test_pred, average="macro", zero_division=0)
    test_f1 = f1_score(y_test, y_test_pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_test, y_test_pred, labels=range(len(CANONICAL_CLASSES)))
    report = classification_report(y_test, y_test_pred, target_names=CANONICAL_CLASSES, output_dict=True, zero_division=0)

    logger.info(f"Champion Test Metrics: Acc={test_acc:.4f}, Prec={test_prec:.4f}, Rec={test_rec:.4f}, F1={test_f1:.4f}")

    # Latency evaluation: 1000 single predictions
    latencies = []
    booster: xgb.Booster = clf.get_booster()
    for i in range(min(500, len(X_test))):
        t0 = time.perf_counter()
        _ = booster.inplace_predict(X_test[i : i + 1])
        latencies.append((time.perf_counter() - t0) * 1000)
    avg_latency = float(np.mean(latencies))
    p99_latency = float(np.percentile(latencies, 99))
    logger.info(f"Single-Request Latency: Avg={avg_latency:.3f} ms, P99={p99_latency:.3f} ms")

    # Export to UBJSON (Zero-Pickle format)
    model_path = artifacts_dir / "xgb_v2.ubj"
    booster.save_model(str(model_path))
    model_sha256 = compute_file_sha256(model_path)
    logger.info(f"Exported Champion model to {model_path} (SHA-256: {model_sha256})")

    metadata = {
        "model_name": "Champion Cost-Sensitive Regularized XGBoost v2.0",
        "model_file": "xgb_v2.ubj",
        "model_version": "2.0.0",
        "sha256_hash": model_sha256,
        "feature_count": 26,
        "feature_names": CANONICAL_FEATURE_NAMES_V2,
        "classes": CANONICAL_CLASSES,
        "class_mapping": CLASS_TO_INT,
        "attack_threshold": 0.50,
        "latency_benchmark": {
            "mean_ms": round(avg_latency, 4),
            "p99_ms": round(p99_latency, 4),
        },
        "metrics": {
            "test_accuracy": round(float(test_acc), 4),
            "test_precision_macro": round(float(test_prec), 4),
            "test_recall_macro": round(float(test_rec), 4),
            "test_f1_macro": round(float(test_f1), 4),
            "confusion_matrix": cm.tolist(),
            "classification_report": report,
        },
        "hyperparameters": {
            "n_estimators": 150,
            "max_depth": 6,
            "learning_rate": 0.08,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "min_child_weight": 3,
            "reg_lambda": 2.0,
            "nthread": 1,
        },
    }

    meta_path = artifacts_dir / "xgb_v2_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    logger.info(f"Saved metadata to {meta_path}")

    return booster, metadata


def train_calibrated_isolation_forest_v2(
    X_train_benign: np.ndarray,
    X_val_benign: np.ndarray,
    artifacts_dir: Path,
    repo_root: Path,
) -> dict[str, Any]:
    """Trains RobustScaler + IsolationForest v2 on Benign traffic, exports zero-pickle npz, and calibrates percentiles."""
    logger.info(">>> Training RobustScaler + IsolationForest v2.0 (Zero CSIC) <<<")

    scaler = RobustScaler()
    X_scaled_train = scaler.fit_transform(X_train_benign)

    iforest = IsolationForest(
        n_estimators=100,
        max_samples=512,
        contamination=0.04,
        random_state=42,
        n_jobs=1,
    )
    iforest.fit(X_scaled_train)

    # Empirical Percentile Calibration on Benign Validation Set
    X_scaled_val = scaler.transform(X_val_benign)
    val_scores = iforest.decision_function(X_scaled_val)

    p01 = float(np.percentile(val_scores, 1))
    p05 = float(np.percentile(val_scores, 5))
    p10 = float(np.percentile(val_scores, 10))
    p25 = float(np.percentile(val_scores, 25))
    p50 = float(np.percentile(val_scores, 50))
    p95 = float(np.percentile(val_scores, 95))

    logger.info(f"Empirical Benign Percentiles: p01={p01:.4f}, p05={p05:.4f}, p10={p10:.4f}, p25={p25:.4f}, p50={p50:.4f}, p95={p95:.4f}")

    def score_anomaly(raw_score: float) -> float:
        """Calibrates raw decision score to 0.0-100.0 risk score.
        Normal benign is <= 30.0; Anomalies (below p10) are >= 60.0.
        """
        if raw_score >= p50:
            norm = min(1.0, (raw_score - p50) / max(1e-5, p95 - p50))
            return max(0.0, 15.0 * (1.0 - norm))
        elif raw_score >= p25:
            norm = (raw_score - p25) / max(1e-5, p50 - p25)
            return 30.0 - (15.0 * norm)
        elif raw_score >= p10:
            norm = (raw_score - p10) / max(1e-5, p25 - p10)
            return 60.0 - (30.0 * norm)
        else:
            diff = min(1.0, (p10 - raw_score) / max(1e-5, abs(p10)))
            return min(100.0, 60.0 + (40.0 * diff))

    # Evaluate on Benchmark 1000 Diverse
    bench_path = repo_root / "data" / "benchmark_1000_diverse.csv"
    bench_eval: dict[str, Any] = {}
    if bench_path.exists():
        df_bench = pd.read_csv(bench_path)
        X_bench = extract_batch_26_vectors(df_bench.to_dict(orient="records"))
        y_bench_is_attack = df_bench["label"].to_numpy() != 0

        X_bench_scaled = scaler.transform(X_bench)
        bench_scores = iforest.decision_function(X_bench_scaled)
        bench_risks = np.array([score_anomaly(s) for s in bench_scores])

        is_anom_60 = bench_risks >= 60.0
        is_anom_30 = bench_risks >= 30.0

        attack_indices = np.where(y_bench_is_attack)[0]
        benign_indices = np.where(~y_bench_is_attack)[0]
        total_attacks = len(attack_indices)
        total_benign = len(benign_indices)

        det_60 = int(np.sum(is_anom_60[attack_indices]))
        fp_60 = int(np.sum(is_anom_60[benign_indices]))
        rec_60 = float(det_60 / max(1, total_attacks))
        fpr_60 = float(fp_60 / max(1, total_benign))

        det_30 = int(np.sum(is_anom_30[attack_indices]))
        fp_30 = int(np.sum(is_anom_30[benign_indices]))
        rec_30 = float(det_30 / max(1, total_attacks))
        fpr_30 = float(fp_30 / max(1, total_benign))

        bench_eval = {
            "at_60": {
                "threshold": 60.0,
                "total_attacks": total_attacks,
                "detected_anomalies": det_60,
                "recall": round(rec_60, 4),
                "false_positives": fp_60,
                "fpr": round(fpr_60, 4),
                "recall_target_met": bool(rec_60 >= 0.50),
                "fpr_target_met": bool(fpr_60 <= 0.05),
            },
            "at_30": {
                "threshold": 30.0,
                "total_attacks": total_attacks,
                "detected_anomalies": det_30,
                "recall": round(rec_30, 4),
                "false_positives": fp_30,
                "fpr": round(fpr_30, 4),
                "recall_target_met": bool(rec_30 >= 0.50),
            },
        }
        logger.info(
            f"Benchmark 1000 Diverse Anomaly Detection: "
            f"@60.0 (Gateway Alert): Recall={rec_60:.2%} ({det_60}/{total_attacks}), FPR={fpr_60:.2%} ({fp_60}/{total_benign}) | "
            f"@30.0: Recall={rec_30:.2%} ({det_30}/{total_attacks}), FPR={fpr_30:.2%} ({fp_30}/{total_benign})"
        )

    # Export ZERO-PICKLE NPZ structure
    max_nodes = max(e.tree_.node_count for e in iforest.estimators_)
    n_trees = len(iforest.estimators_)

    left_arr = np.full((n_trees, max_nodes), -1, dtype=np.int32)
    right_arr = np.full((n_trees, max_nodes), -1, dtype=np.int32)
    feat_arr = np.full((n_trees, max_nodes), -1, dtype=np.int32)
    thresh_arr = np.zeros((n_trees, max_nodes), dtype=np.float32)
    samples_arr = np.zeros((n_trees, max_nodes), dtype=np.int32)

    for i, e in enumerate(iforest.estimators_):
        nc = e.tree_.node_count
        left_arr[i, :nc] = e.tree_.children_left
        right_arr[i, :nc] = e.tree_.children_right
        feat_arr[i, :nc] = e.tree_.feature
        thresh_arr[i, :nc] = e.tree_.threshold
        samples_arr[i, :nc] = e.tree_.n_node_samples

    c_n_table = np.zeros(513, dtype=np.float32)
    for n in range(2, 513):
        if n == 2:
            c_n_table[n] = 1.0
        else:
            c_n_table[n] = 2.0 * (np.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n
    c_max = float(c_n_table[512])

    npz_path = artifacts_dir / "iforest_v2.npz"
    np.savez_compressed(
        npz_path,
        scaler_center=scaler.center_.astype(np.float32),
        scaler_scale=scaler.scale_.astype(np.float32),
        children_left=left_arr,
        children_right=right_arr,
        feature=feat_arr,
        threshold=thresh_arr,
        n_node_samples=samples_arr,
        c_n_table=c_n_table,
        c_max=np.float32(c_max),
        offset=np.float32(iforest.offset_),
        max_samples=np.int32(512),
    )
    npz_sha256 = compute_file_sha256(npz_path)
    logger.info(f"Saved Zero-Pickle IForest v2 to {npz_path} (SHA-256: {npz_sha256})")

    # Save fallback joblib for backward compatibility
    out_model_path = artifacts_dir / "iforest_v2.joblib"
    joblib.dump({"scaler": scaler, "model": iforest}, out_model_path)

    metadata = {
        "model_name": "Zero-Pickle Calibrated IsolationForest v2.0",
        "model_file": "iforest_v2.npz",
        "model_version": "2.0.0",
        "sha256_hash": npz_sha256,
        "feature_count": 26,
        "feature_names": CANONICAL_FEATURE_NAMES_V2,
        "hyperparameters": {
            "n_estimators": 100,
            "max_samples": 512,
            "contamination": 0.04,
            "random_state": 42,
            "n_jobs": 1,
        },
        "percentiles": {
            "p01": round(p01, 5),
            "p05": round(p05, 5),
            "p10": round(p10, 5),
            "p25": round(p25, 5),
            "p50": round(p50, 5),
            "p95": round(p95, 5),
        },
        "benchmark_1000_diverse_eval": bench_eval,
    }

    meta_path = artifacts_dir / "iforest_v2_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    logger.info(f"Saved IForest v2 metadata to {meta_path}")

    # Export evaluation summary
    eval_summary_path = artifacts_dir / "anomaly_eval_summary.json"
    eval_summary_path.write_text(json.dumps(bench_eval, indent=2), encoding="utf-8")
    logger.info(f"Saved anomaly evaluation summary to {eval_summary_path}")

    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Defense ML Models v2.0")
    parser.add_argument(
        "--xgb-only",
        action="store_true",
        help="Retrain supervised benchmark + Champion XGBoost v2.0 only, preserving calibrated IForest v2.0 artifacts.",
    )
    args = parser.parse_args()

    logger.info("Starting Defense ML Models v2.0 Training Pipeline...")
    data_dir = REPO_ROOT / "data" / "processed" / "defense_v2"
    artifacts_dir = ML_ENGINE_DIR / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Zero-Leakage Dataset v2
    train_df = pd.read_csv(data_dir / "train.csv")
    val_df = pd.read_csv(data_dir / "val.csv")
    test_df = pd.read_csv(data_dir / "test.csv")

    X_train, y_train = extract_features_and_labels(train_df)
    X_val, y_val = extract_features_and_labels(val_df)
    X_test, y_test = extract_features_and_labels(test_df)

    # 2. Benchmark 5 Candidate Models
    benchmark_results = benchmark_candidate_models(X_train, y_train, X_val, y_val)
    benchmarks_path = artifacts_dir / "models_benchmark_v2.json"
    benchmarks_path.write_text(json.dumps(benchmark_results, indent=2), encoding="utf-8")
    logger.info(f"Benchmark results saved to {benchmarks_path}")

    # 3. Train Champion Cost-Sensitive Regularized XGBoost
    _, champion_meta = train_champion_xgboost(
        X_train, y_train, X_val, y_val, X_test, y_test, artifacts_dir
    )

    # 4. Train Calibrated Isolation Forest v2 on Benign subset (unless --xgb-only)
    if not args.xgb_only:
        benign_train_mask = (y_train == CLASS_TO_INT["BENIGN"])
        benign_val_mask = (y_val == CLASS_TO_INT["BENIGN"])
        X_train_benign = X_train[benign_train_mask]
        X_val_benign = X_val[benign_val_mask]

        _ = train_calibrated_isolation_forest_v2(
            X_train_benign, X_val_benign, artifacts_dir, REPO_ROOT
        )
    else:
        logger.info("Preserving existing Calibrated IsolationForest v2.0 artifacts (--xgb-only).")

    logger.info(">>> DEFENSE ML MODELS v2.0 PIPELINE 100% COMPLETE! <<<")


if __name__ == "__main__":
    main()
