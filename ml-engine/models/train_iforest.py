#!/usr/bin/env python3
"""Isolation Forest Training Pipeline on Pure Benign Baseline.

This module implements Task 6.1 (Issue #26) and Task 6.2 (Issue #27) for the
WAF ML Defense Engine.
It trains an unsupervised Anomaly Detection model (Isolation Forest) on pure
benign traffic (data/synthetic_benign.csv) using the unified 17-dimensional
canonical feature vector.

Key Architecture & Academic Foundation:
1. Liu et al. (2008 ICDM) Isolation Forest:
   - Sub-sampling with max_samples=256 creates shorter average path lengths
     for anomalous points (outliers) while maintaining minimal memory usage.
   - n_estimators=100 isolated trees for smooth, robust path length convergence.
   - contamination=0.01 (1% allowance for empirical baseline noise).
2. MDPI Electronics (2025) Lightweight Hybrid WAF:
   - Evaluates uninspected requests under < 5ms CPU latency budget.
   - Provides standardized continuous mapping from raw decision scores into
     a 0 - 100 Risk Scale for the Hybrid RiskEngine (Phase 7).
3. Cryptographic Artifact Integrity:
   - Serializes iforest_model.joblib (single-thread n_jobs=1 for fast gateway inline).
   - Generates iforest_metadata.json with SHA-256 cryptographic checksum.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# Ensure ml-engine root is in sys.path for features module resolution
_ML_ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(_ML_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ML_ENGINE_ROOT))

from features.extractor import (  # noqa: E402
    CANONICAL_FEATURE_NAMES,
    extract_batch_vectors,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("waf.ml_engine.train_iforest")


# -----------------------------------------------------------------------------
# 1. DATASET LOADING & VECTORIZATION
# -----------------------------------------------------------------------------

def load_benign_baseline(
    data_dir: str | Path = "data",
) -> tuple[np.ndarray, pd.DataFrame]:
    """Loads pure benign baseline dataset and extracts 17-D canonical feature vectors.

    Args:
        data_dir: Path to directory containing synthetic_benign.csv.

    Returns:
        tuple (X, df_benign) where X is an (N, 17) numpy float array.
    """
    data_path = Path(data_dir)
    benign_path = data_path / "synthetic_benign.csv"

    if not benign_path.exists():
        raise FileNotFoundError(f"Benign baseline dataset not found at: {benign_path.resolve()}")

    logger.info(f"Loading pure benign baseline from {benign_path}...")
    df_benign = pd.read_csv(benign_path)
    total_samples = len(df_benign)
    logger.info(f"Loaded {total_samples:,} benign baseline traffic records.")

    samples = df_benign.to_dict("records")
    logger.info("Extracting 17-dimensional canonical feature vectors...")
    t0 = time.perf_counter()
    X = extract_batch_vectors(samples, normalize=False, include_http_context=False)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    logger.info(
        f"Extracted {X.shape[0]:,} vectors (shape={X.shape}) in "
        f"{elapsed_ms:.2f}ms ({elapsed_ms / total_samples:.4f}ms/sample)."
    )
    return X, df_benign


def split_benign_data(
    X: np.ndarray,
    val_size: float = 0.20,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Splits baseline feature vectors into Train and Validation subsets.

    Args:
        X: (N, 17) feature matrix.
        val_size: Proportion for validation (default: 0.20).
        random_state: Seed for reproducibility.

    Returns:
        tuple (X_train, X_val).
    """
    X_train, X_val = train_test_split(X, test_size=val_size, random_state=random_state)
    logger.info(
        f"Benign Baseline Split: Train={len(X_train):,} samples, "
        f"Validation={len(X_val):,} samples."
    )
    return X_train, X_val


# -----------------------------------------------------------------------------
# 2. ISOLATION FOREST TRAINING
# -----------------------------------------------------------------------------

def train_isolation_forest(
    X_train: np.ndarray,
    n_estimators: int = 100,
    max_samples: int | str = 256,
    contamination: float | str = 0.01,
    random_state: int = 42,
    n_jobs: int = 1,
) -> IsolationForest:
    """Trains an Isolation Forest anomaly detector on pure benign traffic.

    Args:
        X_train: (N, 17) benign feature vectors.
        n_estimators: Number of isolation trees (default: 100).
        max_samples: Subsample size per tree (default: 256, Liu et al. 2008).
        contamination: Expected proportion of outliers in the data (default: 0.01).
        random_state: Seed for deterministic tree splits.
        n_jobs: Number of parallel jobs (default: 1 for single-thread low latency).

    Returns:
        Fitted IsolationForest model.
    """
    logger.info(
        f"Initializing IsolationForest: n_estimators={n_estimators}, "
        f"max_samples={max_samples}, contamination={contamination}, "
        f"n_jobs={n_jobs}, random_state={random_state}..."
    )
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        random_state=random_state,
        n_jobs=n_jobs,
    )

    t0 = time.perf_counter()
    model.fit(X_train)
    fit_time_ms = (time.perf_counter() - t0) * 1000.0
    logger.info(f"Isolation Forest model successfully trained in {fit_time_ms:.2f}ms.")
    return model


# -----------------------------------------------------------------------------
# 3. EVALUATION & DISTRIBUTION ANALYSIS
# -----------------------------------------------------------------------------

def normalize_anomaly_score(raw_decision_score: float) -> float:
    """Standardizes raw Isolation Forest decision score into 0-100 risk scale.

    Conforms to MDPI Electronics (2025) & Gateway AnomalyDetector contract:
      - raw >= 0.0: inlier (benign traffic), mapped to [0.0, 30.0] (ALLOW).
      - raw < 0.0:  outlier (abnormal traffic / zero-day), mapped to [30.0, 100.0].

    Formula:
      - raw >= 0: max(0.0, 30.0 - raw * 300.0)
      - raw < 0:  min(100.0, 30.0 + abs(raw) * 850.0)
    """
    raw = float(raw_decision_score)
    if raw >= 0.0:
        return round(max(0.0, 30.0 - raw * 300.0), 2)
    return round(min(100.0, 30.0 + abs(raw) * 850.0), 2)


def evaluate_isolation_forest(
    model: IsolationForest,
    X_train: np.ndarray,
    X_val: np.ndarray,
) -> dict[str, Any]:
    """Evaluates Isolation Forest on Train and Validation baseline sets.

    Calculates score distributions, inlier/outlier ratios, and per-sample latency.

    Returns:
        Structured evaluation metrics dictionary.
    """
    logger.info("Evaluating Isolation Forest baseline distribution...")

    # Training distribution
    train_scores = model.decision_function(X_train)
    train_inliers = int((train_scores >= 0.0).sum())
    train_outliers = int((train_scores < 0.0).sum())

    # Validation distribution
    t0 = time.perf_counter()
    val_scores = model.decision_function(X_val)
    val_eval_time = (time.perf_counter() - t0) * 1000.0
    latency_per_sample_ms = val_eval_time / len(X_val)

    val_inliers = int((val_scores >= 0.0).sum())
    val_outliers = int((val_scores < 0.0).sum())
    val_inlier_rate = val_inliers / len(X_val)
    val_false_alarm_rate = val_outliers / len(X_val)

    # Risk scores calculation
    val_risk_scores = np.array([normalize_anomaly_score(s) for s in val_scores])

    metrics: dict[str, Any] = {
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "train_inliers": train_inliers,
        "train_outliers": train_outliers,
        "train_inlier_rate": round(train_inliers / len(X_train), 4),
        "val_inliers": val_inliers,
        "val_outliers": val_outliers,
        "val_inlier_rate": round(val_inlier_rate, 4),
        "val_false_alarm_rate": round(val_false_alarm_rate, 4),
        "raw_score_stats": {
            "min": round(float(val_scores.min()), 4),
            "mean": round(float(val_scores.mean()), 4),
            "median": round(float(np.median(val_scores)), 4),
            "max": round(float(val_scores.max()), 4),
            "std": round(float(val_scores.std()), 4),
        },
        "risk_score_stats": {
            "min": round(float(val_risk_scores.min()), 2),
            "mean": round(float(val_risk_scores.mean()), 2),
            "median": round(float(np.median(val_risk_scores)), 2),
            "max": round(float(val_risk_scores.max()), 2),
            "std": round(float(val_risk_scores.std()), 2),
        },
        "avg_latency_ms": round(latency_per_sample_ms, 5),
    }

    logger.info(
        f"Validation Results: Inlier Rate={val_inlier_rate * 100:.2f}%, "
        f"False Alarm Rate={val_false_alarm_rate * 100:.2f}%, "
        f"Mean Raw Score={metrics['raw_score_stats']['mean']:.4f}, "
        f"Mean Risk Score={metrics['risk_score_stats']['mean']:.2f}, "
        f"Latency={latency_per_sample_ms:.4f}ms/sample."
    )
    return metrics


# -----------------------------------------------------------------------------
# 4. ARTIFACT SERIALIZATION & METADATA
# -----------------------------------------------------------------------------

def export_iforest_artifacts(
    model: IsolationForest,
    metrics: dict[str, Any],
    output_dir: str | Path = "ml-engine/artifacts",
) -> tuple[Path, Path]:
    """Exports production-ready Isolation Forest model and metadata.

    Enforces n_jobs=1 on the serialized object to guarantee sub-5ms latency
    when loaded by the Uvicorn/FastAPI Gateway.

    Args:
        model: Fitted IsolationForest.
        metrics: Evaluation metrics dictionary.
        output_dir: Directory where artifacts will be saved.

    Returns:
        tuple (model_path, metadata_path).
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    model_path = out_path / "iforest_model.joblib"
    metadata_path = out_path / "iforest_metadata.json"

    # Enforce n_jobs=1
    if hasattr(model, "n_jobs") and model.n_jobs != 1:
        model.n_jobs = 1

    logger.info(f"Saving Isolation Forest model to {model_path}...")
    joblib.dump(model, model_path, compress=3)
    model_size_bytes = model_path.stat().st_size
    logger.info(f"Saved model binary ({model_size_bytes:,} bytes, {model_size_bytes / 1024 / 1024:.2f} MB).")

    # Compute SHA-256 hash of serialized artifact
    sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    logger.info(f"Model artifact SHA-256: {sha256}")

    metadata: dict[str, Any] = {
        "model_name": "IsolationForest (WAF Anomaly Detector)",
        "model_version": "1.0.0",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sha256_hash": sha256,
        "feature_count": len(CANONICAL_FEATURE_NAMES),
        "feature_names": CANONICAL_FEATURE_NAMES,
        "hyperparameters": {
            "n_estimators": model.n_estimators,
            "max_samples": model.max_samples,
            "contamination": model.contamination,
            "random_state": model.random_state,
            "n_jobs": model.n_jobs,
        },
        "normalization": {
            "type": "piecewise_continuous",
            "inlier_formula": "max(0.0, 30.0 - raw * 300.0)",
            "outlier_formula": "min(100.0, 30.0 + abs(raw) * 850.0)",
            "threshold_allow": 30.0,
            "threshold_monitor": 60.0,
            "threshold_block": 80.0,
        },
        "baseline_metrics": metrics,
        "status": "PRODUCTION_READY",
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Saved metadata file to {metadata_path}.")

    return model_path, metadata_path


# -----------------------------------------------------------------------------
# 5. CLI EXECUTION PIPELINE
# -----------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PBL6 Isolation Forest Training Pipeline on Pure Benign Baseline."
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data",
        help="Directory containing synthetic_benign.csv (default: data).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="ml-engine/artifacts",
        help="Directory to export artifacts (default: ml-engine/artifacts).",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of isolation trees (default: 100).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=256,
        help="Subsample size per tree (default: 256).",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="Expected contamination rate (default: 0.01).",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.20,
        help="Validation split ratio (default: 0.20).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed (default: 42).",
    )
    parser.add_argument(
        "--skip-export",
        action="store_true",
        help="Skip artifact export.",
    )
    return parser.parse_args()


def main() -> int:
    """Orchestrates Isolation Forest training, validation, and artifact export."""
    args = parse_args()
    logger.info("=== Starting PBL6 Isolation Forest Training Pipeline (Task 6.1) ===")

    try:
        # 1. Load data
        X, df_benign = load_benign_baseline(args.data_dir)

        # 2. Split into Train & Validation
        X_train, X_val = split_benign_data(
            X, val_size=args.val_size, random_state=args.random_state
        )

        # 3. Train model
        model = train_isolation_forest(
            X_train=X_train,
            n_estimators=args.n_estimators,
            max_samples=args.max_samples,
            contamination=args.contamination,
            random_state=args.random_state,
            n_jobs=1,
        )

        # 4. Evaluate baseline distribution
        metrics = evaluate_isolation_forest(model, X_train, X_val)

        # 5. Export artifacts
        if not args.skip_export:
            model_path, metadata_path = export_iforest_artifacts(
                model=model,
                metrics=metrics,
                output_dir=args.output_dir,
            )
            logger.info(f"Artifacts successfully exported to: {model_path} & {metadata_path}")

        logger.info("=== Isolation Forest Training Pipeline Completed Successfully ===")
        return 0
    except Exception as e:
        logger.exception(f"Pipeline execution failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
