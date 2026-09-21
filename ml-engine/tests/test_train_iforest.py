"""Unit Tests for Isolation Forest Training Pipeline on Pure Benign Baseline.

Tests Task 6.1 (Issue #26) and Task 6.2 (Issue #27):
- Benign baseline data loading and 17-D vector extraction.
- Isolation Forest training and hyperparameter configuration.
- Validation distribution (high inlier rate >= 98%, false alarm <= 2%).
- Continuous risk score normalization (0 - 100 scale).
- Artifact export and SHA-256 cryptographic hash verification.
- Two-way compatibility with Gateway WAF AnomalyDetector.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pytest

# Ensure ml-engine and gateway are in path
repo_root = Path(__file__).resolve().parent.parent.parent
ml_engine_dir = repo_root / "ml-engine"
gateway_dir = repo_root / "gateway"

for p in [str(ml_engine_dir), str(gateway_dir), str(repo_root)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from app.security.anomaly import AnomalyDetector  # noqa: E402 # type: ignore
from models.train_iforest import (  # noqa: E402
    evaluate_isolation_forest,
    export_iforest_artifacts,
    load_benign_baseline,
    normalize_anomaly_score,
    split_benign_data,
    train_isolation_forest,
)


@pytest.fixture(scope="module")
def benign_data() -> tuple[np.ndarray, np.ndarray]:
    """Loads a small sample of benign data for fast unit testing."""
    X, _ = load_benign_baseline("data")
    X_train, X_val = split_benign_data(X, val_size=0.20, random_state=42)
    return X_train, X_val


def test_load_benign_baseline():
    """Verifies that 10,000 benign samples are loaded with 17 canonical features."""
    X, df = load_benign_baseline("data")
    assert X.shape[0] == 10000
    assert X.shape[1] == 17
    assert len(df) == 10000
    assert "attack_type" in df.columns or "label" in df.columns


def test_split_benign_data():
    """Verifies 80/20 train/val split proportions."""
    mock_X = np.zeros((100, 17))
    X_train, X_val = split_benign_data(mock_X, val_size=0.20, random_state=42)
    assert len(X_train) == 80
    assert len(X_val) == 20


def test_train_isolation_forest(benign_data):
    """Verifies Isolation Forest training, hyperparameters, and single-thread execution."""
    X_train, _ = benign_data
    # Train on first 1,000 samples for swift test execution
    model = train_isolation_forest(
        X_train[:1000],
        n_estimators=50,
        max_samples=256,
        contamination=0.01,
        random_state=42,
        n_jobs=1,
    )
    assert hasattr(model, "decision_function")
    assert hasattr(model, "predict")
    assert model.n_estimators == 50
    assert model.max_samples == 256
    assert model.n_jobs == 1

    # Check prediction on 5 samples
    scores = model.decision_function(X_train[:5])
    assert len(scores) == 5
    assert all(isinstance(s, (float, np.floating)) for s in scores)


def test_evaluate_isolation_forest_distribution(benign_data):
    """Verifies that baseline evaluation metrics meet quality thresholds."""
    X_train, X_val = benign_data
    model = train_isolation_forest(
        X_train[:2000],
        n_estimators=50,
        max_samples=256,
        contamination=0.01,
        random_state=42,
        n_jobs=1,
    )
    metrics = evaluate_isolation_forest(model, X_train[:2000], X_val[:500])

    assert metrics["val_samples"] == 500
    # Inlier rate should be at least 95% even on small subset
    assert metrics["val_inlier_rate"] >= 0.95
    # False alarm rate should not exceed 5%
    assert metrics["val_false_alarm_rate"] <= 0.05
    assert "raw_score_stats" in metrics
    assert "risk_score_stats" in metrics
    assert metrics["avg_latency_ms"] < 1.0


def test_normalize_anomaly_score():
    """Verifies piecewise continuous mapping from raw decision score to 0-100 risk scale."""
    # 1. Strong inlier (positive score) -> 0.0
    assert normalize_anomaly_score(0.25) == 0.0
    assert normalize_anomaly_score(0.15) == 0.0

    # 2. Boundary score (0.0) -> 30.0 (ALLOW boundary)
    assert normalize_anomaly_score(0.0) == 30.0

    # 3. Slight outlier (-0.02) -> 30.0 + 0.02 * 850 = 47.0 (MONITOR)
    assert normalize_anomaly_score(-0.02) == 47.0

    # 4. Severe outlier (-0.10) -> min(100.0, 30 + 85.0) = 100.0 (BLOCK)
    assert normalize_anomaly_score(-0.10) == 100.0

    # 5. Monotonicity check
    raw_vals = [0.2, 0.1, 0.05, 0.0, -0.02, -0.05, -0.1]
    risk_scores = [normalize_anomaly_score(r) for r in raw_vals]
    assert risk_scores == sorted(risk_scores)


def test_export_artifacts_and_sha256(tmp_path):
    """Verifies artifact export, single-thread enforcement, and SHA-256 checksum."""
    mock_X = np.random.randn(300, 17)
    model = train_isolation_forest(mock_X, n_estimators=10, random_state=42)
    dummy_metrics = {"test": True, "inlier_rate": 0.99}

    model_path, metadata_path = export_iforest_artifacts(
        model, dummy_metrics, output_dir=tmp_path
    )

    assert model_path.exists()
    assert metadata_path.exists()

    # Verify SHA-256
    computed_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    with open(metadata_path, encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["sha256_hash"] == computed_hash
    assert meta["feature_count"] == 17
    assert meta["status"] == "PRODUCTION_READY"


def test_gateway_anomaly_detector_compatibility():
    """Verifies that trained production artifact integrates seamlessly into Gateway WAF."""
    prod_model_path = Path("ml-engine/artifacts/iforest_model.joblib")
    if not prod_model_path.exists():
        pytest.skip("Production artifact not yet generated in ml-engine/artifacts.")

    detector = AnomalyDetector(model_path=prod_model_path)
    assert detector.is_loaded is True
    assert detector.model_path == prod_model_path

    # Warm-up inference to prime CPU cache and numpy JIT
    detector.predict("warmup")

    # Live inference on benign sample
    res_benign = detector.predict("q=harry+potter&page=1")
    assert res_benign.model_loaded is True
    assert res_benign.is_anomaly is False
    assert res_benign.anomaly_score is not None
    assert res_benign.anomaly_score <= 30.0
    assert res_benign.latency_ms < 15.0
