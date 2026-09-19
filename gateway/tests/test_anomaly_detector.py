import tempfile
import time
from pathlib import Path

import pytest

from app.security.anomaly import AnomalyDetector, AnomalyResult

try:
    import joblib
    from sklearn.ensemble import IsolationForest
except ImportError:
    joblib = None
    IsolationForest = None


def test_anomaly_detector_graceful_fallback() -> None:
    """Verifies that AnomalyDetector operates gracefully when no model file exists (NIST SP 800-115)."""
    detector = AnomalyDetector(model_path="non_existent_model_file.joblib")
    assert not detector.is_loaded
    assert detector.model_path is None

    result = detector.predict("GET /api/books HTTP/1.1")
    assert isinstance(result, AnomalyResult)
    assert not result.model_loaded
    assert not result.is_anomaly
    assert result.raw_score is None
    assert result.anomaly_score is None
    assert result.latency_ms >= 0.0


def test_anomaly_score_normalization() -> None:
    """Verifies standardization of raw decision function scores into 0-100 risk scale."""
    # Typical high inlier: raw_score = 0.20 -> 0.0
    assert AnomalyDetector.normalize_anomaly_score(0.20) == 0.0

    # Mild inlier: raw_score = 0.05 -> 30 - 0.05*300 = 15.0
    assert AnomalyDetector.normalize_anomaly_score(0.05) == 15.0

    # Decision boundary: raw_score = 0.0 -> 30.0
    assert AnomalyDetector.normalize_anomaly_score(0.0) == 30.0

    # Moderate anomaly: raw_score = -0.05 -> 30 + 0.05*850 = 72.5
    assert AnomalyDetector.normalize_anomaly_score(-0.05) == 72.5

    # Severe anomaly: raw_score = -0.15 -> 100.0 (clamped)
    assert AnomalyDetector.normalize_anomaly_score(-0.15) == 100.0


@pytest.mark.skipif(
    joblib is None or IsolationForest is None,
    reason="scikit-learn and joblib required for model training test",
)
def test_anomaly_detector_trained_model_inference() -> None:
    """Verifies real-time inference, sub-10ms latency, and anomaly scoring using an active Isolation Forest model."""
    from app.security.ml_detector import MLDetector

    benign_urls = [
        f"/api/books/{i}" for i in range(1, 50)
    ] + [
        f"/api/books?category=fiction&page={i}" for i in range(1, 50)
    ] + [
        f"/rest/products/search?q=book{i}" for i in range(1, 50)
    ]
    benign_samples = [MLDetector.extract_features(u) for u in benign_urls]

    model = IsolationForest(n_estimators=20, random_state=42)
    model.fit(benign_samples)

    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        joblib.dump(model, tmp_path)

    try:
        detector = AnomalyDetector(model_path=tmp_path, anomaly_threshold=50.0)
        assert detector.is_loaded
        assert detector.model_path == tmp_path

        # 1. Normal benign payload
        start = time.perf_counter()
        benign_result = detector.predict("/rest/products/search?q=book10")
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        assert benign_result.model_loaded
        assert benign_result.latency_ms < 10.0, f"Latency {benign_result.latency_ms}ms exceeded 10ms budget"
        assert elapsed_ms < 15.0
        assert benign_result.anomaly_score is not None
        assert benign_result.raw_score is not None

        # 2. Heavily distorted / anomalous payload
        anomalous_payload = "/api/v1/search?q=" + ("%27%22" * 50) + "--!@#$%^&*()_+"
        anomaly_res = detector.predict(anomalous_payload)
        assert anomaly_res.model_loaded
        assert anomaly_res.anomaly_score is not None
        # Anomalous payload should have higher anomaly score than benign
        assert anomaly_res.anomaly_score > benign_result.anomaly_score
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


@pytest.mark.skipif(
    joblib is None or IsolationForest is None,
    reason="scikit-learn and joblib required for hot reload test",
)
def test_anomaly_detector_hot_reload() -> None:
    """Verifies that AnomalyDetector can hot-reload without gateway restart."""
    model = IsolationForest(n_estimators=10, random_state=42)
    model.fit([[10.0] + [0.0] * 16 for _ in range(20)])

    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        joblib.dump(model, tmp_path)

    try:
        detector = AnomalyDetector(model_path="non_existent_init.joblib")
        assert not detector.is_loaded

        success = detector.load_model(tmp_path)
        assert success
        assert detector.is_loaded

        result = detector.predict("/test")
        assert result.model_loaded
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
