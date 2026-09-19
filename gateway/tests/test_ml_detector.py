import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from app.security.ml_detector import FEATURE_NAMES, MLDetector, MLPredictionResult


def test_ml_detector_graceful_fallback_when_model_absent():
    """Verifies that MLDetector does not crash when model is absent,

    returning model_loaded=False and risk_score=None (NIST SP 800-115).
    """
    detector = MLDetector(model_path="/nonexistent/model.joblib")
    assert detector.is_loaded is False
    assert detector.model_path is None

    result = detector.predict("SELECT * FROM users WHERE id = 1")
    assert isinstance(result, MLPredictionResult)
    assert result.model_loaded is False
    assert result.is_attack is False
    assert result.risk_score is None
    assert result.confidence == 0.0
    assert result.latency_ms >= 0.0


def test_ml_detector_17_feature_extraction():
    """Verifies that extract_features accurately extracts 17 morphological features."""
    payload = "'; UNION SELECT * FROM users WHERE id=1; --"
    features = MLDetector.extract_features(payload)

    assert len(features) == 17
    assert len(features) == len(FEATURE_NAMES)

    # Check specific features
    assert features[0] == len(payload)  # length
    assert features[1] > 0.0  # entropy
    assert features[2] >= 1.0  # single quotes
    assert features[6] >= 2.0  # semicolons
    assert features[7] >= 2.0  # hyphens
    assert features[12] >= 2.0  # sql_keyword_count (union, select, from, where)
    assert features[14] >= 1.0  # sqli_regex_matches


def test_ml_detector_shannon_entropy():
    """Verifies that Shannon entropy measures randomness correctly."""
    zero_entropy = MLDetector.calculate_shannon_entropy("")
    assert zero_entropy == 0.0

    low_entropy = MLDetector.calculate_shannon_entropy("aaaaaaaaaa")
    assert low_entropy == 0.0

    high_entropy = MLDetector.calculate_shannon_entropy("a1B#9$xZ!q@7*k")
    assert high_entropy > 3.0


def test_ml_detector_sub_15ms_latency_with_active_model():
    """Verifies that inference execution complies with the sub-15ms budget (MDPI 2025)."""
    # 1. Train a lightweight mock RandomForestClassifier with 17 features
    rng = np.random.RandomState(42)
    X_train = rng.rand(50, 17)
    y_train = ["BENIGN"] * 25 + ["SQLI"] * 25

    clf = RandomForestClassifier(n_estimators=10, max_depth=4, random_state=42)
    clf.fit(X_train, y_train)

    # 2. Serialize to temporary joblib file
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "test_rf_model.joblib"
        joblib.dump(clf, model_file)

        # 3. Load model into MLDetector
        detector = MLDetector(model_path=model_file)
        assert detector.is_loaded is True

        # 4. Measure inference latency across 10 sample predictions
        latencies = []
        for _ in range(10):
            t0 = time.perf_counter()
            res = detector.predict("UNION SELECT password FROM accounts")
            elapsed = (time.perf_counter() - t0) * 1000
            latencies.append(elapsed)

            assert res.model_loaded is True
            assert res.confidence >= 0.0
            assert res.risk_score is not None
            assert res.latency_ms < 15.0, f"Latency exceeded 15ms budget: {res.latency_ms}ms"

        avg_latency = sum(latencies) / len(latencies)
        assert avg_latency < 15.0, f"Average latency {avg_latency:.2f}ms exceeds 15ms threshold"


def test_ml_detector_hot_reload_and_unload():
    """Verifies that load_model and unload dynamically manage model state in RAM."""
    detector = MLDetector(model_path="/dummy/path")
    assert detector.is_loaded is False

    # Create dummy trained classifier
    clf = RandomForestClassifier(n_estimators=5, random_state=42)
    clf.fit([[0.0] * 17, [1.0] * 17], ["BENIGN", "SQLI"])

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "hot_reload_rf.joblib"
        joblib.dump(clf, model_file)

        # Hot load
        loaded = detector.load_model(model_file)
        assert loaded is True
        assert detector.is_loaded is True
        assert detector.predict("test").model_loaded is True

        # Unload
        detector.unload()
        assert detector.is_loaded is False
        assert detector.predict("test").model_loaded is False
