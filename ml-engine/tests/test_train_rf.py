"""Unit and Integration Tests for Phase 5 Random Forest Training Pipeline.

Tests:
1. Dataset loading and 17-dimensional vector extraction
2. Stratified train/val/test splitting
3. Multi-model candidate benchmarking
4. Champion Random Forest training & latency budget verification
5. Model serialization, metadata JSON export, and SHA-256 integrity
6. Integration with Gateway MLDetector service
"""

import sys
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pytest

# Ensure ml-engine and gateway are in path
repo_root = Path(__file__).resolve().parent.parent.parent
ml_engine_dir = repo_root / "ml-engine"
gateway_dir = repo_root / "gateway"

for p in [str(ml_engine_dir), str(gateway_dir), str(repo_root)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from app.security.ml_detector import MLDetector  # noqa: E402
from models.evaluate import evaluate_classifier  # noqa: E402
from models.train_rf import (  # noqa: E402
    CANONICAL_CLASSES,
    benchmark_candidate_models,
    export_champion_artifacts,
    load_combined_dataset,
    split_dataset,
    train_champion_random_forest,
)


@pytest.fixture(scope="module")
def real_dataset():
    """Loads a fast subset of the dataset for testing."""
    X, y, df = load_combined_dataset(data_dir=repo_root / "data")
    return X, y, df


def test_load_combined_dataset(real_dataset):
    """Verifies that the dataset loads 20,000 samples with 17 features."""
    X, y, df = real_dataset
    assert X.shape == (20000, 17)
    assert len(y) == 20000
    assert set(np.unique(y)) == set(CANONICAL_CLASSES)
    assert df["attack_type"].value_counts()["BENIGN"] == 10000


def test_split_dataset_proportions(real_dataset):
    """Verifies 70/15/15 stratified partitioning."""
    X, y, _ = real_dataset
    X_train, y_train, X_val, y_val, X_test, y_test = split_dataset(X, y)

    assert len(X_train) == 14000
    assert len(X_val) == 3000
    assert len(X_test) == 3000

    # Verify class balance preserved in test set
    unique_test, counts_test = np.unique(y_test, return_counts=True)
    class_counts = dict(zip(unique_test, counts_test))
    assert class_counts["BENIGN"] == 1500  # 15% of 10,000
    assert class_counts["SQLI"] == 375    # 15% of 2,500


def test_benchmark_candidate_models_execution():
    """Tests the multi-model benchmarking pipeline on a synthetic sample subset."""
    np.random.seed(42)
    # Generate 300 mock samples with 17 features
    n_samples = 300
    X_mock = np.random.rand(n_samples, 17).astype(np.float32)
    y_mock = np.random.choice(CANONICAL_CLASSES, size=n_samples)

    X_tr, y_tr = X_mock[:200], y_mock[:200]
    X_te, y_te = X_mock[200:], y_mock[200:]

    results = benchmark_candidate_models(X_tr, y_tr, X_te, y_te)
    assert len(results) >= 5

    model_names = [r["model_name"] for r in results]
    assert any("Logistic" in m for m in model_names)
    assert any("Decision Tree" in m for m in model_names)
    assert any("SVM" in m for m in model_names)
    assert any("Random Forest" in m for m in model_names)
    assert any("XGBoost" in m for m in model_names)

    for res in results:
        assert "accuracy" in res
        assert "f1_macro" in res
        assert "youden_index_j" in res
        assert "avg_latency_ms" in res
        assert res["avg_latency_ms"] >= 0.0


def test_train_champion_random_forest_and_latency(real_dataset):
    """Tests training Champion Random Forest and verifies < 15ms latency budget."""
    X, y, _ = real_dataset
    # Subsample 1,000 samples for fast testing
    X_sub = X[:1000]
    y_sub = y[:1000]
    X_tr, y_tr = X_sub[:700], y_sub[:700]
    X_vl, y_vl = X_sub[700:], y_sub[700:]

    model, metrics = train_champion_random_forest(X_tr, y_tr, X_vl, y_vl, tune_hyperparameters=False)
    assert hasattr(model, "predict")
    assert hasattr(model, "predict_proba")
    assert metrics["val_f1_macro"] >= 0.0

    # Test latency on 100 samples
    import time
    t0 = time.perf_counter()
    _ = model.predict_proba(X_vl[:100])
    dur_ms = (time.perf_counter() - t0) * 1000
    avg_lat = dur_ms / 100.0
    assert avg_lat < 5.0, f"Average latency {avg_lat}ms exceeds 5ms threshold"


def test_artifact_export_and_hash():
    """Tests artifact packaging, SHA-256 computation, and metadata generation."""
    from sklearn.ensemble import RandomForestClassifier

    X_dummy = np.random.rand(50, 17)
    y_dummy = np.array(["BENIGN"] * 25 + ["SQLI"] * 25)
    model = RandomForestClassifier(n_estimators=10, random_state=42).fit(X_dummy, y_dummy)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        paths = export_champion_artifacts(
            model=model,
            benchmark_results=[{"model_name": "Random Forest", "f1_macro": 0.99}],
            champion_metrics={"val_f1_macro": 0.99},
            test_metrics={"f1_macro": 0.99, "avg_latency_ms": 1.2, "youden_index_j": 0.98},
            primary_dir=tmp_path / "artifacts",
            secondary_dir=tmp_path / "models",
        )

        assert paths["primary_model"].exists()
        assert paths["metadata"].exists()
        assert paths["benchmark"].exists()

        loaded_model = joblib.load(paths["primary_model"])
        assert hasattr(loaded_model, "predict_proba")

        import json
        with open(paths["metadata"], encoding="utf-8") as f:
            meta = json.load(f)
        assert meta["feature_count"] == 17
        assert "sha256_hash" in meta
        assert len(meta["sha256_hash"]) == 64


def test_evaluate_classifier_metrics():
    """Tests evaluate_classifier utility function."""
    from sklearn.ensemble import RandomForestClassifier

    X = np.random.rand(100, 17)
    y = np.array(["BENIGN"] * 20 + ["SQLI"] * 20 + ["XSS"] * 20 + ["PATH_TRAVERSAL"] * 20 + ["COMMAND_INJECTION"] * 20)
    model = RandomForestClassifier(n_estimators=10, random_state=42).fit(X, y)

    res = evaluate_classifier(model, X, y, classes=CANONICAL_CLASSES)
    assert "accuracy" in res
    assert "f1_macro" in res
    assert "confusion_matrix" in res
    assert len(res["confusion_matrix"]) == 5


def test_gateway_mldetector_compatibility():
    """Tests that trained model file is compatible with Gateway MLDetector."""
    model_file = repo_root / "ml-engine" / "artifacts" / "rf_model.joblib"
    if not model_file.exists():
        pytest.skip("Model artifact not yet compiled in artifacts directory.")

    detector = MLDetector(model_path=model_file)
    assert detector.is_loaded is True

    # Warmup predictions to absorb Windows dynamic DLL/thread initialization
    for _ in range(5):
        _ = detector.predict("warmup test request")

    # Test benign prediction
    res_benign = detector.predict("/books/1/read/?page=2")
    assert res_benign.model_loaded is True
    assert res_benign.is_attack is False

    # Test SQLi attack prediction across 5 iterations
    latencies = []
    for _ in range(5):
        res_sqli = detector.predict("UNION SELECT username, password FROM users--")
        latencies.append(res_sqli.latency_ms)

    assert res_sqli.model_loaded is True
    assert res_sqli.is_attack is True
    assert res_sqli.attack_type.upper() in ["SQLI", "SQL_INJECTION", "ATTACK"]
    assert res_sqli.confidence > 0.50
    avg_lat = sum(latencies) / len(latencies)
    assert avg_lat < 15.0, f"Average latency {avg_lat:.2f}ms exceeds 15ms threshold"
