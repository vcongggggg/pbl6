"""Unit tests for Task 6.3: Zero-Day & Obfuscated Attack Anomaly Evaluation and CWE-502 Verification.

Academic & Security Specs:
  - Task 6.3 (Issue #28): Multi-Tier WAF Anomaly Detection Evaluation.
  - CWE-502: Mitigation of Deserialization of Untrusted Data via SHA-256 signature checking.
  - MDPI Electronics (2025): 3-Tier WAF Risk Score normalization and evaluation.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pytest

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ML_ENGINE_DIR = BASE_DIR / "ml-engine"
GATEWAY_DIR = BASE_DIR / "gateway"

if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

from app.security.anomaly import AnomalyDetector  # noqa: E402
from app.security.ml_detector import MLDetector  # noqa: E402
from models.evaluate_anomaly import (  # noqa: E402
    generate_markdown_report,
    generate_obfuscated_zero_day_payloads,
)
from models.train_iforest import normalize_anomaly_score  # noqa: E402

# -----------------------------------------------------------------------------
# 1. EVALUATION SUITE GENERATION TESTS
# -----------------------------------------------------------------------------

def test_generate_obfuscated_zero_day_payloads_structure():
    """Verify that generate_obfuscated_zero_day_payloads generates required structure."""
    samples = generate_obfuscated_zero_day_payloads()
    assert isinstance(samples, list)
    assert len(samples) == 500

    expected_keys = {"method", "path", "query_params", "headers", "body", "attack_type", "label"}
    attack_types = set()

    for s in samples:
        assert expected_keys.issubset(s.keys())
        assert s["label"] in [1, 2, 3, 4]
        assert s["method"] in ["GET", "POST"]
        attack_types.add(s["attack_type"])

    assert "SQLI_OBFUSCATED" in attack_types
    assert "XSS_OBFUSCATED" in attack_types
    assert "PATH_OBFUSCATED" in attack_types
    assert "CMD_OBFUSCATED" in attack_types


def test_normalize_anomaly_score_properties():
    """Verify mathematical properties of normalize_anomaly_score:

    - raw >= 0: inlier -> mapped to [0, 30]
    - raw < 0: outlier -> mapped to [30, 100]
    - strictly monotonic
    - bounded within [0.0, 100.0]
    """
    assert normalize_anomaly_score(0.2) == 0.0
    assert normalize_anomaly_score(0.1) == 0.0
    assert normalize_anomaly_score(0.0) == 30.0
    assert normalize_anomaly_score(-0.01) == 38.5
    assert normalize_anomaly_score(-0.05) == 72.5
    assert normalize_anomaly_score(-0.1) == 100.0
    assert normalize_anomaly_score(-0.5) == 100.0

    # Monotonicity test
    scores = np.linspace(0.3, -0.2, 50)
    risk_scores = [normalize_anomaly_score(s) for s in scores]
    for i in range(len(risk_scores) - 1):
        assert risk_scores[i] <= risk_scores[i + 1], "Risk score must be monotonically non-decreasing as raw score decreases"


def test_generate_markdown_report_structure(tmp_path: Path):
    """Verify markdown report generation formatting and tables."""
    fake_summary = {
        "task": "TASK-6.3-TEST",
        "description": "Test Summary",
        "evaluated_at": "2026-09-20 12:00:00 UTC",
        "models": {
            "isolation_forest": "ml-engine/artifacts/iforest_model.joblib",
            "random_forest": "ml-engine/artifacts/rf_model.joblib",
        },
        "datasets": {
            "benign_baseline": {
                "name": "Benign Validation Baseline",
                "sample_count": 100,
                "is_attack": False,
                "rule_engine": {"triggered": 0, "rate": 0.0, "avg_risk_score": 0.0, "avg_latency_ms": 0.01},
                "random_forest": {"triggered": 0, "rate": 0.0, "avg_risk_score": 0.5, "avg_latency_ms": 0.02},
                "isolation_forest": {"triggered": 1, "triggered_high_risk": 0, "rate": 1.0, "avg_risk_score": 2.0, "avg_raw_score": 0.2, "raw_min": -0.01, "raw_max": 0.3, "avg_latency_ms": 0.01},
                "ensemble_3tier": {"triggered": 1, "rate": 1.0, "avg_risk_score": 2.5, "total_pipeline_latency_ms": 0.04},
            },
            "known_attacks": {
                "name": "Known Attack Test Set",
                "sample_count": 100,
                "is_attack": True,
                "rule_engine": {"triggered": 75, "rate": 75.0, "avg_risk_score": 60.0, "avg_latency_ms": 0.01},
                "random_forest": {"triggered": 100, "rate": 100.0, "avg_risk_score": 99.0, "avg_latency_ms": 0.02},
                "isolation_forest": {"triggered": 25, "triggered_high_risk": 20, "rate": 25.0, "avg_risk_score": 28.0, "avg_raw_score": 0.02, "raw_min": -0.15, "raw_max": 0.25, "avg_latency_ms": 0.01},
                "ensemble_3tier": {"triggered": 100, "rate": 100.0, "avg_risk_score": 99.5, "total_pipeline_latency_ms": 0.04},
            },
            "zero_day_obfuscated": {
                "name": "Zero-Day & Obfuscated Attacks",
                "sample_count": 100,
                "is_attack": True,
                "rule_engine": {"triggered": 60, "rate": 60.0, "avg_risk_score": 48.0, "avg_latency_ms": 0.01},
                "random_forest": {"triggered": 100, "rate": 100.0, "avg_risk_score": 98.0, "avg_latency_ms": 0.02},
                "isolation_forest": {"triggered": 24, "triggered_high_risk": 24, "rate": 24.0, "avg_risk_score": 26.0, "avg_raw_score": 0.03, "raw_min": -0.12, "raw_max": 0.24, "avg_latency_ms": 0.01},
                "ensemble_3tier": {"triggered": 100, "rate": 100.0, "avg_risk_score": 98.5, "total_pipeline_latency_ms": 0.04},
            },
        },
    }

    report_path = generate_markdown_report(fake_summary)
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "# Báo Cáo Đánh Giá Phát Hiện Tấn Công Dị Biệt & Zero-Day (Task 6.3)" in content
    assert "3 tầng" in content
    assert "Isolation Forest" in content


# -----------------------------------------------------------------------------
# 2. CWE-502 CRYPTOGRAPHIC SHA-256 VERIFICATION TESTS
# -----------------------------------------------------------------------------

def test_anomaly_detector_sha256_verification_and_tamper_rejection():
    """Ensure AnomalyDetector verifies SHA-256 and rejects tampered joblib files."""
    real_model_path = ML_ENGINE_DIR / "artifacts" / "iforest_model.joblib"
    if not real_model_path.exists():
        pytest.skip("Artifacts not available")

    detector = AnomalyDetector()
    # Legitimate load should succeed
    success = detector.load_model(real_model_path)
    assert success is True
    assert detector.is_loaded is True

    # Test tampering rejection in a temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        fake_model = tmp_path / "iforest_model.joblib"
        fake_meta = tmp_path / "iforest_metadata.json"

        fake_model.write_bytes(b"tampered_malicious_payload_content")
        # Metadata expects different hash
        fake_meta.write_text(json.dumps({"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}))

        tampered_detector = AnomalyDetector()
        tamper_success = tampered_detector.load_model(fake_model)

        assert tamper_success is False, "AnomalyDetector must reject model when SHA-256 hash does not match"
        assert tampered_detector.is_loaded is False


def test_ml_detector_sha256_verification_and_tamper_rejection():
    """Ensure MLDetector (Random Forest) verifies SHA-256 and rejects tampered files."""
    real_model_path = ML_ENGINE_DIR / "artifacts" / "rf_model.joblib"
    if not real_model_path.exists():
        pytest.skip("Artifacts not available")

    detector = MLDetector()
    # Legitimate load should succeed
    success = detector.load_model(real_model_path)
    assert success is True
    assert detector.is_loaded is True

    # Test tampering rejection
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        fake_model = tmp_path / "rf_model.joblib"
        fake_meta = tmp_path / "rf_metadata.json"

        fake_model.write_bytes(b"tampered_rf_payload_content")
        fake_meta.write_text(json.dumps({"sha256_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}))

        tampered_detector = MLDetector()
        tamper_success = tampered_detector.load_model(fake_model)

        assert tamper_success is False, "MLDetector must reject model when SHA-256 hash does not match"
        assert tampered_detector.is_loaded is False
