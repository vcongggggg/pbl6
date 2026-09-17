import json
import tempfile
from pathlib import Path

import joblib
import numpy as np
import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response
from sklearn.ensemble import RandomForestClassifier

from app.api.proxy import get_ml_detector
from app.db.models import SecurityEvent, WafConfigModel
from app.db.session import SessionLocal
from app.security.ml_detector import MLDetector


@respx.mock
def test_ml_proxy_graceful_fallback_without_model(client: TestClient):
    """Verifies that when ML model is not loaded, Gateway proxies seamlessly

    using RuleEngine, without throwing exceptions or attaching ML headers.
    """
    detector = get_ml_detector()
    detector.unload()

    # Upstream mock
    respx.get("http://vulnerable-api:5000/rest/products/search?q=apple").mock(
        return_value=Response(200, json={"items": ["apple"]})
    )

    response = client.get("/api/proxy/rest/products/search?q=apple")
    assert response.status_code == status.HTTP_200_OK
    assert "X-WAF-Action" in response.headers
    assert "X-WAF-Decision" in response.headers
    assert "X-WAF-ML-Score" not in response.headers


@respx.mock
def test_ml_proxy_integration_with_active_model(client: TestClient):
    """Verifies that with active ML model in RAM, Gateway incorporates rf_score

    into RiskEngine, attaches X-WAF-ML headers, and records ml_score in SQLite.
    """
    # 1. Train a classifier on representative benign and attack feature vectors
    benign_vec = MLDetector.extract_features("apple fresh organic")
    sqli_vec = MLDetector.extract_features("' UNION SELECT null,null--")
    X_train = np.array([benign_vec] * 10 + [sqli_vec] * 10)
    y_train = ["BENIGN"] * 10 + ["SQLI"] * 10

    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    clf.fit(X_train, y_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_path = Path(tmp_dir) / "active_rf.joblib"
        joblib.dump(clf, model_path)

        detector = get_ml_detector()
        loaded = detector.load_model(model_path)
        assert loaded is True

        # Ensure ACTIVE_BLOCKING mode
        with SessionLocal() as db:
            cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
            if not cfg:
                cfg = WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING")
                db.add(cfg)
            else:
                cfg.value = "ACTIVE_BLOCKING"
            db.commit()

        # Upstream route (should not be reached when critical attack is blocked)
        upstream = respx.get(
            "http://vulnerable-api:5000/rest/products/search?q=%27%20UNION%20SELECT%20null%2Cnull--"
        ).mock(return_value=Response(200, json={"data": []}))

        response = client.get(
            "/api/proxy/rest/products/search?q=%27%20UNION%20SELECT%20null%2Cnull--"
        )

        # Must be blocked with 403
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert upstream.called is False

        # Verify ML telemetry headers
        assert "X-WAF-ML-Score" in response.headers
        assert "X-WAF-ML-Type" in response.headers
        assert "X-WAF-ML-Latency" in response.headers
        assert response.headers["X-WAF-ML-Latency"].endswith("ms")

        # Verify SQLite event has ml_score populated
        req_id = response.headers["X-Request-ID"]
        with SessionLocal() as db:
            event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
            assert event is not None
            assert event.ml_score is not None
            assert event.ml_score >= 0.0

            details = json.loads(event.details)
            assert "ml_inference" in details
            assert details["ml_inference"]["model_loaded"] is True

        # Clean up detector state
        detector.unload()
