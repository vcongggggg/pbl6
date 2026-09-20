import json
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pytest
import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response
from sklearn.ensemble import IsolationForest

from app.api.proxy import get_anomaly_detector
from app.db.models import SecurityEvent, WafConfigModel
from app.db.session import SessionLocal
from app.security.ml_detector import MLDetector


@respx.mock
def test_anomaly_proxy_graceful_fallback_without_model(client: TestClient):
    """Verifies that when Anomaly model is not loaded, Gateway proxies seamlessly

    without throwing exceptions or attaching Anomaly telemetry headers (NIST SP 800-115).
    """
    detector = get_anomaly_detector()
    detector.unload()

    # Upstream mock
    respx.get("http://vulnerable-api:5000/rest/products/search?q=orange").mock(
        return_value=Response(200, json={"items": ["orange"]})
    )

    response = client.get("/api/proxy/rest/products/search?q=orange")
    assert response.status_code == status.HTTP_200_OK
    assert "X-WAF-Action" in response.headers
    assert "X-WAF-Decision" in response.headers
    assert "X-WAF-Anomaly-Score" not in response.headers


@respx.mock
def test_anomaly_proxy_integration_with_active_model(client: TestClient):
    """Verifies that with active Isolation Forest model in RAM, Gateway incorporates anomaly_score

    into RiskEngine, attaches X-WAF-Anomaly headers, and records anomaly_score in SQLite.
    """
    # 1. Train an Isolation Forest model on benign vectors
    benign_urls = [
        f"/rest/products/search?q=item{i}&category=books&page={i % 5}"
        for i in range(1, 60)
    ]
    X_train = np.array([MLDetector.extract_features(u) for u in benign_urls])

    model = IsolationForest(n_estimators=30, random_state=42)
    model.fit(X_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_path = Path(tmp_dir) / "active_iforest.joblib"
        joblib.dump(model, model_path)

        detector = get_anomaly_detector()
        loaded = detector.load_model(model_path)
        assert loaded is True

        try:
            # Ensure ACTIVE_BLOCKING mode
            with SessionLocal() as db:
                cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
                if not cfg:
                    cfg = WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING")
                    db.add(cfg)
                else:
                    cfg.value = "ACTIVE_BLOCKING"
                db.commit()

            # 2. Send normal traffic -> should forward with telemetry headers
            respx.get("http://vulnerable-api:5000/rest/products/search?q=apple").mock(
                return_value=Response(200, json={"items": ["apple"]})
            )

            resp_benign = client.get("/api/proxy/rest/products/search?q=apple")
            assert resp_benign.status_code == status.HTTP_200_OK
            assert "X-WAF-Anomaly-Score" in resp_benign.headers
            assert "X-WAF-Anomaly-Latency" in resp_benign.headers
            assert resp_benign.headers["X-WAF-Anomaly-Latency"].endswith("ms")

            # 3. Send attack traffic -> blocked with 403, headers attached, anomaly_score logged to SQLite
            respx.get(
                "http://vulnerable-api:5000/rest/products/search?q=%27%20UNION%20SELECT%20null%2Cnull--"
            ).mock(return_value=Response(200, json={"data": []}))

            resp_attack = client.get(
                "/api/proxy/rest/products/search?q=%27%20UNION%20SELECT%20null%2Cnull--"
            )
            assert resp_attack.status_code == status.HTTP_403_FORBIDDEN
            assert "X-WAF-Anomaly-Score" in resp_attack.headers
            assert "X-WAF-Anomaly-Latency" in resp_attack.headers

            # Verify SQLite event has anomaly_score populated
            req_id = resp_attack.headers["X-Request-ID"]
            with SessionLocal() as db:
                event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
                assert event is not None
                assert event.anomaly_score is not None
                assert event.anomaly_score >= 0.0

                details = json.loads(event.details)
                assert "anomaly_inference" in details
                assert details["anomaly_inference"]["model_loaded"] is True
                assert details["breakdown"]["anomaly_score"] is not None
        finally:
            detector.unload()


@respx.mock
def test_anomaly_proxy_production_artifact_integration(client: TestClient):
    """Verifies that the production iforest_model.joblib artifact operates seamlessly

    within the live reverse proxy pipeline, attaching headers and logging anomaly scores.
    """
    repo_root = Path(__file__).resolve().parents[2]
    model_path = repo_root / "ml-engine" / "artifacts" / "iforest_model.joblib"
    if not model_path.exists():
        pytest.skip("Production artifact iforest_model.joblib not present")

    detector = get_anomaly_detector()
    loaded = detector.load_model(model_path)
    assert loaded is True
    assert detector.is_loaded

    try:
        # Ensure ACTIVE_BLOCKING mode
        with SessionLocal() as db:
            cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
            if not cfg:
                cfg = WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING")
                db.add(cfg)
            else:
                cfg.value = "ACTIVE_BLOCKING"
            db.commit()

        # 1. Normal benign request
        respx.get("http://vulnerable-api:5000/api/v1/users?page=1").mock(
            return_value=Response(200, json={"users": ["alice", "bob"]})
        )

        resp_benign = client.get("/api/proxy/api/v1/users?page=1")
        assert resp_benign.status_code == status.HTTP_200_OK
        assert "X-WAF-Anomaly-Score" in resp_benign.headers
        assert float(resp_benign.headers["X-WAF-Anomaly-Score"]) <= 30.0
        assert "X-WAF-Anomaly-Latency" in resp_benign.headers

        # 2. Critical obfuscated attack request triggering active blocking
        attack_query = ("%27%22" * 40) + "--UNION%20SELECT%20null,null--"
        respx.get(
            "http://vulnerable-api:5000/rest/products/search"
        ).mock(return_value=Response(200, json={"items": []}))

        resp_attack = client.get(
            f"/api/proxy/rest/products/search?q={attack_query}"
        )
        assert resp_attack.status_code == status.HTTP_403_FORBIDDEN
        assert "X-WAF-Anomaly-Score" in resp_attack.headers
        anomaly_score_header = float(resp_attack.headers["X-WAF-Anomaly-Score"])
        assert anomaly_score_header > 60.0

        # 3. Verify SQLite persistence of anomaly_score
        req_id = resp_attack.headers["X-Request-ID"]
        with SessionLocal() as db:
            event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
            assert event is not None
            assert event.anomaly_score is not None
            assert event.anomaly_score == anomaly_score_header
            assert event.action == "BLOCKED"
    finally:
        detector.unload()
