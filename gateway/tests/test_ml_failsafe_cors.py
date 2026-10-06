from fastapi.testclient import TestClient

from app.api.proxy import get_ml_detector


def test_health_ml_status(client: TestClient):
    """Verifies that GET /health returns ml_status field."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "ml_status" in data
    assert data["ml_status"] in ("available", "unavailable")


def test_ml_failsafe_when_unloaded(client: TestClient):
    """Verifies fail-safe behavior when ML model is unloaded."""
    detector = get_ml_detector()
    orig_model = detector._model
    orig_classes = detector._classes
    orig_path = detector._model_path
    orig_is_loaded = detector._is_loaded
    try:
        detector.unload()
        assert not detector.ml_available

        # Check /health reflects unavailable
        res_health = client.get("/health")
        assert res_health.status_code == 200
        assert res_health.json()["ml_status"] == "unavailable"

        # Prediction returns model_loaded=False
        pred = detector.predict("SELECT * FROM users")
        assert not pred.model_loaded
        assert not pred.is_attack
    finally:
        detector._model = orig_model
        detector._classes = orig_classes
        detector._model_path = orig_path
        detector._is_loaded = orig_is_loaded


def test_cors_configuration(client: TestClient):
    """Verifies strict CORS origin validation (Master Plan A4)."""
    # 1. Allowed origin preflight
    res_allowed = client.options(
        "/api/proxy/books",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"

    # 2. Disallowed untrusted origin
    res_untrusted = client.options(
        "/api/proxy/books",
        headers={
            "Origin": "http://untrusted-evil-site.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_untrusted.headers.get("access-control-allow-origin") != "http://untrusted-evil-site.com"
