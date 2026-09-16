import json

import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response

from app.db.models import SecurityEvent, WafConfigModel
from app.db.session import SessionLocal


@respx.mock
def test_phase7_active_blocking_enforces_403_and_records_event(client: TestClient):
    """Verifies that in ACTIVE_BLOCKING mode, critical attack is blocked with HTTP 403

    and structured JSON error response containing Phase 7 breakdown.
    """
    # 1. Set runtime WAF mode to ACTIVE_BLOCKING in database
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if not cfg:
            cfg = WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING")
            db.add(cfg)
        else:
            cfg.value = "ACTIVE_BLOCKING"
        db.commit()

    # Upstream should NOT be called when request is blocked
    upstream_route = respx.get(
        "http://vulnerable-api:5000/rest/products/search?q=apple%27%20UNION%20SELECT%20null%2Cnull--"
    ).mock(return_value=Response(200, json={"data": []}))

    # 2. Fire critical SQLi payload
    response = client.get(
        "/api/proxy/rest/products/search?q=apple%27%20UNION%20SELECT%20null%2Cnull--"
    )

    # 3. Verify HTTP 403 Forbidden and headers
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert upstream_route.called is False
    assert response.headers.get("X-WAF-Action") == "BLOCKED"
    assert response.headers.get("X-WAF-Decision") == "BLOCK"
    assert "X-WAF-Risk-Score" in response.headers
    assert response.headers.get("X-WAF-Mode") == "ACTIVE_BLOCKING"

    # 4. Verify structured JSON body
    data = response.json()
    assert data["blocked"] is True
    assert data["status"] == 403
    assert data["error"] == "WAF_ACCESS_DENIED"
    assert data["decision"] == "BLOCK"
    assert data["attack_type"] == "SQL_INJECTION"
    assert data["threat_score"] >= 80.0
    assert "breakdown" in data
    assert data["breakdown"]["weighted_score"] >= 80.0
    assert "reason" in data

    # 5. Verify database audit record
    req_id = response.headers["X-Request-ID"]
    with SessionLocal() as db:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
        assert sec_event is not None
        assert sec_event.action == "BLOCKED"
        assert sec_event.risk_score >= 80.0
        assert sec_event.rule_score is not None

        details = json.loads(sec_event.details)
        assert details.get("decision") == "BLOCK"
        assert "breakdown" in details


@respx.mock
def test_phase7_monitor_only_mode_forwards_and_attaches_headers(client: TestClient):
    """Verifies that in MONITOR_ONLY mode, critical attack is NOT blocked,

    forwarded with 200 OK, and labeled DETECTED.
    """
    # 1. Set runtime WAF mode to MONITOR_ONLY in database
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if not cfg:
            cfg = WafConfigModel(key="waf_mode", value="MONITOR_ONLY")
            db.add(cfg)
        else:
            cfg.value = "MONITOR_ONLY"
        db.commit()

    # Upstream should be reached in monitor mode
    upstream_route = respx.get(
        "http://vulnerable-api:5000/rest/products/search?q=apple%27%20OR%201%3D1--"
    ).mock(return_value=Response(200, json={"status": "success", "data": []}))

    # 2. Fire SQLi payload
    response = client.get("/api/proxy/rest/products/search?q=apple%27%20OR%201%3D1--")

    # 3. Verify forwarded 200 OK
    assert response.status_code == status.HTTP_200_OK
    assert upstream_route.called is True
    assert response.headers.get("X-WAF-Action") == "MONITOR"
    assert response.headers.get("X-WAF-Decision") == "MONITOR"

    # 4. Verify database record has DETECTED action for monitor mode
    req_id = response.headers["X-Request-ID"]
    with SessionLocal() as db:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
        assert sec_event is not None
        assert sec_event.action == "DETECTED"
        assert sec_event.risk_score > 0.0


@respx.mock
def test_phase7_benign_request_evaluated_as_allow(client: TestClient):
    """Verifies legitimate traffic is evaluated as ALLOW with low threat score."""
    respx.get("http://vulnerable-api:5000/rest/products/search?q=fresh-orange").mock(
        return_value=Response(200, json={"data": [{"id": 1, "name": "Orange"}]})
    )

    response = client.get("/api/proxy/rest/products/search?q=fresh-orange")
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("X-WAF-Action") == "ALLOW"
    assert response.headers.get("X-WAF-Decision") == "ALLOW"
    assert float(response.headers.get("X-WAF-Risk-Score", "100.0")) < 30.0
