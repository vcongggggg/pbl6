import json

import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response

from app.api.proxy import get_rate_limiter
from app.db.models import SecurityEvent, WafConfigModel
from app.db.session import SessionLocal


@respx.mock
def test_rate_limit_active_enforces_429_and_records_event(client: TestClient):
    """Verifies that exceeding rate limit in ACTIVE_BLOCKING triggers HTTP 429,

    returns Retry-After header, blocks upstream call, and logs SecurityEvent.
    """
    # 1. Reset rate limiter to ensure clean state
    limiter = get_rate_limiter()
    limiter.reset()

    # 2. Configure ACTIVE_BLOCKING mode
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if not cfg:
            cfg = WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING")
            db.add(cfg)
        else:
            cfg.value = "ACTIVE_BLOCKING"
        db.commit()

    # Upstream route for login endpoint (sensitive scope 'auth' has limit = 10)
    upstream_route = respx.post("http://vulnerable-api:5000/rest/user/login").mock(
        return_value=Response(200, json={"token": "fake-jwt-token"})
    )

    # 3. Fire 10 legitimate login requests within allowed quota
    for i in range(10):
        res = client.post(
            "/api/proxy/rest/user/login",
            json={"email": f"user{i}@example.com", "password": "securePassword123"},
        )
        assert res.status_code == status.HTTP_200_OK
        assert "X-RateLimit-Limit" in res.headers
        assert int(res.headers["X-RateLimit-Remaining"]) == 10 - (i + 1)

    assert upstream_route.call_count == 10

    # 4. The 11th request MUST be blocked with HTTP 429 Too Many Requests
    blocked_res = client.post(
        "/api/proxy/rest/user/login",
        json={"email": "attacker@example.com", "password": "wrongPassword"},
    )

    # Upstream should NOT receive the 11th request
    assert upstream_route.call_count == 10
    assert blocked_res.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert blocked_res.headers.get("X-WAF-Action") == "RATE_LIMIT"
    assert blocked_res.headers.get("X-WAF-Decision") == "RATE_LIMIT"
    assert "Retry-After" in blocked_res.headers
    assert int(blocked_res.headers["Retry-After"]) > 0
    assert blocked_res.headers.get("X-RateLimit-Remaining") == "0"

    # Verify JSON body structure
    data = blocked_res.json()
    assert data["blocked"] is True
    assert data["status"] == 429
    assert data["error"] == "RATE_LIMIT_EXCEEDED"
    assert data["scope"] == "auth"
    assert data["limit"] == 10
    assert data["current_count"] == 10
    assert data["retry_after"] > 0

    # Verify SecurityEvent was persisted in SQLite
    req_id = blocked_res.headers["X-Request-ID"]
    with SessionLocal() as db:
        event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
        assert event is not None
        assert event.attack_type == "RATE_LIMIT_EXCEEDED"
        assert event.action == "RATE_LIMIT"
        assert event.severity == "HIGH"
        assert event.risk_score == 75.0

        details = json.loads(event.details)
        assert details["scope"] == "auth"
        assert details["limit"] == 10


@respx.mock
def test_rate_limit_monitor_only_does_not_block(client: TestClient):
    """Verifies that in MONITOR_ONLY mode, rate limit exceeded allows request through

    with status 200 and records SecurityEvent with action DETECTED.
    """
    limiter = get_rate_limiter()
    limiter.reset()

    # Configure MONITOR_ONLY mode
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if not cfg:
            cfg = WafConfigModel(key="waf_mode", value="MONITOR_ONLY")
            db.add(cfg)
        else:
            cfg.value = "MONITOR_ONLY"
        db.commit()

    upstream_route = respx.post("http://vulnerable-api:5000/rest/user/login").mock(
        return_value=Response(200, json={"token": "test-token"})
    )

    # Fire 11 requests in monitor mode
    for _ in range(11):
        res = client.post(
            "/api/proxy/rest/user/login",
            json={"email": "monitored@example.com", "password": "pass"},
        )
        assert res.status_code == status.HTTP_200_OK

    # All 11 reached upstream
    assert upstream_route.call_count == 11

    # Verify database has DETECTED record for the 11th request
    last_req_id = res.headers["X-Request-ID"]
    with SessionLocal() as db:
        event = db.query(SecurityEvent).filter(SecurityEvent.request_id == last_req_id).first()
        assert event is not None
        assert event.attack_type == "RATE_LIMIT_EXCEEDED"
        assert event.action == "DETECTED"
