import json

import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response

from app.db.models import RequestLog, SecurityEvent
from app.db.session import SessionLocal


@respx.mock
def test_gateway_detects_sqli_and_persists_security_event_non_blocking(client: TestClient):
    """Verifies that a malicious SQLi request is detected, logged, and forwarded."""
    respx.get("http://juice-shop:3000/rest/products/search?q=apple%27%20OR%201%3D1--").mock(
        return_value=Response(200, json={"status": "success", "data": []})
    )

    response = client.get("/api/proxy/rest/products/search?q=apple%27%20OR%201%3D1--")
    # Non-blocking: request still succeeds with 200 OK
    assert response.status_code == status.HTTP_200_OK
    assert "X-Request-ID" in response.headers
    req_id = response.headers["X-Request-ID"]

    # Verify Database Traceability
    with SessionLocal() as db:
        req_log = db.query(RequestLog).filter(RequestLog.request_id == req_id).first()
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()

        assert req_log is not None
        assert sec_event is not None
        assert sec_event.request_id == req_log.request_id
        assert sec_event.attack_type == "SQL_INJECTION"
        assert sec_event.action == "DETECTED"
        assert sec_event.rule_score is not None and sec_event.rule_score > 0.0

        details = json.loads(sec_event.details)
        assert details["total_matches"] >= 1
        assert any(m["rule_id"] == "SQLI-001" for m in details["matches"])


@respx.mock
def test_gateway_detects_xss_in_body_non_blocking(client: TestClient):
    """Verifies XSS payload in POST body is detected, logged, and forwarded."""
    respx.post("http://juice-shop:3000/api/Feedbacks").mock(
        return_value=Response(201, json={"status": "created"})
    )

    xss_body = {
        "comment": "<script>alert('XSS-PBL6')</script>",
        "rating": 1,
    }
    response = client.post("/api/proxy/api/Feedbacks", json=xss_body)
    assert response.status_code == status.HTTP_201_CREATED
    req_id = response.headers["X-Request-ID"]

    with SessionLocal() as db:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
        assert sec_event is not None
        assert sec_event.attack_type == "XSS"
        assert sec_event.severity in ("HIGH", "CRITICAL")


@respx.mock
def test_gateway_detects_path_traversal_non_blocking(client: TestClient):
    """Verifies Path Traversal in query param is detected, logged, and forwarded."""
    respx.get("http://juice-shop:3000/rest/doc?file=../../etc/passwd").mock(
        return_value=Response(200, json={"content": "mocked file"})
    )

    response = client.get("/api/proxy/rest/doc?file=../../etc/passwd")
    assert response.status_code == status.HTTP_200_OK
    req_id = response.headers["X-Request-ID"]

    with SessionLocal() as db:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
        assert sec_event is not None
        assert sec_event.attack_type == "PATH_TRAVERSAL"


@respx.mock
def test_gateway_detects_command_injection_non_blocking(client: TestClient):
    """Verifies Command Injection in query param is detected, logged, and forwarded."""
    respx.get("http://juice-shop:3000/api/system/ping?host=127.0.0.1%3B%20whoami").mock(
        return_value=Response(200, json={"output": "pong"})
    )

    response = client.get("/api/proxy/api/system/ping?host=127.0.0.1%3B%20whoami")
    assert response.status_code == status.HTTP_200_OK
    req_id = response.headers["X-Request-ID"]

    with SessionLocal() as db:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
        assert sec_event is not None
        assert sec_event.attack_type == "COMMAND_INJECTION"


@respx.mock
def test_gateway_benign_request_creates_no_security_event(client: TestClient):
    """Verifies that legitimate traffic is logged in requests table with NO security_event."""
    respx.get("http://juice-shop:3000/rest/products/search?q=apple+juice").mock(
        return_value=Response(200, json={"status": "success", "data": [{"name": "Apple Juice"}]})
    )

    response = client.get("/api/proxy/rest/products/search?q=apple+juice")
    assert response.status_code == status.HTTP_200_OK
    req_id = response.headers["X-Request-ID"]

    with SessionLocal() as db:
        req_log = db.query(RequestLog).filter(RequestLog.request_id == req_id).first()
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()

        assert req_log is not None
        assert sec_event is None  # Benign request must NOT generate security event
