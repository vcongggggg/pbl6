import json

import httpx
import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response

from app.db.models import RequestLog
from app.db.session import SessionLocal


@respx.mock
def test_request_id_generated_and_propagated(client: TestClient):
    """Verifies that an incoming request without X-Request-ID gets one generated and returned."""
    respx.get("http://juice-shop:3000/rest/products").mock(
        return_value=Response(200, json=[{"id": 1, "name": "Apple Juice"}])
    )

    response = client.get("/api/proxy/rest/products")
    assert response.status_code == status.HTTP_200_OK
    assert "X-Request-ID" in response.headers
    request_id = response.headers["X-Request-ID"]
    assert len(request_id) > 0


@respx.mock
def test_custom_request_id_preserved(client: TestClient):
    """Verifies that a valid client-supplied X-Request-ID is preserved and echoed."""
    respx.get("http://juice-shop:3000/rest/products").mock(
        return_value=Response(200, json=[{"id": 1, "name": "Apple Juice"}])
    )

    custom_id = "custom-client-req-9999"
    response = client.get(
        "/api/proxy/rest/products",
        headers={"X-Request-ID": custom_id},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("X-Request-ID") == custom_id


@respx.mock
def test_get_proxy_forwarding_and_query_params(client: TestClient):
    """Verifies GET forwarding preserves path and query parameters."""
    route = respx.get("http://juice-shop:3000/rest/products/search?q=orange").mock(
        return_value=Response(200, json={"data": [{"id": 2, "name": "Orange Juice"}]})
    )

    response = client.get("/api/proxy/rest/products/search?q=orange")
    assert response.status_code == status.HTTP_200_OK
    assert route.called

    data = response.json()
    assert data["data"][0]["name"] == "Orange Juice"

    # Verify DB logging
    req_id = response.headers["X-Request-ID"]
    with SessionLocal() as db:
        log = db.query(RequestLog).filter(RequestLog.request_id == req_id).first()
        assert log is not None
        assert log.method == "GET"
        assert log.path == "/rest/products/search"
        assert log.query_params == "q=orange"
        assert log.response_status == 200
        assert log.response_time_ms is not None
        assert log.response_size is not None


@respx.mock
def test_post_json_proxy_forwarding(client: TestClient):
    """Verifies POST forwarding preserves JSON body and content headers."""
    route = respx.post("http://juice-shop:3000/api/Users").mock(
        return_value=Response(201, json={"status": "success", "data": {"id": 10}})
    )

    payload = {"email": "student@example.com", "password": "SuperSecretPassword123"}
    response = client.post(
        "/api/proxy/api/Users",
        json=payload,
        headers={"Authorization": "Bearer fake-token-12345"},
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert route.called

    req_id = response.headers["X-Request-ID"]
    with SessionLocal() as db:
        log = db.query(RequestLog).filter(RequestLog.request_id == req_id).first()
        assert log is not None
        assert log.method == "POST"
        assert log.path == "/api/Users"
        assert log.response_status == 201

        # Verify sensitive data redaction
        assert log.headers is not None
        headers_dict = json.loads(log.headers)
        assert headers_dict.get("authorization") == "[REDACTED]"
        assert "fake-token-12345" not in log.headers


@respx.mock
def test_response_status_preservation(client: TestClient):
    """Verifies upstream status codes (e.g., 404, 400) are accurately preserved."""
    respx.get("http://juice-shop:3000/rest/unknown-path").mock(
        return_value=Response(404, json={"error": "Not Found"})
    )

    response = client.get("/api/proxy/rest/unknown-path")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["error"] == "Not Found"


@respx.mock
def test_target_unavailable_returns_controlled_502(client: TestClient):
    """Verifies that upstream connection failure returns a controlled 502 Bad Gateway."""
    respx.get("http://juice-shop:3000/rest/down").mock(
        side_effect=httpx.ConnectError("Connection refused by target")
    )

    response = client.get("/api/proxy/rest/down")
    assert response.status_code == status.HTTP_502_BAD_GATEWAY

    data = response.json()
    assert data["status"] == "error"
    assert data["error"]["code"] == "TARGET_UNAVAILABLE"
    # Ensure no internal stack trace leaked
    assert "Traceback" not in response.text

    # Verify DB logging of failed connection
    req_id = response.headers.get("X-Request-ID")
    with SessionLocal() as db:
        log = db.query(RequestLog).filter(RequestLog.request_id == req_id).first()
        assert log is not None
        assert log.response_status == 502


@respx.mock
def test_target_timeout_returns_controlled_504(client: TestClient):
    """Verifies that upstream read/connect timeout returns a controlled 504 Gateway Timeout."""
    respx.get("http://juice-shop:3000/rest/slow").mock(
        side_effect=httpx.ReadTimeout("Target took too long to respond")
    )

    response = client.get("/api/proxy/rest/slow")
    assert response.status_code == status.HTTP_504_GATEWAY_TIMEOUT

    data = response.json()
    assert data["status"] == "error"
    assert data["error"]["code"] == "GATEWAY_TIMEOUT"
    assert "Traceback" not in response.text

    req_id = response.headers.get("X-Request-ID")
    with SessionLocal() as db:
        log = db.query(RequestLog).filter(RequestLog.request_id == req_id).first()
        assert log is not None
        assert log.response_status == 504


@respx.mock
def test_hop_by_hop_headers_are_filtered(client: TestClient):
    """Verifies hop-by-hop headers like Upgrade and custom proxy headers are filtered."""
    route = respx.get("http://juice-shop:3000/rest/headers-check").mock(
        return_value=Response(200, json={"status": "ok"})
    )

    client.get(
        "/api/proxy/rest/headers-check",
        headers={
            "Upgrade": "websocket",
            "X-Custom-Client-Header": "TestValue",
        },
    )
    assert route.called
    sent_request = route.calls.last.request
    assert "upgrade" not in sent_request.headers
    assert sent_request.headers.get("x-custom-client-header") == "TestValue"


@respx.mock
def test_open_proxy_protection(client: TestClient):
    """Verifies gateway only proxies to configured juice-shop despite client headers."""
    route = respx.get("http://juice-shop:3000/api/target").mock(
        return_value=Response(200, json={"status": "safe"})
    )

    response = client.get(
        "/api/proxy/api/target",
        headers={"Host": "evil-external-site.com", "X-Forwarded-Host": "evil.com"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert route.called
    assert route.calls.last.request.url.host == "juice-shop"
