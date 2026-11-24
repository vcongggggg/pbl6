from unittest.mock import patch

import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response


@respx.mock
def test_proxy_bola_order_endpoint(client: TestClient):
    """Verifies Gateway proxies single BOLA/IDOR endpoint request before enumeration threshold."""
    respx.get("http://vulnerable-api:5000/api/v1/vulnerable/orders/163/").mock(
        return_value=Response(
            200,
            json={
                "status": "success",
                "vulnerability": "BOLA_IDOR",
                "order_id": 163,
                "customer_username": "victim_alice",
                "total_amount": 500000.0,
            },
        )
    )

    with patch("app.api.proxy._resolve_active_waf_mode", return_value="MONITOR_ONLY"):
        response = client.get("/api/proxy/api/v1/vulnerable/orders/163/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["vulnerability"] == "BOLA_IDOR"
        assert data["order_id"] == 163


@respx.mock
def test_proxy_ssrf_endpoint(client: TestClient):
    """Verifies SSRF endpoint forwards with MONITOR header in MONITOR_ONLY and blocks 403 in ACTIVE_BLOCKING."""
    target_url = "http://127.0.0.1:8000/api/dashboard/stats"
    respx.get(f"http://vulnerable-api:5000/api/v1/vulnerable/books/fetch-cover/?url={target_url}").mock(
        return_value=Response(
            200,
            json={
                "status": "success",
                "vulnerability": "SSRF",
                "fetched_url": target_url,
                "http_status": 200,
            },
        )
    )

    with patch("app.api.proxy._resolve_active_waf_mode", return_value="MONITOR_ONLY"):
        response = client.get(f"/api/proxy/api/v1/vulnerable/books/fetch-cover/?url={target_url}")
        assert response.status_code == status.HTTP_200_OK
        assert response.headers.get("X-WAF-Action") == "MONITOR"
        assert response.json()["vulnerability"] == "SSRF"

    with patch("app.api.proxy._resolve_active_waf_mode", return_value="ACTIVE_BLOCKING"):
        blocked = client.get(f"/api/proxy/api/v1/vulnerable/books/fetch-cover/?url={target_url}")
        assert blocked.status_code == status.HTTP_403_FORBIDDEN
        assert blocked.json()["attack_type"] == "SSRF"


@respx.mock
def test_proxy_mass_assignment_endpoint(client: TestClient):
    """Verifies Mass Assignment forwards in MONITOR_ONLY and blocks 403 in ACTIVE_BLOCKING."""
    respx.post("http://vulnerable-api:5000/api/v1/vulnerable/users/profile/update/").mock(
        return_value=Response(
            200,
            json={
                "status": "success",
                "vulnerability": "MASS_ASSIGNMENT",
                "is_staff": True,
                "is_superuser": True,
                "escalated_fields_exploited": ["role=admin", "is_staff=True"],
            },
        )
    )

    payload = {"user_id": 2, "role": "admin", "is_staff": True}
    with patch("app.api.proxy._resolve_active_waf_mode", return_value="MONITOR_ONLY"):
        response = client.post("/api/proxy/api/v1/vulnerable/users/profile/update/", json=payload)
        assert response.status_code == status.HTTP_200_OK
        assert response.headers.get("X-WAF-Action") == "MONITOR"
        assert response.json()["vulnerability"] == "MASS_ASSIGNMENT"

    with patch("app.api.proxy._resolve_active_waf_mode", return_value="ACTIVE_BLOCKING"):
        blocked = client.post("/api/proxy/api/v1/vulnerable/users/profile/update/", json=payload)
        assert blocked.status_code == status.HTTP_403_FORBIDDEN
        assert blocked.json()["attack_type"] == "MASS_ASSIGNMENT"


@respx.mock
def test_proxy_excessive_data_exposure_endpoint(client: TestClient):
    """Verifies Data Exposure endpoint preserves key in MONITOR_ONLY and scrubs value in ACTIVE_BLOCKING."""
    respx.get("http://vulnerable-api:5000/api/v1/vulnerable/users/list/").mock(
        return_value=Response(
            200,
            json={
                "status": "success",
                "vulnerability": "EXCESSIVE_DATA_EXPOSURE",
                "count": 1,
                "users": [{"id": 1, "username": "admin", "password_hash": "pbkdf2_sha256$..."}],
            },
        )
    )

    with patch("app.api.proxy._resolve_active_waf_mode", return_value="MONITOR_ONLY"):
        response = client.get("/api/proxy/api/v1/vulnerable/users/list/")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["vulnerability"] == "EXCESSIVE_DATA_EXPOSURE"
        assert response.json()["users"][0]["password_hash"] == "pbkdf2_sha256$..."

    with patch("app.api.proxy._resolve_active_waf_mode", return_value="ACTIVE_BLOCKING"):
        scrubbed = client.get("/api/proxy/api/v1/vulnerable/users/list/")
        assert scrubbed.status_code == status.HTTP_200_OK
        assert scrubbed.headers.get("X-WAF-DLP-Redacted") == "true"
        assert scrubbed.json()["users"][0]["password_hash"] == "[REDACTED_BY_WAF_DLP]"
