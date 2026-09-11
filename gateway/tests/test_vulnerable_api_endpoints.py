import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response


@respx.mock
def test_proxy_bola_order_endpoint(client: TestClient):
    """Verifies Gateway proxies BOLA/IDOR endpoint (/api/v1/vulnerable/orders/{id}/)."""
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

    response = client.get("/api/proxy/api/v1/vulnerable/orders/163/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["vulnerability"] == "BOLA_IDOR"
    assert data["order_id"] == 163


@respx.mock
def test_proxy_ssrf_endpoint(client: TestClient):
    """Verifies Gateway proxies SSRF endpoint (/api/v1/vulnerable/books/fetch-cover/)."""
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

    response = client.get(f"/api/proxy/api/v1/vulnerable/books/fetch-cover/?url={target_url}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["vulnerability"] == "SSRF"


@respx.mock
def test_proxy_mass_assignment_endpoint(client: TestClient):
    """Verifies Gateway proxies Mass Assignment endpoint (/api/v1/vulnerable/users/profile/update/)."""
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
    response = client.post("/api/proxy/api/v1/vulnerable/users/profile/update/", json=payload)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["vulnerability"] == "MASS_ASSIGNMENT"
    assert response.json()["is_staff"] is True


@respx.mock
def test_proxy_excessive_data_exposure_endpoint(client: TestClient):
    """Verifies Gateway proxies Data Exposure endpoint (/api/v1/vulnerable/users/list/)."""
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

    response = client.get("/api/proxy/api/v1/vulnerable/users/list/")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["vulnerability"] == "EXCESSIVE_DATA_EXPOSURE"
    assert "password_hash" in response.json()["users"][0]
