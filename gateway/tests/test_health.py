import respx
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response


def test_health_check_endpoint(client: TestClient):
    """Verifies that GET /health returns status 200 and structured health metadata."""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] == "ok"
    assert "app" in data
    assert "environment" in data
    assert data["version"] == "0.1.0"


def test_root_ping_endpoint(client: TestClient):
    """Verifies that GET / returns status 200 and root ping response."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] == "ok"
    assert "docs" in data


@respx.mock
def test_target_health_reachable(client: TestClient):
    """Verifies that GET /health/target returns ok when target is reachable."""
    respx.get("http://juice-shop:3000").mock(return_value=Response(200, text="Juice Shop OK"))

    response = client.get("/health/target")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] == "ok"
    assert data["reachable"] is True
    assert data["upstream_status"] == 200
    assert data["error"] is None


@respx.mock
def test_target_health_unreachable(client: TestClient):
    """Verifies that GET /health/target gracefully handles unreachable target."""
    import httpx

    respx.get("http://juice-shop:3000").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    response = client.get("/health/target")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] == "unreachable"
    assert data["reachable"] is False
    assert data["upstream_status"] is None
    assert "Connection refused" in data["error"]
