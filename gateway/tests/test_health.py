from fastapi import status
from fastapi.testclient import TestClient


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
