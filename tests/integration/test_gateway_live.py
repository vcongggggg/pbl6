import os
import pytest
import httpx

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")
TARGET_URL = os.environ.get("TARGET_API_URL", "http://localhost:3000")


@pytest.mark.integration
def test_live_gateway_proxy_to_juice_shop():
    """Live integration test: Verifies genuine end-to-end traffic flow:

    Client -> Gateway -> Juice Shop Target -> Gateway -> Client
    Requires the Docker Compose stack to be running (make docker-up).
    """
    # 1. Check if Gateway is reachable
    try:
        health_resp = httpx.get(f"{GATEWAY_URL}/health", timeout=3.0)
        assert health_resp.status_code == 200
    except Exception as err:
        pytest.skip(
            f"Live Gateway is not running at {GATEWAY_URL} ({err}). "
            "Start Docker stack with 'docker compose up -d' before running integration tests."
        )

    # 2. Check if Gateway target check reports target reachability
    target_health_resp = httpx.get(f"{GATEWAY_URL}/health/target", timeout=3.0)
    assert target_health_resp.status_code == 200
    target_data = target_health_resp.json()
    if not target_data.get("reachable"):
        pytest.skip(
            f"Juice Shop target is not reachable from Gateway ({target_data.get('error')})."
        )

    # 3. Send real proxied request to search products
    client = httpx.Client(timeout=10.0)
    custom_request_id = "integration-test-req-001"

    response = client.get(
        f"{GATEWAY_URL}/api/proxy/rest/products/search",
        params={"q": "apple"},
        headers={"X-Request-ID": custom_request_id},
    )

    # 4. Verify end-to-end expectations
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_request_id
    assert "application/json" in response.headers.get("content-type", "")

    data = response.json()
    assert "data" in data
    assert isinstance(data["data"], list)
