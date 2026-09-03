import datetime
import json

import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.db.models import RequestLog, SecurityEvent
from app.db.session import SessionLocal


def test_dashboard_stats_empty(client: TestClient):
    """Verifies stats endpoint on empty or baseline database."""
    # Reset first
    client.post("/dashboard/reset-demo")

    res = client.get("/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_requests"] == 0
    assert data["attacks_detected"] == 0
    assert data["safe_requests"] == 0
    assert data["safe_request_rate"] == 100.0
    assert data["avg_threat_score"] == 0.0
    assert data["waf_mode"] in ["MONITOR_ONLY", "ACTIVE_BLOCKING", "HYBRID", "OFF"]
    assert "Phase 2" in data["active_phase"]


def test_dashboard_events_and_filters(client: TestClient):
    """Verifies events listing, pagination, and severity/type filters."""
    db = SessionLocal()
    try:
        # Seed 2 events
        ev1 = SecurityEvent(
            event_id="evt-sqli-test-1",
            request_id="req-sqli-test-1",
            timestamp=datetime.datetime.utcnow(),
            client_ip="192.168.1.100",
            attack_type="SQL_INJECTION",
            severity="CRITICAL",
            action="DETECTED",
            rule_score=95.0,
            details=json.dumps({
                "rule_matches": [
                    {
                        "rule_id": "SQLI-001",
                        "name": "SQL Injection Tautology",
                        "severity": "CRITICAL",
                        "location": "QUERY",
                        "evidence": "q=' OR 1=1",
                    }
                ]
            }),
        )
        ev2 = SecurityEvent(
            event_id="evt-xss-test-2",
            request_id="req-xss-test-2",
            timestamp=datetime.datetime.utcnow(),
            client_ip="192.168.1.200",
            attack_type="XSS",
            severity="HIGH",
            action="DETECTED",
            rule_score=85.0,
            details=json.dumps({
                "rule_matches": [
                    {
                        "rule_id": "XSS-001",
                        "name": "Script Tag Injection",
                        "severity": "HIGH",
                        "location": "BODY",
                        "evidence": "<script>",
                    }
                ]
            }),
        )
        db.add(ev1)
        db.add(ev2)
        db.commit()
    finally:
        db.close()

    # List all
    res = client.get("/dashboard/events")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2

    # Filter severity CRITICAL
    res_crit = client.get("/dashboard/events?severity=CRITICAL")
    assert res_crit.status_code == 200
    data_crit = res_crit.json()
    assert all(item["severity"] == "CRITICAL" for item in data_crit["items"])

    # Filter attack_type XSS
    res_xss = client.get("/dashboard/events?attack_type=XSS")
    assert res_xss.status_code == 200
    data_xss = res_xss.json()
    assert all(item["attack_type"] == "XSS" for item in data_xss["items"])

    # Search query
    res_q = client.get("/dashboard/events?q=192.168.1.100")
    assert res_q.status_code == 200
    data_q = res_q.json()
    assert any(item["client_ip"] == "192.168.1.100" for item in data_q["items"])


def test_dashboard_timeline(client: TestClient):
    """Verifies timeline endpoint returns formatted list."""
    res = client.get("/dashboard/timeline?minutes=60")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_dashboard_distribution(client: TestClient):
    """Verifies distribution endpoint returns all 4 attack families."""
    res = client.get("/dashboard/distribution")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 4
    keys = {d["key"] for d in data}
    assert "SQL_INJECTION" in keys
    assert "XSS" in keys
    assert "PATH_TRAVERSAL" in keys
    assert "COMMAND_INJECTION" in keys


@respx.mock
def test_dashboard_simulate_and_reset(client: TestClient):
    """Verifies simulator fires requests and reset-demo clears test data."""
    # Mock proxy target upstream for simulate
    respx.get("http://juice-shop:3000/rest/products/search").mock(
        return_value=Response(200, json={"status": "success"})
    )
    respx.post("http://juice-shop:3000/api/Feedbacks").mock(
        return_value=Response(200, json={"status": "created"})
    )

    # Test simulate SQLI
    res_sqli = client.post("/dashboard/simulate", json={"attack_type": "SQLI"})
    assert res_sqli.status_code == 200
    assert res_sqli.json()["simulated"] == "SQL_INJECTION"

    # Test simulate XSS
    res_xss = client.post("/dashboard/simulate", json={"attack_type": "XSS"})
    assert res_xss.status_code == 200
    assert res_xss.json()["simulated"] == "XSS"

    # Test simulate BENIGN
    res_benign = client.post("/dashboard/simulate", json={"attack_type": "BENIGN"})
    assert res_benign.status_code == 200
    assert res_benign.json()["simulated"] == "BENIGN"

    # Verify reset-demo
    res_reset = client.post("/dashboard/reset-demo")
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "ok"

    # Verify database is cleared
    db = SessionLocal()
    try:
        assert db.query(SecurityEvent).count() == 0
        assert db.query(RequestLog).count() == 0
    finally:
        db.close()
