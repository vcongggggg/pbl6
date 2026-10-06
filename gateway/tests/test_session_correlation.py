"""Unit and integration tests for Attack Session Correlation (Master Plan B4)."""

import datetime

from fastapi.testclient import TestClient

from app.db.models import SecurityEvent
from app.db.session import SessionLocal
from app.services.security import derive_session_id, map_to_kill_chain_stage


def test_derive_session_id_windowing():
    t0 = datetime.datetime(2026, 10, 7, 10, 0, 0, tzinfo=datetime.timezone.utc)
    t1 = datetime.datetime(2026, 10, 7, 10, 10, 0, tzinfo=datetime.timezone.utc)  # +10m (same window)
    t2 = datetime.datetime(2026, 10, 7, 10, 20, 0, tzinfo=datetime.timezone.utc)  # +20m (new window)

    # Same window -> same session
    sess_0 = derive_session_id("192.168.1.100", t0)
    sess_1 = derive_session_id("192.168.1.100", t1)
    assert sess_0 == sess_1

    # Different IP -> different session
    sess_other_ip = derive_session_id("192.168.1.101", t0)
    assert sess_0 != sess_other_ip

    # Shifted window -> different session
    sess_2 = derive_session_id("192.168.1.100", t2)
    assert sess_0 != sess_2


def test_map_to_kill_chain_stage():
    assert map_to_kill_chain_stage("SQLI") == "EXPLOITATION"
    assert map_to_kill_chain_stage("COMMAND_INJECTION") == "EXPLOITATION"
    assert map_to_kill_chain_stage("XSS") == "EXPLOITATION"
    assert map_to_kill_chain_stage("RECON_PROBE") == "RECONNAISSANCE"
    assert map_to_kill_chain_stage("SCHEMA_VIOLATION") == "RECONNAISSANCE"
    assert map_to_kill_chain_stage("EVASION_OBFUSCATION") == "EVASION"
    assert map_to_kill_chain_stage("RATE_LIMIT_EXCEEDED") == "PRIVILEGE_ABUSE"
    assert map_to_kill_chain_stage("PATH_TRAVERSAL") == "EXFILTRATION"


def test_dashboard_sessions_api(client: TestClient):
    # Insert a correlated test session with 2 events
    test_ip = "192.168.99.99"
    test_session = derive_session_id(test_ip)

    db = SessionLocal()
    try:
        ev1 = SecurityEvent(
            event_id="test_ev_recon_001",
            request_id="req_recon_001",
            client_ip=test_ip,
            attack_type="RECON_PROBE",
            severity="LOW",
            action="MONITOR",
            risk_score=35.0,
            session_id=test_session,
            kill_chain_stage="RECONNAISSANCE",
        )
        ev2 = SecurityEvent(
            event_id="test_ev_sqli_002",
            request_id="req_sqli_002",
            client_ip=test_ip,
            attack_type="SQLI",
            severity="CRITICAL",
            action="BLOCKED",
            risk_score=95.0,
            session_id=test_session,
            kill_chain_stage="EXPLOITATION",
        )
        db.add_all([ev1, ev2])
        db.commit()
    finally:
        db.close()

    # Query GET /dashboard/sessions
    res = client.get(f"/dashboard/sessions?client_ip={test_ip}")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert data["total"] >= 1

    matched_session = next((s for s in data["items"] if s["session_id"] == test_session), None)
    assert matched_session is not None
    assert matched_session["client_ip"] == test_ip
    assert matched_session["total_events"] == 2
    assert matched_session["max_risk_score"] == 95.0
    assert matched_session["has_blocked"] is True
    assert "RECONNAISSANCE" in matched_session["kill_chain_stages"]
    assert "EXPLOITATION" in matched_session["kill_chain_stages"]
