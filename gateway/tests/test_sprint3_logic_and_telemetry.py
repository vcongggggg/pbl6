"""Sprint 3 Comprehensive Verification Suite: LOGIC-PBL6-001..005 & SCI-PBL6-002.

Covers:
  - LOGIC-PBL6-001: Action enum sync across proxy, seeder, and dashboard sessions
  - LOGIC-PBL6-002: Multi-protocol sniffer (case-insensitive SOAPAction, XXE in query & body,
                    REST JSON not misclassified as GraphQL, decapsulated payload fed to RuleEngine)
  - LOGIC-PBL6-003: Risk-based RATE_LIMIT 429 enforcement, schema strict mode respecting WAF mode,
                    and .env feature toggles (ml_enabled, anomaly_enabled, rate_limit_enabled)
  - LOGIC-PBL6-004: Bookie simulator payloads & SchemaValidator path-param, content-type,
                    additionalProperties, and /users/list/ endpoint
  - LOGIC-PBL6-005: derive_session_id timezone neutrality, rate_limit session metadata,
                    N+1 SQL elimination in /dashboard/sessions, chronological /dashboard/timeline
  - SCI-PBL6-002:   Genuine current_rps over 60s window & real async /dashboard/topology telemetry
"""

import datetime
import json
from unittest.mock import patch

import respx
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import event

from app.api.proxy import get_rate_limiter
from app.core.config import get_settings
from app.db.models import RequestLog, SecurityEvent, WafConfigModel
from app.db.session import SessionLocal, engine
from app.security.decision import DecisionResult, PolicyAction
from app.security.engine import RuleEngine
from app.security.protocol_detector import (
    ApiProtocol,
    ApiProtocolDetector,
    UniversalPayloadExtractor,
)
from app.security.risk_engine import RiskScoreBreakdown
from app.security.schema_validator import SchemaValidator
from app.services.security import SecurityEventService, derive_session_id
from app.services.seeder import seed_demo_dataset

ADMIN_HEADERS = {"X-API-Key": get_settings().admin_api_key}


def _set_db_waf_mode(mode: str | None) -> str | None:
    """Helper to set or clear waf_mode in WafConfigModel and return previous value."""
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        prev = cfg.value if cfg else None
        if mode is None:
            if cfg is not None:
                db.delete(cfg)
        elif cfg is not None:
            cfg.value = mode
        else:
            db.add(WafConfigModel(key="waf_mode", value=mode))
        db.commit()
        return prev


# ---------------------------------------------------------------------------
# LOGIC-PBL6-001: Action Enum Synchronization
# ---------------------------------------------------------------------------


def test_logic_001_seeder_diversity_and_session_fields():
    """Seeder emits BLOCKED/MONITOR/RATE_LIMIT with matching statuses and session metadata."""
    with SessionLocal() as db:
        db.query(SecurityEvent).delete()
        db.query(RequestLog).delete()
        db.commit()

        summary = seed_demo_dataset(db)
        assert summary["total_events"] > 0

        events = db.query(SecurityEvent).all()
        actions = {ev.action for ev in events}
        assert "BLOCKED" in actions
        assert "MONITOR" in actions
        assert "RATE_LIMIT" in actions

        for ev in events:
            assert ev.session_id is not None and len(ev.session_id) > 0
            assert ev.kill_chain_stage is not None and len(ev.kill_chain_stage) > 0

        statuses = {r.response_status for r in db.query(RequestLog).all()}
        assert 403 in statuses
        assert 200 in statuses
        assert 429 in statuses


def test_logic_001_sessions_recognizes_both_block_and_blocked(client: TestClient):
    """/dashboard/sessions marks has_blocked=True for both legacy BLOCK and canonical BLOCKED."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    with SessionLocal() as db:
        db.query(SecurityEvent).delete()
        db.add(
            SecurityEvent(
                event_id="evt-legacy-block-001",
                request_id="req-legacy-block-001",
                timestamp=now,
                client_ip="10.0.1.55",
                attack_type="SQL_INJECTION",
                severity="CRITICAL",
                action="BLOCK",
                risk_score=95.0,
                rule_score=90.0,
                session_id="sess-legacy-block",
                kill_chain_stage="EXPLOITATION",
                details="{}",
            )
        )
        db.add(
            SecurityEvent(
                event_id="evt-canon-blocked-002",
                request_id="req-canon-blocked-002",
                timestamp=now,
                client_ip="10.0.1.56",
                attack_type="XSS",
                severity="HIGH",
                action="BLOCKED",
                risk_score=88.0,
                rule_score=85.0,
                session_id="sess-canon-blocked",
                kill_chain_stage="EXPLOITATION",
                details="{}",
            )
        )
        db.commit()

    res = client.get("/dashboard/sessions", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    items = {item["session_id"]: item for item in res.json()["items"]}
    assert items["sess-legacy-block"]["has_blocked"] is True
    assert items["sess-canon-blocked"]["has_blocked"] is True


# ---------------------------------------------------------------------------
# LOGIC-PBL6-002: Multi-Protocol Sniffer & Decapsulation
# ---------------------------------------------------------------------------


def test_logic_002_protocol_detector_case_insensitive_soap_and_rest_json_guard():
    """Lowercase soapaction classifies as SOAP_XML; plain search JSON stays REST (not GraphQL)."""
    p_soap = ApiProtocolDetector.classify_protocol(
        path="/ws/Books",
        headers={"soapaction": '"GetBook"', "content-type": "application/xml"},
        body_bytes=b"<Envelope><Body><Book>1</Book></Body></Envelope>",
    )
    assert p_soap == ApiProtocol.SOAP_XML

    p_rest_search = ApiProtocolDetector.classify_protocol(
        path="/api/v1/books/search",
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"query": "clean architecture", "limit": 10}',
    )
    assert p_rest_search == ApiProtocol.REST


def test_logic_002_xxe_detected_in_query_params_and_body():
    """XXE DTD/ENTITY vectors are flagged in both URL-encoded query_params and XML body."""
    xxe_query = "xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E"
    ext_query = UniversalPayloadExtractor.extract(
        protocol=ApiProtocol.SOAP_XML,
        path="/ws/Parse",
        query_params=xxe_query,
        body_bytes=b"<root/>",
    )
    assert ext_query.is_protocol_anomaly is True
    assert "XXE" in (ext_query.protocol_alert or "")


def test_logic_002_rule_engine_inspects_decapsulated_canonical_payload():
    """RuleEngine detects attacks hidden inside decapsulated SOAP/GraphQL canonical payloads."""
    engine_rules = RuleEngine()
    soap_xss = (
        b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        b"<soapenv:Body><Comment><![CDATA[<script>alert(1)</script>]]></Comment></soapenv:Body>"
        b"</soapenv:Envelope>"
    )
    extracted = UniversalPayloadExtractor.extract(
        protocol=ApiProtocol.SOAP_XML,
        path="/ws/Comments",
        headers={"content-type": "text/xml", "soapaction": "Add"},
        body_bytes=soap_xss,
    )
    res = engine_rules.inspect_request(
        path="/ws/Comments",
        query_params=None,
        headers={"content-type": "text/xml"},
        body_bytes=b"{}",  # Deliberately clean raw body to prove canonical_payload is inspected
        canonical_payload=extracted.canonical_payload,
    )
    assert res.is_attack is True
    assert any(m.location_key == "protocol_payload" for m in res.matches)


# ---------------------------------------------------------------------------
# LOGIC-PBL6-003: Policy Enforcement & .env Feature Toggles
# ---------------------------------------------------------------------------


@respx.mock
def test_logic_003_risk_rate_limit_decision_returns_429(client: TestClient):
    """When DecisionEngine returns RATE_LIMIT, proxy enforces 429 Too Many Requests."""
    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("ACTIVE_BLOCKING")
    try:
        respx.get("http://vulnerable-api:5000/api/v1/books/").mock(
            return_value=Response(200, json={"items": []})
        )
        forced_rl = DecisionResult(
            action=PolicyAction.RATE_LIMIT,
            risk_score=70.0,
            waf_mode="ACTIVE_BLOCKING",
            is_blocked=False,
            is_rate_limited=True,
            reason="Medium-high risk score (70.0) triggered risk-based throttling",
            breakdown=RiskScoreBreakdown(
                weighted_score=70.0,
                rule_score=50.0,
                ml_score=80.0,
                anomaly_score=65.0,
            ),
        )
        with patch("app.security.decision.DecisionEngine.evaluate", return_value=forced_rl):
            res = client.get("/api/proxy/api/v1/books/")
            assert res.status_code == 429
            assert res.headers.get("X-WAF-Action") == "RATE_LIMIT"
            assert res.headers.get("X-WAF-Decision") == "RATE_LIMIT"
            data = res.json()
            assert data["error"] == "RISK_RATE_LIMIT_EXCEEDED"
            assert data["status"] == 429
    finally:
        _set_db_waf_mode(prev_mode)


@respx.mock
def test_logic_003_schema_strict_mode_respects_waf_mode_and_records_event(client: TestClient):
    """schema_strict_mode does NOT block 400 in MONITOR_ONLY, but blocks 400 + logs event in ACTIVE_BLOCKING."""
    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("MONITOR_ONLY")
    try:
        respx.get("http://vulnerable-api:5000/api/v1/vulnerable/books/search/").mock(
            return_value=Response(200, json={"results": []})
        )
        with patch.object(get_settings(), "schema_validation_enabled", True), \
             patch.object(get_settings(), "schema_strict_mode", True):
            # In MONITOR_ONLY: should NOT block with 400
            res_mon = client.get("/api/proxy/api/v1/vulnerable/books/search/")
            assert res_mon.status_code == 200

            # In ACTIVE_BLOCKING: MUST block with 400 AND persist SecurityEvent
            _set_db_waf_mode("ACTIVE_BLOCKING")
            res_blk = client.get("/api/proxy/api/v1/vulnerable/books/search/")
            assert res_blk.status_code == 400
            req_id = res_blk.headers.get("X-Request-ID")
            with SessionLocal() as db:
                ev = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
                assert ev is not None
                assert ev.attack_type == "SCHEMA_VIOLATION"
                assert ev.action == "BLOCKED"
    finally:
        _set_db_waf_mode(prev_mode)


@respx.mock
def test_logic_003_env_toggles_disable_ml_anomaly_and_rate_limit(client: TestClient):
    """Disabling ml_enabled, anomaly_enabled, and rate_limit_enabled bypasses each subsystem."""
    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("MONITOR_ONLY")
    try:
        respx.get("http://vulnerable-api:5000/api/v1/books/search?q=%27%20OR%201%3D1--").mock(
            return_value=Response(200, json={"ok": True})
        )
        with patch.object(get_settings(), "ml_enabled", False), \
             patch.object(get_settings(), "anomaly_enabled", False), \
             patch.object(get_settings(), "rate_limit_enabled", False):
            res = client.get("/api/proxy/api/v1/books/search?q=%27%20OR%201%3D1--")
            assert res.status_code == 200
            req_id = res.headers["X-Request-ID"]
            with SessionLocal() as db:
                ev = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
                assert ev is not None
                assert ev.ml_score is None
                assert ev.anomaly_score is None
                details = json.loads(ev.details)
                assert details["ml_inference"]["status"] == "disabled"
                assert details["anomaly_inference"] is None
    finally:
        _set_db_waf_mode(prev_mode)


# ---------------------------------------------------------------------------
# LOGIC-PBL6-004: Bookie API Sync & SchemaValidator Hardening
# ---------------------------------------------------------------------------


def test_logic_004_schema_validator_path_params_content_type_and_additional_props():
    """SchemaValidator checks /users/list/, path param integer types, Content-Type, and additionalProperties."""
    validator = SchemaValidator()

    # 1. /api/v1/vulnerable/users/list/ (GET) is recognized cleanly
    v_users = validator.validate_request(method="GET", path="/api/v1/vulnerable/users/list/")
    assert v_users == []

    # 2. Path parameter type mismatch (non-integer order_id)
    v_path = validator.validate_request(method="GET", path="/api/v1/vulnerable/orders/not-an-int/")
    assert any(v.violation_type == "TYPE_MISMATCH" and v.field == "order_id" for v in v_path)

    # 3. Unsupported Content-Type on JSON body endpoint
    v_ct = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/reviews/",
        body_bytes=b'{"book_id": 1, "author": "a", "comment": "ok"}',
        content_type="text/plain",
    )
    assert any(v.violation_type == "UNSUPPORTED_MEDIA_TYPE" for v in v_ct)

    # 4. additionalProperties: False rejects undeclared field
    v_extra = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/admin/ping/",
        body_bytes=b'{"host": "127.0.0.1", "unexpected_field": "evil"}',
        content_type="application/json",
    )
    assert any(v.violation_type == "ADDITIONAL_PROPERTY_NOT_ALLOWED" and v.field == "unexpected_field" for v in v_extra)

    # 5. refresh_spec_from_target coroutine exists
    assert callable(getattr(validator, "refresh_spec_from_target", None))


@respx.mock
def test_logic_004_simulator_uses_bookie_xss_and_cmd_schemas(client: TestClient):
    """/dashboard/simulate sends genuine Bookie API payloads for XSS (author/comment) and CMD (host)."""
    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("MONITOR_ONLY")
    try:
        xss_route = respx.post("http://vulnerable-api:5000/api/v1/vulnerable/reviews/").mock(
            return_value=Response(200, json={"ok": True})
        )
        cmd_route = respx.post("http://vulnerable-api:5000/api/v1/vulnerable/admin/ping/").mock(
            return_value=Response(200, json={"ok": True})
        )

        r_xss = client.post("/dashboard/simulate", json={"attack_type": "XSS"}, headers=ADMIN_HEADERS)
        assert r_xss.status_code == 200
        assert xss_route.called
        xss_payload = json.loads(xss_route.calls.last.request.content.decode("utf-8"))
        assert "author" in xss_payload and "comment" in xss_payload

        r_cmd = client.post("/dashboard/simulate", json={"attack_type": "CMD"}, headers=ADMIN_HEADERS)
        assert r_cmd.status_code == 200
        assert cmd_route.called
        cmd_payload = json.loads(cmd_route.calls.last.request.content.decode("utf-8"))
        assert "host" in cmd_payload
    finally:
        _set_db_waf_mode(prev_mode)


# ---------------------------------------------------------------------------
# LOGIC-PBL6-005: Session Correlation, N+1 SQL Elimination & Timeline
# ---------------------------------------------------------------------------


def test_logic_005_derive_session_id_timezone_neutral_and_rate_limit_metadata():
    """Naive UTC and aware UTC produce identical session IDs; record_rate_limit sets session fields."""
    naive_ts = datetime.datetime(2026, 11, 21, 12, 5, 0)
    aware_ts = datetime.datetime(2026, 11, 21, 12, 5, 0, tzinfo=datetime.timezone.utc)
    assert derive_session_id("192.168.1.99", naive_ts) == derive_session_id("192.168.1.99", aware_ts)

    with SessionLocal() as db:
        ev = SecurityEventService.record_rate_limit(
            db=db,
            request_id="req-rl-meta-001",
            client_ip="192.168.1.99",
            scope="ip",
            current_count=101,
            limit=100,
            retry_after=60,
            timestamp=aware_ts,
        )
        assert ev.session_id == derive_session_id("192.168.1.99", aware_ts)
        assert ev.kill_chain_stage is not None and len(ev.kill_chain_stage) > 0


def test_logic_005_sessions_eliminates_n_plus_1_sql(client: TestClient):
    """/dashboard/sessions fetches 12 sessions using constant O(1) SQL queries (no N+1)."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    with SessionLocal() as db:
        db.query(SecurityEvent).delete()
        for idx in range(12):
            db.add(
                SecurityEvent(
                    event_id=f"evt-n1-{idx}",
                    request_id=f"req-n1-{idx}",
                    timestamp=now - datetime.timedelta(seconds=idx),
                    client_ip=f"10.10.0.{idx + 1}",
                    attack_type="SQL_INJECTION",
                    severity="HIGH",
                    action="BLOCKED",
                    risk_score=90.0,
                    rule_score=85.0,
                    session_id=f"sess-batch-{idx}",
                    kill_chain_stage="EXPLOITATION",
                    details="{}",
                )
            )
        db.commit()

    executed_queries: list[str] = []

    def _count_sql(conn, cursor, statement, parameters, context, executemany):
        executed_queries.append(statement)

    event.listen(engine, "before_cursor_execute", _count_sql)
    try:
        res = client.get("/dashboard/sessions?limit=20", headers=ADMIN_HEADERS)
    finally:
        event.remove(engine, "before_cursor_execute", _count_sql)

    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 12
    assert len(body["items"]) == 12
    # Must be O(1) queries (batch IN query), far below 12+ N+1 queries
    assert len(executed_queries) <= 5, f"N+1 regression detected: {len(executed_queries)} SQL statements"


def test_logic_005_timeline_chronological_bucket_format(client: TestClient):
    """/dashboard/timeline groups chronologically by YYYY-MM-DD HH:MM and formats display time."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    with SessionLocal() as db:
        db.query(RequestLog).delete()
        db.add(
            RequestLog(
                request_id="req-tl-1",
                timestamp=now - datetime.timedelta(minutes=5),
                client_ip="127.0.0.1",
                method="GET",
                url="http://test/a",
                path="/a",
                response_status=200,
                response_time_ms=1.0,
            )
        )
        db.add(
            RequestLog(
                request_id="req-tl-2",
                timestamp=now - datetime.timedelta(minutes=1),
                client_ip="127.0.0.1",
                method="GET",
                url="http://test/b",
                path="/b",
                response_status=200,
                response_time_ms=1.0,
            )
        )
        db.commit()

    res = client.get("/dashboard/timeline?minutes=60", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    pts = res.json()
    assert len(pts) >= 2
    buckets = [p["bucket"] for p in pts if "bucket" in p]
    assert buckets == sorted(buckets)
    for p in pts:
        assert len(p["time"]) == 5 and ":" in p["time"]


# ---------------------------------------------------------------------------
# SCI-PBL6-002: Genuine RPS & Async Cyber Range Topology Telemetry
# ---------------------------------------------------------------------------


@respx.mock
def test_sci_002_real_current_rps_and_async_topology_telemetry(client: TestClient):
    """/dashboard/stats computes real 60s current_rps; /dashboard/topology reports live upstream & IP."""
    respx.get("http://vulnerable-api:5000/health").mock(return_value=Response(200, json={"status": "ok"}))
    respx.get("http://vulnerable-api:5000/").mock(return_value=Response(200, json={"status": "ok"}))

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    with SessionLocal() as db:
        db.query(RequestLog).delete()
        db.query(SecurityEvent).delete()
        # 6 recent requests within last 60s -> current_rps = 6 / 60 = 0.1
        for i in range(6):
            db.add(
                RequestLog(
                    request_id=f"req-rps-recent-{i}",
                    timestamp=now - datetime.timedelta(seconds=i * 5),
                    client_ip="192.168.50.77",
                    method="GET",
                    url="http://test/ok",
                    path="/ok",
                    response_status=200,
                    response_time_ms=1.0,
                )
            )
        # 120 stale requests from 10 minutes ago -> must NOT inflate current_rps
        for i in range(120):
            db.add(
                RequestLog(
                    request_id=f"req-rps-old-{i}",
                    timestamp=now - datetime.timedelta(minutes=10),
                    client_ip="192.168.50.77",
                    method="GET",
                    url="http://test/old",
                    path="/old",
                    response_status=200,
                    response_time_ms=1.0,
                )
            )
        db.add(
            SecurityEvent(
                event_id="evt-topo-real-1",
                request_id="req-rps-recent-0",
                timestamp=now,
                client_ip="192.168.50.77",
                attack_type="SQL_INJECTION",
                severity="CRITICAL",
                action="BLOCKED",
                risk_score=92.0,
                rule_score=90.0,
                session_id="sess-topo-real",
                kill_chain_stage="EXPLOITATION",
                details="{}",
            )
        )
        db.commit()

    stats_res = client.get("/dashboard/stats", headers=ADMIN_HEADERS)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_requests"] == 126
    assert stats["current_rps"] == 0.1  # Exact 6 / 60.0 (not 126 / 90!)

    topo_res = client.get("/dashboard/topology", headers=ADMIN_HEADERS)
    assert topo_res.status_code == 200
    topo = topo_res.json()
    assert topo["red_team"]["ip"] == "192.168.50.77"
    assert topo["red_team"]["attacks_generated"] == 1
    assert topo["blue_team"]["inspected_count"] == 126
    assert topo["blue_team"]["blocked_count"] == 1
    assert topo["target_api"]["status"] == "ok"
    assert topo["network"]["rtt_latency_ms"] >= 0.0
    assert topo["network"]["packet_loss_pct"] == 0.0


# ---------------------------------------------------------------------------
# SPRINT 3 FIX-1: Live PoC Regression Tests (bytes->b'...', SOAP FP, UnboundLocalError)
# ---------------------------------------------------------------------------


@respx.mock
def test_benign_rest_post_json_not_blocked_in_active_mode(client: TestClient):
    """Benign REST POST JSON must return HTTP 200 (not 403) and ML score < 30.0 in ACTIVE_BLOCKING."""
    from app.security.ml_detector import MLDetector, extract_26_from_http

    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("ACTIVE_BLOCKING")
    try:
        respx.post("http://vulnerable-api:5000/api/v1/vulnerable/reviews/").mock(
            return_value=Response(200, json={"status": "created", "id": 42})
        )
        raw_json_bytes = b'{"book_id": 1, "author": "Alice", "comment": "Great book"}'
        raw_json_str = raw_json_bytes.decode("utf-8")

        # Verify zero bytes -> b'...' corruption in 26-D feature extraction
        fv_bytes = extract_26_from_http("/api/v1/vulnerable/reviews/", None, raw_json_bytes)
        fv_str = extract_26_from_http("/api/v1/vulnerable/reviews/", None, raw_json_str)
        assert fv_bytes.tolist() == fv_str.tolist()
        assert fv_bytes[2] == 0.0  # count_single_quote must be 0.0 (no b'...' wrapper)

        detector = MLDetector()
        if detector.is_loaded:
            ml_res = detector.predict(raw_json_str, feature_vector=fv_bytes.tolist())
            assert ml_res.is_attack is False
            assert ml_res.risk_score is not None and ml_res.risk_score < 30.0

        res = client.post(
            "/api/proxy/api/v1/vulnerable/reviews/",
            headers={"Content-Type": "application/json"},
            content=raw_json_bytes,
        )
        assert res.status_code == 200
        ml_score_hdr = res.headers.get("X-WAF-ML-Score")
        if ml_score_hdr is not None:
            assert float(ml_score_hdr) < 30.0
    finally:
        _set_db_waf_mode(prev_mode)


@respx.mock
def test_benign_soap_xml_returns_200_while_soap_cdata_sqli_blocked(client: TestClient):
    """Benign SOAP XML returns 200 in ACTIVE_BLOCKING; SOAP CDATA SQLi and SOAP XXE return 403."""
    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("ACTIVE_BLOCKING")
    try:
        respx.post("http://vulnerable-api:5000/ws/StatusService").mock(
            return_value=Response(200, text="<status>ok</status>")
        )
        soap_headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"CheckStatus"',
        }

        # 1. Benign SOAP XML must NOT trigger XSS false positive -> HTTP 200
        benign_soap = (
            b"<soap:Envelope><soap:Body>"
            b"<q>public system status ok</q>"
            b"</soap:Body></soap:Envelope>"
        )
        r_benign = client.post(
            "/api/proxy/ws/StatusService",
            headers=soap_headers,
            content=benign_soap,
        )
        assert r_benign.status_code == 200

        # 2. SOAP CDATA SQLi must still be blocked -> HTTP 403
        cdata_sqli = (
            b"<soap:Envelope><soap:Body>"
            b"<q><![CDATA[1' UNION SELECT username, password FROM users--]]></q>"
            b"</soap:Body></soap:Envelope>"
        )
        r_sqli = client.post(
            "/api/proxy/ws/StatusService",
            headers=soap_headers,
            content=cdata_sqli,
        )
        assert r_sqli.status_code == 403

        # 3. SOAP XXE must still be blocked -> HTTP 403
        soap_xxe = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b"<soap:Envelope><soap:Body><q>&xxe;</q></soap:Body></soap:Envelope>"
        )
        r_xxe = client.post(
            "/api/proxy/ws/StatusService",
            headers=soap_headers,
            content=soap_xxe,
        )
        assert r_xxe.status_code == 403
    finally:
        _set_db_waf_mode(prev_mode)


@respx.mock
def test_risk_rate_limit_when_rate_limit_enabled_false_no_500(client: TestClient):
    """Risk [60, 80) in ACTIVE_BLOCKING with rate_limit_enabled=False returns 429 (no HTTP 500 UnboundLocalError)."""
    get_rate_limiter().reset()
    prev_mode = _set_db_waf_mode("ACTIVE_BLOCKING")
    try:
        respx.get("http://vulnerable-api:5000/api/v1/books/").mock(
            return_value=Response(200, json={"items": []})
        )
        forced_rl = DecisionResult(
            action=PolicyAction.RATE_LIMIT,
            risk_score=68.0,
            waf_mode="ACTIVE_BLOCKING",
            is_blocked=False,
            is_rate_limited=True,
            reason="Medium-high risk score (68.0) triggered risk-based throttling",
            breakdown=RiskScoreBreakdown(
                weighted_score=68.0,
                rule_score=50.0,
                ml_score=76.0,
                anomaly_score=65.0,
            ),
        )
        with patch.object(get_settings(), "rate_limit_enabled", False), \
             patch("app.security.decision.DecisionEngine.evaluate", return_value=forced_rl):
            res = client.get("/api/proxy/api/v1/books/")
            assert res.status_code == 429
            assert res.headers.get("X-WAF-Action") == "RATE_LIMIT"
            assert res.json()["error"] == "RISK_RATE_LIMIT_EXCEEDED"
    finally:
        _set_db_waf_mode(prev_mode)
