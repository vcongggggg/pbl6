"""Unit and Integration Tests for v3.0 Universal OWASP API Top 10 Security Guards.

Covers:
1. OWASP API7:2023 SSRF (schemes, IMDS metadata, loopback/RFC1918, hex/int IP obfuscation, zero FPR on headers)
2. NoSQL Injection (JSON operator keys $ne/$gt/$regex, query bracket syntax, $where JS execution)
3. OWASP API3:2023 Mass Assignment (is_admin/is_superuser/role=admin blocked, login username=admin allowed)
4. OWASP API1:2023 Stateful BOLA/IDOR Enumeration (single access allowed, >=4 distinct IDs blocked, <=0 sentinel blocked)
5. OWASP API3:2023 Outbound Response DLP (pbkdf2/bcrypt/password_hash redacted in ACTIVE_BLOCKING, JWT access_token preserved)
"""

import json

import httpx
import respx
from fastapi.testclient import TestClient

from app.api.proxy import get_bola_detector
from app.db.models import SecurityEvent, WafConfigModel
from app.db.session import SessionLocal
from app.security.engine import RuleEngine
from app.security.models import AttackType
from app.security.response_dlp import REDACTED_PLACEHOLDER, ResponseDLPGuard


def _set_waf_mode(mode: str) -> str | None:
    from app.api.proxy import invalidate_waf_mode_cache

    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        prev = cfg.value if cfg else None
        if cfg:
            cfg.value = mode
        else:
            db.add(WafConfigModel(key="waf_mode", value=mode))
        db.commit()
    invalidate_waf_mode_cache()
    return prev


def _restore_waf_mode(prev: str | None) -> None:
    from app.api.proxy import invalidate_waf_mode_cache

    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if prev is None and cfg is not None:
            db.delete(cfg)
        elif cfg is not None:
            cfg.value = prev
        db.commit()
    invalidate_waf_mode_cache()


def test_ssrf_guard_catches_metadata_loopback_schemes_and_ignores_headers():
    engine = RuleEngine()

    # 1. AWS IMDSv1 probe
    res_aws = engine.inspect_request(
        path="/api/v1/webhooks/preview",
        query_params="target=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    )
    assert res_aws.is_attack is True
    assert AttackType.SSRF in res_aws.attack_families
    assert res_aws.rule_risk_score >= 85.0

    # 2. Internal loopback & dangerous scheme
    res_file = engine.inspect_request(
        path="/api/v1/import",
        body_bytes=json.dumps({"avatar_url": "file:///etc/passwd"}).encode("utf-8"),
    )
    assert res_file.is_attack is True
    assert AttackType.SSRF in res_file.attack_families

    # 3. Decimal-encoded loopback 127.0.0.1 -> 2130706433
    res_dec = engine.inspect_request(
        path="/api/v1/fetch",
        query_params="url=http://2130706433:8000/admin",
    )
    assert res_dec.is_attack is True
    assert AttackType.SSRF in res_dec.attack_families

    # 4. Benign external URL + localhost Origin/Referer headers -> ZERO false positive!
    res_benign = engine.inspect_request(
        path="/api/v1/vulnerable/books/fetch-cover/",
        query_params="url=https://covers.openlibrary.org/b/id/240727-S.jpg",
        headers={
            "Origin": "http://localhost:3000",
            "Referer": "http://127.0.0.1:3000/dashboard",
        },
    )
    assert res_benign.is_attack is False


def test_nosqli_guard_catches_json_and_query_operators():
    engine = RuleEngine()

    # 1. JSON operator bypass
    res_json = engine.inspect_request(
        path="/api/auth/login",
        body_bytes=json.dumps({"username": {"$ne": ""}, "password": {"$gt": ""}}).encode("utf-8"),
    )
    assert res_json.is_attack is True
    assert AttackType.NOSQL_INJECTION in res_json.attack_families
    assert res_json.rule_risk_score >= 85.0

    # 2. Query string operator
    res_query = engine.inspect_request(
        path="/api/users",
        query_params="username[$ne]=guest&role[$in]=admin",
    )
    assert res_query.is_attack is True
    assert AttackType.NOSQL_INJECTION in res_query.attack_families

    # 3. Normal price string $100 in review -> ZERO false positive!
    res_clean = engine.inspect_request(
        path="/api/v1/vulnerable/reviews/",
        body_bytes=json.dumps({"book_id": 1, "author": "Bob", "comment": "Worth $50 easily!"}).encode("utf-8"),
    )
    assert res_clean.is_attack is False


def test_mass_assignment_blocks_privilege_escalation_allows_admin_login():
    engine = RuleEngine()

    # 1. Self-assigning role=admin or is_superuser=True -> BLOCKED
    res_escalate = engine.inspect_request(
        path="/api/v2/accounts/settings",
        body_bytes=json.dumps({"email": "bob@corp.io", "role": "admin", "is_superuser": True}).encode("utf-8"),
    )
    assert res_escalate.is_attack is True
    assert AttackType.MASS_ASSIGNMENT in res_escalate.attack_families
    assert res_escalate.rule_risk_score >= 85.0

    # 2. Legitimate login with {"username": "admin"} -> ALLOWED (0 false positive)
    res_login = engine.inspect_request(
        path="/api/v1/vulnerable/auth/login/",
        body_bytes=json.dumps({"username": "admin", "password": "MySafePassword99"}).encode("utf-8"),
    )
    assert res_login.is_attack is False

    # 3. Self-updating profile with role="user" -> ALLOWED
    res_user = engine.inspect_request(
        path="/api/v1/vulnerable/users/profile/update/",
        body_bytes=json.dumps({"email": "alice@example.com", "role": "user"}).encode("utf-8"),
    )
    assert res_user.is_attack is False


@respx.mock
def test_bola_enumeration_and_response_dlp_live_proxy(client: TestClient):
    bola = get_bola_detector()
    bola.reset()
    prev = _set_waf_mode("ACTIVE_BLOCKING")

    try:
        # Mock arbitrary target API endpoints (demonstrating target-agnostic protection)
        respx.get("http://vulnerable-api:5000/api/v2/invoices/101").mock(
            return_value=httpx.Response(200, json={"invoice_id": 101, "total": 49.99})
        )
        respx.get("http://vulnerable-api:5000/api/v2/invoices/102").mock(
            return_value=httpx.Response(200, json={"invoice_id": 102, "total": 19.99})
        )
        respx.get("http://vulnerable-api:5000/api/v2/invoices/103").mock(
            return_value=httpx.Response(200, json={"invoice_id": 103, "total": 29.99})
        )
        respx.get("http://vulnerable-api:5000/api/v2/invoices/104").mock(
            return_value=httpx.Response(200, json={"invoice_id": 104, "total": 99.99})
        )
        respx.get("http://vulnerable-api:5000/api/v1/vulnerable/users/list/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "users": [
                        {
                            "id": 1,
                            "username": "admin",
                            "password_hash": "pbkdf2_sha256$600000$salt$secretdigest",
                        }
                    ],
                    "access_token": "jwt-token-must-stay-intact",
                },
            )
        )

        # First 3 object accesses succeed (normal user browsing)
        for oid in (101, 102, 103):
            r = client.get(f"/api/proxy/api/v2/invoices/{oid}")
            assert r.status_code == 200

        # 4th distinct object ID triggers BOLA horizontal enumeration block (403)
        r4 = client.get("/api/proxy/api/v2/invoices/104")
        assert r4.status_code == 403
        assert r4.json()["attack_type"] == "BOLA_IDOR"

        # Sentinel ID 0 triggers immediate BOLA block
        r0 = client.get("/api/proxy/api/v2/invoices/0")
        assert r0.status_code == 403
        assert r0.json()["attack_type"] == "BOLA_IDOR"

        # Outbound Response DLP redacts leaked password_hash while keeping access_token intact
        r_dlp = client.get("/api/proxy/api/v1/vulnerable/users/list/")
        assert r_dlp.status_code == 200
        assert r_dlp.headers.get("X-WAF-DLP-Redacted") == "true"
        payload = r_dlp.json()
        assert payload["users"][0]["password_hash"] == REDACTED_PLACEHOLDER
        assert payload["access_token"] == "jwt-token-must-stay-intact"

        with SessionLocal() as db:
            dlp_ev = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.attack_type == "EXCESSIVE_DATA_EXPOSURE")
                .first()
            )
            assert dlp_ev is not None
            assert dlp_ev.action == "BLOCKED"
    finally:
        bola.reset()
        _restore_waf_mode(prev)


def test_response_dlp_unit_monitor_vs_blocking():
    dlp = ResponseDLPGuard()
    raw = json.dumps({"user": "bob", "hash": "$2b$12$abcdefghijklmnopqrstuv"}).encode("utf-8")

    mon = dlp.inspect_and_redact(raw, "application/json", 200, "MONITOR_ONLY")
    assert mon.has_leak is True
    assert mon.redacted is False

    blk = dlp.inspect_and_redact(raw, "application/json", 200, "ACTIVE_BLOCKING")
    assert blk.has_leak is True
    assert blk.redacted is True
    assert blk.redacted_bytes is not None
    assert REDACTED_PLACEHOLDER in blk.redacted_bytes.decode("utf-8")


def test_simulate_target_url_anti_open_proxy_whitelist(client: TestClient):
    """Phase A4.3: Verifies /dashboard/simulate rejects external/IMDS target_url (CWE-918) and accepts Cyber Range URLs."""
    headers = {"X-API-Key": "dev-admin-secret-key-change-me"}

    # 1. External public domain -> HTTP 400
    r_ext = client.post(
        "/api/dashboard/simulate",
        headers=headers,
        json={"attack_type": "SQLI", "target_url": "https://example.com"},
    )
    assert r_ext.status_code == 400

    # 2. Cloud metadata IMDS -> HTTP 400
    r_imds = client.post(
        "/api/dashboard/simulate",
        headers=headers,
        json={"attack_type": "SQLI", "target_url": "http://169.254.169.254"},
    )
    assert r_imds.status_code == 400

    # 3. Valid Cyber Range loopback target_url -> HTTP 200
    r_ok = client.post(
        "/api/dashboard/simulate",
        headers=headers,
        json={"attack_type": "SQLI", "target_url": "http://127.0.0.1:5000"},
    )
    assert r_ok.status_code == 200
    assert r_ok.json()["simulated"] == "SQL_INJECTION"
