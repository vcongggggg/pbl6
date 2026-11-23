import json
import time

import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.db.session import SessionLocal
from app.security.engine import RuleEngine
from app.security.models import InspectionLocation
from app.security.normalizer import InputNormalizer
from app.security.rate_limiter import SlidingWindowRateLimiter
from app.security.rules.xss import get_xss_rules
from app.services.security import SecurityEventService


def test_sec_pbl6_001_rate_limiter_ip_hard_cap_rotation():
    """SEC-PBL6-001: Verifies rotating session_id / UA from single IP cannot bypass limit."""
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, default_limit=60, sensitive_limits={"auth": 10})
    client_ip = "192.168.10.99"

    # Send 10 requests with rotating session_ids
    for i in range(10):
        res = limiter.check_rate_limit(
            client_ip=client_ip,
            path="/api/v1/auth/login",
            session_id=f"token_rotation_{i}",
            user_agent=f"AttackerBrowser/{i}.0",
        )
        assert res.is_limited is False, f"Request {i+1} should be allowed"

    # 11th request with a brand new session_id MUST be blocked by IP Hard Cap
    res_11 = limiter.check_rate_limit(
        client_ip=client_ip,
        path="/api/v1/auth/login",
        session_id="brand_new_token_11",
        user_agent="BrandNewUA/1.0",
    )
    assert res_11.is_limited is True
    assert res_11.limit == 10
    assert res_11.remaining == 0
    assert res_11.retry_after > 0


def test_sec_pbl6_001_rate_limiter_lru_eviction():
    """SEC-PBL6-001: Verifies OrderedDict LRU eviction prevents unbounded memory growth."""
    limiter = SlidingWindowRateLimiter()
    # Mock MAX_TRACKED_KEYS to 10 for deterministic testing
    limiter.MAX_TRACKED_KEYS = 10

    for i in range(25):
        limiter.check_rate_limit(client_ip=f"10.0.0.{i}", path="/api/test")

    assert len(limiter._records) <= 10


def test_perf_pbl6_001_xss002_redos_hardened():
    """PERF-PBL6-001: Verifies XSS-002 regex executes in < 20ms on 9KB catastrophic input."""
    xss_rules = [r for r in get_xss_rules() if r.rule_id == "XSS-002"]
    assert len(xss_rules) == 1
    rule = xss_rules[0]

    # Malicious backtracking payload: 3000 repetitions of '<a ' (~9KB) followed by onerror
    redos_payload = "<a " * 3000 + "onerror=1"

    start = time.perf_counter()
    match = rule.evaluate(redos_payload, location=InspectionLocation.BODY)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    # Must complete well under 20ms (previously took 923ms+)
    assert elapsed_ms < 20.0, f"ReDoS vulnerability detected: took {elapsed_ms:.2f} ms"
    assert match is None or match is not None  # Finished evaluation without hanging


def test_sec_pbl6_006_evasion_zero_width_and_inline_comments():
    """SEC-PBL6-006: Verifies zero-width stripping and inline SQL comments canonicalization."""
    # 1. Zero-width Unicode characters stripped
    zero_width_payload = "<scr\u200bipt>alert(1)</script>"
    normalized = InputNormalizer.normalize(zero_width_payload)
    assert "<script>alert(1)</script>" in normalized

    engine = RuleEngine()
    result = engine.inspect_request(path="/api/test", query_params={"q": zero_width_payload})
    assert result.is_attack is True
    assert any(m.rule_id == "XSS-001" for m in result.matches)

    # 2. Inline SQL comment evasion stripped
    sqli_comment_payload = "UNION/**/SELECT/**/1,2,3"
    result_sqli = engine.inspect_request(path="/api/test", query_params={"id": sqli_comment_payload})
    assert result_sqli.is_attack is True
    assert any(m.rule_id == "SQLI-002" for m in result_sqli.matches)


def test_sec_pbl6_006_command_injection_expanded_rules():
    """SEC-PBL6-006: Verifies expanded CMD-001 and CMD-002 catch chained shell commands."""
    engine = RuleEngine()

    test_commands = [
        ("; env", "CMD-001"),
        ("; ls -la", "CMD-001"),
        ("; python3 -c 'print(1)'", "CMD-001"),
        ("; sh -c id", "CMD-001"),
        ("| head -n 10", "CMD-001"),
        ("$(env)", "CMD-002"),
        ("`ls`", "CMD-002"),
    ]

    for payload, expected_rule in test_commands:
        res = engine.inspect_request(path="/api/test", query_params={"cmd": payload})
        assert res.is_attack is True, f"Failed to detect {payload}"
        assert any(m.rule_id == expected_rule for m in res.matches), f"Expected rule {expected_rule} for {payload}"


def test_sec_pbl6_006_cookie_inspection():
    """SEC-PBL6-006: Verifies cookie header is inspected by RuleEngine."""
    engine = RuleEngine()
    res = engine.inspect_request(
        path="/api/test",
        headers={"cookie": "session_id=123; tracking=' UNION SELECT 1,2--"},
    )
    assert res.is_attack is True
    assert any(m.rule_id == "SQLI-002" for m in res.matches)


def test_sec_pbl6_003_record_detection_handles_none_result():
    """SEC-PBL6-003: Verifies SecurityEventService.record_detection handles None safely."""
    db = SessionLocal()
    try:
        # Must not raise AttributeError when detection_result is None
        event = SecurityEventService.record_detection(
            db=db,
            request_id="test-fail-open-req",
            client_ip="127.0.0.1",
            detection_result=None,
            action="BLOCKED",
            risk_score=90.0,
        )
        assert event is not None
        assert event.action == "BLOCKED"
    finally:
        db.close()


@respx.mock
def test_sec_pbl6_002_max_body_size_returns_413(client: TestClient):
    """SEC-PBL6-002: Verifies request bodies > 1MB return HTTP 413 Payload Too Large."""
    oversized_body = b"A" * (1048576 + 100)  # > 1MB
    res = client.post("/api/proxy/v1/upload", content=oversized_body, headers={"Content-Type": "application/octet-stream"})
    assert res.status_code == 413
    assert res.headers.get("X-WAF-Block-Reason") == "BODY_TOO_LARGE"


@respx.mock
def test_sec_pbl6_002_padding_and_non_utf8_prefix_blocked(client: TestClient):
    """SEC-PBL6-002: Verifies 17KB padding and non-UTF-8 prefix are inspected and blocked."""
    # Ensure active blocking mode
    client.post("/dashboard/toggle-waf-mode", headers={"X-API-Key": "dev-admin-secret-key-change-me"})
    stats = client.get("/dashboard/stats", headers={"X-API-Key": "dev-admin-secret-key-change-me"}).json()
    if stats["waf_mode"] != "ACTIVE_BLOCKING":
        client.post("/dashboard/toggle-waf-mode", headers={"X-API-Key": "dev-admin-secret-key-change-me"})

    # 1. 17KB JSON padding containing SQLi + XSS
    padding = "a" * 17000
    padded_json = f'{{"pad": "{padding}", "attack": "\' UNION SELECT 1,2--", "xss": "<script>alert(1)</script>"}}'.encode("utf-8")

    respx.post("http://vulnerable-api:5000/api/v1/books").mock(return_value=Response(200, json={"status": "ok"}))
    res_padded = client.post(
        "/api/proxy/v1/books",
        content=padded_json,
        headers={"Content-Type": "application/json"},
    )
    assert res_padded.status_code == 403, "17KB padded JSON attack was not blocked"

    # 2. Non-UTF-8 prefix (\xff) with SQL injection
    non_utf8_body = b"\xff\xfe" + b"username=' OR 1=1--"
    res_non_utf8 = client.post(
        "/api/proxy/v1/search",
        content=non_utf8_body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "203.0.113.1"},
    )
    assert res_non_utf8.status_code == 403, "Non-UTF-8 prefixed attack was not blocked"


def test_sec_pbl6_002_single_json_leaf_string_over_16kb_detected():
    """SEC-PBL6-002: Verifies single JSON leaf string >16KB is scanned via sliding window."""
    engine = RuleEngine()
    padding = "A" * 17000
    body_json = f'{{"comment": "{padding}\' UNION SELECT 1,2-- <script>alert(1)</script>"}}'.encode("utf-8")
    res = engine.inspect_request(path="/api/test", body_bytes=body_json)
    assert res.is_attack is True
    assert any(m.rule_id in ("SQLI-002", "XSS-001") for m in res.matches)


def test_sec_pbl6_002_deeply_nested_json_depth_fallback():
    """SEC-PBL6-002: Verifies JSON nesting depth > 32 triggers fallback to raw text scanning."""
    engine = RuleEngine()
    curr: dict = {"leaf": "' UNION SELECT 1,2--"}
    for _ in range(35):
        curr = {"nested": curr}
    body_json = json.dumps(curr).encode("utf-8")
    res = engine.inspect_request(path="/api/test", body_bytes=body_json)
    assert res.is_attack is True
    assert any(m.rule_id == "SQLI-002" for m in res.matches)


def test_sec_pbl6_006_multiline_sql_inline_comment():
    """SEC-PBL6-006: Verifies multiline SQL comment /*\n*/ is normalized with re.DOTALL."""
    payload = "1' UNION/*\n*/SELECT 1,2,3--"
    normalized = InputNormalizer.normalize(payload)
    assert "UNION SELECT" in normalized

    engine = RuleEngine()
    res = engine.inspect_request(path="/api/test", query_params={"id": payload})
    assert res.is_attack is True
    assert any(m.rule_id == "SQLI-002" for m in res.matches)


def test_sec_pbl6_002_chunked_streaming_body_over_1mb_returns_413(client: TestClient):
    """SEC-PBL6-002: Verifies chunked body streaming > 1MB immediately returns HTTP 413."""
    def chunk_generator():
        for _ in range(1025):
            yield b"A" * 1024

    res = client.post(
        "/api/proxy/v1/upload-stream",
        content=chunk_generator(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res.status_code == 413
    assert res.headers.get("X-WAF-Block-Reason") == "BODY_TOO_LARGE"

