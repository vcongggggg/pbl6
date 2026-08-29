import json

from app.security.engine import RuleEngine
from app.security.models import AttackType, Severity


def test_engine_sqli_detection_in_query():
    """Verifies SQL injection detection in query parameter."""
    engine = RuleEngine()
    result = engine.inspect_request(
        path="/rest/products/search",
        query_params="q=apple%27%20OR%201%3D1--",
    )
    assert result.is_attack
    assert AttackType.SQL_INJECTION in result.attack_families
    assert result.rule_risk_score >= 80.0
    assert any(m.rule_id == "SQLI-001" for m in result.matches)


def test_engine_xss_detection_in_json_body():
    """Verifies XSS detection in nested JSON request body."""
    engine = RuleEngine()
    payload = json.dumps({
        "user": {
            "name": "Attacker",
            "bio": "<script>alert('XSS')</script>",
        }
    }).encode("utf-8")

    result = engine.inspect_request(
        path="/api/Users",
        body_bytes=payload,
    )
    assert result.is_attack
    assert AttackType.XSS in result.attack_families
    assert result.highest_severity == Severity.CRITICAL
    assert any(m.rule_id == "XSS-001" for m in result.matches)


def test_engine_path_traversal_in_path():
    """Verifies Path Traversal detection in request path."""
    engine = RuleEngine()
    result = engine.inspect_request(
        path="/ftp/../../../etc/passwd",
    )
    assert result.is_attack
    assert AttackType.PATH_TRAVERSAL in result.attack_families
    assert any(m.rule_id in ("PATH-001", "PATH-002") for m in result.matches)


def test_engine_command_injection_in_header():
    """Verifies Command Injection detection in custom header."""
    engine = RuleEngine()
    result = engine.inspect_request(
        path="/api/ping",
        headers={"User-Agent": "Mozilla/5.0; whoami"},
    )
    assert result.is_attack
    assert AttackType.COMMAND_INJECTION in result.attack_families
    assert any(m.rule_id == "CMD-001" for m in result.matches)


def test_engine_multi_attack_aggregation():
    """Verifies score calculation and multi-match aggregation for combined attacks."""
    engine = RuleEngine()
    payload = json.dumps({
        "search": "1 UNION SELECT username, password FROM users",
        "comment": "<img src=x onerror=alert(1)>",
    }).encode("utf-8")

    result = engine.inspect_request(
        path="/api/mixed/../../../etc/shadow",
        body_bytes=payload,
    )
    assert result.is_attack
    assert result.total_matches >= 3
    # Contains SQLI, XSS, and PATH_TRAVERSAL
    assert AttackType.SQL_INJECTION in result.attack_families
    assert AttackType.XSS in result.attack_families
    assert AttackType.PATH_TRAVERSAL in result.attack_families
    assert 0.0 <= result.rule_risk_score <= 100.0
    assert result.rule_risk_score >= 90.0
