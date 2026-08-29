from app.security.models import AttackType, Severity
from app.security.rules.base import RegexRule


def get_sqli_rules() -> list[RegexRule]:
    """Returns the deterministic SQL Injection rule collection."""
    return [
        RegexRule(
            rule_id="SQLI-001",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Boolean-based SQL Injection Tautology",
            rationale=(
                "Detects logical OR/AND tautologies commonly used to bypass authentication "
                "(e.g. ' OR '1'='1)."
            ),
            pattern=r"""(?i)(?:\b(?:or|and)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?|\b(?:or|and)\s+\d+\s*=\s*\d+)""",
        ),
        RegexRule(
            rule_id="SQLI-002",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="UNION-based SQL Injection",
            rationale=(
                "Detects UNION SELECT statements designed to exfiltrate "
                "unauthorized database rows."
            ),
            pattern=r"""(?i)\bunion\s+(?:all\s+|distinct\s+)?select\b""",
        ),
        RegexRule(
            rule_id="SQLI-003",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            confidence=0.90,
            description="SQL Comment Syntax Termination",
            rationale=(
                "Detects trailing quote characters coupled with "
                "SQL comment indicators (-- , /*, #)."
            ),
            pattern=r"""(?i)(?:[\'\"`]\s*(?:--|#|/\*)|/\*!\d+.*?(\*/|$))""",
        ),
        RegexRule(
            rule_id="SQLI-004",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            confidence=0.90,
            description="Database Enumeration and Fingerprinting Function Abuse",
            rationale=(
                "Detects dangerous SQL functions such as sleep(), benchmark(), database(), "
                "load_file() or INTO OUTFILE."
            ),
            pattern=r"""(?i)\b(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|version\s*\(\s*\)|database\s*\(\s*\)|schema\s*\(\s*\)|load_file\s*\(|into\s+(?:outfile|dumpfile))""",
        ),
        RegexRule(
            rule_id="SQLI-005",
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.90,
            description="Stacked Query and Destructive SQL DDL/DML",
            rationale=(
                "Detects semicolon-terminated stacked statements executing "
                "DROP, TRUNCATE, DELETE, or ALTER."
            ),
            pattern=r"""(?i);\s*(?:drop\s+table|drop\s+database|truncate\s+table|alter\s+table|insert\s+into|update\s+\w+\s+set|delete\s+from)\b""",
        ),
    ]
