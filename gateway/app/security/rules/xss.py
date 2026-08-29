from app.security.models import AttackType, Severity
from app.security.rules.base import RegexRule


def get_xss_rules() -> list[RegexRule]:
    """Returns the deterministic Cross-Site Scripting (XSS) rule collection."""
    return [
        RegexRule(
            rule_id="XSS-001",
            attack_type=AttackType.XSS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="HTML Script Tag Injection",
            rationale="Detects explicit <script> or </script> tags injected into request payloads.",
            pattern=r"""(?i)<\s*\/?\s*script\b[^>]*>""",
        ),
        RegexRule(
            rule_id="XSS-002",
            attack_type=AttackType.XSS,
            severity=Severity.HIGH,
            confidence=0.90,
            description="Inline HTML Event Handler Injection",
            rationale=(
                "Detects event attributes like onerror, onload, onclick attached to HTML tags "
                "(e.g. <img src=x onerror=alert(1)>)."
            ),
            pattern=r"""(?i)<\s*\w+\b[^>]*\b(?:on(?:error|load|click|mouseover|focus|blur|submit|change|keydown|keyup))\s*=\s*[\'\"]?[^>]*>""",
        ),
        RegexRule(
            rule_id="XSS-003",
            attack_type=AttackType.XSS,
            severity=Severity.HIGH,
            confidence=0.90,
            description="JavaScript/Data Pseudo-Protocol Execution",
            rationale=(
                "Detects javascript: or data:text/html pseudo-protocols "
                "commonly used in href or src attributes."
            ),
            pattern=r"""(?i)(?:\b(?:javascript|vbscript)\s*:[^\s\'\"]+|\bdata\s*:\s*text\/html\b[^\s\'\"]*)""",
        ),
        RegexRule(
            rule_id="XSS-004",
            attack_type=AttackType.XSS,
            severity=Severity.MEDIUM,
            confidence=0.85,
            description="Dangerous DOM API Access and Iframe Injection",
            rationale=(
                "Detects direct access to document.cookie, document.write(), window.location "
                "assignments or <iframe src= injection."
            ),
            pattern=r"""(?i)(?:document\.cookie|document\.write\s*\(|window\.location\s*=|eval\s*\(|<\s*iframe\b[^>]*src\s*=)""",
        ),
    ]
