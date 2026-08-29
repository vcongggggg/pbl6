from app.security.models import AttackType, Severity
from app.security.rules.base import RegexRule


def get_path_traversal_rules() -> list[RegexRule]:
    """Returns the deterministic Path Traversal rule collection."""
    return [
        RegexRule(
            rule_id="PATH-001",
            attack_type=AttackType.PATH_TRAVERSAL,
            severity=Severity.HIGH,
            confidence=0.90,
            description="Directory Traversal Sequence",
            rationale=(
                "Detects dot-dot-slash patterns (../ or ..\\) "
                "attempting to escape target root directories."
            ),
            pattern=r"""(?i)(?:\.{2,}[/\\]|\.{2,}%2f|\.{2,}%5c)""",
        ),
        RegexRule(
            rule_id="PATH-002",
            attack_type=AttackType.PATH_TRAVERSAL,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Sensitive Operating System File Access",
            rationale=(
                "Detects explicit references to critical OS paths such as "
                "/etc/passwd, /etc/shadow, win.ini, or boot.ini."
            ),
            pattern=r"""(?i)(?:[/\\]etc[/\\](?:passwd|shadow|hosts|group)|[/\\]proc[/\\]self|[/\\]windows[/\\](?:win\.ini|system32|repair)|[c-z]:[/\\](?:boot\.ini|windows))""",
        ),
        RegexRule(
            rule_id="PATH-003",
            attack_type=AttackType.PATH_TRAVERSAL,
            severity=Severity.HIGH,
            confidence=0.90,
            description="Application Configuration and Credential Traversal",
            rationale=(
                "Detects attempts to access configuration descriptors or keys "
                "(e.g. .env, WEB-INF/web.xml, .git/config, id_rsa)."
            ),
            pattern=r"""(?i)(?:(?:^|[/\\])\.env\b|WEB-INF[/\\]web\.xml|\.git[/\\]config|wp-config\.php|\.ssh[/\\]id_rsa)""",
        ),
    ]
