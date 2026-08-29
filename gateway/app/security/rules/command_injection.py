from app.security.models import AttackType, Severity
from app.security.rules.base import RegexRule


def get_command_injection_rules() -> list[RegexRule]:
    """Returns the deterministic Command Injection rule collection."""
    return [
        RegexRule(
            rule_id="CMD-001",
            attack_type=AttackType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Shell Metacharacter Command Chaining",
            rationale=(
                "Detects shell metacharacters (; | && ||) chained with core OS utilities "
                "(whoami, id, uname, cat, etc.)."
            ),
            pattern=r"""(?i)(?:[;&|`]\s*(?:whoami|id|uname\s+-a|cat\s+[/\\]etc|netstat|ifconfig|ipconfig|hostname)\b)""",
        ),
        RegexRule(
            rule_id="CMD-002",
            attack_type=AttackType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Subshell and Backtick Command Substitution",
            rationale="Detects $() or backtick command substitution evaluating shell binaries.",
            pattern=r"""(?i)(?:\$\((?:whoami|id|cat|uname|ls|dir|pwd|curl|wget)\b|`\s*(?:whoami|id|cat|uname|ls|dir|pwd|curl|wget)\b[^`]*`)""",
        ),
        RegexRule(
            rule_id="CMD-003",
            attack_type=AttackType.COMMAND_INJECTION,
            severity=Severity.HIGH,
            confidence=0.90,
            description="Windows Command Shell and PowerShell Execution",
            rationale=(
                "Detects invocation of cmd.exe /c, PowerShell encoded commands, "
                "or certutil downloaders."
            ),
            pattern=r"""(?i)\b(?:cmd(?:\.exe)?\s*\/(?:c|k)|powershell(?:\.exe)?\s*(?:-[eE]nc|-[cC]ommand|-[eE]xecutionPolicy)|certutil\s+-urlcache)\b""",
        ),
        RegexRule(
            rule_id="CMD-004",
            attack_type=AttackType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Network Reverse Shell and Pipe Execution",
            rationale=(
                "Detects piped script executions (curl ... | bash) "
                "or netcat reverse shells (nc -e /bin/sh)."
            ),
            pattern=r"""(?i)(?:(?:curl|wget)\s+[^\n|;&]+\|\s*(?:sh|bash|zsh)|\bnc\s+(?:-\w+\s+)*\d+\.\d+\.\d+\.\d+\s+\d+\s+-e\s+\/bin\/(?:sh|bash)|\/bin\/(?:ba)?sh\s+-i)""",
        ),
    ]
