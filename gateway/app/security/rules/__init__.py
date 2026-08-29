from app.security.rules.base import BaseRule, RegexRule
from app.security.rules.command_injection import get_command_injection_rules
from app.security.rules.path_traversal import get_path_traversal_rules
from app.security.rules.sqli import get_sqli_rules
from app.security.rules.xss import get_xss_rules


def get_all_rules() -> list[BaseRule]:
    """Returns the central registry of all active signature rules."""
    rules: list[BaseRule] = []
    rules.extend(get_sqli_rules())
    rules.extend(get_xss_rules())
    rules.extend(get_path_traversal_rules())
    rules.extend(get_command_injection_rules())
    return rules


__all__ = [
    "BaseRule",
    "RegexRule",
    "get_all_rules",
    "get_sqli_rules",
    "get_xss_rules",
    "get_path_traversal_rules",
    "get_command_injection_rules",
]
