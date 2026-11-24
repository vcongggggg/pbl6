"""Universal OWASP API7:2023 Server-Side Request Forgery (SSRF) Detection Rules.

Inspects query parameters and request body values (never normal HTTP headers like
Origin/Referer or static URI paths) for internal loopback, RFC1918 private networks,
cloud instance metadata services, dangerous non-HTTP URI schemes, and IP obfuscation.
"""

import re
from typing import Pattern

from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity
from app.security.rules.base import RegexRule


class ParameterScopedRegexRule(RegexRule):
    """Evaluates SSRF regex patterns strictly on query/body parameter values."""

    def __init__(
        self,
        rule_id: str,
        severity: Severity,
        confidence: float,
        description: str,
        rationale: str,
        pattern: str | Pattern[str],
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            attack_type=AttackType.SSRF,
            severity=severity,
            confidence=confidence,
            description=description,
            rationale=rationale,
            pattern=pattern,
            flags=re.IGNORECASE | re.DOTALL,
        )

    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        if location not in (InspectionLocation.QUERY, InspectionLocation.BODY):
            return None
        if location_key and (location_key.startswith("key:") or ".key(" in location_key):
            return None
        return super().evaluate(input_text=input_text, location=location, location_key=location_key)


def get_ssrf_rules() -> list[ParameterScopedRegexRule]:
    """Returns universal target-agnostic SSRF signature rules."""
    return [
        ParameterScopedRegexRule(
            rule_id="SSRF-001",
            severity=Severity.CRITICAL,
            confidence=0.98,
            description="Dangerous non-HTTP URI scheme (file/gopher/dict/ldap/tftp)",
            rationale="Blocks local file read and internal protocol smuggling via SSRF sinks.",
            pattern=r"\b(?:file|gopher|dict|ldap|ldaps|tftp|netdoc|jar|php)://[^\s'\"<>]+",
        ),
        ParameterScopedRegexRule(
            rule_id="SSRF-002",
            severity=Severity.CRITICAL,
            confidence=0.99,
            description="Cloud Instance Metadata Service (IMDS) SSRF probe",
            rationale="Blocks credential theft against AWS/GCP/Azure/Alibaba metadata endpoints.",
            pattern=(
                r"(?:https?://)?(?:169\.254\.169\.254|100\.100\.100\.200|"
                r"metadata\.google\.internal|metadata\.azure\.com|\[?fd00:ec2::254\]?)(?:[:/?#&\s]|$)"
            ),
        ),
        ParameterScopedRegexRule(
            rule_id="SSRF-003",
            severity=Severity.CRITICAL,
            confidence=0.96,
            description="Internal loopback or RFC1918 private network URL in parameter",
            rationale="Blocks SSRF pivots targeting localhost, IPv6 loopback, or private LAN services.",
            pattern=(
                r"\bhttps?://(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|"
                r"\[::1?\]|\[0:0:0:0:0:0:0:1\]|"
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?:[:/?#&\s]|$)"
            ),
        ),
        ParameterScopedRegexRule(
            rule_id="SSRF-004",
            severity=Severity.CRITICAL,
            confidence=0.97,
            description="Decimal, hexadecimal, or octal obfuscated loopback/metadata IP URL",
            rationale="Blocks SSRF filter bypasses using integer or hex IPv4 representations.",
            pattern=(
                r"\bhttps?://(?:0x7f[0-9a-f]{6}|2130706433|0177\.[0-7.]+|"
                r"2852039166|0xa9fea9fe)(?:[:/?#&\s]|$)"
            ),
        ),
    ]
