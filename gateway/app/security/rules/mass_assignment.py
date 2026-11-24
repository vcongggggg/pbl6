"""Universal OWASP API3:2023 Broken Object Property Level Authorization (Mass Assignment) Rules.

Detects unauthorized client-side injection of privileged object properties
(e.g., is_admin, is_superuser, is_staff, permissions, role=admin) across any REST/JSON API,
without false-positiving on legitimate authentication fields like {"username": "admin"}.
"""

import re

from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity
from app.security.rules.base import BaseRule, clean_evidence

_FORBIDDEN_PRIVILEGE_KEYS = {
    "is_admin",
    "is_superuser",
    "is_staff",
    "is_root",
    "permissions",
    "privileges",
    "account_balance",
    "wallet_balance",
    "credit_limit",
    "verified_admin",
    "admin_override",
}

_ROLE_FIELD_NAMES = {
    "role",
    "user_role",
    "account_role",
    "access_level",
    "privilege_level",
}

_PRIVILEGED_ROLE_VALUES = {
    "admin",
    "administrator",
    "superadmin",
    "superuser",
    "moderator",
    "root",
    "staff",
    "system",
    "owner",
}

_RAW_MASS_ASSIGNMENT_RE = re.compile(
    r"(?:^|[?&])(?:is_admin|is_superuser|is_staff|is_root)=(?:true|1|yes)\b"
    r"|(?:^|[?&])(?:role|user_role|access_level)=(?:admin|administrator|superadmin|superuser|moderator|root)\b",
    re.IGNORECASE,
)


class PrivilegedKeyMassAssignmentRule(BaseRule):
    """Flags client-supplied administrative/financial object keys in JSON or query payloads."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MASS-001",
            attack_type=AttackType.MASS_ASSIGNMENT,
            severity=Severity.CRITICAL,
            confidence=0.98,
            description="Unauthorized privileged property injection (Mass Assignment)",
            rationale="Blocks client-supplied administrative flags (is_admin, is_superuser, is_staff, permissions).",
        )

    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        if not input_text or location not in (InspectionLocation.BODY, InspectionLocation.QUERY):
            return None

        if location_key and (".key(" in location_key or location_key.startswith("key:")):
            normalized_key = input_text.strip().lower()
            if normalized_key in _FORBIDDEN_PRIVILEGE_KEYS:
                return RuleMatch(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    confidence=self.confidence,
                    description=self.description,
                    location=location,
                    location_key=location_key,
                    matched_pattern="forbidden_privileged_property",
                    evidence=clean_evidence(f"{normalized_key}"),
                    normalized_sample=input_text[:100],
                )

        m = _RAW_MASS_ASSIGNMENT_RE.search(input_text)
        if m:
            return RuleMatch(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                confidence=self.confidence,
                description=self.description,
                location=location,
                location_key=location_key,
                matched_pattern=_RAW_MASS_ASSIGNMENT_RE.pattern,
                evidence=clean_evidence(m.group(0)),
                normalized_sample=input_text[:100],
            )
        return None


class PrivilegedRoleEscalationRule(BaseRule):
    """Flags attempts to self-assign administrative roles via role/access_level properties."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MASS-002",
            attack_type=AttackType.MASS_ASSIGNMENT,
            severity=Severity.CRITICAL,
            confidence=0.98,
            description="Unauthorized administrative role escalation in request payload",
            rationale="Prevents privilege escalation through self-service role mutation.",
        )

    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        if not input_text or location not in (InspectionLocation.BODY, InspectionLocation.QUERY):
            return None
        if not location_key:
            return None

        leaf_key = location_key.rsplit(".", 1)[-1].lower()
        if leaf_key in _ROLE_FIELD_NAMES:
            val_norm = input_text.strip().lower()
            if val_norm in _PRIVILEGED_ROLE_VALUES:
                return RuleMatch(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    confidence=self.confidence,
                    description=self.description,
                    location=location,
                    location_key=location_key,
                    matched_pattern="privileged_role_value",
                    evidence=clean_evidence(f"{leaf_key}={val_norm}"),
                    normalized_sample=input_text[:100],
                )
        return None


def get_mass_assignment_rules() -> list[BaseRule]:
    """Returns universal OWASP API3 Mass Assignment rules."""
    return [
        PrivilegedKeyMassAssignmentRule(),
        PrivilegedRoleEscalationRule(),
    ]
