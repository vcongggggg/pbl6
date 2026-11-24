"""Universal NoSQL Injection (MongoDB / Document DB) Detection Rules."""

import re

from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity
from app.security.rules.base import BaseRule, RegexRule, clean_evidence

_NOSQL_OPERATORS = {
    "$ne",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$nin",
    "$in",
    "$regex",
    "$where",
    "$exists",
    "$elemmatch",
    "$or",
    "$and",
    "$nor",
    "$not",
    "$expr",
}

_BRACKET_OR_JSON_OP_RE = re.compile(
    r"(?:\[\$(?:ne|gt|gte|lt|lte|nin|in|regex|where|exists|elemMatch|or|and|nor|not|expr)\]"
    r"|['\"]\$(?:ne|gt|gte|lt|lte|nin|in|regex|where|exists|elemMatch|or|and|nor|not|expr)['\"]\s*:)",
    re.IGNORECASE,
)


class NoSQLOperatorRule(BaseRule):
    """Detects MongoDB query/projection operators in JSON keys or URL parameters."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="NOSQLI-001",
            attack_type=AttackType.NOSQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.98,
            description="NoSQL query operator injection ($ne, $gt, $regex, $where)",
            rationale="Prevents authentication bypass and unauthorized document extraction in NoSQL APIs.",
        )

    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        if not input_text or location not in (InspectionLocation.QUERY, InspectionLocation.BODY):
            return None

        stripped = input_text.strip().lower()
        if location_key and (".key(" in location_key or location_key.startswith("key:")):
            if stripped in _NOSQL_OPERATORS:
                return RuleMatch(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    confidence=self.confidence,
                    description=self.description,
                    location=location,
                    location_key=location_key,
                    matched_pattern="nosql_json_operator_key",
                    evidence=clean_evidence(input_text),
                    normalized_sample=input_text[:100],
                )

        m = _BRACKET_OR_JSON_OP_RE.search(input_text)
        if m:
            return RuleMatch(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                confidence=self.confidence,
                description=self.description,
                location=location,
                location_key=location_key,
                matched_pattern=_BRACKET_OR_JSON_OP_RE.pattern,
                evidence=clean_evidence(m.group(0)),
                normalized_sample=input_text[:100],
            )
        return None


def get_nosqli_rules() -> list[BaseRule]:
    """Returns universal NoSQL injection detection rules."""
    return [
        NoSQLOperatorRule(),
        RegexRule(
            rule_id="NOSQLI-002",
            attack_type=AttackType.NOSQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence=0.97,
            description="MongoDB server-side JavaScript / shell execution ($where / db.*)",
            rationale="Blocks arbitrary server-side JS evaluation and collection manipulation.",
            pattern=r"(?:\$where\s*:|\bdb\.[a-zA-Z0-9_]+\.(?:find|findOne|drop|remove|update|insert|aggregate)\s*\()",
        ),
    ]
