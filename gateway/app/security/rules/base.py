import abc
import re
from typing import Pattern

from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity

# Sensitive substrings to mask within evidence snippets
SENSITIVE_SUBSTRINGS = ["password", "secret", "token", "api_key", "bearer "]


def clean_evidence(evidence_raw: str, max_chars: int = 160) -> str:
    """Truncates evidence string and masks sensitive token patterns."""
    if not evidence_raw:
        return ""

    snippet = evidence_raw.strip()
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars] + "...[TRUNCATED]"

    for term in SENSITIVE_SUBSTRINGS:
        if term in snippet.lower():
            # Replace actual values after sensitive keywords
            snippet = re.sub(
                rf"(?i)({re.escape(term)}\s*[:=]\s*)([^\s,;&]+)",
                r"\1[REDACTED]",
                snippet,
            )

    return snippet


class BaseRule(abc.ABC):
    """Abstract base class for all deterministic signature detection rules."""

    def __init__(
        self,
        rule_id: str,
        attack_type: AttackType,
        severity: Severity,
        confidence: float,
        description: str,
        rationale: str,
    ) -> None:
        self.rule_id = rule_id
        self.attack_type = attack_type
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.rationale = rationale

    @abc.abstractmethod
    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        """Evaluates an input string against this rule's signature patterns."""
        pass


class RegexRule(BaseRule):
    """Helper rule implementation based on compiled regular expressions."""

    def __init__(
        self,
        rule_id: str,
        attack_type: AttackType,
        severity: Severity,
        confidence: float,
        description: str,
        rationale: str,
        pattern: str | Pattern[str],
        flags: int = re.IGNORECASE | re.DOTALL,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            description=description,
            rationale=rationale,
        )
        if isinstance(pattern, str):
            self.regex: Pattern[str] = re.compile(pattern, flags)
            self.pattern_str: str = pattern
        else:
            self.regex = pattern
            self.pattern_str = pattern.pattern

    def evaluate(
        self,
        input_text: str,
        location: InspectionLocation,
        location_key: str | None = None,
    ) -> RuleMatch | None:
        if not input_text:
            return None

        match = self.regex.search(input_text)
        if match:
            matched_str = match.group(0)
            evidence = clean_evidence(matched_str)
            return RuleMatch(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                confidence=self.confidence,
                description=self.description,
                location=location,
                location_key=location_key,
                matched_pattern=self.pattern_str,
                evidence=evidence,
                normalized_sample=input_text[:100],
            )
        return None
