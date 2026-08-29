from app.security.models import AttackType, RuleMatch, Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 45.0,
    Severity.LOW: 25.0,
}

SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]


class RuleScorer:
    """Calculates deterministic Rule Risk Scores for detection results."""

    @staticmethod
    def calculate_score(matches: list[RuleMatch]) -> float:
        """Calculates a deterministic 0.0 to 100.0 score from rule matches."""
        if not matches:
            return 0.0

        # 1. Base score from the highest impact match (severity weight * confidence)
        max_base = 0.0
        for match in matches:
            weight = SEVERITY_WEIGHTS.get(match.severity, 20.0)
            match_score = weight * match.confidence
            if match_score > max_base:
                max_base = match_score

        # 2. Multi-match aggregation bonus (+4.0 per additional match, up to +16.0)
        extra_match_count = max(0, len(matches) - 1)
        multi_match_bonus = min(16.0, extra_match_count * 4.0)

        # 3. Multi-family attack diversity bonus (+5.0 if combined e.g. SQLi + XSS)
        distinct_families = {m.attack_type for m in matches}
        family_bonus = 5.0 if len(distinct_families) > 1 else 0.0

        total_score = max_base + multi_match_bonus + family_bonus
        bounded_score = min(100.0, max(0.0, total_score))
        return round(bounded_score, 2)

    @staticmethod
    def get_highest_severity(matches: list[RuleMatch]) -> Severity | None:
        """Returns the highest severity among matched rules."""
        if not matches:
            return None
        severities = {m.severity for m in matches}
        for sev in SEVERITY_ORDER:
            if sev in severities:
                return sev
        return None

    @staticmethod
    def get_attack_families(matches: list[RuleMatch]) -> list[AttackType]:
        """Returns ordered list of distinct attack types detected."""
        seen = set()
        families: list[AttackType] = []
        for m in matches:
            if m.attack_type not in seen:
                seen.add(m.attack_type)
                families.append(m.attack_type)
        return families
