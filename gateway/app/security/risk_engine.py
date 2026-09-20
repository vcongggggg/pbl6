from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskScoreBreakdown:
    """Detailed breakdown of individual and aggregated risk components."""

    weighted_score: float
    rule_score: float
    rf_score: float | None = None
    anomaly_score: float | None = None
    rule_contribution: float = 0.0
    rf_contribution: float = 0.0
    anomaly_contribution: float = 0.0
    active_weights: dict[str, float] = field(default_factory=dict)
    normalized_weights: dict[str, float] = field(default_factory=dict)
    is_fully_evaluated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serializes breakdown into dictionary format for logging and APIs."""
        return {
            "weighted_score": self.weighted_score,
            "rule_score": self.rule_score,
            "rf_score": self.rf_score,
            "anomaly_score": self.anomaly_score,
            "rule_contribution": self.rule_contribution,
            "rf_contribution": self.rf_contribution,
            "anomaly_contribution": self.anomaly_contribution,
            "active_weights": self.active_weights,
            "normalized_weights": self.normalized_weights,
            "is_fully_evaluated": self.is_fully_evaluated,
        }


class RiskEngine:
    """Aggregates multi-pillar detection scores into a unified weighted risk score (0 - 100).

    Formulation:
        R_hybrid = clamp(w'_rule * S_rule + w'_rf * S_rf + w'_anomaly * S_anomaly, 0.0, 100.0)
    where:
        w'_i = w_i / sum_{j in Active} w_j (Dynamic Weight Renormalization)
    Default Base Weights:
        Rule = 0.40, Random Forest = 0.35, Isolation Forest Anomaly = 0.25
    Academic Foundation:
        - Torrano-Gimenez et al. (Wiley 2015)
        - Al-Asli et al. (MDPI Electronics 2025)
    """

    DEFAULT_RULE_WEIGHT: float = 0.40
    DEFAULT_RF_WEIGHT: float = 0.35
    DEFAULT_ANOMALY_WEIGHT: float = 0.25

    def __init__(
        self,
        rule_weight: float = DEFAULT_RULE_WEIGHT,
        rf_weight: float = DEFAULT_RF_WEIGHT,
        anomaly_weight: float = DEFAULT_ANOMALY_WEIGHT,
    ) -> None:
        """Initializes RiskEngine with custom or default 3-pillar weights."""
        self.rule_weight = float(rule_weight)
        self.rf_weight = float(rf_weight)
        self.anomaly_weight = float(anomaly_weight)

    def calculate_weighted_score(
        self,
        rule_score: float,
        rf_score: float | None = None,
        anomaly_score: float | None = None,
    ) -> RiskScoreBreakdown:
        """Calculates normalized weighted risk score (0.0 to 100.0).

        When all 3 pillars are provided:
            Score = (0.40 * Rule) + (0.35 * RF) + (0.25 * Anomaly)

        When ML/Anomaly are None (e.g. before models are loaded or during transition),
        the engine dynamically normalizes active weights so detection remains calibrated.
        """
        # Clamp inputs between 0.0 and 100.0
        clamped_rule = min(100.0, max(0.0, float(rule_score)))
        clamped_rf = (
            min(100.0, max(0.0, float(rf_score))) if rf_score is not None else None
        )
        clamped_anomaly = (
            min(100.0, max(0.0, float(anomaly_score)))
            if anomaly_score is not None
            else None
        )

        active_weights: dict[str, float] = {"rule": self.rule_weight}
        total_active_weight = self.rule_weight

        if clamped_rf is not None:
            active_weights["rf"] = self.rf_weight
            total_active_weight += self.rf_weight

        if clamped_anomaly is not None:
            active_weights["anomaly"] = self.anomaly_weight
            total_active_weight += self.anomaly_weight

        # Check if all 3 pillars evaluated
        is_fully_evaluated = (clamped_rf is not None) and (clamped_anomaly is not None)

        if total_active_weight <= 0.0:
            total_active_weight = 1.0

        # Calculate normalized weights and individual contributions
        normalized_weights: dict[str, float] = {}
        normalized_rule_weight = round(self.rule_weight / total_active_weight, 4)
        normalized_weights["rule"] = normalized_rule_weight
        rule_contrib = round(clamped_rule * (self.rule_weight / total_active_weight), 2)

        rf_contrib = 0.0
        if clamped_rf is not None:
            normalized_rf_weight = round(self.rf_weight / total_active_weight, 4)
            normalized_weights["rf"] = normalized_rf_weight
            rf_contrib = round(clamped_rf * (self.rf_weight / total_active_weight), 2)

        anomaly_contrib = 0.0
        if clamped_anomaly is not None:
            normalized_anomaly_weight = round(self.anomaly_weight / total_active_weight, 4)
            normalized_weights["anomaly"] = normalized_anomaly_weight
            anomaly_contrib = round(
                clamped_anomaly * (self.anomaly_weight / total_active_weight), 2
            )

        total_weighted = rule_contrib + rf_contrib + anomaly_contrib
        final_score = round(min(100.0, max(0.0, total_weighted)), 2)

        return RiskScoreBreakdown(
            weighted_score=final_score,
            rule_score=clamped_rule,
            rf_score=clamped_rf,
            anomaly_score=clamped_anomaly,
            rule_contribution=rule_contrib,
            rf_contribution=rf_contrib,
            anomaly_contribution=anomaly_contrib,
            active_weights=active_weights,
            normalized_weights=normalized_weights,
            is_fully_evaluated=is_fully_evaluated,
        )
