from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskScoreBreakdown:
    """Detailed breakdown of individual and aggregated risk components.

    Model-Agnostic Design:
    - Supervised Machine Learning pillar is generalized as ml_score / ml_contribution.
    - Backward-compatible aliases (rf_score, rf_contribution) are preserved for seamless integration.
    """

    weighted_score: float
    rule_score: float
    ml_score: float | None = None
    rf_score: float | None = None
    anomaly_score: float | None = None
    rule_contribution: float = 0.0
    ml_contribution: float = 0.0
    rf_contribution: float = 0.0
    anomaly_contribution: float = 0.0
    active_weights: dict[str, float] = field(default_factory=dict)
    normalized_weights: dict[str, float] = field(default_factory=dict)
    is_fully_evaluated: bool = False

    def __post_init__(self) -> None:
        """Synchronizes ml_score and rf_score aliases."""
        if self.ml_score is None and self.rf_score is not None:
            self.ml_score = self.rf_score
        elif self.rf_score is None and self.ml_score is not None:
            self.rf_score = self.ml_score

        if self.ml_contribution == 0.0 and self.rf_contribution != 0.0:
            self.ml_contribution = self.rf_contribution
        elif self.rf_contribution == 0.0 and self.ml_contribution != 0.0:
            self.rf_contribution = self.ml_contribution

    def to_dict(self) -> dict[str, Any]:
        """Serializes breakdown into dictionary format for logging and APIs."""
        return {
            "weighted_score": self.weighted_score,
            "rule_score": self.rule_score,
            "ml_score": self.ml_score,
            "rf_score": self.rf_score,
            "anomaly_score": self.anomaly_score,
            "rule_contribution": self.rule_contribution,
            "ml_contribution": self.ml_contribution,
            "rf_contribution": self.rf_contribution,
            "anomaly_contribution": self.anomaly_contribution,
            "active_weights": self.active_weights,
            "normalized_weights": self.normalized_weights,
            "is_fully_evaluated": self.is_fully_evaluated,
        }


class RiskEngine:
    """Aggregates multi-pillar detection scores into a unified weighted risk score (0 - 100).

    Formulation:
        R_hybrid = clamp(w'_rule * S_rule + w'_ml * S_ml + w'_anomaly * S_anomaly, 0.0, 100.0)
    where:
        w_rule = 0.40  (Deterministic OWASP Signatures)
        w_ml   = 0.35  (Supervised ML Classifier: Champion Model e.g. RF / XGBoost / LightGBM)
        w_anomaly = 0.25 (Unsupervised Isolation Forest for Zero-Day anomaly detection)

    Model-Agnostic Design:
    - Accepts generic `ml_score` as well as backward-compatible `rf_score`.
    - Automatically normalizes weights w'_i = w_i / sum(active_w) when any model is offline.
    """

    DEFAULT_RULE_WEIGHT: float = 0.40
    DEFAULT_ML_WEIGHT: float = 0.35
    DEFAULT_RF_WEIGHT: float = 0.35  # Backward-compatible alias
    DEFAULT_ANOMALY_WEIGHT: float = 0.25

    def __init__(
        self,
        rule_weight: float = DEFAULT_RULE_WEIGHT,
        ml_weight: float = DEFAULT_ML_WEIGHT,
        rf_weight: float | None = None,
        anomaly_weight: float = DEFAULT_ANOMALY_WEIGHT,
    ) -> None:
        """Initializes RiskEngine with custom or default 3-pillar weights."""
        self.rule_weight = float(rule_weight)
        effective_ml = rf_weight if rf_weight is not None else ml_weight
        self.ml_weight = float(effective_ml)
        self.rf_weight = self.ml_weight  # Backward-compatible alias
        self.anomaly_weight = float(anomaly_weight)

    def calculate_weighted_score(
        self,
        rule_score: float,
        rf_score: float | None = None,
        anomaly_score: float | None = None,
        ml_score: float | None = None,
    ) -> RiskScoreBreakdown:
        """Calculates normalized weighted risk score (0.0 to 100.0).

        When all 3 pillars are provided:
            Score = (0.40 * Rule) + (0.35 * ML) + (0.25 * Anomaly)

        When ML/Anomaly are None (e.g. before models are loaded or during transition),
        the engine dynamically normalizes active weights so detection remains calibrated.
        """
        effective_ml_score = ml_score if ml_score is not None else rf_score

        # Clamp inputs between 0.0 and 100.0
        clamped_rule = min(100.0, max(0.0, float(rule_score)))
        clamped_ml = (
            min(100.0, max(0.0, float(effective_ml_score))) if effective_ml_score is not None else None
        )
        clamped_anomaly = (
            min(100.0, max(0.0, float(anomaly_score)))
            if anomaly_score is not None
            else None
        )

        active_weights: dict[str, float] = {"rule": self.rule_weight}
        total_active_weight = self.rule_weight

        if clamped_ml is not None:
            active_weights["ml"] = self.ml_weight
            active_weights["rf"] = self.ml_weight  # Backward compatibility
            total_active_weight += self.ml_weight

        if clamped_anomaly is not None:
            active_weights["anomaly"] = self.anomaly_weight
            total_active_weight += self.anomaly_weight

        # Check if all 3 pillars evaluated
        is_fully_evaluated = (clamped_ml is not None) and (clamped_anomaly is not None)

        if total_active_weight <= 0.0:
            total_active_weight = 1.0

        # Calculate normalized weights and individual contributions
        normalized_weights: dict[str, float] = {}
        normalized_rule_weight = round(self.rule_weight / total_active_weight, 4)
        normalized_weights["rule"] = normalized_rule_weight
        rule_contrib = round(clamped_rule * (self.rule_weight / total_active_weight), 2)

        ml_contrib = 0.0
        if clamped_ml is not None:
            normalized_ml_weight = round(self.ml_weight / total_active_weight, 4)
            normalized_weights["ml"] = normalized_ml_weight
            normalized_weights["rf"] = normalized_ml_weight  # Backward compatibility
            ml_contrib = round(clamped_ml * (self.ml_weight / total_active_weight), 2)

        anomaly_contrib = 0.0
        if clamped_anomaly is not None:
            normalized_anomaly_weight = round(self.anomaly_weight / total_active_weight, 4)
            normalized_weights["anomaly"] = normalized_anomaly_weight
            anomaly_contrib = round(
                clamped_anomaly * (self.anomaly_weight / total_active_weight), 2
            )

        total_weighted = rule_contrib + ml_contrib + anomaly_contrib
        final_score = round(min(100.0, max(0.0, total_weighted)), 2)

        return RiskScoreBreakdown(
            weighted_score=final_score,
            rule_score=clamped_rule,
            ml_score=clamped_ml,
            rf_score=clamped_ml,
            anomaly_score=clamped_anomaly,
            rule_contribution=rule_contrib,
            ml_contribution=ml_contrib,
            rf_contribution=ml_contrib,
            anomaly_contribution=anomaly_contrib,
            active_weights=active_weights,
            normalized_weights=normalized_weights,
            is_fully_evaluated=is_fully_evaluated,
        )
