import pytest

from app.security.risk_engine import RiskEngine, RiskScoreBreakdown


def test_risk_engine_default_weights():
    """Verifies default weights align with PBL6 master plan (40% Rule, 35% RF, 25% IF)."""
    engine = RiskEngine()
    assert engine.rule_weight == 0.40
    assert engine.rf_weight == 0.35
    assert engine.anomaly_weight == 0.25


def test_risk_engine_three_pillars_calculation():
    """Verifies 3-pillar formula: Score = (0.40 * Rule) + (0.35 * RF) + (0.25 * Anomaly)."""
    engine = RiskEngine()
    # 0.40 * 80 + 0.35 * 60 + 0.25 * 40 = 32.0 + 21.0 + 10.0 = 63.0
    breakdown = engine.calculate_weighted_score(rule_score=80.0, rf_score=60.0, anomaly_score=40.0)

    assert isinstance(breakdown, RiskScoreBreakdown)
    assert breakdown.weighted_score == 63.0
    assert breakdown.rule_score == 80.0
    assert breakdown.rf_score == 60.0
    assert breakdown.anomaly_score == 40.0
    assert breakdown.rule_contribution == 32.0
    assert breakdown.rf_contribution == 21.0
    assert breakdown.anomaly_contribution == 10.0
    assert breakdown.is_fully_evaluated is True


def test_risk_engine_dynamic_normalization_rule_only():
    """Verifies dynamic weight normalization when only Rule score is present (Phase 2)."""
    engine = RiskEngine()
    breakdown = engine.calculate_weighted_score(rule_score=90.0, rf_score=None, anomaly_score=None)

    # With only Rule active, normalized weight is 1.0 -> score remains 90.0
    assert breakdown.weighted_score == 90.0
    assert breakdown.rule_score == 90.0
    assert breakdown.rf_score is None
    assert breakdown.anomaly_score is None
    assert breakdown.is_fully_evaluated is False
    assert breakdown.rule_contribution == 90.0


def test_risk_engine_dynamic_normalization_partial_ml():
    """Verifies dynamic normalization when Rule and RF are present, but Anomaly is None."""
    engine = RiskEngine()
    # Active weights: Rule 0.40, RF 0.35 -> Total = 0.75
    # Normalized weights: Rule = 0.40/0.75 = 0.5333, RF = 0.35/0.75 = 0.4667
    # rule = 100.0, rf = 50.0 -> 100 * (40/75) + 50 * (35/75) = 53.33 + 23.33 = 76.67
    breakdown = engine.calculate_weighted_score(rule_score=100.0, rf_score=50.0, anomaly_score=None)

    assert pytest.approx(breakdown.weighted_score, rel=1e-2) == 76.67
    assert breakdown.is_fully_evaluated is False
    assert breakdown.anomaly_score is None


def test_risk_engine_clamping_and_bounds():
    """Verifies inputs below 0 or above 100 are properly bounded."""
    engine = RiskEngine()
    breakdown = engine.calculate_weighted_score(rule_score=-20.0, rf_score=150.0, anomaly_score=200.0)

    assert breakdown.rule_score == 0.0
    assert breakdown.rf_score == 100.0
    assert breakdown.anomaly_score == 100.0
    # 0.40 * 0.0 + 0.35 * 100.0 + 0.25 * 100.0 = 60.0
    assert breakdown.weighted_score == 60.0


def test_risk_score_breakdown_serialization():
    """Verifies to_dict serialization contains all required fields for logging and UI."""
    engine = RiskEngine()
    breakdown = engine.calculate_weighted_score(rule_score=75.0, rf_score=50.0, anomaly_score=30.0)
    data = breakdown.to_dict()

    assert "weighted_score" in data
    assert "rule_score" in data
    assert "rf_score" in data
    assert "anomaly_score" in data
    assert "active_weights" in data
    assert "is_fully_evaluated" in data
    assert data["is_fully_evaluated"] is True
