"""Unit and integration tests for Ablation Study Mode (Master Plan B3)."""

from app.security.risk_engine import RiskEngine


def test_ablation_rules_only():
    engine = RiskEngine()
    # Rules: 80.0, ML: 10.0, Anomaly: 20.0
    breakdown = engine.calculate_weighted_score(
        rule_score=80.0,
        ml_score=10.0,
        anomaly_score=20.0,
        ablation_mode="rules_only",
    )
    assert breakdown.weighted_score == 80.0
    assert breakdown.rule_contribution == 80.0
    assert breakdown.ml_contribution == 0.0
    assert breakdown.anomaly_contribution == 0.0
    assert breakdown.ablation_mode == "rules_only"


def test_ablation_ml_only():
    engine = RiskEngine()
    # Rules: 80.0, ML: 95.0, Anomaly: 20.0
    breakdown = engine.calculate_weighted_score(
        rule_score=80.0,
        ml_score=95.0,
        anomaly_score=20.0,
        ablation_mode="ml_only",
    )
    assert breakdown.weighted_score == 95.0
    assert breakdown.rule_contribution == 0.0
    assert breakdown.ml_contribution == 95.0
    assert breakdown.anomaly_contribution == 0.0
    assert breakdown.ablation_mode == "ml_only"


def test_ablation_anomaly_only():
    engine = RiskEngine()
    # Rules: 10.0, ML: 10.0, Anomaly: 75.0
    breakdown = engine.calculate_weighted_score(
        rule_score=10.0,
        ml_score=10.0,
        anomaly_score=75.0,
        ablation_mode="anomaly_only",
    )
    assert breakdown.weighted_score == 75.0
    assert breakdown.rule_contribution == 0.0
    assert breakdown.ml_contribution == 0.0
    assert breakdown.anomaly_contribution == 75.0
    assert breakdown.ablation_mode == "anomaly_only"


def test_ablation_hybrid_default():
    engine = RiskEngine()
    # 0.40 * 100 + 0.35 * 100 + 0.25 * 0 = 40 + 35 = 75.0
    breakdown = engine.calculate_weighted_score(
        rule_score=100.0,
        ml_score=100.0,
        anomaly_score=0.0,
        ablation_mode="hybrid",
    )
    assert breakdown.weighted_score == 75.0
    assert breakdown.ablation_mode == "hybrid"
