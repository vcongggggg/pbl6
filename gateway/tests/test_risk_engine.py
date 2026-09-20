import time

from app.security.risk_engine import RiskEngine


def test_default_weights_initialization():
    engine = RiskEngine()
    assert engine.rule_weight == 0.40
    assert engine.rf_weight == 0.35
    assert engine.anomaly_weight == 0.25


def test_custom_weights_initialization():
    engine = RiskEngine(rule_weight=0.50, rf_weight=0.30, anomaly_weight=0.20)
    assert engine.rule_weight == 0.50
    assert engine.rf_weight == 0.30
    assert engine.anomaly_weight == 0.20


def test_full_3_pillars_evaluation():
    engine = RiskEngine()
    # Rule=100.0, RF=100.0, Anomaly=100.0 => Expected = 100.0
    res = engine.calculate_weighted_score(rule_score=100.0, rf_score=100.0, anomaly_score=100.0)
    assert res.weighted_score == 100.0
    assert res.is_fully_evaluated is True
    assert res.rule_contribution == 40.0
    assert res.rf_contribution == 35.0
    assert res.anomaly_contribution == 25.0
    assert res.normalized_weights["rule"] == 0.40
    assert res.normalized_weights["rf"] == 0.35
    assert res.normalized_weights["anomaly"] == 0.25


def test_mixed_scores_calculation():
    engine = RiskEngine()
    # 0.40*80 (32) + 0.35*60 (21) + 0.25*40 (10) = 63.0
    res = engine.calculate_weighted_score(rule_score=80.0, rf_score=60.0, anomaly_score=40.0)
    assert res.weighted_score == 63.0
    assert res.rule_contribution == 32.0
    assert res.rf_contribution == 21.0
    assert res.anomaly_contribution == 10.0


def test_dynamic_renormalization_missing_rf():
    engine = RiskEngine()
    # Missing RF: active weights = Rule(0.40), Anomaly(0.25), sum = 0.65
    # w'_rule = 0.40/0.65 ~= 0.6154, w'_anomaly = 0.25/0.65 ~= 0.3846
    res = engine.calculate_weighted_score(rule_score=100.0, rf_score=None, anomaly_score=100.0)
    assert res.weighted_score == 100.0
    assert res.rf_score is None
    assert res.rf_contribution == 0.0
    assert res.is_fully_evaluated is False
    assert "rf" not in res.active_weights
    assert res.normalized_weights["rule"] == 0.6154
    assert res.normalized_weights["anomaly"] == 0.3846


def test_dynamic_renormalization_missing_anomaly():
    engine = RiskEngine()
    # Missing Anomaly: active weights = Rule(0.40), RF(0.35), sum = 0.75
    # w'_rule = 0.40/0.75 ~= 0.5333, w'_rf = 0.35/0.75 ~= 0.4667
    res = engine.calculate_weighted_score(rule_score=100.0, rf_score=100.0, anomaly_score=None)
    assert res.weighted_score == 100.0
    assert res.anomaly_score is None
    assert res.anomaly_contribution == 0.0
    assert res.is_fully_evaluated is False
    assert "anomaly" not in res.active_weights
    assert res.normalized_weights["rule"] == 0.5333
    assert res.normalized_weights["rf"] == 0.4667


def test_dynamic_renormalization_rule_only():
    engine = RiskEngine()
    # Missing both ML components: Rule weight normalized to 1.0 (100%)
    res = engine.calculate_weighted_score(rule_score=75.5, rf_score=None, anomaly_score=None)
    assert res.weighted_score == 75.5
    assert res.rule_contribution == 75.5
    assert res.rf_contribution == 0.0
    assert res.anomaly_contribution == 0.0
    assert res.normalized_weights["rule"] == 1.0


def test_score_clamping_and_boundaries():
    engine = RiskEngine()
    # Test values beyond [0.0, 100.0] boundaries
    res_overflow = engine.calculate_weighted_score(rule_score=150.0, rf_score=200.0, anomaly_score=999.0)
    assert res_overflow.weighted_score == 100.0
    assert res_overflow.rule_score == 100.0

    res_negative = engine.calculate_weighted_score(rule_score=-50.0, rf_score=-10.0, anomaly_score=-5.0)
    assert res_negative.weighted_score == 0.0
    assert res_negative.rule_score == 0.0


def test_breakdown_serialization():
    engine = RiskEngine()
    res = engine.calculate_weighted_score(rule_score=50.0, rf_score=60.0, anomaly_score=70.0)
    d = res.to_dict()
    assert isinstance(d, dict)
    assert d["weighted_score"] == res.weighted_score
    assert d["rule_score"] == 50.0
    assert d["rf_score"] == 60.0
    assert d["anomaly_score"] == 70.0
    assert "normalized_weights" in d


def test_execution_throughput_performance():
    engine = RiskEngine()
    start = time.perf_counter()
    iterations = 10000
    for _ in range(iterations):
        _ = engine.calculate_weighted_score(85.0, 90.0, 75.0)
    duration_ms = (time.perf_counter() - start) * 1000
    per_op_ms = duration_ms / iterations
    # Budget: each evaluation must be < 0.05ms (50 microseconds)
    assert per_op_ms < 0.05
