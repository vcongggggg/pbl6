from app.security.decision import DecisionEngine, DecisionResult, PolicyAction
from app.security.risk_engine import RiskEngine


def test_decision_engine_threshold_boundaries():
    """Verifies standard 4-tier policy boundaries:

    - <30.0 -> ALLOW
    - 30.0 - 59.9 -> MONITOR
    - 60.0 - 79.9 -> RATE_LIMIT
    - >=80.0 -> BLOCK
    """
    risk_engine = RiskEngine()
    decision_engine = DecisionEngine()

    # 1. ALLOW zone
    bd_allow = risk_engine.calculate_weighted_score(rule_score=20.0, rf_score=10.0, anomaly_score=0.0)
    res_allow = decision_engine.evaluate(bd_allow, waf_mode="ACTIVE_BLOCKING")
    assert res_allow.action == PolicyAction.ALLOW
    assert res_allow.is_blocked is False
    assert res_allow.is_rate_limited is False

    # 2. MONITOR zone
    bd_monitor = risk_engine.calculate_weighted_score(rule_score=45.0, rf_score=40.0, anomaly_score=35.0)
    res_monitor = decision_engine.evaluate(bd_monitor, waf_mode="ACTIVE_BLOCKING")
    assert res_monitor.action == PolicyAction.MONITOR
    assert res_monitor.is_blocked is False
    assert res_monitor.is_rate_limited is False

    # 3. RATE_LIMIT zone
    bd_rate = risk_engine.calculate_weighted_score(rule_score=70.0, rf_score=65.0, anomaly_score=60.0)
    res_rate = decision_engine.evaluate(bd_rate, waf_mode="ACTIVE_BLOCKING")
    assert res_rate.action == PolicyAction.RATE_LIMIT
    assert res_rate.is_blocked is False
    assert res_rate.is_rate_limited is True

    # 4. BLOCK zone
    bd_block = risk_engine.calculate_weighted_score(rule_score=90.0, rf_score=85.0, anomaly_score=80.0)
    res_block = decision_engine.evaluate(bd_block, waf_mode="ACTIVE_BLOCKING")
    assert res_block.action == PolicyAction.BLOCK
    assert res_block.is_blocked is True
    assert res_block.is_rate_limited is False


def test_decision_engine_waf_modes():
    """Verifies decision behavior under different runtime WAF modes."""
    risk_engine = RiskEngine()
    decision_engine = DecisionEngine()

    # Critical attack score (95.0)
    bd_critical = risk_engine.calculate_weighted_score(rule_score=95.0, rf_score=95.0, anomaly_score=95.0)

    # Mode 1: OFF -> Never blocks, allows all
    res_off = decision_engine.evaluate(bd_critical, waf_mode="OFF")
    assert res_off.action == PolicyAction.ALLOW
    assert res_off.is_blocked is False

    # Mode 2: MONITOR_ONLY -> Downgrades to MONITOR, never blocks
    res_mon = decision_engine.evaluate(bd_critical, waf_mode="MONITOR_ONLY")
    assert res_mon.action == PolicyAction.MONITOR
    assert res_mon.is_blocked is False
    assert "MONITOR_ONLY" in res_mon.reason

    # Mode 3: ACTIVE_BLOCKING -> Blocks critical attacks
    res_block = decision_engine.evaluate(bd_critical, waf_mode="ACTIVE_BLOCKING")
    assert res_block.action == PolicyAction.BLOCK
    assert res_block.is_blocked is True

    # Mode 4: HYBRID -> Blocks critical attacks
    res_hybrid = decision_engine.evaluate(bd_critical, waf_mode="HYBRID")
    assert res_hybrid.action == PolicyAction.BLOCK
    assert res_hybrid.is_blocked is True


def test_decision_result_serialization():
    """Verifies DecisionResult to_dict output contains full audit info."""
    risk_engine = RiskEngine()
    decision_engine = DecisionEngine()
    bd = risk_engine.calculate_weighted_score(rule_score=85.0)
    res = decision_engine.evaluate(bd, waf_mode="ACTIVE_BLOCKING")

    data = res.to_dict()
    assert isinstance(res, DecisionResult)
    assert data["action"] == "BLOCK"
    assert data["is_blocked"] is True
    assert data["risk_score"] == 85.0
    assert "breakdown" in data
    assert "waf_mode" in data
