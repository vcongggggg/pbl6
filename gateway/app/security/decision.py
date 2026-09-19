from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.security.risk_engine import RiskScoreBreakdown


class PolicyAction(str, Enum):
    """Enforcement actions determined by security policy evaluation."""

    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    RATE_LIMIT = "RATE_LIMIT"
    BLOCK = "BLOCK"


@dataclass
class DecisionResult:
    """Outcome of security policy evaluation for an inspected request."""

    action: PolicyAction
    risk_score: float
    is_blocked: bool
    is_rate_limited: bool
    reason: str
    breakdown: RiskScoreBreakdown
    waf_mode: str

    def to_dict(self) -> dict[str, Any]:
        """Serializes decision into dictionary format."""
        return {
            "action": self.action.value,
            "risk_score": self.risk_score,
            "is_blocked": self.is_blocked,
            "is_rate_limited": self.is_rate_limited,
            "reason": self.reason,
            "breakdown": self.breakdown.to_dict(),
            "waf_mode": self.waf_mode,
        }


class DecisionEngine:
    """Enforces multi-threshold security policies based on aggregated risk scores."""

    DEFAULT_ALLOW_THRESHOLD: float = 30.0
    DEFAULT_MONITOR_THRESHOLD: float = 60.0
    DEFAULT_RATE_LIMIT_THRESHOLD: float = 80.0

    def __init__(
        self,
        allow_threshold: float = DEFAULT_ALLOW_THRESHOLD,
        monitor_threshold: float = DEFAULT_MONITOR_THRESHOLD,
        rate_limit_threshold: float = DEFAULT_RATE_LIMIT_THRESHOLD,
    ) -> None:
        """Initializes thresholds for policy boundaries."""
        self.allow_threshold = allow_threshold
        self.monitor_threshold = monitor_threshold
        self.rate_limit_threshold = rate_limit_threshold

    def evaluate(
        self,
        risk_breakdown: RiskScoreBreakdown,
        waf_mode: str = "ACTIVE_BLOCKING",
    ) -> DecisionResult:
        """Evaluates policy decision against risk score and active WAF operating mode.

        Threshold Boundaries:
            - score < 30.0: ALLOW (HTTP 200)
            - 30.0 <= score < 60.0: MONITOR (Log incident, forward)
            - 60.0 <= score < 80.0: RATE_LIMIT (Rate limit window check)
            - score >= 80.0: BLOCK (HTTP 403 Forbidden)
        """
        score = risk_breakdown.weighted_score
        normalized_mode = (waf_mode or "ACTIVE_BLOCKING").upper()

        # 1. Base threshold evaluation
        if score < self.allow_threshold:
            base_action = PolicyAction.ALLOW
        elif score < self.monitor_threshold:
            base_action = PolicyAction.MONITOR
        elif score < self.rate_limit_threshold:
            base_action = PolicyAction.RATE_LIMIT
        else:
            base_action = PolicyAction.BLOCK

        # 2. Modulate decision according to WAF Mode
        if normalized_mode == "OFF":
            return DecisionResult(
                action=PolicyAction.ALLOW,
                risk_score=score,
                is_blocked=False,
                is_rate_limited=False,
                reason="WAF is disabled (OFF mode) - all traffic permitted.",
                breakdown=risk_breakdown,
                waf_mode=normalized_mode,
            )

        if normalized_mode in ("MONITOR_ONLY", "MONITOR"):
            # Never block or throttle in monitor-only mode
            is_monitored = base_action != PolicyAction.ALLOW
            action = PolicyAction.MONITOR if is_monitored else PolicyAction.ALLOW
            reason = (
                f"WAF in MONITOR_ONLY mode - threat detected (Score {score:.1f}) but not blocked."
                if is_monitored
                else f"Traffic within safe parameters (Score {score:.1f} < {self.allow_threshold})."
            )
            return DecisionResult(
                action=action,
                risk_score=score,
                is_blocked=False,
                is_rate_limited=False,
                reason=reason,
                breakdown=risk_breakdown,
                waf_mode=normalized_mode,
            )

        # ACTIVE_BLOCKING / HYBRID / BLOCKING
        if base_action == PolicyAction.BLOCK:
            return DecisionResult(
                action=PolicyAction.BLOCK,
                risk_score=score,
                is_blocked=True,
                is_rate_limited=False,
                reason=(
                    f"Critical threat severity exceeded (Score {score:.1f} >= {self.rate_limit_threshold}) "
                    "- request actively terminated."
                ),
                breakdown=risk_breakdown,
                waf_mode=normalized_mode,
            )

        if base_action == PolicyAction.RATE_LIMIT:
            return DecisionResult(
                action=PolicyAction.RATE_LIMIT,
                risk_score=score,
                is_blocked=False,
                is_rate_limited=True,
                reason=(
                    f"Elevated risk score ({score:.1f}) in rate limiting zone "
                    f"[{self.monitor_threshold:.0f}-{self.rate_limit_threshold:.0f})."
                ),
                breakdown=risk_breakdown,
                waf_mode=normalized_mode,
            )

        if base_action == PolicyAction.MONITOR:
            return DecisionResult(
                action=PolicyAction.MONITOR,
                risk_score=score,
                is_blocked=False,
                is_rate_limited=False,
                reason=(
                    f"Low/Medium threat signature recorded (Score {score:.1f}) "
                    f"[{self.allow_threshold:.0f}-{self.monitor_threshold:.0f})."
                ),
                breakdown=risk_breakdown,
                waf_mode=normalized_mode,
            )

        return DecisionResult(
            action=PolicyAction.ALLOW,
            risk_score=score,
            is_blocked=False,
            is_rate_limited=False,
            reason=f"Safe request verified (Score {score:.1f} < {self.allow_threshold:.0f}).",
            breakdown=risk_breakdown,
            waf_mode=normalized_mode,
        )
