import json
import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.request_id import resolve_request_id
from app.db.models import WafConfigModel
from app.db.session import get_db
from app.security.decision import DecisionEngine, PolicyAction
from app.security.engine import RuleEngine
from app.security.ml_detector import MLDetector
from app.security.rate_limiter import SlidingWindowRateLimiter
from app.security.risk_engine import RiskEngine
from app.services.proxy import ProxyService
from app.services.security import SecurityEventService
from app.services.traffic import TrafficService

logger = logging.getLogger("waf.gateway.api.proxy")

router = APIRouter(tags=["Proxy"])

# Global shared security engine instances for gateway
_rule_engine = RuleEngine()
_risk_engine = RiskEngine()
_decision_engine = DecisionEngine()
_rate_limiter = SlidingWindowRateLimiter()
_ml_detector = MLDetector()


def get_proxy_service(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> ProxyService:
    """Dependency injecting ProxyService with shared AsyncClient from app state."""
    client = getattr(request.app.state, "http_client", None)
    return ProxyService(settings=settings, client=client)


def get_rule_engine() -> RuleEngine:
    """Dependency injecting the rule engine instance."""
    return _rule_engine


def get_risk_engine() -> RiskEngine:
    """Dependency injecting the risk engine instance."""
    return _risk_engine


def get_decision_engine() -> DecisionEngine:
    """Dependency injecting the policy decision engine instance."""
    return _decision_engine


def get_rate_limiter() -> SlidingWindowRateLimiter:
    """Dependency injecting the in-memory sliding window rate limiter instance."""
    return _rate_limiter


def get_ml_detector() -> MLDetector:
    """Dependency injecting the machine learning inference service instance."""
    return _ml_detector


@router.api_route(
    "/api/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    summary="Reverse Proxy Endpoint with Security Inspection",
    description=(
        "Inspects requests using signature-based Rule Engine and Hybrid Risk Engine (Phase 7), "
        "evaluates policy decisions (ALLOW / MONITOR / RATE_LIMIT / BLOCK), persists security events, "
        "forwards authorized requests to the upstream Target Web API, and records traffic metadata."
    ),
)
async def proxy_endpoint(
    path: str,
    request: Request,
    db: Session = Depends(get_db),
    proxy_service: ProxyService = Depends(get_proxy_service),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    decision_engine: DecisionEngine = Depends(get_decision_engine),
    rate_limiter: SlidingWindowRateLimiter = Depends(get_rate_limiter),
    ml_detector: MLDetector = Depends(get_ml_detector),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Handles signature inspection, reverse proxying, and DB persistence (non-blocking)."""
    # 1. Obtain unified request ID
    request_id = getattr(request.state, "request_id", None) or resolve_request_id(
        request.headers.get("x-request-id")
    )
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")
    body_bytes = await request.body()
    query_str = str(request.url.query) if request.url.query else None

    # 2. Check active runtime WAF Mode (persisted in SQLite, fallback to env)
    active_waf_mode = settings.waf_mode
    try:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if cfg and cfg.value:
            active_waf_mode = cfg.value
    except Exception:
        pass

    # 3. Phase 8: In-Memory Sliding Window Rate Limiting (API4:2023, ModSecurity CRS v4.0)
    rate_limit_result = None
    if active_waf_mode != "OFF":
        rate_limit_result = rate_limiter.check_rate_limit(
            client_ip=client_ip,
            path=f"/{path}",
        )

        if rate_limit_result.is_limited:
            if active_waf_mode in ("MONITOR_ONLY", "MONITOR"):
                SecurityEventService.record_rate_limit(
                    db=db,
                    request_id=request_id,
                    client_ip=client_ip,
                    scope=rate_limit_result.scope,
                    current_count=rate_limit_result.current_count,
                    limit=rate_limit_result.limit,
                    retry_after=rate_limit_result.retry_after,
                    action="DETECTED",
                )
            else:
                SecurityEventService.record_rate_limit(
                    db=db,
                    request_id=request_id,
                    client_ip=client_ip,
                    scope=rate_limit_result.scope,
                    current_count=rate_limit_result.current_count,
                    limit=rate_limit_result.limit,
                    retry_after=rate_limit_result.retry_after,
                    action="RATE_LIMIT",
                )

                rate_limit_body = json.dumps({
                    "blocked": True,
                    "status": 429,
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded. Temporary access restricted by [SHIELD] WAF.",
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "scope": rate_limit_result.scope,
                    "limit": rate_limit_result.limit,
                    "current_count": rate_limit_result.current_count,
                    "retry_after": rate_limit_result.retry_after,
                    "window_seconds": rate_limit_result.window_seconds,
                }).encode("utf-8")

                response = Response(
                    content=rate_limit_body,
                    status_code=429,
                    media_type="application/json",
                    headers={
                        "Retry-After": str(rate_limit_result.retry_after),
                        "X-RateLimit-Limit": str(rate_limit_result.limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(rate_limit_result.retry_after),
                        "X-Request-ID": request_id,
                        "X-WAF-Action": "RATE_LIMIT",
                        "X-WAF-Decision": "RATE_LIMIT",
                        "X-WAF-Risk-Score": "75.0",
                        "X-WAF-Mode": active_waf_mode,
                    },
                )

                try:
                    TrafficService.record_traffic(
                        db=db,
                        request_id=request_id,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        method=request.method,
                        url=str(request.url),
                        path=f"/{path}",
                        headers=dict(request.headers),
                        query_params=query_str,
                        body_bytes=body_bytes,
                        response_status=429,
                        response_time_ms=1.0,
                        response_size=len(rate_limit_body),
                    )
                except Exception as err:
                    logger.error(f"Failed to record rate limit traffic [{request_id}]: {err}")

                return response

    detection_result = None

    # 4. Inspect request through signature Rule Engine
    try:
        detection_result = rule_engine.inspect_request(
            path=f"/{path}",
            query_params=query_str,
            headers=dict(request.headers),
            body_bytes=body_bytes,
        )
    except Exception as sec_err:
        logger.error(f"Security inspection failed for request [{request_id}]: {sec_err}")

    # 5. Task 5.4: Machine Learning Inference (Random Forest, <15ms latency)
    body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    payload_content = f"/{path} {query_str or ''} {body_text}".strip()
    ml_result = ml_detector.predict(payload_content)
    rf_score = ml_result.risk_score if ml_result.model_loaded else None

    # 6. Phase 7: Calculate Weighted Risk Score (Rule 40% + RF 35% + IF 25%)
    rule_score = detection_result.rule_risk_score if detection_result else 0.0
    risk_breakdown = risk_engine.calculate_weighted_score(
        rule_score=rule_score,
        rf_score=rf_score,
        anomaly_score=None,
    )

    # 7. Phase 7: Evaluate Multi-Threshold Policy Decision
    decision = decision_engine.evaluate(
        risk_breakdown=risk_breakdown,
        waf_mode=active_waf_mode,
    )

    # 8. Persist security event if attacks were detected or elevated risk observed
    if detection_result and (detection_result.is_attack or decision.action != PolicyAction.ALLOW):
        action_label = (
            "BLOCKED"
            if decision.is_blocked
            else (
                "DETECTED"
                if active_waf_mode in ("MONITOR_ONLY", "MONITOR")
                else decision.action.value
            )
        )
        SecurityEventService.record_detection(
            db=db,
            request_id=request_id,
            client_ip=client_ip,
            detection_result=detection_result,
            action=action_label,
            risk_score=decision.risk_score,
            ml_score=risk_breakdown.rf_score,
            anomaly_score=risk_breakdown.anomaly_score,
            details_extra={
                "decision": decision.action.value,
                "reason": decision.reason,
                "breakdown": risk_breakdown.to_dict(),
                "ml_inference": ml_result.to_dict() if ml_result.model_loaded else None,
            },
        )

    # 7. Enforcement: Block with 403 Forbidden or forward to upstream
    if decision.is_blocked and detection_result:
        primary_family = (
            detection_result.attack_families[0].value
            if detection_result.attack_families
            else "UNKNOWN"
        )
        block_content = json.dumps({
            "blocked": True,
            "status": 403,
            "error": "WAF_ACCESS_DENIED",
            "message": "Access blocked by [SHIELD] Web API Security Platform (WAF).",
            "request_id": request_id,
            "decision": decision.action.value,
            "attack_type": primary_family,
            "threat_score": decision.risk_score,
            "breakdown": risk_breakdown.to_dict(),
            "reason": decision.reason,
        }).encode("utf-8")

        block_headers = {
            "X-Request-ID": request_id,
            "X-WAF-Action": "BLOCKED",
            "X-WAF-Decision": decision.action.value,
            "X-WAF-Risk-Score": str(decision.risk_score),
            "X-WAF-Mode": active_waf_mode,
        }
        if ml_result and ml_result.model_loaded:
            block_headers["X-WAF-ML-Score"] = str(ml_result.risk_score)
            block_headers["X-WAF-ML-Type"] = ml_result.attack_type
            block_headers["X-WAF-ML-Latency"] = f"{ml_result.latency_ms}ms"

        response = Response(
            content=block_content,
            status_code=403,
            media_type="application/json",
            headers=block_headers,
        )
        latency_ms = 1.2
        response_size = len(block_content)
    else:
        # Forward request to upstream target
        response, latency_ms, response_size = await proxy_service.forward(
            request=request,
            path=path,
            request_id=request_id,
            body_bytes=body_bytes,
        )
        # Attach security headers
        response.headers["X-WAF-Action"] = decision.action.value
        response.headers["X-WAF-Decision"] = decision.action.value
        response.headers["X-WAF-Risk-Score"] = str(decision.risk_score)
        if rate_limit_result:
            response.headers["X-RateLimit-Limit"] = str(rate_limit_result.limit)
            response.headers["X-RateLimit-Remaining"] = str(rate_limit_result.remaining)
            response.headers["X-RateLimit-Reset"] = str(rate_limit_result.retry_after)
        if ml_result and ml_result.model_loaded:
            response.headers["X-WAF-ML-Score"] = str(ml_result.risk_score)
            response.headers["X-WAF-ML-Type"] = ml_result.attack_type
            response.headers["X-WAF-ML-Latency"] = f"{ml_result.latency_ms}ms"

    # 5. Persist traffic metadata in SQLite
    try:
        TrafficService.record_traffic(
            db=db,
            request_id=request_id,
            client_ip=client_ip,
            user_agent=user_agent,
            method=request.method,
            url=str(request.url),
            path=f"/{path}",
            headers=dict(request.headers),
            query_params=query_str,
            body_bytes=body_bytes,
            response_status=response.status_code,
            response_time_ms=latency_ms,
            response_size=response_size,
        )
    except Exception as err:
        logger.error(f"Failed to record traffic for request [{request_id}]: {err}")

    return response
