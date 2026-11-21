import json
import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.request_id import resolve_request_id
from app.db.models import WafConfigModel
from app.db.session import get_db
from app.security.anomaly import AnomalyDetector, get_anomaly_detector
from app.security.decision import DecisionEngine, PolicyAction
from app.security.engine import RuleEngine
from app.security.ml_detector import MLDetector, extract_26_from_http
from app.security.models import DetectionResult
from app.security.protocol_detector import (
    ApiProtocol,
    ApiProtocolDetector,
    UniversalPayloadExtractor,
)
from app.security.rate_limiter import SlidingWindowRateLimiter
from app.security.risk_engine import RiskEngine
from app.security.schema_validator import SchemaValidator, SchemaViolation
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
_anomaly_detector = get_anomaly_detector()
_schema_validator = SchemaValidator()


def get_schema_validator() -> SchemaValidator:
    """Dependency injecting the OpenAPI schema validator instance."""
    return _schema_validator


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


def get_decision_engine(settings: object = Depends(get_settings)) -> DecisionEngine:
    """Dependency injecting the policy decision engine instance configured with settings thresholds."""
    cfg = settings if isinstance(settings, Settings) else get_settings()
    return DecisionEngine(
        monitor_threshold=float(cfg.risk_rate_limit_threshold),
        rate_limit_threshold=float(cfg.risk_block_threshold),
    )


def get_rate_limiter(settings: object = Depends(get_settings)) -> SlidingWindowRateLimiter:
    """Dependency injecting the in-memory sliding window rate limiter instance."""
    global _rate_limiter
    cfg = settings if isinstance(settings, Settings) else get_settings()
    if _rate_limiter.default_limit != cfg.rate_limit_per_minute:
        _rate_limiter.default_limit = cfg.rate_limit_per_minute
    return _rate_limiter


def get_ml_detector() -> MLDetector:
    """Dependency injecting the machine learning inference service instance."""
    return _ml_detector


def get_anomaly_detector_dep() -> AnomalyDetector:
    """Dependency injecting the anomaly detection service instance."""
    return _anomaly_detector


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
    anomaly_detector: AnomalyDetector = Depends(get_anomaly_detector_dep),
    schema_validator: SchemaValidator = Depends(get_schema_validator),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Handles signature inspection, reverse proxying, and DB persistence (non-blocking)."""
    # 1. Obtain unified request ID
    request_id = getattr(request.state, "request_id", None) or resolve_request_id(
        request.headers.get("x-request-id")
    )
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")
    # SEC-PBL6-002: Check Content-Length and stream body with cumulative byte counter
    # Defends against chunked transfer-encoding OOM attacks without Content-Length
    content_length_header = request.headers.get("content-length")
    if content_length_header:
        try:
            content_length = int(content_length_header)
            if content_length > settings.max_request_body_bytes:
                body_resp = json.dumps({
                    "type": "https://tools.ietf.org/html/rfc7231#section-6.5.11",
                    "title": "Payload Too Large",
                    "status": 413,
                    "detail": f"Request body size exceeds maximum limit of {settings.max_request_body_bytes} bytes",
                    "request_id": request_id,
                }).encode("utf-8")
                return Response(
                    content=body_resp,
                    status_code=413,
                    media_type="application/problem+json",
                    headers={
                        "X-Request-ID": request_id,
                        "X-WAF-Decision": "BLOCK",
                        "X-WAF-Block-Reason": "BODY_TOO_LARGE",
                    },
                )
        except ValueError:
            pass

    body_chunks: list[bytes] = []
    total_bytes = 0
    max_bytes = settings.max_request_body_bytes

    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            body_resp = json.dumps({
                "type": "https://tools.ietf.org/html/rfc7231#section-6.5.11",
                "title": "Payload Too Large",
                "status": 413,
                "detail": f"Request body size exceeds maximum limit of {max_bytes} bytes",
                "request_id": request_id,
            }).encode("utf-8")
            return Response(
                content=body_resp,
                status_code=413,
                media_type="application/problem+json",
                headers={
                    "X-Request-ID": request_id,
                    "X-WAF-Decision": "BLOCK",
                    "X-WAF-Block-Reason": "BODY_TOO_LARGE",
                },
            )
        body_chunks.append(chunk)

    body_bytes = b"".join(body_chunks)
    query_str = str(request.url.query) if request.url.query else None

    # 2. Check active runtime WAF Mode (persisted in SQLite, fallback to env)
    active_waf_mode = settings.waf_mode
    try:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if cfg and cfg.value:
            active_waf_mode = cfg.value
    except Exception:
        pass

    # 3. Phase 8: In-Memory Sliding Window Rate Limiting with Session-Aware Fingerprinting & Exponential Backoff
    rate_limit_result = None
    if active_waf_mode != "OFF" and settings.rate_limit_enabled:
        user_agent = request.headers.get("user-agent")
        session_id = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            session_id = auth_header[7:].strip()[:32]
        if not session_id:
            session_id = request.cookies.get("session_id") or request.cookies.get("token")

        rate_limit_result = rate_limiter.check_rate_limit(
            client_ip=client_ip,
            path=f"/{path}",
            session_id=session_id,
            user_agent=user_agent,
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
                    action="MONITOR",
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
                    "type": "https://api.bookie.local/errors/rate-limit-exceeded",
                    "title": "Too Many Requests: Rate Limit Exceeded",
                    "status": 429,
                    "detail": (
                        f"Rate limit quota exceeded for scope '{rate_limit_result.scope}' "
                        f"({rate_limit_result.current_count}/{rate_limit_result.limit} requests per "
                        f"{int(rate_limit_result.window_seconds)}s). Please retry after {rate_limit_result.retry_after} seconds."
                    ),
                    "instance": f"/api/proxy/{path}",
                    "blocked": True,
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

    # 4. Task 5.4 & Task 6.4: Multi-Protocol Web API Sniffer & Protocol-Specific Decapsulation (REST / GraphQL / SOAP / JSON-RPC) (LOGIC-PBL6-002)
    api_protocol = ApiProtocolDetector.classify_protocol(
        path=f"/{path}",
        headers=dict(request.headers),
        body_bytes=body_bytes,
        query_params=query_str,
    )
    extracted_api = UniversalPayloadExtractor.extract(
        protocol=api_protocol,
        path=f"/{path}",
        query_params=query_str,
        headers=dict(request.headers),
        body_bytes=body_bytes,
    )
    payload_content = extracted_api.canonical_payload or f"/{path}"

    detection_result = DetectionResult()
    rule_failed = False

    # 4.1 Inspect request through signature Rule Engine (including decapsulated protocol payload)
    try:
        detection_result = rule_engine.inspect_request(
            path=f"/{path}",
            query_params=query_str,
            headers=dict(request.headers),
            body_bytes=body_bytes,
            canonical_payload=extracted_api.canonical_payload if api_protocol in (ApiProtocol.SOAP_XML, ApiProtocol.GRAPHQL, ApiProtocol.JSON_RPC) else None,
        )
    except Exception as sec_err:
        rule_failed = True
        logger.error(f"Security inspection failed for request [{request_id}]: {sec_err}")

    # 4.2 Positive Security Model: OpenAPI Schema Validation (Master Plan B1 & LOGIC-PBL6-003)
    schema_violations: list[SchemaViolation] = []
    if settings.schema_validation_enabled:
        content_type = request.headers.get("content-type")
        schema_violations = schema_validator.validate_request(
            method=request.method,
            path=f"/{path}",
            query_params=query_str,
            body_bytes=body_bytes,
            content_type=content_type,
        )
        if schema_violations:
            logger.warning(
                f"Positive security violations [{request_id}]: {[v.to_dict() for v in schema_violations]}"
            )
            violation_details = [v.to_dict() for v in schema_violations]
            if settings.schema_strict_mode and active_waf_mode not in ("OFF", "MONITOR_ONLY", "MONITOR"):
                body_resp = json.dumps({
                    "type": "https://api.bookie.local/errors/schema-validation-failed",
                    "title": "Positive Security Model: Schema Validation Failed",
                    "status": 400,
                    "detail": "Request payload violated target OpenAPI schema contract.",
                    "instance": f"/api/proxy/{path}",
                    "blocked": True,
                    "violations": violation_details,
                    "request_id": request_id,
                }).encode("utf-8")

                SecurityEventService.record_detection(
                    db=db,
                    request_id=request_id,
                    client_ip=client_ip,
                    detection_result=detection_result,
                    action="BLOCKED",
                    risk_score=100.0,
                    ml_score=None,
                    anomaly_score=None,
                    details_extra={
                        "decision": "BLOCK",
                        "reason": "Request payload violated OpenAPI schema contract (schema_strict_mode active)",
                        "api_protocol": api_protocol.value,
                        "schema_violations": violation_details,
                    },
                    attack_type_override="SCHEMA_VIOLATION",
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
                        response_status=400,
                        response_time_ms=1.0,
                        response_size=len(body_resp),
                    )
                except Exception as err:
                    logger.error(f"Failed to record schema violation traffic [{request_id}]: {err}")

                return Response(
                    content=body_resp,
                    status_code=400,
                    media_type="application/json",
                    headers={
                        "X-Request-ID": request_id,
                        "X-WAF-Action": "BLOCKED",
                        "X-WAF-Decision": "BLOCK",
                        "X-WAF-Risk-Score": "100.0",
                        "X-WAF-Mode": active_waf_mode,
                        "X-WAF-Schema-Violation": str(len(schema_violations)),
                    },
                )

    # 5. Single-pass 26-D feature extraction shared across ML and Anomaly detectors (SCI-PBL6-001)
    try:
        path_norm = f"/{path}" if not path.startswith("/") else path
        feature_vector_26 = extract_26_from_http(
            path=path_norm,
            query_params=query_str,
            body=body_bytes,
        ).tolist()
    except Exception:
        feature_vector_26 = None

    if settings.ml_enabled:
        ml_result = ml_detector.predict(payload_content, feature_vector=feature_vector_26)
        ml_is_available = bool(ml_result.model_loaded and ml_detector.ml_available)
        ml_score = ml_result.risk_score if ml_is_available else None
    else:
        ml_result = None
        ml_is_available = True
        ml_score = None

    if settings.anomaly_enabled:
        anomaly_result = anomaly_detector.predict(payload_content, feature_vector=feature_vector_26)
        anomaly_score = anomaly_result.anomaly_score if anomaly_result.model_loaded else None
    else:
        anomaly_result = None
        anomaly_score = None

    # 6. Phase 7: Calculate Weighted Risk Score (Rule 40% + Supervised ML 35% + Anomaly 25%)
    rule_score = detection_result.rule_risk_score if detection_result else 0.0
    risk_breakdown = risk_engine.calculate_weighted_score(
        rule_score=rule_score,
        ml_score=ml_score,
        rf_score=ml_score,  # Backward compatibility
        anomaly_score=anomaly_score,
        ablation_mode=settings.ablation_mode,
    )

    if settings.ml_enabled and not ml_is_available:
        logger.warning(
            f"ML model unavailable for request [{request_id}]. Applying fail-safe risk penalty: +{settings.ml_unavailable_risk_penalty}"
        )
        risk_breakdown.weighted_score = min(
            100.0,
            round(risk_breakdown.weighted_score + float(settings.ml_unavailable_risk_penalty), 2),
        )

    if rule_failed:
        logger.warning(
            f"Rule engine inspection failed for request [{request_id}]. Applying fail-closed risk penalty: +25.0"
        )
        risk_breakdown.weighted_score = min(
            100.0,
            round(risk_breakdown.weighted_score + 25.0, 2),
        )

    if settings.schema_validation_enabled and schema_violations:
        logger.info(
            f"Applying Positive Security risk penalty: +{settings.schema_violation_penalty} to request [{request_id}]"
        )
        risk_breakdown.weighted_score = min(
            100.0,
            round(risk_breakdown.weighted_score + float(settings.schema_violation_penalty), 2),
        )

    if extracted_api.is_protocol_anomaly:
        logger.warning(
            f"Protocol anomaly flagged on [{api_protocol.value}]: {extracted_api.protocol_alert} for request [{request_id}]"
        )
        risk_breakdown.weighted_score = max(risk_breakdown.weighted_score, 88.0)

    # 7. Phase 7: Evaluate Multi-Threshold Policy Decision
    decision = decision_engine.evaluate(
        risk_breakdown=risk_breakdown,
        waf_mode=active_waf_mode,
    )

    # 8. Persist security event if attacks were detected or elevated risk observed
    # Also record security event if ML model was unavailable (Master Plan A3)
    # Only record security events for attacks or elevated risk (do not record for clean ALLOWed traffic)
    record_security_event = (
        (detection_result and (detection_result.is_attack or decision.action != PolicyAction.ALLOW))
        or bool(settings.schema_validation_enabled and schema_violations)
    )
    if record_security_event:
        action_label = (
            "BLOCKED"
            if decision.is_blocked
            else (
                "MONITOR"
                if active_waf_mode in ("MONITOR_ONLY", "MONITOR") or decision.action == PolicyAction.MONITOR
                else decision.action.value
            )
        )
        override_type = None
        if not detection_result or not detection_result.is_attack:
            if settings.schema_validation_enabled and schema_violations:
                override_type = "SCHEMA_VIOLATION"
            elif not ml_is_available:
                override_type = "ML_UNAVAILABLE"

        SecurityEventService.record_detection(
            db=db,
            request_id=request_id,
            client_ip=client_ip,
            detection_result=detection_result,
            action=action_label,
            risk_score=decision.risk_score,
            ml_score=risk_breakdown.ml_score,
            anomaly_score=risk_breakdown.anomaly_score,
            details_extra={
                "decision": decision.action.value,
                "reason": decision.reason,
                "api_protocol": api_protocol.value,
                "protocol_alert": extracted_api.protocol_alert,
                "is_protocol_anomaly": extracted_api.is_protocol_anomaly,
                "schema_violations": [v.to_dict() for v in schema_violations] if schema_violations else [],
                "breakdown": risk_breakdown.to_dict(),
                "ml_inference": ml_result.to_dict() if (ml_result and ml_result.model_loaded) else ({"status": "disabled"} if not settings.ml_enabled else {"status": "unavailable", "fail_safe_penalty": settings.ml_unavailable_risk_penalty}),
                "anomaly_inference": anomaly_result.to_dict() if (anomaly_result and anomaly_result.model_loaded) else None,
                "ml_available": ml_is_available,
            },
            attack_type_override=override_type,
        )

    # 9. Enforcement: Block with 403 Forbidden, rate limit with 429, or forward to upstream
    if decision.is_blocked:
        if detection_result.attack_families:
            primary_family = detection_result.attack_families[0].value
        elif anomaly_result and anomaly_result.is_anomaly:
            primary_family = "ANOMALY_ZERO_DAY"
        elif ml_result and ml_result.is_attack:
            primary_family = ml_result.attack_type
        else:
            primary_family = "UNKNOWN"
        block_content = json.dumps({
            "type": "https://api.bookie.local/errors/waf-forbidden",
            "title": "Forbidden by Web Application Firewall",
            "blocked": True,
            "status": 403,
            "error": "WAF_ACCESS_DENIED",
            "message": "Access blocked by [SHIELD] Web API Security Platform (WAF).",
            "detail": decision.reason,
            "instance": f"/api/proxy/{path}",
            "request_id": request_id,
            "decision": decision.action.value,
            "action": "BLOCKED",
            "attack_type": primary_family,
            "risk_score": decision.risk_score,
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
            "X-WAF-API-Protocol": api_protocol.value,
        }
        if ml_result and ml_result.model_loaded:
            block_headers["X-WAF-ML-Score"] = str(ml_result.risk_score)
            block_headers["X-WAF-ML-Type"] = ml_result.attack_type
            block_headers["X-WAF-ML-Latency"] = f"{ml_result.latency_ms}ms"
        if anomaly_result and anomaly_result.model_loaded:
            block_headers["X-WAF-Anomaly-Score"] = str(anomaly_result.anomaly_score)
            block_headers["X-WAF-Anomaly-Latency"] = f"{anomaly_result.latency_ms}ms"

        response = Response(
            content=block_content,
            status_code=403,
            media_type="application/json",
            headers=block_headers,
        )
        latency_ms = 1.2
        response_size = len(block_content)
    elif decision.is_rate_limited:
        risk_rl_result = rate_limiter.check_rate_limit(
            client_ip=client_ip,
            path=f"/{path}",
            session_id=session_id,
            user_agent=user_agent,
            risk_penalty=True,
        )
        retry_after_sec = risk_rl_result.retry_after if risk_rl_result.is_limited else 60
        quota_limit = risk_rl_result.limit
        quota_current = risk_rl_result.current_count
        rate_limit_body = json.dumps({
            "type": "https://api.bookie.local/errors/risk-rate-limit-exceeded",
            "title": "Too Many Requests: Elevated Risk Throttled",
            "status": 429,
            "detail": (
                f"Request throttled due to elevated risk score ({decision.risk_score:.1f}). "
                f"Quota restricted for scope '{risk_rl_result.scope}'. Please retry after {retry_after_sec} seconds."
            ),
            "instance": f"/api/proxy/{path}",
            "blocked": True,
            "error": "RISK_RATE_LIMIT_EXCEEDED",
            "message": "Elevated risk traffic throttled by [SHIELD] Multi-Tier Policy Engine.",
            "request_id": request_id,
            "client_ip": client_ip,
            "scope": risk_rl_result.scope,
            "limit": quota_limit,
            "current_count": quota_current,
            "retry_after": retry_after_sec,
            "risk_score": decision.risk_score,
        }).encode("utf-8")

        response = Response(
            content=rate_limit_body,
            status_code=429,
            media_type="application/json",
            headers={
                "Retry-After": str(retry_after_sec),
                "X-RateLimit-Limit": str(quota_limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(retry_after_sec),
                "X-Request-ID": request_id,
                "X-WAF-Action": "RATE_LIMIT",
                "X-WAF-Decision": "RATE_LIMIT",
                "X-WAF-Risk-Score": str(decision.risk_score),
                "X-WAF-Mode": active_waf_mode,
                "X-WAF-API-Protocol": api_protocol.value,
            },
        )
        latency_ms = 1.0
        response_size = len(rate_limit_body)
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
        response.headers["X-WAF-API-Protocol"] = api_protocol.value
        if rate_limit_result:
            response.headers["X-RateLimit-Limit"] = str(rate_limit_result.limit)
            response.headers["X-RateLimit-Remaining"] = str(rate_limit_result.remaining)
            response.headers["X-RateLimit-Reset"] = str(rate_limit_result.retry_after)
        if ml_result and ml_result.model_loaded:
            response.headers["X-WAF-ML-Score"] = str(ml_result.risk_score)
            response.headers["X-WAF-ML-Type"] = ml_result.attack_type
            response.headers["X-WAF-ML-Latency"] = f"{ml_result.latency_ms}ms"
        if anomaly_result and anomaly_result.model_loaded:
            response.headers["X-WAF-Anomaly-Score"] = str(anomaly_result.anomaly_score)
            response.headers["X-WAF-Anomaly-Latency"] = f"{anomaly_result.latency_ms}ms"

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
