import json
import logging
import threading
import time
from typing import Any

import anyio
from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, get_settings
from app.core.request_id import resolve_request_id
from app.db.models import WafConfigModel
from app.db.session import SessionLocal, engine
from app.security.anomaly import AnomalyDetector, get_anomaly_detector
from app.security.bola_detector import BOLADetector
from app.security.decision import DecisionEngine, PolicyAction
from app.security.engine import RuleEngine
from app.security.ml_detector import MLDetector, extract_26_from_http
from app.security.models import AttackType, DetectionResult
from app.security.protocol_detector import (
    ApiProtocol,
    ApiProtocolDetector,
    ExtractedApiPayload,
    UniversalPayloadExtractor,
)
from app.security.rate_limiter import SlidingWindowRateLimiter
from app.security.response_dlp import ResponseDLPGuard
from app.security.risk_engine import RiskEngine
from app.security.schema_validator import SchemaValidator, SchemaViolation
from app.security.scoring import RuleScorer
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
_bola_detector = BOLADetector()
_response_dlp = ResponseDLPGuard()

# RAM TTL cache for runtime WAF mode (PERF-PBL6-001: avoids per-request SQLite SELECT)
_WAF_MODE_CACHE: dict[int, tuple[str | None, float]] = {}
_WAF_MODE_CACHE_TTL: float = 5.0


def invalidate_waf_mode_cache() -> None:
    """Clears cached runtime WAF mode across all DB engine bindings."""
    _WAF_MODE_CACHE.clear()


@event.listens_for(WafConfigModel, "after_insert")
@event.listens_for(WafConfigModel, "after_update")
@event.listens_for(WafConfigModel, "after_delete")
def _auto_invalidate_waf_mode_cache(_mapper: Any, _connection: Any, target: Any) -> None:
    """Automatically invalidates RAM cache whenever WafConfigModel('waf_mode') mutates."""
    if getattr(target, "key", None) == "waf_mode":
        invalidate_waf_mode_cache()


def _resolve_active_waf_mode(bind: Any, settings: Settings) -> str:
    """Returns active runtime WAF mode from RAM TTL cache, opening SQLite ONLY on cache miss."""
    cache_key = id(bind)
    now = time.monotonic()
    cached = _WAF_MODE_CACHE.get(cache_key)
    if cached is not None:
        cached_val, cached_at = cached
        if (now - cached_at) < _WAF_MODE_CACHE_TTL:
            return cached_val if cached_val is not None else settings.waf_mode

    db_mode: str | None = None
    try:
        with SessionLocal() as db:
            cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
            if cfg and cfg.value:
                db_mode = cfg.value
    except Exception:
        pass

    _WAF_MODE_CACHE[cache_key] = (db_mode, now)
    return db_mode if db_mode is not None else settings.waf_mode


def _run_security_inspection(
    path_norm: str,
    method: str,
    query_str: str | None,
    req_headers: dict[str, str],
    body_bytes: bytes,
    active_waf_mode: str,
    rule_engine: RuleEngine,
    schema_validator: SchemaValidator,
    ml_detector: MLDetector,
    anomaly_detector: AnomalyDetector,
    settings: Settings,
    request_id: str,
) -> tuple[
    ApiProtocol,
    ExtractedApiPayload,
    DetectionResult,
    bool,
    list[SchemaViolation],
    bool,
    Any,
    bool,
    float | None,
    Any,
    float | None,
]:
    """Executes CPU-bound synchronous WAF inspection off the asyncio event loop (PERF-PBL6-001)."""
    # 1. Multi-Protocol Web API Sniffer & Protocol-Specific Decapsulation (LOGIC-PBL6-002)
    api_protocol = ApiProtocolDetector.classify_protocol(
        path=path_norm,
        headers=req_headers,
        body_bytes=body_bytes,
        query_params=query_str,
    )
    extracted_api = UniversalPayloadExtractor.extract(
        protocol=api_protocol,
        path=path_norm,
        query_params=query_str,
        headers=req_headers,
        body_bytes=body_bytes,
    )
    payload_content = extracted_api.canonical_payload or path_norm

    # 2. Deterministic Signature Rule Engine (including decapsulated payload)
    detection_result = DetectionResult()
    rule_failed = False
    try:
        detection_result = rule_engine.inspect_request(
            path=path_norm,
            query_params=query_str,
            headers=req_headers,
            body_bytes=body_bytes,
            canonical_payload=(
                extracted_api.canonical_payload
                if api_protocol in (ApiProtocol.SOAP_XML, ApiProtocol.GRAPHQL, ApiProtocol.JSON_RPC)
                else None
            ),
        )
    except Exception as sec_err:
        rule_failed = True
        logger.error(f"Security inspection failed for request [{request_id}]: {sec_err}")

    # 3. Positive Security Model: OpenAPI Schema Validation (Master Plan B1 & LOGIC-PBL6-003)
    schema_violations: list[SchemaViolation] = []
    if settings.schema_validation_enabled:
        content_type = req_headers.get("content-type")
        schema_violations = schema_validator.validate_request(
            method=method,
            path=path_norm,
            query_params=query_str,
            body_bytes=body_bytes,
            content_type=content_type,
        )
        if (
            schema_violations
            and settings.schema_strict_mode
            and active_waf_mode not in ("OFF", "MONITOR_ONLY", "MONITOR")
        ):
            # Early short-circuit on strict schema block to avoid unnecessary ML CPU work
            return (
                api_protocol,
                extracted_api,
                detection_result,
                rule_failed,
                schema_violations,
                True,
                None,
                True,
                None,
                None,
                None,
            )

    # 4. Single-pass 26-D feature extraction shared across ML and Anomaly detectors (SCI-PBL6-001)
    try:
        if api_protocol == ApiProtocol.SOAP_XML and not extracted_api.is_protocol_anomaly:
            ml_body: str | None = extracted_api.metadata.get("extracted_text") or ""
        else:
            ml_body = body_bytes.decode("utf-8", errors="replace") if body_bytes else None
        feature_vector_26 = extract_26_from_http(
            path=path_norm,
            query_params=query_str,
            body=ml_body,
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

    return (
        api_protocol,
        extracted_api,
        detection_result,
        rule_failed,
        schema_violations,
        False,
        ml_result,
        ml_is_available,
        ml_score,
        anomaly_result,
        anomaly_score,
    )


# Leader-Follower Group Commit prevents SQLite WAL lock contention under C=50 concurrency
_QUEUE_LOCK = threading.Lock()
_DB_WRITE_LOCK = threading.Lock()
_PENDING_WRITES: dict[
    int,
    list[
        tuple[
            Any,
            dict[str, Any] | None,
            dict[str, Any] | None,
            dict[str, Any] | None,
            threading.Event,
        ]
    ],
] = {}
_SESSION_FACTORY_CACHE: dict[int, sessionmaker] = {}


def _persist_background_logs(
    bind: Any,
    detection_kwargs: dict[str, Any] | None = None,
    rate_limit_kwargs: dict[str, Any] | None = None,
    traffic_kwargs: dict[str, Any] | None = None,
) -> None:
    """Persists SecurityEvent and RequestLog via Leader-Follower Group Commit off the response path."""
    bind_key = id(bind)
    done_event = threading.Event()
    with _QUEUE_LOCK:
        _PENDING_WRITES.setdefault(bind_key, []).append(
            (bind, detection_kwargs, rate_limit_kwargs, traffic_kwargs, done_event)
        )

    while not done_event.is_set():
        if _DB_WRITE_LOCK.acquire(blocking=False):
            try:
                while True:
                    with _QUEUE_LOCK:
                        batch = _PENDING_WRITES.pop(bind_key, [])
                    if not batch:
                        break
                    session_factory = _SESSION_FACTORY_CACHE.get(bind_key)
                    if session_factory is None:
                        session_factory = sessionmaker(autocommit=False, autoflush=False, bind=bind)
                        _SESSION_FACTORY_CACHE[bind_key] = session_factory
                    with session_factory() as bg_db:
                        try:
                            for _b, det_kw, rl_kw, tr_kw, _ev in batch:
                                if rl_kw is not None:
                                    SecurityEventService.record_rate_limit(
                                        db=bg_db, commit=False, **rl_kw
                                    )
                                if det_kw is not None:
                                    SecurityEventService.record_detection(
                                        db=bg_db, commit=False, **det_kw
                                    )
                                if tr_kw is not None:
                                    TrafficService.record_traffic(
                                        db=bg_db, commit=False, **tr_kw
                                    )
                            bg_db.commit()
                        except Exception as err:
                            bg_db.rollback()
                            logger.error(
                                f"Background group-commit persistence error (batch={len(batch)}): {err}"
                            )
                        finally:
                            for _b, _d, _r, _t, ev in batch:
                                ev.set()
            finally:
                _DB_WRITE_LOCK.release()
        else:
            done_event.wait(timeout=0.005)


def get_schema_validator() -> SchemaValidator:
    """Dependency injecting the OpenAPI schema validator instance."""
    return _schema_validator


def get_bola_detector() -> BOLADetector:
    """Dependency injecting the stateful BOLA/IDOR detector instance."""
    return _bola_detector


def get_response_dlp() -> ResponseDLPGuard:
    """Dependency injecting the outbound response DLP guard instance."""
    return _response_dlp


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
        "evaluates policy decisions (ALLOW / MONITOR / RATE_LIMIT / BLOCK), persists security events "
        "asynchronously via BackgroundTasks, forwards authorized requests to the upstream Target Web API, "
        "and records traffic metadata."
    ),
)
async def proxy_endpoint(
    path: str,
    request: Request,
    background_tasks: BackgroundTasks,
) -> Response:
    """Handles async offloaded security inspection, reverse proxying, and non-blocking DB logging."""
    req_start = time.perf_counter()

    # Resolve in-memory dependencies directly without per-dependency FastAPI threadpool hops (PERF-PBL6-001)
    settings = get_settings()
    proxy_service = get_proxy_service(request=request, settings=settings)
    rule_engine = get_rule_engine()
    risk_engine = get_risk_engine()
    decision_engine = get_decision_engine(settings=settings)
    rate_limiter = get_rate_limiter(settings=settings)
    ml_detector = get_ml_detector()
    anomaly_detector = get_anomaly_detector_dep()
    schema_validator = get_schema_validator()

    # 1. Obtain unified request ID
    request_id = getattr(request.state, "request_id", None) or resolve_request_id(
        request.headers.get("x-request-id")
    )
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")
    req_headers_dict = dict(request.headers)
    db_bind = engine

    # SEC-PBL6-002: Check Content-Length and stream body with cumulative byte counter
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
    path_norm = f"/{path}" if not path.startswith("/") else path

    # 2. Check active runtime WAF Mode via RAM TTL cache (PERF-PBL6-001)
    active_waf_mode = _resolve_active_waf_mode(db_bind, settings)

    # 3. Extract session_id unconditionally & apply Sliding Window Rate Limiting
    session_id = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        session_id = auth_header[7:].strip()[:32]
    if not session_id:
        session_id = request.cookies.get("session_id") or request.cookies.get("token")

    rate_limit_result = None
    pending_rate_limit_kwargs: dict[str, Any] | None = None
    if active_waf_mode != "OFF" and settings.rate_limit_enabled:
        rate_limit_result = rate_limiter.check_rate_limit(
            client_ip=client_ip,
            path=path_norm,
            session_id=session_id,
            user_agent=user_agent,
        )

        if rate_limit_result.is_limited:
            if active_waf_mode in ("MONITOR_ONLY", "MONITOR"):
                pending_rate_limit_kwargs = {
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "scope": rate_limit_result.scope,
                    "current_count": rate_limit_result.current_count,
                    "limit": rate_limit_result.limit,
                    "retry_after": rate_limit_result.retry_after,
                    "action": "MONITOR",
                }
            else:
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

                elapsed_ms = round((time.perf_counter() - req_start) * 1000.0, 3)
                background_tasks.add_task(
                    _persist_background_logs,
                    db_bind,
                    rate_limit_kwargs={
                        "request_id": request_id,
                        "client_ip": client_ip,
                        "scope": rate_limit_result.scope,
                        "current_count": rate_limit_result.current_count,
                        "limit": rate_limit_result.limit,
                        "retry_after": rate_limit_result.retry_after,
                        "action": "RATE_LIMIT",
                    },
                    traffic_kwargs={
                        "request_id": request_id,
                        "client_ip": client_ip,
                        "user_agent": user_agent,
                        "method": request.method,
                        "url": str(request.url),
                        "path": path_norm,
                        "headers": req_headers_dict,
                        "query_params": query_str,
                        "body_bytes": body_bytes,
                        "response_status": 429,
                        "response_time_ms": elapsed_ms,
                        "response_size": len(rate_limit_body),
                    },
                )

                return Response(
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

    # 4-5. Offload synchronous CPU-bound WAF inspection onto worker thread (PERF-PBL6-001)
    (
        api_protocol,
        extracted_api,
        detection_result,
        rule_failed,
        schema_violations,
        strict_schema_blocked,
        ml_result,
        ml_is_available,
        ml_score,
        anomaly_result,
        anomaly_score,
    ) = await anyio.to_thread.run_sync(
        _run_security_inspection,
        path_norm,
        request.method,
        query_str,
        req_headers_dict,
        body_bytes,
        active_waf_mode,
        rule_engine,
        schema_validator,
        ml_detector,
        anomaly_detector,
        settings,
        request_id,
    )

    if schema_violations:
        violation_details = [v.to_dict() for v in schema_violations]
        logger.warning(f"Positive security violations [{request_id}]: {violation_details}")
        if strict_schema_blocked:
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

            elapsed_ms = round((time.perf_counter() - req_start) * 1000.0, 3)
            background_tasks.add_task(
                _persist_background_logs,
                db_bind,
                rate_limit_kwargs=pending_rate_limit_kwargs,
                detection_kwargs={
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "detection_result": detection_result,
                    "action": "BLOCKED",
                    "risk_score": 100.0,
                    "ml_score": None,
                    "anomaly_score": None,
                    "details_extra": {
                        "decision": "BLOCK",
                        "reason": "Request payload violated OpenAPI schema contract (schema_strict_mode active)",
                        "api_protocol": api_protocol.value,
                        "schema_violations": violation_details,
                    },
                    "attack_type_override": "SCHEMA_VIOLATION",
                },
                traffic_kwargs={
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "method": request.method,
                    "url": str(request.url),
                    "path": path_norm,
                    "headers": req_headers_dict,
                    "query_params": query_str,
                    "body_bytes": body_bytes,
                    "response_status": 400,
                    "response_time_ms": elapsed_ms,
                    "response_size": len(body_resp),
                },
            )

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

    # 6. Phase 7: Stateful BOLA/IDOR Check + Weighted Risk Score (Rule 40% + Supervised ML 35% + Anomaly 25%)
    if (
        active_waf_mode != "OFF"
        and settings.ablation_mode not in ("ml_only", "anomaly_only")
    ):
        bola_res = _bola_detector.inspect(
            client_ip=client_ip,
            path=path_norm,
            method=request.method,
            session_id=session_id,
        )
        if bola_res.is_bola and bola_res.rule_match is not None:
            detection_result.matches.append(bola_res.rule_match)
            detection_result.is_attack = True
            detection_result.total_matches = len(detection_result.matches)
            detection_result.rule_risk_score = RuleScorer.calculate_score(detection_result.matches)
            detection_result.highest_severity = RuleScorer.get_highest_severity(detection_result.matches)
            detection_result.attack_families = RuleScorer.get_attack_families(detection_result.matches)

    rule_score = detection_result.rule_risk_score if detection_result else 0.0
    risk_breakdown = risk_engine.calculate_weighted_score(
        rule_score=rule_score,
        ml_score=ml_score,
        rf_score=ml_score,
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

    # 8. Prepare security event record payload if attacks or elevated risk observed
    detection_kwargs: dict[str, Any] | None = None
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

        detection_kwargs = {
            "request_id": request_id,
            "client_ip": client_ip,
            "detection_result": detection_result,
            "action": action_label,
            "risk_score": decision.risk_score,
            "ml_score": risk_breakdown.ml_score,
            "anomaly_score": risk_breakdown.anomaly_score,
            "details_extra": {
                "decision": decision.action.value,
                "reason": decision.reason,
                "api_protocol": api_protocol.value,
                "protocol_alert": extracted_api.protocol_alert,
                "is_protocol_anomaly": extracted_api.is_protocol_anomaly,
                "schema_violations": [v.to_dict() for v in schema_violations] if schema_violations else [],
                "breakdown": risk_breakdown.to_dict(),
                "ml_inference": (
                    ml_result.to_dict()
                    if (ml_result and ml_result.model_loaded)
                    else (
                        {"status": "disabled"}
                        if not settings.ml_enabled
                        else {
                            "status": "unavailable",
                            "fail_safe_penalty": settings.ml_unavailable_risk_penalty,
                        }
                    )
                ),
                "anomaly_inference": (
                    anomaly_result.to_dict() if (anomaly_result and anomaly_result.model_loaded) else None
                ),
                "ml_available": ml_is_available,
            },
            "attack_type_override": override_type,
        }

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
            "X-WAF-Rule-Score": str(round(rule_score, 2)),
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
        latency_ms = round((time.perf_counter() - req_start) * 1000.0, 3)
        response_size = len(block_content)
    elif decision.is_rate_limited:
        risk_rl_result = rate_limiter.check_rate_limit(
            client_ip=client_ip,
            path=path_norm,
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
        latency_ms = round((time.perf_counter() - req_start) * 1000.0, 3)
        response_size = len(rate_limit_body)
    else:
        # Forward request to upstream target
        response, _upstream_ms, response_size = await proxy_service.forward(
            request=request,
            path=path,
            request_id=request_id,
            body_bytes=body_bytes,
        )
        # Outbound Response DLP Guard (OWASP API3:2023 Excessive Data Exposure)
        if active_waf_mode != "OFF":
            dlp_res = _response_dlp.inspect_and_redact(
                body_bytes=response.body,
                content_type=response.headers.get("content-type"),
                status_code=response.status_code,
                active_waf_mode=active_waf_mode,
            )
            if dlp_res.has_leak:
                if dlp_res.redacted and dlp_res.redacted_bytes is not None:
                    preserved_headers = [
                        (k, v)
                        for k, v in response.headers.raw
                        if k.decode("latin-1").lower() != "content-length"
                    ]
                    response = Response(
                        content=dlp_res.redacted_bytes,
                        status_code=response.status_code,
                    )
                    for hk_bytes, hv_bytes in preserved_headers:
                        response.headers.append(
                            hk_bytes.decode("latin-1"),
                            hv_bytes.decode("latin-1"),
                        )
                    response.headers["X-WAF-DLP-Redacted"] = "true"
                    response.headers["X-WAF-DLP-Findings"] = str(dlp_res.finding_count)
                    response_size = len(dlp_res.redacted_bytes)
                else:
                    response.headers["X-WAF-DLP-Alert"] = "MONITOR"

                dlp_action = "BLOCKED" if dlp_res.redacted else "MONITOR"
                if detection_kwargs is None:
                    detection_kwargs = {
                        "request_id": request_id,
                        "client_ip": client_ip,
                        "detection_result": detection_result,
                        "action": dlp_action,
                        "risk_score": 88.0,
                        "ml_score": risk_breakdown.ml_score,
                        "anomaly_score": risk_breakdown.anomaly_score,
                        "details_extra": {
                            "decision": "DLP_REDACT" if dlp_res.redacted else "MONITOR",
                            "reason": (
                                f"Outbound Response DLP intercepted {dlp_res.finding_count} leaked "
                                f"credential/secret field(s): {', '.join(dlp_res.leaked_fields[:5])}"
                            ),
                            "api_protocol": api_protocol.value,
                            "dlp_leaked_fields": dlp_res.leaked_fields,
                            "dlp_redacted": dlp_res.redacted,
                        },
                        "attack_type_override": AttackType.EXCESSIVE_DATA_EXPOSURE.value,
                    }

        latency_ms = round((time.perf_counter() - req_start) * 1000.0, 3)
        # Attach security headers
        response.headers["X-WAF-Action"] = decision.action.value
        response.headers["X-WAF-Decision"] = decision.action.value
        response.headers["X-WAF-Risk-Score"] = str(decision.risk_score)
        response.headers["X-WAF-Rule-Score"] = str(round(rule_score, 2))
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

    # 10. Offload SQLite persistence into FastAPI BackgroundTasks (PERF-PBL6-001)
    background_tasks.add_task(
        _persist_background_logs,
        db_bind,
        detection_kwargs=detection_kwargs,
        rate_limit_kwargs=pending_rate_limit_kwargs,
        traffic_kwargs={
            "request_id": request_id,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "method": request.method,
            "url": str(request.url),
            "path": path_norm,
            "headers": req_headers_dict,
            "query_params": query_str,
            "body_bytes": body_bytes,
            "response_status": response.status_code,
            "response_time_ms": latency_ms,
            "response_size": response_size,
        },
    )

    return response
