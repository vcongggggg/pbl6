import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.request_id import resolve_request_id
from app.db.session import get_db
from app.security.engine import RuleEngine
from app.services.proxy import ProxyService
from app.services.security import SecurityEventService
from app.services.traffic import TrafficService

logger = logging.getLogger("waf.gateway.api.proxy")

router = APIRouter(tags=["Proxy"])

# Global shared rule engine instance for gateway
_rule_engine = RuleEngine()


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


@router.api_route(
    "/api/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    summary="Reverse Proxy Endpoint with Security Inspection",
    description=(
        "Inspects requests using signature-based Rule Engine (Phase 2 Detection Only), "
        "persists security events if matches are found, forwards requests to the upstream "
        "Target Web API (OWASP Juice Shop), and records traffic metadata."
    ),
)
async def proxy_endpoint(
    path: str,
    request: Request,
    db: Session = Depends(get_db),
    proxy_service: ProxyService = Depends(get_proxy_service),
    rule_engine: RuleEngine = Depends(get_rule_engine),
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

    # 2. Inspect request through signature Rule Engine (Detection Only)
    try:
        detection_result = rule_engine.inspect_request(
            path=f"/{path}",
            query_params=query_str,
            headers=dict(request.headers),
            body_bytes=body_bytes,
        )

        # 3. Persist security event if attacks were detected
        if detection_result.is_attack:
            SecurityEventService.record_detection(
                db=db,
                request_id=request_id,
                client_ip=client_ip,
                detection_result=detection_result,
            )
    except Exception as sec_err:
        logger.error(f"Security inspection failed for request [{request_id}]: {sec_err}")

    # 4. Forward request to upstream target (NON-BLOCKING in Phase 2)
    response, latency_ms, response_size = await proxy_service.forward(
        request=request,
        path=path,
        request_id=request_id,
        body_bytes=body_bytes,
    )

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
