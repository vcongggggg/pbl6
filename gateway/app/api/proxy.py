import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.request_id import resolve_request_id
from app.db.session import get_db
from app.services.proxy import ProxyService
from app.services.traffic import TrafficService

logger = logging.getLogger("waf.gateway.api.proxy")

router = APIRouter(tags=["Proxy"])


def get_proxy_service(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> ProxyService:
    """Dependency injecting ProxyService with shared AsyncClient from app state."""
    client = getattr(request.app.state, "http_client", None)
    return ProxyService(settings=settings, client=client)


@router.api_route(
    "/api/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    summary="Reverse Proxy Endpoint",
    description=(
        "Forwards requests to the upstream Target Web API (OWASP Juice Shop) "
        "and records traffic metadata."
    ),
)
async def proxy_endpoint(
    path: str,
    request: Request,
    db: Session = Depends(get_db),
    proxy_service: ProxyService = Depends(get_proxy_service),
) -> Response:
    """Handles reverse proxying, request ID injection, latency measurement, and DB persistence."""
    # Obtain unified request ID from request.state or header
    request_id = getattr(request.state, "request_id", None) or resolve_request_id(
        request.headers.get("x-request-id")
    )
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")
    body_bytes = await request.body()

    # Forward request to upstream target
    response, latency_ms, response_size = await proxy_service.forward(
        request=request,
        path=path,
        request_id=request_id,
        body_bytes=body_bytes,
    )

    # Persist traffic metadata in SQLite
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
            query_params=str(request.url.query) if request.url.query else None,
            body_bytes=body_bytes,
            response_status=response.status_code,
            response_time_ms=latency_ms,
            response_size=response_size,
        )
    except Exception as err:
        logger.error(f"Failed to record traffic for request [{request_id}]: {err}")

    return response
