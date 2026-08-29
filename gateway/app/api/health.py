import time

import httpx
from fastapi import APIRouter, Depends, Request

from app.core.config import Settings, get_settings
from app.schemas.health import HealthResponse, TargetHealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    description="Returns the current operating status and environment metadata of the Gateway.",
)
async def get_health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Returns gateway application health status."""
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.app_env,
        version="0.1.0",
    )


@router.get(
    "/health/target",
    response_model=TargetHealthResponse,
    summary="Target API connectivity check",
    description="Probes the configured upstream target API to verify network connectivity.",
)
async def get_target_health(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> TargetHealthResponse:
    """Probes the configured Target Web API (Juice Shop) to verify reachability."""
    target_url = settings.target_api_url.rstrip("/")
    client = getattr(request.app.state, "http_client", None)

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=2.0)
        close_client = True

    start_time = time.perf_counter()
    try:
        resp = await client.get(target_url, timeout=2.0)
        latency = (time.perf_counter() - start_time) * 1000
        return TargetHealthResponse(
            status="ok",
            target_url=target_url,
            reachable=True,
            upstream_status=resp.status_code,
            latency_ms=round(latency, 2),
            error=None,
        )
    except Exception as err:
        latency = (time.perf_counter() - start_time) * 1000
        return TargetHealthResponse(
            status="unreachable",
            target_url=target_url,
            reachable=False,
            upstream_status=None,
            latency_ms=round(latency, 2),
            error=str(err),
        )
    finally:
        if close_client:
            await client.aclose()
