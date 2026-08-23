from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    description="Returns the current operating status and environment metadata.",
)
async def get_health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Returns application health status."""
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.app_env,
        version="0.1.0",
    )
