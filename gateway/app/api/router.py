from fastapi import APIRouter

from app.api import dashboard, health, proxy

api_router = APIRouter()

# Register health check endpoints
api_router.include_router(health.router)

# Register dashboard endpoints (supports both /dashboard and /api/dashboard)
api_router.include_router(dashboard.router)
api_router.include_router(dashboard.router, prefix="/api")

# Register proxy endpoints
api_router.include_router(proxy.router)
