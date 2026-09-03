from fastapi import APIRouter

from app.api import dashboard, health, proxy

api_router = APIRouter()

# Register health check endpoints
api_router.include_router(health.router)

# Register dashboard endpoints
api_router.include_router(dashboard.router)

# Register proxy endpoints
api_router.include_router(proxy.router)
