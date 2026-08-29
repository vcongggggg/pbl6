from fastapi import APIRouter

from app.api import health, proxy

api_router = APIRouter()

# Register health check endpoints
api_router.include_router(health.router)

# Register proxy endpoints
api_router.include_router(proxy.router)
