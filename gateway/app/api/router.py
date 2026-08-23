from fastapi import APIRouter

from app.api import health

api_router = APIRouter()

# Register health check endpoint
api_router.include_router(health.router)
