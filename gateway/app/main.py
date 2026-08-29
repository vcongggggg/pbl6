from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging import setup_logging
from app.core.request_id import resolve_request_id
from app.db.session import init_db

settings = get_settings()
logger = setup_logging(settings.log_level)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware ensuring every request and response has a validated X-Request-ID."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming_rid = request.headers.get("x-request-id")
        request_id = resolve_request_id(incoming_rid)
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context for startup and shutdown routines."""
    logger.info(f"Starting {settings.app_name} in [{settings.app_env}] environment...")

    # Initialize SQLite database schema
    init_db()
    logger.info("Database schema verified and initialized.")

    # Initialize shared AsyncClient for reverse proxy with connection pooling
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=settings.proxy_timeout_connect,
            read=settings.proxy_timeout_read,
            write=settings.proxy_timeout_write,
            pool=settings.proxy_timeout_pool,
        ),
        follow_redirects=False,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
    )
    logger.info(f"Reverse proxy HTTP client initialized targeting: {settings.target_api_url}")

    yield

    # Cleanly close HTTP client on shutdown
    logger.info(f"Shutting down {settings.app_name}...")
    if hasattr(app.state, "http_client") and app.state.http_client is not None:
        await app.state.http_client.aclose()
        logger.info("Reverse proxy HTTP client closed.")


def create_application() -> FastAPI:
    """Factory creating and configuring the FastAPI Gateway application."""
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Web API Security Platform — Gateway Component (Phase 1 Proxy Infrastructure)",
        lifespan=lifespan,
    )

    # Register standardized error handlers
    register_error_handlers(application)

    # Register Request Context Middleware
    application.add_middleware(RequestContextMiddleware)

    # Configure CORS Middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routers
    application.include_router(api_router)

    # Direct root health endpoint for standard container orchestrators
    @application.get("/", tags=["Health"])
    async def root_ping():
        return {
            "status": "ok",
            "message": "Web API Security Platform Gateway is operational.",
            "proxy_target": settings.target_api_url,
            "docs": "/docs",
        }

    return application


app = create_application()
