from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging import setup_logging
from app.db.session import init_db

settings = get_settings()
logger = setup_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context for startup and shutdown routines."""
    logger.info(f"Starting {settings.app_name} in [{settings.app_env}] environment...")
    # Initialize SQLite database schema
    init_db()
    logger.info("Database schema verified and initialized.")
    yield
    logger.info(f"Shutting down {settings.app_name}...")


def create_application() -> FastAPI:
    """Factory creating and configuring the FastAPI Gateway application."""
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Web API Security Platform — Gateway Component (Phase 0 Foundation)",
        lifespan=lifespan,
    )

    # Register standardized error handlers
    register_error_handlers(application)

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
            "docs": "/docs",
        }

    return application


app = create_application()
