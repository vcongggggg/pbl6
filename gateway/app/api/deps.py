"""Security dependencies for Gateway WAF management endpoints."""

from __future__ import annotations

import logging
import secrets

from fastapi import Header, HTTPException, status

from app.core.config import get_settings

logger = logging.getLogger("waf.gateway.deps")


async def require_admin(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Enforces constant-time comparison authentication for administrative operations.

    Args:
        x_api_key: Value provided in the X-API-Key request header.

    Raises:
        HTTPException(401): If key is missing, invalid, or unconfigured.

    Returns:
        The validated API key string.
    """
    settings = get_settings()
    configured_key = settings.admin_api_key

    if not configured_key:
        logger.error("Admin operations blocked: admin_api_key is not configured in settings.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication is not configured",
        )

    if not x_api_key or not secrets.compare_digest(x_api_key, configured_key):
        logger.warning("Unauthorized admin access attempt with invalid or missing API key.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing X-API-Key header",
        )

    return x_api_key
