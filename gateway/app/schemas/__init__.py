"""Pydantic Schemas for Request/Response serialization"""

from app.schemas.common import ErrorDetail, ErrorResponse, MessageResponse
from app.schemas.health import HealthResponse, TargetHealthResponse

__all__ = [
    "HealthResponse",
    "TargetHealthResponse",
    "ErrorResponse",
    "ErrorDetail",
    "MessageResponse",
]
