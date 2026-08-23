from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Detailed field-level error information."""

    field: str = Field(description="Target field or parameter causing error")
    msg: str = Field(description="Error explanation")


class ErrorBody(BaseModel):
    """Standardized error payload."""

    code: str = Field(description="Machine-readable error code")
    message: str = Field(description="Human-readable error description")
    details: list[ErrorDetail] | None = Field(default=None, description="Optional field errors")


class ErrorResponse(BaseModel):
    """Standard API error response wrapper."""

    status: str = Field(default="error")
    error: ErrorBody


class MessageResponse(BaseModel):
    """Generic status response."""

    status: str = Field(default="ok")
    message: str
    data: dict[str, Any] | None = Field(default=None)
