from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="ok", description="Service health status")
    app: str = Field(default="Web API Security Platform Gateway", description="Application name")
    environment: str = Field(default="development", description="Current operating environment")
    version: str = Field(default="0.1.0", description="Application version")
