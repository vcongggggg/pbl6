from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="ok", description="Service health status")
    app: str = Field(default="Web API Security Platform Gateway", description="Application name")
    environment: str = Field(default="development", description="Current operating environment")
    version: str = Field(default="0.1.0", description="Application version")


class TargetHealthResponse(BaseModel):
    """Target API connectivity health response schema."""

    status: str = Field(description="Target connectivity status: ok or unreachable")
    target_url: str = Field(description="Configured Target API URL")
    reachable: bool = Field(description="Whether the target is reachable from the gateway")
    upstream_status: int | None = Field(
        default=None, description="Upstream HTTP status code if reachable"
    )
    latency_ms: float | None = Field(
        default=None, description="Probe round-trip latency in milliseconds"
    )
    error: str | None = Field(default=None, description="Error message if target is unreachable")
