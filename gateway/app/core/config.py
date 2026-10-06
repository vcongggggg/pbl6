import logging
from functools import lru_cache
from typing import Any, Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("waf.gateway.config")


class Settings(BaseSettings):
    """Centralized Application Configuration"""

    # Environment
    app_name: str = "Web API Security Platform Gateway"
    app_env: Literal["development", "test", "production"] = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"

    # Security
    admin_api_key: str = "dev-admin-secret-key-change-me"
    allowed_hosts: list[str] = ["*"]
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Database
    database_url: str = "sqlite:///./data/waf_security.db"

    # Target Web API (In-house Bookie / Vulnerable API)
    target_api_url: str = "http://vulnerable-api:5000"

    # Proxy Timeouts (in seconds)
    proxy_timeout_connect: float = 5.0
    proxy_timeout_read: float = 30.0
    proxy_timeout_write: float = 10.0
    proxy_timeout_pool: float = 5.0

    # Traffic Logging Limits
    max_body_log_bytes: int = 4096

    # WAF Controls (Baseline flags for future phases)
    waf_mode: Literal["OFF", "MONITOR_ONLY", "ACTIVE_BLOCKING", "HYBRID"] = "MONITOR_ONLY"
    ml_enabled: bool = False
    anomaly_enabled: bool = False
    rate_limit_enabled: bool = False

    # ML Fail-Safe & Resilience (Master Plan A3)
    ml_unavailable_risk_penalty: float = 15.0

    # Risk & Rate Limit Thresholds (Baseline parameters)
    rate_limit_per_minute: int = 60
    risk_block_threshold: int = 80
    risk_rate_limit_threshold: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @model_validator(mode="before")
    @classmethod
    def parse_cors_origins(cls, data: Any) -> Any:
        if isinstance(data, dict) and "cors_origins" in data:
            val = data["cors_origins"]
            if isinstance(val, str):
                data["cors_origins"] = [o.strip() for o in val.split(",") if o.strip()]
        return data

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if self.app_env == "production":
            if not self.admin_api_key or self.admin_api_key == "dev-admin-secret-key-change-me":
                raise ValueError(
                    "In production mode, ADMIN_API_KEY must be set to a strong custom secret."
                )
            if "*" in self.cors_origins:
                raise ValueError("In production mode, CORS origins must not include wildcard '*'.")
        else:
            if self.admin_api_key == "dev-admin-secret-key-change-me":
                logger.warning(
                    "SECURITY WARNING: Using default dev-admin-secret-key-change-me API key in %s environment.",
                    self.app_env,
                )
            if "*" in self.cors_origins:
                logger.warning(
                    "CORS WARNING: Wildcard origin '*' is configured in %s environment.",
                    self.app_env,
                )
        return self


@lru_cache
def get_settings() -> Settings:
    """Provide cached settings instance for dependency injection."""
    return Settings()
