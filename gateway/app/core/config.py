import logging
from functools import lru_cache
from typing import Literal

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
    cors_origins: list[str] = ["*"]

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

    @model_validator(mode="after")
    def validate_admin_security(self) -> "Settings":
        if self.app_env == "production":
            if not self.admin_api_key or self.admin_api_key == "dev-admin-secret-key-change-me":
                raise ValueError(
                    "In production mode, ADMIN_API_KEY must be set to a strong custom secret."
                )
        elif self.admin_api_key == "dev-admin-secret-key-change-me":
            logger.warning(
                "SECURITY WARNING: Using default dev-admin-secret-key-change-me API key in %s environment.",
                self.app_env,
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Provide cached settings instance for dependency injection."""
    return Settings()
