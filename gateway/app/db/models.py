import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def utc_now() -> datetime.datetime:
    """Returns current UTC timestamp as naive datetime (avoids deprecated utcnow())."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class RequestLog(Base):
    """Stores incoming HTTP request metadata and execution lifecycle."""

    __tablename__ = "requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utc_now, index=True
    )
    client_ip: Mapped[str] = mapped_column(String(45), index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(String(255), index=True)
    headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    query_params: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)


class SecurityEvent(Base):
    """Stores security detection incidents, risk scores, and decisions."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utc_now, index=True
    )
    client_ip: Mapped[str] = mapped_column(String(45), index=True)
    attack_type: Mapped[str] = mapped_column(String(50), index=True)  # e.g., SQLI, XSS, BENIGN
    severity: Mapped[str] = mapped_column(String(20))  # LOW, MEDIUM, HIGH, CRITICAL
    action: Mapped[str] = mapped_column(String(20))  # ALLOW, MONITOR, RATE_LIMIT, BLOCK
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    rule_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    behavior_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    kill_chain_stage: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    api_protocol: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


class AuditLog(Base):
    """Tracks administrative configuration updates and security policy changes."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utc_now, index=True
    )
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    key: Mapped[str] = mapped_column(String(100))
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)


class WafConfigModel(Base):
    """Persists runtime WAF configuration settings."""

    __tablename__ = "waf_config"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now
    )
