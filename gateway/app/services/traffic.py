import datetime
import hashlib
import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import RequestLog

logger = logging.getLogger("waf.gateway.traffic")

# Sensitive header keys to redact in stored metadata
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "admin-api-key",
    "proxy-authorization",
    "x-auth-token",
}

# Sensitive JSON keys to mask in stored metadata
SENSITIVE_JSON_KEYS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "secret",
    "credential",
    "private_key",
}


def sanitize_headers(headers: dict[str, str] | list[tuple[str, str]]) -> str:
    """Filter and redact sensitive request headers, returning a safe JSON string."""
    header_dict = dict(headers) if isinstance(headers, list) else headers
    safe_dict: dict[str, str] = {}

    for key, value in header_dict.items():
        lower_key = key.lower()
        if lower_key in SENSITIVE_HEADERS:
            safe_dict[key] = "[REDACTED]"
        else:
            safe_dict[key] = value

    return json.dumps(safe_dict)


def sanitize_body(body_bytes: bytes, max_bytes: int = 4096) -> tuple[str | None, str | None]:
    """Compute SHA-256 hash and produce a redacted body representation (if text/JSON).

    Returns:
        tuple[body_hash, sanitized_body_string]
    """
    if not body_bytes:
        return None, None

    # Calculate SHA-256
    body_hash = hashlib.sha256(body_bytes).hexdigest()

    # Truncate if too long
    truncated_bytes = body_bytes[:max_bytes]

    try:
        text = truncated_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return body_hash, f"[BINARY DATA - {len(body_bytes)} bytes]"

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            redacted_data = _redact_dict(data)
            return body_hash, json.dumps(redacted_data)
        elif isinstance(data, list):
            redacted_list = [
                _redact_dict(item) if isinstance(item, dict) else item for item in data
            ]
            return body_hash, json.dumps(redacted_list)
    except Exception:
        pass

    return body_hash, text


def _redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively mask sensitive keys in a dictionary."""
    result: dict[str, Any] = {}
    for key, val in data.items():
        if isinstance(key, str) and key.lower() in SENSITIVE_JSON_KEYS:
            result[key] = "******"
        elif isinstance(val, dict):
            result[key] = _redact_dict(val)
        elif isinstance(val, list):
            result[key] = [_redact_dict(item) if isinstance(item, dict) else item for item in val]
        else:
            result[key] = val
    return result


class TrafficService:
    """Service responsible for persisting request & response traffic metadata."""

    @staticmethod
    def record_traffic(
        db: Session,
        request_id: str,
        client_ip: str,
        method: str,
        url: str,
        path: str,
        headers: dict[str, str],
        query_params: str | None,
        body_bytes: bytes,
        response_status: int | None,
        response_time_ms: float | None,
        response_size: int | None,
        user_agent: str | None = None,
        timestamp: datetime.datetime | None = None,
    ) -> RequestLog:
        """Create and persist a traffic record into SQLite."""
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        safe_headers_json = sanitize_headers(headers)
        body_hash, _ = sanitize_body(body_bytes)

        log_entry = RequestLog(
            request_id=request_id,
            timestamp=timestamp,
            client_ip=client_ip,
            user_agent=user_agent,
            method=method,
            url=url,
            path=path,
            headers=safe_headers_json,
            query_params=query_params,
            body_hash=body_hash,
            response_status=response_status,
            response_time_ms=response_time_ms,
            response_size=response_size,
        )

        try:
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)
            return log_entry
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to persist traffic log [{request_id}]: {e}")
            raise
