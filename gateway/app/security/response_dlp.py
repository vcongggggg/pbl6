"""Outbound Response Data Loss Prevention (DLP) Guard (OWASP API3:2023 Excessive Data Exposure).

Inspects JSON responses from upstream APIs (bounded <= 512 KB) to detect and redact
leaked password hashes, raw credential fields, private keys, and server secrets before
they leave the Reverse Proxy Gateway.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

REDACTED_PLACEHOLDER = "[REDACTED_BY_WAF_DLP]"

_SENSITIVE_RESPONSE_KEYS = {
    "password",
    "password_hash",
    "hashed_password",
    "secret_key",
    "private_key",
    "aws_secret_access_key",
    "client_secret",
    "ssn",
    "credit_card_number",
}

_HASH_OR_SECRET_VALUE_RE = re.compile(
    r"(?:^pbkdf2_sha256\$|^\$2[aby]\$\d{2}\$|^\$argon2(?:i|d|id)\$|^scrypt:|"
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class DLPInspectionResult:
    """Outcome of outbound response DLP inspection and optional field redaction."""

    has_leak: bool = False
    redacted: bool = False
    finding_count: int = 0
    leaked_fields: list[str] = field(default_factory=list)
    redacted_bytes: bytes | None = None


class ResponseDLPGuard:
    """Scans JSON API responses for sensitive credential/secret exposure."""

    MAX_INSPECT_BYTES: int = 524288  # 512 KB cap to protect gateway latency

    def inspect_and_redact(
        self,
        body_bytes: bytes | None,
        content_type: str | None,
        status_code: int,
        active_waf_mode: str = "ACTIVE_BLOCKING",
    ) -> DLPInspectionResult:
        if not body_bytes or not (200 <= status_code < 300):
            return DLPInspectionResult()
        if len(body_bytes) > self.MAX_INSPECT_BYTES:
            return DLPInspectionResult()

        ct_lower = (content_type or "").lower()
        stripped = body_bytes.lstrip()
        if "json" not in ct_lower and not stripped.startswith((b"{", b"[")):
            return DLPInspectionResult()

        try:
            payload = json.loads(body_bytes.decode("utf-8", errors="replace"))
        except Exception:
            return DLPInspectionResult()

        leaked_fields: list[str] = []
        should_redact = (active_waf_mode or "").upper() not in ("OFF", "MONITOR_ONLY", "MONITOR")

        mutated = self._walk_and_scrub(
            node=payload,
            path="response",
            leaked_fields=leaked_fields,
            redact=should_redact,
            depth=0,
        )

        if not leaked_fields:
            return DLPInspectionResult()

        redacted_bytes: bytes | None = None
        if should_redact:
            redacted_bytes = json.dumps(mutated, ensure_ascii=False).encode("utf-8")

        return DLPInspectionResult(
            has_leak=True,
            redacted=should_redact,
            finding_count=len(leaked_fields),
            leaked_fields=leaked_fields[:16],
            redacted_bytes=redacted_bytes,
        )

    def _walk_and_scrub(
        self,
        node: Any,
        path: str,
        leaked_fields: list[str],
        redact: bool,
        depth: int,
    ) -> Any:
        if depth > 24:
            return node

        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for k, v in node.items():
                key_str = str(k)
                key_lower = key_str.lower()
                field_path = f"{path}.{key_str}"
                if key_lower in _SENSITIVE_RESPONSE_KEYS and v not in (None, "", REDACTED_PLACEHOLDER):
                    leaked_fields.append(field_path)
                    out[k] = REDACTED_PLACEHOLDER if redact else v
                else:
                    out[k] = self._walk_and_scrub(v, field_path, leaked_fields, redact, depth + 1)
            return out

        if isinstance(node, list):
            return [
                self._walk_and_scrub(item, f"{path}[{idx}]", leaked_fields, redact, depth + 1)
                for idx, item in enumerate(node)
            ]

        if isinstance(node, str) and node != REDACTED_PLACEHOLDER:
            if _HASH_OR_SECRET_VALUE_RE.search(node):
                leaked_fields.append(path)
                return REDACTED_PLACEHOLDER if redact else node

        return node
