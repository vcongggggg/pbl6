"""Stateful OWASP API1:2023 Broken Object Level Authorization (BOLA / IDOR) Detector.

Tracks distinct object identifiers accessed per client/session across REST resource
templates (e.g., /orders/{id}, /users/{id}, /invoices/{id}) using a bounded thread-safe
LRU sliding window. Detects horizontal/sequential ID enumeration bursts and sentinel probes
without locking to any specific backend application schema.
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity

_INT_SEGMENT_RE = re.compile(r"^-?\d+$")
_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SKIP_COLLECTION_NAMES = {"api", "v1", "v2", "v3", "proxy", "public", "static", "page"}


@dataclass(frozen=True, slots=True)
class BOLADetectionResult:
    """Result of stateful BOLA / IDOR object-ID access analysis."""

    is_bola: bool = False
    resource_template: str | None = None
    object_id: str | None = None
    distinct_ids_in_window: int = 0
    reason: str = ""
    rule_match: RuleMatch | None = None


def extract_resource_object_id(path: str) -> tuple[str, str] | None:
    """Extracts (normalized_resource_template, object_id) from a REST path if present."""
    if not path:
        return None
    segments = [seg for seg in path.strip("/").split("/") if seg]
    if len(segments) < 2:
        return None

    for idx in range(1, len(segments)):
        seg = segments[idx]
        prev = segments[idx - 1].lower()
        if prev in _SKIP_COLLECTION_NAMES:
            continue
        if _INT_SEGMENT_RE.match(seg) or _UUID_SEGMENT_RE.match(seg):
            templated = list(segments)
            templated[idx] = "{id}"
            return "/" + "/".join(templated), seg
    return None


class BOLADetector:
    """Bounded LRU sliding-window BOLA/IDOR enumeration and sentinel detector."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        enumeration_threshold: int = 4,
        max_keys: int = 10000,
    ) -> None:
        self.window_seconds = window_seconds
        self.enumeration_threshold = enumeration_threshold
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._history: OrderedDict[tuple[str, str], deque[tuple[float, str]]] = OrderedDict()

    def reset(self) -> None:
        """Clears in-memory tracking state (used in isolated unit tests)."""
        with self._lock:
            self._history.clear()

    def inspect(
        self,
        client_ip: str,
        path: str,
        method: str = "GET",
        session_id: str | None = None,
    ) -> BOLADetectionResult:
        """Evaluates an incoming REST object access for BOLA/IDOR anomalies."""
        extracted = extract_resource_object_id(path)
        if extracted is None:
            return BOLADetectionResult()

        resource_template, object_id = extracted

        # 1. Immediate sentinel/negative object ID probe detection (e.g. /orders/0, /orders/-1)
        if _INT_SEGMENT_RE.match(object_id):
            try:
                numeric_id = int(object_id)
                if numeric_id <= 0:
                    reason = (
                        f"BOLA/IDOR sentinel object probe ({object_id}) on '{resource_template}'"
                    )
                    return BOLADetectionResult(
                        is_bola=True,
                        resource_template=resource_template,
                        object_id=object_id,
                        distinct_ids_in_window=1,
                        reason=reason,
                        rule_match=RuleMatch(
                            rule_id="BOLA-001",
                            attack_type=AttackType.BOLA_IDOR,
                            severity=Severity.CRITICAL,
                            confidence=0.96,
                            description=reason,
                            location=InspectionLocation.PATH,
                            location_key="object_id",
                            matched_pattern="sentinel_object_id_probe",
                            evidence=f"{method.upper()} {path}",
                            normalized_sample=path[:100],
                        ),
                    )
            except ValueError:
                pass

        # 2. Sliding-window distinct object ID enumeration tracking
        actor = f"{client_ip or 'unknown'}:{session_id or 'anon'}"
        bucket_key = (actor, resource_template)
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            dq = self._history.get(bucket_key)
            if dq is None:
                if len(self._history) >= self.max_keys:
                    self._history.popitem(last=False)
                dq = deque()
                self._history[bucket_key] = dq
            else:
                self._history.move_to_end(bucket_key)

            while dq and dq[0][0] < cutoff:
                dq.popleft()

            dq.append((now, object_id))
            distinct_ids = len({oid for _, oid in dq})

        if distinct_ids >= self.enumeration_threshold:
            reason = (
                f"Horizontal BOLA/IDOR enumeration detected: {distinct_ids} distinct object IDs "
                f"accessed on '{resource_template}' within {int(self.window_seconds)}s"
            )
            return BOLADetectionResult(
                is_bola=True,
                resource_template=resource_template,
                object_id=object_id,
                distinct_ids_in_window=distinct_ids,
                reason=reason,
                rule_match=RuleMatch(
                    rule_id="BOLA-002",
                    attack_type=AttackType.BOLA_IDOR,
                    severity=Severity.CRITICAL,
                    confidence=0.97,
                    description=reason,
                    location=InspectionLocation.PATH,
                    location_key="object_id",
                    matched_pattern="horizontal_id_enumeration",
                    evidence=f"{method.upper()} {path} (distinct_ids={distinct_ids})",
                    normalized_sample=path[:100],
                ),
            )

        return BOLADetectionResult(
            is_bola=False,
            resource_template=resource_template,
            object_id=object_id,
            distinct_ids_in_window=distinct_ids,
        )
