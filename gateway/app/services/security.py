import datetime
import json
import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import SecurityEvent
from app.security.models import DetectionResult

logger = logging.getLogger("waf.gateway.security_service")


class SecurityEventService:
    """Service responsible for persisting detected security incidents into SQLite."""

    @staticmethod
    def record_detection(
        db: Session,
        request_id: str,
        client_ip: str,
        detection_result: DetectionResult,
        timestamp: datetime.datetime | None = None,
    ) -> SecurityEvent | None:
        """Persists security event record if an attack signature was matched."""
        if not detection_result.is_attack or not detection_result.matches:
            return None

        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        event_id = uuid.uuid4().hex

        # Determine dominant attack type & severity
        primary_attack = (
            detection_result.attack_families[0].value
            if detection_result.attack_families
            else "UNKNOWN"
        )
        primary_severity = (
            detection_result.highest_severity.value
            if detection_result.highest_severity
            else "LOW"
        )

        # Build explainable details payload
        details_dict: dict[str, Any] = {
            "total_matches": detection_result.total_matches,
            "attack_families": [f.value for f in detection_result.attack_families],
            "highest_severity": primary_severity,
            "rule_risk_score": detection_result.rule_risk_score,
            "execution_time_ms": detection_result.execution_time_ms,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "attack_type": m.attack_type.value,
                    "severity": m.severity.value,
                    "confidence": m.confidence,
                    "description": m.description,
                    "location": m.location.value,
                    "location_key": m.location_key,
                    "evidence": m.evidence,
                }
                for m in detection_result.matches
            ],
        }

        event_record = SecurityEvent(
            event_id=event_id,
            request_id=request_id,
            timestamp=timestamp,
            client_ip=client_ip,
            attack_type=primary_attack,
            severity=primary_severity,
            action="DETECTED",
            risk_score=detection_result.rule_risk_score,
            rule_score=detection_result.rule_risk_score,
            ml_score=None,
            anomaly_score=None,
            behavior_score=None,
            details=json.dumps(details_dict),
        )

        try:
            db.add(event_record)
            db.commit()
            db.refresh(event_record)
            logger.info(
                f"Security event recorded [{event_id}] for request [{request_id}]: "
                f"type={primary_attack} score={detection_result.rule_risk_score}"
            )
            return event_record
        except Exception as err:
            db.rollback()
            logger.error(
                f"Failed to persist security event for request [{request_id}]: {err}"
            )
            return None
