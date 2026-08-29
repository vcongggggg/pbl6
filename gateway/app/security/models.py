from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Deterministic severity levels for detection rules."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    """Core attack classification categories."""

    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"


class InspectionLocation(str, Enum):
    """Location within HTTP request where match occurred."""

    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"


@dataclass
class RuleMatch:
    """Represents a single deterministic rule detection match."""

    rule_id: str
    attack_type: AttackType
    severity: Severity
    confidence: float
    description: str
    location: InspectionLocation
    location_key: str | None = None
    matched_pattern: str = ""
    evidence: str = ""
    normalized_sample: str | None = None


@dataclass
class DetectionResult:
    """Aggregated detection outcome for an inspected HTTP request."""

    is_attack: bool = False
    matches: list[RuleMatch] = field(default_factory=list)
    total_matches: int = 0
    attack_families: list[AttackType] = field(default_factory=list)
    highest_severity: Severity | None = None
    rule_risk_score: float = 0.0
    execution_time_ms: float = 0.0
