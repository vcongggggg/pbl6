import json
import time
from typing import Any
from urllib.parse import parse_qs

from app.security.models import (
    DetectionResult,
    InspectionLocation,
    RuleMatch,
)
from app.security.normalizer import InputNormalizer
from app.security.rules import BaseRule, get_all_rules
from app.security.scoring import RuleScorer

# Headers that are safe and meaningful to inspect for attack patterns
INSPECTABLE_HEADERS = {
    "user-agent",
    "referer",
    "origin",
    "accept",
    "x-forwarded-for",
    "x-real-ip",
    "x-requested-with",
}


class RuleEngine:
    """Core deterministic signature-based detection engine."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        self.rules: list[BaseRule] = rules if rules is not None else get_all_rules()

    def inspect_request(
        self,
        path: str,
        query_params: str | dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        body_bytes: bytes | None = None,
    ) -> DetectionResult:
        """Inspects all relevant HTTP components of a request and aggregates matches."""
        start_time = time.perf_counter()
        matches: list[RuleMatch] = []
        seen_keys: set[tuple[str, InspectionLocation, str | None]] = set()

        def add_match(match: RuleMatch | None):
            if match is not None:
                dedup_key = (match.rule_id, match.location, match.location_key)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    matches.append(match)

        # 1. Inspect URI Path
        if path:
            self._inspect_text(
                text=path,
                location=InspectionLocation.PATH,
                location_key="path",
                on_match=add_match,
            )

        # 2. Inspect Query Parameters
        if query_params:
            if isinstance(query_params, str):
                self._inspect_text(
                    text=query_params,
                    location=InspectionLocation.QUERY,
                    location_key="raw_query",
                    on_match=add_match,
                )
                try:
                    parsed = parse_qs(query_params, keep_blank_values=True)
                    for qk, qvals in parsed.items():
                        self._inspect_text(
                            text=qk,
                            location=InspectionLocation.QUERY,
                            location_key=f"key:{qk}",
                            on_match=add_match,
                        )
                        for qv in qvals:
                            self._inspect_text(
                                text=qv,
                                location=InspectionLocation.QUERY,
                                location_key=qk,
                                on_match=add_match,
                            )
                except Exception:
                    pass
            elif isinstance(query_params, dict):
                for qk, qv in query_params.items():
                    self._inspect_text(
                        text=str(qk),
                        location=InspectionLocation.QUERY,
                        location_key=f"key:{qk}",
                        on_match=add_match,
                    )
                    self._inspect_text(
                        text=str(qv),
                        location=InspectionLocation.QUERY,
                        location_key=str(qk),
                        on_match=add_match,
                    )

        # 3. Inspect Safe Headers
        if headers:
            for hk, hv in headers.items():
                lower_hk = hk.lower()
                if lower_hk in INSPECTABLE_HEADERS or lower_hk.startswith("x-custom"):
                    self._inspect_text(
                        text=str(hv),
                        location=InspectionLocation.HEADER,
                        location_key=hk,
                        on_match=add_match,
                    )

        # 4. Inspect Request Body
        if body_bytes:
            self._inspect_body(body_bytes=body_bytes, on_match=add_match)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        is_attack = len(matches) > 0
        rule_risk_score = RuleScorer.calculate_score(matches)
        highest_severity = RuleScorer.get_highest_severity(matches)
        attack_families = RuleScorer.get_attack_families(matches)

        return DetectionResult(
            is_attack=is_attack,
            matches=matches,
            total_matches=len(matches),
            attack_families=attack_families,
            highest_severity=highest_severity,
            rule_risk_score=rule_risk_score,
            execution_time_ms=round(duration_ms, 3),
        )

    def _inspect_text(
        self,
        text: str,
        location: InspectionLocation,
        location_key: str | None,
        on_match: Any,
    ) -> None:
        """Evaluates rules on both raw bounded text and canonicalized representation."""
        if not text:
            return

        raw_sample, canonical = InputNormalizer.get_canonical_representations(text)

        # Evaluate all rules on canonical representation
        for rule in self.rules:
            match = rule.evaluate(
                input_text=canonical,
                location=location,
                location_key=location_key,
            )
            if match:
                on_match(match)
            elif raw_sample != canonical:
                # Fallback to evaluate on raw representation
                raw_match = rule.evaluate(
                    input_text=raw_sample,
                    location=location,
                    location_key=location_key,
                )
                if raw_match:
                    on_match(raw_match)

    def _inspect_body(self, body_bytes: bytes, on_match: Any) -> None:
        """Parses and inspects request body (JSON, form, or raw text)."""
        if not body_bytes:
            return

        try:
            text = body_bytes[:16384].decode("utf-8")
        except UnicodeDecodeError:
            return

        # Attempt JSON traversal
        try:
            data = json.loads(text)
            self._inspect_json_recursive(data=data, on_match=on_match, prefix="body")
            return
        except Exception:
            pass

        # Fallback to plain text inspection
        self._inspect_text(
            text=text,
            location=InspectionLocation.BODY,
            location_key="raw_body",
            on_match=on_match,
        )

    def _inspect_json_recursive(self, data: Any, on_match: Any, prefix: str) -> None:
        """Recursively inspects keys and values in nested JSON objects."""
        if isinstance(data, dict):
            for k, v in data.items():
                k_str = str(k)
                self._inspect_text(
                    text=k_str,
                    location=InspectionLocation.BODY,
                    location_key=f"{prefix}.key({k_str})",
                    on_match=on_match,
                )
                self._inspect_json_recursive(data=v, on_match=on_match, prefix=f"{prefix}.{k_str}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._inspect_json_recursive(data=item, on_match=on_match, prefix=f"{prefix}[{i}]")
        elif isinstance(data, (str, int, float, bool)) and data is not None:
            self._inspect_text(
                text=str(data),
                location=InspectionLocation.BODY,
                location_key=prefix,
                on_match=on_match,
            )
