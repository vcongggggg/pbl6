"""Unit tests for Task 10.3: Tool-Augmented Evasion Engine and Tool Registry.

Verifies:
1. Semantic-preserving tamper mutation functions (SQLi, XSS, Path Traversal, Command Injection).
2. HttpDispatcher parsing of WAF Gateway telemetry and connection safety.
3. SqlmapApiWrapper REST client communication.
4. ToolRegistry tool management.
5. EvasionEngine multi-round adaptive evasion workflows.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

# Ensure attack-lab is on sys.path
attack_lab_path = str(Path(__file__).parents[2] / "attack-lab")
if attack_lab_path not in sys.path:
    sys.path.insert(0, attack_lab_path)

from agent.evasion import (  # noqa: E402
    TAMPER_CATALOG,
    EvasionEngine,
    tamper_cmd_dollar_at_split,
    tamper_cmd_quote_concatenation,
    tamper_cmd_subshell,
    tamper_cmd_whitespace_ifs,
    tamper_cmd_wildcard_glob,
    tamper_hpp_query_pollution,
    tamper_json_duplicate_key_tamper,
    tamper_nosql_nin_exists_blind,
    tamper_path_backslash_substitute,
    tamper_path_double_encode,
    tamper_path_nested_traversal,
    tamper_path_null_byte_extension,
    tamper_path_overlong_mixed_slash,
    tamper_sql_between_operator,
    tamper_sql_case_randomize,
    tamper_sql_double_url_encode,
    tamper_sql_space_to_comment,
    tamper_sql_versioned_comment,
    tamper_sqli_char_chr_concat,
    tamper_sqli_scientific_float,
    tamper_xss_case_randomize,
    tamper_xss_double_url_encode,
    tamper_xss_event_handler,
    tamper_xss_html_entity,
    tamper_xss_json_unicode_escape,
    tamper_xss_svg_mathml_onbegin,
)
from agent.tools import (  # noqa: E402
    DispatchResult,
    HttpDispatcher,
    SqlmapApiWrapper,
    ToolRegistry,
)

# =============================================================================
# 1. Tests for Individual Tamper Mutation Functions
# =============================================================================


class TestTamperMutations:
    """Verify tamper transformations preserve attack semantics while mutating syntax."""

    def test_sql_space_to_comment(self) -> None:
        payload = "admin' OR 1=1--"
        mutated = tamper_sql_space_to_comment(payload)
        assert "/**/" in mutated
        assert "admin'/**/OR/**/1=1--" == mutated

    def test_sql_case_randomize(self) -> None:
        payload = "UNION SELECT username FROM users"
        mutated = tamper_sql_case_randomize(payload)
        assert mutated.lower() == payload.lower()
        # Verify at least some letters changed case
        assert "select" not in mutated.split()
        assert "SELECT" not in mutated.split()

    def test_sql_double_url_encode(self) -> None:
        payload = "admin' OR 1=1--"
        mutated = tamper_sql_double_url_encode(payload)
        assert "%2527" in mutated  # '
        assert "%2520" in mutated  # space
        assert "%253d" in mutated  # =
        assert "%252d" in mutated  # -

    def test_sql_between_operator(self) -> None:
        payload = "1=1"
        mutated = tamper_sql_between_operator(payload)
        assert mutated == "1 BETWEEN 1 AND 1"

    def test_sql_versioned_comment(self) -> None:
        payload = "UNION SELECT 1, 2"
        mutated = tamper_sql_versioned_comment(payload)
        assert "/*!50000UNION*/" in mutated
        assert "/*!50000SELECT*/" in mutated

    def test_xss_case_randomize(self) -> None:
        payload = "<script>alert(1)</script>"
        mutated = tamper_xss_case_randomize(payload)
        assert mutated.lower() == payload.lower()
        assert "<script>" not in mutated

    def test_xss_event_handler(self) -> None:
        payload = "<script>alert('XSS')</script>"
        mutated = tamper_xss_event_handler(payload)
        assert "<img src=x onerror=" in mutated
        assert "alert('XSS')" in mutated

    def test_xss_html_entity(self) -> None:
        payload = "<script>"
        mutated = tamper_xss_html_entity(payload)
        assert "&#x3C;" in mutated
        assert "<" not in mutated

    def test_xss_double_url_encode(self) -> None:
        payload = "<script>"
        mutated = tamper_xss_double_url_encode(payload)
        assert "%253c" in mutated
        assert "%253e" in mutated

    def test_path_double_encode(self) -> None:
        payload = "../../etc/passwd"
        mutated = tamper_path_double_encode(payload)
        assert "..%252f..%252fetc/passwd" == mutated

    def test_path_nested_traversal(self) -> None:
        payload = "../../etc/passwd"
        mutated = tamper_path_nested_traversal(payload)
        assert "....//....//etc/passwd" == mutated

    def test_path_backslash_substitute(self) -> None:
        payload = "../etc/passwd"
        mutated = tamper_path_backslash_substitute(payload)
        assert "..\\etc\\passwd" == mutated

    def test_path_null_byte_extension(self) -> None:
        payload = "../../etc/passwd"
        mutated = tamper_path_null_byte_extension(payload)
        assert mutated == "../../etc/passwd%00.jpg"

    def test_cmd_whitespace_ifs(self) -> None:
        payload = "cat /etc/passwd"
        mutated = tamper_cmd_whitespace_ifs(payload)
        assert mutated == "cat${IFS}/etc/passwd"

    def test_cmd_quote_concatenation(self) -> None:
        payload = "cat /etc/passwd"
        mutated = tamper_cmd_quote_concatenation(payload)
        assert "c''at" in mutated
        assert "p''asswd" in mutated

    def test_cmd_subshell(self) -> None:
        payload = "127.0.0.1 | whoami"
        mutated = tamper_cmd_subshell(payload)
        assert "127.0.0.1 | $(whoami)" == mutated

    def test_hpp_query_pollution(self) -> None:
        payload = "admin' OR 1=1--"
        mutated = tamper_hpp_query_pollution(payload)
        assert mutated == f"1&q={payload}"

    def test_sqli_scientific_float(self) -> None:
        payload = "python' UNION SELECT id, username FROM auth_user --"
        mutated = tamper_sqli_scientific_float(payload)
        assert "1e0UNION/*s*/SELECT" in mutated
        assert " " not in mutated

        or_mutated = tamper_sqli_scientific_float("admin' OR '1'='1")
        assert "9e0OR" in or_mutated
        assert " " not in or_mutated

    def test_sqli_char_chr_concat(self) -> None:
        mutated_admin = tamper_sqli_char_chr_concat("SELECT * FROM users WHERE username='admin'")
        assert "CHAR(97,100,109,105,110)" in mutated_admin
        assert "'" not in mutated_admin

        mutated_one = tamper_sqli_char_chr_concat("admin' OR '1'='1")
        assert "CHAR(49)" in mutated_one
        assert "'" not in mutated_one

    def test_xss_json_unicode_escape(self) -> None:
        mutated = tamper_xss_json_unicode_escape("<script>alert('1=1')</script>")
        assert r"\u003c" in mutated
        assert r"\u003e" in mutated
        assert r"\u003d" in mutated
        assert r"\u0027" in mutated
        assert "<" not in mutated

    def test_json_duplicate_key_tamper(self) -> None:
        mutated = tamper_json_duplicate_key_tamper("<script>alert(1)</script>")
        assert mutated.count('"comment"') == 2
        assert '"benign_preview"' in mutated
        parsed = json.loads(mutated)
        assert parsed["comment"] == "<script>alert(1)</script>"

    def test_xss_svg_mathml_onbegin(self) -> None:
        mutated = tamper_xss_svg_mathml_onbegin("<script>alert(1)</script>")
        assert mutated.startswith("<svg><animate/onbegin=")
        assert "alert(1)" in mutated
        assert " " not in mutated

    def test_cmd_dollar_at_split(self) -> None:
        mutated = tamper_cmd_dollar_at_split("cat /etc/passwd")
        assert "c$@at${IFS}/etc/p$@asswd" == mutated
        assert "w$@hoami" in tamper_cmd_dollar_at_split("; whoami")

    def test_cmd_wildcard_glob(self) -> None:
        assert tamper_cmd_wildcard_glob("cat /etc/passwd") == "/bin/c?t /???/p??s??"
        assert tamper_cmd_wildcard_glob("whoami") == "/???/bin/wh??mi"

    def test_path_overlong_mixed_slash(self) -> None:
        mutated = tamper_path_overlong_mixed_slash("../../etc/passwd")
        assert "%c0%af" in mutated
        assert "%5c..%2f" in mutated
        assert "../" not in mutated

    def test_nosql_nin_exists_blind(self) -> None:
        mutated = tamper_nosql_nin_exists_blind('{"$ne": ""}')
        parsed = json.loads(mutated)
        assert parsed == {"$nin": ["__nonexistent__"], "$exists": True}


# =============================================================================
# 2. Tests for HttpDispatcher & Telemetry Parsing
# =============================================================================


class TestHttpDispatcher:
    """Verify HTTP dispatching and telemetry extraction from WAF responses."""

    def test_dispatch_blocked_403(self) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 403
        mock_resp.headers = {
            "x-waf-action": "BLOCKED",
            "x-waf-decision": "BLOCK",
            "x-waf-risk-score": "88.5",
            "x-waf-ml-type": "SQLI",
            "x-request-id": "req-test-123",
        }
        mock_resp.text = json.dumps({
            "status": 403,
            "reason": "SQL Injection Pattern Detected",
            "threat_score": 88.5,
        })
        mock_resp.json.return_value = {
            "status": 403,
            "reason": "SQL Injection Pattern Detected",
            "threat_score": 88.5,
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_resp

        dispatcher = HttpDispatcher(base_url="http://localhost:8000", client=mock_client)
        result = dispatcher.dispatch(
            method="POST",
            path="/api/v1/vulnerable/auth/login/",
            json_data={"username": "admin' OR 1=1--"},
        )

        assert result.status_code == 403
        assert result.is_blocked is True
        assert result.waf_action == "BLOCKED"
        assert result.waf_threat_score == 88.5
        assert result.waf_ml_type == "SQLI"
        assert result.request_id == "req-test-123"
        assert result.blocked_reason == "SQL Injection Pattern Detected"
        assert result.confirmed_bypass is False

    def test_dispatch_bypass_200(self) -> None:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = {
            "x-waf-action": "ALLOW",
            "x-waf-risk-score": "15.0",
            "x-request-id": "req-test-pass",
        }
        mock_resp.text = json.dumps({"access_token": "jwt-token-sample", "user": "admin"})

        mock_client = MagicMock()
        mock_client.request.return_value = mock_resp

        dispatcher = HttpDispatcher(base_url="http://localhost:8000", client=mock_client)
        result = dispatcher.dispatch(
            method="POST",
            path="/api/v1/vulnerable/auth/login/",
            json_data={"username": "admin'/**/OR/**/1=1--"},
            bypass_detection_keywords=["access_token"],
        )

        assert result.status_code == 200
        assert result.is_blocked is False
        assert result.confirmed_bypass is True

    def test_dispatch_connection_error_handling(self) -> None:
        mock_client = MagicMock()
        mock_client.request.side_effect = httpx.ConnectError("Gateway connection refused")

        dispatcher = HttpDispatcher(base_url="http://localhost:8000", client=mock_client)
        result = dispatcher.dispatch(method="GET", path="/api/v1/vulnerable/books/")

        assert result.status_code == 0
        assert result.is_blocked is False
        assert "Gateway connection refused" in (result.error_message or "")


# =============================================================================
# 3. Tests for SqlmapApiWrapper
# =============================================================================


class TestSqlmapApiWrapper:
    """Verify REST client communication with SQLMap API server."""

    def test_create_task_success(self) -> None:
        wrapper = SqlmapApiWrapper(api_url="http://localhost:8775")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True, "taskid": "task_abc123"}
        wrapper._client.get = MagicMock(return_value=mock_resp)

        task_id = wrapper.create_task()
        assert task_id == "task_abc123"

    def test_start_scan_with_tamper(self) -> None:
        wrapper = SqlmapApiWrapper(api_url="http://localhost:8775")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True}
        wrapper._client.post = MagicMock(return_value=mock_resp)

        success = wrapper.start_scan(
            task_id="task_abc123",
            target_url="http://localhost:8000/api/proxy/api/v1/vulnerable/books/search/?q=test",
            tamper="space2comment",
        )
        assert success is True

    def test_connection_error_safe_fallback(self) -> None:
        wrapper = SqlmapApiWrapper(api_url="http://localhost:8775")
        wrapper._client.get = MagicMock(side_effect=httpx.ConnectError("Connection refused"))

        task_id = wrapper.create_task()
        assert task_id is None


# =============================================================================
# 4. Tests for ToolRegistry
# =============================================================================


class TestToolRegistry:
    """Verify registration and discovery of tools."""

    def test_register_and_get(self) -> None:
        registry = ToolRegistry()
        dispatcher = HttpDispatcher()
        registry.register("http_dispatcher", dispatcher)

        assert registry.has("http_dispatcher") is True
        assert registry.get("http_dispatcher") is dispatcher

    def test_unregistered_key_error(self) -> None:
        registry = ToolRegistry()
        with pytest.raises(KeyError):
            registry.get("non_existent_tool")


# =============================================================================
# 5. Tests for EvasionEngine & Multi-round Adaptive Workflows
# =============================================================================


class TestEvasionEngine:
    """Verify multi-round adaptive evasion logic against simulated WAF responses."""

    def test_get_available_techniques(self) -> None:
        engine = EvasionEngine()
        sqli_techs = engine.get_available_techniques("SQL_INJECTION")
        assert "inline_comment" in sqli_techs
        assert "case_randomize" in sqli_techs
        assert "double_url_encode" in sqli_techs
        assert "hpp_query_pollution" in sqli_techs
        assert "sqli_scientific_float" in sqli_techs
        assert "sqli_char_chr_concat" in sqli_techs

        xss_techs = engine.get_available_techniques("XSS")
        assert {"xss_json_unicode_escape", "json_duplicate_key_tamper", "xss_svg_mathml_onbegin"}.issubset(xss_techs)

        cmd_techs = engine.get_available_techniques("COMMAND_INJECTION")
        assert {"cmd_dollar_at_split", "cmd_wildcard_glob"}.issubset(cmd_techs)

        path_techs = engine.get_available_techniques("PATH_TRAVERSAL")
        assert "path_overlong_mixed_slash" in path_techs

        nosql_techs = engine.get_available_techniques("NOSQL_INJECTION")
        assert "nosql_nin_exists_blind" in nosql_techs
        assert "NOSQL_INJECTION" in TAMPER_CATALOG

        unknown_techs = engine.get_available_techniques("UNKNOWN_FAMILY")
        assert unknown_techs == []

    def test_phase_e_extended_mutators_via_evasion_engine(self) -> None:
        engine = EvasionEngine()
        cases = [
            ("SQL_INJECTION", "hpp_query_pollution", "admin' OR 1=1--"),
            ("SQLI", "sqli_scientific_float", "python' UNION SELECT 1,2 --"),
            ("SQL_INJECTION", "sqli_char_chr_concat", "admin' OR '1'='1"),
            ("XSS", "xss_json_unicode_escape", "<script>alert('1')</script>"),
            ("XSS", "json_duplicate_key_tamper", "<script>alert(1)</script>"),
            ("XSS", "xss_svg_mathml_onbegin", "<script>alert(1)</script>"),
            ("COMMAND_INJECTION", "cmd_dollar_at_split", "127.0.0.1; whoami"),
            ("COMMAND_INJECTION", "cmd_wildcard_glob", "cat /etc/passwd"),
            ("PATH_TRAVERSAL", "path_overlong_mixed_slash", "../../etc/passwd"),
            ("NOSQL_INJECTION", "nosql_nin_exists_blind", '{"$ne": ""}'),
        ]
        for fam, tech, payload in cases:
            mutated, used = engine.mutate(payload=payload, family=fam, technique=tech)
            assert used == tech
            assert mutated != payload

    def test_mutate_payload_tracks_used(self) -> None:
        engine = EvasionEngine()
        payload = "UNION SELECT 1, 2"
        mutated1, tech1 = engine.mutate(payload, "SQL_INJECTION", used_techniques=[])
        assert tech1 != "none"
        assert mutated1 != payload

        # Second mutation picks a different technique
        mutated2, tech2 = engine.mutate(payload, "SQL_INJECTION", used_techniques=[tech1])
        assert tech2 != tech1

    def test_adaptive_evasion_bypass_on_round_2(self) -> None:
        """Simulate Round 1 blocked on 403, Round 2 bypassed on 200."""
        mock_dispatcher = MagicMock(spec=HttpDispatcher)

        # First call -> 403 Blocked, Second call -> 200 Bypass
        res_blocked = DispatchResult(
            status_code=403,
            response_body=json.dumps({"detail": "SQLi Detected"}),
            latency_ms=1.5,
            is_blocked=True,
            waf_threat_score=92.0,
        )
        res_bypass = DispatchResult(
            status_code=200,
            response_body=json.dumps({"token": "jwt-token-bypass"}),
            latency_ms=2.1,
            is_blocked=False,
            confirmed_bypass=True,
        )
        mock_dispatcher.dispatch.side_effect = [res_blocked, res_bypass]

        engine = EvasionEngine(dispatcher=mock_dispatcher, max_attempts=4)
        battle_record = engine.adaptive_evasion_round(
            method="POST",
            path="/api/v1/vulnerable/auth/login/",
            param_name="username",
            baseline_payload="admin' OR 1=1--",
            family="SQL_INJECTION",
            request_type="json",
            bypass_keywords=["token"],
        )

        assert battle_record["success"] is True
        assert battle_record["total_rounds"] == 2
        assert battle_record["winning_technique"] is not None
        assert battle_record["rounds"][0]["is_blocked"] is True
        assert battle_record["rounds"][1]["confirmed_bypass"] is True

    def test_adaptive_evasion_max_attempts_exhausted(self) -> None:
        """Simulate WAF blocking all mutation attempts."""
        mock_dispatcher = MagicMock(spec=HttpDispatcher)
        res_blocked = DispatchResult(
            status_code=403,
            response_body="Blocked",
            latency_ms=1.0,
            is_blocked=True,
            waf_threat_score=85.0,
        )
        mock_dispatcher.dispatch.return_value = res_blocked

        engine = EvasionEngine(dispatcher=mock_dispatcher, max_attempts=3)
        battle_record = engine.adaptive_evasion_round(
            method="GET",
            path="/api/v1/vulnerable/files/download/",
            param_name="path",
            baseline_payload="../../etc/passwd",
            family="PATH_TRAVERSAL",
        )

        assert battle_record["success"] is False
        assert battle_record["total_rounds"] == 3
        assert battle_record["winning_technique"] is None

