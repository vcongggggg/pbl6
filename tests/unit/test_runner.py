"""Unit tests for Task 10.4: Offensive AI Red Team CLI Runner.

Verifies:
1. CLI Argument parser (defaults, custom flags, validation, error handling).
2. Campaign execution in dry-run mode (replay, live, and ai_agent modes).
3. Campaign filtering across attack families (sqli, xss, traversal, cmd, all).
4. JSON report generation and schema validation.
5. Error handling and resilience when target WAF is unreachable.
6. Metric bounds and standard 0-100 threat score scale compliance.
7. DQNEvasionAdvisor integration and graceful fallback.
8. CLI entrypoint invocation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure attack-lab and repository root are on sys.path
_REPO_ROOT = Path(__file__).resolve().parents[2]
_ATTACK_LAB_DIR = _REPO_ROOT / "attack-lab"
for p in [str(_REPO_ROOT), str(_ATTACK_LAB_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agent.tools import DispatchResult  # noqa: E402
from runner import (  # noqa: E402
    DEFAULT_TEST_CASES,
    DQNEvasionAdvisor,
    build_arg_parser,
    filter_test_cases,
    main,
    run_campaign,
)

# =============================================================================
# 1. Tests for CLI Argument Parser
# =============================================================================

class TestArgParser:
    """Verify command-line argument parsing and validation."""

    def test_arg_parser_defaults(self) -> None:
        parser = build_arg_parser()
        args = parser.parse_args([])

        assert args.mode == "ai_agent"
        assert args.campaign == "all"
        assert args.target == "http://localhost:8000"
        assert args.max_rounds == 4
        assert args.dry_run is False
        assert "campaign_report.json" in args.output
        assert args.quiet is False

    def test_arg_parser_custom_values(self) -> None:
        parser = build_arg_parser()
        cmd = [
            "--mode", "replay",
            "--campaign", "sqli",
            "--target", "http://waf-test:8000",
            "--max-rounds", "2",
            "--dry-run",
            "--quiet",
            "--output", "custom_dir/report.json",
        ]
        args = parser.parse_args(cmd)

        assert args.mode == "replay"
        assert args.campaign == "sqli"
        assert args.target == "http://waf-test:8000"
        assert args.max_rounds == 2
        assert args.dry_run is True
        assert args.quiet is True
        assert args.output == "custom_dir/report.json"

    def test_arg_parser_invalid_mode(self) -> None:
        parser = build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--mode", "invalid_mode"])

    def test_arg_parser_invalid_campaign(self) -> None:
        parser = build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--campaign", "invalid_campaign"])


# =============================================================================
# 2. Tests for Campaign Filtering
# =============================================================================

class TestCampaignFiltering:
    """Verify test case filtering by attack family."""

    def test_filter_all_campaigns(self) -> None:
        cases = filter_test_cases("all")
        assert len(cases) == len(DEFAULT_TEST_CASES)

    def test_filter_sqli_campaign(self) -> None:
        cases = filter_test_cases("sqli")
        assert len(cases) >= 2
        for case in cases:
            assert case["family"] == "SQL_INJECTION"

    def test_filter_xss_campaign(self) -> None:
        cases = filter_test_cases("xss")
        assert len(cases) >= 1
        for case in cases:
            assert case["family"] == "XSS"

    def test_filter_traversal_campaign(self) -> None:
        cases = filter_test_cases("traversal")
        assert len(cases) >= 1
        for case in cases:
            assert case["family"] == "PATH_TRAVERSAL"

    def test_filter_cmd_campaign(self) -> None:
        cases = filter_test_cases("cmd")
        assert len(cases) >= 1
        for case in cases:
            assert case["family"] == "COMMAND_INJECTION"


# =============================================================================
# 3. Tests for Campaign Execution (Dry-Run Modes)
# =============================================================================

class TestCampaignExecution:
    """Verify campaign runner execution workflows across different modes."""

    def test_run_campaign_dry_run_ai_agent(self, tmp_path: Path) -> None:
        output_file = tmp_path / "test_ai_agent_report.json"
        report = run_campaign(
            mode="ai_agent",
            campaign="all",
            max_rounds=3,
            output=output_file,
            dry_run=True,
            quiet=True,
        )

        assert report["mode"] == "ai_agent"
        assert report["campaign"] == "all"
        assert report["dry_run"] is True
        assert report["max_rounds"] == 3
        assert "timestamp" in report

        summary = report["summary"]
        assert summary["total_requests"] >= summary["total_endpoints"]
        assert summary["blocked_count"] > 0
        assert summary["bypass_count"] > 0
        assert summary["total_endpoints"] == 5
        assert summary["bypass_rate_pct"] == 100.0
        assert 0.0 <= summary["avg_threat_score"] <= 100.0
        assert summary["avg_latency_ms"] > 0

        # Verify results per endpoint
        results = report["results"]
        assert len(results) == 5
        for res in results:
            assert res["success"] is True
            assert res["total_rounds"] >= 2  # Mutated in round 2 or later
            assert res["winning_technique"] is not None
            assert len(res["rounds"]) == res["total_rounds"]
            # Validate standard 0-100 threat score scale
            for r in res["rounds"]:
                if r.get("threat_score") is not None:
                    assert 0.0 <= r["threat_score"] <= 100.0

    def test_run_campaign_dry_run_replay(self, tmp_path: Path) -> None:
        output_file = tmp_path / "test_replay_report.json"
        report = run_campaign(
            mode="replay",
            campaign="sqli",
            max_rounds=4,
            output=output_file,
            dry_run=True,
            quiet=True,
        )

        assert report["mode"] == "replay"
        assert report["campaign"] == "sqli"

        summary = report["summary"]
        results = report["results"]

        # Replay only runs exactly 1 round per endpoint
        assert summary["total_requests"] == len(results)
        assert summary["bypass_count"] == 0
        assert summary["bypass_rate_pct"] == 0.0
        assert summary["blocked_count"] == summary["total_requests"]

        for res in results:
            assert res["total_rounds"] == 1
            assert res["success"] is False
            assert res["winning_technique"] is None
            assert res["rounds"][0]["is_blocked"] is True

    def test_run_campaign_dry_run_live(self, tmp_path: Path) -> None:
        output_file = tmp_path / "test_live_report.json"
        report = run_campaign(
            mode="live",
            campaign="xss",
            output=output_file,
            dry_run=True,
            quiet=True,
        )

        assert report["mode"] == "live"
        assert report["campaign"] == "xss"
        assert len(report["results"]) >= 1


# =============================================================================
# 4. Tests for Report JSON Persistence
# =============================================================================

class TestReportPersistence:
    """Verify JSON file persistence and schema consistency."""

    def test_json_file_created_and_valid(self, tmp_path: Path) -> None:
        output_file = tmp_path / "nested" / "artifacts" / "report.json"
        report = run_campaign(
            mode="ai_agent",
            campaign="cmd",
            output=output_file,
            dry_run=True,
            quiet=True,
        )

        assert output_file.exists()
        with output_file.open("r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["campaign"] == "cmd"
        assert data["mode"] == "ai_agent"
        assert "summary" in data
        assert "results" in data
        assert data["summary"]["total_requests"] == report["summary"]["total_requests"]


# =============================================================================
# 5. Tests for Unreachable Target and Exception Resilience
# =============================================================================

class TestExceptionResilience:
    """Verify runner handles network errors gracefully without crashing."""

    def test_target_unreachable_handling(self, tmp_path: Path) -> None:
        output_file = tmp_path / "error_report.json"

        # Mock HttpDispatcher to simulate unreachable target (status_code 0)
        mock_dispatcher = MagicMock()
        mock_dispatcher.dispatch.return_value = DispatchResult(
            status_code=0,
            response_body="",
            latency_ms=0.0,
            is_blocked=False,
            error_message="Connection refused: http://nonexistent:8000",
        )

        with patch("runner.HttpDispatcher", return_value=mock_dispatcher):
            report = run_campaign(
                mode="ai_agent",
                campaign="sqli",
                target="http://nonexistent:8000",
                output=output_file,
                dry_run=False,
                quiet=True,
            )

        assert report is not None
        summary = report["summary"]
        assert summary["bypass_count"] == 0
        assert summary["bypass_rate_pct"] == 0.0

        for res in report["results"]:
            assert res["success"] is False
            assert len(res["rounds"]) == 1
            assert res["rounds"][0]["status_code"] == 0
            assert "Connection refused" in res["rounds"][0]["error_message"]

    def test_dispatch_exception_handled_cleanly(self, tmp_path: Path) -> None:
        output_file = tmp_path / "exception_report.json"

        mock_dispatcher = MagicMock()
        mock_dispatcher.dispatch.side_effect = RuntimeError("Socket timeout")

        with patch("runner.HttpDispatcher", return_value=mock_dispatcher):
            report = run_campaign(
                mode="ai_agent",
                campaign="cmd",
                target="http://timeout-target:8000",
                output=output_file,
                dry_run=False,
                quiet=True,
            )

        assert report is not None
        assert report["summary"]["bypass_count"] == 0
        for res in report["results"]:
            assert res["success"] is False
            assert "Socket timeout" in str(res["rounds"][0]["error_message"])


# =============================================================================
# 6. Tests for PyTorch DQN Advisor Integration
# =============================================================================

class TestDQNEvasionAdvisor:
    """Verify DQN model loader and action recommendation."""

    def test_advisor_with_existing_checkpoint(self) -> None:
        pytest.importorskip("torch", reason="PyTorch not installed in CI environment")
        model_path = _ATTACK_LAB_DIR / "models" / "evasion_agent.pt"
        if not model_path.exists():
            pytest.skip("Model checkpoint not present in test environment")

        advisor = DQNEvasionAdvisor(model_path=model_path)
        assert advisor.available is True
        assert len(advisor.action_ids) == 14

        # Dummy feature vector of size 40
        dummy_features = [0.1] * 40
        available_actions = ["sqli_probe", "sqli_encoding", "select_next_endpoint"]
        rec = advisor.recommend_action(dummy_features, available_actions)
        assert rec in available_actions

    def test_advisor_missing_checkpoint(self, tmp_path: Path) -> None:
        fake_path = tmp_path / "nonexistent.pt"
        advisor = DQNEvasionAdvisor(model_path=fake_path)
        assert advisor.available is False
        rec = advisor.recommend_action([0.0] * 40, ["sqli_probe"])
        assert rec is None


# =============================================================================
# 7. Tests for CLI Main Entrypoint
# =============================================================================

class TestCLIMain:
    """Verify main entrypoint execution and exit codes."""

    def test_cli_main_success(self, tmp_path: Path) -> None:
        output_file = str(tmp_path / "cli_report.json")
        code = main(["--dry-run", "--campaign", "sqli", "--output", output_file, "--quiet"])
        assert code == 0
        assert Path(output_file).exists()

    def test_cli_main_failure(self) -> None:
        with patch("runner.run_campaign", side_effect=ValueError("Fatal runtime error")):
            code = main(["--dry-run", "--quiet"])
            assert code == 1
