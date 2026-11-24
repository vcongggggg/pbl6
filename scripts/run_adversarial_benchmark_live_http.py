"""Live HTTP 3x3 Adversarial Benchmark Runner (Sprint C1).

Evaluates 3 Red Team Strategies against 3 Blue Team Defense Tiers
over REAL HTTP sockets (2-hop TCP Gateway + Upstream):
- Upstream Target: http://127.0.0.1:5055
- Gateway Hybrid v3.0: http://127.0.0.1:8055/api/proxy/...
- Gateway Rules Only: http://127.0.0.1:8056/api/proxy/...
- No WAF: Direct to upstream http://127.0.0.1:5055/...

Evaluates:
- 15 Familiar cases (from attack_surface.json)
- 18 Strange held-out out-of-distribution cases

Outputs:
- docs/reports/adversarial_benchmark_live_http.json
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
for _p in (str(ROOT_DIR), str(ROOT_DIR / "gateway"), str(ROOT_DIR / "attack-lab"), str(ROOT_DIR / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent.evasion import TAMPER_CATALOG, EvasionEngine  # noqa: E402
from agent.pentest_advisor import PentestDQNAdvisor  # noqa: E402
from environment.pentest_env import (  # noqa: E402
    encode_pentest_state_64d,
    get_valid_actions_for_case,
)
from run_adversarial_benchmark import (  # noqa: E402
    build_familiar_suite,
    build_strange_heldout_suite,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_http_adversarial")

OUTPUT_JSON = ROOT_DIR / "docs" / "reports" / "adversarial_benchmark_live_http.json"


def run_live_http_episode(
    *,
    client: httpx.Client,
    base_url: str,
    blue_tier: str,
    red_strategy: str,
    case: dict[str, Any],
    ep_idx: int,
    total_eps: int,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    rng: random.Random,
    max_rounds: int = 4,
) -> dict[str, Any]:
    """Runs a multi-round attack episode over real HTTP sockets."""
    family = str(case["family"]).upper()
    baseline = str(case.get("baseline_payload", ""))
    endpoint_tpl = str(case["endpoint"])
    method = str(case.get("method", "GET")).upper()
    rtype = str(case.get("request_type", "query"))
    param = str(case.get("param_name", ""))
    extra = dict(case.get("extra_fields", {}))

    tried_action_ids: set[str] = set()
    used_techs: list[str] = []
    consec_blocks = 0
    last_status: int | None = None
    last_rule = 0.0
    last_ml: float | None = None
    last_anom: float | None = None
    last_threat = 0.0
    last_dlp = False

    round_latencies: list[float] = []
    round_threats: list[float] = []
    episode_bypassed = False

    uuid_probes = (
        "550e8400-e29b-41d4-a716-446655440001",
        "550e8400-e29b-41d4-a716-446655440002",
        "550e8400-e29b-41d4-a716-446655440003",
        "550e8400-e29b-41d4-a716-446655440004",
    )

    for attempt in range(max_rounds):
        if family == "BOLA_IDOR":
            payload = uuid_probes[attempt] if "uuid" in baseline or "-" in baseline else str(attempt + 1)
        elif attempt == 0 or red_strategy == "Static Replay":
            payload = baseline
        elif red_strategy == "Random Mutator":
            techs = [t for t in TAMPER_CATALOG.get(family, {}).keys() if t not in used_techs]
            if techs:
                chosen_t = rng.choice(techs)
                payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=chosen_t)
                used_techs.append(used_t)
            else:
                payload = baseline
        else:
            # Dueling-DQN v2.0
            valid_specs = get_valid_actions_for_case(
                family=family,
                phase="evasion",
                tried_action_ids=tried_action_ids,
                consecutive_blocks=consec_blocks,
                can_pivot=False,
            )
            prev_t = round_threats[-2] if len(round_threats) >= 2 else last_threat
            state_64 = encode_pentest_state_64d(
                phase="evasion",
                family=family,
                method=method,
                request_type=rtype,
                endpoint_index=ep_idx,
                total_endpoints=total_eps,
                attempt_num=attempt,
                max_attempts=max_rounds,
                last_status=last_status,
                rule_score=last_rule,
                ml_score=last_ml,
                anomaly_score=last_anom,
                threat_score=last_threat,
                prev_threat_score=prev_t,
                dlp_redacted=last_dlp,
                consecutive_blocks=consec_blocks,
                tried_action_ids=tried_action_ids,
                available_actions=valid_specs,
            )
            chosen_spec, _ = dqn_advisor.recommend(state_64, valid_specs)
            tried_action_ids.add(chosen_spec.action_id)

            if chosen_spec.action_id.startswith("mutate_"):
                tech_name = chosen_spec.action_id.replace("mutate_", "")
                payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=tech_name)
                used_techs.append(used_t)
            else:
                payload = baseline

        # Format HTTP request
        path = endpoint_tpl
        params_dict: dict[str, Any] | None = None
        json_obj: dict[str, Any] | None = None

        if family == "NOSQL_INJECTION":
            try:
                parsed_op = json.loads(payload)
            except Exception:
                parsed_op = {"$ne": ""}
            json_obj = dict(extra)
            json_obj[param or "username"] = parsed_op
        elif rtype == "path" or "{" in endpoint_tpl:
            path = re.sub(r"\{[^}]+\}", str(payload or "1"), endpoint_tpl)
            if extra and method in ("POST", "PUT", "PATCH"):
                json_obj = extra
        elif method == "GET":
            params_dict = dict(extra)
            if param:
                params_dict[param] = payload
        else:
            json_obj = dict(extra)
            if param:
                json_obj[param] = payload

        # Clean target URL path
        clean_path = path.lstrip("/")
        if blue_tier == "No WAF":
            url = f"{base_url}/{clean_path}"
        else:
            url = f"{base_url}/api/proxy/{clean_path}"

        headers = {
            "X-Forwarded-For": f"10.77.{ep_idx // 250}.{ep_idx % 250}",
            "User-Agent": "PBL6-LiveRedTeam/3.1",
        }

        # Send Real HTTP Request
        t_start = time.perf_counter()
        try:
            if method == "GET":
                resp = client.get(url, params=params_dict, headers=headers)
            elif method == "POST":
                resp = client.post(url, json=json_obj, headers=headers)
            elif method == "PUT":
                resp = client.put(url, json=json_obj, headers=headers)
            elif method == "DELETE":
                resp = client.delete(url, params=params_dict, headers=headers)
            else:
                resp = client.get(url, params=params_dict, headers=headers)
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            status_code = resp.status_code
            resp_headers = resp.headers
        except Exception:
            t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            status_code = 502
            resp_headers = {}

        round_latencies.append(t_elapsed_ms)

        # Parse WAF feedback from response
        is_blocked = (status_code == 403 or status_code == 429)
        threat = float(resp_headers.get("x-waf-risk-score", 100.0 if is_blocked else 0.0))
        rule_sc = float(resp_headers.get("x-waf-rule-score", 85.0 if is_blocked else 0.0))
        ml_sc = float(resp_headers.get("x-waf-ml-score", 0.9 if is_blocked else 0.1))
        anom_sc = float(resp_headers.get("x-waf-anomaly-score", 0.85 if is_blocked else 0.1))
        dlp_flag = bool(resp_headers.get("x-waf-dlp-redacted", "false").lower() == "true")

        last_status = status_code
        last_threat = threat
        last_rule = rule_sc
        last_ml = ml_sc
        last_anom = anom_sc
        last_dlp = dlp_flag

        round_threats.append(threat)

        if not is_blocked and not dlp_flag and 200 <= status_code < 300:
            episode_bypassed = True
            break
        else:
            consec_blocks += 1
            if red_strategy == "Static Replay":
                break

    return {
        "case_name": case.get("name", case.get("endpoint", "unknown")),
        "bypassed": episode_bypassed,
        "blocked": not episode_bypassed,
        "rounds_executed": len(round_latencies),
        "mean_latency_ms": float(np.mean(round_latencies)),
        "final_threat_score": last_threat,
        "last_status": last_status,
    }


def evaluate_live_suite(
    suite_name: str,
    cases: list[dict[str, Any]],
    client: httpx.Client,
    upstream_url: str,
    gw_hybrid_url: str,
    gw_rules_url: str,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
) -> dict[str, Any]:
    red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
    blue_tiers = ["No WAF", "Rules Only", "Hybrid v3.0"]

    suite_results: dict[str, dict[str, Any]] = {}

    for red in red_strategies:
        suite_results[red] = {}
        for blue in blue_tiers:
            base_url = upstream_url if blue == "No WAF" else (gw_rules_url if blue == "Rules Only" else gw_hybrid_url)
            rng = random.Random(42)

            ep_outcomes = []
            for ep_idx, case in enumerate(cases):
                outcome = run_live_http_episode(
                    client=client,
                    base_url=base_url,
                    blue_tier=blue,
                    red_strategy=red,
                    case=case,
                    ep_idx=ep_idx,
                    total_eps=len(cases),
                    evasion_engine=evasion_engine,
                    dqn_advisor=dqn_advisor,
                    rng=rng,
                    max_rounds=4,
                )
                ep_outcomes.append(outcome)

            total = len(ep_outcomes)
            bypasses = sum(1 for o in ep_outcomes if o["bypassed"])
            blocks = sum(1 for o in ep_outcomes if o["blocked"])
            lats = [o["mean_latency_ms"] for o in ep_outcomes]
            threats = [o["final_threat_score"] for o in ep_outcomes]

            suite_results[red][blue] = {
                "total_cases": total,
                "blocked_count": blocks,
                "bypass_count": bypasses,
                "block_rate_pct": round((blocks / total) * 100.0, 1) if total > 0 else 0.0,
                "evasion_rate_pct": round((bypasses / total) * 100.0, 1) if total > 0 else 0.0,
                "avg_threat_score": round(float(np.mean(threats)), 1),
                "avg_latency_ms": round(float(np.mean(lats)), 3),
                "p95_latency_ms": round(float(np.percentile(lats, 95)), 3),
            }
            logger.info("  [%s][%s vs %s]: Block=%d/%d (%.1f%%), Bypass=%d (%.1f%%), Latency=%.2fms",
                        suite_name, red, blue, blocks, total, suite_results[red][blue]["block_rate_pct"],
                        bypasses, suite_results[red][blue]["evasion_rate_pct"], suite_results[red][blue]["avg_latency_ms"])

    return suite_results


def main() -> None:
    logger.info("=== Starting C1 Live HTTP 3x3 Adversarial Benchmark ===")
    tmp_dir = Path(tempfile.mkdtemp(prefix="pbl6_live_bench_"))

    # 1. Fast Upstream Target Server
    upstream_file = tmp_dir / "target_upstream.py"
    upstream_file.write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "@app.api_route('/{path:path}', methods=['GET','POST','PUT','PATCH','DELETE'])\n"
        "async def handle(path: str, request: Request):\n"
        "    return {\n"
        "        'status': 'ok',\n"
        "        'bookie': True,\n"
        "        'user': 'admin',\n"
        "        'SECRET_KEY': 'django-insecure-pbl6-test-key',\n"
        "        'result': 'clean_execution',\n"
        "        'id': 1,\n"
        "    }\n",
        encoding="utf-8",
    )

    up_log = (tmp_dir / "up.log").open("w", encoding="utf-8")
    gw_hybrid_log = (tmp_dir / "gw_hybrid.log").open("w", encoding="utf-8")
    gw_rules_log = (tmp_dir / "gw_rules.log").open("w", encoding="utf-8")
    db_hybrid = tmp_dir / "hybrid.db"
    db_rules = tmp_dir / "rules.db"

    p_up = p_hybrid = p_rules = None

    try:
        # Start Upstream (port 5055)
        p_up = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "target_upstream:app", "--host", "127.0.0.1", "--port", "5055", "--log-level", "warning"],
            cwd=str(tmp_dir),
            stdout=up_log,
            stderr=subprocess.STDOUT,
        )

        for _ in range(40):
            try:
                with urllib.request.urlopen("http://127.0.0.1:5055/health", timeout=1.0) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.2)

        # Start Gateway Hybrid (port 8055)
        env_h = os.environ.copy()
        env_h.update({
            "PYTHONIOENCODING": "utf-8",
            "TARGET_API_URL": "http://127.0.0.1:5055",
            "WAF_MODE": "ACTIVE_BLOCKING",
            "ABLATION_MODE": "hybrid",
            "RATE_LIMIT_ENABLED": "false",
            "DATABASE_URL": f"sqlite:///{db_hybrid.as_posix()}",
            "LOG_LEVEL": "WARNING",
        })
        p_hybrid = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8055", "--log-level", "warning"],
            cwd=str(ROOT_DIR / "gateway"),
            env=env_h,
            stdout=gw_hybrid_log,
            stderr=subprocess.STDOUT,
        )

        # Start Gateway Rules Only (port 8056)
        env_r = os.environ.copy()
        env_r.update({
            "PYTHONIOENCODING": "utf-8",
            "TARGET_API_URL": "http://127.0.0.1:5055",
            "WAF_MODE": "ACTIVE_BLOCKING",
            "ABLATION_MODE": "rules_only",
            "RATE_LIMIT_ENABLED": "false",
            "DATABASE_URL": f"sqlite:///{db_rules.as_posix()}",
            "LOG_LEVEL": "WARNING",
        })
        p_rules = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8056", "--log-level", "warning"],
            cwd=str(ROOT_DIR / "gateway"),
            env=env_r,
            stdout=gw_rules_log,
            stderr=subprocess.STDOUT,
        )

        # Wait for both gateways to come online
        for port in (8055, 8056):
            online = False
            for _ in range(50):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1.0) as r:
                        if r.status == 200:
                            online = True
                            break
                except Exception:
                    time.sleep(0.25)
            if not online:
                raise RuntimeError(f"Gateway on port {port} failed to start in time.")

        logger.info("All 3 services successfully running over live HTTP sockets!")

        familiar_cases = build_familiar_suite()
        strange_cases = build_strange_heldout_suite()
        logger.info("Loaded Familiar (%d) and Strange (%d) test cases", len(familiar_cases), len(strange_cases))

        evasion_engine = EvasionEngine()
        dqn_advisor = PentestDQNAdvisor()

        with httpx.Client(timeout=10.0) as client:
            # Warm up keep-alive sockets
            for p in (5055, 8055, 8056):
                client.get(f"http://127.0.0.1:{p}/health")

            logger.info("--- Evaluating Familiar Suite over Live HTTP ---")
            familiar_results = evaluate_live_suite(
                "familiar",
                familiar_cases,
                client,
                "http://127.0.0.1:5055",
                "http://127.0.0.1:8055",
                "http://127.0.0.1:8056",
                evasion_engine,
                dqn_advisor,
            )

            logger.info("--- Evaluating Strange Suite over Live HTTP ---")
            strange_results = evaluate_live_suite(
                "strange",
                strange_cases,
                client,
                "http://127.0.0.1:5055",
                "http://127.0.0.1:8055",
                "http://127.0.0.1:8056",
                evasion_engine,
                dqn_advisor,
            )

        report = {
            "metadata": {
                "benchmark_type": "Live HTTP Socket End-to-End Adversarial Benchmark (C1)",
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
                "endpoints": {
                    "upstream_target": "http://127.0.0.1:5055",
                    "gateway_hybrid_v3": "http://127.0.0.1:8055",
                    "gateway_rules_only": "http://127.0.0.1:8056",
                },
                "max_rounds_per_episode": 4,
                "familiar_cases_total": len(familiar_cases),
                "strange_cases_total": len(strange_cases),
            },
            "familiar_results": familiar_results,
            "strange_results": strange_results,
        }

        OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Saved live HTTP benchmark artifact to: %s", OUTPUT_JSON)

    finally:
        for p in (p_up, p_hybrid, p_rules):
            if p:
                try:
                    p.terminate()
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
        for f in (up_log, gw_hybrid_log, gw_rules_log):
            try:
                f.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
