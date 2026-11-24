"""Full Strange Suite v3.2 Episode-Level Verification Runner (In-Process & Live HTTP).

Executes all 18 held-out Strange Suite cases x 3 passes = 54 episodes per cell
with the 26-rule v3.2 WAF engine (including SQLI-006 unquoted arithmetic tautology)
across both:
1. In-Process 3x3 Evaluation (Static Replay, Random Mutator, Dueling-DQN v2.0
   vs No WAF, Legacy Rules Only [5 static regexes], Hybrid v3.2 [26 rules + XGBoost + IForest + Dual-AI])
2. Live TCP HTTP 3x3 Evaluation (real uvicorn Upstream :5055, Gateway Rules-Only :8056 [26 rules],
   Gateway Hybrid v3.2 :8055)

Writes NEW non-frozen episode-level evidence files:
- docs/reports/strange_suite_v32_full_episodes.json (every episode + every round trace)
- docs/reports/strange_case2_sqli006_verification.json (all 3 passes In-Process & Live-HTTP + dedup/scoring proof)
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
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

os.environ.setdefault("OMP_NUM_THREADS", "1")

ROOT_DIR = Path(__file__).resolve().parent.parent
for _p in (
    str(ROOT_DIR),
    str(ROOT_DIR / "gateway"),
    str(ROOT_DIR / "ml-engine"),
    str(ROOT_DIR / "attack-lab"),
    str(ROOT_DIR / "scripts"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent.evasion import TAMPER_CATALOG, EvasionEngine  # noqa: E402
from agent.pentest_advisor import PentestDQNAdvisor  # noqa: E402
from app.security.bola_detector import BOLADetector  # noqa: E402
from app.security.engine import RuleEngine  # noqa: E402
from app.security.rules import get_all_rules  # noqa: E402
from app.security.scoring import RuleScorer  # noqa: E402
from environment.pentest_env import encode_pentest_state_64d, get_valid_actions_for_case  # noqa: E402
from run_adversarial_benchmark import (  # noqa: E402
    RealMultiRoundWAFEvaluator,
    build_strange_heldout_suite,
)
from run_adversarial_benchmark_live_http import (  # noqa: E402
    _extract_real_waf_telemetry,
    _kill_proc_tree,
    _write_route_accurate_upstream,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("verify_strange_suite_v32")

FULL_EPISODES_JSON = ROOT_DIR / "docs" / "reports" / "strange_suite_v32_full_episodes.json"
CASE2_JSON = ROOT_DIR / "docs" / "reports" / "strange_case2_sqli006_verification.json"


def _run_inprocess_strange_episodes(
    strange_cases: list[dict[str, Any]],
    evaluator: RealMultiRoundWAFEvaluator,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    passes: int = 3,
    max_rounds: int = 4,
) -> dict[str, Any]:
    red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
    blue_tiers = ["No WAF", "Rules Only", "Hybrid v3.0"]
    expanded = [
        (pass_idx + 1, case_idx + 1, dict(c))
        for pass_idx in range(passes)
        for case_idx, c in enumerate(strange_cases)
    ]

    uuid_probes = (
        "550e8400-e29b-41d4-a716-446655440001",
        "550e8400-e29b-41d4-a716-446655440002",
        "550e8400-e29b-41d4-a716-446655440003",
        "550e8400-e29b-41d4-a716-446655440004",
    )

    matrix: dict[str, dict[str, Any]] = {}
    for red in red_strategies:
        matrix[red] = {}
        for blue in blue_tiers:
            rng = random.Random(2026)
            episodes_log: list[dict[str, Any]] = []
            blocked_eps = 0
            bypass_eps = 0
            total_probes = 0
            all_lats: list[float] = []

            for ep_idx, (pass_num, case_id, case) in enumerate(expanded):
                family = str(case["family"]).upper()
                baseline = str(case.get("baseline_payload", ""))
                bola_detector = BOLADetector(window_seconds=60.0, enumeration_threshold=4)

                tried_action_ids: set[str] = set()
                used_techs: list[str] = []
                consec_blocks = 0
                last_status: int | None = None
                last_rule = 0.0
                last_ml: float | None = None
                last_anom: float | None = None
                last_threat = 0.0
                last_dlp = False

                round_threats: list[float] = []
                round_traces: list[dict[str, Any]] = []
                episode_bypassed = False

                for attempt in range(max_rounds):
                    if family == "BOLA_IDOR":
                        payload = uuid_probes[attempt] if "uuid" in baseline or "-" in baseline else str(attempt + 1)
                        action_label = "bola_enum_probe"
                    elif attempt == 0 or red == "Static Replay":
                        payload = baseline
                        action_label = "baseline_probe"
                    elif red == "Random Mutator":
                        techs = [t for t in TAMPER_CATALOG.get(family, {}).keys() if t not in used_techs]
                        if techs:
                            chosen_t = rng.choice(techs)
                            payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=chosen_t)
                            used_techs.append(used_t)
                            action_label = f"random:{used_t}"
                        else:
                            payload = baseline
                            action_label = "baseline_fallback"
                    else:
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
                            method=str(case.get("method", "GET")),
                            request_type=str(case.get("request_type", "query")),
                            endpoint_index=ep_idx,
                            total_endpoints=len(expanded),
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
                        best_spec, _ = dqn_advisor.recommend(state_64, valid_specs, top_k=5)
                        tried_action_ids.add(best_spec.action_id)
                        action_label = best_spec.action_id
                        if best_spec.transformation != "none" and family in TAMPER_CATALOG:
                            payload, used_t = evasion_engine.mutate(
                                payload=baseline,
                                family=family,
                                technique=best_spec.transformation,
                            )
                            used_techs.append(used_t)
                        elif best_spec.action_id == "probe_ssrf_internal":
                            payload = "http://2130706433:8000/api/dashboard/stats"
                        else:
                            payload = baseline

                    outcome = evaluator.evaluate_single_request(
                        blue_tier=blue,
                        case=case,
                        payload=payload,
                        bola_detector=bola_detector,
                        client_ip=f"10.55.{ep_idx}.10",
                    )
                    total_probes += 1
                    all_lats.append(outcome["latency_ms"])
                    round_threats.append(outcome["threat_score"])

                    last_status = outcome["status_code"]
                    last_rule = outcome["rule_score"]
                    last_ml = outcome["ml_score"]
                    last_anom = outcome["anomaly_score"]
                    last_threat = outcome["threat_score"]
                    last_dlp = outcome["dlp_redacted"]

                    round_traces.append(
                        {
                            "round": attempt + 1,
                            "action": action_label,
                            "payload": payload,
                            "status_code": outcome["status_code"],
                            "blocked": outcome["blocked"],
                            "dlp_redacted": outcome["dlp_redacted"],
                            "rule_score": round(float(outcome["rule_score"]), 2),
                            "ml_score": round(float(outcome["ml_score"]), 2) if outcome["ml_score"] is not None else None,
                            "anomaly_score": round(float(outcome["anomaly_score"]), 2) if outcome["anomaly_score"] is not None else None,
                            "threat_score": round(float(outcome["threat_score"]), 2),
                            "latency_ms": round(float(outcome["latency_ms"]), 3),
                        }
                    )

                    if family == "BOLA_IDOR":
                        if outcome["blocked"]:
                            episode_bypassed = False
                            break
                        if attempt == max_rounds - 1:
                            episode_bypassed = True
                    else:
                        if not outcome["blocked"]:
                            episode_bypassed = True
                            break
                        consec_blocks += 1
                        if red == "Static Replay":
                            break

                is_ep_blocked = not episode_bypassed
                if is_ep_blocked:
                    blocked_eps += 1
                else:
                    bypass_eps += 1

                episodes_log.append(
                    {
                        "episode_index": ep_idx + 1,
                        "pass_num": pass_num,
                        "case_id": case_id,
                        "endpoint": case["endpoint"],
                        "method": case.get("method", "GET"),
                        "family": family,
                        "blocked": is_ep_blocked,
                        "bypassed": episode_bypassed,
                        "rounds_executed": len(round_traces),
                        "rounds": round_traces,
                    }
                )

            tot_eps = len(expanded)
            matrix[red][blue] = {
                "summary": {
                    "total_cases": len(strange_cases),
                    "passes_per_case": passes,
                    "total_episodes": tot_eps,
                    "total_probes_dispatched": total_probes,
                    "blocked_count": blocked_eps,
                    "bypass_count": bypass_eps,
                    "block_rate_pct": round((blocked_eps / tot_eps) * 100.0, 2),
                    "evasion_rate_pct": round((bypass_eps / tot_eps) * 100.0, 2),
                    "avg_latency_ms": round(float(np.mean(all_lats)), 3) if all_lats else 0.0,
                    "p95_latency_ms": round(float(np.percentile(all_lats, 95)), 3) if all_lats else 0.0,
                },
                "episodes": episodes_log,
            }
    return matrix


def _run_live_http_strange_episodes(
    strange_cases: list[dict[str, Any]],
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    passes: int = 3,
    max_rounds: int = 4,
) -> dict[str, Any]:
    tmp_dir = Path(tempfile.mkdtemp(prefix="pbl6_strange_v32_"))
    up_log = (tmp_dir / "up.log").open("w", encoding="utf-8")
    gw_hybrid_log = (tmp_dir / "gw_hybrid.log").open("w", encoding="utf-8")
    gw_rules_log = (tmp_dir / "gw_rules.log").open("w", encoding="utf-8")
    db_hybrid = tmp_dir / "hybrid.db"
    db_rules = tmp_dir / "rules.db"

    p_up = p_hybrid = p_rules = None
    upstream_url = "http://127.0.0.1:5055"
    gw_hybrid_url = "http://127.0.0.1:8055"
    gw_rules_url = "http://127.0.0.1:8056"

    uuid_probes = (
        "550e8400-e29b-41d4-a716-446655440001",
        "550e8400-e29b-41d4-a716-446655440002",
        "550e8400-e29b-41d4-a716-446655440003",
        "550e8400-e29b-41d4-a716-446655440004",
    )

    try:
        upstream_file = tmp_dir / "target_upstream.py"
        _write_route_accurate_upstream(upstream_file)
        p_up = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "target_upstream:app", "--host", "127.0.0.1", "--port", "5055", "--log-level", "warning"],
            cwd=str(tmp_dir),
            stdout=up_log,
            stderr=subprocess.STDOUT,
        )
        for _ in range(40):
            try:
                with urllib.request.urlopen(f"{upstream_url}/health", timeout=1.0) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.2)

        py_path = os.pathsep.join([str(ROOT_DIR / "gateway"), str(ROOT_DIR / "ml-engine")])

        env_h = os.environ.copy()
        env_h.update(
            {
                "PYTHONIOENCODING": "utf-8",
                "OMP_NUM_THREADS": "1",
                "PYTHONPATH": py_path,
                "TARGET_API_URL": upstream_url,
                "WAF_MODE": "ACTIVE_BLOCKING",
                "ABLATION_MODE": "hybrid",
                "ML_ENABLED": "true",
                "ANOMALY_ENABLED": "true",
                "RATE_LIMIT_ENABLED": "false",
                "DATABASE_URL": f"sqlite:///{db_hybrid.as_posix()}",
                "LOG_LEVEL": "WARNING",
            }
        )
        p_hybrid = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8055", "--log-level", "warning"],
            cwd=str(ROOT_DIR / "gateway"),
            env=env_h,
            stdout=gw_hybrid_log,
            stderr=subprocess.STDOUT,
        )

        env_r = os.environ.copy()
        env_r.update(
            {
                "PYTHONIOENCODING": "utf-8",
                "OMP_NUM_THREADS": "1",
                "PYTHONPATH": py_path,
                "TARGET_API_URL": upstream_url,
                "WAF_MODE": "ACTIVE_BLOCKING",
                "ABLATION_MODE": "rules_only",
                "ML_ENABLED": "false",
                "ANOMALY_ENABLED": "false",
                "RATE_LIMIT_ENABLED": "false",
                "DATABASE_URL": f"sqlite:///{db_rules.as_posix()}",
                "LOG_LEVEL": "WARNING",
            }
        )
        p_rules = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8056", "--log-level", "warning"],
            cwd=str(ROOT_DIR / "gateway"),
            env=env_r,
            stdout=gw_rules_log,
            stderr=subprocess.STDOUT,
        )

        for port in (8055, 8056):
            online = False
            for _ in range(60):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1.0) as r:
                        if r.status == 200:
                            online = True
                            break
                except Exception:
                    time.sleep(0.25)
            if not online:
                raise RuntimeError(f"Gateway on port {port} failed to start in time.")

        red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
        blue_tiers = ["No WAF", "Rules Only", "Hybrid v3.0"]
        expanded = [
            (pass_idx + 1, case_idx + 1, dict(c))
            for pass_idx in range(passes)
            for case_idx, c in enumerate(strange_cases)
        ]

        live_matrix: dict[str, dict[str, Any]] = {}
        with httpx.Client(timeout=10.0) as client:
            for port in (8055, 8056):
                for _ in range(5):
                    client.get(f"http://127.0.0.1:{port}/health")

            for red in red_strategies:
                live_matrix[red] = {}
                for blue in blue_tiers:
                    base_url = (
                        upstream_url
                        if blue == "No WAF"
                        else (gw_rules_url if blue == "Rules Only" else gw_hybrid_url)
                    )
                    rng = random.Random(42)
                    episodes_log: list[dict[str, Any]] = []
                    blocked_eps = 0
                    bypass_eps = 0
                    total_probes = 0
                    all_lats: list[float] = []

                    for ep_idx, (pass_num, case_id, case) in enumerate(expanded):
                        cell_offset = (red_strategies.index(red) * 3 + blue_tiers.index(blue)) * 1000 + ep_idx
                        distinct_ip = f"10.88.{(cell_offset // 240) % 250}.{(cell_offset % 240) + 2}"
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
                        round_threats: list[float] = []
                        round_traces: list[dict[str, Any]] = []
                        episode_bypassed = False

                        for attempt in range(max_rounds):
                            if family == "BOLA_IDOR":
                                payload = uuid_probes[attempt] if ("uuid" in baseline or "-" in baseline) else str(attempt + 1)
                                action_label = "bola_enum_probe"
                            elif attempt == 0 or red == "Static Replay":
                                payload = baseline
                                action_label = "baseline_probe"
                            elif red == "Random Mutator":
                                techs = [t for t in TAMPER_CATALOG.get(family, {}).keys() if t not in used_techs]
                                if techs:
                                    chosen_t = rng.choice(techs)
                                    payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=chosen_t)
                                    used_techs.append(used_t)
                                    action_label = f"random:{used_t}"
                                else:
                                    payload = baseline
                                    action_label = "baseline_fallback"
                            else:
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
                                    endpoint_index=cell_offset,
                                    total_endpoints=len(expanded),
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
                                action_label = chosen_spec.action_id
                                if chosen_spec.action_id.startswith("mutate_"):
                                    tech_name = chosen_spec.action_id.replace("mutate_", "")
                                    payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=tech_name)
                                    used_techs.append(used_t)
                                else:
                                    payload = baseline

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

                            clean_path = path.lstrip("/")
                            url = f"{base_url}/{clean_path}" if blue == "No WAF" else f"{base_url}/api/proxy/{clean_path}"
                            headers = {"X-Forwarded-For": distinct_ip, "User-Agent": "PBL6-LiveRedTeam/3.2"}

                            t_start = time.perf_counter()
                            resp = client.request(method=method, url=url, params=params_dict, json=json_obj, headers=headers)
                            dt_ms = (time.perf_counter() - t_start) * 1000.0
                            total_probes += 1
                            all_lats.append(dt_ms)

                            is_blocked, dlp_flag, rule_sc, ml_sc, anom_sc, threat = _extract_real_waf_telemetry(resp, blue)
                            last_status = resp.status_code
                            last_rule = rule_sc
                            last_ml = ml_sc
                            last_anom = anom_sc
                            last_threat = threat
                            last_dlp = dlp_flag
                            round_threats.append(threat)

                            round_traces.append(
                                {
                                    "round": attempt + 1,
                                    "action": action_label,
                                    "payload": payload,
                                    "status_code": resp.status_code,
                                    "blocked": bool(is_blocked or dlp_flag),
                                    "dlp_redacted": dlp_flag,
                                    "rule_score": round(float(rule_sc), 2),
                                    "ml_score": round(float(ml_sc), 2) if ml_sc is not None else None,
                                    "anomaly_score": round(float(anom_sc), 2) if anom_sc is not None else None,
                                    "threat_score": round(float(threat), 2),
                                    "latency_ms": round(float(dt_ms), 3),
                                }
                            )

                            if family == "BOLA_IDOR" and not is_blocked and not dlp_flag and attempt < max_rounds - 1:
                                continue
                            if not is_blocked and not dlp_flag and 200 <= resp.status_code < 300:
                                episode_bypassed = True
                                break
                            consec_blocks += 1
                            if red == "Static Replay" and family != "BOLA_IDOR":
                                break

                        is_ep_blocked = not episode_bypassed
                        if is_ep_blocked:
                            blocked_eps += 1
                        else:
                            bypass_eps += 1

                        episodes_log.append(
                            {
                                "episode_index": ep_idx + 1,
                                "pass_num": pass_num,
                                "case_id": case_id,
                                "endpoint": endpoint_tpl,
                                "method": method,
                                "family": family,
                                "blocked": is_ep_blocked,
                                "bypassed": episode_bypassed,
                                "rounds_executed": len(round_traces),
                                "rounds": round_traces,
                            }
                        )

                    tot_eps = len(expanded)
                    live_matrix[red][blue] = {
                        "summary": {
                            "total_cases": len(strange_cases),
                            "passes_per_case": passes,
                            "total_episodes": tot_eps,
                            "total_probes_dispatched": total_probes,
                            "blocked_count": blocked_eps,
                            "bypass_count": bypass_eps,
                            "block_rate_pct": round((blocked_eps / tot_eps) * 100.0, 2),
                            "evasion_rate_pct": round((bypass_eps / tot_eps) * 100.0, 2),
                            "avg_latency_ms": round(float(np.mean(all_lats)), 3) if all_lats else 0.0,
                            "p95_latency_ms": round(float(np.percentile(all_lats, 95)), 3) if all_lats else 0.0,
                        },
                        "episodes": episodes_log,
                    }
        return live_matrix
    finally:
        for p in (p_rules, p_hybrid, p_up):
            _kill_proc_tree(p)
        for fh in (up_log, gw_hybrid_log, gw_rules_log):
            try:
                fh.close()
            except Exception:
                pass
        time.sleep(0.4)
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> None:
    measured_ts = datetime.now(timezone.utc).astimezone().isoformat()
    strange_cases = build_strange_heldout_suite()
    evaluator = RealMultiRoundWAFEvaluator()
    evasion_engine = EvasionEngine()
    dqn_advisor = PentestDQNAdvisor()
    n_rules = len(get_all_rules())

    logger.info("Running In-Process Strange Suite (18 cases x 3 passes = 54 episodes/cell)...")
    inproc_matrix = _run_inprocess_strange_episodes(
        strange_cases=strange_cases,
        evaluator=evaluator,
        evasion_engine=evasion_engine,
        dqn_advisor=dqn_advisor,
        passes=3,
    )

    logger.info("Running Live-HTTP Strange Suite (18 cases x 3 passes = 54 episodes/cell)...")
    live_matrix = _run_live_http_strange_episodes(
        strange_cases=strange_cases,
        evasion_engine=evasion_engine,
        dqn_advisor=dqn_advisor,
        passes=3,
    )

    for mode_lbl, mat in [("IN-PROCESS", inproc_matrix), ("LIVE-HTTP", live_matrix)]:
        logger.info("=== STRANGE SUITE v3.2 (%s, %d Rules) ===", mode_lbl, n_rules)
        for r_k, b_dict in mat.items():
            for b_k, cell in b_dict.items():
                s = cell["summary"]
                logger.info(
                    "  [%s] vs [%s]: Block=%d/%d (%.2f%%), Evasion=%.2f%%, AvgLat=%.3fms",
                    r_k,
                    b_k,
                    s["blocked_count"],
                    s["total_episodes"],
                    s["block_rate_pct"],
                    s["evasion_rate_pct"],
                    s["avg_latency_ms"],
                )

    full_report = {
        "metadata": {
            "task_id": "pbl6-v3-2-fix-003",
            "benchmark": "Strange Suite v3.2 Full Episode Verification (In-Process & Live HTTP)",
            "measured_at": measured_ts,
            "active_rules_count": n_rules,
            "sqli_006_included": True,
            "strange_unique_cases": len(strange_cases),
            "passes_per_case": 3,
            "episodes_per_cell": len(strange_cases) * 3,
            "frozen_baseline_policy": (
                "Does NOT mutate frozen baseline files (adversarial_benchmark_3x3.json / adversarial_benchmark_live_http.json); "
                "records all 54 episode traces per cell independently."
            ),
        },
        "summary_comparison": {
            "in_process": {
                r_k: {b_k: cell["summary"] for b_k, cell in b_dict.items()}
                for r_k, b_dict in inproc_matrix.items()
            },
            "live_http": {
                r_k: {b_k: cell["summary"] for b_k, cell in b_dict.items()}
                for r_k, b_dict in live_matrix.items()
            },
        },
        "in_process_cells": inproc_matrix,
        "live_http_cells": live_matrix,
    }
    FULL_EPISODES_JSON.write_text(json.dumps(full_report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Saved full episode-level strange suite report -> %s", FULL_EPISODES_JSON)

    # Build clean, non-duplicated Case 2 verification artifact with all 3 passes (In-Process & Live-HTTP)
    rule_engine = RuleEngine()
    raw_query_plus = urllib.parse.urlencode({"category_id": "105 OR 17-7=10"})
    raw_query_pct20 = "category_id=105%20OR%2017-7%3D10"
    det_plus = rule_engine.inspect_request(path="/api/v3/catalog/items", query_params=raw_query_plus)
    det_pct20 = rule_engine.inspect_request(path="/api/v3/catalog/items", query_params=raw_query_pct20)

    unique_rule_ids = sorted({m.rule_id for m in det_pct20.matches})
    location_matches_pct20 = [
        {
            "rule_id": m.rule_id,
            "location": str(m.location),
            "location_key": m.location_key,
            "severity": str(m.severity),
            "confidence": m.confidence,
            "base_score_contribution": round(90.0 * m.confidence, 2),
            "description": m.description,
        }
        for m in det_pct20.matches
    ]

    inproc_case2_dqn = [ep for ep in inproc_matrix["Dueling-DQN v2.0"]["Hybrid v3.0"]["episodes"] if ep["case_id"] == 2]
    inproc_case2_static = [ep for ep in inproc_matrix["Static Replay"]["Hybrid v3.0"]["episodes"] if ep["case_id"] == 2]
    live_case2_dqn = [ep for ep in live_matrix["Dueling-DQN v2.0"]["Hybrid v3.0"]["episodes"] if ep["case_id"] == 2]
    live_case2_rules = [ep for ep in live_matrix["Dueling-DQN v2.0"]["Rules Only"]["episodes"] if ep["case_id"] == 2]

    case2_report = {
        "metadata": {
            "task_id": "pbl6-v3-2-fix-003",
            "verification_target": "Strange Suite Case 2 SQLI-006 Multi-Pass & Scoring Verification",
            "measured_at": measured_ts,
            "rules_count": n_rules,
            "full_suite_evidence_ref": "docs/reports/strange_suite_v32_full_episodes.json",
        },
        "case_details": {
            "suite": "strange_heldout",
            "case_id": 2,
            "endpoint": "/api/v3/catalog/items",
            "parameter": "category_id",
            "raw_payload": "105 OR 17-7=10",
            "encoded_query_plus": raw_query_plus,
            "encoded_query_pct20": raw_query_pct20,
            "attack_family": "SQL_INJECTION",
        },
        "rule_inspection_and_scoring_explanation": {
            "unique_matched_rule_ids": unique_rule_ids,
            "sqli_006_activated": "SQLI-006" in unique_rule_ids,
            "score_when_query_uses_plus_urlencode_single_match": RuleScorer.calculate_score(det_plus.matches),
            "score_when_query_uses_pct20_encoding_two_locations": RuleScorer.calculate_score(det_pct20.matches),
            "why_92_2_vs_88_2": (
                "SQLI-006 has Severity.CRITICAL (weight 90.0) and confidence 0.98, giving a single-match base score "
                "of 90.0 * 0.98 = 88.2. In RealMultiRoundWAFEvaluator (fix-001), urllib.parse.urlencode encodes spaces as '+' "
                "('category_id=105+OR+17-7%3D10'): InputNormalizer uses urllib.parse.unquote (keeping '+' in location_key='raw_query'), "
                "while urllib.parse.parse_qs decodes '+' to spaces on location_key='category_id', so SQLI-006 matches ONCE (score = 88.2). "
                "When spaces are percent-encoded as '%20' ('category_id=105%20OR%2017-7%3D10', as in fix-002's standalone probe), "
                "unquote decodes '%20' on location_key='raw_query' AND parse_qs decodes location_key='category_id'; "
                "gateway/app/security/engine.py:49-87 deduplicates by (rule_id, location, location_key), recording 2 distinct location "
                "matches ('raw_query' and 'category_id') and adding RuleScorer's +4.0 multi_match_bonus (scoring.py:36-37): 88.2 + 4.0 = 92.2."
            ),
            "distinct_location_matches_on_pct20": location_matches_pct20,
        },
        "three_pass_episode_results": {
            "in_process_static_replay_vs_hybrid_v32": {
                "blocked_passes": f"{sum(1 for e in inproc_case2_static if e['blocked'])}/{len(inproc_case2_static)}",
                "episodes": inproc_case2_static,
            },
            "in_process_dueling_dqn_vs_hybrid_v32": {
                "blocked_passes": f"{sum(1 for e in inproc_case2_dqn if e['blocked'])}/{len(inproc_case2_dqn)}",
                "episodes": inproc_case2_dqn,
            },
            "live_http_dueling_dqn_vs_rules_only_26rules": {
                "blocked_passes": f"{sum(1 for e in live_case2_rules if e['blocked'])}/{len(live_case2_rules)}",
                "episodes": live_case2_rules,
            },
            "live_http_dueling_dqn_vs_hybrid_v32": {
                "blocked_passes": f"{sum(1 for e in live_case2_dqn if e['blocked'])}/{len(live_case2_dqn)}",
                "episodes": live_case2_dqn,
            },
        },
        "strange_suite_54_episode_totals": {
            "in_process_static_replay_hybrid_v32": inproc_matrix["Static Replay"]["Hybrid v3.0"]["summary"],
            "in_process_random_mutator_hybrid_v32": inproc_matrix["Random Mutator"]["Hybrid v3.0"]["summary"],
            "in_process_dueling_dqn_hybrid_v32": inproc_matrix["Dueling-DQN v2.0"]["Hybrid v3.0"]["summary"],
            "live_http_static_replay_hybrid_v32": live_matrix["Static Replay"]["Hybrid v3.0"]["summary"],
            "live_http_dueling_dqn_rules_only_26rules": live_matrix["Dueling-DQN v2.0"]["Rules Only"]["summary"],
            "live_http_dueling_dqn_hybrid_v32": live_matrix["Dueling-DQN v2.0"]["Hybrid v3.0"]["summary"],
        },
    }
    CASE2_JSON.write_text(json.dumps(case2_report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Saved Case 2 multi-pass verification artifact -> %s", CASE2_JSON)


if __name__ == "__main__":
    main()
