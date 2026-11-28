"""Phase E Adversarial Suite Evaluator: Strange Suite v3.3 + Optional Blind Vault v2 (E4).

Evaluates `data/benchmarks/strange_suite_v33.json` (38 cases) across BOTH:
  1. In-Process 3x3 Evaluation (`Static Replay`, `Random Mutator`, `Dueling-DQN v2.0`
     vs `No WAF`, `Rules Only`, `Hybrid v3.3`) using real `EvasionEngine` + `PentestDQNAdvisor`
  2. Live TCP HTTP Evaluation against Gateway `:8056` (Rules Only) & `:8055` (Hybrid v3.3)
Writes `docs/reports/strange_suite_v33_results.json`.

When `--include-blind-vault` is passed:
  - Fail-closed verifies `data/benchmarks/blind_heldout_vault_v2.json` SHA-256 against
    `docs/reports/blind_heldout_vault_v2_lock.json["vault_file_sha256"]`
  - Runs the SAME In-Process + Live HTTP evaluator once on all 30 cases
  - Writes `docs/reports/blind_heldout_vault_v2_results.json`.
"""

from __future__ import annotations

import argparse
import hashlib
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
from app.security.anomaly import get_anomaly_detector  # noqa: E402
from app.security.bola_detector import BOLADetector  # noqa: E402
from app.security.decision import DecisionEngine  # noqa: E402
from app.security.engine import RuleEngine  # noqa: E402
from app.security.ml_detector import MLDetector, extract_26_from_http  # noqa: E402
from app.security.models import AttackType, InspectionLocation, RuleMatch, Severity  # noqa: E402
from app.security.response_dlp import ResponseDLPGuard  # noqa: E402
from app.security.risk_engine import RiskEngine  # noqa: E402
from app.security.scoring import RuleScorer  # noqa: E402
from environment.pentest_env import encode_pentest_state_64d, get_valid_actions_for_case  # noqa: E402
from features.canonicalizer import canonicalize_http_request  # noqa: E402
from run_adversarial_benchmark import _LEGACY_STATIC_REGEXES  # noqa: E402
from run_adversarial_benchmark_live_http import (  # noqa: E402
    _extract_real_waf_telemetry,
    _kill_proc_tree,
    _write_route_accurate_upstream,
)

try:
    from features.canonicalizer import normalize_http_for_ml  # type: ignore[attr-defined]
except ImportError:
    normalize_http_for_ml = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_phase_e_suites")

STRANGE_V33_PATH = ROOT_DIR / "data" / "benchmarks" / "strange_suite_v33.json"
STRANGE_V33_RESULTS = ROOT_DIR / "docs" / "reports" / "strange_suite_v33_results.json"

BLIND_VAULT_PATH = ROOT_DIR / "data" / "benchmarks" / "blind_heldout_vault_v2.json"
BLIND_LOCK_PATH = ROOT_DIR / "docs" / "reports" / "blind_heldout_vault_v2_lock.json"
BLIND_VAULT_RESULTS = ROOT_DIR / "docs" / "reports" / "blind_heldout_vault_v2_results.json"

UUID_PROBES = (
    "550e8400-e29b-41d4-a716-446655440001",
    "550e8400-e29b-41d4-a716-446655440002",
    "550e8400-e29b-41d4-a716-446655440003",
    "550e8400-e29b-41d4-a716-446655440004",
)


def _build_request_parts(
    case: dict[str, Any],
    payload: str,
    technique: str = "",
) -> tuple[str, str | None, str | None, dict[str, str]]:
    """Builds (path, query_str, body_str, headers) cleanly for query/json/form/path cases."""
    family = str(case["family"]).upper()
    endpoint_tpl = str(case["endpoint"])
    method = str(case.get("method", "GET")).upper()
    rtype = str(case.get("request_type", "query")).lower()
    param = str(case.get("param_name", ""))
    extra = dict(case.get("extra_fields", {}))

    path = endpoint_tpl
    query_str: str | None = None
    body_text: str | None = None
    headers: dict[str, str] = {}

    if family == "NOSQL_INJECTION":
        try:
            parsed_op = json.loads(payload)
        except Exception:
            parsed_op = {"$ne": ""}
        body_obj = dict(extra)
        body_obj[param or "username"] = parsed_op
        body_text = json.dumps(body_obj)
        headers["Content-Type"] = "application/json"
    elif rtype == "path" or "{" in endpoint_tpl:
        path = re.sub(r"\{[^}]+\}", str(payload or "1"), endpoint_tpl)
        if extra and method in ("POST", "PUT", "PATCH"):
            body_text = json.dumps(extra)
            headers["Content-Type"] = "application/json"
    elif rtype == "form":
        form_dict = dict(extra)
        if param:
            form_dict[param] = payload
        body_text = urllib.parse.urlencode(form_dict)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif method == "GET":
        if technique == "hpp_query_pollution" and payload.startswith("1&") and "=" in payload:
            raw_tail = payload.split("=", 1)[1]
            p_name = param or "q"
            extra_q = f"&{urllib.parse.urlencode(extra)}" if extra else ""
            query_str = f"{p_name}=1&{p_name}={urllib.parse.quote_plus(raw_tail)}{extra_q}"
        else:
            q_dict = dict(extra)
            if param:
                q_dict[param] = payload
            query_str = urllib.parse.urlencode(q_dict) if q_dict else None
    else:
        if technique == "json_duplicate_key_tamper" and payload.lstrip().startswith("{"):
            p_name = param or "comment"
            raw_dup = payload.replace('"comment":', f'"{p_name}":')
            if extra:
                extra_json = json.dumps(extra)[1:-1].strip()
                if extra_json:
                    raw_dup = f"{raw_dup[:-1]}, {extra_json}}}"
            body_text = raw_dup
        else:
            body_obj = dict(extra)
            if param:
                body_obj[param] = payload
            body_text = json.dumps(body_obj)
        headers["Content-Type"] = "application/json"

    return path, query_str, body_text, headers


class PhaseEInProcessEvaluator:
    """In-process evaluator supporting predict_http & normalize_http_for_ml."""

    def __init__(self) -> None:
        self.rule_engine = RuleEngine()
        self.ml_detector = MLDetector()
        self.anomaly_detector = get_anomaly_detector()
        self.risk_engine = RiskEngine()
        self.decision_engine = DecisionEngine()
        self.dlp_guard = ResponseDLPGuard()
        if not self.ml_detector.ml_available:
            raise RuntimeError("MLDetector (xgb_v2.ubj) is required for Phase E evaluation.")

    def evaluate_single_request(
        self,
        *,
        blue_tier: str,
        case: dict[str, Any],
        payload: str,
        bola_detector: BOLADetector,
        client_ip: str,
        technique: str = "",
    ) -> dict[str, Any]:
        family = str(case["family"]).upper()
        method = str(case.get("method", "GET")).upper()
        path, query_str, body_text, req_hdrs = _build_request_parts(case, payload, technique=technique)
        body_bytes = body_text.encode("utf-8") if body_text else None

        t0 = time.perf_counter()

        if blue_tier == "No WAF":
            return {
                "status_code": 200,
                "blocked": False,
                "dlp_redacted": False,
                "rule_score": 0.0,
                "ml_score": None,
                "anomaly_score": None,
                "threat_score": 0.0,
                "latency_ms": (time.perf_counter() - t0) * 1000.0,
            }

        if blue_tier == "Rules Only":
            raw_surface = f"{path}?{query_str or ''} {body_text or ''}"
            legacy_matches: list[RuleMatch] = []
            for r_id, atk_t, rx in _LEGACY_STATIC_REGEXES:
                m = rx.search(raw_surface)
                if m:
                    legacy_matches.append(
                        RuleMatch(
                            rule_id=r_id,
                            attack_type=atk_t,
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            description="Legacy static regex match",
                            location=InspectionLocation.QUERY,
                            evidence=m.group(0)[:80],
                        )
                    )
            r_score = RuleScorer.calculate_score(legacy_matches)
            rb_leg = self.risk_engine.calculate_weighted_score(
                rule_score=r_score, ml_score=None, anomaly_score=None, ablation_mode="rules_only"
            )
            dec_leg = self.decision_engine.evaluate(rb_leg, waf_mode="ACTIVE_BLOCKING")
            return {
                "status_code": 403 if dec_leg.is_blocked else 200,
                "blocked": dec_leg.is_blocked,
                "dlp_redacted": False,
                "rule_score": r_score,
                "ml_score": None,
                "anomaly_score": None,
                "threat_score": float(dec_leg.risk_score),
                "latency_ms": (time.perf_counter() - t0) * 1000.0,
            }

        det = self.rule_engine.inspect_request(
            path=path,
            query_params=query_str,
            headers=req_hdrs,
            body_bytes=body_bytes,
        )
        bola_res = bola_detector.inspect(client_ip=client_ip, path=path, method=method)
        if bola_res.is_bola and bola_res.rule_match is not None:
            det.matches.append(bola_res.rule_match)
            det.is_attack = True
            det.total_matches = len(det.matches)
            det.rule_risk_score = RuleScorer.calculate_score(det.matches)

        if callable(getattr(self.ml_detector, "predict_http", None)):
            ml_out = self.ml_detector.predict_http(path=path, query_params=query_str, body=body_text)
            if isinstance(ml_out, tuple) and len(ml_out) == 2:
                ml_res, vec26 = ml_out
            else:
                ml_res = ml_out
                vec26 = ml_res.feature_vector or extract_26_from_http(
                    path=path, query_params=query_str, body=body_text
                ).tolist()
            if normalize_http_for_ml is not None:
                np_, nq_, nb_ = normalize_http_for_ml(path=path, query_params=query_str, body=body_text)
                p_txt = canonicalize_http_request(path=np_, query_params=nq_, body=nb_)
            else:
                p_txt = canonicalize_http_request(path=path, query_params=query_str, body=body_text)
        else:
            if normalize_http_for_ml is not None:
                np_, nq_, nb_ = normalize_http_for_ml(path=path, query_params=query_str, body=body_text)
            else:
                np_, nq_, nb_ = path, query_str, body_text
            vec26 = extract_26_from_http(path=np_, query_params=nq_, body=nb_).tolist()
            p_txt = canonicalize_http_request(path=np_, query_params=nq_, body=nb_)
            ml_res = self.ml_detector.predict(p_txt, feature_vector=vec26)

        anom_res = self.anomaly_detector.predict(p_txt, feature_vector=vec26)

        rb = self.risk_engine.calculate_weighted_score(
            rule_score=det.rule_risk_score,
            ml_score=ml_res.risk_score,
            anomaly_score=anom_res.anomaly_score,
            ablation_mode="hybrid",
        )
        dec = self.decision_engine.evaluate(risk_breakdown=rb, waf_mode="ACTIVE_BLOCKING")

        dlp_redacted = False
        dlp_score = 0.0
        if not dec.is_blocked and family == "EXCESSIVE_DATA_EXPOSURE":
            upstream_leak = json.dumps(
                {"users": [{"id": 1, "password_hash": "$2b$12$abcdefghijklmnopqrstuv123456"}]}
            ).encode("utf-8")
            dlp_out = self.dlp_guard.inspect_and_redact(
                upstream_leak, "application/json", 200, "ACTIVE_BLOCKING"
            )
            if dlp_out.redacted:
                dlp_redacted = True
                dlp_match = RuleMatch(
                    rule_id="DLP-001",
                    attack_type=AttackType.EXCESSIVE_DATA_EXPOSURE,
                    severity=Severity.CRITICAL,
                    confidence=0.96,
                    description="Outbound Response DLP redacted sensitive hash",
                    location=InspectionLocation.BODY,
                )
                dlp_score = RuleScorer.calculate_score([dlp_match])

        is_defended = bool(dec.is_blocked or dec.is_rate_limited or dlp_redacted)
        effective_threat = max(float(dec.risk_score), dlp_score)
        status_code = 403 if dec.is_blocked else (429 if dec.is_rate_limited else 200)

        return {
            "status_code": status_code,
            "blocked": is_defended,
            "dlp_redacted": dlp_redacted,
            "rule_score": float(det.rule_risk_score),
            "ml_score": float(ml_res.risk_score) if ml_res.risk_score is not None else None,
            "anomaly_score": float(anom_res.anomaly_score) if anom_res.anomaly_score is not None else None,
            "threat_score": round(effective_threat, 2),
            "latency_ms": (time.perf_counter() - t0) * 1000.0,
        }


def _select_payload_for_round(
    *,
    attempt: int,
    max_rounds: int,
    red_strategy: str,
    case: dict[str, Any],
    ep_idx: int,
    total_eps: int,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    rng: random.Random,
    tried_action_ids: set[str],
    used_techs: list[str],
    consec_blocks: int,
    last_status: int | None,
    last_rule: float,
    last_ml: float | None,
    last_anom: float | None,
    last_threat: float,
    last_dlp: bool,
    round_threats: list[float],
) -> tuple[str, str, str]:
    family = str(case["family"]).upper()
    baseline = str(case.get("baseline_payload", ""))

    if family == "BOLA_IDOR":
        return (
            UUID_PROBES[attempt] if ("uuid" in baseline or "-" in baseline) else str(attempt + 1),
            "bola_enum_probe",
            "none",
        )
    if attempt == 0 or red_strategy == "Static Replay":
        return baseline, "baseline_probe", "none"
    if red_strategy == "Random Mutator":
        techs = [t for t in TAMPER_CATALOG.get(family, {}).keys() if t not in used_techs]
        if techs:
            chosen_t = rng.choice(techs)
            payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=chosen_t)
            used_techs.append(used_t)
            return payload, f"random:{used_t}", used_t
        return baseline, "baseline_fallback", "none"

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
    best_spec, _ = dqn_advisor.recommend(state_64, valid_specs, top_k=5)
    tried_action_ids.add(best_spec.action_id)

    if best_spec.transformation != "none" and family in TAMPER_CATALOG:
        payload, used_t = evasion_engine.mutate(
            payload=baseline,
            family=family,
            technique=best_spec.transformation,
        )
        used_techs.append(used_t)
        return payload, best_spec.action_id, used_t
    if best_spec.action_id.startswith("mutate_"):
        tech_name = best_spec.action_id.replace("mutate_", "")
        payload, used_t = evasion_engine.mutate(payload=baseline, family=family, technique=tech_name)
        used_techs.append(used_t)
        return payload, best_spec.action_id, used_t
    if best_spec.action_id == "probe_ssrf_internal":
        return "http://2130706433:8000/api/dashboard/stats", best_spec.action_id, "ssrf_loopback"
    return baseline, best_spec.action_id, "none"


def _run_inprocess_suite(
    cases: list[dict[str, Any]],
    evaluator: PhaseEInProcessEvaluator,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    passes: int = 3,
    max_rounds: int = 4,
) -> dict[str, Any]:
    red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
    blue_tiers = ["No WAF", "Rules Only", "Hybrid v3.3"]
    expanded = [(p + 1, c) for p in range(passes) for c in cases]

    matrix: dict[str, dict[str, Any]] = {}
    for red in red_strategies:
        matrix[red] = {}
        for blue in blue_tiers:
            rng = random.Random(2026)
            blocked_eps = 0
            bypass_eps = 0
            total_probes = 0
            lats: list[float] = []
            threats: list[float] = []
            bypassed_cases: list[dict[str, Any]] = []

            for ep_idx, (pass_num, case) in enumerate(expanded):
                family = str(case["family"]).upper()
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
                episode_bypassed = False
                last_action = "baseline_probe"

                for attempt in range(max_rounds):
                    payload, action_id, used_tech = _select_payload_for_round(
                        attempt=attempt,
                        max_rounds=max_rounds,
                        red_strategy=red,
                        case=case,
                        ep_idx=ep_idx,
                        total_eps=len(expanded),
                        evasion_engine=evasion_engine,
                        dqn_advisor=dqn_advisor,
                        rng=rng,
                        tried_action_ids=tried_action_ids,
                        used_techs=used_techs,
                        consec_blocks=consec_blocks,
                        last_status=last_status,
                        last_rule=last_rule,
                        last_ml=last_ml,
                        last_anom=last_anom,
                        last_threat=last_threat,
                        last_dlp=last_dlp,
                        round_threats=round_threats,
                    )
                    last_action = action_id

                    outcome = evaluator.evaluate_single_request(
                        blue_tier=blue,
                        case=case,
                        payload=payload,
                        bola_detector=bola_detector,
                        client_ip=f"10.77.{ep_idx // 250}.{(ep_idx % 250) + 1}",
                        technique=used_tech,
                    )
                    total_probes += 1
                    lats.append(outcome["latency_ms"])
                    round_threats.append(outcome["threat_score"])

                    last_status = outcome["status_code"]
                    last_rule = outcome["rule_score"]
                    last_ml = outcome["ml_score"]
                    last_anom = outcome["anomaly_score"]
                    last_threat = outcome["threat_score"]
                    last_dlp = outcome["dlp_redacted"]

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

                threats.append(last_threat)
                if episode_bypassed:
                    bypass_eps += 1
                    bypassed_cases.append(
                        {
                            "pass": pass_num,
                            "case_id": case.get("case_id") or case.get("vault_id"),
                            "endpoint": case.get("endpoint"),
                            "family": family,
                            "action": last_action,
                            "threat_score": last_threat,
                        }
                    )
                else:
                    blocked_eps += 1

            total_eps = len(expanded)
            matrix[red][blue] = {
                "total_cases": len(cases),
                "passes_per_case": passes,
                "total_episodes": total_eps,
                "total_probes_dispatched": total_probes,
                "blocked_count": blocked_eps,
                "bypass_count": bypass_eps,
                "block_rate_pct": round((blocked_eps / total_eps) * 100.0, 2) if total_eps else 0.0,
                "evasion_rate_pct": round((bypass_eps / total_eps) * 100.0, 2) if total_eps else 0.0,
                "avg_threat_score": round(float(np.mean(threats)), 1) if threats else 0.0,
                "avg_latency_ms": round(float(np.mean(lats)), 3) if lats else 0.0,
                "p95_latency_ms": round(float(np.percentile(lats, 95)), 3) if lats else 0.0,
                "bypassed_families": sorted({b["family"] for b in bypassed_cases}),
                "bypassed_samples": bypassed_cases[:15],
            }
            logger.info(
                "  [InProcess][%s vs %s]: Block=%d/%d (%.2f%%)",
                red,
                blue,
                blocked_eps,
                total_eps,
                matrix[red][blue]["block_rate_pct"],
            )

    return matrix


def _run_live_http_suite(
    *,
    cases: list[dict[str, Any]],
    passes: int,
    client: httpx.Client,
    gw_hybrid_url: str,
    gw_rules_url: str,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    max_rounds: int = 4,
) -> dict[str, Any]:
    red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
    blue_tiers = ["Rules Only", "Hybrid v3.3"]
    expanded = [(p + 1, c) for p in range(passes) for c in cases]

    matrix: dict[str, dict[str, Any]] = {}
    for red in red_strategies:
        matrix[red] = {}
        for blue in blue_tiers:
            base_url = gw_rules_url if blue == "Rules Only" else gw_hybrid_url
            rng = random.Random(2026)
            blocked_eps = 0
            bypass_eps = 0
            total_probes = 0
            lats: list[float] = []
            threats: list[float] = []
            bypassed_cases: list[dict[str, Any]] = []

            for ep_idx, (pass_num, case) in enumerate(expanded):
                family = str(case["family"]).upper()
                method = str(case.get("method", "GET")).upper()
                rtype = str(case.get("request_type", "query")).lower()
                cell_offset = (red_strategies.index(red) * 2 + blue_tiers.index(blue)) * 1000 + ep_idx
                distinct_ip = f"10.89.{(cell_offset // 240) % 250}.{(cell_offset % 240) + 2}"

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
                episode_bypassed = False
                last_action = "baseline_probe"

                for attempt in range(max_rounds):
                    payload, action_id, used_tech = _select_payload_for_round(
                        attempt=attempt,
                        max_rounds=max_rounds,
                        red_strategy=red,
                        case=case,
                        ep_idx=cell_offset,
                        total_eps=len(expanded),
                        evasion_engine=evasion_engine,
                        dqn_advisor=dqn_advisor,
                        rng=rng,
                        tried_action_ids=tried_action_ids,
                        used_techs=used_techs,
                        consec_blocks=consec_blocks,
                        last_status=last_status,
                        last_rule=last_rule,
                        last_ml=last_ml,
                        last_anom=last_anom,
                        last_threat=last_threat,
                        last_dlp=last_dlp,
                        round_threats=round_threats,
                    )
                    last_action = action_id

                    path, query_str, body_text, extra_hdrs = _build_request_parts(case, payload, technique=used_tech)
                    clean_path = path.lstrip("/")
                    url = f"{base_url}/api/proxy/{clean_path}"
                    if query_str:
                        url = f"{url}?{query_str}"
                    headers = {
                        "X-Forwarded-For": distinct_ip,
                        "User-Agent": "PBL6-PhaseE-LiveEval/3.3",
                        **extra_hdrs,
                    }

                    t_req = time.perf_counter()
                    if rtype == "form":
                        resp = client.request(
                            method=method,
                            url=url,
                            content=body_text.encode("utf-8") if body_text else None,
                            headers=headers,
                        )
                    elif body_text is not None:
                        resp = client.request(
                            method=method,
                            url=url,
                            content=body_text.encode("utf-8"),
                            headers=headers,
                        )
                    else:
                        resp = client.request(method=method, url=url, headers=headers)
                    lats.append((time.perf_counter() - t_req) * 1000.0)
                    total_probes += 1

                    is_blocked, dlp_flag, r_sc, ml_sc, a_sc, threat = _extract_real_waf_telemetry(
                        resp, "Rules Only" if blue == "Rules Only" else "Hybrid v3.0"
                    )
                    last_status = resp.status_code
                    last_rule = r_sc
                    last_ml = ml_sc
                    last_anom = a_sc
                    last_threat = threat
                    last_dlp = dlp_flag
                    round_threats.append(threat)

                    if family == "BOLA_IDOR" and not is_blocked and not dlp_flag and attempt < max_rounds - 1:
                        continue
                    if not is_blocked and not dlp_flag and 200 <= resp.status_code < 300:
                        episode_bypassed = True
                        break
                    consec_blocks += 1
                    if red == "Static Replay" and family != "BOLA_IDOR":
                        break

                threats.append(last_threat)
                if episode_bypassed:
                    bypass_eps += 1
                    bypassed_cases.append(
                        {
                            "pass": pass_num,
                            "case_id": case.get("case_id") or case.get("vault_id"),
                            "endpoint": case.get("endpoint"),
                            "family": family,
                            "action": last_action,
                            "threat_score": last_threat,
                        }
                    )
                else:
                    blocked_eps += 1

            total_eps = len(expanded)
            matrix[red][blue] = {
                "total_cases": len(cases),
                "passes_per_case": passes,
                "total_episodes": total_eps,
                "total_probes_dispatched": total_probes,
                "blocked_count": blocked_eps,
                "bypass_count": bypass_eps,
                "block_rate_pct": round((blocked_eps / total_eps) * 100.0, 2) if total_eps else 0.0,
                "evasion_rate_pct": round((bypass_eps / total_eps) * 100.0, 2) if total_eps else 0.0,
                "avg_threat_score": round(float(np.mean(threats)), 1) if threats else 0.0,
                "avg_latency_ms": round(float(np.mean(lats)), 3) if lats else 0.0,
                "p95_latency_ms": round(float(np.percentile(lats, 95)), 3) if lats else 0.0,
                "bypassed_families": sorted({b["family"] for b in bypassed_cases}),
                "bypassed_samples": bypassed_cases[:15],
            }
            logger.info(
                "  [LiveHTTP][%s vs %s]: Block=%d/%d (%.2f%%)",
                red,
                blue,
                blocked_eps,
                total_eps,
                matrix[red][blue]["block_rate_pct"],
            )

    return matrix


def _verify_blind_vault_lock() -> dict[str, Any]:
    if not BLIND_VAULT_PATH.is_file() or not BLIND_LOCK_PATH.is_file():
        raise FileNotFoundError("Missing blind_heldout_vault_v2.json or blind_heldout_vault_v2_lock.json")
    lock = json.loads(BLIND_LOCK_PATH.read_text(encoding="utf-8"))
    actual_sha = hashlib.sha256(BLIND_VAULT_PATH.read_bytes()).hexdigest().lower()
    expected_sha = str(lock["vault_file_sha256"]).lower()
    if actual_sha != expected_sha:
        raise RuntimeError(
            f"Blind Vault SHA-256 mismatch! Expected {expected_sha}, got {actual_sha}."
        )
    return {"verified": True, "vault_file_sha256": actual_sha, "case_count": lock.get("case_count")}


def evaluate_suite(
    *,
    suite_name: str,
    suite_path: Path,
    out_path: Path,
    passes: int,
    run_live_http: bool,
    extra_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    suite_json = json.loads(suite_path.read_text(encoding="utf-8"))
    cases = list(suite_json.get("cases", []))

    evaluator = PhaseEInProcessEvaluator()
    evasion_engine = EvasionEngine()
    dqn_advisor = PentestDQNAdvisor()
    if not dqn_advisor.available:
        raise RuntimeError("PentestDQNAdvisor is required for Phase E suite evaluation.")

    logger.info("=== Evaluating %s (%d cases x %d passes) ===", suite_name, len(cases), passes)
    inproc_matrix = _run_inprocess_suite(cases, evaluator, evasion_engine, dqn_advisor, passes=passes)

    live_matrix: dict[str, Any] | None = None
    if run_live_http:
        tmp_dir = Path(tempfile.mkdtemp(prefix="pbl6_phase_e_eval_"))
        up_log = (tmp_dir / "up.log").open("w", encoding="utf-8")
        gw_h_log = (tmp_dir / "gw_hybrid.log").open("w", encoding="utf-8")
        gw_r_log = (tmp_dir / "gw_rules.log").open("w", encoding="utf-8")
        p_up: subprocess.Popen[Any] | None = None
        p_h: subprocess.Popen[Any] | None = None
        p_r: subprocess.Popen[Any] | None = None
        try:
            upstream_url = "http://127.0.0.1:5055"
            up_file = tmp_dir / "target_upstream.py"
            _write_route_accurate_upstream(up_file)
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

            def _spawn_gw(port: int, db_name: str, mode: str, ml_en: str, anom_en: str, log_f: Any) -> subprocess.Popen[Any]:
                env = os.environ.copy()
                env.update(
                    {
                        "PYTHONIOENCODING": "utf-8",
                        "PYTHONPATH": py_path,
                        "TARGET_API_URL": upstream_url,
                        "WAF_MODE": "ACTIVE_BLOCKING",
                        "ABLATION_MODE": mode,
                        "ML_ENABLED": ml_en,
                        "ANOMALY_ENABLED": anom_en,
                        "RATE_LIMIT_ENABLED": "false",
                        "DATABASE_URL": f"sqlite:///{(tmp_dir / db_name).as_posix()}",
                        "LOG_LEVEL": "WARNING",
                    }
                )
                return subprocess.Popen(
                    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
                    cwd=str(ROOT_DIR / "gateway"),
                    env=env,
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                )

            p_h = _spawn_gw(8055, "hybrid.db", "hybrid", "true", "true", gw_h_log)
            p_r = _spawn_gw(8056, "rules.db", "rules_only", "false", "false", gw_r_log)

            for port in (8055, 8056):
                for _ in range(60):
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1.0) as r:
                            if r.status == 200:
                                break
                    except Exception:
                        time.sleep(0.25)

            with httpx.Client(timeout=10.0) as client:
                live_matrix = _run_live_http_suite(
                    cases=cases,
                    passes=passes,
                    client=client,
                    gw_hybrid_url="http://127.0.0.1:8055",
                    gw_rules_url="http://127.0.0.1:8056",
                    evasion_engine=evasion_engine,
                    dqn_advisor=dqn_advisor,
                )
        finally:
            _kill_proc_tree(p_h)
            _kill_proc_tree(p_r)
            _kill_proc_tree(p_up)
            for f in (up_log, gw_h_log, gw_r_log):
                try:
                    f.close()
                except Exception:
                    pass
            shutil.rmtree(tmp_dir, ignore_errors=True)

    payload: dict[str, Any] = {
        "metadata": {
            "suite_name": suite_name,
            "suite_path": str(suite_path.relative_to(ROOT_DIR)),
            "total_cases": len(cases),
            "passes_per_case": passes,
            "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
            "dqn_backend": dqn_advisor.backend,
            "dqn_actions_count": len(dqn_advisor.metadata.get("actions", [])) or 36,
            "ml_model_path": str(evaluator.ml_detector.model_path),
            **(extra_metadata or {}),
        },
        "in_process": inproc_matrix,
        "live_http": live_matrix,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("[OK] Saved suite evaluation results to %s", out_path)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase E Adversarial Suite Evaluator (E4)")
    parser.add_argument("--passes", type=int, default=3, help="Passes per case (default 3)")
    parser.add_argument("--no-live-http", action="store_true", help="Skip live HTTP :8055/:8056 pass")
    parser.add_argument(
        "--include-blind-vault",
        action="store_true",
        help="Verify blind_heldout_vault_v2.json SHA-256 lock and run post-fix evaluation into --vault-out",
    )
    parser.add_argument(
        "--vault-out",
        type=Path,
        default=ROOT_DIR / "docs" / "reports" / "blind_heldout_vault_v2_postfix_results.json",
        help="Output path for Blind Held-Out Vault v2 re-evaluation (never overwrites frozen baseline unless explicitly specified).",
    )
    args = parser.parse_args()

    evaluate_suite(
        suite_name="PBL6 Strange Held-Out Suite v3.3",
        suite_path=STRANGE_V33_PATH,
        out_path=STRANGE_V33_RESULTS,
        passes=args.passes,
        run_live_http=not args.no_live_http,
    )

    if args.include_blind_vault:
        lock_check = _verify_blind_vault_lock()
        evaluate_suite(
            suite_name="PBL6 Blind Held-Out Vault v2.0",
            suite_path=BLIND_VAULT_PATH,
            out_path=args.vault_out,
            passes=1,  # Blind vault evaluation
            run_live_http=not args.no_live_http,
            extra_metadata={"lock_verification": lock_check},
        )


if __name__ == "__main__":
    main()
