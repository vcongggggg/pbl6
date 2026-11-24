import asyncio
import datetime
import json
import logging
import re
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

import anyio
from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, sessionmaker
from starlette.responses import StreamingResponse

from app.api.deps import require_admin
from app.api.proxy import (
    _anomaly_detector,
    _decision_engine,
    _ml_detector,
    _response_dlp,
    _risk_engine,
    _rule_engine,
    _schema_validator,
)
from app.db.session import engine as default_db_engine
from app.db.session import get_db
from app.security.bola_detector import BOLADetector
from app.security.ml_detector import extract_26_from_http
from app.security.normalizer import InputNormalizer
from app.services.security import SecurityEventService

# Connect Red Team attack-lab advisor, OpenAPI recon & synthesizer (zero training-serving skew)
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ATTACK_LAB_ROOT = _REPO_ROOT / "attack-lab"
for _p in (str(_REPO_ROOT), str(_ATTACK_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from agent.pentest_advisor import PentestDQNAdvisor
    from agent.recon import APIReconAgent
    from agent.synthesizer import OpenAPIPayloadSynthesizer
    from environment.pentest_env import encode_pentest_state_64d, get_valid_actions_for_case

    _PENTEST_ADVISOR = PentestDQNAdvisor()
except Exception as _adv_err:  # pragma: no cover
    _PENTEST_ADVISOR = None  # type: ignore
    logging.getLogger("waf.gateway.api.arena").warning("PentestDQNAdvisor init warning: %s", _adv_err)

logger = logging.getLogger("waf.gateway.api.arena")

router = APIRouter(
    prefix="/dashboard/arena",
    tags=["AI Arena"],
    dependencies=[Depends(require_admin)],
)

# In-memory history cache (max 50 battles)
_MAX_HISTORY_ENTRIES = 50
_BATTLE_HISTORY: list[dict[str, Any]] = []
_CURRENT_OR_LAST_BATTLE: dict[str, Any] | None = None
_CURRENT_OR_LAST_PENTEST: dict[str, Any] | None = None


# -----------------------------------------------------------------------------
# Semantic-Preserving Tamper Mutations for Adversarial Evaluation
# -----------------------------------------------------------------------------


def tamper_sql_space_to_comment(payload: str) -> str:
    """Replaces whitespace with inline comments /**/."""
    return re.sub(r"\s+", "/**/", payload)


def tamper_sql_case_randomize(payload: str) -> str:
    """Randomizes casing of SQL keywords (e.g. SELECT -> SeLeCt)."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "INSERT", "UPDATE"]
    result = payload
    for kw in keywords:
        pattern = re.compile(rf"\b{kw}\b", re.IGNORECASE)

        def _casing(match: re.Match[str]) -> str:
            text = match.group(0)
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))

        result = pattern.sub(_casing, result)
    return result


def tamper_sql_double_url_encode(payload: str) -> str:
    """Double URL encodes sensitive SQL characters (' -> %2527)."""
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
    return "".join(char_map.get(c, c) for c in payload)


def tamper_sql_between_operator(payload: str) -> str:
    """Replaces equality comparisons like 1=1 with 1 BETWEEN 1 AND 1."""
    return re.sub(r"(\d+)\s*=\s*(\d+)", r"\1 BETWEEN \2 AND \2", payload)


def tamper_sql_versioned_comment(payload: str) -> str:
    """Wraps sensitive SQL keywords in MySQL/SQLite versioned comments /*!50000...*/."""
    keywords = ["UNION", "SELECT", "OR"]
    result = payload
    for kw in keywords:
        pattern = re.compile(rf"\b{kw}\b", re.IGNORECASE)
        result = pattern.sub(f"/*!50000{kw}*/", result)
    return result


def tamper_xss_case_randomize(payload: str) -> str:
    """Randomizes HTML tag casing (<script> -> <ScRiPt>)."""
    pattern = re.compile(r"<(/?)([a-zA-Z0-9]+)", re.IGNORECASE)

    def _tag_casing(match: re.Match[str]) -> str:
        slash = match.group(1)
        tag = match.group(2)
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(tag))
        return f"<{slash}{mixed}"

    return pattern.sub(_tag_casing, payload)


def tamper_xss_event_handler(payload: str) -> str:
    """Transforms <script> tag into an img/svg event handler payload."""
    if "<script" in payload.lower():
        m = re.search(r"<script.*?>(.*?)</script>", payload, re.IGNORECASE | re.DOTALL)
        inner = m.group(1).strip() if m else "alert(1)"
        if not inner:
            inner = "alert(1)"
        return f"<img src=x onerror={inner}>"
    return payload.replace("alert(", "confirm(")


def tamper_xss_html_entity(payload: str) -> str:
    """Encodes special angle brackets into hexadecimal HTML entities."""
    return payload.replace("<", "&#x3C;").replace(">", "&#x3E;")


def tamper_xss_double_url_encode(payload: str) -> str:
    """Double URL encodes XSS punctuation characters (< -> %253c)."""
    char_map = {
        "<": "%253c",
        ">": "%253e",
        '"': "%2522",
        "'": "%2527",
        "(": "%2528",
        ")": "%2529",
    }
    return "".join(char_map.get(c, c) for c in payload)


def tamper_path_double_encode(payload: str) -> str:
    """Double URL encodes directory traversal sequences (../ -> ..%252f)."""
    return payload.replace("../", "..%252f").replace("..\\", "..%255c")


def tamper_path_nested_traversal(payload: str) -> str:
    """Uses nested traversal sequences (../ -> ....//)."""
    return payload.replace("../", "....//").replace("..\\", "....\\\\")


def tamper_path_backslash_substitute(payload: str) -> str:
    """Substitutes forward slashes with Windows backslashes."""
    return payload.replace("/", "\\")


def tamper_path_null_byte_extension(payload: str) -> str:
    """Appends null byte extension (%00.jpg)."""
    if not payload.endswith(".jpg") and not payload.endswith(".png"):
        return f"{payload}%00.jpg"
    return payload


def tamper_cmd_whitespace_ifs(payload: str) -> str:
    """Replaces spaces with ${IFS} shell variable."""
    return payload.replace(" ", "${IFS}")


def tamper_cmd_quote_concatenation(payload: str) -> str:
    """Concatenates commands using single quotes (cat -> c''at)."""
    commands = ["cat", "passwd", "echo", "sh", "bash", "id", "whoami"]
    result = payload
    for cmd in commands:
        pattern = re.compile(rf"\b{cmd}\b")
        if len(cmd) >= 2:
            split_cmd = f"{cmd[0]}''{cmd[1:]}"
            result = pattern.sub(split_cmd, result)
    return result


def tamper_cmd_subshell(payload: str) -> str:
    """Wraps command in subshell syntax $()."""
    if "|" in payload and "$(" not in payload:
        parts = payload.split("|", 1)
        return f"{parts[0].strip()} | $({parts[1].strip()})"
    return payload


# -----------------------------------------------------------------------------
# Attack Campaign Profiles (Synced with Bookie Bookstore OpenAPI Contract)
# -----------------------------------------------------------------------------

ATTACK_CONFIGS: dict[str, dict[str, Any]] = {
    "SQL_INJECTION": {
        "endpoint": "/api/v1/vulnerable/books/search/",
        "method": "GET",
        "param": "q",
        "extra_fields": {},
        "baseline": "' OR 1=1--",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("inline_comment", tamper_sql_space_to_comment),
            ("case_randomize", tamper_sql_case_randomize),
            ("between_operator", tamper_sql_between_operator),
            ("versioned_comment", tamper_sql_versioned_comment),
            ("double_url_encode", tamper_sql_double_url_encode),
        ],
    },
    "XSS": {
        "endpoint": "/api/v1/vulnerable/reviews/",
        "method": "POST",
        "param": "comment",
        "extra_fields": {"book_id": 1, "author": "PBL6-Arena"},
        "baseline": "<script>alert('PBL6_ARENA')</script>",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("case_randomize", tamper_xss_case_randomize),
            ("event_handler", tamper_xss_event_handler),
            ("html_entity_encoding", tamper_xss_html_entity),
            ("double_url_encode", tamper_xss_double_url_encode),
        ],
    },
    "PATH_TRAVERSAL": {
        "endpoint": "/api/v1/vulnerable/files/download/",
        "method": "GET",
        "param": "file",
        "extra_fields": {},
        "baseline": "../../../../etc/passwd",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("nested_traversal", tamper_path_nested_traversal),
            ("double_url_encode", tamper_path_double_encode),
            ("backslash_substitute", tamper_path_backslash_substitute),
            ("null_byte_extension", tamper_path_null_byte_extension),
        ],
    },
    "COMMAND_INJECTION": {
        "endpoint": "/api/v1/vulnerable/admin/ping/",
        "method": "POST",
        "param": "host",
        "extra_fields": {},
        "baseline": "127.0.0.1; cat /etc/passwd",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("whitespace_ifs", tamper_cmd_whitespace_ifs),
            ("quote_concatenation", tamper_cmd_quote_concatenation),
            ("subshell", tamper_cmd_subshell),
        ],
    },
    "SSRF": {
        "endpoint": "/api/v1/vulnerable/books/fetch-cover/",
        "method": "GET",
        "param": "url",
        "extra_fields": {},
        "baseline": "http://127.0.0.1:8000/api/dashboard/stats",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("decimal_ip_encoding", lambda p: p.replace("127.0.0.1", "2130706433")),
            ("hex_ip_encoding", lambda p: p.replace("127.0.0.1", "0x7f000001")),
            ("cloud_metadata_probe", lambda p: "http://169.254.169.254/latest/meta-data/"),
        ],
    },
    "BOLA_IDOR": {
        "endpoint": "/api/v1/vulnerable/orders/1/",
        "method": "GET",
        "param": "order_id",
        "extra_fields": {},
        "baseline": "1",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("sequential_enumeration_2", lambda p: "2"),
            ("sequential_enumeration_3", lambda p: "3"),
            ("admin_order_probe_99", lambda p: "99"),
        ],
    },
    "MASS_ASSIGNMENT": {
        "endpoint": "/api/v1/vulnerable/users/profile/update/",
        "method": "POST",
        "param": "role",
        "extra_fields": {"user_id": 1, "is_staff": True, "is_superuser": True},
        "baseline": "admin",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("moderator_privilege_escalation", lambda p: "moderator"),
            ("superuser_field_binding", lambda p: "superadmin"),
        ],
    },
    "EXCESSIVE_DATA_EXPOSURE": {
        "endpoint": "/api/v1/vulnerable/users/list/",
        "method": "GET",
        "param": "q",
        "extra_fields": {},
        "baseline": "all",
        "techniques": [
            ("baseline_probe", lambda p: p),
            ("sensitive_dump_probe", lambda p: "dump"),
        ],
    },
}


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------


class BattleRequest(BaseModel):
    campaign: str = Field(
        default="all",
        description="Attack campaign: 'all', 'sqli', 'xss', 'path', 'cmd'",
    )
    max_rounds: int = Field(
        default=4,
        ge=1,
        le=20,
        description="Number of rounds in the battle (1-20)",
    )
    target_mode: str = Field(
        default="waf",
        description="Target mode: 'waf' (evaluated by Blue Team v2.0 WAF) or 'direct' (unprotected baseline)",
    )


class RoundDetail(BaseModel):
    round_num: int
    attack_type: str
    endpoint: str
    technique: str
    payload: str
    original_payload: str
    response_status: int  # 403 (Blocked) or 200 (Bypassed)
    waf_threat_score: float  # Scale 0 - 100
    waf_decision: str  # "BLOCK" or "ALLOW"
    latency_ms: float
    winner: str  # "RED_TEAM" or "BLUE_TEAM"


class BattleResponse(BaseModel):
    battle_id: str
    timestamp: str
    campaign: str
    total_rounds: int
    blocked_count: int
    bypass_count: int
    winner: str  # "RED_TEAM" | "BLUE_TEAM" | "DRAW"
    avg_threat_score: float  # Scale 0 - 100
    target_mode: str
    rounds: list[RoundDetail]


def _run_battle_sync(body: BattleRequest) -> dict[str, Any]:
    """Executes CPU-bound Blue Team v2.0 Arena evaluation off the asyncio event loop."""
    raw_campaign = (body.campaign or "all").strip().lower()
    if "sql" in raw_campaign:
        selected_families = ["SQL_INJECTION"]
    elif "xss" in raw_campaign:
        selected_families = ["XSS"]
    elif "path" in raw_campaign or "trav" in raw_campaign:
        selected_families = ["PATH_TRAVERSAL"]
    elif "cmd" in raw_campaign or "command" in raw_campaign:
        selected_families = ["COMMAND_INJECTION"]
    else:
        selected_families = ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION"]

    rounds_data: list[dict[str, Any]] = []
    num_rounds = max(1, min(body.max_rounds, 20))
    is_direct_mode = body.target_mode.strip().lower() == "direct"

    for r in range(1, num_rounds + 1):
        family = selected_families[(r - 1) % len(selected_families)]
        cfg = ATTACK_CONFIGS[family]
        tech_index = (r - 1) // len(selected_families) if len(selected_families) > 1 else (r - 1)
        tech_name, tech_func = cfg["techniques"][min(tech_index, len(cfg["techniques"]) - 1)]

        baseline_payload = cfg["baseline"]
        payload = tech_func(baseline_payload)

        start_time = time.perf_counter()
        if is_direct_mode:
            # Direct unprotected baseline: request bypasses WAF inspection completely
            waf_threat_score = 0.0
            waf_decision = "ALLOW"
            response_status = 200
            round_winner = "RED_TEAM"
            latency_ms = max(0.01, round((time.perf_counter() - start_time) * 1000.0, 3))
        else:
            # Blue Team v2.0 WAF evaluation: zero Training-Serving Skew (unified 26-D extractor)
            query_str: str | None = None
            body_text: str | None = None
            body_bytes: bytes | None = None
            if cfg["method"] == "GET":
                query_str = urllib.parse.urlencode({cfg["param"]: payload})
            else:
                body_obj = dict(cfg.get("extra_fields", {}))
                body_obj[cfg["param"]] = payload
                body_text = json.dumps(body_obj)
                body_bytes = body_text.encode("utf-8")

            detection_result = _rule_engine.inspect_request(
                path=cfg["endpoint"],
                query_params=query_str,
                headers={},
                body_bytes=body_bytes,
            )

            vec_26 = extract_26_from_http(
                path=cfg["endpoint"],
                query_params=query_str,
                body=body_text,
            ).tolist()
            payload_content = f"{cfg['endpoint']} {query_str or ''} {body_text or ''}".strip()

            ml_result = _ml_detector.predict(payload_content, feature_vector=vec_26)
            ml_score = ml_result.risk_score if ml_result.model_loaded else None

            anomaly_result = _anomaly_detector.predict(payload_content, feature_vector=vec_26)
            anomaly_score = anomaly_result.anomaly_score if anomaly_result.model_loaded else None

            rule_score = detection_result.rule_risk_score if detection_result else 0.0
            risk_breakdown = _risk_engine.calculate_weighted_score(
                rule_score=rule_score,
                ml_score=ml_score,
                anomaly_score=anomaly_score,
            )

            decision = _decision_engine.evaluate(
                risk_breakdown=risk_breakdown,
                waf_mode="ACTIVE_BLOCKING",
            )

            # Genuine measured latency (zero random.uniform fabrication)
            latency_ms = max(0.01, round((time.perf_counter() - start_time) * 1000.0, 3))

            # Strict compliance with Rule 2: 0 - 100 Threat Score scale
            waf_threat_score = max(0.0, min(100.0, round(float(decision.risk_score), 1)))

            if decision.is_blocked:
                response_status = 403
                waf_decision = "BLOCK"
                round_winner = "BLUE_TEAM"
            else:
                response_status = 200
                waf_decision = "ALLOW"
                round_winner = "RED_TEAM"

        rounds_data.append({
            "round_num": r,
            "attack_type": family,
            "endpoint": cfg["endpoint"],
            "technique": tech_name,
            "payload": payload,
            "original_payload": baseline_payload,
            "response_status": response_status,
            "waf_threat_score": waf_threat_score,
            "waf_decision": waf_decision,
            "latency_ms": latency_ms,
            "winner": round_winner,
        })

    blocked_count = sum(1 for rd in rounds_data if rd["response_status"] == 403)
    bypass_count = sum(1 for rd in rounds_data if rd["response_status"] == 200)

    if blocked_count > bypass_count:
        battle_winner = "BLUE_TEAM"
    elif bypass_count > blocked_count:
        battle_winner = "RED_TEAM"
    else:
        battle_winner = "DRAW"

    avg_threat_score = (
        round(sum(rd["waf_threat_score"] for rd in rounds_data) / len(rounds_data), 1)
        if rounds_data
        else 0.0
    )
    avg_threat_score = max(0.0, min(100.0, avg_threat_score))

    battle_id = f"battle-{uuid.uuid4().hex[:10]}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "battle_id": battle_id,
        "timestamp": timestamp,
        "campaign": body.campaign,
        "total_rounds": len(rounds_data),
        "blocked_count": blocked_count,
        "bypass_count": bypass_count,
        "winner": battle_winner,
        "avg_threat_score": avg_threat_score,
        "target_mode": body.target_mode,
        "status": "completed",
        "rounds": rounds_data,
    }


# -----------------------------------------------------------------------------
# Endpoints (Protected by require_admin via router dependency)
# -----------------------------------------------------------------------------


@router.post("/battle", response_model=BattleResponse, summary="Execute AI Red vs Blue Arena Battle")
async def execute_arena_battle(
    body: BattleRequest = Body(default_factory=BattleRequest),
) -> dict[str, Any]:
    """Chạy một phiên đối kháng thực tế giữa Red Team Tamper/DQN và Blue Team v2.0 WAF."""
    global _CURRENT_OR_LAST_BATTLE, _BATTLE_HISTORY

    battle_record = await anyio.to_thread.run_sync(_run_battle_sync, body)

    # Maintain in-memory battle history cache (max 50)
    _BATTLE_HISTORY.insert(0, battle_record)
    if len(_BATTLE_HISTORY) > _MAX_HISTORY_ENTRIES:
        _BATTLE_HISTORY.pop()

    _CURRENT_OR_LAST_BATTLE = battle_record
    return battle_record


@router.get("/live", summary="Get Current or Latest AI Arena Battle")
def get_live_arena_battle() -> dict[str, Any]:
    """Trả về thông tin trận đấu đang diễn ra hoặc trận đấu gần nhất."""
    if _CURRENT_OR_LAST_BATTLE is None:
        return {
            "status": "idle",
            "battle_id": None,
            "message": "Chưa có trận đấu nào diễn ra.",
            "campaign": None,
            "total_rounds": 0,
            "blocked_count": 0,
            "bypass_count": 0,
            "winner": None,
            "avg_threat_score": 0.0,
            "target_mode": "waf",
            "rounds": [],
        }
    return _CURRENT_OR_LAST_BATTLE


@router.get("/history", summary="Get AI Arena Battle History & Aggregate Statistics")
def get_arena_history() -> dict[str, Any]:
    """Trả về danh sách lịch sử các trận đấu đã diễn ra kèm số liệu thống kê tổng hợp."""
    total_battles = len(_BATTLE_HISTORY)
    red_wins = sum(1 for b in _BATTLE_HISTORY if b.get("winner") == "RED_TEAM")
    blue_wins = sum(1 for b in _BATTLE_HISTORY if b.get("winner") == "BLUE_TEAM")
    draws = sum(1 for b in _BATTLE_HISTORY if b.get("winner") == "DRAW")

    red_team_win_rate = round((red_wins / total_battles) * 100, 1) if total_battles > 0 else 0.0
    blue_team_defense_rate = round((blue_wins / total_battles) * 100, 1) if total_battles > 0 else 0.0

    return {
        "total_battles": total_battles,
        "red_wins": red_wins,
        "blue_wins": blue_wins,
        "red_team_wins": red_wins,
        "blue_team_wins": blue_wins,
        "draw_count": draws,
        "red_team_win_rate": red_team_win_rate,
        "blue_team_defense_rate": blue_team_defense_rate,
        "battles": list(_BATTLE_HISTORY),
    }


# -----------------------------------------------------------------------------
# Autonomous Pentest Evaluation Engine (Sprint 3)
# -----------------------------------------------------------------------------


# Legacy single-pass static regex signatures (Tier 2 baseline without recursive normalizer/ML/API guards)
_LEGACY_STATIC_REGEXES: list[re.Pattern[str]] = [
    re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    re.compile(r"'\s*OR\s*'?1'?\s*=\s*'?1", re.IGNORECASE),
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"\.\./\.\./", re.IGNORECASE),
    re.compile(r";\s*(?:whoami|cat|id|ls|sh|bash)\b", re.IGNORECASE),
]

_MUTATOR_FUNCTIONS: dict[str, Any] = {
    "none": lambda p: p,
    "baseline_probe": lambda p: p,
    "inline_comment": tamper_sql_space_to_comment,
    "case_randomize": tamper_sql_case_randomize,
    "double_url_encode": tamper_sql_double_url_encode,
    "between_operator": tamper_sql_between_operator,
    "versioned_comment": tamper_sql_versioned_comment,
    "event_handler": tamper_xss_event_handler,
    "html_entity_encoding": tamper_xss_html_entity,
    "nested_traversal": tamper_path_nested_traversal,
    "backslash_substitute": tamper_path_backslash_substitute,
    "null_byte_extension": tamper_path_null_byte_extension,
    "whitespace_ifs": tamper_cmd_whitespace_ifs,
    "quote_concatenation": tamper_cmd_quote_concatenation,
    "subshell": tamper_cmd_subshell,
    "ssrf_loopback": lambda _p: "http://2130706433:8000/api/dashboard/stats",
    "nosql_ne_operator": lambda _p: '{"$ne": ""}',
    "role_escalation": lambda _p: "admin",
    "id_enumeration_burst": lambda _p: "4",
    "sensitive_dump": lambda _p: "all",
}


class PentestRunRequest(BaseModel):
    target_url: str = Field(
        default="http://127.0.0.1:5000",
        description="Target Web API or WAF Gateway base URL for OpenAPI reconnaissance (Cyber Range CWE-918 whitelisted)",
    )
    defense_tier: str = Field(
        default="hybrid_v3",
        description="Defense tier: 'no_waf', 'rules_only', or 'hybrid_v3'",
    )
    scope: str = Field(
        default="full_pentest",
        description="Evaluation scope: 'full_pentest', 'injection', 'api_logic', 'sqli', 'xss', 'path', 'cmd', 'ssrf', 'bola', 'mass_assignment'",
    )
    sync_to_soc: bool = Field(
        default=False,
        description="Whether to synchronize incidents to SQLite SecurityEvent table (default False to keep live SOC clean)",
    )
    max_rounds: int = Field(
        default=8,
        ge=1,
        le=20,
        description="Number of evaluation rounds (1-20)",
    )
    execution_mode: str = Field(
        default="in_process",
        description="Evaluation mode: 'in_process' (deterministic engine) or 'live_http' (end-to-end /api/proxy pipeline)",
    )


def _resolve_scope_families(raw_scope: str) -> list[str]:
    sc = (raw_scope or "full_pentest").strip().lower()
    if sc in ("injection", "injections"):
        return ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION"]
    if sc in ("api_logic", "logic", "owasp_api"):
        return ["SSRF", "BOLA_IDOR", "MASS_ASSIGNMENT", "EXCESSIVE_DATA_EXPOSURE"]
    if "sql" in sc:
        return ["SQL_INJECTION"]
    if "xss" in sc:
        return ["XSS"]
    if "path" in sc or "trav" in sc:
        return ["PATH_TRAVERSAL"]
    if "cmd" in sc or "command" in sc:
        return ["COMMAND_INJECTION"]
    if "ssrf" in sc:
        return ["SSRF"]
    if "bola" in sc or "idor" in sc:
        return ["BOLA_IDOR"]
    if "mass" in sc:
        return ["MASS_ASSIGNMENT"]
    return [
        "SQL_INJECTION",
        "XSS",
        "PATH_TRAVERSAL",
        "COMMAND_INJECTION",
        "SSRF",
        "BOLA_IDOR",
        "MASS_ASSIGNMENT",
        "EXCESSIVE_DATA_EXPOSURE",
    ]


def _is_tcp_reachable(url: str, timeout: float = 0.08) -> bool:
    """Fast non-blocking TCP port check supporting Docker Compose hostnames (e.g. vulnerable-api)."""
    import os
    import socket

    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        # Skip external DNS lookup only inside offline pytest runs targeting mock hostname
        if os.environ.get("PYTEST_CURRENT_TEST") and host == "vulnerable-api":
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _discover_openapi_pentest_plan(
    target_url: str,
    selected_families: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Discovers target endpoints via OpenAPI Recon + Synthesizer with fast offline fallback."""
    spec_source = "gateway_schema_cache"
    recon_dict: dict[str, Any] | None = None

    clean_url = (target_url or "").strip()
    # Probe live OpenAPI when target TCP port is reachable
    if (
        clean_url.startswith(("http://", "https://"))
        and APIReconAgent is not None
        and _is_tcp_reachable(clean_url)
    ):
        try:
            rep = APIReconAgent(target_base_url=clean_url, timeout=0.6).run()
            recon_dict = rep.to_dict()
            spec_source = rep.spec_source
        except Exception:
            recon_dict = None

    synthesized: list[dict[str, Any]] = []
    if OpenAPIPayloadSynthesizer is not None:
        synth = (
            OpenAPIPayloadSynthesizer(attack_surface_source=recon_dict)
            if recon_dict is not None
            else OpenAPIPayloadSynthesizer()
        )
        synthesized = synth.synthesize_test_cases("all")
        if recon_dict is None:
            spec_source = "attack_surface_openapi_v3"

    by_family: dict[str, dict[str, Any]] = {}
    for tc in synthesized:
        fam = str(tc.get("family", "")).upper()
        if fam not in by_family:
            by_family[fam] = tc

    # Fill any missing families from SchemaValidator / canonical configs
    schema_paths = (_schema_validator._spec or {}).get("paths", {})
    ordered_cases: list[dict[str, Any]] = []
    graph_nodes: list[dict[str, Any]] = []

    for idx, fam in enumerate(selected_families, start=1):
        if fam in by_family:
            tc = by_family[fam]
            endpoint = tc["endpoint"]
            method = tc["method"].upper()
            param = tc.get("param_name") or ATTACK_CONFIGS.get(fam, {}).get("param", "q")
            rtype = tc.get("request_type", "query")
            extra = dict(tc.get("extra_fields", {}))
            baseline = str(tc.get("baseline_payload") or ATTACK_CONFIGS.get(fam, {}).get("baseline", ""))
        else:
            cfg = ATTACK_CONFIGS.get(fam, ATTACK_CONFIGS["SQL_INJECTION"])
            endpoint = cfg["endpoint"]
            if schema_paths and endpoint not in schema_paths:
                for cand_p in schema_paths:
                    if fam == "EXCESSIVE_DATA_EXPOSURE" and "list" in cand_p:
                        endpoint = cand_p
                        break
            method = cfg["method"].upper()
            param = cfg["param"]
            rtype = "path" if "{" in endpoint else ("query" if method == "GET" else "json")
            extra = dict(cfg.get("extra_fields", {}))
            baseline = str(cfg["baseline"])

        category = "Injection" if fam in ("SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION") else "API Logic"
        ordered_cases.append(
            {
                "family": fam,
                "endpoint": endpoint,
                "method": method,
                "param": param,
                "request_type": rtype,
                "extra_fields": extra,
                "baseline": baseline,
            }
        )
        graph_nodes.append(
            {
                "endpoint": endpoint,
                "method": method,
                "category": category,
                "flaw": f"{fam} ({param})" if param else fam,
                "priority": idx,
                "surfaces": [param] if param else ["response_body"],
            }
        )

    return ordered_cases, graph_nodes, spec_source


def _apply_family_mutation(family: str, baseline: str, transformation: str) -> str:
    if family == "XSS" and transformation == "case_randomize":
        return tamper_xss_case_randomize(baseline)
    if family == "XSS" and transformation == "double_url_encode":
        return tamper_xss_double_url_encode(baseline)
    if family == "PATH_TRAVERSAL" and transformation == "double_url_encode":
        return tamper_path_double_encode(baseline)
    fn = _MUTATOR_FUNCTIONS.get(transformation)
    return fn(baseline) if fn is not None else baseline


def _evaluate_single_pentest_round(
    *,
    round_num: int,
    total_rounds: int,
    case: dict[str, Any],
    endpoint_index: int,
    total_endpoints: int,
    tier: str,
    family_state: dict[str, Any],
    sync_to_soc: bool,
    db_bind: Any,
    client_ip: str,
) -> dict[str, Any]:
    """Executes one round using real 64-D Dueling-DQN inference and authentic WAF evaluation."""
    family = case["family"]
    endpoint_tpl = case["endpoint"]
    method = case["method"]
    param = case["param"]
    rtype = case["request_type"]
    extra = dict(case.get("extra_fields", {}))
    baseline_payload = str(case["baseline"])

    tried_ids: set[str] = family_state.setdefault("tried_ids", set())
    consec_blocks: int = int(family_state.get("consec_blocks", 0))
    prev_status: int | None = family_state.get("last_status")
    prev_rule: float = float(family_state.get("rule_score", 0.0))
    prev_ml: float | None = family_state.get("ml_score")
    prev_anom: float | None = family_state.get("anomaly_score")
    prev_threat: float = float(family_state.get("threat_score", 0.0))
    prev_dlp: bool = bool(family_state.get("dlp_redacted", False))
    fam_attempt: int = int(family_state.get("attempts", 0))

    # Select action via REAL trained 64-D Dueling-DQN forward pass
    dqn_phase = "probe" if (tier == "no_waf" and fam_attempt == 0) else "evasion"
    valid_specs = get_valid_actions_for_case(
        family=family,
        phase=dqn_phase,
        tried_action_ids=tried_ids,
        consecutive_blocks=consec_blocks,
        can_pivot=False,
    )
    state_64 = encode_pentest_state_64d(
        phase=dqn_phase,
        family=family,
        method=method,
        request_type=rtype,
        endpoint_index=endpoint_index,
        total_endpoints=total_endpoints,
        attempt_num=fam_attempt,
        max_attempts=max(total_rounds, 4),
        last_status=prev_status,
        rule_score=prev_rule,
        ml_score=prev_ml,
        anomaly_score=prev_anom,
        threat_score=prev_threat,
        prev_threat_score=prev_threat,
        dlp_redacted=prev_dlp,
        consecutive_blocks=consec_blocks,
        tried_action_ids=tried_ids,
        available_actions=valid_specs,
    )

    if _PENTEST_ADVISOR is not None and _PENTEST_ADVISOR.available:
        chosen_spec, dqn_q_values = _PENTEST_ADVISOR.recommend(state_64, valid_specs, top_k=5)
        tech_name = (
            chosen_spec.transformation
            if chosen_spec.transformation != "none"
            else chosen_spec.action_id
        )
        tried_ids.add(chosen_spec.action_id)
        mutated_payload = _apply_family_mutation(family, baseline_payload, chosen_spec.transformation)
    else:  # pragma: no cover
        cfg = ATTACK_CONFIGS.get(family, ATTACK_CONFIGS["SQL_INJECTION"])
        tech_name, tech_fn = cfg["techniques"][min(fam_attempt, len(cfg["techniques"]) - 1)]
        mutated_payload = tech_fn(baseline_payload)
        dqn_q_values = []

    _, normalized_payload = InputNormalizer.get_canonical_representations(mutated_payload)

    # Resolve concrete HTTP path, query, and JSON body
    resolved_path = endpoint_tpl
    query_str: str | None = None
    body_text: str | None = None
    body_bytes: bytes | None = None

    if rtype == "path" or "{" in endpoint_tpl:
        resolved_path = re.sub(r"\{[^}]+\}", str(mutated_payload or "1"), endpoint_tpl)
        if extra and method in ("POST", "PUT", "PATCH"):
            body_text = json.dumps(extra)
            body_bytes = body_text.encode("utf-8")
    elif method == "GET":
        if param:
            query_str = urllib.parse.urlencode({param: mutated_payload})
    else:
        body_obj = dict(extra)
        if param:
            body_obj[param] = mutated_payload
        body_text = json.dumps(body_obj)
        body_bytes = body_text.encode("utf-8")

    start_time = time.perf_counter()
    dlp_redacted = False
    detection_result = None

    if tier == "no_waf":
        latency_ms = max(0.02, round((time.perf_counter() - start_time) * 1000.0, 3))
        waf_threat_score = 0.0
        rule_score = 0.0
        matched_rules: list[str] = []
        ml_score_val = 0.0
        anomaly_score_val = 0.0
        response_status = 200
        waf_blocked = False
        waf_decision = "ALLOW"
        winner = "RED_TEAM"
        reasoning_vi = (
            f"Chế độ Không WAF: Tác tử Dueling-DQN thực thi '{tech_name}' vào '{resolved_path}', "
            "máy chủ đích phản hồi trực tiếp HTTP 200 OK (lọt lưới hoàn toàn)."
        )

    elif tier == "rules_only":
        # Legacy single-pass static regex WAF (no recursive normalizer, no ML, no stateful API guards)
        raw_surface = f"{resolved_path}?{query_str or ''} {body_text or ''}"
        matched_static = [f"STATIC-RX-{i + 1}" for i, rx in enumerate(_LEGACY_STATIC_REGEXES) if rx.search(raw_surface)]
        matched_rules = matched_static
        rule_score = 88.0 if matched_static else 0.0
        waf_threat_score = rule_score
        ml_score_val = 0.0
        anomaly_score_val = 0.0
        waf_blocked = bool(matched_static)
        response_status = 403 if waf_blocked else 200
        waf_decision = "BLOCK" if waf_blocked else "ALLOW"
        winner = "BLUE_TEAM" if waf_blocked else "RED_TEAM"
        latency_ms = max(0.02, round((time.perf_counter() - start_time) * 1000.0, 3))

        if waf_blocked:
            reasoning_vi = (
                f"Chế độ Luật Tĩnh: Tập regex cơ bản bắt được mẫu tĩnh ({', '.join(matched_rules)}) "
                f"và chặn HTTP 403 ({waf_threat_score:.1f}/100)."
            )
        else:
            reasoning_vi = (
                f"Chế độ Luật Tĩnh: Đột biến '{tech_name}' từ Dueling-DQN hoặc lỗ hổng logic API ({family}) "
                "vượt qua tập regex tĩnh không có chuẩn hóa đệ quy & ML -> Bypass HTTP 200!"
            )

    else:
        # Full Blue Team v3.0 Hybrid: Normalizer + OWASP Web/API Rules + Stateful BOLA + XGBoost 26-D + IForest 26-D + DLP
        detection_result = _rule_engine.inspect_request(
            path=resolved_path,
            query_params=query_str,
            headers={},
            body_bytes=body_bytes,
        )

        # Stateful BOLA / IDOR enumeration check on parameterized object endpoints
        if family == "BOLA_IDOR" or "{" in endpoint_tpl or "/orders/" in resolved_path:
            local_bola = BOLADetector(window_seconds=60.0, enumeration_threshold=4)
            bola_res = None
            for probe_oid in ("1", "2", "3", "4"):
                p_try = (
                    re.sub(r"\{[^}]+\}", probe_oid, endpoint_tpl)
                    if "{" in endpoint_tpl
                    else re.sub(r"/\d+(/?)$", rf"/{probe_oid}\1", resolved_path)
                )
                bola_res = local_bola.inspect(client_ip=client_ip, path=p_try, method=method)
            if bola_res and bola_res.is_bola and bola_res.rule_match is not None:
                detection_result.matches.append(bola_res.rule_match)
                detection_result.is_attack = True
                detection_result.total_matches = len(detection_result.matches)
                detection_result.rule_risk_score = max(detection_result.rule_risk_score, 92.0)

        matched_rules = [m.rule_id for m in detection_result.matches] if detection_result else []
        rule_score = float(detection_result.rule_risk_score if detection_result else 0.0)

        vec_26 = extract_26_from_http(
            path=resolved_path,
            query_params=query_str,
            body=body_text,
        ).tolist()
        payload_content = f"{resolved_path} {query_str or ''} {body_text or ''}".strip()

        ml_result = _ml_detector.predict(payload_content, feature_vector=vec_26)
        ml_score_val = float(ml_result.risk_score if ml_result.model_loaded else 0.0)

        anomaly_result = _anomaly_detector.predict(payload_content, feature_vector=vec_26)
        anomaly_score_val = float(anomaly_result.anomaly_score if anomaly_result.model_loaded else 0.0)

        risk_breakdown = _risk_engine.calculate_weighted_score(
            rule_score=rule_score,
            ml_score=ml_score_val,
            anomaly_score=anomaly_score_val,
        )
        decision = _decision_engine.evaluate(
            risk_breakdown=risk_breakdown,
            waf_mode="ACTIVE_BLOCKING",
        )

        # Outbound Response DLP check when upstream returns sensitive credential listings
        if not decision.is_blocked and family == "EXCESSIVE_DATA_EXPOSURE":
            sim_upstream_json = json.dumps(
                {
                    "users": [
                        {
                            "id": 1,
                            "username": "admin",
                            "password_hash": "pbkdf2_sha256$600000$salt$hashdigest",
                        }
                    ]
                }
            ).encode("utf-8")
            dlp_out = _response_dlp.inspect_and_redact(
                body_bytes=sim_upstream_json,
                content_type="application/json",
                status_code=200,
                active_waf_mode="ACTIVE_BLOCKING",
            )
            if dlp_out.redacted:
                dlp_redacted = True
                matched_rules.append("DLP-001")
                rule_score = max(rule_score, 88.0)

        latency_ms = max(0.02, round((time.perf_counter() - start_time) * 1000.0, 3))

        if decision.is_blocked:
            response_status = 403
            waf_blocked = True
            waf_decision = "BLOCK"
            winner = "BLUE_TEAM"
            waf_threat_score = max(0.0, min(100.0, round(float(decision.risk_score), 1)))
            rule_display = f"Rules: {', '.join(matched_rules)}" if matched_rules else "Rules: Clean"
            reasoning_vi = (
                f"Chế độ Hybrid v3.0: Chuẩn hóa đệ quy + {rule_display}, "
                f"XGBoost ({ml_score_val:.1f}) & Isolation Forest ({anomaly_score_val:.1f}) hợp nhất điểm rủi ro "
                f"{waf_threat_score:.1f}/100 -> Chặn đứng HTTP 403 trong {latency_ms:.2f}ms."
            )
        elif dlp_redacted:
            response_status = 200
            waf_blocked = True
            waf_decision = "DLP_REDACT"
            winner = "BLUE_TEAM"
            waf_threat_score = 88.0
            reasoning_vi = (
                f"Chế độ Hybrid v3.0: Request GET hợp lệ nhưng Response DLP phát hiện rò rỉ băm mật khẩu "
                f"trên '{resolved_path}' -> Tự động che giấu [REDACTED_BY_WAF_DLP] bảo toàn dữ liệu!"
            )
        else:
            response_status = 200
            waf_blocked = False
            waf_decision = "ALLOW"
            winner = "RED_TEAM"
            waf_threat_score = max(0.0, min(100.0, round(float(decision.risk_score), 1)))
            reasoning_vi = (
                f"Chế độ Hybrid v3.0: Điểm rủi ro tổng hợp {waf_threat_score:.1f}/100 dưới ngưỡng chặn -> "
                f"Request được phép đi qua (HTTP 200 OK)."
            )

    # Update per-family RL memory for multi-round stateful adaptation
    family_state["attempts"] = fam_attempt + 1
    family_state["last_status"] = response_status
    family_state["rule_score"] = rule_score
    family_state["ml_score"] = ml_score_val if tier == "hybrid_v3" else None
    family_state["anomaly_score"] = anomaly_score_val if tier == "hybrid_v3" else None
    family_state["threat_score"] = waf_threat_score
    family_state["dlp_redacted"] = dlp_redacted
    family_state["consec_blocks"] = (consec_blocks + 1) if waf_blocked else 0

    # Thread-safe persistence to SQLite SecurityEvent table via canonical SecurityEventService
    if sync_to_soc and db_bind is not None and tier != "no_waf":
        try:
            local_session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db_bind)
            with local_session_factory() as sync_db:
                soc_action = "BLOCKED" if waf_blocked else "MONITOR"
                SecurityEventService.record_detection(
                    db=sync_db,
                    request_id=f"pentest-{uuid.uuid4().hex[:10]}",
                    client_ip=client_ip,
                    detection_result=detection_result,
                    action=soc_action,
                    risk_score=max(waf_threat_score, 55.0 if not waf_blocked else waf_threat_score),
                    ml_score=ml_score_val if tier == "hybrid_v3" else None,
                    anomaly_score=anomaly_score_val if tier == "hybrid_v3" else None,
                    details_extra={
                        "source": "arena_pentest",
                        "api_protocol": "REST",
                        "defense_tier": tier,
                        "technique": tech_name,
                        "endpoint": resolved_path,
                        "dlp_redacted": dlp_redacted,
                        "payload": mutated_payload[:160],
                    },
                    attack_type_override=family,
                    commit=True,
                )
        except Exception as exc:
            logger.warning("Could not sync pentest event to SOC DB: %s", exc)

    phase_label = "PROBE" if round_num == 1 else "DQN_MUTATE"
    return {
        "round_num": round_num,
        "round": round_num,
        "phase": phase_label,
        "event_type": phase_label,
        "attack_type": family,
        "endpoint": resolved_path,
        "target_endpoint": resolved_path,
        "method": method,
        "technique": tech_name,
        "mutation_technique": tech_name,
        "original_payload": baseline_payload,
        "mutated_payload": mutated_payload,
        "normalized_payload": normalized_payload,
        "response_status": response_status,
        "http_status": response_status,
        "waf_blocked": waf_blocked,
        "dlp_redacted": dlp_redacted,
        "waf_decision": waf_decision,
        "waf_threat_score": round(waf_threat_score, 1),
        "threat_score": round(waf_threat_score, 1),
        "rule_score": round(rule_score, 1),
        "matched_rules": matched_rules,
        "ml_score": round(ml_score_val, 2),
        "anomaly_score": round(anomaly_score_val, 2),
        "latency_ms": latency_ms,
        "winner": winner,
        "dqn_q_values": dqn_q_values,
        "reasoning_vi": reasoning_vi,
    }


def _finalize_pentest_report(
    *,
    body: PentestRunRequest,
    tier: str,
    spec_source: str,
    graph_nodes: list[dict[str, Any]],
    rounds_data: list[dict[str, Any]],
    started_perf: float,
) -> dict[str, Any]:
    global _CURRENT_OR_LAST_PENTEST, _BATTLE_HISTORY

    blocked_cnt = sum(1 for rd in rounds_data if rd["waf_blocked"])
    bypass_cnt = len(rounds_data) - blocked_cnt
    battle_winner = (
        "BLUE_TEAM"
        if blocked_cnt > bypass_cnt
        else ("RED_TEAM" if bypass_cnt > blocked_cnt else "DRAW")
    )
    avg_threat = (
        round(sum(rd["waf_threat_score"] for rd in rounds_data) / len(rounds_data), 1)
        if rounds_data
        else 0.0
    )
    avg_lat = (
        round(sum(rd["latency_ms"] for rd in rounds_data) / len(rounds_data), 3)
        if rounds_data
        else 0.0
    )
    duration_ms = round((time.perf_counter() - started_perf) * 1000.0, 2)

    report = {
        "battle_id": f"pentest-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target_url": body.target_url,
        "spec_source": spec_source,
        "defense_tier": tier,
        "target_mode": tier,
        "scope": body.scope,
        "campaign": body.scope,
        "total_rounds": len(rounds_data),
        "blocked_count": blocked_cnt,
        "bypass_count": bypass_cnt,
        "winner": battle_winner,
        "avg_threat_score": avg_threat,
        "avg_latency_ms": avg_lat,
        "duration_ms": duration_ms,
        "status": "completed",
        "attack_graph": graph_nodes,
        "rounds": rounds_data,
    }
    _CURRENT_OR_LAST_PENTEST = report
    _BATTLE_HISTORY.insert(0, report)
    if len(_BATTLE_HISTORY) > _MAX_HISTORY_ENTRIES:
        _BATTLE_HISTORY.pop()
    return report


def _run_pentest_evaluation(
    body: PentestRunRequest,
    db_bind: Any = None,
    client_ip: str = "127.0.0.1",
) -> dict[str, Any]:
    """Executes autonomous 5-phase pentest evaluation off the event loop."""
    started_perf = time.perf_counter()
    selected_families = _resolve_scope_families(body.scope)
    tier = (body.defense_tier or "hybrid_v3").lower().strip()
    if tier not in ("no_waf", "rules_only", "hybrid_v3"):
        tier = "hybrid_v3"

    ordered_cases, graph_nodes, spec_source = _discover_openapi_pentest_plan(
        body.target_url, selected_families
    )
    num_rounds = max(1, min(body.max_rounds, 20))
    rounds_data: list[dict[str, Any]] = []
    per_family_state: dict[str, dict[str, Any]] = {}

    for r in range(1, num_rounds + 1):
        ep_idx = (r - 1) % len(ordered_cases)
        case = ordered_cases[ep_idx]
        f_state = per_family_state.setdefault(case["family"], {})
        rd = _evaluate_single_pentest_round(
            round_num=r,
            total_rounds=num_rounds,
            case=case,
            endpoint_index=ep_idx,
            total_endpoints=len(ordered_cases),
            tier=tier,
            family_state=f_state,
            sync_to_soc=body.sync_to_soc,
            db_bind=db_bind,
            client_ip=client_ip,
        )
        rounds_data.append(rd)

    return _finalize_pentest_report(
        body=body,
        tier=tier,
        spec_source=spec_source,
        graph_nodes=graph_nodes,
        rounds_data=rounds_data,
        started_perf=started_perf,
    )


async def _run_live_http_pentest_evaluation(
    request: Request,
    body: PentestRunRequest,
    caller_ip: str,
) -> dict[str, Any]:
    """Executes Pentest Arena rounds through the real ASGI HTTP /api/proxy pipeline (Phase C1)."""
    import httpx

    from app.db.models import WafConfigModel
    from app.db.session import SessionLocal

    started_perf = time.perf_counter()
    selected_families = _resolve_scope_families(body.scope)
    tier = (body.defense_tier or "hybrid_v3").lower().strip()
    if tier not in ("no_waf", "rules_only", "hybrid_v3"):
        tier = "hybrid_v3"

    ordered_cases, graph_nodes, spec_source = await anyio.to_thread.run_sync(
        _discover_openapi_pentest_plan, body.target_url, selected_families
    )
    num_rounds = max(1, min(body.max_rounds, 20))
    rounds_data: list[dict[str, Any]] = []
    per_family_state: dict[str, dict[str, Any]] = {}

    with SessionLocal() as cfg_db:
        cfg_row = cfg_db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        prev_waf_mode = cfg_row.value if cfg_row else None
        desired_mode = "OFF" if tier == "no_waf" else "ACTIVE_BLOCKING"
        if cfg_row:
            cfg_row.value = desired_mode
        else:
            cfg_db.add(WafConfigModel(key="waf_mode", value=desired_mode))
        cfg_db.commit()

    from app.api.proxy import invalidate_waf_mode_cache
    from app.core.config import get_settings

    invalidate_waf_mode_cache()
    settings = get_settings()
    prev_ablation = settings.ablation_mode
    settings.ablation_mode = "rules_only" if tier == "rules_only" else "hybrid"

    try:
        transport = httpx.ASGITransport(app=request.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
            for r in range(1, num_rounds + 1):
                ep_idx = (r - 1) % len(ordered_cases)
                case = ordered_cases[ep_idx]
                family = case["family"]
                f_state = per_family_state.setdefault(family, {})
                tried_ids: set[str] = f_state.setdefault("tried_ids", set())
                consec_blocks = int(f_state.get("consec_blocks", 0))
                fam_attempt = int(f_state.get("attempts", 0))

                dqn_phase = "probe" if (tier == "no_waf" and fam_attempt == 0) else "evasion"
                valid_specs = get_valid_actions_for_case(
                    family=family,
                    phase=dqn_phase,
                    tried_action_ids=tried_ids,
                    consecutive_blocks=consec_blocks,
                    can_pivot=False,
                )
                state_64 = encode_pentest_state_64d(
                    phase=dqn_phase,
                    family=family,
                    method=case["method"],
                    request_type=case["request_type"],
                    endpoint_index=ep_idx,
                    total_endpoints=len(ordered_cases),
                    attempt_num=fam_attempt,
                    max_attempts=max(num_rounds, 4),
                    last_status=f_state.get("last_status"),
                    rule_score=float(f_state.get("rule_score", 0.0)),
                    ml_score=f_state.get("ml_score"),
                    anomaly_score=f_state.get("anomaly_score"),
                    threat_score=float(f_state.get("threat_score", 0.0)),
                    prev_threat_score=float(f_state.get("threat_score", 0.0)),
                    dlp_redacted=bool(f_state.get("dlp_redacted", False)),
                    consecutive_blocks=consec_blocks,
                    tried_action_ids=tried_ids,
                    available_actions=valid_specs,
                )
                if _PENTEST_ADVISOR is not None and _PENTEST_ADVISOR.available:
                    chosen_spec, dqn_q_values = _PENTEST_ADVISOR.recommend(state_64, valid_specs, top_k=5)
                    tech_name = (
                        chosen_spec.transformation
                        if chosen_spec.transformation != "none"
                        else chosen_spec.action_id
                    )
                    tried_ids.add(chosen_spec.action_id)
                    mutated_payload = _apply_family_mutation(family, str(case["baseline"]), chosen_spec.transformation)
                else:  # pragma: no cover
                    tech_name = "baseline_probe"
                    mutated_payload = str(case["baseline"])
                    dqn_q_values = []

                _, normalized_payload = InputNormalizer.get_canonical_representations(mutated_payload)
                endpoint_tpl = case["endpoint"]
                method = case["method"]
                param = case["param"]
                rtype = case["request_type"]
                extra = dict(case.get("extra_fields", {}))

                resolved_path = endpoint_tpl
                params_dict: dict[str, Any] | None = None
                json_obj: dict[str, Any] | None = None
                if rtype == "path" or "{" in endpoint_tpl:
                    resolved_path = re.sub(r"\{[^}]+\}", str(mutated_payload or "1"), endpoint_tpl)
                    if extra and method in ("POST", "PUT", "PATCH"):
                        json_obj = extra
                elif method == "GET":
                    if param:
                        params_dict = {**extra, param: mutated_payload}
                else:
                    json_obj = {**extra, param: mutated_payload} if param else dict(extra)

                t0 = time.perf_counter()
                if family == "BOLA_IDOR" and tier != "no_waf":
                    resp = None
                    for oid in ("1", "2", "3", "4"):
                        p_try = re.sub(r"\{[^}]+\}", oid, endpoint_tpl) if "{" in endpoint_tpl else re.sub(r"/\d+(/?)$", rf"/{oid}\1", resolved_path)
                        resp = await client.request(
                            method=method,
                            url=f"/api/proxy{p_try}",
                            headers={"X-Forwarded-For": f"10.99.0.{r}", "User-Agent": "PBL6-ArenaLiveHTTP/3.1"},
                        )
                    assert resp is not None
                else:
                    resp = await client.request(
                        method=method,
                        url=f"/api/proxy{resolved_path}",
                        params=params_dict,
                        json=json_obj,
                        headers={"X-Forwarded-For": f"10.99.1.{r}", "User-Agent": "PBL6-ArenaLiveHTTP/3.1"},
                    )
                latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

                hdrs = resp.headers
                status_code = resp.status_code
                dlp_redacted = hdrs.get("x-waf-dlp-redacted", "false").lower() == "true"
                waf_blocked = status_code in (403, 429) or dlp_redacted

                bd: dict[str, Any] = {}
                if status_code == 403:
                    try:
                        bd = resp.json().get("breakdown") or {}
                    except Exception:
                        bd = {}

                rule_score = float(hdrs.get("x-waf-rule-score") or bd.get("rule_score") or 0.0)
                ml_score_val = float(hdrs.get("x-waf-ml-score") or bd.get("ml_score") or 0.0)
                anomaly_score_val = float(hdrs.get("x-waf-anomaly-score") or bd.get("anomaly_score") or 0.0)
                waf_threat_score = float(hdrs.get("x-waf-risk-score") or (88.0 if dlp_redacted else 0.0))
                waf_decision = "BLOCK" if status_code in (403, 429) else ("DLP_REDACT" if dlp_redacted else "ALLOW")
                winner = "BLUE_TEAM" if waf_blocked else "RED_TEAM"

                f_state["attempts"] = fam_attempt + 1
                f_state["last_status"] = status_code
                f_state["rule_score"] = rule_score
                f_state["ml_score"] = ml_score_val if tier == "hybrid_v3" else None
                f_state["anomaly_score"] = anomaly_score_val if tier == "hybrid_v3" else None
                f_state["threat_score"] = waf_threat_score
                f_state["dlp_redacted"] = dlp_redacted
                f_state["consec_blocks"] = (consec_blocks + 1) if waf_blocked else 0

                phase_label = "PROBE" if r == 1 else "DQN_MUTATE"
                rounds_data.append(
                    {
                        "round_num": r,
                        "round": r,
                        "phase": phase_label,
                        "event_type": phase_label,
                        "attack_type": family,
                        "endpoint": resolved_path,
                        "target_endpoint": resolved_path,
                        "method": method,
                        "technique": tech_name,
                        "mutation_technique": tech_name,
                        "original_payload": str(case["baseline"]),
                        "mutated_payload": mutated_payload,
                        "normalized_payload": normalized_payload,
                        "response_status": status_code,
                        "http_status": status_code,
                        "waf_blocked": waf_blocked,
                        "dlp_redacted": dlp_redacted,
                        "waf_decision": waf_decision,
                        "waf_threat_score": round(waf_threat_score, 1),
                        "threat_score": round(waf_threat_score, 1),
                        "rule_score": round(rule_score, 1),
                        "matched_rules": [],
                        "ml_score": round(ml_score_val, 2),
                        "anomaly_score": round(anomaly_score_val, 2),
                        "latency_ms": latency_ms,
                        "winner": winner,
                        "dqn_q_values": dqn_q_values,
                        "execution_mode": "live_http",
                        "reasoning_vi": (
                            f"[Live HTTP /api/proxy] {method} {resolved_path} -> HTTP {status_code} "
                            f"(Risk={waf_threat_score:.1f}/100, Rule={rule_score:.1f}, ML={ml_score_val:.1f})."
                        ),
                    }
                )
    finally:
        settings.ablation_mode = prev_ablation
        with SessionLocal() as restore_db:
            cfg_row = restore_db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
            if prev_waf_mode is None and cfg_row is not None:
                restore_db.delete(cfg_row)
            elif cfg_row is not None:
                cfg_row.value = prev_waf_mode
            restore_db.commit()
        invalidate_waf_mode_cache()

    report = _finalize_pentest_report(
        body=body,
        tier=tier,
        spec_source=spec_source,
        graph_nodes=graph_nodes,
        rounds_data=rounds_data,
        started_perf=started_perf,
    )
    report["execution_mode"] = "live_http"
    return report


@router.post("/pentest/run", summary="Run Full Autonomous Pentest Evaluation")
async def run_pentest_evaluation_endpoint(
    request: Request,
    body: PentestRunRequest = Body(default_factory=PentestRunRequest),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Chạy đánh giá đối kháng toàn trình (OpenAPI Recon, Attack Graph, Probe, Dueling-DQN, Verdict)."""
    from app.api.dashboard import _validate_cyber_range_target_url
    from app.core.config import get_settings

    if body.target_url:
        body.target_url = _validate_cyber_range_target_url(body.target_url, get_settings().target_api_url)

    caller_ip = (request.client.host if request.client else None) or "127.0.0.1"
    if (body.execution_mode or "in_process").strip().lower() == "live_http":
        return await _run_live_http_pentest_evaluation(request, body, caller_ip)

    db_bind = db.get_bind() if db is not None else default_db_engine
    return await anyio.to_thread.run_sync(_run_pentest_evaluation, body, db_bind, caller_ip)


@router.get("/pentest/stream", summary="Stream Live Autonomous Pentest Telemetry via SSE")
async def stream_pentest_evaluation_endpoint(
    request: Request,
    target_url: str = Query("http://127.0.0.1:5000"),
    defense_tier: str = Query("hybrid_v3"),
    scope: str = Query("full_pentest"),
    max_rounds: int = Query(8, ge=1, le=20),
    sync_to_soc: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Phát trực tiếp Server-Sent Events (SSE) thời gian thực từng pha và từng vòng đối kháng."""
    req = PentestRunRequest(
        target_url=target_url,
        defense_tier=defense_tier,
        scope=scope,
        max_rounds=max_rounds,
        sync_to_soc=sync_to_soc,
    )
    db_bind = db.get_bind() if db is not None else default_db_engine
    caller_ip = (request.client.host if request.client else None) or "127.0.0.1"

    async def sse_event_generator():
        started_perf = time.perf_counter()
        selected_families = _resolve_scope_families(req.scope)
        tier = (req.defense_tier or "hybrid_v3").lower().strip()
        if tier not in ("no_waf", "rules_only", "hybrid_v3"):
            tier = "hybrid_v3"

        ordered_cases, graph_nodes, spec_source = await anyio.to_thread.run_sync(
            _discover_openapi_pentest_plan,
            req.target_url,
            selected_families,
        )

        # Phase 1: RECON
        recon_evt = {
            "type": "RECON",
            "phase": "1. Reconnaissance",
            "status": "completed",
            "target_url": target_url,
            "spec_source": spec_source,
            "message": f"Khám phá OpenAPI từ {target_url} ({len(graph_nodes)} bề mặt tấn công).",
            "endpoints_count": len(graph_nodes),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        yield f"event: recon\ndata: {json.dumps(recon_evt, ensure_ascii=False)}\n\n"
        await asyncio.sleep(0.02)

        # Phase 2: ATTACK_GRAPH
        graph_evt = {
            "type": "ATTACK_GRAPH",
            "phase": "2. Attack Graph",
            "status": "completed",
            "nodes_count": len(graph_nodes),
            "nodes": graph_nodes,
            "priority_targets": [n["endpoint"] for n in graph_nodes],
            "message": "Đã dựng đồ thị tấn công và xếp hạng tham số nhạy cảm.",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        yield f"event: attack_graph\ndata: {json.dumps(graph_evt, ensure_ascii=False)}\n\n"
        await asyncio.sleep(0.02)

        # Phase 3 & 4: Per-round live Dueling-DQN inference & WAF evaluation
        num_rounds = max(1, min(req.max_rounds, 20))
        rounds_data: list[dict[str, Any]] = []
        per_family_state: dict[str, dict[str, Any]] = {}

        for r in range(1, num_rounds + 1):
            ep_idx = (r - 1) % len(ordered_cases)
            case = ordered_cases[ep_idx]
            f_state = per_family_state.setdefault(case["family"], {})
            rd = await anyio.to_thread.run_sync(
                lambda r_i=r, c_i=case, e_i=ep_idx, fs=f_state: _evaluate_single_pentest_round(
                    round_num=r_i,
                    total_rounds=num_rounds,
                    case=c_i,
                    endpoint_index=e_i,
                    total_endpoints=len(ordered_cases),
                    tier=tier,
                    family_state=fs,
                    sync_to_soc=req.sync_to_soc,
                    db_bind=db_bind,
                    client_ip=caller_ip,
                )
            )
            rounds_data.append(rd)
            rd_payload = {
                "type": "ROUND",
                "phase": f"Round {rd['round_num']}/{num_rounds}",
                "round_data": rd,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            yield f"event: round\ndata: {json.dumps(rd_payload, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.02)

        # Phase 5: VERDICT
        report = _finalize_pentest_report(
            body=req,
            tier=tier,
            spec_source=spec_source,
            graph_nodes=graph_nodes,
            rounds_data=rounds_data,
            started_perf=started_perf,
        )
        verdict_evt = {
            **report,
            "type": "VERDICT",
            "phase": "5. Verdict",
        }
        yield f"event: verdict\ndata: {json.dumps(verdict_evt, ensure_ascii=False)}\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        sse_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
