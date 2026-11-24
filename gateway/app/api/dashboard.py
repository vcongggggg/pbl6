import datetime
import json
import time
import urllib.parse
from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.config import Settings, get_settings
from app.db.models import RequestLog, SecurityEvent, WafConfigModel
from app.db.session import get_db

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(require_admin)],
)


class SimulateRequest(BaseModel):
    attack_type: str = Field(
        ...,
        description="Type of attack to simulate: SQLI, XSS, PATH, CMD, SSRF, NOSQLI, BOLA, MASS, DATA_EXPOSURE, SOAP, GRAPHQL, or BENIGN",
    )
    target_url: str | None = Field(
        default=None,
        description="Optional Cyber Range target base URL (loopback / RFC1918 LAN whitelist) for dynamic OpenAPI route discovery",
    )


async def check_target_upstream(request: Request, target_url: str) -> tuple[str, float]:
    """Helper to ping target upstream for latency and status."""
    client = getattr(request.app.state, "http_client", None)
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=2.0)
        close_client = True

    start_time = time.perf_counter()
    try:
        resp = await client.get(target_url, timeout=2.0)
        latency = (time.perf_counter() - start_time) * 1000
        if close_client:
            await client.aclose()
        return ("ok" if resp.status_code < 500 else "degraded", round(latency, 1))
    except Exception:
        latency = (time.perf_counter() - start_time) * 1000
        if close_client:
            await client.aclose()
        return ("unreachable", round(latency, 1))


@router.get("/stats", summary="Get aggregated dashboard metrics")
async def get_dashboard_stats(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Computes genuine real-time telemetry metrics and security KPIs directly from SQLite tables (NIST SP 800-137 & ISO/IEC 27004)."""
    total_requests = db.query(RequestLog).count()
    attacks_detected = db.query(SecurityEvent).count()
    safe_requests = max(0, total_requests - attacks_detected)

    safe_request_rate = (
        round((safe_requests / total_requests) * 100, 1) if total_requests > 0 else 100.0
    )

    # Threat scores: Deterministic Rule Engine score & Comprehensive Hybrid Risk score
    avg_threat_score = (
        db.query(func.avg(SecurityEvent.rule_score)).scalar() or 0.0
    )
    avg_risk_score = (
        db.query(func.avg(SecurityEvent.risk_score)).scalar() or 0.0
    )

    # Enforcement action counts (Decision Engine & Rate Limiter)
    blocked_count = (
        db.query(SecurityEvent).filter(SecurityEvent.action.in_(["BLOCK", "BLOCKED"])).count()
    )
    rate_limited_count = (
        db.query(SecurityEvent)
        .filter(
            (SecurityEvent.action == "RATE_LIMIT")
            | (SecurityEvent.attack_type == "RATE_LIMIT_EXCEEDED")
        )
        .count()
    )
    monitored_count = (
        db.query(SecurityEvent).filter(SecurityEvent.action.in_(["MONITOR", "DETECTED"])).count()
    )

    # Breakdown by attack family
    attack_counts = (
        db.query(SecurityEvent.attack_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.attack_type)
        .all()
    )
    family_counts = {str(k): int(v) for k, v in attack_counts}

    # Calculate real current RPS over the last 60 seconds (NIST SP 800-137)
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cutoff_60s = now - datetime.timedelta(seconds=60)
    req_count_60s = db.query(func.count(RequestLog.id)).filter(RequestLog.timestamp >= cutoff_60s).scalar() or 0
    current_rps = round(req_count_60s / 60.0, 2)

    # Ping target upstream
    target_status, target_latency_ms = await check_target_upstream(
        request, settings.target_api_url.rstrip("/")
    )

    active_waf_mode = settings.waf_mode
    try:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if cfg and cfg.value:
            active_waf_mode = cfg.value
    except Exception:
        pass

    return {
        "total_requests": total_requests,
        "attacks_detected": attacks_detected,
        "safe_requests": safe_requests,
        "safe_request_rate": safe_request_rate,
        "avg_threat_score": round(float(avg_threat_score), 1),
        "avg_risk_score": round(float(avg_risk_score), 1),
        "blocked_count": blocked_count,
        "rate_limited_count": rate_limited_count,
        "monitored_count": monitored_count,
        "family_counts": family_counts,
        "target_status": target_status,
        "target_latency_ms": target_latency_ms,
        "target_url": settings.target_api_url,
        "waf_mode": active_waf_mode,
        "current_rps": current_rps,
        "active_phase": "Phase 2 & Phase 7/8 (Rule + ML + Rate Limiting Active)",
    }


@router.get("/events", summary="Get paginated security events")
def get_dashboard_events(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    severity: str | None = None,
    attack_type: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    """Returns genuine security detection incidents with filtering and pagination."""
    query = db.query(SecurityEvent)

    if severity and severity.upper() != "ALL":
        query = query.filter(SecurityEvent.severity == severity.upper())

    if attack_type and attack_type.upper() != "ALL":
        query = query.filter(SecurityEvent.attack_type == attack_type.upper())

    if q and q.strip():
        search_term = f"%{q.strip()}%"
        query = query.filter(
            (SecurityEvent.client_ip.ilike(search_term))
            | (SecurityEvent.request_id.ilike(search_term))
        )

    total = query.count()
    events = (
        query.order_by(SecurityEvent.timestamp.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    items = []
    for ev in events:
        details_obj = {}
        if ev.details:
            try:
                details_obj = json.loads(ev.details)
            except Exception:
                details_obj = {"raw": ev.details}

        # Extract primary rule match info if available
        rule_id = "UNKNOWN"
        location = "PAYLOAD"
        rule_name = ev.attack_type
        evidence_snippet = ""

        rule_matches = details_obj.get("rule_matches") or details_obj.get("matches") or []
        if rule_matches and isinstance(rule_matches, list):
            first_match = rule_matches[0]
            rule_id = first_match.get("rule_id", "UNKNOWN")
            location = first_match.get("location", "PAYLOAD")
            rule_name = first_match.get("name") or first_match.get("description", ev.attack_type)
            evidence_snippet = first_match.get("evidence") or first_match.get("raw_input", "")

        items.append({
            "event_id": ev.event_id,
            "request_id": ev.request_id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
            "client_ip": ev.client_ip,
            "attack_type": ev.attack_type,
            "severity": ev.severity,
            "action": ev.action,
            "risk_score": ev.risk_score or 0.0,
            "rule_score": ev.rule_score or 0.0,
            "ml_score": ev.ml_score,
            "anomaly_score": ev.anomaly_score,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "location": location,
            "evidence": evidence_snippet,
            "details": details_obj,
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/timeline", summary="Get timeline traffic vs attacks data")
def get_dashboard_timeline(
    db: Session = Depends(get_db),
    minutes: int = Query(30, ge=5, le=1440),
) -> list[dict[str, Any]]:
    """Gathers real-time request and attack volumes grouped into time buckets."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cutoff = now - datetime.timedelta(minutes=minutes)

    # Fetch request counts grouped by minute (using YYYY-MM-DD HH:MM to maintain chronological sort across midnight)
    req_rows = (
        db.query(
            func.strftime("%Y-%m-%d %H:%M", RequestLog.timestamp).label("minute"),
            func.count(RequestLog.id).label("cnt"),
        )
        .filter(RequestLog.timestamp >= cutoff)
        .group_by("minute")
        .order_by("minute")
        .all()
    )
    req_dict = {str(r.minute): int(r.cnt) for r in req_rows}

    # Fetch attack counts grouped by minute
    sec_rows = (
        db.query(
            func.strftime("%Y-%m-%d %H:%M", SecurityEvent.timestamp).label("minute"),
            func.count(SecurityEvent.id).label("cnt"),
        )
        .filter(SecurityEvent.timestamp >= cutoff)
        .group_by("minute")
        .order_by("minute")
        .all()
    )
    sec_dict = {str(r.minute): int(r.cnt) for r in sec_rows}

    # If no data in the time window, return an empty list
    all_keys = sorted(set(list(req_dict.keys()) + list(sec_dict.keys())))
    if not all_keys:
        return []

    timeline = []
    for k in all_keys:
        total = req_dict.get(k, 0)
        attacks = sec_dict.get(k, 0)
        benign = max(0, total - attacks)
        time_part = k.split(" ")[1] if " " in k else k
        timeline.append({
            "time": time_part,
            "bucket": k,
            "total_traffic": total,
            "benign_traffic": benign,
            "attacks": attacks,
        })

    return timeline


@router.get("/distribution", summary="Get attack family distribution")
def get_dashboard_distribution(
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Calculates percentage distribution across the 4 core attack families."""
    rows = (
        db.query(SecurityEvent.attack_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.attack_type)
        .all()
    )

    total_attacks = sum(v for _, v in rows)
    if total_attacks == 0:
        return [
            {
                "name": "SQL Injection",
                "key": "SQL_INJECTION",
                "count": 0,
                "percentage": 0.0,
                "color": "#3b82f6",
            },
            {
                "name": "XSS",
                "key": "XSS",
                "count": 0,
                "percentage": 0.0,
                "color": "#f43f5e",
            },
            {
                "name": "Path Traversal",
                "key": "PATH_TRAVERSAL",
                "count": 0,
                "percentage": 0.0,
                "color": "#10b981",
            },
            {
                "name": "Command Injection",
                "key": "COMMAND_INJECTION",
                "count": 0,
                "percentage": 0.0,
                "color": "#f59e0b",
            },
        ]

    counts = {str(k): int(v) for k, v in rows}
    color_map = {
        "SQL_INJECTION": "#3b82f6",
        "XSS": "#f43f5e",
        "PATH_TRAVERSAL": "#10b981",
        "COMMAND_INJECTION": "#f59e0b",
    }
    label_map = {
        "SQL_INJECTION": "SQL Injection",
        "XSS": "XSS",
        "PATH_TRAVERSAL": "Path Traversal",
        "COMMAND_INJECTION": "Command Injection",
    }

    result = []
    for key, label in label_map.items():
        cnt = counts.get(key, 0)
        pct = round((cnt / total_attacks) * 100, 1)
        result.append({
            "name": label,
            "key": key,
            "count": cnt,
            "percentage": pct,
            "color": color_map.get(key, "#8b5cf6"),
        })

    return result


@router.get("/protocols", summary="Get multi-protocol traffic distribution")
def get_dashboard_protocol_distribution(
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Calculates percentage and count distribution across the 5 canonical API protocols using SQL GROUP BY."""
    protocol_counts: dict[str, int] = {
        "REST": 0,
        "GRAPHQL": 0,
        "SOAP_XML": 0,
        "JSON_RPC": 0,
        "GENERIC_WEB": 0,
    }

    # Fast indexed SQL aggregation for events with populated api_protocol column (PERF-PBL6-002)
    grouped_rows = (
        db.query(SecurityEvent.api_protocol, func.count(SecurityEvent.id))
        .filter(SecurityEvent.api_protocol.isnot(None))
        .group_by(SecurityEvent.api_protocol)
        .all()
    )
    for proto_key, cnt in grouped_rows:
        norm = str(proto_key).upper() if proto_key else "REST"
        if norm in protocol_counts:
            protocol_counts[norm] += int(cnt)
        else:
            protocol_counts["REST"] += int(cnt)

    # Legacy fallback strictly for historical rows where api_protocol IS NULL
    legacy_rows = (
        db.query(SecurityEvent.details)
        .filter(SecurityEvent.api_protocol.is_(None), SecurityEvent.details.isnot(None))
        .all()
    )
    for (details_str,) in legacy_rows:
        if details_str:
            try:
                data = json.loads(details_str)
                proto = data.get("api_protocol") or data.get("protocol")
                if proto and proto.upper() in protocol_counts:
                    protocol_counts[proto.upper()] += 1
                else:
                    protocol_counts["REST"] += 1
            except Exception:
                protocol_counts["REST"] += 1

    total = sum(protocol_counts.values())

    meta = {
        "REST": {"name": "RESTful API", "color": "#3b82f6", "description": "JSON / OpenAPI 3.0 endpoints"},
        "GRAPHQL": {"name": "GraphQL API", "color": "#e10098", "description": "Queries, Mutations & AST Traversal"},
        "SOAP_XML": {"name": "SOAP / XML", "color": "#f59e0b", "description": "XML Envelopes & WSDL Services"},
        "JSON_RPC": {"name": "JSON-RPC 2.0", "color": "#10b981", "description": "Microservice Remote Procedure Calls"},
        "GENERIC_WEB": {"name": "Generic Web", "color": "#8b5cf6", "description": "HTML / Form-encoded Endpoints"},
    }

    result = []
    for key, info in meta.items():
        cnt = protocol_counts.get(key, 0)
        pct = round((cnt / total) * 100, 1) if total > 0 else 0.0
        result.append({
            "name": info["name"],
            "key": key,
            "count": cnt,
            "percentage": pct,
            "color": info["color"],
            "description": info["description"],
        })
    return result


@router.get("/topology", summary="Get distributed cyber range network topology and telemetry")
async def get_cyber_range_topology(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Returns real-time distributed Cyber Range network topology conforming to Ref 17 (Elsevier)."""
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    blocked_events = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.action.in_(["BLOCK", "BLOCKED"])).scalar() or 0
    total_requests = db.query(func.count(RequestLog.id)).scalar() or 0

    active_waf_mode = settings.waf_mode
    try:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if cfg and cfg.value:
            active_waf_mode = cfg.value
    except Exception:
        pass

    target_status, target_latency_ms = await check_target_upstream(
        request, settings.target_api_url.rstrip("/")
    )

    newest_event = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).first()
    red_team_ip = newest_event.client_ip if (newest_event and newest_event.client_ip) else "No active attacker"
    blue_team_ip = request.url.hostname or settings.app_host

    def _derive_subnet(ip_addr: str) -> str:
        parts = ip_addr.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "Local / Loopback"

    derived_subnet = (
        _derive_subnet(red_team_ip)
        if red_team_ip != "No active attacker" and "." in red_team_ip
        else _derive_subnet(blue_team_ip)
    )

    packet_loss_pct = 0.0 if target_status != "unreachable" else 100.0
    net_status = "optimal" if target_status == "ok" else target_status

    try:
        parsed_target = urllib.parse.urlparse(settings.target_api_url)
        target_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
    except Exception:
        target_port = 5000

    return {
        "red_team": {
            "name": "Red Team Host (Máy 2)",
            "ip": red_team_ip,
            "role": "Autonomous Offensive AI Agent",
            "status": "active" if total_events > 0 else "idle",
            "agent_model": "Autonomous Attack Suite",
            "attacks_generated": total_events,
        },
        "network": {
            "type": "Physical LAN Boundary (802.3 Ethernet / 802.11 Wi-Fi)",
            "subnet": derived_subnet,
            "rtt_latency_ms": target_latency_ms,
            "jitter_ms": 0.0,
            "packet_loss_pct": packet_loss_pct,
            "status": net_status,
        },
        "blue_team": {
            "name": "Blue Team Host (Máy 1)",
            "ip": blue_team_ip,
            "waf_port": settings.app_port,
            "mode": active_waf_mode,
            "pipeline": "Rule Engine + XGBoost v2.0 + Isolation Forest v2.0",
            "inspected_count": total_requests,
            "blocked_count": blocked_events,
        },
        "target_api": {
            "name": "Bookie Bookstore (Target API)",
            "port": target_port,
            "url": settings.target_api_url,
            "status": target_status,
            "flaws_monitored": [
                "SQLi",
                "XSS",
                "Path Traversal",
                "Command Injection",
                "SSRF",
                "NoSQLi",
                "Mass Assignment",
                "BOLA/IDOR",
                "Response DLP",
            ],
        },
        "soc_monitoring": {
            "name": "SOC Situational Awareness Dashboard",
            "port": 3000,
            "url": f"http://{request.url.hostname or settings.app_host}:3000",
            "status": "live",
        },
    }


def _validate_cyber_range_target_url(target_url: str, configured_target: str) -> str:
    """Enforces CWE-918 anti-open-proxy whitelist on optional simulator target_url."""
    import ipaddress

    raw = target_url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid target_url: must be an http/https URL within the Cyber Range.",
        )
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="Invalid target_url: embedded credentials are forbidden (CWE-918).",
        )

    host = parsed.hostname.lower()
    cfg_host = (urllib.parse.urlparse(configured_target).hostname or "").lower()
    allowed_named_hosts = {"localhost", "vulnerable-api"}
    if cfg_host:
        allowed_named_hosts.add(cfg_host)

    if host in allowed_named_hosts:
        return raw

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"target_url host '{host}' rejected by Cyber Range CWE-918 anti-open-proxy policy.",
        ) from exc

    if ip_obj.is_link_local or str(ip_obj).startswith("169.254."):
        raise HTTPException(
            status_code=400,
            detail="Cloud link-local metadata addresses are strictly forbidden (CWE-918).",
        )
    if not (ip_obj.is_loopback or ip_obj.is_private):
        raise HTTPException(
            status_code=400,
            detail=f"External public IP '{host}' is forbidden by Cyber Range anti-open-proxy policy.",
        )
    return raw


def _resolve_openapi_sim_path(
    keyword: str,
    method: str,
    fallback_path: str,
    spec_paths: dict[str, Any] | None = None,
) -> str:
    """Dynamically resolves an active OpenAPI path matching `keyword` & `method`."""
    from app.api.proxy import get_schema_validator

    paths = spec_paths if spec_paths is not None else ((get_schema_validator()._spec or {}).get("paths", {}))
    m_low = method.lower()
    for raw_path, ops in paths.items():
        if isinstance(ops, dict) and m_low in ops and keyword.lower() in raw_path.lower():
            return raw_path
    return fallback_path


@router.post("/simulate", summary="Execute real test request through proxy", dependencies=[Depends(require_admin)])
async def simulate_attack_request(
    request: Request,
    payload: SimulateRequest,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Fires a genuine HTTP request through the Gateway's proxy using OpenAPI-resolved routes."""
    attack_upper = payload.attack_type.upper()

    dynamic_spec_paths: dict[str, Any] | None = None
    validated_target: str | None = None
    if payload.target_url:
        validated_target = _validate_cyber_range_target_url(payload.target_url, settings.target_api_url)
        try:
            async with httpx.AsyncClient(timeout=0.8) as probe_client:
                for cand in ("/api/v1/vulnerable/openapi.json", "/openapi.json", "/api/schema/"):
                    r_spec = await probe_client.get(f"{validated_target}{cand}")
                    if r_spec.status_code == 200:
                        data = r_spec.json()
                        if isinstance(data, dict) and isinstance(data.get("paths"), dict):
                            dynamic_spec_paths = data["paths"]
                            break
        except Exception:
            dynamic_spec_paths = None

    search_p = _resolve_openapi_sim_path("search", "get", "/api/v1/vulnerable/books/search/", dynamic_spec_paths)
    review_p = _resolve_openapi_sim_path("review", "post", "/api/v1/vulnerable/reviews/", dynamic_spec_paths)
    download_p = _resolve_openapi_sim_path("download", "get", "/api/v1/vulnerable/files/download/", dynamic_spec_paths)
    ping_p = _resolve_openapi_sim_path("ping", "post", "/api/v1/vulnerable/admin/ping/", dynamic_spec_paths)
    ssrf_p = _resolve_openapi_sim_path("fetch", "get", "/api/v1/vulnerable/books/fetch-cover/", dynamic_spec_paths)
    order_tpl = _resolve_openapi_sim_path("order", "get", "/api/v1/vulnerable/orders/{order_id}/", dynamic_spec_paths)
    profile_p = _resolve_openapi_sim_path("profile", "post", "/api/v1/vulnerable/users/profile/update/", dynamic_spec_paths)
    users_p = _resolve_openapi_sim_path("list", "get", "/api/v1/vulnerable/users/list/", dynamic_spec_paths)

    transport = httpx.ASGITransport(app=request.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
        if attack_upper == "SQLI":
            res = await client.get(
                f"/api/proxy{search_p}?q=Python%27%20OR%201%3D1--",
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "SQL_INJECTION",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired SQL Injection payload (' OR 1=1--) to {search_p}.",
            }
        elif attack_upper == "XSS":
            res = await client.post(
                f"/api/proxy{review_p}",
                json={"book_id": 1, "author": "PBL6-Simulator", "comment": "<script>alert('PBL6')</script>"},
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "XSS",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired XSS payload (<script>alert('PBL6')</script>) to {review_p}.",
            }
        elif attack_upper == "PATH":
            res = await client.get(
                f"/api/proxy{download_p}?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "PATH_TRAVERSAL",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired Path Traversal payload (../../etc/passwd) to {download_p}.",
            }
        elif attack_upper == "CMD":
            res = await client.post(
                f"/api/proxy{ping_p}",
                json={"host": "127.0.0.1; whoami"},
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "COMMAND_INJECTION",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired Command Injection payload (; whoami) to {ping_p}.",
            }
        elif attack_upper == "SSRF":
            res = await client.get(
                f"/api/proxy{ssrf_p}?url=http://169.254.169.254/latest/meta-data/",
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "SSRF",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired Cloud IMDS SSRF payload to {ssrf_p}.",
            }
        elif attack_upper in ("NOSQL", "NOSQLI"):
            login_p = _resolve_openapi_sim_path("login", "post", "/api/v1/vulnerable/auth/login/")
            res = await client.post(
                f"/api/proxy{login_p}",
                json={"username": {"$ne": ""}, "password": {"$gt": ""}},
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "NOSQL_INJECTION",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired NoSQL Operator Injection ($ne / $gt) to {login_p}.",
            }
        elif attack_upper in ("BOLA", "IDOR"):
            import re as _re

            res = None
            for oid in (1, 2, 3, 4):
                resolved_order = _re.sub(r"\{[^}]+\}", str(oid), order_tpl)
                res = await client.get(
                    f"/api/proxy{resolved_order}",
                    headers={"User-Agent": "PBL6-Simulator/3.0"},
                )
            assert res is not None
            return {
                "status": "success",
                "simulated": "BOLA_IDOR",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired 4-ID horizontal BOLA/IDOR enumeration burst against {order_tpl}.",
            }
        elif attack_upper in ("MASS", "MASS_ASSIGNMENT"):
            res = await client.post(
                f"/api/proxy{profile_p}",
                json={"email": "attacker@lab.local", "role": "admin", "is_staff": True, "is_superuser": True},
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "MASS_ASSIGNMENT",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired Mass Assignment privilege escalation payload to {profile_p}.",
            }
        elif attack_upper in ("DATA_EXPOSURE", "EXPOSURE", "DLP"):
            res = await client.get(
                f"/api/proxy{users_p}",
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "EXCESSIVE_DATA_EXPOSURE",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "dlp_redacted": res.headers.get("X-WAF-DLP-Redacted") == "true",
                "request_id_header": res.headers.get("X-Request-ID"),
                "message": f"Fired Data Exposure probe to {users_p} (Response DLP inspected).",
            }
        elif attack_upper in ("SOAP", "SOAP_XXE", "XXE"):
            xxe_body = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soapenv:Body><searchBooks><title>&xxe;</title></searchBooks></soapenv:Body>'
                "</soapenv:Envelope>"
            )
            res = await client.post(
                f"/api/proxy{review_p}",
                content=xxe_body.encode("utf-8"),
                headers={"Content-Type": "application/soap+xml", "User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "SOAP_XXE",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired SOAP XML External Entity (XXE) injection payload.",
            }
        elif attack_upper in ("GRAPHQL", "GRAPHQL_SQLI"):
            res = await client.post(
                f"/api/proxy{review_p}",
                json={"query": "query { books(q: \"' OR 1=1--\") { id title } }"},
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "GRAPHQL_SQLI",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired GraphQL query with embedded SQL Injection payload.",
            }
        else:  # BENIGN
            res = await client.get(
                f"/api/proxy{search_p}?q=Clean+Code",
                headers={"User-Agent": "PBL6-Simulator/3.0"},
            )
            return {
                "status": "success",
                "simulated": "BENIGN",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": f"Fired legitimate benign book search request (Clean Code) to {search_p}.",
            }


@router.post("/reset-demo", summary="Reset lab demonstration records", dependencies=[Depends(require_admin)])
def reset_demo_data(db: Session = Depends(get_db)) -> dict[str, str]:
    """Cleans test records from SQLite database to prepare for a fresh presentation."""
    from app.api.proxy import invalidate_waf_mode_cache
    from app.db.models import AuditLog

    prev_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    prev_requests = db.query(func.count(RequestLog.id)).scalar() or 0
    db.query(SecurityEvent).delete()
    db.query(RequestLog).delete()
    db.add(
        AuditLog(
            actor="admin",
            action="RESET_DEMO",
            key="demo_data",
            old_value=f"events={prev_events},requests={prev_requests}",
            new_value="events=0,requests=0",
        )
    )
    db.commit()
    invalidate_waf_mode_cache()
    return {
        "status": "ok",
        "message": "Security events and request logs reset successfully for clean demonstration.",
    }


@router.post("/seed-demo", summary="Seed rich demo traffic and security incidents", dependencies=[Depends(require_admin)])
def seed_demo_data_endpoint(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Populates ~125 realistic HTTP requests and 36 security incidents spanning the last 60 minutes."""
    from app.db.models import AuditLog
    from app.services.seeder import seed_demo_dataset

    result = seed_demo_dataset(db)
    db.add(
        AuditLog(
            actor="admin",
            action="SEED_DEMO",
            key="demo_data",
            old_value=None,
            new_value=f"requests={result.get('total_requests', 0)},events={result.get('total_events', 0)}",
        )
    )
    db.commit()
    return result


class ToggleWafModeRequest(BaseModel):
    mode: str | None = Field(
        default=None,
        description="Optional explicit mode: MONITOR_ONLY, ACTIVE_BLOCKING, or OFF. Omit to toggle.",
    )
    waf_mode: str | None = Field(
        default=None,
        description="Backward-compatible alias for mode.",
    )


@router.post("/toggle-waf-mode", summary="Toggle or set WAF mode between MONITOR_ONLY and ACTIVE_BLOCKING", dependencies=[Depends(require_admin)])
def toggle_waf_mode_endpoint(
    payload: ToggleWafModeRequest | None = Body(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Toggles or explicitly sets runtime WAF operational mode (MONITOR_ONLY / ACTIVE_BLOCKING / OFF)."""
    from app.api.proxy import invalidate_waf_mode_cache
    from app.db.models import AuditLog

    cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
    current_mode = cfg.value if (cfg and cfg.value) else settings.waf_mode

    requested_raw = None
    if payload is not None:
        requested_raw = payload.mode or payload.waf_mode

    if requested_raw:
        normalized = requested_raw.strip().upper()
        if normalized == "ACTIVE_BLOCK":
            normalized = "ACTIVE_BLOCKING"
        if normalized not in ("MONITOR_ONLY", "ACTIVE_BLOCKING", "OFF"):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid waf_mode '{requested_raw}'. Expected MONITOR_ONLY, ACTIVE_BLOCKING, or OFF.",
            )
        new_mode = normalized
    else:
        new_mode = "ACTIVE_BLOCKING" if current_mode == "MONITOR_ONLY" else "MONITOR_ONLY"

    if cfg:
        cfg.value = new_mode
    else:
        cfg = WafConfigModel(key="waf_mode", value=new_mode)
        db.add(cfg)
    db.add(
        AuditLog(
            actor="admin",
            action="TOGGLE_WAF_MODE",
            key="waf_mode",
            old_value=current_mode,
            new_value=new_mode,
        )
    )
    db.commit()
    invalidate_waf_mode_cache()

    return {
        "status": "success",
        "waf_mode": new_mode,
        "message": f"Chế độ WAF đã chuyển sang [{new_mode}] thành công!",
    }




@router.get("/sessions", summary="Get aggregated attack sessions correlated by kill chain")
def get_attack_sessions(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=50),
    client_ip: str | None = None,
    stage: str | None = None,
) -> dict[str, Any]:
    """Returns aggregated attack sessions correlated across time windows and kill-chain stages (Master Plan B4)."""
    base_query = db.query(SecurityEvent).filter(SecurityEvent.session_id.isnot(None))

    if client_ip and client_ip.strip():
        base_query = base_query.filter(SecurityEvent.client_ip == client_ip.strip())

    if stage and stage.strip() and stage.upper() != "ALL":
        base_query = base_query.filter(SecurityEvent.kill_chain_stage == stage.strip().upper())

    # Get distinct session IDs ordered by latest activity
    session_rows = (
        base_query.with_entities(
            SecurityEvent.session_id,
            SecurityEvent.client_ip,
            func.min(SecurityEvent.timestamp).label("start_time"),
            func.max(SecurityEvent.timestamp).label("end_time"),
            func.count(SecurityEvent.id).label("total_events"),
            func.max(SecurityEvent.risk_score).label("max_risk"),
        )
        .group_by(SecurityEvent.session_id, SecurityEvent.client_ip)
        .order_by(func.max(SecurityEvent.timestamp).desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    total_sessions_count = (
        base_query.with_entities(SecurityEvent.session_id)
        .distinct()
        .count()
    )

    # Batch-fetch all session events in a single query to eliminate N+1 SQL (LOGIC-PBL6-005)
    session_ids = [row.session_id for row in session_rows if row.session_id]
    all_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id.in_(session_ids))
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    ) if session_ids else []

    events_by_session: dict[str, list[SecurityEvent]] = {}
    for ev in all_events:
        if ev.session_id:
            events_by_session.setdefault(ev.session_id, []).append(ev)

    items = []
    for row in session_rows:
        sess_id = row.session_id
        sess_events = events_by_session.get(sess_id, [])

        stages_seen = []
        attack_types_seen = set()
        has_blocked = False

        event_summaries = []
        for ev in sess_events:
            stage_name = ev.kill_chain_stage or "EXPLOITATION"
            if stage_name not in stages_seen:
                stages_seen.append(stage_name)
            attack_types_seen.add(ev.attack_type)
            if ev.action in ("BLOCK", "BLOCKED"):
                has_blocked = True

            event_summaries.append({
                "event_id": ev.event_id,
                "request_id": ev.request_id,
                "timestamp": ev.timestamp.isoformat(),
                "attack_type": ev.attack_type,
                "severity": ev.severity,
                "action": ev.action,
                "risk_score": ev.risk_score,
                "kill_chain_stage": stage_name,
            })

        duration_sec = 0.0
        if row.start_time and row.end_time:
            duration_sec = max(0.0, (row.end_time - row.start_time).total_seconds())

        items.append({
            "session_id": sess_id,
            "client_ip": row.client_ip,
            "start_time": row.start_time.isoformat() if row.start_time else None,
            "end_time": row.end_time.isoformat() if row.end_time else None,
            "duration_seconds": round(duration_sec, 1),
            "total_events": row.total_events,
            "max_risk_score": row.max_risk or 0.0,
            "kill_chain_stages": stages_seen,
            "attack_types": sorted(list(attack_types_seen)),
            "has_blocked": has_blocked,
            "events": event_summaries,
        })

    return {
        "total": total_sessions_count,
        "page": page,
        "limit": limit,
        "items": items,
    }
