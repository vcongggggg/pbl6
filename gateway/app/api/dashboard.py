import datetime
import json
import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.models import RequestLog, SecurityEvent
from app.db.session import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class SimulateRequest(BaseModel):
    attack_type: str = Field(
        ...,
        description="Type of attack to simulate: SQLI, XSS, PATH, CMD, or BENIGN",
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
    """Computes genuine real-time statistics directly from SQLite tables."""
    total_requests = db.query(RequestLog).count()
    attacks_detected = db.query(SecurityEvent).count()
    safe_requests = max(0, total_requests - attacks_detected)

    safe_request_rate = (
        round((safe_requests / total_requests) * 100, 1) if total_requests > 0 else 100.0
    )

    avg_threat_score = (
        db.query(func.avg(SecurityEvent.rule_score)).scalar() or 0.0
    )

    # Breakdown by attack family
    attack_counts = (
        db.query(SecurityEvent.attack_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.attack_type)
        .all()
    )
    family_counts = {str(k): int(v) for k, v in attack_counts}

    # Ping target upstream
    target_status, target_latency_ms = await check_target_upstream(
        request, settings.target_api_url.rstrip("/")
    )

    return {
        "total_requests": total_requests,
        "attacks_detected": attacks_detected,
        "safe_requests": safe_requests,
        "safe_request_rate": safe_request_rate,
        "avg_threat_score": round(float(avg_threat_score), 1),
        "family_counts": family_counts,
        "target_status": target_status,
        "target_latency_ms": target_latency_ms,
        "target_url": settings.target_api_url,
        "waf_mode": settings.waf_mode,
        "active_phase": "Phase 2 (Rule Engine Active)",
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

        rule_matches = details_obj.get("rule_matches", [])
        if rule_matches and isinstance(rule_matches, list):
            first_match = rule_matches[0]
            rule_id = first_match.get("rule_id", "UNKNOWN")
            location = first_match.get("location", "PAYLOAD")
            rule_name = first_match.get("name", ev.attack_type)
            evidence_snippet = first_match.get("evidence", "")

        items.append({
            "event_id": ev.event_id,
            "request_id": ev.request_id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
            "client_ip": ev.client_ip,
            "attack_type": ev.attack_type,
            "severity": ev.severity,
            "action": ev.action,
            "rule_score": ev.rule_score or 0.0,
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
    now = datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(minutes=minutes)

    # Fetch request counts grouped by minute
    req_rows = (
        db.query(
            func.strftime("%H:%M", RequestLog.timestamp).label("minute"),
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
            func.strftime("%H:%M", SecurityEvent.timestamp).label("minute"),
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
        timeline.append({
            "time": k,
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


@router.post("/simulate", summary="Execute real test request through proxy")
async def simulate_attack_request(
    request: Request,
    payload: SimulateRequest,
) -> dict[str, Any]:
    """Fires a genuine HTTP request through the Gateway's proxy to trigger detection."""
    attack_upper = payload.attack_type.upper()

    transport = httpx.ASGITransport(app=request.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
        if attack_upper == "SQLI":
            res = await client.get(
                "/api/proxy/rest/products/search?q=apple%27%20OR%201%3D1--",
                headers={"User-Agent": "PBL6-Simulator/1.0"},
            )
            return {
                "status": "success",
                "simulated": "SQL_INJECTION",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired SQL Injection payload (' OR 1=1--) through proxy pipeline.",
            }
        elif attack_upper == "XSS":
            res = await client.post(
                "/api/proxy/api/Feedbacks",
                json={"comment": "<script>alert('PBL6')</script>", "rating": 5},
                headers={"User-Agent": "PBL6-Simulator/1.0"},
            )
            return {
                "status": "success",
                "simulated": "XSS",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired XSS payload (<script>alert('PBL6')</script>) in JSON body.",
            }
        elif attack_upper == "PATH":
            res = await client.get(
                "/api/proxy/rest/products/search?file=..%2f..%2fetc%2fpasswd",
                headers={"User-Agent": "PBL6-Simulator/1.0"},
            )
            return {
                "status": "success",
                "simulated": "PATH_TRAVERSAL",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired Path Traversal payload (../../etc/passwd) through query string.",
            }
        elif attack_upper == "CMD":
            res = await client.get(
                "/api/proxy/api/system/ping?host=127.0.0.1%3B%20whoami",
                headers={"User-Agent": "PBL6-Simulator/1.0"},
            )
            return {
                "status": "success",
                "simulated": "COMMAND_INJECTION",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired Command Injection payload (; whoami) through query parameter.",
            }
        else:  # BENIGN
            res = await client.get(
                "/api/proxy/rest/products/search?q=fresh+apple+juice",
                headers={"User-Agent": "PBL6-Simulator/1.0"},
            )
            return {
                "status": "success",
                "simulated": "BENIGN",
                "status_code": res.status_code,
                "request_id": res.headers.get("X-Request-ID"),
                "message": "Fired legitimate benign search request (fresh apple juice).",
            }


@router.post("/reset-demo", summary="Reset lab demonstration records")
def reset_demo_data(db: Session = Depends(get_db)) -> dict[str, str]:
    """Cleans test records from SQLite database to prepare for a fresh presentation."""
    db.query(SecurityEvent).delete()
    db.query(RequestLog).delete()
    db.commit()
    return {
        "status": "ok",
        "message": "Security events and request logs reset successfully for clean demonstration.",
    }
