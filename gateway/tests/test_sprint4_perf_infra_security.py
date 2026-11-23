"""Sprint 4 Final Verification Suite: PERF-PBL6-001/002, SEC-PBL6-007, INFRA-PBL6-001, QUAL-PBL6-001, ARCH-PBL6-001."""

import asyncio
import importlib.util
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.api.proxy import (
    _WAF_MODE_CACHE,
    get_rate_limiter,
    invalidate_waf_mode_cache,
)
from app.core.config import get_settings
from app.db.models import AuditLog, RequestLog, SecurityEvent, WafConfigModel
from app.db.session import SessionLocal
from app.main import app
from app.services.proxy import (
    ProxyService,
    filter_request_headers,
    filter_response_header_items,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ADMIN_HEADERS = {"X-API-Key": get_settings().admin_api_key}


def _set_db_waf_mode(mode: str | None) -> str | None:
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        prev = cfg.value if cfg else None
        if mode is None:
            if cfg is not None:
                db.delete(cfg)
        elif cfg is not None:
            cfg.value = mode
        else:
            db.add(WafConfigModel(key="waf_mode", value=mode))
        db.commit()
        return prev


# ---------------------------------------------------------------------------
# PERF-PBL6-001: High-Concurrency Async, RAM Cache & Real Latency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_perf_001_high_concurrency_async_non_blocking_and_real_latency():
    """Verifies async proxy handles 25 concurrent requests cleanly with real latency and BackgroundTasks."""
    limiter = get_rate_limiter()
    limiter.reset()
    prev_limit = limiter.default_limit
    limiter.default_limit = 10000
    prev_mode = _set_db_waf_mode("ACTIVE_BLOCKING")
    invalidate_waf_mode_cache()
    try:
        def _mock_upstream(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{"id": 1, "title": "Clean Code"}]})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_mock_upstream), timeout=10.0
        ) as upstream_client:
            app.state.http_client = upstream_client
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver", timeout=20.0
            ) as async_client:
                tasks = [
                    async_client.get(
                        "/api/proxy/api/v1/vulnerable/books/search/?q=Clean+Code",
                        headers={"X-Request-ID": f"async-conc-{i}"},
                    )
                    for i in range(25)
                ]
                responses = await asyncio.gather(*tasks)

        assert all(r.status_code == 200 for r in responses)
        assert len(_WAF_MODE_CACHE) >= 1

        with SessionLocal() as db:
            logs = (
                db.query(RequestLog)
                .filter(RequestLog.request_id.like("async-conc-%"))
                .all()
            )
            assert len(logs) == 25
            # Every logged latency must be genuinely measured (> 0.0)
            assert all(log.response_time_ms is not None and log.response_time_ms > 0.0 for log in logs)
    finally:
        limiter.default_limit = prev_limit
        _set_db_waf_mode(prev_mode)


def test_perf_001_waf_mode_cache_invalidated_on_toggle(client: TestClient):
    """Toggling WAF mode invalidates _WAF_MODE_CACHE and writes AuditLog."""
    invalidate_waf_mode_cache()
    prev_mode = _set_db_waf_mode("MONITOR_ONLY")
    try:
        res = client.post("/dashboard/toggle-waf-mode", headers=ADMIN_HEADERS)
        assert res.status_code == 200
        assert res.json()["waf_mode"] == "ACTIVE_BLOCKING"
        assert len(_WAF_MODE_CACHE) == 0

        with SessionLocal() as db:
            audit = (
                db.query(AuditLog)
                .filter(AuditLog.action == "TOGGLE_WAF_MODE")
                .order_by(AuditLog.id.desc())
                .first()
            )
            assert audit is not None
            assert audit.key == "waf_mode"
            assert audit.old_value == "MONITOR_ONLY"
            assert audit.new_value == "ACTIVE_BLOCKING"
    finally:
        _set_db_waf_mode(prev_mode)


# ---------------------------------------------------------------------------
# PERF-PBL6-002: AuditLog, Indexed api_protocol & Proxy Client Hygiene
# ---------------------------------------------------------------------------


def test_perf_002_audit_log_recorded_for_reset_and_seed_demo(client: TestClient):
    """Admin mutating endpoints /reset-demo and /seed-demo persist AuditLog entries."""
    with SessionLocal() as db:
        db.query(AuditLog).delete()
        db.commit()

    r_reset = client.post("/dashboard/reset-demo", headers=ADMIN_HEADERS)
    assert r_reset.status_code == 200
    r_seed = client.post("/dashboard/seed-demo", headers=ADMIN_HEADERS)
    assert r_seed.status_code == 200

    with SessionLocal() as db:
        actions = {row.action for row in db.query(AuditLog).all()}
        assert "RESET_DEMO" in actions
        assert "SEED_DEMO" in actions


@respx.mock
def test_perf_002_api_protocol_column_indexed_and_grouped(client: TestClient):
    """SecurityEvent.api_protocol is persisted on attack detection and aggregated in /dashboard/protocols."""
    prev_mode = _set_db_waf_mode("ACTIVE_BLOCKING")
    try:
        with SessionLocal() as db:
            db.query(SecurityEvent).delete()
            db.commit()

        gql_sqli = b'{"query": "query { book(id: \\"1\' UNION SELECT username, password FROM users--\\") { title } }"}'
        res = client.post(
            "/api/proxy/api/v1/graphql",
            headers={"Content-Type": "application/json"},
            content=gql_sqli,
        )
        assert res.status_code == 403
        req_id = res.headers["X-Request-ID"]

        with SessionLocal() as db:
            ev = db.query(SecurityEvent).filter(SecurityEvent.request_id == req_id).first()
            assert ev is not None
            assert ev.api_protocol == "GRAPHQL"

        proto_res = client.get("/dashboard/protocols", headers=ADMIN_HEADERS)
        assert proto_res.status_code == 200
        proto_map = {item["key"]: item["count"] for item in proto_res.json()}
        assert proto_map["GRAPHQL"] >= 1
    finally:
        _set_db_waf_mode(prev_mode)


@pytest.mark.asyncio
async def test_perf_002_proxy_service_closes_temporary_client():
    """When ProxyService is created without a shared client, temporary AsyncClient is closed in finally."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.request.return_value = httpx.Response(200, json={"ok": True})
    svc = ProxyService(settings=get_settings(), client=None)

    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/proxy/health",
        "query_string": b"",
        "headers": [],
    }
    dummy_req = StarletteRequest(scope)
    with patch.object(svc, "get_client", return_value=mock_client):
        resp, _lat, _sz = await svc.forward(dummy_req, "health", "req-close-test", b"")
    assert resp.status_code == 200
    mock_client.aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# SEC-PBL6-007: X-API-Key Stripping, Multi Set-Cookie, Circular $ref, VNPay HMAC
# ---------------------------------------------------------------------------


@respx.mock
def test_sec_007_x_api_key_stripped_and_multi_set_cookie_preserved(client: TestClient):
    """X-API-Key is never forwarded to upstream; multiple Set-Cookie headers are preserved intact."""
    filtered = filter_request_headers(
        {"X-API-Key": "super-secret-admin-key", "X-Custom": "keep-me", "Connection": "keep-alive"}
    )
    assert "X-API-Key" not in filtered
    assert "x-api-key" not in {k.lower() for k in filtered}
    assert filtered.get("X-Custom") == "keep-me"

    multi_headers = httpx.Headers([
        ("set-cookie", "session=abc123; Path=/; HttpOnly"),
        ("set-cookie", "csrf=xyz789; Path=/; SameSite=Lax"),
        ("content-type", "application/json"),
    ])
    items = filter_response_header_items(multi_headers)
    cookies = [v for k, v in items if k.lower() == "set-cookie"]
    assert len(cookies) == 2

    prev_mode = _set_db_waf_mode("MONITOR_ONLY")
    try:
        route = respx.get("http://vulnerable-api:5000/api/v1/session/init").mock(
            return_value=Response(
                200,
                content=json.dumps({"ok": True}).encode("utf-8"),
                headers=[
                    ("content-type", "application/json"),
                    ("set-cookie", "sid=111; Path=/"),
                    ("set-cookie", "theme=dark; Path=/"),
                ],
            )
        )
        res = client.get(
            "/api/proxy/api/v1/session/init",
            headers={"X-API-Key": "dev-admin-secret-key-change-me"},
        )
        assert res.status_code == 200
        assert route.called
        sent_headers = {k.lower() for k in route.calls.last.request.headers.keys()}
        assert "x-api-key" not in sent_headers
        returned_cookies = res.headers.get_list("set-cookie")
        assert len(returned_cookies) == 2
        assert any("sid=111" in c for c in returned_cookies)
        assert any("theme=dark" in c for c in returned_cookies)
    finally:
        _set_db_waf_mode(prev_mode)


def test_sec_007_recon_circular_ref_guard():
    """APIReconAgent.resolve_ref safely terminates on circular OpenAPI $ref cycles."""
    import sys

    recon_path = REPO_ROOT / "attack-lab" / "agent" / "recon.py"
    spec = importlib.util.spec_from_file_location("pbl6_recon_module", recon_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(spec.name, None)

    agent = mod.APIReconAgent()
    agent.raw_spec = {
        "components": {
            "schemas": {
                "NodeA": {"$ref": "#/components/schemas/NodeB"},
                "NodeB": {"$ref": "#/components/schemas/NodeA"},
            }
        }
    }
    resolved = agent.resolve_ref("#/components/schemas/NodeA")
    assert resolved == {}


def test_sec_007_vnpay_uses_hmac_compare_digest():
    """VNPay.validate_response uses constant-time hmac.compare_digest and rejects tampered/missing hashes."""
    vnpay_path = REPO_ROOT / "vulnerable-api" / "books" / "vnpay.py"
    source = vnpay_path.read_text(encoding="utf-8")
    assert "hmac.compare_digest" in source

    spec = importlib.util.spec_from_file_location("pbl6_vnpay_module", vnpay_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    vnp = mod.VNPay("TMN01", "SECRET_KEY_TEST", "http://localhost/ret", "http://localhost/pay")
    url = vnp.get_payment_url("ORD100", 50000, "TestOrder", "127.0.0.1")
    from urllib.parse import parse_qs, urlparse

    qs = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    assert vnp.validate_response(qs) is True
    assert vnp.validate_response({**qs, "vnp_SecureHash": "0" * 128}) is False
    assert vnp.validate_response({k: v for k, v in qs.items() if k != "vnp_SecureHash"}) is False


# ---------------------------------------------------------------------------
# INFRA-PBL6-001 & ARCH-PBL6-001: Dockerfiles, .dockerignore, ESLint & Anti-Drift
# ---------------------------------------------------------------------------


def test_infra_and_arch_hardening_artifacts():
    """Verifies non-root Dockerfiles, Node 20, .dockerignore files, compose default WAF_MODE, and ESLint config."""
    for rel in (
        "gateway/.dockerignore",
        "dashboard/.dockerignore",
        "vulnerable-api/.dockerignore",
        "dashboard/.eslintrc.json",
    ):
        assert (REPO_ROOT / rel).exists(), f"Missing required hardening file: {rel}"

    gw_df = (REPO_ROOT / "gateway" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER appuser" in gw_df and "appuser" in gw_df

    vuln_df = (REPO_ROOT / "vulnerable-api" / "Dockerfile").read_text(encoding="utf-8")
    assert "USER appuser" in vuln_df and "appuser" in vuln_df

    dash_df = (REPO_ROOT / "dashboard" / "Dockerfile").read_text(encoding="utf-8")
    assert "node:20-alpine" in dash_df and "npm ci" in dash_df

    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "${WAF_MODE:-ACTIVE_BLOCKING}" in compose

    # Verify redundant wrapper components were removed
    assert not (REPO_ROOT / "dashboard" / "src" / "components" / "LiveEventsTable.tsx").exists()
    assert not (REPO_ROOT / "dashboard" / "src" / "components" / "PayloadEvidenceDrawer.tsx").exists()

    # Anti-drift: Juice Shop removed from gateway health & README
    health_src = (REPO_ROOT / "gateway" / "app" / "api" / "health.py").read_text(encoding="utf-8")
    assert "juice shop" not in health_src.lower()
    readme_src = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "juice shop" not in readme_src.lower()
    assert "attack-lab/cli.py" not in readme_src
