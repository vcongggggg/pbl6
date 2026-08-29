import asyncio
import json
import os
import sqlite3
import sys

# Ensure gateway package is on sys.path
sys.path.insert(0, os.path.abspath("gateway"))

import httpx
import uvicorn
from fastapi import FastAPI, Request

# 1. Build a realistic upstream Target server (simulating OWASP Juice Shop)
target_app = FastAPI(title="Mock Juice Shop Target API")


@target_app.get("/")
async def target_root():
    return {"name": "OWASP Juice Shop", "status": "operational"}


@target_app.get("/rest/products/search")
async def search_products(q: str = ""):
    return {
        "status": "success",
        "data": [{"id": 1, "name": f"Juice matching '{q}'", "price": 2.99}],
    }


@target_app.post("/api/Users")
async def create_user(request: Request):
    data = await request.json()
    return {"status": "success", "data": {"id": 42, "email": data.get("email")}}


async def run_server(app, port):
    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.8)
    return server, task


async def main():
    print("============================================================")
    print("PHASE 1 - REAL GATEWAY LIVE END-TO-END VERIFICATION")
    print("============================================================")

    # Configure Gateway environment
    os.environ["APP_ENV"] = "test"
    os.environ["TARGET_API_URL"] = "http://127.0.0.1:3000"
    os.environ["DATABASE_URL"] = "sqlite:///./data/live_verify_waf.db"

    # Clean up test DB
    if os.path.exists("./data/live_verify_waf.db"):
        try:
            os.remove("./data/live_verify_waf.db")
        except OSError:
            pass

    # Import gateway app after env vars set
    from app.db.session import engine
    from app.main import app as gateway_app

    # 1. Start Upstream Target on port 3000
    print("[1/7] Starting Upstream Target API on http://127.0.0.1:3000...")
    target_server, target_task = await run_server(target_app, 3000)

    # 2. Start Gateway on port 8000
    print("[2/7] Starting FastAPI Gateway on http://127.0.0.1:8000...")
    gateway_server, gateway_task = await run_server(gateway_app, 8000)

    client = httpx.AsyncClient(timeout=10.0)

    try:
        # 3. Test Gateway /health
        print("[3/7] Testing Gateway Health (/health)...")
        r_health = await client.get("http://127.0.0.1:8000/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"
        print("      [PASS] /health returned 200 OK")

        # 4. Test Gateway /health/target (Target is up)
        print("[4/7] Testing Gateway Target Probe (/health/target)...")
        r_target_health = await client.get("http://127.0.0.1:8000/health/target")
        assert r_target_health.status_code == 200
        th_data = r_target_health.json()
        assert th_data["reachable"] is True
        assert th_data["upstream_status"] == 200
        print(
            f"      [PASS] /health/target reachable=True, latency={th_data['latency_ms']}ms"
        )

        # 5. Test Live Proxy GET & POST (Client -> Gateway -> Juice Shop -> Gateway -> Client)
        print("[5/7] Sending real traffic through Gateway to Target...")
        custom_rid = "live-verify-req-1001"
        r_proxy_get = await client.get(
            "http://127.0.0.1:8000/api/proxy/rest/products/search?q=apple",
            headers={"X-Request-ID": custom_rid, "User-Agent": "LiveVerifyClient/1.0"},
        )
        assert r_proxy_get.status_code == 200
        assert r_proxy_get.headers.get("X-Request-ID") == custom_rid
        get_json = r_proxy_get.json()
        assert get_json["data"][0]["name"] == "Juice matching 'apple'"
        print("      [PASS] GET /api/proxy/rest/products/search returned 200 with Target payload")

        post_rid = "live-verify-req-1002"
        r_proxy_post = await client.post(
            "http://127.0.0.1:8000/api/proxy/api/Users",
            json={"email": "demo@pbl6.edu.vn", "password": "SecretPassword999"},
            headers={"X-Request-ID": post_rid, "Authorization": "Bearer secret-demo-token"},
        )
        assert r_proxy_post.status_code == 200
        assert r_proxy_post.headers.get("X-Request-ID") == post_rid
        print("      [PASS] POST /api/proxy/api/Users returned 200 with Target payload")

        # 6. Verify SQLite Database Persistence
        print("[6/7] Inspecting SQLite database records...")
        conn = sqlite3.connect("./data/live_verify_waf.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT request_id, method, path, response_status, response_time_ms, headers, client_ip FROM requests"
        )
        rows = cursor.fetchall()
        assert len(rows) >= 2
        print(f"      [PASS] SQLite contains {len(rows)} recorded traffic rows")
        for row in rows:
            rid, method, path, status_code, latency, headers_str, client_ip = row
            print(
                f"        -> Record: [{rid}] {method} {path} | status={status_code} | latency={latency:.2f}ms | ip={client_ip}"
            )
            headers_dict = json.loads(headers_str)
            if "authorization" in headers_dict:
                assert headers_dict["authorization"] == "[REDACTED]"
                print("           [PASS] Authorization header properly [REDACTED]")
        conn.close()

        # 7. Test Target Down (Controlled 502 behavior)
        print("[7/7] Stopping Upstream Target to verify controlled 502 Bad Gateway...")
        target_server.should_exit = True
        await target_task
        await asyncio.sleep(0.5)

        # Probe target health when target is down
        r_th_down = await client.get("http://127.0.0.1:8000/health/target")
        assert r_th_down.status_code == 200
        assert r_th_down.json()["reachable"] is False
        print("      [PASS] /health/target correctly reports reachable=False")

        # Send request through proxy when target is down
        r_proxy_down = await client.get("http://127.0.0.1:8000/api/proxy/rest/products/search")
        assert r_proxy_down.status_code == 502
        err_json = r_proxy_down.json()
        assert err_json["status"] == "error"
        assert err_json["error"]["code"] == "TARGET_UNAVAILABLE"
        assert "Traceback" not in r_proxy_down.text
        print("      [PASS] Proxy returned controlled 502 Bad Gateway without leaking stack traces")

        print("============================================================")
        print("ALL REAL LIVE END-TO-END VERIFICATION CHECKS PASSED!")
        print("============================================================")

    finally:
        await client.aclose()
        gateway_server.should_exit = True
        await gateway_task
        if not target_server.should_exit:
            target_server.should_exit = True
            await target_task
        engine.dispose()
        if os.path.exists("./data/live_verify_waf.db"):
            try:
                os.remove("./data/live_verify_waf.db")
            except OSError:
                pass


if __name__ == "__main__":
    asyncio.run(main())
