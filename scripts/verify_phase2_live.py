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

# Upstream Target API (simulating OWASP Juice Shop)
target_app = FastAPI(title="Mock Juice Shop Target API")


@target_app.get("/rest/products/search")
async def search_products(q: str = "", file: str = ""):
    return {
        "status": "success",
        "data": [{"id": 1, "name": f"Product query='{q}' file='{file}'"}],
    }


@target_app.post("/api/Feedbacks")
async def create_feedback(request: Request):
    data = await request.json()
    return {"status": "success", "data": data}


@target_app.get("/api/system/ping")
async def ping_system(host: str = ""):
    return {"status": "success", "host": host}


async def run_server(app, port):
    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.8)
    return server, task


async def main():
    print("============================================================")
    print("PHASE 2 - REAL GATEWAY SIGNATURE DETECTION LIVE VERIFICATION")
    print("============================================================")

    db_path = "./data/live_phase2_verify.db"
    os.environ["APP_ENV"] = "test"
    os.environ["TARGET_API_URL"] = "http://127.0.0.1:3000"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    from app.db.session import engine
    from app.main import app as gateway_app

    # 1. Start Upstream Target
    print("[1/6] Starting Upstream Target API on http://127.0.0.1:3000...")
    target_server, target_task = await run_server(target_app, 3000)

    # 2. Start Gateway
    print("[2/6] Starting FastAPI Gateway on http://127.0.0.1:8000...")
    gateway_server, gateway_task = await run_server(gateway_app, 8000)

    client = httpx.AsyncClient(timeout=10.0)

    try:
        # 3. Test SQL Injection Detection
        print("[3/6] Testing SQL Injection detection (Client -> Gateway -> Juice Shop)...")
        r_sqli = await client.get(
            "http://127.0.0.1:8000/api/proxy/rest/products/search?q=apple%27%20OR%201%3D1--",
            headers={"X-Request-ID": "live-p2-sqli-01"},
        )
        assert r_sqli.status_code == 200, "Must be NON-BLOCKING"
        print("      [PASS] SQLi request forwarded non-blocking (200 OK)")

        # 4. Test XSS Detection
        print("[4/6] Testing XSS detection in POST body...")
        r_xss = await client.post(
            "http://127.0.0.1:8000/api/proxy/api/Feedbacks",
            json={"comment": "<script>alert('XSS')</script>", "rating": 5},
            headers={"X-Request-ID": "live-p2-xss-01"},
        )
        assert r_xss.status_code == 200, "Must be NON-BLOCKING"
        print("      [PASS] XSS request forwarded non-blocking (200 OK)")

        # 5. Test Path Traversal & Command Injection Detection
        print("[5/6] Testing Path Traversal & Command Injection...")
        r_path = await client.get(
            "http://127.0.0.1:8000/api/proxy/rest/products/search?file=..%2f..%2fetc%2fpasswd",
            headers={"X-Request-ID": "live-p2-path-01"},
        )
        assert r_path.status_code == 200, "Must be NON-BLOCKING"
        print("      [PASS] Path Traversal request forwarded non-blocking (200 OK)")

        r_cmd = await client.get(
            "http://127.0.0.1:8000/api/proxy/api/system/ping?host=127.0.0.1%3B%20whoami",
            headers={"X-Request-ID": "live-p2-cmd-01"},
        )
        assert r_cmd.status_code == 200, "Must be NON-BLOCKING"
        print("      [PASS] Command Injection request forwarded non-blocking (200 OK)")

        # 6. Test Benign Request (No False Positives)
        print("[6/6] Testing Benign Request (No Security Event)...")
        r_benign = await client.get(
            "http://127.0.0.1:8000/api/proxy/rest/products/search?q=fresh+apple+juice",
            headers={"X-Request-ID": "live-p2-benign-01"},
        )
        assert r_benign.status_code == 200
        print("      [PASS] Benign request forwarded (200 OK)")

        # 7. Database Verification
        print("[DB] Verifying SQLite security_events records & traceability...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT request_id, attack_type, severity, rule_score, action, details FROM security_events"
        )
        sec_rows = cursor.fetchall()
        print(f"      [PASS] security_events table has {len(sec_rows)} recorded attack incidents")
        assert len(sec_rows) == 4, f"Expected exactly 4 attack events, got {len(sec_rows)}"

        detected_types = set()
        for s_row in sec_rows:
            s_rid, s_type, s_sev, s_score, s_action, s_details = s_row
            detected_types.add(s_type)
            print(
                f"        -> Event: [{s_rid}] type={s_type} sev={s_sev} score={s_score} action={s_action}"
            )
            # Verify traceability to requests table
            cursor.execute("SELECT id, path FROM requests WHERE request_id = ?", (s_rid,))
            req_match = cursor.fetchone()
            assert req_match is not None, f"Missing corresponding requests table row for {s_rid}"

        assert "SQL_INJECTION" in detected_types
        assert "XSS" in detected_types
        assert "PATH_TRAVERSAL" in detected_types
        assert "COMMAND_INJECTION" in detected_types
        print("      [PASS] All 4 attack families accurately recorded and traceable!")

        # Verify benign request did NOT create a security event
        cursor.execute(
            "SELECT id FROM security_events WHERE request_id = 'live-p2-benign-01'"
        )
        assert cursor.fetchone() is None, "Benign request must NOT have security_events row"
        print("      [PASS] Zero false positive events created for benign request")

        conn.close()
        print("============================================================")
        print("PHASE 2 LIVE SECURITY VERIFICATION COMPLETED SUCCESSFULLY!")
        print("============================================================")

    finally:
        await client.aclose()
        gateway_server.should_exit = True
        await gateway_task
        target_server.should_exit = True
        await target_task
        engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


if __name__ == "__main__":
    asyncio.run(main())
