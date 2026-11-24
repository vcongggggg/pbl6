"""Orchestrates 3 Live Services and Executes Demo Rehearsal v3.0 Dry Run (Phase C5).

Launches:
1. Target Vulnerable API (Django on 127.0.0.1:5050 or 127.0.0.1:5000)
2. WAF Gateway v3.0 (FastAPI on 127.0.0.1:8000)
3. SOC Dashboard UI (Next.js on 127.0.0.1:3000)

Executes:
`python scripts/demo_rehearsal.py --auto --interval 0.15`
Saves full execution log to `docs/reports/demo_rehearsal_v3_run.log`.
Cleanly terminates all 3 services upon completion.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
LOG_PATH = ROOT_DIR / "docs" / "reports" / "demo_rehearsal_v3_run.log"


def is_service_ready(url: str, timeout: float = 1.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PBL6-RehearsalChecker/3.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 304, 404)
    except Exception:
        return False


def wait_until_ready(name: str, url: str, max_wait: float = 35.0) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        if is_service_ready(url):
            print(f"  [READY] {name} is alive at {url}")
            return True
        time.sleep(0.5)
    print(f"  [TIMEOUT] {name} failed to become ready at {url} within {max_wait}s")
    return False


def terminate_process(proc: subprocess.Popen[str] | subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
            proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def main() -> int:
    print("\n" + "=" * 78)
    print(" [C5] PBL6 v3.0 LIVE DEMO REHEARSAL ORCHESTRATOR")
    print(" Starting 3 services: Vulnerable API (5000), Gateway (8000), Dashboard (3000)")
    print("=" * 78)

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["ADMIN_API_KEY"] = "dev-admin-secret-key-change-me"
    env["TARGET_API_URL"] = "http://127.0.0.1:5000"
    env["WAF_MODE"] = "ACTIVE_BLOCKING"
    env["RATE_LIMIT_ENABLED"] = "true"
    env["PORT"] = "3000"
    env["GATEWAY_URL"] = "http://127.0.0.1:8000"

    procs: list[tuple[str, subprocess.Popen[Any]]] = []

    try:
        # 1. Target Vulnerable API
        print("\n1. Spawning Bookie Target API (Port 5000)...")
        v_env = dict(env)
        v_env["DJANGO_ENV"] = "development"
        v_env["ALLOWED_HOSTS"] = "*"
        p_vuln = subprocess.Popen(
            [sys.executable, "manage.py", "runserver", "127.0.0.1:5000", "--noreload"],
            cwd=str(ROOT_DIR / "vulnerable-api"),
            env=v_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(("Vulnerable API", p_vuln))

        # 2. WAF Gateway
        print("2. Spawning WAF Gateway v3.0 (Port 8000)...")
        g_env = dict(env)
        py_paths = [str(ROOT_DIR / "gateway"), str(ROOT_DIR / "ml-engine"), str(ROOT_DIR / "attack-lab")]
        g_env["PYTHONPATH"] = os.pathsep.join(py_paths)
        p_gw = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
            cwd=str(ROOT_DIR / "gateway"),
            env=g_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(("WAF Gateway", p_gw))

        # 3. SOC Dashboard (production build or start)
        print("3. Spawning SOC Dashboard (Port 3000)...")
        d_env = dict(env)
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        p_dash = subprocess.Popen(
            [npm_cmd, "run", "start", "--", "-p", "3000"],
            cwd=str(ROOT_DIR / "dashboard"),
            env=d_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(("SOC Dashboard", p_dash))

        # Wait for health checks
        print("\nWaiting for all 3 services to respond...")
        v_ok = wait_until_ready("Vulnerable API", "http://127.0.0.1:5000/api/v1/vulnerable/openapi.json", 25.0)
        g_ok = wait_until_ready("WAF Gateway", "http://127.0.0.1:8000/health", 25.0)
        d_ok = wait_until_ready("SOC Dashboard", "http://127.0.0.1:3000", 25.0)

        if not (v_ok and g_ok and d_ok):
            print(f"\n[ERROR] Service health check failed: Vuln={v_ok}, Gateway={g_ok}, Dashboard={d_ok}")
            return 1

        print("\n>>> ALL 3 SERVICES READY! Starting 10-Minute Demo Rehearsal Dry Run...\n")

        # Run demo rehearsal
        rehearsal_cmd = [
            sys.executable,
            str(ROOT_DIR / "scripts" / "demo_rehearsal.py"),
            "--auto",
            "--interval",
            "0.15",
            "--gateway-url",
            "http://127.0.0.1:8000",
            "--api-key",
            "dev-admin-secret-key-change-me",
        ]

        res = subprocess.run(
            rehearsal_cmd,
            cwd=str(ROOT_DIR),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        output_text = res.stdout + ("\n--- STDERR ---\n" + res.stderr if res.stderr else "")
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text(output_text, encoding="utf-8")

        print(output_text)
        print(f"\n[DONE] Demo rehearsal log written to: {LOG_PATH}")
        print(f"Exit code: {res.returncode}")
        return res.returncode

    finally:
        print("\nTerminating child services...")
        for name, proc in procs:
            print(f"  Stopping {name} (PID: {proc.pid})...")
            terminate_process(proc)
        print("All services stopped.")


if __name__ == "__main__":
    sys.exit(main())
