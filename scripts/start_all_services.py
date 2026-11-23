"""PBL6 Service Orchestration Script (Blue Team v2.0 Live Demo Launcher).

Starts and health-checks all 3 core Machine 1 services:
1. Vulnerable API (Bookie Bookstore — Django on 127.0.0.1:5000)
2. WAF Gateway (FastAPI + XGBoost v2.0 + IForest v2.0 on 0.0.0.0:8000)
3. SOC Command Center Dashboard (Next.js 14 + BFF Proxy on 0.0.0.0:3000)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def check_port(url: str, name: str, timeout: float = 2.5) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PBL6-HealthChecker/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            print(f"  [OK] {name} is reachable at {url} (HTTP {resp.status})")
            return True
    except Exception as exc:
        print(f"  [WAITING] {name} is not reachable at {url}: {exc}")
        return False


def check_all_services() -> bool:
    print("\n--- CHECKING PBL6 BLUE TEAM v2.0 SERVICES STATUS ---")
    v_ok = check_port(
        "http://127.0.0.1:5000/api/v1/vulnerable/openapi.json",
        "Bookie Target API (Port 5000)",
    )
    g_ok = check_port(
        "http://127.0.0.1:8000/health",
        "WAF Gateway v2.0 (Port 8000)",
    )
    d_ok = check_port(
        "http://127.0.0.1:3000",
        "SOC Dashboard UI (Port 3000)",
    )

    if v_ok and g_ok and d_ok:
        print("\n>>> ALL 3 PBL6 BLUE TEAM v2.0 SERVICES ARE RUNNING AND HEALTHY! <<<")
        print("- SOC Dashboard URL: http://localhost:3000")
        print("- WAF Gateway URL:   http://localhost:8000  (LAN: http://<LAN-IP>:8000)")
        print("- Bookie Target API: http://127.0.0.1:5000 (Loopback isolated)\n")
        return True
    print("\nSome services are offline. Run with --start to launch them.")
    return False


def wait_for_services(timeout_seconds: int = 35) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if check_all_services():
            return True
        time.sleep(2.5)
    return check_all_services()


def start_docker() -> None:
    print("\nStarting services with Docker Compose...")
    res = subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=str(ROOT_DIR))
    if res.returncode == 0:
        print("Docker Compose started successfully. Waiting for health checks...")
        wait_for_services(35)
    else:
        print(f"Docker Compose failed (exit {res.returncode}). Falling back to local process launch...")
        start_local(prod_dashboard=False)


def start_local(prod_dashboard: bool = False) -> None:
    print("\nStarting PBL6 Blue Team v2.0 services as local processes...")
    admin_key = os.environ.get("ADMIN_API_KEY", "dev-admin-secret-key-change-me")
    creation_flags = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0

    # 1. Vulnerable API (isolated to loopback 127.0.0.1:5000)
    vulnerable_dir = ROOT_DIR / "vulnerable-api"
    vulnerable_env = os.environ.copy()
    vulnerable_env.setdefault("DJANGO_ENV", "development")
    vulnerable_env.setdefault("ALLOWED_HOSTS", "*")
    vulnerable_cmd = [sys.executable, "manage.py", "runserver", "127.0.0.1:5000", "--noreload"]
    print(f"Launching Bookie Target API in {vulnerable_dir}...")
    subprocess.Popen(vulnerable_cmd, cwd=str(vulnerable_dir), env=vulnerable_env, creationflags=creation_flags)

    # 2. WAF Gateway (with PYTHONPATH including gateway + ml-engine)
    gateway_dir = ROOT_DIR / "gateway"
    gateway_env = os.environ.copy()
    py_paths = [str(gateway_dir), str(ROOT_DIR / "ml-engine")]
    if gateway_env.get("PYTHONPATH"):
        py_paths.append(gateway_env["PYTHONPATH"])
    gateway_env["PYTHONPATH"] = os.pathsep.join(py_paths)
    gateway_env.setdefault("TARGET_API_URL", "http://127.0.0.1:5000")
    gateway_env.setdefault("WAF_MODE", "ACTIVE_BLOCKING")
    gateway_env.setdefault("ADMIN_API_KEY", admin_key)
    gateway_env.setdefault("DATABASE_URL", f"sqlite:///{(ROOT_DIR / 'data' / 'waf_security.db').as_posix()}")
    gateway_cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    print(f"Launching WAF Gateway v2.0 in {gateway_dir}...")
    subprocess.Popen(gateway_cmd, cwd=str(gateway_dir), env=gateway_env, creationflags=creation_flags)

    # 3. Next.js SOC Dashboard (with server-side BFF credentials)
    dashboard_dir = ROOT_DIR / "dashboard"
    dashboard_env = os.environ.copy()
    dashboard_env["BACKEND_URL"] = "http://127.0.0.1:8000"
    dashboard_env["ADMIN_API_KEY"] = admin_key
    dashboard_env.setdefault("NEXT_PUBLIC_API_BASE_URL", "http://localhost:8000")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    dashboard_cmd = [npm_cmd, "run", "start" if prod_dashboard else "dev"]
    print(f"Launching SOC Dashboard ({'prod' if prod_dashboard else 'dev'}) in {dashboard_dir}...")
    subprocess.Popen(dashboard_cmd, cwd=str(dashboard_dir), env=dashboard_env, creationflags=creation_flags)

    print("Services spawned! Waiting for startup health checks...")
    wait_for_services(35)


def main() -> None:
    parser = argparse.ArgumentParser(description="PBL6 Blue Team v2.0 Service Management Utility")
    parser.add_argument("--start", action="store_true", help="Start all 3 services")
    parser.add_argument("--docker", action="store_true", help="Start via Docker Compose")
    parser.add_argument("--prod", action="store_true", help="Run built Next.js production server (npm run start)")
    parser.add_argument("--check", action="store_true", help="Check services health status")
    args = parser.parse_args()

    if args.start:
        if args.docker:
            start_docker()
        else:
            start_local(prod_dashboard=args.prod)
    else:
        ok = check_all_services()
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
