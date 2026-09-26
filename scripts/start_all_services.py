"""PBL6 Service Orchestration Script (Task 9.5 & Demo Preparation).

Supports starting, stopping, and health-checking all 3 core services:
1. Vulnerable API (Bookie Bookstore - Django/Port 5000)
2. WAF Gateway (FastAPI/Port 8000)
3. Security Dashboard (Next.js/Port 3000)
"""

import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.stdout.reconfigure(encoding="utf-8")


def check_port(url: str, name: str, timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PBL6-HealthChecker/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            print(f"  [OK] {name} is reachable at {url} (HTTP {resp.status})")
            return True
    except Exception as e:
        print(f"  [WAITING] {name} is not reachable at {url}: {e}")
        return False


def check_all_services():
    print("\n--- CHECKING PBL6 SERVICES STATUS ---")
    v_ok = check_port("http://localhost:5000/api/v1/vulnerable/books/search/?q=Clean", "Vulnerable API (Port 5000)")
    g_ok = check_port("http://localhost:8000/api/health", "WAF Gateway (Port 8000)")
    d_ok = check_port("http://localhost:3000", "Security Dashboard (Port 3000)")

    if v_ok and g_ok and d_ok:
        print("\n>>> ALL SERVICES ARE RUNNING AND HEALTHY! <<<")
        print("- Dashboard URL: http://localhost:3000")
        print("- Gateway URL:   http://localhost:8000")
        print("- Target API:    http://localhost:5000\n")
        return True
    else:
        print("\nSome services are offline. Run with --start to launch them.")
        return False


def start_docker():
    print("\nStarting services with Docker Compose...")
    res = subprocess.run(["docker", "compose", "up", "-d"], cwd=str(ROOT_DIR))
    if res.returncode == 0:
        print("Docker Compose started successfully. Waiting 5 seconds for health checks...")
        time.sleep(5)
        check_all_services()
    else:
        print(f"Docker Compose failed with code {res.returncode}. Falling back to local process start...")
        start_local()


def start_local():
    print("\nStarting services as local background processes...")
    # 1. Vulnerable API
    vulnerable_cmd = [sys.executable, "manage.py", "runserver", "0.0.0.0:5000"]
    vulnerable_dir = ROOT_DIR / "vulnerable-api"
    print(f"Launching Vulnerable API in {vulnerable_dir}...")
    subprocess.Popen(vulnerable_cmd, cwd=str(vulnerable_dir), creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)

    # 2. WAF Gateway
    gateway_cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    gateway_dir = ROOT_DIR / "gateway"
    print(f"Launching WAF Gateway in {gateway_dir}...")
    subprocess.Popen(gateway_cmd, cwd=str(gateway_dir), creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)

    # 3. Next.js Dashboard
    dashboard_dir = ROOT_DIR / "dashboard"
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    dashboard_cmd = [npm_cmd, "run", "dev"]
    print(f"Launching Next.js Dashboard in {dashboard_dir}...")
    subprocess.Popen(dashboard_cmd, cwd=str(dashboard_dir), creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)

    print("Services spawned! Waiting 6 seconds for initial warm-up...")
    time.sleep(6)
    check_all_services()


def main():
    parser = argparse.ArgumentParser(description="PBL6 Service Management Utility")
    parser.add_argument("--start", action="store_true", help="Start all services")
    parser.add_argument("--docker", action="store_true", help="Start via Docker Compose")
    parser.add_argument("--check", action="store_true", help="Check services health status")
    args = parser.parse_args()

    if args.start:
        if args.docker:
            start_docker()
        else:
            start_local()
    elif args.check:
        check_all_services()
    else:
        check_all_services()


if __name__ == "__main__":
    main()
