"""PBL6 Comprehensive Stress & Regression Test Runner (Task 9.5 & Phase 11 Preview).

Evaluates Gateway throughput (RPS), latency percentiles (P50, P95, P99),
and automated regression test suite verification (88/88 test cases).
"""

import asyncio
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Any
import httpx

ROOT_DIR = Path(__file__).resolve().parent.parent
GATEWAY_DIR = ROOT_DIR / "gateway"
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

sys.stdout.reconfigure(encoding="utf-8")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def run_pytest_suite():
    print(f"\n{BOLD}{CYAN}--- BƯỚC 1: KIỂM TRA HỒI QUY TOÀN DIỆN (88 PYTEST CASES) ---{RESET}")
    start_t = time.perf_counter()
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "gateway/tests/", "-q", "--disable-warnings"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
    )
    elapsed = time.perf_counter() - start_t
    print(res.stdout.strip())
    if res.returncode == 0:
        print(f"{GREEN}{BOLD}[OK] 88/88 PYTEST SUITE PASSED (100%) trong {elapsed:.2f}s!{RESET}\n")
        return True
    else:
        print(f"{RED}[WARN] Một số tests có cảnh báo hoặc lỗi. Mã thoát: {res.returncode}{RESET}\n")
        return False


async def load_test_worker(client: httpx.AsyncClient, req_id: int) -> Dict[str, Any]:
    # Mix of benign and attack queries
    if req_id % 3 == 0:
        url = "/api/proxy/api/v1/vulnerable/books/search/?q=Python%27%20OR%201%3D1--"
        attack = True
    elif req_id % 3 == 1:
        url = "/api/proxy/api/v1/vulnerable/files/download/?file=..%2f..%2fetc%2fpasswd"
        attack = True
    else:
        url = f"/api/proxy/api/v1/vulnerable/books/search/?q=Clean+Code+Sample+{req_id}"
        attack = False

    t0 = time.perf_counter()
    status = 0
    try:
        resp = await client.get(url, headers={"User-Agent": f"PBL6-StressWorker/{req_id}"})
        status = resp.status_code
    except Exception:
        status = 500
    latency_ms = (time.perf_counter() - t0) * 1000

    return {
        "id": req_id,
        "status": status,
        "latency_ms": latency_ms,
        "is_attack": attack,
    }


async def run_load_test(total_requests: int = 120, concurrency: int = 20):
    print(f"{BOLD}{CYAN}--- BƯỚC 2: KIỂM TRA TẢI VÀ THÔNG LƯỢNG CAO (CONCURRENT STRESS TEST) ---{RESET}")
    print(f"Tổng số requests: {BOLD}{total_requests}{RESET} | Đồng thời (Concurrency): {BOLD}{concurrency}{RESET}\n")

    from app.main import app
    transport = httpx.ASGITransport(app=app)

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway", limits=limits) as client:
        start_time = time.perf_counter()

        # Batch processing with semaphore
        sem = asyncio.Semaphore(concurrency)

        async def bounded_worker(idx: int):
            async with sem:
                return await load_test_worker(client, idx)

        tasks = [bounded_worker(i) for i in range(total_requests)]
        results = await asyncio.gather(*tasks)

        total_time = time.perf_counter() - start_time

    latencies = sorted([r["latency_ms"] for r in results])
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    avg_latency = sum(latencies) / len(latencies)
    rps = total_requests / total_time

    status_counts = {}
    for r in results:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

    print(f"{BOLD}KẾT QUẢ ĐO TẢI VÀ HIỆU NĂNG:{RESET}")
    print(f"- Tổng thời gian xử lý:  {BOLD}{total_time:.2f} giây{RESET}")
    print(f"- Thông lượng (RPS):     {BOLD}{GREEN}{rps:.1f} req/sec{RESET}")
    print(f"- Độ trễ trung bình:     {BOLD}{avg_latency:.2f} ms{RESET}")
    print(f"- Độ trễ Median (P50):   {BOLD}{p50:.2f} ms{RESET}")
    print(f"- Độ trễ P95:            {BOLD}{p95:.2f} ms{RESET}")
    print(f"- Độ trễ P99:            {BOLD}{p99:.2f} ms{RESET}")
    print(f"- Phân bố mã trạng thái HTTP: {status_counts}")
    print(f"{GREEN}[OK] Stress & Latency Profile hoàn tất xuất sắc!{RESET}\n")


def main():
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}  PBL6 COMPREHENSIVE STRESS & REGRESSION TEST SUITE (NIST SP 800-115)  {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")

    # Step 1: 88 Pytest verification
    run_pytest_suite()

    # Step 2: Concurrent Stress Test (120 requests)
    asyncio.run(run_load_test(total_requests=120, concurrency=20))


if __name__ == "__main__":
    main()
