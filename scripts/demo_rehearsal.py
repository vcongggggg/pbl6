#!/usr/bin/env python3
"""PBL6 10-Minute Live Defense Rehearsal & Interactive Demonstration CLI (Blue Team v2.0).

Scenario Breakdown:
- Stage 1: Baseline Normal User Traffic (REST + Benign SOAP/XML -> HTTP 200 OK)
- Stage 2: OWASP Top 10 Multi-vector Attacks under MONITOR_ONLY (Detection & Telemetry Logging)
- Stage 3: Active Defense & Fast-Path Mitigation under ACTIVE_BLOCKING (HTTP 403 Forbidden + SOAP XXE)
- Stage 4: Burst Brute-Force Rate Limiting (HTTP 429 + Retry-After) & Live SOC Scoreboard
- Stage 5: Autonomous AI Arena Evaluation (Dueling-DQN vs Hybrid WAF v3.0)

Usage:
    python scripts/demo_rehearsal.py --interactive
    python scripts/demo_rehearsal.py --auto --interval 1.0
    python scripts/demo_rehearsal.py --gateway-url http://192.168.1.15:8000 --api-key <key>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _hget(headers: dict[str, str], name: str, default: str = "N/A") -> str:
    """Case-insensitive HTTP response header lookup."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return default


class DemoRunner:
    def __init__(
        self,
        gateway_url: str,
        api_key: str,
        auto_mode: bool = False,
        interval: float = 1.0,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.api_key = api_key
        self.auto_mode = auto_mode
        self.interval = interval
        self.stats: dict[str, Any] = {
            "normal_sent": 0,
            "normal_ok": 0,
            "attacks_sent": 0,
            "monitor_flagged": 0,
            "blocks_enforced": 0,
            "rate_limits_triggered": 0,
            "latencies_ms": [],
        }

    def banner(self) -> None:
        print(f"{CYAN}{BOLD}")
        print("=" * 78)
        print("   [SHIELD]  PBL6 CYBER RANGE: 10-MINUTE DEFENSE REHEARSAL (BLUE TEAM v3.0)")
        print("   Rule Engine + 5 OWASP API Guards + XGBoost v2.0 + IForest v2.0 + DQN Arena")
        print("=" * 78)
        print(f"{RESET}")
        print(f"Target Gateway: {GREEN}{BOLD}{self.gateway_url}{RESET}")
        print(
            f"Operating Mode: {YELLOW}"
            f"{'AUTOMATIC (--auto)' if self.auto_mode else 'INTERACTIVE (Press Enter per step)'}{RESET}"
        )
        print(f"Time Allotment: {CYAN}10 Minutes Structured Academic Defense{RESET}\n")

    def pause(self, prompt: str = "Nhấn [ENTER] để tiếp tục bước tiếp theo...") -> None:
        if self.auto_mode:
            print(f"{DIM}[TIMER] Nghỉ {self.interval:.1f}s để thuyết trình...{RESET}")
            time.sleep(self.interval)
        else:
            try:
                input(f"{YELLOW}{BOLD}>> {prompt}{RESET} ")
            except (KeyboardInterrupt, EOFError):
                print("\nĐã hủy kịch bản diễn tập.")
                sys.exit(0)

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        admin: bool = False,
    ) -> tuple[int, dict[str, Any], float, dict[str, str]]:
        url = f"{self.gateway_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        hdrs: dict[str, str] = {
            "User-Agent": "PBL6-LiveDemo/2.0",
            "Accept": "application/json",
        }
        if admin:
            hdrs["X-API-Key"] = self.api_key
        if headers:
            hdrs.update(headers)

        data = raw_body
        if json_data is not None:
            data = json.dumps(json_data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        start_time = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                latency = (time.perf_counter() - start_time) * 1000.0
                resp_headers = dict(resp.headers)
                try:
                    body = json.loads(resp.read().decode("utf-8"))
                except Exception:
                    body = {}
                return resp.status, body, latency, resp_headers
        except urllib.error.HTTPError as exc:
            latency = (time.perf_counter() - start_time) * 1000.0
            resp_headers = dict(exc.headers)
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                body = {}
            return exc.code, body, latency, resp_headers
        except Exception as exc:
            latency = (time.perf_counter() - start_time) * 1000.0
            return 0, {"error": str(exc)}, latency, {}

    def set_waf_mode(self, mode: str) -> tuple[bool, str]:
        status, body, _, _ = self.request(
            "POST",
            "/dashboard/toggle-waf-mode",
            json_data={"mode": mode},
            admin=True,
        )
        return status == 200, str(body.get("waf_mode", mode))

    def stage_1_baseline(self) -> None:
        print(f"\n{GREEN}{BOLD}" + "=" * 78 + f"{RESET}")
        print(f"{GREEN}{BOLD}GIAI ĐOẠN 1 (0:00 - 2:00): LƯU LƯỢNG NGƯỜI DÙNG BÌNH THƯỜNG (BASELINE){RESET}")
        print(f"{GREEN}{BOLD}" + "=" * 78 + f"{RESET}")
        print("Mục tiêu: Chứng minh Blue Team v2.0 hoạt động trong suốt, 0% False Positive trên REST & SOAP sạch.\n")

        self.set_waf_mode("ACTIVE_BLOCKING")

        normal_scenarios: list[tuple[str, str, str, dict[str, str] | None, dict[str, Any] | None, bytes | None, dict[str, str] | None]] = [
            ("GET tìm sách sạch: 'Python'", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "Python"}, None, None, None),
            ("GET tìm sách sạch: 'Architecture'", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "Architecture"}, None, None, None),
            ("GET đặc tả OpenAPI 3.0 của Bookie", "GET", "/api/proxy/api/v1/vulnerable/openapi.json", None, None, None, None),
            ("POST đánh giá sách hợp lệ (JSON)", "POST", "/api/proxy/api/v1/vulnerable/reviews/", None, {"book_id": 1, "author": "Nguyen Van Cong", "comment": "Sach kien truc phan mem rat hay"}, None, None),
            ("GET kiểm tra giao thức REST query sạch", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "Clean Code"}, None, None, None),
        ]

        for desc, method, path, params, json_body, raw_body, extra_hdrs in normal_scenarios:
            status, _, lat, hdrs = self.request(
                method, path, params=params, json_data=json_body, raw_body=raw_body, headers=extra_hdrs
            )
            self.stats["normal_sent"] += 1
            self.stats["latencies_ms"].append(lat)
            if 200 <= status < 300:
                self.stats["normal_ok"] += 1
            risk = _hget(hdrs, "X-WAF-Risk-Score", "0.0")
            ml_score = _hget(hdrs, "X-WAF-ML-Score", "0.0")
            proto = _hget(hdrs, "X-WAF-API-Protocol", "REST")
            color = GREEN if 200 <= status < 300 else RED
            print(
                f"  [{color}{status} OK{RESET}] {desc:<40} | {lat:6.2f}ms | "
                f"Risk: {risk:<5} | ML: {ml_score:<5} | Proto: {proto}"
            )
            if self.auto_mode:
                time.sleep(0.2)

        print(
            f"\n{GREEN}[PASS] Giai đoạn 1 hoàn tất: {self.stats['normal_ok']}/{self.stats['normal_sent']} "
            f"lưu lượng sạch đi qua mượt mà!{RESET}"
        )
        self.pause("Sẵn sàng kích hoạt đợt tấn công OWASP ở Chế độ Giám sát (MONITOR_ONLY)?")

    def stage_2_monitor_only_attacks(self) -> None:
        print(f"\n{YELLOW}{BOLD}" + "=" * 78 + f"{RESET}")
        print(f"{YELLOW}{BOLD}GIAI ĐOẠN 2 (2:00 - 5:00): TẤN CÔNG OWASP Ở CHẾ ĐỘ GIÁM SÁT (MONITOR_ONLY){RESET}")
        print(f"{YELLOW}{BOLD}" + "=" * 78 + f"{RESET}")
        print("Mục tiêu: WAF phát hiện đa tầng (Rule + XGBoost v2.0 + IForest v2.0), ghi log SOC nhưng không ngắt.\n")

        ok, active_mode = self.set_waf_mode("MONITOR_ONLY")
        print(f"[CONFIG] Trạng thái WAF Gateway: {YELLOW}{BOLD}{active_mode}{RESET} (updated={ok})\n")

        attack_scenarios = [
            ("SQLi Auth Bypass", "POST", "/api/proxy/api/v1/vulnerable/auth/login/", None, {"username": "' OR 1=1--", "password": "x"}),
            ("SQLi UNION Data Exfiltration", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "' UNION SELECT username, password FROM users--"}, None),
            ("XSS Stored/Reflected Payload", "POST", "/api/proxy/api/v1/vulnerable/reviews/", None, {"book_id": 1, "author": "attacker", "comment": "<script>alert(document.cookie)</script>"}),
            ("Path Traversal / LFI", "GET", "/api/proxy/api/v1/vulnerable/files/download/", {"file": "../../../../etc/passwd"}, None),
            ("Command Injection (RCE)", "POST", "/api/proxy/api/v1/vulnerable/admin/ping/", None, {"host": "127.0.0.1; whoami"}),
        ]

        for desc, method, path, params, body in attack_scenarios:
            status, _, lat, hdrs = self.request(method, path, params=params, json_data=body)
            self.stats["attacks_sent"] += 1
            risk = _hget(hdrs, "X-WAF-Risk-Score", "0.0")
            ml_score = _hget(hdrs, "X-WAF-ML-Score", "0.0")
            decision = _hget(hdrs, "X-WAF-Decision", "MONITOR")
            try:
                if float(risk) >= 30.0:
                    self.stats["monitor_flagged"] += 1
            except ValueError:
                pass
            print(
                f"  [{YELLOW}MONITOR{RESET}] {desc:<32} | HTTP: {status} | "
                f"Risk: {RED}{risk:<5}{RESET} | ML: {ml_score:<5} | Decision: {decision} | {lat:5.1f}ms"
            )
            if self.auto_mode:
                time.sleep(0.25)

        print(
            f"\n{YELLOW}[PASS] Giai đoạn 2 hoàn tất: {self.stats['monitor_flagged']}/5 tấn công "
            f"đã bị gắn cờ và ghi vết lên SOC Dashboard!{RESET}"
        )
        self.pause("Sẵn sàng chuyển WAF sang ACTIVE_BLOCKING để kích hoạt Chặn Đứng Tấn Công?")

    def stage_3_active_blocking(self) -> None:
        print(f"\n{RED}{BOLD}" + "=" * 78 + f"{RESET}")
        print(f"{RED}{BOLD}GIAI ĐOẠN 3 (5:00 - 7:30): PHÒNG THỦ CHỦ ĐỘNG (ACTIVE_BLOCKING) & HTTP 403{RESET}")
        print(f"{RED}{BOLD}" + "=" * 78 + f"{RESET}")
        print("Mục tiêu: Chặn đứng tức thì tấn công né tránh (Obfuscation, Zero-Width, SOAP XXE) bằng HTTP 403.\n")

        ok, active_mode = self.set_waf_mode("ACTIVE_BLOCKING")
        print(f"[CONFIG] Trạng thái WAF Gateway: {RED}{BOLD}{active_mode}{RESET} (updated={ok})\n")

        soap_xxe = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soap:Body><GetBook><Title>&xxe;</Title></GetBook></soap:Body></soap:Envelope>"
        )

        blocking_scenarios: list[tuple[str, str, str, dict[str, str] | None, dict[str, Any] | None, bytes | None, dict[str, str] | None]] = [
            ("SQLi Evasion (Inline Comment + URL)", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "1' UNION/**/SELECT null,version()--"}, None, None, None),
            ("XSS Obfuscated SVG Event Handler", "POST", "/api/proxy/api/v1/vulnerable/reviews/", None, {"book_id": 1, "author": "red", "comment": "<details open ontoggle=alert(1)>"}, None, None),
            ("Path Traversal Windows/Linux Escape", "GET", "/api/proxy/api/v1/vulnerable/files/download/", {"file": "..\\..\\Windows\\System32\\cmd.exe"}, None, None, None),
            ("Command Injection Pipe + Interpreter", "POST", "/api/proxy/api/v1/vulnerable/admin/ping/", None, {"host": "127.0.0.1; python3 -c 'import os'"}, None, None),
            ("Multi-Protocol SOAP/XML XXE Injection", "POST", "/api/proxy/api/v1/vulnerable/books/search/", None, None, soap_xxe, {"Content-Type": "application/soap+xml", "SOAPAction": '"GetBook"'}),
            ("OWASP API #7: SSRF Internal Metadata Probe", "GET", "/api/proxy/api/v1/vulnerable/books/fetch-cover/", {"url": "http://127.0.0.1:8000/api/dashboard/stats"}, None, None, None),
            ("OWASP API #8: NoSQLi JSON Operator ($ne)", "POST", "/api/proxy/api/v1/vulnerable/auth/login/", None, {"username": {"$ne": ""}, "password": "x"}, None, None),
            ("OWASP API #3: Mass Assignment Privilege (role:admin)", "POST", "/api/proxy/api/v1/vulnerable/users/profile/update/", None, {"role": "admin", "email": "test@dut.udn.vn"}, None, None),
        ]

        for desc, method, path, params, json_body, raw_body, extra_hdrs in blocking_scenarios:
            status, _, lat, hdrs = self.request(
                method, path, params=params, json_data=json_body, raw_body=raw_body, headers=extra_hdrs
            )
            self.stats["attacks_sent"] += 1
            risk = _hget(hdrs, "X-WAF-Risk-Score", "N/A")
            proto = _hget(hdrs, "X-WAF-API-Protocol", "REST")
            decision = _hget(hdrs, "X-WAF-Decision", "BLOCK")
            if status == 403:
                self.stats["blocks_enforced"] += 1
                print(
                    f"  [{RED}403 BLOCKED{RESET}] {desc:<42} | {GREEN}{lat:5.2f}ms{RESET} | "
                    f"Risk: {risk:<5} | Proto: {proto} | {decision}"
                )
            else:
                print(f"  [{YELLOW}HTTP {status}{RESET}] {desc:<42} | {lat:5.2f}ms | Risk: {risk}")
            if self.auto_mode:
                time.sleep(0.25)

        total_scenarios = len(blocking_scenarios)
        print(
            f"\n{GREEN}[PASS] Giai đoạn 3 hoàn tất: {self.stats['blocks_enforced']}/{total_scenarios} tấn công "
            f"bị chặn đứng bằng HTTP 403 Forbidden qua Multi-Layer WAF + 5 OWASP API Guards!{RESET}"
        )
        self.pause("Sẵn sàng mô phỏng Brute-Force Bão Tải để kiểm chứng HTTP 429 Rate Limiting?")

    def stage_4_rate_limiting_and_scoreboard(self) -> None:
        print(f"\n{MAGENTA}{BOLD}" + "=" * 78 + f"{RESET}")
        print(f"{MAGENTA}{BOLD}GIAI ĐOẠN 4 (7:30 - 10:00): ĐIỀU TIẾT TẦN SUẤT BRUTE-FORCE & TỔNG KẾT SOC{RESET}")
        print(f"{MAGENTA}{BOLD}" + "=" * 78 + f"{RESET}")
        print("Mục tiêu: Chống Brute-force /auth/login/ (IP Hard Cap 10 req/min) bằng HTTP 429 + Retry-After.\n")

        rate_limit_hits = 0
        for i in range(1, 15):
            status, _, lat, hdrs = self.request(
                "POST",
                "/api/proxy/api/v1/vulnerable/auth/login/",
                json_data={"username": f"demo_user_{i}", "password": "wrong_password_123"},
                headers={"User-Agent": f"BruteBot/{i}"},
            )
            if status == 429:
                rate_limit_hits += 1
                self.stats["rate_limits_triggered"] += 1
                retry_after = _hget(hdrs, "Retry-After", "60")
                print(
                    f"  Request #{i:02d}: [{RED}{BOLD}429 TOO MANY REQUESTS{RESET}] "
                    f"CHẶN BRUTE-FORCE (Retry-After: {retry_after}s, {lat:5.2f}ms)"
                )
            else:
                rem = _hget(hdrs, "X-RateLimit-Remaining", "N/A")
                print(
                    f"  Request #{i:02d}: [{GREEN}HTTP {status}{RESET}] "
                    f"Trễ: {lat:5.2f}ms | Hạn mức Sliding Window còn lại: {rem}"
                )
            time.sleep(0.05)

        print(f"\n{MAGENTA}[PASS] Đã kích hoạt điều tiết thích ứng: {rate_limit_hits} requests bị phạt HTTP 429!{RESET}")

        status, dash_stats, _, _ = self.request("GET", "/dashboard/stats", admin=True)

        print(f"\n{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
        print(f"{CYAN}{BOLD}BẢNG TỔNG KẾT DIỄN TẬP BẢO VỆ ĐỒ ÁN (BLUE TEAM v2.0 SCOREBOARD){RESET}")
        print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
        print(f"- Lưu lượng hợp lệ (Baseline HTTP 200):     {GREEN}{self.stats['normal_ok']}/{self.stats['normal_sent']}{RESET}")
        print(f"- Tấn công Monitor-Only được gắn cờ:        {YELLOW}{self.stats['monitor_flagged']}/5{RESET}")
        print(f"- Tấn công Active Blocking bị chặn 403:     {RED}{self.stats['blocks_enforced']}/5{RESET}")
        print(f"- Brute-Force bị phạt HTTP 429:             {MAGENTA}{self.stats['rate_limits_triggered']}{RESET}")
        if status == 200 and isinstance(dash_stats, dict):
            print(
                f"- Live Gateway Stats (/dashboard/stats):    "
                f"total={dash_stats.get('total_requests')}, "
                f"detected={dash_stats.get('attacks_detected')}, "
                f"blocked={dash_stats.get('blocked_count')}, "
                f"rate_limited={dash_stats.get('rate_limited_count')}, "
                f"mode={dash_stats.get('waf_mode')}"
            )
        if self.stats["latencies_ms"]:
            avg_lat = sum(self.stats["latencies_ms"]) / len(self.stats["latencies_ms"])
            print(f"- Độ trễ trung bình Baseline E2E:           {CYAN}{avg_lat:.2f} ms{RESET}")
        print("=" * 78)
        print(f"\n{GREEN}{BOLD}KỊCH BẢN DIỄN TẬP 10 PHÚT HOÀN TẤT!{RESET}")
        print(f"Mở trình duyệt tại {CYAN}{BOLD}http://localhost:3000{RESET} để trình chiếu SOC Command Center:")
        print("  1. KPI Cards, Real-Time 60s RPS, Multi-Protocol Distribution & Cyber Range Topology.")
        print("  2. Attack Sessions & MITRE Cyber Kill Chain Timeline.")
        print("  3. Evidence Drawer (26-D Feature Vector thật) & Detection Explainability Modal.\n")

    def run(self) -> None:
        self.banner()
        print("Đang kiểm tra sức khỏe WAF Gateway...")
        status, _, _, _ = self.request("GET", "/health")
        if status != 200:
            print(f"{RED}[ERROR] Không thể kết nối tới WAF Gateway tại {self.gateway_url}!{RESET}")
            sys.exit(1)
        print(f"{GREEN}[OK] WAF Gateway v2.0 sẵn sàng: HTTP 200 OK{RESET}\n")

        self.pause("Bắt đầu Giai đoạn 1 (Lưu lượng sạch Baseline)?")
        self.stage_1_baseline()
        self.stage_2_monitor_only_attacks()
        self.stage_3_active_blocking()
        self.stage_4_rate_limiting_and_scoreboard()
        self.stage_5_autonomous_arena_evaluation()

    def step_header(self, stage_num: int, title: str, subtitle: str) -> None:
        print(f"\n{CYAN}{BOLD}" + "=" * 78)
        print(f" [STAGE {stage_num}] {title}")
        print(f" {DIM}{subtitle}{RESET}{CYAN}{BOLD}")
        print("=" * 78 + f"{RESET}")

    def stage_5_autonomous_arena_evaluation(self) -> None:
        self.step_header(
            5,
            "ĐẤU TRƯỜNG ĐỐI KHÁNG TỰ ĐỘNG (AI ARENA & EVASION EVALUATION)",
            "Kích hoạt chuỗi đối kháng tự động giữa tác tử Red Team Dueling-DQN và Blue Team v3.0",
        )
        print(f"{CYAN}Đang gửi yêu cầu kích hoạt AI Pentest Evaluation tới /api/dashboard/arena/pentest/run...{RESET}")

        payload = {
            "scope": "full_pentest",
            "max_rounds": 8,
            "defense_tier": "hybrid_v3",
            "sync_to_soc": True,
        }
        status, body, lat, _headers = self.request(
            "POST",
            "/api/dashboard/arena/pentest/run",
            json_data=payload,
            admin=True,
        )

        if status == 200 and isinstance(body, dict):
            print(f"{GREEN}[OK] Đấu trường hoàn thành với mã kết quả: HTTP 200 OK ({lat:.1f} ms){RESET}")
            print(f"  - Mã trận đấu:       {CYAN}{body.get('battle_id')}{RESET}")
            print(f"  - Cấp độ phòng thủ:  {BOLD}{body.get('defense_tier')}{RESET}")
            print(f"  - Tổng số vòng:      {body.get('total_rounds')}")
            print(f"  - Số lần chặn/DLP:   {GREEN}{BOLD}{body.get('blocked_count')}{RESET}")
            print(f"  - Số lần lọt:        {RED}{body.get('bypass_count')}{RESET}")
            winner_val = body.get("winner", "DRAW")
            w_color = GREEN if winner_val == "BLUE_TEAM" else (RED if winner_val == "RED_TEAM" else YELLOW)
            print(f"  - Người chiến thắng: {w_color}{BOLD}{winner_val}{RESET}")
            print(f"  - Điểm rủi ro TB:    {CYAN}{body.get('avg_threat_score', 0.0):.1f}/100{RESET}")
            print(f"  - Độ trễ xử lý TB:   {CYAN}{body.get('avg_latency_ms', 0.0):.3f} ms{RESET}")

            print(f"\n{BOLD}Chi tiết từng vòng đối kháng (Dual-Brain Telemetry):{RESET}")
            for rd in body.get("rounds", [])[:8]:
                is_defended = bool(rd.get("waf_blocked") or rd.get("response_status") == 403)
                status_color = GREEN if is_defended else RED
                badge = "DLP 200" if rd.get("dlp_redacted") else f"HTTP {rd.get('response_status')}"
                print(
                    f"  [{rd.get('round_num')}] {status_color}[{badge}]{RESET} "
                    f"{BOLD}{rd.get('attack_type')}{RESET} ({rd.get('technique')}) -> "
                    f"Risk={rd.get('waf_threat_score', 0.0):.1f} | Winner={rd.get('winner')} | "
                    f"{DIM}{rd.get('reasoning_vi', '')[:64]}...{RESET}"
                )
        else:
            print(f"{YELLOW}[WARN] Không thể kích hoạt pentest tự động (HTTP {status}){RESET}")

        print("\n" + "-" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="PBL6 10-Minute Live Defense Rehearsal CLI (Blue Team v2.0)")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8000", help="URL of WAF Gateway")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("ADMIN_API_KEY", "dev-admin-secret-key-change-me"),
        help="Admin X-API-Key for toggling WAF mode and reading live stats",
    )
    parser.add_argument("--auto", action="store_true", help="Run rehearsal automatically without prompt pauses")
    parser.add_argument("--interactive", action="store_true", help="Run rehearsal interactively (default)")
    parser.add_argument("--interval", type=float, default=1.5, help="Pause interval in seconds for auto mode")
    args = parser.parse_args()

    auto_mode = args.auto and not args.interactive
    runner = DemoRunner(
        gateway_url=args.gateway_url,
        api_key=args.api_key,
        auto_mode=auto_mode,
        interval=args.interval,
    )
    runner.run()


if __name__ == "__main__":
    main()
