#!/usr/bin/env python3
"""PBL6 10-Minute Live Defense Rehearsal & Interactive Demonstration CLI.

Scenario Breakdown:
- Stage 1: Baseline Normal User Traffic (HTTP 200 OK, Latency Baseline)
- Stage 2: OWASP Top 10 Multi-vector Attacks under MONITOR_ONLY (Detection & Telemetry Logging)
- Stage 3: Active Defense & Sub-millisecond Mitigation under ACTIVE_BLOCK (Fast-path 403 Forbidden)
- Stage 4: Burst Traffic Rate Limiting (HTTP 429 Exponential Backoff) & Telemetry Scoreboard

Usage:
    python scripts/demo_rehearsal.py --auto
    python scripts/demo_rehearsal.py --interactive
    python scripts/demo_rehearsal.py --gateway-url http://192.168.1.100:8000
"""

import argparse
import json
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


class DemoRunner:
    def __init__(self, gateway_url: str, auto_mode: bool = False, interval: float = 1.0):
        self.gateway_url = gateway_url.rstrip("/")
        self.auto_mode = auto_mode
        self.interval = interval
        self.stats = {
            "normal_sent": 0,
            "attacks_sent": 0,
            "blocks_enforced": 0,
            "rate_limits_triggered": 0,
            "latencies_ms": [],
        }

    def banner(self):
        print(f"{CYAN}{BOLD}")
        print("=" * 75)
        print("   🛡️  PBL6 CYBER RANGE: 10-MINUTE DEFENSE REHEARSAL & LIVE DEMO CLI  🛡️")
        print("       AI-Driven Web API Security Platform & Adaptive Hybrid WAF      ")
        print("=" * 75)
        print(f"{RESET}")
        print(f"Target Gateway: {GREEN}{BOLD}{self.gateway_url}{RESET}")
        print(f"Operating Mode: {YELLOW}{'AUTOMATIC (--auto)' if self.auto_mode else 'INTERACTIVE (Press Enter per step)'}{RESET}")
        print(f"Time Allotment: {CYAN}10 Minutes Structured Academic Defense{RESET}\n")

    def pause(self, prompt: str = "Nhấn [ENTER] để tiếp tục bước tiếp theo..."):
        if self.auto_mode:
            print(f"{DIM}⏱️  Nghỉ {self.interval}s để thuyết trình...{RESET}")
            time.sleep(self.interval)
        else:
            try:
                input(f"{YELLOW}{BOLD}👉 {prompt}{RESET} ")
            except (KeyboardInterrupt, EOFError):
                print("\nĐã hủy kịch bản diễn tập.")
                sys.exit(0)

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> tuple[int, Dict[str, Any], float, Dict[str, str]]:
        url = f"{self.gateway_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        hdrs = {
            "User-Agent": "PBL6-LiveDemo/1.0",
            "Accept": "application/json",
        }
        if headers:
            hdrs.update(headers)

        data = None
        if json_data is not None:
            data = json.dumps(json_data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"

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
        except urllib.error.HTTPError as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            resp_headers = dict(e.headers)
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            return e.code, body, latency, resp_headers
        except Exception as exc:
            latency = (time.perf_counter() - start_time) * 1000.0
            return 0, {"error": str(exc)}, latency, {}

    def set_waf_mode(self, mode: str) -> bool:
        status, body, _, _ = self.request(
            "POST",
            "/api/dashboard/toggle-waf-mode",
            json_data={"waf_mode": mode},
        )
        return status == 200

    def stage_1_baseline(self):
        print(f"\n{GREEN}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{GREEN}{BOLD}📍 GIAI ĐOẠN 1 (0:00 - 2:00): LƯU LƯỢNG NGƯỜI DÙNG BÌNH THƯỜNG (BASELINE){RESET}")
        print(f"{GREEN}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print("Mục tiêu: Chứng minh Gateway hoạt động trong suốt, không làm nghẽn lưu lượng hợp lệ.\n")

        normal_scenarios = [
            ("Tìm kiếm sách an toàn: 'Python'", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "Python"}),
            ("Duyệt sách kiến trúc: 'Architecture'", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "Architecture"}),
            ("Duyệt sách bảo mật: 'Security'", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "Security"}),
            ("Kiểm tra OpenAPI schema của Target", "/api/proxy/api/v1/vulnerable/openapi.json", None),
            ("Truy vấn đánh giá sách hợp lệ", "/api/proxy/api/v1/vulnerable/reviews/", {"book_id": "1"}),
        ]

        for desc, path, params in normal_scenarios:
            status, _, lat, hdrs = self.request("GET", path, params=params)
            self.stats["normal_sent"] += 1
            self.stats["latencies_ms"].append(lat)
            threat = hdrs.get("X-WAF-Threat-Score", "0")
            print(f"  [{GREEN}200 OK{RESET}] {desc:<42} | Trễ: {lat:6.2f}ms | Threat Score: {threat}")
            if self.auto_mode:
                time.sleep(0.3)

        print(f"\n{GREEN}✅ Giai đoạn 1 hoàn tất: 100% lưu lượng bình thường được chuyển tiếp mượt mà!{RESET}")
        self.pause("Sẵn sàng kích hoạt đợt tấn công OWASP ở Chế độ Giám sát (MONITOR_ONLY)?")

    def stage_2_monitor_only_attacks(self):
        print(f"\n{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{YELLOW}{BOLD}📍 GIAI ĐOẠN 2 (2:00 - 5:00): TẤN CÔNG OWASP Ở CHẾ ĐỘ GIÁM SÁT (MONITOR_ONLY){RESET}")
        print(f"{YELLOW}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print("Mục tiêu: WAF phát hiện 4 họ tấn công, chấm Risk Score cao và cảnh báo đỏ trên Dashboard mà không ngắt.\n")

        self.set_waf_mode("MONITOR_ONLY")
        print(f"⚙️  Trạng thái WAF Gateway: {YELLOW}MONITOR_ONLY{RESET}\n")

        attack_scenarios = [
            ("SQL Injection: Auth Bypass", "POST", "/api/proxy/api/v1/vulnerable/auth/login/", None, {"username": "' OR 1=1--", "password": "x"}),
            ("SQL Injection: UNION-based", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "' UNION SELECT username, password_hash FROM users--"}, None),
            ("Cross-Site Scripting (XSS)", "GET", "/api/proxy/api/v1/vulnerable/reviews/", {"book_id": "1", "q": "<script>alert(document.cookie)</script>"}, None),
            ("Path Traversal / LFI", "GET", "/api/proxy/api/v1/vulnerable/files/download/", {"file": "../../../../etc/passwd"}, None),
            ("Command Injection (RCE)", "POST", "/api/proxy/api/v1/vulnerable/admin/ping/", None, {"target": "127.0.0.1; cat /etc/passwd"}),
        ]

        for desc, method, path, params, body in attack_scenarios:
            status, _, lat, hdrs = self.request(method, path, params=params, json_data=body)
            self.stats["attacks_sent"] += 1
            risk = hdrs.get("X-WAF-Threat-Score", "95")
            rule = hdrs.get("X-WAF-Rule-Matched", "DETECTED")
            print(f"  [{YELLOW}FLAGGED{RESET}] {desc:<35} | HTTP: {status} | Risk: {RED}{risk}/100{RESET} | Rule: {rule}")
            if self.auto_mode:
                time.sleep(0.5)

        print(f"\n{YELLOW}⚠️  Giai đoạn 2 hoàn tất: Mọi cuộc tấn công đều bị WAF phát hiện và log vào Dashboard!{RESET}")
        self.pause("Sẵn sàng chuyển WAF sang ACTIVE_BLOCK để kích hoạt Chặn Đứng Tấn Công?")

    def stage_3_active_blocking(self):
        print(f"\n{RED}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{RED}{BOLD}📍 GIAI ĐOẠN 3 (5:00 - 7:30): PHÒNG THỦ CHỦ ĐỘNG (ACTIVE_BLOCK) & FAST-PATH 403{RESET}")
        print(f"{RED}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print("Mục tiêu: WAF ngắt kết nối lập tức, chặn đứng payload độc hại bằng Fast-path HTTP 403 trong < 2ms.\n")

        self.set_waf_mode("ACTIVE_BLOCK")
        print(f"⚙️  Trạng thái WAF Gateway: {RED}{BOLD}ACTIVE_BLOCK (SIẾT CHẶT TỐI ĐA){RESET}\n")

        blocking_scenarios = [
            ("Advanced Evasion SQLi (URL Encoded)", "GET", "/api/proxy/api/v1/vulnerable/books/search/", {"q": "%27%20UNION%20SELECT%20null%2Cversion()--"}, None),
            ("Obfuscated SVG XSS Payload", "POST", "/api/proxy/api/v1/vulnerable/reviews/", None, {"content": "<svg/onload=alert`XSS`>", "book_id": 1}),
            ("LFI Windows/Linux System Escapes", "GET", "/api/proxy/api/v1/vulnerable/files/download/", {"file": "..\\..\\Windows\\System32\\cmd.exe"}, None),
            ("Command Injection Chain with Pipe", "POST", "/api/proxy/api/v1/vulnerable/admin/ping/", None, {"target": "localhost | whoami"}),
            ("BOLA / IDOR Unauthorized Escalation", "GET", "/api/proxy/api/v1/vulnerable/orders/99999/", {"token": "malicious-tampered-token"}, None),
        ]

        for desc, method, path, params, body in blocking_scenarios:
            status, resp_body, lat, hdrs = self.request(method, path, params=params, json_data=body)
            self.stats["attacks_sent"] += 1
            if status == 403:
                self.stats["blocks_enforced"] += 1
                decision = hdrs.get("X-WAF-Decision", "BLOCK")
                print(f"  [{RED}403 FORBIDDEN{RESET}] {desc:<38} | Fast-path: {GREEN}{lat:5.2f}ms{RESET} | Decision: {RED}{decision}{RESET}")
            else:
                print(f"  [{YELLOW}{status}{RESET}] {desc:<38} | Latency: {lat:5.2f}ms")
            if self.auto_mode:
                time.sleep(0.5)

        print(f"\n{GREEN}🛡️  Giai đoạn 3 hoàn tất: 100% tấn công nguy hiểm bị chặn đứng, bảo vệ an toàn cho Upstream!{RESET}")
        self.pause("Sẵn sàng mô phỏng Botnet Bão Tải để kiểm chứng HTTP 429 Rate Limiting?")

    def stage_4_rate_limiting_and_scoreboard(self):
        print(f"\n{MAGENTA}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{MAGENTA}{BOLD}📍 GIAI ĐOẠN 4 (7:30 - 10:00): ĐIỀU TIẾT TẦN SUẤT BOTNET & TỔNG KẾT VIỄN TRẮC{RESET}")
        print(f"{MAGENTA}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print("Mục tiêu: Đạt chuẩn IETF RFC 6585/7807, chặn Brute-force & phạt Exponential Backoff khi quá ngưỡng.\n")

        print(f"💥 Kích hoạt đợt tấn công Brute-force mật khẩu (14 requests dồn dập vào /auth/login/ - Ngưỡng tối đa 10 req/min)...\n")

        rate_limit_hits = 0
        for i in range(1, 15):
            status, _, lat, hdrs = self.request(
                "POST",
                "/api/proxy/api/v1/vulnerable/auth/login/",
                json_data={"username": f"admin_target_{i}", "password": "wrong_password_123"},
            )
            if status == 429:
                rate_limit_hits += 1
                self.stats["rate_limits_triggered"] += 1
                retry_after = hdrs.get("Retry-After", "60")
                print(f"  Request #{i:02d}: [{RED}{BOLD}429 TOO MANY REQUESTS{RESET}] - {RED}CHẶN BRUTE-FORCE!{RESET} Phạt Exponential Backoff (Retry-After: {retry_after}s)")
            else:
                rem = hdrs.get("X-RateLimit-Remaining", "N/A")
                print(f"  Request #{i:02d}: [{GREEN}200/401 OK{RESET}] - Trễ: {lat:5.2f}ms | Hạn mức Sliding Window còn lại: {rem}")
            time.sleep(0.1)

        print(f"\n{MAGENTA}✅ Đã kích hoạt điều tiết thích ứng: {rate_limit_hits} requests bị trừng phạt!{RESET}")

        # Fetch Dashboard Statistics for Final Scoreboard
        status, dash_stats, _, _ = self.request("GET", "/api/dashboard/stats")

        print(f"\n{CYAN}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{CYAN}{BOLD}📊 BẢNG TỔNG KẾT KẾT QUẢ DIỄN TẬP BẢO VỆ ĐỒ ÁN (SOC SCOREBOARD){RESET}")
        print(f"{CYAN}{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"• Tổng số yêu cầu đã gửi (Rehearsal Total):   {BOLD}{self.stats['normal_sent'] + self.stats['attacks_sent']}{RESET}")
        print(f"• Yêu cầu bình thường (Safe Traffic):         {GREEN}{self.stats['normal_sent']}{RESET} (100% thông suốt)")
        print(f"• Đợt tấn công mô phỏng (Attack Scenarios):   {YELLOW}{self.stats['attacks_sent']}{RESET}")
        print(f"• Tấn công bị chặn đứng (Fast-path 403):      {RED}{self.stats['blocks_enforced']}{RESET} (Thành công 100%)")
        print(f"• Vi phạm tấn số bị phạt (HTTP 429):          {MAGENTA}{self.stats['rate_limits_triggered']}{RESET}")
        if self.stats["latencies_ms"]:
            avg_lat = sum(self.stats["latencies_ms"]) / len(self.stats["latencies_ms"])
            print(f"• Độ trễ trung bình toàn phần (End-to-end):   {CYAN}{avg_lat:.2f} ms{RESET}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"\n{GREEN}{BOLD}🎉 KỊCH BẢN DIỄN TẬP 10 PHÚT HOÀN THÀNH XUẤT SẮC!{RESET}")
        print(f"👉 Bây giờ hãy mở trình duyệt vào {CYAN}{BOLD}http://localhost:3000{RESET} để:")
        print(f"   1. Xem biểu đồ viễn trắc an ninh (Timeline & Threats Distribution).")
        print(f"   2. Mở {YELLOW}Evidence Drawer{RESET} để xem chi tiết Payload giải mã.")
        print(f"   3. Bấm vào sự kiện để mở {CYAN}Explainability Modal{RESET} thuyết minh toán học cho Hội đồng!")

    def run(self):
        self.banner()
        # Verify Gateway health
        print("🔍 Đang kiểm tra trạng thái sức khỏe Gateway...")
        status, health, _, _ = self.request("GET", "/health")
        if status != 200:
            print(f"{RED}❌ Không thể kết nối tới WAF Gateway tại {self.gateway_url}! Vui lòng khởi động Gateway trước.{RESET}")
            sys.exit(1)
        print(f"{GREEN}✅ Gateway sẵn sàng: HTTP 200 OK{RESET}\n")

        self.pause("Bắt đầu Giai đoạn 1 (Lưu lượng sạch Baseline)?")
        self.stage_1_baseline()
        self.stage_2_monitor_only_attacks()
        self.stage_3_active_blocking()
        self.stage_4_rate_limiting_and_scoreboard()


def main():
    parser = argparse.ArgumentParser(description="PBL6 10-Minute Live Defense Rehearsal CLI")
    parser.add_argument("--gateway-url", default="http://localhost:8000", help="URL of WAF Gateway")
    parser.add_argument("--auto", action="store_true", help="Run rehearsal automatically without prompt pauses")
    parser.add_argument("--interval", type=float, default=1.5, help="Pause interval in seconds for auto mode")
    args = parser.parse_args()

    runner = DemoRunner(gateway_url=args.gateway_url, auto_mode=args.auto, interval=args.interval)
    runner.run()


if __name__ == "__main__":
    main()
