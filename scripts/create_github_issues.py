import urllib.request
import json
import subprocess
import time

def get_git_token():
    p = subprocess.Popen(
        ['git', 'credential', 'fill'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    out, _ = p.communicate(input="url=https://github.com/vcongggggg/pbl6\n")
    for line in out.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    return None

def create_issue(token, title, body, labels, close=False):
    url = "https://api.github.com/repos/vcongggggg/pbl6/issues"
    data = {
        "title": title,
        "body": body,
        "labels": labels
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "PBL6-Issue-Creator",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
    )
    with urllib.request.urlopen(req) as resp:
        issue = json.loads(resp.read().decode())
        issue_number = issue["number"]
        print(f"Created Issue #{issue_number}: {title}")

    if close:
        update_url = f"https://api.github.com/repos/vcongggggg/pbl6/issues/{issue_number}"
        update_data = {"state": "closed"}
        patch_req = urllib.request.Request(
            update_url,
            data=json.dumps(update_data).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "PBL6-Issue-Creator",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            },
            method="PATCH"
        )
        with urllib.request.urlopen(patch_req) as patch_resp:
            print(f"  -> Marked #{issue_number} as CLOSED (Completed)")

    return issue_number

TASKS = [
    {
        "title": "[Phase 0] Bootstrap Monorepo, Docker Compose & FastAPI Foundation",
        "body": "### Mục tiêu\nKhởi tạo cấu trúc dự án monorepo, Docker Compose stack (Gateway, Dashboard, Juice Shop), SQLite database schema, logging chuẩn, kiểm thử tự động và CI.\n\n### Trạng thái\n✅ **HOÀN THÀNH 100%**",
        "labels": ["phase-0", "infrastructure", "completed"],
        "close": True
    },
    {
        "title": "[Phase 1] Real Reverse Proxy Gateway & SQLite Traffic Logging",
        "body": "### Mục tiêu\nXây dựng Reverse Proxy bất đồng bộ trên FastAPI (`/api/proxy/{path}`), quản lý `X-Request-ID`, lọc hop-by-hop headers, ghi nhật ký lưu lượng vào SQLite (`requests`) và kiểm tra sức khỏe upstream `/health/target`.\n\n### Trạng thái\n✅ **HOÀN THÀNH 100% (7/7 live tests passed)**",
        "labels": ["phase-1", "gateway", "completed"],
        "close": True
    },
    {
        "title": "[Phase 2] Rule Engine: Signature Detection for SQLi, XSS, Path Traversal, Cmd Injection",
        "body": "### Mục tiêu\nTriển khai bộ luật 16 rules tĩnh tất định, Input Normalizer đa tầng, tính điểm rủi ro Rule Risk Score (0-100), lưu vết sự kiện an ninh vào bảng `security_events`.\n\n### Trạng thái\n✅ **HOÀN THÀNH 100% (33/33 unit tests passed, 0 Ruff errors)**",
        "labels": ["phase-2", "security", "rule-engine", "completed"],
        "close": True
    },
    {
        "title": "[Phase 3] Feature Engineering: Extract 17 Payload & Behavior Features",
        "body": "### Mục tiêu\nTrích xuất 17 đặc trưng định lượng từ HTTP requests (độ dài URL/body, Shannon entropy, tỷ lệ ký tự đặc biệt, tần suất từ khóa SQLi/XSS/Command, HTTP method, client behavior) làm đầu vào cho Machine Learning.\n\n### Deliverables\n- `ml-engine/features/extractor.py`\n- Unit tests kiểm thử vector đặc trưng",
        "labels": ["phase-3", "ml-engine", "feature-engineering"],
        "close": False
    },
    {
        "title": "[Phase 4] Dataset Generation & Lab Traffic Collection",
        "body": "### Mục tiêu\nThu thập và sinh tập dữ liệu lưu lượng Web API thực tế (kết hợp lưu lượng hợp lệ Benign và lưu lượng tấn công Malicious đa dạng) phục vụ huấn luyện mô hình.\n\n### Deliverables\n- Dataset CSV/Parquet đã gán nhãn chuẩn hóa\n- Script sinh dữ liệu tự động",
        "labels": ["phase-4", "dataset", "ml-engine"],
        "close": False
    },
    {
        "title": "[Phase 5] Supervised Machine Learning: Random Forest Multiclass Model",
        "body": "### Mục tiêu\nHuấn luyện mô hình Random Forest phân loại đa nhãn (BENIGN, SQLI, XSS, PATH_TRAVERSAL, CMD_INJECTION), đánh giá Precision/Recall/F1-score và đóng gói artifact `.joblib`.\n\n### Deliverables\n- Pipeline huấn luyện và đánh giá\n- File model artifact tích hợp vào Gateway",
        "labels": ["phase-5", "ml-engine", "random-forest"],
        "close": False
    },
    {
        "title": "[Phase 6] Anomaly Detection: Isolation Forest Time-window Model",
        "body": "### Mục tiêu\nHuấn luyện mô hình Isolation Forest phát hiện hành vi tấn công bất thường, API abuse và các payload biến dị chưa từng thấy dựa trên cửa sổ thời gian trượt.\n\n### Deliverables\n- Isolation Forest model artifact\n- Inference pipeline tính Anomaly Score",
        "labels": ["phase-6", "ml-engine", "anomaly-detection"],
        "close": False
    },
    {
        "title": "[Phase 7] Hybrid Risk Engine & Decision Engine (ALLOW / MONITOR / RATE_LIMIT / BLOCK)",
        "body": "### Mục tiêu\nTổng hợp điểm số từ Rule Engine, Random Forest và Isolation Forest thành điểm nguy cơ hợp nhất (Total Risk Score 0-100), đưa ra quyết định thực thi: ALLOW, MONITOR, RATE_LIMIT (429), hoặc BLOCK (403).\n\n### Deliverables\n- Decision Engine module\n- Blocking proxy middleware",
        "labels": ["phase-7", "gateway", "decision-engine"],
        "close": False
    },
    {
        "title": "[Phase 8] IP-based Rate Limiting & Sliding Window Tracker",
        "body": "### Mục tiêu\nTriển khai cơ chế kiểm soát tần suất truy cập theo địa chỉ IP sử dụng thuật toán cửa sổ trượt (Sliding Window), tự động kích hoạt HTTP 429 khi phát hiện dấu hiệu quét tự động hoặc brute-force.\n\n### Deliverables\n- Rate Limiter middleware\n- IP tracker repository",
        "labels": ["phase-8", "gateway", "rate-limiting"],
        "close": False
    },
    {
        "title": "[Phase 9] Security Dashboard UI & Real-time Threat Visualization",
        "body": "### Mục tiêu\nXây dựng giao diện Next.js trực quan: Thống kê lưu lượng thời gian thực, bảng Security Events có filter, biểu đồ phân bố loại tấn công và màn hình giải thích nguyên nhân quyết định WAF.\n\n### Deliverables\n- Real-time event feed\n- Interactive charts & alert panels",
        "labels": ["phase-9", "frontend", "dashboard"],
        "close": False
    },
    {
        "title": "[Phase 10] AI Attack Planner: Autonomous Red Teaming & Adaptive Evasion",
        "body": "### Mục tiêu\nNâng cấp Attack Lab thành tác nhân AI (Agent) có khả năng tự động đọc API specification của Juice Shop, lập kế hoạch tấn công nhiều bước và tự biến đổi payload (Evasion) khi bị WAF chặn.\n\n### Deliverables\n- ReAct Planning Agent\n- Automated penetration testing runner",
        "labels": ["phase-10", "attack-lab", "offensive-ai"],
        "close": False
    },
    {
        "title": "[Phase 11] Multi-method Evaluation & Benchmark Comparison (Rules vs ML vs Hybrid)",
        "body": "### Mục tiêu\nThực nghiệm đo lường và so sánh hiệu quả giữa 4 phương pháp: (1) Chỉ dùng Rule, (2) Chỉ dùng ML, (3) Chỉ dùng Anomaly, (4) Hybrid Defense trước các đợt tấn công của AI Attack Planner.\n\n### Deliverables\n- Báo cáo đối chiếu F1-Score, FPR, Độ trễ (Latency ms)\n- Biểu đồ Benchmark",
        "labels": ["phase-11", "evaluation", "benchmark"],
        "close": False
    },
    {
        "title": "[Phase 12] Final System Hardening, Audit Logs & Production Defense Report",
        "body": "### Mục tiêu\nTối ưu hóa hiệu năng toàn diện, rà soát bảo mật mã nguồn, hoàn thiện nhật ký kiểm toán (Audit Log) và chuẩn bị tài liệu báo cáo nghiệm thu đồ án PBL6.\n\n### Deliverables\n- Báo cáo đồ án hoàn chỉnh\n- Bộ tài liệu thuyết trình & kịch bản demo",
        "labels": ["phase-12", "documentation", "hardening"],
        "close": False
    }
]

def main():
    token = get_git_token()
    if not token:
        print("Error: Could not retrieve GitHub token")
        return
    
    print(f"Starting creation of {len(TASKS)} GitHub Issues on vcongggggg/pbl6...")
    for item in TASKS:
        create_issue(token, item["title"], item["body"], item["labels"], item["close"])
        time.sleep(0.5)
    print("\nAll 13 Issues created successfully!")

if __name__ == "__main__":
    main()
