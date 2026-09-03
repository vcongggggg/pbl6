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

def create_issue(token, title, body, labels):
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
            "User-Agent": "PBL6-All-Subtasks-Creator",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
    )
    with urllib.request.urlopen(req) as resp:
        issue = json.loads(resp.read().decode())
        print(f"Created #{issue['number']}: {title}")
        return issue["number"]

ALL_SUBTASKS = [
    # Phase 4
    {
        "title": "[Task 4.1] Generate Synthetic Benign HTTP Traffic Dataset (10,000 samples)",
        "body": "### Mục tiêu\nTạo 10,000 requests hợp lệ mô phỏng tương tác bình thường của người dùng trên Juice Shop.\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `data/synthetic_benign.csv`",
        "labels": ["phase-4", "dataset", "member-b"]
    },
    {
        "title": "[Task 4.2] Generate Synthetic Malicious Attack Dataset with Evasion Variations",
        "body": "### Mục tiêu\nTạo các biến thể payload SQLi, XSS, Path Traversal, Cmd Injection kèm làm rối (Obfuscation).\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `data/synthetic_attacks.csv`",
        "labels": ["phase-4", "dataset", "member-b"]
    },
    {
        "title": "[Task 4.3] Preprocessing, Stratified Split & Label Distribution Report",
        "body": "### Mục tiêu\nLàm sạch dữ liệu, gán nhãn 5 lớp (`0: BENIGN, 1: SQLI, 2: XSS, 3: PATH, 4: CMD`), chia tỷ lệ 70/15/15.\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `data/processed/train.csv`, `test.csv`",
        "labels": ["phase-4", "dataset", "member-b"]
    },

    # Phase 5
    {
        "title": "[Task 5.1] Random Forest Model Training Pipeline with Hyperparameter Tuning",
        "body": "### Mục tiêu\nXây dựng script huấn luyện `RandomForestClassifier` với GridSearchCV (`n_estimators`, `max_depth`).\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `ml-engine/models/train_rf.py`",
        "labels": ["phase-5", "random-forest", "member-b"]
    },
    {
        "title": "[Task 5.2] Model Validation, Metrics Evaluation (Precision, Recall, F1, ROC-AUC)",
        "body": "### Mục tiêu\nĐo lường Precision, Recall, F1-Score từng lớp và vẽ biểu đồ Ma trận nhầm lẫn (Confusion Matrix).\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `docs/reports/rf_evaluation.md`",
        "labels": ["phase-5", "random-forest", "member-b"]
    },
    {
        "title": "[Task 5.3] Model Serialization & Export (rf_model.joblib + schema metadata)",
        "body": "### Mục tiêu\nXuất mô hình `rf_model.joblib` kèm file JSON lưu danh sách 17 features và ngưỡng phân loại.\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `ml-engine/artifacts/rf_model.joblib`",
        "labels": ["phase-5", "random-forest", "member-b"]
    },
    {
        "title": "[Task 5.4] FastAPI Gateway ML Inference Service Integration (<15ms latency)",
        "body": "### Mục tiêu\nNạp model vào bộ nhớ RAM khi Gateway khởi động, dự đoán thời gian thực với độ trễ $< 15\\text{ms}$.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/security/ml_detector.py`",
        "labels": ["phase-5", "gateway", "member-a"]
    },

    # Phase 6
    {
        "title": "[Task 6.1] Isolation Forest Training Pipeline on Pure Benign Baseline",
        "body": "### Mục tiêu\nHuấn luyện mô hình Isolation Forest chỉ trên dữ liệu hợp lệ để học phân bố lưu lượng chuẩn.\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `ml-engine/models/train_iforest.py`",
        "labels": ["phase-6", "anomaly-detection", "member-b"]
    },
    {
        "title": "[Task 6.2] Anomaly Score Calibration & Normalization (0 - 100 Risk Scale)",
        "body": "### Mục tiêu\nChuyển đổi raw decision function của Isolation Forest thành thang điểm rủi ro trực quan từ 0 đến 100.\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `gateway/app/security/anomaly.py`",
        "labels": ["phase-6", "anomaly-detection", "member-b"]
    },
    {
        "title": "[Task 6.3] Zero-Day & Obfuscated Attack Anomaly Detection Evaluation",
        "body": "### Mục tiêu\nĐánh giá khả năng phát hiện các payload bị làm rối dị biệt mà Rule Engine và RF bỏ sót.\n\n### Phân công\n- **Phụ trách:** Thành viên B (ML/Data)\n- **Deliverable:** `docs/reports/anomaly_eval.md`",
        "labels": ["phase-6", "anomaly-detection", "member-b"]
    },
    {
        "title": "[Task 6.4] Gateway Anomaly Detection Hook & Realtime Logging",
        "body": "### Mục tiêu\nGọi bộ kiểm tra bất thường trong Gateway và ghi nhận trường `anomaly_score` vào `security_events`.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/security/engine.py`",
        "labels": ["phase-6", "gateway", "member-a"]
    },

    # Phase 7
    {
        "title": "[Task 7.1] Weighted Risk Scoring Aggregator (Rule 40% + RF 35% + IF 25%)",
        "body": "### Mục tiêu\nTổng hợp điểm số: $\\text{Score} = 0.40 \\times \\text{Rule} + 0.35 \\times \\text{RF} + 0.25 \\times \\text{Anomaly}$.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/security/risk_engine.py`",
        "labels": ["phase-7", "decision-engine", "member-a"]
    },
    {
        "title": "[Task 7.2] Policy Decision Engine (ALLOW / MONITOR / RATE_LIMIT / BLOCK)",
        "body": "### Mục tiêu\nĐịnh nghĩa 4 hành động: $<30$ `ALLOW`, $30-60$ `MONITOR`, $60-80$ `RATE_LIMIT`, $>80$ `BLOCK (403)`.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/security/decision.py`",
        "labels": ["phase-7", "decision-engine", "member-a"]
    },
    {
        "title": "[Task 7.3] Enforcement Reverse Proxy Middleware with Safe Custom 403 Page",
        "body": "### Mục tiêu\nKhi quyết định là `BLOCK`, ngắt luồng proxy ngay lập tức, trả về HTTP 403 tùy biến an toàn.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/api/proxy.py`",
        "labels": ["phase-7", "gateway", "member-a"]
    },

    # Phase 8
    {
        "title": "[Task 8.1] In-Memory Sliding Window IP Request Counter & Endpoint Tracker",
        "body": "### Mục tiêu\nQuản lý bộ đếm request theo IP trong bộ nhớ RAM với thời gian trượt 60 giây.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/security/rate_limiter.py`",
        "labels": ["phase-8", "rate-limiting", "member-a"]
    },
    {
        "title": "[Task 8.2] Dynamic HTTP 429 Too Many Requests Enforcement & Retry-After Header",
        "body": "### Mục tiêu\nTự động chặn tạm thời IP vượt ngưỡng tần suất (RPS limit) kèm header `Retry-After: 60`.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `gateway/app/api/proxy.py`",
        "labels": ["phase-8", "rate-limiting", "member-a"]
    },

    # Phase 9
    {
        "title": "[Task 9.1] Gateway Admin Stats & Event Stream REST APIs (/api/stats, /api/events)",
        "body": "### Mục tiêu\nViết các endpoint `GET /api/stats`, `GET /api/events`, `GET /api/traffic-series` trên FastAPI Gateway.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Dashboard UI)\n- **Deliverable:** `gateway/app/api/dashboard.py`",
        "labels": ["phase-9", "dashboard", "member-a"]
    },
    {
        "title": "[Task 9.2] Overview Metric Cards & Real-Time Threat Activity Charts",
        "body": "### Mục tiêu\nThiết kế Overview Cards và biểu đồ dòng thời gian tấn công bằng Recharts/Chart.js trên Next.js.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Dashboard UI)\n- **Deliverable:** `dashboard/src/components/charts/`",
        "labels": ["phase-9", "dashboard", "member-a"]
    },
    {
        "title": "[Task 9.3] Interactive Security Events Table with Filter, Search & Payload Viewer",
        "body": "### Mục tiêu\nBảng có tìm kiếm, lọc theo Severity, IP, Attack Type và cửa sổ xem chi tiết payload evidence.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Dashboard UI)\n- **Deliverable:** `dashboard/src/components/events/`",
        "labels": ["phase-9", "dashboard", "member-a"]
    },
    {
        "title": "[Task 9.4] Detection Explainability Modal (Why WAF Blocked: Rule vs ML vs Anomaly)",
        "body": "### Mục tiêu\nTrực quan hóa lý do WAF chặn (Rule nào khớp, Model nào dự đoán, điểm bao nhiêu).\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Dashboard UI)\n- **Deliverable:** `dashboard/src/components/explain/`",
        "labels": ["phase-9", "dashboard", "member-a"]
    },

    # Phase 10
    {
        "title": "[Task 10.1] API Reconnaissance Module (Target Spec Discovery & Endpoint Mapping)",
        "body": "### Mục tiêu\nTác nhân AI tự động đọc OpenAPI spec của Juice Shop để lập danh sách endpoint và tham số.\n\n### Phân công\n- **Phụ trách:** Thành viên B (AI/ML & Red Team)\n- **Deliverable:** `attack-lab/agent/recon.py`",
        "labels": ["phase-10", "attack-lab", "offensive-ai", "member-b"]
    },
    {
        "title": "[Task 10.2] Multi-Step Attack Planning Agent with ReAct Reasoning Loop",
        "body": "### Mục tiêu\nSử dụng LLM suy luận chuỗi tấn công logic (Thăm dò $\\rightarrow$ Khai thác SQLi $\\rightarrow$ Chiếm quyền).\n\n### Phân công\n- **Phụ trách:** Thành viên B (AI/ML & Red Team)\n- **Deliverable:** `attack-lab/agent/planner.py`",
        "labels": ["phase-10", "attack-lab", "offensive-ai", "member-b"]
    },
    {
        "title": "[Task 10.3] Adaptive Evasion Engine (Obfuscate Payloads on 403 WAF Block)",
        "body": "### Mục tiêu\nKhi nhận phản hồi HTTP 403 từ WAF, tự động biến đổi payload (Hex, Double URL) để thử vượt rào.\n\n### Phân công\n- **Phụ trách:** Thành viên B (AI/ML & Red Team)\n- **Deliverable:** `attack-lab/agent/evasion.py`",
        "labels": ["phase-10", "attack-lab", "offensive-ai", "member-b"]
    },
    {
        "title": "[Task 10.4] Attack Campaign Runner CLI & AI Arena Visualization",
        "body": "### Mục tiêu\nCLI runner chạy chiến dịch kiểm thử tự động và màn hình đối kháng trực tiếp trên Dashboard.\n\n### Phân công\n- **Phụ trách:** Thành viên B & A\n- **Deliverable:** `attack-lab/runner.py`, `dashboard/src/app/arena/page.tsx`",
        "labels": ["phase-10", "attack-lab", "offensive-ai", "member-b", "member-a"]
    },

    # Phase 11
    {
        "title": "[Task 11.1] Benchmark Experiment: Rule vs RF vs IF vs Hybrid on Clean Test Set",
        "body": "### Mục tiêu\nĐo lường Precision, Recall, F1, FPR giữa (1) Chỉ Rule, (2) Chỉ RF, (3) Chỉ IF, (4) Hybrid.\n\n### Phân công\n- **Phụ trách:** Thành viên B (AI/ML & Red Team)\n- **Deliverable:** `docs/reports/benchmark.md`",
        "labels": ["phase-11", "benchmark", "member-b"]
    },
    {
        "title": "[Task 11.2] Adversarial Robustness Test: WAF Detection Rate on AI-Generated Attacks",
        "body": "### Mục tiêu\nThống kê tỷ lệ WAF chặn thành công các payload biến dị do AI Attack Planner sinh ra.\n\n### Phân công\n- **Phụ trách:** Thành viên B (AI/ML & Red Team)\n- **Deliverable:** `docs/reports/evasion_benchmark.md`",
        "labels": ["phase-11", "benchmark", "member-b"]
    },
    {
        "title": "[Task 11.3] Gateway Performance & Latency Overhead Profiling under Load",
        "body": "### Mục tiêu\nĐo độ trễ trung bình, RPS tối đa và mức tiêu thụ RAM/CPU của Gateway khi bật đầy đủ AI.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `docs/reports/performance_profile.md`",
        "labels": ["phase-11", "benchmark", "member-a"]
    },
    {
        "title": "[Task 11.4] Comprehensive Evaluation Report, Plots & Metrics Tables",
        "body": "### Mục tiêu\nXuất biểu đồ so sánh ROC-AUC, biểu đồ thời gian xử lý phục vụ báo cáo bảo vệ.\n\n### Phân công\n- **Phụ trách:** Thành viên B (AI/ML & Red Team)\n- **Deliverable:** `docs/reports/final_evaluation.md`",
        "labels": ["phase-11", "benchmark", "member-b"]
    },

    # Phase 12
    {
        "title": "[Task 12.1] Gateway Security Hardening, Clean Error Responses & Audit Logs",
        "body": "### Mục tiêu\nKhử rò rỉ bộ nhớ, kiểm toán bảo mật mã nguồn, chuẩn hóa error handlers an toàn tuyệt đối.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** Gateway release candidate",
        "labels": ["phase-12", "hardening", "member-a"]
    },
    {
        "title": "[Task 12.2] Production Docker Compose Multi-Container Orchestration Verification",
        "body": "### Mục tiêu\nĐảm bảo toàn bộ 3 dịch vụ (Gateway, Dashboard, Juice Shop) khởi động 1 lệnh `docker compose up`.\n\n### Phân công\n- **Phụ trách:** Thành viên A (Tech Lead / Backend)\n- **Deliverable:** `docker-compose.yml` verified",
        "labels": ["phase-12", "hardening", "member-a"]
    },
    {
        "title": "[Task 12.3] End-to-End Live Rehearsal Script & 10-Minute Demo Scenario",
        "body": "### Mục tiêu\nChuẩn bị script tự động kích hoạt đợt tấn công của AI để biểu diễn trực tiếp trước Hội đồng.\n\n### Phân công\n- **Phụ trách:** Thành viên A & B\n- **Deliverable:** `scripts/demo_rehearsal.py`",
        "labels": ["phase-12", "demo", "member-a", "member-b"]
    },
    {
        "title": "[Task 12.4] Academic Defense Slide Deck & Final PBL6 Project Thesis Report",
        "body": "### Mục tiêu\nSoạn thảo báo cáo PDF hoàn chỉnh theo mẫu trường và thiết kế slide thuyết trình bảo vệ.\n\n### Phân công\n- **Phụ trách:** Thành viên A & B\n- **Deliverable:** `docs/PBL6_FINAL_REPORT.pdf` & Slides",
        "labels": ["phase-12", "documentation", "member-a", "member-b"]
    }
]

def main():
    token = get_git_token()
    if not token:
        print("Error: Could not retrieve GitHub token")
        return
    
    print(f"Starting creation of {len(ALL_SUBTASKS)} subtasks across all phases on GitHub...")
    for item in ALL_SUBTASKS:
        create_issue(token, item["title"], item["body"], item["labels"])
        time.sleep(0.4)
    print("\nAll subtasks across all phases created successfully on GitHub!")

if __name__ == "__main__":
    main()
