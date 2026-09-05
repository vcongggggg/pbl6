# Kiến Trúc Hệ Thống (System Architecture) — PBL6

## 1. Tổng Quan Kiến Trúc (Architecture Overview)

Dự án **Web API Security Platform** được xây dựng nhằm cung cấp giải pháp bảo vệ toàn diện cho các dịch vụ Web API thông qua kiến trúc Reverse Proxy Gateway kết hợp đa tầng phòng thủ:

```mermaid
graph TD
    Client[Người dùng / Attack Lab] -->|HTTP Request /api/proxy/...| Gateway[FastAPI WAF Gateway]
    
    subgraph Gateway_Pipeline["Gateway Request Pipeline (Phase 1-8)"]
        ReqID[Request ID Resolver & Header Filter]
        Parser[Request Surface Parser: Path, Query, Header, Body]
        Normalizer[Input Normalizer: URL, HTML, Unicode, Spaces]
        
        subgraph Detection_Engines["Detection Layer (Phase 2-6)"]
            RuleEngine[Rule Engine - Phase 2: SQLi, XSS, Path, Cmd]
            RFEngine[Random Forest Model - Planned Phase 5]
            IFEngine[Isolation Forest Model - Planned Phase 6]
        end
        
        RiskEngine[Risk Scoring Engine - Planned Phase 7]
        DecisionEngine[Decision Engine - Planned Phase 7]
        RateLimiter[Rate Limiter - Planned Phase 8]
    end
    
    Gateway --> ReqID
    ReqID --> Parser
    Parser --> Normalizer
    Normalizer --> RuleEngine
    RuleEngine -.-> RFEngine
    RuleEngine -.-> IFEngine
    
    RuleEngine -->|Persist Detected Incidents| DB_Sec[(SQLite: security_events)]
    
    Normalizer -->|Phase 2: Non-blocking Async Proxy Forward| Target[Target Web API - Juice Shop]
    
    Gateway -->|Async Traffic Log & Redaction| DB_Req[(SQLite: requests)]
    Dashboard[Next.js Dashboard - Phase 9] <-->|API Base URL| Gateway
```

---

## 2. Ranh Giới Và Trách Nhiệm Từng Thành Phần (Component Boundaries)

### 2.1. `gateway/` (Backend / WAF Engine)
* **Phase 0:** Khởi tạo ứng dụng FastAPI, cấu hình biến môi trường (`core/config.py`), logging chuẩn (`core/logging.py`), xử lý lỗi an toàn (`core/errors.py`), cấu trúc cơ sở dữ liệu SQLAlchemy (`db/`), và endpoint kiểm tra trạng thái `GET /health`.
* **Phase 1:** Dynamic Reverse Proxy bất đồng bộ (`/api/proxy/{path:path}`), quản lý `X-Request-ID`, lọc hop-by-hop headers, khử thông tin nhạy cảm, chống Open Proxy/SSRF, và endpoint `GET /health/target`.
* **Phase 2 (Hoàn thành):**
  * Triển khai **Rule Engine** (`app/security/`) với 16 rules tất định phủ 4 họ tấn công (SQL Injection, XSS, Path Traversal, Command Injection).
  * Bộ chuẩn hóa dữ liệu đầu vào có giới hạn độ sâu và độ dài (`InputNormalizer`).
  * Cơ chế chấm điểm rủi ro tất định từ 0 đến 100 (`RuleScorer`).
  * Lưu trữ và truy vết sự kiện bảo mật vào bảng `security_events` liên kết chặt chẽ với bảng `requests` qua `request_id`.
  * Hoạt động theo nguyên tắc **Detection Only (Non-blocking)**: Không chặn request ở Phase 2, request vẫn tiếp tục được forward sang target.
* **Tương lai (Phase 3–8 - Planned):** Triển khai trích xuất đặc trưng payload, nạp mô hình ML inference, tính toán Risk score và cơ chế chặn/rate limit.

### 2.2. `ml-engine/` (ML/Data Boundary - Reserved for ML Team)
* **Hiện tại (Phase 0-2):** Khởi tạo cấu trúc thư mục và tài liệu giao diện kết nối kỹ thuật [docs/ML_INTEGRATION.md](file:///c:/Study/HocKy6/PBL6/docs/ML_INTEGRATION.md).
* **Tương lai (Phase 3–6, 11 - Planned):** Xây dựng module trích xuất đặc trưng, sinh tập dữ liệu huấn luyện, huấn luyện mô hình Random Forest & Isolation Forest, xuất file artifacts (`.joblib`).

### 2.3. `dashboard/` (Frontend Visualization & SOC Command Center)
* **Hiện tại (Đã hoàn thành Phase 9 Task 9.1 & 9.2):**
  * Giao diện trung tâm chỉ huy an ninh **SOC Command Center** chuẩn Dark Cyber Glassmorphism trên Next.js 14 + Tailwind CSS + Lucide Icons + Recharts.
  * **5 Thẻ KPI:** Total Traffic (RPS), Attacks Detected, Threat Score (Rule Engine Phase 2), Safe Request Rate (Forwarded 200 OK), và Hộp **Quick Simulator 1-click test**.
  * **Biểu đồ thời gian thực:** Recharts Area Chart sóng kép (Benign vs Attacks) và Donut Chart phân bố 4 họ tấn công.
  * **Bảng Live Security Events Table:** Tìm kiếm, phân trang, lọc Severity/Type, xuất file JSON.
  * **Payload Evidence Drawer:** Tab 1 xem chi tiết bằng chứng Rule Engine (Raw vs Canonical Normalized), Tab 2 chờ sẵn 17-Feature Vector cho Phase 3.
  * Tích hợp 6 REST APIs thật trên Gateway (`/api/dashboard/*`), cơ chế Smart Polling tự động tạm dừng khi xem chi tiết bằng chứng.
* **Tương lai (Phase 5-7 - Planned):** Bổ sung hiển thị nhãn Random Forest, Anomaly gauge của Isolation Forest, và điều khiển chế độ chặn Active Defense (HTTP 403).

### 2.4. `attack-lab/` (Offensive AI — AI Attack Planner & Autonomous Red Teaming)
* **Hiện tại (Phase 0-2):** Cấu trúc thư mục kịch bản `scenarios/` và tài liệu hướng dẫn an toàn.
* **Định hướng nâng cấp (Phase 10 — Theo chỉ đạo của Thầy hướng dẫn):**
  * Nâng cấp từ script kịch bản tĩnh thành **AI Attack Planner Agent (Autonomous Red Teaming)**.
  * Sử dụng AI để lập kế hoạch tấn công có mục tiêu, tự động sinh chuỗi request khai thác (SQLi, XSS, Path, Cmd, Brute Force).
  * **Adaptive Evasion Engine:** Khi Gateway chặn bằng mã `403 Forbidden`, AI Agent sẽ tự động phân tích và áp dụng các kỹ thuật biến đổi payload (Obfuscation, URL encoding, token mixing, semantic mutation) để thử nghiệm vượt rào và đánh giá độ bền vững (Robustness) của hệ thống phòng thủ.

---

## 3. Quy Ước Trạng Thái Triển Khai

| Module / Tính Năng | Trạng Thái Hiện Tại | Kế Hoạch Triển Khai |
| :--- | :---: | :--- |
| **FastAPI Foundation & Health API** | ✅ Implemented | Phase 0 |
| **Centralized Config & Safe Logging** | ✅ Implemented | Phase 0 |
| **Database Models & Session Management** | ✅ Implemented | Phase 0 |
| **Next.js Frontend Foundation** | ✅ Implemented | Phase 0 |
| **Docker Compose Orchestration** | ✅ Implemented | Phase 0 |
| **Reverse Proxy & Request Forwarding** | ✅ Implemented | Phase 1 |
| **Traffic Metadata & Redacted DB Logging** | ✅ Implemented | Phase 1 |
| **Open Proxy / SSRF Protection** | ✅ Implemented | Phase 1 |
| **Target Connectivity Health Probe** | ✅ Implemented | Phase 1 |
| **Rule-based Detection Engine (16 Rules)** | ✅ Implemented | Phase 2 |
| **Input Normalization & Canonicalization** | ✅ Implemented | Phase 2 |
| **Rule Risk Scoring (0–100 Bounded)** | ✅ Implemented | Phase 2 |
| **Security Events DB Traceability** | ✅ Implemented | Phase 2 |
| **SOC Dashboard UI & Real-time Charts** | ✅ Implemented | Phase 9 (Task 9.1 & 9.2) |
| **Feature Extraction (17 Payload + Behavior)**| ⏳ Planned | Phase 3 (ML Team) |
| **Dataset Generation & Lab Collection** | ⏳ Planned | Phase 4 (ML Team) |
| **Random Forest Supervised ML** | ⏳ Planned | Phase 5 (ML Team) |
| **Isolation Forest Anomaly Detection** | ⏳ Planned | Phase 6 (ML Team) |
| **Weighted Risk Scoring & Decision Engine** | ⏳ Planned | Phase 7 |
| **IP-based Rate Limiter (HTTP 429)** | ⏳ Planned | Phase 8 |
| **AI Attack Planner & Autonomous Red Team** | ⏳ Planned | Phase 10 |
| **Multi-method Evaluation & Benchmark** | ⏳ Planned | Phase 11 (ML Team) |
| **Final Hardening & Defense Report** | ⏳ Planned | Phase 12 |
