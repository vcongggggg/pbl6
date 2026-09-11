# Tiến Độ Triển Khai Dự Án (Project Progress)

Tài liệu theo dõi trạng thái thực hiện các giai đoạn phát triển (Development Phases) theo đặc tả trong [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).

---

## Bảng Tổng Hợp Trạng Thái Các Phase (Phase 0 → Phase 12)

| Phase | Tên Giai Đoạn (Phase Name) | Phân Công Trọng Tâm | Trạng Thái (Status) | Ghi Chú |
| :---: | :--- | :--- | :---: | :--- |
| **Phase 0** | **Project Bootstrap & Codebase Foundation** | Toàn đội / System Architect | **COMPLETED** | Thiết lập cấu trúc Monorepo, tooling, CI, database models, tests và Next.js. |
| **Phase 1** | **Infrastructure Setup** | Backend / DevOps (Member A) | **COMPLETED** | Reverse Proxy bất đồng bộ, X-Request-ID, lọc Header, ghi log SQLite, bảo vệ Open Proxy / SSRF, Probe Target Health. |
| **Phase 2** | **Rule Engine / Signature-Based Detection** | Security Engineer (Member A) | **COMPLETED** | 16 rules tất định (SQLi, XSS, Path Traversal, Command Injection), Input Normalizer, Rule Risk Scoring (0-100), Security Event persistence & traceability. |
| **Phase 2B**| **Custom Vulnerable Web API (`vulnerable-api`)** | Tech Lead (Member A) | **COMPLETED ✅** | Tự xây dựng Web API mục tiêu (Bookie Bookstore - 8 kịch bản lỗ hổng chuẩn OWASP Web & API Top 10 + OpenAPI Recon) thay thế Juice Shop theo chỉ đạo của Thầy. |
| **Phase 3** | **Feature Engineering** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* 17 payload features, HTTP & Context features. |
| **Phase 4** | **Dataset Generation & Lab Traffic** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* Sinh dữ liệu từ vulnerable-api + SecLists. |
| **Phase 5** | **Supervised ML — Random Forest** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* Training, Multiclass, Evaluation, Serialization (`.joblib`). |
| **Phase 6** | **Anomaly Detection — Isolation Forest** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* Behavior window, Isolation Forest anomaly scoring. |
| **Phase 7** | **Hybrid Risk Engine & Decision** | Backend / Security (Member A) | **NOT STARTED** | Weighted Risk Score (0–100), Thresholds (ALLOW/MONITOR/RATE_LIMIT/BLOCK). |
| **Phase 8** | **Rate Limiting & Behavior Tracker** | Backend / Security (Member A) | **NOT STARTED** | IP tracking time-window, HTTP 429 response, endpoint limits. |
| **Phase 9** | **Dashboard UI (Next.js)** | Frontend / Tech Lead (Member A) | **COMPLETED (100% Tasks 9.1 → 9.5) ✅** | SOC Dashboard, 5 KPI cards, Timeline, Distribution, Events table with Client IP origin, Payload Drawer, Quick Simulator, Reset Demo, Detection Explainability Modal (#38). |
| **Phase 10** | **Offensive AI — AI Attack Planner (Máy 2)** | AI/ML & Red Team (Member B) | **NOT STARTED** | AI Attack Planner Agent trên Máy 2, trinh sát OpenAPI, sinh payload né tránh (Adaptive Evasion) qua mạng LAN. |
| **Phase 11** | **System Evaluation & Comparison** | ML/Data & Red Team (Member B & A) | **NOT STARTED** | So sánh Rule vs ML vs Anomaly vs Hybrid, Evasion test, Benchmark. |
| **Phase 12** | **Final Hardening & Thesis Report** | Toàn đội (Member A & B) | **NOT STARTED** | Chạy multi-machine lab, audit log, hoàn thiện slide thuyết trình và báo cáo đồ án. |

> **🔔 ĐIỀU CHỈNH CHIẾN LƯỢC THEO CHỈ ĐẠO CỦA GIẢNG VIÊN HƯỚNG DẪN:**
> * Không sử dụng OWASP Juice Shop vì là sản phẩm bên thứ ba có sẵn; nhóm tự xây dựng service **`vulnerable-api`** (FastAPI) để làm chủ 100% mã nguồn và logic lỗ hổng.
> * Triển khai mô hình **Thao trường An ninh Đối kháng Phân tán (Distributed Cyber Range)** giữa 2 máy vật lý qua mạng LAN: **MÁY 1 (Blue Team: `vcongggggg`)** đối đầu với **MÁY 2 (Red Team: `naocavang08`)**.

---

## Chi Tiết Triển Khai Từng Phase

### Phase 0 — Project Bootstrap & Codebase Foundation (COMPLETED)
* Monorepo layout, FastAPI backend structure, SQLite models, Next.js frontend, Docker Compose, Makefile, CI workflow.

---

### Phase 1 — Infrastructure Setup (COMPLETED)
* Dynamic Reverse Proxy (`/api/proxy/{path:path}`), Request ID validation & generation, Hop-by-hop header filtering, SQLite traffic persistence with redaction, Open Proxy protection, Target health check (`/health/target`).

---

### Phase 2 — Rule Engine / Signature-Based Detection (COMPLETED)

* **Mục tiêu (Objectives):**
  * Xây dựng bộ luật phát hiện dấu hiệu tấn công tĩnh (Signature-Based Detection) cho 4 họ tấn công: SQL Injection, XSS, Path Traversal, Command Injection.
  * Xây dựng quy trình chuẩn hóa chuỗi an toàn (`InputNormalizer`) với giới hạn độ sâu (`max_depth = 3`) và kích thước (`16 KB`).
  * Xây dựng cơ chế chấm điểm rủi ro tất định từ 0 đến 100 (`RuleScorer`).
  * Lưu vết và liên kết chặt chẽ sự kiện tấn công (`security_events`) với bản ghi lưu lượng (`requests`) thông qua `request_id`.
  * Đảm bảo nguyên tắc **Detection Only / Non-Blocking**: Mọi request độc hại đều được ghi log nhưng vẫn được chuyển tiếp an toàn tới target API.

* **Sản phẩm bàn giao (Deliverables):**
  * `gateway/app/security/models.py`: Data models, enums (`Severity`, `AttackType`, `InspectionLocation`, `RuleMatch`, `DetectionResult`).
  * `gateway/app/security/normalizer.py`: `InputNormalizer` canonicalization (URL percent decoding, HTML unescaping, Unicode NFKC, whitespace/null bytes stripping).
  * `gateway/app/security/rules/base.py`: `BaseRule`, `RegexRule` contract và bằng chứng khử nhạy cảm.
  * `gateway/app/security/rules/sqli.py`: 5 rules phát hiện SQL Injection (`SQLI-001` đến `SQLI-005`).
  * `gateway/app/security/rules/xss.py`: 4 rules phát hiện Cross-Site Scripting (`XSS-001` đến `XSS-004`).
  * `gateway/app/security/rules/path_traversal.py`: 3 rules phát hiện Path Traversal (`PATH-001` đến `PATH-003`).
  * `gateway/app/security/rules/command_injection.py`: 4 rules phát hiện Command Injection (`CMD-001` đến `CMD-004`).
  * `gateway/app/security/rules/__init__.py`: Rule registry tập trung (`get_all_rules`).
  * `gateway/app/security/scoring.py`: `RuleScorer` tính điểm tất định $0 - 100$.
  * `gateway/app/security/engine.py`: `RuleEngine` quét toàn diện Path, Query, Safe Headers, Body (JSON recursive / Form / Text).
  * `gateway/app/services/security.py`: `SecurityEventService` lưu bản ghi sự kiện bảo mật.
  * `docs/RULE_ENGINE.md`: Tài liệu đặc tả kỹ thuật và danh mục luật Rule Catalog chi tiết.
  * `scripts/verify_phase2_live.py`: Script kiểm thử thực tế 4 họ tấn công qua cổng mạng thật.

* **Kiểm thử & Xác minh (Tests & Verification):**
  * `pytest`: **33/33 tests PASSED (100%)** bao gồm tests cho từng rule độc lập, test bộ dữ liệu hợp lệ (Benign corpus), test normalization, test engine aggregation, test proxy non-blocking integration và regression tests của Phase 1.
  * `ruff check gateway`: **All checks passed! (0 errors)**.
  * `live security verification`: **4/4 attack families detected, 0 false positives on benign traffic, 100% request_id traceability**.
  * `docker compose config`: Hợp lệ 100%.

* **Giới hạn chủ đích (Known Limitations in Phase 2):**
  * Chưa triển khai trích xuất đặc trưng payload cho ML $\rightarrow$ Thuộc về **Phase 3**.
  * Chưa triển khai mô hình Machine Learning (Random Forest & Isolation Forest) $\rightarrow$ Thuộc về **Phase 5 & 6**.
  * Chưa triển khai Risk Engine, Decision Engine và Rate Limiter chặn tự động $\rightarrow$ Thuộc về **Phase 7 & 8**.
  * Chưa hiển thị biểu đồ và sự kiện trên Dashboard UI $\rightarrow$ Thuộc về **Phase 9**.
  * Chưa triển khai Attack Lab automated runner $\rightarrow$ Thuộc về **Phase 10**.

---

### Phase 2B — Custom Vulnerable Web API (`vulnerable-api`) (COMPLETED ✅)

* **Mục tiêu (Objectives):**
  * Tự xây dựng ứng dụng mục tiêu Bookie Bookstore (`vulnerable-api`, Port 5000) thay thế OWASP Juice Shop bên thứ ba theo chỉ đạo của Thầy hướng dẫn để làm chủ 100% mã nguồn và logic lỗ hổng.
  * Cài cắm có chủ đích **8 kịch bản lỗ hổng trọng điểm** kết hợp giữa OWASP Top 10 Web và OWASP Top 10 API Security:
    1. **SQL Injection (Auth Bypass & Brute Force):** `POST /api/v1/vulnerable/auth/login/`
    2. **SQL Injection (UNION-based Search):** `GET /api/v1/vulnerable/books/search/?q=...`
    3. **Stored & Reflected XSS:** `GET /api/v1/vulnerable/reviews/?book_id=...` & `POST /api/v1/vulnerable/reviews/`
    4. **Path Traversal / Local File Inclusion (LFI):** `GET /api/v1/vulnerable/files/download/?file=...`
    5. **Command Injection (RCE):** `POST /api/v1/vulnerable/admin/ping/`
    6. **Broken Object Level Authorization (BOLA / IDOR - OWASP API1:2023):** `GET & PUT /api/v1/vulnerable/orders/<order_id>/`
    7. **Server-Side Request Forgery (SSRF - OWASP API7:2023):** `GET & POST /api/v1/vulnerable/books/fetch-cover/?url=...`
    8. **Mass Assignment (Privilege Escalation - OWASP API6:2023):** `POST /api/v1/vulnerable/users/profile/update/`
    * Kèm **Excessive Data Exposure (OWASP API3:2023):** `GET /api/v1/vulnerable/users/list/`
    * Cung cấp **OpenAPI 3.0 Reconnaissance Endpoint:** `GET /api/v1/vulnerable/openapi.json` cho AI Attack Planner (Máy 2) tự động trinh sát.

* **Sản phẩm bàn giao (Deliverables):**
  * `vulnerable-api/books/api_vulnerable.py`: Module 8 endpoints chứa lỗ hổng có kiểm soát và OpenAPI schema generator.
  * `vulnerable-api/books/test_vulnerable_api.py`: Bộ kiểm thử trực tiếp nội bộ cho các kịch bản lỗ hổng và dữ liệu hạt giống.
  * `gateway/tests/test_vulnerable_api_endpoints.py`: Bộ test tích hợp Gateway proxying an toàn và truy vết tới các endpoints mới (BOLA, SSRF, Mass Assignment).
  * `vulnerable-api/Dockerfile`: Dockerfile tối ưu hóa độc lập, cấu hình sẵn nạp fixtures và chạy trên port 5000.
  * Các issues GitHub hoàn thành: #57, #58, #59, #60, #61, #64 (Merged qua PR #62).

* **Kiểm thử & Xác minh (Tests & Verification):**
  * `pytest gateway/tests/`: **44/44 tests PASSED (100%)**.
  * `ruff check gateway/`: **0 errors**.
  * Docker Compose liên kết 3 container hoạt động thông suốt.

---

### Phase 9 — Dashboard UI & Real-Time Threat Visualization (COMPLETED Tasks 9.1, 9.2, 9.3, 9.5 ✅ | In Progress: Task 9.4 🚀)

* **Mục tiêu (Objectives):**
  * Xây dựng trung tâm chỉ huy an ninh trực quan (SOC Command Center) theo phong cách Dark Cyber Glassmorphism.
  * Đảm bảo nguyên tắc học thuật 100%: Dữ liệu truy vấn trực tiếp từ bảng `requests` và `security_events` trong SQLite, không mock data.
  * Chuẩn hóa danh xưng theo Phase 2: `ATTACKS DETECTED`, `SAFE REQUEST RATE`, `Threat Score (Rule Engine Phase 2)`.
  * Tích hợp bảng bắn thử nghiệm Quick Simulator (1-click test) để demo trực quan trước Hội đồng mà không cần Postman.
  * Tích hợp tính năng Reset Demo Data (`POST /api/dashboard/reset-demo`) chuẩn bị sẵn cho kịch bản báo cáo bảo vệ.

* **Sản phẩm bàn giao (Deliverables):**
  * `gateway/app/api/dashboard.py`: 6 REST APIs thật (`/api/dashboard/stats`, `/events`, `/timeline`, `/distribution`, `/simulate`, `/reset-demo`).
  * `gateway/tests/test_dashboard_api.py`: Bộ unit test tự động kiểm thử toàn bộ dashboard endpoints.
  * `dashboard/src/components/Header.tsx`: Target status (`● 12.4ms`), WAF Mode (`MONITOR_ONLY`), Smart Polling (`3s/5s/Off`), Reset Demo.
  * `dashboard/src/components/MetricCards.tsx`: 4 thẻ chỉ số KPI + Hộp Quick Simulator (SQLi, XSS, Path, Cmd, Benign) (Task 9.2 & 9.5 - #63).
  * `dashboard/src/components/ThreatTimelineChart.tsx`: Biểu đồ Area Chart sóng Cyan (Benign) vs sóng Rose (Attacks) (Task 9.2).
  * `dashboard/src/components/AttackDistributionChart.tsx`: Biểu đồ Donut Chart phân bố 4 họ tấn công (Task 9.2).
  * `dashboard/src/components/events/LiveEventsTable.tsx`: Bảng nhật ký sự kiện an ninh thời gian thực hiển thị nguồn Client IP (phân biệt LAN Attacker Máy 2 vs Localhost), tìm kiếm theo Request ID / IP, lọc Severity, Attack Type, reset bộ lọc, nút copy 1-click, phân trang và xuất dữ liệu JSON (Task 9.3).
  * `dashboard/src/components/events/PayloadEvidenceDrawer.tsx`: Cửa sổ Drawer 2 tab phân tích sâu đối sánh Canonical vs Raw Input, giải thích chi tiết cơ chế tấn công (CWE/CAPEC/MITRE), hiển thị regex pattern và chuẩn bị sẵn giao diện Vector 17 đặc trưng cho Phase 3 (Task 9.3).
  * `dashboard/src/components/events/index.ts`: Export chuẩn hóa module events theo đúng kiến trúc TASKS_BREAKDOWN.
  * `dashboard/src/components/explain/DetectionExplainabilityModal.tsx`: Modal giải thích quyết định phòng thủ của WAF: trực quan hóa công thức tính điểm kết hợp Rule (40%) + RF (35%) + IF (25%), thang đo quyết định ALLOW/MONITOR/RATE_LIMIT/BLOCK 403, phân tích bối cảnh an ninh CWE/CAPEC/MITRE, và hỗ trợ xuất báo cáo JSON 1-click (Task 9.4 - #38).
  * `dashboard/src/components/explain/index.ts`: Export chuẩn hóa module explainability.
  * `docs/DASHBOARD_SPEC.md`: Tài liệu đặc tả kỹ thuật toàn diện cho Dashboard.

* **Đánh giá hoàn thành Phase 9 (100% DONE):**
  * Đã giải quyết đầy đủ tất cả **5/5 Subtasks** của Phase 9:
    * Task 9.1 (#35): REST APIs Gateway.
    * Task 9.2 (#36): 4 KPI Cards + 2 Biểu đồ Recharts.
    * Task 9.3 (#37): Bảng Live Events + Payload Evidence Drawer.
    * Task 9.4 (#38): Detection Explainability Modal.
    * Task 9.5 (#63): UI/UX Polish, Quick Simulator & WAF Switcher.

* **Kiểm thử & Xác minh (Tests & Verification):**
  * `pytest gateway/tests/`: **44/44 tests PASSED (100%)**.
  * `ruff check gateway/`: **0 errors**.
  * `next build`: **Compiled successfully, static generation 4/4 (133 kB)**.

---

### Phase 3 — Feature Engineering (NOT STARTED)
- [ ] *(RESERVED FOR ML TEAM)* 17 payload features (chiều dài, entropy, tỷ lệ ký tự đặc biệt, từ khóa SQL/XSS/Path).
- [ ] *(RESERVED FOR ML TEAM)* HTTP & Behavior metadata features.

---

*(Các phase còn lại từ Phase 4 đến Phase 12 giữ nguyên trạng thái theo kế hoạch)*
