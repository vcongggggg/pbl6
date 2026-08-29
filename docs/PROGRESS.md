# Tiến Độ Triển Khai Dự Án (Project Progress)

Tài liệu theo dõi trạng thái thực hiện các giai đoạn phát triển (Development Phases) theo đặc tả trong [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).

---

## Bảng Tổng Hợp Trạng Thái Các Phase (Phase 0 → Phase 12)

| Phase | Tên Giai Đoạn (Phase Name) | Phân Công Trọng Tâm | Trạng Thái (Status) | Ghi Chú |
| :---: | :--- | :--- | :---: | :--- |
| **Phase 0** | **Project Bootstrap & Codebase Foundation** | Toàn đội / System Architect | **COMPLETED** | Thiết lập cấu trúc Monorepo, tooling, CI, database models, tests và Next.js. |
| **Phase 1** | **Infrastructure Setup** | Backend / DevOps (Member A) | **COMPLETED** | Reverse Proxy bất đồng bộ, X-Request-ID, lọc Header, ghi log SQLite, bảo vệ Open Proxy / SSRF, Probe Target Health. |
| **Phase 2** | **Rule Engine** | Security Engineer (Member A) | **NOT STARTED** | SQLi, XSS, Traversal, Command Injection, Brute Force, API Abuse. |
| **Phase 3** | **Feature Engineering** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* 17 payload features, HTTP & Behavior features. |
| **Phase 4** | **Dataset Generation & Lab Traffic** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* Synthetic dataset, Benign cases, Lab traffic collection. |
| **Phase 5** | **Supervised ML — Random Forest** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* Training, Multiclass, Evaluation, Serialization (`.joblib`). |
| **Phase 6** | **Anomaly Detection — Isolation Forest** | ML/Data Team (Member B) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* Behavior window, Isolation Forest anomaly scoring. |
| **Phase 7** | **Hybrid Risk Engine & Decision** | Backend / Security (Member A) | **NOT STARTED** | Weighted Risk Score (0–100), Thresholds (ALLOW/MONITOR/RATE_LIMIT/BLOCK). |
| **Phase 8** | **Rate Limiting & Behavior Tracker** | Backend / Security (Member A) | **NOT STARTED** | IP tracking time-window, HTTP 429 response, endpoint limits. |
| **Phase 9** | **Dashboard UI (Next.js)** | Frontend / Fullstack (Member C) | **NOT STARTED** | Overview cards, Timeline chart, Distribution, Security events, Explain UI. |
| **Phase 10** | **Attack Lab & Scenario Runner** | Fullstack / QA (Member C & D) | **NOT STARTED** | Attack scenarios JSON, CLI Runner, Automated campaigns. |
| **Phase 11** | **System Evaluation & Comparison** | ML/Data & QA (Member B & D) | **NOT STARTED** | *(RESERVED FOR ML TEAM)* So sánh Rule vs ML vs Anomaly vs Hybrid, Evasion test, Benchmark. |
| **Phase 12** | **Final Hardening & Documentation** | Toàn đội / Documentation | **NOT STARTED** | Clean run, error handling, audit log, hoàn thiện docs báo cáo. |

---

## Chi Tiết Triển Khai Từng Phase

### Phase 0 — Project Bootstrap & Codebase Foundation (COMPLETED)

* **Mục tiêu (Objectives):**
  * Thiết lập cấu trúc Monorepo chuẩn không lồng thư mục thừa.
  * Xây dựng nền tảng Backend FastAPI, Database models (SQLAlchemy), Error handlers, Logging và Pydantic schemas.
  * Xây dựng nền tảng Frontend Next.js + TypeScript + Tailwind CSS (không fake metrics).
  * Xây dựng Docker Compose, Makefile, CI workflow (.github), .gitignore, .dockerignore và tài liệu kiến trúc.

* **Sản phẩm bàn giao (Deliverables):**
  * `docs/PLAN.md`, `docs/PROGRESS.md`, `docs/GAP_ANALYSIS.md`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`, `docs/ML_INTEGRATION.md`.
  * `gateway/`: FastAPI app, `GET /health`, database models, pytest test suite (100% pass), ruff linting (0 errors).
  * `dashboard/`: Next.js 14 standalone build thành công (`npm run build`).
  * `docker-compose.yml`, `Makefile`, `.github/workflows/ci.yml`.

---

### Phase 1 — Infrastructure Setup (COMPLETED)

* **Mục tiêu (Objectives):**
  * Xây dựng Reverse Proxy Gateway hoàn chỉnh nhận HTTP request, chuyển tiếp an toàn tới OWASP Juice Shop và phản hồi client.
  * Xử lý định danh `X-Request-ID` xuyên suốt (validate hoặc sinh mới UUID4).
  * Lọc Hop-by-hop headers (`Connection`, `Keep-Alive`, `Upgrade`, `Host`, `Content-Length`).
  * Chống Open Proxy / SSRF: Địa chỉ đích luôn cố định theo cấu hình `TARGET_API_URL`.
  * Ghi nhận lưu lượng và độ trễ vào bảng `requests` trong SQLite có khử thông tin nhạy cảm (`Authorization`, `Cookie`, `password`, `token`).
  * Xử lý lỗi an toàn: Trả về HTTP 502/504 chuẩn hóa khi upstream mất kết nối hoặc timeout mà không lộ stack trace.
  * Bổ sung endpoint `GET /health/target` kiểm tra độ thông mạng tới Target API.

* **Sản phẩm bàn giao (Deliverables):**
  * `gateway/app/api/proxy.py`: Dynamic proxy router `/api/proxy/{path:path}` hỗ trợ GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD.
  * `gateway/app/services/proxy.py`: ProxyService sử dụng `httpx.AsyncClient` có pool và timeouts cấu hình được.
  * `gateway/app/services/traffic.py`: TrafficService xử lý khử dữ liệu nhạy cảm và persist vào SQLite.
  * `gateway/app/core/request_id.py`: Utility xử lý xác thực và sinh mã Request ID an toàn.
  * `gateway/app/api/health.py`: Bổ sung `GET /health/target`.
  * `docs/API.md`, `docs/GATEWAY.md`: Tài liệu đặc tả API và kiến trúc Gateway.
  * `tests/integration/test_gateway_live.py`: Test suite tích hợp end-to-end.

* **Tập tin đã tạo & chỉnh sửa (Files Created & Modified):**
  * Tạo mới: `gateway/app/api/proxy.py`, `gateway/app/services/__init__.py`, `gateway/app/services/proxy.py`, `gateway/app/services/traffic.py`, `gateway/app/core/request_id.py`
  * Tạo mới: `gateway/tests/test_proxy.py`, `tests/integration/__init__.py`, `tests/integration/test_gateway_live.py`
  * Tạo mới: `docs/API.md`, `docs/GATEWAY.md`
  * Chỉnh sửa: `gateway/app/core/config.py`, `gateway/app/db/models.py`, `gateway/app/api/router.py`, `gateway/app/api/health.py`, `gateway/app/schemas/health.py`, `gateway/app/schemas/__init__.py`, `gateway/app/main.py`, `gateway/tests/conftest.py`, `gateway/tests/test_health.py`, `docs/ARCHITECTURE.md`, `.github/workflows/ci.yml`, `gateway/pyproject.toml`

* **Kiểm thử & Xác minh (Tests & Verification):**
  * `pytest`: **13/13 tests passed** (100% pass, bao gồm health, target connectivity, request-id, GET/POST proxy, query params, status preservation, 502/504 errors, hop-by-hop filter, open proxy protection, DB persistence, sensitive redaction).
  * `ruff check gateway`: **All checks passed! (0 errors)**.
  * `dashboard build`: `npm run build` thành công 100%.
  * `docker compose config`: Hợp lệ 100%.

* **Giới hạn chủ đích (Known Limitations in Phase 1):**
  * Chưa triển khai các luật phát hiện WAF (SQLi, XSS, Traversal) $\rightarrow$ Phase 2.
  * Chưa triển khai trích xuất đặc trưng và mô hình ML $\rightarrow$ Phase 3, 5, 6.
  * Chưa triển khai Risk Engine, Rate Limiting, Decision Engine $\rightarrow$ Phase 7, 8.
  * Chưa triển khai giao diện hiển thị biểu đồ và danh sách log $\rightarrow$ Phase 9.
  * Chưa triển khai kịch bản Attack Lab $\rightarrow$ Phase 10.

---

### Phase 2 — Rule Engine (NOT STARTED)
- [ ] Xây dựng Regex Matcher phát hiện SQL Injection, XSS, Path Traversal, Command Injection.
- [ ] Phân tích URL, Query Parameters, Headers, Request Body.
- [ ] Gán Rule Risk Score ($0 - 100$) và nhãn tấn công tương ứng.

---

*(Các phase từ Phase 3 đến Phase 12 giữ nguyên trạng thái NOT STARTED theo kế hoạch)*
