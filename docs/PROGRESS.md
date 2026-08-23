# Tiến Độ Triển Khai Dự Án (Project Progress)

Tài liệu theo dõi trạng thái thực hiện các giai đoạn phát triển (Development Phases) theo đặc tả trong [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).

---

## Bảng Tổng Hợp Trạng Thái Các Phase (Phase 0 → Phase 12)

| Phase | Tên Giai Đoạn (Phase Name) | Phân Công Trọng Tâm | Trạng Thái (Status) | Ghi Chú |
| :---: | :--- | :--- | :---: | :--- |
| **Phase 0** | **Project Bootstrap & Codebase Foundation** | Toàn đội / System Architect | **COMPLETED** | Thiết lập cấu trúc Monorepo, tooling, CI, database models, tests và Next.js. |
| **Phase 1** | **Infrastructure Setup** | Backend / DevOps (Member A) | **NOT STARTED** | Docker Compose, FastAPI Gateway, Juice Shop Target, SQLite logging. |
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

* **Tập tin đã tạo (Files Created):**
  * `.gitignore`, `.dockerignore`, `.env.example`, `README.md`, `Makefile`, `docker-compose.yml`
  * `.github/workflows/ci.yml`
  * `gateway/pyproject.toml`, `gateway/Dockerfile`
  * `gateway/app/__init__.py`, `gateway/app/main.py`
  * `gateway/app/core/__init__.py`, `gateway/app/core/config.py`, `gateway/app/core/logging.py`, `gateway/app/core/errors.py`
  * `gateway/app/db/__init__.py`, `gateway/app/db/base.py`, `gateway/app/db/session.py`, `gateway/app/db/models.py`
  * `gateway/app/schemas/__init__.py`, `gateway/app/schemas/health.py`, `gateway/app/schemas/common.py`
  * `gateway/app/api/__init__.py`, `gateway/app/api/router.py`, `gateway/app/api/health.py`
  * `gateway/tests/__init__.py`, `gateway/tests/conftest.py`, `gateway/tests/test_health.py`
  * `dashboard/package.json`, `dashboard/tsconfig.json`, `dashboard/next.config.js`, `dashboard/tailwind.config.js`, `dashboard/postcss.config.js`, `dashboard/Dockerfile`
  * `dashboard/src/config/env.ts`, `dashboard/src/app/layout.tsx`, `dashboard/src/app/page.tsx`, `dashboard/src/app/globals.css`
  * `ml-engine/README.md`, `attack-lab/README.md`, `shared/README.md`, `tests/README.md`, `scripts/README.md`, `config/README.md`, `docker/README.md`
  * `data/raw/.gitkeep`, `data/processed/.gitkeep`, `data/artifacts/.gitkeep`
  * `docs/PLAN.md`, `docs/GAP_ANALYSIS.md`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`, `docs/ML_INTEGRATION.md`

* **Kiểm thử & Xác minh (Tests & Verification):**
  * `pytest`: 2/2 tests passed (`GET /health` trả về 200 OK và `GET /` ping thành công).
  * `ruff check gateway`: 0 errors.
  * `npm run build`: Static pages generated successfully (Route /: 807 B).
  * `docker compose config`: Validated cleanly without warnings.

* **Giới hạn chủ đích (Known Limitations in Phase 0):**
  * Chưa triển khai các luật phát hiện WAF (SQLi, XSS, Traversal) $\rightarrow$ Phase 2.
  * Chưa triển khai trích xuất đặc trưng và mô hình ML $\rightarrow$ Phase 3, 5, 6.
  * Chưa triển khai Risk Engine, Rate Limiting, Decision Engine $\rightarrow$ Phase 7, 8.
  * Chưa triển khai giao diện biểu đồ và danh sách log $\rightarrow$ Phase 9.
  * Chưa triển khai kịch bản Attack Lab $\rightarrow$ Phase 10.

---

### Phase 1 — Infrastructure (NOT STARTED)
- [ ] Thiết lập mạng Docker nội bộ kết nối Gateway và Juice Shop.
- [ ] Khởi tạo reverse proxy chuyển tiếp request thô.
- [ ] Tích hợp ghi log traffic vào SQLite database.
- **Deliverables:** Request xuyên suốt từ Client $\rightarrow$ Gateway $\rightarrow$ Juice Shop.

---

*(Các phase từ Phase 2 đến Phase 12 giữ nguyên trạng thái NOT STARTED theo kế hoạch)*
