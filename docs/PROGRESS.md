# Tiến Độ Triển Khai Dự Án (Project Progress)

Tài liệu theo dõi trạng thái thực hiện các giai đoạn phát triển (Development Phases) theo đặc tả trong [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).

---

## Bảng Tổng Hợp Trạng Thái Các Phase (Phase 0 → Phase 12)

| Phase | Tên Giai Đoạn (Phase Name) | Phân Công Trọng Tâm | Trạng Thái (Status) | Ghi Chú |
| :---: | :--- | :--- | :---: | :--- |
| **Phase 0** | **Project Bootstrap & Codebase Foundation** | Toàn đội / System Architect | **COMPLETED** | Thiết lập cấu trúc Monorepo, tooling, CI, database models, tests và Next.js. |
| **Phase 1** | **Infrastructure Setup** | Backend / DevOps (Member A) | **COMPLETED** | Reverse Proxy bất đồng bộ, X-Request-ID, lọc Header, ghi log SQLite, bảo vệ Open Proxy / SSRF, Probe Target Health. |
| **Phase 2** | **Rule Engine / Signature-Based Detection** | Security Engineer (Member A) | **COMPLETED** | 16 rules tất định (SQLi, XSS, Path Traversal, Command Injection), Input Normalizer, Rule Risk Scoring (0-100), Security Event persistence & traceability. |
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

### Phase 3 — Feature Engineering (NOT STARTED)
- [ ] *(RESERVED FOR ML TEAM)* 17 payload features (chiều dài, entropy, tỷ lệ ký tự đặc biệt, từ khóa SQL/XSS/Path).
- [ ] *(RESERVED FOR ML TEAM)* HTTP & Behavior metadata features.

---

*(Các phase từ Phase 4 đến Phase 12 giữ nguyên trạng thái NOT STARTED theo kế hoạch)*
