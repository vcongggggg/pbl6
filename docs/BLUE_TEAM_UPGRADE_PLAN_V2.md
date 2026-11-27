# KẾ HOẠCH NÂNG CẤP TOÀN DIỆN BLUE TEAM & MODEL PHÒNG THỦ HYBRID (PBL6)

> **Đề tài:** Phát hiện và ngăn chặn tấn công Web API thông minh bằng Machine Learning kết hợp Thao trường An ninh Đối kháng (Distributed Cyber Range)  
> **Phạm vi:** Khối Blue Team — Máy 1 (`ml-engine/`, `gateway/`, `dashboard/`, `docker-compose.yml`, CI/CD)  
> **Đồng bộ từ:** Kiểm toán độc lập 8 lớp (`@pbl6-reviewer`) & `docs/REVIEW_FEEDBACK.md`

---

## TỔNG QUAN 4 SPRINTS TRIỂN KHAI (AUDIT-GATED PIPELINE)

Mỗi Sprint sau khi hoàn thành sẽ được phiên Reviewer kiểm toán độc lập lại bằng PoC thực tế trước khi mở khóa Sprint tiếp theo:

1. **SPRINT 1 (P0 — Khẩn cấp):** Vá toàn bộ **5 lỗ hổng CRITICAL** + **Evasion Rule Engine** (`SEC-PBL6-001`, `SEC-PBL6-002`, `SEC-PBL6-003`, `PERF-PBL6-001` phần ReDoS `XSS-002`, `SEC-PBL6-004`, `SEC-PBL6-006`).
2. **SPRINT 2 (P1 — Lõi AI Defense Model):**
   - Dataset **Zero-Leakage** (Canonical SHA-256 hash-disjoint từ OpenAppSec + `data/external/hf_http_attacks` + Synthetic Bookie + Multi-Protocol; tách rời **100% CSIC 2010** làm Zero-Shot Cross-Dataset Benchmark).
   - **Unified 26-D Feature Extractor** (`ml-engine/features/canonicalizer.py` dùng chung cho Train và Serving để xóa sổ Training-Serving Skew): giữ 17 đặc trưng gốc + kích hoạt lại `cmd_keyword_count` & `cmd_regex_matches` (`f18-f19`) + bổ sung 7 đặc trưng mới (`encoding_layer_depth`, `sql_comment_and_func_score`, `param_value_entropy_ratio`, `numeric_anomaly_flag`, `natural_text_ratio`, `safe_structured_ratio`, `protocol_complexity_score`).
   - Huấn luyện **Calibrated Cost-Sensitive XGBoost** + **`RobustScaler -> IsolationForest`** (percentile calibration cứu Recall từ 5.88% -> >= 50%), xuất **ONNX Runtime** (`.onnx` + SHA-256 Fail-Closed manifest -> cắt single-request latency từ 20.55 ms xuống <= 2.5 ms và triệt tiêu CWE-502).
   - Đồng bộ nhãn `SQL_INJECTION`, sửa Notebook 01 & 02 (verify SHA-256 **TRƯỚC** khi load, không test trên tập trùng train).
3. **SPRINT 3 (P1 — Logic WAF & SOC Dashboard Truthfulness):**
   - Vá False Positive HTTP 403 trên SOAP/XML sạch (`protocol_detector.py:284`) và phân loại nhầm REST JSON có key `"query"` (`LOGIC-PBL6-002`).
   - Đồng bộ enum `BLOCKED`/`MONITOR`/`RATE_LIMIT` để sửa `blocked_count = 0` (`LOGIC-PBL6-001`), thực thi `RATE_LIMIT` zone `[60, 80)`, sửa `schema_strict_mode` tôn trọng `WAF_MODE=OFF/MONITOR_ONLY`, nối đủ biến `.env` (`LOGIC-PBL6-003`), đồng bộ `/dashboard/simulate` với Bookie (`comment`, `host`) và `SchemaValidator` (`LOGIC-PBL6-004`).
   - Sửa timezone `derive_session_id`, gán session cho rate-limit/seeder, khử N+1 SQL `/sessions`, sửa `/timeline` qua nửa đêm, sửa `AttackSessionsModal` không refetch khi expand + backdrop click-to-close (`LOGIC-PBL6-005`).
   - Gỡ toàn bộ số liệu giả lập trên UI (`/protocols`, `/topology`, 26-Feature Drawer thật, XAI Modal thật, RPS 60s thật) (`SCI-PBL6-002`).
4. **SPRINT 4 (P2 — High-Concurrency Async, Docker/CI & Hồ Sơ Bảo Vệ):**
   - Đẩy Gateway từ ~19 RPS lên `>= 150 RPS` (`anyio.to_thread.run_sync`, Fast-Path `Rule >= 85`, `BackgroundTasks` DB writer, cache `waf_mode`, cột index `api_protocol`, `PRAGMA busy_timeout=5000`, ghi `AuditLog`, đóng `AsyncClient` tạm, giữ multi `Set-Cookie`) (`PERF-PBL6-001`, `PERF-PBL6-002`).
   - Tạo `.dockerignore` riêng cho `gateway/`, `dashboard/`, `vulnerable-api/`; non-root `USER` + `cap_drop`; đồng bộ `dashboard/Dockerfile` lên `node:20-alpine` + `npm ci`; mở rộng CI chạy đủ 3 test suite + `ruff` 0 lỗi + `dashboard/.eslintrc.json` (`INFRA-PBL6-001`, `QUAL-PBL6-001`).
   - Viết lại `scripts/run_gateway_profiling.py` đo trực tiếp class thật (xóa hằng số giả `24.5 us`/`11.8 us`), chạy lại toàn bộ benchmark trung thực, xóa sạch di chứng `Juice Shop` và cập nhật `README.md` (`ARCH-PBL6-001`, `SCI-PBL6-001`, `SEC-PBL6-007`).

---

## KPI MỤC TIÊU NGHIỆM THU CUỐI CÙNG (Baseline -> Hybrid)

| Chỉ Số | Baseline Ban Đầu | Mục Tiêu Đạt Chuẩn |
| :--- | :---: | :---: |
| Lỗ hổng CRITICAL / HIGH | 5 CRITICAL, 7 HIGH | **0 CRITICAL, 0 HIGH** |
| ReDoS `XSS-002` (chuỗi 9KB) | `923.37 ms` | **`< 10 ms`** |
| Latency AI đơn lẻ (Classifier + IForest) | `20.55 ms/req` | **`<= 2.5 ms/req` (ONNX)** |
| Throughput Gateway (`C=50`) | `~19.9 RPS` | **`>= 150 RPS` (`P95 < 30 ms`)** |
| Zero-Shot CSIC 2010 F1 / FPR | `65.88%` / `29.60%` | **`>= 82%` / `<= 8.0%` (Zero Leakage)** |
| Isolation Forest Recall (`benchmark_1000`) | `5.88%` | **`>= 50%`** |
| CWE-502 Model Deserialization | Pickle Fail-Open | **ONNX + SHA-256 Fail-Closed** |

