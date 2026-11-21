# 📋 REVIEW FEEDBACK & ACTIONABLE TASKS (DÀNH CHO PHIÊN CODER @PBL6)

## CẬP NHẬT MỚI NHẤT: SPRINT 2 (`pbl6-blueteam-v2-sprint2-fix1`) ĐẠT 100% VERIFIED PASS — ĐÃ MỞ CỔNG SPRINT 3 (`pbl6-blueteam-v2-sprint3-logic-ui`)
- **Reviewer:** `@pbl6-reviewer` (Senior Security Architect & Independent Code Auditor)
- **Trạng thái Sprint 1 (`pbl6-blueteam-v2-sprint1-p0` + `fix1`):** 🟢 **APPROVED / 100% VERIFIED PASS** (`9e073ad`)
- **Trạng thái Sprint 2 (`pbl6-blueteam-v2-sprint2-ml-v2` + `fix1`):** 🟢 **APPROVED / 100% VERIFIED PASS**
  - **`SEC-PBL6-005` Fail-Closed SHA-256 & Zero-Pickle (`[VERIFIED PASS]`):** Đã gỡ hoàn toàn backdoor `"tmp"` trong `ml_detector.py` và `anomaly.py`; thiếu metadata hoặc sai hash đều fail-closed (`is_loaded=False`); nạp tự động từ mọi CWD qua `repo_root`; cả 2 model đều **Zero-Pickle** (`xgb_v2.ubj` + `iforest_v2.npz` với `allow_pickle=False`).
  - **Độ trễ Single-Request AI (`[VERIFIED PASS]`):** Đo độc lập 500 request: `feat26 (0.451ms) + xgb_v2.ubj (1.366ms) + iforest_v2.npz (0.429ms) = 2.246ms/req <= 2.5ms SLA` (nhanh gấp **9.15x** so với `20.55ms` v1.0; `iforest_v2.npz` nhanh gấp **66x**).
  - **Zero-Leakage Multi-Source Dataset `defense_v2` (`[VERIFIED PASS]`):** `Train=32,330 | Val=6,928 | Test=6,929` (đã nạp lại `4,835` mẫu `hf_http_*`), kiểm chứng hash độc lập không header: **`tr&va=0, tr&te=0, va&te=0, all&csic=0`**.
  - **Zero-Skew 26-D Pipeline & `MLPredictionResult.to_dict()` (`[VERIFIED PASS]`):** `diff_dims == 0`; `to_dict()` trả đủ `model_name="Champion Cost-Sensitive Regularized XGBoost v2.0"`, `model_version="2.0.0"`, `feature_names` (26), `feature_vector` (26), `attack_threshold`.
  - **Anomaly Recall & Zero-Shot CSIC 2010 (`[VERIFIED PASS]`):** `iforest_v2.npz` trên `benchmark_1000_diverse.csv` đạt **`Recall = 57.75%`, `FPR = 4.00%`** tại ngưỡng Gateway `@60.0` (tăng từ `5.88%` v1.0); CSIC 2010 Zero-Shot đạt **`FPR = 0.00%`, `Precision = 100.00%`, Hybrid `XSS = 100.00%`, `SQLi = 49.61%`** (đã xóa số `99.93%` cũ).
  - **Notebooks & Tests (`[VERIFIED PASS]`):** Đã tái sinh `01_model_training_and_comparison.ipynb` và `02_model_evaluation_and_testing.ipynb` (kiểm SHA-256 cả 2 model, xóa hoàn toàn `raw_unfiltered_500k`); `ruff check gateway/` = `0 errors`; full `pytest gateway/tests/ tests/unit/ ml-engine/tests/` = **271/271 PASSED (0 FAILED)**.
- **Trạng thái Sprint 3 (`pbl6-blueteam-v2-sprint3-logic-ui`):** 🔵 **ĐÃ GIAO LỆNH — ĐANG THỰC THI**
  - Phạm vi bắt buộc: Commit sạch Sprint 2 trước -> Triển khai toàn bộ `LOGIC-PBL6-001`, `LOGIC-PBL6-002`, `LOGIC-PBL6-003`, `LOGIC-PBL6-004`, `LOGIC-PBL6-005`, `SCI-PBL6-002` + test hồi quy + `ruff`, `pytest`, `tsc --noEmit`, `next build` -> xuất `task_done` với `"task_id": "pbl6-blueteam-v2-sprint3-logic-ui"`.

---

### 🔴 NHÓM P0 — CRITICAL (ĐÃ VÁ & XÁC MINH 100% TRONG SPRINT 1)

- [x] **[SEC-PBL6-001] Vá Bypass Rate Limiter & Unbounded Memory DoS (`gateway/app/security/rate_limiter.py`, `gateway/app/api/proxy.py`)** — `[VERIFIED PASS]` (Auth 25 req xoay token/UA -> `limited=15, tracked_keys=11`; Global 200 -> `limited=20`; `OrderedDict` LRU `50000`).

- [x] **[SEC-PBL6-002] Vá Bypass WAF qua > 16KB Padding, Non-UTF-8 Byte Prefix & Giới Hạn Kích Thước Body (`gateway/app/security/engine.py`, `gateway/app/api/proxy.py`, `gateway/app/security/protocol_detector.py`)** — `[VERIFIED PASS]` (Single 17KB JSON leaf `score=94.5`; JSON depth=35 `score=85.5`; Chunked >1MB `HTTP 413`; Non-UTF-8 `\xff` `HTTP 403`).

- [x] **[SEC-PBL6-003] Vá Lỗi Fail-Open Khi `detection_result is None` (`gateway/app/api/proxy.py:474`, `gateway/app/services/security.py:66`)** — `[VERIFIED PASS]` (RuleEngine crash trên SQLi trả `HTTP 403 BLOCK, risk=100.0`; `record_detection(None)` an toàn).

- [ ] **[PERF-PBL6-001] Vá ReDoS `O(n^2)` ở `XSS-002` & Bỏ Block Asyncio Event Loop (`gateway/app/security/rules/xss.py:27`, `gateway/app/api/proxy.py`, `gateway/app/db/session.py`)** — `PARTIAL`: ReDoS `XSS-002` **`[VERIFIED PASS]`** (`923.37 ms -> 0.891 ms`); phần Async Event Loop (`>= 150 RPS`) thuộc Sprint 4.

- [x] **[SEC-PBL6-004] Gỡ `NEXT_PUBLIC_ADMIN_API_KEY` Khỏi Client Bundle & Bảo Vệ Toàn Bộ `/dashboard/*` (`dashboard/`, `docker-compose.yml`, `gateway/app/api/dashboard.py`)** — `[VERIFIED PASS]` (0 secret trong `.next/static/`; 7/7 `GET /dashboard/*` trả `401`; BFF Proxy `route.ts` chặn traversal + whitelist endpoint + origin check + Docker `BACKEND_URL:-http://gateway:8000`).

---

### 🟠 NHÓM P1 — HIGH (BẢO MẬT ML, LOGIC NGHIỆP VỤ & LIÊM CHÍNH KHOA HỌC)

- [x] **[SEC-PBL6-005] Ép Xác Minh SHA-256 Fail-Closed & Zero-Pickle Artifacts (`gateway/app/security/ml_detector.py`, `anomaly.py`, `ml-engine/notebooks/generate_notebooks.py`)** — `[VERIFIED PASS]`
  - Đã xóa sạch backdoor `"tmp"` trong `ml_detector.py` & `anomaly.py`; thiếu metadata hoặc sai hash đều fail-closed (`is_loaded=False`); chỉ cho phép bypass qua `allow_unverified=True` tường minh; `repo_root` auto-load hoạt động từ mọi CWD.
  - Cả 2 model đều **Zero-Pickle**: `xgb_v2.ubj` + `iforest_v2.npz` (`allow_pickle=False`), tốc độ suy luận tổng `2.246 ms/req <= 2.5 ms`.
  - Notebook 02 (`generate_notebooks.py`) xác minh SHA-256 cho **cả hai** model (`xgb_v2.ubj` + `iforest_v2.npz`) **TRƯỚC** khi nạp.

- [x] **[SEC-PBL6-006] Vá Các Kỹ Thuật Né Tránh Rule Engine (`normalizer.py`, `engine.py`, `rules/`)** — `[VERIFIED PASS]` (Zero-width Unicode, `UNION/**/SELECT`, `UNION/*\n*/SELECT` `re.DOTALL`, `Cookie` header, HTML5 `ontoggle`, `; env`, `; python3`, `; ls`, `| head` đều bị phát hiện).

- [ ] **[LOGIC-PBL6-001] Đồng Bộ Enum `SecurityEvent.action` Để Sửa `blocked_count = 0` (`dashboard.py`, `proxy.py`, `seeder.py`)**
  - Sửa `dashboard.py:74,406` lọc `SecurityEvent.action.in_(["BLOCK", "BLOCKED"])` và `monitored_count` lọc `.in_(["MONITOR", "DETECTED"])`; thống nhất chuẩn ghi `"BLOCKED"` / `"MONITOR"` / `"RATE_LIMIT"`.

- [ ] **[LOGIC-PBL6-002] Sửa False Positive HTTP 403 trên SOAP/XML & Phân Loại Sai REST (`gateway/app/security/protocol_detector.py`)**
  - Thay dòng 284 bằng regex XXE chuẩn: `re.search(r"(?i)<!(?:DOCTYPE|ENTITY)\b[^>]*\b(?:SYSTEM|PUBLIC)\b|<!ENTITY\b", xml_text)` (tuyệt đối không match từ đơn `"system"`/`"public"`!).
  - Không gán nhầm REST JSON có key `"query"` thành `GRAPHQL` (kiểm tra giá trị là chuỗi GraphQL thực có `{...}` hoặc path `/graphql`).
  - Chuẩn hóa lowercase headers trước khi đọc `soapaction`; quét XXE cả trên `query_params`; chạy `UniversalPayloadExtractor` trước hoặc bổ sung decapsulated payload vào `RuleEngine`.

- [ ] **[LOGIC-PBL6-003] Hoàn Thiện Policy Enforcement & Nối Cấu Hình `.env` (`gateway/app/api/proxy.py`, `config.py`)**
  - Xử lý nhánh `elif decision.is_rate_limited:` áp dụng `rate_limiter.check_rate_limit(..., risk_penalty=True)` và trả HTTP 429 khi vượt ngưỡng.
  - Ở `schema_strict_mode`: chỉ chặn 400 khi `active_waf_mode not in ("OFF", "MONITOR_ONLY", "MONITOR")`, và luôn ghi `SecurityEvent`.
  - Nối `ML_ENABLED`, `ANOMALY_ENABLED`, `RATE_LIMIT_ENABLED`, `RATE_LIMIT_PER_MINUTE`, `RISK_BLOCK_THRESHOLD`, `RISK_RATE_LIMIT_THRESHOLD` vào khởi tạo engine.

- [x] **[SCI-PBL6-001] Khắc Phục Sai Lệch Khoa Học, Data Leakage & Training-Serving Skew (`scripts/build_defense_dataset_v2.py`, `features/canonicalizer.py`, `evaluate_csic2010.py`, `generate_notebooks.py`)** — `[VERIFIED PASS]`
  - Gỡ bỏ 100% CSIC 2010 khỏi tập train; chia Train/Val/Test hoàn toàn tách biệt theo canonical SHA-256 hash giữa Notebook 01 và Notebook 02 (tuyệt đối không test trên `raw_unfiltered_500k` trùng mẫu train).
  - Đồng nhất pipeline trích xuất đặc trưng `canonicalize_payload()` và `extract_26_vector()` giữa training và `proxy.py` (xóa sạch Training-Serving Skew).
  - Đánh giá Zero-Shot trên CSIC 2010 đạt FPR = 0.00% (cải thiện từ 29.60%), trung thực phản ánh năng lực từng thành phần Defense-in-Depth.

- [ ] **[SCI-PBL6-002] Gỡ Bỏ Toàn Bộ Số Liệu Giả Lập Trên SOC Dashboard (`dashboard.py`, `NetworkTopologyMap.tsx`, `PayloadEvidenceDrawer.tsx`, `DetectionExplainabilityModal.tsx`, `MetricCards.tsx`)**
  - `/dashboard/protocols`: trả 0% khi CSDL rỗng (bỏ fallback 68/18/8/4/2%).
  - `/dashboard/topology`: đọc `active_waf_mode`, `target_api_url`, ping latency thật và trạng thái thực thay vì hardcode IP/RTT/PyTorch DQN.
  - `PayloadEvidenceDrawer`: đọc `details.matches || details.rule_matches`; sửa nhãn `(Forwarded & Logged)` theo `event.action` thật; hiển thị đúng 17 đặc trưng thật từ `details.ml_inference.feature_vector` (tên chuẩn theo `CANONICAL_FEATURE_NAMES`).
  - `DetectionExplainabilityModal`: đọc `ml_inference.confidence` thật (bỏ công thức `88 + length % 12`); đổi `event.rule_score || 85.0` thành `event.rule_score ?? 0`; không bịa điểm ML/Anomaly khi `null`; hiển thị đúng tên model đang chạy (`Random Forest`); lấy quyết định thực từ `event.action` thay vì tự suy diễn theo ngưỡng; bỏ `+2.4σ` cứng.
  - `MetricCards`: tính RPS thật trên cửa sổ 60s gần nhất từ backend thay vì `totalRequests / 90`.

---

### 🟡 NHÓM P2 — MEDIUM & LOW (HẠ TẦNG, CHẤT LƯỢNG & ANTI-DRIFT)

- [ ] **[INFRA-PBL6-001]** Thêm `.dockerignore` riêng vào `gateway/`, `dashboard/`, `vulnerable-api/`; thêm non-root `USER` cho `gateway` & `vulnerable-api`; đồng bộ `dashboard/Dockerfile` lên `node:20-alpine` + `npm ci`; cân nhắc đổi default `WAF_MODE=${WAF_MODE:-ACTIVE_BLOCKING}` trong `docker-compose.yml`.
- [ ] **[LOGIC-PBL6-004]** Sửa `/dashboard/simulate` gửi đúng trường Bookie (`author`/`comment`, `host`); hoàn thiện `SchemaValidator` (live spec fetch, thêm `/users/list/`, kiểm tra path param type, `content_type`, chặn `additionalProperties`).
- [ ] **[LOGIC-PBL6-005]** Sửa timezone trong `derive_session_id` (ép UTC khi naive); gán `session_id`/`kill_chain_stage` trong `record_rate_limit` & `seeder.py`; khử N+1 SQL ở `/dashboard/sessions`; sửa `/dashboard/timeline` dùng `%Y-%m-%d %H:%M`; sửa `AttackSessionsModal` bỏ `expandedSessionId` khỏi `useCallback` và thêm backdrop click-to-close.
- [ ] **[PERF-PBL6-002]** Đóng tạm `httpx.AsyncClient` trong `ProxyService`; đo `latency_ms` thực cho request bị chặn; thêm cột index `api_protocol` thay cho full-table `json.loads` ở `/protocols`; ghi `AuditLog` khi gọi admin APIs; bật rõ `PRAGMA busy_timeout=5000;`.
- [ ] **[QUAL-PBL6-001]** Sửa 6 lỗi `ruff check gateway/` và 51 lỗi ở `ml-engine/` + `attack-lab/`; mở rộng `.github/workflows/ci.yml` chạy đầy đủ test suites; thêm `dashboard/.eslintrc.json`; xóa 2 file component dư thừa ở `dashboard/src/components/` và dọn `scratch/`.
- [ ] **[ARCH-PBL6-001]** Xóa toàn bộ di chứng `Juice Shop` trong `health.py`, `gateway/tests/`, `DASHBOARD_SPEC.md`, `GAP_ANALYSIS.md`, `GLOSSARY.md`; cập nhật `README.md` (xóa tham chiếu không tồn tại `attack-lab/cli.py`, cập nhật Phase & số lượng test) và footer `page.tsx`.
- [ ] **[SEC-PBL6-007]** Chặn chuyển tiếp `X-API-Key` qua `/api/proxy/`; giữ nguyên multi-value `Set-Cookie` trong proxy; sửa hàm `isLanAttacker` (`172.16.0.0/12`) ở `LiveEventsTable.tsx`; thêm cycle guard cho `resolve_ref` ở `attack-lab/agent/recon.py`; dùng `hmac.compare_digest` ở `vnpay.py`; thay `datetime.utcnow()` sang `datetime.now(datetime.timezone.utc)`.

---

# 📋 LỊCH SỬ THẨM ĐỊNH CÁC TASK TRƯỚC
*(PR #111 Task 10.2 APPROVE 9.9/10; Task 10.1, Task 12.2, Task 12.1, Task 11.3, Phase 8, Phase 6)*
