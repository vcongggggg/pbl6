# 📋 REVIEW FEEDBACK & ACTIONABLE TASKS (DÀNH CHO PHIÊN CODER @PBL6)

## CẬP NHẬT MỚI NHẤT: TÁI-AUDIT ĐỘC LẬP SPRINT 1 P0 (`pbl6-blueteam-v2-sprint1-p0`) — CONDITIONAL FAIL (FIX-UP DISPATCHED)
- **Reviewer:** `@pbl6-reviewer` (Senior Security Architect & Independent Code Auditor)
- **Trạng thái Sprint 1:** 🟡 **CONDITIONAL FAIL -> Đã gửi lệnh Fix-Up `pbl6-blueteam-v2-sprint1-fix1`**
- **Bằng chứng kiểm thử Sprint 1 (`[VERIFIED]`):**
  - `ruff check gateway/`: **0 errors (PASS)** (đã sửa sạch 6 lỗi cũ)
  - `pytest gateway/tests/ tests/unit/ ml-engine/tests/`: **261/261 PASS**
  - `dashboard` (`tsc --noEmit` + `next build`): **PASS**; quét `dashboard/.next/static/`: **0 secret leaks**
  - Live PoC PASS: Rate-Limit IP Hard Cap & LRU (`limited=15/25` auth), RuleEngine exception fail-closed (`HTTP 403 risk=100.0`), ReDoS `XSS-002` (`923ms -> 0.89ms`), `7/7 GET /dashboard/*` trả `HTTP 401` khi không có key, `UNION/**/SELECT`, `<scr\u200bipt>`, `ontoggle`, `; env`, `; python3`, `Cookie` SQLi đều bị phát hiện.
- **4 lỗi sót phát hiện qua Adversarial PoC cần vá trong `pbl6-blueteam-v2-sprint1-fix1`:**
  1. `[CRITICAL - SEC-PBL6-002]` Single JSON string value > 16KB (`{"comment": "A"*17000 + "' UNION SELECT 1,2--"}`) vẫn bị cắt cụt ở `_inspect_text()` (`is_attack=False, score=0.0`). Cần đưa sliding window (`16384/512`) vào trực tiếp `RuleEngine._inspect_text()`.
  2. `[CRITICAL - SEC-PBL6-002]` JSON lồng sâu `depth=35` bị silent return tại `_inspect_json_recursive()` (`is_attack=False, score=0.0`) + `proxy.py:142` vẫn `await request.body()` trước khi kiểm tra 1MB (chunked OOM). Cần fallback sang raw sliding window khi vượt `max_depth` và đọc streaming chunk ở `proxy.py`.
  3. `[HIGH - SEC-PBL6-004]` BFF Proxy `dashboard/src/app/api/gateway/[...path]/route.ts` chưa chặn path traversal (`..` / `%2e%2e` -> SSRF tới `/api/proxy/*` kèm `X-API-Key`) và `docker-compose.yml:71` đặt `BACKEND_URL:-http://localhost:8000` gây 502 trong Docker (phải là `http://gateway:8000`).
  4. `[MEDIUM - SEC-PBL6-006]` `normalizer.py:54` thiếu `flags=re.DOTALL` nên `1' UNION/*\n*/SELECT 1,2,3--` lọt (`is_attack=False, score=0.0`).

---

### 🔴 NHÓM P0 — CRITICAL (BẮT BUỘC SỬA TRƯỚC KHI MERGE / DEMO)

- [x] **[SEC-PBL6-001] Vá Bypass Rate Limiter & Unbounded Memory DoS (`gateway/app/security/rate_limiter.py`, `gateway/app/api/proxy.py`)** — `[VERIFIED PASS]` (Auth 25 req xoay token/UA -> `limited=15, tracked_keys=11`; Global 200 -> `limited=20`; `OrderedDict` LRU `50000`).

- [ ] **[SEC-PBL6-002] Vá Bypass WAF qua > 16KB Padding, Non-UTF-8 Byte Prefix & Giới Hạn Kích Thước Body (`gateway/app/security/engine.py`, `gateway/app/api/proxy.py`, `gateway/app/security/protocol_detector.py`)** — `PARTIAL`: Đã vá 17KB separate-key JSON, non-UTF-8 `\xff` và `>1MB` HTTP 413; **còn sót 2 bypass (`pbl6-blueteam-v2-sprint1-fix1`)**: (1) Single JSON leaf string > 16KB bị cắt ở `_inspect_text()`, (2) JSON depth > 32 bị silent return, (3) đọc chunked stream thay vì `await request.body()`.

- [x] **[SEC-PBL6-003] Vá Lỗi Fail-Open Khi `detection_result is None` (`gateway/app/api/proxy.py:474`, `gateway/app/services/security.py:66`)** — `[VERIFIED PASS]` (RuleEngine crash trên SQLi trả `HTTP 403 BLOCK, risk=100.0`; `record_detection(None)` an toàn).

- [ ] **[PERF-PBL6-001] Vá ReDoS `O(n^2)` ở `XSS-002` & Bỏ Block Asyncio Event Loop (`gateway/app/security/rules/xss.py:27`, `gateway/app/api/proxy.py`, `gateway/app/db/session.py`)** — `PARTIAL`: ReDoS `XSS-002` **`[VERIFIED PASS]`** (`923.37 ms -> 0.891 ms`); phần Async Event Loop (`>= 150 RPS`) thuộc Sprint 4.

- [ ] **[SEC-PBL6-004] Gỡ `NEXT_PUBLIC_ADMIN_API_KEY` Khỏi Client Bundle & Bảo Vệ Toàn Bộ `/dashboard/*` (`dashboard/`, `docker-compose.yml`, `gateway/app/api/dashboard.py`)** — `PARTIAL`: Đã gỡ sạch key khỏi `.next/static/` (`0 hits`) và bảo vệ 7/7 `GET /dashboard/*` (`HTTP 401`); **cần vá BFF path traversal (`..`) trong `route.ts` + đổi `BACKEND_URL` mặc định sang `http://gateway:8000` trong `docker-compose.yml` (`pbl6-blueteam-v2-sprint1-fix1`)**.

---

### 🟠 NHÓM P1 — HIGH (BẢO MẬT ML, LOGIC NGHIỆP VỤ & LIÊM CHÍNH KHOA HỌC)

- [ ] **[SEC-PBL6-005] Ép Xác Minh SHA-256 Fail-Closed Trước `joblib.load()` (`gateway/app/security/ml_detector.py`, `anomaly.py`, `ml-engine/notebooks/generate_notebooks.py`)**
  - Từ chối nạp model nếu thiếu metadata hoặc thiếu `sha256_hash` (chỉ cho phép bypass qua cờ test tường minh).
  - Khớp tên file metadata theo tên model (`{stem}_metadata.json` / `rf_metadata.json`).
  - Trong Notebook 02 (`generate_notebooks.py:643`), di chuyển bước tính & `assert actual_rf_hash == expected_hash` lên **TRƯỚC** `joblib.load(rf_path)`.

- [ ] **[SEC-PBL6-006] Vá Các Kỹ Thuật Né Tránh Rule Engine (`normalizer.py`, `engine.py`, `rules/`)**
  - `InputNormalizer.normalize()`: loại bỏ ký tự zero-width (`re.sub(r"[\u200b-\u200f\ufeff]", "", current)`) và thay SQL inline comment `/*...*/` bằng khoảng trắng (song song với kiểm tra raw).
  - Thêm `"cookie"` vào `INSPECTABLE_HEADERS`.
  - Mở rộng `XSS-002` bắt `ontoggle` & mọi `on[a-z]+=` hợp lệ; mở rộng `CMD-001` bắt `; env`, `; ls`, `; python3`, `; sh`, `| head`.

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

- [ ] **[SCI-PBL6-001] Khắc Phục Sai Lệch Khoa Học, Data Leakage & Training-Serving Skew (`scripts/run_gateway_profiling.py`, `evaluate_csic2010.py`, `run_ablation_study.py`, `curate_and_deduplicate_dataset.py`, `generate_notebooks.py`)**
  - Gỡ CSIC 2010 khỏi tập train `curated_deduped_dataset.csv`; chia Train/Val/Test hoàn toàn tách biệt theo canonical SHA-256 hash giữa Notebook 01 và Notebook 02 (tuyệt đối không test trên `raw_unfiltered_500k` trùng mẫu train).
  - Đồng nhất pipeline trích xuất đặc trưng giữa training và `proxy.py` (gỡ Training-Serving Skew) và huấn luyện lại trên tập đa nguồn để kéo FPR trên CSIC 2010 từ `29.60%` về `< 5%`.
  - Viết lại `run_gateway_profiling.py` gọi trực tiếp class thật của Gateway (xóa hằng số giả `24500.0` / `11800.0` và CPU/RAM giả); đồng bộ lời văn báo cáo Markdown trung thực 100% với số đo thực.

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
