# 📋 REVIEW FEEDBACK & FINAL SIGN-OFF REPORT (FULL PBL6: BLUE TEAM v2.0 + RED TEAM + THESIS & DEMO READY)

## 🏆 NGHIỆM THU TỔNG THỂ TRƯỚC BẢO VỆ (2026-11-23): 26/26 HẠNG MỤC ĐẠT 100% `[VERIFIED PASS]` — READY TO PRINT & DEFEND
- **Reviewer:** `@pbl6-reviewer` (Senior Security Architect & Independent Code Auditor)
- **Ngày nghiệm thu toàn hệ thống:** `2026-11-23`
- **Nhánh Git cục bộ:** `feat/blue-team-v2-sprint3-logic-ui`
- **Chuỗi Commit đã tái-audit độc lập:**
  - **Sprint 1 (`9e073ad`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: P0 Critical Security Hardening (`SEC-PBL6-001..004`, `SEC-PBL6-006`, ReDoS `XSS-002`).
  - **Sprint 2 (`4f62c74`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: Defense ML Engine v2.0 (`SEC-PBL6-005`, `SCI-PBL6-001`: Zero-Pickle `xgb_v2.ubj` + `iforest_v2.npz`, Zero-Leakage `defense_v2`, `2.246 ms/req` single-req / `0.867 ms` microbench, Anomaly Recall `57.75%` / FPR `4.00%`, Zero-Shot CSIC 2010 FPR `0.00%`).
  - **Sprint 3 (`5fa0371` + `a4b34ff`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: WAF Logic & SOC Dashboard Truthfulness (`LOGIC-PBL6-001..005`, `SCI-PBL6-002`: `0` fake telemetry hits trên `dashboard/src/`, fix `bytes -> b'...'` 93.2% SQLi FP & `UnboundLocalError: session_id`, khử N+1 `/dashboard/sessions`).
  - **Sprint 4 (`665a782`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: High-Concurrency Async Gateway, SQLite WAL Group-Commit, Infrastructure & Anti-Drift (`PERF-PBL6-001..002`, `SEC-PBL6-007`, `INFRA-PBL6-001`, `QUAL-PBL6-001`, `ARCH-PBL6-001`, `SCI-PBL6-001` real profiling).
  - **Pre-Defense Integration & Audit Pass (2026-11-23)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: Full audit & integration of Minh's Red Team (`origin/feat/evasion-engine`, commit `ec87fc5`, `RED-PBL6-001..007`), Live Demo/Docker Blocker Fixes, Real Blue Team v2.0 Ablation Study, Live Red DQN vs Blue WAF Campaign, Print-Ready Thesis `.docx` (8 files) + 4x 300 DPI Charts + 14-Slide Defense `.pptx`, and Live 3-Service E2E Dry Run.
- **Tổng kết kiểm chứng độc lập cuối cùng (2026-11-23):**
  - **Lint (`ruff check gateway/ ml-engine/ attack-lab/ tests/unit/test_evasion.py tests/unit/test_runner.py scripts/...`):** `0 errors` (`All checks passed!`) — dọn sạch toàn bộ 50 lỗi từ nhánh Red Team + 57 lỗi nền trước đó.
  - **Unit & Integration Tests (`pytest gateway/tests/ tests/unit/ ml-engine/tests/`):** **353/353 PASSED (100%)** (`297` Blue Team + `56` Red Team & AI Arena).
  - **Frontend Build (`npm run lint` + `tsc --noEmit` + `next build`):** `0 ESLint warnings/errors`, `0 TypeScript errors`, `✓ Compiled successfully` (`/` + `/arena` + `/api/gateway/[...path]`), `0` secrets trong `.next/static/`.
  - **Docker Compose Config (`docker compose config --quiet`):** Exit `0` (`0` warnings), bổ sung `"xgboost>=2.0.0"` vào `gateway/pyproject.toml`.
  - **Ablation Study Thực Tế v2.0 (`data/benchmark_1000_diverse.csv`, `0` overlap):** Hybrid đạt Accuracy **`97.80%`**, Precision **`100.00%`**, Recall **`97.25%`**, F1 **`98.61%`**, FPR **`0.00%`**, Youden's `J = 0.9725`, Mean **`0.848 ms`** (P95 `1.075 ms`).
  - **Live Red Team PyTorch DQN vs Blue Team v2.0 (`attack-lab/artifacts/campaign_report.json`):** **`20/20 BLOCKED (100.0%)`**, **`0.0%` bypass**, avg threat score **`95.63/100`**, avg live HTTP latency **`4.29 ms`**.
  - **Live 3-Service E2E Demo Dry Run (`Bookie :5000` + `Gateway :8000` + `Dashboard Prod :3000`):** `start_all_services.py --check` exit `0`; `4x HTTP 401` unauth + `HTTP 403` BFF block; `/` & `/arena` HTTP `200`; Live Arena Battles `all` (`8/8` BLUE_TEAM, `94.6/100`) & `sqli` (`6/6` BLUE_TEAM, `96.9/100`); `demo_rehearsal.py --auto` đạt 4/4 giai đoạn (`5/5` Baseline `200`, `5/5` Monitor, `5/5` Active Block `403` gồm SOAP XXE, `5` Brute-Force `429`); `recon.py` phát hiện sống `11` endpoint OpenAPI Bookie qua WAF Gateway.
  - **Independent Live ASGI Benchmark (`C=50`):** Benign `300/300 HTTP 200` -> **`269.50 RPS`** (report profiling: `340.14 RPS`); Attack SQLi `200/200 HTTP 403` -> **`272.75 RPS`** (report profiling: `253.31 RPS`) — vượt xa SLA `>= 150 RPS`.

---

### 🟣 NHÓM RED TEAM & AI ARENA INTEGRATION (`origin/feat/evasion-engine`, `ec87fc5` — 7/7 ĐÃ VÁ & XÁC MINH 100%)

- [x] **[RED-PBL6-001] Khóa Xác Thực Admin & BFF Whitelist Cho AI Arena (`gateway/app/api/arena.py`, `gateway/app/api/router.py`, `dashboard/src/app/api/gateway/[...path]/route.ts`)** — `[VERIFIED PASS]` (Gắn `dependencies=[Depends(require_admin)]` cho toàn bộ `/dashboard/arena/*`; đăng ký router trong `router.py`; mở whitelist chặt `"arena"` với 3 subpath `{"battle", "live", "history"}` trên Next.js BFF; live test trả `401` khi gọi trực tiếp không key và `200` qua BFF).

- [x] **[RED-PBL6-002] Ép Xác Minh SHA-256 Fail-Closed & `weights_only=True` Cho PyTorch DQN (`attack-lab/runner.py`, `attack-lab/models/evasion_agent_metadata.json`)** — `[VERIFIED PASS]` (Xác minh SHA-256 `b89d7dc6b7c9533dffe010457843f2507f37a699510203c33b15f094ea768744` trước khi nạp `evasion_agent.pt` bằng `torch.load(..., map_location="cpu", weights_only=True)`, ngăn chặn RCE qua pickle payload).

- [x] **[RED-PBL6-003] Loại Bỏ Số Liệu Độ Trễ & Lịch Sử Trận Đấu Giả Lập (`gateway/app/api/arena.py`, `dashboard/src/services/api.ts`, `dashboard/src/types/dashboard.ts`)** — `[VERIFIED PASS]` (Xóa `random.uniform(...)` trong `arena.py`, đo bằng `time.perf_counter()` thật; loại hoàn toàn `inMemoryBattleHistory` & `generateMockBattle()` trên frontend; đồng bộ chuẩn `red_wins`/`blue_wins`, `red_team_wins`/`blue_team_wins`, `original_payload`).

- [x] **[RED-PBL6-004] Xử Lý Training-Serving Skew & Offload Async Event Loop Trong `arena.py` (`gateway/app/api/arena.py`)** — `[VERIFIED PASS]` (Sử dụng `extract_26_from_http` + URL-encoded `query_str` + `anyio.to_thread.run_sync` + trường thật của Bookie `comment`/`author`/`book_id`, `host`).

- [x] **[RED-PBL6-005] Vá Lỗi `if threat_score is None` & HTTP `429` Trong Red Team Tooling (`attack-lab/agent/tools.py`)** — `[VERIFIED PASS]` (Sửa falsy bug `threat_score == 0.0` và nhận diện HTTP `429` là bị chặn/điều tiết thay vì bypass).

- [x] **[RED-PBL6-006] Thay Thế `campaign_report.json` Hỏng (`WinError 10061`) Bằng Chiến Dịch Đối Kháng Live Thật (`attack-lab/artifacts/campaign_report.json`)** — `[VERIFIED PASS]` (Chạy live `runner.py --mode ai_agent --campaign all --max-rounds 4` qua WAF Gateway v2.0 + Bookie API -> **`20/20 BLOCKED (100.0%)`**, `0.0%` bypass, `95.63/100` avg risk, `4.29 ms` live HTTP latency).

- [x] **[RED-PBL6-007] Tích Hợp Điều Hướng SOC <-> Arena & Dọn Sạch 50 Lỗi Lint Red Team (`dashboard/src/components/Header.tsx`, `attack-lab/`, `tests/unit/test_{evasion,runner}.py`)** — `[VERIFIED PASS]` (Thêm thanh chuyển tab `Tổng quan SOC /` <-> `Đấu Trường AI /arena`; sửa 50 lỗi ruff kể cả E402 trong `01_train_attack_agent.ipynb`; `56/56` unit & integration test Arena/Evasion/Runner PASS).

---

### 📄 BỘ TÀI LIỆU IN BÁO CÁO & SLIDE BẢO VỆ (VERIFIED 100% ĐỒNG BỘ SỐ LIỆU THẬT)

- [x] **8 Tệp Word A4 Sẵn Sàng In Ấn (`docs/reports/PBL6_Bao_Cao.docx`, `PBL6_Bao_Cao_Tong_Hop_Toan_Van.docx`, Chương 1–5 & Phụ lục):** Đã chuẩn hóa tên GVHD (`TS. Nguyễn Thế Xuân Ly`), nhóm thực hiện (`Nguyễn Văn Công` — `21T_DT`, `Nguyễn Minh`), nhúng 4 biểu đồ 300 DPI (`docs/reports/figures/fig1..4_*.png`), `0` lỗi LaTeX/escape, `0` di chứng `Juice Shop`, `0` placeholder.
- [x] **14 Slide PowerPoint 16:9 (`docs/reports/PBL6_Academic_Defense_Slides.pptx` & `SLIDE_THUYET_TRINH_BAO_VE_PBL6.md`):** Đã nhúng biểu đồ thực nghiệm 300 DPI, đầy đủ ghi chú thuyết trình (Speaker Notes) cho 14/14 slide và phân vai trình bày 10 phút Blue Team + Red Team.

---

### 🔴 NHÓM P0 — CRITICAL (5/5 ĐÃ VÁ & XÁC MINH 100%)

- [x] **[SEC-PBL6-001] Vá Bypass Rate Limiter & Unbounded Memory DoS (`gateway/app/security/rate_limiter.py`, `gateway/app/api/proxy.py`)** — `[VERIFIED PASS]` (`9e073ad`: Auth 25 req xoay token/UA -> `limited=15, tracked_keys=11`; Global 200 -> `limited=20`; `OrderedDict` LRU `50000`).

- [x] **[SEC-PBL6-002] Vá Bypass WAF qua > 16KB Padding, Non-UTF-8 Byte Prefix & Giới Hạn Kích Thước Body (`gateway/app/security/engine.py`, `gateway/app/api/proxy.py`, `gateway/app/security/protocol_detector.py`)** — `[VERIFIED PASS]` (`9e073ad`: Single 17KB JSON leaf `score=94.5`; JSON depth=35 `score=85.5`; Chunked >1MB `HTTP 413`; Non-UTF-8 `\xff` `HTTP 403`).

- [x] **[SEC-PBL6-003] Vá Lỗi Fail-Open Khi `detection_result is None` (`gateway/app/api/proxy.py`, `gateway/app/services/security.py`)** — `[VERIFIED PASS]` (`9e073ad`: RuleEngine crash trên SQLi trả `HTTP 403 BLOCK, risk=100.0`; `record_detection(None)` an toàn).

- [x] **[PERF-PBL6-001] Vá ReDoS `O(n^2)` ở `XSS-002` & Bỏ Block Asyncio Event Loop (`gateway/app/security/rules/xss.py`, `gateway/app/api/proxy.py`, `gateway/app/main.py`, `gateway/app/db/session.py`)** — `[VERIFIED PASS]` (`9e073ad` + `665a782`: ReDoS `XSS-002` giảm từ `923.37 ms -> 0.891 ms`; offload WAF/ML qua `anyio.to_thread.run_sync`, pure ASGI middleware, RAM TTL cache `waf_mode`, Leader-Follower Group Commit WAL; đo độc lập `C=50`: Benign **`269.50 RPS`** `300/300 HTTP 200`, Attack **`272.75 RPS`** `200/200 HTTP 403`).

- [x] **[SEC-PBL6-004] Gỡ `NEXT_PUBLIC_ADMIN_API_KEY` Khỏi Client Bundle & Bảo Vệ Toàn Bộ `/dashboard/*` (`dashboard/`, `docker-compose.yml`, `gateway/app/api/dashboard.py`)** — `[VERIFIED PASS]` (`9e073ad`: `0` secret trong `.next/static/`; 7/7 `GET /dashboard/*` trả `401`; BFF Proxy `route.ts` chặn traversal + whitelist endpoint + origin check + Docker `BACKEND_URL:-http://gateway:8000`).

---

### 🟠 NHÓM P1 — HIGH (7/7 ĐÃ VÁ & XÁC MINH 100%)

- [x] **[SEC-PBL6-005] Ép Xác Minh SHA-256 Fail-Closed & 100% Zero-Pickle (`gateway/app/security/ml_detector.py`, `anomaly.py`, `ml-engine/notebooks/generate_notebooks.py`)** — `[VERIFIED PASS]` (`4f62c74`: Fail-Closed SHA-256 không còn backdoor `"tmp"`, nạp `xgb_v2.ubj` + `iforest_v2.npz` với `allow_pickle=False`, tự định vị `repo_root` độc lập CWD).

- [x] **[SEC-PBL6-006] Vá Các Kỹ Thuật Né Tránh Rule Engine (`normalizer.py`, `engine.py`, `rules/`)** — `[VERIFIED PASS]` (`9e073ad`: Zero-width Unicode, `UNION/**/SELECT`, `UNION/*\n*/SELECT` `re.DOTALL`, `Cookie` header, HTML5 `ontoggle`, `; env`, `; python3`, `; ls`, `| head` đều bị phát hiện).

- [x] **[LOGIC-PBL6-001] Đồng Bộ Enum `SecurityEvent.action` Để Sửa `blocked_count = 0` (`dashboard.py`, `proxy.py`, `seeder.py`)** — `[VERIFIED PASS]` (`5fa0371`: `blocked=27, monitored=3, rate_limited=7`; đồng bộ `"BLOCKED"`/`"MONITOR"`/`"RATE_LIMIT"`).

- [x] **[LOGIC-PBL6-002] Sửa False Positive HTTP 403 trên SOAP/XML & Phân Loại Sai REST (`gateway/app/security/protocol_detector.py`, `proxy.py`, `extractor.py`)** — `[VERIFIED PASS]` (`5fa0371` + `a4b34ff`: `benign_post=200 ML=1.28`, `benign_soap=200 ML=0.89`, `soap_cdata_sqli=403`, `soap_xxe=403`, REST `"query"` -> `REST`, `SOAPAction` case-insensitive).

- [x] **[LOGIC-PBL6-003] Hoàn Thiện Policy Enforcement & Nối Cấu Hình `.env` (`gateway/app/api/proxy.py`, `config.py`)** — `[VERIFIED PASS]` (`5fa0371` + `a4b34ff`: Risk `[60, 80)` -> 429 kể cả khi `rate_limit_enabled=False`, `schema_strict_mode` tôn trọng `WAF_MODE` & ghi `SecurityEvent`, `ML_ENABLED`/`ANOMALY_ENABLED`/`RATE_LIMIT_*`/`RISK_*` nối thực tế).

- [x] **[SCI-PBL6-001] Khắc Phục Sai Lệch Khoa Học, Data Leakage, Training-Serving Skew & Real Profiling (`scripts/build_defense_dataset_v2.py`, `features/canonicalizer.py`, `evaluate_csic2010.py`, `generate_notebooks.py`, `scripts/run_gateway_profiling.py`)** — `[VERIFIED PASS]` (`4f62c74` + `a4b34ff` + `665a782`: `0` canonical hash leakage giữa Train/Val/Test/CSIC; Anomaly Recall `57.75%` / FPR `4.00%`; Zero-Shot CSIC 2010 FPR `0.00%`, Precision `100.00%`, Hybrid XSS `100.00%`; `scripts/run_gateway_profiling.py` đo trực tiếp class Gateway thật với `0` hằng số giả, `ai_pipeline_mean_ms = 0.8674 ms`, `full_inspection_mean_ms = 1.0951 ms`).

- [x] **[SCI-PBL6-002] Gỡ Bỏ Toàn Bộ Số Liệu Giả Lập Trên SOC Dashboard (`dashboard.py`, `NetworkTopologyMap.tsx`, `PayloadEvidenceDrawer.tsx`, `DetectionExplainabilityModal.tsx`, `MetricCards.tsx`)** — `[VERIFIED PASS]` (`5fa0371`: `0` fake hits trên toàn `dashboard/src/`, `/stats` `current_rps` thật, `/topology` async ping/mode thật, `PayloadEvidenceDrawer` 26 đặc trưng thật, `DetectionExplainabilityModal` không bịa số).

---

### 🟡 NHÓM P2 — MEDIUM & LOW (7/7 ĐÃ VÁ & XÁC MINH 100%)

- [x] **[INFRA-PBL6-001]** `[VERIFIED PASS]` (`665a782`) — Đã tạo `.dockerignore` riêng cho `gateway/`, `dashboard/`, `vulnerable-api/`; thêm non-root `USER appuser` cho `gateway/Dockerfile` & `vulnerable-api/Dockerfile`; nâng `dashboard/Dockerfile` lên `node:20-alpine` + `npm ci` + `USER nextjs`; đổi default `docker-compose.yml` sang `WAF_MODE=${WAF_MODE:-ACTIVE_BLOCKING}`.

- [x] **[LOGIC-PBL6-004]** `[VERIFIED PASS]` (`5fa0371`) — `/dashboard/simulate` gửi đúng trường Bookie (`author`/`comment`, `host`); `SchemaValidator` hỗ trợ `/users/list/`, path param `TYPE_MISMATCH`, `UNSUPPORTED_MEDIA_TYPE`, `ADDITIONAL_PROPERTY_NOT_ALLOWED`, `refresh_spec_from_target()`.

- [x] **[LOGIC-PBL6-005]** `[VERIFIED PASS]` (`5fa0371`) — `derive_session_id` ép UTC; `record_rate_limit` & `seeder.py` gán đủ `session_id`/`kill_chain_stage`; `/dashboard/sessions` khử N+1 (`3` SQL queries cho `18` sessions); `/dashboard/timeline` dùng `%Y-%m-%d %H:%M`; `AttackSessionsModal` bỏ `expandedSessionId` khỏi `useCallback` và hỗ trợ click backdrop để đóng.

- [x] **[PERF-PBL6-002]** `[VERIFIED PASS]` (`665a782`) — Đóng tạm `httpx.AsyncClient` trong `finally` ở `ProxyService`; đo `response_time_ms` thực cho request bị chặn (`2.185 ms`, không hardcode `1.2`); thêm cột `SecurityEvent.api_protocol` có index (`ix_security_events_api_protocol`) + SQL `GROUP BY` ở `/dashboard/protocols`; ghi `AuditLog` đầy đủ trên `toggle-waf-mode`, `reset-demo`, `seed-demo` (`count=3`); bật `PRAGMA journal_mode=WAL;` & `PRAGMA busy_timeout=5000;` + `QueuePool`.

- [x] **[QUAL-PBL6-001]** `[VERIFIED PASS]` (`665a782`) — `ruff check gateway/ ml-engine/ attack-lab/` đạt `0 errors`; `.github/workflows/ci.yml` chạy đủ `ruff` 3 repo + `pytest` 3 suite + `dashboard` (`npm run lint`, `tsc --noEmit`, `next build`); bổ sung `dashboard/.eslintrc.json`; xóa 2 file wrapper dư thừa tại `dashboard/src/components/`; dọn sạch `scratch/` (`0` file tồn).

- [x] **[ARCH-PBL6-001]** `[VERIFIED PASS]` (`665a782`) — `0` di chứng `Juice Shop` trên `health.py`, `test_health.py`, `DASHBOARD_SPEC.md`, `GAP_ANALYSIS.md`, `GLOSSARY.md`, `ARCHITECTURE.md`, `README.md`; xóa tham chiếu ảo `attack-lab/cli.py` trong `README.md`; cập nhật footer `dashboard/src/app/page.tsx` sang `Blue Team v2.0: Rule + XGBoost v2.0 + Isolation Forest v2.0`.

- [x] **[SEC-PBL6-007]** `[VERIFIED PASS]` (`665a782`) — `filter_request_headers` chặn rò rỉ `X-API-Key` xuống upstream; `filter_response_header_items` giữ nguyên multi-value `Set-Cookie` (`count=2`); `LiveEventsTable.tsx` sửa chuẩn CIDR `172.16.0.0/12`; `attack-lab/agent/recon.py` có cycle guard chống circular `$ref` (`self_cycle=guarded, ab_cycle=guarded`); `vnpay.py` dùng `hmac.compare_digest`; bỏ toàn bộ `datetime.utcnow()` sang `datetime.now(datetime.timezone.utc)`.
  - *Ghi chú tồn dư vi mô (non-blocking, `[CODE-VERIFIED]`):* (1) `filter_request_headers` chưa tách các header tùy biến liệt kê động trong `Connection:` (RFC 7230 §6.1); (2) `attack-lab/environment/env.py:248` (phần Red Team Máy 2) có đặc trưng `index / max(count - 1, 1)` song song `index / max(count, 1)`. Cả hai không ảnh hưởng an toàn Blue Team và có thể tinh chỉnh ở backlog phụ.

---

# 📋 LỊCH SỬ THẨM ĐỊNH CÁC TASK TRƯỚC
*(PR #111 Task 10.2 APPROVE 9.9/10; Task 10.1, Task 12.2, Task 12.1, Task 11.3, Phase 8, Phase 6; Blue Team v2.0 Upgrade Pipeline Sprints 1–4: 19/19 Findings `[VERIFIED PASS]`)*
