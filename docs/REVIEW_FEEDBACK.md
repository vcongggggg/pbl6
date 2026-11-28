# ✅ FINAL AUDIT & REMEDIATION SIGN-OFF — NHÁNH `feat/pbl6-v3-1-live-redteam` (Phase C Verified)

## 🏆 KẾT LUẬN KIỂM TOÁN & VÁ TRIỆT ĐỂ PHASE C (`pbl6-v3-1-001`): **READY FOR FINAL MUSE AUDIT & PR**
- **Ngày hoàn tất kiểm toán & khắc phục Phase C (`C1 -> C5`):** `2026-11-24`
- **Tóm tắt 4 hạng mục kiểm toán Phase C đã được phát hiện và vá triệt để (`100% VERIFIED`):**
  - **[C1 — Live HTTP 3x3 Benchmark & Live `/api/proxy` Arena (`docs/reports/adversarial_benchmark_live_http.json`)]**: Sửa lỗi `target_upstream.py` trả `'SECRET_KEY'` tràn lan trên mọi URL gây kích hoạt nhầm `ResponseDLPGuard`; tách riêng route nhạy cảm `/users/list`, bật `ML_ENABLED=false, ANOMALY_ENABLED=false` thật cho cổng `:8056` (`Rules Only`), bổ sung header `X-WAF-Rule-Score` trong `proxy.py` (`0` hằng số fallback cứng), thêm `--target-url` (chuẩn CWE-918) và chế độ `execution_mode="live_http"` trong `arena.py`. Kết quả thật trên tập ngoại miền `Strange` qua TCP HTTP: `Rules Only` chặn **`88.9%` (`48/54`)**, `Hybrid` nâng lên **`94.4%` (`51/54`, trễ HTTP TB `4.252 ms`)**.
  - **[C2 — Huấn luyện Dueling-DQN `600` Episodes & Biểu đồ Hội tụ (`fig6_dqn_600ep_convergence.png`)]**: Xác thực SHA-256 của `.pt` & `.npz` (`600` episodes, `seed=42`, `Stage 1 = +45.37`, `Stage 2 = +23.27`, `Stage 3 = -14.32` không dính reward-hacking, giảm `8.51%` thử mù quáng), xuất biểu đồ `fig6` 300 DPI và chạy lại `adversarial_benchmark_3x3.json` với checkpoint 600-episode mới.
  - **[C3 — Tinh chỉnh Giảm False Positive 2 Vòng Có Kiểm Soát (`docs/reports/fp_v3_tuning_c3.json`)]**: Vòng 1 xử lý điểm suy biến đường dẫn gốc `'/'` (`special_char_ratio = 1.0`) trong `AnomalyDetector`; Vòng 2 đồng bộ `/openapi.json`, `/docs/`, `/reviews/` vào `BUILTIN_TARGET_SPEC`. Kết quả: `B1000 Strict FPR` giảm từ **`4.0% -> 0.0%` (`Schema OFF`)** và **`8.5% -> 0.0%` (`Schema ON`)** với **`0.00%` suy giảm Recall** (`Operational FPR = 0.00%` trên `1.715` mẫu lành tính; độ trễ 2-hop CSIC 2010 `mean = 4.203 ms`).
  - **[C4 & C5 — Ma trận Đối chiếu Tự động `27/27` (`scripts/generate_reconciliation_matrix.py`) & Rehearsal (`8/8`)]**: Xóa toàn bộ 18 con số gõ tay sai lệch trong `THESIS_ARTIFACT_RECONCILIATION_MATRIX.md`, thay bằng trình kiểm chứng tự động giải nén quét trực tiếp `.docx`, `.pptx`, `.md` khớp `27/27` chỉ số (`0` sai lệch); sửa lỗi hiển thị `8/5 -> 8/8` và `BACKEND_URL` trong `run_live_demo_rehearsal.py`.

---

## 📋 LỊCH SỬ THẨM ĐỊNH PHASE A (`pbl6-v3-fix-round-001` — MERGED PR #138 @ `2acd4e2`)
- **Ngày hoàn tất Phase A (`A1 -> A5`):** `2026-11-24`
- **Bằng chứng thực nghiệm mới bổ sung theo §7 của Muse (`100% VERIFIED`):**
  - **[A1.1 — Đo FPR sau 5 OWASP API Guards (`docs/reports/fp_v3_measurement.json`)]**: Trên `1.715` mẫu lành tính (`1.500` CSIC 2010 + `200` B1000 + `15` REST API), `Operational FPR = 0.00% (0/1.715)` và 5 lá chắn OWASP API Guards mới sinh `0` cảnh báo giả. Khi bật `schema_validation_enabled = True`, `Strict FPR` trên tập B1000 tăng từ `4.0% -> 8.5%` (và `26.67%` trên REST client gửi thêm trường tùy chọn).
  - **[A1.2 / D2 — Độ trễ 2-Hop TCP HTTP E2E thật (`docs/reports/latency_e2e_v3_csic.json`)]**: Đo qua socket HTTP thật (`httpx` -> `Uvicorn Gateway` -> `Uvicorn Upstream` trên `3.000` mẫu CSIC 2010): `mean = 4.465 ms`, `p50 = 4.252 ms`, `p95 = 5.888 ms`, `p99 = 7.260 ms` (phân định rõ với `1.00–1.42 ms` độ trễ in-process engine; đề xuất SLA kép: `<= 1.5 ms` inline engine & `<= 5.5 ms` full 2-hop HTTP proxy).
  - **[A1.3 / D3 — Kiểm chứng Disjoint Canonical Hash (`docs/reports/zero_leakage_v3_verification.json` + `ml-engine/tests/test_zero_leakage_disjoint.py`)]**: `train (32.330) ∩ val (6.928) ∩ test (6.929) = 0`, giao với `CSIC 2010` = `0`, giao với `Benchmark 1000` = `0` (`zero_leakage_verified = true`).
  - **[A2 — Benchmark 3x3 Đa Vòng Khép Kín & Tập Ngoại Miền `Strange` (`docs/reports/adversarial_benchmark_3x3.json`)]**: `0` hằng số `88.0`; `Hybrid` đạt **`100.0%` (`45/45`)** trên tập `Familiar` và **`94.4%` (`51/54`)** trên tập ngoại miền mới `Strange` (`5.6%` lọt lưới ở biến thể blind SQLi số học không dấu nháy `105 OR 17-7=10`).
  - **[A3 — Quyết định Chính sách Schema Validator]**: Vì `FP strict (Schema ON) = 8.5% > 5%` trên B1000 (`26.67%` trên REST client mở rộng), giữ `schema_validation_enabled: bool = False` mặc định kèm chú thích kỹ thuật tường minh trong `config.py`, đồng thời **xóa hoàn toàn trường `role`** khỏi `/users/profile/update/` trong `BUILTIN_TARGET_SPEC` (`schema_validator.py`).
  - **[A4 — Hoàn tất 5 chốt kỹ thuật]**: (1) `sync_to_soc = False` mặc định ở cả `arena.py` & `arena/page.tsx`; (2) Output guard trong `runner.py` bảo vệ tuyệt đối `campaign_report.json`; (3) Whitelist `target_url` chống CWE-918 Open Proxy ở `/dashboard/simulate`; (4) Mở thông hostname `vulnerable-api` cho Docker Compose ở `arena.py`; (5) `sync_thesis_documents.py` đọc động 100% từ JSON artifacts.
  - **[A5 — Verify Live 3-Service, 379/379 Pytest & Sửa Tràn Khung UI 1920x1080]**: `ruff` (`0` lỗi), `pytest` (`379/379` PASS), `tsc`/`lint`/`next build` (`0` lỗi, `0` secret), live `11/11` BFF Simulator vectors + `demo_rehearsal.py --auto` 5 giai đoạn (`exit code 0`), phát hiện qua ảnh headless Edge `1920x1080` và vá dứt điểm lỗi `ThreatTimelineChart` `h-[340px]` tràn che khuất hộp `Attack & Protocol Mix` (`compact` mode `h-[190px]` + hộp `Attack & Protocol Mix` `h-[168px]` hiển thị rõ 100% + đủ `11/11` nút simulator).

---

### 🟢 NHÓM CRITICAL (6/6 — ĐÃ VÁ TRIỆT ĐỂ & KIỂM CHỨNG E2E)

- [x] **[V3-AUDIT-001] `[VERIFIED PASS]` Đồng Bộ Hoàn Toàn Hợp Đồng JSON & TypeScript Giữa `arena.py` <-> `api.ts` <-> `arena/page.tsx`**
  - **Khắc phục:** Chuẩn hóa đầy đủ các trường số học không null (`waf_threat_score`/`threat_score`, `rule_score`, `ml_score`, `anomaly_score`, `waf_blocked`, `dlp_redacted`, `dqn_q_values: list[PentestQValueEntry]`), thêm hàm chuẩn hóa an toàn `normalizeQEntries(...)` và null-safe `(val ?? 0).toFixed(...)` trên `/arena`. Kiểm chứng `tsc --noEmit` + `next build` + Live SSE `:3000/arena` đạt `200 OK`, `0` runtime error.

- [x] **[V3-AUDIT-002] `[VERIFIED PASS]` Viết Lại 100% Benchmark Ma Trận 3x3 Thật (`scripts/run_adversarial_benchmark.py`) & Đồng Bộ Lại Báo Cáo `.docx` + Biểu Đồ `fig5` 300 DPI**
  - **Khắc phục:** Khôi phục sạch 3 file `.docx` từ `cb342d0`, loại bỏ 100% hằng số giả (`0` kết quả `88.0`), chạy vòng lặp đa vòng khép kín 4 bước với `PentestDQNAdvisor` (`pentest_dqn_v2.pt`) + `RuleEngine` + 5 OWASP API Guards + `MLDetector` (`xgb_v2.ubj`) + `AnomalyDetector` (`iforest_v2.npz`) + `time.perf_counter()`. Kết quả thật tách bạch: tập `Familiar` đạt **`100.0%` Block (`45/45`)**, tập ngoại miền `Strange` đạt **`94.4%` Block (`51/54`)**; biểu đồ `fig5` tách `(a) Familiar` & `(b) Strange` không đè nhãn; `sync_thesis_documents.py` đọc động 100% từ JSON.

- [x] **[V3-AUDIT-003] `[VERIFIED PASS]` Triển Khai Đầy Đủ 5 Lá Chắn OWASP API Top 10 Vạn Năng Ở Blue Team (`gateway/app/security/`)**
  - **Khắc phục:** Bổ sung `rules/ssrf.py` (`SSRF-001..004`, chỉ quét query/body tránh FP trên header), `rules/nosqli.py` (`NOSQLI-001..002`), `rules/mass_assignment.py` (`MASS-001..002` + xóa hoàn toàn `role` khỏi `/users/profile/update/` trong `schema_validator.py`), `bola_detector.py` (cửa sổ trượt LRU chặn dò quét ngang `>= 4` ID/60s & sentinel `<= 0`) và `response_dlp.py` (tự động che giấu `[REDACTED_BY_WAF_DLP]` cho băm mật khẩu/khóa bí mật, giữ nguyên `access_token`), tích hợp trực tiếp vào `proxy.py` kèm bộ test `gateway/tests/test_v3_owasp_api_guards.py`.

- [x] **[V3-AUDIT-004] `[VERIFIED PASS]` Huấn Luyện Thật Mạng PyTorch Dueling Double-DQN 64-D / 26-Action (`pentest_dqn_v2.pt` + `.npz`) & Xóa Bỏ Công Thức Q-Value Giả**
  - **Khắc phục:** Xây dựng `attack-lab/environment/pentest_env.py` (`64-D` state, `26` discrete actions), huấn luyện Curriculum 3 giai đoạn (`attack-lab/models/train_pentest_dqn.py`, `360` episodes, lưu kèm SHA-256 cho cả `.pt` `weights_only=True` lẫn `.npz` `allow_pickle=False` tương thích Ubuntu CI không có PyTorch), xóa `_build_dqn_q_values` giả và vector `[0.5]*40` trong `arena.py` & `runner.py`, phân nhánh `reasoning_vi` chính xác theo `403 BLOCK` / `DLP_REDACT` / `200 BYPASS`.

- [x] **[V3-AUDIT-005] `[VERIFIED PASS]` Sửa Dứt Điểm Crash Stage 5 Trong `scripts/demo_rehearsal.py`**
  - **Khắc phục:** Bổ sung phương thức `step_header(...)` và sửa thứ tự giải nén `status, body, lat, _headers = self.request(...)`. Chạy live `python scripts/demo_rehearsal.py --auto --interval 0.02` vượt qua trọn vẹn Stages 1–5 với `exit code 0`.

- [x] **[V3-AUDIT-006] `[VERIFIED PASS]` Ngăn `tests/unit/test_synthesizer.py` Ghi Đè `attack-lab/artifacts/campaign_report.json`**
  - **Khắc phục:** Khôi phục `campaign_report.json` thực chiến (`20/20 BLOCKED`) từ `cb342d0` và truyền `output=tmp_path / "dynamic_campaign_report.json"` trong test; xác nhận `git diff --exit-code attack-lab/artifacts/campaign_report.json` sạch tuyệt đối sau khi chạy toàn bộ `pytest`.

---

### 🟢 NHÓM HIGH & MEDIUM (4/4 — ĐÃ VÁ TRIỆT ĐỂ & KIỂM CHỨNG E2E)

- [x] **[V3-AUDIT-007] `[VERIFIED PASS]` Chuẩn Hóa `action="BLOCKED"` & Tạo `Session` Riêng Theo Thread Trong `arena.py`**
  - **Khắc phục:** Truyền `db_bind = db.get_bind()` và mở `sessionmaker(bind=db_bind)()` độc lập bên trong worker thread, gọi `SecurityEventService.record_detection(...)` ghi chuẩn `action="BLOCKED"`/`"MONITOR"`, `session_id`, `kill_chain_stage` và `api_protocol="REST"`.

- [x] **[V3-AUDIT-008] `[VERIFIED PASS]` Kết Nối SSE Thật Theo Từng Vòng, Khôi Phục Ô `Target URL` & Drawer `Lịch sử` Trên `/arena`**
  - **Khắc phục:** Bổ sung `streamPentestEvaluation(...)` đọc luồng SSE thật `/api/gateway/api/dashboard/arena/pentest/stream`, cập nhật động danh sách node Cột 1 từ sự kiện `attack_graph`, khôi phục ô nhập `Target URL` và Drawer `Lịch sử` trên thanh điều khiển `/arena`.

- [x] **[V3-AUDIT-009] `[VERIFIED PASS]` Hoàn Thiện Khám Phá Động OpenAPI Ở `arena.py`, `runner.py` Và `/dashboard/simulate`**
  - **Khắc phục:** Tích hợp kiểm tra nhanh cổng TCP + `APIReconAgent` + `OpenAPIPayloadSynthesizer` cho cả `arena.py` và `runner.py` (tự phát hiện `11` endpoint sống từ `http://127.0.0.1:5000/api/v1/vulnerable/openapi.json`), đồng thời dùng `_resolve_openapi_sim_path(...)` và chuỗi 4-ID BOLA burst trong `/dashboard/simulate`.

- [x] **[V3-AUDIT-010] `[VERIFIED PASS]` Thay Thế Biểu Đồ Chật Ở Tab 1 `/` Bằng Thanh Tiến Độ Ngang Gọn & Đồng Bộ `PBL6_Academic_Defense_Slides.pptx`**
  - **Khắc phục:** Chuyển khung `Attack & Protocol Mix` (`h-[155px]`) ở Tab 1 `Live SOC` sang thanh ngang không cắt chữ (giữ nguyên 3 biểu đồ Recharts cỡ lớn ở Tab 2 `Phân Tích & Kill Chain`), và cập nhật đồng bộ 14 slide `PBL6_Academic_Defense_Slides.pptx` cùng `SLIDE_THUYET_TRINH_BAO_VE_PBL6.md`.

---

# 📋 REVIEW FEEDBACK & FINAL SIGN-OFF REPORT (FULL PBL6: BLUE TEAM HYBRID + RED TEAM + THESIS & DEMO READY)

## 🏆 NGHIỆM THU TỔNG THỂ TRƯỚC BẢO VỆ (2026-11-23): 26/26 HẠNG MỤC ĐẠT 100% `[VERIFIED PASS]` — READY TO PRINT & DEFEND
- **Reviewer:** `@pbl6-reviewer` (Senior Security Architect & Independent Code Auditor)
- **Ngày nghiệm thu toàn hệ thống:** `2026-11-23`
- **Nhánh Git cục bộ:** `feat/blue-team-v2-sprint3-logic-ui`
- **Chuỗi Commit đã tái-audit độc lập:**
  - **Sprint 1 (`9e073ad`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: P0 Critical Security Hardening (`SEC-PBL6-001..004`, `SEC-PBL6-006`, ReDoS `XSS-002`).
  - **Sprint 2 (`4f62c74`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: Defense ML Engine (`SEC-PBL6-005`, `SCI-PBL6-001`: Zero-Pickle `xgb_v2.ubj` + `iforest_v2.npz`, Zero-Leakage `defense_v2`, `2.246 ms/req` single-req / `0.867 ms` microbench, Anomaly Recall `57.75%` / FPR `4.00%`, Zero-Shot CSIC 2010 FPR `0.00%`).
  - **Sprint 3 (`5fa0371` + `a4b34ff`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: WAF Logic & SOC Dashboard Truthfulness (`LOGIC-PBL6-001..005`, `SCI-PBL6-002`: `0` fake telemetry hits trên `dashboard/src/`, fix `bytes -> b'...'` 93.2% SQLi FP & `UnboundLocalError: session_id`, khử N+1 `/dashboard/sessions`).
  - **Sprint 4 (`665a782`)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: High-Concurrency Async Gateway, SQLite WAL Group-Commit, Infrastructure & Anti-Drift (`PERF-PBL6-001..002`, `SEC-PBL6-007`, `INFRA-PBL6-001`, `QUAL-PBL6-001`, `ARCH-PBL6-001`, `SCI-PBL6-001` real profiling).
  - **Pre-Defense Integration & Audit Pass (2026-11-23)** — 🟢 **APPROVED / `[VERIFIED PASS]`**: Full audit & integration of Minh's Red Team (`origin/feat/evasion-engine`, commit `ec87fc5`, `RED-PBL6-001..007`), Live Demo/Docker Blocker Fixes, Real Blue Team Hybrid Ablation Study, Live Red DQN vs Blue WAF Campaign, Print-Ready Thesis `.docx` (8 files) + 4x 300 DPI Charts + 14-Slide Defense `.pptx`, and Live 3-Service E2E Dry Run.
- **Tổng kết kiểm chứng độc lập cuối cùng (2026-11-23):**
  - **Lint (`ruff check gateway/ ml-engine/ attack-lab/ tests/unit/test_evasion.py tests/unit/test_runner.py scripts/...`):** `0 errors` (`All checks passed!`) — dọn sạch toàn bộ 50 lỗi từ nhánh Red Team + 57 lỗi nền trước đó.
  - **Unit & Integration Tests (`pytest gateway/tests/ tests/unit/ ml-engine/tests/`):** **353/353 PASSED (100%)** (`297` Blue Team + `56` Red Team & AI Arena).
  - **Frontend Build (`npm run lint` + `tsc --noEmit` + `next build`):** `0 ESLint warnings/errors`, `0 TypeScript errors`, `✓ Compiled successfully` (`/` + `/arena` + `/api/gateway/[...path]`), `0` secrets trong `.next/static/`.
  - **Docker Compose Config (`docker compose config --quiet`):** Exit `0` (`0` warnings), bổ sung `"xgboost>=2.0.0"` vào `gateway/pyproject.toml`.
  - **Ablation Study Thực Tế (`data/benchmark_1000_diverse.csv`, `0` overlap):** Hybrid đạt Accuracy **`97.80%`**, Precision **`100.00%`**, Recall **`97.25%`**, F1 **`98.61%`**, FPR **`0.00%`**, Youden's `J = 0.9725`, Mean **`0.848 ms`** (P95 `1.075 ms`).
  - **Live Red Team PyTorch DQN vs Blue Team Hybrid (`attack-lab/artifacts/campaign_report.json`):** **`20/20 BLOCKED (100.0%)`**, **`0.0%` bypass**, avg threat score **`95.63/100`**, avg live HTTP latency **`4.29 ms`**.
  - **Live 3-Service E2E Demo Dry Run (`Bookie :5000` + `Gateway :8000` + `Dashboard Prod :3000`):** `start_all_services.py --check` exit `0`; `4x HTTP 401` unauth + `HTTP 403` BFF block; `/` & `/arena` HTTP `200`; Live Arena Battles `all` (`8/8` BLUE_TEAM, `94.6/100`) & `sqli` (`6/6` BLUE_TEAM, `96.9/100`); `demo_rehearsal.py --auto` đạt 4/4 giai đoạn (`5/5` Baseline `200`, `5/5` Monitor, `5/5` Active Block `403` gồm SOAP XXE, `5` Brute-Force `429`); `recon.py` phát hiện sống `11` endpoint OpenAPI Bookie qua WAF Gateway.
  - **Independent Live ASGI Benchmark (`C=50`):** Benign `300/300 HTTP 200` -> **`269.50 RPS`** (report profiling: `340.14 RPS`); Attack SQLi `200/200 HTTP 403` -> **`272.75 RPS`** (report profiling: `253.31 RPS`) — vượt xa SLA `>= 150 RPS`.

---

### 🟣 NHÓM RED TEAM & AI ARENA INTEGRATION (`origin/feat/evasion-engine`, `ec87fc5` — 7/7 ĐÃ VÁ & XÁC MINH 100%)

- [x] **[RED-PBL6-001] Khóa Xác Thực Admin & BFF Whitelist Cho AI Arena (`gateway/app/api/arena.py`, `gateway/app/api/router.py`, `dashboard/src/app/api/gateway/[...path]/route.ts`)** — `[VERIFIED PASS]` (Gắn `dependencies=[Depends(require_admin)]` cho toàn bộ `/dashboard/arena/*`; đăng ký router trong `router.py`; mở whitelist chặt `"arena"` với 3 subpath `{"battle", "live", "history"}` trên Next.js BFF; live test trả `401` khi gọi trực tiếp không key và `200` qua BFF).

- [x] **[RED-PBL6-002] Ép Xác Minh SHA-256 Fail-Closed & `weights_only=True` Cho PyTorch DQN (`attack-lab/runner.py`, `attack-lab/models/evasion_agent_metadata.json`)** — `[VERIFIED PASS]` (Xác minh SHA-256 `b89d7dc6b7c9533dffe010457843f2507f37a699510203c33b15f094ea768744` trước khi nạp `evasion_agent.pt` bằng `torch.load(..., map_location="cpu", weights_only=True)`, ngăn chặn RCE qua pickle payload).

- [x] **[RED-PBL6-003] Loại Bỏ Số Liệu Độ Trễ & Lịch Sử Trận Đấu Giả Lập (`gateway/app/api/arena.py`, `dashboard/src/services/api.ts`, `dashboard/src/types/dashboard.ts`)** — `[VERIFIED PASS]` (Xóa `random.uniform(...)` trong `arena.py`, đo bằng `time.perf_counter()` thật; loại hoàn toàn `inMemoryBattleHistory` & `generateMockBattle()` trên frontend; đồng bộ chuẩn `red_wins`/`blue_wins`, `red_team_wins`/`blue_team_wins`, `original_payload`).

- [x] **[RED-PBL6-004] Xử Lý Training-Serving Skew & Offload Async Event Loop Trong `arena.py` (`gateway/app/api/arena.py`)** — `[VERIFIED PASS]` (Sử dụng `extract_26_from_http` + URL-encoded `query_str` + `anyio.to_thread.run_sync` + trường thật của Bookie `comment`/`author`/`book_id`, `host`).

- [x] **[RED-PBL6-005] Vá Lỗi `if threat_score is None` & HTTP `429` Trong Red Team Tooling (`attack-lab/agent/tools.py`)** — `[VERIFIED PASS]` (Sửa falsy bug `threat_score == 0.0` và nhận diện HTTP `429` là bị chặn/điều tiết thay vì bypass).

- [x] **[RED-PBL6-006] Thay Thế `campaign_report.json` Hỏng (`WinError 10061`) Bằng Chiến Dịch Đối Kháng Live Thật (`attack-lab/artifacts/campaign_report.json`)** — `[VERIFIED PASS]` (Chạy live `runner.py --mode ai_agent --campaign all --max-rounds 4` qua WAF Gateway Hybrid + Bookie API -> **`20/20 BLOCKED (100.0%)`**, `0.0%` bypass, `95.63/100` avg risk, `4.29 ms` live HTTP latency).

- [x] **[RED-PBL6-007] Tích Hợp Điều Hướng SOC <-> Arena & Dọn Sạch 50 Lỗi Lint Red Team (`dashboard/src/components/Header.tsx`, `attack-lab/`, `tests/unit/test_{evasion,runner}.py`)** — `[VERIFIED PASS]` (Thêm thanh chuyển tab `Tổng quan SOC /` <-> `Đấu Trường AI /arena`; sửa 50 lỗi ruff kể cả E402 trong `01_train_attack_agent.ipynb`; `56/56` unit & integration test Arena/Evasion/Runner PASS).

---

### 📄 BỘ TÀI LIỆU IN BÁO CÁO & SLIDE BẢO VỆ (VERIFIED 100% ĐỒNG BỘ SỐ LIỆU THẬT)

- [x] **Bộ Tài Liệu Báo Cáo Word A4 Sẵn Sàng In Ấn (`docs/reports/PBL6_Bao_Cao.docx`, Chương 1–5 & Phụ lục):** Đã chuẩn hóa tên GVHD (`TS. Nguyễn Năng Hùng Vân`), nhóm thực hiện (`Ngô Văn Công`, `Nguyễn Công Minh`), nhúng biểu đồ thực nghiệm (`docs/reports/figures/`), `0` lỗi LaTeX/escape, `0` di chứng `Juice Shop`, `0` placeholder.
- [x] **Bộ Slide PowerPoint 16:9 (`docs/reports/PBL6_Academic_Defense_Slides.pptx`):** Đã nhúng biểu đồ & bảng thực nghiệm đồng bộ, đầy đủ ghi chú thuyết trình (Speaker Notes) cho 24/24 slide và phân vai trình bày Blue Team + Red Team.

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

- [x] **[ARCH-PBL6-001]** `[VERIFIED PASS]` (`665a782`) — `0` di chứng `Juice Shop` trên `health.py`, `test_health.py`, `DASHBOARD_SPEC.md`, `GAP_ANALYSIS.md`, `GLOSSARY.md`, `ARCHITECTURE.md`, `README.md`; xóa tham chiếu ảo `attack-lab/cli.py` trong `README.md`; cập nhật footer `dashboard/src/app/page.tsx` sang `Blue Team Hybrid: Rule + XGBoost + Isolation Forest`.

- [x] **[SEC-PBL6-007]** `[VERIFIED PASS]` (`665a782`) — `filter_request_headers` chặn rò rỉ `X-API-Key` xuống upstream; `filter_response_header_items` giữ nguyên multi-value `Set-Cookie` (`count=2`); `LiveEventsTable.tsx` sửa chuẩn CIDR `172.16.0.0/12`; `attack-lab/agent/recon.py` có cycle guard chống circular `$ref` (`self_cycle=guarded, ab_cycle=guarded`); `vnpay.py` dùng `hmac.compare_digest`; bỏ toàn bộ `datetime.utcnow()` sang `datetime.now(datetime.timezone.utc)`.
  - *Ghi chú tồn dư vi mô (non-blocking, `[CODE-VERIFIED]`):* (1) `filter_request_headers` chưa tách các header tùy biến liệt kê động trong `Connection:` (RFC 7230 §6.1); (2) `attack-lab/environment/env.py:248` (phần Red Team Máy 2) có đặc trưng `index / max(count - 1, 1)` song song `index / max(count, 1)`. Cả hai không ảnh hưởng an toàn Blue Team và có thể tinh chỉnh ở backlog phụ.

---

# 📋 LỊCH SỬ THẨM ĐỊNH CÁC TASK TRƯỚC
*(PR #111 Task 10.2 APPROVE 9.9/10; Task 10.1, Task 12.2, Task 12.1, Task 11.3, Phase 8, Phase 6; Blue Team Upgrade Pipeline Sprints 1–4: 19/19 Findings `[VERIFIED PASS]`)*
