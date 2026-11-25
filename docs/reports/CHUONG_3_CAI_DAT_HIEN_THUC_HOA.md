# CHƯƠNG 3: CÀI ĐẶT VÀ HIỆN THỰC HÓA HỆ THỐNG

---

## 3.1. Môi Trường Phát Triển và Ngăn Xếp Công Nghệ Thực Tế

*Bảng 3.1: Ngăn xếp công nghệ triển khai thực tế của PBL6 (Blue Team v2.0–v3.3 + Red Team)*

| Phân Hệ | Công Nghệ / Thư Viện Cốt Lõi | Phiên Bản | Vai Trò Kỹ Thuật Thực Tế |
| :--- | :--- | :---: | :--- |
| **WAF Gateway (Blue Team)** | Python, FastAPI, Uvicorn, AnyIO, HTTPX | 3.12 / 0.110+ | Reverse Proxy bất đồng bộ chịu tải cao (`>= 250 RPS @ C=50`), pure ASGI middleware, threadpool offload. |
| **AI/ML Defense (v2.0–v3.3)** | XGBoost (UBJSON), NumPy (NPZ), Scikit-learn | 2.x / 1.26+ | Suy luận Zero-Pickle (`xgb_v2.ubj`, `iforest_v2.npz`, `allow_pickle=False`) + Per-Parameter Max-Pooling + xác thực SHA-256 Fail-Closed. |
| **Target API (`vulnerable-api`)** | Python Django, SQLite3 | 6.0+ | Ứng dụng Bookie Bookstore với 8 lỗ hổng OWASP, OpenAPI 3.0, HMAC `compare_digest` (cô lập `127.0.0.1:5000`). |
| **Red Team (`attack-lab`)** | PyTorch, HTTPX, Rich | 2.x / 0.27+ | OpenAPI Recon (cycle guard), AttackGraph MDP (`40-D/14-A` -> `74-D/36-A`), Dueling Double-DQN `pentest_dqn_v2.pt` (`weights_only=True`) & `evasion_agent.pt`, CLI Runner. |
| **SOC Dashboard & AI Arena** | Next.js 14 (App Router), TypeScript, Tailwind CSS, Recharts, Lucide | 14.2.35 / Node 20 | Trung tâm SOC 100% dữ liệu thật + Đấu Trường AI `/arena`, xác thực qua Server-Side BFF Proxy `/api/gateway/*`. |
| **CSDL & Kiểm Toán** | SQLAlchemy 2.0, SQLite WAL (`QueuePool`) | 2.0.28+ | Lưu trữ `requests`, `security_events` (indexed `api_protocol`/`session_id`), `audit_logs`, `waf_config` với Group Commit. |
| **DevOps & CI/CD** | Docker Compose, Non-root Dockerfiles, GitHub Actions, Ruff, Pytest | Compose v5 / Ruff | 3 container non-root (`appuser`/`nextjs`), 3 `.dockerignore`, CI tự động kiểm tra lint + 350+ test + Next.js build. |

---

## 3.2. Cài Đặt Phân Hệ Cổng WAF Gateway v2.0 (`gateway/`)

### 3.2.1. Kiến trúc Reverse Proxy Bất Đồng Bộ & Group Commit WAL (`gateway/app/api/proxy.py`)
1. **Kiểm soát kích thước Request & Chống Chunked DoS (`SEC-PBL6-002`):** Đọc body theo luồng `async for chunk in request.stream()` với bộ đếm lũy tiến chặn vượt quá `1 MB` bằng `HTTP 413 Payload Too Large` chuẩn RFC 7231.
2. **RAM TTL Cache `waf_mode` (`PERF-PBL6-001`):** Hàm `_resolve_active_waf_mode()` đọc chế độ hoạt động từ cache RAM (TTL 5s) và tự động xóa cache qua SQLAlchemy listener `@event.listens_for(WafConfigModel, ...)` mỗi khi quản trị viên đổi chế độ.
3. **Offload kiểm tra CPU-bound:** Toàn bộ chuỗi `_run_security_inspection()` được đẩy sang worker thread qua `await anyio.to_thread.run_sync(...)` để không chặn vòng lặp sự kiện asyncio.
4. **Leader-Follower Group Commit (`_persist_background_logs`):** Sau khi trả phản hồi HTTP cho client, FastAPI `BackgroundTasks` gom nhiều bản ghi `SecurityEvent` và `RequestLog` vào một transaction SQLite WAL duy nhất, triệt tiêu xung đột khóa ghi ở tải cao `C = 50`.
5. **Thanh lọc Header & Quản lý kết nối (`gateway/app/services/proxy.py`):** `filter_request_headers()` gỡ bỏ toàn bộ hop-by-hop headers và tiêu đề nhạy cảm `X-API-Key` trước khi chuyển tiếp; `filter_response_header_items()` dùng `upstream_headers.multi_items()` giữ nguyên nhiều header `Set-Cookie`; client tạm luôn đóng trong khối `finally`.

### 3.2.2. Multi-Protocol Sniffer, InputNormalizer & Hardened Rule Engine
- **`gateway/app/security/protocol_detector.py`:** Phân loại 5 giao thức (`REST`, `GRAPHQL`, `SOAP_XML`, `JSON_RPC`, `GENERIC_WEB`), sửa triệt để false positive trên REST có khóa `"query"` và XML sạch chứa từ tiếng Anh `"system"`/`"public"` bằng biểu thức cấu trúc XXE chặt (`<!(?:DOCTYPE|ENTITY)\b[^>]*\b(?:SYSTEM|PUBLIC)\b|<!ENTITY\b`) trên cả body và query string; bóc tách văn bản lá SOAP/XML (`extracted_text`) truyền vào ML nhằm tránh nhầm thẻ `<soap:Envelope>` thành XSS.
- **`gateway/app/security/normalizer.py` & `engine.py`:** Chuẩn hóa đệ quy URL -> HTML Entity -> Unicode NFKC -> loại Zero-Width Unicode -> gom comment `/*...*/` đa dòng -> quét cửa sổ trượt (Sliding Window > 16 KB) & duyệt JSON đệ quy (`max_depth=32`) bằng **`json.loads(..., object_pairs_hook=list)`** để bảo toàn khóa trùng lặp chống `json_duplicate_key_tamper`, kết hợp `parse_qs` giải mã tham số form `application/x-www-form-urlencoded` (xử lý `+` và `%XX` theo từng trường). Bộ luật mở rộng lên **28 Hardened Signatures** (thêm các lá chắn API, `SQLI-006`, `SQLI-007` scientific-float/CHAR/subquery và `CMD-006` wildcard-globbing/SSI). Khi `RuleEngine` gặp ngoại lệ đột xuất, Gateway xử lý **Fail-Closed (`HTTP 403`)** thay vì Fail-Open (`SEC-PBL6-003`).
- **`gateway/app/security/rules/xss.py`:** Viết lại `XSS-002` sang dạng tuyến tính không quay lui bậc hai (`[^<>]*` + `\bon[a-z]{3,20}\s*=`), giảm độ trễ worst-case trên payload 50 KB từ **923.37 ms** xuống **0.891 ms** (nhanh hơn **1,036 lần**).

### 3.2.3. Bộ Trích Xuất 26 Đặc Trưng Thống Nhất & Suy Luận Zero-Pickle (`ml-engine/` + `gateway/app/security/`)
- **`ml-engine/features/extractor.py`:** Hàm `extract_26_from_http(path, query_params, body)` chuẩn hóa UTF-8 (decode sạch `bytes`, tránh lỗi chuỗi `b'...'` gây false positive SQLi), dùng chung duy nhất cho huấn luyện (`train_defense_v2.py`), benchmark (`evaluate_csic2010.py`, `run_ablation_study.py`) và runtime Gateway (`proxy.py`, `arena.py`).
- **`gateway/app/security/ml_detector.py`:** Xác thực mã băm SHA-256 Fail-Closed đối chiếu `xgb_v2_metadata.json` (`a166334e22e4...`) rồi nạp `ml-engine/artifacts/xgb_v2.ubj` (UBJSON Zero-Pickle) với bộ đệm thread-local tối ưu cho đa luồng; đồng thời cung cấp `predict_http()` kết hợp `normalize_http_for_ml` (đổi `+` -> khoảng trắng trên query/form) và **Per-Parameter Max-Pooling** (duyệt tối đa 2 tham số đáng ngờ nhất bằng `object_pairs_hook=list`, lấy điểm rủi ro lớn nhất giữa toàn cục và tham số cục bộ).
- **`gateway/app/security/anomaly.py`:** Xác thực mã băm SHA-256 Fail-Closed đối chiếu `iforest_v2_metadata.json` (`12e15cd99927...`) rồi nạp `ml-engine/artifacts/iforest_v2.npz` bằng `np.load(..., allow_pickle=False)` và tính độ sâu cây cô lập trực tiếp bằng NumPy thuần, hiệu chuẩn điểm `0–100` theo phân vị thực nghiệm kèm bảo vệ đường dẫn gốc trần `'/'`.

### 3.2.4. Risk Engine, Decision Engine, Rate Limiter & Attack Session Correlation
- **`risk_engine.py` & `decision.py`:** Tổng hợp trọng số `0.40 * Rule + 0.35 * ML + 0.25 * Anomaly` với High-Confidence Override (`Rule >= 85` hoặc `ML >= 90` -> `BLOCK`) và **Dual-AI Consensus (`ML >= 70 & Anomaly >= 70` -> `BLOCK`)**, nối trực tiếp mọi tham số ngưỡng từ `Settings` (`.env`, bật `schema_validation_enabled=True` với chính sách `schema_enforcement_policy="route_tiered"`) và thực thi đầy đủ cả tầng `RATE_LIMIT` (Risk `60–79` -> HTTP 429).
- **`rate_limiter.py`:** Cửa sổ trượt `SlidingWindowRateLimiter` dùng `OrderedDict` giới hạn tối đa `50,000` khóa (LRU eviction) kết hợp **IP Hard Cap** trên mọi endpoint nhạy cảm (`/auth/login/` tối đa 10 req/phút/IP bất chấp xoay token/UA).
- **`services/security.py`:** Tính `session_id = HMAC-SHA256(client_ip || floor(utc_ts / 900))` chuẩn hóa UTC tuyệt đối và ánh xạ `kill_chain_stage` (`RECONNAISSANCE`, `EXPLOITATION`, `EVASION`, `PRIVILEGE_ABUSE`, `EXFILTRATION`) cho cả sự kiện detection lẫn rate-limit; truy vấn `/dashboard/sessions` gom theo lô khử hoàn toàn lỗi N+1 SQL.

---

## 3.3. Cài Đặt Ứng Dụng Mục Tiêu Bookie Bookstore (`vulnerable-api/`)

Ứng dụng được cài đặt bằng **Python Django** tại `vulnerable-api/books/api_vulnerable.py` và `vulnerable-api/books/vnpay.py`:
- Triển khai đủ 8 nhóm lỗ hổng OWASP Web & API Top 10 với schema đồng bộ hoàn toàn với Gateway và Red Team: `POST /auth/login/` (`username`, `password`), `GET /books/search/?q=`, `POST /reviews/` (`book_id`, `author`, `comment`), `GET /files/download/?file=`, `POST /admin/ping/` (`host`), `GET /orders/{order_id}/`, `POST /books/fetch-cover/`, `PUT /users/profile/update/`.
- Cổng xác thực chữ ký thanh toán `books/vnpay.py` sử dụng so sánh thời gian hằng `hmac.compare_digest()` chống tấn công kênh kề thời gian (Timing Attack).
- Trong `docker-compose.yml`, container `pbl6-vulnerable-api` chạy dưới quyền non-root `USER appuser` và chỉ ánh xạ `127.0.0.1:5000:5000` để chặn truy cập trực tiếp từ mạng LAN.

---

## 3.4. Cài Đặt Hệ Thống Tác Tử Red Team & AI Arena (`attack-lab/` + `arena.py`)

Do Thành viên B (**Nguyễn Minh**) phát triển và đã được kiểm toán, gia cố đồng bộ với Blue Team v2.0:
1. **`attack-lab/agent/recon.py` (Task 10.1):** `APIReconAgent` tự động dò OpenAPI spec trên Gateway, bảo vệ chống vòng lặp `$ref` bằng tập `seen_refs`, sinh danh sách `EndpointProfile` và chỉ báo lỗ hổng tiềm năng.
2. **`attack-lab/environment/` (Task 10.2):** `AttackGraph` (`attack_graph.py`), 14 hành động rời rạc (`actions.py`) và máy trạng thái `AttackEnvironment` (`env.py`) sinh vector quan sát 40 chiều phục vụ huấn luyện và suy luận DQN.
3. **`attack-lab/agent/evasion.py` & `tools.py` (Task 10.3):** Bộ `TAMPER_CATALOG` gồm 14 hàm biến dị bảo toàn ngữ nghĩa cho SQLi, XSS, Path Traversal, CMD Injection; `HttpDispatcher` thu thập telemetry chuẩn thang `0–100` (nhận diện cả `403` lẫn `429`, sửa chính xác `threat_score is None`).
4. **`attack-lab/runner.py`, `models/pentest_dqn_v2.pt` & `models/evasion_agent.pt` (Task 10.4 & Phase E):** Lớp `DQNEvasionAdvisor` / `PentestDQNAdvisor` xác thực **SHA-256 Fail-Closed** đối chiếu metadata (`fc414d6a8068...` cho Dueling Double-DQN `74-D/36-A` huấn luyện 800 episodes 4-stage Live-HTTP; `b89d7dc6b7c9...` cho `evasion_agent.pt` 40-D/14-A gốc) và nạp trọng số an toàn bằng **`torch.load(..., map_location="cpu", weights_only=True)`** (triệt tiêu CWE-502, kèm bản `.npz` cho CI), điều phối 3 chế độ `replay`, `live`, `ai_agent` và xuất báo cáo `campaign_report.json`.
5. **`gateway/app/api/arena.py`:** Cung cấp 3 API `/dashboard/arena/battle`, `/live`, `/history` được bảo vệ bởi `require_admin`, thực thi trên threadpool (`anyio.to_thread.run_sync`), sử dụng đúng pipeline `extract_26_from_http` + `XGBoost v2.0` + `IForest v2.0`, đo độ trễ thực bằng `perf_counter` (loại bỏ 100% hằng số random giả).

---

## 3.5. Cài Đặt SOC Command Center & Bảo Mật Frontend BFF (`dashboard/`)

1. **Server-Side BFF Proxy (`dashboard/src/app/api/gateway/[...path]/route.ts`):** Mọi yêu cầu từ trình duyệt đi vào `/api/gateway/api/dashboard/*` (bao gồm cả `/arena/battle`, `/arena/live`, `/arena/history`). Server Next.js tự chèn header `X-API-Key` từ biến môi trường `ADMIN_API_KEY`, áp dụng kiểm tra regex từng phân đoạn đường dẫn, whitelist chặt danh sách endpoint và xác minh origin chống SSRF. Kết quả kiểm định: **`0` chuỗi bí mật tồn tại trong `.next/static/`**, và mọi truy cập trực tiếp không có key tới Gateway đều bị từ chối `HTTP 401`.
2. **100% Số Liệu Thật Trên Toàn Giao Diện (`SCI-PBL6-002`):**
   - `MetricCards.tsx`: Hiển thị KPI thật và `current_rps` tính trên cửa sổ 60 giây gần nhất từ bảng `requests`.
   - `NetworkTopologyMap.tsx`: Hiển thị trạng thái, độ trễ ping thật tới Bookie và chế độ `waf_mode` thật từ `/dashboard/topology`.
   - `ProtocolDistributionChart`: Đọc từ `/dashboard/protocols` dùng SQL `GROUP BY` trên cột index `SecurityEvent.api_protocol` (trả `0%` trung thực khi chưa có sự kiện).
   - `PayloadEvidenceDrawer.tsx` & `DetectionExplainabilityModal.tsx`: Hiển thị đầy đủ **26 đặc trưng thật**, chi tiết luật khớp `details.matches`, điểm `Rule / XGBoost v2.0 / IForest v2.0` thật.
   - `AttackSessionsModal.tsx`: Hiển thị chuỗi phiên tấn công 5 bước Cyber Kill Chain (đóng được bằng `Escape` và click backdrop).
   - `dashboard/src/app/arena/page.tsx`: Giao diện **Đấu Trường AI (Red vs Blue Arena)** nối trực tiếp BFF thật (đã gỡ bỏ 100% `inMemoryBattleHistory` và `generateMockBattle()` giả lập), chuyển đổi mượt mà với trang SOC chính qua thanh điều hướng trên `Header.tsx`.

---

## 3.6. Đóng Gói Docker Hardening & CI/CD Tự Động

- **Docker Hardening (`INFRA-PBL6-001`):** Tạo 3 file `.dockerignore` riêng (`gateway/`, `dashboard/`, `vulnerable-api/`); chạy toàn bộ 3 container dưới quyền **non-root** (`USER appuser` / `USER nextjs`); đồng bộ `dashboard/Dockerfile` lên `node:20-alpine` + `npm ci`; khai báo `xgboost>=2.0.0` trong `gateway/pyproject.toml`; đặt mặc định an toàn `WAF_MODE=${WAF_MODE:-ACTIVE_BLOCKING}` trong `docker-compose.yml`.
- **CI Pipeline (`.github/workflows/ci.yml`):** Tự động chạy `ruff check gateway/ ml-engine/ attack-lab/`, chạy trọn bộ `pytest` trên `gateway/tests/`, `tests/unit/`, `ml-engine/tests/`, và kiểm tra `npm run lint`, `tsc --noEmit`, `next build` trên `dashboard/`.
