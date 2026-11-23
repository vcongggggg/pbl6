# CHƯƠNG 2: PHÂN TÍCH YÊU CẦU VÀ THIẾT KẾ KIẾN TRÚC HỆ THỐNG

---

## 2.1. Phân Tích Yêu Cầu Hệ Thống (System Requirements Analysis)

### 2.1.1. Bối cảnh bài toán và phạm vi đề tài
Các hệ thống Web API hiện đại trao đổi dữ liệu có cấu trúc đa dạng (REST/JSON, GraphQL, SOAP/XML, JSON-RPC 2.0) trực tiếp giữa client và microservices. Các tường lửa tĩnh truyền thống bộc lộ rõ giới hạn trước kỹ thuật làm mờ payload, lỗ hổng đa giao thức và tấn công tự động hóa bằng AI **[Ref 06, Ref 13]**.

Đề tài xây dựng **Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng Đối kháng Phân tán (Distributed Cyber Range)** gồm 3 phân hệ đồng bộ:
1. **Ứng dụng Mục tiêu (`vulnerable-api` — Bookie Bookstore):** Hệ thống Web API thương mại điện tử tự phát triển bằng **Python Django** (lắng nghe cô lập trên `127.0.0.1:5000`), tích hợp 8 nhóm lỗ hổng kinh điển chuẩn OWASP Web & API Top 10 kèm đặc tả OpenAPI 3.0.
2. **Hệ thống Phòng thủ Chủ động Blue Team v2.0 (`gateway` + `ml-engine` + `dashboard`):** Cổng WAF Reverse Proxy bất đồng bộ chịu tải cao (FastAPI, Port 8000), tích hợp Multi-Protocol Sniffer, Positive Security OpenAPI Schema Validator, 16 Hardened Signatures, bộ trích xuất thống nhất 26 đặc trưng, **Champion XGBoost v2.0 (UBJSON)** + **Calibrated Isolation Forest v2.0 (NPZ)**, Sliding Window Rate Limiter chống bypass (LRU 50,000 + IP Hard Cap), bảng kiểm toán `AuditLog`, cùng Trung tâm Chỉ huy SOC & Đấu Trường AI (`dashboard`, Next.js 14, Port 3000) bảo vệ qua Server-Side BFF Proxy.
3. **Tác tử Tấn công Tự hành Red Team (`attack-lab`):** Vận hành độc lập trên Máy 2 qua mạng LAN, gồm bộ trinh sát OpenAPI (`recon.py` có bảo vệ chống vòng lặp `$ref`), mô hình hóa Đồ thị Tấn công (`environment/`), động cơ biến dị bảo toàn ngữ nghĩa (`evasion.py`), mô hình PyTorch DQN (`evasion_agent.pt`) và bộ điều phối chiến dịch (`runner.py`).

### 2.1.2. Yêu cầu chức năng (Functional Requirements — FR)

*Bảng 2.1: Tổng hợp 8 nhóm yêu cầu chức năng cốt lõi của hệ thống*

| Mã YC | Tên Yêu Cầu Chức Năng | Mô Tả Chi Tiết Kỹ Thuật | Phân Hệ |
| :--- | :--- | :--- | :--- |
| **FR-01** | **Chặn bắt Reverse Proxy & Kiểm soát Body** | Chặn bắt toàn bộ HTTP/1.1 tới `/api/proxy/*`, gán `X-Request-ID`, giới hạn kích thước body `<= 1 MB` (kể cả chunked transfer -> HTTP 413), thanh lọc `X-API-Key` trước khi chuyển tiếp, bảo toàn đa giá trị `Set-Cookie`. | `gateway` (Proxy) |
| **FR-02** | **Nhận diện Đa giao thức & Bóc tách** | Phân loại chính xác `REST`, `GRAPHQL`, `SOAP_XML`, `JSON_RPC`, `GENERIC_WEB`; bóc tách `<![CDATA[...]]>` / lá văn bản XML, phát hiện XXE trên cả query/body và GraphQL Deep Nesting DoS. | `gateway` (`protocol_detector`) |
| **FR-03** | **Positive Security OpenAPI Validator** | Kiểm chứng HTTP method, kiểu path param, query param, `Content-Type`, JSON body và chặn `additionalProperties` (Mass Assignment); tôn trọng `WAF_MODE` và ghi `SecurityEvent`. | `gateway` (`schema_validator`) |
| **FR-04** | **Phát hiện Đa tầng (Rule + ML + Anomaly)** | Tầng 1: `InputNormalizer` (đệ quy URL, HTML, Unicode NFC, khử Zero-Width & comment đa dòng) + 16 luật OWASP an toàn ReDoS với Sliding Window > 16 KB. Tầng 2: `XGBoost v2.0` (26-D UBJSON). Tầng 3: `Calibrated IForest v2.0` (26-D NPZ). | `gateway` + `ml-engine` |
| **FR-05** | **Đánh giá Rủi ro, Chính sách & Rate Limit** | Hợp nhất điểm `0–100` (`0.40*Rule + 0.35*ML + 0.25*Anomaly` + High-Confidence Override); thực thi `ALLOW` (<30), `MONITOR` (30–59), `RATE_LIMIT` (60–79 -> HTTP 429), `BLOCK` (>=80 -> HTTP 403 RFC 7807); Sliding Window LRU 50,000 + IP Hard Cap chống xoay token/UA. | `gateway` (Risk / Rate Limit) |
| **FR-06** | **Ứng dụng Mục tiêu Bookie Bookstore** | 8 kịch bản lỗ hổng OWASP Web/API trên Django (`127.0.0.1:5000`), kiểm chứng HMAC VNPay bằng `hmac.compare_digest`, xuất bản đặc tả OpenAPI 3.0 tại `/api/v1/vulnerable/openapi.json`. | `vulnerable-api` |
| **FR-07** | **Tác tử Red Team Tự hành & DQN Evasion** | Trinh sát OpenAPI (có cycle guard `$ref`), lập Đồ thị Tấn công MDP (40-D state, 14 actions), điều phối chiến dịch đối kháng bằng PyTorch DQN (`evasion_agent.pt`, `weights_only=True` + SHA-256) và 14 toán tử biến dị ngữ nghĩa. | `attack-lab` |
| **FR-08** | **SOC Command Center & AI Arena UI** | Next.js 14 giao tiếp 100% qua Server-Side BFF Proxy (`/api/gateway/*`, `0` secret trên trình duyệt): KPI thật, Real-Time 60s RPS, Topology phân tán, Protocol Distribution, Attack Sessions Kill Chain, Evidence Drawer 26-D, XAI Modal và màn hình Đấu Trường AI (`/arena`). | `dashboard` |

### 2.1.3. Yêu cầu phi chức năng (Non-Functional Requirements — NFR)

*Bảng 2.2: Chỉ tiêu phi chức năng và cam kết chất lượng dịch vụ (SLA)*

| Mã NFR | Tiêu Chí | Chỉ Số Mục Tiêu (SLA) | Cơ Chế Đảm Bảo Kiến Trúc |
| :--- | :--- | :--- | :--- |
| **NFR-01** | **Độ trễ xử lý nội bộ (Inline Latency)** | Pipeline AI (`26-D + XGBoost + IForest`) `<= 2.5 ms/req`; Toàn bộ kiểm tra WAF `<= 5.0 ms/req`; Chống ReDoS `< 20 ms` trên chuỗi 50 KB. | Zero-Pickle `xgb_v2.ubj` + `iforest_v2.npz`, single-pass 26-D extraction, regex không quay lui bậc hai. |
| **NFR-02** | **Thông lượng đồng thời (Throughput)** | `>= 150 RPS` tại mức tải đồng thời `C = 50` không rơi gói, không khóa nghẽn Event Loop. | `anyio.to_thread.run_sync`, pure ASGI middleware, RAM TTL cache `waf_mode`, SQLite WAL Leader-Follower Group Commit (`busy_timeout=5000`). |
| **NFR-03** | **Hiệu năng An ninh & Liêm chính Khoa học** | Detection Recall `>= 95%`, Benign FPR `<= 1.0%`, Youden's Index `J >= 0.90`, `0` Data Leakage, `0` telemetry giả lập. | Zero-Leakage `defense_v2` split, Zero Training-Serving Skew, 100% số liệu thật từ SQLite/Backend. |
| **NFR-04** | **An toàn Chuỗi Cung Ứng & Phòng vệ Fail-Closed** | `0` Pickle trong runtime defense; xác thực SHA-256 Fail-Closed trước nạp model; lỗi RuleEngine xử lý Fail-Closed (`HTTP 403`); khóa mọi `/dashboard/*` bằng `X-API-Key`. | UBJSON + NPZ (`allow_pickle=False`), `torch.load(..., weights_only=True)`, `require_admin` + Next.js BFF Proxy. |
| **NFR-05** | **Đóng gói Container & Chất lượng Mã** | Non-root containers, `.dockerignore` riêng từng service, default `ACTIVE_BLOCKING`, `0` lỗi linter (`ruff`, ESLint, `tsc`), `100%` test suites PASS. | Hardened Dockerfiles (`appuser`/`nextjs`), GitHub Actions CI chạy đủ 3 repo Python + Frontend. |

---

## 2.2. Thiết Kế Kiến Trúc Tổng Thể Thao Trường Đối Kháng Phân Tán

Hệ thống tách biệt rõ vai trò giữa **Máy 1 (Blue Team — Phòng thủ)** và **Máy 2 (Red Team — Tấn công)** qua mạng LAN vật lý theo mô hình Cyber Range của Yamin et al. **[Ref 16]**:

```text
+---------------------------------------------------------------------------------+
|                MÁY 2: RED TEAM HOST (ATTACKER — Nguyễn Minh)                    |
|  [OpenAPI Recon (cycle guard)] -> [Attack Graph MDP (40-D, 14 actions)]         |
|  -> [PyTorch DQN Agent (evasion_agent.pt, SHA-256 + weights_only=True)]         |
|  -> [Semantic Tamper EvasionEngine & CLI Runner (attack-lab/runner.py)]         |
+----------------------------------------+----------------------------------------+
                                         | HTTP/1.1 qua mạng LAN (192.168.1.0/24)
                                         v
+---------------------------------------------------------------------------------+
|                MÁY 1: BLUE TEAM HOST (DEFENDER — Nguyễn Văn Công)               |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  | WAF GATEWAY v2.0 (FastAPI Async, 0.0.0.0:8000, Pure ASGI + Thread Offload)|  |
|  |  1. Request ID + Body Limit (<= 1MB, HTTP 413) + RAM TTL Cache (waf_mode) |  |
|  |  2. Sliding Window Rate Limiter (LRU 50,000 + IP Hard Cap -> HTTP 429)    |  |
|  |  3. Multi-Protocol Sniffer (REST/GraphQL/SOAP-XML/JSON-RPC) & Decapsul.   |  |
|  |  4. InputNormalizer + 16 Hardened Rules (Sliding Window > 16KB, No ReDoS) |  |
|  |  5. OpenAPI 3.0 Positive Security Schema Validator                        |  |
|  |  6. Unified 26-D Feature Extractor -> XGBoost v2.0 (UBJ) + IForest v2(NPZ)|  |
|  |  7. Hybrid Risk (0.40/0.35/0.25 + Override) -> ALLOW/MONITOR/429/BLOCK 403|  |
|  +-----------------+-------------------------------+-------------------------+  |
|                    | ALLOW (X-API-Key stripped)    | BackgroundTasks GroupCommit|
|                    v                               v                            |
|  +-------------------------------+   +---------------------------------------+  |
|  | BOOKIE BOOKSTORE TARGET API   |   | SQLite WAL (busy_timeout=5000, Queue) |  |
|  | Django (127.0.0.1:5000)       |   | requests | security_events (indexed)  |  |
|  | 8 OWASP Flaws + OpenAPI 3.0   |   | audit_logs | waf_config               |  |
|  +-------------------------------+   +-------------------+-------------------+  |
|                                                          ^                      |
|                                                          | X-API-Key (Server)   |
|  +-------------------------------------------------------+-------------------+  |
|  | SOC COMMAND CENTER & AI ARENA (Next.js 14, Port 3000)                     |  |
|  | Server-Side BFF Proxy (/api/gateway/*) — 0 Secrets in Browser Bundle      |  |
|  | [/] SOC Overview (KPI, RPS, Topology, Protocols, Kill Chain, 26-D XAI)    |  |
|  | [/arena] Live Red vs Blue Adversarial Combat Arena                        |  |
|  +---------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------+
```

*Bảng 2.3: Phân công trách nhiệm triển khai giữa 2 thành viên trên Thao trường 2 Máy*

| Hạng Mục | Máy 1 — Blue Team (`vcongggggg` / Nguyễn Văn Công) | Máy 2 — Red Team (`naocavang08` / Nguyễn Minh) |
| :--- | :--- | :--- |
| **Vai trò chính** | Tech Lead / Blue Team Defender & ML/Platform Hardening | Red Team Lead / Offensive AI Agent & Arena UI |
| **Phân hệ đảm nhiệm** | `gateway/` (WAF Async, Rule, Protocol, Schema, Risk, Rate Limiter, WAL DB), `ml-engine/` (Dataset v2, 26-D, XGBoost v2, IForest v2), `vulnerable-api/` (Bookie Django), `dashboard/` (SOC Command Center & BFF), Docker/CI | `attack-lab/` (Task 10.1 Recon, Task 10.2 AttackGraph MDP, Task 10.3 Semantic Tamper & PyTorch DQN `evasion_agent.pt`, Task 10.4 CLI Runner), `gateway/app/api/arena.py`, `dashboard/src/app/arena/page.tsx` |
| **Kiểm soát an toàn** | Cổng 5000 cô lập loopback; cổng 8000 bảo vệ bằng `ACTIVE_BLOCKING` & `X-API-Key`; BFF chống lộ secret | Toàn bộ chiến dịch tấn công bị giới hạn chặt vào đường dẫn `/api/proxy/api/v1/vulnerable/*` trong môi trường Lab |

---

## 2.3. Thiết Kế Chi Tiết Đường Ống WAF Gateway v2.0

### 2.3.1. Kiến trúc bất đồng bộ chịu tải cao (High-Concurrency Async Pipeline)
Nhằm loại bỏ hoàn toàn hiện tượng nghẽn Asyncio Event Loop, `gateway` được thiết kế theo 4 nguyên lý tối ưu đồng thời:
1. **Pure ASGI Middleware (`RequestContextMiddleware`):** Gắn `X-Request-ID` và xử lý streaming body trực tiếp ở tầng ASGI thay vì `BaseHTTPMiddleware` (tránh tạo tác vụ phụ và copy buffer thừa).
2. **RAM TTL Cache cho cấu hình `waf_mode` (TTL 5s):** Tự động vô hiệu hóa (auto-invalidate) qua SQLAlchemy event listener khi `WafConfigModel` thay đổi hoặc khi gọi `/dashboard/toggle-waf-mode` & `/dashboard/reset-demo` — triệt tiêu `SELECT` đồng bộ lặp lại trên mọi request.
3. **Offload tác vụ CPU-bound (`anyio.to_thread.run_sync`):** Toàn bộ chuỗi kiểm tra (Protocol Sniffer, InputNormalizer, RuleEngine, SchemaValidator, 26-D Extraction, XGBoost v2.0, IForest v2.0) chạy trên worker thread pool độc lập, giữ Event Loop rảnh để phục vụ hàng trăm kết nối HTTP đồng thời.
4. **SQLite WAL Leader-Follower Group Commit qua `BackgroundTasks`:** Ghi `RequestLog` và `SecurityEvent` theo lô (batch commit) ngoài đường dẫn phản hồi HTTP, kết hợp `QueuePool(pool_size=8, max_overflow=16)`, `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL` và `PRAGMA busy_timeout=5000`.

### 2.3.2. Bộ Chuẩn hóa Đầu vào & 16 Luật Chữ ký Gia cố (Anti-Evasion & Anti-ReDoS)
- **`InputNormalizer`:** Giải mã URL đệ quy (tối đa 5 vòng), giải mã HTML entities, chuẩn hóa Unicode NFC, gỡ bỏ ký tự vô hình Zero-Width (`[\u200b-\u200f\ufeff]`), chuẩn hóa chú thích nội tuyến đa dòng `/*...*/` (`re.DOTALL`) thành khoảng trắng.
- **Chống tràn bộ đệm & ReDoS:** Áp dụng cơ chế **Sliding Window** quét toàn phần chuỗi > 16 KB (không cắt cụt phần đuôi), duyệt sâu JSON đến độ sâu giới hạn an toàn, xử lý byte không phải UTF-8 bằng chế độ fail-closed an toàn, và viết lại mẫu `XSS-002` dùng `[^<>]*` với nhóm `on[a-z]{3,20}\s*=` (triệt tiêu quay lui `O(n^2)` từ 923 ms xuống < 1 ms).
- **Mở rộng bề mặt kiểm tra:** Quét đầy đủ path, query, body, các payload bóc tách từ SOAP CDATA/GraphQL/JSON-RPC và tiêu đề nhạy cảm bao gồm `Cookie`, `User-Agent`, `Referer`.

### 2.3.3. Đặc tả Không gian 26 Đặc trưng Thống nhất (Unified 26-D Feature Vector)
Mọi mô hình AI trong Blue Team v2.0 (`xgb_v2.ubj` và `iforest_v2.npz`) cùng tab **Payload Evidence Drawer** trên SOC Dashboard đều sử dụng duy nhất một danh sách **26 đặc trưng chuẩn tắc** định nghĩa trong `ml-engine/features/extractor.py` (xem bảng đặc tả chi tiết toàn bộ 26 trường tại **Phụ lục C**):
- 12 đặc trưng hình thái & entropy (`length`, `entropy`, đếm ký tự `'`, `"`, `<`, `>`, `;`, `-`, `/`, `\`, `()`, `special_char_ratio`).
- 7 đặc trưng từ khóa & mẫu cú pháp 4 họ tấn công (`sql_keyword_count`, `xss_keyword_count`, `sqli_regex_matches`, `xss_regex_matches`, `path_traversal_matches`, `cmd_keyword_count`, `cmd_regex_matches`).
- 7 đặc trưng ngữ cảnh & cấu trúc v2.0 (`encoding_layer_depth`, `sql_comment_and_func_score`, `param_value_entropy_ratio`, `numeric_anomaly_flag`, `natural_text_ratio`, `safe_structured_ratio`, `protocol_complexity_score`).

### 2.3.4. Động cơ Quyết định Rủi ro Đa tầng & Sliding Window Rate Limiter
*Bảng 2.4: Ma trận quyết định hành động của Hybrid Decision Engine (`0 - 100`)*

| Điều Kiện Điểm Rủi Ro / Chính Sách | Hành Động | Mã HTTP | Cơ Chế Thực Thi Tại Gateway |
| :--- | :---: | :---: | :--- |
| `0 <= Risk < 30` | `ALLOW` | `200 OK` | Chuyển tiếp tới Bookie API; gắn `X-WAF-Risk-Score`, `X-WAF-API-Protocol`. |
| `30 <= Risk < 60` | `MONITOR` | `200 OK` | Chuyển tiếp tới Upstream, đồng thời ghi `SecurityEvent` (nhãn `MONITOR`) vào SQLite WAL. |
| `60 <= Risk < 80` (hoặc vượt quota) | `RATE_LIMIT` | `429 Too Many Requests` | Áp dụng `risk_penalty=True` / khóa tạm thời kèm `Retry-After` chuẩn RFC 6585 & RFC 7807. |
| `Risk >= 80` hoặc `Rule >= 85` hoặc `ML >= 90` hoặc XXE/Schema Strict | `BLOCK` | `403 Forbidden` | Ngắt kết nối ngay tại Gateway (khi `ACTIVE_BLOCKING`), ghi `SecurityEvent` (`BLOCKED`) & đo thực `response_time_ms`. |

Bộ điều tiết tần suất **Sliding Window Rate Limiter** lưu trữ bằng `OrderedDict` với cơ chế **LRU Cap = 50,000 khóa** (chống tràn RAM OOM DoS) và áp dụng **IP Hard Cap** (10 req/phút trên `/auth/login/`, 60 req/phút mặc định) bất kể kẻ tấn công xoay vòng `User-Agent` hay `Bearer Token`.

---

## 2.4. Thiết Kế Ứng Dụng Mục Tiêu (`vulnerable-api` — Bookie Bookstore)

Nhóm nghiên cứu tự xây dựng hoàn chỉnh hệ thống Web API thương mại điện tử **Bookie Bookstore** bằng **Python Django** (SQLite backend, lắng nghe cô lập `127.0.0.1:5000`) thay vì phụ thuộc vào ứng dụng mẫu bên thứ ba. Hệ thống cung cấp **8 kịch bản lỗ hổng OWASP Web & API Top 10** (`vulnerable-api/books/api_vulnerable.py`) cùng đặc tả OpenAPI 3.0 (`/api/v1/vulnerable/openapi.json`):

*Bảng 2.5: 8 nhóm lỗ hổng Web API trong Bookie Bookstore (`vulnerable-api`)*

| STT | Endpoint | Chuẩn OWASP | Tham Số & Cơ Chế Lỗ Hổng |
| :---: | :--- | :--- | :--- |
| 1 | `POST /api/v1/vulnerable/auth/login/` | Web A03:2021 (SQLi) | Trường `username`, `password` ghép chuỗi trực tiếp vào truy vấn SQL (Auth Bypass). |
| 2 | `GET /api/v1/vulnerable/books/search/?q=` | Web A03:2021 (SQLi UNION) | Tham số `q` nội suy trực tiếp mệnh đề `LIKE` cho phép UNION trích xuất bảng người dùng. |
| 3 | `POST /api/v1/vulnerable/reviews/` | Web A03:2021 (Stored XSS) | Trường `book_id`, `author`, `comment` lưu thẳng không mã hóa HTML/JS. |
| 4 | `GET /api/v1/vulnerable/files/download/?file=` | Web A01:2021 (Path Traversal) | Tham số `file` không giới hạn thư mục gốc cho phép đọc tệp hệ thống (`../../`). |
| 5 | `POST /api/v1/vulnerable/admin/ping/` | Web A03:2021 (CMD Injection) | Trường `host` truyền thẳng vào lệnh shell `ping`, cho phép nối lệnh `; whoami`. |
| 6 | `GET /api/v1/vulnerable/orders/{order_id}/` | API1:2023 (BOLA / IDOR) | Không kiểm tra quyền sở hữu `order_id` theo danh tính phiên. |
| 7 | `POST /api/v1/vulnerable/books/fetch-cover/` | API7:2023 (SSRF) | Cho phép truy xuất URL nội bộ hoặc metadata service qua trường URL đầu vào. |
| 8 | `PUT /api/v1/vulnerable/users/profile/update/` | API6:2023 (Mass Assignment) | Gán trực tiếp các thuộc tính JSON chưa lọc (`role`, `is_admin`) vào hồ sơ người dùng. |

---

## 2.5. Thiết Kế Hệ Thống Tác Tử Red Team & Đấu Trường AI (`attack-lab` + `/arena`)

1. **Module Trinh sát Tự động (`attack-lab/agent/recon.py` — Task 10.1):** Quét OpenAPI 3.0 từ Gateway, tích hợp `seen_refs` cycle guard chống lỗi đệ quy vô hạn trên `$ref` vòng tròn, xuất bản đồ bề mặt tấn công `attack_surface.json`.
2. **Môi trường Đồ thị Tấn công (`attack-lab/environment/` — Task 10.2):** Biểu diễn tập endpoint thành đồ thị có hướng `AttackGraph`, cung cấp vector quan sát cố định **40 chiều** và từ điển **14 hành động rời rạc** có mặt nạ hợp lệ (`action_mask`).
3. **Động cơ Biến dị & PyTorch DQN (`evasion.py`, `tools.py`, `runner.py` — Task 10.3 & 10.4):** Kết hợp 14 bộ biến dị bảo toàn ngữ nghĩa cho 4 họ tấn công với mạng DQN nội bộ (`evasion_agent.pt`, `40 -> 128 -> 128 -> 14`) có xác thực SHA-256 Fail-Closed và `weights_only=True`.
4. **Đấu Trường AI Trực Quan (`gateway/app/api/arena.py` + `dashboard/src/app/arena/page.tsx`):** Cho phép điều phối trực tiếp trận đấu Red Team vs Blue Team v2.0 ngay trên SOC Dashboard (bảo vệ bằng `require_admin` qua BFF Proxy, đo độ trễ thực bằng `perf_counter`, dùng đúng pipeline 26-D và hiển thị lịch sử đối đầu theo thời gian thực).

---

## 2.6. Thiết Kế Cơ Sở Dữ Liệu SQLite WAL & Kiểm Toán (`gateway/app/db/models.py`)

CSDL gồm **4 bảng chuẩn hóa** hoạt động ở chế độ `WAL` (`busy_timeout=5000`):
1. **`requests` (`RequestLog`):** Lưu `request_id` (indexed), `timestamp` (UTC), `client_ip`, `user_agent`, `method`, `url`, `path`, `headers`, `query_params`, `body_hash`, `response_status`, `response_time_ms` (đo thực cho cả request cho qua lẫn bị chặn), `response_size`.
2. **`security_events` (`SecurityEvent`):** Lưu `event_id` (unique), `request_id`, `timestamp`, `client_ip`, `attack_type`, `severity`, `action` (`BLOCKED`/`MONITOR`/`RATE_LIMIT`/`ALLOW`), `risk_score`, `rule_score`, `ml_score`, `anomaly_score`, `behavior_score`, `details` (JSON gồm rule matches, 26-D feature vector thật, risk breakdown, schema violations), cùng 3 cột có index phục vụ truy vấn nhanh không quét toàn bảng: **`session_id`**, **`kill_chain_stage`** và **`api_protocol`**.
3. **`audit_logs` (`AuditLog`):** Lưu vết kiểm toán quản trị (`timestamp`, `actor`, `action`, `key`, `old_value`, `new_value`) mỗi khi quản trị viên gọi `/dashboard/toggle-waf-mode`, `/dashboard/reset-demo` hay `/dashboard/seed-demo`.
4. **`waf_config` (`WafConfigModel`):** Lưu cấu hình runtime bền vững (`waf_mode`), liên kết với bộ nhớ đệm RAM TTL cache qua SQLAlchemy hook.
