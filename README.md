# Web API Security Platform & Autonomous Red Teaming (PBL6 — An Toàn Thông Tin)

> **Đề tài:** Phát hiện và ngăn chặn tấn công Web API thông minh bằng Machine Learning kết hợp Thao trường An ninh Đối kháng (Distributed Cyber Range).
> **Kiến trúc hiện tại:** **Blue Team v2.0** — High-Concurrency Async Reverse Proxy WAF + Multi-Protocol Sniffer (REST / GraphQL / SOAP / JSON-RPC) + OpenAPI Schema Validator + Champion XGBoost v2.0 (Zero-Pickle UBJSON) + Calibrated Isolation Forest v2.0 (Zero-Pickle NPZ) + Real-time SOC Command Center Dashboard.

---

## 1. Tổng Quan Dự Án (Project Overview)

**Web API Security Platform** là giải pháp an ninh mạng toàn diện bảo vệ các dịch vụ Web API thông qua kiến trúc **Reverse Proxy WAF Gateway** kết hợp đa tầng phòng thủ (Defense-in-Depth), được triển khai theo mô hình **Thao trường Đối kháng Phân tán (Distributed Cyber Range)** giữa 2 máy tính vật lý qua mạng cục bộ (LAN):

* **MÁY 1: BLUE TEAM (DEFENDER — Phụ trách: `vcongggggg`):**
  * **High-Concurrency Async WAF Gateway (FastAPI):** Lắng nghe trên `0.0.0.0:8000`, offload tác vụ kiểm tra CPU-bound ra worker thread (`anyio.to_thread.run_sync`), cache cấu hình `waf_mode` trên RAM TTL, ghi log SQLite WAL không chặn qua `BackgroundTasks` (đạt >= 150 RPS ở C=50).
  * **Multi-Protocol Sniffer & Decapsulation:** Tự động nhận diện và bóc tách payload đa giao thức (`REST`, `GraphQL`, `SOAP/XML`, `JSON-RPC 2.0`), phát hiện GraphQL Deep Nesting DoS và XML XXE trên cả query và body.
  * **Positive Security Model (`SchemaValidator`):** Kiểm chứng hợp đồng OpenAPI 3.0 (HTTP method, path parameter types, query params, `Content-Type`, JSON body schema & `additionalProperties`).
  * **Deterministic Rule Engine:** 16 signatures chuẩn hóa bằng `InputNormalizer` với sliding-window chống bypass tràn bộ đệm (SQLi, XSS, Path Traversal, Command Injection).
  * **Machine Learning Engine v2.0 (Zero-Pickle + Fail-Closed SHA-256):**
    * Unified 26-D Feature Extractor dùng chung 100% giữa Training và Serving (Zero Training-Serving Skew).
    * **Champion Cost-Sensitive XGBoost v2.0 (`xgb_v2.ubj`):** Phân loại đa lớp siêu nhanh (< 2.5ms tổng pipeline AI).
    * **Calibrated Isolation Forest v2.0 (`iforest_v2.npz`):** Phát hiện bất thường Zero-Day đã hiệu chuẩn phân vị thực nghiệm.
  * **Hybrid Risk & Multi-Tier Decision Engine:** Hợp nhất 3 tầng trọng số (`Rule 40% + Supervised ML 35% + Anomaly 25%`) ra quyết định `ALLOW` / `MONITOR` / `RATE_LIMIT 429` / `BLOCK 403`, kết hợp Sliding Window Rate Limiter và bảng `AuditLog` kiểm toán quản trị.
  * **Bookie Bookstore Target API (`vulnerable-api`):** Ứng dụng Web API mục tiêu tự xây dựng (Django, Port 5000), tích hợp 8 kịch bản lỗ hổng chuẩn OWASP Web & API Top 10 (SQLi, XSS, Path Traversal, Command Injection, BOLA/IDOR, SSRF, Mass Assignment, Excessive Data Exposure) kèm đặc tả OpenAPI 3.0 phục vụ AI trinh sát.
  * **SOC Command Center Dashboard (Next.js 14):** 100% số liệu thật từ backend (real 60s RPS, Distributed Cyber Range Topology, Protocol Distribution Pie/Bar Chart, Attack Session Kill-Chain Correlation, 26-Feature Payload Evidence Drawer, Real Explainability Modal).
* **MÁY 2: RED TEAM (ATTACKER — Phụ trách: `naocavang08`):**
  * **AI Attack Planner Agent (`attack-lab/agent/`):** Tác nhân AI tự động trinh sát OpenAPI (`recon.py`), lập kế hoạch chuỗi tấn công (`planner.py`) và mô phỏng môi trường học tăng cường (`environment/`) qua mạng LAN sang Máy 1.

---

## 2. Ranh Giới Trách Nhiệm Nhóm 2 Thành Viên

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│             PHÂN CÔNG TRÁCH NHIỆM: CYBER RANGE 2 MÁY ĐỐI KHÁNG (PBL6)            │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ THÀNH VIÊN A: vcongggggg               │ THÀNH VIÊN B: naocavang08               │
│ Vai trò: Tech Lead / Blue Team (Phòng) │ Vai trò: Red Team Lead (Tấn) & AI Eng   │
│ Vị trí: MÁY 1 (Target API, WAF, SOC UI)│ Vị trí: MÁY 2 (AI Attack Planner Agent) │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ • Bookie Bookstore Target API (Port 5k)│ • Feature Engineering (26-D Unified)    │
│ • High-Concurrency Async WAF Gateway   │ • Zero-Leakage Multi-Source Dataset v2  │
│ • Rule Engine + Multi-Protocol Sniffer │ • Champion XGBoost v2.0 (UBJSON)        │
│ • OpenAPI Schema Validator & Normalizer│ • Calibrated Isolation Forest v2 (NPZ)  │
│ • Hybrid Risk + Rate Limiter + AuditLog│ • AI Attack Planner & Recon Agent       │
│ • Real-time SOC Dashboard UI (Next 14) │ • Adaptive Evasion & Kill-Chain RL      │
│ • Docker Hardening & CI/CD Pipeline    │ • Đánh giá thực nghiệm & Báo cáo đồ án  │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

---

## 3. Cấu Trúc Thư Mục Repository (Repository Structure)

```text
pbl6/
├── gateway/              # FastAPI WAF Gateway (Async Reverse Proxy, Rule, ML v2, SQLite WAL)
│   ├── app/
│   │   ├── api/          # Route handlers (Health, Proxy, Dashboard REST APIs)
│   │   ├── core/         # Config, logging, request ID, standardized errors
│   │   ├── db/           # SQLAlchemy session (WAL + busy_timeout), models (RequestLog, SecurityEvent, AuditLog)
│   │   ├── security/     # Normalizer, Rule Engine, Protocol Detector, Schema Validator, ML/Anomaly, Risk/Decision
│   │   └── services/     # Reverse proxy client, Traffic & Security event persistence, Seeder
│   └── tests/            # Unit & Integration test suite
├── vulnerable-api/       # Bookie Bookstore Target Web API (Django, Port 5000)
│   ├── bookstore/        # Cấu hình Django, settings, urls
│   ├── books/            # Nghiệp vụ & api_vulnerable.py (8 lỗ hổng OWASP + OpenAPI 3.0)
│   └── Dockerfile
├── dashboard/            # Next.js 14 SOC Command Center (Port 3000)
│   ├── src/              # App router, KPI Cards, Topology, Protocol Pie/Bar, Events Drawer, XAI Modal
│   └── Dockerfile
├── ml-engine/            # AI/ML Pipeline v2.0 (Unified 26-D Features, XGBoost UBJSON, Isolation Forest NPZ, Benchmarks)
├── attack-lab/           # Offensive AI (agent/recon.py, agent/planner.py, environment/, scenarios/)
├── scripts/              # Dataset builders, profiling suite (run_gateway_profiling.py), ablation benchmarks
├── tests/unit/           # Cross-module unit tests
├── docs/                 # Tài liệu kiến trúc, đặc tả API/Dashboard, báo cáo hiệu năng & đánh giá khoa học
├── docker-compose.yml    # Triển khai 3 container hardened (gateway, dashboard, vulnerable-api)
└── README.md
```

---

## 4. Khởi Chạy Hệ Thống

### A. Khởi chạy bằng Docker Compose (Khuyến nghị)
```bash
# Thiết lập ADMIN_API_KEY trong .env (WAF_MODE mặc định ACTIVE_BLOCKING)
docker compose up --build -d
```
* **WAF Gateway:** [http://localhost:8000](http://localhost:8000)
* **SOC Dashboard:** [http://localhost:3000](http://localhost:3000)
* **Bookie Bookstore Target API:** [http://127.0.0.1:5000](http://127.0.0.1:5000) (chỉ lắng nghe loopback để tránh vượt qua WAF)

### B. Vận hành Thao trường Đối kháng 2 Máy (Cyber Range qua LAN)
1. **Máy 1 (Blue Team):** Khởi chạy Gateway và Dashboard. Xác định IP mạng LAN (ví dụ `192.168.1.15`).
2. **Máy 2 (Red Team):** Chạy tác nhân trinh sát và lập kế hoạch tấn công:
   ```bash
   python attack-lab/agent/recon.py --target http://192.168.1.15:8000
   python attack-lab/agent/planner.py --target http://192.168.1.15:8000/api/proxy
   ```
3. **Quan sát trực tiếp:** Mở SOC Dashboard trên Máy 1 (`http://localhost:3000`) xem Topology phân tán, phân bổ giao thức và chuỗi tấn công Kill Chain theo thời gian thực.

---

## 5. Kiểm Thử, Lint & Đo Hiệu Năng

```bash
# 1. Kiểm tra Linter toàn bộ codebase Python (0 errors)
ruff check gateway/ ml-engine/ attack-lab/

# 2. Chạy toàn bộ bộ test tự động (Gateway + Unit + ML Engine: 290+ tests)
python -m pytest gateway/tests/ tests/unit/ ml-engine/tests/

# 3. Kiểm tra Lint, Typecheck & Build Frontend Next.js
cd dashboard && npm run lint && npx tsc --noEmit && npm run build

# 4. Chạy đo hiệu năng thực tế Blue Team v2.0 (In-Process ASGI >= 150 RPS @ C=50)
python scripts/run_gateway_profiling.py --in-process
```
