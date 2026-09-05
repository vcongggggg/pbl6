# Web API Security Platform & Autonomous Red Teaming (PBL6 — An Toàn Thông Tin)

> **Đề tài:** Phát hiện và ngăn chặn tấn công Web API thông minh bằng Machine Learning kết hợp Thao trường An ninh Đối kháng (Distributed Cyber Range).  
> **Trạng thái:** **Phase 0, 1, 2, 9 HOÀN THÀNH ✅** | **Đang triển khai:** `vulnerable-api` & **Phase 3 (Feature Engineering) 🚀**.

---

## 1. Tổng Quan Dự Án (Project Overview)

**Web API Security Platform** là giải pháp an ninh mạng toàn diện bảo vệ các dịch vụ Web API thông qua kiến trúc **Reverse Proxy WAF Gateway** kết hợp đa tầng phòng thủ (Defense-in-depth), được triển khai theo mô hình **Thao trường Đối kháng Phân tán (Distributed Cyber Range)** giữa 2 máy tính vật lý qua mạng cục bộ (LAN):

* **MÁY 1: BLUE TEAM (DEFENDER — Phụ trách: `vcongggggg`):**
  * **WAF Reverse Proxy Gateway (FastAPI):** Lắng nghe trên `0.0.0.0:8000`, tiếp nhận lưu lượng từ mạng LAN.
  * **Rule Engine (Phase 2):** 16 signatures tĩnh tất định bắt SQLi, XSS, Path Traversal, Command Injection.
  * **Machine Learning Engine (Phase 5 & 6):** Random Forest (Supervised classification) + Isolation Forest (Zero-day anomaly detection).
  * **Hybrid Risk Engine (Phase 7):** Ra quyết định phòng thủ tự động (`ALLOW` / `MONITOR` / `RATE_LIMIT 429` / `BLOCK 403`).
  * **Vulnerable Web API (`vulnerable-api`):** Ứng dụng mục tiêu tự xây dựng (Port 5000), có 6 endpoints chứa các lỗ hổng OWASP Top 10 có chủ đích (thay thế Juice Shop theo chỉ đạo của Thầy).
  * **SOC Command Center Dashboard (Next.js 14):** Giám sát lưu lượng mạng, cảnh báo mối đe dọa thời gian thực trên port 3000.
* **MÁY 2: RED TEAM (ATTACKER — Phụ trách: `naocavang08`):**
  * **AI Attack Planner Agent (Offensive AI — Phase 10):** Tác nhân AI tự động đọc OpenAPI spec từ Máy 1, lập kế hoạch chuỗi tấn công (Kill Chain) và gửi payload qua mạng LAN sang Máy 1.
  * **Adaptive Evasion Engine:** Tự động đột biến/làm rối payload (Obfuscation, URL encoding, comment injection) khi bị WAF chặn 403 để thử nghiệm vượt rào.

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
│ • Xây dựng vulnerable-api (6 endpoints)│ • Feature Engineering (17 Features)     │
│ • Reverse Proxy Gateway (0.0.0.0:8000) │ • Thu thập & sinh Dataset (vulnerable)  │
│ • Rule Engine (16 Rules tất định)      │ • Huấn luyện Random Forest (Supervised) │
│ • Input Normalizer & Scorer            │ • Huấn luyện Isolation Forest (Anomaly) │
│ • Hybrid Decision Engine (Phase 7)     │ • Xây dựng AI Attack Planner (Phase 10) │
│ • IP Rate Limiting - 429 (Phase 8)     │ • Adaptive Evasion Engine qua mạng LAN  │
│ • SOC Dashboard UI & Recharts (Phase 9)│ • Đánh giá thực nghiệm so sánh (Phase 11)│
│ • Docker Compose Hardening (Phase 12)  │ • Soạn thảo Slide & Báo cáo đồ án       │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

---

## 3. Cấu Trúc Thư Mục Repository (Repository Structure)

```text
pbl6/
├── gateway/              # FastAPI WAF Gateway (Reverse Proxy, Rule, ML, SQLite DB)
│   ├── app/
│   │   ├── api/          # Route handlers (Health, Proxy, Dashboard REST APIs)
│   │   ├── core/         # Config, logging, errors
│   │   ├── db/           # SQLAlchemy session, SQLite models (requests, security_events)
│   │   ├── security/     # Normalizer, Rule Engine (16 rules), Scorer
│   │   └── services/     # Traffic logging, Security event persistence
│   └── tests/            # Gateway unit tests (38/38 tests pass 100%)
├── vulnerable-api/       # Target Web API tự xây dựng (FastAPI + SQLite, Port 5000)
│   ├── app/
│   │   ├── main.py       # Khởi tạo API, OpenAPI spec
│   │   └── routes/       # Auth (SQLi), Products (SQLi), Comments (XSS), Documents (Path), Tools (Cmd)
│   └── Dockerfile
├── dashboard/            # Next.js 14 SOC Command Center (Port 3000)
│   ├── src/              # App router, KPI Cards, Recharts, Event Drawer, Quick Simulator
│   └── Dockerfile
├── ml-engine/            # AI/ML Pipeline (Features, Dataset, Random Forest, Isolation Forest)
├── attack-lab/           # Offensive AI (AI Attack Planner Agent, Adaptive Evasion, Scenarios)
├── docs/                 # Toàn bộ tài liệu kỹ thuật & học thuật dự án
│   ├── PLAN.md           # Master Plan 2.0 (Toàn bộ 13 Phases & WBS)
│   ├── ARCHITECTURE.md   # Kiến trúc Thao trường An ninh Đối kháng 2 Máy
│   ├── API.md            # Đặc tả API Gateway & vulnerable-api
│   ├── GATEWAY.md        # Đặc tả Reverse Proxy & Security Pipeline
│   ├── RULE_ENGINE.md    # Danh mục 16 luật tĩnh & Input Normalizer
│   ├── DASHBOARD_SPEC.md # Đặc tả giao diện SOC Command Center
│   ├── GLOSSARY.md       # Bảng thuật ngữ chuyên ngành (60+ terms)
│   ├── PROGRESS.md       # Bảng theo dõi tiến độ chi tiết
│   └── TASKS_BREAKDOWN.md# Bảng phân rã 50 GitHub Issues
├── docker-compose.yml    # Khởi chạy 3 container (Gateway, Dashboard, vulnerable-api)
└── README.md
```

---

## 4. Khởi Chạy Hệ Thống

### A. Khởi chạy 1 lệnh bằng Docker Compose (Khuyến nghị)
```bash
docker compose up --build -d
```
* **WAF Gateway:** [http://localhost:8000](http://localhost:8000)
* **SOC Dashboard:** [http://localhost:3000](http://localhost:3000)
* **Vulnerable Web API:** [http://localhost:5000](http://localhost:5000) (Swagger UI: `/docs`)

### B. Vận hành Thao trường Đối kháng 2 Máy (Cyber Range qua LAN)
1. **Máy 1 (Blue Team):** Khởi chạy Gateway và Dashboard. Xác định IP mạng LAN (`ipconfig`, ví dụ `192.168.1.15`).
2. **Máy 2 (Red Team):** Chạy AI Attack Planner:
   ```bash
   python attack-lab/cli.py --target http://192.168.1.15:8000/api/proxy --campaign sqli
   ```
3. **Quan sát trực tiếp:** Mở SOC Dashboard trên Máy 1 xem sự kiện tấn công từ Máy 2 xuất hiện theo thời gian thực!

---

## 5. Kiểm Thử & Đảm Bảo Chất Lượng Mã Nguồn

```bash
# Chạy Unit Tests Backend (38/38 tests)
pytest gateway/tests

# Kiểm tra Linter (0 warnings/errors)
ruff check .

# Build Frontend Next.js Production
cd dashboard && npm run build
```
