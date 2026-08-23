# Web API Security Platform (PBL6 — An Toàn Thông Tin)

> **Dự án:** Xây dựng hệ thống phát hiện và ngăn chặn tấn công Web API thông minh sử dụng Machine Learning.  
> **Trạng thái hiện tại:** **Phase 0 — Project Bootstrap & Codebase Foundation (Hoàn thành)**.

---

## 1. Tổng Quan Dự Án (Project Overview)

Web API Security Platform là giải pháp an ninh mạng đóng vai trò như một Reverse Proxy / WAF Gateway thông minh đứng trước các dịch vụ Web API. 

Hệ thống được thiết kế theo mô hình phòng thủ nhiều tầng (Defense-in-depth), kết hợp:
* **Rule-based Detection:** Bộ lọc mẫu tấn công cổ điển (SQLi, XSS, Path Traversal, Command Injection).
* **Supervised Machine Learning:** Mô hình phân loại Random Forest nhận diện payload độc hại dạng đa nhãn (Multiclass).
* **Anomaly Detection:** Mô hình Isolation Forest phát hiện hành vi bất thường theo cửa sổ thời gian (Time-window).
* **Weighted Risk Scoring Engine:** Tổng hợp các tín hiệu phát hiện thành điểm nguy cơ (Risk Score $0 - 100$) để đưa ra quyết định (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK`).

---

## 2. Ranh Giới Trách Nhiệm (Team Responsibility Boundary)

Dự án phân chia ranh giới chuyên môn rõ ràng:

* **Backend / Security Team (Member A & C):**
  * Xây dựng API Gateway, Reverse Proxy bằng FastAPI (`gateway/`).
  * Quản lý Rule Engine, Rate Limiting, Risk Scoring Engine, Decision Engine và SQLite Database.
  * Xây dựng giao diện giám sát Real-time Dashboard bằng Next.js (`dashboard/`) và Attack Lab (`attack-lab/`).
* **ML / Data Team (Member B):**
  * Nghiên cứu, thu thập và tiền xử lý dữ liệu huấn luyện (`ml-engine/`).
  * Trích xuất đặc trưng (Feature Engineering).
  * Huấn luyện, đánh giá và xuất bản các artifacts mô hình (`.joblib`) theo đặc tả [docs/ML_INTEGRATION.md](file:///c:/Study/HocKy6/PBL6/docs/ML_INTEGRATION.md).

---

## 3. Cấu Trúc Thư Mục Repository (Repository Structure)

```text
pbl6/
├── gateway/              # FastAPI WAF Gateway application
│   ├── app/
│   │   ├── api/          # Route handlers (Health, etc.)
│   │   ├── core/         # Config, logging, errors
│   │   ├── db/           # SQLAlchemy session, base, models
│   │   └── schemas/      # Pydantic request/response schemas
│   ├── tests/            # Gateway unit tests (pytest)
│   ├── pyproject.toml    # Python project & tooling configuration
│   └── Dockerfile
├── ml-engine/            # Reserved for ML/Data team (training, features, models)
├── attack-lab/           # Local attack scenarios and campaign runner
├── dashboard/            # Next.js TypeScript frontend dashboard
│   ├── src/              # App router, components, central config
│   ├── package.json
│   └── Dockerfile
├── shared/               # Shared types, contracts, and utilities
├── tests/                # Integration, security, and performance test suites
├── scripts/              # Automation and database helper scripts
├── docs/                 # Documentation (Plan, Architecture, Development, ML contract)
│   ├── PLAN.md
│   ├── PROGRESS.md
│   ├── GAP_ANALYSIS.md
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT.md
│   └── ML_INTEGRATION.md
├── config/               # Configuration templates
├── data/                 # Raw, processed data and model artifacts (.gitkeep)
├── docker/               # Additional docker configs
├── .github/workflows/    # CI Pipeline (lint, tests, build)
├── .gitignore
├── .dockerignore
├── .env.example
├── docker-compose.yml    # Root multi-container orchestration
├── Makefile              # Developer task runner
└── README.md
```

---

## 4. Yêu Cầu Cài Đặt (Prerequisites)

* **Python:** $\ge 3.11$ (Khuyến nghị 3.12).
* **Node.js:** $\ge 18$ kèm `npm`.
* **Docker & Docker Compose:** Đã cài đặt và đang chạy.

---

## 5. Cấu Hình Môi Trường (Environment Configuration)

Sao chép file cấu hình mẫu `.env.example` sang `.env`:
```bash
# Linux / macOS
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Các biến môi trường chính:
* `APP_ENV`: Môi trường thực thi (`development` / `test` / `production`).
* `APP_PORT`: Cổng Gateway (`8000`).
* `TARGET_API_URL`: URL dịch vụ đích cần bảo vệ (`http://juice-shop:3000`).
* `DATABASE_URL`: Đường dẫn SQLite (`sqlite:///./data/waf_security.db`).
* `ADMIN_API_KEY`: Khóa xác thực cho các API quản trị WAF.

---

## 6. Khởi Chạy Hệ Thống Bằng Docker (Khuyến nghị)

Chạy toàn bộ cụm dịch vụ (Gateway, Dashboard, OWASP Juice Shop) bằng một lệnh duy nhất:

```bash
docker compose up --build -d
```

Truy cập các dịch vụ:
* **Gateway API:** [http://localhost:8000](http://localhost:8000)
* **Gateway Health Check:** [http://localhost:8000/health](http://localhost:8000/health)
* **Swagger API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **Dashboard Frontend:** [http://localhost:3001](http://localhost:3001)
* **Target Web API (Juice Shop):** [http://localhost:3000](http://localhost:3000)

Dừng hệ thống:
```bash
docker compose down
```

---

## 7. Kiểm Thử & Kiểm Tra Chất Lượng Mã Nguồn

### Chạy Unit Tests Backend
```bash
pytest gateway/tests
```

### Chạy Linter (Ruff)
```bash
ruff check gateway
```

### Build Frontend
```bash
cd dashboard && npm run build
```

---

## 8. Tài Liệu Dự Án (Documentation Links)

* 📄 [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md): Đặc tả kế hoạch tổng thể và yêu cầu kỹ thuật chi tiết.
* 📄 [docs/PROGRESS.md](file:///c:/Study/HocKy6/PBL6/docs/PROGRESS.md): Bảng theo dõi tiến độ Phase 0 $\rightarrow$ Phase 12.
* 📄 [docs/ARCHITECTURE.md](file:///c:/Study/HocKy6/PBL6/docs/ARCHITECTURE.md): Kiến trúc luồng xử lý và ranh giới hệ thống.
* 📄 [docs/DEVELOPMENT.md](file:///c:/Study/HocKy6/PBL6/docs/DEVELOPMENT.md): Hướng dẫn chi tiết thiết lập môi trường lập trình.
* 📄 [docs/ML_INTEGRATION.md](file:///c:/Study/HocKy6/PBL6/docs/ML_INTEGRATION.md): Giao kèo tích hợp giữa Gateway và ML Engine.

---

## 9. Giới Hạn Hiện Tại (Known Limitations in Phase 0)

Theo quy định nghiêm ngặt của **Phase 0 — Codebase Foundation**:
* **Chưa triển khai các luật WAF (SQLi, XSS, Path Traversal, Command Injection)** $\rightarrow$ Sẽ triển khai tại **Phase 2**.
* **Chưa triển khai trích xuất đặc trưng và mô hình ML** $\rightarrow$ Sẽ triển khai tại **Phase 3, 5, 6**.
* **Chưa triển khai tính toán Risk Score, Rate Limiting và chặn tự động** $\rightarrow$ Sẽ triển khai tại **Phase 7, 8**.
* **Chưa triển khai giao diện biểu đồ và danh sách log trên Dashboard** $\rightarrow$ Sẽ triển khai tại **Phase 9**.
* **Chưa triển khai kịch bản Attack Lab** $\rightarrow$ Sẽ triển khai tại **Phase 10**.

---

## 10. Giai Đoạn Kế Tiếp (Next Phase)

👉 **Phase 1 — Infrastructure** (Thiết lập mạng Docker, kết nối reverse proxy thô tới Target Web API và hoàn thiện database logging).
