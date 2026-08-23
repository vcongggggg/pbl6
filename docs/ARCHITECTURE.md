# Kiến Trúc Hệ Thống (System Architecture) — PBL6

## 1. Tổng Quan Kiến Trúc (Architecture Overview)

Dự án **Web API Security Platform** được xây dựng nhằm cung cấp giải pháp bảo vệ toàn diện cho các dịch vụ Web API thông qua kiến trúc Reverse Proxy Gateway kết hợp đa tầng phòng thủ:

```mermaid
graph TD
    Client[Người dùng / Attack Lab] -->|HTTP Request| Gateway[FastAPI WAF Gateway]
    
    subgraph Gateway_Pipeline["Gateway Request Pipeline (Phase 1-8)"]
        Parser[Request Parser & Metadata]
        Extractor[Feature Extraction Engine - Planned]
        
        subgraph Detection_Engines["Detection Layer (Planned)"]
            RuleEngine[Rule-based Engine]
            RFEngine[Random Forest Model]
            IFEngine[Isolation Forest Model]
        end
        
        RiskEngine[Risk Scoring Engine - Planned]
        DecisionEngine[Decision Engine - Planned]
        RateLimiter[Rate Limiter - Planned]
    end
    
    Gateway --> Parser
    Parser --> Extractor
    Extractor --> RuleEngine
    Extractor --> RFEngine
    Extractor --> IFEngine
    
    RuleEngine --> RiskEngine
    RFEngine --> RiskEngine
    IFEngine --> RiskEngine
    
    RiskEngine --> DecisionEngine
    DecisionEngine -->|ALLOW / MONITOR| Target[Target Web API - Juice Shop]
    DecisionEngine -->|BLOCK 403 / RATE LIMIT 429| BlockResponse[HTTP Error Response]
    
    Gateway -->|Async Security Log| DB[(SQLite Database)]
    Dashboard[Next.js Dashboard - Phase 9] <-->|Admin API + X-WAF-API-Key| Gateway
```

---

## 2. Ranh Giới Và Trách Nhiệm Từng Thành Phần (Component Boundaries)

### 2.1. `gateway/` (Backend / WAF Engine)
* **Hiện tại (Phase 0):** Khởi tạo ứng dụng FastAPI, cấu hình biến môi trường (`core/config.py`), logging chuẩn (`core/logging.py`), xử lý lỗi an toàn (`core/errors.py`), cấu trúc cơ sở dữ liệu SQLAlchemy (`db/`), và endpoint kiểm tra trạng thái `GET /health`.
* **Tương lai (Phase 1–8 - Planned):** Triển khai reverse proxy bất đồng bộ, bộ luật Rule detection, nạp mô hình ML inference, tính toán Risk score và cơ chế chặn/rate limit.

### 2.2. `ml-engine/` (ML/Data Boundary - Reserved for ML Team)
* **Hiện tại (Phase 0):** Khởi tạo cấu trúc thư mục và tài liệu [docs/ML_INTEGRATION.md](file:///c:/Study/HocKy6/PBL6/docs/ML_INTEGRATION.md).
* **Tương lai (Phase 3–6, 11 - Planned):** Xây dựng module trích xuất đặc trưng, sinh tập dữ liệu huấn luyện, huấn luyện mô hình Random Forest & Isolation Forest, xuất file artifacts (`.joblib`).

### 2.3. `dashboard/` (Frontend Visualization)
* **Hiện tại (Phase 0):** Khởi tạo khung dự án Next.js + TypeScript sạch sẽ, build thành công và hiển thị trang landing thông báo trạng thái nền tảng.
* **Tương lai (Phase 9 - Planned):** Hiển thị thống kê lưu lượng thời gian thực, bảng nhật ký sự kiện bảo mật, giao diện cấu hình WAF và panel điều khiển Attack Lab.

### 2.4. `attack-lab/` (Attack Simulation)
* **Hiện tại (Phase 0):** Cấu trúc thư mục kịch bản `scenarios/` và tài liệu hướng dẫn an toàn.
* **Tương lai (Phase 10 - Planned):** Triển khai các kịch bản tấn công (SQLi, XSS, Path Traversal, API Abuse) và script `runner.py` để tự động hóa chiến dịch thử nghiệm.

### 2.5. `data/` & Database Layer
* **Hiện tại (Phase 0):** Cấu hình SQLite, định nghĩa schema bảng dữ liệu (`requests`, `security_events`, `audit_logs`, `waf_config`) thông qua SQLAlchemy Base models.
* **Tương lai (Phase 1+ - Planned):** Ghi nhận log lưu lượng và vết kiểm toán cấu hình thực tế.

---

## 3. Quy Ước Trạng Thái Triển Khai

| Module / Tính Năng | Trạng Thái Hiện Tại | Kế Hoạch Triển Khai |
| :--- | :---: | :--- |
| **FastAPI Foundation & Health API** | ✅ Implemented | Phase 0 |
| **Centralized Config & Safe Logging** | ✅ Implemented | Phase 0 |
| **Database Models & Session Management** | ✅ Implemented | Phase 0 |
| **Next.js Frontend Foundation** | ✅ Implemented | Phase 0 |
| **Docker Compose Orchestration** | ✅ Implemented | Phase 0 |
| **Reverse Proxy & Request Forwarding** | ⏳ Planned | Phase 1 |
| **Rule-based Detection Engine** | ⏳ Planned | Phase 2 |
| **Feature Extraction (17 Payload + Behavior)**| ⏳ Planned | Phase 3 (ML Team) |
| **Dataset Generation & Lab Collection** | ⏳ Planned | Phase 4 (ML Team) |
| **Random Forest Supervised ML** | ⏳ Planned | Phase 5 (ML Team) |
| **Isolation Forest Anomaly Detection** | ⏳ Planned | Phase 6 (ML Team) |
| **Weighted Risk Scoring & Decision Engine** | ⏳ Planned | Phase 7 |
| **IP-based Rate Limiter (HTTP 429)** | ⏳ Planned | Phase 8 |
| **Security Dashboard UI & Real-time Charts** | ⏳ Planned | Phase 9 |
| **Attack Lab Scenarios & Runner CLI** | ⏳ Planned | Phase 10 |
| **Multi-method Evaluation & Benchmark** | ⏳ Planned | Phase 11 (ML Team) |
