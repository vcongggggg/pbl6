# Kiến Trúc Hệ Thống (System Architecture) — PBL6
## Mô Hình Thao Trường An Ninh Phân Tán (Distributed Cyber Range: Red Team vs Blue Team)

---

## 1. Tổng Quan Kiến Trúc (Architecture Overview)

Dự án **Web API Security Platform & Autonomous Red Teaming** được thiết kế theo mô hình **Thao trường An ninh Đối kháng Phân tán (Distributed Cyber Range)** triển khai trên **2 máy vật lý độc lập** kết nối qua mạng cục bộ (LAN / Wi-Fi):

* **MÁY 1 (Blue Team — Phòng thủ — Phụ trách: `vcongggggg`):** Vận hành hệ thống phòng vệ gồm WAF Gateway (Reverse Proxy + Rule Engine + ML Detection Engine), ứng dụng mục tiêu tự xây dựng `vulnerable-api`, và trung tâm chỉ huy an ninh SOC Dashboard.
* **MÁY 2 (Red Team — Tấn công — Phụ trách: `naocavang08`):** Vận hành hệ thống tấn công tự động gồm **AI Attack Planner (Offensive AI Agent)** và công cụ bắn payload thích ứng (Adaptive Evasion Engine) tấn công từ xa qua mạng LAN vào Máy 1.

```mermaid
graph LR
    subgraph Machine2["MÁY 2: RED TEAM (ATTACKER) — naocavang08"]
        AI_Planner["AI Attack Planner\n(Offensive AI Agent)"]
        Recon["Recon Engine\n(OpenAPI Schema Parser)"]
        Evasion["Adaptive Evasion Engine\n(Payload Obfuscator)"]
        AttackEngine["Attack Lab Runner\n(LAN HTTP Client)"]
        
        AI_Planner --> Recon
        AI_Planner --> Evasion
        Evasion --> AttackEngine
    end

    subgraph LAN["MẠNG CỤC BỘ (LAN / WI-FI)"]
        LAN_Traffic["HTTP / REST API Traffic\nTarget: http://192.168.1.X:8000/api/proxy/..."]
    end

    subgraph Machine1["MÁY 1: BLUE TEAM (DEFENDER) — vcongggggg"]
        subgraph Gateway["WAF Gateway (Lắng nghe 0.0.0.0:8000)"]
            ReqID["Request ID Resolver & Header Filter"]
            Normalizer["Input Normalizer: URL, HTML, Unicode"]
            
            subgraph DetectionLayer["Đa Tầng Phát Hiện (Multi-Layer Detection)"]
                RuleEngine["Rule Engine (16 OWASP Signatures)"]
                FeatureExt["17-Feature Extractor"]
                RFEngine["Random Forest Classifier (Supervised)"]
                IFEngine["Isolation Forest (Anomaly Detection)"]
            end
            
            RiskEngine["Hybrid Risk Scoring & Decision Engine"]
            RateLimiter["IP Rate Limiter (Sliding Window - 429)"]
        end
        
        subgraph TargetService["Target Web API (Port 5000)"]
            VulnAPI["vulnerable-api (Custom FastAPI)\n• /auth/login (SQLi & BruteForce)\n• /products/search (SQLi UNION)\n• /comments (Stored/Reflected XSS)\n• /documents/view (Path Traversal)\n• /tools/ping (Command Injection)\n• /docs & /openapi.json"]
        end
        
        subgraph Storage["Cơ Sở Dữ Liệu"]
            DB_Req[("SQLite: requests")]
            DB_Sec[("SQLite: security_events")]
        end
        
        subgraph Monitoring["Giao Diện SOC"]
            Dashboard["Next.js SOC Dashboard (Port 3000)\n• 5 KPI Cards • Quick Simulator\n• Area & Donut Charts • Event Drawer"]
        end
    end

    AttackEngine -->|LAN Network Call| LAN_Traffic
    LAN_Traffic -->|Gửi tới Gateway| ReqID
    ReqID --> Normalizer
    Normalizer --> DetectionLayer
    RuleEngine & FeatureExt --> RFEngine & IFEngine
    DetectionLayer --> RiskEngine
    RiskEngine --> RateLimiter
    
    RateLimiter -->|ALLOW: Forward 200 OK| VulnAPI
    RateLimiter -->|BLOCK: Ngắt kết nối 403 Forbidden| LAN_Traffic
    
    Gateway -->|Lưu vết truy cập| DB_Req
    Gateway -->|Lưu sự kiện bảo mật| DB_Sec
    Dashboard <-->|REST API Polling| Gateway
```

---

## 2. Ranh Giới Và Trách Nhiệm Từng Thành Phần (Component Boundaries)

### 2.1. `vulnerable-api/` (Target Web API Tự Xây Dựng — Thay Thế Juice Shop)
* **Lý do tự xây dựng:** Theo chỉ đạo của Giảng viên hướng dẫn, việc tự xây dựng Web API giúp nhóm làm chủ 100% mã nguồn, hiểu tường tận cơ chế khai thác các lỗ hổng OWASP Top 10 trên Web API thực tế, và cho phép định hình cấu trúc dữ liệu theo đúng yêu cầu đề tài.
* **Công nghệ:** Python 3.12, FastAPI, SQLite, Pydantic, Uvicorn.
* **Cổng dịch vụ:** Chạy nội bộ trên Port `5000` (chỉ cho phép Gateway kết nối qua mạng Docker hoặc localhost).
* **6 Endpoints nghiệp vụ có chủ đích cài cắm lỗ hổng:**
  1. `POST /api/v1/auth/login`: Xác thực người dùng — Lỗ hổng **SQL Injection Auth Bypass** (`' OR '1'='1`) và **Brute Force**.
  2. `GET /api/v1/products/search`: Tra cứu danh mục — Lỗ hổng **SQL Injection UNION-based** (`' UNION SELECT ...`).
  3. `POST /api/v1/comments` & `GET /api/v1/comments`: Đánh giá — Lỗ hổng **Stored & Reflected XSS** (`<script>alert(1)</script>`).
  4. `GET /api/v1/documents/view`: Tải tài liệu — Lỗ hổng **Path Traversal / LFI** (`../../etc/passwd` hoặc `windows/win.ini`).
  5. `POST /api/v1/tools/ping`: Quản trị mạng — Lỗ hổng **Command Injection** (`127.0.0.1; whoami`).
  6. `GET /openapi.json` & `/docs`: Cung cấp đặc tả OpenAPI chuẩn để AI Attack Planner bên Máy 2 tự động trinh sát (Reconnaissance).

### 2.2. `gateway/` (WAF Reverse Proxy Gateway — Lớp Phòng Thủ Chính)
* **Vị trí:** Đứng trước `vulnerable-api`, lắng nghe trên `0.0.0.0:8000` để các máy trong mạng LAN đều có thể gửi request tới.
* **Pipeline xử lý tuần tự (Request Pipeline):**
  1. **Request Surface Parser & Resolver:** Bóc tách toàn bộ bề mặt request (Path, Query Params, Headers, JSON/Form Body), cấp phát `X-Request-ID`.
  2. **Input Normalizer:** Chuẩn hóa đa tầng (URL decode đệ quy, HTML unescape, Unicode NFC canonicalization, loại bỏ ký tự rác/khoảng trắng dư thừa).
  3. **Rule Engine (Phase 2 - Hoàn thành):** Kiểm tra đối sánh 16 signatures tất định (SQLi, XSS, Path, Cmd), chấm điểm rủi ro quy chuẩn 0–100 (`RuleScorer`).
  4. **Feature Extraction (Phase 3 - Sắp làm):** Trích xuất vector 17 đặc trưng thống kê và ngữ cảnh từ request.
  5. **Machine Learning Engines (Phase 5 & 6):**
     * **Random Forest:** Phân loại đa lớp (Benign, SQLi, XSS, Path Traversal, Command Injection).
     * **Isolation Forest:** Đo lường độ dị biệt (Anomaly Score) phát hiện các cuộc tấn công Zero-day hoặc hành vi bất thường.
  6. **Hybrid Decision Engine (Phase 7):** Tổng hợp điểm số từ Rule + ML + Anomaly thành Weighted Risk Score và ra quyết định phòng thủ:
     * `ALLOW` ($< 40$): Cho phép request đi tiếp tới `vulnerable-api`.
     * `MONITOR` ($40 - 69$): Cho phép đi tiếp nhưng đánh dấu nghi vấn và ghi log chi tiết.
     * `RATE_LIMIT` / `CHALLENGE`: Trả về `HTTP 429 Too Many Requests`.
     * `BLOCK` ($\ge 70$): Ngắt kết nối ngay lập tức tại Gateway, trả về `HTTP 403 Forbidden`.
  7. **Persistence:** Ghi nhận lưu lượng vào bảng `requests` và sự kiện an ninh vào `security_events` trong SQLite (`waf_gateway.db`).

### 2.3. `dashboard/` (SOC Command Center — Màn Hình Giám Sát Thời Gian Thực)
* **Công nghệ:** Next.js 14 (App Router), Tailwind CSS, Recharts, Lucide Icons.
* **Cổng dịch vụ:** Port `3000`.
* **Tính năng hoàn thành (Phase 9):**
  * 5 KPI Cards (Total Traffic, Attacks Detected, Threat Score, Safe Request Rate, Quick Simulator).
  * Area Chart sóng kép biểu diễn lưu lượng sạch vs tấn công theo thời gian thực.
  * Donut Chart phân bố tỷ lệ các họ tấn công đã nhận diện.
  * Bảng sự kiện an ninh Live Events và ngăn kéo Payload Evidence Drawer đối chiếu chi tiết Raw Input vs Canonical Normalized.

### 2.4. `attack-lab/` (Offensive AI — AI Attack Planner Trên Máy 2)
* **Vị trí triển khai:** Chạy độc lập trên **MÁY 2 (Red Team)**.
* **Cơ chế hoạt động:**
  1. **Tự động Trinh sát (Automated Reconnaissance):** Đọc file đặc tả OpenAPI schema từ Máy 1 (`http://192.168.1.X:8000/api/proxy/openapi.json`), lập bản đồ bề mặt tấn công (Attack Surface Mapping).
  2. **AI Planning Agent:** Sử dụng AI/LLM hoặc máy trạng thái heuristic để lên kế hoạch chuỗi tấn công (Kill Chain: Dò quét $\rightarrow$ Vượt quyền đăng nhập bằng SQLi $\rightarrow$ Khai thác chiếm quyền server qua Command Injection).
  3. **Adaptive Evasion Engine:** Khi Gateway của Máy 1 chặn `403 Forbidden`, AI Planner tự động suy luận lý do bị chặn và tiến hành biến đổi payload (Mã hóa URL kép, hoán đổi ký tự viết hoa/thường, chèn comment nội dòng `/**/`, thay thế hàm tương đương) để bắn lại nhằm tìm cách vượt rào WAF.

---

## 3. Ma Trận Triển Khai & Phân Chia Trách Nhiệm 2 Máy

| Thành Phần Hệ Thống | Vị Trí Triển Khai | Thành Viên Phụ Trách | Trạng Thái Kỹ Thuật |
| :--- | :--- | :--- | :---: |
| **vulnerable-api** (Custom Web API) | **MÁY 1 (Blue Team)** | `vcongggggg` | 🚀 Tiếp tục xây dựng |
| **FastAPI WAF Reverse Proxy** | **MÁY 1 (Blue Team)** | `vcongggggg` | ✅ Hoàn thành Phase 1 |
| **Rule-based Detection Engine (16 Rules)** | **MÁY 1 (Blue Team)** | `vcongggggg` | ✅ Hoàn thành Phase 2 |
| **SOC Dashboard (Next.js 14)** | **MÁY 1 (Blue Team)** | `vcongggggg` | ✅ Hoàn thành Phase 9 |
| **Hybrid Decision & Active Blocking (403)**| **MÁY 1 (Blue Team)** | `vcongggggg` | ⏳ Phase 7 |
| **IP Sliding Window Rate Limiter (429)** | **MÁY 1 (Blue Team)** | `vcongggggg` | ⏳ Phase 8 |
| **17-Feature Extractor Pipeline** | Dùng chung (Shared) | `naocavang08` | ⏳ Phase 3 |
| **Dataset Generation (Raw + Synthetic)** | Dùng chung (Shared) | `naocavang08` | ⏳ Phase 4 |
| **Random Forest Supervised Classifier** | Model nạp Máy 1 | `naocavang08` | ⏳ Phase 5 |
| **Isolation Forest Anomaly Detection** | Model nạp Máy 1 | `naocavang08` | ⏳ Phase 6 |
| **AI Attack Planner (Offensive AI Agent)** | **MÁY 2 (Red Team)** | `naocavang08` | ⏳ Phase 10 |
| **Adaptive Evasion & Red Team Campaigns** | **MÁY 2 (Red Team)** | `naocavang08` | ⏳ Phase 10 |
| **Multi-Method Performance Evaluation** | Cả 2 máy | `naocavang08` & `vcongggggg` | ⏳ Phase 11 |
