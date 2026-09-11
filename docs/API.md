# API Documentation (Gateway & Target API Interface)

Tài liệu đặc tả các API endpoints của hệ thống **FastAPI WAF Gateway** và ứng dụng mục tiêu tự xây dựng **Vulnerable Target Web API (`vulnerable-api`)**.

---

## 1. Health Endpoints

### 1.1. Gateway Health Check
* **Endpoint:** `GET /health`
* **Mô tả:** Kiểm tra trạng thái hoạt động nội bộ của Gateway và trả về thông tin môi trường. Endpoint này hoạt động độc lập và không phụ thuộc vào trạng thái của Target API.
* **Headers:**
  * Request: `X-Request-ID` (Tùy chọn)
  * Response: `X-Request-ID`
* **Response:** `200 OK`
  ```json
  {
    "status": "ok",
    "app": "Web API Security Platform Gateway",
    "environment": "development",
    "version": "0.1.0"
  }
  ```

### 1.2. Target Connectivity Health Check
* **Endpoint:** `GET /health/target`
* **Mô tả:** Kiểm tra kết nối mạng từ Gateway tới Web API đích tự xây dựng (`vulnerable-api`).
* **Response (Target sẵn sàng):** `200 OK`
  ```json
  {
    "status": "ok",
    "target_url": "http://vulnerable-api:5000",
    "reachable": true,
    "upstream_status": 200,
    "latency_ms": 3.45,
    "error": null
  }
  ```
* **Response (Target không khả dụng):** `200 OK`
  ```json
  {
    "status": "unreachable",
    "target_url": "http://vulnerable-api:5000",
    "reachable": false,
    "upstream_status": null,
    "latency_ms": 2005.12,
    "error": "All connection attempts failed"
  }
  ```

---

## 2. Reverse Proxy & Security Inspection Endpoint

### 2.1. Dynamic Reverse Proxy with Signature Inspection
* **Endpoint:** `/api/proxy/{path:path}`
* **Methods:** `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`
* **Mô tả:** Nhận request từ Client/Máy 2 (Red Team), gắn `X-Request-ID`, chuẩn hóa dữ liệu, quét qua bộ luật Rule Engine (Phase 2 Detection Only) và ML Engine (Phase 5), ghi nhận sự kiện vào `security_events` nếu phát hiện dấu hiệu tấn công, forward an toàn tới `TARGET_API_URL/{path}`, nhận kết quả từ Target, ghi log traffic vào bảng `requests` và trả lại kết quả cho Client.
* **Nguyên tắc Non-blocking (Phase 2):** Các request chứa dấu hiệu tấn công vẫn được chuyển tiếp tới Target và phản hồi cho Client bình thường.
* **Nguyên tắc Active Blocking (Phase 7):** Các request có điểm rủi ro $\ge 70$ sẽ bị Gateway ngắt kết nối và trả về `HTTP 403 Forbidden`.

#### Ví dụ: Request Chứa Tấn Công SQL Injection (GET)
* **Client Request (từ Máy 2 gửi qua LAN):**
  ```http
  GET /api/proxy/api/v1/vulnerable/books/search/?q=laptop%27%20OR%201%3D1-- HTTP/1.1
  Host: 192.168.1.15:8000
  X-Request-ID: req-sqli-001
  ```
* **Xử lý nội bộ tại Gateway (Máy 1):**
  * Rule Engine khớp `SQLI-001` (Severity: `CRITICAL`, Score: `89.5`).
  * Ghi bản ghi vào bảng `security_events` với `request_id = "req-sqli-001"`.
  * Chuyển tiếp request sang `http://vulnerable-api:5000/api/v1/vulnerable/books/search/?q=laptop%27%20OR%201%3D1--`.
* **Client Response:** Nhận kết quả phản hồi từ `vulnerable-api` (`200 OK`).

---

## 3. Dashboard Endpoints (SOC Command Center Interface)

Các API endpoints phục vụ Dashboard UI thời gian thực (Phase 9 Task 9.1):

### 3.1. Aggregated Dashboard Statistics
* **Endpoint:** `GET /api/dashboard/stats`
* **Mô tả:** Trả về các chỉ số thống kê tổng hợp thực tế được truy vấn trực tiếp từ 2 bảng `requests` và `security_events` trong SQLite, kèm trạng thái và độ trễ của Upstream Target (`vulnerable-api`).
* **Response:** `200 OK`
  ```json
  {
    "total_requests": 1248,
    "attacks_detected": 142,
    "safe_requests": 1106,
    "safe_request_rate": 88.6,
    "avg_threat_score": 82.5,
    "family_counts": {
      "SQL_INJECTION": 64,
      "XSS": 42,
      "PATH_TRAVERSAL": 21,
      "COMMAND_INJECTION": 15
    },
    "target_status": "ok",
    "target_latency_ms": 3.4,
    "target_url": "http://vulnerable-api:5000",
    "waf_mode": "MONITOR_ONLY",
    "active_phase": "Phase 2 (Rule Engine Active)"
  }
  ```

### 3.2. Paginated Security Events Log
* **Endpoint:** `GET /api/dashboard/events`
* **Query Parameters:**
  * `page` (int, default: 1)
  * `limit` (int, default: 10, max: 100)
  * `severity` (str: `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  * `attack_type` (str: `ALL`, `SQL_INJECTION`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`)
  * `q` (str: tìm kiếm theo IP hoặc Request ID)
* **Response:** `200 OK`

### 3.3. Real-Time Traffic & Threat Timeline
* **Endpoint:** `GET /api/dashboard/timeline?minutes=60`
* **Mô tả:** Gom nhóm dữ liệu lưu lượng và đòn tấn công theo từng phút trong cửa sổ thời gian gần nhất để vẽ biểu đồ Area Chart sóng kép.

### 3.4. Attack Family Distribution
* **Endpoint:** `GET /api/dashboard/distribution`
* **Mô tả:** Thống kê số lượng và tỷ lệ % của 4 họ tấn công chính phục vụ vẽ biểu đồ Donut Chart.

### 3.5. Quick Attack Simulator
* **Endpoint:** `POST /api/dashboard/simulate`
* **Request Body:**
  ```json
  { "attack_type": "SQLI" }
  ```
  *(Các giá trị hỗ trợ: `SQLI`, `XSS`, `PATH`, `CMD`, `BENIGN`)*
* **Mô tả:** Bắn request thử nghiệm thật thông qua pipeline Proxy của Gateway để kích hoạt Rule Engine và lưu log tự động.

### 3.6. Reset Lab Demo Data
* **Endpoint:** `POST /api/dashboard/reset-demo`
* **Mô tả:** Xóa sạch toàn bộ các bản ghi trong 2 bảng `requests` và `security_events` để chuẩn bị cho lượt biểu diễn mới trước Hội đồng.

---

## 4. Vulnerable Target Web API (`vulnerable-api` — Bookie Bookstore)

Ứng dụng mục tiêu Bookie Bookstore tự xây dựng (chạy trên port 5000), có cài cắm 8 kịch bản lỗ hổng có chủ đích chuẩn OWASP Web & API Top 10 phục vụ thao trường an ninh đối kháng:

### 4.1. Auth Service (`POST /api/v1/vulnerable/auth/login/`)
* **Chức năng:** Xác thực người dùng & quản trị viên.
* **Lỗ hổng:** **SQL Injection Auth Bypass** & **Brute Force**.
* **Payload:** `username: admin' OR '1'='1 --`, `password: any`
* **Khai thác:** Ghép chuỗi truy vấn trực tiếp không dùng bind parameters, cho phép đăng nhập trái phép vào tài khoản superuser.

### 4.2. Books Search Service (`GET /api/v1/vulnerable/books/search/?q=...`)
* **Chức năng:** Tìm kiếm sách theo tiêu đề hoặc tác giả.
* **Lỗ hổng:** **SQL Injection UNION-based Search**.
* **Payload:** `?q=' UNION SELECT id, username, email, is_superuser FROM auth_user --`
* **Khai thác:** Trích xuất toàn bộ dữ liệu người dùng và mật khẩu từ cơ sở dữ liệu.

### 4.3. Reviews Service (`GET & POST /api/v1/vulnerable/reviews/`)
* **Chức năng:** Đọc và đăng nhận xét đánh giá sách.
* **Lỗ hổng:** **Stored & Reflected Cross-Site Scripting (XSS)**.
* **Payload:** `{"comment": "<script>alert('PBL6_XSS_STORED')</script>"}`
* **Khai thác:** Lưu trữ và render nguyên văn chuỗi JavaScript/HTML độc hại mà không qua sanitization/escaping.

### 4.4. Files Service (`GET /api/v1/vulnerable/files/download/?file=...`)
* **Chức năng:** Tải tài liệu đọc thử hoặc file đính kèm.
* **Lỗ hổng:** **Path Traversal / Local File Inclusion (LFI)**.
* **Payload:** `?file=../../windows/win.ini` hoặc `?file=../../../../etc/passwd`
* **Khai thác:** Đọc file hệ thống tùy ý ngoài thư mục lưu trữ `media/` do thiếu kiểm tra chuẩn hóa đường dẫn.

### 4.5. Admin Ping Tool (`POST /api/v1/vulnerable/admin/ping/`)
* **Chức năng:** Công cụ kiểm tra kết nối mạng (chẩn đoán máy chủ).
* **Lỗ hổng:** **Command Injection (RCE)**.
* **Payload:** `{"host": "127.0.0.1; whoami"}` hoặc `{"host": "127.0.0.1 & dir"}`
* **Khai thác:** Thực thi lệnh hệ điều hành trực tiếp thông qua hàm `subprocess` không lọc đầu vào.

### 4.6. Orders Service (`GET & PUT /api/v1/vulnerable/orders/<int:order_id>/`)
* **Chức năng:** Xem và cập nhật trạng thái đơn hàng.
* **Lỗ hổng:** **Broken Object Level Authorization (BOLA / IDOR - OWASP API1:2023)**.
* **Khai thác:** Bỏ qua kiểm tra quyền sở hữu đối tượng người dùng; bất kỳ người dùng nào cũng có thể đọc hoặc sửa địa chỉ, ghi chú, trạng thái đơn hàng của người khác chỉ bằng cách đổi ID.

### 4.7. Book Cover Fetcher (`GET & POST /api/v1/vulnerable/books/fetch-cover/?url=...`)
* **Chức năng:** Tải ảnh bìa sách từ URL bên ngoài.
* **Lỗ hổng:** **Server-Side Request Forgery (SSRF - OWASP API7:2023)**.
* **Payload:** `?url=http://127.0.0.1:8000/api/dashboard/stats`
* **Khai thác:** Dùng server làm bàn đạp gửi request tới các tài nguyên nội bộ, quét mạng LAN hoặc đọc metadata máy chủ.

### 4.8. User Profile Service (`POST & PUT /api/v1/vulnerable/users/profile/update/`)
* **Chức năng:** Cập nhật thông tin tài khoản người dùng.
* **Lỗ hổng:** **Mass Assignment & Privilege Escalation (OWASP API6:2023)**.
* **Payload:** `{"user_id": 2, "is_staff": true, "is_superuser": true}`
* **Khai thác:** Nạp toàn bộ các thuộc tính từ JSON vào model mà không có whitelist, cho phép người dùng thường tự leo thang thành quản trị viên.

### 4.9. Users List Service (`GET /api/v1/vulnerable/users/list/`)
* **Chức năng:** Danh sách người dùng hệ thống.
* **Lỗ hổng:** **Excessive Data Exposure (OWASP API3:2023)**.
* **Khai thác:** Trả về toàn bộ trường dữ liệu nhạy cảm bao gồm `password_hash`, `internal_secret_token` trong JSON response.

### 4.10. OpenAPI 3.0 Reconnaissance Endpoint
* **Endpoint:** `GET /api/v1/vulnerable/openapi.json`
* **Mô tả:** Cung cấp đặc tả chuẩn OpenAPI 3.0 đầy đủ của tất cả 8 endpoints có lỗ hổng để **AI Attack Planner** (Máy 2) tự động trinh sát, bóc tách cấu trúc tham số và lập kế hoạch tấn công (Phase 10).
