# API Documentation (Gateway Interface)

Tài liệu đặc tả các API endpoints của hệ thống **FastAPI WAF Gateway**.

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
* **Mô tả:** Kiểm tra kết nối mạng từ Gateway tới Web API đích (OWASP Juice Shop).
* **Response (Target sẵn sàng):** `200 OK`
  ```json
  {
    "status": "ok",
    "target_url": "http://juice-shop:3000",
    "reachable": true,
    "upstream_status": 200,
    "latency_ms": 12.45,
    "error": null
  }
  ```
* **Response (Target không khả dụng):** `200 OK`
  ```json
  {
    "status": "unreachable",
    "target_url": "http://juice-shop:3000",
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
* **Mô tả:** Nhận request từ Client, gắn `X-Request-ID`, chuẩn hóa dữ liệu, quét qua bộ luật Rule Engine (Phase 2 Detection Only), ghi nhận sự kiện vào `security_events` nếu phát hiện dấu hiệu tấn công, forward an toàn tới `TARGET_API_URL/{path}`, nhận kết quả từ Target, ghi log traffic vào bảng `requests` và trả lại kết quả cho Client.
* **Nguyên tắc Non-blocking (Phase 2):** Các request chứa dấu hiệu tấn công vẫn được chuyển tiếp tới Target và phản hồi cho Client bình thường.

#### Ví dụ 1: Request Chứa Tấn Công SQL Injection (GET)
* **Client Request:**
  ```http
  GET /api/proxy/rest/products/search?q=apple%27%20OR%201%3D1-- HTTP/1.1
  Host: localhost:8000
  X-Request-ID: req-sqli-001
  ```
* **Xử lý nội bộ:**
  * Rule Engine khớp `SQLI-001` (Severity: `CRITICAL`, Score: `89.5`).
  * Ghi bản ghi vào bảng `security_events` với `request_id = "req-sqli-001"`.
  * Chuyển tiếp request sang `http://juice-shop:3000/rest/products/search?q=apple%27%20OR%201%3D1--`.
* **Client Response:** Nhận kết quả phản hồi thực tế từ Juice Shop (`200 OK`).

---

---

## 3. Dashboard Endpoints (SOC Command Center Interface)

Các API endpoints phục vụ Dashboard UI thời gian thực (Phase 9 Task 9.1):

### 3.1. Aggregated Dashboard Statistics
* **Endpoint:** `GET /api/dashboard/stats`
* **Mô tả:** Trả về các chỉ số thống kê tổng hợp thực tế được truy vấn trực tiếp từ 2 bảng `requests` và `security_events` trong SQLite, kèm trạng thái và độ trễ của Upstream Target (Juice Shop).
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
    "target_latency_ms": 12.4,
    "target_url": "http://juice-shop:3000",
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
  ```json
  {
    "items": [
      {
        "event_id": "evt-7a91...",
        "request_id": "req-b28e...",
        "timestamp": "2026-09-03T11:15:02",
        "client_ip": "127.0.0.1",
        "attack_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "action": "DETECTED",
        "rule_score": 89.5,
        "rule_id": "SQLI-001",
        "rule_name": "SQL Injection Tautology",
        "location": "QUERY",
        "evidence": "q=' OR '1'='1",
        "details": { "rule_matches": [...] }
      }
    ],
    "total": 142,
    "page": 1,
    "limit": 10
  }
  ```

### 3.3. Real-Time Traffic & Threat Timeline
* **Endpoint:** `GET /api/dashboard/timeline?minutes=60`
* **Mô tả:** Gom nhóm dữ liệu lưu lượng và đòn tấn công theo từng phút trong cửa sổ thời gian gần nhất để vẽ biểu đồ Area Chart sóng kép.
* **Response:** `200 OK`
  ```json
  [
    {
      "time": "11:14",
      "total_traffic": 25,
      "benign_traffic": 22,
      "attacks": 3
    }
  ]
  ```

### 3.4. Attack Family Distribution
* **Endpoint:** `GET /api/dashboard/distribution`
* **Mô tả:** Thống kê số lượng và tỷ lệ % của 4 họ tấn công chính phục vụ vẽ biểu đồ Donut Chart.
* **Response:** `200 OK`
  ```json
  [
    { "name": "SQL Injection", "key": "SQL_INJECTION", "count": 64, "percentage": 45.1, "color": "#3b82f6" },
    { "name": "XSS", "key": "XSS", "count": 42, "percentage": 29.6, "color": "#f43f5e" },
    { "name": "Path Traversal", "key": "PATH_TRAVERSAL", "count": 21, "percentage": 14.8, "color": "#10b981" },
    { "name": "Command Injection", "key": "COMMAND_INJECTION", "count": 15, "percentage": 10.5, "color": "#f59e0b" }
  ]
  ```

### 3.5. Quick Attack Simulator
* **Endpoint:** `POST /api/dashboard/simulate`
* **Request Body:**
  ```json
  { "attack_type": "SQLI" }
  ```
  *(Các giá trị hỗ trợ: `SQLI`, `XSS`, `PATH`, `CMD`, `BENIGN`)*
* **Mô tả:** Bắn request thử nghiệm thật thông qua pipeline Proxy của Gateway để kích hoạt Rule Engine và lưu log tự động.
* **Response:** `200 OK`
  ```json
  {
    "status": "success",
    "simulated": "SQL_INJECTION",
    "status_code": 200,
    "request_id": "req-sim-...",
    "message": "Fired SQL Injection payload (' OR 1=1--) through proxy pipeline."
  }
  ```

### 3.6. Reset Lab Demo Data
* **Endpoint:** `POST /api/dashboard/reset-demo`
* **Mô tả:** Xóa sạch toàn bộ các bản ghi trong 2 bảng `requests` và `security_events` để chuẩn bị cho lượt biểu diễn mới trước Hội đồng.
* **Response:** `200 OK`
  ```json
  {
    "status": "ok",
    "message": "Security events and request logs reset successfully for clean demonstration."
  }
  ```

---

## 4. Error Responses (Cơ Chế Xử Lý Lỗi Chuẩn Hóa)

Khi xảy ra sự cố kết nối tới upstream, Gateway trả về phản hồi lỗi có cấu trúc chuẩn, không lộ stack trace hay cấu trúc file:

### 4.1. Target Service Unavailable (`502 Bad Gateway`)
Trả về khi không thể kết nối tới Target Web API (Target tắt hoặc mất mạng):
```json
{
  "status": "error",
  "error": {
    "code": "TARGET_UNAVAILABLE",
    "message": "The upstream target service is currently unreachable."
  }
}
```

### 4.2. Target Service Timeout (`504 Gateway Timeout`)
Trả về khi Target Web API xử lý quá thời gian timeout quy định (`proxy_timeout_read` / `proxy_timeout_connect`):
```json
{
  "status": "error",
  "error": {
    "code": "GATEWAY_TIMEOUT",
    "message": "The upstream target service timed out."
  }
}
```
