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

## 2. Reverse Proxy Endpoint

### 2.1. Dynamic Reverse Proxy
* **Endpoint:** `/api/proxy/{path:path}`
* **Methods:** `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`
* **Mô tả:** Nhận request từ Client, gắn Request ID, đo độ trễ, forward an toàn tới `TARGET_API_URL/{path}`, nhận kết quả từ Target, ghi log traffic vào SQLite và trả lại kết quả cho Client.
* **Header Handling:**
  * Client có thể gửi `X-Request-ID` (chuỗi ký tự an toàn $\le 64$ ký tự). Nếu không có, Gateway sẽ tự động sinh UUID4.
  * Các Hop-by-hop headers (`Connection`, `Keep-Alive`, `Upgrade`, `Host`, `Content-Length`) được lọc tự động trước khi chuyển tiếp.
* **Bảo vệ Open Proxy / SSRF:** Địa chỉ target luôn được khóa cố định theo cấu hình `TARGET_API_URL`. Gateway từ chối mọi yêu cầu chuyển tiếp tới domain lạ ngoài target được định cấu hình.

#### Ví dụ 1: Tìm kiếm sản phẩm (GET)
* **Client Request:**
  ```http
  GET /api/proxy/rest/products/search?q=apple HTTP/1.1
  Host: localhost:8000
  X-Request-ID: req-client-001
  ```
* **Gateway Forward tới Upstream:**
  ```http
  GET http://juice-shop:3000/rest/products/search?q=apple
  X-Request-ID: req-client-001
  ```
* **Response nhận được từ Target:** `200 OK`
  ```json
  {
    "status": "success",
    "data": [
      { "id": 1, "name": "Apple Juice (1000ml)", "price": 1.99 }
    ]
  }
  ```

#### Ví dụ 2: Tạo người dùng (POST)
* **Client Request:**
  ```http
  POST /api/proxy/api/Users HTTP/1.1
  Host: localhost:8000
  Content-Type: application/json
  Authorization: Bearer secret-token-example

  {
    "email": "user@example.com",
    "password": "UserPassword123"
  }
  ```
* **Response:** `201 Created`
* **Lưu trữ bảo mật (Database Persistence):**
  * Trường `headers` trong database được ẩn: `{"authorization": "[REDACTED]"}`.
  * Trường `password` không bao giờ xuất hiện ở dạng plaintext trong database log.

---

## 3. Error Responses (Cơ Chế Xử Lý Lỗi Chuẩn Hóa)

Khi xảy ra sự cố kết nối tới upstream, Gateway trả về phản hồi lỗi có cấu trúc chuẩn, không lộ stack trace hay cấu trúc file:

### 3.1. Target Service Unavailable (`502 Bad Gateway`)
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

### 3.2. Target Service Timeout (`504 Gateway Timeout`)
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
