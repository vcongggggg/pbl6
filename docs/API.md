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
