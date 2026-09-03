# ĐẶC TẢ KỸ THUẬT GIAO DIỆN SECURITY OPERATIONS CENTER (SOC) DASHBOARD

Tài liệu thiết kế chi tiết kiến trúc, thành phần giao diện, luồng dữ liệu thực tế và lộ trình tiến hóa của **Next.js Dashboard** cho dự án **PBL6 — Web API Security Platform**.

---

## 1. TRIẾT LÝ THIẾT KẾ & NGUYÊN TẮC HỌC THUẬT CỐT LÕI

1. **Phong cách Dark Cyber SOC / Glassmorphism:**
   * Nền tối sâu sang trọng (`#09090b` / Slate-950) với hiệu ứng kính mờ `backdrop-blur-md` và viền mảnh bán trong suốt (`border-slate-800`).
   * Sử dụng font chữ hiện đại (`Inter` cho tiêu đề/nội dung; `JetBrains Mono` cho IP, Request ID, Regex và Payload).
2. **Tuyệt đối trung thực về số liệu (Zero Mock Data):**
   * 100% số liệu hiển thị phải được truy vấn trực tiếp từ cơ sở dữ liệu SQLite (`requests` và `security_events` tables) thông qua Gateway API.
   * Khi chưa có dữ liệu, hiển thị giao diện rỗng trung thực: *"No security events detected yet. Click simulator or send traffic to inspect."*
3. **Độ chính xác thuật ngữ theo từng Phase (Terminology Precision):**
   * **Phase 2 (Hiện tại - Detection Only):**
     * Sử dụng **`ATTACKS DETECTED`** (Phát hiện tấn công), **tuyệt đối không dùng** `Attacks Blocked` hay `Attacks Caught`.
     * Sử dụng **`SAFE REQUEST RATE`** thay cho `Target Protection Rate`.
     * Điểm số hiển thị là **`Threat Score (Rule Engine)`**, chưa hiển thị `AI Score` khi chưa tích hợp ML.
   * **Phase 7 (Tương lai - Active Defense):** Lúc này mới kích hoạt nhãn `ACTIVE DEFENSE`, `BLOCKED REQUESTS`, `BLOCK RATE (HTTP 403)`.
4. **Hệ thống huy hiệu tiến độ theo Phase (Phase Progression Badges):**
   * Mỗi module trên giao diện đều có badge thể hiện trạng thái triển khai:
     * `Rule Engine`: **`● Phase 2: Active`**
     * `Feature Vector`: **`◌ Phase 3: Pending`**
     * `Random Forest ML`: **`◌ Phase 5: Pending`**
     * `Isolation Forest Anomaly`: **`◌ Phase 6: Pending`**
     * `Active Blocking 403`: **`◌ Phase 7: Pending`**

---

## 2. KIẾN TRÚC TÍCH HỢP HỆ THỐNG (SYSTEM INTEGRATION)

```text
┌─────────────────────────────────────────────────────────────┐
│             Next.js 14 Dashboard UI (Port 3000)             │
│   (App Router + Tailwind CSS + Lucide Icons + Recharts)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
               HTTP Polling (Mỗi 3s / 5s / Off)
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                FastAPI Gateway (Port 8000)                  │
│  ├── GET  /api/dashboard/stats        (Thống kê tổng quan)   │
│  ├── GET  /api/dashboard/events       (Sự kiện phân trang)  │
│  ├── GET  /api/dashboard/timeline     (Lưu lượng chuỗi giờ) │
│  ├── GET  /api/dashboard/distribution (Tỷ lệ các loại đòn)  │
│  ├── POST /api/dashboard/simulate     (Bắn đòn test thật)   │
│  └── POST /api/dashboard/reset-demo   (Dọn sạch log test)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                      SQLAlchemy ORM
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    SQLite Database                          │
│  ├── Table `requests`        (Toàn bộ traffic metadata)     │
│  └── Table `security_events` (Sự kiện tấn công & bằng chứng)│
└─────────────────────────────────────────────────────────────┘
```

---

## 3. BỐ CỤC MÀN HÌNH CHI TIẾT (SCREEN WIREFRAME)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [SHIELD] Web API Security Platform — SOC Command Center                             [● LIVE 3s]  │
│ Target: http://juice-shop:3000 (● 12ms) | Mode: [MONITOR_ONLY] | [🔄 Refresh] [🧹 Reset Demo]   │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐ │
│ │ TOTAL TRAFFIC  │ │ATTACKS DETECTED│ │ THREAT SCORE   │ │SAFE REQUEST RAT│ │ QUICK SIMULATOR  │ │
│ │     1,248      │ │      142       │ │     82.5       │ │     88.6%      │ │ [💥 SQLi Test]   │ │
│ │  RPS: 14 req/s │ │  SQLi, XSS...  │ │   Rule-based   │ │  Forwarded 200 │ │ [⚡ XSS Test]    │ │
│ └────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘ └──────────────────┘ │
├─────────────────────────────────────────────────────────────┬────────────────────────────────────┤
│ 📈 TRAFFIC & ATTACK TIMELINE (Chuỗi Thời Gian Thực)         │ 🍩 ATTACK DISTRIBUTION (Tỷ Lệ Đòn) │
│ [ Sóng Cyan: Lưu lượng hợp lệ (Benign)                      │    ■ SQL Injection: 45%            │
│   Sóng Rose: Đòn tấn công bị phát hiện (Detected)         ] │    ■ Cross-Site Scripting: 30%     │
│                                                             │    ■ Path Traversal: 15%           │
│                                                             │    ■ Command Injection: 10%        │
├─────────────────────────────────────────────────────────────┴────────────────────────────────────┤
│ 🚨 LIVE SECURITY EVENTS LOG (Bảng Nhật Ký Sự Kiện An Ninh Thời Gian Thực)                        │
│ [🔍 Tìm IP / Request ID...] [Lọc Severity: ALL ▾] [Lọc Loại Tấn Công: ALL ▾] [Export JSON]      │
│ ┌──────────┬────────────┬──────────────┬──────────┬──────────┬──────────┬─────────┬────────────┐ │
│ │ Time     │ Request ID │ Attack Type  │ Severity │ Location │ Rule ID  │ Score   │ Action     │ │
│ ├──────────┼────────────┼──────────────┼──────────┼──────────┼──────────┼─────────┼────────────┤ │
│ │ 11:15:02 │ #req-a81f  │ SQL_INJECTION│ CRITICAL │ QUERY    │ SQLI-001 │  89.5   │ [👁 View]  │ │
│ │ 11:14:48 │ #req-c92e  │ XSS          │ HIGH     │ BODY     │ XSS-001  │  85.5   │ [👁 View]  │ │
│ └──────────┴────────────┴──────────────┴──────────┴──────────┴──────────┴─────────┴────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. ĐẶC TẢ CHI TIẾT CÁC PHÂN KHU CHỨC NĂNG

### 4.1. Top Header Bar (Thanh Điều Hướng & Trạng Thái)
* **Logo & Tiêu đề:** Biểu tượng khiên bảo mật phát sáng ánh tím neon kèm chữ `Web API Security Platform`.
* **Trạng thái Upstream (Juice Shop Health):**
  * `● Connected (12.4ms)` màu xanh lá nếu Target phản hồi `200 OK`.
  * `● Unreachable` màu đỏ rực nếu Target mất kết nối kèm cảnh báo.
* **Chế độ Gateway (WAF Mode):**
  * Hiện badge màu vàng hổ phách: `● MONITOR_ONLY (Phase 2)`.
* **Bộ điều khiển Smart Polling (Auto-Refresh):**
  * Tùy chọn chu kỳ: `[3s] [5s] [Tắt]`.
  * Có vòng tròn tiến độ đếm ngược thời gian.
  * **UX Safeguard:** Khi người dùng đang mở Modal xem chi tiết hoặc đang gõ ô tìm kiếm, hệ thống **tự động tạm dừng polling** để tránh giật giao diện.
* **Nút `[Dọn dẹp log demo]`:** 1-click xóa dữ liệu rác sau khi demo cho Hội đồng để chuẩn bị cho lượt thử nghiệm tiếp theo.

---

### 4.2. Hàng 5 Thẻ Chỉ Số (Key Metrics KPI Cards)
1. **Total Requests:** Tổng số requests đã đi qua Gateway, kèm tốc độ thời gian thực (RPS).
2. **Attacks Detected:** Tổng số sự kiện an ninh được ghi nhận trong bảng `security_events`.
3. **Threat Score (Rule-based):** Điểm số rủi ro cao nhất hoặc trung bình từ Rule Engine (thang điểm 0 - 100).
4. **Safe Request Rate:** Tỷ lệ % số request hợp lệ được chuyển tiếp tới Target API an toàn.
5. **Quick Attack Simulator (Bảng Bắn Đòn Thử Nghiệm 1-Click — Ăn Điểm Demo):**
   * Nút 1: `[💥 SQLi Test]` $\rightarrow$ Bắn `' OR 1=1--`
   * Nút 2: `[⚡ XSS Test]` $\rightarrow$ Bắn `<script>alert('PBL6')</script>`
   * Nút 3: `[📂 Path Traversal]` $\rightarrow$ Bắn `../../etc/passwd`
   * Nút 4: `[💻 Cmd Injection]` $\rightarrow$ Bắn `; whoami`
   * Nút 5: `[🍏 Benign Traffic]` $\rightarrow$ Bắn request tìm kiếm bình thường
   * *Ngay khi bấm, thông báo Toast xuất hiện, bảng sự kiện phía dưới tự động chèn dòng cảnh báo mới lên đầu trang.*

---

### 4.3. Đồ Thị Trực Quan Thời Gian Thực (Visual Analytics)
* **Traffic & Threat Timeline (Area Spline Chart - Recharts):**
  * Trục hoành là mốc thời gian (phút/giờ).
  * Vùng màu Cyan: Lưu lượng hợp lệ bình thường.
  * Vùng màu Rose: Số lượng đòn tấn công xuất hiện đột biến.
* **Threat Distribution (Donut Chart - Recharts):**
  * Tỷ lệ phần trăm các họ tấn công: `SQL Injection`, `XSS`, `Path Traversal`, `Command Injection`.

---

### 4.4. Bảng Nhật Ký Sự Kiện An Ninh (Live Security Events Table)
* **Bộ lọc và tìm kiếm:**
  * Tìm kiếm theo `Client IP`, `Request ID`, hoặc đường dẫn `Path`.
  * Lọc theo mức độ nghiêm trọng: `ALL`, `CRITICAL` (Đỏ), `HIGH` (Cam), `MEDIUM` (Vàng), `LOW` (Xanh).
  * Lọc theo họ tấn công: `ALL`, `SQL_INJECTION`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`.
* **Cột dữ liệu:** Thời gian, Request ID, Họ tấn công, Mức độ, Vị trí (PATH / QUERY / BODY / HEADER), Rule ID (`SQLI-001`), Điểm số (0-100), Hành động (`DETECTED`), Nút xem chi tiết.

---

### 4.5. Cửa Sổ Soi Chi Tiết Bằng Chứng (Payload Evidence Drawer)
Cửa sổ trượt ra từ cạnh phải màn hình khi bấm nút `[View]` ở một sự kiện, chia làm 2 tab:
* **Tab 1: Rule Engine Evidence (Phase 2 - Đang Hoạt Động 100%):**
  * Header request & Client IP.
  * Vị trí phát hiện (`Inspection Location`).
  * Đối chiếu chuỗi thô (`Raw Input`) vs Chuỗi đã chuẩn hóa (`Canonical Input`).
  * Tên rule, Regex pattern khớp và bằng chứng trích xuất (đã khử mật khẩu/token).
* **Tab 2: 17-Feature Vector (Dành Sẵn Cho Phase 3):**
  * Hiển thị sẵn khung bảng 17 đặc trưng (Độ dài, Shannon Entropy, Tỷ lệ ký tự đặc biệt, Keyword counts...).
  * Ngay khi Phase 3 hoàn thành, vector số học sẽ tự động hiển thị tại tab này mà không cần sửa giao diện.

---

## 5. ĐẶC TẢ CÁC REST API TRÊN GATEWAY (TASK 9.1)

### 1. `GET /api/dashboard/stats`
```json
{
  "total_requests": 1248,
  "attacks_detected": 142,
  "safe_requests": 1106,
  "safe_request_rate": 88.62,
  "avg_threat_score": 78.5,
  "target_status": "ok",
  "target_latency_ms": 12.4,
  "waf_mode": "MONITOR_ONLY",
  "active_phase": "Phase 2 (Rule Engine Active)"
}
```

### 2. `GET /api/dashboard/events?page=1&limit=10&severity=CRITICAL&attack_type=SQL_INJECTION`
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
      "details": {
        "rule_matches": [
          {
            "rule_id": "SQLI-001",
            "name": "SQL Injection Tautology",
            "severity": "CRITICAL",
            "location": "QUERY",
            "evidence": "q=' OR '1'='1"
          }
        ]
      }
    }
  ],
  "total": 142,
  "page": 1,
  "limit": 10
}
```

### 3. `GET /api/dashboard/timeline?minutes=30`
Trả về mảng chuỗi thời gian đếm số lượng requests và attacks theo từng mốc phút để vẽ đồ thị Area Chart.

### 4. `POST /api/dashboard/simulate`
Body: `{"attack_type": "SQLI" | "XSS" | "PATH" | "CMD" | "BENIGN"}`
Thực hiện bắn HTTP request thật qua `/api/proxy/...` để tạo sự kiện ngay lập tức.

---

## 6. LỘ TRÌNH TIẾN HÓA CỦA DASHBOARD THEO CÁC PHASE

| Giai đoạn | Trạng thái Dashboard | Những gì được bổ sung |
| :---: | :--- | :--- |
| **Phase 2 (Hiện tại)** | **Rule-based SOC Dashboard** | KPI Cards, Live Events, Threat Timeline, Payload Drawer, Simulator. |
| **Phase 3** | **Feature Vector Tab** | Bật hiển thị bảng 17 đặc trưng trong Drawer. |
| **Phase 5** | **Supervised ML Badge** | Hiển thị nhãn dự đoán của Random Forest & Confidence %. |
| **Phase 6** | **Anomaly Gauge** | Hiển thị thang đo Anomaly Score của Isolation Forest. |
| **Phase 7** | **Active Defense Mode** | Chuyển trạng thái sang `BLOCKED`, đổi nút hành động sang màu đỏ 403. |
| **Phase 8** | **Rate Limit Monitor** | Thêm biểu đồ RPS theo IP và bảng danh sách IP bị 429 tạm thời. |
| **Phase 10** | **AI Arena Tab** | Thêm tab đối kháng: Log suy luận của AI Attack Planner vs Phản ứng WAF. |
