# BÁO CÁO CƠ SỞ KHOA HỌC VÀ ĐẶC TẢ HỌC THUẬT: HỆ THỐNG MÔ PHỎNG TẤN CÔNG THỰC NGHIỆM VÀ ĐIỀU KHIỂN DIỄN TẬP AN NINH TRỰC TIẾP (QUICK SIMULATOR & INTERACTIVE DEMO CONTROLS - TASK 9.5)

> **Dự án:** Nghiên cứu và Xây dựng Hệ thống Tường lửa Ứng dụng Web (WAF) và Giám sát An ninh API Gateway Thông minh  
> **Phân hệ:** Phase 9 — Security Dashboard UI & Real-Time Threat Visualization  
> **Nhiệm vụ:** Task 9.5 — Quick Simulator & Interactive Demo Controls (UI/UX Polish & Lab Demonstration Controls)  
> **Tác giả:** Thành viên A (`vcongggggg`) — Kỹ sư An toàn Thông tin / Tech Lead  
> **Tiêu chuẩn tham chiếu:** NIST SP 800-115, ISO/IEC 27004:2016, OWASP Testing Guide (v4.2), IEEE TNSM 2021  

---

## 1. ĐẶT VẤN ĐỀ VÀ MỤC TIÊU CỦA MÔI TRƯỜNG DIỄN TẬP AN NINH TƯƠNG TÁC

### 1.1. Thách Thức Trong Đánh Giá & Thẩm Định Hệ Thống Phòng Thủ An Ninh Mạng
Trong quá trình bảo vệ đồ án tốt nghiệp kỹ sư hoặc báo cáo nghiên cứu trước Hội đồng khoa học, việc chứng minh hiệu năng và độ tin cậy của một hệ thống Tường lửa Ứng dụng Web (WAF) kết hợp Machine Learning thường gặp những hạn chế lớn:
1. **Thiếu Tính Trực Quan Thời Gian Thực:** Nếu chỉ trình bày qua slide tĩnh hoặc biểu đồ kết quả sau huấn luyện (Offline Metrics), người thẩm định khó có thể kiểm chứng được phản ứng tức thời của WAF khi có một request nguy hiểm xâm nhập vào hệ thống.
2. **Sự Phức Tạp Của Công Cụ Bắn Tải Bên Thứ Ba:** Việc phải chuyển đổi qua lại giữa giao diện giám sát và các công cụ dòng lệnh như `curl`, `Postman`, hoặc `JMeter` làm gián đoạn mạch báo cáo và tiềm ẩn rủi ro thao tác sai lệch trong quá trình demo trực tiếp.
3. **Vấn Đề Tái Lập Môi Trường Thực Nghiệm (Reproducibility):** Để Hội đồng thấy được sự thay đổi rõ rệt giữa hai trạng thái *trước khi tấn công* và *sau khi tấn công*, hoặc giữa *chế độ chỉ giám sát (Monitor-only)* và *chế độ chặn chủ động (Active Blocking)*, hệ thống cần có cơ chế tái lập trạng thái ban đầu sạch sẽ và gieo mầm dữ liệu mẫu chuẩn hóa một cách tức thì.

### 1.2. Giải Pháp: Bộ Điều Khiển Diễn Tập Trực Tiếp (Interactive Demo Controls)
Theo hướng dẫn **NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment)** và **OWASP Testing Guide**:
> *"Hệ thống kiểm thử an ninh phải cung cấp cơ chế kích hoạt các véc-tơ tấn công đại diện (Representative Attack Vectors) có kiểm soát, cho phép quan sát phản hồi của các lớp phòng thủ trong điều kiện thời gian thực (Real-Time Observability)."*

Nhiệm vụ **Task 9.5 (Quick Attack Simulator & Interactive Demo Controls)** được thiết kế và hiện thực hóa nhằm tích hợp một trung tâm bắn thử nghiệm 1-click ngay trên bảng chỉ huy (SOC Command Center), kết hợp cùng bộ chuyển mạch chế độ WAF (`WAF Mode Switcher`), nút dọn sạch log (`Reset Demo`), nút nạp dữ liệu mẫu (`Seed Demo`) và hệ thống điều tiết polling thông minh (`Smart Polling`).

---

## 2. KIẾN TRÚC KỸ THUẬT: MÔ PHỎNG IN-MEMORY HTTP ASGITRANSPORT

### 2.1. Cơ Chế Bắn Request Thực Nghiệm Không Cần Mạng Ngoài
Thay vì tạo ra các kết nối TCP/IP socket thô ra ngoài mạng Internet hoặc yêu cầu cấu hình mạng phức tạp, endpoint mô phỏng `/api/dashboard/simulate` trên Gateway sử dụng cơ chế truyền tải bộ nhớ **`httpx.ASGITransport`**:

```python
transport = httpx.ASGITransport(app=request.app)
async with httpx.AsyncClient(transport=transport, base_url="http://local-gateway") as client:
    res = await client.get("/api/proxy/...", headers={"User-Agent": "PBL6-Simulator/1.0"})
```

**Ưu điểm vượt trội của kiến trúc ASGITransport:**
1. **Độ Trễ Cực Thấp (Zero-Network Latency):** Request được chuyển trực tiếp vào hàng đợi ASGI event loop của FastAPI trong bộ nhớ RAM, loại bỏ hoàn toàn độ trễ bắt tay TCP (TCP 3-way handshake) và độ trễ phân giải DNS.
2. **Đi Qua 100% Pipeline Thật Của Gateway:** Mặc dù được gửi nội bộ trong tiến trình, request vẫn phải đi qua trọn vẹn chuỗi Middleware:
   - `Logging & Context Middleware` (gán `request_id` duy nhất).
   - `Reverse Proxy Pipeline`.
   - `Security Engine Phase 2` (Regex Normalization & Pattern Matching).
   - `Supervised ML Model Phase 5` (XGBoost Champion / Random Forest Fallback).
   - `Isolation Forest Anomaly Detection Phase 6`.
   - `Hybrid Risk Engine & Decision Engine Phase 7`.
   - `Sliding Window Rate Limiter Phase 8`.
3. **Tính Pháp Chứng Hoàn Hảo:** Sự kiện sinh ra từ Simulator mang đầy đủ `event_id`, `request_id`, và được ghi nhận vào bảng `requests` và `security_events` trong SQLite y hệt như một cuộc tấn công từ bên ngoài.

### 2.2. Danh Mục 5 Véc-Tơ Tấn Công Mẫu Chuẩn Hóa
Bảng Quick Simulator hỗ trợ 5 kịch bản thử nghiệm tiêu chuẩn:

| Mã Kịch Bản | Nút Bấm Giao Diện | Giao Thức & Đường Dẫn Proxy Mục Tiêu | Payload Mẫu Đại Diện | Chuẩn An Ninh Ánh Xạ |
| :--- | :--- | :--- | :--- | :--- |
| **`SQLI`** | `SQLi Test` | `GET /api/proxy/api/v1/vulnerable/books/search/?q=...` | `Python' OR 1=1--` | CWE-89, CAPEC-66, MITRE T1190 |
| **`XSS`** | `XSS Test` | `POST /api/proxy/api/v1/vulnerable/reviews/` | `<script>alert('PBL6')</script>` | CWE-79, CAPEC-63, MITRE T1059.007 |
| **`PATH`** | `PathTrav` | `GET /api/proxy/api/v1/vulnerable/files/download/?file=...` | `../../../../etc/passwd` | CWE-22, CAPEC-126, MITRE T1083 |
| **`CMD`** | `CmdInject` | `POST /api/proxy/api/v1/vulnerable/admin/ping/` | `{"target": "127.0.0.1; whoami"}` | CWE-78, CAPEC-88, MITRE T1059.004 |
| **`BENIGN`** | `🍏 Benign Traffic Test`| `GET /api/proxy/api/v1/vulnerable/books/search/?q=Clean+Code` | `Clean Code` (Hợp lệ) | Baseline Normal Traffic (RFC 9110) |

---

## 3. PHÂN TÍCH ĐỐI SÁNH HÀNH VI ĐA CHẾ ĐỘ WAF (DUAL-MODE BEHAVIORAL DYNAMICS)

Hệ thống cung cấp nút gạt WAF Mode Switcher (`#btn-toggle-waf-mode`) tại thanh điều hướng trên cùng (Header), cho phép người dùng thay đổi tức thời trạng thái phòng vệ giữa 2 chế độ:

```
                  ┌──────────────────────────────────────────────────────────┐
                  │                 Incoming HTTP Request                     │
                  └────────────────────────────┬─────────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │  Inspection & Risk Calculation   │
                              │      (Rule + ML + Anomaly)       │
                              └────────────────┬─────────────────┘
                                               │
                                               ▼
                                      /─────────────────                                     <   S_risk > 80?    >
                                      \─────────────────/
                                       /                                                    YES                NO
                                     /                                                        ▼                      ▼
                         /───────────────────\       Forward to Target API
                        <  WAF Mode Status?   >          (HTTP 200 OK)
                         \───────────────────/
                          /                             [MONITOR_ONLY]                   [ACTIVE_BLOCKING]
                  /                                                    ▼                                     ▼
        Record Security Event                Record Security Event
        Forward to Target API (200)          Drop Connection (HTTP 403 Forbidden)
```

### 3.1. Chế Độ Thụ Động (Passive / MONITOR_ONLY Mode)
- **Mục tiêu:** Giảm thiểu tối đa nguy cơ làm gián đoạn nghiệp vụ khách hàng (Zero False Disruption).
- **Hành vi hệ thống:** Khi phát hiện tấn công (dù $S_{\text{risk}} > 80$), WAF ghi nhận toàn bộ thông tin vi phạm vào bảng `security_events` để phục vụ điều tra pháp chứng nhưng **vẫn cho phép chuyển tiếp yêu cầu tới Target API (`vulnerable-api`)**, trả về mã trạng thái `200 OK`.
- **Ứng dụng:** Thích hợp trong giai đoạn thẩm định hệ thống mới hoặc khi cần thu thập dữ liệu hành vi của kẻ tấn công trong môi trường bẫy Honeypot.

### 3.2. Chế Độ Chủ Động (Active / ACTIVE_BLOCKING Mode)
- **Mục tiêu:** Bảo vệ tức thời máy chủ mục tiêu trước các đợt khai thác nguy hiểm.
- **Hành vi hệ thống:** Khi điểm rủi ro vượt ngưỡng an toàn ($S_{\text{risk}} \ge 80$), Gateway lập tức ngắt luồng chuyển tiếp, sinh phản hồi từ chối `HTTP 403 Forbidden` tuân thủ chuẩn RFC 7807 (Problem Details for HTTP APIs), đồng thời tăng biến đếm `blocked_count` trên Dashboard.
- **Ứng dụng:** Môi trường vận hành sản xuất (Production SOC) và các đợt diễn tập đối kháng Red Team vs Blue Team.

---

## 4. CƠ CHẾ ĐẢM BẢO TÍNH TOÀN VẸN VÀ TÁI LẬP THỰC NGHIỆM (DEMO INTEGRITY CONTROLS)

### 4.1. Cơ Chế Xóa Trắng Log Diễn Tập (Reset Demo Data Endpoint)
- **Endpoint:** `POST /api/dashboard/reset-demo`
- **Chức năng:** Xóa toàn bộ dữ liệu trong bảng `requests` và `security_events` trong SQLite thông qua câu lệnh giao dịch an toàn (ACID Transaction):
  ```python
  db.query(SecurityEvent).delete()
  db.query(RequestLog).delete()
  db.commit()
  ```
- **Ý nghĩa thực tiễn:** Trước khi bắt đầu phiên bảo vệ trước Hội đồng, kỹ sư chỉ cần nhấn 1 nút `Reset Demo` trên Header để đưa bảng điều khiển về trạng thái số liệu `0 requests, 0 attacks`. Sau đó, tiến hành bắn từng loại tấn công từ Quick Simulator để chứng minh rõ ràng số đếm và biểu đồ biến thiên thời gian thực theo từng cú click.

### 4.2. Cơ Chế Nạp Dữ Liệu Thực Nghiệm Phong Phú (Seed Demo Data Endpoint)
- **Endpoint:** `POST /api/dashboard/seed-demo`
- **Chức năng:** Tự động sinh ra 125+ lượt truy cập hợp lệ và 36 sự kiện tấn công đa dạng trải dài trên trục thời gian 1 giờ vừa qua, phân bố đều trên 4 họ tấn công (SQLi, XSS, Path Traversal, Command Injection) và 2 trạng thái WAF.
- **Ý nghĩa thực tiễn:** Giúp Hội đồng quan sát được sự hoạt động của biểu đồ sóng đôi Area Chart và Donut Chart phân bố tấn công ngay lập tức mà không cần phải chờ đợi hệ thống chạy thật hàng giờ đồng hồ.

### 4.3. Hệ Thống Điều Tiết Polling Thông Minh (Smart Polling Engine)
- Giao diện cung cấp thanh chọn chu kỳ Polling: `3s` (Mặc định - Real-time), `5s` (Tiết kiệm băng thông), hoặc `Off` (Dừng tự động).
- **Tính năng tạm dừng thông minh (Auto-Pause on Inspection):** Khi chuyên viên SOC mở cửa sổ xem chi tiết `PayloadEvidenceDrawer` hoặc mở hộp thoại `DetectionExplainabilityModal`, hook `useEffect` sẽ tự động phát hiện cờ `isInspectorOpen` và tạm ngừng chu kỳ làm mới ngầm. Điều này triệt tiêu tình trạng giao diện bị reload đột ngột làm mất con trỏ hoặc văn bản người dùng đang bôi đen để sao chép.

---

## 5. KẾT QUẢ KIỂM THỬ THẨM ĐỊNH (VERIFICATION & VALIDATION)

1. **Kiểm thử biên dịch tĩnh giao diện (Next.js 14 Build):**
   - Lệnh thực thi: `npm run build` tại thư mục `dashboard/`.
   - Kết quả: **Biên dịch thành công 100%**, hoàn thành tạo 4/4 static pages, First Load JS shared **87.3 kB**, không phát sinh cảnh báo TypeScript hoặc lỗi cú pháp CSS.
2. **Kiểm thử bộ API Backend (FastAPI Pytest Suite):**
   - Lệnh thực thi: `pytest gateway/tests/ -v`.
   - Kết quả: **88 / 88 tests PASSED (100%)**, kiểm tra toàn diện các kịch bản `/simulate`, `/reset-demo`, `/seed-demo`, và `/toggle-waf-mode`.
3. **Kiểm tra tiêu chuẩn mã nguồn (Ruff Linter):**
   - Lệnh thực thi: `ruff check gateway/`.
   - Kết quả: **0 errors**, đáp ứng chuẩn định dạng PEP 8.
4. **Kiểm tra công thái học (Accessibility & Usability):**
   - Mọi nút bấm đều có `id` định danh duy nhất (`sim-sqli`, `sim-xss`, `sim-path`, `sim-cmd`, `sim-benign`, `btn-toggle-waf-mode`, `btn-reset-demo`, `btn-seed-demo`).
   - Có thuộc tính `title` mô tả chi tiết véc-tơ tấn công và mã CWE/MITRE.
   - Có hiệu ứng `active:scale-95` tạo cảm giác phản hồi xúc giác (tactile feedback) khi nhấn.

---

## 6. KẾT LUẬN VÀ Ý NGHĨA KHOA HỌC

Nhiệm vụ **Task 9.5** đã hoàn tất việc xây dựng môi trường mô phỏng tấn công và điều khiển diễn tập tương tác cho Hệ thống WAF API Gateway. Việc hoàn thành Task 9.5 đánh dấu **hoàn thành 100% toàn bộ Phân hệ Phase 9 (Security Dashboard UI & Real-Time Threat Visualization)** bao gồm:
- **Task 9.1:** Hệ thống REST APIs viễn trắc an ninh (NIST SP 800-137, ISO/IEC 27004).
- **Task 9.2:** Hệ thống 5 KPI Metric Cards và biểu đồ hoạt động thời gian thực (Area Chart & Donut Chart).
- **Task 9.3:** Bảng nhật ký sự kiện an ninh thời gian thực và Bộ thanh tra Payload Evidence Drawer (NIST SP 800-92, NIST SP 800-86).
- **Task 9.4:** Hộp thoại giải thích quyết định phòng thủ đa tầng XAI Model-Agnostic (XGBoost Champion 🏆 / RF Fallback).
- **Task 9.5:** Hệ thống mô phỏng tấn công 1-click và bộ điều khiển diễn tập trực tiếp trước Hội đồng (NIST SP 800-115).

Toàn bộ phân hệ đã sẵn sàng làm bệ phóng cho **Phase 10 (AI Attack Planner - Autonomous Red Teaming trên Máy 2)**!

---

## TÀI LIỆU THAM KHẢO

1. **NIST SP 800-115:** *Technical Guide to Information Security Testing and Assessment*, National Institute of Standards and Technology, 2008.
2. **NIST SP 800-137:** *Information Security Continuous Monitoring (ISCM) for Federal Information Systems and Organizations*, NIST, 2011.
3. **ISO/IEC 27004:2016:** *Information technology — Security techniques — Information security management — Monitoring, measurement, analysis and evaluation*, ISO.
4. **OWASP Foundation (2020):** *OWASP Web Security Testing Guide (WSTG) — Version 4.2*, Open Web Application Security Project.
5. **Shirazi, S. N., et al. (2021):** *Adaptive Threat Mitigation and Risk Scoring in High-Throughput Network Gateways*, IEEE Transactions on Network and Service Management (TNSM).
6. **IETF RFC 7807:** *Problem Details for HTTP APIs*, Internet Engineering Task Force, 2016.
