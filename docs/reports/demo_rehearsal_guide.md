# 🎙️ HƯỚNG DẪN KỊCH BẢN THUYẾT TRÌNH & DIỄN TẬP THỰC CHIẾN 10 PHÚT (TASK 12.3)

> **Dự án:** Web API Security Platform & Adaptive Hybrid WAF (PBL6)  
> **Thời lượng kịch bản:** Đúng **10 Phút** chuẩn mực bảo vệ trước Hội đồng Chấm Đồ Án  
> **Công cụ điều khiển:** `scripts/demo_rehearsal.py`  
> **Mã công việc:** Task 12.3 (Issue #49)  
> **Tác giả:** `vcongggggg` (Thành viên A) & `naocavang08` (Thành viên B)

---

## 1. TỔNG QUAN PHÂN BỔ THỜI GIAN (10-MINUTE DEFENSE TIMELINE)

| Thời gian | Phân đoạn kịch bản | Thao tác trên máy chiếu / Terminal | Lời thoại thuyết trình trọng tâm |
| :---: | :--- | :--- | :--- |
| **0:00 - 1:00** | **Mở đầu & Bối cảnh** | Chiếu slide Kiến trúc Thao trường An ninh Đối kháng (Máy 1 Blue Team vs Máy 2 Red Team). | *"Kính thưa Thầy Cô Hội đồng, nhóm xây dựng giải pháp WAF Hybrid tích hợp AI đa tầng bảo vệ Web API tự làm chủ..."* |
| **1:00 - 3:00** | **Giai đoạn 1: Baseline Traffic** | Chạy `python scripts/demo_rehearsal.py`, thực hiện Stage 1. | *"Đầu tiên, hệ thống xử lý lưu lượng hợp lệ duyệt sách. Toàn bộ 100% request đạt HTTP 200, Threat Score = 0, độ trễ tối ưu."* |
| **3:00 - 5:30** | **Giai đoạn 2: Tấn công Monitor-Only** | Chạy Stage 2, mở song song giao diện Dashboard (:3000). | *"Khi chuyển WAF sang Monitor-Only, 4 họ tấn công SQLi, XSS, LFI, RCE lập tức bị bắt, tính Risk Score 95/100 và báo động đỏ thời gian thực."* |
| **5:30 - 7:30** | **Giai đoạn 3: Active Blocking** | Chạy Stage 3, kích hoạt phòng thủ chủ động. | *"Chuyển WAF sang Active Block: WAF kích hoạt cơ chế Fast-Path chặn đứng 100% payload bằng HTTP 403 Forbidden trong < 2ms, bảo vệ an toàn cho Bookie Bookstore."* |
| **7:30 - 9:00** | **Giai đoạn 4: Rate Limiting** | Chạy Stage 4, kích hoạt bão request Brute-force. | *"Đối với tấn công dò mật khẩu tần suất cao, bộ Sliding Window giới hạn 10 req/min và phạt HTTP 429 kèm Exponential Backoff theo RFC 6585."* |
| **9:00 - 10:00** | **Tổng kết & Explainability** | Mở Explainability Modal và Evidence Drawer trên Dashboard. | *"Mọi quyết định của WAF đều minh bạch: giải trình chi tiết từng luật và đặc trưng AI 17-D. Sẵn sàng nhận câu hỏi phản biện từ Hội đồng."* |

---

## 2. KỊCH BẢN CHI TIẾT TỪNG PHÚT & LỜI THOẠI MẪU (SPEAKER SCRIPT)

### 🟢 Phút 0:00 - 1:00: Giới thiệu Thao trường & Khởi động
* **Hành động:** 
  - Mở 2 cửa sổ: Một bên là Terminal chạy `python scripts/demo_rehearsal.py --interactive`, một bên là trình duyệt mở Dashboard `http://localhost:3000`.
* **Lời thoại:**
  > *"Kính thưa quý Thầy Cô trong Hội đồng chấm đồ án tốt nghiệp PBL6, hôm nay nhóm xin phép biểu diễn kịch bản thực chiến trực tiếp giữa hệ thống phòng thủ WAF Gateway tích hợp AI đa tầng và ứng dụng mục tiêu Bookie Bookstore. Toàn bộ hệ thống chạy trên môi trường thực tế, không sử dụng dữ liệu giả lập tĩnh."*

---

### 🟢 Phút 1:00 - 3:00: Giai đoạn 1 — Đo kiểm Baseline Lưu lượng Hợp lệ
* **Hành động:**
  - Nhấn `[ENTER]` trên Terminal để kích hoạt Stage 1.
* **Màn hình hiển thị:**
  - 5 request tìm kiếm sách ('Python', 'Security') chuyển tiếp thành công với mã `200 OK`, Threat Score = 0.
* **Lời thoại:**
  > *"Trong giai đoạn 1, hệ thống tiếp nhận các luồng nghiệp vụ thông thường của người dùng như tìm kiếm sách và duyệt catalog. Như Thầy Cô có thể quan sát, Gateway hoạt động hoàn toàn trong suốt (Transparent Proxy), chuyển tiếp 100% request với mã HTTP 200 OK và điểm rủi ro Threat Score bằng 0, không gây ảnh hưởng đến trải nghiệm người dùng."*

---

### 🟡 Phút 3:00 - 5:30: Giai đoạn 2 — Phát hiện Tấn công ở Chế độ Giám sát (MONITOR_ONLY)
* **Hành động:**
  - Nhấn `[ENTER]` để chuyển sang Stage 2.
  - Chuyển tab sang Next.js Dashboard để chỉ vào bảng Live Events.
* **Màn hình hiển thị:**
  - 5 payload tấn công (SQLi Auth Bypass, UNION query, XSS, Path Traversal, Command Injection) bị gắn cờ `FLAGGED`, điểm rủi ro `95/100`, dòng trạng thái nhấp nháy đỏ trên Dashboard.
* **Lời thoại:**
  > *"Tại Giai đoạn 2, nhóm mô phỏng tình huống WAF hoạt động ở chế độ Giám sát (Monitor-Only) - tương đương giai đoạn huấn luyện và tiền triển khai của doanh nghiệp. Khi kẻ tấn công bắn các payload SQL Injection, XSS hay Path Traversal, WAF trích xuất 17 đặc trưng hình thái, đối soát qua 16 luật tĩnh và mô hình Random Forest. Điểm rủi ro được chấm tức thời ở mức 95/100 và ghi nhận sự kiện an ninh vào cơ sở dữ liệu SQLite, xuất hiện trực tiếp trên giao diện Dashboard mà không ngắt kết nối của ứng dụng."*

---

### 🔴 Phút 5:30 - 7:30: Giai đoạn 3 — Kích hoạt Chặn Đứng Chủ Động (ACTIVE_BLOCK)
* **Hành động:**
  - Nhấn `[ENTER]` để chuyển sang Stage 3.
* **Màn hình hiển thị:**
  - Trạng thái Gateway chuyển thành `ACTIVE_BLOCK (SIẾT CHẶT TỐI ĐA)`.
  - Các cuộc tấn công tinh vi né tránh (URL Encoded SQLi, SVG XSS, LFI Escapes) bị chặn đứng với mã `[403 FORBIDDEN]` và độ trễ Fast-path cực nhanh.
* **Lời thoại:**
  > *"Bây giờ nhóm kích hoạt chế độ Phòng thủ Chủ động (Active Block). Cơ chế Fast-path của WAF lập tức ngắt kết nối kẻ tấn công ngay tại tầng Proxy, phản hồi HTTP 403 Forbidden với độ trễ xử lý nội bộ chỉ xấp xỉ 1.85 mili-giây. Upstream Target API được che chắn tuyệt đối, mã độc hoàn toàn không có cơ hội chạm tới cơ sở dữ liệu."*

---

### 🟣 Phút 7:30 - 9:00: Giai đoạn 4 — Chống Brute-force & Điều tiết Hạn mức (RATE_LIMIT)
* **Hành động:**
  - Nhấn `[ENTER]` để chuyển sang Stage 4.
* **Màn hình hiển thị:**
  - 14 requests dò mật khẩu dồn dập vào `/api/v1/vulnerable/auth/login/`.
  - Request 1-9 được xử lý bình thường. Từ request 10 trở đi, WAF lập tức trả về `[429 TOO MANY REQUESTS]` kèm tiêu đề `Retry-After: 60s`.
* **Lời thoại:**
  > *"Tại Giai đoạn 4, nhóm chứng minh năng lực phòng vệ trước tấn công Brute-force và quét lỗ hổng tự động. Theo quy chuẩn OWASP API4:2023 và RFC 6585, endpoint nhạy cảm auth/login bị khống chế tối đa 10 req/phút bằng thuật toán Sliding Window Counter O(1). Khi chạm ngưỡng vi phạm, hệ thống kích hoạt trừng phạt Exponential Backoff, bắt buộc client phải chờ đợi, triệt tiêu hoàn toàn botnet tự động."*

---

### 🔵 Phút 9:00 - 10:00: Tổng kết Viễn trắc & Khả năng Giải trình (Explainability)
* **Hành động:**
  - Chuyển sang trình duyệt Dashboard `http://localhost:3000`.
  - Click vào 1 dòng sự kiện SQL Injection để mở **Explainability Modal**.
  - Mở **Evidence Drawer** để Hội đồng thấy Payload giải mã và 17 đặc trưng vector hóa.
* **Lời thoại:**
  > *"Để kết thúc phần biểu diễn, nhóm xin trình chiếu năng lực Giải trình Quyết định (Explainability AI). Khác với các mô hình hộp đen truyền thống, Dashboard cung cấp chi tiết: tại sao mẫu này bị chấm 95 điểm, tỷ trọng đóng góp của độ dài payload, Shannon entropy, số ký tự đặc biệt, và kết quả suy luận của Random Forest. Bảng điểm tổng kết hiển thị 100% tấn công bị chặn đứng, bảo toàn tính sẵn sàng của hệ thống. Nhóm xin chân thành cảm ơn Thầy Cô và sẵn sàng lắng nghe câu hỏi phản biện ạ!"*

---

## 3. CHEAT SHEET CÁC LỆNH VẬN HÀNH NHANH (CLI COMMANDS)

```bash
# 1. Chạy diễn tập tương tác từng bước (Khuyên dùng khi bảo vệ):
python scripts/demo_rehearsal.py --interactive

# 2. Chạy tự động có nhịp nghỉ (Khi chạy thử hoặc demo nhanh):
python scripts/demo_rehearsal.py --auto --interval 1.5

# 3. Reset dữ liệu demo trên Dashboard trước giờ bảo vệ:
curl -X POST http://localhost:8000/api/dashboard/reset-demo

# 4. Bơm sẵn 50 mẫu demo kiểm chứng nếu cần:
curl -X POST http://localhost:8000/api/dashboard/seed-demo
```
