# BÁO CÁO CƠ SỞ KHOA HỌC VÀ ĐẶC TẢ HỌC THUẬT: BẢNG NHẬT KÝ SỰ KIỆN AN NINH THỜI GIAN THỰC VÀ BỘ THANH TRA PAYLOAD EVIDENCE (TASK 9.3)

> **Dự án:** Nghiên cứu và Xây dựng Hệ thống Tường lửa Ứng dụng Web (WAF) và Giám sát An ninh API Gateway Thông minh  
> **Phân hệ:** Phase 9 — Security Dashboard UI & Real-Time Threat Visualization  
> **Nhiệm vụ:** Task 9.3 — Interactive Security Events Table with Filter, Search & Payload Viewer  
> **Tác giả:** Thành viên A (`vcongggggg`) — Kỹ sư An toàn Thông tin / Tech Lead  
> **Tiêu chuẩn tham chiếu:** NIST SP 800-92, NIST SP 800-86, OWASP API10:2023, MITRE ATT&CK  

---

## 1. ĐẶT VẤN ĐỀ VÀ BỐI CẢNH PHÁP CHỨNG SỰ CỐ (DIGITAL FORENSICS)

Trong chu trình phản ứng sự cố an ninh mạng (Incident Response Lifecycle), bước phân tích và điều tra nguyên nhân gốc rễ (Root-Cause Analysis) đóng vai trò sống còn nhằm ngăn chặn kẻ tấn công tiếp tục leo thang đặc quyền hoặc duy trì quyền truy cập trái phép.

Theo tiêu chuẩn **NIST SP 800-92 (Guide to Computer Security Log Management)** và **NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response)**:
1. Mọi bản ghi vi phạm an ninh phải được lưu vết đầy đủ dấu ấn thời gian (Timestamp), định danh tác nhân (Client IP Address kèm thông tin định tuyến mạng LAN/WAN), và mã định danh phiên phân tán duy nhất (`request_id` - UUIDv4) phục vụ điều tra chéo.
2. Hệ thống phòng thủ phải hỗ trợ khả năng phân tích pháp chứng sâu (Deep Payload Inspection): Đối sánh trực quan giữa dữ liệu thô kẻ tấn công gửi tới (*Raw Input*) và dữ liệu sau khi giải mã chuẩn hóa (*Canonical Decoded Input*) để vạch trần các thủ đoạn làm mờ payload (Obfuscation / Encoding Evasion).
3. Đảm bảo tuân thủ khuyến nghị **OWASP API Security Top 10 (API10:2023 - Insufficient Logging & Monitoring, CWE-778)** bằng việc cung cấp giao diện tương tác linh hoạt cho chuyên viên SOC: Phân trang, tìm kiếm mờ, lọc đa chiều, và trích xuất dữ liệu chứng cứ (Evidence Export).

---

## 2. THIẾT KẾ BẢNG SỰ KIỆN AN NINH THỜI GIAN THỰC (LIVE EVENTS TABLE)

Bảng sự kiện `LiveEventsTable.tsx` được thiết kế theo phong cách Cyber Glassmorphism với khả năng hiển thị dữ liệu viễn trắc an ninh đa chiều:

### 2.1. Cấu Trúc Các Trường Viễn Trắc An Ninh
Mỗi sự kiện hiển thị trên bảng bao gồm 9 cột thông tin chuẩn hóa:
1. **Time:** Thời điểm phát hiện sự kiện (định dạng `HH:MM:SS` theo múi giờ hệ thống).
2. **Client IP (Origin):** Địa chỉ IP nguồn kèm nhãn phân biệt thông minh:
   - `LAN Attacker (Red Team - Máy 2)`: Đối với các dải mạng nội bộ `192.168.x.x`, `10.x.x.x`, `172.x.x.x` phản ánh cuộc tấn công từ Máy 2 trong Thao trường Đối kháng.
   - `Localhost / Gateway`: Đối với `127.0.0.1`.
3. **Request ID:** Mã định danh truy vết duy nhất, hỗ trợ sao chép 1-click để tìm kiếm trên các hệ thống giám sát khác.
4. **Attack Type:** Phân loại họ tấn công với mã màu nhận diện đặc trưng (SQLi - Xanh lam, XSS - Đỏ hồng, Path Traversal - Xanh lục, Command Injection - Vàng cam).
5. **Severity:** Mức độ nghiêm trọng định lượng (CRITICAL, HIGH, MEDIUM, LOW) theo thang điểm CVSS v3.1.
6. **Location:** Vị trí xuất hiện mã độc (QUERY, JSON BODY, FORM, PATH, SAFE_HEADERS).
7. **Rule ID:** Mã quy tắc nhận dạng tương ứng trong Rule Catalog (ví dụ: `SQLI-001`, `XSS-003`).
8. **Threat & Risk Score:** Hiển thị điểm rủi ro tổng hợp đa tầng $S_{\text{risk}} \in [0, 100]$ từ Phase 7 (hoặc điểm luật $S_{\text{rule}}$ từ Phase 2).
9. **Action & Explainability:** Nhãn hành động thực thi an ninh (`BLOCKED 403` hoặc `THROTTLED 429`) kèm nút kích hoạt Modal giải thích quyết định phòng thủ (Detection Explainability Modal - Task 9.4).

### 2.2. Khả Năng Tương Tác và Lọc Dữ Liệu Đa Chiều
- **Bộ lọc Severity:** `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- **Bộ lọc Attack Type:** `ALL`, `SQL_INJECTION`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`.
- **Tìm kiếm mờ (Search Query):** Lọc tức thời theo Client IP hoặc Request ID.
- **Xuất dữ liệu chứng cứ (Evidence Export):** Tải về toàn bộ danh sách sự kiện dưới định dạng chuẩn `JSON` phục vụ lưu trữ pháp chứng hoặc lập báo cáo gửi Ban Giám đốc/Hội đồng.

---

## 3. CƠ SỞ KHOA HỌC CỦA CỬA SỔ THANH TRA PAYLOAD EVIDENCE (PAYLOAD DRAWER)

Cửa sổ trượt `PayloadEvidenceDrawer.tsx` cung cấp môi trường thanh tra pháp chứng chuyên sâu với cấu trúc 2 Tab phân tích:

### 3.1. Tab 1: Thanh Tra Pháp Chứng Luật & Ánh Xạ Chuẩn Quốc Tế (Rule Evidence & Threat Intelligence)
1. **Đối sánh Raw Input vs Canonical Input:**
   - Làm rõ cơ chế bóc tách mã hóa (URL Decoding, Base64 Decoding, HTML Entity Decoding, Null-byte Stripping) của Rule Engine (Phase 2), chứng minh khả năng triệt tiêu các kỹ thuật né tránh WAF (WAF Evasion / Obfuscation).
2. **Ánh Xạ Cơ Sở Tri Thức An Ninh Toàn Cầu (Threat Intelligence Mapping):**
   - **SQL Injection:** Ánh xạ CWE-89 (Improper Neutralization of Special Elements used in an SQL Command), CAPEC-66 (SQL Injection), MITRE ATT&CK T1190 (Exploit Public-Facing Application).
   - **Cross-Site Scripting:** Ánh xạ CWE-79 (Improper Neutralization of Input During Web Page Generation), CAPEC-63 (Cross-Site Scripting), MITRE ATT&CK T1059 (Command and Scripting Interpreter).
   - **Path Traversal / LFI:** Ánh xạ CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CAPEC-126 (Path Traversal), MITRE ATT&CK T1083 (File and Directory Discovery).
   - **Command Injection:** Ánh xạ CWE-78 (Improper Neutralization of Special Elements used in an OS Command), CAPEC-88 (OS Command Injection), MITRE ATT&CK T1059 (Command and Scripting Interpreter).

### 3.2. Tab 2: Trực Quan Hóa Vector 17 Đặc Trưng Học Máy (Explainable ML Feature Vector)
Phục vụ tính minh bạch của mô hình AI (Explainable AI - XAI), Tab này hiển thị chi tiết 17 đặc trưng được trích xuất từ payload (Phase 3):
- **12 Đặc Trưng Hình Thái & Entropy (`ml-engine/features/morphological.py`):**
  - Chiều dài chuỗi (`length`), tỷ lệ ký tự đặc biệt (`special_char_ratio`), tỷ lệ chữ số (`digit_ratio`), entropy thông tin Shannon (`entropy`), độ dài token dài nhất (`max_token_length`), tỷ lệ khoảng trắng (`whitespace_ratio`), tỷ lệ ký tự in hoa (`uppercase_ratio`), số lượng ký tự không in được (`non_printable_count`),...
- **5 Đặc Trưng Từ Khóa Tấn Công (`ml-engine/features/attack_keywords.py`):**
  - Tần suất xuất hiện từ khóa SQLi (`sqli_keyword_count`), XSS (`xss_keyword_count`), Path Traversal (`path_traversal_count`), Command Injection (`cmd_injection_count`), và cờ phát hiện ký tự nguy hiểm (`has_sql_comment`, `has_script_tag`).

---

## 4. KIỂM THỬ THẨM ĐỊNH VÀ HIỆU NĂNG GIAO DIỆN (VERIFICATION)

- **Biên dịch Frontend (Next.js 14.2.35 Production Build):**
  - Trạng thái: `✓ Compiled successfully`.
  - Type-checking & Linting: **0 errors, 0 warnings**.
  - Static Page Generation: **4 / 4 pages generated**.
  - Kích thước Bundle: **87.3 kB** (First Load JS shared by all).
- **Trải Nghiệm Người Dùng (UX & Accessibility):**
  - Hỗ trợ phím tắt `Escape` tự động đóng Drawer.
  - Hiệu ứng chuyển động mượt mà (Slide-in Drawer transition).
  - Tự động reset bộ lọc chỉ bằng 1-click (`Reset Filters`).

---

## 5. TÀI LIỆU THAM KHẢO (REFERENCES)

1. **National Institute of Standards and Technology (NIST) (2006).** *Guide to Computer Security Log Management.* NIST Special Publication 800-92. DOI: 10.6028/NIST.SP.800-92.
2. **National Institute of Standards and Technology (NIST) (2008).** *Guide to Integrating Forensic Techniques into Incident Response.* NIST Special Publication 800-86. DOI: 10.6028/NIST.SP.800-86.
3. **OWASP Foundation (2023).** *OWASP API Security Top 10 2023 — API10:2023 Insufficient Logging & Monitoring.* OWASP Foundation.
4. **MITRE Corporation (2024).** *MITRE ATT&CK® Enterprise Matrix: Exploit Public-Facing Application (T1190) & Command and Scripting Interpreter (T1059).*
