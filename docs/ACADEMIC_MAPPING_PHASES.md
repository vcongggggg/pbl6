# BẢNG ĐỐI CHIẾU CƠ SỞ KHOA HỌC & CÁC CÔNG TRÌNH NGHIÊN CỨU THEO TỪNG TASK DỰ ÁN (ACADEMIC PAPER MAPPING)

> **Dự án:** Web API Security Platform & Autonomous Red Teaming on Distributed Cyber Range (PBL6 - 2026)  
> **Tài liệu tham khảo chính thức:** [docs/REFERENCES.md](file:///c:/Study/HocKy6/PBL6/docs/REFERENCES.md) (20 Papers/Standards)  
> **Báo cáo đối chiếu chuyên sâu:** [docs/ACADEMIC_DEEP_DIVE_GAP_ANALYSIS.md](file:///c:/Study/HocKy6/PBL6/docs/ACADEMIC_DEEP_DIVE_GAP_ANALYSIS.md)  
> **Mục đích:** Tài liệu này phân rã chi tiết từng Phase, từng Task kỹ thuật của hệ thống và đối chiếu trực tiếp với các bài báo khoa học (USENIX, IEEE, ACM, MDPI), tiêu chuẩn an toàn thông tin (NIST, OWASP, MITRE) đã được công bố.

---

## 1. TỔNG QUAN MA TRẬN ÁP DỤNG HỌC THUẬT THEO CÁC PHASE

| Phase | Tên Giai Đoạn / Tính Năng | Trọng Tâm Kỹ Thuật | Tài Liệu Khoa Học & Tiêu Chuẩn Áp Dụng |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Target Web API & Vulnerability Lab | Triển khai REST API có chủ đích dính lỗ hổng bảo mật | **[Ref 11]** OWASP API Security Top 10 (2023)<br>**[Ref 14]** OWASP WSTG v4.2<br>**[Ref 18]** DefAtt Cyber Labs (IEEE CyberSA 2021) |
| **Phase 2** | Reverse Proxy & Traffic Ingestion | Gateway bắt gói tin, đo lường độ trễ và chuyển tiếp | **[Ref 15]** Cyber Ranges (Computers & Security 2020)<br>**[Ref 19]** NIST SP 800-115 Security Testing |
| **Phase 2b** | Signature Rule Engine | Regex chuẩn hóa ModSecurity CRS v4.0, giải mã URL kép | **[Ref 12]** OWASP ModSecurity CRS v4.0<br>**[Ref 10]** Systematic Review SQLi (IEEE Access 2023) |
| **Phase 3** | Dataset & Preprocessing | Thu thập HTTP payloads, chuẩn hóa token, trích xuất đặc trưng | **[Ref 06]** CSIC 2010 HTTP Dataset<br>**[Ref 07]** Feature Extraction HTTP (Wiley 2015) |
| **Phase 4** | Supervised ML Model (RF/XGBoost) | Huấn luyện Random Forest phân loại 5 họ tấn công | **[Ref 09]** Lightweight Ensemble WAF (MDPI Electronics 2025)<br>**[Ref 13]** OWASP Benchmark Project |
| **Phase 5** | Unsupervised Anomaly Detection | Isolation Forest phát hiện Zero-day & Outliers | **[Ref 07]** Feature Extraction HTTP (Wiley 2015)<br>**[Ref 09]** Lightweight Ensemble WAF (MDPI 2025) |
| **Phase 6** | Feature Extraction Service | Service trích xuất Shannon Entropy, Length, Char ratio | **[Ref 07]** Feature Extraction HTTP (Wiley 2015)<br>**[Ref 08]** Transformer/BERT Web Attacks (IEEE 2024) |
| **Phase 7** | Hybrid Risk & Decision Engine | Công thức tính điểm rủi ro có trọng số và 4 ngưỡng hành động | **[Ref 12]** OWASP ModSecurity Anomaly Scoring<br>**[Ref 09]** MDPI 2025 Ensemble Security Decision<br>**[Ref 17]** MITRE ATT&CK Mitigation |
| **Phase 8** | IP Rate Limiting & Sliding Window | Bộ đếm cửa sổ trượt 60s trên RAM, HTTP 429 & Retry-After | **[Ref 11]** OWASP API4:2023 Resource Consumption<br>**[Ref 12]** OWASP ModSecurity CRS v4.0 Flood Defense<br>**[Ref 19]** NIST SP 800-115 Attack Disruption<br>**[Ref 20]** RFC 6585 HTTP 429 & Retry-After |
| **Phase 9** | Dashboard & Security Monitoring | Quản lý WAF Mode, biểu đồ phân loại, timeline sự kiện | **[Ref 15]** Cyber Ranges Metrics Visualization<br>**[Ref 16]** MITRE CALDERA Telemetry UI |
| **Phase 10**| Attack Scripts & Autonomous Agent | Tác tử AI tự động lập kế hoạch và tấn công API | **[Ref 01]** PentestGPT (USENIX Security 2024)<br>**[Ref 02]** AutoAttacker (arXiv 2024)<br>**[Ref 04]** RESTler (IEEE/ACM ICSE 2019) |
| **Phase 11**| Distributed Cyber Range Testbed | Mạng phân tán 2 máy vật lý qua Switch/LAN | **[Ref 03]** Incalmo Multi-Host (CMU/SEI 2024)<br>**[Ref 15]** Cyber Range Testbed Standards |
| **Phase 12**| Benchmark, Evaluation & Evasion | Đo lường TPR, FPR, F1, kiểm thử kỹ thuật vượt rào AI | **[Ref 05]** Survey on LLM Cyberattacks (2024)<br>**[Ref 13]** OWASP Benchmark Youden Index |

---

## 2. CHI TIẾT ÁP DỤNG KHOA HỌC TRONG TỪNG GIAI ĐOẠN ĐÃ TRIỂN KHAI

### 🔹 Phase 2b: Signature-Based Rule Engine (Tasks 2b.1 – 2b.4)
* **File mã nguồn:** `gateway/app/security/engine.py`, `gateway/app/security/rules.py`, `gateway/app/security/normalizer.py`.
* **Cơ sở khoa học & Tiêu chuẩn áp dụng:**
  1. **[Ref 12] OWASP ModSecurity Core Rule Set (CRS v4.0):**
     * **Ứng dụng:** Kế thừa bộ luật phát hiện đặc trưng (attack signatures) của CRS v4.0 đối với SQL Injection (942xxx), Cross-Site Scripting (941xxx), Path Traversal (930xxx) và OS Command Injection (932xxx).
     * **Cơ chế:** Phân tích cú pháp HTTP nhiều vị trí (Path, Query string, Headers, Request Body) với độ ưu tiên và mức độ nghiêm trọng (CRITICAL, HIGH, MEDIUM, LOW).
  2. **[Ref 10] Systematic Literature Review on SQLi Detection (IEEE Access 2023):**
     * **Ứng dụng:** Kỹ thuật chuẩn hóa đa tầng (Multi-layer Normalization) giải mã đệ quy URL Encoding (`%2527` $\rightarrow$ `%27` $\rightarrow$ `'`), Unicode unescaping, Base64 decoding và Strip NULL bytes (`\x00`) nhằm ngăn chặn kỹ thuật vượt rào (WAF Evasion / Obfuscation).

---

### 🔹 Phase 7: Hybrid Risk Engine & Multi-Threshold Policy Decision (Tasks 7.1 – 7.3)
* **File mã nguồn:** `gateway/app/security/risk_engine.py`, `gateway/app/security/decision.py`, `gateway/app/api/proxy.py`.
* **Cơ sở khoa học & Tiêu chuẩn áp dụng:**
  1. **[Ref 12] OWASP ModSecurity CRS Anomaly Scoring Mode:**
     * **Ứng dụng:** Thay thế mô hình chặn cứng đơn điểm (Single-Rule Disruption) truyền thống bằng cơ chế cộng dồn điểm rủi ro có trọng số (Anomaly Scoring).
     * **Công thức toán học áp dụng:**
       $$\text{Risk Score} = 0.40 \times \text{RuleScore} + 0.35 \times \text{RFScore} + 0.25 \times \text{AnomalyScore}$$
  2. **[Ref 09] Lightweight Ensemble Web Application Firewall (MDPI Electronics 2025):**
     * **Ứng dụng:** Mô hình kiến trúc Ensemble tích hợp cả chữ ký tĩnh và học máy để vừa duy trì độ trễ xử lý cực thấp ($< 2\text{ms}$), vừa phát hiện được biến thể tấn công mới.
  3. **[Ref 17] MITRE ATT&CK Enterprise Mitigation & Tiered Policy Enforcement:**
     * **Ứng dụng:** Hệ thống ra quyết định đa ngưỡng (Multi-threshold Decision Matrix):
       * Điểm $< 30$: `ALLOW` (Cho phép truy cập bình thường).
       * Điểm $30 \le S < 60$: `MONITOR` (Ghi nhận nhật ký giám sát chuyên sâu).
       * Điểm $60 \le S < 80$: `RATE_LIMIT` (Áp đặt hình phạt siết chặt hạn ngạch truy cập 50%).
       * Điểm $\ge 80$: `BLOCK` (Lập tức từ chối với HTTP 403 Forbidden).

---

### 🔹 Phase 8: In-Memory Sliding Window IP Rate Limiting (Tasks 8.1 & 8.2)
* **File mã nguồn:** `gateway/app/security/rate_limiter.py`, `gateway/app/api/proxy.py`, `gateway/app/services/security.py`.
* **Cơ sở khoa học & Tiêu chuẩn áp dụng:**
  1. **[Ref 11] OWASP API Security Top 10 (2023) - API4:2023 (Unrestricted Resource Consumption):**
     * **Vấn đề giải quyết:** Tấn công từ chối dịch vụ (DoS), brute-force dò mật khẩu đăng nhập tài khoản và vét cạn tài nguyên máy chủ do thiếu cơ chế kiểm soát tần suất gửi yêu cầu.
     * **Giải pháp áp dụng:** Phân loại quota theo từng phạm vi endpoint nhạy cảm (Endpoint Scoping):
       * `auth` (Đăng nhập, xác thực): Tối đa **10 requests/phút** (Chống Brute-force mật khẩu).
       * `admin` (Thao tác quản trị hệ thống): Tối đa **15 requests/phút**.
       * `files` (Tải tệp tin, dữ liệu lớn): Tối đa **20 requests/phút** (Chống cạn kiệt băng thông I/O).
       * `global` (Các API thông thường): Tối đa **60 requests/phút**.
  2. **[Ref 12] OWASP ModSecurity CRS v4.0 (Sliding Window Flood Defense):**
     * **Ứng dụng:** Sử dụng cấu trúc dữ liệu hàng đợi hai đầu (`collections.deque`) lưu trữ dấu thời gian (timestamps) trong bộ nhớ RAM, cho phép loại bỏ dấu thời gian hết hạn với độ phức tạp thời gian $O(1)$.
     * **Ưu điểm so với Fixed Window:** Khắc phục triệt để nhược điểm "Traffic Spike at Boundary" của thuật toán cửa sổ cố định (nơi kẻ tấn công gửi dồn 2x giới hạn ngay tại thời điểm giao thoa giữa 2 phút).
  3. **[Ref 19] NIST SP 800-115 & RFC 6585 (Additional HTTP Status Codes):**
     * **Ứng dụng:** Khi IP vượt ngưỡng hạn ngạch cho phép, Gateway từ chối phục vụ ngay lập tức với mã trạng thái **HTTP 429 Too Many Requests**, trả về tiêu chuẩn:
       * Header `Retry-After: <seconds>`: Báo chính xác số giây còn lại cần chờ trước khi request tiếp theo được chấp nhận:
         $$\text{Retry-After} = \max\left(1, \left\lceil t_{\text{oldest}} + W - t_{\text{now}} \right\rceil\right)$$
       * Các header đo lường: `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0`, `X-RateLimit-Reset`.
       * Ghi nhận sự kiện `RATE_LIMIT_EXCEEDED` vào bảng kiểm toán `security_events` để giám sát trên Dashboard.

---

### 🔹 Phase 9: Dashboard & Real-Time Security Operations (Tasks 9.1 – 9.5)
* **File mã nguồn:** `gateway/app/api/dashboard.py`, `dashboard/src/components/*`.
* **Cơ sở khoa học & Tiêu chuẩn áp dụng:**
  1. **[Ref 15] Cyber Ranges & Testbeds (Computers & Security 2020):**
     * **Ứng dụng:** Mô hình hiển thị trực quan hóa số liệu diễn tập an ninh mạng: Phân bố các họ tấn công (Attack Families Breakdown), đường xu hướng thời gian (Traffic & Threat Timeline), đo lường độ trễ xử lý (WAF Processing Overhead $< 2\text{ms}$).
  2. **[Ref 16] MITRE CALDERA Platform Telemetry Interface:**
     * **Ứng dụng:** Trực quan hóa chi tiết bằng chứng tấn công (Evidence Drawer) hiển thị chính xác vị trí bị tấn công (`header`, `query`, `body`), chuỗi ký tự vi phạm và luật WAF tương ứng. Cho phép chuyển đổi chế độ vận hành WAF Mode (`ACTIVE_BLOCKING`, `MONITOR_ONLY`, `OFF`) theo thời gian thực mà không cần khởi động lại Gateway.

---

### 🔹 Kế Hoạch Cho Các Phase Tiếp Theo (Phase 10, 11, 12)
* **Phase 10 (AI Red Teaming Autonomous Agent):**
  * Áp dụng trực tiếp kiến trúc 3 module của **PentestGPT [Ref 01]** (*Reasoning $\rightarrow$ Tool $\rightarrow$ Parsing*) và cơ chế phân rã mục tiêu API của **AutoAttacker [Ref 02]** & **RESTler [Ref 04]**.
* **Phase 11 (Mạng Diễn Tập Phân Tán Cyber Range):**
  * Áp dụng mô hình điều phối tấn công từ xa của **Incalmo (CMU 2024) [Ref 03]** và kiến trúc phòng thí nghiệm ảo **DefAtt [Ref 18]** trên 2 máy vật lý kết nối qua LAN Switch.
* **Phase 12 (Đánh Giá Toàn Diện & Kỹ Thuật Vượt Rào):**
  * Áp dụng thang đo Youden Index của **OWASP Benchmark [Ref 13]** và các kỹ thuật Evasion từ **Survey on LLM Cyberattacks [Ref 05]** để kiểm chứng độ bền vững của hệ sinh thái bảo mật.

---

## 3. BẢNG TRA CỨU NHANH THEO TỪNG TASK CỤ THỂ

| Mã Task | Mô Tả Tính Năng | File Deliverable | Paper / Chuẩn Áp Dụng | Điểm Mấu Chốt Áp Dụng |
| :--- | :--- | :--- | :--- | :--- |
| **Task 2b.1** | SQLi & XSS Signatures | `rules.py` | ModSecurity CRS v4.0 [Ref 12] | Regex 942xxx, 941xxx |
| **Task 2b.2** | Command Inj & Traversal | `rules.py` | ModSecurity CRS v4.0 [Ref 12] | Regex 930xxx, 932xxx |
| **Task 2b.3** | Normalizer (URL/Unicode) | `normalizer.py` | IEEE Access 2023 [Ref 10] | Đệ quy decode chống bypass |
| **Task 2b.4** | Multi-location Inspection | `engine.py` | ModSecurity CRS [Ref 12] | Duyệt Path, Query, Header, Body |
| **Task 7.1** | Weighted Risk Formula | `risk_engine.py` | CRS Anomaly + MDPI [Ref 09, 12] | $0.40R + 0.35RF + 0.25IF$ |
| **Task 7.2** | 4-Tier Policy Engine | `decision.py` | MITRE Enterprise [Ref 17] | ALLOW, MONITOR, RATE_LIMIT, BLOCK |
| **Task 7.3** | 403 Forbidden & Headers | `proxy.py` | NIST SP 800-115 [Ref 19] | JSON block body + audit trail |
| **Task 8.1** | In-Memory Sliding Window | `rate_limiter.py` | OWASP API4:2023 [Ref 11, 12] | $O(1)$ deque, 60s sliding window |
| **Task 8.2** | HTTP 429 & Retry-After | `proxy.py` | RFC 6585 + NIST [Ref 19, 20] | Dynamic `Retry-After: <sec>` header |
| **Task 9.1** | Stats & Timeline API | `dashboard.py` | Cyber Ranges [Ref 15] | Aggregated analytics & time series |
| **Task 9.2** | Events & Filter API | `dashboard.py` | CALDERA Telemetry [Ref 16] | Query audit logs with pagination |
| **Task 9.3** | WAF Mode Toggle API | `dashboard.py` | ModSecurity Engine Control | Active / Monitor runtime toggle |
| **Task 9.4** | Next.js Frontend UI | `dashboard/` | Modern SecOps Design | Responsive real-time monitoring |
| **Task 9.5** | Payload Evidence Drawer | `dashboard/` | Explainable AI WAF [Ref 08] | Hiển thị vị trí & ký tự vi phạm |
