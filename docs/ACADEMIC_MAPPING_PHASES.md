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
| **Phase 3** | Feature Engineering Pipeline | Trích xuất 17 đặc trưng (Shannon Entropy, Length, Char ratio, Keywords, HTTP Context) | **[Ref 07]** Feature Extraction HTTP (Wiley 2015)<br>**[Ref 08]** Transformer/BERT Web Attacks (IEEE 2024) |
| **Phase 4** | Dataset Generation & Lab Traffic | Thu thập HTTP payloads từ vulnerable-api, chuẩn hóa token, kết hợp CSIC 2010 | **[Ref 06]** CSIC 2010 HTTP Dataset<br>**[Ref 07]** Feature Extraction HTTP (Wiley 2015) |
| **Phase 5** | Supervised ML Model (Random Forest) | Huấn luyện Random Forest phân loại 5 họ tấn công, nạp inference $<15\text{ms}$ | **[Ref 09]** Lightweight Ensemble WAF (MDPI Electronics 2025)<br>**[Ref 13]** OWASP Benchmark Project |
| **Phase 6** | Unsupervised Anomaly Detection | Isolation Forest phát hiện Zero-day & Outliers trên lưu lượng sạch baseline | **[Ref 07]** Feature Extraction HTTP (Wiley 2015)<br>**[Ref 09]** Lightweight Ensemble WAF (MDPI 2025) |
| **Phase 7** | Hybrid Risk & Decision Engine | Công thức tính điểm rủi ro có trọng số và 4 ngưỡng hành động | **[Ref 12]** OWASP ModSecurity Anomaly Scoring<br>**[Ref 09]** MDPI 2025 Ensemble Security Decision<br>**[Ref 17]** MITRE ATT&CK Mitigation |
| **Phase 8** | IP Rate Limiting & Sliding Window | Bộ đếm cửa sổ trượt 60s trên RAM, HTTP 429 & Retry-After | **[Ref 11]** OWASP API4:2023 Resource Consumption<br>**[Ref 12]** OWASP ModSecurity CRS v4.0 Flood Defense<br>**[Ref 19]** NIST SP 800-115 Attack Disruption<br>**[Ref 20]** RFC 6585 HTTP 429 & Retry-After |
| **Phase 9** | Dashboard & Security Monitoring | Quản lý WAF Mode, biểu đồ phân loại, timeline sự kiện | **[Ref 15]** Cyber Ranges Metrics Visualization<br>**[Ref 16]** MITRE CALDERA Telemetry UI |
| **Phase 10**| Offensive AI — PyTorch RL Evasion Model & Autonomous Red Teaming | Tác tử AI trinh sát OpenAPI, mô phỏng Attack Graph, huấn luyện Deep RL DQN Evasion Model (100% In-house PyTorch, KHÔNG dùng OpenAI API) | **[Ref 01]** PentestGPT (USENIX Security 2024)<br>**[Ref 02]** AutoAttacker (arXiv 2024)<br>**[Ref 04]** RESTler (IEEE/ACM ICSE 2019)<br>**[Ref 05]** Survey on LLM Cyberattacks (2024) |
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

### 🔹 Task 5.4: FastAPI Gateway ML Inference Service Integration (Task 5.4 - #25)
* **File mã nguồn:** `gateway/app/security/ml_detector.py`, `gateway/app/api/proxy.py`.
* **Cơ sở khoa học & Tiêu chuẩn áp dụng:**
  1. **[Ref 09] Lightweight Ensemble Web Application Firewall (MDPI Electronics 2025):**
     * **Ứng dụng:** Nạp sẵn mô hình học máy vào bộ nhớ RAM (Pre-warmed Model Caching), tối ưu hóa thời gian dự đoán với ngân sách độ trễ $< 15\text{ms}$ cho mỗi request.
     * **Cơ chế:** Xuất vector phân bố xác suất `probabilities`, xác định lớp tấn công chiếm ưu thế (`SQLI`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`, `BENIGN`), và ánh xạ độ tin cậy thành điểm rủi ro `rf_score` tích hợp trực tiếp vào công thức trọng số 35% của Phase 7.
  2. **[Ref 07] Feature Extraction HTTP (Wiley 2015) & [Ref 08] IEEE 2024:**
     * **Ứng dụng:** Bộ trích xuất 17 đặc trưng hình thái học (Morphological Features) siêu nhanh ($< 0.1\text{ms}$): Chiều dài chuỗi, Shannon entropy, số lượng dấu nháy đơn/kép, dấu ngoặc, tỷ lệ ký tự đặc biệt, và số lượng từ khóa/regex đặc trưng.
  3. **[Ref 19] NIST SP 800-115 & Graceful Degradation Pattern:**
     * **Ứng dụng:** Cơ chế fallback tự động (Resilient Fallback): khi Thành viên B chưa huấn luyện xong file model `rf_model.joblib`, Gateway không bị crash mà tự động chuyển sang chế độ Rule-only và ghi log cảnh báo; khi file mô hình xuất hiện, Gateway lập tức nạp nóng (Hot-reload) mà không cần khởi động lại.

---

### 🔹 Task 6.4: Gateway Anomaly Detection Hook & Realtime Logging (Task 6.4 - #29)
* **File mã nguồn:** `gateway/app/security/anomaly.py`, `gateway/app/api/proxy.py`.
* **Cơ sở khoa học & Tiêu chuẩn áp dụng:**
  1. **[Ref 09] Lightweight Ensemble Web Application Firewall (MDPI Electronics 2025):**
     * **Ứng dụng:** Hoàn thiện mảnh ghép thứ 3 trong kiến trúc WAF Hybrid kết hợp: Signature Rule (40%) + Supervised Random Forest (35%) + Unsupervised Isolation Forest (25%).
     * **Cơ chế:** Nạp sẵn mô hình `iforest_model.joblib` trong bộ nhớ RAM, thực hiện suy luận dị biệt thời gian thực với ngân sách độ trễ $< 10\text{ms}$ ($2-5\text{ms}$ thực tế).
     * **Phát hiện Zero-day:** Bắt các payload biến dị hoặc dị biệt về cấu trúc mà Rule Engine tĩnh và mô hình Random Forest chưa từng gặp trong tập huấn luyện.
  2. **[Ref 07] Feature Extraction HTTP (Wiley 2015) & [Ref 08] IEEE 2024:**
     * **Ứng dụng:** Đồng bộ vector 17 đặc trưng hình thái học (Morphological HTTP Features) từ `MLDetector` mà không cần trích xuất lại, tối ưu hóa $O(1)$ RAM và không tốn I/O.
     * **Chuẩn hóa điểm số:** Ánh xạ hàm quyết định `decision_function(X)` thành thang điểm rủi ro liên tục từng đoạn $0.0 - 100.0$:
       * $raw \ge 0$ (Inlier - Lưu lượng bình thường): $\max(0.0, 30.0 - raw \times 300.0) \in [0, 30]$ (`ALLOW`).
       * $raw < 0$ (Outlier - Dị biệt / Zero-day): $\min(100.0, 30.0 + |raw| \times 850.0) \in [30, 100]$ (`MONITOR`, `RATE_LIMIT`, `BLOCK`).
  3. **[Ref 19] NIST SP 800-115 & Graceful Degradation Pattern:**
     * **Ứng dụng:** Cơ chế fallback an toàn: Khi Thành viên B chưa hoàn tất huấn luyện `iforest_model.joblib`, Gateway tự động đặt `anomaly_score = None`, `RiskEngine` tự động co giãn tỷ trọng cho các tầng sẵn có ($0.40/0.75$ Rule và $0.35/0.75$ RF). Khi file mô hình xuất hiện, Gateway tự động nạp nóng (Hot-reload).
  4. **Telemetry & Audit Logging:**
     * Ghi nhận trường `anomaly_score` vào SQLite `security_events` và trả về headers `X-WAF-Anomaly-Score`, `X-WAF-Anomaly-Latency`.

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
* **Phase 10 (Offensive AI — In-house PyTorch Deep RL Evasion Model & Autonomous Red Teaming):**
  * **Trinh sát & Phân rã mục tiêu API:** Áp dụng cơ chế đọc OpenAPI schema và phân rã mục tiêu của **RESTler [Ref 04]** và **AutoAttacker [Ref 02]**.
  * **Mô hình AI Tấn Công In-house (100% PyTorch, KHÔNG dùng OpenAI/Ollama API):** Tự xây dựng mô hình Deep Reinforcement Learning (DQN / Policy Gradient) theo cảm hứng từ các công trình *WAF-A-MoLE* và *Gym-WAF*, biến đổi payload đa hình (Polymorphic Mutation [Ref 05]) với không gian hành động biến dị (URL encoding, comment injection `/**/`, case swapping, keyword substitution) và hàm thưởng phạt từ Gateway phản hồi (Chặn `403` $\rightarrow$ Phạt $-1$, Vượt rào thành công $\rightarrow$ Thưởng $+10$).
  * **Kiến trúc điều phối Red Team:** Kế thừa mô hình điều phối suy luận của **PentestGPT [Ref 01]** (*Reasoning $\rightarrow$ Tool $\rightarrow$ Parsing*).
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
| **Task 3.1** | Morphological Features | `payload.py` | Wiley SCN 2015 [Ref 08] | Shannon Entropy, Length, 9 char counts, special ratio |
| **Task 5.4** | ML Inference Service | `ml_detector.py` | MDPI Electronics 2025 [Ref 09] | Pre-warmed RAM cache, $<15\text{ms}$ latency |
| **Task 6.4** | Anomaly Hook & Logging | `anomaly.py` | MDPI 2025 + Wiley [Ref 07, 09] | Isolation Forest $<10\text{ms}$, zero-day catch |
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
