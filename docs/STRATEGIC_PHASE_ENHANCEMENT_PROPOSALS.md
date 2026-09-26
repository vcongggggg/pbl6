# 🚀 TỔNG HỢP ĐỀ XUẤT ĐỘT PHÁ & CẢI TIẾN CHIẾN LƯỢC TOÀN DIỆN CÁC PHASE (PBL6)

**Học phần:** Đồ Án Chuyên Ngành An Toàn Thông Tin (PBL6)  
**Đề tài:** Phát Hiện và Ngăn Chặn Tấn Công Web API bằng Học Máy kết hợp Thao Trường Đối Kháng An Ninh Mạng (Distributed Cyber Range)  
**Tác giả:** Anh Văn Công (@vcongggggg - Tech Lead & Defense AI/ML Engineer)  
**Cố vấn & Giám định độc lập:** @reviewer (Senior Security Architect & Independent Code Reviewer)  
**Mục tiêu tài liệu:** Lưu trữ tập trung các ý tưởng sáng tạo, cải tiến kỹ thuật nâng cao và đề xuất đột phá học thuật cho **TẤT CẢ 12 PHASES** của dự án. Tài liệu này đóng vai trò kim chỉ nam giúp nhóm chọn lọc các tính năng tạo dấu ấn khác biệt (Key Differentiators), chinh phục điểm 10 tuyệt đối trước Hội đồng Bảo vệ Đồ án.

---

## 📑 MỤC LỤC TỔNG QUAN CÁC PHASE

1. [Phase 1: Reverse Proxy & Gateway Infrastructure](#phase-1-reverse-proxy--gateway-infrastructure)
2. [Phase 2: Rule Engine & Signature-Based Detection](#phase-2-rule-engine--signature-based-detection)
3. [Phase 2B: Custom Vulnerable Target API (Bookie Bookstore)](#phase-2b-custom-vulnerable-target-api-bookie-bookstore)
4. [Phase 3: Feature Engineering (Morphology & HTTP Context)](#phase-3-feature-engineering-morphology--http-context)
5. [Phase 4: Dataset Generation & Lab Traffic Synthesis](#phase-4-dataset-generation--lab-traffic-synthesis)
6. [Phase 5: Supervised ML — Multi-Model Benchmarking & Inference](#phase-5-supervised-ml--multi-model-benchmarking--inference)
7. [Phase 6: Anomaly Detection — Isolation Forest & Zero-Day](#phase-6-anomaly-detection--isolation-forest--zero-day)
8. [Phase 7: Hybrid Risk Engine & Defense-in-Depth Decision](#phase-7-hybrid-risk-engine--defense-in-depth-decision)
9. [Phase 8: Risk-Adaptive Sliding Window Rate Limiter](#phase-8-risk-adaptive-sliding-window-rate-limiter)
10. [Phase 9: SOC Command Center Dashboard & Live Telemetry](#phase-9-soc-command-center-dashboard--live-telemetry)
11. [Phase 10: Offensive AI — In-House PyTorch Deep RL Evasion Agent](#phase-10-offensive-ai--in-house-pytorch-deep-rl-evasion-agent)
12. [Phase 11: Multi-Method Evaluation & Adversarial Cyber Range Testing](#phase-11-multi-method-evaluation--adversarial-cyber-range-testing)
13. [Phase 12: Production Hardening, System Deployment & Thesis Report](#phase-12-production-hardening-system-deployment--thesis-report)

---

## Phase 1: Reverse Proxy & Gateway Infrastructure

### 📌 Hiện trạng đã đạt được:
- Reverse Proxy bất đồng bộ (FastAPI / `httpx.AsyncClient`) với cơ chế định tuyến động `/api/proxy/{path:path}`.
- Tạo lập và truyền dẫn `X-Request-ID` cho phép truy vết 100% dòng đời request.
- Lọc bỏ triệt để Hop-by-hop headers (RFC 7230), chống tấn công SSRF và Open Proxy, ghi log bảo mật vào SQLite.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Dynamic Circuit Breaker & Upstream Health Degrade (Cắt mạch tự động):**
   - *Vấn đề:* Khi dịch vụ backend (Target API) bị sập hoặc quá tải do tấn công DoS, Gateway nếu tiếp tục chuyển tiếp request sẽ gây nghẽn hàng đợi (connection pool exhaustion).
   - *Cải tiến:* Tích hợp thuật toán Circuit Breaker 3 trạng thái (`CLOSED`, `OPEN`, `HALF_OPEN`). Khi tỷ lệ lỗi upstream >= 50% trong 10 giây, Gateway tự ngắt mạch và trả ngay lỗi `503 Service Unavailable` kèm `Retry-After`, bảo vệ tài nguyên Gateway.
2. **HTTP/2 & Persistent Connection Pooling:**
   - *Cải tiến:* Cấu hình `httpx.Limits(max_keepalive_connections=50, max_connections=200)` duy trì kết nối TCP bền vững (Persistent Keep-Alive) tới upstream, giảm độ trễ bắt tay TCP/TLS handshake xuống dưới 0.5ms.
3. **mTLS (Mutual TLS) Upstream Zero-Trust:**
   - *Cải tiến:* Xác thực hai chiều bằng chứng chỉ số giữa WAF Gateway và Target API, đảm bảo nguyên tắc Zero-Trust nội bộ mạng backend.

---

## Phase 2: Rule Engine & Signature-Based Detection

### 📌 Hiện trạng đã đạt được:
- 16 rules tĩnh tất định phủ 4 họ tấn công kinh điển (SQLi, XSS, Path Traversal, Command Injection).
- Bộ tiền xử lý `InputNormalizer` (đệ quy giải mã URL, Unicode, Hex, HTML Entities với `max_depth = 3`).
- Quy đổi điểm rủi ro $S_{\text{rule}} \in [0, 100]$.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **AST-based SQL Injection Semantic Parser (Phân tích cú pháp ngữ nghĩa thay vì Regex thuần):**
   - *Vấn đề:* Regex tĩnh rất dễ bị qua mặt bởi các kỹ thuật làm rối (Obfuscation) như inline comments `/**/`, whitespace manipulation, hàm tương đương `CHAR()`, `HEX()`.
   - *Cải tiến:* Tích hợp thư viện phân tích cú pháp ngữ nghĩa (tương tự thuật toán Libinjection hoặc SQLGlot AST parser). Thay vì so khớp chuỗi, hệ thống tokenize payload thành cây cú pháp trừu tượng (AST) để nhận diện cấu trúc logic luôn đúng (`1=1`, `OR true`), nâng tỷ lệ bắt SQLi obfuscated lên gần 100%.
2. **ReDoS Guard & Pre-compiled Hyperscan Engine:**
   - *Vấn đề:* Các biểu thức chính quy phức tạp dễ bị tấn công Từ chối dịch vụ Regex (Regular Expression Denial of Service - ReDoS).
   - *Cải tiến:* Bổ sung cơ chế Timeout Guard (tối đa 2ms / regex) hoặc chuyển đổi sang thư viện Intel Hyperscan chạy trên tập chỉ thị SIMD AVX-512, tăng tốc độ quét regex lên gấp 10 - 20 lần.

---

## Phase 2B: Custom Vulnerable Target API (Bookie Bookstore)

### 📌 Hiện trạng đã đạt được:
- Dịch vụ Web API mục tiêu tự xây dựng 100% bằng FastAPI (`vulnerable-api` cổng 5000), loại bỏ hoàn toàn Juice Shop bên thứ ba.
- Mô phỏng đầy đủ 8 kịch bản lỗ hổng chuẩn OWASP Web & API Top 10 kèm endpoint trinh sát OpenAPI (`/openapi.json`).

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **1-Click Ephemeral Sandbox Reset (Khôi phục dữ liệu tức thời qua In-Memory SQLite):**
   - *Cải tiến:* Bổ sung endpoint nội bộ `/api/internal/reset-db` cho phép Cyber Range tự động phục hồi lại trạng thái cơ sở dữ liệu gốc chỉ sau 0.1s sau mỗi đợt tấn công khai thác (Data Wiping, DROP TABLE) của Red Team.
2. **Vulnerability Flag & Canary Token System (Hệ thống cờ CTF nội bộ):**
   - *Cải tiến:* Cài cắm các Canary Tokens / Honey-tokens bí mật vào database (ví dụ: tài khoản admin `admin_canary_flag{pbl6_secret}`). Nếu Red Team trích xuất được token này qua SQLi, hệ thống lập tức ghi nhận bằng chứng khai thác thành công (Exploit Verification Proof).

---

## Phase 3: Feature Engineering (Morphology & HTTP Context)

### 📌 Hiện trạng đã đạt được:
- 17 payload features (12 đặc trưng hình thái học/entropy + 5 đặc trưng từ khóa cú pháp).
- 23 HTTP context features (header anomaly, path depth, query param counts).
- Chuẩn hóa đầu ra vector đặc trưng 17 chiều tương thích tuyệt đối giữa huấn luyện và suy luận runtime.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Byte-level Shannon & Chi-Square Entropy Divergence:**
   - *Cải tiến:* Bổ sung độ lệch entropy so với phân phối ký tự chuẩn của ngôn ngữ tiếng Anh/tiếng Việt. Các payload mã hóa Base64 hoặc shellcode nén sẽ có độ phân tán Chi-Square rất khác biệt so với văn bản tự nhiên, giúp mô hình bắt payload mã hóa mà không cần giải mã trước.
2. **Structural Token Ratio Features (Tỷ lệ ký tự cấu trúc cú pháp):**
   - *Cải tiến:* Tính tỷ lệ giữa ký tự điều khiển cú pháp (`'`, `"`, `;`, `--`, `/*`, `|`, `$`, `(`, `)`) trên tổng chiều dài chuỗi. Đây là đặc trưng bất biến cao (high invariant) rất khó bị Red Team né tránh kể cả khi thay đổi từ khóa.

---

## Phase 4: Dataset Generation & Lab Traffic Synthesis

### 📌 Hiện trạng đã đạt được:
- Bộ dữ liệu 20.000 mẫu cân bằng chuẩn hóa (10.000 Benign, 10.000 Attacks).
- Phân tầng Stratified 70/15/15 (Train/Val/Test) kèm kiểm tra tính toàn vẹn SHA-256.
- Đã đưa vào 60% mẫu kỹ thuật làm rối (obfuscation) và 22.23% mẫu vượt qua Rule Engine.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Adversarial Synthesis via WGAN-GP (Tạo mẫu tấn công đối kháng bằng Mạng GAN):**
   - *Cải tiến:* Ứng dụng Wasserstein GAN with Gradient Penalty để tự động sinh các biến thể tấn công mới lạ (Payload Mutations) dựa trên phân phối của các cuộc tấn công đã biết, giúp tập dữ liệu huấn luyện phòng thủ có độ bao phủ đa dạng vượt bậc.
2. **Automated Data Drift Detection (Giám sát trôi dữ liệu theo thời gian thực):**
   - *Cải tiến:* Tích hợp kiểm định thống kê Kolmogorov-Smirnov (KS-test) hoặc Population Stability Index (PSI) trên Gateway. Khi phân phối lưu lượng truy cập thực tế trôi lệch quá 15% so với tập huấn luyện ban đầu, hệ thống tự động phát cảnh báo kích hoạt quy trình tái huấn luyện (Retraining Alert).

---

## Phase 5: Supervised ML — Multi-Model Benchmarking & Inference

### 📌 Hiện trạng đã đạt được:
- Đối sánh thực nghiệm 5 mô hình (Logistic Regression, Decision Tree, Linear SVM, Random Forest, XGBoost).
- Xác định Quán quân Thực nghiệm XGBoost ($F_1 = 99.97\%$, latency $0.004\text{ms}$) và Random Forest dự phòng.
- Đóng gói serialization chuẩn SHA-256 chống CWE-502 Deserialization.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **ONNX Runtime Engine Acceleration (Tối ưu hóa suy luận cấp vi mô):**
   - *Cải tiến:* Xuất mô hình Scikit-Learn / XGBoost sang định dạng **ONNX (Open Neural Network Exchange)** và chạy bằng `onnxruntime` với bộ biên dịch tối ưu C++. Giảm độ trễ suy luận từ $0.004\text{ms}$ xuống còn dưới $0.001\text{ms}$ ($< 1\mu\text{s}$), đẩy thông lượng lên trên $150.000\text{ req/s}$.
2. **Explainable AI (XAI) via TreeSHAP in Real-Time:**
   - *Cải tiến:* Trích xuất trực tiếp Top 3 đặc trưng đóng góp lớn nhất (Feature Attribution) bằng TreeSHAP ngay khi phát hiện request độc hại, ghi thẳng vào trường `threat_factors` của log sự kiện. Giúp chuyên viên SOC hiểu ngay lập tức *vì sao mô hình lại phân loại đây là tấn công*.

---

## Phase 6: Anomaly Detection — Isolation Forest & Zero-Day

### 📌 Hiện trạng đã đạt được:
- Huấn luyện mô hình bán giám sát (Semi-supervised) Isolation Forest trên 10.000 mẫu Benign thuần túy.
- Chuẩn hóa điểm Anomaly Score về thang $0 - 100$ theo chuẩn học thuật MDPI Electronics 2025.
- Tỷ lệ báo động nhầm (False Alarm Rate) cực thấp: $0.70\%$.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Extreme Value Theory (EVT) for Threshold Calibration (Lý thuyết giá trị cực trị):**
   - *Cải tiến:* Thay vì chọn ngưỡng contamination cố định $0.01$, áp dụng định lý Pickands-Balkema-de Haan (EVT) để mô hình hóa phần đuôi phân phối bất thường (Heavy-tail Distribution). Giúp hệ thống tự động thiết lập ngưỡng phát hiện Zero-Day tối ưu mà không cần giả định trước phân phối dữ liệu.
2. **Streaming Online Isolation Forest (Cập nhật đường cơ sở động theo khung giờ):**
   - *Cải tiến:* Cho phép mô hình cập nhật nhẹ trọng số cây (Tree adaptation) theo lưu lượng hợp lệ trong ngày (ví dụ: giờ hành chính traffic nghiệp vụ khác ban đêm), giảm thiểu triệt để tình trạng báo động sai khi có tính mùa vụ (Seasonality).

---

## Phase 7: Hybrid Risk Engine & Defense-in-Depth Decision

### 📌 Hiện trạng đã đạt được:
- Công thức tính điểm rủi ro tổng hợp $S = w_{\text{rule}} S_{\text{rule}} + w_{\text{rf}} S_{\text{rf}} + w_{\text{iforest}} S_{\text{iforest}}$.
- Bốn mức hành vi: `ALLOW` ($< 35$), `MONITOR` ($[35, 60)$), `RATE_LIMIT` ($[60, 80)$), `BLOCK` ($[80, 100]$).
- Tích hợp cờ bảo vệ tối thượng: Nếu Rule tĩnh xác định $S_{\text{rule}} \ge 80$, cưỡng chế `BLOCK` ngay lập tức.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Bayesian Dynamic Weighting (Điều chỉnh trọng số động theo độ tự tin Bayes):**
   - *Vấn đề:* Trọng số tĩnh ($0.35, 0.45, 0.20$) có thể không tối ưu cho mọi loại payload. Ví dụ: với payload quá mới (chưa có trong signature), trọng số của Rule nên giảm xuống và trọng số Anomaly nên tăng lên.
   - *Cải tiến:* Ứng dụng mô hình suy luận Bayes (Bayesian Uncertainty Estimation): Trọng số của từng thành phần sẽ tỉ lệ thuận với độ tin cậy (Confidence Interval) của thành phần đó trên request hiện tại.
2. **Context-Aware Dynamic Thresholds (Ngưỡng phòng thủ co giãn theo trạng thái hệ thống):**
   - *Cải tiến:* Khi hệ thống phát hiện đang trong đợt tấn công dồn dập (Cyber Attack Wave), ngưỡng kích hoạt `BLOCK` tự động hạ từ $80$ xuống $70$, chuyển hệ thống sang chế độ phòng thủ cấp cao (DefCon 1).

---

## Phase 8: Risk-Adaptive Sliding Window Rate Limiter

### 📌 Hiện trạng đã đạt được:
- Thuật toán Sliding Window Counter bằng `collections.deque` với chi phí khấu hao $\mathcal{O}(1)$, triệt tiêu Bursty Boundary Attack.
- Co giãn hạn ngạch động: Giảm 50% hạn mức khi $S \in [60, 80)$.
- Phân tách 4 scopes (`auth`, `admin`, `files`, `global`) và phản hồi chuẩn IETF RFC 6585 & RFC 7807 Problem Details.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Exponential Backoff Throttling (Hình phạt lũy tiến theo chu kỳ vi phạm):**
   - *Cải tiến:* Lưu lịch sử vi phạm trong $T_{\text{window}} = 10\text{ phút}$. Nếu 1 IP liên tục vi phạm hạn ngạch >= 3 lần, thời gian `Retry-After` tăng lũy tiến:
     $$60\text{s} \longrightarrow 120\text{s} \longrightarrow 300\text{s} \longrightarrow \text{Tạm khóa IP 15 phút (Jail)}$$
   - *Tác dụng:* Chặn đứng hoàn toàn kỹ thuật tấn công Slow-and-Low Scan và Low-Rate DoS Attacks.
2. **Fingerprint & Session-Aware Scoping (Định danh kết hợp chống bẫy NAT):**
   - *Cải tiến:* Định danh khóa trạng thái kết hợp:
     $$\text{Key} = \text{IP} \mathbin{\Vert} \text{Hash(User-Agent, Accept-Lang)} \mathbin{\Vert} \text{JWT Subject / Session Cookie}$$
   - *Tác dụng:* Đảm bảo trừng phạt đích danh kẻ tấn công, không gây ảnh hưởng tới người dùng lành tính dùng chung mạng WiFi/NAT công ty hoặc trường đại học.
3. **Pluggable Redis Distributed Rate Limiter (Sẵn sàng mở rộng đa cụm Gateway):**
   - *Cải tiến:* Thiết kế `RateLimiterBase` theo mẫu Adapter Pattern, cho phép chuyển đổi từ In-Memory sang Redis Sorted Sets (`ZADD`, `ZREMRANGEBYSCORE`) khi triển khai nhiều replica WAF Gateway phía sau Load Balancer.

---

## Phase 9: SOC Command Center Dashboard & Live Telemetry

### 📌 Hiện trạng đã đạt được:
- Dashboard Next.js 14 hiện đại với 5 thẻ KPI thống kê, đồ thị phân phối tấn công, biểu đồ đường thời gian thực.
- Bảng nhật ký Security Events với phân loại Client IP, Drawer xem chi tiết payload và modal giải thích quyết định rủi ro.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **WebSocket / SSE Full-Duplex Real-Time Stream (Đẩy sự kiện tức thời không cần Polling):**
   - *Cải tiến:* Thay thế cơ chế HTTP Polling định kỳ bằng kết nối Server-Sent Events (SSE) hoặc WebSocket, sự kiện tấn công vừa xuất hiện tại Gateway sẽ nhấp nháy đỏ trên màn hình SOC trong vòng dưới 10ms.
2. **Interactive SHAP Waterfall Chart (Biểu đồ thác nước trực quan hóa AI):**
   - *Cải tiến:* Tích hợp thư viện biểu đồ trực quan hóa giá trị SHAP (Waterfall Plot). Giúp Giảng viên và Ban giám khảo khi bấm vào 1 request bất kỳ trên Dashboard có thể thấy ngay biểu đồ trực quan giải thích từng đặc trưng đã đẩy điểm rủi ro lên ra sao.
3. **1-Click Active Defense Remediation (Tương tác phòng thủ chủ động 1-click):**
   - *Cải tiến:* Thêm nút thao tác nhanh trên từng dòng sự kiện: `[Khóa IP vĩnh viễn]`, `[Giảm hạn ngạch 80%]`, `[Tạo Rule chữ ký mới từ payload này]`.

---

## Phase 10: Offensive AI — In-House PyTorch Deep RL Evasion Agent

### 📌 Hiện trạng đã đạt được:
- Phân công cho Thành viên B (`naocavang08`) trên Máy 2 (Red Team vật lý).
- Định hướng kiến trúc 100% PyTorch Deep Reinforcement Learning (DQN / Policy Gradient), tuyệt đối không dùng OpenAI API.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Curriculum Reinforcement Learning for Evasion (Học tăng cường theo giáo trình):**
   - *Cải tiến:* Thiết kế hàm phần thưởng (Reward Function) đa mục tiêu:
     $$R = +10 \cdot \mathbb{I}(\text{Passed WAF}) + 20 \cdot \mathbb{I}(\text{Exploit Success}) - 5 \cdot \text{Payload Length Penalty}$$
   - Cho agent học từ các biến đổi đơn giản (đổi khoảng trắng sang comment `/**/`) đến các biến đổi phức tạp (kỹ thuật lồng hàm nhị phân, encoding kép), tạo ra mô hình né tránh tự động cực kỳ thông minh.
2. **Multi-Action Mutation Graph (Đồ thị biến dị đa hành động):**
   - *Cải tiến:* Xây dựng tập hành động rời rạc (Action Space) gồm 15 phép biến dị cú pháp SQL/XSS (Case Randomization, Comment Injection, URL Double Encoding, Null Byte Insertion, Hex Literal Conversion).

---

## Phase 11: Multi-Method Evaluation & Adversarial Cyber Range Testing

### 📌 Hiện trạng đã đạt được:
- Kế hoạch so sánh 4 cấu hình phòng thủ: (1) Rule-Only, (2) ML-Only, (3) Anomaly-Only, (4) Hybrid Defense-in-Depth.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Adversarial Robustness Evaluation Matrix (Ma trận đo lường độ bền vững đối kháng):**
   - *Cải tiến:* Định lượng khả năng phòng thủ qua thước đo:
     $$\text{Robustness Score} = \frac{\text{Attacks Blocked After Mutation}}{\text{Total Mutated Attacks}} \times 100\%$$
   - Chứng minh rõ ràng trên đồ thị: Khi Red Team liên tục biến dị né tránh, cấu hình Hybrid vẫn giữ tỷ lệ chặn trên 95%, trong khi Rule-Only bị tụt dốc thảm hại xuống dưới 40%.
2. **High-Concurrency Stress Testing (Kiểm thử tải tới hạn 10.000 req/s):**
   - *Cải tiến:* Sử dụng công cụ `wrk` hoặc `Locust` để đo lường:
     - Throughput tối đa ($RPS$).
     - Độ trễ phân vị $P50, P95, P99$.
     - Tỷ lệ tiêu hao CPU/RAM của Gateway khi bật toàn bộ pipeline phòng thủ.

---

## Phase 12: Production Hardening, System Deployment & Thesis Report

### 📌 Hiện trạng đã đạt được:
- Kế hoạch đóng gói Docker Compose, chạy đa máy vật lý qua LAN và xuất bản báo cáo đồ án.

### 💡 Đề xuất Đột phá & Nâng cấp Chiến lược:
1. **Container Hardening & Least-Privilege Execution (Đóng gói an toàn cấp độ Enterprise):**
   - *Cải tiến:* Thiết lập Dockerfile chạy dưới user phi đặc quyền (`nobody:nogroup`), hệ thống tệp chỉ đọc (`read_only_rootfs: true`), hủy bỏ mọi Linux Capabilities không cần thiết (`cap_drop: ALL`), chặn đứng nguy cơ Container Escape nếu Target API bị Remote Code Execution.
2. **Automated Academic Benchmark Report Generator:**
   - *Cải tiến:* Script tự động trích xuất toàn bộ bảng số liệu thực nghiệm, độ trễ, ma trận nhầm lẫn (Confusion Matrix) và tự sinh file Markdown / LaTeX chuẩn định dạng bài báo khoa học, giúp tiết kiệm 80% thời gian viết báo cáo đồ án cuối kỳ.

---

## 🏆 BẢNG TỔNG HỢP ƯU TIÊN TRIỂN KHAI (EFFORT VS. IMPACT)

| Thứ Tự Ưu Tiên | Phân Hệ | Tính Năng Đề Xuất | Độ Phức Tạp | Tác Động Học Thuật / Điểm Số |
| :---: | :---: | :--- | :---: | :---: |
| 🥇 **Ưu tiên 1** | **Phase 8** | **Exponential Backoff Throttling** (Phạt lũy tiến theo chu kỳ) | Thấp (1-2 ngày) | ⭐⭐⭐⭐⭐ (Khắc phục triệt để botnet lách luật) |
| 🥈 **Ưu tiên 2** | **Phase 5** | **TreeSHAP Explainability in Logs** (Giải thích quyết định AI) | Thấp (1-2 ngày) | ⭐⭐⭐⭐⭐ (Ghi điểm tuyệt đối phần Explainable AI) |
| 🥉 **Ưu tiên 3** | **Phase 8** | **Session/Fingerprint-Aware Scoping** (Tránh bẫy NAT WiFi) | Thấp (1 ngày) | ⭐⭐⭐⭐ (Tính ứng dụng thực tiễn cực cao) |
| 4 | **Phase 9** | **WebSocket / SSE Realtime Live Stream** cho Dashboard | Trung bình (2 ngày) | ⭐⭐⭐⭐⭐ (Hiệu ứng Demo trực quan thuyết phục) |
| 5 | **Phase 2** | **AST-based SQLi Semantic Parser** | Trung bình (2-3 ngày) | ⭐⭐⭐⭐ (Chống Bypass SQLi cấp cao) |
| 6 | **Phase 10** | **Multi-Action Mutation Graph cho RL Evasion Agent** | Cao (3-5 ngày) | ⭐⭐⭐⭐⭐ (Trọng tâm của Thành viên B Red Team) |

---

*Tài liệu được biên soạn và bảo chứng chuyên môn bởi **@reviewer (Senior Security Architect & Independent Code Reviewer)**.*
