# CHƯƠNG 1: CƠ SỞ LÝ THUYẾT VÀ TỔNG QUAN CÔNG NGHỆ

> **Đề tài:** Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán  
> **Sinh viên thực hiện:** Nguyễn Văn Công (Blue Team) & Nguyễn Minh (Red Team)  
> **Giảng viên hướng dẫn:** TS. Nguyễn Thế Xuân Ly  
> **Cơ sở khoa học tham chiếu:** 20 công trình và giáo trình kinh điển quốc tế (Pearson/Prentice Hall, CRC Press, Sybex/Wiley, O'Reilly, IEEE, ACM KDD, Elsevier, MDPI, NIST, OWASP, MITRE).

---

## 1.1. TỔNG QUAN VỀ BẢO MẬT WEB API VÀ CÁC THÁCH THỨC AN NINH HIỆN ĐẠI

### 1.1.1. Xu hướng kiến trúc Microservices và sự bùng nổ của Web API
Trong kỷ nguyên chuyển đổi số và điện toán đám mây, kiến trúc phần mềm đã dịch chuyển căn bản từ các hệ thống nguyên khối (Monolithic Architecture) sang kiến trúc phân tán và vi dịch vụ (Microservices Architecture). Giao diện lập trình ứng dụng web (Web API) — bao gồm RESTful API (JSON/HTTP), GraphQL, SOAP/XML và JSON-RPC 2.0 — đã trở thành huyết mạch kết nối toàn bộ hệ sinh thái số: từ ứng dụng web SPA (React/Next.js), ứng dụng di động (Mobile Apps), thiết bị IoT đến hệ thống thanh toán liên ngân hàng.

Tuy nhiên, việc Web API phơi bày trực tiếp logic nghiệp vụ, tham số truy vấn và lược đồ đặc tả kỹ thuật (OpenAPI 3.0 / Swagger) đã mở rộng mạnh bề mặt tấn công (Attack Surface). Kẻ tấn công có thể triển khai các tác tử tự động bóc tách đặc tả API, lập bản đồ bề mặt tấn công và thực hiện khai thác hàng loạt mà không bị cản trở bởi giao diện người dùng **[Ref 04]**.

### 1.1.2. Phân tích các mối đe dọa hàng đầu theo OWASP API Security Top 10 (2023)
Theo tài liệu *OWASP Top 10 API Security Risks 2023* **[Ref 06]** và *OWASP Top 10 Web 2021*, đồ án tập trung phòng thủ toàn diện đối với các nhóm hiểm họa nghiêm trọng nhất:
1. **Các lỗ hổng tiêm mã độc (Injection — SQLi, OS Command Injection, Path Traversal, XXE):** Kẻ tấn công chèn câu lệnh SQL, lệnh shell hệ điều hành, chuỗi thoát thư mục (`../`) hoặc thực thể XML độc hại (`<!ENTITY ... SYSTEM>`) vào tham số truy vấn, header (`Cookie`), hoặc body JSON/XML nhằm trích xuất dữ liệu hay chiếm quyền thực thi từ xa (RCE).
2. **Tấn công Cross-Site Scripting (XSS):** Chèn mã JavaScript (`<script>`, `<svg onload=...>`, `<details open ontoggle=...>`) vào trường dữ liệu JSON do API lưu trữ và trả về cho SPA, dẫn tới đánh cắp phiên đăng nhập và leo thang chiếm tài khoản.
3. **Phá vỡ kiểm soát truy cập & Mass Assignment (BOLA/IDOR — API1:2023, BOPLA — API6:2023, SSRF — API7:2023):** Thay đổi mã định danh đối tượng (`/orders/{id}`), chèn thêm trường đặc quyền không khai báo (`{"role": "admin"}`), hoặc lợi dụng chức năng nạp tài nguyên URL để trinh sát mạng nội bộ.
4. **Tiêu thụ tài nguyên không hạn chế (Unrestricted Resource Consumption — API4:2023):** Tấn công Brute-force xác thực, GraphQL Deep Nesting DoS, nhồi body dung lượng lớn (chunked transfer DoS), hoặc kích hoạt ReDoS (Regular Expression Denial of Service) làm treo CPU của tường lửa ứng dụng **[Ref 05, Ref 06]**.

### 1.1.3. Các kỹ thuật làm mờ payload và né tránh tường lửa (WAF Evasion & Obfuscation)
Theo giáo trình *CompTIA PenTest+* **[Ref 04]** và thực tiễn kiểm thử đối kháng, kẻ tấn công và tác tử AI Red Team thường áp dụng các kỹ thuật biến dị bảo toàn ngữ nghĩa (Semantic-Preserving Tamper) nhằm đánh lừa WAF dựa trên chữ ký tĩnh:

| Kỹ Thuật Né Tránh | Cơ Chế Bản Chất | Ví Dụ Minh Họa | Hệ Quả Đối Với WAF Tĩnh |
| :--- | :--- | :--- | :--- |
| **Mã hóa URL đa tầng (Double URL Encoding)** | Mã hóa lặp ký tự `%` thành `%25` (`'` -> `%27` -> `%2527`). | `%2527%2520OR%25201%253D1` | WAF chỉ giải mã 1 vòng sẽ bỏ lọt payload sang backend. |
| **Chèn chú thích nội tuyến & đa dòng** | Chèn comment `/**/`, `/*!50000...*/` hoặc xuống dòng giữa từ khóa. | `1' UNION/*\n*/SELECT 1,2--` | Phá vỡ biểu thức chính quy không hỗ trợ chuẩn hóa comment/DOTALL. |
| **Ký tự vô hình Unicode (Zero-Width)** | Chèn `\u200b`–`\u200f`, `\ufeff` xen kẽ thẻ HTML hoặc từ khóa. | `<scr\u200bipt>alert(1)</scr\u200bipt>` | Làm đứt mẫu chuỗi regex tĩnh dù trình duyệt/parser vẫn thực thi. |
| **Khoảng trắng & Toán tử thay thế** | Dùng `${IFS}`, `BETWEEN`, nối nháy đơn `c''at`, thẻ HTML5 `ontoggle`. | `127.0.0.1;cat${IFS}/etc/passwd` | Vượt qua các quy tắc regex chỉ kiểm tra khoảng trắng ASCII cố định. |
| **Nhồi đệm dung lượng (Payload Padding > 16KB)** | Chèn chuỗi vô hại ở đầu body để đẩy payload độc hại vượt giới hạn quét. | `{"pad": "AAAA...", "q": "' OR 1=1--"}` | WAF cắt cụt chuỗi ở 16 KB sẽ mù hoàn toàn với phần đuôi độc hại. |
| **Che giấu qua giao thức phức hợp (SOAP CDATA / Cookie)** | Giấu SQLi trong `<![CDATA[...]]>` của SOAP/XML hoặc tiêu đề `Cookie`. | `<![CDATA[' OR 1=1--]]>` | WAF chỉ quét query/body REST thông thường sẽ bỏ sót payload. |

---

## 1.2. CƠ CHẾ HOẠT ĐỘNG CỦA WAF REVERSE PROXY VÀ MÔ HÌNH PHÒNG THỦ ĐA TẦNG

### 1.2.1. Cổng tầng ứng dụng (Application-Level Gateway / Reverse Proxy WAF)
Theo giáo trình *Cryptography and Network Security* của William Stallings **[Ref 01]** và *NGINX Cookbook* **[Ref 05]**, tường lửa tiến hóa qua 3 thế hệ: Bộ lọc gói tin (Layer 3/4), Bộ lọc trạng thái (Stateful Inspection) và **Cổng tầng ứng dụng (Layer 7 Application-Level Gateway / Reverse Proxy WAF)**. Triển khai WAF theo mô hình Reverse Proxy đem lại 4 lợi thế chiến lược:
- **Ẩn giấu và cô lập máy chủ gốc (Origin Cloaking):** Ứng dụng mục tiêu (`vulnerable-api:5000`) chỉ lắng nghe trên giao diện loopback nội bộ, buộc 100% lưu lượng mạng LAN phải đi qua chốt chặn Gateway (`0.0.0.0:8000`).
- **Thanh lọc tiêu đề giao thức (Header Sanitization):** Loại bỏ hop-by-hop headers và chặn rò rỉ tiêu đề nhạy cảm (`X-API-Key`) xuống máy chủ đích, đồng thời bảo toàn chuẩn các tiêu đề đa giá trị như `Set-Cookie`.
- **Kiểm chứng Positive Security (OpenAPI 3.0 Contract):** Thực thi nguyên lý "chỉ cho phép những gì hợp lệ đã định nghĩa" (method, kiểu path parameter, `Content-Type`, schema body, chặn `additionalProperties`).
- **Đường ống phòng thủ chiều sâu (Defense-in-Depth Pipeline):** Tích hợp tuần tự Chuẩn hóa -> Multi-Protocol Decapsulation -> Schema Validator -> Hardened Rule Engine -> Unified 26-D AI/ML -> Hybrid Risk & Rate Limiting.

### 1.2.2. Cơ chế chấm điểm tích lũy và giới hạn của luật tĩnh
Chuẩn công nghiệp **OWASP ModSecurity CRS v4.0** **[Ref 07]** sử dụng mô hình tính điểm bất thường tích lũy (Anomaly Scoring) thay vì chặn cứng một luật đơn lẻ nhằm giảm báo động nhầm. Dù đạt tốc độ siêu nhanh (0.10–0.20 ms/req), WAF chỉ dùng luật tĩnh vẫn có 3 hạn chế cố hữu: (1) bất lực trước biến thể obfuscated/zero-day chưa có chữ ký, (2) đánh đổi gay gắt giữa False Positive và False Negative, và (3) rủi ro treo CPU do biểu thức chính quy quay lui bậc hai (**ReDoS O(n^2)**).

---

## 1.3. CƠ SỞ LÝ THUYẾT VỀ TRÍCH XUẤT ĐẶC TRƯNG 26 CHIỀU VÀ HỌC MÁY PHÒNG THỦ

### 1.3.1. Lý thuyết Shannon Entropy và Không gian 26 Đặc trưng Thống nhất (Unified 26-D Feature Vector)
Theo giáo trình *Cryptography: Theory and Practice* của Douglas R. Stinson và Maura B. Paterson **[Ref 02]**, độ hỗn loạn thông tin Shannon Entropy H(S) của chuỗi ký tự S độ dài L với tập ký tự phân biệt {c_1, ..., c_k} và xác suất p(c_i) = count(c_i) / L được định nghĩa:

    H(S) = - sum_{i=1..k} [ p(c_i) * log2(p(c_i)) ]

Văn bản tự nhiên hợp lệ có entropy vừa phải (2.0 <= H(S) <= 3.5 bit), trong khi payload tấn công bị mã hóa Base64/Hex hoặc làm mờ bằng ký tự đặc biệt thường đẩy H(S) tăng vọt (>= 3.8–4.5 bit).

Kế thừa nghiên cứu nền tảng của C. Torrano-Gimenez et al. (Wiley SCN 2015) **[Ref 15]** và khắc phục hoàn toàn hiện tượng lệch phân phối huấn luyện–vận hành (**Training-Serving Skew**), phiên bản **Blue Team v2.0** mở rộng từ không gian 17 chiều ban đầu lên **Không gian 26 đặc trưng thống nhất (`extract_26_from_http`)** dùng chung 100% giữa quá trình huấn luyện và suy luận thực tế:
- **Nhóm 1 — Hình thái & Entropy nền (12 đặc trưng):** `length`, `entropy`, `count_single_quote`, `count_double_quote`, `count_less_than`, `count_greater_than`, `count_semicolon`, `count_hyphen`, `count_slash`, `count_backslash`, `count_parenthesis`, `special_char_ratio`.
- **Nhóm 2 — Tín hiệu cú pháp 4 họ OWASP (7 đặc trưng):** `sql_keyword_count`, `xss_keyword_count`, `sqli_regex_matches`, `xss_regex_matches`, `path_traversal_matches`, `cmd_keyword_count`, `cmd_regex_matches`.
- **Nhóm 3 — Đặc trưng ngữ cảnh nâng cao chống False Positive & chống Evasion (7 đặc trưng):** `encoding_layer_depth` (số lớp mã hóa lồng), `sql_comment_and_func_score`, `param_value_entropy_ratio`, `numeric_anomaly_flag`, `natural_text_ratio` (nhận diện văn bản tự nhiên hợp lệ), `safe_structured_ratio` (nhận diện JSON/XML sạch), `protocol_complexity_score`.

### 1.3.2. Học máy có giám sát — Gradient Boosted Decision Trees (XGBoost v2.0) vs Random Forest
Đồ án đối sánh 5 trường phái học máy (Logistic Regression, Decision Tree, Random Forest **[Ref 12]**, LightGBM, và **XGBoost — Chen & Guestrin, ACM KDD 2016**):
- **Random Forest (Bagging Ensemble):** Xây dựng độc lập B cây quyết định trên các mẫu bootstrap và bỏ phiếu trung bình xác suất; ổn định nhưng chi phí suy luận single-request bằng scikit-learn `.joblib` cao (~10.8 ms/req) và tiềm ẩn rủi ro Pickle (CWE-502).
- **Champion Cost-Sensitive Regularized XGBoost v2.0 (Boosting Ensemble):** Huấn luyện tuần tự K cây hồi quy tối ưu hàm mục tiêu có điều chuẩn L2 (`reg_lambda = 2.0`, `max_depth = 6`, `n_estimators = 150`, `subsample = 0.8`, `colsample_bytree = 0.8`, `min_child_weight = 3`) kết hợp trọng số lớp nhạy chi phí (cost-sensitive) để kiểm soát chặt tỷ lệ báo động giả (FPR). Hàm mục tiêu tối ưu ở vòng lặp t:

      Obj(t) = sum_{i=1..N} L(y_i, y_hat_i^(t-1) + f_t(x_i)) + Omega(f_t)
      Omega(f) = gamma * T + 0.5 * lambda * sum_{j=1..T} w_j^2

- **Ưu thế kỹ thuật vượt trội ở Blue Team v2.0–v3.3:** XGBoost v2.0 hỗ trợ tuần tự hóa **Zero-Pickle UBJSON (`xgb_v2.ubj`)**, loại bỏ hoàn toàn nguy cơ thực thi mã tùy ý CWE-502, đồng thời đạt tốc độ suy luận **`0.439 ms/req`** (`0.618 ms` trên gateway micro-benchmark) với độ chính xác Test Set sau tái huấn luyện Zero-Leakage (`N = 6.929`) đạt **99.16%** và Macro-F1 **98.77%**.

### 1.3.3. Học máy không giám sát — Calibrated Isolation Forest v2.0 (Zero-Pickle NPZ)
Để phát hiện các payload dị biệt / Zero-Day nằm ngoài 5 nhãn đã học, hệ thống sử dụng thuật toán **Isolation Forest (iForest)** của Liu et al. (IEEE ICDM 2008) **[Ref 11]**. Điểm bất thường lý thuyết dựa trên độ sâu đường đi trung bình E(h(x)) trên các cây cô lập nhị phân ngẫu nhiên:

    s(x, n) = 2 ^ ( - E(h(x)) / c(n) )
    c(n) = 2 * ln(n - 1) + 0.5772156649 - 2 * (n - 1) / n

Thay vì dùng công thức tuyến tính cứng kém nhạy ở v1.0 (Recall chỉ 5.88%), **Blue Team v2.0** áp dụng **Hiệu chuẩn phân vị thực nghiệm (Empirical Percentile Calibration)** trên tập lưu lượng Benign sạch (`p01`, `p05`, `p10`, `p25`, `p50`, `p95`) và trích xuất toàn bộ cấu trúc cây sang định dạng **Zero-Pickle NumPy (`iforest_v2.npz`, 50.5 KB, `allow_pickle=False`)**, nâng tốc độ suy luận thuần lên **`0.095 ms/req`** (nhanh hơn ~100x) và tăng Recall phát hiện dị biệt `@60.0` lên **57.75%** (tăng **9.8x** so với v1.0).

### 1.3.4. Mô hình dung hợp rủi ro đa tầng (Hybrid Multi-Layer Risk & Decision Engine)
Theo kiến trúc đường ống đa tầng **[Ref 13]**, điểm rủi ro tổng hợp nằm trên thang chuẩn **0.0 – 100.0**:

    R_hybrid = clamp( w_rule * S_rule + w_ml * S_ml + w_anomaly * S_anomaly , 0.0 , 100.0 )
    với: w_rule = 0.40 , w_ml = 0.35 , w_anomaly = 0.25

Khi một thành phần ML ngoại tuyến, các trọng số hoạt động được tự động tái chuẩn hóa `w'_i = w_i / sum(w_active)` kèm Fail-Safe Risk Penalty (+15 điểm). Đồng thời, theo nguyên lý **High-Confidence Threat Override** **[Ref 15]**, nếu `S_rule >= 85.0`, `S_ml >= 90.0` hoặc phát hiện dị thường giao thức nghiêm trọng (XXE / GraphQL Deep Nesting), hệ thống lập tức nâng mức lên `BLOCK` để tránh bị pha loãng thống kê. Ma trận chính sách 4 ngưỡng:
- `Risk < 30.0`: **`ALLOW`** (HTTP 200 — chuyển tiếp sạch tới Upstream).
- `30.0 <= Risk < 60.0`: **`MONITOR`** (chuyển tiếp kèm ghi nhật ký `SecurityEvent`).
- `60.0 <= Risk < 80.0`: **`RATE_LIMIT`** (siết hạn ngạch / phạt HTTP 429).
- `Risk >= 80.0` (hoặc High-Confidence Override): **`BLOCK`** (ngắt kết nối HTTP 403 Forbidden chuẩn RFC 7807).

---

## 1.4. THAO TRƯỜNG MẠNG ĐỐI KHÁNG (CYBER RANGE) VÀ TÁC TỬ TẤN CÔNG TỰ ĐỘNG (OFFENSIVE AI)

### 1.4.1. Khung kiến trúc Thao trường mạng phân tán (Elsevier Yamin et al. 2020)
Theo khảo sát chuẩn mực của M. Yamin et al. (*Elsevier Computers & Security*, 2020) **[Ref 16]**, Thao trường mạng đối kháng của đề tài gồm 3 phân hệ phối hợp trên 2 máy tính vật lý kết nối qua mạng LAN:
1. **Target Environment (Máy 1):** Ứng dụng Web API mục tiêu Bookie Bookstore (`vulnerable-api`, Django, Port 5000) chứa 8 nhóm lỗ hổng OWASP chuẩn kèm đặc tả OpenAPI 3.0.
2. **Scoring & Monitoring Defense (Máy 1 — Blue Team):** High-Concurrency Async WAF Gateway v2.0 (Port 8000) + SOC Command Center Dashboard & AI Arena (Port 3000).
3. **Attack Simulation Engine (Máy 2 — Red Team):** Tác tử AI tự động trinh sát OpenAPI (`recon.py`), mô hình hóa Đồ thị Tấn công (`AttackGraph`), bộ biến dị bảo toàn ngữ nghĩa (`evasion.py`) và mô hình Học tăng cường sâu PyTorch DQN (`evasion_agent.pt`).

### 1.4.2. Trò chơi an ninh đối kháng (Adversarial Security Game) & Markov Decision Process (MDP)
Dựa trên mô hình hình thức của Katz & Lindell **[Ref 03]** và lý thuyết Học tăng cường của Sutton & Barto **[Ref 17]** cùng Mnih et al. (Nature 2015) **[Ref 18]**, bài toán kiểm thử né tránh WAF được mô hình hóa thành trò chơi đối kháng giữa Tác tử Red Team A và Cổng phòng thủ Blue Team C trên quy trình MDP `(S, A, P, R, gamma)`:
- **Không gian trạng thái & hành động tiến hóa qua các phiên bản:** Từ nguyên mẫu Task 10.2 (`40-D` state, `14` actions, `evasion_agent.pt`) mở rộng lên v3.0 (`64-D` state, `26` actions) và hoàn thiện ở **Phase E v3.3 (`pentest_dqn_v2.pt` / `.npz`) với `74` chiều trạng thái (`74-D`) và `36` hành động rời rạc (`36` actions)** kết hợp 17+ đặc trưng tiến trình/telemetry, one-hot họ lỗ hổng và mặt nạ hành động hợp lệ (Action Mask).
- **Không gian hành động (Action Space A — 14 -> 36 hành động rời rạc):** Bao gồm các pha trinh sát, thăm dò chuẩn và các toán tử đột biến bảo toàn ngữ nghĩa (SQL inline comment, case randomization, `BETWEEN` substitution, scientific-float `1e0UNION`, versioned comment `/*!50000...*/`, double URL encoding, XSS event handler/HTML entity, nested traversal `....//`, CMD `${IFS}`/quote concatenation/wildcard-globbing `/???/c?t`, JSON duplicate-key tamper).
- **Mạng nơ-ron PyTorch Dueling Double-DQN có Action Masking (`74 -> 128 -> 128 -> V(s) + A(s,a)`):** Xấp xỉ hàm giá trị tối ưu Q*(s, a) qua phương trình Bellman, huấn luyện theo giáo trình 4 giai đoạn (`800 episodes`: `600` RAM + `200` Live-HTTP `:8056/:8055`) và lọc bỏ mọi hành động không hợp lệ bằng mặt nạ `-1e9` trước bước `argmax`, được lưu và xác thực bằng `torch.load(..., weights_only=True)` + mã băm SHA-256 (kèm bản suy luận NumPy `.npz` cho môi trường CI).

---

## 1.5. CÁC THƯỚC ĐO VÀ TIÊU CHUẨN ĐÁNH GIÁ KHOA HỌC

Việc kiểm định khoa học tuân thủ nghiêm ngặt **OWASP Benchmark Project** **[Ref 08]**, **NIST SP 800-115** **[Ref 09]** và **ISO/IEC 27004:2016**, tuyệt đối không sử dụng số liệu mô phỏng hay rò rỉ dữ liệu Train/Test:
- **Các chỉ số phân loại:** `Accuracy`, `Precision`, `Recall (TPR)`, `False Positive Rate (FPR)`, `F1-Score (Macro & Binary)` và **Youden's Index `J = TPR - FPR`** (mục tiêu `J >= 0.90`, `FPR <= 1.0%` trên tập kiểm thử độc lập).
- **Tiêu chuẩn Zero-Leakage & Cross-Dataset Generalization:** Phân tách dữ liệu theo mã băm chuẩn hóa (Canonical Hash Disjoint Split) bảo đảm `0` mẫu trùng lặp giữa Train/Val/Test và tập chuẩn quốc tế **CSIC 2010** **[Ref 14]** cũng như tập kiểm định `benchmark_1000_diverse.csv`.
- **Ngân sách độ trễ & Thông lượng (Dual-Tier SLA):** Độ trễ xử lý nội bộ inline của engine AI/WAF `<= 1.5 ms/req`, độ trễ toàn trình 2-hop TCP HTTP proxy E2E `<= 5.5 ms/req`, thông lượng xử lý đồng thời của Gateway `>= 150 RPS` ở mức tải đồng thời `C = 50` không nghẽn Event Loop **[Ref 05]**.

---

## 1.6. TỔNG KẾT CHƯƠNG 1

Chương 1 đã xây dựng hệ thống cơ sở lý thuyết chặt chẽ gồm 20 tài liệu học thuật và tiêu chuẩn công nghiệp quốc tế, định hình toàn bộ nền tảng cho kiến trúc **Blue Team v2.0–v3.3** (Unified 26-D Feature Vector + Per-Parameter Max-Pooling, Zero-Pickle XGBoost v2.0 + Calibrated Isolation Forest v2.0, 28 Hardened Rules & 5 OWASP API Guards, Multi-Protocol Defense-in-Depth) và **Red Team Offensive AI** (OpenAPI Recon, Attack Graph MDP, PyTorch Dueling Double-DQN `74-D/36-A` với Action Masking) sẽ được thiết kế và cài đặt trong Chương 2 và Chương 3.
