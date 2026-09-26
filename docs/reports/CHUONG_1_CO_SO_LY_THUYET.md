# BÁO CÁO ĐỒ ÁN MÔN HỌC CHUYÊN NGÀNH AN TOÀN THÔNG TIN (PBL6)
# CHƯƠNG 1: CƠ SỞ LÝ THUYẾT VÀ TỔNG QUAN CÔNG TRÌNH NGHIÊN CỨU

> **Đề tài:** Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán  
> **Sinh viên thực hiện:** Ngô Văn Công  
> **Cơ sở khoa học tham chiếu:** 20 công trình và giáo trình kinh điển quốc tế (Prentice Hall, CRC Press, Sybex/Wiley, O'Reilly, IEEE, ACM, Elsevier, MDPI, NIST, OWASP, MITRE).

---

## 1.1. TỔNG QUAN VỀ BẢO MẬT WEB API VÀ CÁC THÁCH THỨC AN NINH HIỆN ĐẠI

### 1.1.1. Xu hướng kiến trúc Microservices và sự bùng nổ của Web API
Trong kỷ nguyên chuyển đổi số và điện toán đám mây, kiến trúc phần mềm đã trải qua sự chuyển dịch mang tính nền tảng từ các hệ thống nguyên khối (Monolithic Architecture) sang kiến trúc phân tán và vi dịch vụ (Microservices Architecture). Trong mô hình này, giao diện lập trình ứng dụng web (Web API), đặc biệt là chuẩn RESTful API truyền tải dữ liệu qua giao thức HTTP/HTTPS với định dạng JSON, đã trở thành huyết mạch kết nối toàn bộ hệ sinh thái dịch vụ số: từ ứng dụng Single Page Application (SPA), ứng dụng di động (Mobile Apps), hệ thống Internet vạn vật (IoT) cho đến các cổng thanh toán tài chính liên ngân hàng.

Tuy nhiên, sự bùng nổ về số lượng và tính phức tạp của Web API đã làm mở rộng đáng kể bề mặt tấn công (Attack Surface). Không giống như các ứng dụng web truyền thống hiển thị giao diện qua HTML/CSS, Web API phơi bày trực tiếp logic nghiệp vụ, các tham số truy vấn cơ sở dữ liệu và cấu trúc dữ liệu nhạy cảm. Kẻ tấn công có thể dễ dàng sử dụng các công cụ phân tích tự động, bóc tách tài liệu OpenAPI/Swagger specification để lập bản đồ các endpoint và thực hiện tấn công hàng loạt mà không bị cản trở bởi lớp giao diện người dùng **[Ref 04]**.

### 1.1.2. Phân tích các mối đe dọa hàng đầu theo OWASP Top 10 API Security Risks (2023)
Theo công bố chính thức từ tổ chức an toàn thông tin uy tín thế giới OWASP trong tài liệu *OWASP Top 10 API Security Risks 2023* **[Ref 06]**, các cuộc tấn công nhắm vào Web API ngày càng trở nên tinh vi và có tổ chức. Đồ án tập trung nghiên cứu và xây dựng giải pháp phòng thủ cho 4 nhóm hiểm họa nghiêm trọng nhất:

#### 1. Các lỗ hổng tiêm mã độc (Injection Vulnerabilities)
Bao gồm SQL Injection (In-band, Error-based, Time-based Blind SQLi **[Ref 10]**), OS Command Injection thực thi shellcode trực tiếp, và Path Traversal đọc tệp tin cấu hình nhạy cảm. Kẻ tấn công lợi dụng dữ liệu đầu vào chưa được kiểm duyệt để thay đổi logic truy vấn hoặc chiếm toàn quyền điều khiển hệ điều hành máy chủ.

#### 2. Tấn công Cross-Site Scripting (XSS)
Mặc dù API chủ yếu trả về dữ liệu JSON, nhưng các trường dữ liệu do API phản hồi thường được render trực tiếp lên trình duyệt của người dùng cuối trong các ứng dụng SPA (React, Vue, Next.js). Khi kẻ tấn công chèn thành công các payload chứa mã JavaScript nguy hại (`<script>`, `<img onerror=...>`) qua API, mã độc sẽ thực thi trong ngữ cảnh phiên nạn nhân, dẫn đến nguy cơ đánh cắp token JWT, session cookies hoặc chiếm đoạt tài khoản.

#### 3. Phá vỡ kiểm soát phân quyền mức đối tượng (Broken Object Level Authorization - BOLA / IDOR - API1:2023)
Lỗ hổng logic nghiệp vụ đứng số 1 về mức độ phổ biến, xảy ra khi máy chủ API không kiểm tra xem người dùng hiện tại có quyền thao tác trên mã đối tượng trong URL hay không (ví dụ: đổi `/orders/1` thành `/orders/2`). Các bộ lọc chữ ký regex truyền thống hoàn toàn bất lực trước loại lỗ hổng logic này **[Ref 06]**.

#### 4. Tiêu thụ tài nguyên không hạn chế (Unrestricted Resource Consumption - API4:2023)
Web API thường xuyên phải đối mặt với các cuộc tấn công tự động dò quét mật khẩu (Credential Stuffing, Password Brute-force) hoặc tấn công từ chối dịch vụ (Denial of Service - DoS) ở tầng ứng dụng (Layer 7). Khi không có cơ chế giới hạn tần suất (Rate Limiting) hiệu quả dựa trên địa chỉ IP hoặc định danh tài khoản, máy chủ API sẽ nhanh chóng bị vét cạn tài nguyên CPU, bộ nhớ RAM, kết nối cơ sở dữ liệu và băng thông mạng, dẫn đến tê liệt toàn bộ hệ thống dịch vụ **[Ref 05, Ref 06]**.

### 1.1.3. Các kỹ thuật làm mờ payload và né tránh tường lửa (WAF Evasion & Obfuscation Techniques)
Theo giáo trình kiểm thử xâm nhập chuẩn quốc tế *CompTIA PenTest+ Study Guide* **[Ref 04]**, trong bối cảnh các hệ thống tường lửa ứng dụng web truyền thống phụ thuộc nặng nề vào các tập luật kiểm tra mẫu chuỗi (Regex Pattern Matching), kẻ tấn công hiện đại — đặc biệt khi có sự hỗ trợ của các tác tử AI tấn công tự động — đã áp dụng các kỹ thuật làm mờ payload (Obfuscation) cực kỳ phức tạp để vượt rào (WAF Evasion):

| Kỹ Thuật Né Tránh | Cơ Chế Bản Chất | Ví Dụ Minh Họa | Hậu Quả Đối Với WAF Truyền Thống |
| :--- | :--- | :--- | :--- |
| **Mã hóa URL đa tầng (Double URL Encoding)** | Mã hóa ký tự `%` thành `%25` (ví dụ: dấu `'` thành `%27`, rồi thành `%2527`). | `%2527%20OR%20%2531%253D%2531` | WAF chỉ giải mã 1 lần thành `%27` và bỏ qua vì không thấy `'`; khi đến backend API, framework giải mã lần 2 kích hoạt SQLi. |
| **Chèn chú thích nội tuyến (Inline Comments)** | Chèn các chuỗi comment vô hại của ngôn ngữ đích vào giữa các từ khóa nhạy cảm. | `UN/**/ION/**/SEL/**/ECT` hoặc `cat</**/>etc/passwd` | Làm đứt gãy mẫu chuỗi regex chuẩn `UNION.*SELECT` hoặc `cat /etc/passwd`. |
| **Biến đổi chữ hoa/thường xen kẽ (Mixed-case Alternation)** | Thay đổi ngẫu nhiên trạng thái hoa thường không chuẩn hóa. | `sElEcT`, `<sCrIpt>`, `uNiOn` | Vượt qua các rule regex không thiết lập cờ `IGNORECASE` hoặc bộ chuẩn hóa đơn giản. |
| **Ký tự khoảng trắng thay thế (Alternative Whitespaces)** | Sử dụng ký tự đặc biệt của shell/SQL thay thế dấu cách thông thường (`0x20`). | `$IFS$9` trong Bash; `/**/`, `+`, `%09` (Tab), `%0a` (Newline). | Vượt qua các bộ luật kiểm tra sự tồn tại của dấu cách giữa các mệnh đề. |
| **Ký tự NULL Byte Injection** | Chèn ký tự kết thúc chuỗi `\x00` hoặc `%00`. | `../../etc/passwd%00.jpg` | Làm lừa các hàm kiểm tra đuôi mở rộng file ở ngôn ngữ bậc thấp (C/C++), cắt cụt chuỗi kiểm tra. |
| **Thực thi lệnh gián tiếp & Đa hình (Polymorphic Execution)** | Tận dụng cơ chế biến môi trường, nối chuỗi và subshell execution. | `c''a""t /e*c/pas*wd`, `$(echo Y2F0...\|base64 -d)` | Không chứa bất kỳ từ khóa tĩnh nào trong payload, vô hiệu hóa 100% chữ ký tĩnh. |

---

## 1.2. CƠ CHẾ HOẠT ĐỘNG CỦA TƯỜNG LỬA ỨNG DỤNG WEB (WAF) VÀ GIỚI HẠN CỦA PHƯƠNG PHÁP TRUYỀN THỐNG

### 1.2.1. Phân loại thế hệ Tường lửa và Nguyên lý Cổng tầng ứng dụng (Application-Level Gateway)
Trong công trình giáo trình kinh điển *Cryptography and Network Security: Principles and Practice* (Chương 20: Firewalls) **[Ref 01]**, Giáo sư William Stallings đã hệ thống hóa tường lửa thành ba thế hệ công nghệ tiến hóa:
1. **Bộ lọc gói tin (Packet Filtering Firewall):** Hoạt động ở tầng Mạng và Vận chuyển (Layer 3 & 4), chỉ kiểm tra địa chỉ IP nguồn/đích, cổng TCP/UDP mà hoàn toàn không có khả năng thấu hiểu nội dung dữ liệu ứng dụng.
2. **Bộ lọc trạng thái (Stateful Inspection Firewall):** Theo dõi trạng thái kết nối TCP (SYN, ACK, ESTABLISHED) nhằm ngăn chặn các gói tin giả mạo phiên.
3. **Cổng tầng ứng dụng (Application-Level Gateway / Reverse Proxy WAF):** Là thế hệ tường lửa tiên tiến nhất, hoạt động như một thực thể trung gian (Relay/Proxy) ở tầng Ứng dụng (Layer 7). Cổng ứng dụng tiếp nhận toàn bộ kết nối TCP từ máy khách, phân giải và tái cấu trúc hoàn chỉnh giao thức HTTP/HTTPS, kiểm tra toàn diện dữ liệu tải trọng (Payload) trước khi quyết định chuyển tiếp yêu cầu đến máy chủ nội bộ.

Theo kiến trúc điều phối lưu lượng trong cuốn *NGINX Cookbook* **[Ref 05]**, cơ chế Reverse Proxy WAF mang lại những lợi ích bảo mật vượt trội:
- **Ẩn giấu máy chủ gốc (Origin Cloaking):** Toàn bộ địa chỉ IP và kiến trúc nội bộ của máy chủ Web API được bảo vệ hoàn toàn phía sau Gateway.
- **Khử trùng tiêu đề giao thức (Hop-by-hop Headers Sanitization):** Loại bỏ các tiêu đề nhạy cảm hoặc có nguy cơ gây ô nhiễm giao thức (HTTP Request Smuggling, Open Proxy abuse).
- **Phân luồng kiểm tra chuyên sâu:** Cho phép tích hợp các bộ tiền xử lý (Input Normalizer), bộ kiểm tra luật (Rule Engine), bộ suy luận học máy (ML Detector) và bộ giới hạn tần suất (Rate Limiter) trên cùng một đường ống tuần tự.

### 1.2.2. Cơ chế chấm điểm bất thường lũy tiến (Anomaly Scoring System)
Khác với các cơ chế tường lửa cũ áp dụng phương thức chặn tức thời khi khớp một luật duy nhất (Traditional Disruptive Action / Single-Rule Blocking), chuẩn công nghiệp hiện đại **OWASP ModSecurity Core Rule Set (CRS v4.0)** **[Ref 07]** áp dụng kiến trúc **Collaborative Anomaly Scoring System**:
- Mỗi quy tắc phát hiện khi kích hoạt sẽ không chặn ngay request mà gán một trọng số bất thường dựa trên mức độ nghiêm trọng:
  - `CRITICAL`: +5 điểm (khớp trực tiếp cú pháp khai thác SQLi, OS Command Injection).
  - `HIGH`: +4 điểm (phát hiện hành vi quét lỗ hổng, traversal).
  - `MEDIUM`: +3 điểm (phát hiện từ khóa nhạy cảm, ký tự đặc biệt).
  - `LOW`: +2 điểm (sai lệch chuẩn giao thức HTTP).
- Điểm bất thường tích lũy (Cumulative Inbound Anomaly Score) được tính bằng tổng điểm của tất cả các quy tắc bị kích hoạt trên toàn bộ các trường của request:
  $$S_{\text{anomaly}} = \sum_{i \in \text{Rules matched}} \text{Score}(i)$$
- Chỉ khi $S_{\text{anomaly}} \ge \text{Anomaly Threshold}$ (thường mặc định là 5 điểm), WAF mới thực hiện ngắt kết nối và trả về mã lỗi `HTTP 403 Forbidden`. Mô hình này giảm thiểu đáng kể tỷ lệ chặn nhầm các yêu cầu hợp lệ có chứa một vài ký tự đặc biệt ngẫu nhiên.

### 1.2.3. Những giới hạn cốt tử của phương pháp dựa trên luật tĩnh
Mặc dù đóng vai trò là hàng rào lọc thô không thể thiếu nhờ tốc độ xử lý nhanh, WAF dựa trên luật tĩnh bộc lộ những khiếm khuyết nội tại không thể khắc phục trong môi trường tác chiến hiện đại theo phân tích của William Stallings **[Ref 01]**:
1. **Bất lực trước biến thể mới và tấn công chưa từng biết (Zero-day Attacks):** Luật chữ ký chỉ có thể phát hiện những gì đã được định nghĩa trước. Khi kẻ tấn công sử dụng cú pháp mới lạ, kỹ thuật zero-day hoặc chuỗi khai thác logic phức tạp, luật tĩnh hoàn toàn bị mù.
2. **Nghịch lý giữa Tỷ lệ báo động giả (False Positive) và Bỏ lọt mối đe dọa (False Negative):**
   - Nếu viết biểu thức chính quy quá chặt chẽ (strict), WAF sẽ chặn nhầm các yêu cầu nghiệp vụ hợp lệ chứa ký tự toán học, dấu nháy trong văn bản tiếng Việt/tiếng Anh hoặc mã định danh người dùng (False Positive cao), gây gián đoạn trải nghiệm người dùng.
   - Nếu nới lỏng biểu thức chính quy để tránh False Positive, kẻ tấn công sẽ dễ dàng chèn các ký tự làm mờ để lọt qua mắt WAF (False Negative cao).
3. **Chi phí tính toán và bảo trì tăng theo cấp số nhân (Regex Performance Degradation):** Khi số lượng luật tăng lên hàng nghìn regex phức tạp, chi phí kiểm tra mỗi request tăng mạnh, đặc biệt đối với các regex có nguy cơ dính lỗ hổng ReDoS (Regular Expression Denial of Service), khiến độ trễ proxy tăng vọt, gây nghẽn cổ chai cho toàn bộ hệ thống.

---

## 1.3. CƠ SỞ LÝ THUYẾT VỀ TRÍCH XUẤT ĐẶC TRƯNG VÀ HỌC MÁY TRONG PHÁT HIỆN TẤN CÔNG WEB

### 1.3.1. Phương pháp trích xuất đặc trưng hình thái học và thống kê chuỗi HTTP
Để giải quyết bài toán phân loại chuỗi ký tự HTTP bất kỳ mà không phụ thuộc vào từ điển chữ ký cố định, hệ thống chuyển đổi payload văn bản thành một vector đặc trưng số học nhiều chiều.

#### 1. Cơ sở toán học của độ hỗn loạn thông tin Shannon Entropy
Theo giáo trình kinh điển *Cryptography: Theory and Practice* của Douglas R. Stinson và Maura B. Paterson (Chương 2: Information Theory) **[Ref 02]**, độ hỗn loạn thông tin (Shannon Entropy) là thước đo định lượng toán học về tính ngẫu nhiên, độ bất định và lượng thông tin trung bình chứa trong một biến ngẫu nhiên rời rạc.

Cho một chuỗi ký tự payload $S$ có độ dài $L$, tập các ký tự phân biệt xuất hiện trong chuỗi là $\Sigma = \{c_1, c_2, \dots, c_k\}$. Xác suất xuất hiện $p(c_i)$ của ký tự $c_i$ được ước lượng bằng tần suất tương đối:
$$p(c_i) = \frac{\text{count}(c_i)}{L}$$
Độ hỗn loạn Shannon Entropy $H(S)$ (tính theo đơn vị bit) được định nghĩa theo công thức chuẩn:
$$H(S) = - \sum_{i=1}^{k} p(c_i) \log_2 p(c_i)$$

**Ý nghĩa vật lý và an ninh thông tin của $H(S)$:**
- **Văn bản tự nhiên / Tham số hợp lệ:** Chứa các từ ngữ ngữ pháp thông thường, có tính lặp lại cao về mặt ngôn ngữ (nguyên âm, phụ âm, từ vựng thông dụng), giá trị entropy thường dao động ở mức vừa phải: $2.0 \le H(S) \le 3.5$.
- **Payload tấn công / Mã độc làm mờ (Obfuscated Payloads):** Kẻ tấn công sử dụng các hàm băm, mã hóa Base64, mã hóa Hex, chèn ký tự ngẫu nhiên hoặc các toán tử đặc biệt nhằm phá vỡ cấu trúc cú pháp thông thường. Phân phối ký tự trở nên phân tán đều, khiến độ bất định tăng vọt, đẩy giá trị entropy lên rất cao: $H(S) \ge 3.8 - 4.5$.
- Do đó, Shannon Entropy đóng vai trò là một đặc trưng hình thái học cực kỳ nhạy cảm để phát hiện dấu hiệu bất thường mà không cần quan tâm đến ngữ nghĩa cụ thể của chuỗi.

#### 2. Không gian 17 đặc trưng hình thái chuẩn tắc (Canonical 17-D Feature Vector)
Kế thừa và chuẩn hóa công trình nghiên cứu nền tảng của C. Torrano-Gimenez et al. (Wiley Security and Communication Networks 2015) **[Ref 08]** và bài báo tổng quan SQLi của M. Hasan et al. (IEEE Access 2023) **[Ref 10]**, đồ án xây dựng một vector đặc trưng chuẩn tắc 17 chiều:
- **Nhóm 1: Thống kê hình thái học & Entropy (12 đặc trưng):**
  1. `length`: Độ dài ký tự của payload.
  2. `entropy`: Độ hỗn loạn Shannon Entropy.
  3. `count_single_quote`: Số lượng dấu nháy đơn `'` (chỉ thị tiêm SQLi).
  4. `count_double_quote`: Số lượng dấu nháy kép `"` (chỉ thị tiêm SQLi/XSS).
  5. `count_less_than`: Số lượng dấu nhỏ hơn `<` (chỉ thị mở thẻ HTML/XSS).
  6. `count_greater_than`: Số lượng dấu lớn hơn `>` (chỉ thị đóng thẻ HTML/XSS).
  7. `count_semicolon`: Số lượng dấu chấm phẩy `;` (chỉ thị kết thúc lệnh SQL/Shell).
  8. `count_hyphen`: Số lượng dấu gạch nối `-` (chỉ thị chuỗi comment SQL `--`).
  9. `count_slash`: Số lượng dấu gạch chéo `/` (chỉ thị Path Traversal/Comment).
  10. `count_backslash`: Số lượng dấu gạch chéo ngược `\` (chỉ thị Path Traversal Windows/Escape).
  11. `count_parenthesis`: Số lượng dấu đóng/mở ngoặc đơn `(` và `)`.
  12. `special_char_ratio`: Tỷ lệ ký tự đặc biệt trên tổng độ dài chuỗi:
      $$\text{special\_char\_ratio} = \frac{\sum \text{ký tự không phải alnum và khoảng trắng}}{\max(1, \text{length})}$$
- **Nhóm 2: Mật độ từ khóa và cú pháp tấn công (5 đặc trưng):**
  13. `sql_keyword_count`: Tần suất xuất hiện các từ khóa SQL (SELECT, UNION, DROP, WHERE, EXEC...).
  14. `xss_keyword_count`: Tần suất xuất hiện các từ khóa JavaScript/DOM (script, alert, onerror, eval...).
  15. `sqli_regex_matches`: Số lượng mẫu cú pháp SQLi điển hình khớp (`UNION SELECT`, `OR 1=1`, `'--`).
  16. `xss_regex_matches`: Số lượng mẫu thực thi XSS khớp (`<script>`, `javascript:`, `on*=`...).
  17. `path_traversal_matches`: Số lượng mẫu duyệt thư mục khớp (`../`, `..\`, `/etc/passwd`...).

### 1.3.2. Thuật toán học máy có giám sát (Supervised Learning) — Rừng ngẫu nhiên (Random Forest)
#### 1. Cơ sở lý thuyết của Random Forest
Random Forest là một thuật toán học máy kết hợp (Ensemble Learning) dựa trên kỹ thuật **Bootstrap Aggregating (Bagging)** và chọn lọc đặc trưng ngẫu nhiên (Random Subspace Method) do Leo Breiman đề xuất năm 2001:
- Huấn luyện một tập hợp $B$ cây quyết định độc lập $\{T_1, T_2, \dots, T_B\}$.
- Mỗi cây được huấn luyện trên một tập dữ liệu con được rút mẫu có hoàn lại (bootstrap sample) từ tập huấn luyện gốc.
- Tại mỗi nút phân nhánh của cây, thuật toán chỉ chọn ngẫu nhiên một tập con gồm $m \approx \sqrt{p}$ đặc trưng (với $p=17$) để tìm điểm phân tách tối ưu theo chỉ số Gini Impurity:
  $$\text{Gini}(D) = 1 - \sum_{i=1}^{C} p_i^2$$
- Kết quả phân loại cuối cùng của toàn bộ rừng được xác định bằng cơ chế bỏ phiếu đa số (Majority Voting) hoặc trung bình xác suất có trọng số:
  $$\hat{y} = \arg\max_{c} \frac{1}{B} \sum_{b=1}^{B} P_{T_b}(y = c \mid \mathbf{x})$$

#### 2. Động lực lựa chọn Random Forest thay vì Deep Learning / Transformers
Theo kết quả khảo sát thực nghiệm chuyên sâu được công bố trên *IEEE Access* (2024) **[Ref 12]** và *MDPI Electronics* (2025) **[Ref 11]**, việc ứng dụng các mạng nơ-ron sâu phức tạp (CNN, Bi-LSTM) hoặc Transformers (BERT) vào tầng WAF Gateway gặp phải các trở ngại bất khả thi trong môi trường sản xuất thực tế:
1. **Ngân sách độ trễ (Inference Latency):** Random Forest chỉ tiêu tốn từ $0.02\text{ms}$ đến $0.05\text{ms}$ trên CPU đơn lõi thông thường để hoàn thành phân loại một request. Trong khi đó, các mô hình ngôn ngữ như DistilBERT cần từ $60\text{ms}$ đến $150\text{ms}$ (kể cả khi chạy trên GPU), gây nghẽn nghiêm trọng thông lượng mạng.
2. **Khả năng diễn giải (Explainability & Interpretability):** Random Forest cho phép tính toán chỉ số tầm quan trọng của đặc trưng (Feature Importance), giúp các kỹ sư bảo mật SOC hiểu rõ lý do mô hình đưa ra kết luận (ví dụ: `count_single_quote` và `entropy` đóng góp 75% vào quyết định phân loại SQLi).
3. **Độ bền vững và khả năng chống quá khớp (Anti-overfitting):** Nhờ cơ chế lấy mẫu ngẫu nhiên hai tầng, Random Forest có khả năng chống nhiễu cực tốt khi gặp phải các payload có biến đổi nhỏ về hình thái.

### 1.3.3. Thuật toán học máy không giám sát (Unsupervised Learning) — Rừng cô lập (Isolation Forest)
Để đối phó với các cuộc tấn công Zero-day hoặc các mẫu biến dị payload mà tập huấn luyện có giám sát chưa từng gặp, hệ thống tích hợp mô hình phát hiện bất thường không giám sát **Isolation Forest (iForest)** (Liu et al. ICDM 2008).

#### 1. Nguyên lý cô lập dữ liệu (Isolation Principle)
Thuật toán dựa trên hai quan sát thực tế trong an ninh mạng:
1. Các điểm dữ liệu dị biệt (Anomalies / Attacks) chiếm thiểu số trong tổng lưu lượng.
2. Các điểm dị biệt có các giá trị thuộc tính phân tán rất khác so với phần lớn các mẫu bình thường (Inliers / Benign).

Thay vì tính toán khoảng cách hình học hoặc mật độ cụm (rất tốn kém về thời gian tính toán như $k$-Means hay DBSCAN), Isolation Forest xây dựng tập hợp $T$ cây cô lập nhị phân (**Isolation Trees - iTrees**):
- Tại mỗi nút, chọn ngẫu nhiên một đặc trưng $q$ và chọn ngẫu nhiên một giá trị phân tách $p$ trong khoảng $(\min(q), \max(q))$.
- Quá trình phân nhánh đệ quy tiếp diễn cho đến khi mỗi mẫu dữ liệu bị cô lập hoàn toàn tại một nút lá hoặc đạt độ sâu giới hạn.
- Do các điểm dị biệt nằm ở vùng thưa thớt, chúng sẽ bị cô lập rất nhanh chóng và có **độ sâu đường đi (Path Length $h(x)$)** từ gốc đến lá rất ngắn so với các điểm dữ liệu bình thường nằm tập trung ở vùng mật độ cao.

#### 2. Công thức toán học tính điểm bất thường (Anomaly Score)
Điểm bất thường $s(x, n)$ của một mẫu $x$ trên tập dữ liệu $n$ mẫu được định nghĩa theo công thức chuẩn:
$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$
Trong đó:
- $\mathbb{E}(h(x))$ là độ dài đường đi trung bình của mẫu $x$ qua toàn bộ các cây iTrees trong rừng.
- $c(n)$ là độ dài đường đi trung bình lý thuyết của cây nhị phân không thành công, tương đương cây tìm kiếm nhị phân ngẫu nhiên (Binary Search Tree):
  $$c(n) = 2 \ln(n - 1) + 0.5772156649 \text{ (Hằng số Euler-Mascheroni)} - \frac{2(n - 1)}{n}$$

**Quy tắc diễn giải điểm số $s(x, n)$:**
- Nếu $s \to 1.0$: Mẫu có $\mathbb{E}(h(x)) \to 0$, bị cô lập cực kỳ nhanh $\rightarrow$ Khả năng rất cao là mối đe dọa dị biệt / Zero-day.
- Nếu $s < 0.5$: Mẫu có độ sâu lớn, nằm sâu trong cụm phân phối bình thường $\rightarrow$ Dữ liệu an toàn (Benign).
- Nếu $s \approx 0.5$: Toàn bộ tập mẫu không có sự phân tách rõ rệt.

### 1.3.4. Mô hình dung hợp rủi ro đa tầng (Hybrid Multi-Layer Risk Engine)
Nhằm đạt được sự cân bằng tối ưu giữa độ trễ cực thấp và độ chính xác phòng thủ tuyệt đối, hệ thống áp dụng kiến trúc **Dual-Stage Pipeline** theo nghiên cứu MDPI Electronics 2025 **[Ref 11]**:
- **Tầng 1 (Fast Path):** Rule Engine kiểm tra nhanh các biểu thức chính quy tĩnh. Nếu vi phạm nghiêm trọng (Critical Signature), hệ thống có thể kích hoạt chặn ngay trong $< 1\text{ms}$.
- **Tầng 2 (Deep Path):** Đối với các request vượt qua Fast Path hoặc ở mức nghi vấn, trích xuất 17 đặc trưng và chạy song song qua Random Forest và Isolation Forest.

Điểm rủi ro tổng hợp cuối cùng (**Weighted Hybrid Risk Score**) nằm trong thang đo chuẩn $0.0 - 100.0$, được tính toán theo công thức kết hợp tuyến tính có trọng số:
$$\text{Risk Score} = w_1 \times S_{\text{Rule}} + w_2 \times S_{\text{RF}} + w_3 \times S_{\text{Anomaly}}$$
Với các trọng số được tối ưu hóa qua thực nghiệm:
- $w_1 = 0.40$ (Tỷ trọng 40% cho Rule Engine tĩnh nhằm đảm bảo tính chắc chắn tuyệt đối đối với các mẫu chữ ký đã biết).
- $w_2 = 0.35$ (Tỷ trọng 35% cho mô hình có giám sát Random Forest phân loại hành vi tấn công).
- $w_3 = 0.25$ (Tỷ trọng 25% cho mô hình không giám sát Isolation Forest bắt bất thường và Zero-day).

Hệ thống ra quyết định phòng thủ đa ngưỡng (**Multi-Threshold Policy Matrix**) phân tầng theo chuẩn MITRE ATT&CK Mitigation **[Ref 16]**:
- $\text{Risk Score} < 30$: `ALLOW` (Cho phép yêu cầu đi tiếp đến backend API).
- $30 \le \text{Risk Score} < 60$: `MONITOR` (Cho phép đi qua nhưng ghi log kiểm toán chuyên sâu để phân tích).
- $60 \le \text{Risk Score} < 80$: `RATE_LIMIT` (Áp đặt hình phạt cắt giảm 50% hạn ngạch truy cập và trì hoãn phản hồi).
- $\text{Risk Score} \ge 80$: `BLOCK` (Lập tức từ chối yêu cầu với mã phản hồi `HTTP 403 Forbidden`).

---

## 1.4. CƠ SỞ LÝ THUYẾT VỀ THAO TRƯỜNG MẠNG (CYBER RANGE) VÀ TÁC TỬ TẤN CÔNG TỰ ĐỘNG (OFFENSIVE AI)

### 1.4.1. Khung kiến trúc Thao trường mạng phân tán tiêu chuẩn quốc tế
Theo định nghĩa chuẩn mực từ công trình nghiên cứu toàn diện của M. Yamin et al. công bố trên tạp chí quốc tế *Elsevier Computers & Security* (2020) **[Ref 14]**, một nền tảng Thao trường mạng (Cyber Range) tiêu chuẩn phải bao gồm tối thiểu 3 phân hệ chức năng độc lập:

```
+-----------------------------------------------------------------------------------+
|               DISTRIBUTED CYBER RANGE ARCHITECTURE (Yamin et al. 2020)            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [PHÂN HỆ 1: TARGET ENVIRONMENT]          [PHÂN HỆ 2: ATTACK SIMULATION ENGINE]  |
|  • Máy chủ Web API dễ bị tổn thương       • Tác tử tấn công tự động (Red Team)    |
|  • Chứa các điểm yếu OWASP Top 10         • Trinh sát OpenAPI & Fuzzing phụ thuộc |
|  • Cơ sở dữ liệu SQLite/PostgreSQL        • Đột biến Payload né tránh WAF         |
|  • Môi trường Docker cô lập               • Huấn luyện Deep RL (DQN Evasion)      |
|               ^                                           |                       |
|               |              VẬT LÝ QUA MẠNG LAN          |                       |
|               +--------------------+----------------------+                       |
|                                    |                                              |
|                                    v                                              |
|                    [PHÂN HỆ 3: SCORING & MONITORING WAF]                          |
|                    • Cổng bảo vệ WAF Gateway (Reverse Proxy)                      |
|                    • Động cơ đa tầng: Rule + RF + Isolation Forest                |
|                    • Chấm điểm rủi ro thời gian thực (0 - 100)                    |
|                    • SOC Telemetry Dashboard (Next.js 14)                         |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 1.4.2. Cơ sở lý thuyết về Trò chơi an ninh đối kháng (Adversarial Security Game)
Để thiết lập nền tảng lý thuyết toán học vững chắc cho cuộc đối đầu giữa Red Team và Blue Team trong Thao trường mạng, đồ án vận dụng mô hình hóa hình thức từ giáo trình kinh điển *Introduction to Modern Cryptography* của Jonathan Katz và Yehuda Lindell (Chương 3: Adversarial Models) **[Ref 03]**.

Bài toán vượt rào WAF được hình thức hóa dưới dạng một **Trò chơi an ninh đối kháng (Security Game)** giữa Bên tấn công (Adversary $\mathcal{A}$) và Bên phòng thủ (Defender/Challenger $\mathcal{C}$):
1. **Thiết lập (Setup):** Bên phòng thủ $\mathcal{C}$ thiết lập hệ thống phòng thủ WAF với tập tham số $\Pi = \{\text{Rules}, \mathbf{w}_{\text{RF}}, \theta_{\text{iForest}}, \tau_{\text{threshold}}\}$.
2. **Truy vấn Oracle (Oracle Query):** Bên tấn công $\mathcal{A}$ gửi một chuỗi các yêu cầu thử nghiệm $x_1, x_2, \dots, x_m$ đến cổng phòng thủ và quan sát phản hồi từ Oracle $\mathcal{O}_{\mathcal{C}}(x) \to (\text{Status}, \text{Latency}, \text{Blocked})$.
3. **Mục tiêu tấn công:** Bên tấn công chiến thắng trò chơi nếu tìm ra được một biến thể payload $x^*$ sao cho:
   - $x^*$ khai thác thành công lỗ hổng trên ứng dụng mục tiêu: $\text{Exploit}(x^*) = 1$.
   - Đồng thời $x^*$ qua mặt được bộ lọc phòng thủ: $\text{WAF}(x^*) = \text{ALLOW}$.
4. **Hàm lợi thế tấn công (Adversarial Advantage):**
   $$\mathbf{Adv}(\mathcal{A}) = \left| \Pr[\mathcal{A} \text{ bypasses WAF}] - \Pr[\text{Random Guess bypasses WAF}] \right|$$

Hệ thống phòng thủ đạt độ an toàn vững chắc khi và chỉ khi với mọi tác tử tấn công $\mathcal{A}$ bị giới hạn về ngân sách tài nguyên tính toán trong thời gian đa thức (Probabilistic Polynomial-Time - PPT), hàm lợi thế $\mathbf{Adv}(\mathcal{A})$ là một hàm không đáng kể (negligible function) đối với các lỗ hổng đã biết.

### 1.4.3. Quy trình trinh sát và Tác tử tấn công tự động (Offensive AI & Red Teaming)
Theo phương pháp luận kiểm thử xâm nhập của giáo trình *CompTIA PenTest+* **[Ref 04]**, tác tử Red Team (Máy 2) được thiết kế vận hành theo chu trình 3 bước:
1. **Trinh sát tự động (Reconnaissance & OpenAPI Parsing):**
   - Tác tử tự động gửi yêu cầu đọc tài liệu OpenAPI Specification (`/openapi.json` hoặc `/docs`).
   - Bóc tách toàn bộ danh sách endpoint, phương thức HTTP (GET, POST, PUT, DELETE), cấu trúc dữ liệu schema JSON, và kiểu dữ liệu tham số.
2. **Kiểm thử tự động phụ thuộc trạng thái (Stateful REST API Fuzzing):**
   - Vận dụng nguyên lý của công cụ khoa học hàng đầu **RESTler** (IEEE ICSE 2019) **[Ref 17]**, tác tử xây dựng đồ thị phụ thuộc (Producer-Consumer Dependency Graph): ví dụ tạo đơn hàng trước để lấy `order_id`, sau đó dùng `order_id` này để fuzzing các endpoint khai thác BOLA/IDOR hoặc SQLi.
3. **Kiểm thử xác minh lỗ hổng (Exploitation & Verification):**
   - Bơm các payload độc hại được đột biến có chủ đích vào từng tham số.
   - Giám sát mã phản hồi HTTP: nếu nhận mã lỗi `200 OK` hoặc `500 Internal Server Error` kèm dữ liệu trích xuất nhạy cảm, tác tử ghi nhận khai thác thành công.

Toàn bộ các kỹ thuật tấn công được ánh xạ chuẩn tắc theo danh mục **MITRE ATT&CK Enterprise Matrix** **[Ref 16]**:
- **T1190 (Exploit Public-Facing Application):** Khai thác lỗ hổng Web API (SQLi, Command Injection).
- **T1059 (Command and Scripting Interpreter):** Thực thi lệnh shell qua OS Command Injection.
- **T1083 (File and Directory Discovery):** Dò quét cấu trúc thư mục hệ thống qua Path Traversal.
- **T1595 (Active Scanning):** Quét dò endpoint và trinh sát OpenAPI tự động.

### 1.4.4. Mô hình Học tăng cường sâu (Deep Reinforcement Learning - DQN) trong né tránh phòng thủ
Để mô hình hóa hành vi né tránh WAF một cách tối ưu và hoàn toàn độc lập với các dịch vụ đám mây thương mại (100% In-house PyTorch) theo khuyến nghị từ các nghiên cứu khảo sát tác tử AI **[Ref 19, Ref 20]**, bài toán vượt WAF được phát biểu dưới dạng **Quy trình quyết định Markov (Markov Decision Process - MDP)**:
- **Không gian trạng thái (State Space $\mathcal{S}$):** Vector biểu diễn đặc trưng của payload hiện tại và thông tin phản hồi từ Gateway (Mã trạng thái HTTP: 200, 403, 429, 500; Điểm rủi ro trả về trong Header `X-WAF-Risk-Score`).
- **Không gian hành động (Action Space $\mathcal{A}$):** Tập hợp các toán tử đột biến payload:
  $$\mathcal{A} = \{\text{Double URL Encode, Inline Comment, Mixed-case, Null-byte, Base64 Wrap, Subshell Expansion}\}$$
- **Hàm phần thưởng (Reward Function $\mathcal{R}$):**
  $$\mathcal{R}(s, a) = \begin{cases} +100 & \text{nếu vượt WAF thành công (HTTP 200/500 và khai thác được dữ liệu)} \\ -50 & \text{nếu bị WAF chặn (HTTP 403 Forbidden)} \\ -10 & \text{chi phí độ trễ cho mỗi bước đột biến dư thừa} \end{cases}$$
- **Mạng nơ-ron Q sâu (Deep Q-Network - DQN):** Tác tử sử dụng mạng nơ-ron nhiều lớp (Multi-Layer Perceptron) xấp xỉ hàm giá trị tối ưu $Q^*(s, a)$ dựa trên phương trình Bellman:
  $$Q(s, a) \leftarrow Q(s, a) + \alpha \left[ r + \gamma \max_{a'} Q(s', a') - Q(s, a) \right]$$
Thông qua hàng nghìn vòng lặp huấn luyện đối kháng đối đầu trực tiếp với WAF Gateway, mạng DQN tự động học được chiến lược đột biến payload tối ưu nhất để luồn lách qua các khe hở của mô hình phòng thủ.

---

## 1.5. CÁC THƯỚC ĐO VÀ TIÊU CHUẨN ĐÁNH GIÁ HIỆU NĂNG KHOA HỌC (EVALUATION METRICS & BENCHMARKS)

Để loại bỏ các đánh giá mang tính cảm tính và đảm bảo tính chặt chẽ về mặt phương pháp luận khoa học, việc đánh giá hiệu năng của hệ thống WAF phòng thủ và mô hình Machine Learning được quy chuẩn hóa theo các tiêu chuẩn đo lường của **OWASP Benchmark Project** **[Ref 13]**, hướng dẫn đánh giá an ninh của **NIST SP 800-115** **[Ref 15]** và lý thuyết học máy thống kê:

### 1.5.1. Ma trận nhầm lẫn (Confusion Matrix)
| Thực tế \ Dự đoán | Dự đoán là TẤN CÔNG (Positive) | Dự đoán là AN TOÀN (Negative) |
| :--- | :--- | :--- |
| **Thực tế là TẤN CÔNG** | **True Positive (TP):** Bắt đúng tấn công. | **False Negative (FN):** Bỏ lọt tấn công (Nguy hiểm nhất). |
| **Thực tế là AN TOÀN** | **False Positive (FP):** Báo động nhầm người dùng tốt. | **True Negative (TN):** Cho qua đúng yêu cầu hợp lệ. |

### 1.5.2. Các chỉ số thống kê cốt lõi
1. **Độ chính xác tổng thể (Accuracy):**
   $$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$$
2. **Độ chuẩn xác (Precision):** Tỷ lệ các cảnh báo thực sự là tấn công:
   $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
3. **Độ nhạy / Tỷ lệ phát hiện (Recall / True Positive Rate - TPR):** Khả năng tóm gọn các cuộc tấn công của hệ thống:
   $$\text{TPR} = \text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
4. **Tỷ lệ báo động giả (False Positive Rate - FPR):** Tỷ lệ người dùng lành tính bị hệ thống chặn nhầm:
   $$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$
5. **Điểm F1-Score (F-measure):** Trung bình điều hòa giữa Precision và Recall, đặc biệt quan trọng khi dữ liệu có sự mất cân bằng lớp:
   $$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2\text{TP}}{2\text{TP} + \text{FP} + \text{FN}}$$

### 1.5.3. Thước đo Youden's Index ($J$) theo chuẩn OWASP Benchmark Project
Theo tiêu chuẩn đánh giá WAF của tổ chức OWASP (**OWASP Benchmark Score Metric**) **[Ref 13]**, một hệ thống tường lửa thương mại chỉ được coi là đạt chất lượng khi vừa tối đa hóa tỷ lệ bắt tấn công (TPR), vừa triệt tiêu tối đa tỷ lệ báo động giả gây gián đoạn kinh doanh (FPR). Thước đo khoa học **Youden's Index $J$** được định nghĩa:
$$J = \text{TPR} - \text{FPR} = \frac{\text{TP}}{\text{TP} + \text{FN}} - \frac{\text{FP}}{\text{FP} + \text{TN}}$$
- Thang đo Youden's $J \in [-1.0, 1.0]$.
- $J = 1.0$: Hệ thống lý tưởng tuyệt đối ($\text{TPR} = 100\%$, $\text{FPR} = 0\%$).
- $J = 0.0$: Hệ thống hoạt động không hơn gì một bộ đoán ngẫu nhiên (Random Guessing).
- $J < 0.0$: Hệ thống hoàn toàn sai lệch (bắt nhầm người tốt nhiều hơn kẻ tấn công).
- **Mục tiêu của đồ án PBL6:** Đạt chỉ số $J \ge 0.90$ trên tập dữ liệu kiểm thử thực nghiệm đa dạng.

### 1.5.4. Các chỉ số về hiệu năng mạng và độ trễ hệ thống (Latency Budget & Throughput)
Theo tiêu chuẩn vận hành kiến trúc Reverse Proxy hiệu năng cao trong *NGINX Cookbook* **[Ref 05]**, một hệ thống WAF bảo vệ ứng dụng Web API bắt buộc phải tuân thủ nghiêm ngặt các yêu cầu phi chức năng về hiệu năng vận hành:
1. **Ngân sách độ trễ gia tăng (Proxy Overhead Latency Budget):**
   $$\Delta t = t_{\text{with WAF}} - t_{\text{direct}}$$
   Hệ thống đặt mục tiêu $\Delta t \le 15\text{ms}$ cho quy trình hoàn chỉnh (Fast Path Regex + Feature Extraction + RF Inference + Isolation Forest + Decision Engine).
2. **Thông lượng xử lý (System Throughput):** Đo lường số lượng yêu cầu phục vụ trên một giây ($\text{Requests Per Second - RPS}$) mà không làm tràn hàng đợi CPU hoặc rò rỉ bộ nhớ RAM.

---

## 1.6. TỔNG KẾT CHƯƠNG 1

Chương 1 đã thiết lập một nền tảng cơ sở lý thuyết toàn diện và vững chắc cho toàn bộ đồ án PBL6 dựa trên mô hình Kiềng ba chân học thuật:
1. **Giáo trình kinh điển:** Vận dụng lý thuyết Cổng tầng ứng dụng của William Stallings, cơ sở toán học về Shannon Entropy của Douglas Stinson, mô hình Trò chơi an ninh đối kháng của Jonathan Katz & Yehuda Lindell, phương pháp luận kiểm thử của CompTIA PenTest+, và kiến trúc Reverse Proxy từ NGINX Cookbook.
2. **Tiêu chuẩn công nghiệp:** Bám sát bộ rủi ro OWASP Top 10 API Security Risks (2023), kiến trúc Anomaly Scoring của OWASP ModSecurity CRS v4.0, quy trình đánh giá NIST SP 800-115, và ma trận kỹ thuật MITRE ATT&CK.
3. **Công trình khoa học thực nghiệm:** Triển khai không gian 17 đặc trưng hình thái chuẩn Torrano-Gimenez (Wiley 2015), bộ dữ liệu chuẩn quốc tế CSIC 2010, khảo sát SQLi của IEEE Access (2023), kiến trúc Hybrid WAF của MDPI Electronics (2025), và mô hình Thao trường mạng chuẩn Elsevier (2020).

Hệ thống lý thuyết này định hình trực tiếp toàn bộ thiết kế kiến trúc, thuật toán và phương pháp luận thực nghiệm sẽ được trình bày chi tiết trong các chương tiếp theo của đồ án.
