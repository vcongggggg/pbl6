# BÁO CÁO ĐỒ ÁN MÔN HỌC CHUYÊN NGÀNH AN TOÀN THÔNG TIN (PBL6)
# CHƯƠNG 1: CƠ SỞ LÝ THUYẾT VÀ TỔNG QUAN CÔNG TRÌNH NGHIÊN CỨU

> **Đề tài:** Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán  
> **(Web API Security Platform & Autonomous Red Teaming on Distributed Cyber Range)**  
> **Sinh viên thực hiện:** Thành viên A (Tech Lead & Defense ML) - Thành viên B (Offensive AI & PyTorch RL)  
> **Đơn vị đào tạo:** Khoa Công nghệ Thông tin - Bộ môn An toàn Thông tin, Trường Đại học Bách khoa - Đại học Đà Nẵng  
> **Tài liệu tham khảo học thuật:** 20 công trình khoa học và tiêu chuẩn quốc tế (USENIX Security, IEEE, ACM, MDPI, NIST, OWASP, MITRE)  

---

## 1.1. TỔNG QUAN VỀ BẢO MẬT WEB API VÀ CÁC THÁCH THỨC AN NINH HIỆN ĐẠI

### 1.1.1. Xu hướng kiến trúc Microservices và sự bùng nổ của Web API
Trong kỷ nguyên chuyển đổi số và điện toán đám mây, kiến trúc phần mềm đã trải qua sự chuyển dịch mạnh mẽ từ các ứng dụng nguyên khối (Monolithic Architecture) sang kiến trúc hướng dịch vụ phân tán và vi dịch vụ (Microservices Architecture). Trong mô hình này, giao diện lập trình ứng dụng web (Web API), đặc biệt là chuẩn RESTful API truyền tải dữ liệu qua giao thức HTTP/HTTPS với định dạng JSON, đã trở thành xương sống kết nối toàn bộ hệ sinh thái dịch vụ: từ ứng dụng Single Page Application (SPA), ứng dụng di động (Mobile Apps), hệ thống Internet vạn vật (IoT) cho đến các cổng thanh toán tài chính liên ngân hàng.

Tuy nhiên, sự bùng nổ về số lượng và tính phức tạp của Web API đã làm mở rộng đáng kể bề mặt tấn công (Attack Surface). Không giống như các ứng dụng web truyền thống hiển thị giao diện người dùng qua HTML/CSS, Web API phơi bày trực tiếp logic nghiệp vụ, các tham số truy vấn cơ sở dữ liệu và cấu trúc dữ liệu nhạy cảm. Kẻ tấn công có thể dễ dàng sử dụng các công cụ phân tích tự động, phân tích cú pháp OpenAPI/Swagger specification để lập bản đồ các endpoint và thực hiện tấn công hàng loạt mà không bị cản trở bởi lớp giao diện người dùng.

### 1.1.2. Phân tích các mối đe dọa hàng đầu theo OWASP Top 10 API Security Risks (2023)
Theo công bố chính thức từ tổ chức bảo mật uy tín toàn cầu OWASP trong tài liệu *OWASP Top 10 API Security Risks 2023* **[Ref 13]**, các cuộc tấn công nhắm vào Web API ngày càng trở nên tinh vi và có chủ đích. Dưới đây là phân tích chi tiết các lớp hiểm họa trọng tâm mà hệ thống phòng thủ cần giải quyết:

#### 1. Các lỗ hổng tiêm mã độc (Injection Vulnerabilities)
- **SQL Injection (SQLi):** Xảy ra khi dữ liệu đầu vào không tin cậy từ người dùng (qua URL path, Query string, Headers hoặc JSON body) được ghép trực tiếp vào câu lệnh truy vấn SQL gửi xuống hệ quản trị cơ sở dữ liệu (RDBMS) mà không qua cơ chế kiểm tra (sanitization) hoặc tham số hóa (parameterization). Kẻ tấn công có thể thay đổi logic truy vấn, trích xuất toàn bộ dữ liệu bí mật (In-band SQLi), kích hoạt ngoại lệ hệ thống để đọc cấu trúc bảng (Error-based SQLi), suy luận thông tin qua phản hồi boolean hoặc độ trễ thời gian thực thi (Inferential/Time-based Blind SQLi), hoặc thực thi mã lệnh cấp hệ điều hành qua các thủ tục lưu sẵn (Out-of-band SQLi) **[Ref 10]**.
- **OS Command Injection:** Xuất hiện khi API gọi trực tiếp các lệnh shell của hệ điều hành (ví dụ: `os.system()`, `subprocess.Popen()` trong Python hoặc `exec()` trong PHP) với dữ liệu đầu vào chưa được kiểm duyệt. Kẻ tấn công lợi dụng các ký tự phân tách lệnh như `;`, `&&`, `|`, `$(...)`, `` `...` `` để thực thi các lệnh nhạy cảm như đọc `/etc/passwd`, tạo reverse shell kết nối về máy chủ tấn công (C2 Server), chiếm toàn quyền kiểm soát máy chủ web.
- **Path Traversal (Directory Traversal):** Khai thác sự thiếu sót trong việc kiểm tra đường dẫn tệp tin khi API xử lý yêu cầu đọc/ghi dữ liệu từ hệ thống tệp cục bộ. Bằng việc chèn chuỗi `../` (hoặc các biến thể mã hóa `%2e%2e%2f`), kẻ tấn công có thể thoát khỏi thư mục gốc của ứng dụng (Document Root) để truy cập các tệp tin cấu hình nhạy cảm (`config.env`, `settings.py`, database files).

#### 2. Tấn công Cross-Site Scripting (XSS)
Mặc dù Web API chủ yếu trả về dữ liệu dạng JSON thô, nhưng các trường dữ liệu do API phản hồi thường được render trực tiếp lên trình duyệt của người dùng cuối trong các ứng dụng SPA (React, Vue, Angular). Khi kẻ tấn công gửi thành công các payload chứa mã script nguy hại (`<script>`, `<img src=x onerror=...>`, JavaScript pseudo-protocols `javascript:alert(1)`) lưu trữ vào cơ sở dữ liệu qua API (Stored XSS) hoặc phản xạ ngay lập tức (Reflected XSS), mã độc sẽ thực thi trong ngữ cảnh phiên người dùng nạn nhân, dẫn đến nguy cơ đánh cắp token xác thực (JWT, Session Cookies) hoặc chiếm quyền điều khiển tài khoản (Account Takeover) **[Ref 12]**.

#### 3. Phá vỡ kiểm soát phân quyền mức đối tượng (Broken Object Level Authorization - BOLA / IDOR)
Chiếm vị trí số 1 trong danh mục OWASP API Top 10 (API1:2023). Lỗ hổng này phát sinh do máy chủ API không thực hiện xác thực quyền hạn truy cập của người dùng đối với đối tượng dữ liệu cụ thể được định danh trong URL (ví dụ: `GET /api/v1/orders/{order_id}`). Người dùng hợp lệ A chỉ cần thay đổi `order_id` sang mã của người dùng B là có thể xem hoặc chỉnh sửa dữ liệu trái phép. Đây là một lỗ hổng logic nghiệp vụ mà các bộ lọc chữ ký regex truyền thống hoàn toàn bất lực trong việc nhận diện.

#### 4. Tiêu thụ tài nguyên không hạn chế (Unrestricted Resource Consumption - API4:2023)
Web API thường xuyên phải đối mặt với các cuộc tấn công tự động dò quét mật khẩu (Credential Stuffing, Password Brute-force) hoặc tấn công từ chối dịch vụ (Denial of Service - DoS) ở tầng ứng dụng (Layer 7). Khi không có cơ chế giới hạn tần suất (Rate Limiting) hiệu quả dựa trên địa chỉ IP hoặc định danh tài khoản, máy chủ API sẽ nhanh chóng bị vét cạn tài nguyên CPU, bộ nhớ RAM, kết nối cơ sở dữ liệu và băng thông mạng, dẫn đến tê liệt toàn bộ hệ thống dịch vụ **[Ref 11]**.

### 1.1.3. Các kỹ thuật làm mờ payload và né tránh tường lửa (WAF Evasion & Obfuscation Techniques)
Trong bối cảnh các hệ thống tường lửa ứng dụng web truyền thống phụ thuộc nặng nề vào các tập luật kiểm tra mẫu chuỗi (Regex Pattern Matching), kẻ tấn công hiện đại — đặc biệt khi có sự hỗ trợ của các tác tử AI tấn công tự động — đã áp dụng các kỹ thuật làm mờ payload (Obfuscation) cực kỳ phức tạp để vượt rào (WAF Evasion) **[Ref 04]**:

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

### 1.2.1. Nguyên lý hoạt động của WAF dựa trên luật (Signature-Based Inspection)
Tường lửa ứng dụng web (WAF) đóng vai trò là một lớp Reverse Proxy bảo vệ đứng trung gian giữa mạng Internet công cộng và máy chủ ứng dụng nội bộ. Khi một yêu cầu HTTP gửi đến, WAF thực hiện các bước phân tích:
1. **Phân tích cú pháp giao thức HTTP (HTTP Parsing):** Bóc tách các thành phần URL Path, Query Parameters, HTTP Headers (User-Agent, Cookie, Authorization, Referer) và Request Body (JSON, Form-data, XML).
2. **Chuẩn hóa đầu vào (Input Normalization/Canonicalization):** Chuyển đổi chuỗi đầu vào về dạng chuẩn (URL decoding, Unicode normalization, lowercase conversion) để tránh sự sai lệch mã hóa.
3. **So khớp mẫu chữ ký (Pattern Matching):** So khớp nội dung đã chuẩn hóa với tập hợp các biểu thức chính quy (Regular Expressions) đại diện cho các mẫu tấn công đã biết. Đại diện tiêu biểu nhất cho trường phái này là bộ luật nguồn mở chuẩn công nghiệp **OWASP ModSecurity Core Rule Set (CRS v4.0)** **[Ref 14]**.

### 1.2.2. Cơ chế chấm điểm bất thường lũy tiến (Anomaly Scoring System)
Khác với các cơ chế tường lửa cũ áp dụng phương thức chặn tức thời khi khớp một luật duy nhất (Traditional Disruptive Action / Single-Rule Blocking), chuẩn OWASP ModSecurity CRS v4.0 áp dụng kiến trúc **Anomaly Scoring System** **[Ref 14]**:
- Mỗi quy tắc phát hiện khi kích hoạt sẽ không chặn ngay request mà gán một trọng số bất thường dựa trên mức độ nghiêm trọng:
  - `CRITICAL`: +5 điểm (khớp trực tiếp cú pháp khai thác SQLi, OS Command Injection).
  - `HIGH`: +4 điểm (phát hiện hành vi quét lỗ hổng, traversal).
  - `MEDIUM`: +3 điểm (phát hiện từ khóa nhạy cảm, ký tự đặc biệt).
  - `LOW`: +2 điểm (sai lệch chuẩn giao thức HTTP).
- Điểm bất thường tích lũy (Cumulative Inbound Anomaly Score) được tính bằng tổng điểm của tất cả các quy tắc bị kích hoạt trên toàn bộ các trường của request:
  $$S_{\text{anomaly}} = \sum_{i \in \text{Rules matched}} \text{Score}(i)$$
- Chỉ khi $S_{\text{anomaly}} \ge \text{Anomaly Threshold}$ (thường mặc định là 5 điểm), WAF mới thực hiện ngắt kết nối và trả về mã lỗi `HTTP 403 Forbidden`. Mô hình này giảm thiểu đáng kể tỷ lệ chặn nhầm các yêu cầu hợp lệ có chứa một vài ký tự đặc biệt ngẫu nhiên.

### 1.2.3. Những giới hạn cốt tử của phương pháp dựa trên luật tĩnh
Mặc dù đóng vai trò là hàng rào lọc thô không thể thiếu nhờ tốc độ xử lý nhanh, WAF dựa trên luật tĩnh bộc lộ những khiếm khuyết nội tại không thể khắc phục trong môi trường tác chiến hiện đại:
1. **Bất lực trước biến thể mới và tấn công chưa từng biết (Zero-day Attacks):** Luật chữ ký chỉ có thể phát hiện những gì đã được định nghĩa trước. Khi kẻ tấn công sử dụng cú pháp mới lạ, kỹ thuật zero-day hoặc chuỗi khai thác logic phức tạp, luật tĩnh hoàn toàn bị mù.
2. **Nghịch lý giữa Tỷ lệ báo động giả (False Positive) và Bỏ lọt mối đe dọa (False Negative):**
   - Nếu viết biểu thức chính quy quá chặt chẽ (strict), WAF sẽ chặn nhầm các yêu cầu nghiệp vụ hợp lệ chứa ký tự toán học, dấu nháy trong văn bản tiếng Việt/tiếng Anh hoặc mã định danh người dùng (False Positive cao), gây gián đoạn trải nghiệm người dùng.
   - Nếu nới lỏng biểu thức chính quy để tránh False Positive, kẻ tấn công sẽ dễ dàng chèn các ký tự làm mờ để lọt qua mắt WAF (False Negative cao).
3. **Chi phí tính toán và bảo trì tăng theo cấp số nhân (Regex Performance Degradation):** Khi số lượng luật tăng lên hàng nghìn regex phức tạp, chi phí kiểm tra mỗi request tăng mạnh, đặc biệt đối với các regex có nguy cơ dính lỗ hổng ReDoS (Regular Expression Denial of Service), khiến độ trễ proxy tăng vọt, gây nghẽn cổ chai cho toàn bộ hệ thống.

---

## 1.3. CƠ SỞ LÝ THUYẾT VỀ TRÍCH XUẤT ĐẶC TRƯNG VÀ HỌC MÁY TRONG PHÁT HIỆN TẤN CÔNG WEB

Nhằm khắc phục những giới hạn của phương pháp chữ ký tĩnh, việc ứng dụng Trí tuệ nhân tạo và Học máy (Machine Learning) vào giám sát an toàn thông tin là xu hướng tất yếu. Thay vì so khớp chuỗi cứng nhắc, mô hình học máy học các phân phối thống kê, cấu trúc hình thái và tính dị biệt của luồng dữ liệu để tổng quát hóa (generalize) khả năng nhận diện.

### 1.3.1. Phương pháp trích xuất đặc trưng hình thái học và thống kê chuỗi HTTP
Dựa trên công trình nghiên cứu kinh điển của C. Torrano-Gimenez et al. (Wiley Security and Communication Networks 2015) **[Ref 08]**, thay vì phân tích cú pháp toàn bộ payload bằng các mô hình xử lý ngôn ngữ tự nhiên nặng nề (như Transformer/BERT tiêu tốn 50–150ms phần cứng GPU), ta có thể vector hóa yêu cầu HTTP thành các đặc trưng hình thái học (Morphological Features) và số liệu thống kê với chi phí thời gian siêu thấp ($< 0.5\text{ms}$ trên CPU thông thường).

#### 1. Cơ sở toán học của độ hỗn loạn thông tin Shannon Entropy
Độ hỗn loạn thông tin Shannon Entropy được áp dụng để đo lường mức độ ngẫu nhiên và phân tán của các ký tự xuất hiện trong chuỗi payload $S$ có độ dài $N$:
$$H(S) = -\sum_{i=1}^{K} p(c_i) \log_2 p(c_i)$$
Trong đó:
- $K$ là số lượng ký tự phân biệt xuất hiện trong chuỗi $S$.
- $p(c_i) = \frac{f(c_i)}{N}$ là xác suất xuất hiện của ký tự $c_i$, với $f(c_i)$ là tần suất xuất hiện của $c_i$ trong chuỗi.

**Ý nghĩa an ninh mạng:**
- Chuỗi văn bản thông thường (tiếng Anh hoặc tiếng Việt không dấu) có entropy thấp và ổn định ($2.0 \le H(S) \le 3.5$) do tần suất xuất hiện của các nguyên âm và phụ âm tuân theo phân phối tự nhiên.
- Chuỗi chứa payload tấn công bị làm mờ (mã hóa Base64, Hex, URL encoding kép) hoặc chứa shellcode/ký tự ngẫu nhiên có độ hỗn loạn ký tự rất cao, đẩy entropy lên ngưỡng cao đột biến ($H(S) > 4.5$). Đây là một chỉ dấu cực kỳ mạnh để phát hiện hành vi mã hóa che giấu mã độc.

#### 2. Không gian 17 đặc trưng hình thái chuẩn tắc (Canonical 17-D Feature Vector)
Hệ thống chuẩn hóa không gian vector đặc trưng thành 17 chiều độc lập, bao quát toàn diện các khía cạnh cú pháp của một yêu cầu web:

| STT | Tên Đặc Trưng | Ký Hiệu Toán Học / Công Thức | Ý Nghĩa An Ninh Mạng |
| :---: | :--- | :--- | :--- |
| 1 | `payload_length` | $L = |S|$ | Đo độ dài chuỗi; các cuộc tấn công SQLi dạng UNION hoặc buffer overflow thường có độ dài vượt trội. |
| 2 | `entropy` | $H(S) = -\sum p_i \log_2 p_i$ | Đo lường độ ngẫu nhiên/hỗn loạn; phát hiện chuỗi mã hóa, băm mật mã và obfuscation. |
| 3 | `special_char_ratio` | $R_{\text{spec}} = \frac{N_{\text{spec}}}{L}$ | Tỷ lệ ký tự đặc biệt (`!@#$%^&*()_+-=[]{}...`); payload tấn công luôn có mật độ ký tự đặc biệt cao. |
| 4 | `digit_ratio` | $R_{\text{digit}} = \frac{N_{\text{digit}}}{L}$ | Tỷ lệ chữ số; phát hiện các đòn brute force ID, số liệu nhị phân hoặc chuỗi hex. |
| 5 | `uppercase_ratio` | $R_{\text{upper}} = \frac{N_{\text{upper}}}{L}$ | Tỷ lệ chữ hoa; nhận diện kỹ thuật né tránh đổi hoa thường xen kẽ (Mixed-case Evasion). |
| 6 | `single_quote_count` | $C_{\text{sq}} = \text{count}(')$ | Số lượng dấu nháy đơn; chỉ dấu cơ bản của SQL Injection đóng chuỗi. |
| 7 | `double_quote_count` | $C_{\text{dq}} = \text{count}(")$ | Số lượng dấu nháy kép; chỉ dấu của XSS attribute injection và SQLi. |
| 8 | `parentheses_count` | $C_{\text{paren}} = \text{count}('(') + \text{count}(')')$ | Số lượng dấu ngoặc tròn; phát hiện lời gọi hàm SQL (`CONCAT`, `VERSION`, `SLEEP`) hoặc hàm JavaScript (`alert`, `eval`). |
| 9 | `angle_bracket_count` | $C_{\text{angle}} = \text{count}('<') + \text{count}('>')$ | Số lượng dấu đóng/mở thẻ; chỉ dấu trực tiếp của việc tiêm mã thẻ HTML/XSS. |
| 10 | `semicolon_count` | $C_{\text{semi}} = \text{count}(';')$ | Số lượng dấu chấm phẩy; chỉ dấu của kỹ thuật xếp chồng câu lệnh SQL (Stacked Queries) hoặc ngắt lệnh Shell. |
| 11 | `whitespace_count` | $C_{\text{ws}} = \text{count}(\text{space}, \text{tab}, \text{newline})$ | Số lượng khoảng trắng; phân tích cấu trúc cú pháp câu lệnh. |
| 12 | `null_byte_count` | $C_{\text{null}} = \text{count}('\x00') + \text{count}('%00')$ | Số lượng byte rỗng; phát hiện kỹ thuật cắt chuỗi tệp tin và vượt rào kiểm tra. |
| 13 | `sqli_keyword_count` | $K_{\text{sqli}} = \sum \mathbb{I}(\text{kw} \in S)$ | Mật độ từ khóa SQL kinh điển (`SELECT`, `UNION`, `DROP`, `INFORMATION_SCHEMA`, `SLEEP`, `BENCHMARK`). |
| 14 | `xss_keyword_count` | $K_{\text{xss}} = \sum \mathbb{I}(\text{kw} \in S)$ | Mật độ từ khóa/thuộc tính XSS nguy hiểm (`SCRIPT`, `ONERROR`, `ONLOAD`, `JAVASCRIPT:`, `EVAL`, `FETCH`). |
| 15 | `cmdi_keyword_count` | $K_{\text{cmdi}} = \sum \mathbb{I}(\text{kw} \in S)$ | Mật độ từ khóa lệnh hệ thống (`ETC/PASSWD`, `BIN/SH`, `CMD.EXE`, `POWERSHELL`, `WHOAMI`, `CURL`, `WGET`). |
| 16 | `path_keyword_count` | $K_{\text{path}} = \sum \mathbb{I}(\text{kw} \in S)$ | Mật độ mẫu duyệt đường dẫn (`..`, `WEB-INF`, `BOOT.INI`, `ENV`, `WIN.INI`). |
| 17 | `syntax_pattern_count` | $K_{\text{syn}} = \sum \mathbb{I}(\text{regex} \in S)$ | Mật độ các cấu trúc toán tử logic đặc trưng (`OR 1=1`, `AND 1=1`, `/*`, `--`, `#`, `\|\|`, `&&`). |

### 1.3.2. Thuật toán học máy có giám sát (Supervised Learning) — Rừng ngẫu nhiên (Random Forest)
Mô hình học máy có giám sát được giao nhiệm vụ phân loại đa lớp (Multiclass Classification) để xác định chính xác danh tính của cuộc tấn công trong tập nhãn: $\mathcal{Y} = \{\text{BENIGN: 0, SQLI: 1, XSS: 2, PATH\_TRAVERSAL: 3, COMMAND\_INJECTION: 4}\}$.

#### 1. Cơ sở lý thuyết của Random Forest
Random Forest là một thuật toán học tăng cường tập hợp (Ensemble Learning) kết hợp nhiều cây quyết định (Decision Trees) đơn lẻ thông qua kỹ thuật **Bootstrap Aggregating (Bagging)** và **Random Feature Subspace Selection**:
- Với tập dữ liệu huấn luyện $\mathcal{D}$ gồm $N$ mẫu, thuật toán tạo ra $B$ tập dữ liệu con $\mathcal{D}_b$ bằng cách lấy mẫu ngẫu nhiên có lặp lại (Bootstrap Sampling).
- Tại mỗi nút của mỗi cây quyết định $T_b$, thay vì tìm điểm phân tách tối ưu trên toàn bộ $M$ đặc trưng ($M=17$), thuật toán chỉ chọn ngẫu nhiên một tập con gồm $m$ đặc trưng ($m = \sqrt{M} \approx 4$). Điểm phân tách được xác định bằng cách tối đa hóa độ giảm độ bất thuần Gini (Gini Impurity):
  $$I_G(p) = 1 - \sum_{k=1}^{C} p_k^2$$
  $$\Delta I_G = I_{G}(\text{Parent}) - \left( \frac{N_{\text{Left}}}{N_{\text{Total}}} I_G(\text{Left}) + \frac{N_{\text{Right}}}{N_{\text{Total}}} I_G(\text{Right}) \right)$$
- Dự đoán cuối cùng của mô hình cho vector đầu vào $\mathbf{x}$ là sự biểu quyết đa số (Majority Voting) hoặc trung bình cộng vector phân bố xác suất:
  $$\hat{p}_k(\mathbf{x}) = \frac{1}{B} \sum_{b=1}^{B} P_{T_b}(y = k \mid \mathbf{x})$$

#### 2. Động lực lựa chọn Random Forest thay vì Deep Learning / Transformers
Theo kết quả khảo sát thực nghiệm chuyên sâu được công bố trên *IEEE Access* (2024) **[Ref 09]** và *MDPI Electronics* (2025) **[Ref 11]**, việc ứng dụng các mạng nơ-ron sâu phức tạp (CNN, Bi-LSTM) hoặc Transformers (BERT) vào tầng WAF Gateway gặp phải các trở ngại bất khả thi trong môi trường sản xuất thực tế:
1. **Ngân sách độ trễ (Inference Latency):** Random Forest chỉ tiêu tốn từ $1.2\text{ms}$ đến $3.5\text{ms}$ trên CPU đơn lõi thông thường để hoàn thành phân loại một request. Trong khi đó, các mô hình ngôn ngữ như DistilBERT cần từ $60\text{ms}$ đến $150\text{ms}$ (kể cả khi chạy trên GPU), gây nghẽn nghiêm trọng thông lượng mạng.
2. **Khả năng diễn giải (Explainability & Interpretability):** Random Forest cho phép tính toán chỉ số tầm quan trọng của đặc trưng (Feature Importance), giúp các kỹ sư bảo mật SOC hiểu rõ lý do mô hình đưa ra kết luận (ví dụ: `single_quote_count` và `entropy` đóng góp 75% vào quyết định phân loại SQLi).
3. **Độ bền vững và khả năng chống quá khớp (Anti-overfitting):** Nhờ cơ chế lấy mẫu ngẫu nhiên hai tầng, Random Forest có khả năng chống nhiễu cực tốt khi gặp phải các payload có biến đổi nhỏ về hình thái.

### 1.3.3. Thuật toán học máy không giám sát (Unsupervised Learning) — Rừng cô lập (Isolation Forest)
Để đối phó với các cuộc tấn công Zero-day hoặc các mẫu biến dị payload mà tập huấn luyện có giám sát chưa từng gặp, hệ thống tích hợp mô hình phát hiện bất thường không giám sát **Isolation Forest (iForest)**.

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

Hệ thống ra quyết định phòng thủ đa ngưỡng (**Multi-Threshold Policy Matrix**) phân tầng theo chuẩn MITRE ATT&CK Mitigation **[Ref 17]**:
- $\text{Risk Score} < 30$: `ALLOW` (Cho phép yêu cầu đi tiếp đến backend API).
- $30 \le \text{Risk Score} < 60$: `MONITOR` (Cho phép đi qua nhưng ghi log kiểm toán chuyên sâu để phân tích).
- $60 \le \text{Risk Score} < 80$: `RATE_LIMIT` (Áp đặt hình phạt cắt giảm 50% hạn ngạch truy cập và trì hoãn phản hồi).
- $\text{Risk Score} \ge 80$: `BLOCK` (Lập tức từ chối yêu cầu với mã phản hồi `HTTP 403 Forbidden`).

---

## 1.4. CƠ SỞ LÝ THUYẾT VỀ THAO TRƯỜNG MẠNG (CYBER RANGE) VÀ TÁC TỬ TẤN CÔNG TỰ ĐỘNG (OFFENSIVE AI)

### 1.4.1. Khung kiến trúc Thao trường mạng phân tán tiêu chuẩn quốc tế
Theo định nghĩa chuẩn mực từ công trình nghiên cứu toàn diện của M. Yamin et al. công bố trên tạp chí quốc tế *Elsevier Computers & Security* (2020) **[Ref 17]**, một nền tảng Thao trường mạng (Cyber Range) tiêu chuẩn phải bao gồm tối thiểu 3 phân hệ chức năng độc lập:

```
+-----------------------------------------------------------------------------------+
|               DISTRIBUTED CYBER RANGE ARCHITECTURE (Yamin et al. 2020)            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [PHÂN HỆ 1: TARGET ENVIRONMENT]          [PHÂN HỆ 2: ATTACK SIMULATION ENGINE]  |
|  • Máy chủ Web API dễ bị tổn thương       • Tác tử tấn công tự động (Red Team)    |
|  • Chứa các điểm yếu OWASP Top 10         • Trinh sát OpenAPI & Fuzzing phụ thuộc|
|  • Cơ sở dữ liệu SQLite/PostgreSQL        • Đột biến Payload né tránh WAF         |
|  • Môi trường Docker cô lập               • Huấn luyện Deep RL (DQN Evasion)      |
|               ^                                           |                       |
|               |              VẬT LÝ QUA MẠNG LAN          |                       |
|               +===========================================+                       |
|                                     |                                             |
|                                     v                                             |
|                 [PHÂN HỆ 3: MONITORING & SCORING SUBSYSTEM]                       |
|                 • API Gateway WAF (Máy 1 - Blue Team)                             |
|                 • Thu thập Telemetry & Độ trễ mạng (Network RTT)                  |
|                 • Đánh giá hiệu quả phòng thủ: Precision, Recall, Youden's J      |
|                 • Trực quan hóa trung tâm chỉ huy SOC Dashboard (Next.js 14)      |
+-----------------------------------------------------------------------------------+
```

Khác biệt cốt lõi của đồ án PBL6 là triển khai mô hình **mạng phân tán thực tế trên 2 máy tính vật lý độc lập kết nối qua hạ tầng mạng LAN/Switch** (Máy 1: Blue Team WAF Gateway & Target API; Máy 2: Red Team Autonomous Agent) thay vì chạy cục bộ mô phỏng trên cùng một máy (localhost). Thiết kế này bám sát kết luận của nghiên cứu *Incalmo* (Carnegie Mellon University & SEI, 2024) **[Ref 03]**, khẳng định rằng việc triển khai đa máy trạm phân tán đem lại độ trễ mạng thực (Network RTT), hiện tượng phân mảnh gói tin và tính chân thực cao hơn 85% so với môi trường giả lập cục bộ.

### 1.4.2. Tác tử tấn công tự động (Offensive AI & Autonomous Red Teaming)
Trong môi trường an ninh hiện đại, các cuộc tấn công không còn là những xung lực đơn lẻ của con người mà đã được tự động hóa bằng các tác tử AI có khả năng thích ứng. Dựa trên các công trình nghiên cứu hàng đầu tại *USENIX Security 2024* (PentestGPT) **[Ref 01]**, *arXiv 2024* (AutoAttacker) **[Ref 02]**, và *IEEE/ACM ICSE 2019* (RESTler) **[Ref 06]**, tác tử tấn công tự động (Red Team Agent) được xây dựng theo kiến trúc 3 module tự điều phối:
1. **Module Lập kế hoạch (Attack Planner):** Tự động phân tích tài liệu đặc tả OpenAPI 3.0 (`/api/schema/`) của hệ thống mục tiêu, xây dựng đồ thị phụ thuộc (API Dependency Graph) để duy trì ngữ cảnh phiên làm việc (Session/JWT Authentication Tokens) cho các bước tấn công tiếp theo.
2. **Module Thực thi (HTTP Executor):** Bắn các gói tin HTTP chứa payload thử nghiệm qua giao thức mạng đến địa chỉ IP của Gateway phòng thủ.
3. **Module Phân tích phản hồi (Response Analyzer & Feedback Loop):** Khi nhận phản hồi từ WAF:
   - Nếu nhận mã lỗi `403 Forbidden`, tác tử nhận diện rằng đòn tấn công đã bị WAF phát hiện. Vòng lặp phản hồi kích hoạt bộ đột biến payload (Payload Mutator) để áp dụng các kỹ thuật mã hóa làm mờ (Double URL encoding, comment insertion, hex) và bắn lại.
   - Nếu nhận mã lỗi `200 OK` hoặc `500 Internal Server Error` (kèm dữ liệu trích xuất nhạy cảm), tác tử ghi nhận khai thác thành công và leo thang sang bước tiếp theo của chuỗi tấn công.

Toàn bộ các kỹ thuật tấn công được ánh xạ chuẩn tắc theo danh mục **MITRE ATT&CK Enterprise Matrix** **[Ref 19-20]**:
- **T1190 (Exploit Public-Facing Application):** Khai thác lỗ hổng Web API (SQLi, Command Injection).
- **T1059 (Command and Scripting Interpreter):** Thực thi lệnh shell qua OS Command Injection.
- **T1083 (File and Directory Discovery):** Dò quét cấu trúc thư mục hệ thống qua Path Traversal.

### 1.4.3. Mô hình Học tăng cường sâu (Deep Reinforcement Learning - DQN) trong né tránh phòng thủ
Để mô hình hóa hành vi né tránh WAF một cách tối ưu và hoàn toàn độc lập với các dịch vụ đám mây thương mại (100% In-house PyTorch), bài toán vượt WAF được phát biểu dưới dạng **Quy trình quyết định Markov (Markov Decision Process - MDP)**:
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

Để loại bỏ các đánh giá mang tính cảm tính và đảm bảo tính chặt chẽ về mặt phương pháp luận khoa học, việc đánh giá hiệu năng của hệ thống WAF phòng thủ và mô hình Machine Learning được quy chuẩn hóa theo các tiêu chuẩn đo lường của **OWASP Benchmark Project** **[Ref 15-16]** và lý thuyết học máy thống kê:

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
Theo tiêu chuẩn đánh giá WAF của tổ chức OWASP (**OWASP Benchmark Score Metric**) **[Ref 15-16]**, một hệ thống tường lửa thương mại chỉ được coi là đạt chất lượng khi vừa tối đa hóa tỷ lệ bắt tấn công (TPR), vừa triệt tiêu tối đa tỷ lệ báo động giả gây gián đoạn kinh doanh (FPR). Thước đo khoa học **Youden's Index $J$** được định nghĩa:
$$J = \text{TPR} - \text{FPR} = \frac{\text{TP}}{\text{TP} + \text{FN}} - \frac{\text{FP}}{\text{FP} + \text{TN}}$$
- Thang đo Youden's $J \in [-1.0, 1.0]$.
- $J = 1.0$: Hệ thống lý tưởng tuyệt đối ($\text{TPR} = 100\%$, $\text{FPR} = 0\%$).
- $J = 0.0$: Hệ thống hoạt động không hơn gì một bộ đoán ngẫu nhiên (Random Guessing).
- $J < 0.0$: Hệ thống hoàn toàn sai lệch (bắt nhầm người tốt nhiều hơn kẻ tấn công).
- **Mục tiêu của đồ án PBL6:** Đạt chỉ số $J \ge 0.90$ trên tập dữ liệu kiểm thử thực nghiệm đa dạng.

### 1.5.4. Các chỉ số về hiệu năng mạng và độ trễ hệ thống (Latency Budget & Throughput)
Ngoài độ chính xác an ninh, một hệ thống WAF bảo vệ ứng dụng Web API bắt buộc phải tuân thủ nghiêm ngặt các yêu cầu phi chức năng về hiệu năng vận hành:
1. **Ngân sách độ trễ gia tăng (Proxy Overhead Latency Budget):**
   $$\Delta t = t_{\text{with WAF}} - t_{\text{direct}}$$
   Hệ thống đặt mục tiêu $\Delta t \le 15\text{ms}$ cho quy trình hoàn chỉnh (Fast Path Regex + Feature Extraction + RF Inference + Isolation Forest + Decision Engine).
2. **Thông lượng xử lý (System Throughput):** Đo lường số lượng yêu cầu phục vụ trên một giây ($\text{Requests Per Second - RPS}$) mà không làm tràn hàng đợi CPU hoặc rò rỉ bộ nhớ RAM.

---

## 1.6. TỔNG KẾT CHƯƠNG 1

Chương 1 đã thiết lập một nền tảng cơ sở lý thuyết toàn diện và vững chắc cho toàn bộ đồ án PBL6:
1. Phân tích bản chất kỹ thuật của các lỗ hổng Web API nguy hiểm hàng đầu theo chuẩn OWASP Top 10 API Security Risks (2023) và bóc tách các cơ chế làm mờ payload vượt WAF tinh vi.
2. Chỉ ra nguyên lý hoạt động của WAF dựa trên luật tĩnh ModSecurity CRS v4.0 cùng những giới hạn cố hữu về tấn công Zero-day, chi phí bảo trì regex và tỷ lệ cảnh báo sai lệch.
3. Luận chứng khoa học về việc kết hợp trích xuất 17 đặc trưng hình thái học HTTP theo chuẩn Wiley 2015 cùng thuật toán Random Forest và Isolation Forest, hình thành kiến trúc WAF Hybrid cân bằng hoàn hảo giữa độ trễ microsecond và độ chính xác phân loại.
4. Đặt nền móng cho thao trường mạng đối kháng phân tán trên 2 máy trạm vật lý theo chuẩn Elsevier 2020, kết hợp tác tử tấn công tự động và mô hình Deep Reinforcement Learning (PyTorch DQN).
5. Thiết lập hệ thống thước đo hiệu năng định lượng khách quan (Confusion Matrix, Youden's Index $J$, Latency Budget) làm kim chỉ nam kiểm chứng thực nghiệm cho các giai đoạn tiếp theo của đồ án.
