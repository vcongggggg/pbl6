# TỔNG HỢP THUẬT NGỮ CHUYÊN NGÀNH & TỪ VIẾT TẮT (GLOSSARY)
## Dự án: Web API Security & Autonomous Red Teaming Platform (PBL6)

Tài liệu giải thích chi tiết toàn bộ các khái niệm, từ ngữ chuyên ngành an toàn thông tin, mạng máy tính, trí tuệ nhân tạo (AI/ML) và kỹ thuật phần mềm được sử dụng xuyên suốt trong đồ án PBL6.

---

## 📌 MỤC LỤC
1. [Khái Niệm Cốt Lõi: WAF Là Gì?](#1-khái-niệm-cốt-lõi-waf-là-gì)
2. [Hạ Tầng Mạng & Kiến Trúc Bảo Mật (Network & Security Architecture)](#2-hạ-tầng-mạng--kiến-trúc-bảo-mật)
3. [Các Họ Tấn Công & Lỗ Hổng Ứng Dụng Web (Web Attack Vectors & OWASP)](#3-các-họ-tấn-công--lỗ-hổng-ứng-dụng-web)
4. [Kỹ Thuật Phòng Thủ & Chuẩn Hóa Dữ Liệu (Defense & Normalization)](#4-kỹ-thuật-phòng-thủ--chuẩn-hóa-dữ-liệu)
5. [Trí Tuệ Nhân Tạo & Machine Learning trong An Toàn Thông Tin (AI/ML in Security)](#5-trí-tuệ-nhân-tạo--machine-learning-trong-attt)
6. [Diễn Tập Đối Kháng & Đội Ngũ An Ninh (Cyber Range & Red/Blue Team)](#6-diễn-tập-đối-kháng--đội-ngũ-an-ninh)
7. [Kỹ Thuật Phần Mềm & DevOps (Software Engineering & DevOps)](#7-kỹ-thuật-phần-mềm--devops)

---

## 1. KHÁI NIỆM CỐT LÕI: WAF LÀ GÌ?

### 🛡️ WAF — Web Application Firewall (Tường Lửa Ứng Dụng Web)
* **Định nghĩa:** Là một hệ thống bảo mật chuyên dụng hoạt động ở **Tầng 7 (Application Layer - Tầng ứng dụng)** trong mô hình mạng OSI, đóng vai trò như một tấm khiên chắn đứng giữa người dùng ngoài Internet và máy chủ Web API / Backend Server.
* **Sự khác biệt với Tường lửa mạng thông thường (Network Firewall):**
  * *Network Firewall (Tầng 3/4):* Chỉ kiểm tra địa chỉ IP nguồn, IP đích, và Port (ví dụ: mở cổng 80/443, chặn cổng 22). Nó hoàn toàn "mù" trước nội dung dữ liệu bên trong request. Kẻ tấn công gửi mã độc SQL Injection qua cổng 80 hợp lệ thì Network Firewall vẫn cho qua.
  * *WAF (Tầng 7):* Mở gói tin HTTP/HTTPS ra, đọc và soi xét kỹ lưỡng từng ký tự trong **URL, Query string, Request Headers, Cookies và Request Body (JSON/Form)** để phát hiện và ngăn chặn các hành vi khai thác lỗ hổng ứng dụng web.
* **Trong đồ án PBL6:**
  * Hệ thống của nhóm là một **Next-Gen AI WAF (WAF thế hệ mới kết hợp AI)**:
    * Tầng 1: **Rule Engine** bắt các mẫu tấn công đã biết với độ trễ cực thấp ($< 1\text{ms}$).
    * Tầng 2: **Random Forest (Supervised ML)** phân loại đa lớp các biến thể tấn công phức tạp.
    * Tầng 3: **Isolation Forest (Anomaly Detection)** phát hiện các hành vi bất thường, tấn công Zero-day chưa từng có mẫu trước đây.
    * Tầng 4: **Hybrid Decision Engine** tự động ra quyết định `ALLOW`, `MONITOR`, `RATE_LIMIT (429)` hoặc `BLOCK (403)`.

---

## 2. HẠ TẦNG MẠNG & KIẾN TRÚC BẢO MẬT

| Thuật ngữ / Viết tắt | Tên tiếng Anh đầy đủ | Ý nghĩa & Ứng dụng trong PBL6 |
| :--- | :--- | :--- |
| **API** | Application Programming Interface | Giao diện lập trình ứng dụng, cầu nối cho phép các phần mềm giao tiếp với nhau qua giao thức HTTP/REST. |
| **REST** | Representational State Transfer | Kiểu kiến trúc API phổ biến sử dụng các phương thức chuẩn HTTP (`GET`, `POST`, `PUT`, `DELETE`). |
| **Reverse Proxy** | Reverse Proxy Server | Máy chủ proxy ngược đứng trước web server đích. Client chỉ nhìn thấy Reverse Proxy (cổng 8000), Proxy nhận request, kiểm tra an ninh rồi mới forward sang máy chủ nội bộ (`juice-shop:3000`). |
| **Forward Proxy** | Forward Proxy Server | Proxy xuôi đứng ở phía client (người dùng), thường dùng để ẩn danh hoặc vượt tường lửa nội bộ ra ngoài Internet. |
| **Upstream / Target** | Upstream Target API | Máy chủ dịch vụ đích nằm phía sau WAF (trong đồ án chính là OWASP Juice Shop). |
| **Hop-by-hop Headers** | Hop-by-hop Headers | Các header HTTP chỉ có ý nghĩa giữa 2 điểm truyền thông liền kề (`Connection`, `Keep-Alive`, `Upgrade`...). Gateway phải lọc bỏ chúng trước khi forward để tránh lỗi giao vận. |
| **Request ID** | Request Identifier (`X-Request-ID`) | Chuỗi định danh duy nhất (UUID) gán cho mỗi request để theo dõi vết (traceability) từ Client $\rightarrow$ Gateway $\rightarrow$ Database $\rightarrow$ Dashboard. |
| **SSRF** | Server-Side Request Forgery | Lỗ hổng cho phép kẻ tấn công lợi dụng server để gửi request độc hại tới mạng nội bộ. Gateway chống SSRF bằng cách cố định cứng URL target qua biến môi trường. |
| **Open Proxy** | Open Proxy Vulnerability | Nguy cơ Gateway bị kẻ xấu biến thành cầu nối để tấn công các trang web khác trên Internet. Hệ thống chống bằng cách cấm chỉ định URL tùy ý từ client. |
| **Rate Limiting** | Rate Limiting | Kỹ thuật giới hạn số lượng request tối đa mà một Client/IP được phép gửi trong một khoảng thời gian (ví dụ: tối đa 60 req/phút). |
| **Sliding Window** | Sliding Window Algorithm | Thuật toán cửa sổ trượt theo dõi tần suất gọi API trong bộ nhớ với độ chính xác cao hơn thuật toán Fixed Window. |
| **DoS / DDoS** | Denial of Service / Distributed DoS | Tấn công từ chối dịch vụ (gửi lượng request khổng lồ làm sập server). WAF chống DoS ứng dụng bằng Rate Limiting (trả về `HTTP 429`). |
| **OSI Model** | Open Systems Interconnection | Mô hình 7 tầng mạng tiêu chuẩn (Tầng 1 Physical $\rightarrow$ Tầng 7 Application). |

---

## 3. CÁC HỌ TẤN CÔNG & LỖ HỔNG ỨNG DỤNG WEB

| Thuật ngữ / Viết tắt | Tên tiếng Anh đầy đủ | Ý nghĩa & Biểu hiện thực tế |
| :--- | :--- | :--- |
| **OWASP** | Open Web Application Security Project | Tổ chức phi lợi nhuận quốc tế uy tín hàng đầu về bảo mật ứng dụng web, nổi tiếng với danh sách **OWASP Top 10**. |
| **SQLi** | SQL Injection | Kỹ thuật chèn các câu lệnh SQL độc hại vào ô nhập liệu/URL để thao túng cơ sở dữ liệu (ví dụ: `' OR '1'='1`, `UNION SELECT`). |
| **Tautology** | Tautology Attack | Kỹ thuật chèn biểu thức luôn đúng trong SQLi (`' OR 1=1--`, `'admin'--`) để đăng nhập không cần mật khẩu hoặc lấy toàn bộ dữ liệu. |
| **XSS** | Cross-Site Scripting | Kỹ thuật chèn các đoạn mã JavaScript độc hại vào trang web (ví dụ: `<script>alert('PBL6')</script>`, `<img src=x onerror=...`), khiến trình duyệt của nạn nhân thực thi mã độc. |
| **Reflected XSS** | Reflected Cross-Site Scripting | Mã độc phản xạ ngay lập tức từ request (thường nằm trên đường link phishing) vào trang kết quả. |
| **Stored XSS** | Stored / Persistent XSS | Mã độc được lưu vĩnh viễn vào database (ví dụ trong phần bình luận, hồ sơ người dùng), ai mở trang đó lên cũng bị nhiễm. |
| **Path Traversal** | Path / Directory Traversal | Kỹ thuật sử dụng chuỗi thoát thư mục (`../`, `..\`, `%2e%2e%2f`) để đọc các file nhạy cảm trên hệ điều hành máy chủ (như `/etc/passwd` hoặc `win.ini`). |
| **Command Injection** | OS Command Injection | Kỹ thuật chèn các ký tự điều khiển shell (`;`, `\|`, `&&`, `` ` ``) để ép máy chủ thực thi lệnh hệ điều hành (ví dụ: `; cat /etc/passwd`, `; whoami`). |
| **Brute Force** | Brute Force Attack | Tấn công vét cạn: Thử liên tục hàng ngàn mật khẩu hoặc mã PIN cho đến khi tìm được đáp án đúng. |
| **Credential Stuffing** | Credential Stuffing | Sử dụng các bộ danh sách tài khoản/mật khẩu đã bị rò rỉ từ trang web khác để thử đăng nhập tự động hàng loạt trên hệ thống mục tiêu. |
| **API Abuse** | API Abuse / Endpoint Scraping | Hành vi lạm dụng gọi API với tần suất cao bất thường để cào dữ liệu (scraping), vét vé, làm cạn kiệt tài nguyên hệ thống. |
| **Zero-Day** | Zero-Day Vulnerability / Exploit | Lỗ hổng an ninh mới tinh chưa từng được công bố và chưa có bản vá hoặc signature (WAF rule truyền thống sẽ bị qua mặt, cần AI/Anomaly phát hiện). |

---

## 4. KỸ THUẬT PHÒNG THỦ & CHUẨN HÓA DỮ LIỆU

| Thuật ngữ / Viết tắt | Tên tiếng Anh đầy đủ | Ý nghĩa & Cơ chế hoạt động |
| :--- | :--- | :--- |
| **Signature-based** | Signature-based Detection | Phương pháp phát hiện theo dấu hiệu tĩnh (so khớp chuỗi hoặc biểu thức chính quy Regex với các mẫu tấn công đã biết). Ưu điểm: cực nhanh, độ chính xác cao; Nhược điểm: không bắt được biến thể mới. |
| **Anomaly-based** | Anomaly-based Detection | Phương pháp phát hiện theo hành vi dị biệt: Học thế nào là lưu lượng "bình thường", bất kỳ request nào lệch chuẩn quá xa sẽ bị coi là tấn công. |
| **Hybrid Detection** | Hybrid Detection | Cơ chế kết hợp sức mạnh của cả Rule tĩnh + Machine Learning + Anomaly để bù trừ điểm yếu cho nhau. |
| **Input Normalization** | Input Normalization / Canonicalization | Quá trình đưa dữ liệu bị mã hóa/xáo trộn về dạng chuỗi gốc chuẩn tắc (Canonical form) trước khi đưa vào bộ kiểm tra an ninh, nhằm chống kỹ thuật lách luật (Evasion). |
| **URL Decoding** | Percent-Encoding Decoding | Giải mã các ký tự URL encode (ví dụ: `%27` $\rightarrow$ `'`, `%20` $\rightarrow$ khoảng trắng). Hệ thống có cơ chế giải mã đệ quy để chống **Double Encoding** (`%2527` $\rightarrow$ `%27` $\rightarrow$ `'`). |
| **HTML Unescape** | HTML Entity Unescaping | Chuyển đổi các thực thể HTML (ví dụ: `&lt;` $\rightarrow$ `<`, `&quot;` $\rightarrow$ `"`) về ký tự nguyên bản. |
| **Unicode NFKC** | Unicode Normalization Form KC | Chuẩn hóa các ký tự Unicode tương đương về dạng chuẩn tương thích, chống kỹ thuật dùng font lạ hoặc ký tự full-width để vượt WAF. |
| **De-obfuscation** | De-obfuscation | Kỹ thuật làm sạch và xóa bỏ các lớp ngụy trang (khoảng trắng thừa, chú thích SQL `/**/`, ký tự null `\0`) của payload. |
| **True Positive (TP)** | True Positive | Dự đoán đúng là có tấn công (Request độc hại và WAF phát hiện đúng). |
| **True Negative (TN)** | True Negative | Dự đoán đúng là an toàn (Request bình thường và WAF cho qua). |
| **False Positive (FP)** | False Positive (Báo động giả) | Sai lầm loại 1: Request của người dùng bình thường nhưng WAF bắt nhầm và chặn lại (gây ức chế cho khách hàng). |
| **False Negative (FN)** | False Negative (Bỏ lọt tấn công) | Sai lầm loại 2: Request là đòn tấn công nhưng WAF không phát hiện ra và cho qua (gây nguy cơ bị hack hệ thống). |

---

## 5. TRÍ TUỆ NHÂN TẠO & MACHINE LEARNING TRONG AN TOÀN THÔNG TIN

| Thuật ngữ / Viết tắt | Tên tiếng Anh đầy đủ | Ý nghĩa & Vai trò trong PBL6 |
| :--- | :--- | :--- |
| **Supervised Learning** | Học có giám sát (Supervised ML) | Phương pháp huấn luyện mô hình trên tập dữ liệu đã có sẵn nhãn (ví dụ: nhãn 0 = Benign, 1 = SQLi, 2 = XSS...). Trong đồ án dùng **Random Forest**. |
| **Unsupervised Learning** | Học không giám sát (Unsupervised ML) | Phương pháp huấn luyện không cần nhãn, thuật toán tự tìm quy luật và phân nhóm dữ liệu. Trong đồ án dùng **Isolation Forest** để bắt hành vi bất thường. |
| **Random Forest (RF)** | Random Forest Classifier | Thuật toán học máy kết hợp (Ensemble) xây dựng từ hàng trăm cây quyết định (Decision Trees), có độ chính xác rất cao, kháng nhiễu tốt và cho phép trích xuất độ quan trọng của đặc trưng (Feature Importance). |
| **Isolation Forest (IF)** | Isolation Forest | Thuật toán chuyên biệt để phát hiện bất thường dựa trên nguyên lý: Điểm dị biệt (Anomalies) thường ít và khác biệt nên sẽ bị cô lập ở những nhánh rất nông của cây. |
| **Feature Extraction** | Trích xuất đặc trưng | Quá trình biến đổi một chuỗi văn bản HTTP thô thành một **vector số học (Feature Vector)** mà máy tính có thể hiểu được (trong đồ án gồm 17 đặc trưng). |
| **Shannon Entropy** | Shannon Entropy | Thước đo độ ngẫu nhiên hoặc độ hỗn loạn thông tin trong chuỗi văn bản. Payload bị mã hóa/obfuscate/shellcode thường có entropy cao bất thường so với văn bản tiếng Anh/Việt tự nhiên. |
| **Anomaly Score** | Điểm số bất thường | Điểm số chuẩn hóa từ $0.0$ đến $1.0$ do Isolation Forest trả về, thể hiện mức độ lệch chuẩn của request so với lưu lượng sạch thông thường. |
| **Risk Score** | Điểm rủi ro tổng hợp | Điểm số từ $0$ đến $100$ được tính bằng công thức trọng số kết hợp giữa điểm Rule Engine, điểm Supervised ML và điểm Anomaly. |
| **Precision** | Độ chuẩn xác | Tỷ lệ những cảnh báo do mô hình phát hiện thực sự là tấn công: $\frac{TP}{TP + FP}$. |
| **Recall (Sensitivity)** | Độ nhạy / Tỷ lệ bao phủ | Tỷ lệ số đòn tấn công thực tế mà mô hình tóm được: $\frac{TP}{TP + FN}$. |
| **F1-Score** | F1-Score | Trung bình điều hòa giữa Precision và Recall: $2 \times \frac{Precision \times Recall}{Precision + Recall}$. Thước đo quan trọng nhất cho bài toán phân loại an ninh. |
| **ROC / AUC** | Receiver Operating Characteristic / Area Under Curve | Đồ thị và diện tích dưới đường cong đánh giá năng lực phân loại của mô hình ở các ngưỡng quyết định khác nhau (AUC càng gần 1.0 càng xịn). |
| **Adversarial Robustness** | Độ bền vững trước tấn công đối kháng | Khả năng của mô hình AI/ML vẫn nhận diện chính xác khi kẻ tấn công cố tình chèn thêm nhiễu hoặc thay đổi cú pháp để đánh lừa mô hình. |
| **Data Drift** | Trôi dữ liệu (Data / Concept Drift) | Hiện tượng dữ liệu thực tế ngoài đời thay đổi theo thời gian so với dữ liệu lúc huấn luyện mô hình, đòi hỏi hệ thống phải có quy trình huấn luyện lại (Retraining pipeline). |

---

## 6. DIỄN TẬP ĐỐI KHÁNG & ĐỘI NGŨ AN NINH

| Thuật ngữ / Viết tắt | Tên tiếng Anh đầy đủ | Ý nghĩa & Vị trí trong đồ án |
| :--- | :--- | :--- |
| **SOC** | Security Operations Center | Trung tâm điều hành an ninh mạng — nơi giám sát, phát hiện và ứng phó các sự cố an ninh mạng 24/7. |
| **SOC Dashboard** | SOC Command Center Dashboard | Bảng điều khiển trực quan (Next.js) hiển thị biểu đồ lưu lượng, cảnh báo tấn công, điểm rủi ro và bằng chứng vi phạm. |
| **Red Team** | Đội tấn công (Red Team) | Đội đóng vai trò tin tặc, cố gắng tìm mọi cách thâm nhập và khai thác điểm yếu hệ thống. Trong PBL6: Thành phần `attack-lab/` và **AI Attack Planner**. |
| **Blue Team** | Đội phòng thủ (Blue Team) | Đội bảo vệ hệ thống, phân tích log, vận hành WAF để phát hiện và ngăn chặn Red Team. Trong PBL6: Thành phần **FastAPI Gateway + WAF + Decision Engine**. |
| **Cyber Range** | Thao trường mạng | Môi trường lab giả lập khép kín (Docker Compose) cho phép hai đội Red Team và Blue Team diễn tập đối kháng an toàn mà không ảnh hưởng hệ thống thật. |
| **AI Attack Planner** | Tác nhân lập kế hoạch tấn công bằng AI | Module nâng cấp của `attack-lab/` (theo định hướng của Thầy giáo): Sử dụng AI để tự động thăm dò endpoint, lên kịch bản tấn công và tự động thay đổi payload né tránh khi bị WAF chặn. |
| **Adaptive Evasion** | Né tránh thích ứng | Khả năng của AI Attack Planner: Khi nhận mã lỗi `403 Forbidden` $\rightarrow$ Tự động phân tích lý do chặn $\rightarrow$ Áp dụng kỹ thuật mã hóa/obfuscate mới để thử lại. |

---

## 7. KỸ THUẬT PHẦN MỀM & DEVOPS

| Thuật ngữ / Viết tắt | Tên tiếng Anh đầy đủ | Ý nghĩa & Ứng dụng trong PBL6 |
| :--- | :--- | :--- |
| **Monorepo** | Monolithic Repository | Kiến trúc lưu trữ toàn bộ các thành phần của dự án (`gateway/`, `dashboard/`, `ml-engine/`, `attack-lab/`, `docs/`) trong một Git repository duy nhất để dễ quản lý và kiểm thử. |
| **FastAPI** | FastAPI Framework | Web framework hiệu năng cực cao của Python xây dựng trên nền tảng Starlette và Pydantic, hỗ trợ bất đồng bộ `async/await` nguyên bản. |
| **ASGI** | Asynchronous Server Gateway Interface | Chuẩn giao tiếp máy chủ bất đồng bộ của Python (thay thế cho chuẩn đồng bộ cũ WSGI). |
| **Uvicorn** | Uvicorn ASGI Server | Web server siêu nhanh chạy ứng dụng FastAPI trên nền tảng uvloop. |
| **Next.js** | Next.js Framework (React) | Framework full-stack hàng đầu cho React, hỗ trợ Server-Side Rendering (SSR) và App Router thế hệ mới. |
| **Glassmorphism** | Phong cách thiết kế kính mờ | Xu hướng thiết kế giao diện hiện đại với nền tối sâu, hiệu ứng mờ bán trong suốt (`backdrop-blur`) và viền phát sáng neon tinh tế. |
| **Recharts** | Recharts Data Visualization | Thư viện vẽ biểu đồ React dựa trên SVG chuyên nghiệp, dùng để vẽ đồ thị sóng kép Timeline và đồ thị vành khăn Donut Chart. |
| **ORM** | Object-Relational Mapping (SQLAlchemy) | Kỹ thuật ánh xạ bảng cơ sở dữ liệu quan hệ thành các class/object trong mã nguồn Python giúp thao tác dữ liệu an toàn, chống lỗi SQLi nội bộ. |
| **SQLite** | SQLite Database | Hệ quản trị cơ sở dữ liệu quan hệ nhỏ gọn, nhúng trực tiếp trong file (`waf_security.db`), cực kỳ phù hợp cho môi trường lab và đồ án môn học. |
| **Docker Compose** | Docker Compose Multi-container | Công cụ định nghĩa và chạy cùng lúc nhiều container Docker (`gateway`, `dashboard`, `juice-shop`) chỉ với 1 câu lệnh `docker compose up --build`. |
| **CI / CD** | Continuous Integration / Deployment | Quy trình tích hợp và kiểm thử mã nguồn liên tục tự động trên GitHub Actions mỗi khi tạo Pull Request. |
| **PR** | Pull Request | Yêu cầu gộp nhánh code: Cho phép các thành viên trong nhóm và Tech Lead review, kiểm tra bài test tự động trước khi hòa nhập vào nhánh `main`. |
| **Branch Protection** | Branch Protection Ruleset | Tính năng của GitHub khóa nhánh `main`, cấm các thành viên push code thẳng lên main nhằm tránh làm hỏng dự án. |
| **WBS** | Work Breakdown Structure | Cơ cấu phân chia công việc: Chia nhỏ đồ án thành các Phase (Epic) và các Task cụ thể để quản lý tiến độ khoa học. |
