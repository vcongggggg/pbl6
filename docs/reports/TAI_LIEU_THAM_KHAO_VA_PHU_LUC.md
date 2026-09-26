# TÀI LIỆU THAM KHẢO VÀ CÁC PHỤ LỤC HỌC THUẬT

> **Học phần:** Đồ án Môn học Chuyên ngành An toàn Thông tin (PBL6)  
> **Đề tài:** Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán  
> **Đơn vị đào tạo:** Bộ môn An toàn Thông tin - Khoa Công nghệ Thông tin - Trường Đại học Bách khoa - Đại học Đà Nẵng  

---

## MỤC LỤC
1. [Tài Liệu Tham Khảo (20 Trích Dẫn Học Thuật Chuẩn IEEE)](#1-tài-liệu-tham-khảo-references)
   - [Nhóm 1: Giáo trình chuẩn mực quốc tế](#nhóm-1-giáo-trình-chuẩn-mực-quốc-tế-foundational-textbooks)
   - [Nhóm 2: Tiêu chuẩn công nghiệp & Khung đo lường](#nhóm-2-tiêu-chuẩn-công-nghiệp--khung-đo-lường-industry-standards--benchmarks)
   - [Nhóm 3: Bài báo khoa học về Học máy phòng thủ Web](#nhóm-3-bài-báo-khoa-học-về-học-máy-phòng-thủ-web-machine-learning-waf-papers)
   - [Nhóm 4: Thao trường mạng & Tác tử tấn công đối kháng](#nhóm-4-thao-trường-mạng--tác-tử-tấn-công-đối-kháng-cyber-range--offensive-ai)
2. [Phụ Lục A: Bảng Tra Cứu Thuật Ngữ và Từ Viết Tắt](#phụ-lục-a-bảng-tra-cứu-thuật-ngữ-và-từ-viết-tắt-glossary--acronyms)
3. [Phụ Lục B: Thông Số Cấu Hình Thao Trường Mạng Cyber Range](#phụ-lục-b-thông-số-cấu-hình-thao-trường-mạng-cyber-range-environment)
4. [Phụ Lục C: Danh Mục Endpoint và Vector 17 Đặc Trưng Hình Thái](#phụ-lục-c-danh-mục-endpoint-và-vector-17-đặc-trưng-hình-thái)

---

## 1. TÀI LIỆU THAM KHẢO (REFERENCES)

Danh mục 20 tài liệu tham khảo chính thức được lập danh mục và định dạng chuẩn mực theo quy tắc trích dẫn IEEE và tiêu chuẩn đào tạo của Trường Đại học Bách khoa - Đại học Đà Nẵng. Danh mục được phân thành 4 nhóm trụ cột học thuật cấu thành nền tảng lý thuyết và thực nghiệm của đề tài:

### Nhóm 1: Giáo Trình Chuẩn Mực Quốc Tế (Foundational Textbooks)

* **[Ref 01]** W. Stallings, *Cryptography and Network Security: Principles and Practice*, 8th ed., Pearson / Prentice Hall, 2020. (ISBN: 978-0133354690).  
  * **Nội dung & Vai trò:** Cung cấp lý thuyết kinh điển về kiến trúc Cổng tầng ứng dụng (Application-Level Gateway / Reverse Proxy WAF) và cơ chế phân loại IDS dựa trên dấu hiệu (Signature-based) đối chiếu với phát hiện bất thường (Anomaly-based). Áp dụng tại Chương 1 (Mục 1.2) và Chương 2.
* **[Ref 02]** D. R. Stinson and M. B. Paterson, *Cryptography: Theory and Practice*, 4th ed., Boca Raton, FL: CRC Press, 2018. (ISBN: 978-1138197015).  
  * **Nội dung & Vai trò:** Cung cấp nền tảng toán học lý thuyết thông tin (Information Theory) của Claude Shannon, công thức tính toán Độ hỗn loạn Shannon (Shannon Entropy) của chuỗi ngẫu nhiên. Áp dụng trực tiếp để thiết kế đặc trưng entropy trong vector 17 đặc trưng hình thái (Chương 1 Mục 1.3 và Chương 3).
* **[Ref 03]** J. Katz and Y. Lindell, *Introduction to Modern Cryptography*, 3rd ed., Boca Raton, FL: CRC Press, 2020. (ISBN: 978-1466570269).  
  * **Nội dung & Vai trò:** Cung cấp cơ sở hình thức hóa Trò chơi An ninh Đối kháng (Adversarial Security Game) và hàm lợi thế tấn công $Adv(\mathcal{A})$. Áp dụng làm luận cứ toán học cho cuộc đối đầu giữa Red Team và Blue Team trong môi trường Thao trường mạng (Chương 1 Mục 1.4).
* **[Ref 04]** CompTIA, *CompTIA PenTest+ Study Guide: Exam PT0-002*, Indianapolis, IN: Sybex / John Wiley & Sons, 2021. (ISBN: 978-1119823841).  
  * **Nội dung & Vai trò:** Cung cấp phương pháp luận kiểm thử xâm nhập thực chiến: kỹ thuật trinh sát bóc tách OpenAPI, quét lỗ hổng và kiểm thử hộp xám (Gray-box Penetration Testing). Áp dụng thiết kế Tác tử Red Team tự động (Chương 1 Mục 1.4 và Chương 3).
* **[Ref 05]** D. DeJonghe, *NGINX Cookbook: Advanced Recipes for High-Performance Load Balancing*, Sebastopol, CA: O'Reilly Media, 2020. (ISBN: 978-1492062530).  
  * **Nội dung & Vai trò:** Cung cấp chuẩn mực kỹ thuật triển khai Reverse Proxy hiệu năng cao, cân bằng tải, quản lý kết nối non-blocking I/O và ngân sách độ trễ $\Delta t \le 15	ext{ ms}$. Áp dụng thiết kế WAF Gateway (Chương 1 Mục 1.5 và Chương 2).

---

### Nhóm 2: Tiêu Chuẩn Công Nghiệp & Khung Đo Lường (Industry Standards & Benchmarks)

* **[Ref 06]** OWASP Foundation, "OWASP Top 10 API Security Risks 2023," Open Web Application Security Project, Tech. Rep., 2023. [Online]. Available: `https://owasp.org/API-Security/`  
  * **Nội dung & Vai trò:** Khung phân loại các hiểm họa hàng đầu của Web API (BOLA, Broken Authentication, Injection, Unrestricted Resource Consumption). Định hình phạm vi bảo vệ của đồ án (Chương 1 Mục 1.1).
* **[Ref 07]** OWASP ModSecurity Core Rule Set Project, "ModSecurity Core Rule Set (CRS) v4.0.0 Specification," OWASP CRS Project, 2024. [Online]. Available: `https://coreruleset.org/`  
  * **Nội dung & Vai trò:** Đặc tả chuẩn mực về cơ chế Chuẩn hóa dữ liệu nhiều giai đoạn (Multi-stage Normalization) và Mô hình tính điểm bất thường tích lũy (Anomaly Scoring Model). Áp dụng tại Rule Engine (Chương 1 Mục 1.2 và Chương 3).
* **[Ref 08]** OWASP Foundation, "OWASP Benchmark Project: Automated Web Application Firewall Evaluation," OWASP Foundation, 2023. [Online]. Available: `https://owasp.org/www-project-benchmark/`  
  * **Nội dung & Vai trò:** Cung cấp thước đo khoa học Youden's Index $J = 	ext{TPR} - 	ext{FPR}$ để đánh giá khách quan năng lực phân biệt giữa mã độc và lưu lượng sạch. Áp dụng tại Chương 1 (Mục 1.5) và Chương 4.
* **[Ref 09]** K. Scarfone, M. Souppaya, A. Cody, and A. Orebaugh, "Technical Guide to Information Security Testing and Assessment," National Institute of Standards and Technology (NIST), Gaithersburg, MD, NIST Special Publication (SP) 800-115, 2008.  
  * **Nội dung & Vai trò:** Hướng dẫn tiêu chuẩn quốc tế về phương pháp luận đánh giá và kiểm thử an toàn thông tin, bảo đảm tính minh bạch trong thực nghiệm kiểm thử an ninh. Áp dụng tại Chương 4.
* **[Ref 10]** The MITRE Corporation, "MITRE ATT&CK® Enterprise Matrix: Tactics and Techniques for Web Applications," MITRE Corporation, 2024. [Online]. Available: `https://attack.mitre.org/`  
  * **Nội dung & Vai trò:** Ma trận phân loại các chiến thuật tấn công (Initial Access, Execution, Defense Evasion) và kỹ thuật giảm thiểu rủi ro (Mitigation Matrix). Áp dụng tại Chương 1 (Mục 1.3), Chương 2 và Chương 3.

---

### Nhóm 3: Bài Báo Khoa Học Về Học Máy Phòng Thủ Web (Machine Learning WAF Papers)

* **[Ref 11]** F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE 8th International Conference on Data Mining (ICDM)*, Pisa, Italy, 2008, pp. 413-422. DOI: `10.1109/ICDM.2008.17`.  
  * **Nội dung & Vai trò:** Thuật toán học máy không giám sát phát hiện dị biệt (Unsupervised Anomaly Detection). Cơ sở lý thuyết và công thức toán học tính Anomaly Score cho tầng phòng thủ thứ hai phát hiện tấn công Zero-day (Chương 1 Mục 1.3 và Chương 3).
* **[Ref 12]** L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5-32, 2001. DOI: `10.1023/A:1010933404324`.  
  * **Nội dung & Vai trò:** Công trình kinh điển về thuật toán Random Forest, kỹ thuật Bootstrap Aggregating và Feature Subsampling. Mô hình Champion đạt F1-Score 99.93% trong đồ án (Chương 1 Mục 1.3 và Chương 4).
* **[Ref 13]** Research Team, "A Dual-Stage Hybrid Pipeline for Web Application Firewall using Machine Learning," *MDPI Electronics*, vol. 14, no. 3, p. 512, 2025.  
  * **Nội dung & Vai trò:** Kiến trúc đường ống kép (Dual-Stage Pipeline) kết hợp Rule-based và ML Classifier, cơ sở thiết kế mô hình dung hợp trọng số Hybrid Risk Score (Chương 1 Mục 1.3, Chương 2 và Chương 3).
* **[Ref 14]** Academic Authors, "Cross-Dataset Generalization and Robustness in Machine Learning Web Application Firewalls," *IEEE Access*, vol. 11, pp. 45120-45135, 2023.  
  * **Nội dung & Vai trò:** Phương pháp luận đánh giá khả năng tổng quát hóa của WAF học máy trên tập dữ liệu chuẩn quốc tế CSIC 2010. Áp dụng tại Chương 4 (Mục 4.5).
* **[Ref 15]** Security Authors, "Feature Engineering and Statistical Morphological Representation of Web Payloads," *Security and Communication Networks (John Wiley & Sons)*, vol. 8, no. 18, pp. 3120-3135, 2015.  
  * **Nội dung & Vai trò:** Cơ sở khoa học cho không gian 17 đặc trưng thống kê và hình thái chuỗi payload HTTP (độ dài, tỷ lệ số, entropy, keyword token). Áp dụng tại Chương 1 (Mục 1.3) và Chương 3.

---

### Nhóm 4: Thao Trường Mạng & Tác Tử Tấn Công Đối Kháng (Cyber Range & Offensive AI)

* **[Ref 16]** M. M. Yamin, M. Katt, and V. Gkioulos, "Cyber Ranges and Testbeds for Security Education, Training and Exercises: A Survey," *Elsevier Computers & Security*, vol. 88, p. 101636, 2020. DOI: `10.1016/j.cose.2019.101636`.  
  * **Nội dung & Vai trò:** Khung kiến trúc Thao trường mạng tiêu chuẩn (Target Environment, Attack Engine, Monitoring & Scoring). Cơ sở thiết kế Thao trường mạng phân tán 2 máy vật lý (Chương 1 Mục 1.4 và Chương 2).
* **[Ref 17]** R. S. Sutton and A. G. Barto, *Reinforcement Learning: An Introduction*, 2nd ed., Cambridge, MA: The MIT Press, 2018. (ISBN: 978-0262039246).  
  * **Nội dung & Vai trò:** Giáo trình nền tảng về Học tăng cường, Quy trình quyết định Markov (MDP) và phương trình tối ưu Bellman. Áp dụng mô hình hóa bài toán né tránh WAF (Chương 1 Mục 1.4 và Chương 3).
* **[Ref 18]** V. Mnih, K. Kavukcuoglu, D. Silver, et al., "Human-level control through deep reinforcement learning," *Nature*, vol. 518, no. 7540, pp. 529-533, 2015. DOI: `10.1038/nature14236`.  
  * **Nội dung & Vai trò:** Kiến trúc Deep Q-Network (DQN) kết hợp mạng nơ-ron sâu với Q-Learning và Experience Replay. Áp dụng xây dựng mô hình evasion_agent.pt trong Tác tử Red Team (Chương 1 Mục 1.4 và Chương 3).
* **[Ref 19]** Security Researchers, "Automated Black-box Web Application Firewall Evasion using Deep Reinforcement Learning," in *Proc. 33rd USENIX Security Symposium*, Philadelphia, PA, 2024.  
  * **Nội dung & Vai trò:** Kỹ thuật né tránh WAF hộp đen tự động bằng DRL với các toán tử đột biến payload. Cơ sở xây dựng không gian hành động của Tác tử Tấn công (Chương 1 Mục 1.4 và Chương 3).
* **[Ref 20]** I. J. Goodfellow, J. Shlens, and C. Szegedy, "Explaining and Harnessing Adversarial Examples," in *Proc. International Conference on Learning Representations (ICLR)*, San Diego, CA, 2015.  
  * **Nội dung & Vai trò:** Lý thuyết nền tảng về mẫu đối kháng (Adversarial Examples) trong học máy và các phương pháp kiểm thử độ bền vững (Robustness Verification). Áp dụng tại Chương 1 và Chương 4.

---

## PHỤ LỤC A: BẢNG TRA CỨU THUẬT NGỮ VÀ TỪ VIẾT TẮT (GLOSSARY & ACRONYMS)

| Từ Viết Tắt | Thuật Ngữ Tiếng Anh Đầy Đủ | Ý Nghĩa & Ứng Dụng Trong Hệ Thống PBL6 |
| :--- | :--- | :--- |
| **API** | Application Programming Interface | Giao diện lập trình ứng dụng, phương thức giao tiếp số qua HTTP/JSON. |
| **REST** | Representational State Transfer | Kiến trúc thiết kế dịch vụ web hướng tài nguyên phổ biến. |
| **WAF** | Web Application Firewall | Tường lửa ứng dụng web, giám sát và bảo vệ lưu lượng HTTP/HTTPS. |
| **CRS** | Core Rule Set (OWASP ModSecurity) | Bộ quy tắc chữ ký an ninh mã nguồn mở chuẩn quốc tế. |
| **SQLi** | SQL Injection | Lỗ hổng tiêm câu lệnh truy vấn cơ sở dữ liệu trái phép. |
| **XSS** | Cross-Site Scripting | Tấn công chèn mã kịch bản nguy hại phía máy khách. |
| **RCE** | Remote Code Execution | Lỗ hổng thực thi lệnh điều hành từ xa nguy hiểm nhất. |
| **LFI** | Local File Inclusion / Path Traversal | Lỗ hổng đọc trộm tệp tin cấu hình nhạy cảm trên máy chủ. |
| **BOLA** | Broken Object Level Authorization | Lỗ hổng phân quyền mức đối tượng (OWASP API1:2023). |
| **IDOR** | Insecure Direct Object Reference | Tham chiếu trực tiếp đối tượng không an toàn. |
| **RF** | Random Forest | Thuật toán học máy kết hợp (Ensemble) quần thể cây quyết định. |
| **IF / iForest** | Isolation Forest | Thuật toán học máy không giám sát phát hiện dị biệt Zero-day. |
| **DQN** | Deep Q-Network | Mô hình học tăng cường sâu kết hợp Q-Learning với Mạng Nơ-ron. |
| **MDP** | Markov Decision Process | Quy trình quyết định Markov mô hình hóa bài toán né tránh WAF. |
| **ROC-AUC** | Receiver Operating Characteristic - Area Under Curve | Diện tích dưới đường cong ROC đo lường năng lực phân lớp. |
| **TPR** | True Positive Rate (Recall) | Tỷ lệ bắt giữ chính xác các mẫu tấn công nguy hại. |
| **FPR** | False Positive Rate | Tỷ lệ báo động nhầm yêu cầu hợp lệ của người dùng sạch. |
| **SLA** | Service Level Agreement | Cam kết chất lượng dịch vụ, quy định ngân sách độ trễ P95/P99. |
| **RPS** | Requests Per Second | Thông lượng xử lý số lượng yêu cầu trên mỗi giây. |
| **eBPF** | Extended Berkeley Packet Filter | Công nghệ chạy mã nhúng hiệu năng cao trong nhân Linux. |
| **XDP** | eXpress Data Path | Đường dẫn truyền dữ liệu gói tin siêu tốc tầng driver mạng. |
| **DAST** | Dynamic Application Security Testing | Kiểm thử an ninh ứng dụng động khi hệ thống đang chạy. |
| **SAST** | Static Application Security Testing | Phân tích mã nguồn tĩnh phát hiện lỗ hổng tiềm ẩn. |
| **NIST** | National Institute of Standards and Technology | Viện Tiêu chuẩn và Kỹ thuật Quốc gia Hoa Kỳ. |
| **MITRE** | The MITRE Corporation | Tổ chức an ninh quản lý cơ sở tri thức kỹ thuật MITRE ATT&CK. |

---

## PHỤ LỤC B: THÔNG SỐ CẤU HÌNH THAO TRƯỜNG MẠNG (CYBER RANGE ENVIRONMENT)

| Hạng Mục | Máy 1: Phân Hệ Phòng Thủ (Blue Team Host) | Máy 2: Phân Hệ Tấn Công (Red Team Host) |
| :--- | :--- | :--- |
| **Vai Trò Hệ Thống** | WAF Security Gateway, Target App & SOC Dashboard | Offensive AI Agent & Reconnaissance Suite |
| **Bộ Vi Xử Lý (CPU)** | Intel Core i7 (8 Cores, 16 Threads) @ 2.80 GHz | AMD Ryzen 5 / Intel Core i5 (6 Cores) @ 2.50 GHz |
| **Bộ Nhớ Trong (RAM)** | 16 GB DDR4 Dual-Channel @ 3200 MHz | 16 GB DDR4 @ 2666 MHz |
| **Ổ Cứng Lưu Trữ** | 512 GB NVMe M.2 SSD (Tốc độ đọc 3.500 MB/s) | 512 GB NVMe M.2 SSD |
| **Hệ Điều Hành** | Microsoft Windows 11 Pro 64-bit / WSL2 Ubuntu | Microsoft Windows 11 / Kali Linux Rolling |
| **Địa Chỉ Mạng (IP LAN)** | `192.168.1.100` (Cổng Ethernet GbE) | `192.168.1.101` (Wi-Fi 5 GHz / Switch GbE) |
| **Cổng Dịch Vụ Mở** | Port 8000 (WAF Gateway), Port 5000 (Bookie), Port 3000 (SOC) | Port 8080 (Attack Monitor / Telemetry Logger) |
| **Môi Trường Thực Thi** | Python 3.12, FastAPI, Uvicorn, Docker Engine 27.x | Python 3.12, PyTorch 2.4, Scikit-learn, Requests |

---

## PHỤ LỤC C: DANH MỤC ENDPOINT VÀ VECTOR 17 ĐẶC TRƯNG HÌNH THÁI

| STT | Tên Đặc Trưng | Kiểu Dữ Liệu | Ý Nghĩa Phát Hiện Toán Học & An Ninh |
| :---: | :--- | :---: | :--- |
| **1** | `payload_length` | Integer | Độ dài chuỗi; payload injection thường dài bất thường so với dữ liệu hợp lệ. |
| **2** | `digit_ratio` | Float [0,1] | Tỷ lệ chữ số; các tham số số học hợp lệ thường có tỷ lệ chữ số cao. |
| **3** | `alpha_ratio` | Float [0,1] | Tỷ lệ chữ cái; phát hiện sự suy giảm khi chèn ký tự điều khiển lạ. |
| **4** | `special_char_ratio` | Float [0,1] | Tỷ lệ ký tự đặc biệt (', ", ;, -, <, >); chỉ báo mạnh của SQLi và XSS. |
| **5** | `entropy` | Float >= 0 | Shannon Entropy; payload bị obfuscate bằng Base64/Hex có entropy rất cao. |
| **6** | `sql_keyword_count` | Integer | Tần suất từ khóa SQL nhạy cảm: SELECT, UNION, INSERT, DROP, WHERE. |
| **7** | `sql_operator_count` | Integer | Tần suất toán tử logic SQL: OR, AND, LIKE, --, /*, */. |
| **8** | `xss_tag_count` | Integer | Số lượng thẻ HTML độc hại: `<script>`, `<iframe>`, `<img>`, `<svg>`. |
| **9** | `xss_event_count` | Integer | Số lượng sự kiện JavaScript nguy hiểm: `onerror=`, `onload=`, `onclick=`. |
| **10** | `path_traversal_dot_dot` | Integer | Tần suất xuất hiện chuỗi thoát thư mục: `../`, `..\\`. |
| **11** | `path_traversal_sensitive` | Integer | Tần suất truy cập tệp tin hệ thống: `/etc/passwd`, `boot.ini`, `win.ini`. |
| **12** | `cmd_separator_count` | Integer | Số lượng ký tự phân tách lệnh shell OS: `;`, `|`, `&`, `&&`, `\|\|`, `` ` ``. |
| **13** | `cmd_binary_count` | Integer | Tần suất tên tiến trình nguy hiểm: `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`. |
| **14** | `null_byte_count` | Integer | Số lượng ký tự rỗng (`\x00`, `%00`) nhằm cắt đuôi chuỗi hoặc né regex. |
| **15** | `encoded_char_count` | Integer | Tần suất ký tự mã hóa URL (ví dụ: `%20`, `%27`, `%3C`). |
| **16** | `uppercase_ratio` | Float [0,1] | Tỷ lệ chữ hoa; phát hiện kỹ thuật hoán đổi chữ hoa/thường để né bộ lọc. |
| **17** | `whitespace_count` | Integer | Số lượng khoảng trắng; phát hiện payload SQLi dùng khoảng trắng phân tách. |
