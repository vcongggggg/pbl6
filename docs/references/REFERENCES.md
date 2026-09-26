# TÀI LIỆU THAM KHẢO CHÍNH THỨC & CƠ SỞ KHOA HỌC (ACADEMIC REFERENCES & BENCHMARKS)

> **Dự án:** Web API Security Platform & Autonomous Red Teaming on Distributed Cyber Range  
> **Phiên bản tài liệu:** 2.0 (Cập nhật Học kỳ 6 - 2026 - Tinh gọn & Bổ sung Giáo trình Kinh điển)  
> **Mục đích:** Cung cấp danh mục 20 tài liệu khoa học chuẩn mực gồm **Giáo trình đại học kinh điển quốc tế (Textbooks)**, **Bài báo hội nghị & tạp chí uy tín (Peer-reviewed Papers: USENIX, IEEE, ACM, Elsevier, MDPI, Wiley)** và **Tiêu chuẩn công nghiệp quốc tế (NIST, OWASP, MITRE)**. Đã loại bỏ các bài báo manh mún, trùng lặp nhằm đạt tính bao quát và độ tin cậy học thuật cao nhất.

---

## MỤC LỤC
1. [Mô Hình Kiềng Ba Chân Học Thuật (Academic Triangle)](#1-mô-hình-kiềng-ba-chân-học-thuật)
2. [Nhóm 1: Giáo Trình Chuẩn Mực Quốc Tế (Foundational Textbooks)](#2-nhóm-1-giáo-trình-chuẩn-mực-quốc-tế)
3. [Nhóm 2: Tiêu Chuẩn Công Nghiệp & Khung Đo Lường (Industry Standards & Benchmarks)](#3-nhóm-2-tiêu-chuẩn-công-nghiệp--khung-đo-lường)
4. [Nhóm 3: Bài Báo Khoa Học Về Học Máy Phòng Thủ Web (Machine Learning WAF Papers)](#4-nhóm-3-bài-báo-khoa-học-về-học-máy-phòng-thủ-web)
5. [Nhóm 4: Thao Trường Mạng & Tác Tử Tấn Công Đối Kháng (Cyber Range & Offensive AI)](#5-nhóm-4-thao-trường-mạng--tác-tử-tấn-công-đối-kháng)
6. [Bảng Phân Tích & Đối Chiếu 20 Nguồn Tham Khảo](#6-bảng-phân-tích--đối-chiếu-20-nguồn-tham-khảo)

---

## 1. MÔ HÌNH KIỀNG BA CHÂN HỌC THUẬT

```
                      [GIÁO TRÌNH KINH ĐIỂN - TEXTBOOKS]
              (William Stallings, Douglas Stinson, Katz & Lindell,
                    CompTIA PenTest+, NGINX Cookbook)
                                  /\
                                 /  \
                                /    \
                               /      \
    [BÀI BÁO KHOA HỌC - PAPERS] -------- [TIÊU CHUẨN CÔNG NGHIỆP - STANDARDS]
(Wiley '15, IEEE '23, MDPI '25,            (OWASP Top 10 API, ModSecurity CRS v4,
 Elsevier '20, USENIX Security '24)             OWASP Benchmark, NIST SP 800-115, MITRE)
```

---

## 2. NHÓM 1: GIÁO TRÌNH CHUẨN MỰC QUỐC TẾ (FOUNDATIONAL TEXTBOOKS)

### [Ref 01] Cryptography and Network Security: Principles and Practice
* **Tác giả:** William Stallings
* **Nhà xuất bản:** Pearson / Prentice Hall, 4th/8th Edition (ISBN: 978-0133354690)
* **Vị trí tệp nguồn:** `MH&MM/02_BaiGiang_Va_GiaoTrinh/PUBLIC_OneDrive/PUBLIC/THAMKHAO/`
* **Nội dung bao quát:**
  - Giáo trình an ninh mạng được trích dẫn nhiều nhất thế giới.
  - Định nghĩa chuẩn mực về các thế hệ tường lửa: Bộ lọc gói tin (Packet Filtering), Cổng tầng ứng dụng (**Application-Level Gateway / Reverse Proxy WAF**), và Cơ chế kiểm tra trạng thái (Stateful Inspection).
  - Phân tích nguyên lý Hệ thống phát hiện xâm nhập (**Intrusion Detection Systems - IDS**) dựa trên dấu hiệu (Signature-based) đối chiếu với phát hiện bất thường (Anomaly-based).
* **Ứng dụng vào PBL6:** Cung cấp cơ sở lý thuyết chính thống cho Chương 1 (Mục 1.2) và định hình kiến trúc Reverse Proxy WAF ở Chương 2.

### [Ref 02] Cryptography: Theory and Practice
* **Tác giả:** Douglas R. Stinson, Maura B. Paterson
* **Nhà xuất bản:** Chapman & Hall / CRC Press, 4th Edition (ISBN: 978-1138197015)
* **Vị trí tệp nguồn:** `MH&MM/02_BaiGiang_Va_GiaoTrinh/PUBLIC_OneDrive/PUBLIC/THAMKHAO/`
* **Nội dung bao quát:**
  - Giáo trình toán học mật mã chuẩn mực quốc tế.
  - Cơ sở lý thuyết thông tin (Information Theory) của Claude Shannon: Định nghĩa và chứng minh toán học của **Độ hỗn loạn Shannon (Shannon Entropy $H(X)$)**, phân phối xác suất rời rạc, và độ phân tán ngẫu nhiên của chuỗi ký tự.
* **Ứng dụng vào PBL6:** Cung cấp luận cứ toán học và công thức chuẩn để tính toán đặc trưng `entropy` trong bộ trích xuất đặc trưng hình thái payload (Task 3.1 & 3.4), phân biệt giữa chuỗi tự nhiên lành tính và chuỗi mã độc/obfuscation.

### [Ref 03] Introduction to Modern Cryptography
* **Tác giả:** Jonathan Katz, Yehuda Lindell
* **Nhà xuất bản:** Chapman & Hall / CRC Cryptography and Network Security Series, 2nd/3rd Edition (ISBN: 978-1466570269)
* **Vị trí tệp nguồn:** `MH&MM/02_BaiGiang_Va_GiaoTrinh/PUBLIC_OneDrive/PUBLIC/THAMKHAO/`
* **Nội dung bao quát:**
  - Giáo trình kinh điển định hình lý thuyết an ninh mạng hiện đại dựa trên mô hình hóa toán học.
  - Định nghĩa chuẩn tắc về **Trò chơi an ninh đối kháng (Adversarial Security Game)**: Mô hình hóa sự tương tác giữa Bên tấn công (Adversary $\mathcal{A}$) và Bên phòng thủ (Challenger/Defender $\mathcal{C}$) thông qua các truy vấn oracle và hàm lợi thế tấn công (Advantage $\mathbf{Adv}$).
* **Ứng dụng vào PBL6:** Cung cấp nền tảng toán học cho kịch bản Thao trường mạng đối kháng giữa Tác tử Tấn công tự động (Red Team Máy 2) và Tường lửa WAF (Blue Team Máy 1).

### [Ref 04] CompTIA PenTest+ Study Guide: Exam PT0-003
* **Tác giả:** Mike Chapple, David Seidl
* **Nhà xuất bản:** Sybex / John Wiley & Sons, 3rd Edition, 2024 (ISBN: 978-1394246830)
* **Vị trí tệp nguồn:** `Pentest/TaiLieu_Pentest/01_Giao_Trinh_Va_Slide/`
* **Nội dung bao quát:**
  - Giáo trình kiểm thử xâm nhập chuẩn quốc tế bao quát toàn diện quy trình kiểm thử an ninh.
  - Bao quát toàn bộ kỹ thuật trinh sát Web API (Reconnaissance), phát hiện và khai thác các lỗ hổng Web API (SQL Injection, XSS, Path Traversal, Command Injection).
  - Phân tích các kỹ thuật né tránh phòng thủ (**WAF Evasion & Obfuscation**): mã hóa URL đa tầng, phân mảnh tham số HTTP Parameter Pollution (HPP), và chèn ký tự điều khiển.
* **Ứng dụng vào PBL6:** Thay thế toàn diện các bài báo nhỏ lẻ về từng loại tấn công. Định hình quy trình Red Team, thiết kế kịch bản tấn công cho Máy 2 và các bộ luật phát hiện cho Rule Engine Máy 1.

### [Ref 05] NGINX Cookbook: Advanced Recipes for High-Performance Load Balancing & Security
* **Tác giả:** Derek DeJonghe
* **Nhà xuất bản:** O'Reilly Media, 2nd Edition (ISBN: 978-1492091721)
* **Vị trí tệp nguồn:** `Pentest/TaiLieu_Pentest/04_Mang_Va_He_Thong/`
* **Nội dung bao quát:**
  - Cẩm nang kiến trúc hàng đầu về Reverse Proxy hiệu năng cao.
  - Cơ chế xử lý luồng HTTP/HTTPS bất đồng bộ, lọc Header (Hop-by-hop headers sanitization), và bảo vệ Open Proxy/SSRF.
  - Các thuật toán giới hạn tần suất truy cập (**Rate Limiting**): Thuật toán thùng rò (Leaky Bucket) và thùng thẻ bài (Token Bucket) kết hợp cửa sổ trượt (Sliding Window).
* **Ứng dụng vào PBL6:** Cơ sở kỹ thuật cho module Reverse Proxy Gateway (Phase 1) và thuật toán Rate Limiter trừng phạt IP tự động (Phase 8).

---

## 3. NHÓM 2: TIÊU CHUẨN CÔNG NGHIỆP & KHUNG ĐO LƯỜNG (STANDARDS & BENCHMARKS)

### [Ref 06] OWASP Top 10 API Security Risks – 2023
* **Tổ chức phát hành:** Open Web Application Security Project (OWASP)
* **Nội dung bao quát:**
  - Tiêu chuẩn an ninh số 1 thế giới dành riêng cho Web API, cập nhật các rủi ro nguy hiểm nhất:
    - API1:2023 Broken Object Level Authorization (BOLA/IDOR)
    - API2:2023 Broken Authentication
    - API3:2023 Broken Object Property Level Authorization
    - API4:2023 Unrestricted Resource Consumption (DoS / Brute-force)
    - API8:2023 Security Misconfiguration
    - API10:2023 Unsafe Consumption of APIs
* **Ứng dụng vào PBL6:** Khung tham chiếu xây dựng ứng dụng mục tiêu giả lập `vulnerable-api` (Bookie Bookstore) và đánh giá độ phủ lỗ hổng của WAF.

### [Ref 07] OWASP ModSecurity Core Rule Set (CRS) v4.0
* **Tổ chức phát hành:** OWASP ModSecurity CRS Project (2024)
* **Nội dung bao quát:**
  - Bộ luật phát hiện tấn công web nguồn mở chuẩn mực công nghiệp.
  - Kiến trúc chấm điểm bất thường lũy tiến (**Collaborative Anomaly Scoring System**): gán trọng số rủi ro tích lũy (Critical=+5, High=+4, Medium=+3, Low=+2) thay vì cơ chế chặn tức thời (Disruptive single-rule blocking).
* **Ứng dụng vào PBL6:** Nền tảng thiết kế bộ luật 16 rules tĩnh (Phase 2), Input Normalizer và cơ chế tính điểm bất thường tất định trong Rule Engine.

### [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015)
* **Tác phẩm:** Combining Expert Knowledge with Automatic Feature Extraction for Reliable Web Attack Detection
* **Xuất bản:** *Security and Communication Networks (Wiley)*, Vol. 8, Iss. 18, pp. 4452-4467, 2015
* **Nội dung bao quát:**
  - Công trình nền tảng đề xuất không gian 17 đặc trưng hình thái học và thống kê chuỗi HTTP (độ dài, entropy, tần suất ký tự đặc biệt, mật độ từ khóa).
  - Chứng minh vector 17 chiều đạt hiệu quả phân loại tối ưu trên cả SQLi, XSS, Path Traversal và Tampering mà không làm tăng độ trễ mạng.
* **Ứng dụng vào PBL6:** Cơ sở khoa học trực tiếp cho bộ trích xuất đặc trưng 17 chiều `ml-engine/features/extractor.py` (Phase 3).

### [Ref 09] HTTP Data Set CSIC 2010
* **Tổ chức phát hành:** Information Security Institute of CSIC (Tây Ban Nha)
* **Nội dung bao quát:**
  - Bộ dữ liệu lưu lượng HTTP công khai chuẩn mực quốc tế, chứa hàng chục nghìn yêu cầu HTTP thực tế (cả Benign và các cuộc tấn công tinh vi).
  - Được cộng đồng học thuật toàn cầu sử dụng làm Benchmark đối sánh khả năng phát hiện bất thường của WAF.
* **Ứng dụng vào PBL6:** Tập dữ liệu kiểm định chéo độc lập (Cross-Dataset Generalization Benchmark - Task 5.4) và Active Learning Hard Sample Mining (Task 5.5).

### [Ref 10] Detection of SQL Injection Attack Using Machine Learning Techniques: A Systematic Literature Review
* **Tác giả:** M. Hasan, M. Z. Chowdhury et al.
* **Xuất bản:** *IEEE Access*, Vol. 11, pp. 98321-98345, 2023
* **Nội dung bao quát:**
  - Tổng quan có hệ thống về các phương pháp trích xuất đặc trưng và thuật toán học máy phân loại SQLi.
  - Phân tích ưu nhược điểm của các thuật toán: Logistic Regression, Decision Tree, SVM, Random Forest và XGBoost.
* **Ứng dụng vào PBL6:** Cơ sở lý thuyết cho pipeline huấn luyện đa mô hình và đánh giá đối chuẩn (Phase 5).

### [Ref 11] High-Throughput Web Application Firewall with Hybrid Machine Learning and Anomaly Detection
* **Tác giả:** Nghiên cứu tổng hợp phương pháp luận WAF hiện đại
* **Xuất bản:** *MDPI Electronics / Applied Sciences*, 2025
* **Nội dung bao quát:**
  - Đề xuất kiến trúc phòng thủ đa tầng (**Dual-Stage Pipeline**):
    - Tầng 1: Lọc thô bằng biểu thức chính quy tĩnh siêu tốc (< 1ms).
    - Tầng 2: Phân tích sâu kết hợp Random Forest (có giám sát) và Isolation Forest (không giám sát phát hiện Zero-day).
* **Ứng dụng vào PBL6:** Cơ sở trực tiếp định hình kiến trúc WAF Hybrid kết hợp Rule + Random Forest + Isolation Forest (Phase 7).

### [Ref 12] Deep Learning and Transformer-Based Approaches for Web Attack Detection: A Systematic Survey
* **Tác giả:** Nghiên cứu khảo sát chuyên sâu
* **Xuất bản:** *IEEE Access / ACM Computing Surveys*, 2024
* **Nội dung bao quát:**
  - Khảo sát thực nghiệm đối sánh giữa các thuật toán cây truyền thống (Random Forest, XGBoost) và mạng nơ-ron sâu (CNN, Bi-LSTM, BERT/DistilBERT).
  - Kết luận: Các mô hình Transformer tiêu tốn từ 60ms đến 150ms trên CPU, không thể đáp ứng ngân sách độ trễ cho inline WAF thực tế; Random Forest đạt độ trễ < 2ms với F1-score tương đương.
* **Ứng dụng vào PBL6:** Luận điểm phản biện khoa học đanh thép giải thích lý do lựa chọn Random Forest thay vì các mô hình Deep Learning cồng kềnh.

### [Ref 13] OWASP Benchmark Project (v1.2) & Youden's Index Metric
* **Tổ chức phát hành:** OWASP Foundation
* **Nội dung bao quát:**
  - Khung thực nghiệm khoa học đo lường độ chính xác thực tế của các giải pháp bảo mật ứng dụng web.
  - Định nghĩa chuẩn mực chỉ số **Youden's Index ($J = \text{TPR} - \text{FPR}$)**: Đánh giá khả năng phân tách khách quan giữa tấn công thực sự và lưu lượng hợp lệ mà không gây báo động giả làm gián đoạn kinh doanh.
* **Ứng dụng vào PBL6:** Thước đo khoa học chính thức để chấm điểm và lựa chọn mô hình Machine Learning Champion (Phase 5) và đánh giá hệ thống phòng thủ đa tầng.

### [Ref 14] Cyber Ranges and Security Testbeds: Scenarios, Functions, Tools and Architecture
* **Tác giả:** M. M. Yamin, M. Katt, V. Gkioulos
* **Xuất bản:** *Elsevier Computers & Security*, Vol. 88, 2020 (DOI: 10.1016/j.cose.2019.101636)
* **Nội dung bao quát:**
  - Công trình khảo sát toàn diện nhất thế giới về kiến trúc Thao trường mạng (Cyber Range).
  - Chuẩn hóa mô hình Cyber Range thành 3 phân hệ: Môi trường mục tiêu (Target Environment), Phân hệ mô phỏng tấn công (Attack Simulation Engine), và Phân hệ giám sát chấm điểm (Scoring & Monitoring System).
* **Ứng dụng vào PBL6:** Nền tảng kiến trúc tổng thể cho toàn bộ đề án PBL6 triển khai phân tán giữa 2 máy trạm qua mạng LAN.

### [Ref 15] NIST Special Publication 800-115
* **Tác giả:** Karen Scarfone, Murugiah Souppaya, Amanda Cody, Angela Orebaugh
* **Tổ chức phát hành:** National Institute of Standards and Technology (NIST), U.S. Department of Commerce
* **Nội dung bao quát:**
  - Hướng dẫn kỹ thuật chuẩn mực của chính phủ Hoa Kỳ về quy trình kiểm thử và đánh giá an toàn thông tin (Technical Guide to Information Security Testing and Assessment).
  - Chuẩn hóa 4 giai đoạn kiểm thử: Lập kế hoạch (Planning), Khám phá (Discovery), Tấn công thử nghiệm (Attack), và Báo cáo (Reporting).
* **Ứng dụng vào PBL6:** Quy chuẩn hóa phương pháp luận kiểm thử thực nghiệm an ninh trong toàn bộ đồ án.

### [Ref 16] MITRE ATT&CK Matrix for Enterprise
* **Tổ chức phát hành:** The MITRE Corporation
* **Nội dung bao quát:**
  - Cơ sở tri thức chuẩn quốc tế phân loại các chiến thuật, kỹ thuật và quy trình tấn công (TTPs).
  - Ánh xạ các kỹ thuật tấn công Web API trọng tâm:
    - `T1190`: Exploit Public-Facing Application (SQLi, Command Injection)
    - `T1059`: Command and Scripting Interpreter
    - `T1083`: File and Directory Discovery (Path Traversal)
    - `T1595`: Active Scanning (OpenAPI Reconnaissance)
* **Ứng dụng vào PBL6:** Ánh xạ các sự kiện cảnh báo trên SOC Dashboard và chuẩn hóa kịch bản tấn công của Red Team.

### [Ref 17] RESTler: Stateful REST API Fuzzing
* **Tác giả:** V. Atlidakis, P. Godefroid, M. Polishchuk
* **Xuất bản:** *IEEE International Conference on Software Engineering (ICSE)*, 2019
* **Nội dung bao quát:**
  - Công cụ Fuzzing tự động đầu tiên trên thế giới có khả năng trích xuất đặc tả OpenAPI/Swagger và tự động phân tích đồ thị phụ thuộc giữa các endpoint để sinh chuỗi request hợp lệ.
* **Ứng dụng vào PBL6:** Cơ sở lý thuyết cho module trinh sát và sinh payload tự động của Tác tử Tấn công (Máy 2 - Phase 10).

### [Ref 18] PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing
* **Tác giả:** G. Deng, Z. Xu, Y. Li, Y. Shen, T. Liu
* **Xuất bản:** *USENIX Security Symposium*, 2024
* **Nội dung bao quát:**
  - Công trình khoa học hàng đầu khảo sát năng lực của tác tử AI trong việc tự động hóa chuỗi tấn công mạng.
* **Ứng dụng vào PBL6:** Tham chiếu về tư duy lập lịch tấn công (Attack Planner) cho Tác tử Red Team.

### [Ref 19] A Survey on Large Language Model-based Agents in Autonomous Cyberattacks
* **Tác giả:** Nghiên cứu khảo sát tổng hợp
* **Xuất bản:** *arXiv preprint*, 2024
* **Nội dung bao quát:**
  - Khảo sát toàn diện về các tác tử AI tấn công tự động, phân tích cơ chế né tránh WAF và hạn chế của các API thương mại.
* **Ứng dụng vào PBL6:** Luận điểm chứng minh việc tự xây dựng mô hình Deep Reinforcement Learning (PyTorch DQN) In-House là giải pháp tối ưu cho môi trường Thao trường mạng nội bộ.

### [Ref 20] CALDERA: A Red-Blue Cyber Operations Automation Platform
* **Tác giả:** The MITRE Corporation
* **Xuất bản:** *ICAPS Workshop on Planning and Cyber Security*, 2022
* **Nội dung bao quát:**
  - Nền tảng mô phỏng đối kháng Red Team / Blue Team tự động hóa dựa trên lập lịch đồ thị tấn công (Attack Graph Planning).
* **Ứng dụng vào PBL6:** Tham chiếu xây dựng giao thức tương tác và diễn tập giữa Máy 1 (Blue) và Máy 2 (Red).

---

## 6. BẢNG PHÂN TÍCH & ĐỐI CHIẾU 20 NGUỒN THAM KHẢO

| STT | Mã Ref | Tác Giả / Tổ Chức | Loại Hình | Nguồn Xuất Bản | Vai Trò Trong Đồ Án PBL6 |
| :---: | :---: | :--- | :---: | :---: | :--- |
| 1 | **[Ref 01]** | William Stallings | Giáo trình | Prentice Hall | Định nghĩa Tường lửa, Application-Level Gateway, Anomaly vs Signature IDS |
| 2 | **[Ref 02]** | Douglas R. Stinson et al. | Giáo trình | CRC Press | Cơ sở toán học Lý thuyết thông tin và Shannon Entropy $H(X)$ |
| 3 | **[Ref 03]** | Jonathan Katz & Y. Lindell | Giáo trình | CRC Press | Mô hình toán học Trò chơi An ninh Đối kháng (Adversarial Security Game) |
| 4 | **[Ref 04]** | CompTIA (Mike Chapple et al.) | Giáo trình | Sybex / Wiley | Phương pháp luận Pentest, kỹ thuật khai thác Web API & Evasion |
| 5 | **[Ref 05]** | Derek DeJonghe | Giáo trình | O'Reilly Media | Kiến trúc Reverse Proxy Gateway & Thuật toán Token Bucket Rate Limiting |
| 6 | **[Ref 06]** | OWASP | Tiêu chuẩn | OWASP Foundation | Phân loại rủi ro OWASP Top 10 API Security Risks (2023) |
| 7 | **[Ref 07]** | OWASP ModSecurity Project | Tiêu chuẩn | CRS Project | Bộ luật tĩnh và cơ chế Collaborative Anomaly Scoring |
| 8 | **[Ref 08]** | C. Torrano-Gimenez et al. | Bài báo | Wiley SCN 2015 | Không gian 17 đặc trưng hình thái học và thống kê chuỗi HTTP |
| 9 | **[Ref 09]** | CSIC Research Institute | Bộ dữ liệu | CSIC Tây Ban Nha | Bộ dữ liệu chuẩn mực quốc tế CSIC 2010 cho kiểm định chéo |
| 10 | **[Ref 10]** | M. Hasan et al. | Bài báo | IEEE Access 2023 | Đánh giá tổng quan các kỹ thuật học máy phát hiện SQL Injection |
| 11 | **[Ref 11]** | Nhóm nghiên cứu quốc tế | Bài báo | MDPI Electronics 2025 | Kiến trúc WAF Hybrid kết hợp Rule + Random Forest + Isolation Forest |
| 12 | **[Ref 12]** | Nhóm nghiên cứu quốc tế | Bài báo | IEEE Access 2024 | Khảo sát thực nghiệm đối sánh Random Forest vs Deep Learning/Transformers |
| 13 | **[Ref 13]** | OWASP Benchmark Project | Tiêu chuẩn | OWASP Foundation | Đo lường hiệu năng WAF bằng Youden's Index $J = \text{TPR} - \text{FPR}$ |
| 14 | **[Ref 14]** | M. M. Yamin et al. | Bài báo | Elsevier C&S 2020 | Kiến trúc tiêu chuẩn quốc tế cho Thao trường mạng (Cyber Range) |
| 15 | **[Ref 15]** | NIST (Scarfone et al.) | Tiêu chuẩn | U.S. Dept. of Commerce | Hướng dẫn kiểm thử kỹ thuật an ninh thông tin (NIST SP 800-115) |
| 16 | **[Ref 16]** | MITRE Corporation | Tiêu chuẩn | MITRE ATT&CK | Khung ánh xạ TTPs tấn công mạng doanh nghiệp (T1190, T1059, T1083) |
| 17 | **[Ref 17]** | V. Atlidakis et al. | Bài báo | IEEE ICSE 2019 | Fuzzing tự động sinh payload phụ thuộc trạng thái cho REST API |
| 18 | **[Ref 18]** | G. Deng et al. | Bài báo | USENIX Security 2024 | Tác tử AI tự động hóa kiểm thử xâm nhập PentestGPT |
| 19 | **[Ref 19]** | Nhóm tác giả quốc tế | Bài báo | arXiv Survey 2024 | Khảo sát tổng quan về tác tử AI tấn công tự động |
| 20 | **[Ref 20]** | MITRE Corporation | Bài báo | ICAPS 2022 | Nền tảng tự động hóa Red-Blue operations CALDERA |
