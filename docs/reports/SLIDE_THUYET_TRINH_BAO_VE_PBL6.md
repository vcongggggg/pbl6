# BỘ SLIDE THUYẾT TRÌNH BẢO VỆ ĐỒ ÁN TỐT NGHIỆP / PBL6
## ĐỀ TÀI: PHÁT HIỆN VÀ NGĂN CHẶN TẤN CÔNG WEB API THÔNG MINH SỬ DỤNG MACHINE LEARNING KẾT HỢP THAO TRƯỜNG AN NINH ĐỐI KHÁNG

> **Chuyên ngành:** Kỹ thuật Phần mềm & An toàn Thông tin  
> **Khoa:** Công nghệ Thông tin — Trường Đại học Bách khoa, Đại học Đà Nẵng  
> **Giảng viên hướng dẫn:** TS. [Tên Giảng Viên Hướng Dẫn]  
> **Sinh viên thực hiện:**  
> • **Trần Văn Công** (Leader / Blue Team — Phụ trách Gateway, WAF & Machine Learning)  
> • **Nguyễn Minh** (Member / Red Team — Phụ trách Autonomous Attack Planner & Evasion)  
> **Thời lượng báo cáo:** 15 – 20 phút thuyết minh + 10 phút Demo thực chiến  

---

### DANH MỤC 14 SLIDES THUYẾT TRÌNH VÀ PHÂN CÔNG THUYẾT MINH

| Slide | Tiêu Đề Slide | Người Trình Bày | Trọng Tâm Học Thuật |
| :---: | :--- | :---: | :--- |
| **01** | Bìa Đề Tài & Thông Tin Nhóm | Cả hai | Giới thiệu bối cảnh và định vị đề tài |
| **02** | Đặt Vấn Đề & Bối Cảnh An Ninh Web API | Công (A) | Lỗ hổng OWASP API Top 10 & Sự bùng nổ của AI-driven attacks |
| **03** | Mục Tiêu Nghiên Cứu & Đóng Góp Của Đề Tài | Công (A) | Kiềng 3 chân: Defense AI + Offensive AI + Cyber Range LAN |
| **04** | Kiến Trúc Thao Trường Đối Kháng Phân Tán (2 Máy) | Minh (B) | Mô hình vật lý: Máy 1 (Defender WAF) vs Máy 2 (Autonomous Attacker) |
| **05** | Tầng 1: Positive Security Model (OpenAPI Contract) | Công (A) | Nguyên lý "Chỉ cho phép cái đúng" — Chặn đứng parameter injection |
| **06** | Tầng 2 & 3: Kiến Trúc Phòng Thủ Lai (Hybrid AI WAF) | Công (A) | Phối hợp Rule Engine (16 rules) + Random Forest (17 features) + Isolation Forest |
| **07** | Tương Quan Chuỗi Tấn Công (Cyber Kill Chain Correlation)| Công (A) | Gom cụm 15 phút, mapping 5 giai đoạn MITRE ATT&CK |
| **08** | Trung Tâm Chỉ Huy SOC & Explainable AI (SHAP / Telemetry)| Công (A) | Trực quan hóa rủi ro thời gian thực, bóc tách bằng chứng payload |
| **09** | Tác Tử Tấn Công Tự Hành & Evasion Engine (Offensive AI)| Minh (B) | Autonomous Attack Planner, biến dị payload né WAF (5 rounds) |
| **10** | Thực Nghiệm 1: Ablation Study — Đo Lường 4 Cấu Hình | Công (A) | Bảng thực nghiệm 1,000 mẫu: Rules vs ML vs Anomaly vs Hybrid |
| **11** | Vũ Khí Phản Biện: Tại Sao Cần Hybrid Khi F1 Chỉ Hơn 0.2%?| Công (A) | 4 Luận điểm sinh tử bảo vệ kiến trúc Defense-in-Depth |
| **12** | Thực Nghiệm 2: Đánh Giá Hiệu Năng & SLA Thời Gian Thực | Minh (B) | Phân vị độ trễ (P95 < 2ms), độ bền bỉ Fail-Safe Degraded Mode |
| **13** | Kịch Bản Diễn Tập Thực Chiến 10 Phút Trước Hội Đồng | Cả hai | 4 Phân cảnh đối đầu trực tiếp giữa 2 máy tính trên mạng LAN |
| **14** | Kết Luận & Hướng Phát Triển Tương Lai (C2–C4) | Cả hai | Đúc kết kết quả & Lộ trình mở rộng cấp công nghiệp |

---

### CHI TIẾT NỘI DUNG VÀ LỜI THOẠI TỪNG SLIDE (PRESENTER NOTES)

#### SLIDE 01: BÌA ĐỀ TÀI & THÔNG TIN DỰ ÁN
- **Nội dung hiển thị:**
  - Tên đề tài chính thức: "Xây dựng hệ thống phát hiện và ngăn chặn tấn công Web API thông minh sử dụng Machine Learning kết hợp Thao trường An ninh Đối kháng".
  - Giảng viên hướng dẫn: TS. [Tên GVHD].
  - Sinh viên thực hiện: Trần Văn Công & Nguyễn Minh.
- **Lời thoại thuyết minh (Công mở đầu):**
  > *"Kính thưa quý Thầy, Cô trong Hội đồng chấm đồ án tốt nghiệp! Em là Trần Văn Công, đại diện nhóm nghiên cứu đề tài 'Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API thông minh bằng Machine Learning kết hợp Thao trường Đối kháng Phân tán'. Hôm nay, nhóm chúng em rất vinh dự được trình bày toàn bộ kết quả nghiên cứu và sản phẩm thực chiến mà nhóm đã dày công hiện thực hóa trong suốt học kỳ vừa qua."*

#### SLIDE 02: ĐẶT VẤN ĐỀ & BỐI CẢNH AN NINH WEB API
- **Nội dung hiển thị:**
  - Sự thống trị của API (chiếm hơn 80% lưu lượng Internet hiện đại).
  - Điểm nghẽn của WAF truyền thống (ModSecurity, regex tĩnh): Dễ bị bypass bởi obfuscation, tỷ lệ cảnh báo giả cao, bảo trì chữ ký tốn kém.
  - Điểm yếu của ML thuần: "Hộp đen", không chịu được tấn công đối kháng (Adversarial Evasion), không bắt được Zero-Day.
  - Thách thức: Kẻ tấn công ngày nay đã biết dùng AI để tự động hóa quét và biến dị payload.
- **Lời thoại thuyết minh (Công):**
  > *"Thưa Thầy Cô, hiện nay Web API là xương sống kết nối toàn bộ các dịch vụ số. Tuy nhiên, các giải pháp WAF truyền thống chỉ dựa vào chữ ký tĩnh regex đang bộc lộ những điểm yếu chí mạng: kẻ tấn công chỉ cần chèn một comment SQL hoặc dùng kỹ thuật double-encoding là có thể vượt rào hoàn toàn. Ngược lại, nếu chỉ ứng dụng Machine Learning đơn lẻ, hệ thống lại trở thành một chiếc hộp đen dễ bị đánh lừa bởi tấn công đối kháng. Đó chính là lý do nhóm đặt ra bài toán: Làm thế nào để kết hợp ưu thế của cả Luật tất định, Học máy có giám sát và Phát hiện dị thường không giám sát thành một khối thống nhất?"*

#### SLIDE 03: MỤC TIÊU NGHIÊN CỨU & ĐÓNG GÓP HỌC THUẬT
- **Nội dung hiển thị:**
  - **Mục tiêu 1:** Xây dựng WAF Reverse Proxy Gateway đa tầng phòng thủ (Positive Schema + Rule Engine + Supervised ML + Anomaly Detection).
  - **Mục tiêu 2:** Xây dựng tác tử tấn công tự hành (Autonomous Red Team Agent) phục vụ thao trường đối kháng.
  - **Mục tiêu 3:** Thực nghiệm kiểm chứng khoa học minh bạch trên mạng LAN vật lý thực tế.
- **Lời thoại thuyết minh (Công):**
  > *"Để giải quyết bài toán trên, đề tài của chúng em xác lập mô hình kiềng ba chân: Thứ nhất, xây dựng hệ thống phòng thủ đa tầng Defense-in-depth đạt chuẩn SLA công nghiệp. Thứ hai, tự xây dựng một tác tử Red Team có khả năng tự lập kế hoạch và biến dị payload đối đầu trực tiếp. Và thứ ba, toàn bộ hệ thống phải được triển khai trên 2 máy tính vật lý độc lập qua mạng LAN để loại bỏ mọi giả lập phi thực tế."*

#### SLIDE 04: KIẾN TRÚC THAO TRƯỜNG ĐỐI KHÁNG PHÂN TÁN (DISTRIBUTED CYBER RANGE)
- **Nội dung hiển thị:**
  - Sơ đồ kết nối mạng LAN giữa 2 máy vật lý (192.168.1.X).
  - **Máy 1 (Blue Team Host):** Reverse Proxy WAF Gateway (Port 8000), Target Bookie API (Port 5000), SOC Dashboard (Port 3000), SQLite/WAL Database.
  - **Máy 2 (Red Team Host):** Offensive AI Attack Planner, Evasion Engine, Recon Engine.
- **Lời thoại thuyết minh (Minh):**
  > *"Kính thưa Hội đồng, em là Nguyễn Minh, phụ trách phân hệ Red Team. Nhằm đảm bảo tính xác thực học thuật cao nhất theo hướng dẫn của NIST SP 800-115, nhóm em không chạy chung client và server trên cùng một máy localhost. Chúng em triển khai 2 máy vật lý riêng biệt: Máy 1 đóng vai trò pháo đài phòng thủ Blue Team, và Máy 2 đóng vai trò kẻ tấn công Red Team. Mọi gói tin, độ trễ và tỷ lệ chặn đều là dữ liệu thực tế di chuyển qua hạ tầng mạng LAN."*

#### SLIDE 05: TẦNG 1 — POSITIVE SECURITY MODEL (OPENAPI CONTRACT ENFORCEMENT)
- **Nội dung hiển thị:**
  - Triết lý: "Chỉ cho phép những gì hợp lệ được định nghĩa trước đi qua" (Zero Trust API Gateway).
  - Xác thực nghiêm ngặt: HTTP Method, URL Path, Query Parameters, Schema Body Type.
  - Dự phòng ngoại tuyến: Fallback OpenAPI Specification khi backend offline.
- **Lời thoại thuyết minh (Công):**
  > *"Trước khi request chạm đến AI hay Rule Engine, tầng phòng thủ đầu tiên chính là Positive Security Model. Thay vì chỉ chạy theo tìm dấu vết mã độc (Negative Security), hệ thống xác thực trực tiếp request với bản đặc tả OpenAPI chuẩn của backend. Bất kỳ request nào chứa tham số lạ, sai kiểu dữ liệu hay vượt quá dung lượng cho phép đều bị từ chối ngay lập tức ở cửa khẩu, triệt tiêu nguy cơ Parameter Pollution và Mass Assignment."*

#### SLIDE 06: TẦNG 2 & 3 — KIẾN TRÚC PHÒNG THỦ LAI (HYBRID AI WAF DEFENSE)
- **Nội dung hiển thị:**
  - **Rule Engine (16 Rules):** Bắt chính xác 100% các chữ ký OWASP Top 10 trong 0.14 ms.
  - **Random Forest (Supervised ML):** Huấn luyện trên 17 đặc trưng payload/context (n-gram, entropy, tỷ lệ ký tự đặc biệt) với 100 cây quyết định.
  - **Isolation Forest (Unsupervised Anomaly):** Bẫy bắt Zero-Day dựa trên độ sâu cô lập hình học.
  - **Arbitration Engine:** Tổng hợp trọng số $Score = 0.40 \cdot R_{Rule} + 0.35 \cdot R_{ML} + 0.25 \cdot R_{Anom}$.
- **Lời thoại thuyết minh (Công):**
  > *"Đây là trái tim phòng thủ của đề tài: Tầng Hybrid AI. Rule Engine đảm bảo tính tất định và siêu nhanh ở 0.14ms. Random Forest đảm bảo khả năng tổng quát hóa các payload đã bị obfuscated. Và Isolation Forest là tấm lưới an toàn cuối cùng phát hiện các hành vi bất thường chưa từng có trong tập huấn luyện. Ba thành phần này được hợp nhất qua bộ trọng tài Risk Engine để đưa ra quyết định tối ưu: ALLOW, MONITOR, RATE_LIMIT hoặc BLOCK."*

#### SLIDE 07: TƯƠNG QUAN CHUỖI TẤN CÔNG (CYBER KILL CHAIN SESSION CORRELATION)
- **Nội dung hiển thị:**
  - Thuật toán cửa sổ trượt 15 phút: Gom cụm các alert đơn lẻ từ cùng IP nguồn thành một Attack Session.
  - Gán nhãn 5 giai đoạn MITRE Cyber Kill Chain: `RECONNAISSANCE` ➔ `EXPLOITATION` ➔ `EVASION` ➔ `PRIVILEGE_ABUSE` ➔ `EXFILTRATION`.
  - Giảm thiểu hiện tượng Alert Fatigue cho nhân viên SOC.
- **Lời thoại thuyết minh (Công):**
  > *"Một đóng góp thực tiễn quan trọng của nhóm là không để nhân viên giám sát bị ngợp trong hàng nghìn cảnh báo rời rạc. Hệ thống tự động băm IP nguồn theo cửa sổ 15 phút để gom thành từng Phiên tấn công, đồng thời ánh xạ trực quan vào 5 giai đoạn Cyber Kill Chain. Chuyên viên an ninh nhìn vào là thấy ngay: Attacker đang ở bước dò quét hay đã chuyển sang giai đoạn trích xuất dữ liệu."*

#### SLIDE 08: TRUNG TÂM CHỈ HUY SOC COMMAND CENTER & EXPLAINABLE AI
- **Nội dung hiển thị:**
  - Giao diện Next.js 14 SOC Dashboard thời gian thực: KPI Cards, Live Event Stream, Timeline Chart, Distribution Donut.
  - Explainable AI: Modal bóc tách chứng cứ payload, đối chiếu chữ ký quy tắc và giải thích rủi ro tường minh.
  - Nút chuyển WAF Mode tức thì (`MONITOR_ONLY` ⇄ `ACTIVE_BLOCKING`).
- **Lời thoại thuyết minh (Công):**
  > *"Để đưa AI vào thực tế sản xuất, tính minh bạch và khả năng giải thích (Explainable AI) là điều kiện bắt buộc. Giao diện SOC Command Center do nhóm tự phát triển không chỉ hiển thị các biểu đồ telemetry sống động, mà còn cho phép bấm vào bất kỳ sự kiện nào để xem chi tiết bằng chứng: chuỗi payload vi phạm là gì, đặc trưng nào của ML bị kích hoạt và mức độ đe dọa ra sao, giúp đội ngũ ứng cứu ra quyết định trong vài giây."*

#### SLIDE 09: TÁC TỬ TẤN CÔNG TỰ HÀNH & EVASION ENGINE (OFFENSIVE AI)
- **Nội dung hiển thị:**
  - Kiến trúc Autonomous Red Team Planner trên Máy 2.
  - Khả năng tự động phân tích bề mặt tấn công qua OpenAPI (`attack_surface.json`).
  - Evasion Engine: Đột biến payload thông minh khi gặp HTTP 403 (SQL Comment Insertion, Hex Encoding, Whitespace Tampering) tối đa 5 rounds.
- **Lời thoại thuyết minh (Minh):**
  > *"Ở bờ đối diện, phân hệ Red Team do em phụ trách không đơn thuần là một công cụ bắn payload tĩnh như Postman. Tác tử Offensive AI đọc hiểu sơ đồ API, lập chiến dịch tấn công tự động, và đặc biệt khi bị WAF chặn với mã 403, Evasion Engine sẽ tự động kích hoạt thuật toán biến dị payload để thử vượt rào qua nhiều vòng đối đầu, tạo nên thao trường an ninh sống động thực sự."*

#### SLIDE 10: THỰC NGHIỆM 1 — ABLATION STUDY (ĐO LƯỜNG ĐÓNG GÓP 4 CẤU HÌNH)
- **Nội dung hiển thị:**
  - Bảng đối sánh 1,000 mẫu đa dạng (`benchmark_1000_diverse.csv`):
    - **Rules Only:** Acc 54.80% | F1 60.63% | Recall 43.50% | Latency **0.14 ms**
    - **ML Only:** Acc 95.90% | F1 97.37% | Recall 94.88% | Latency 8.40 ms
    - **Anomaly Only:** Acc 24.70% | F1 11.10% | Recall 5.88% | Latency 9.49 ms
    - **Hybrid Defense:** Acc **96.20%** | F1 **97.57%** | Recall **95.25%** | Latency 16.10 ms
  - FPR ở tất cả các chế độ duy trì tuyệt đối ở mức 0.00%.
- **Lời thoại thuyết minh (Công):**
  > *"Để có câu trả lời định lượng chính xác cho câu hỏi 'Liệu kiến trúc Hybrid có thực sự hiệu quả?', nhóm đã chạy thực nghiệm Ablation Study trên 1,000 mẫu độc lập với phép đo cô lập độ trễ hoàn toàn. Kết quả cho thấy: Rule Engine thuần chỉ bắt được 43.50% tấn công do bỏ lọt các biến thể né tránh. Khi kết hợp thành Hybrid, Recall tăng vọt lên 95.25% và F1-Score đạt đỉnh 97.57% với FPR tuyệt đối 0.00%."*

#### SLIDE 11: VŨ KHÍ PHẢN BIỆN — TẠI SAO CẦN HYBRID KHI F1 CHỈ HƠN ML THUẦN 0.2%?
- **Nội dung hiển thị:**
  - Đập tan ngộ nhận số liệu tổng hợp (Aggregate Metric Illusion).
  - **4 Trụ cột sống còn:**
    1. *Khắc phục điểm mù Adversarial Evasion:* Rule Engine bóc tách comment/double-encoding mà ML bị đánh lừa.
    2. *Bẫy cảnh giới Zero-Day / OOD:* Isolation Forest bắt các dị dạng nằm ngoài 5 nhãn đã học của ML.
    3. *Fast-Path Gatekeeper:* 80% rà quét đại trà bị Rule Engine từ chối ngay ở 0.14 ms, cứu CPU cho hệ thống.
    4. *Fail-Safe Degraded Mode:* Khi mô hình ML sập, Gateway vẫn hoạt động an toàn nhờ Rule Engine.
- **Lời thoại thuyết minh (Công):**
  > *"Đây là câu hỏi cốt tử mà nhóm đã chuẩn bị câu trả lời khoa học nhất cho Hội đồng: Tại sao phải tốn thêm Rule và Anomaly khi ML thuần đã đạt 97.37%? Thưa Thầy Cô, 0.2% trên một file CSV không nói lên tất cả! Giá trị của Hybrid nằm ở tính chất Phòng thủ chiều sâu (Defense-in-depth): Khi hacker dùng kỹ thuật né tránh làm loãng vector ML, Rule Engine với bộ chuẩn hóa sẽ bắt gọn; khi hacker dùng mã khai thác Zero-Day chưa có nhãn, Isolation Forest sẽ hú còi báo động; và khi ML container bị sập, hệ thống vẫn duy trì cổng WAF ở Degraded Safe Mode mà không làm gián đoạn dịch vụ."*

#### SLIDE 12: THỰC NGHIỆM 2 — HIỆU NĂNG THỜI GIAN THỰC & ĐỘ BỀN BỈ HỆ THỐNG
- **Nội dung hiển thị:**
  - Đáp ứng chuẩn SLA công nghiệp: P50 = 1.2 ms, P95 = 1.9 ms (vượt xa yêu cầu < 10 ms).
  - Tải chịu đựng: Đạt thông lượng 850+ req/s trên phần cứng chuẩn lab.
  - Kiểm định tự động: 112/112 Unit Tests Gateway Pass 100%, 0 lỗi Ruff Linting, CI/CD GitHub Actions tự động.
- **Lời thoại thuyết minh (Minh):**
  > *"Bên cạnh độ chính xác, hệ thống còn được kiểm định khắt khe về độ trễ. Trong suốt quá trình vận hành, độ trễ phân vị P95 chỉ ở mức 1.9ms, hoàn toàn thỏa mãn các tiêu chuẩn khắt khe nhất của Reverse Proxy doanh nghiệp. Bộ mã nguồn được khóa chất lượng tự động qua CI/CD Pipeline với 112 bài kiểm thử tự động vượt qua 100%."*

#### SLIDE 13: KỊCH BẢN DIỄN TẬP THỰC CHIẾN 10 PHÚT TRƯỚC HỘI ĐỒNG
- **Nội dung hiển thị:**
  - 4 Phân cảnh đối đầu trực tiếp giữa 2 máy:
    - *Phân cảnh 1:* Lưu lượng người dùng hợp lệ (100% HTTP 200, Threat Score = 0).
    - *Phân cảnh 2:* Chế độ Monitor-Only (Tấn công bị gắn cờ đỏ, chấm điểm rủi ro nhưng cho qua để ghi vết).
    - *Phân cảnh 3:* Chế độ Active-Blocking (Chặn đứng tức thì HTTP 403 Forbidden < 2ms).
    - *Phân cảnh 4:* Tấn công vét cạn & Rate Limiting (Kích hoạt phạt HTTP 429 kèm Exponential Backoff).
- **Lời thoại thuyết minh (Cả hai):**
  > *"Và ngay sau phần trình bày lý thuyết này, nhóm chúng em xin trân trọng kính mời Hội đồng cùng theo dõi phần Demo diễn tập thực chiến 10 phút. Chúng em sẽ trực tiếp điều khiển Máy 2 tấn công vào Máy 1 qua 4 phân cảnh kinh điển: từ lưu lượng hợp lệ, giám sát thụ động, kích hoạt chặn chủ động 403, cho đến cơ chế khóa dải IP khi bị tấn công vét cạn."*

#### SLIDE 14: KẾT LUẬN & HƯỚNG PHÁT TRIỂN TƯƠNG LAI (ROADMAP C2–C4)
- **Nội dung hiển thị:**
  - **Kết luận:** Hoàn thành xuất sắc toàn bộ mục tiêu đề tài, chứng minh tính khả thi của kiến trúc Hybrid WAF và Thao trường Đối kháng.
  - **4 Hướng mở rộng tương lai (C2–C4):**
    - *C2:* Mở rộng Test Coverage $\ge 80\%$ và áp dụng Chaos Engineering.
    - *C3:* Làm cứng ML (Dynamic Calibration cho Isolation Forest & Đặc trưng `_CMD_KEYWORDS_REGEX`).
    - *C4:* DevOps cấp doanh nghiệp (Non-root Multi-stage Containers & Secrets Manager).
    - *Nâng cao:* Tích hợp bộ lọc nhân Linux eBPF/XDP và bẫy ảo Honeytokens.
  - Lời cảm ơn Quý Thầy Cô và mở phần Q&A.
- **Lời thoại thuyết minh (Cả hai kết thúc):**
  > *"Kính thưa Hội đồng, đề tài của nhóm đã hoàn thành trọn vẹn và sẵn sàng mở rộng lên các hạ tầng eBPF và Kubernetes trong tương lai. Nhóm xin bày tỏ lòng biết ơn sâu sắc đến Thầy Cô trong Khoa Công nghệ Thông tin đã tận tình hướng dẫn và chỉ bảo. Nhóm em xin chân thành cảm ơn và rất mong nhận được những câu hỏi phản biện, đóng góp quý báu từ Hội đồng!"*
