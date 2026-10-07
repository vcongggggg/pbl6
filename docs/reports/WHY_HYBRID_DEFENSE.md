# LUẬN CỨ HỌC THUẬT: TẠI SAO CẦN KIẾN TRÚC HYBRID DEFENSE?
## *Giải Trình Khoa Học Cho Câu Hỏi Phản Biện Của Hội Đồng Đồ Án PBL6*

> **Tác giả:** Nhóm Đề tài PBL6 — Hệ thống Giám sát & Phòng thủ API Gateway  
> **Tài liệu tham chiếu:** [Báo Cáo Ablation Study](file:///C:/Study/HocKy6/PBL6/docs/reports/ablation_report.md) & [Master Plan P1 B3](file:///C:/Study/HocKy6/PBL6/gateway/app/security/risk_engine.py)  
> **Câu hỏi trọng tâm:**  
> *"Kết quả thực nghiệm trên tập benchmark 1,000 mẫu cho thấy mô hình ML-Only đạt F1-Score 97.37%, trong khi Hybrid Defense đạt 97.57% (chỉ chênh lệch 0.20%). Vậy tại sao hệ thống phải duy trì kiến trúc Hybrid phức tạp gồm 3 tầng (Rule Engine + Random Forest + Isolation Forest) thay vì chỉ sử dụng một mình Machine Learning?"*

---

### 1. NGHỊCH LÝ CỦA SỐ LIỆU TỔNG HỢP (AGGREGATE METRIC ILLUSION)

Trong nghiên cứu khoa học máy tính và an toàn thông tin, việc chỉ nhìn vào một chỉ số F1-Score tổng thể trên một tập dữ liệu benchmark đóng (Closed-World Benchmark) thường dẫn đến **ngộ nhận đơn giản hóa (Oversimplification Fallacy)**.

Chênh lệch 0.20% F1-Score trên tập test chuẩn phản ánh rằng trên **các mẫu tấn công thông thường, phân phối đều**, mô hình Random Forest đã được huấn luyện rất tốt. Tuy nhiên, an toàn thông tin không phải là bài toán phân loại ảnh hay dịch ngôn ngữ; đây là **cuộc chiến bất đối xứng (Asymmetric Adversarial Game)** giữa Kẻ tấn công (Red Team) và Hệ thống phòng thủ (Blue Team).

Hội đồng phản biện cần một hệ thống có khả năng sống sót trong môi trường thực tế — nơi kẻ tấn công không gửi những payload mẫu mực trong sách giáo khoa, mà chủ động tìm kiếm các điểm mù chết người của từng giải pháp đơn lẻ.

---

### 2. BỐN TRỤ CỘT BẢO VỆ CHO KIẾN TRÚC HYBRID (CORE ARGUMENTS)

```
                            [ INCOMING HTTP REQUEST ]
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        ▼                                                             ▼
┌──────────────────┐                                          ┌───────────────┐
│ 1. RULE ENGINE   │ <─── Sub-millisecond (0.14 ms)           │ FAST REJECTION│
│ (Aho-Corasick /  │      Bắt trọn Known CVEs 100% Precision  │ CỦA CÁC ĐÒN   │
│  Regex AST)      │      Không thể bị đánh lừa bởi Loãng TF  │ MASS-SCANNING │
└────────┬─────────┘                                          └───────────────┘
         │
         ▼
┌──────────────────┐
│ 2. SUPERVISED ML │ <─── Tổng quát hóa trên 17 Features
│ (Random Forest)  │      Bắt các biến thể Obfuscated / Evasion
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 3. ANOMALY (IF)  │ <─── Unsupervised Outlier Detector
│ (Isolation Forest│      Tấm lưới an toàn cuối cùng bắt Zero-Day / OOD
└────────┬─────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. RISK ARBITRATION ENGINE: Tổng hợp trọng số & Fail-Safe Tolerance │
└─────────────────────────────────────────────────────────────────────┘
```

---

#### 🏛️ Luận Điểm 1: Khắc Phục Điểm Mù "Adversarial Evasion" (Tấn Công Đối Kháng) Của ML
- **Điểm yếu của ML thuần:** Các mô hình học máy phân loại văn bản (kể cả Random Forest, SVM hay Deep Learning dựa trên n-gram và TF-IDF) đều dựa vào thống kê tần suất từ khóa và độ hỗn loạn (entropy). Kẻ tấn công sử dụng các công cụ như SQLMap Tamper Scripts hoặc Evasion Engine (Task B2) để thực hiện:
  - Chèn comment rác xen kẽ: `UN/**/ION/**/SE/**/LECT`
  - URL double-encoding: `%2527%2520OR%2520%25271`
  - Chèn tham số vô hại khổng lồ (Payload Dilution) nhằm kéo tỷ lệ ký tự nguy hiểm xuống cực thấp.
- **Vai trò của Rule Engine:** Trước khi kiểm tra signature, Rule Engine bắt buộc phải chạy qua tầng tiền xử lý chuẩn hóa (Canonicalization & URL/Hex decoding). Signature Engine nhận diện chính xác token SQL hoặc pattern Directory Traversal bất chấp các thủ thuật làm loãng vector của ML.
- **Ý nghĩa:** Khi ML bị đánh lừa đưa ra điểm số nguy cơ thấp (< 0.30), Rule Engine phát hiện signature sẽ kéo điểm rủi ro lên thông qua công thức trọng số kết hợp, ngăn chặn cuộc tấn công thành công.

---

#### 🏛️ Luận Điểm 2: Năng Lực Ứng Phó Tấn Công Mới Chưa Từng Thấy (Zero-Day & OOD)
- **Hạn chế của Supervised ML:** Học có giám sát hoạt động dưới giả định thế giới đóng (Closed-World Assumption). Mô hình chỉ có thể phân loại chính xác các lớp nó đã được huấn luyện (`SQLI`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`). Khi một lỗ hổng Zero-Day bùng phát (ví dụ: Log4Shell `${jndi:ldap:...}`, Spring4Shell, hay SSRF vào metadata cloud `http://169.254.169.254`), vector đặc trưng của payload không khớp với bất kỳ lớp tấn công nào trong 4 lớp trên, khiến Supervised ML phân loại nhầm thành `BENIGN`.
- **Vai trò của Anomaly Detector (Isolation Forest):** Isolation Forest là mô hình học không giám sát (Unsupervised). Nó không quan tâm payload thuộc loại tấn công nào; nó chỉ đo lường **mức độ dị biệt hình học của request so với phân phối dữ liệu chuẩn của lưu lượng sạch**.
- Một chuỗi JNDI lookup hoặc URI dị thường sẽ có độ sâu phân nhánh cây (tree depth path length) cực ngắn, ngay lập tức bị gán điểm bất thường cao (Anomaly Score > 0.70).
- **Ý nghĩa:** Trong kiến trúc Hybrid, dù cả Rule Engine (chưa kịp update CVE) và Supervised ML (chưa được train) đều bỏ lọt, thì Anomaly Detector vẫn phát tín hiệu báo động, chuyển request sang trạng thái `MONITOR` hoặc `BLOCK`.

---

#### 🏛️ Luận Điểm 3: Tối Ưu Độ Trễ Thực Tế Qua "Fast-Path Gatekeeper" (0.14 ms vs 8.4 ms)
Số liệu đo đạc thực tế trong Ablation Study:
- **Rule Engine:** **0.14 ms / request**
- **ML Detector:** **8.40 ms / request** (bao gồm Feature Engineering 17 chiều + Decision Tree evaluation)

Trên Internet thực tế, **hơn 80% lưu lượng tấn công là các đợt quét tự động hàng loạt (Mass Scanning / Script Kiddies)** dùng các payload signature chuẩn (`' OR '1'='1`, `../../../etc/passwd`, `<script>alert(1)</script>`).
- Nếu chỉ dùng ML: 100% request đều phải tốn ~8.4 ms để trích xuất đặc trưng và suy luận, tiêu tốn năng lực CPU và tạo thắt cổ chai nghẽn mạng (DDoS / Gateway bottleneck).
- Trong kiến trúc Hybrid: Rule Engine đóng vai trò "Fast-Path Filter". Đối với các tấn công thô sơ, hệ thống phát hiện ngay ở 0.14 ms và có thể đưa ra quyết định từ chối nhanh, giải phóng tài nguyên tính toán quý giá cho gateway.

---

#### 🏛️ Luận Điểm 4: Tính Sẵn Sàng Cao & Cơ Chế Suy Thoái An Toàn (Fail-Safe Resilience)
Trong môi trường sản xuất thực tế, mô hình ML là một thành phần có rủi ro vận hành cao:
- File artifacts model `.joblib` có thể bị lỗi tải, hash mismatch, hoặc tiến trình Python ML-Engine bị tràn bộ nhớ (OOM).
- Nếu hệ thống chỉ phụ thuộc vào ML (Single Point of Failure): Khi ML Engine sập, hệ thống buộc phải chọn 1 trong 2 tình huống thảm họa:
  1. *Fail-Open:* Thả nổi toàn bộ lưu lượng → Kẻ tấn công thoải mái xâm nhập backend.
  2. *Fail-Closed:* Chặn toàn bộ lưu lượng → Dịch vụ ngừng hoạt động (Outage hoàn toàn).
- Với kiến trúc Hybrid: Nếu ML Engine gặp sự cố, Gateway tự động chuyển sang chế độ **Degraded Safe Mode** (đã được kiểm chứng thực tế tại Task A3):
  Rule Engine và Anomaly cục bộ tiếp tục hoạt động độc lập, đảm bảo hệ thống duy trì khả năng chặn đứng 100% các cuộc tấn công đã biết mà dịch vụ của người dùng vẫn hoạt động liên tục (High Availability).

---

### 3. BẢNG SO SÁNH ĐA CHIỀU CÁC PHƯƠNG PHÁP PHÒNG THỦ

| Tiêu Chí So Sánh | 1. Rules Only (Snort/ModSec) | 2. ML Only (Random Forest) | 3. Anomaly Only (IForest) | 4. HYBRID DEFENSE (Đề Tài PBL6) |
| :--- | :---: | :---: | :---: | :---: |
| **Độ trễ suy luận (ms)** | **0.14 ms (Siêu tốc)** | 8.40 ms | 9.49 ms | 16.10 ms (Chấp nhận được theo SLA) |
| **Độ chính xác trên CVE đã biết** | **100% (Tuyệt đối)** | 95.9% | 24.7% | **100% (Tối ưu)** |
| **Khả năng bắt Evasion / Obfuscation** | Kém (43.5% Recall) | Tốt (94.9% Recall) | Trung bình | **Đỉnh cao (95.3% Recall, F1 97.57%)** |
| **Phản ứng trước Zero-Day / OOD** | Hoàn toàn mù | Mù (phụ thuộc nhãn cũ) | **Rất nhạy bén** | **Phát hiện sớm qua tầng Anomaly** |
| **Khả năng giải thích (Explainability)** | Rõ ràng (Rule ID, CVE) | Hộp đen / Khó hiểu | Khó giải thích | **Đa tầng (Cung cấp cả Rule + Feature SHAP)** |
| **Tính sẵn sàng khi sập module** | Rất cao | Thấp (Điểm chết duy nhất) | Trung bình | **Tối đa (Có Fail-Safe Degraded Mode)** |

---

### 4. KẾT LUẬN & THÔNG ĐIỆP BẢO VỆ TRƯỚC HỘI ĐỒNG

> **"0.20% F1-Score trên tập dữ liệu tĩnh không đo lường được giá trị của kiến trúc bảo mật. Giá trị của kiến trúc Hybrid nằm ở tính chất Phòng thủ Chiều sâu (Defense-in-Depth):**
> 
> **Chúng tôi không xây dựng một hệ thống chỉ để đạt điểm số cao trên một file CSV; chúng tôi xây dựng một pháo đài đa tầng. Rule Engine mang lại tốc độ và tính tất định; Supervised ML mang lại sự linh hoạt trước biến dị; và Anomaly Detection đóng vai trò chiếc còi báo động trước những hiểm họa chưa biết. Sự kết hợp này triệt tiêu điểm yếu cốt tử của từng phương pháp đơn lẻ, mang lại sự an toàn và bền vững thực thụ cho hệ thống."**
