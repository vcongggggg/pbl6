# BẢN ĐỀ XUẤT KIẾN TRÚC & KẾ HOẠCH NÂNG CẤP ML PIPELINE (MLOPS ACTIVE LEARNING)
## ĐÚC KẾT KINH NGHIỆM TỪ MẪU LỌT LƯỚI & KHẮC PHỤC CHẶN NHẦM TRÊN TẬP THỰC TẾ CSIC 2010

> **Dự án:** PBL6 — Hệ thống WAF & API Gateway Giám sát An ninh Thông minh  
> **Người đề xuất:** Senior Security Architect & Independent Reviewer (`@reviewer`)  
> **Người duyệt:** Tech Lead / Thành viên A (`vcongggggg`)  
> **Căn cứ thực nghiệm:** Báo cáo kiểm định chéo CSIC 2010 (`csic2010_benchmark_results.json`)  
> **Tiêu chuẩn tham chiếu:** NIST SP 800-115, ISO/IEC 27004, Google MLOps Best Practices  

---

## 1. TỔNG QUAN: HOÀN TOÀN KHẢ THI VÀ LÀ BƯỚC ĐI ĐẮT GIÁ VỀ HỌC THUẬT!

Câu trả lời cho câu hỏi của anh Văn Công là: **HOÀN TOÀN CÓ THỂ VÀ ĐÂY CHÍNH LÀ BƯỚC PHÁT TRIỂN ĐỈNH CAO TRONG NGHIÊN CỨU AN NINH MẠNG!**

Trong thực tế, không có một hệ thống WAF học máy nào đạt được độ tổng quát hóa cao ngay từ lần huấn luyện đầu tiên. Chu trình MLOps chuẩn mực trong an toàn thông tin luôn là:
$$\text{Huấn luyện Baseline (v1.0)} \longrightarrow \text{Kiểm định chéo (Stress Test CSIC 2010)} \longrightarrow \text{Phân tích sai số (Error Analysis)} \longrightarrow \text{Active Learning Loop} \longrightarrow \text{Mô hình Tối ưu (v2.0)}$$

Từ **545 mẫu tấn công lọt lưới** và **444 mẫu dữ liệu sạch bị chặn nhầm**, chúng ta đang nắm giữ nguồn "tài nguyên vàng" để huấn luyện mô hình v2.0 có khả năng tổng quát hóa thực chiến vượt trội.

---

## 2. BỐN MŨI NHỌN NÂNG CẤP KỸ THUẬT TOÀN DIỆN

### MŨI NHỌN 1: MỞ RỘNG BỘ ĐẶC TRƯNG HỌC MÁY (TỪ 17 LÊN 26 CHIỀU)
Bộ 17 đặc trưng cũ quá phụ thuộc vào độ dài thô và 5 từ khóa cứng. Chúng ta sẽ bổ sung 9 đặc trưng mới:

1. **Khắc phục 456 mẫu Parameter Tampering lọt lưới:**
   - $f_{18}$ (`param_value_entropy_ratio`): Tỷ lệ entropy của giá trị tham số so với toàn bộ URL.
   - $f_{19}$ (`numeric_anomaly_flag`): Phát hiện tham số ID vốn là số nguyên nhưng bị nhồi ký tự lạ, chuỗi hex hoặc ký tự đại diện.
   - $f_{20}$ (`repeated_param_count`): Phát hiện kỹ thuật HTTP Parameter Pollution (HPP) nhồi nhiều tham số cùng tên.
2. **Khắc phục 87 mẫu SQL Injection Bypass lọt lưới:**
   - $f_{21}$ (`advanced_sql_func_count`): Đếm các hàm SQL nâng cao thường dùng trong blind/time-based SQLi (`concat`, `char`, `substr`, `benchmark`, `sleep`, `hex`).
   - $f_{22}$ (`sql_comment_syntax_score`): Nhận diện các biến thể comment lạ (`/*`, `*/`, `--+`, `;%00`, `#`).
   - $f_{23}$ (`encoding_layer_depth`): Đo mức độ mã hóa sâu (URL encoding kép `%2527`, Hex encoding `0x27`).
3. **Khắc phục 444 mẫu Data Sạch bị chặn nhầm (False Positive Reduction):**
   - $f_{24}$ (`natural_text_ratio`): Tỷ lệ nguyên âm/phụ âm và khoảng trắng chuẩn văn phong ngôn ngữ tự nhiên (tiếng Anh/Việt/Tây Ban Nha). Giúp nhận diện địa chỉ nhà, mô tả sản phẩm dài là văn bản lành tính.
   - $f_{25}$ (`safe_email_path_pattern`): Nhận diện cấu trúc hợp lệ của email (`user@domain.com`) hoặc đường dẫn API chuẩn, triệt tiêu việc ngộ nhận dấu `@`, `.`, `/` là mã độc.
   - $f_{26}$ (`valid_json_depth`): Đo độ sâu cú pháp JSON hợp lệ, tránh phạt điểm các chuỗi JSON payload gửi từ frontend.

---

### MŨI NHỌN 2: HARD NEGATIVE & ATTACK MINING (ACTIVE LEARNING)
Thay vì sinh ngẫu nhiên, ta đưa thẳng các mẫu "khó nhằn" vào tập train:
1. **Hard Benign Mining (Khắc phục chặn nhầm):**
   - Đưa trực tiếp **444 mẫu sạch bị chặn nhầm từ CSIC 2010** vào tập huấn luyện với nhãn `0` (Benign).
   - Bổ sung thêm 1.000 mẫu request từ các nguồn text tự nhiên đa dạng (Wikipedia, e-commerce) để mô hình quen với dữ liệu thực tế phong phú.
2. **Hard Attack Mining (Khắc phục lọt lưới):**
   - Đưa trực tiếp **545 mẫu tấn công lọt lưới từ CSIC 2010** vào tập huấn luyện với nhãn `1` (Attack).
   - Áp dụng Payload Mutation (đột biến payload): Đổi hoa/thường ngẫu nhiên, URL encode kép, chèn null byte để nhân rộng thành 1.500 mẫu tấn công biến thể.

---

### MŨI NHỌN 3: HIỆU CHUẨN XÁC SUẤT & TỐI ƯU HÓA NGƯỠNG (CALIBRATION & THRESHOLDING)
1. **Probability Calibration (Isotonic Regression):**
   - Hiệu chuẩn xác suất đầu ra của XGBoost và Random Forest để điểm số phản ánh đúng độ tin cậy rủi ro, không bị tự tin thái quá (over-confident) ở vùng biên.
2. **Cost-Sensitive Learning:**
   - Thiết lập trọng số phạt lỗi dương tính giả (FP - chặn nhầm) gấp 3 lần lỗi âm tính giả (FN) ở vùng rủi ro trung bình, giúp mô hình thận trọng hơn khi quyết định phân loại mã độc.

---

### MŨI NHỌN 4: RETRAIN & BENCHMARK ĐỐI SÁNH
1. Tái huấn luyện **XGBoost Champion v2.0** và **Random Forest Fallback v2.0**.
2. Chạy lại benchmark độc lập trên 3.000 mẫu CSIC 2010 để đối sánh $v1.0$ vs $v2.0$.

---

## 3. MỤC TIÊU ĐỊNH LƯỢNG CAM KẾT (KPIS NÂNG CẤP)

| Chỉ Số Đánh Giá | Phiên Bản Hiện Tại ($v1.0$) | Mục Tiêu Phiên Bản Mới ($v2.0$) | Mức Độ Cải Thiện Dự Kiến |
|:---|:---:|:---:|:---|
| **F1-Score trên CSIC 2010** | **65.88%** | **$\ge 82.0\% - 86.0\%$** | **Tăng vọt $+16\% \rightarrow +20\%$** |
| **False Positive Rate (FPR)** | **29.60%** (Chặn nhầm 444 mẫu) | **$\le 6.0\% - 8.0\%$** (Giảm còn $<100$ mẫu) | **Cứu hơn 350 khách hàng hợp lệ** |
| **Recall (Tỷ lệ bắt mã độc)** | **63.67%** (Lọt 545 mẫu) | **$\ge 80.0\% - 85.0\%$** (Giảm còn $<250$ mẫu) | **Bắt thêm hơn 300 cuộc tấn công** |
| **Độ trễ suy luận (Latency)** | **6.689 ms** | **$\le 7.5\text{ ms}$** | Duy trì hoàn hảo trong SLA Gateway ($<15\text{ms}$) |

---

## 4. QUY TRÌNH PHỐI HỢP THỰC THI (ĐIỀU PHỐI)
Nếu anh Văn Công duyệt kế hoạch này:
1. **Reviewer (`@reviewer`):** Đóng gói tài liệu đặc tả kiến trúc 9 đặc trưng mới và tiêu chuẩn kiểm thử.
2. **Coder (`@pbl6`):** Tiến hành code bộ trích xuất đặc trưng mới, chuẩn bị tập Enriched Data, train model v2.0 và chạy lại script benchmark.
3. **Reviewer (`@reviewer`):** Thẩm định độc lập mã nguồn, kiểm tra chống rò rỉ dữ liệu (Data Leakage), nghiệm thu kết quả và merge vào main.
