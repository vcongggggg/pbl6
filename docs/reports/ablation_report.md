# BÁO CÁO THỰC NGHIỆM ĐO LƯỜNG ĐÓNG GÓP TỪNG THÀNH PHẦN (ABLATION STUDY)
> **Mã công việc:** Task B3 (Issue #126 — Master Plan P1: Vũ khí tủ)
> **Người thực hiện:** Thành viên A (`vcongggggg` — Tech Lead / Blue Team)
> **Thời gian đo kiểm:** 2026-10-07 00:17:10
> **Tập dữ liệu:** `benchmark_1000_diverse.csv` (1000 mẫu: 200 Benign, 800 Attacks)

---

### 1. BẢNG ĐỐI SÁNH THỰC NGHIỆM 4 CẤU HÌNH PHÒNG THỦ (ABLATION MATRIX)

| Chế Độ Cấu Hình Phòng Thủ | Accuracy (%) | Precision (%) | Recall / DR (%) | F1-Score (%) | FPR (%) | Độ Trễ (ms/req) | Đánh Giá Vai Trò Học Thuật |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **1. Rules Only (Tất định)** | 54.80% | **100.00%** | 43.50% | 60.63% | **0.00%** | 26.16 ms | Độ chính xác tuyệt đối trên chữ ký đã biết; bỏ lọt các biến thể né tránh (Recall thấp). |
| **2. ML Only (Random Forest)** | 95.90% | 100.00% | 94.88% | 97.37% | 0.00% | 21.85 ms | Tổng quát hóa cao trên 17 đặc trưng, bắt được đa số tấn công obfuscated. |
| **3. Anomaly Only (Isolation Forest)** | 24.70% | 100.00% | 5.88% | 11.10% | 0.00% | 21.55 ms | Đóng vai trò phanh an toàn nhạy bén, cảnh báo các payload dị biệt bất thường. |
| **4. Hybrid Defense (Toàn diện)** | **96.20%** | **100.00%** | **95.25%** | **97.57%** | **0.00%** | 17.76 ms | **TỐI ƯU TOÀN DIỆN**: F1-Score và Recall cao nhất, triệt tiêu False Negative của Rule Engine. |

---

### 2. KẾT LUẬN VÀ LUẬN ĐIỂM BẢO VỆ (DEFENSE HIGHLIGHTS)
1. **Minh chứng khoa học cho kiến trúc Hybrid:**
   - Khi tách riêng, **Rule Engine chỉ đạt Recall 43.50%** do không thể bao phủ các kỹ thuật né tránh động.
   - Khi kết hợp thành **Hybrid Defense (Rule 40% + ML 35% + Anomaly 25%)**, Recall tăng vọt lên **95.25%**, F1-Score đạt đỉnh **97.57%** trong khi vẫn duy trì **FPR ở mức tuyệt đối 0.00%**.
2. **Chi phí độ trễ suy luận (Inference Overhead):**
   - Độ trễ trung bình của hệ thống Hybrid duy trì ở mức **17.76 ms**, hoàn toàn đáp ứng chuẩn SLA thời gian thực của các hệ thống Reverse Proxy công nghiệp.
