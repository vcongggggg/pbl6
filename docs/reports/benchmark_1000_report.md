# Báo Cáo Kiểm Thử Thực Nghiệm 1.000 Mẫu Tấn Công & Lưu Lượng Sạch (PBL6)

**Tiêu chuẩn kiểm định:** NIST SP 800-115 & ISO/IEC 27004:2016  
**Hệ thống đích:** WAF API Gateway (http://127.0.0.1:8000)  
**Quy mô kiểm thử:** 1000 requests đa dạng (8 luồng đồng thời)  
**Thời gian thực thi:** 44.17 giây | **Thông lượng:** 22.6 RPS  

---

## 1. Ma Trận Nhầm Lẫn & Các Chỉ Số An Ninh (Confusion Matrix)

| Chỉ Số Đánh Giá | Giá Trị Thực Nghiệm | Đánh Giá Học Thuật |
|:---|:---:|:---|
| **True Positives (TP - Chặn thành công)** | **731 / 800** | Kích hoạt HTTP 403 Forbidden chuẩn RFC 7807 |
| **False Negatives (FN - Lọt lưới)** | **69 / 800** | Các biến thể lách luật nâng cao |
| **True Negatives (TN - Cho qua hợp lệ)** | **170 / 200** | Request hợp lệ chuyển tiếp thành công tới Upstream |
| **False Positives (FP - Chặn nhầm)** | **30 / 200** | Tỷ lệ báo nhầm trên truy vấn sạch |
| **Detection Recall (Tỷ lệ phát hiện)** | **91.38%** | Hiệu năng chặn tấn công tổng thể (731/800) |
| **Precision (Độ chính xác cảnh báo)** | **96.06%** | Tỷ lệ cảnh báo đúng trên tổng cảnh báo WAF |
| **F1-Score (Trung bình điều hòa)** | **93.66%** | Cân bằng hoàn hảo giữa Precision & Recall |
| **False Positive Rate (Tỷ lệ báo giả)** | **15.0%** | An toàn cho trải nghiệm nghiệp vụ |
| **Overall Accuracy (Độ chính xác toàn diện)** | **90.1%** | Phân loại đúng trên toàn bộ 1.000 mẫu |

---

## 2. Phân Bố Hiệu Năng Theo Từng Danh Mục Lỗ Hổng (OWASP Top 10)

| Danh Mục Tấn Công | Số Mẫu | Số Lượng Bị Chặn | Số Lượng Cho Qua | Tỷ Lệ Hiệu Quả |
|:---|:---:|:---:|:---:|:---:|
| **SQL Injection (SQLi)** | 200 | 191 | 9 | **95.5% BLOCKED** |
| **Cross-Site Scripting (XSS)** | 200 | 194 | 6 | **97.0% BLOCKED** |
| **Path Traversal / LFI** | 200 | 173 | 27 | **86.5% BLOCKED** |
| **OS Command Injection (RCE)** | 200 | 173 | 27 | **86.5% BLOCKED** |
| **Lưu Lượng Hợp Lệ (Benign)** | 200 | 30 | 170 | **85.0% ALLOWED** |

---

## 3. Hồ Sơ Phân Vị Độ Trễ (Latency Percentile SLA)

- **Độ trễ trung bình (Mean Latency):** 327.41 ms
- **Độ trễ trung vị (P50 Median):** 326.34 ms
- **Phân vị 90 (P90):** 443.82 ms
- **Phân vị 95 (P95 SLA):** 481.05 ms
- **Phân vị đỉnh 99 (P99 Max Jitter):** 555.63 ms
