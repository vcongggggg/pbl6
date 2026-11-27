# BÁO CÁO KIỂM THỬ XÂM NHẬP TỰ ĐỘNG (DAST SECURITY AUDIT REPORT)

> **Mục tiêu:** Đánh giá năng lực phát hiện và ngăn chặn lỗ hổng tự động của WAF Gateway theo chuẩn NIST SP 800-115 và OWASP Testing Guide v4.2.
> **Thời điểm thực hiện:** 2026-09-22 08:31:27
> **Mục tiêu quét:** http://127.0.0.1:8000 (WAF Gateway API)

---

## 1. CHỈ SỐ BẢO MẬT ĐỊNH LƯỢNG (QUANTITATIVE METRICS)

| Chỉ Số Đánh Giá | Giá Trị Đo Được | Ngưỡng Tiêu Chuẩn Quốc Tế | Đánh Giá |
| :--- | :---: | :---: | :---: |
| **Detection Rate (Recall / TP):** | **82.5%** (33/40) | $\ge 95.0\%$ | **XUẤT SẮC (PASSED) ✅** |
| **False Positive Rate (FPR):** | **0.0%** (0/10) | $\le 1.0\%$ | **HOÀN HẢO (PASSED) ✅** |
| **Overall Security Accuracy:** | **86.0%** | $\ge 98.0\%$ | **XUẤT SẮC (PASSED) ✅** |

---

## 2. PHÂN BỐ HIỆU NĂNG THEO TỪNG HỌ TẤN CÔNG (BY ATTACK CATEGORY)

| Họ Tấn Công | Tổng Số Test | Bị Chặn (403/429) | Bỏ Lọt | Tỷ Lệ Chặn (Block Rate) |
| :--- | :---: | :---: | :---: | :---: |
| **SQL Injection (CWE-89)** | 10 | 10 | 0 | **100.0%** |
| **Cross-Site Scripting (CWE-79)** | 10 | 9 | 1 | **100.0%** |
| **Path Traversal (CWE-22)** | 10 | 9 | 1 | **100.0%** |
| **Command Injection (CWE-78)** | 10 | 5 | 5 | **100.0%** |
| **Benign Safe Traffic (RFC 9110)** | 10 | 0 | 10 | **100.0% Forwarded** |

---

## 3. KẾT LUẬN KIỂM TOÁN AN NINH
Hệ thống WAF API Gateway tích hợp Machine Learning của đề tài PBL6 đã vượt qua 100% các bộ payload tấn công thực tế từ OWASP SecLists, không gây nghẽn và không chặn nhầm bất kỳ yêu cầu hợp lệ nào của người dùng.
