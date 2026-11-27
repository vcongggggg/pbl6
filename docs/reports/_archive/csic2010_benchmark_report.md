# Báo Cáo Đánh Giá Khả Năng Tổng Quát Hóa Liên Tập Dữ Liệu (Task 5.4 - CSIC 2010 Benchmark)

**Chuẩn mực khoa học:** NIST SP 800-115, ISO/IEC 27004:2016, Liu et al. (IEEE ICDM 2008), Torrano-Gimenez et al. (Wiley SCN 2015)
**Tập dữ liệu kiểm định chéo:** CSIC 2010 HTTP Dataset (Viện Nghiên cứu CSIC, Tây Ban Nha)
**Quy mô mẫu kiểm định:** 3000 requests (1.500 Benign và 1.500 Attacks)
**Mô hình được đánh giá:** Champion Cost-Sensitive XGBoost v2 (Zero-Pickle UBJSON, 26 chiều) + Calibrated Isolation Forest v2 (.npz) + Rule Engine
**Thời gian thực thi:** 2.87 giây | **Tốc độ suy luận:** 1047.0 requests/giây

---

## 1. Bảng Đối Sánh Khoa Học: Tập Nội Bộ (In-Domain) vs Chuẩn Quốc Tế CSIC 2010 (Zero-Shot)

| Chỉ Số Đánh Giá (Metric) | Tập Nội Bộ (In-Domain Test) | CSIC 2010 (XGBoost v2 Đơn Lẻ) | CSIC 2010 (Hybrid Loose) | CSIC 2010 (Hybrid Operational T=80) | Nhận Xét Khoa Học |
|:---|:---:|:---:|:---:|:---:|:---|
| **Độ chính xác (Accuracy)** | **99.16%** | **57.90%** | **58.60%** | **58.20%** | Phản ánh tỷ lệ nhận diện tổng quát (1.500 attacks gồm cả Group B) |
| **Precision (Độ tin cậy cảnh báo)** | **98.60%** | **99.58%** | **99.62%** | **100.00%** | Độ tin cậy cảnh báo thực tế |
| **Recall Overall (1.500 attacks)** | **98.95%** | **15.87%** | **17.27%** | **16.40%** | Bắt 246/1.500 (Op T=80) / 259/1.500 (Loose) |
| **Recall Nhóm A True Payload (221 mẫu)** | — | **93.21%** | **100.00%** | **100.00%** | Bắt 221/221 True Payloads (Op T=80) / 221/221 (Loose) |
| **F1-Score (Trung bình điều hòa)** | **98.77%** | **27.37%** | **29.43%** | **28.18%** | Điểm cân bằng trên 3.000 mẫu |
| **Tỷ lệ dương tính giả (FPR)** | **0.05%** | **0.07%** | **0.07%** | **0.00%** | Độ sạch luồng lành tính (1.500 Benign) |
| **Độ trễ suy luận trung bình** | **0.439 ms** | **0.841 ms** | **0.841 ms** | **0.841 ms** | Đạt chuẩn inline SLA (&lt; 1.5ms/request) |

---

## 2. Phân Tích Chi Tiết Theo Phân Loại Hai Tầng Đã Kiểm Toán (Two-Tier CSIC Taxonomy)

> **Lưu ý kiểm toán phân loại (D2 -> E3):** Bộ CSIC gốc gán nhầm `modo=insertar` tiếng Tây Ban Nha vào `SQLI` (133/254 ca không chứa cú pháp SQL). Bảng 2 sử dụng chuẩn Two-Tier đã kiểm toán từ `audit_csic2010_taxonomy.py` (tách **Group A True Payload** gồm 221 mẫu và **Group B Parameter Tampering** gồm 1279 mẫu). Số lượng mẫu Group A tăng từ **196 (D2) lên 221 (E3)** (+25 mẫu SQLi) do `audit_csic2010_taxonomy.py` đã chuyển sang giải mã `urllib.parse.unquote_plus` cho dấu `+` thành khoảng trắng trước khi nhận diện từ khóa SQL.

| Phân Nhóm CSIC 2010 (Two-Tier) | Tổng Mẫu | XGBoost v2 Đơn Lẻ | Hybrid Loose | Hybrid Operational T=80 |
|:---|:---:|:---:|:---:|:---:|
| **Group A — `SQLI_CLASSIC_UNION`** | 7 | 7 (100.0%) | 7 (100.0%) | 7 (100.0%) |
| **Group A — `SQLI_BLIND_BOOLEAN` (+ legacy `--` SSI)** | 75 | 60 (80.0%) | 75 (100.0%) | 75 (100.0%) |
| **Group A — `SQLI_TSQL_TIME_DELAY`** | 61 | 61 (100.0%) | 61 (100.0%) | 61 (100.0%) |
| **Group A — `XSS`** | 78 | 78 (100.0%) | 78 (100.0%) | 78 (100.0%) |
| **Group A — Tổng True Payload Attacks** | **221** | **206 (93.21%)** | **221 (100.00%)** | **221 (100.00%)** |
| **Group B — `PARAMETER_TAMPERING` (App Logic)** | 1279 | 32 (2.50%) | 38 (2.97%) | 25 (1.95%) |
| **Lưu lượng hợp lệ (`BENIGN` Allow Rate)** | 1500 | 1499 (99.93%) | 1499 (99.93%) | 1500 (100.00%) |

---

## 3. Kết Luận Học Thuật & Luận Điểm Kiến Trúc Defense-in-Depth

1. **Khách quan khoa học:** Khi đối đầu với dữ liệu ngoại miền CSIC 2010 (hoàn toàn zero-shot, không có trong tập huấn luyện), kiến trúc WAF Hybrid chặn chính xác **Group A (True Payload)** ở mức **100.00%** (`DecisionEngine T=80`, FPR **`0.00%`**) và **100.00%** (`Loose Monitoring`, FPR **`0.07%`**). Nhóm **Group B (`PARAMETER_TAMPERING`, 1279 mẫu)** mang sai lệch nghiệp vụ riêng của ứng dụng `/tienda1`, đòi hỏi lớp Positive Security OpenAPI Schema (`csic2010_tienda1_schema_proof.json`).
2. **Sức mạnh của kiến trúc đa tầng (Defense-in-Depth):** Kết hợp Supervised XGBoost v2 (với URL-normalized per-parameter max-pooling), Unsupervised Calibrated Isolation Forest v2, và 28 Hardened Signatures duy trì FPR vận hành **`0.00%`** trong **0.841 ms/request**.
