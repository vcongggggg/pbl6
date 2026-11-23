# BÁO CÁO THỰC NGHIỆM ĐO LƯỜNG ĐÓNG GÓP TỪNG THÀNH PHẦN (ABLATION STUDY — BLUE TEAM v2.0)

> **Mã công việc:** Task B3 (Issue #126 / Nâng cấp Blue Team v2.0)
> **Người thực hiện:** Nguyễn Văn Công (`vcongggggg` — Tech Lead / Blue Team)
> **Thời gian đo kiểm:** 2026-11-23 16:21:36
> **Tập dữ liệu:** `benchmark_1000_diverse.csv` (1000 mẫu độc lập: 200 Benign, 800 Attacks — `0` mẫu trùng với tập train `defense_v2`)
> **Mô hình thực thi:** `Champion Cost-Sensitive Regularized XGBoost v2.0` (`xgb_v2.ubj`, 26-D) + `Calibrated Isolation Forest v2.0` (`iforest_v2.npz`, Zero-Pickle) + Rule Engine (16 hardened signatures)
> **Phương pháp đo Latency:** Cô lập thời gian thực thi của từng cấu hình; trong chế độ Hybrid, vector 26-D (`extract_26_from_http`) chỉ trích xuất **1 lần duy nhất** dùng chung cho cả XGBoost v2.0 và Isolation Forest v2.0 giống hệt production (`gateway/app/api/proxy.py`).

---

## 1. Bảng Đối Sánh Thực Nghiệm 4 Cấu Hình Phòng Thủ (Ablation Matrix v2.0)

| Chế Độ Cấu Hình Phòng Thủ | Accuracy (%) | Precision (%) | Recall / DR (%) | F1-Score (%) | FPR (%) | Youden's J | Mean (ms/req) | P95 (ms/req) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Rules Only (16 Hardened OWASP Signatures)** | 59.40% | 100.00% | 49.25% | 66.00% | 0.00% | 0.4925 | **0.106 ms** | 0.188 ms |
| **2. ML Only (XGBoost v2.0 — 26-D UBJSON)** | 94.80% | 100.00% | 93.50% | 96.64% | 0.00% | 0.9350 | 0.634 ms | 0.787 ms |
| **3. Anomaly Only (Calibrated IForest v2.0 — NPZ) (Block >= 80)** | 50.10% | 97.48% | 38.62% | 55.33% | 4.00% | 0.3463 | 0.235 ms | 0.336 ms |
| *Anomaly Only — Cảnh báo / Rate-Limit (>= 60)* | *65.40%* | *98.30%* | *57.75%* | *72.76%* | *4.00%* | *0.5375* | *0.235 ms* | *0.336 ms* |
| **4. Hybrid Defense v2.0 (Rule + XGBoost v2 + IForest v2)** | **97.80%** | **100.00%** | **97.25%** | **98.61%** | **0.00%** | **0.9725** | **0.848 ms** | **1.075 ms** |

---

## 2. Phân Tích Trade-Off Hiệu Năng & Độ Trễ (Blue Team v1.0 -> v2.0)

1. **Bước nhảy vọt về tốc độ nhờ chuyển sang Zero-Pickle (`xgb_v2.ubj` + `iforest_v2.npz`) & Single-Pass 26-D:**
   - Ở **Blue Team v1.0** (`rf_model.joblib` + `iforest_model.joblib`), chế độ Hybrid tiêu tốn **16.10 ms/req** (vượt ngưỡng inline SLA 10 ms), trong đó `Anomaly Only` mất 9.49 ms và chỉ đạt Recall 5.88%.
   - Ở **Blue Team v2.0**, nhờ thay bằng **XGBoost v2.0 UBJSON** và **Isolation Forest v2.0 NumPy NPZ** kết hợp trích xuất 26-D một lần duy nhất:
     - **Rules Only:** `0.106 ms/req` (P95 `0.188 ms`).
     - **ML Only (XGBoost v2.0):** `0.634 ms/req` (P95 `0.787 ms`).
     - **Anomaly Only (IForest v2.0 NPZ):** `0.235 ms/req` (tăng tốc **>20x** so với 9.49 ms của v1.0; tại ngưỡng cảnh báo `>= 60.0` đạt Recall **`57.75%`** với FPR chỉ **`4.00%`**).
     - **Hybrid Defense v2.0:** **`0.848 ms/req`** (P95 **`1.075 ms`**) — nằm sâu dưới ngưỡng inline SLA `< 5 ms`, tăng thêm chỉ **`+0.214 ms`** so với ML thuần!
2. **Chất lượng phòng thủ tổng hợp:**
   - **Hybrid Defense v2.0** đạt Accuracy **`97.80%`**, Precision **`100.00%`**, Recall **`97.25%`**, F1-Score **`98.61%`** (chênh lệch `+1.97%` so với ML thuần), FPR **`0.00%`** và Youden's Index **`J = 0.9725`**.

---

## 3. Luận Điểm Học Thuật: Giá Trị Defense-in-Depth Của Kiến Trúc Hybrid v2.0

*(Xem phân tích đầy đủ tại `docs/reports/WHY_HYBRID_DEFENSE.md`)*

1. **Chống tấn công đối kháng (Adversarial Evasion) & Obfuscation:** Rule Engine đã được gia cố (`InputNormalizer` khử Zero-Width Unicode, `/*...*/` multiline, recursive URL decoding, sliding window > 16KB) giúp chặn đứng mọi kỹ thuật né tránh signature và làm loãng vector ML.
2. **Phát hiện Zero-Day & Out-of-Distribution (OOD):** Calibrated Isolation Forest v2.0 (`.npz`, hiệu chuẩn theo phân vị thực nghiệm) nâng độ nhạy phát hiện bất thường ở ngưỡng cảnh báo `>= 60` từ **5.88% (v1.0)** lên **`57.75%` (v2.0)** trong khi kiểm soát chặt FPR ở mức **`4.00%`**.
3. **An toàn chuỗi cung ứng & Khả năng chịu lỗi (Fail-Closed & Fail-Safe):** Triệt tiêu 100% rủi ro Deserialization RCE (CWE-502) nhờ định dạng Zero-Pickle + xác thực SHA-256 Fail-Closed trước khi nạp; khi tầng ML gặp sự cố, Gateway tự động áp dụng Fail-Safe penalty và duy trì phòng thủ bằng Rule Engine + Schema Validator.
