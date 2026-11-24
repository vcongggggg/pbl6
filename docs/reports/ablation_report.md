# BÁO CÁO THỰC NGHIỆM ĐO LƯỜNG ĐÓNG GÓP TỪNG THÀNH PHẦN (ABLATION STUDY — BLUE TEAM v3.2)

> **Mã công việc:** Task B3 / D4 (Nâng cấp Blue Team v3.2 — 26 Hardened OWASP Signatures)
> **Người thực hiện:** Nguyễn Văn Công (`vcongggggg` — Tech Lead / Blue Team)
> **Thời gian đo kiểm:** 2026-11-24 23:08:44
> **Tập dữ liệu:** `benchmark_1000_diverse.csv` (1000 mẫu độc lập: 200 Benign, 800 Attacks — `0` mẫu trùng với tập train `defense_v2`)
> **Mô hình thực thi:** `Champion Cost-Sensitive Regularized XGBoost v2.0` (`xgb_v2.ubj`, 26-D) + `Calibrated Isolation Forest v2.0 (with bare-root '/' special_char_ratio guard)` (`iforest_v2.npz`, Zero-Pickle) + Rule Engine (26 hardened signatures, bao gồm `SQLI-006`)
> **Phương pháp đo Latency:** Cô lập thời gian thực thi single-pass của từng cấu hình; trong chế độ Hybrid, vector 26-D (`extract_26_from_http`) chỉ trích xuất **1 lần duy nhất** dùng chung cho cả XGBoost v2.0 và Isolation Forest v2.0 giống hệt production (`gateway/app/api/proxy.py`).

---

## 1. Bảng Đối Sánh Thực Nghiệm 4 Cấu Hình Phòng Thủ (Ablation Matrix v3.2)

| Chế Độ Cấu Hình Phòng Thủ | Accuracy (%) | Precision (%) | Recall / DR (%) | F1-Score (%) | FPR (%) | Youden's J | Mean (ms/req) | P95 (ms/req) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Rules Only (26 Hardened OWASP Signatures)** | 62.40% | 100.00% | 53.00% | 69.28% | 0.00% | 0.5300 | **0.156 ms** | 0.291 ms |
| **2. ML Only (XGBoost v2.0 — 26-D UBJSON)** | 94.80% | 100.00% | 93.50% | 96.64% | 0.00% | 0.9350 | 0.322 ms | 0.582 ms |
| **3. Anomaly Only (Calibrated IForest v2.0 — NPZ) (Block >= 80)** | 50.90% | 100.00% | 38.62% | 55.73% | 0.00% | 0.3862 | 0.268 ms | 0.458 ms |
| *Anomaly Only — Cảnh báo / Rate-Limit (>= 60)* | *66.20%* | *100.00%* | *57.75%* | *73.22%* | *0.00%* | *0.5775* | *0.268 ms* | *0.458 ms* |
| **4. Hybrid Defense v3.2 (26 Rules + XGBoost v2 + IForest v2 + Dual-AI)** | **98.20%** | **100.00%** | **97.75%** | **98.86%** | **0.00%** | **0.9775** | **0.561 ms** | **0.806 ms** |

---

## 2. Phân Tích Trade-Off Hiệu Năng & Độ Trễ (Hybrid Defense v3.2 so với Blue Team v1.0)

1. **Bước nhảy vọt về tốc độ nhờ chuyển sang Zero-Pickle (`xgb_v2.ubj` + `iforest_v2.npz`) & Single-Pass 26-D:**
   - Ở **Blue Team v1.0** (`rf_model.joblib` + `iforest_model.joblib`), chế độ Hybrid tiêu tốn **16.10 ms/req** (vượt ngưỡng inline SLA 10 ms), trong đó `Anomaly Only` mất 9.49 ms và chỉ đạt Recall 5.88%.
   - Ở **Hybrid Defense v3.2** (26 Hardened Rules + **XGBoost v2.0 UBJSON** + **Isolation Forest v2.0 NumPy NPZ** kết hợp trích xuất 26-D một lần duy nhất):
     - **Rules Only:** `0.156 ms/req` (P95 `0.291 ms`).
     - **ML Only (XGBoost v2.0):** `0.322 ms/req` (P95 `0.582 ms`).
     - **Anomaly Only (IForest v2.0 NPZ):** `0.268 ms/req` (tăng tốc vượt trội so với 9.49 ms của v1.0; tại ngưỡng cảnh báo `>= 60.0` đạt Recall **`57.75%`** với FPR chỉ **`0.00%`**).
     - **Hybrid Defense v3.2:** **`0.561 ms/req`** (P95 **`0.806 ms`**) — nằm sâu dưới ngưỡng inline SLA `<= 1.5 ms`, tăng thêm chỉ **`+0.239 ms`** so với ML thuần!
2. **Chất lượng phòng thủ tổng hợp:**
   - **Hybrid Defense v3.2** đạt Accuracy **`98.20%`**, Precision **`100.00%`**, Recall **`97.75%`**, F1-Score **`98.86%`** (chênh lệch `+2.22%` so với ML thuần), FPR **`0.00%`** và Youden's Index **`J = 0.9775`**.
3. **Triệt tiêu FPR của `Anomaly Only` từ `4.00%` (`8/200`) xuống `0.00%` (`0/200`) sau Phase C3 Round 1:**
   - Ở phiên bản v2.0, `Anomaly Only` ghi nhận FPR **`4.00%` (`8/200`)** do hiện tượng suy biến đường dẫn gốc trần `'/'` (*bare-root `'/'` degeneracy*): 8 truy vấn `GET /` lành tính không có query/body bị tính `special_char_ratio = 1.0` (do `'/'` là ký tự duy nhất) và bị Isolation Forest đánh nhãn ngoại lai.
   - Sau **Phase C3 Round 1** bổ sung bộ bảo vệ đường dẫn gốc `'/'` (*bare-root guard* trong `AnomalyDetector` / pipeline trích xuất đặc trưng), `Anomaly Only` giảm FPR về **`0.00%` (`0/200`)** ở ngưỡng chặn `>= 80.0` và **`0.00%` (`0/200`)** ở ngưỡng cảnh báo `>= 60.0` mà vẫn bảo toàn nguyên vẹn Recall `57.75%`.

---

## 3. Luận Điểm Học Thuật: Giá Trị Defense-in-Depth Của Kiến Trúc Hybrid Defense v3.2

*(Xem phân tích đầy đủ tại `docs/reports/WHY_HYBRID_DEFENSE.md`)*

1. **Chống tấn công đối kháng (Adversarial Evasion) & Obfuscation:** Rule Engine (26 rules, bao gồm `SQLI-006`) đã được gia cố (`InputNormalizer` khử Zero-Width Unicode, `/*...*/` multiline, recursive URL decoding, sliding window > 16KB) giúp chặn đứng mọi kỹ thuật né tránh signature và làm loãng vector ML.
2. **Phát hiện Zero-Day & Out-of-Distribution (OOD):** Calibrated Isolation Forest v2.0 (`.npz`, hiệu chuẩn theo phân vị thực nghiệm) nâng độ nhạy phát hiện bất thường ở ngưỡng cảnh báo `>= 60` từ **5.88% (v1.0)** lên **`57.75%` (v3.2)** trong khi kiểm soát chặt FPR ở mức **`0.00%`**.
3. **An toàn chuỗi cung ứng & Khả năng chịu lỗi (Fail-Closed & Fail-Safe):** Triệt tiêu 100% rủi ro Deserialization RCE (CWE-502) nhờ định dạng Zero-Pickle + xác thực SHA-256 Fail-Closed trước khi nạp; khi tầng ML gặp sự cố, Gateway tự động áp dụng Fail-Safe penalty và duy trì phòng thủ bằng Rule Engine + Schema Validator.
