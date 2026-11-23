# LUẬN CỨ HỌC THUẬT: TẠI SAO CẦN KIẾN TRÚC HYBRID DEFENSE v2.0?
## *Giải Trình Khoa Học Cho Câu Hỏi Phản Biện Của Hội Đồng Đồ Án PBL6*

- **Tác giả:** Nguyễn Văn Công (`vcongggggg` — Tech Lead / Blue Team) & Nguyễn Minh (`naocavang08` — Red Team)
- **Tài liệu tham chiếu:** [ablation_report.md](file:///C:/Study/HocKy6/PBL6/docs/reports/ablation_report.md), [performance_profile.md](file:///C:/Study/HocKy6/PBL6/docs/reports/performance_profile.md), [csic2010_benchmark_report.md](file:///C:/Study/HocKy6/PBL6/docs/reports/csic2010_benchmark_report.md)
- **Câu hỏi trọng tâm của Hội đồng:**
  > *"Tại sao hệ thống phải duy trì kiến trúc Hybrid đa tầng (OpenAPI Positive Schema + Hardened Rule Engine + XGBoost v2.0 + Calibrated Isolation Forest v2.0) thay vì chỉ triển khai một mô hình Machine Learning đơn lẻ?"*

---

## 1. BẰNG CHỨNG THỰC NGHIỆM ĐỘC LẬP TRÊN BLUE TEAM v2.0

Thực nghiệm Ablation Study trên **1,000 mẫu đa dạng (`benchmark_1000_diverse.csv`, 0 mẫu trùng tập train `defense_v2`)** và **3,000 mẫu ngoại miền CSIC 2010 (Zero-Shot)** chứng minh sự vượt trội định lượng rõ rệt của kiến trúc Hybrid v2.0 so với bất kỳ thành phần đơn lẻ nào:

- **Trên tập `benchmark_1000_diverse.csv` (1,000 mẫu):**
  - **ML Only (XGBoost v2.0):** Recall `93.50%` (bỏ lọt `52/800` tấn công), F1 `96.64%`, Latency `0.634 ms/req`.
  - **Hybrid Defense v2.0:** Recall vọt lên **`97.25%`** (giảm số tấn công bỏ lọt từ `52` xuống `22`, tăng **+3.75% Recall** và **+1.97% F1-Score** lên **`98.61%`**), giữ nguyên **FPR `0.00%` (`0/200`)** và chỉ cộng thêm **`+0.214 ms`** độ trễ (`0.848 ms/req` tổng, P95 `1.075 ms`).
- **Trên tập ngoại miền quốc tế CSIC 2010 (3,000 mẫu Zero-Shot):**
  - **ML Only (XGBoost v2.0):** SQLi `34.65%`, XSS `95.38%`, tổng Recall `11.60%`, FPR `0.00%`.
  - **Hybrid Defense v2.0:** SQLi tăng lên **`49.61%` (+14.96%)**, XSS đạt tuyệt đối **`100.00%` (65/65)**, tổng Recall tăng lên **`17.07%` (+5.47%)**, đồng thời giữ vững **Precision `100.00%`** và **FPR `0.00%` (0/1,500 request sạch bị chặn oan)**!

---

## 2. BỐN TRỤ CỘT BẢO VỆ CHO KIẾN TRÚC HYBRID DEFENSE v2.0

```text
                             [ INCOMING HTTP / API REQUEST ]
                                            |
                                            v
                    +-----------------------------------------------+
                    | 0. MULTI-PROTOCOL SNIFFER & SCHEMA VALIDATOR  |
                    |    REST / GraphQL / SOAP-XML / JSON-RPC       |
                    |    OpenAPI 3.0 Positive Security Contract     |
                    +-----------------------+-----------------------+
                                            |
                    +-----------------------v-----------------------+
                    | 1. HARDENED RULE ENGINE (0.106 ms)            |
                    |    16 OWASP Signatures + InputNormalizer      |
                    |    Sliding Window > 16KB + Zero-Width Strip   |
                    +-----------------------+-----------------------+
                                            | (Single-Pass 26-D Unified Vector)
                           +----------------+----------------+
                           v                                 v
            +-----------------------------+   +-----------------------------+
            | 2. SUPERVISED ML (0.618 ms) |   | 3. ANOMALY DETECT (0.095 ms)|
            |    Champion XGBoost v2.0    |   |    Calibrated IForest v2.0  |
            |    Zero-Pickle UBJSON (26-D)|   |    Zero-Pickle NPZ (50 KB)  |
            +--------------+--------------+   +--------------+--------------+
                           +----------------+----------------+
                                            v
                    +-----------------------------------------------+
                    | 4. HYBRID RISK & MULTI-TIER DECISION ENGINE   |
                    |    0.40*Rule + 0.35*ML + 0.25*Anomaly         |
                    |    + High-Confidence Override & Fail-Safe     |
                    |    ALLOW (<30) | MONITOR | 429 | BLOCK (>=80) |
                    +-----------------------------------------------+
```

### Trụ cột 1: Chống Tấn Công Đối Kháng (Adversarial Evasion) & Obfuscation
- Kẻ tấn công thường dùng kỹ thuật chèn comment nội tuyến (`UNION/**/SELECT`), ký tự Zero-Width Unicode (`\u200b`), mã hóa URL lồng nhau (`%2527`) hoặc nhồi padding > 16 KB nhằm làm loãng vector đặc trưng ML.
- Tầng `InputNormalizer` + `RuleEngine` với cửa sổ trượt (Sliding Window > 16 KB) bóc tách và chặn đứng chính xác các biến thể này; trong thực nghiệm, Hybrid bắt thêm `30` mẫu tấn công mà ML đơn lẻ bỏ sót (từ `748 -> 778/800`).

### Trụ cột 2: Phát Hiện Tấn Công Chưa Từng Biết (Zero-Day & Out-of-Distribution)
- Mô hình học có giám sát (`XGBoost v2.0`) bị giới hạn bởi giả định thế giới đóng (5 lớp nhãn đã học). Khi gặp payload dị dạng ngoài phân phối (như JSFuck, XML XXE biến dị, JNDI/Log4Shell), ML có giám sát dễ suy giảm độ tin cậy.
- `Calibrated Isolation Forest v2.0` (`.npz`) học hoàn toàn từ phân phối lưu lượng sạch và hiệu chuẩn phân vị thực nghiệm, đạt **57.75% Recall @60.0** (và **85.88% @30.0**), đóng vai trò hệ thống cảnh báo sớm Zero-Day với chi phí chỉ **`0.095 ms`**.

### Trụ cột 3: Tối Ưu Chi Phí Độ Trễ Dưới 1 Millisecond (`0.848 ms/req`)
- Nhờ chuyển sang định dạng nhị phân tối ưu (`xgb_v2.ubj` + `iforest_v2.npz`) và chia sẻ một lần trích xuất vector 26-D duy nhất:
  - `Rules Only`: **`0.106 ms`**
  - `ML Only (XGBoost v2.0)`: **`0.634 ms`**
  - `Anomaly Only (IForest v2.0)`: **`0.235 ms`** (chỉ `0.095 ms` khi dùng lại vector 26-D)
  - `Hybrid Defense v2.0`: **`0.848 ms`** (P95 **`1.075 ms`**) — nhanh hơn **19 lần** so với bản v1.0 (`16.10 ms`), kết hợp kiến trúc bất đồng bộ (`anyio.to_thread.run_sync` + SQLite WAL Group Commit) cho phép Gateway đạt **`269.50 – 340.14 RPS`** tại mức đồng thời `C=50`.

### Trụ cột 4: An Toàn Chuỗi Cung Ứng & Suy Thoái An Toàn (Zero-Pickle + Fail-Safe)
- Toàn bộ mô hình v2.0 loại bỏ 100% Pickle (triệt tiêu CWE-502) và xác thực SHA-256 Fail-Closed trước khi nạp.
- Nếu tầng ML bị lỗi hoặc không khả dụng, Gateway tự động chuyển sang *Degraded Safe Mode* (áp dụng Fail-Safe penalty +15 điểm rủi ro và duy trì phòng thủ bằng Rule Engine + OpenAPI Schema Validator), không bao giờ xảy ra lỗi Fail-Open bỏ lọt mã độc.

---

## 3. BẢNG SO SÁNH ĐA CHIỀU 4 CẤU HÌNH PHÒNG THỦ (BLUE TEAM v2.0)

| Tiêu Chí So Sánh | 1. Rules Only | 2. ML Only (XGBoost v2.0) | 3. Anomaly Only (IForest v2.0) | 4. HYBRID DEFENSE v2.0 (Đề Tài) |
| :--- | :---: | :---: | :---: | :---: |
| **Độ trễ trung bình / P95** | **0.106 ms** / 0.188 ms | 0.634 ms / 0.787 ms | 0.235 ms / 0.336 ms | **0.848 ms / 1.075 ms (< 5 ms SLA)** |
| **Recall (`benchmark_1000`)** | 49.25% | 93.50% | 38.62% (>=80) / 57.75% (>=60) | **97.25% (SQLi/XSS/Path = 100%)** |
| **F1-Score & Youden's J** | 66.00% (`J = 0.4925`) | 96.64% (`J = 0.9350`) | 55.33% (`>=80`) / 72.76% (`>=60`) | **98.61% (`J = 0.9725`)** |
| **FPR (Benign Clean Traffic)** | **0.00%** | **0.00%** | 4.00% | **0.00% (Tuyệt đối)** |
| **CSIC 2010 Zero-Shot (XSS / SQLi)** | — | 95.38% / 34.65% | — | **100.00% / 49.61% (FPR 0.00%)** |
| **Khả năng giải thích (XAI)** | Rule ID & Matched Token | 26-D Feature Vector | Anomaly Percentile Score | **Đầy đủ: Rule + 26-D XAI + Kill Chain** |
| **Tính sẵn sàng (Fail-Safe)** | Rất cao | Điểm lỗi đơn (SPOF) | Trung bình | **Tối đa (Fail-Closed + Degraded Mode)** |
