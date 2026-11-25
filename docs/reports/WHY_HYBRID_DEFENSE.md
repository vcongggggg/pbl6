# LUẬN CỨ HỌC THUẬT: TẠI SAO CẦN KIẾN TRÚC HYBRID DEFENSE 4 TẦNG (v3.3)?
## *Giải Trình Khoa Học Cho Câu Hỏi Phản Biện Của Hội Đồng Đồ Án PBL6*

- **Tác giả:** Nguyễn Văn Công (`vcongggggg` — Tech Lead / Blue Team) & Nguyễn Minh (`naocavang08` — Red Team)
- **Tài liệu tham chiếu:** [ablation_report.md](file:///C:/Study/HocKy6/PBL6/docs/reports/ablation_report.md), [performance_profile.md](file:///C:/Study/HocKy6/PBL6/docs/reports/performance_profile.md), [csic2010_benchmark_report.md](file:///C:/Study/HocKy6/PBL6/docs/reports/csic2010_benchmark_report.md)
- **Câu hỏi trọng tâm của Hội đồng:**
  > *"Tại sao hệ thống phải duy trì kiến trúc tiến hóa 4 tầng (`Rules Static -> Rules Hardened+Normalizer -> Hybrid XGBoost 26-D + IForest 26-D + Dual-AI -> + Route-Tiered OpenAPI Schema / DLP`) thay vì chỉ triển khai một mô hình Machine Learning đơn lẻ?"*

---

## 1. BẰNG CHỨNG THỰC NGHIỆM ĐỘC LẬP TRÊN BLUE TEAM v3.3

Thực nghiệm Ablation Study trên **1,000 mẫu đa dạng (`benchmark_1000_diverse.csv`, 0 mẫu trùng trong `47.372` dòng `defense_v2`)** và **3,000 mẫu ngoại miền CSIC 2010 (Zero-Shot Two-Tier)** chứng minh sự vượt trội định lượng rõ rệt của kiến trúc Hybrid v3.3 so với bất kỳ thành phần đơn lẻ nào:

- **Trên tập `benchmark_1000_diverse.csv` (1,000 mẫu, 28 Hardened Rules):**
  - **ML Only (XGBoost v2.0):** Recall `95.12%` (bỏ lọt `39/800` tấn công), F1 `97.50%`, Latency `0.461 ms/req` (P95 `0.942 ms`).
  - **Hybrid Defense v3.3:** Recall vọt lên **`97.75%`** (giảm số tấn công bỏ lọt từ `39` xuống `18`, tăng **+2.63% Recall** và **+1.36% F1-Score** lên **`98.86%`**), giữ nguyên **FPR `0.00%` (`0/200`)** và chỉ tiêu tốn **`0.803 ms/req`** inline (P95 `1.465 ms`, `<= 1.5 ms` SLA; `4.138 ms` 2-hop TCP HTTP E2E `<= 5.5 ms` SLA).
- **Trên tập ngoại miền quốc tế CSIC 2010 (3,000 mẫu Zero-Shot, Two-Tier Audited):**
  - **ML Only (XGBoost v2.0):** Group A True Payload (`221` mẫu) đạt **`93.21%` (`206/221`)** (`SQLi 89.51%`, `XSS 100.00%`), Overall `15.87%` (`238/1.500`), FPR `0.07%` (`1/1.500`).
  - **Hybrid Defense v3.3 (không Schema `/tienda1`):** Group A True Payload đạt tuyệt đối **`100.00%` (`221/221`)** (`143/143` SQLi gồm `75/75` `SQLI_BLIND_BOOLEAN`, `61/61` T-SQL time-delay, `7/7` Union; và `78/78` XSS), đồng thời giữ vững **Precision `100.00%`** và **FPR `0.00%` (`0/1.500` request sạch bị chặn oan)** ở chế độ Operational `DecisionEngine T=80` (Overall `16.40%` Op T=80 / `17.27%` Loose do **CSIC Domain Shift** của `1.279` mẫu Group B Parameter Tampering).
  - **Hybrid Defense v3.3 + OpenAPI `/tienda1` Schema (suy dẫn chỉ từ Benign):** Nâng Group B lên **`66.54%` (`851/1.279`)** và Overall lên **`71.47%` (`1.072/1.500`)** tại **`0.00%` FPR** (`csic2010_tienda1_schema_proof.json`).

---

## 2. KIẾN TRÚC TIẾN HÓA 4 TẦNG & BỐN TRỤ CỘT BẢO VỆ (BLUE TEAM v3.3)

```text
                             [ INCOMING HTTP / API REQUEST ]
                                            |
                                            v
                    +-----------------------------------------------+
                    | 0. MULTI-PROTOCOL SNIFFER & SCHEMA VALIDATOR  |
                    |    REST / GraphQL / SOAP-XML / JSON-RPC       |
                    |    OpenAPI 3.0 Route-Tiered Positive Contract |
                    +-----------------------+-----------------------+
                                            |
                    +-----------------------v-----------------------+
                    | 1. HARDENED RULE ENGINE (0.178 ms)            |
                    |    28 OWASP Rules + InputNormalizer + JSON    |
                    |    object_pairs_hook=list + Form + >16KB      |
                    +-----------------------+-----------------------+
                                            | (26-D + Per-Param Max-Pooling)
                           +----------------+----------------+
                           v                                 v
            +-----------------------------+   +-----------------------------+
            | 2. SUPERVISED ML (0.461 ms) |   | 3. ANOMALY DETECT (0.297 ms)|
            |    Champion XGBoost v2.0    |   |    Calibrated IForest v2.0  |
            |    Zero-Pickle UBJSON (26-D)|   |    Zero-Pickle NPZ (50 KB)  |
            +--------------+--------------+   +--------------+--------------+
                           +----------------+----------------+
                                            v
                    +-----------------------------------------------+
                    | 4. HYBRID RISK & MULTI-TIER DECISION ENGINE   |
                    |    0.40*Rule + 0.35*ML + 0.25*Anomaly         |
                    |    + High-Confidence / Dual-AI Consensus      |
                    |    ALLOW (<30) | MONITOR | 429 | BLOCK (>=80) |
                    +-----------------------------------------------+
```

### Trụ cột 1: Chống Tấn Công Đối Kháng (Adversarial Evasion) & Obfuscation
- Kẻ tấn công thường dùng kỹ thuật chèn comment nội tuyến (`UNION/**/SELECT`), ký tự Zero-Width Unicode (`\u200b`), mã hóa URL lồng nhau (`%2527`), nối số khoa học (`1e0UNION`), wildcard-globbing (`/???/c?t`), trùng lặp khóa JSON (`json_duplicate_key_tamper`) hoặc nhồi padding > 16 KB nhằm làm loãng vector đặc trưng ML.
- Tầng `InputNormalizer` + `RuleEngine` (**28 rules**, gồm `SQLI-006/007`, `CMD-006`, `object_pairs_hook=list` đệ quy JSON lồng nhau, `parse_qs` form) + `MLDetector.predict_http()` (Per-Parameter Max-Pooling) bóc tách và chặn đứng chính xác các biến thể này; trong thực nghiệm Ablation, Hybrid bắt thêm `21` mẫu tấn công mà ML đơn lẻ bỏ sót (`761 -> 782/800`) và cứu `15/221` Group A trên CSIC 2010 (`206 -> 221/221`).

### Trụ cột 2: Phát Hiện Tấn Công Chưa Từng Biết (Zero-Day & Out-of-Distribution)
- Mô hình học có giám sát (`XGBoost v2.0`) bị giới hạn bởi giả định thế giới đóng (5 lớp nhãn đã học). Khi gặp payload dị dạng ngoài phân phối (như JSFuck, XML XXE biến dị, JNDI/Log4Shell), ML có giám sát dễ suy giảm độ tin cậy.
- `Calibrated Isolation Forest v2.0` (`.npz`, có bare-root `'/'` degeneracy guard hạ FPR từ `4.00%` v2.0 xuống **`0.00%`** trên `B1000`) học hoàn toàn từ phân phối lưu lượng sạch và hiệu chuẩn phân vị thực nghiệm, đạt **57.75% Recall @60.0** (và **85.88% @30.0**), kết hợp **Dual-AI Consensus (`ML >= 70 & Anomaly >= 70 -> BLOCK`)** đóng vai trò hệ thống phòng vệ Zero-Day.

### Trụ cột 3: Tối Ưu Chi Phí Độ Trễ Dưới 1 Millisecond (`0.803 ms/req` Inline)
- Nhờ chuyển sang định dạng nhị phân tối ưu (`xgb_v2.ubj` + `iforest_v2.npz`) và chia sẻ một lần trích xuất vector 26-D duy nhất:
  - `Rules Only (28 rules)`: **`0.178 ms`** (P95 `0.317 ms`)
  - `ML Only (XGBoost v2.0)`: **`0.461 ms`** (P95 `0.942 ms`)
  - `Anomaly Only (IForest v2.0)`: **`0.297 ms`** (P95 `0.496 ms`; `0.095 ms` trên gateway micro-benchmark khi tái sử dụng vector)
  - `Hybrid Defense v3.3`: **`0.803 ms`** inline (P95 **`1.465 ms`**, `<= 1.5 ms` SLA) — nhanh hơn **~22 lần** so với bản v1.0 (`16.10 ms`), còn toàn trình 2-hop TCP HTTP E2E trên `3.000` mẫu CSIC đạt **`4.138 ms`** mean (`<= 5.5 ms` Dual-Tier SLA), kết hợp kiến trúc bất đồng bộ (`anyio.to_thread.run_sync` + SQLite WAL Group Commit) đạt **`253.31 – 340.14 RPS`** tại mức đồng thời `C=50`.

### Trụ cột 4: An Toàn Chuỗi Cung Ứng & Suy Thoái An Toàn (Zero-Pickle + Fail-Safe)
- Toàn bộ mô hình phòng thủ loại bỏ 100% Pickle (triệt tiêu CWE-502) và xác thực SHA-256 Fail-Closed trước khi nạp.
- Nếu tầng ML bị lỗi hoặc không khả dụng, Gateway tự động chuyển sang *Degraded Safe Mode* (áp dụng Fail-Safe penalty +15 điểm rủi ro và duy trì phòng thủ bằng Rule Engine + OpenAPI Schema Validator), không bao giờ xảy ra lỗi Fail-Open bỏ lọt mã độc.

---

## 3. BẢNG SO SÁNH ĐA CHIỀU 4 CẤU HÌNH PHÒNG THỦ (BLUE TEAM v3.3)

| Tiêu Chí So Sánh | 1. Rules Only (28 Rules) | 2. ML Only (XGBoost v2.0) | 3. Anomaly Only (IForest v2.0) | 4. HYBRID DEFENSE v3.3 (Đề Tài) |
| :--- | :---: | :---: | :---: | :---: |
| **Độ trễ trung bình / P95 (`B1000`)** | **0.178 ms** / 0.317 ms | 0.461 ms / 0.942 ms | 0.297 ms / 0.496 ms | **0.803 ms / 1.465 ms (<= 1.5 ms SLA)** |
| **Recall (`benchmark_1000`)** | 53.62% | 95.12% | 38.62% (>=80) / 57.75% (>=60) | **97.75% (XSS/Path = 100%, SQLi = 98.5%)** |
| **F1-Score & Youden's J** | 69.81% (`J = 0.5363`) | 97.50% (`J = 0.9513`) | 55.73% (`>=80`) / 73.22% (`>=60`) | **98.86% (`J = 0.9775`)** |
| **FPR (Benign Clean Traffic)** | **0.00%** | **0.00%** | **0.00%** (sau bare-root guard) | **0.00% (`N = 1.715` Op FPR)** |
| **CSIC 2010 Zero-Shot (Group A / +Schema)** | — | 93.21% (`206/221`), FPR 0.07% | — | **100.00% (`221/221`) @ 0.00% FPR / 71.47% (+`/tienda1`)** |
| **Khả năng giải thích (XAI)** | Rule ID & Matched Token | 26-D Feature Vector | Anomaly Percentile Score | **Đầy đủ: Rule + 26-D XAI + Kill Chain** |
| **Tính sẵn sàng (Fail-Safe)** | Rất cao | Điểm lỗi đơn (SPOF) | Trung bình | **Tối đa (Fail-Closed + Degraded Mode)** |
