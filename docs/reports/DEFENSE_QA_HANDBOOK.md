# SỔ TAY PHẢN BIỆN HỘI ĐỒNG ĐỒ ÁN CHUYÊN NGÀNH (PBL6 — PHASE F3)
## *Chuẩn Bị Trả Lời Định Lượng Dựa Trên Bằng Chứng Thực Nghiệm & Mã Nguồn Kiểm Định*

- **Đề tài:** Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán
- **Sinh viên thực hiện:** Nguyễn Văn Công (`vcongggggg` — Blue Team) & Nguyễn Minh (`naocavang08` — Red Team)
- **Giảng viên hướng dẫn:** TS. Nguyễn Thế Xuân Ly
- **Nguồn đối chiếu bắt buộc:** Toàn bộ số liệu trong tài liệu này trích xuất trực tiếp từ các JSON đã commit tại [docs/reports/](file:///C:/Study/HocKy6/PBL6/docs/reports) và [attack-lab/models/](file:///C:/Study/HocKy6/PBL6/attack-lab/models).

---

## Q1. Kiến trúc tiến hóa 4 tầng (`Rules Static -> Rules Hardened+Normalizer -> Hybrid XGBoost 26-D + IForest 26-D + Dual-AI -> + Route-Tiered OpenAPI Schema / DLP`) giải quyết gì mà từng tầng đơn lẻ không làm được?

### Luận điểm cốt lõi
Mỗi tầng trong **4-Tier Evolution** ([defense_evolution_tiers_v32.json](file:///C:/Study/HocKy6/PBL6/docs/reports/defense_evolution_tiers_v32.json)) khắc phục đúng một điểm mù cố hữu của tầng trước:
1. **Tier 1 (`No WAF` — `vulnerable-api:5000`):** Đường cơ sở `0%` bảo vệ; cả Static Replay, Random Mutator và Dueling-DQN đều khai thác thành công `100%` (`0/45` Familiar, `0/54` Strange, `0/114` Strange v3.3, `0/30` Blind Vault v2).
2. **Tier 2 (`Legacy Static Regex` — 5 regex thô, không có `InputNormalizer`):** Bị tác tử đột biến ngữ nghĩa đánh sập hoàn toàn. Trên kiểm định In-Process, `Dueling-DQN v2.0` vượt rào `93.3%` trên Familiar (chỉ chặn `3/45 = 6.7%`) và `100.0%` trên Strange (`0/54`) cũng như Strange v3.3 (`0/114`) và Blind Vault v2 (`0/30`).
3. **Tier 3 (`Normalized OWASP API Rules` — Gateway `:8056`, `InputNormalizer` + 28 Hardened Rules + `BOLADetector` + `ResponseDLPGuard`):** Khử được URL encoding đa tầng, comment nội tuyến `/*...*/`, Zero-Width Unicode, JSON duplicate-key (`object_pairs_hook=list`) và các lỗ hổng API logic (`SSRF`, `NoSQLi`, `Mass Assignment`, `BOLA`, `Response DLP`). Tuy nhiên, trên tập `benchmark_1000_diverse.csv` (`N = 1.000`, [ablation_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/ablation_results.json)), `Rules Only` (28 rules) mới đạt **`53.62%` Recall / `69.81%` F1** (`371/800` mẫu obfuscation/structural lọt lưới); qua Live-HTTP Stage 4 (`12` case training greedy), `Dueling-DQN` vẫn vượt `:8056` **`25.0%` (`3/12`)**, và trên `Blind Vault v2` (single-shot) Live-HTTP `Rules Only` chỉ chặn được **`46.67%` (`14/30`)** trước Dueling-DQN.
4. **Tier 4 (`Multi-Pillar Hybrid + Route-Tiered OpenAPI Schema / DLP` — `:8055`, + `XGBoost 26-D` + `IForest 26-D` + `Dual-AI Consensus` + `Per-Parameter Max-Pooling` + `SchemaValidator`):**
   - **Bù đắp lẫn nhau giữa Rules và ML:** Trên `benchmark_1000_diverse.csv`, `ML Only` (`xgb_v2.ubj`) đạt `95.12%` Recall / `97.50%` F1 (`39` ca lọt), `Anomaly Only` (`iforest_v2.npz`) đạt `57.75%` Recall `@60.0` (`0.00%` FPR nhờ bare-root `'/'` guard). Khi hợp nhất thành **Hybrid v3.3**, hệ thống đạt **`98.86%` F1, `97.75%` Recall, `100.00%` Precision, `0.00%` FPR, Youden's `J = 0.9775`** chỉ trong **`0.803 ms/req`** inline (P95 `1.465 ms`) — giảm số tấn công bỏ lọt từ `39 -> 18` so với ML đơn lẻ và từ `371 -> 18` so với Rules đơn lẻ.
   - **Kiểm soát chặt Operational FPR:** Giữ tuyệt đối **`0.00%` (`0/1.715`)** trên toàn bộ mẫu sạch tổng hợp ([fp_v3_measurement.json](file:///C:/Study/HocKy6/PBL6/docs/reports/fp_v3_measurement.json)).
   - **Bền vững trước Red Team Live-HTTP:** Hạ bypass trên Stage 4 xuống `8.33%` (`1/12` so với `25.0%` của `:8056`), đạt **`100.00% (114/114)`** trên toàn bộ 6 ô Hybrid của `Strange Suite v3.3` ([strange_suite_v33_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/strange_suite_v33_results.json)), và trên `Blind Vault v2` nâng từ `46.67%` (`:8056`) lên **`86.67%` (`26/30`)** DQN / **`93.33%` (`28/30`)** Static ở lượt đo đơn khóa SHA-256, rồi **`100.00% (30/30)`** trên cả 6 ô Hybrid sau vá F2b (`postfix2`, [blind_heldout_vault_v2_postfix2_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/blind_heldout_vault_v2_postfix2_results.json)).
   - **Hoàn thiện phòng thủ hợp đồng API:** Lớp `Route-Tiered OpenAPI Schema` chặn `Parameter Tampering` và `Mass Assignment` (`additionalProperties`) — những biến dị hợp cú pháp HTTP mà signature và ML không thể phân biệt nếu thiếu đặc tả ứng dụng.

---

## Q2. Tại sao Recall tổng thể trên CSIC 2010 chỉ đạt `16.40%` (Op T=80) / `17.27%` (Loose) khi chưa bật Schema — có phải mô hình overfit không?

### Trả lời chuẩn khung: **CSIC Domain Shift + Two-Tier Taxonomy** (KHÔNG phải overfit)
1. **Bản chất dữ liệu CSIC 2010 & nhiễu nhãn gốc:**
   - Khi kiểm toán lại 1.500 mẫu Attack trong CSIC 2010 ([csic2010_taxonomy_breakdown.json](file:///C:/Study/HocKy6/PBL6/docs/reports/csic2010_taxonomy_breakdown.json)), nhóm phát hiện bộ nhãn gốc gán nhầm **`133/254` (`52.36%`)** mẫu `modo=insertar` tiếng Tây Ban Nha là `SQLI` dù không chứa cú pháp SQL.
   - Áp dụng chuẩn kiểm toán **Two-Tier** (`unquote_plus` depth=3 + word-boundary `\b`), 1.500 mẫu tấn công CSIC tách thành 2 nhóm bản chất hoàn toàn khác nhau:
     - **Group A — True Payload Attacks (`221` mẫu = `14.73%`):** gồm `143` SQLi (`7` Classic Union, `75` Blind Boolean + legacy `--` SSI, `61` T-SQL Time-Delay) và `78` XSS.
     - **Group B — Application-Specific Parameter Tampering (`1.279` mẫu = `85.27%`):** là các bất thường logic nghiệp vụ riêng của ứng dụng thương mại điện tử Tây Ban Nha `/tienda1` (giá âm, vượt độ dài trường, thiếu/thừa tham số, sai kiểu dữ liệu, đổi method).
2. **Kết quả trên Group A (năng lực bắt mã độc thực sự) — Zero-Shot `100.00%`:**
   - Không có bất kỳ mẫu CSIC nào trong tập train (`csic2010_overlap = 0`).
   - Standalone XGBoost v2 đạt `93.21%` (`206/221`) trên Group A (`0.07%` FPR).
   - **Hybrid v3.3** đạt **`100.00% (221/221)`** ở cả **Operational `DecisionEngine T=80` (`0.00%` FPR, `0/1.500` chặn oan, `100.00%` Precision)** lẫn **Loose Monitoring (`0.07%` FPR, `99.62%` Precision)**: bắt trọn `7/7` Union, `75/75` Blind Boolean/SSI, `61/61` Time-Delay và `78/78` XSS.
3. **Giải thích CSIC Domain Shift trên Group B (`1.279` mẫu) & vai trò OpenAPI `/tienda1` Schema:**
   - Một request `Parameter Tampering` như `cantidad=-5` hay thêm tham số `B2=abc` là chuỗi văn bản hoàn toàn sạch về mặt cú pháp SQL/XSS/CMD — không một WAF signature hay bộ phân loại mã độc tổng quát nào được phép chặn nếu không biết đặc tả hợp đồng API của `/tienda1` (nếu đoán mò sẽ gây hàng loạt False Positive như Blue Team v1.0 đạt `29.60%` FPR = `444/1.500` chặn oan).
   - Khi thực nghiệm nạp đặc tả OpenAPI `/tienda1` **suy dẫn hoàn toàn chỉ từ 1.500 mẫu Benign (`label == 0`, zero label == 1 leakage)** ([csic2010_tienda1_schema_proof.json](file:///C:/Study/HocKy6/PBL6/docs/reports/csic2010_tienda1_schema_proof.json)):
     - Group B nhảy vọt từ `1.95%` (`25/1.279`) lên **`66.54%` (`851/1.279`)**.
     - Overall CSIC Recall tăng từ `16.40%` (`246/1.500`) lên **`71.47%` (`1.072/1.500`)** ở **`0.00%` FPR** (`100.00%` Precision, `83.36%` F1, `85.73%` Accuracy).
4. **Vì sao dừng Schema ở `71.47%` mà không ép rule bừa để đạt 90%?**
   - `428` mẫu Group B còn lại chủ yếu là giá trị hợp kiểu nhưng sai ngữ nghĩa nghiệp vụ bên trong `/tienda1` (nằm trong dải `min/max` suy dẫn từ Benign). Việc viết thêm rule heuristic ép bắt các chuỗi chữ/số bình thường này sẽ đánh sập `0.00%` Operational FPR trên các ứng dụng REST thực tế (đã kiểm chứng trong [fp_v3_tuning_c3.json](file:///C:/Study/HocKy6/PBL6/docs/reports/fp_v3_tuning_c3.json), nơi chính sách mặc định `route_tiered` cân bằng giữa bảo vệ nghiêm ngặt endpoint có đặc tả và giữ `0.00%` FPR trên `N = 1.715`).

---

## Q3. Vì sao ở Phase E R1 nhóm `SQLI_BLIND_BOOLEAN` tụt `66/75 -> 59/75` và làm sao chứng minh gốc rễ (`9` ca SSI `<!--#include` scoring ML `6.86–66.47`, sửa bằng `CMD-006` + `x-www-form-urlencoded` thay vì hạ ngưỡng ML `90 -> 80`)?

### Bằng chứng định lượng từng ca ([csic2010_blind_boolean_per_case_diff.json](file:///C:/Study/HocKy6/PBL6/docs/reports/csic2010_blind_boolean_per_case_diff.json))
1. **Cấu trúc thật của 75 mẫu legacy `SQLI_BLIND_BOOLEAN`:**
   - Trong `75` dòng gắn nhãn legacy `SQLI_BLIND_BOOLEAN`, có **`25` dòng** là Blind Boolean SQLi thật và **`50` dòng** là chỉ thị **Server-Side Include (`SSI_DIRECTIVE`: `<!--#EXEC` / `<!--#include`)** vốn bị bộ lọc regex cũ gom nhầm vào SQLi vì có chuỗi `--` trong comment HTML `<!-- ... -->`.
2. **Nguyên nhân 9 ca tụt hạng ở Phase E R1 (`fb2fe46`):**
   - Khi retrain XGBoost ở Phase E với `+1.185` mẫu (trong đó có `410` mẫu Benign cứng chống FP), mô hình học phân biệt tốt hơn giữa văn bản HTML/text bình thường với SQLi. Hệ quả là **`9` mẫu `SSI_DIRECTIVE`** (`csic_row_index`: `544, 585, 697, 735, 1047, 1610, 1682, 1919, 2659`, dạng body form `id=2%3C%21--%23include+file%3D%22archivo_secreto%22+--%3E`) bị tụt điểm ML:
     - `8/9` ca có điểm ML Phase E R1 rơi xuống **`6.86 – 66.47`** (cụ thể: row `585`: `6.86`, `697`: `13.06`, `1919`: `13.20`, `1047`: `50.62`, `735`: `52.03`, `544`: `62.97`, `1682`: `65.47`, `2659`: `66.47`).
     - Ca còn lại (`1610`) đạt `82.63` — thấp hơn ngưỡng High-Confidence Override `ML >= 90` và tổng `R_hybrid < 80` ở Op T=80.
   - Kết quả ở R1 khiến nhóm `SQLI_BLIND_BOOLEAN` tụt `66/75 -> 59/75` (giảm 9 ca SSI nêu trên, bù lại +2 ca khác).
3. **Vì sao KHÔNG hạ ngưỡng ML Override từ `90 -> 80`?**
   - Thứ nhất, `8/9` ca có điểm ML `6.86 – 66.47` — hạ ngưỡng `90 -> 80` cũng **không thể cứu** được 8 ca đó.
   - Thứ hai, hạ ngưỡng ML xuống `80` sẽ trực tiếp làm tăng False Positive trên dữ liệu thực (`BENIGN` có biên độ nhạy ở vùng 80–89).
4. **Sửa đúng gốc rễ kỹ thuật (Fix R2) -> `75/75 (100.00%)`:**
   - **(a) Thêm luật `CMD-006`** ([command_injection.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/rules/command_injection.py)): nhận diện chuẩn chỉ thị SSI (`<!--\s*#\s*(?:exec|include|config|echo|fsize|flastmod|printenv)\b`) với `Severity.CRITICAL`, `confidence = 0.95`, sinh `rule_score = 98.5 >= 85.0` (kích hoạt High-Confidence Rule Override).
   - **(b) Giải mã chuẩn `application/x-www-form-urlencoded`:** Bổ sung `parse_qs` trong `RuleEngine._inspect_body` ([engine.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/engine.py)) và đổi `+` -> khoảng trắng trong `normalize_http_for_ml` ([ml_detector.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/ml_detector.py)) để bóc tách chuẩn payload form-encoded.
   - **Kết quả sau sửa:** Toàn bộ `9/9` ca SSI đạt `rule_score = 98.5` (`BLOCKED` ở `Op T=80`), đưa `SQLI_BLIND_BOOLEAN` từ `59/75` lên **`75/75 (100.00%)`** ([csic2010_phase_e_comparison.json](file:///C:/Study/HocKy6/PBL6/docs/reports/csic2010_phase_e_comparison.json)) mà vẫn giữ **`0.00%` Benign FPR**.

---

## Q4. Làm sao đảm bảo Zero-Leakage khi train lại (`47.372` mẫu `defense_v2`, `0` trùng lặp SHA-256 trên 8 cặp giao nhau, khóa SHA-256 Blind Vault trước khi retrain)?

### Quy trình kiểm soát 4 bước (Principle 10 — [zero_leakage_v3_verification.json](file:///C:/Study/HocKy6/PBL6/docs/reports/zero_leakage_v3_verification.json) & [phase_e_augmentation_manifest.json](file:///C:/Study/HocKy6/PBL6/docs/reports/phase_e_augmentation_manifest.json))
1. **Chuẩn hóa mã băm bất biến (Canonical SHA-256):** Mọi mẫu HTTP từ mọi nguồn đều đi qua cùng hàm `SHA-256(canonicalize_payload(canonicalize_http_request(path, query_params, body, headers=None)))` để chống trùng lặp do khác biệt hoa/thường, khoảng trắng hay thứ tự mã hóa.
2. **Khóa Blind Vault v2 TRƯỚC khi chạm tập Train:** Tệp `data/benchmarks/blind_heldout_vault_v2.json` (`30` cases) được khóa bất biến bằng [blind_heldout_vault_v2_lock.json](file:///C:/Study/HocKy6/PBL6/docs/reports/blind_heldout_vault_v2_lock.json) với SHA-256 `f0bf69f6c28a5eb26a4b4a5f749e963ee6568f2cf2d9a8ad2cc76e3edc5a6a8a` tại thời điểm `2026-11-25T01:37:08Z` (`"locked_before_e2_e3_retrain": true`).
3. **Danh sách băm cấm (`16.125` Forbidden Hashes):** Trước khi trộn `1.185` mẫu mới (`417` E2a sandbox + `768` E3 Group A) vào `32.330` dòng Train gốc để thành **`33.515` dòng Train (`47.372` tổng `defense_v2`)**, script `build_phase_e_augmentation.py` thu thập toàn bộ mã băm của `val.csv` (`6.928`), `test.csv` (`6.929`), `csic2010` (`1.592` unique), `benchmark_1000` (`609` unique), `strange_suite_v33` (`38`) và `blind_heldout_vault_v2` (`30`), loại bỏ ngay `6` mẫu va chạm cấm và `228` mẫu trùng nội bộ.
4. **Hậu kiểm độc lập trên cả 8 cặp tập dữ liệu (`zero_leakage_verified = true`):**
   - `train_vs_val = 0`, `train_vs_test = 0`, `val_vs_test = 0`
   - `defense_v2_all_vs_csic2010 = 0`
   - `defense_v2_all_vs_benchmark_1000 = 0`
   - `defense_v2_all_vs_strange_suite_v33 = 0`
   - `defense_v2_all_vs_blind_heldout_vault_v2 = 0`
   - `strange_suite_v33_vs_blind_heldout_vault_v2 = 0`

---

## Q5. Giải thích cơ chế Per-Parameter Max-Pooling, bảo vệ `json_duplicate_key_tamper` (`object_pairs_hook=list` đệ quy JSON lồng nhau + `CMD-003 CRITICAL`), wildcard-glob `CMD-006`, scientific-float `SQLI-007`?

1. **Per-Parameter Max-Pooling (`MLDetector.predict_http` trong [ml_detector.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/ml_detector.py#L706-L786)):**
   - **Vấn đề pha loãng vector:** Khi request có nhiều tham số sạch hoặc payload dài (ví dụ form CSIC có 8 tham số bình thường và 1 tham số chứa `' OR '1'='1`), vector 26-D tính trên toàn bộ request bị giảm mạnh `special_char_ratio` và `entropy`, khiến XGBoost chấm điểm thấp.
   - **Giải pháp:** `predict_http()` chuẩn hóa qua `normalize_http_for_ml` (đổi `+` -> khoảng trắng cho query/form), tính `global_vec` & `global_res`. Nếu request có `>= 2` tham số hoặc tổng độ dài ngữ cảnh `> 40` ký tự, `_extract_http_params` tách từng cặp `(key, value)` (hỗ trợ query, form, JSON và JSON lồng nhau), lọc bỏ giá trị thuần an toàn (`_BENIGN_PARAM_VALUE_RE`), chọn tối đa **2 tham số có mật độ ký tự cú pháp đáng ngờ cao nhất**, chạy `predict()` cục bộ và lấy **`max(global_res.risk_score, param_res.risk_score)`**. Chi phí cực nhỏ nên độ trễ Hybrid inline vẫn giữ `0.803 ms/req`.
2. **Bảo vệ `json_duplicate_key_tamper` ([engine.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/engine.py#L203-L291) & [ml_detector.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/ml_detector.py#L131-L167)):**
   - Nếu parse JSON bằng `json.loads(text)` mặc định, Python tạo `dict` và âm thầm ghi đè key trước bằng key sau (hoặc ngược lại tùy parser backend), khiến payload kiểu `{"host": "8.8.8.8; cmd.exe /c whoami", "host": "8.8.8.8"}` lọt qua kiểm tra dict.
   - Cả `RuleEngine._inspect_body` lẫn `_extract_http_params` đều dùng **`json.loads(..., object_pairs_hook=list)`** để giữ nguyên danh sách cặp `(k, v)` trùng tên, sau đó `_inspect_json_recursive` (`max_depth=32`) duyệt đệ quy cả **chuỗi JSON lồng nhau** (`data.lstrip().startswith(("{", "["))`). Khi phát hiện `cmd.exe /c`, PowerShell hay `certutil`, **`CMD-003`** (`Severity.CRITICAL`, `confidence=0.95`) kích hoạt chặn ngay.
3. **Wildcard-Globbing `CMD-006` ([command_injection.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/rules/command_injection.py#L66-L79)):**
   - Kẻ tấn công né danh sách từ khóa lệnh bằng shell globbing như `; /???/c?t /etc/passwd` hoặc `&& /bin/c?t ...`. Luật `CMD-006` (`CRITICAL`, `confidence=0.95`) bắt mẫu đường dẫn chứa ký tự đại diện `?` / `*` nối sau toán tử `; | & && ||` cũng như các chỉ thị SSI (`<!--#exec`, `<!--#include`, ...).
4. **Scientific-Float `SQLI-007` ([sqli.py](file:///C:/Study/HocKy6/PBL6/gateway/app/security/rules/sqli.py#L258-L272)):**
   - Trong SQL/MySQL, chuỗi `1e0UNION SELECT ...` hay `9e0OR 1=1` được parser số học hiểu là hằng số thực `1e0` đứng sát từ khóa mà không cần khoảng trắng, đánh lừa regex có ranh giới từ `\b` ở đầu. Luật `SQLI-007` (`CRITICAL`, `confidence=0.95`) bắt chính xác mẫu `\b\d+(?:\.\d+)?e[+-]?\d+(?:union|select|or|and|...)`, chuỗi `CHAR()/CHR()` nhiều byte không dùng dấu nháy và truy vấn con `(select case when / sqlite_version() / @@version)`.

---

## Q6. Làm sao Dueling Double-DQN (`74-D`, `36` actions, `800 episodes`) vừa là công cụ Red Team không leak vào Blue vừa là thước đo kiểm định định lượng (Live-HTTP vs `:8056` / `:8055`)?

1. **Tách biệt thông tin Black-Box (Zero Weight/Gradient Leakage):**
   - Tác tử **PyTorch Dueling Double-DQN** ([pentest_dqn_v2_metadata.json](file:///C:/Study/HocKy6/PBL6/attack-lab/models/pentest_dqn_v2_metadata.json): `74-D` state, `36` actions, `seed=42`, `800 episodes` trong `88.719s` = `45.588s` RAM Stages 1–3 + `43.131s` Live-HTTP Stage 4) chỉ tương tác như kẻ tấn công hộp đen: gửi payload đột biến và nhận HTTP status / response score telemetry; hoàn toàn **không đọc trọng số, gradient hay ngưỡng nội bộ** của Blue Team.
   - Tập kiểm định `Blind Held-Out Vault v2` được khóa SHA-256 trước khi chạy E2/E3 và chỉ mở để đối đầu 1 lần sau khi đóng băng mô hình phòng thủ.
2. **Thước đo kiểm định định lượng qua Socket HTTP thật (`:8056` Rules-Only vs `:8055` Hybrid):**
   - **Stage 4 Greedy Eval (`12` training cases):** DQN vượt `:8056` Rules-Only **`25.0%` (`3/12`)**, trong khi vượt `:8055` Hybrid chỉ còn **`8.33%` (`1/12`)**.
   - **Strange Suite v3.3 (`38` cases x `3` passes = `114` episodes, [strange_suite_v33_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/strange_suite_v33_results.json)):** Live-HTTP DQN vs `:8056` Rules-Only bị chặn `92.11%` (`105/114`, lọt `9`), còn vs `:8055` Hybrid v3.3 bị chặn **`100.00% (114/114)`** trên cả 6 ô Hybrid (In-Process & Live-HTTP).
   - **Blind Held-Out Vault v2 (`30` cases):** Ở lượt đo đơn khóa SHA-256 ([blind_heldout_vault_v2_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/blind_heldout_vault_v2_results.json)), Live-HTTP DQN vs `:8056` = `46.67%` (`14/30`, lọt `16`), trong khi `:8055` Hybrid v3.3 chặn **`86.67%` (`26/30`)** DQN/Random và **`93.33%` (`28/30`)** Static Replay; sau khi vá F2b case-14 duplicate-key (`postfix2`, [blind_heldout_vault_v2_postfix2_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/blind_heldout_vault_v2_postfix2_results.json)), cả **6/6 ô Hybrid** đạt **`100.00% (30/30)`**.

---

## Q7. Giải thích sự khác biệt giữa độ trễ In-Process (`0.803 ms`), HTTP 2-Hop E2E (`4.138 ms`), SLA 2 tầng (`<= 1.5 ms` / `<= 5.5 ms`) và ảnh hưởng của Power Plan?

1. **In-Process Single-Pass (`0.803 ms` mean, P95 `1.465 ms` — [ablation_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/ablation_results.json)):**
   - Đo thuần thời gian CPU của pipeline kiểm tra bảo mật trên RAM (`InputNormalizer + 28 Rules + 26-D + XGBoost v2 + IForest v2 + DecisionEngine`, tái dùng vector 26-D 1 lần), phục vụ **Tầng SLA 1 (`<= 1.5 ms` inline WAF engine budget)**.
2. **HTTP 2-Hop Socket E2E (`4.138 ms` mean, `p50 = 3.777 ms`, `p95 = 6.275 ms`, `p99 = 8.058 ms`, `233.7 RPS` tuần tự trên `3.000` mẫu CSIC — [latency_e2e_v3_csic.json](file:///C:/Study/HocKy6/PBL6/docs/reports/latency_e2e_v3_csic.json)):**
   - Đo toàn trình thực tế qua TCP Keep-Alive: `httpx.Client -> Uvicorn WAF :8055 -> Uvicorn Upstream :5055`.
   - Khoảng chênh `+3.335 ms` so với In-Process đến từ chi phí thực của hệ điều hành và proxy: 2 chặng parse/serialize HTTP qua loopback TCP socket, chuyển luồng `anyio.to_thread.run_sync`, kiểm tra `BOLADetector` + `SchemaValidator` (`route_tiered`) + `ResponseDLPGuard`, và `BackgroundTasks` SQLite WAL commit. Con số `4.138 ms` đạt chuẩn **Tầng SLA 2 (`<= 5.5 ms` full HTTP 2-hop proxy E2E)**.
3. **Ảnh hưởng của Windows Power Plan:**
   - Trường `host_power_telemetry` trong [latency_e2e_v3_csic.json](file:///C:/Study/HocKy6/PBL6/docs/reports/latency_e2e_v3_csic.json) ghi nhận đo thực tế trên `Intel Core i5-10300H @ 2.50 GHz` dưới chế độ **`High performance` (`6fecc5ae-f350-48a5-b669-b472cb895ccf`)**, giữ xung nhịp ổn định `2496.0 MHz` (`cpu_load_pct = 6.4%`). Nếu chạy dưới chế độ *Balanced / Power Saver*, Windows hạ xung nhịp CPU khi idle giữa các request khiến độ trễ trung bình và P95 tăng giả tạo; do đó quy trình đo chuẩn bắt buộc cố định `High performance` và ghi kèm telemetry vào artifact.

---

## Q8. Tách biệt container khi triển khai thực tế (`docker-compose.yml` không mount `./attack-lab`, non-root UID 1001, BFF server-side `X-API-Key`) và cách demo Live Arena + Replay + Export Evidence D4 ngay trên Dashboard?

1. **Cô lập container triển khai thực tế ([docker-compose.yml](file:///C:/Study/HocKy6/PBL6/docker-compose.yml)):**
   - **4 Container tách biệt, không mount `./attack-lab`:** `docker compose up --build -d` khởi chạy 1 lệnh (không cần `.env` nhờ default fallback) cụm 4 container `healthy`: `pbl6-vulnerable-api` (`127.0.0.1:5000`), `pbl6-ml-engine` (`127.0.0.1:8001` — xác thực SHA-256 + 26-D smoke inference), `pbl6-gateway` (`:8000`) và `pbl6-dashboard` (`:3000`). `pbl6-gateway` chỉ mount `./data:/app/data`, `./ml-engine/artifacts:/app/ml-engine/artifacts:ro` và `./ml-engine/features:/app/ml-engine/features:ro`. Mã nguồn Red Team (`./attack-lab`) hoàn toàn không tồn tại trong container phòng thủ (`arena.py` tự động fallback an toàn sang catalog tích hợp).
   - **Non-root UID `1001`:** `pbl6-gateway`, `pbl6-ml-engine` và `pbl6-vulnerable-api` chạy dưới `USER appuser`, `pbl6-dashboard` chạy dưới `USER nextjs`.
   - **Cô lập mạng & BFF Secret:** `pbl6-vulnerable-api` và `pbl6-ml-engine` chỉ bind loopback host (`127.0.0.1:5000` / `:8001`); `WAF_MODE` mặc định `ACTIVE_BLOCKING`; mọi yêu cầu từ trình duyệt đi qua **Next.js Server-Side BFF Proxy** (`/api/gateway/*`), tự động gắn `X-API-Key` ở phía server nên **`0` secret tồn tại trong client bundle**, truy cập trực tiếp không có key tới `:8000/dashboard/*` nhận `HTTP 401 Unauthorized`.
2. **Quy trình Demo trực tiếp trên Dashboard (`http://localhost:3000` & `/arena`):**
   - **Đấu Trường AI Live-HTTP (`/arena` — [arena/page.tsx](file:///C:/Study/HocKy6/PBL6/dashboard/src/app/arena/page.tsx)):** Chọn chế độ **`Live HTTP (/api/proxy)`** (mặc định), chọn cấp độ (`1. No WAF` / `2. Rules Only` / `3. Hybrid v3.0`), chọn họ tấn công hoặc nhập `Custom Payload`, tích `Sync -> SOC`, rồi bấm **`Chạy Pentest AI`** -> toàn bộ đòn đánh đi thật qua Reverse Proxy `/api/proxy` (`8/8` blocked/redacted trên Docker demo sạch, xem trực tiếp bảng `Rule / XGBoost 26-D / IForest 26-D`).
   - **Traffic Replay (`POST /pentest/replay`):** Bấm nút **`Replay Traffic`** ngay trên thanh điều khiển `/arena` (hoặc trong `Lịch sử`) để phát lại đúng các HTTP request đã ghi qua Gateway `/api/proxy`; UI hiển thị huy hiệu đối chiếu (`matched=8/8, 100.0%`).
   - **Replay 100 Benchmark (`POST /pentest/replay-benchmark`):** Bấm **`Replay 100 Benchmark`** để chạy lại `100` request thật từ `csic_2010_benchmark.csv` (`50` Benign + `50` Attack, `TP=42`, `TN=50`, `FP=0`, `op_fpr_pct=0.0%`) và đối chiếu trực tiếp khớp `0.000%` trong `fp_v3_measurement.json`.
   - **Export Evidence (D4) & In A4 (`POST /pentest/export`, `window.print()`):** Bấm **`Export Evidence (D4)`** để ghi file bằng chứng bất biến gắn SHA-256 và `git_head_sha` thật (`docs/reports/history/arena_live_*.json` trên repo hoặc `/app/data/arena_evidence/` trong Docker — đã kiểm chứng `arena_live_20261125_064412_ed7e0ef.json`, SHA-256 `ca0ffc73e130f3ec24bdb43356ce4a1aebe2712d59383d180ca392c99d4c9f43`, tái tạo 100% qua `sha256_reproduce_cmd`) đồng thời tải xuống máy, hoặc bấm **`In Báo Cáo A4`**; toàn bộ khớp bảng đối chiếu **`33/33 VERIFIED PASS`** tại [THESIS_ARTIFACT_RECONCILIATION_MATRIX.md](file:///C:/Study/HocKy6/PBL6/docs/reports/THESIS_ARTIFACT_RECONCILIATION_MATRIX.md).

---

## Q9. Tại sao Stage-3 Reward của Dueling Double-DQN lại mang giá trị âm (`-4.33` / `-5.45`), và vì sao việc ép thưởng Stage 3 thành dương sẽ phá hỏng chuẩn căn chỉnh RL (Reward Hacking)?

### 1. Số liệu thực nghiệm xác minh qua các phiên bản
- **Mô hình hiện hành (`v3.3`, `74-D` state, `36` actions, `800 episodes`, `seed=42`):**
  - Cửa sổ biên ([pentest_dqn_v2_metadata.json](file:///C:/Study/HocKy6/PBL6/attack-lab/models/pentest_dqn_v2_metadata.json), `[:30]` cho Stage 1 và `[-30:]` cho Stages 2–3): **`Stage 1 = +48.37`** (bypass `86.11%`) -> **`Stage 2 = +29.27`** (bypass `62.22%`) -> **`Stage 3 = -4.33`** (bypass `16.67%`).
  - Trung bình toàn stage ([pentest_dqn_v2_convergence.json](file:///C:/Study/HocKy6/PBL6/attack-lab/models/pentest_dqn_v2_convergence.json), `stage_metrics_summary`): `Stage 1 = +48.11`, `Stage 2 = +26.39`, **`Stage 3 Hybrid = -5.45`** (bypass `15.83%`), `Stage 4 Live-HTTP Rules-Only (:8056) = -1.33` (bypass `26.17%`), **`Stage 4 Live-HTTP Hybrid (:8055) = -9.34`** (bypass `7.83%`).
- **Lịch sử đối chiếu `v3.0` (`64-D/26-A`) trong git:**
  - Bản `360 episodes` (commit `915211e`): `Stage 1 = +58.0`, **`Stage 3 = -6.69`** (bypass `10.56%`).
  - Bản `600 episodes` (commit `ec43d91`): `Stage 1 = +45.37`, `Stage 2 = +23.27`, **`Stage 3 = -14.32`** (bypass `0.00%`).

### 2. Cơ chế hàm thưởng MDP & bằng chứng hội tụ hành vi né đòn
Theo hàm `compute_pentest_reward()` ([pentest_env.py](file:///C:/Study/HocKy6/PBL6/attack-lab/environment/pentest_env.py#L357-L394)):
- Chỉ khi tấn công vượt qua thành công (`2xx`, không bị WAF chặn hay DLP che) tác tử mới nhận thưởng lớn **`+10.0`**.
- Mọi lần bị chặn **HTTP 403/400** đều chịu phạt ròng `-1.2 + 2.5 * score_drop` (với `score_drop = max(0.0, prev_threat_score - new_threat_score) / 100.0`); bị **Response DLP** che nhận `-1.2`; bị **HTTP 429** nhận `-2.5`; thử lặp lại hành động đã thất bại (`already_tried`) nhận **`-3.0`**.
- Hành động chuyển mục tiêu thông minh **`pivot_next_endpoint`** (sau `>= 2` lần bị chặn liên tiếp với `prev_threat_score >= 80.0`) nhận **`+2.2`** (ngược lại chuyển bừa bị `-0.6`).
- Khi đối đầu **Hybrid v3.x** (tỷ lệ chặn **83%–100%** tùy giai đoạn/mô hình), Blue Team thắng áp đảo trong trò chơi tổng bằng không (**zero-sum competition**). Tác tử Red Team vẫn học tối ưu hóa hành vi rất rõ: số lần thử mù lặp lại **`blind_retries` giảm `42.31%`** (từ **`3.90 -> 2.25`** trong `pentest_dqn_v2_convergence.json`, `stage3_avg_stealth_efficiency = 0.4161` cuối Stage 3 và `0.4311` ở Stage 4), nhưng tổng điểm tích lũy theo episode vẫn âm (`-4.33` / `-5.45` / `-9.34`).

### 3. Vì sao tuyệt đối KHÔNG ép Stage-3 Reward thành dương?
- Như đã khóa rõ trong [train_pentest_dqn.py](file:///C:/Study/HocKy6/PBL6/attack-lab/models/train_pentest_dqn.py#L1026) (`# Interleave legacy_rules & hybrid_v3 without artificially forcing Stage 3 rewards positive`), việc chỉnh hàm thưởng giả tạo (như tăng thưởng pivot lên `+10` hoặc xóa phạt `403/429`) sẽ gây ra **Reward Hacking**: tác tử học cách "cày điểm dương giả" bằng thao tác pivot vô nghĩa thay vì tìm đột biến vượt rào thực sự. Điểm âm ở Stage 3/4 chính là bằng chứng khách quan nhất khẳng định Blue Team Hybrid thực sự chiếm ưu thế trước RL Red Team.

---

## Q10. Vì sao báo cáo lịch sử từng ghi nhận độ trễ E2E `11.74 ms` — con số này có mâu thuẫn với SLA `<= 5.5 ms` hay không?

### 1. Nguồn gốc thực nghiệm của `11.74 ms` (Outlier do máy đang tải / chưa khóa Power Plan)
- **Phép đo lịch sử trên máy tải nặng / hạ xung (commit `3959319`, `2026-11-24T13:31:45+0700`, 25 rules, chưa ghi nhận chế độ `High performance`):**
  - Thực thi `3.000` request CSIC qua 2-hop TCP HTTP mất tổng **`36.25s`** (`82.8 RPS`), cho **`mean = 11.74 ms`** (`p50 = 11.06 ms`, `p95 = 15.967 ms`, `p99 = 19.271 ms`).
- **Chuỗi phép đo chuẩn trên máy rỗi khóa `High performance` (`Intel Core i5-10300H @ 2.50GHz`, cố định `2496.0 MHz`):**
  - **25 rules không nghẽn (commit `ec43d91`, `2026-11-24T16:39:44+0700`):** **`4.203 ms`** mean (`p50 = 4.043 ms`, `p95 = 5.443 ms`, `p99 = 6.261 ms`, `13.03s`, `230.2 RPS`).
  - **26 rules `High performance` (commit `2a3969f`, `2026-11-24T23:09:10+0700`, `cpu_load_pct = 0.0%`):** **`3.773 ms`** mean (`p50 = 3.532 ms`, `p95 = 5.298 ms`, `p99 = 7.003 ms`, `255.6 RPS`). *(Lưu ý tránh nhầm đơn vị: trường `wall_clock_seconds = 11.74` ở commit `2a3969f` là tổng thời gian **11.74 giây** chạy hết 3.000 request, KHÔNG phải độ trễ 11.74 ms/request)*.
  - **Phase E — 28 rules (commit `2285ec2`, `2026-11-25T11:07:40+0700`, `cpu_load_pct = 6.4%`):** **`3.839 ms`** mean (`p50 = 3.584 ms`, `p95 = 5.53 ms`, `p99 = 6.718 ms`, `11.91s`, `252.0 RPS`).
  - **Phase F hiện hành — 28 rules + Per-Param Max-Pooling ([latency_e2e_v3_csic.json](file:///C:/Study/HocKy6/PBL6/docs/reports/latency_e2e_v3_csic.json), `2026-11-25T12:58:38+0700`):** **`4.138 ms`** mean (`p50 = 3.777 ms`, `p95 = 6.275 ms`, `p99 = 8.058 ms`, `12.84s`, `233.7 RPS`), với độ trễ AI/WAF nội tiến trình đạt **`0.803 ms`** ([ablation_results.json](file:///C:/Study/HocKy6/PBL6/docs/reports/ablation_results.json)).

### 2. Hợp đồng Dual-Tier SLA & cơ chế dung sai Gate 5 trên VM dùng chung
- Trong [verify_quality_gates.py](file:///C:/Study/HocKy6/PBL6/scripts/verify_quality_gates.py), hệ thống tách bạch rõ hai cấp kiểm soát để không đánh tráo chuẩn Production với nhiễu phần cứng CI/VM:
  - **SLA Production không tranh chấp (Uncontended Dual-Tier SLA):** **Gate 1** khóa **`mean <= 5.5 ms`** cho toàn trình 2-hop TCP HTTP (`4.138 ms <= 5.5 ms` -> PASS) và **Gate 2** khóa **`mean <= 1.5 ms`** cho bộ lọc AI/WAF inline (`0.803 ms <= 1.5 ms` -> PASS).
  - **Gate 5 (Shared VM Anti-Degradation Guard):** Cho phép độ trễ tức thời khi chạy trên máy ảo dùng chung / CI có tranh chấp tài nguyên (`E2E <= 15.0 ms / Inline <= 3.5 ms`). Vì vậy, outlier `11.74 ms` ở bản đo tải nặng ban đầu (`3959319`) vẫn nằm trong ngưỡng dung sai VM dùng chung (`<= 15.0 ms`) do Windows hạ xung/tranh chấp CPU, trong khi SLA vận hành chuẩn trên môi trường không bị bóp xung luôn ổn định ở mức `3.773 – 4.203 ms` (`<= 5.5 ms`).
