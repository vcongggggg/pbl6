# BẢNG PHÂN RÃ CÔNG VIỆC CHI TIẾT (WBS) — NHÓM 2 THÀNH VIÊN

Tài liệu phân rã chi tiết toàn bộ các giai đoạn (Phase 0 → Phase 12) của dự án **PBL6 — Web API Security Platform** thành các Task cụ thể, được tối ưu hóa cho **nhóm 2 thành viên** theo đúng quy định tại Mục 33B của [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).

---

## 👥 1. MA TRẬN PHÂN CÔNG TRÁCH NHIỆM (2-MEMBER TEAM MATRIX)

| Thành Viên | Phân Vai Trọng Tâm | Trách Nhiệm Kỹ Thuật Chính |
| :--- | :--- | :--- |
| **Thành viên A (`vcongggggg`)** | **Tech Lead / Blue Team Lead (Phòng Thủ)**<br/>*Vị trí: MÁY 1 (Target API, Gateway, SOC UI)* | • Xây dựng ứng dụng mục tiêu `vulnerable-api` (6 endpoints lỗ hổng chuẩn).<br/>• Hạ tầng Reverse Proxy Gateway (`gateway/app/api/proxy.py` lắng nghe `0.0.0.0:8000`).<br/>• Rule Engine, Input Normalizer, Bảng `security_events`.<br/>• Rate Limiter cửa sổ trượt (Sliding Window HTTP 429).<br/>• Decision Engine (ALLOW / MONITOR / RATE_LIMIT / BLOCK 403).<br/>• Tích hợp Inference nạp model ML vào Gateway ($<15\text{ms}$).<br/>• Xây dựng toàn bộ Next.js Dashboard UI (`dashboard/`). |
| **Thành viên B (`naocavang08`)** | **Red Team Lead (Tấn Công) & AI/ML Engineer**<br/>*Vị trí: MÁY 2 (Autonomous Red Teaming)* | • Feature Engineering: Trích xuất 17 đặc trưng payload & HTTP (`ml-engine/features/`).<br/>• Thu thập & sinh tập dữ liệu huấn luyện Benign + Attack từ `vulnerable-api` (`data/`).<br/>• Huấn luyện mô hình Random Forest & xuất `rf_model.joblib`.<br/>• Huấn luyện mô hình Anomaly Detection Isolation Forest.<br/>• Xây dựng AI Attack Planner Agent (`attack-lab/`) trinh sát và tấn công qua mạng LAN.<br/>• Đo lường Benchmark, đánh giá so sánh, viết Slide & Báo cáo đồ án. |

---

## 📊 2. BẢNG PHÂN RÃ CHI TIẾT TẤT CẢ CÁC PHASE (PHASE 0 → PHASE 12)

### 🟢 CÁC PHASE ĐÃ HOÀN THÀNH (100% DONE)

* **Phase 0 — Project Bootstrap & Codebase Foundation:** Monorepo, Docker Compose, FastAPI foundation, Next.js foundation, SQLite schema, CI workflow. *(Thành viên A & B)*
* **Phase 1 — Real API Gateway Infrastructure:** Dynamic Reverse Proxy, X-Request-ID, header redaction, SQLite traffic logging (`requests`), `/health/target` probe. *(Thành viên A)*
* **Phase 2 — Rule Engine / Signature Detection:** 16 rules tĩnh (SQLi, XSS, Path, Cmd), Input Normalizer bounded 16KB/depth 3, Rule Risk Score 0-100, `security_events` table, 33/33 tests pass. *(Thành viên A)*

---

### 🟡 PHASE 3: FEATURE ENGINEERING (ĐẶC TRƯNG DỮ LIỆU) — *ĐANG TRIỂN KHAI*

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-3.1`** | `#14` | **Trích xuất đặc trưng hình thái Payload:** Chiều dài URL/Body, Shannon Entropy đo độ hỗn loạn, tỷ lệ ký tự đặc biệt (`'`, `"`, `<`, `>`, `;`, `%`, `\`). | **Thành viên B** | `ml-engine/features/payload.py` |
| **`TASK-3.2`** | `#15` | **Trích xuất đặc trưng từ khóa tấn công:** Tần suất từ khóa SQLi (`UNION`, `SELECT`), XSS (`<script`, `onerror`), Path (`../`), Command (`whoami`, `cat`). | **Thành viên B** | `ml-engine/features/keywords.py` |
| **`TASK-3.3`** | `#16` | **Trích xuất đặc trưng ngữ cảnh HTTP:** Mã hóa One-hot cho Method (GET, POST...), Content-Type, tỷ lệ tham số query. | **Thành viên B** | `ml-engine/features/http_context.py` |
| **`TASK-3.4`** | `#17` | **Pipeline Vector hóa 17 chiều:** Kết hợp các bộ trích xuất thành vector 17 chiều chuẩn hóa (`numpy.ndarray`) có Min-Max scaling. | **Thành viên B** | `ml-engine/features/extractor.py` |
| **`TASK-3.5`** | `#18` | **Unit Test Suite cho Feature Extractor:** Bộ kiểm thử tự động xác minh tính đúng đắn trên các tập dữ liệu mẫu và trường hợp biên (edge cases). | **Thành viên B** | `ml-engine/tests/test_features.py` |

---

### 🔵 PHASE 4: DATASET GENERATION & LAB TRAFFIC COLLECTION

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-4.1`** | `#19` | **Sinh tập dữ liệu hợp lệ (Benign Dataset):** Tạo 10,000 requests hợp lệ mô phỏng tương tác bình thường của người dùng trên vulnerable-api. | **Thành viên B** | `data/synthetic_benign.csv` |
| **`TASK-4.2`** | `#20` | **Sinh tập dữ liệu tấn công đa dạng (Malicious Dataset):** Tạo các biến thể payload SQLi, XSS, Path Traversal, Cmd Injection kèm làm rối (Obfuscation). | **Thành viên B** | `data/synthetic_attacks.csv` |
| **`TASK-4.3`** | `#21` | **Tiền xử lý, Gán nhãn & Chia Stratified Split:** Làm sạch dữ liệu, gán nhãn 5 lớp (`0: BENIGN, 1: SQLI, 2: XSS, 3: PATH, 4: CMD`), chia tỷ lệ 70/15/15. | **Thành viên B** | `data/processed/train.csv`, `test.csv` |

---

### 🔵 PHASE 5: SUPERVISED ML — RANDOM FOREST (PHÂN LOẠI ĐA NHÃN)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-5.1`** | `#22` | **Huấn luyện Random Forest & Tối ưu Siêu tham số:** Xây dựng script huấn luyện `RandomForestClassifier` với GridSearchCV (`n_estimators`, `max_depth`). | **Thành viên B** | `ml-engine/models/train_rf.py` |
| **`TASK-5.2`** | `#23` | **Đánh giá Mô hình & Confusion Matrix:** Đo lường Precision, Recall, F1-Score từng lớp và vẽ biểu đồ Ma trận nhầm lẫn (Confusion Matrix). | **Thành viên B** | `docs/reports/rf_evaluation.md` |
| **`TASK-5.3`** | `#24` | **Đóng gói Model Artifact & Metadata:** Xuất mô hình `rf_model.joblib` kèm file JSON lưu danh sách 17 features và ngưỡng phân loại. | **Thành viên B** | `ml-engine/artifacts/rf_model.joblib` |
| **`TASK-5.4`** | `#25` | **Tích hợp Model Inference vào FastAPI Gateway:** Nạp model vào bộ nhớ RAM khi Gateway khởi động, dự đoán thời gian thực với độ trễ $< 15\text{ms}$. | **Thành viên A** | `gateway/app/security/ml_detector.py` |

---

### 🔵 PHASE 6: ANOMALY DETECTION — ISOLATION FOREST

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-6.1`** | `#26` | **Huấn luyện Isolation Forest trên Baseline Benign:** Huấn luyện mô hình chỉ trên dữ liệu hợp lệ để học phân bố lưu lượng chuẩn. | **Thành viên B** | `ml-engine/models/train_iforest.py` |
| **`TASK-6.2`** | `#27` | **Chuẩn hóa Điểm Bất Thường (Anomaly Score 0–100):** Chuyển đổi raw decision function của Isolation Forest thành thang điểm rủi ro trực quan từ 0 đến 100. | **Thành viên B** | `gateway/app/security/anomaly.py` |
| **`TASK-6.3`** | `#28` | **Kiểm thử Bắt Tấn Công Zero-Day & Obfuscation:** Đánh giá khả năng phát hiện các payload bị làm rối dị biệt mà Rule Engine và RF bỏ sót. | **Thành viên B** | `docs/reports/anomaly_eval.md` |
| **`TASK-6.4`** | `#29` | **Tích hợp Anomaly Hook vào Request Pipeline:** Gọi bộ kiểm tra bất thường trong Gateway và ghi nhận trường `anomaly_score` vào `security_events`. | **Thành viên A** | `gateway/app/security/engine.py` |

---

### 🔵 PHASE 7: HYBRID RISK ENGINE & DECISION ENGINE

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-7.1`** | `#30` | **Tính Điểm Nguy Cơ Tổng Hợp (Weighted Risk Score):** Công thức hợp nhất: $\text{Score} = 0.40 \times \text{Rule} + 0.35 \times \text{RF} + 0.25 \times \text{Anomaly}$. | **Thành viên A** | `gateway/app/security/risk_engine.py` |
| **`TASK-7.2`** | `#31` | **Chính Sách Ra Quyết Định Đa Ngưỡng (Decision Policy):** Định nghĩa 4 hành động: $<30$ `ALLOW`, $30-60$ `MONITOR`, $60-80$ `RATE_LIMIT`, $>80$ `BLOCK (403)`. | **Thành viên A** | `gateway/app/security/decision.py` |
| **`TASK-7.3`** | `#32` | **Cơ Chế Chặn Thực Tế (Blocking Proxy Middleware):** Khi quyết định là `BLOCK`, ngắt luồng proxy ngay lập tức, trả về HTTP 403 tùy biến an toàn. | **Thành viên A** | `gateway/app/api/proxy.py` |

---

### 🔵 PHASE 8: IP-BASED RATE LIMITING & SLIDING WINDOW TRACKER

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-8.1`** | `#33` | **Bộ Theo Dõi Cửa Sổ Trượt Theo IP (Sliding Window Tracker):** Quản lý bộ đếm request theo IP trong bộ nhớ RAM với thời gian trượt 60 giây. | **Thành viên A** | `gateway/app/security/rate_limiter.py` |
| **`TASK-8.2`** | `#34` | **Thực Thi Phản Hồi HTTP 429 Too Many Requests:** Tự động chặn tạm thời IP vượt ngưỡng tần suất (RPS limit) kèm header `Retry-After: 60`. | **Thành viên A** | `gateway/app/api/proxy.py` |

---

### 🔵 PHASE 9: SECURITY DASHBOARD UI & REAL-TIME VISUALIZATION

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-9.1`** | `#35` | **Xây Dựng REST APIs Thống Kê Dashboard:** Viết các endpoint `GET /api/stats`, `GET /api/events`, `GET /api/traffic-series` trên FastAPI Gateway. | **Thành viên A** | `gateway/app/api/dashboard.py` |
| **`TASK-9.2`** | `#36` | **Thẻ Chỉ Số Tổng Quan & Biểu Đồ Hoạt Động Thời Gian Thực:** Thiết kế Overview Cards và biểu đồ dòng thời gian tấn công bằng Recharts. | **Thành viên A** | `dashboard/src/components/charts/` |
| **`TASK-9.3`** | `#37` | **Bảng Quản Lý Sự Kiện An Ninh (Security Events Table):** Bảng có tìm kiếm, lọc theo Severity, IP, Attack Type và cửa sổ xem chi tiết payload. | **Thành viên A** | `dashboard/src/components/events/` |
| **`TASK-9.4`** | `#38` | **Màn Hình Giải Thích Quyết Định (Explainability Panel):** Trực quan hóa lý do WAF chặn (Rule nào khớp, Model nào dự đoán, điểm bao nhiêu). | **Thành viên A** | `dashboard/src/components/explain/` |

---

### 🔵 PHASE 10: AI ATTACK PLANNER (AUTONOMOUS RED TEAMING)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-10.1`**| `#39` | **Module Thăm Dò Cấu Trúc API (Reconnaissance):** Tác nhân tự động đọc OpenAPI spec của vulnerable-api (Máy 1) để lập danh sách endpoint và tham số. | **Thành viên B** | `attack-lab/agent/recon.py` |
| **`TASK-10.2`**| `#40` | **Agent Lập Kế Hoạch Tấn Công Đa Bước (ReAct Planner):** Sử dụng LLM suy luận chuỗi tấn công logic (Thăm dò $\rightarrow$ Khai thác SQLi $\rightarrow$ Chiếm quyền). | **Thành viên B** | `attack-lab/agent/planner.py` |
| **`TASK-10.3`**| `#41` | **Cơ Chế Tự Động Làm Rối Payload (Adaptive Evasion Engine):** Khi nhận phản hồi HTTP 403 từ WAF, tự động biến đổi payload (Hex, Double URL) để thử vượt rào. | **Thành viên B** | `attack-lab/agent/evasion.py` |
| **`TASK-10.4`**| `#42` | **Giao Diện Đấu Trường AI (AI Arena) & Runner:** CLI runner chạy chiến dịch kiểm thử tự động và màn hình đối kháng trực tiếp trên Dashboard. | **Thành viên B & A** | `attack-lab/runner.py` |

---

### 🔵 PHASE 11: MULTI-METHOD EVALUATION & BENCHMARK COMPARISON

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-11.1`**| `#43` | **Thực Nghiệm So Sánh 4 Phương Pháp Phòng Thủ:** Đo lường Precision, Recall, F1, FPR giữa (1) Chỉ Rule, (2) Chỉ RF, (3) Chỉ IF, (4) Hybrid. | **Thành viên B** | `docs/reports/benchmark.md` |
| **`TASK-11.2`**| `#44` | **Đánh Giá Khả Năng Chống Tấn Công Evasion Bằng AI:** Thống kê tỷ lệ WAF chặn thành công các payload biến dị do AI Attack Planner sinh ra. | **Thành viên B** | `docs/reports/evasion_benchmark.md` |
| **`TASK-11.3`**| `#45` | **Đo Lường Hiệu Năng & Độ Trễ Gateway Dưới Tải:** Đo độ trễ trung bình, RPS tối đa và mức tiêu thụ RAM/CPU của Gateway khi bật đầy đủ AI. | **Thành viên A** | `docs/reports/performance_profile.md` |
| **`TASK-11.4`**| `#46` | **Tổng Hợp Báo Cáo Đối Chiếu & Biểu Đồ Trực Quan:** Xuất biểu đồ so sánh ROC-AUC, biểu đồ thời gian xử lý phục vụ báo cáo bảo vệ. | **Thành viên B** | `docs/reports/final_evaluation.md` |

---

### 🔵 PHASE 12: FINAL HARDENING, AUDIT LOGS & PRODUCTION DEFENSE REPORT

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-12.1`**| `#47` | **Tối Ưu Hóa & Rà Soát Bảo Mật Mã Nguồn:** Khử rò rỉ bộ nhớ, kiểm toán bảo mật mã nguồn, chuẩn hóa error handlers an toàn tuyệt đối. | **Thành viên A** | Gateway release candidate |
| **`TASK-12.2`**| `#48` | **Kiểm Thử Sạch Cụm Docker Compose Multi-Container:** Đảm bảo toàn bộ 3 dịch vụ (Gateway, Dashboard, vulnerable-api) khởi động 1 lệnh `docker compose up`. | **Thành viên A** | `docker-compose.yml` verified |
| **`TASK-12.3`**| `#49` | **Kịch Bản & Script Chạy Thử Nghiệm Live Demo 10 Phút:** Chuẩn bị script tự động kích hoạt đợt tấn công của AI để biểu diễn trực tiếp trước Hội đồng. | **Thành viên A & B** | `scripts/demo_rehearsal.py` |
| **`TASK-12.4`**| `#50` | **Hoàn Thiện Báo Cáo Đồ Án PBL6 & Slide Thuyết Trình:** Soạn thảo báo cáo PDF hoàn chỉnh theo mẫu trường và thiết kế slide thuyết trình bảo vệ. | **Thành viên A & B** | `docs/PBL6_FINAL_REPORT.pdf` & Slides |
