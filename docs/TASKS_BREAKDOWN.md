# BẢNG PHÂN RÃ CÔNG VIỆC CHI TIẾT (WBS) — NHÓM 2 THÀNH VIÊN

Tài liệu phân rã chi tiết toàn bộ các giai đoạn (Phase 0 → Phase 12) của dự án **PBL6 — Web API Security Platform** thành các Task cụ thể, được tối ưu hóa cho **nhóm 2 thành viên** theo đúng quy định tại Mục 33B của [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).

---

## 👥 1. MA TRẬN PHÂN CÔNG TRÁCH NHIỆM (2-MEMBER TEAM MATRIX)

| Thành Viên | Phân Vai Trọng Tâm | Trách Nhiệm Kỹ Thuật Chính |
| :--- | :--- | :--- |
| **Thành viên A (`vcongggggg`)** | **Tech Lead / Blue Team Lead & Defense AI/ML Engineer (Phòng Thủ & Mô Hình WAF)**<br/>*Vị trí: MÁY 1 (Target API, Gateway, SOC UI, Defense ML Models)* | • Xây dựng ứng dụng mục tiêu `vulnerable-api` (6 endpoints lỗ hổng chuẩn).<br/>• Hạ tầng Reverse Proxy Gateway (`gateway/app/api/proxy.py` lắng nghe `0.0.0.0:8000`).<br/>• Rule Engine, Input Normalizer, Bảng `security_events`.<br/>• Rate Limiter cửa sổ trượt (Sliding Window HTTP 429).<br/>• Decision Engine (ALLOW / MONITOR / RATE_LIMIT / BLOCK 403).<br/>• **Feature Engineering:** Trích xuất 17 đặc trưng payload & HTTP (`ml-engine/features/`).<br/>• **Dataset Generation:** Sinh tập dữ liệu huấn luyện Benign + Malicious (`data/`).<br/>• **Supervised Model:** Huấn luyện Random Forest & xuất `rf_model.joblib`.<br/>• **Anomaly Model:** Huấn luyện Isolation Forest & xuất `iforest_model.joblib`.<br/>• Tích hợp Inference nạp 2 model ML vào Gateway ($<15\text{ms}$ và $<10\text{ms}$).<br/>• Xây dựng toàn bộ Next.js Dashboard UI (`dashboard/`).<br/>• Đo lường hiệu năng & độ trễ Gateway dưới tải (Task 11.3). |
| **Thành viên B (`naocavang08`)** | **Red Team Lead & Offensive AI Engineer (Tác Tử AI Tấn Công & Evasion Model)**<br/>*Vị trí: MÁY 2 (Autonomous Red Teaming / Attack Lab)* | • Tự động trinh sát bề mặt tấn công OpenAPI spec từ Máy 1 (`attack-lab/agent/recon.py`).<br/>• Xây dựng môi trường mô phỏng chuỗi tấn công Attack Graph & Action Space (`attack-lab/agent/planner.py`).<br/>• **Offensive AI Model:** Tự thiết kế kiến trúc & huấn luyện mô hình né tránh WAF bằng PyTorch nội bộ: Deep Reinforcement Learning (DQN) / Adversarial Payload Generator (`attack-lab/models/evasion_agent.pt`), **KHÔNG dùng OpenAI API**.<br/>• Xây dựng CLI runner thực thi chiến dịch tấn công độc lập qua mạng LAN (`attack-lab/runner.py`).<br/>• Đánh giá khả năng chống tấn công Evasion bằng AI (Task 11.2) và đồng biên soạn Báo cáo đồ án. |

---

## 📊 2. BẢNG PHÂN RÃ CHI TIẾT TẤT CẢ CÁC PHASE (PHASE 0 → PHASE 12)

### 🟢 CÁC PHASE ĐÃ HOÀN THÀNH (100% DONE)

* **Phase 0 — Project Bootstrap & Codebase Foundation:** Monorepo, Docker Compose, FastAPI foundation, Next.js foundation, SQLite schema, CI workflow. *(Thành viên A & B)*
* **Phase 1 — Real API Gateway Infrastructure:** Dynamic Reverse Proxy, X-Request-ID, header redaction, SQLite traffic logging (`requests`), `/health/target` probe. *(Thành viên A)*
* **Phase 2 — Rule Engine / Signature Detection:** 16 rules tĩnh (SQLi, XSS, Path, Cmd), Input Normalizer bounded 16KB/depth 3, Rule Risk Score 0-100, `security_events` table, 33/33 tests pass. *(Thành viên A)*
* **Phase 2B — Custom Vulnerable Web API (`vulnerable-api` - Bookie Bookstore):** Ứng dụng mục tiêu tự xây dựng làm chủ 100% mã nguồn với 8 kịch bản lỗ hổng chuẩn OWASP Web & API Top 10 (SQLi Auth Bypass, SQLi UNION Search, Stored/Reflected XSS, Path Traversal, Command Injection, BOLA/IDOR, SSRF, Mass Assignment) + Excessive Data Exposure + OpenAPI 3.0 Recon spec. Issues: #57, #58, #59, #60, #61, #64 (Merged qua PR #62). *(Thành viên A)*
* **Phase 9 — SOC Dashboard UI & Real-Time Visualization (100% DONE):** 6 Dashboard REST APIs, 4 KPI cards, Quick Simulator 1-click test, Area & Donut Charts, Bảng Live Events phân biệt IP mạng LAN vs localhost, Payload Evidence Drawer, Reset Demo API, Detection Explainability Modal (#38) phân rã 3 tầng phòng thủ Rule 40% + RF 35% + IF 25%. Issues: #35, #36, #37, #38, #63. *(Thành viên A)*

---

### 🟢 PHASE 3: FEATURE ENGINEERING (ĐẶC TRƯNG DỮ LIỆU) — (100% HOÀN THÀNH ✅)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-3.1`** | `#14` | **Trích xuất đặc trưng hình thái Payload:** Chiều dài URL/Body, Shannon Entropy đo độ hỗn loạn, tỷ lệ ký tự đặc biệt (`'`, `"`, `<`, `>`, `;`, `%`, `\`). | **Thành viên A** | **HOÀN THÀNH ✅** | `ml-engine/features/payload.py` |
| **`TASK-3.2`** | `#15` | **Trích xuất đặc trưng từ khóa tấn công:** Tần suất từ khóa SQLi (`UNION`, `SELECT`), XSS (`<script`, `onerror`), Path (`../`), Command (`whoami`, `cat`). | **Thành viên A** | **HOÀN THÀNH ✅** | `ml-engine/features/keywords.py` |
| **`TASK-3.3`** | `#16` | **Trích xuất đặc trưng ngữ cảnh HTTP:** Mã hóa One-hot cho Method (GET, POST...), Content-Type, tỷ lệ tham số query. | **Thành viên A** | **HOÀN THÀNH ✅** | `ml-engine/features/http_context.py` |
| **`TASK-3.4`** | `#17` | **Pipeline Vector hóa 17 chiều:** Kết hợp các bộ trích xuất thành vector 17 chiều chuẩn hóa (`numpy.ndarray`) có Min-Max scaling. | **Thành viên A** | **HOÀN THÀNH ✅** | `ml-engine/features/extractor.py` |
| **`TASK-3.5`** | `#18` | **Unit Test Suite cho Feature Extractor:** Bộ kiểm thử tự động xác minh tính đúng đắn trên các tập dữ liệu mẫu và trường hợp biên (edge cases). | **Thành viên A** | **HOÀN THÀNH ✅** | `ml-engine/tests/test_features.py` |

---

### 🔵 PHASE 4: DATASET GENERATION & LAB TRAFFIC COLLECTION

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-4.1`** | `#19` | **Sinh tập dữ liệu hợp lệ (Benign Dataset):** Tạo 10,000 requests hợp lệ mô phỏng tương tác bình thường của người dùng trên vulnerable-api. | **Thành viên A** | **HOÀN THÀNH ✅** | `data/synthetic_benign.csv` |
| **`TASK-4.2`** | `#20` | **Sinh tập dữ liệu tấn công đa dạng (Malicious Dataset):** Tạo các biến thể payload SQLi, XSS, Path Traversal, Cmd Injection kèm làm rối (Obfuscation). | **Thành viên A** | **HOÀN THÀNH ✅** | `data/synthetic_attacks.csv` |
| **`TASK-4.3`** | `#21` | **Tiền xử lý & Chia Stratified Split cho Model Tấn Công:** Làm sạch dữ liệu tấn công, gán nhãn 4 lớp (`1: SQLI, 2: XSS, 3: PATH, 4: CMD`), chia phân tầng tỷ lệ 70/15/15 cho Model Tấn công (Offensive AI). | **Thành viên A** | **HOÀN THÀNH ✅** | `data/processed/attack/train.csv`, `val.csv`, `test.csv` |

---

### 🔵 PHASE 5: SUPERVISED ML — MULTI-MODEL BENCHMARKING & RANDOM FOREST (CHAMPION MODEL)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-5.1`** | `#22` | **Huấn Luyện & Đối Sánh 5 Mô Hình Ứng Viên (Multi-Model Training Pipeline):** Xây dựng pipeline huấn luyện đồng thời 5 mô hình đại diện 5 trường phái (Logistic Regression, Decision Tree, Linear SVM, Random Forest, XGBoost/GBDT) trên tập 20.000 mẫu vector 17 đặc trưng, tối ưu hóa siêu tham số bằng `GridSearchCV` / K-Fold CV. | **Thành viên A** | **HOÀN THÀNH ✅ (PR #82)** | `ml-engine/models/train_rf.py`, `evaluate.py`, `benchmark_summary.json` |
| **`TASK-5.2`** | `#23` | **Đánh Giá Toàn Diện, Báo Cáo Đối Sánh & Ma Trận Nhầm Lẫn:** Đo lường đa tiêu chí (Accuracy, Precision, Recall, F1-Score, FPR, Youden's Index $J \ge 0.90$, Độ trễ suy luận trên CPU $< 15\text{ms}$), xuất bảng so sánh 5 mô hình, Confusion Matrix của Champion Model và Presentation Notebook. | **Thành viên A** | **SẴN SÀNG TẠO PR 🚀** | `docs/reports/rf_evaluation.md`, `ml-engine/notebooks/01_train_and_benchmark.ipynb` |
| **`TASK-5.3`** | `#24` | **Đóng Gói Champion Model Artifact, Metadata & Kiểm Thử Gateway:** Đóng gói mô hình vô địch `rf_model.joblib` kèm `rf_metadata.json` (schema 17 features, version, thresholds, metrics) cho Gateway nạp nóng; kiểm thử tích hợp Gateway WAF đảm bảo sub-15ms latency budget. | **Thành viên A** | CHƯA BẮT ĐẦU (Chờ PR 5.2) | `ml-engine/artifacts/rf_model.joblib`, `rf_metadata.json` |
| **`TASK-5.4`** | `#25` | **Tích hợp Model Inference vào FastAPI Gateway:** Nạp model vào bộ nhớ RAM khi Gateway khởi động, dự đoán thời gian thực với độ trễ $< 15\text{ms}$, trích xuất 17 đặc trưng nhanh, và tích hợp `rf_score` vào `RiskEngine`. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/security/ml_detector.py` |

---

### 🔵 PHASE 6: ANOMALY DETECTION — ISOLATION FOREST

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-6.1`** | `#26` | **Huấn luyện Isolation Forest trên Baseline Benign:** Huấn luyện mô hình chỉ trên dữ liệu hợp lệ để học phân bố lưu lượng chuẩn. | **Thành viên A** | CHƯA BẮT ĐẦU | `ml-engine/models/train_iforest.py` |
| **`TASK-6.2`** | `#27` | **Chuẩn hóa Điểm Bất Thường (Anomaly Score 0–100):** Chuyển đổi raw decision function của Isolation Forest thành thang điểm rủi ro trực quan từ 0 đến 100. | **Thành viên A** | CHƯA BẮT ĐẦU | `ml-engine/models/train_iforest.py` |
| **`TASK-6.3`** | `#28` | **Kiểm thử Bắt Tấn Công Zero-Day & Obfuscation:** Đánh giá khả năng phát hiện các payload bị làm rối dị biệt mà Rule Engine và RF bỏ sót. | **Thành viên A** | CHƯA BẮT ĐẦU | `docs/reports/anomaly_eval.md` |
| **`TASK-6.4`** | `#29` | **Tích hợp Anomaly Hook vào Request Pipeline:** Nạp Isolation Forest trong RAM ($<10\text{ms}$), chuẩn hóa điểm 0-100, tích hợp vào `RiskEngine`, và ghi nhận trường `anomaly_score` vào `security_events`. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/security/anomaly.py`, `proxy.py` |

---

### 🔵 PHASE 7: HYBRID RISK ENGINE & DECISION ENGINE (100% HOÀN THÀNH ✅)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-7.1`** | `#30` | **Tính Điểm Nguy Cơ Tổng Hợp (Weighted Risk Score):** Công thức hợp nhất: $\text{Score} = 0.40 \times \text{Rule} + 0.35 \times \text{RF} + 0.25 \times \text{Anomaly}$. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/security/risk_engine.py` |
| **`TASK-7.2`** | `#31` | **Chính Sách Ra Quyết Định Đa Ngưỡng (Decision Policy):** Định nghĩa 4 hành động: $<30$ `ALLOW`, $30-60$ `MONITOR`, $60-80$ `RATE_LIMIT`, $>80$ `BLOCK (403)`. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/security/decision.py` |
| **`TASK-7.3`** | `#32` | **Cơ Chế Chặn Thực Tế (Blocking Proxy Middleware):** Khi quyết định là `BLOCK`, ngắt luồng proxy ngay lập tức, trả về HTTP 403 tùy biến an toàn. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/api/proxy.py` |

---

### 🔵 PHASE 8: IP-BASED RATE LIMITING & SLIDING WINDOW TRACKER (100% HOÀN THÀNH ✅)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-8.1`** | `#33` | **Bộ Theo Dõi Cửa Sổ Trượt Theo IP (Sliding Window Tracker):** Quản lý bộ đếm request theo IP trong bộ nhớ RAM với thời gian trượt 60 giây ($O(1)$ deque), phân tách quota theo endpoint scoping (`auth`: 10, `admin`: 15, `files`: 20, `global`: 60). | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/security/rate_limiter.py` |
| **`TASK-8.2`** | `#34` | **Thực Thi Phản Hồi HTTP 429 Too Many Requests:** Tự động chặn tạm thời IP vượt ngưỡng tần suất (RPS limit) kèm header `Retry-After: <sec>`, `X-RateLimit-*`, lưu vết kiểm toán và tích hợp Reverse Proxy. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/api/proxy.py`, `gateway/app/services/security.py` |

---

### 🔵 PHASE 9: SECURITY DASHBOARD UI & REAL-TIME VISUALIZATION

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Trạng Thái | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **`TASK-9.1`** | `#35` | **Xây Dựng REST APIs Thống Kê Dashboard:** Viết các endpoint `GET /api/dashboard/stats`, `/events`, `/timeline`, `/distribution` trên FastAPI Gateway. | **Thành viên A** | **HOÀN THÀNH ✅** | `gateway/app/api/dashboard.py` |
| **`TASK-9.2`** | `#36` | **Thẻ Chỉ Số Tổng Quan & Biểu Đồ Hoạt Động Thời Gian Thực:** Thiết kế 4 KPI Cards và biểu đồ dòng thời gian tấn công sóng kép (Cyan vs Rose) bằng Recharts. | **Thành viên A** | **HOÀN THÀNH ✅** | `dashboard/src/components/ThreatTimelineChart.tsx`, `AttackDistributionChart.tsx` |
| **`TASK-9.3`** | `#37` | **Bảng Quản Lý Sự Kiện An Ninh (Security Events Table):** Bảng có hiển thị Client IP (phân biệt LAN Attacker Máy 2 vs Localhost), tìm kiếm, lọc theo Severity, IP, Attack Type và Payload Evidence Drawer 2 tab đối soát. | **Thành viên A** | **HOÀN THÀNH ✅** | `dashboard/src/components/events/` |
| **`TASK-9.4`** | `#38` | **Màn Hình Giải Thích Quyết Định (Explainability Panel / Modal):** Trực quan hóa tỷ trọng đóng góp rủi ro Rule (40%) + RF (35%) + IF (25%), hiển thị bằng chứng và quyết định phòng thủ của WAF. | **Thành viên A** | **HOÀN THÀNH ✅** | `dashboard/src/components/explain/` |
| **`TASK-9.5`** | `#63` | **Quick Attack Simulator & Reset Demo Data:** Bảng bắn thử nghiệm 5 nút bấm (SQLi, XSS, Path, Cmd, Benign) và endpoint xóa trắng log phục vụ diễn tập trực tiếp. | **Thành viên A** | **HOÀN THÀNH ✅** | `dashboard/src/components/MetricCards.tsx`, `gateway/app/api/dashboard.py` |

---

### 🔵 PHASE 10: AI ATTACK PLANNER (AUTONOMOUS RED TEAMING)

| Mã Task | Issue ID | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :---: | :--- | :---: | :--- |
| **`TASK-10.1`**| `#39` | **Module Thăm Dò Cấu Trúc API (Reconnaissance):** Tác nhân tự động đọc OpenAPI spec của vulnerable-api (Máy 1) qua mạng LAN để lập danh sách endpoint và tham số mục tiêu. | **Thành viên B** | `attack-lab/agent/recon.py` |
| **`TASK-10.2`**| `#40` | **Môi Trường Mô Phỏng Tấn Công & Lập Kế Hoạch Chuỗi (Attack Graph / RL Environment):** Dựng đồ thị tấn công API (State Space, Action Space, Reward Function) phục vụ tác nhân AI đối kháng WAF. | **Thành viên B** | `attack-lab/agent/planner.py`, `attack-lab/environment/` |
| **`TASK-10.3`**| `#41` | **Huấn Luyện Mô Hình Né Tránh WAF Bằng PyTorch (Deep RL DQN / Evasion Model):** Tự xây dựng & huấn luyện mạng nơ-ron bằng **PyTorch** tự học chính sách biến dị payload khi bị WAF chặn 403, xuất `evasion_agent.pt`. **100% In-house, KHÔNG dùng OpenAI API.** | **Thành viên B** | `attack-lab/models/evasion_agent.pt`, `attack-lab/agent/evasion.py` |
| **`TASK-10.4`**| `#42` | **Giao Diện Đấu Trường AI (AI Arena) & Runner:** CLI runner chạy chiến dịch kiểm thử tự động từ Máy 2 và màn hình đối kháng trực tiếp trên Dashboard. | **Thành viên B & A** | `attack-lab/runner.py`, `dashboard/src/components/arena/` |

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
