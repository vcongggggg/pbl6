# BẢNG PHÂN RÃ CÔNG VIỆC CHI TIẾT (WORK BREAKDOWN STRUCTURE - WBS)

Tài liệu phân rã chi tiết các Phase của dự án **PBL6 — Web API Security Platform** thành các Task cụ thể, có phân công vai trò (Member A, B, C, D) và tiêu chí nghiệm thu rõ ràng.

---

## 👥 Ma Trận Phân Công Vai Trò (Team Roles)

| Vai trò | Phụ trách chính | Trọng tâm công việc |
| :--- | :--- | :--- |
| **Thành viên A** | Tech Lead / Backend Security | Gateway Reverse Proxy, Rule Engine, Rate Limiter, Decision Engine |
| **Thành viên B** | ML / Data Engineer | Feature Engineering, Dataset Collection, Random Forest, Isolation Forest |
| **Thành viên C** | Frontend / Offensive AI | Next.js Dashboard UI, AI Attack Planner Agent (`attack-lab/`) |
| **Thành viên D** | QA / Security Analyst / Docs | Benchmark Evaluation, Testing, Slide, Báo cáo đồ án |

---

## 📌 GIAI ĐOẠN 1: TẦNG PHÒNG THỦ MACHINE LEARNING (PHASE 3 → 8)

### 🔹 Phase 3: Feature Engineering (Đặc Trưng Dữ Liệu)
*Mục tiêu: Xây dựng module trích xuất 17 đặc trưng payload và các đặc trưng hành vi HTTP từ request.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-3.1`** | **Trích xuất đặc trưng hình thái Payload:** Tính chiều dài URL, chiều dài Body, Shannon Entropy của chuỗi, tỷ lệ ký tự đặc biệt (`'`, `"`, `<`, `>`, `;`, `%`). | Thành viên B | `ml-engine/features/payload.py` |
| **`TASK-3.2`** | **Trích xuất đặc trưng từ khóa tấn công:** Đếm tần suất xuất hiện các từ khóa SQL (`UNION`, `SELECT`, `OR`), XSS (`<script>`, `onerror`), Path (`../`), Command (`whoami`, `cat`, `;`). | Thành viên B | `ml-engine/features/keywords.py` |
| **`TASK-3.3`** | **Trích xuất đặc trưng ngữ cảnh HTTP:** Mã hóa HTTP Method (GET, POST, PUT, DELETE), Content-Type, số lượng query params, header anomalies. | Thành viên B | `ml-engine/features/http_context.py` |
| **`TASK-3.4`** | **Xây dựng Pipeline Vector hóa 17 chiều:** Kết hợp toàn bộ đặc trưng thành numpy array/pandas vector và chuẩn hóa min-max scaling. | Thành viên B | `ml-engine/features/extractor.py` |
| **`TASK-3.5`** | **Viết Unit Tests cho Feature Extractor:** Kiểm thử trích xuất trên 20 mẫu payload (Benign, SQLi, XSS, Cmd, rỗng, payload dài). | Thành viên D | `ml-engine/tests/test_features.py` |

---

### 🔹 Phase 4: Dataset Generation (Thu Thập & Sinh Dữ Liệu)
*Mục tiêu: Xây dựng tập dữ liệu huấn luyện cân bằng, chất lượng cao.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-4.1`** | **Sinh tập dữ liệu lưu lượng hợp lệ (Benign Dataset):** Tạo 10,000 requests hợp lệ mô phỏng người dùng mua sắm, tìm kiếm, đánh giá trên Juice Shop. | Thành viên B | `data/synthetic_benign.csv` |
| **`TASK-4.2`** | **Sinh tập dữ liệu tấn công (Malicious Dataset):** Tổng hợp và sinh các biến thể SQLi, XSS, Path Traversal, Command Injection (kèm obfuscation/encoding). | Thành viên B | `data/synthetic_attacks.csv` |
| **`TASK-4.3`** | **Tiền xử lý & Chia tập Train/Test/Validation:** Lọc trùng, gắn nhãn chuẩn hóa (`0: BENIGN, 1: SQLI, 2: XSS, 3: PATH, 4: CMD`), chia tỷ lệ 70/15/15 có Stratified Split. | Thành viên B | `data/processed/` & Báo cáo phân bố nhãn |

---

### 🔹 Phase 5: Supervised ML — Random Forest (Phân Loại Đa Nhãn)
*Mục tiêu: Huấn luyện mô hình Random Forest nhận diện loại tấn công với độ chính xác cao.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-5.1`** | **Huấn luyện mô hình Random Forest:** Xây dựng script huấn luyện đa nhãn với tối ưu siêu tham số (GridSearchCV/Optuna: `n_estimators`, `max_depth`). | Thành viên B | `ml-engine/models/train_rf.py` |
| **`TASK-5.2`** | **Đánh giá mô hình & Confusion Matrix:** Đo lường Precision, Recall, F1-score trên tập Test; vẽ ma trận nhầm lẫn (Confusion Matrix). | Thành viên B & D | `docs/reports/rf_evaluation.md` |
| **`TASK-5.3`** | **Đóng gói Model Artifact & Schema:** Xuất file mô hình `rf_model.joblib` kèm metadata phiên bản, ngưỡng phân loại. | Thành viên B | `ml-engine/artifacts/rf_model.joblib` |
| **`TASK-5.4`** | **Tích hợp Model Inference vào FastAPI Gateway:** Viết service nạp mô hình vào bộ nhớ và dự đoán thời gian thực (yêu cầu $< 15\text{ms}$). | Thành viên A | `gateway/app/security/ml_detector.py` |

---

### 🔹 Phase 6: Anomaly Detection — Isolation Forest (Phát Hiện Bất Thường)
*Mục tiêu: Bắt các hành vi bất thường, quét tự động và payload lạ chưa từng thấy.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-6.1`** | **Huấn luyện mô hình Isolation Forest:** Huấn luyện chỉ trên dữ liệu Benign để học ranh giới lưu lượng bình thường. | Thành viên B | `ml-engine/models/train_iforest.py` |
| **`TASK-6.2`** | **Xây dựng Cơ chế Tính Điểm Bất Thường (0–100):** Chuẩn hóa raw anomaly score của Scikit-learn thành điểm rủi ro trực quan. | Thành viên B | `gateway/app/security/anomaly.py` |
| **`TASK-6.3`** | **Kiểm thử khả năng bắt Zero-day / Evasion:** Đưa các payload bị mã hóa dị biệt vào kiểm tra khả năng phát hiện của Isolation Forest. | Thành viên D | `gateway/tests/test_anomaly.py` |

---

### 🔹 Phase 7: Hybrid Risk Engine & Decision Engine (Ra Quyết Định)
*Mục tiêu: Kết hợp đa tầng phòng thủ đưa ra quyết định thực thi.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-7.1`** | **Xây dựng Bộ Tính Điểm Hợp Nhất (Weighted Risk Scoring):** Tổng hợp điểm từ Rule (40%) + Random Forest (35%) + Isolation Forest (25%). | Thành viên A | `gateway/app/security/risk_engine.py` |
| **`TASK-7.2`** | **Xây dựng Decision Engine:** Thiết lập các ngưỡng hành động: $<30$ `ALLOW`, $30-60$ `MONITOR`, $60-80$ `RATE_LIMIT`, $>80$ `BLOCK (403)`. | Thành viên A | `gateway/app/security/decision.py` |
| **`TASK-7.3`** | **Cơ chế Chặn Thực Tế (Blocking Proxy):** Khi quyết định là `BLOCK`, Gateway ngắt kết nối ngay lập tức, trả về HTTP 403 tùy biến an toàn. | Thành viên A | `gateway/app/api/proxy.py` |

---

### 🔹 Phase 8: IP-based Rate Limiting (Kiểm Soát Tần Suất)
*Mục tiêu: Chặn đứng tấn công vét cạn (Brute-force) và DoS tần suất cao.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-8.1`** | **Xây dựng Bộ Theo Dõi Cửa Sổ Trượt (Sliding Window Tracker):** Đếm số lượng request theo từng IP trong khung thời gian 1 phút. | Thành viên A | `gateway/app/security/rate_limiter.py` |
| **`TASK-8.2`** | **Kích hoạt HTTP 429 Too Many Requests:** Tự động chặn tạm thời IP vượt ngưỡng RPS cho phép kèm header `Retry-After`. | Thành viên A | `gateway/app/api/proxy.py` |

---

## 📌 GIAI ĐOẠN 2: TRỰC QUAN HÓA & AI ĐỐI KHÁNG (PHASE 9 → 12)

### 🔹 Phase 9: Security Dashboard UI (Giao Diện Giám Sát Thời Gian Thực)
*Mục tiêu: Hiển thị trực quan dữ liệu phân tích an ninh cho người quản trị.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-9.1`** | **Xây dựng API Backend cung cấp dữ liệu Dashboard:** Viết các endpoint `GET /api/stats`, `GET /api/events`, `GET /api/traffic-series`. | Thành viên A | `gateway/app/api/dashboard.py` |
| **`TASK-9.2`** | **Thiết kế Thẻ Chỉ Số & Biểu Đồ Thời Gian Thực:** Vẽ biểu đồ lượng request, tỷ lệ phát hiện tấn công theo giờ bằng Recharts/Chart.js. | Thành viên C | `dashboard/src/components/charts/` |
| **`TASK-9.3`** | **Bảng Chi Tiết Sự Kiện An Ninh (Security Events Table):** Danh sách sự kiện có lọc theo Severity, IP, Loại tấn công, xem payload evidence. | Thành viên C | `dashboard/src/components/events/` |
| **`TASK-9.4`** | **Màn hình Giải Thích Quyết Định (Explainability Panel):** Trực quan hóa lý do tại sao WAF chặn (Rule nào khớp, Model nào dự đoán, điểm bao nhiêu). | Thành viên C | `dashboard/src/components/explain/` |

---

### 🔹 Phase 10: AI Attack Planner (AI Lập Kế Hoạch Tấn Công Tự Động)
*Mục tiêu: Xây dựng tác nhân AI Red Team kiểm thử thâm nhập tự động.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-10.1`**| **Xây dựng Module Quét Cấu Trúc API (Reconnaissance):** AI Agent tự động đọc file OpenAPI/Swagger của Juice Shop để lập bản đồ endpoint. | Thành viên C | `attack-lab/agent/recon.py` |
| **`TASK-10.2`**| **Xây dựng Bộ Lập Kế Hoạch Đa Bước (ReAct Attack Planner):** Dùng LLM suy luận chuỗi tấn công (Thăm dò $\rightarrow$ Khai thác $\rightarrow$ Chiếm quyền). | Thành viên C | `attack-lab/agent/planner.py` |
| **`TASK-10.3`**| **Cơ chế Tự Động Làm Rối Payload (Adaptive Evasion):** Khi AI nhận mã lỗi 403 từ WAF, tự động suy luận cách mã hóa (Hex, Double URL) để thử vượt rào. | Thành viên C | `attack-lab/agent/evasion.py` |
| **`TASK-10.4`**| **Tích hợp Màn Hình Đối Kháng (AI Arena) trên Dashboard:** Chiếu song song: Nhật ký suy luận của AI Hacker vs Phản ứng ngăn chặn của WAF. | Thành viên C | `dashboard/src/app/arena/page.tsx` |

---

### 🔹 Phase 11 & 12: Đánh Giá, Thực Nghiệm & Hoàn Thiện Báo Cáo
*Mục tiêu: Đo lường khoa học và hoàn thiện đồ án để bảo vệ trước Hội đồng.*

| Mã Task | Tên Task Chi Tiết | Phụ Trách | Đầu Ra (Deliverables) |
| :--- | :--- | :---: | :--- |
| **`TASK-11.1`**| **Thực nghiệm So sánh Đa Phương Pháp:** Lập bảng đo lường F1-score, False Positive Rate (FPR), và độ trễ giữa Rule vs ML vs Anomaly vs Hybrid. | Thành viên D | `docs/reports/benchmark_comparison.md` |
| **`TASK-11.2`**| **Thực nghiệm Khả năng Chống Evasion của AI:** Thống kê tỷ lệ WAF chặn được các payload do AI Attack Planner tự động biến đổi. | Thành viên D | `docs/reports/evasion_defense_test.md` |
| **`TASK-12.1`**| **Rà Soát Bảo Mật & Tối Ưu Hiệu Năng Gateway:** Đảm bảo không rò rỉ bộ nhớ, thời gian proxy trung bình $< 15\text{ms}$. | Thành viên A | Gateway release candidate |
| **`TASK-12.2`**| **Hoàn Thiện Báo Cáo Đồ Án & Slide Thuyết Trình:** Soạn thảo báo cáo PDF chuẩn học thuật, xây dựng kịch bản demo live 10 phút. | Toàn đội | `docs/FINAL_REPORT.pdf` & Slides |
