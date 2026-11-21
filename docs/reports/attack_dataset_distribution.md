# Báo Cáo Phân Bổ Tập Dữ Liệu Model Tấn Công (Task 4.3 — Offensive Dataset Report)

## 1. Tổng Quan Phân Chia Dữ Liệu Model Tấn Công (Stratified Split 70/15/15)

- **Mục đích:** Huấn luyện Tác tử AI Tấn Công (AI Attack Planner & Deep RL DQN Evasion Model — Phase 10).
- **Tổng số mẫu tấn công:** 10,000 HTTP Attack Requests (100% thuần tấn công)
- **Tập Train (70%):** 7,000 samples
- **Tập Validation (15%):** 1,500 samples
- **Tập Test (15%):** 1,500 samples
- **Cố định ngẫu nhiên (Random Seed):** 42
- **Bảo đảm cô lập (Zero Benign Contamination):** 0% mẫu Benign (không chứa nhãn 0).
- **Thư mục lưu trữ Deliverable:** `data/processed/attack/`

---

## 2. Ma Trận Phân Bổ 4 Họ Tấn Công Chuẩn Hóa

| Mã Lớp | Họ Tấn Công (Attack Family) | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) | Tỷ Lệ Chuẩn |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **1** | **SQLI** (SQL Injection) | 2,500 (25.0%) | 1,750 (25.0%) | 375 (25.0%) | 375 (25.0%) | **25.0%** |
| **2** | **XSS** (Cross-Site Scripting) | 2,500 (25.0%) | 1,750 (25.0%) | 375 (25.0%) | 375 (25.0%) | **25.0%** |
| **3** | **PATH** (Path Traversal / LFI) | 2,500 (25.0%) | 1,750 (25.0%) | 375 (25.0%) | 375 (25.0%) | **25.0%** |
| **4** | **CMD** (Command Injection / RCE) | 2,500 (25.0%) | 1,750 (25.0%) | 375 (25.0%) | 375 (25.0%) | **25.0%** |
| **TỔNG** | **4 HỌ TẤN CÔNG** | **10,000 (100%)** | **7,000 (100%)** | **1,500 (100%)** | **1,500 (100%)** | **100.0%** |

---

## 3. Thống Kê Phương Thức & Vị Trí Payload

| Đặc Trưng Kỹ Thuật | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) |
| :--- | :---: | :---: | :---: | :---: |
| **HTTP POST Method** | 5,228 (52.3%) | 3,668 (52.4%) | 771 (51.4%) | 789 (52.6%) |
| **HTTP GET Method** | 4,772 (47.7%) | 3,332 (47.6%) | 729 (48.6%) | 711 (47.4%) |
| **Có Query Parameters** | 3,947 (39.47%) | 2,763 (39.47%) | 606 (40.4%) | 578 (38.53%) |
| **Có Request Body** | 5,228 (52.28%) | 3,668 (52.4%) | 771 (51.4%) | 789 (52.6%) |

---

## 4. Kiểm Định Tính Toàn Vẹn & Mã Băm SHA-256

| Tệp Dữ Liệu | Đường Dẫn Lưu Trữ | Số Bản Ghi | Mã Băm SHA-256 Checksum |
| :--- | :--- | :---: | :--- |
| **Attack Train** | `data/processed/attack/train.csv` | 7,000 | `9e21a9da6fb2a5ca85bd42c5b67d15dc9d9789c31fc94420abf141838bb776d8` |
| **Attack Validation** | `data/processed/attack/val.csv` | 1,500 | `627961446c89993ff9866974f2a23a9111286b0dcd03ec71bfc091b663f86a42` |
| **Attack Test** | `data/processed/attack/test.csv` | 1,500 | `bced48c3d98276c227f3066f777cb81a80b2b47c172f4e1fb7f25707674ece1f` |

---

## 5. Kết Luận Nghiệm Thu (Sign-off)

- [x] Đạt chuẩn tỷ lệ phân tầng 70/15/15 chính xác 25% mỗi lớp tấn công, không bị lệch nhãn.
- [x] Không có mẫu Benign (label 0) lọt vào tập dữ liệu của Model Tấn công.
- [x] Không có hiện tượng rò rỉ dữ liệu (Zero Data Leakage) giữa Train, Validation và Test.
- [x] Đầy đủ 9 cột thuộc tính đồng bộ chuẩn hóa phục vụ huấn luyện Model Tấn công (Offensive AI / Red Team).
