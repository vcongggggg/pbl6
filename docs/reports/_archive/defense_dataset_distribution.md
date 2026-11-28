# Báo Cáo Phân Bổ Tập Dữ Liệu Model Phòng Thủ WAF (Task 4.3 — Defense Dataset Report)

## 1. Tổng Quan Phân Chia Dữ Liệu Model Phòng Thủ (Stratified Split 70/15/15)

- **Mục đích:** Huấn luyện Bộ phân loại học máy có giám sát WAF (Random Forest 5 lớp — Phase 5) và đánh giá Bộ phát hiện bất thường (Isolation Forest — Phase 6).
- **Tổng số mẫu phòng thủ:** 20,000 HTTP Requests (10,000 Benign + 10,000 Attacks)
- **Tập Train (70%):** 14,000 samples
- **Tập Validation (15%):** 3,000 samples
- **Tập Test (15%):** 3,000 samples
- **Cố định ngẫu nhiên (Random Seed):** 42
- **Phương pháp phân chia:** Phân tầng có giám sát (Stratified Sampling theo 5 lớp).
- **Tính nhất quán đối kháng (Adversarial Consistency):** Các mẫu tấn công trong Train/Val/Test đồng nhất với Track Tấn Công.
- **Thư mục lưu trữ Deliverable:** `data/processed/defense/`

---

## 2. Ma Trận Phân Bổ 5 Lớp Phòng Thủ Chuẩn Hóa

| Mã Lớp | Định Danh Lớp (Class Name) | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) | Tỷ Lệ Chuẩn |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **0** | **BENIGN** (Lưu lượng sạch) | 10,000 (50.0%) | 7,000 (50.0%) | 1,500 (50.0%) | 1,500 (50.0%) | **50.0%** |
| **1** | **SQLI** (SQL Injection) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **2** | **XSS** (Cross-Site Scripting) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **3** | **PATH** (Path Traversal / LFI) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **4** | **CMD** (Command Injection / RCE) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **TỔNG** | **5 LỚP TOÀN DIỆN** | **20,000 (100%)** | **14,000 (100%)** | **3,000 (100%)** | **3,000 (100%)** | **100.0%** |

---

## 3. Thống Kê Phương Thức & Vị Trí Payload

| Đặc Trưng Kỹ Thuật | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) |
| :--- | :---: | :---: | :---: | :---: |
| **HTTP POST Method** | 6,981 (34.9%) | 4,915 (35.1%) | 1,028 (34.3%) | 1,038 (34.6%) |
| **HTTP GET Method** | 13,019 (65.1%) | 9,085 (64.9%) | 1,972 (65.7%) | 1,962 (65.4%) |
| **Có Query Parameters** | 8,254 (41.27%) | 5,790 (41.36%) | 1,247 (41.57%) | 1,217 (40.57%) |
| **Có Request Body** | 6,981 (34.91%) | 4,915 (35.11%) | 1,028 (34.27%) | 1,038 (34.6%) |

---

## 4. Kiểm Định Tính Toàn Vẹn & Mã Băm SHA-256

| Tệp Dữ Liệu | Đường Dẫn Lưu Trữ | Số Bản Ghi | Mã Băm SHA-256 Checksum |
| :--- | :--- | :---: | :--- |
| **Defense Train** | `data/processed/defense/train.csv` | 14,000 | `f53ce2abf9029998211eb67484932bf2da089bc7368288fbb3f37533a034b034` |
| **Defense Validation** | `data/processed/defense/val.csv` | 3,000 | `3acf837883cd4fe5708bddb0f77c4fcdab3b718fc49deb3d4d26f76a3a46ebd4` |
| **Defense Test** | `data/processed/defense/test.csv` | 3,000 | `ca5cb610c373d5dc8a019b623db02f1b0144c2c9496949036eae8bdcfd1973b9` |

---

## 5. Kết Luận Nghiệm Thu (Sign-off)

- [x] Đạt chuẩn tỷ lệ phân tầng 70/15/15 chính xác 50% Benign và 12.5% mỗi họ tấn công, không bị lệch nhãn.
- [x] Tính nhất quán đối kháng (Adversarial Consistency) bảo toàn 100% với Track Model Tấn Công.
- [x] Không có hiện tượng rò rỉ dữ liệu (Zero Data Leakage) giữa Train, Validation và Test.
- [x] Cung cấp đầy đủ tập huấn luyện cho WAF Random Forest (Phase 5) và đánh giá Isolation Forest (Phase 6).
