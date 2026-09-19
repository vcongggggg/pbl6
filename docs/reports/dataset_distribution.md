# Báo Cáo Phân Bổ Tập Dữ Liệu Huấn Luyện (Task 4.3 — Label Distribution Report)

## 1. Tổng Quan Phân Chia Dữ Liệu (Stratified Split 70/15/15)

- **Tổng số mẫu toàn diện:** 20,000 HTTP Requests (20,000 samples)
- **Tập Train (70%):** 14,000 samples
- **Tập Validation (15%):** 3,000 samples
- **Tập Test (15%):** 3,000 samples
- **Cố định ngẫu nhiên (Random Seed):** 42
- **Phương pháp phân chia:** Phân tầng có giám sát (Stratified Sampling theo nhãn 5 lớp)

---

## 2. Ma Trận Phân Bổ 5 Lớp Chuẩn Hóa

| Mã Lớp | Tên Lớp (Attack Family) | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) | Tỷ Lệ Chuẩn |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **0** | **BENIGN** | 10,000 (50.0%) | 7,000 (50.0%) | 1,500 (50.0%) | 1,500 (50.0%) | **50.0%** |
| **1** | **SQLI** (SQL Injection) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **2** | **XSS** (Cross-Site Scripting) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **3** | **PATH** (Path Traversal) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **4** | **CMD** (Command Injection) | 2,500 (12.5%) | 1,750 (12.5%) | 375 (12.5%) | 375 (12.5%) | **12.5%** |
| **TỔNG** | **5 LỚP** | **20,000 (100%)** | **14,000 (100%)** | **3,000 (100%)** | **3,000 (100%)** | **100.0%** |

---

## 3. Thống Kê Đặc Trưng HTTP Context

| Đặc Trưng Kỹ Thuật | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) |
| :--- | :---: | :---: | :---: | :---: |
| **HTTP GET Method** | 13,019 (65.1%) | 9,089 (64.9%) | 1,969 (65.6%) | 1,961 (65.4%) |
| **HTTP POST Method** | 6,981 (34.9%) | 4,911 (35.1%) | 1,031 (34.4%) | 1,039 (34.6%) |
| **Có Query Parameters** | 8,254 (41.27%) | 5,791 (41.36%) | 1,234 (41.13%) | 1,229 (40.97%) |
| **Có Request Body** | 6,981 (34.91%) | 4,911 (35.08%) | 1,031 (34.37%) | 1,039 (34.63%) |

---

## 4. Kiểm Định Tính Toàn Vẹn & Mã Băm SHA-256

| Tệp Dữ Liệu | Đường Dẫn Lưu Trữ | Số Bản Ghi | Mã Băm SHA-256 Checksum |
| :--- | :--- | :---: | :--- |
| **Train Set** | `data/processed/train.csv` | 14,000 | `d603b6f7cc86996742eb9613c6deabeaeab97cba9ce3d99f2c87a078b87e7370` |
| **Validation Set** | `data/processed/val.csv` | 3,000 | `9a7a59e697f21fea7902c581fad2ba0ceb52651ed94e710af9d62390b99200b8` |
| **Test Set** | `data/processed/test.csv` | 3,000 | `e51102ece9704aff09635212d95b4ef552dfe04735b2d556cdef9a7d7fcddba4` |

---

## 5. Bộ Dữ Liệu Con Tấn Công Chuyên Biệt (`data/processed/attack/`)

| Tệp Dữ Liệu Con | Số Bản Ghi | Phân Bổ 4 Lớp (SQLI / XSS / PATH / CMD) | Mã Băm SHA-256 |
| :--- | :---: | :---: | :--- |
| `data/processed/attack/train.csv` | 7,000 | 1,750 / 1,750 / 1,750 / 1,750 (25% mỗi lớp) | `a62214b916e42ec041c906f4fc1fd9065f53f399b3b5458a1dde46a54b57c8e9` |
| `data/processed/attack/val.csv` | 1,500 | 375 / 375 / 375 / 375 (25% mỗi lớp) | `6a2a77d902e11399f00df233d9ec4535e4aa4bd26aef4bbe6ab2260fc75d4cc2` |
| `data/processed/attack/test.csv` | 1,500 | 375 / 375 / 375 / 375 (25% mỗi lớp) | `04018fd71cf356d78ba7f9e1e7dd53bfe330c99c1c7ea2caf4b328a324a02a01` |

---

## 6. Kết Luận Nghiệm Thu (Sign-off)

- [x] Đạt chuẩn tỷ lệ phân tầng 70/15/15 chính xác tới 0.00% sai lệch lớp.
- [x] Không có hiện tượng rò rỉ dữ liệu (Zero Data Leakage) giữa Train, Validation và Test.
- [x] Đầy đủ 9 cột thuộc tính tương thích trực tiếp cho bộ trích xuất đặc trưng `ml_detector.py` và `extractor.py`.
- [x] Sẵn sàng chuyển giao cho **Phase 5: Supervised ML — Random Forest Multi-class Training**.
