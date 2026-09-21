# 📋 REVIEW FEEDBACK & ACTIONABLE TASKS (DÀNH CHO PHIÊN CODER)

## Cập Nhật Mới Nhất: PR #83 (Task 5.2 - Champion RF Fine-Tuning, Validation & Feature Importance)
- **Reviewer:** @reviewer (Senior Security Architect & Code Reviewer)
- **Trạng thái thẩm định:** 🟢 **APPROVE (9.2/10) - BÁM SÁT 100% PLAN, ĐỦ ĐIỀU KIỆN MERGE ✅**
- **Đánh giá mức độ bám sát Kế hoạch (Plan Alignment):**
  - [x] Đầy đủ 2 Deliverables bắt buộc theo đặc tả Task 5.2: `docs/reports/rf_evaluation.md` và `ml-engine/notebooks/01_train_and_benchmark.ipynb`.
  - [x] Đạt chuẩn ngân sách độ trễ $< 15\text{ms}$ (thực tế: 0.0368 ms/mẫu) và Youden's Index $J \ge 0.90$ (thực tế: $0.9989$).
  - [x] Ma trận nhầm lẫn 5x5 trên 3.000 mẫu Test độc lập chứng minh $\text{FPR} = 0.00\%$ trên dữ liệu người dùng lành tính.
  - [x] Bảng Feature Importance 17 chiều trích xuất chính xác theo Wiley SCN 2015 [Ref 08].
  - [x] Toàn bộ 105/105 tests trong toàn dự án đều PASS 100% (7.28s), ruff 0 lỗi.
- **Hạt sạn & Khuyến nghị kỹ thuật cần tinh chỉnh:**
  - [x] **Chỉnh sửa mâu thuẫn số liệu trong `rf_evaluation.md`:** Đã sửa văn bản ở Mục 2.1 (loại bỏ `~88%`, ghi nhận chính xác Logistic Regression 97.44% và Random Forest 99.93%) và Mục 2.3 (nêu rõ luận chứng chọn Random Forest vì tính ổn định Bagging Ensemble chống overfitting và không phụ thuộc thư viện native C++ nặng nề trong Docker).
  - [x] **Di dời file tạm:** Đã chuyển `generate_notebook.py` vào `scratch/` để giữ thư mục `ml-engine/notebooks/` sạch sẽ.
  - [x] **Pre-run Notebook outputs:** Đã chạy `nbconvert` lưu sẵn toàn bộ biểu đồ Seaborn Heatmap và Bar Chart trong `01_train_and_benchmark.ipynb` (196 KB) hiển thị trực tiếp trên GitHub UI.
  - [x] **URL-decode ở demo Cell 6:** Đã bổ sung `urllib.parse.unquote()` chuẩn hóa payload trước khi trích xuất đặc trưng, giúp payload Path Traversal bị làm rối (%2f) được nhận diện chính xác 100%.
- **Hành động tiếp theo:** Merge PR #83 vào `main`, sau đó tiếp tục triển khai Task 5.3 & 5.4.

---

## Lịch Sử Thẩm Định: PR #82 (Task 5.1 - Multi-Model Candidate Benchmarking Pipeline)
- **Reviewer:** @reviewer
- **Trạng thái thẩm định:** 🟢 **APPROVE (9.6/10) - SẴN SÀNG MERGE VÀO MAIN ✅**
- **Điểm sáng đã kiểm chứng bằng code thực tế:**
  - [x] Độc lập đối sánh 5 trường phái học máy (Logistic Regression, Decision Tree, Linear SVM, Random Forest Champion, XGBoost, MLP).
  - [x] Áp dụng chuẩn khoa học Youden's Index $J = 0.9989$, $\text{FPR} = 0.00\%$, $\text{F1-Macro} = 99.93\%$.
  - [x] Tối ưu hóa đơn luồng (`n_jobs=1`) tránh nghẽn thread pool trong Uvicorn Gateway.
  - [x] SHA-256 model checksum chống giả mạo artifact.
