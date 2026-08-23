# ML Engine Component (Reserved for ML/Data Team)

Thư mục `ml-engine/` là không gian làm việc độc lập của nhóm ML/Data, chịu trách nhiệm nghiên cứu, xử lý dữ liệu và huấn luyện các mô hình Machine Learning.

## Cấu trúc thư mục:
```text
ml-engine/
├── data/
│   ├── raw/
│   ├── processed/
│   └── evaluation/
├── src/
│   ├── generate_dataset.py     # Sinh tập dữ liệu huấn luyện
│   ├── collect_lab_traffic.py  # Thu thập traffic thực tế từ lab
│   ├── features.py             # Bộ trích xuất đặc trưng dùng chung
│   ├── train_rf.py             # Huấn luyện Random Forest
│   ├── train_anomaly.py        # Huấn luyện Isolation Forest
│   ├── evaluate.py             # Đánh giá các chỉ số
│   ├── compare_models.py       # So sánh đa mô hình
│   └── generate_report.py      # Xuất báo cáo số liệu
├── notebooks/                  # Thử nghiệm Jupyter Notebooks
└── requirements.txt
```

## Trách nhiệm theo Phase:
- **Phase 3:** Xây dựng Feature Engineering.
- **Phase 4:** Tạo Dataset và cơ chế phân chia (Stratified, Unseen payload, Attack family).
- **Phase 5:** Huấn luyện mô hình phân loại có giám sát (Random Forest).
- **Phase 6:** Huấn luyện mô hình phát hiện bất thường (Isolation Forest).
- **Phase 11:** Thực hiện đánh giá thực nghiệm đa phương pháp (Rule vs ML vs Anomaly vs Hybrid).

> **LƯU Ý (Phase 0):** Hiện tại chưa triển khai code huấn luyện hay sinh dữ liệu giả lập. Mã nguồn ML sẽ được triển khai chi tiết ở các phase tương ứng.
