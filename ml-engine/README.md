# ML Engine Component (Phòng Thủ WAF — Phụ Trách: Thành Viên A `vcongggggg`)

Thư mục `ml-engine/` là không gian làm việc của hệ thống phòng thủ Machine Learning, chịu trách nhiệm nghiên cứu, xử lý dữ liệu, trích xuất đặc trưng và huấn luyện các mô hình Machine Learning phòng vệ cho WAF Gateway.

## Cấu trúc thư mục:
```text
ml-engine/
├── data/
│   ├── raw/
│   ├── processed/
│   └── evaluation/
├── features/
│   ├── payload.py              # Trích xuất đặc trưng hình thái payload
│   ├── keywords.py             # Trích xuất tần suất từ khóa tấn công
│   ├── http_context.py         # Trích xuất ngữ cảnh HTTP và hành vi
│   └── extractor.py            # Pipeline vector hóa 17 chiều chuẩn hóa
├── models/
│   ├── train_rf.py             # Huấn luyện Random Forest (Supervised)
│   ├── train_iforest.py        # Huấn luyện Isolation Forest (Anomaly)
│   └── evaluate.py             # Đánh giá chỉ số & ma trận nhầm lẫn
├── artifacts/                  # Nơi lưu model .joblib và metadata JSON
├── tests/                      # Unit test suite cho ml-engine
└── requirements.txt
```

## Trách nhiệm các Phase (Thành Viên A):
- **Phase 3:** Xây dựng Feature Engineering Pipeline 17 đặc trưng (`ml-engine/features/`).
- **Phase 4:** Tạo Dataset cân bằng (Lưu lượng sạch `vulnerable-api` + SecLists/CSIC 2010).
- **Phase 5:** Huấn luyện mô hình phân loại có giám sát (Random Forest).
- **Phase 6:** Huấn luyện mô hình phát hiện bất thường (Isolation Forest).
- **Phase 11:** Phối hợp đánh giá thực nghiệm đối kháng đa phương pháp (Rule vs ML vs Anomaly vs Hybrid).
