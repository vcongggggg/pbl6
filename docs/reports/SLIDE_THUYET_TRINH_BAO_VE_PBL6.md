# BỘ SLIDE THUYẾT TRÌNH BẢO VỆ ĐỒ ÁN CHUYÊN NGÀNH (PBL6)
## ĐỀ TÀI: NỀN TẢNG GIÁM SÁT, PHÁT HIỆN VÀ NGĂN CHẶN TẤN CÔNG WEB API THÔNG MINH SỬ DỤNG MACHINE LEARNING KẾT HỢP THAO TRƯỜNG AN NINH ĐỐI KHÁNG

- **Đơn vị:** Bộ môn An toàn Thông tin — Khoa Công nghệ Thông tin — Trường Đại học Bách khoa, Đại học Đà Nẵng
- **Giảng viên hướng dẫn:** **TS. Nguyễn Thế Xuân Ly**
- **Sinh viên thực hiện:**
  - **Nguyễn Văn Công** (`vcongggggg`, Lớp `21T_DT` — Nhóm trưởng / Blue Team: WAF Gateway v2.0, ML Defense v2.0, Bookie API, SOC Dashboard, Docker/CI)
  - **Nguyễn Minh** (`naocavang08` — Thành viên / Red Team: OpenAPI Recon, Attack Graph MDP, PyTorch DQN Evasion Agent, CLI Runner & AI Arena)
- **Thời lượng báo cáo:** 15 phút thuyết trình + 10 phút Demo trực tiếp (Blue Team v2.0 + Red Team DQN + AI Arena)

---

## DANH MỤC 14 SLIDES THUYẾT TRÌNH & PHÂN CÔNG

| Slide | Tiêu Đề Slide | Trình Bày | Trọng Tâm Học Thuật & Thực Nghiệm |
| :---: | :--- | :---: | :--- |
| **01** | Bìa Đề Tài & Thông Tin Nhóm | Cả hai | Tên đề tài chính thức, GVHD TS. Nguyễn Thế Xuân Ly, Nguyễn Văn Công & Nguyễn Minh |
| **02** | Đặt Vấn Đề & Thách Thức An Ninh Web API | Công | OWASP API Top 10, hạn chế WAF tĩnh (bypass/ReDoS) & ML đơn lẻ (Evasion/Zero-Day/Pickle CWE-502) |
| **03** | Mục Tiêu Nghiên Cứu & Đóng Góp Cốt Lõi | Công | Kiềng 3 chân: Blue Team v2.0 + Red Team Offensive AI + Cyber Range 2 Máy LAN |
| **04** | Kiến Trúc Thao Trường Đối Kháng Phân Tán | Minh | Máy 1 (WAF :8000, Bookie Django :5000 loopback, SOC :3000) vs Máy 2 (Red Team DQN) |
| **05** | Đa Giao Thức & Positive Security Model | Công | Multi-Protocol Sniffer (REST/GraphQL/SOAP-XML/JSON-RPC) + OpenAPI 3.0 Schema Validator |
| **06** | Phòng Thủ Lai v2.0: Rule + XGBoost v2 + IForest v2 | Công | 26-D Unified Extractor, Zero-Pickle `xgb_v2.ubj` + `iforest_v2.npz`, Fail-Closed SHA-256 |
| **07** | Kiến Trúc Chịu Tải Cao & Gia Cố Bảo Mật | Công | Async Offload + SQLite WAL Group Commit, ReDoS `923->0.89ms`, Next.js BFF `0` Secrets |
| **08** | SOC Command Center, Kill Chain & XAI | Công | 100% số liệu thật, Attack Sessions 5 bước MITRE, 26-D Evidence Drawer & Explainability |
| **09** | Tác Tử Red Team Tự Hành & Đấu Trường AI | Minh | Task 10.1–10.4: Recon cycle-guard, AttackGraph 40-D/14-A, DQN `weights_only=True`, `/arena` |
| **10** | Thực Nghiệm 1: Đối Sánh ML & Ablation v2.0 | Công | `defense_v2` (46.187 mẫu Zero-Leakage) & Ablation 1.000 mẫu: Hybrid **98.61% F1 / 97.25% Recall / 0.848 ms** |
| **11** | Thực Nghiệm 2: Zero-Shot CSIC 2010 & Defense-in-Depth | Công | Hạ CSIC FPR `29.60% -> 0.00%`, Precision `100%`, XSS `100%` + 4 trụ cột bảo vệ Hybrid |
| **12** | Thực Nghiệm 3: Hiệu Năng Tải Cao & Đối Kháng Live | Minh | `253–340 RPS @ C=50`, AI `0.867 ms`, **20/20 DQN Blocked (`0%` Bypass)**, `350+` Tests / `0` Lint |
| **13** | Kịch Bản Demo Thực Chiến 10 Phút | Cả hai | 4 giai đoạn `demo_rehearsal.py` + Red Team `runner.py` + Đấu Trường AI `/arena` |
| **14** | Kết Luận & Hướng Phát Triển Tương Lai | Cả hai | Tổng kết 26/26 Findings Closed & Lộ trình Cloud-Native (PostgreSQL/Redis, eBPF/XDP, Online Co-Evolution) |

---

## LỜI THOẠI TRỌNG TÂM TỪNG SLIDE (PRESENTER NOTES)

- **Slide 01 (Công):** Kính chào TS. Nguyễn Thế Xuân Ly và Hội đồng; giới thiệu đề tài và 2 thành viên phụ trách Blue Team v2.0 & Red Team.
- **Slide 02 (Công):** Chỉ rõ 3 điểm chết của WAF truyền thống và ML đơn lẻ (Evasion, Zero-Day, ReDoS, Pickle RCE CWE-502, Data Leakage).
- **Slide 03 (Công):** Nêu rõ 3 mục tiêu cốt lõi cùng 4 con số điểm nhấn của Blue Team v2.0 (`98.61% F1`, `0.00% FPR`, `0.867 ms AI`, `340 RPS @ C=50`).
- **Slide 04 (Minh):** Trình bày mô hình 2 máy vật lý LAN theo Yamin et al. (Elsevier 2020) và phân định cổng chuẩn (`3000`, `8000`, `127.0.0.1:5000`).
- **Slide 05 (Công):** Giải thích Multi-Protocol Sniffer (chống XXE XML sạch không bị false positive, chống GraphQL Deep Nesting) và OpenAPI 3.0 Positive Schema Validator.
- **Slide 06 (Công):** Trình bày bộ trích xuất thống nhất 26-D (Zero Training-Serving Skew), Champion XGBoost v2.0 (`xgb_v2.ubj`) + Calibrated IForest v2.0 (`iforest_v2.npz`) Zero-Pickle + Fail-Closed SHA-256 và công thức `0.40*Rule + 0.35*ML + 0.25*Anomaly`.
- **Slide 07 (Công):** Nhấn mạnh bước nâng cấp từ v1.0 lên v2.0: ReDoS `923.37 ms -> 0.891 ms`, Next.js Server-Side BFF (`0` secrets trong client bundle), Async Thread Offload + SQLite WAL Group Commit + `AuditLog`.
- **Slide 08 (Công):** Trình bày SOC Dashboard 100% số liệu thật (`0` fake telemetry), Cyber Kill Chain 15 phút (UTC HMAC-SHA256) và XAI 26 đặc trưng.
- **Slide 09 (Minh):** Trình bày trọn vẹn chuỗi Task 10.1–10.4 Red Team (`recon.py`, `AttackGraph` 40-D/14-A, 14 Semantic Tamper, PyTorch DQN `evasion_agent.pt` xác thực SHA-256 + `weights_only=True`) và màn hình Đấu Trường AI (`/arena`).
- **Slide 10 (Công):** Phân tích biểu đồ Ablation Study v2.0 (`N = 1.000`, `0` overlap): Hybrid v2.0 đạt `98.61% F1`, `97.25% Recall` (+3.75% so với ML thuần), `0.00% FPR`, chỉ `0.848 ms/req` (nhanh hơn 19x so với v1.0 `16.10 ms`).
- **Slide 11 (Công):** Phân tích Zero-Shot CSIC 2010: FPR hạ từ `29.60% -> 0.00%`, Precision `100%`, Hybrid XSS `100%`, SQLi `49.61%`, và giải thích khách quan domain shift nhóm `ANOMALY_TAMPER`.
- **Slide 12 (Minh):** Trình chiếu biểu đồ tải đồng thời `C=50` (`340.14 RPS` Benign / `253.31 RPS` Attack), kết quả đối kháng sống **Red Team DQN vs Blue Team v2.0 (`20/20 Blocked`, `0.0%` bypass, `4.29 ms`)** và chất lượng CI (`350+` tests PASS, `0` ruff/ESLint errors).
- **Slide 13 (Cả hai):** Giới thiệu 4 phân cảnh Demo thực chiến 10 phút (`demo_rehearsal.py` + `attack-lab/runner.py` + SOC Dashboard & AI Arena).
- **Slide 14 (Cả hai):** Đúc kết đóng góp (26/26 findings đã vá), định hướng Cloud-Native & cảm ơn Hội đồng.
