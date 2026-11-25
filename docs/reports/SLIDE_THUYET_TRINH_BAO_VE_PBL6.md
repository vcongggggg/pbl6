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
| **03** | Mục Tiêu Nghiên Cứu & Đóng Góp Cốt Lõi | Công | Kiềng 3 chân: Blue Team v3.3 + Red Team Offensive AI + Cyber Range 2 Máy LAN |
| **04** | Kiến Trúc Thao Trường Đối Kháng Phân Tán | Minh | Máy 1 (WAF :8000, Bookie Django :5000 loopback, SOC :3000) vs Máy 2 (Red Team DQN) |
| **05** | Đa Giao Thức, OpenAPI & 5 Lá Chắn OWASP API v3.3 | Công | Multi-Protocol Sniffer + `route_tiered` OpenAPI Schema + 28 Rules + 5 API Guards (`SSRF`, `NoSQLi`, `Mass Assignment`, `Stateful BOLA`, `Response DLP`) |
| **06** | Phòng Thủ Lai v3.3: Rule + XGBoost v2 + IForest v2 | Công | 26-D Unified Extractor + Per-Param Max-Pooling, Zero-Pickle `xgb_v2.ubj` + `iforest_v2.npz`, Dual-AI Consensus, Fail-Closed SHA-256 |
| **07** | Kiến Trúc Chịu Tải Cao & Gia Cố Bảo Mật | Công | Async Offload + SQLite WAL Group Commit, ReDoS `923->0.89ms`, JSON Dup-Key `object_pairs_hook=list`, Next.js BFF `0` Secrets |
| **08** | Zero-Scroll SOC Cockpit (`/`), Kill Chain & XAI | Công | 100% số liệu thật, bố cục 3-Tab `100vh`, Attack Sessions 5 bước MITRE & 26-D XAI |
| **09** | Tác Tử Pentest Tự Hành 5 Pha & Cockpit `/arena` | Minh | OpenAPI Recon -> Attack Graph -> `800-Ep` `74-D/36-Act` PyTorch Dueling Double-DQN -> Live SSE `/arena` |
| **10** | Thực Nghiệm 1: Đối Sánh ML & Ablation v3.2/v3.3 | Công | `defense_v2` (`47.372` tổng / `33.515` train, `0` overlap 8 cặp) & Ablation 1.000 mẫu (28 Rules): Hybrid **98.86% F1 / 97.75% Recall / 0.00% FPR / 0.803 ms** |
| **11** | Thực Nghiệm 2: Zero-Shot CSIC 2010 & Domain Shift | Công | Hạ FPR `29.60% -> 0.00%` (Op T=80), **Group A `100.00% (221/221)`** + `/tienda1` Schema **`66.54%` Group B / `71.47%` Overall @ `0.00%` FPR** |
| **12** | Thực Nghiệm 3: Tải Cao `C=50`, 3x3 & Phase E Suites | Minh | `253–340 RPS @ C=50`; E2E `4.138 ms`; Familiar `45/45`; Strange v3.3 **`114/114`**; Blind Vault `28/30` single-shot + **`30/30` postfix2** |
| **13** | Kịch Bản Demo Thực Chiến 10 Phút (5 Giai Đoạn) | Cả hai | 5 giai đoạn `demo_rehearsal.py` + 3 cấp độ phòng thủ (`No WAF -> Rules -> Hybrid v3.4`) trên `/arena` |
| **14** | Kết Luận & Hướng Phát Triển Tương Lai | Cả hai | Tổng kết tiến hóa 4 tầng (`v1.0 -> v3.3`), `0.00%` Op FPR (`N=1.715`) & lộ trình Cloud-Native (PostgreSQL/Redis, eBPF/XDP, Co-Evolution) |

---

## LỜI THOẠI TRỌNG TÂM TỪNG SLIDE (PRESENTER NOTES)

- **Slide 01 (Công):** Kính chào TS. Nguyễn Thế Xuân Ly và Hội đồng; giới thiệu đề tài và 2 thành viên phụ trách Blue Team v3.3 & Red Team Offensive AI.
- **Slide 02 (Công):** Chỉ rõ 3 điểm chết của WAF truyền thống và ML đơn lẻ (Evasion, Zero-Day, ReDoS, Pickle RCE CWE-502, Data Leakage).
- **Slide 03 (Công):** Nêu rõ 3 mục tiêu cốt lõi cùng 4 con số điểm nhấn của Blue Team v3.3 (`98.86% F1`, `0.00% Op FPR / N=1.715`, `0.803 ms inline / 4.138 ms E2E`, `340 RPS @ C=50`).
- **Slide 04 (Minh):** Trình bày mô hình 2 máy vật lý LAN theo Yamin et al. (Elsevier 2020) và phân định cổng chuẩn (`3000`, `8000`, `127.0.0.1:5000`, không mount `./attack-lab` vào Docker runtime).
- **Slide 05 (Công):** Giải thích Multi-Protocol Sniffer (chống XXE XML sạch không bị false positive, chống GraphQL Deep Nesting), 28 Hardened Rules (`SQLI-006/007`, `CMD-006`) và OpenAPI 3.0 Positive Schema Validator (`route_tiered`).
- **Slide 06 (Công):** Trình bày bộ trích xuất thống nhất 26-D + Per-Parameter Max-Pooling (`predict_http`), Champion XGBoost v2.0 (`xgb_v2.ubj`) + Calibrated IForest v2.0 (`iforest_v2.npz`) Zero-Pickle + Fail-Closed SHA-256, công thức `0.40*Rule + 0.35*ML + 0.25*Anomaly` + Dual-AI Consensus.
- **Slide 07 (Công):** Nhấn mạnh bước nâng cấp từ v1.0 lên v3.3: ReDoS `923.37 ms -> 0.891 ms`, chống `json_duplicate_key_tamper` bằng `object_pairs_hook=list` đệ quy JSON lồng nhau, Next.js Server-Side BFF (`0` secrets trong client bundle), Async Thread Offload + SQLite WAL Group Commit.
- **Slide 08 (Công):** Trình bày SOC Dashboard 100% số liệu thật (`0` fake telemetry), Cyber Kill Chain 15 phút (UTC HMAC-SHA256) và XAI 26 đặc trưng + Export JSON.
- **Slide 09 (Minh):** Trình bày trọn vẹn chuỗi Red Team (`recon.py`, `AttackGraph` nâng cấp từ `40-D/14-A` lên `74-D` state / `36` actions, huấn luyện 4 giai đoạn `800 episodes` gồm `600` RAM + `200` Live-HTTP `:8056/:8055`, PyTorch Dueling Double-DQN `pentest_dqn_v2.pt` xác thực SHA-256 + `weights_only=True`) và màn hình Đấu Trường AI (`/arena`).
- **Slide 10 (Công):** Phân tích biểu đồ Ablation Study (`N = 1.000`, 28 Rules, `0` overlap trên `47.372` mẫu `defense_v2` / `33.515` Train): Hybrid đạt `98.86% F1`, `97.75% Recall` (+2.63% so với ML thuần), `0.00% FPR`, chỉ `0.803 ms/req` inline (`<= 1.5 ms` SLA, nhanh hơn ~22x so với v1.0 `16.10 ms`).
- **Slide 11 (Công):** Phân tích Zero-Shot CSIC 2010 Two-Tier (`N = 3.000`): Op T=80 FPR hạ từ `29.60% -> 0.00%`, Precision `100.00%`, **Group A True Payload `100.00% (221/221)`** (`143/143` SQLi gồm `75/75` blind-boolean/SSI, `78/78` XSS), Overall `16.40%` (Op) / `17.27%` (Loose) khi chưa có Schema; giải thích minh bạch **CSIC Domain Shift** của 1.279 mẫu Group B và chứng minh bật OpenAPI `/tienda1` Schema nâng Group B lên **`66.54%` (Overall `71.47%`) ở `0.00%` FPR**.
- **Slide 12 (Minh):** Trình chiếu biểu đồ tải đồng thời `C=50` (`340.14 RPS` Benign / `253.31 RPS` Attack), E2E HTTP 2-hop `4.138 ms` (`<= 5.5 ms` SLA), đối kháng 3x3 Familiar (`45/45` Hybrid), Strange v3.3 **`114/114` trên cả 6 ô Hybrid**, và **Blind Held-Out Vault v2** (`28/30` Static / `26/30` DQN single-shot, **`30/30` trên cả 6 ô Hybrid** sau `postfix2`).
- **Slide 13 (Cả hai):** Giới thiệu 5 phân cảnh Demo thực chiến 10 phút (`demo_rehearsal.py` + `attack-lab/runner.py` + SOC Dashboard `/` & Live Arena `/arena`).
- **Slide 14 (Cả hai):** Đúc kết tiến hóa 4 tầng (`Rules Static -> Rules Hardened+Normalizer -> Hybrid 26-D + Dual-AI -> + Route-Tiered OpenAPI Schema / DLP`), định hướng Cloud-Native & cảm ơn Hội đồng.
