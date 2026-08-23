# PHASE 0 — BÁO CÁO PHÂN TÍCH KIẾN TRÚC & GAP ANALYSIS

---

## 1. Xác Nhận Kiến Trúc Hệ Thống (Architecture Confirmation)

Theo [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md), hệ thống Web API Security Platform sẽ hoạt động theo kiến trúc luồng dữ liệu chuẩn sau:

```text
Client / Attack Lab
        ↓
FastAPI WAF Gateway (Reverse Proxy Layer)
        ↓
Request Normalizer & Parser (URL, Query, Body, Headers, IP)
        ↓
Feature Extraction (Payload 17 features + HTTP metadata + Behavior time-window)
        ↓
        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
   Rule Engine       Random Forest      Isolation Forest
   (Heuristics)       (Supervised)          (Anomaly)
        |                   |                   |
        +-------------------+-------------------+
                            ↓
                   Risk Scoring Engine
           (Weighted Score 0–100 & Thresholds)
                            ↓
                     Decision Engine
        (ALLOW / MONITOR / RATE_LIMIT / BLOCK)
                            ↓
   +------------------------+------------------------+
   |                                                 |
   v (nếu vi phạm: Block / Rate Limit)               v (nếu hợp lệ / Monitor Only)
HTTP 403 Forbidden / 429 Too Many Requests      Proxy tới Target Web API (Juice Shop)
   |                                                 |
   +------------------------+------------------------+
                            ↓
             Ghi Security Logs & Audit Trail (SQLite)
                            ↓
             Next.js Real-time Dashboard
```

---

## 2. Báo Cáo Hiện Trạng & Gap Analysis (So với Specification)

Sau khi dọn sạch mã nguồn thử nghiệm ban đầu, dự án đang ở trạng thái **Clean State (Fresh Start)**. Dưới đây là phân tích yêu cầu kỹ thuật chi tiết cho từng giai đoạn:

| Hạng mục | Yêu cầu trong Plan | Kế hoạch triển khai kỹ thuật |
| :--- | :--- | :--- |
| **Hạ tầng (Phase 1)** | Docker Compose phối hợp 3 services (`gateway`, `dashboard`, `juice-shop`) với SQLite DB. | Cấu hình mạng bridge `pbl6-network`, chuẩn hóa file `.env.example`, Dockerfiles cho Gateway và Dashboard. |
| **Rule Engine (Phase 2)** | Phát hiện SQLi, XSS, Path Traversal, Command Injection, Brute Force, API Abuse. | Xây dựng các lớp Regex chuẩn, module hóa trong `gateway/app/detection/rules.py` trả về `detected`, `attack_type`, `score`, `matched_rules`. |
| **Feature Extraction (Phase 3)** | 17 payload features + HTTP metadata + Behavior features theo time-window 10s/60s. | *(ML/Data Team)* Viết module `features.py` dùng chung duy nhất cho cả Training và Runtime Inference. |
| **Dataset Strategy (Phase 4)** | Synthetic đa dạng (obfuscation, comments) + Benign edge-cases + Lab traffic log. | *(ML/Data Team)* Tạo script sinh dataset cân bằng và các cơ chế chia tập (Stratified, Unseen payload, Attack family). |
| **Supervised ML (Phase 5)** | Random Forest đa nhãn (Multiclass) phân loại các họ tấn công cụ thể. | *(ML/Data Team)* Train model `random_forest.joblib` kèm `metadata.json` (ghi nhận version, metrics, features). |
| **Anomaly Detection (Phase 6)** | Isolation Forest dựa trên đặc trưng hành vi (request rate, scan score...). | *(ML/Data Team)* Train model `isolation_forest.joblib` cho bài toán phát hiện hành vi bất thường. |
| **Risk & Decision (Phase 7)** | Trọng số động: $0.30 \times Rule + 0.35 \times ML + 0.20 \times Anomaly + 0.15 \times Behavior$. Ngưỡng 0-29 (Allow), 30-59 (Monitor), 60-79 (Rate Limit), 80-100 (Block). | Viết `risk_engine.py` và `decision_engine.py`, hỗ trợ 4 chế độ WAF (`OFF`, `MONITOR_ONLY`, `ACTIVE_BLOCKING`, `HYBRID`). |
| **Rate Limiter (Phase 8)** | Giới hạn theo IP/cửa sổ thời gian, trả về HTTP 429. | Triển khai `rate_limiter.py` dựa trên in-memory sliding window cache. |
| **Dashboard (Phase 9)** | 5 khu vực: Overview, Timeline, Distribution, Security Events, Detection Explain. | Xây dựng bằng Next.js (Tailwind + Recharts), hỗ trợ gửi `X-WAF-API-Key` khi gọi admin API. |
| **Attack Lab (Phase 10)** | Bộ scenario JSON và CLI runner thực hiện các campaign tấn công trong lab. | Tạo `attack-lab/scenarios/` và `runner.py`. |
| **Bảo mật Admin WAF** | Xác thực API Key cho các endpoint config/logs và ghi nhận bảng `audit_log`. | Bổ sung API Key middleware và lưu vết mọi thay đổi cấu hình. |

---

## 3. Checklist Thực Thi Phase 0

- [x] Đã sao chép nguyên văn `PBL6_PLAN_CHI_TIET_AI_AGENT_V2.md` sang [docs/PLAN.md](file:///c:/Study/HocKy6/PBL6/docs/PLAN.md).
- [x] Đã tạo [docs/PROGRESS.md](file:///c:/Study/HocKy6/PBL6/docs/PROGRESS.md) theo dõi trạng thái Phase 0 đến Phase 12.
- [x] Đã xác nhận kiến trúc chuẩn và phân công vai trò rõ ràng giữa Backend/Security và ML/Data.
- [x] Đã lập báo cáo Gap Analysis và sẵn sàng bước vào **Phase 1 (Infrastructure Setup)**.
