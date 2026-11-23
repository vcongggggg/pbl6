# HƯỚNG DẪN KỊCH BẢN THUYẾT TRÌNH & DIỄN TẬP THỰC CHIẾN 10 PHÚT (BLUE TEAM v2.0)

- **Dự án:** Web API Security Platform & Adaptive Hybrid WAF (PBL6 — Blue Team v2.0)
- **Thời lượng kịch bản:** Đúng **10 Phút** bảo vệ trực tiếp trước Hội đồng Chấm Đồ Án
- **Công cụ điều khiển:** `scripts/start_all_services.py` & `scripts/demo_rehearsal.py`
- **Tác giả:** Nguyễn Văn Công (`vcongggggg` — Blue Team) & Nguyễn Minh (`naocavang08` — Red Team)

---

## 1. PHÂN BỔ THỜI GIAN DIỄN TẬP (10-MINUTE DEFENSE TIMELINE)

| Thời gian | Phân đoạn kịch bản | Thao tác trên máy chiếu / Terminal | Trọng tâm trình bày trước Hội đồng |
| :---: | :--- | :--- | :--- |
| **0:00 - 1:00** | **Khởi động & Kiến trúc** | Chạy `python scripts/start_all_services.py --check`; mở Dashboard `http://localhost:3000`. | Giới thiệu mô hình Thao trường Đối kháng Phân tán (Máy 1 Blue Team v2.0 vs Máy 2 Red Team), 100% dữ liệu thật, không telemetry giả. |
| **1:00 - 2:30** | **Giai đoạn 1: Baseline Traffic** | Chạy `python scripts/demo_rehearsal.py --interactive`, thực hiện Stage 1. | 5/5 request hợp lệ (GET tìm sách, OpenAPI 3.0, POST JSON review) đều đạt `HTTP 200 OK`, `0% False Positive`. |
| **2:30 - 5:00** | **Giai đoạn 2: Monitor-Only** | Chạy Stage 2 (tự động chuyển WAF sang `MONITOR_ONLY` qua `X-API-Key` & ghi `AuditLog`). | 5/5 tấn công OWASP (SQLi Auth Bypass, SQLi UNION, XSS, Path Traversal, CMD RCE) bị gắn cờ `MONITOR`, hiện trực tiếp trên Live Events Table. |
| **5:00 - 7:30** | **Giai đoạn 3: Active Blocking** | Chạy Stage 3 (chuyển sang `ACTIVE_BLOCKING`). | Chặn đứng 5/5 tấn công né tránh nâng cao (SQLi `UNION/**/SELECT`, XSS `<details ontoggle>`, Windows LFI, CMD `; python3`, và **SOAP/XML XXE**) bằng `HTTP 403 Forbidden` (RFC 7807) trong ~1–3 ms. |
| **7:30 - 9:00** | **Giai đoạn 4: Rate Limiting** | Chạy Stage 4 (gửi 14 request brute-force xoay `User-Agent` vào `/auth/login/`). | Chứng minh cơ chế **IP Hard Cap (10 req/min)** chống xoay token/UA, phạt ngay **`HTTP 429 Too Many Requests`** kèm `Retry-After`. |
| **9:00 - 10:00** | **SOC XAI & Kill Chain** | Trên Dashboard `http://localhost:3000`: mở **Attack Sessions**, **Evidence Drawer (26-D)** và **Explainability Modal**. | Chứng minh giải trình minh bạch: 26 đặc trưng thật, điểm `Rule + XGBoost v2.0 + IForest v2.0`, phân bổ đa giao thức và chuỗi Cyber Kill Chain. |

---

## 2. CHECKLIST CHUẨN BỊ TRƯỚC GIỜ BẢO VỆ (5 PHÚT TRƯỚC KHI LÊN BẢNG)

1. **Khởi động 3 dịch vụ (chọn 1 trong 2 cách):**
   - **Cách A — Chạy trực tiếp trên Windows (nhanh nhất, không cần Docker Desktop):**
     ```bash
     python scripts/start_all_services.py --start --prod
     ```
   - **Cách B — Chạy bằng Docker Compose (3 container non-root hardened):**
     ```bash
     docker compose up --build -d
     docker compose ps
     ```
2. **Kiểm tra sức khỏe toàn hệ thống:**
   ```bash
   python scripts/start_all_services.py --check
   ```
   Xác nhận 3 cổng đều `[OK]`:
   - Bookie Target API: `http://127.0.0.1:5000/api/v1/vulnerable/openapi.json` (cô lập loopback)
   - WAF Gateway v2.0: `http://127.0.0.1:8000/health`
   - SOC Dashboard UI: `http://localhost:3000`
3. **Dọn sạch dữ liệu cũ trên Dashboard (nếu muốn bắt đầu từ 0):**
   Bấm nút **Reset Demo** trên thanh điều khiển Dashboard (`http://localhost:3000`) hoặc gọi qua API có `X-API-Key`:
   ```bash
   curl -X POST http://127.0.0.1:8000/dashboard/reset-demo -H "X-API-Key: dev-admin-secret-key-change-me"
   ```

---

## 3. CHEAT SHEET LỆNH DEMO TRỰC TIẾP TRƯỚC HỘI ĐỒNG

```bash
# 1. Chạy diễn tập tương tác từng bước (Khuyên dùng khi thuyết trình):
python scripts/demo_rehearsal.py --interactive

# 2. Chạy tự động toàn trình 4 giai đoạn (dùng kiểm tra nhanh):
python scripts/demo_rehearsal.py --auto --interval 0.5

# 3. Demo Red Team trinh sát OpenAPI tự động (từ Máy 2 hoặc terminal riêng):
python attack-lab/agent/recon.py --target http://127.0.0.1:8000

# 4. Bơm sẵn dữ liệu mẫu phong phú (nếu cần trình chiếu biểu đồ lịch sử 60 phút):
curl -X POST http://127.0.0.1:8000/dashboard/seed-demo -H "X-API-Key: dev-admin-secret-key-change-me"

# 5. Chạy đo hiệu năng chịu tải thực tế C=50 (>= 250 RPS) ngay trước Hội đồng nếu được hỏi:
python scripts/run_gateway_profiling.py --in-process
```

---

## 4. LƯU Ý XỬ LÝ SỰ CỐ NHANH KHI DEMO (FALLBACK PLAN)

- **Nếu Hội đồng hỏi về bảo mật khóa Admin trên trình duyệt:** Mở DevTools -> tab Network -> chỉ cho Thầy Cô thấy toàn bộ request Dashboard gọi vào `/api/gateway/api/dashboard/*` (Next.js Server-Side BFF Proxy), không hề có header `X-API-Key` hay secret lộ trong JavaScript client bundle; gọi thẳng `curl http://127.0.0.1:8000/dashboard/stats` sẽ bị từ chối `HTTP 401 Unauthorized`.
- **Nếu chạy Stage 4 nhiều lần liên tiếp trong vòng 1 phút:** Bộ Rate Limiter giữ cửa sổ trượt 60 giây trên RAM cho IP `127.0.0.1`, nên nếu cần lặp lại Stage 4 ngay lập tức, chỉ cần đợi 60 giây hoặc khởi động lại Gateway.
