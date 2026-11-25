# CHECKLIST KIỂM TRA TRỰC QUAN TRƯỚC GIỜ BẢO VỆ (USER EYE-TEST CHECKLIST)

> Mục tiêu: Giúp thành viên nhóm kiểm tra trực quan toàn bộ cụm dịch vụ Docker, giao diện Dashboard SOC / AI Arena, và chất lượng hiển thị của bộ tài liệu Word/PowerPoint trước khi ra Hội đồng.

---

## CHECKLIST 1: KHỞI ĐỘNG 1 LỆNH DOCKER COMPOSE & KIỂM TRA CÔ LẬP

1. **Chuẩn bị biến môi trường (nếu máy chưa có `.env`):**
   ```powershell
   Copy-Item .env.example .env
   ```
2. **Build và khởi chạy cụm 3 container:**
   ```powershell
   docker compose up --build -d
   docker compose ps
   ```
   - [ ] Cả 3 container **`pbl6-vulnerable-api`**, **`pbl6-gateway`**, **`pbl6-dashboard`** ở trạng thái `Up (healthy)`.
3. **Kiểm tra tách biệt `./attack-lab`, Non-Root UID 1001 & khóa API:**
   ```powershell
   docker inspect pbl6-gateway --format "{{json .Mounts}}"
   docker exec pbl6-gateway id
   docker exec pbl6-dashboard id
   curl -i http://localhost:8000/dashboard/stats
   ```
   - [ ] Danh sách mount của `pbl6-gateway` **chỉ gồm** `./data`, `./ml-engine/artifacts` (`ro`), `./ml-engine/features` (`ro`) — **tuyệt đối KHÔNG có `./attack-lab`**.
   - [ ] `pbl6-gateway` chạy dưới `uid=1001(appuser)`, `pbl6-dashboard` chạy dưới `uid=1001(nextjs)`.
   - [ ] `http://localhost:8000/dashboard/stats` không kèm `X-API-Key` trả về **`HTTP 401 Unauthorized`**.
   - [ ] Cổng `5000` của Bookie chỉ bind loopback `127.0.0.1:5000:5000` (kiểm tra `docker compose ps`).

---

## CHECKLIST 2: DASHBOARD SOC (`/`) & LIVE ARENA (`/arena`)

1. **Kiểm tra SOC Command Center (`http://localhost:3000/`):**
   - [ ] Header hiển thị `[ACTIVE_BLOCKING] Chặn 403` và trạng thái Target `vulnerable-api:5000` màu xanh (`ms`).
   - [ ] Ở panel **Quick Live Simulator (11 Vectors)** bên phải, bấm thử **`SQLi Probe`** và **`🍏 Gửi Benign Traffic (200 OK)`**:
     - [ ] `SQLi Probe` xuất hiện ngay trên **Live Security Events Table** với badge **`BLOCKED 403`**.
     - [ ] `Benign Traffic` cho qua sạch sẽ (`HTTP 200 OK`, không phát sinh báo động giả).
   - [ ] Bấm **`Inspect`** trên một sự kiện bị chặn -> mở **Payload Evidence Drawer** -> chuyển sang tab **`26-Feature Vector`** xác nhận 26 giá trị số học thật hiển thị đầy đủ (không có `NaN` hay mảng rỗng).
   - [ ] Bấm **`Explain`** -> mở **DetectionExplainabilityModal** kiểm tra điểm phân rã `Rule (40%) + Supervised ML (35%) + Isolation Forest (25%)`.

2. **Kiểm tra Live Arena (`/arena` -> tab `Red Team Pentest AI`):**
   - [ ] Chọn cấp độ **`3. Hybrid v3.0`**, tích chọn **`Sync -> SOC`**, giữ Target `http://127.0.0.1:5000` và bấm **`Chạy Pentest AI`**.
   - [ ] Thanh 5 pha chạy mượt (`1. Recon (OpenAPI) -> 2. Attack Graph -> 3. Baseline Probe -> 4. DQN Mutate & Pivot -> 5. Verdict & SOC`).
   - [ ] Chọn từng vòng trong **SSE Pentest Trace**: cột phải hiển thị **`Trained Action Q(s, a) Ranking`**, `InputNormalizer Canonical Output` và 3 ô điểm **`Rule / API`**, **`XGBoost 26-D`**, **`IForest 26-D`**.
   - [ ] Kiểm tra luồng **Live HTTP `/api/proxy`** (thực hiện Replay cùng payload qua Reverse Proxy):
     ```powershell
     # Kiểm chứng Arena ở chế độ execution_mode="live_http" qua Next.js BFF (hoặc gửi trực tiếp qua /api/proxy):
     curl -i "http://localhost:8000/api/proxy/api/v1/vulnerable/books/search/?q=1%27%20OR%201%3D1--"
     ```
     - [ ] Phản hồi trả về **`HTTP 403 Forbidden`** (RFC 7807) và ghi sự kiện khớp **100% verdict** với vòng tương ứng trên **Live Security Events Table** (`http://localhost:3000/`).

3. **Kiểm tra Export Evidence & D4 Snapshots:**
   - [ ] Trên **Live Security Events Table**, bấm **`Export JSON`** -> trình duyệt tải xuống tệp `security_events_*.json` mở được bằng JSON viewer.
   - [ ] Trong **DetectionExplainabilityModal**, bấm **`Export Full Explainability JSON`** -> xác nhận có đủ `layers`, `threat_intelligence` (CWE/CAPEC/MITRE) và `evidence` (`raw_input` vs `canonical_input`).
   - [ ] Kiểm tra thư mục bằng chứng D4 đã commit tại [docs/reports/history/](file:///C:/Study/HocKy6/PBL6/docs/reports/history) và xác nhận [THESIS_ARTIFACT_RECONCILIATION_MATRIX.md](file:///C:/Study/HocKy6/PBL6/docs/reports/THESIS_ARTIFACT_RECONCILIATION_MATRIX.md) ghi **`33/33 VERIFIED PASS`**.

---

## CHECKLIST 3: KIỂM TRA TRỰC QUAN WORD (`.docx`) & POWERPOINT (`.pptx`)

1. **Mở 3 tệp Word báo cáo chính:**
   - [PBL6_Bao_Cao.docx](file:///C:/Study/HocKy6/PBL6/docs/reports/PBL6_Bao_Cao.docx)
   - [PBL6_Bao_Cao_Chuong_4_Thuc_Nghiem_Danh_Gia.docx](file:///C:/Study/HocKy6/PBL6/docs/reports/PBL6_Bao_Cao_Chuong_4_Thuc_Nghiem_Danh_Gia.docx)
   - [PBL6_Bao_Cao_Tong_Hop_Toan_Van.docx](file:///C:/Study/HocKy6/PBL6/docs/reports/PBL6_Bao_Cao_Tong_Hop_Toan_Van.docx)
   - Kiểm tra bằng mắt thường:
     - [ ] Không có bảng bị vỡ khung, tràn lề hay chữ đè lên nhau (đặc biệt Bảng 4.5, 4.6, 4.7 và các bảng 4.11a/b/c).
     - [ ] Toàn bộ 6 biểu đồ độ phân giải cao trong [docs/reports/figures/](file:///C:/Study/HocKy6/PBL6/docs/reports/figures) (`fig1_model_comparison_v2.png` -> `fig6_dqn_600ep_convergence.png`) hiển thị rõ nét, không bị thiếu ảnh hay lỗi placeholder *(lưu ý: bộ báo cáo hiện sử dụng 6 hình `fig1..fig6`)*.
     - [ ] Mục `4.7.5` hiển thị đầy đủ các số liệu Phase E v3.3 (`47.372` mẫu `defense_v2`, Group A `100.00% (221/221)`, `/tienda1` Schema `66.54% / 71.47%`, Strange v3.3 `114/114`, Blind Vault `86.67% (26/30)`).

2. **Mở bộ Slide bảo vệ [PBL6_Academic_Defense_Slides.pptx](file:///C:/Study/HocKy6/PBL6/docs/reports/PBL6_Academic_Defense_Slides.pptx) (chế độ Slide Show 16:9):**
   - [ ] **Slide 05:** Hiển thị đúng 5 lá chắn OWASP API + chính sách Schema thực nghiệm.
   - [ ] **Slide 09:** Tiêu đề hiển thị **`800-Ep 74-D/36-Act DQN`** và thông số 4-stage Live-HTTP (`:8056` `25.0%`).
   - [ ] **Slide 10:** Bảng/biểu đồ Ablation khớp `98.86% F1`, `97.75% Recall`, `0.00% FPR`, `0.803 ms`.
   - [ ] **Slide 11 (CSIC 2010):** Bảng hiển thị rõ **`0.00% Op | 0.07% Loose`** FPR, **`100.00% (221/221)`** Group A (`143/143` SQLi & `78/78` XSS), **`1.95% Op | 66.54% +Schema`** Group B và **`Overall 71.47% @ 0.00% FPR`** — chữ vừa khít ô, không tràn khung.
   - [ ] **Slide 12:** Hiển thị đủ `340 RPS @ C=50`, `4.138 ms` E2E, Strange `100.00% (114/114)` và Blind Vault `86.67% (26/30)` (cùng note `postfix2` nếu re-sync).
   - [ ] **Slide 14:** Khớp đầy đủ số liệu **Blue Team v3.3** và khung giải thích **4-Tier Evolution + CSIC Domain Shift** (không còn số liệu cũ của v1.0/v2.0 hay thuật ngữ lệch chuẩn).
