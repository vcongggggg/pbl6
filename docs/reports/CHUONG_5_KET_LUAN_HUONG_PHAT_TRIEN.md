# CHƯƠNG 5: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

---

## 5.1. Tổng Kết Các Kết Quả Đạt Được Của Đề Tài

Đề tài **"Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán"** đã hoàn thành toàn diện mọi mục tiêu đặt ra cho cả hai phân hệ **Blue Team v3.3 (Nguyễn Văn Công)** và **Red Team Offensive AI (Nguyễn Minh)**:

### 5.1.1. Thành tựu về mặt Học thuật và Khoa học Dữ liệu
1. **Hệ thống hóa 20 tài liệu chuẩn mực quốc tế:** Kết hợp 5 giáo trình kinh điển (Stallings, Stinson, Katz & Lindell, CompTIA PenTest+, NGINX Cookbook), 5 tiêu chuẩn công nghiệp (OWASP API Top 10, ModSecurity CRS v4.0, OWASP Benchmark, NIST SP 800-115, MITRE ATT&CK) và 10 công trình khoa học trọng điểm (Liu et al. ICDM 2008, Breiman 2001, Chen & Guestrin KDD 2016 XGBoost, Torrano-Gimenez Wiley 2015, Yamin Elsevier 2020, Sutton & Barto, Mnih Nature 2015, Goodfellow ICLR 2015, MDPI 2025, USENIX 2024).
2. **Đảm bảo tuyệt đối Liêm chính Khoa học (Zero-Leakage & Zero-Skew):** Xây dựng bộ dữ liệu `defense_v2` (**`47.372` mẫu**: Train `33.515` [= `32.330` gốc v2.0 + `1.185` Phase E sạch], Val `6.928`, Test `6.929`) với **`0` trùng lặp mã băm SHA-256 chuẩn hóa trên cả 8 cặp giao nhau** (Train/Val/Test, CSIC 2010, `benchmark_1000_diverse.csv`, `Strange Suite v3.3` và `Blind Held-Out Vault v2` khóa SHA-256 `f0bf69f6c28a...` trước khi retrain); thống nhất 100% bộ trích xuất **26 đặc trưng (`extract_26_from_http`)** giữa Training và Serving; loại bỏ 100% số liệu mô phỏng trên cả SOC Dashboard lẫn Đấu Trường AI.
3. **Chứng minh định lượng sức mạnh Phòng thủ Tiến hóa 4 Tầng (4-Tier Evolution & Defense-in-Depth):**
   - Thực nghiệm Ablation Study (`N = 1.000`, **28 hardened rules** + XGBoost 26-D + IForest 26-D + Dual-AI Consensus + Per-Parameter Max-Pooling) chứng minh **Hybrid Defense v3.3** đạt **`98.86%` F1-Score, `97.75%` Recall, `100.00%` Precision, `0.00%` FPR, Youden's Index `J = 0.9775`** trong **`0.803 ms/req`** inline (P95 `1.465 ms`), vượt **`+1.36%` F1 và `+2.63%` Recall** so với XGBoost đơn lẻ (`97.50%` F1 / `95.12%` Recall), đồng thời duy trì **`0.00%` Operational FPR** trên **`N = 1.715`** mẫu sạch.
   - Trên tập ngoại miền Zero-Shot **CSIC 2010 (`N = 3.000`)** theo phân loại kiểm toán **Two-Tier** (`unquote_plus` + word-boundary): hạ **FPR từ `29.60%` (v1.0) xuống `0.00%` (Operational T=80)** với **`100.00%` Precision**, chặn tuyệt đối **`100.00% (221/221)` Group A True Payloads** (`143/143` SQLi gồm `75/75` `SQLI_BLIND_BOOLEAN`, `61/61` T-SQL time-delay, `7/7` Union và `78/78` XSS); lý giải minh bạch **CSIC Domain Shift** của nhóm `Group B Parameter Tampering` (`1.279` mẫu -> `16.40%` Op T=80 / `17.27%` Loose khi chưa có Schema) và chứng minh khi nạp OpenAPI `/tienda1` (suy dẫn chỉ từ Benign) nâng Group B lên **`66.54%` (Overall `71.47%`) ở `0.00%` FPR**.

### 5.1.2. Thành tựu về mặt Kỹ thuật, Bảo mật và Triển khai Thực tiễn
1. **Cổng WAF Gateway Chịu tải cao & Dual-Tier SLA:** Offload xử lý CPU-bound qua `anyio.to_thread.run_sync`, pure ASGI middleware, RAM TTL cache `waf_mode`, SQLite WAL Leader-Follower Group Commit -> đạt **`253–340 RPS` ở `C = 50`**, **`0.803 ms`** inline single-pass (`<= 1.5 ms` SLA) và **`4.138 ms`** mean (`p50 = 3.777 ms`, `<= 5.5 ms` SLA) qua 2-hop TCP HTTP thật trên `3.000` mẫu CSIC 2010.
2. **An toàn Chuỗi Cung Ứng AI & Gia cố Toàn Diện (28 Rules + JSON Dup-Key + Zero-Pickle):** Chuyển 100% mô hình phòng thủ sang **Zero-Pickle** (`xgb_v2.ubj` + `iforest_v2.npz`, `allow_pickle=False`) kèm xác thực SHA-256 Fail-Closed; gia cố `pentest_dqn_v2.pt` & `evasion_agent.pt` bằng `torch.load(..., weights_only=True)` + SHA-256; vá triệt để ReDoS (`923.37 ms -> 0.891 ms`), `json_duplicate_key_tamper` (`object_pairs_hook=list` đệ quy JSON lồng nhau + `CMD-003`), `CMD-006` (wildcard-globbing & SSI), `SQLI-007` (scientific-float), `x-www-form-urlencoded` per-field decoding, padding > 16 KB, chunked > 1 MB (413), IP Hard Cap Rate Limiter, Fail-Closed RuleEngine và Next.js Server-Side BFF Proxy (`0` client secrets).
3. **Làm chủ 100% Ứng dụng Đích Bookie Bookstore (`vulnerable-api`):** Hệ thống Django độc lập chứa 8 nhóm lỗ hổng OWASP Web & API Top 10, OpenAPI 3.0 và kiểm chứng HMAC `compare_digest`, cô lập loopback `127.0.0.1:5000`.
4. **Hoàn thiện Tác tử Pentest Tự Hành Dueling Double-DQN & Cockpit `/arena` (`v3.3`):** Nâng cấp từ nguyên mẫu `40-D/14-A` lên **`74-D` state, `36` actions, huấn luyện 4 giai đoạn `800 episodes` (`600` RAM + `200` Live-HTTP `:8056/:8055`)**, kết hợp **5 lá chắn OWASP API Top 10 vạn năng** (`SSRF`, `NoSQLi`, `Mass Assignment`, `Stateful BOLA`, `Response DLP`) và chính sách OpenAPI `route_tiered`. Trên kiểm định đối kháng Live-HTTP, Dueling-DQN vượt `93.3%` Legacy Rules (Familiar) nhưng bị Hybrid v3.0 chặn `100.0% (45/45)`, **Hybrid v3.3 chặn `100.00% (114/114)` trên cả 6 ô `Strange Suite v3.3`**, và trên **`Blind Held-Out Vault v2`** đạt **`28/30` Static (`26/30` DQN)** ở lượt đo đơn khóa SHA-256 đầu tiên và **`30/30 (100.00%)` trên cả 6 ô Hybrid** sau kiểm chứng `postfix2`.
5. **Đóng gói Hardened Containers & Chất lượng CI/CD:** 3 container non-root (`appuser` / `nextjs` UID 1001, tuyệt đối không mount `./attack-lab`), 3 `.dockerignore`, default `ACTIVE_BLOCKING`, `0` lỗi `ruff` trên toàn repo, toàn bộ bộ test tự động PASS 100% (hỗ trợ suy luận kép PyTorch + NumPy Zero-Pickle trên CI), `33/33` đối chiếu JSON–tài liệu khớp 100%, và `0` lỗi ESLint / TypeScript / Next.js production build.

---

## 5.2. Các Hạn Chế Còn Tồn Tại (System Limitations)

Nhóm nghiên cứu nhìn nhận thẳng thắn 3 giới hạn kỹ thuật còn tồn tại để làm cơ sở cải tiến ở các giai đoạn tiếp theo:
1. **Giới hạn mở rộng ghi phân tán của SQLite đơn nút:** Dù SQLite WAL Group Commit đáp ứng xuất sắc quy mô phòng lab và doanh nghiệp vừa (`250–340 RPS @ C=50`), ở quy mô cụm đa nút phân tán (Horizontal Auto-Scaling vượt ngưỡng `> 2.000 RPS`), cần thay thế bằng cơ sở dữ liệu máy chủ chuyên dụng (PostgreSQL/TimescaleDB) kết hợp Redis phân tán cho Rate Limiter và bộ đếm BOLA.
2. **Phạm vi giao thức nhị phân hiệu năng cao:** Multi-Protocol Sniffer đã hỗ trợ tốt `REST`, `GraphQL`, `SOAP/XML` và `JSON-RPC 2.0`, nhưng chưa giải mã trực tiếp giao thức nhị phân **gRPC (HTTP/2 + Protocol Buffers)** hoặc WebSockets luồng hai chiều.
3. **Phân quyền BOLA đơn lẻ theo sở hữu JWT sâu:** Dù bộ phát hiện `BOLADetector` cửa sổ trượt đã chặn hiệu quả các đợt dò quét liệt kê ngang (`>= 4` định danh đối tượng/60s) và ID bất thường (`<= 0`), việc chặn ngay lập tức 1 truy vấn đơn lẻ khi người dùng A truy cập đúng 1 bản ghi của người dùng B vẫn đòi hỏi tích hợp sâu với bảng ánh xạ quyền sở hữu tài nguyên (IAM / JWT Subject-to-Owner Policy).

---

## 5.3. Hướng Phát Triển Trong Tương Lai (Future Work)

1. **Kiến trúc Phân tán Cloud-Native (PostgreSQL + Redis Cluster + Kubernetes):** Tách tầng lưu trữ telemetry sang PostgreSQL/ClickHouse và đồng bộ trạng thái Sliding Window Rate Limiter qua Redis Lua Script để mở rộng ngang không trạng thái (Stateless Gateway Replicas).
2. **Đồng tiến hóa Đối kháng Trực tuyến (Online Adversarial Co-Evolution):** Thiết lập vòng lặp huấn luyện trực tiếp giữa PyTorch DQN Red Team và WAF Blue Team v2.0: tự động thu thập các mẫu cận biên hoặc biến thể mới phát sinh để tái huấn luyện định kỳ XGBoost v2.0 và hiệu chuẩn động Isolation Forest.
3. **Kiểm tra Giao thức gRPC/WebSockets & Phân tích Hành vi BOLA theo Phiên:** Mở rộng tầng decapsulation hỗ trợ Protobuf schema và mô hình đồ thị hành vi người dùng (UEBA) đối chiếu JWT subject với tài nguyên truy cập.
4. **Lọc Gói Tin Tầng Nhân eBPF/XDP & Quản trị Bí mật Doanh nghiệp:** Triển khai bộ lọc tầng nhân Linux eBPF/XDP chặn DDoS/IP vi phạm trước tầng người dùng, tích hợp HashiCorp Vault / KMS xoay vòng khóa tự động và cài cắm bẫy ảo (Honeytokens / Decoy Endpoints).

---

## 5.4. Lời Kết

Đề tài đã hiện thực hóa thành công một hệ sinh thái an ninh Web API toàn diện — nơi hai lực lượng **Blue Team v2.0** và **Red Team Offensive AI** trực tiếp kiểm chứng lẫn nhau trong môi trường thực tế minh bạch, hiệu năng cao và an toàn chuỗi cung ứng. Các kết quả lý thuyết, kiến trúc kỹ thuật, bằng chứng thực nghiệm và sản phẩm phần mềm hoàn chỉnh của đề tài không chỉ đáp ứng nghiêm ngặt yêu cầu học phần Đồ án Chuyên ngành PBL6 mà còn đặt nền móng vững chắc cho các nghiên cứu và ứng dụng bảo mật API trong thực tiễn doanh nghiệp.
