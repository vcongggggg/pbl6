# CHƯƠNG 5: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

---

## 5.1. Tổng Kết Các Kết Quả Đạt Được Của Đề Tài

Đề tài **"Nền tảng Giám sát, Phát hiện và Ngăn chặn Tấn công Web API dựa trên AI/ML kết hợp Môi trường Thao trường Mạng (Cyber Range) Phân tán"** đã hoàn thành toàn diện mọi mục tiêu đặt ra cho cả hai phân hệ **Blue Team v2.0 (Nguyễn Văn Công)** và **Red Team Offensive AI (Nguyễn Minh)**:

### 5.1.1. Thành tựu về mặt Học thuật và Khoa học Dữ liệu
1. **Hệ thống hóa 20 tài liệu chuẩn mực quốc tế:** Kết hợp 5 giáo trình kinh điển (Stallings, Stinson, Katz & Lindell, CompTIA PenTest+, NGINX Cookbook), 5 tiêu chuẩn công nghiệp (OWASP API Top 10, ModSecurity CRS v4.0, OWASP Benchmark, NIST SP 800-115, MITRE ATT&CK) và 10 công trình khoa học trọng điểm (Liu et al. ICDM 2008, Breiman 2001, Chen & Guestrin KDD 2016 XGBoost, Torrano-Gimenez Wiley 2015, Yamin Elsevier 2020, Sutton & Barto, Mnih Nature 2015, Goodfellow ICLR 2015, MDPI 2025, USENIX 2024).
2. **Đảm bảo tuyệt đối Liêm chính Khoa học (Zero-Leakage & Zero-Skew):** Xây dựng bộ dữ liệu `defense_v2` (`46.187` mẫu) phân tách theo mã băm chuẩn hóa không rò rỉ với CSIC 2010 và `benchmark_1000_diverse.csv`; thống nhất 100% bộ trích xuất **26 đặc trưng (`extract_26_from_http`)** giữa Training và Serving; loại bỏ 100% số liệu mô phỏng trên cả SOC Dashboard lẫn Đấu Trường AI.
3. **Chứng minh định lượng sức mạnh Phòng thủ Chiều sâu (Defense-in-Depth):**
   - Thực nghiệm Ablation Study v2.0 chứng minh **Hybrid Defense v2.0** đạt **98.61% F1-Score, 97.25% Recall, 0.00% FPR, Youden's Index `J = 0.9725`** trong **`0.848 ms/req`** (vượt `+1.97%` F1 và `+3.75%` Recall so với XGBoost đơn lẻ).
   - Trên tập ngoại miền Zero-Shot **CSIC 2010**, hạ **FPR từ 29.60% xuống 0.00%** với **100.00% Precision** và **100.00% Hybrid XSS**, đồng thời phân tích trung thực giới hạn *Domain Shift* của nhóm `ANOMALY_TAMPER`.

### 5.1.2. Thành tựu về mặt Kỹ thuật, Bảo mật và Triển khai Thực tiễn
1. **Cổng WAF Gateway v2.0 Chịu tải cao & Bền vững:** Offload xử lý CPU-bound qua `anyio.to_thread.run_sync`, pure ASGI middleware, RAM TTL cache `waf_mode`, SQLite WAL Leader-Follower Group Commit -> đạt **`253–340 RPS` ở `C = 50`** (`0.867 ms` AI pipeline, `1.095 ms` full inspection).
2. **An toàn Chuỗi Cung Ứng AI & Gia cố 26 Lỗ hổng Kiểm toán:** Chuyển 100% mô hình phòng thủ sang **Zero-Pickle** (`xgb_v2.ubj` + `iforest_v2.npz`, `allow_pickle=False`) kèm xác thực SHA-256 Fail-Closed; gia cố `evasion_agent.pt` bằng `torch.load(..., weights_only=True)` + SHA-256; vá triệt để ReDoS (`923.37 ms -> 0.891 ms`), padding > 16 KB, chunked > 1 MB (413), IP Hard Cap Rate Limiter, Fail-Closed RuleEngine và Next.js Server-Side BFF Proxy (`0` client secrets).
3. **Làm chủ 100% Ứng dụng Đích Bookie Bookstore (`vulnerable-api`):** Hệ thống Django độc lập chứa 8 nhóm lỗ hổng OWASP Web & API Top 10, OpenAPI 3.0 và kiểm chứng HMAC `compare_digest`, cô lập loopback `127.0.0.1:5000`.
4. **Hoàn thiện Tác tử Pentest Tự Hành Dueling-DQN v2.0 & Cockpit `/arena` (`v3.0`):** Nâng cấp kiến trúc từ bộ đột biến cục bộ lên chu trình **5 pha kiểm thử xâm nhập tự động** (`OpenAPI Recon -> Attack Graph -> Baseline Probe -> 64-D PyTorch Dueling-DQN Evasion & Pivot -> Verdict & Live SSE`), kết hợp **5 lá chắn OWASP API Top 10 vạn năng** (`SSRF`, `NoSQLi`, `Mass Assignment`, `Stateful BOLA Enumeration`, `Outbound Response DLP`). Thực nghiệm ma trận 3x3 xác nhận Dueling-DQN v2.0 đạt **`93.3%` Evasion** trước WAF tĩnh nhưng bị **Blue Team v3.0 Hybrid** vô hiệu hóa **`100.0%` (`45/45` lượt, `1.34 ms`)**.
5. **Đóng gói Hardened Containers & Chất lượng CI/CD:** 3 container non-root (`appuser` / `nextjs`), 3 `.dockerignore`, default `ACTIVE_BLOCKING`, `0` lỗi `ruff` trên toàn repo, **`360+` test tự động PASS 100%** (hỗ trợ suy luận kép PyTorch + NumPy Zero-Pickle trên CI) và `0` lỗi ESLint / TypeScript / Next.js production build.

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
