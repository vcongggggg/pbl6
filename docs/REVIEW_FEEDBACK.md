# 📋 REVIEW FEEDBACK & ACTIONABLE TASKS (DÀNH CHO PHIÊN CODER @PBL6)

## 🚨 CHỈ THỊ KHẨN CẤP TỪ ANH VĂN CÔNG: NÂNG CẤP TRIỆT PHÁ 2 ĐIỂM YẾU CỦA PHASE 8
- **Reviewer:** @reviewer (Senior Security Architect & Independent Code Reviewer)
- **Đối tượng thực thi:** @pbl6 (Tech Lead / Coder Session: `a066db5c-22d0-4ca5-becb-95c29e232a63`)
- **Nguyên tắc phân vai:** 
  - Phiên @reviewer: Tuyệt đối Read-only & Audit, KHÔNG can thiệp chỉnh sửa code.
  - Phiên @pbl6: Chịu trách nhiệm 100% việc viết code, bổ sung test và chạy verification.
  - **LƯU Ý SỐNG CÒN:** Khi @pbl6 làm xong, TỰ ĐỘNG THÔNG BÁO NGƯỢC LẠI CHO @REVIEWER ĐỂ KIỂM ĐỊNH LẠI, **TUYỆT ĐỐI KHÔNG LÀM PHIỀN ĐẾN ANH CÔNG!**

---

### 🎯 NHIỆM VỤ 1: EXPONENTIAL BACKOFF THROTTLING (CHỐNG SLOW-AND-LOW SCAN)
- **Vấn đề cần giải quyết:** Cửa sổ trượt 60s hiện tại bị 'đãng trí' (memoryless), cứ hết 60s là kẻ tấn công được tha bổng 100%, cho phép botnet vét mật khẩu rỉ rả 9 req/phút tại `/rest/user/login` cả ngày mà không bị chặn.
- **Yêu cầu kỹ thuật:**
  - [x] Trong `gateway/app/security/rate_limiter.py`:
    - Thêm cấu trúc lưu lịch sử vi phạm: `self._violation_history: dict[str, deque[float]] = defaultdict(deque)` với thời gian theo dõi T_tracking = 600.0 giây (10 phút).
    - Mỗi khi `is_limited == True`:
      - Nạp t_now vào `self._violation_history[key]`.
      - Dọn dẹp các vi phạm cũ quá 600s: `while hist and hist[0] <= now - 600.0: hist.popleft()`.
      - Tính số lần vi phạm trong 10 phút gần nhất: k = len(hist).
      - Nếu k >= 3: Thời gian phạt tăng lũy tiến theo cấp số nhân:
        Delta t_retry = min(900, 60 * 2**(k - 2))
        *(Ví dụ: lần 3 vi phạm: 120s, lần 4: 240s, lần 5: 480s, tối đa 900s / 15 phút)*.
    - Cập nhật trường `retry_after` trong `RateLimitResult`.
  - [x] Trong `gateway/app/api/proxy.py`:
    - Header `Retry-After` và trường `retry_after` trong RFC 7807 Problem Details nhận giá trị lũy tiến này.

---

### 🎯 NHIỆM VỤ 2: FINGERPRINT & SESSION-AWARE SCOPING (CHỐNG BẪY PHẠT OAN SAU MẠNG NAT)
- **Vấn đề cần giải quyết:** Khóa rate-limit hiện tại chỉ dựa vào `client_ip`. Nếu nhiều người dùng chung WiFi trường học/công ty (chung 1 IP NAT Public), một kẻ xấu bị phạt sẽ khiến toàn bộ người dùng lành tính khác bị chặn 429 oan.
- **Yêu cầu kỹ thuật:**
  - [x] Trong `gateway/app/security/rate_limiter.py`:
    - Mở rộng hàm `check_rate_limit`:
      ```python
      def check_rate_limit(
          self,
          client_ip: str,
          path: str,
          risk_penalty: bool = False,
          session_id: str | None = None,
          user_agent: str | None = None,
      ) -> RateLimitResult:
      ```
    - Quy tắc sinh khóa định danh (Composite Tracking Key):
      - Băm ngắn User-Agent (6 ký tự MD5/SHA256) nếu có.
      - Trích xuất token định danh từ Session/Token nếu có.
      - Nếu có Session/Token: Key = client_ip + "::" + session_id + "::" + scope.
      - Nếu không có Session nhưng có User-Agent: Key = client_ip + "::" + ua_hash + "::" + scope.
      - Fallback: Key = client_ip + "::" + scope.
  - [x] Trong `gateway/app/api/proxy.py`:
    - Trích xuất `user_agent = request.headers.get("user-agent")`.
    - Trích xuất `session_id` từ header `authorization` (Bearer token) hoặc cookie `session_id` / `token`.
    - Truyền vào `rate_limiter.check_rate_limit(...)`.

---

### 🎯 NHIỆM VỤ 3: VIẾT TEST VÀ KIỂM ĐỊNH TOÀN BỘ SUITE
- [x] Bổ sung ít nhất 3 unit tests mới trong `gateway/tests/test_rate_limiter.py`:
  - `test_exponential_backoff_after_multiple_violations`: Kiểm tra vi phạm 3 lần thì `retry_after >= 120`.
  - `test_session_aware_scoping_separates_clients_on_same_ip`: Kiểm tra 2 clients cùng IP nhưng khác User-Agent / Session không bị phạt lẫn nhau.
  - `test_violation_history_cleanup_after_window`: Kiểm tra dọn dẹp lịch sử vi phạm quá 10 phút.
- [x] Chạy `pytest gateway/tests/` đảm bảo toàn bộ >= 88 tests PASSED 100%, linter 0 lỗi. (Thực tế: 88/88 tests PASS 100%, Ruff 0 lỗi ✅)

---

### 🎯 NHIỆM VỤ 4: TỰ ĐỘNG THÔNG BÁO CHO @REVIEWER SAU KHI HOÀN THÀNH
Sau khi code xong và test pass 100%, @pbl6 hãy tự động dispatch thông báo hoàn thành sang phiên Reviewer (ID: `38cd4070-7666-46bb-b25c-d6c70ab2c5da`) để Reviewer tự động vào kiểm tra thẩm định lại độc lập.

**LƯU Ý: Tuyệt đối không làm phiền đến anh Văn Công!**

---

# 📋 REVIEW FEEDBACK & ACTIONABLE TASKS (DÀNH CHO PHIÊN CODER)

## Cập Nhật Mới Nhất: ĐÁNH GIÁ CHIẾN LƯỢC & ĐỊNH HƯỚNG PHASE 8 (Tasks 8.1 & 8.2)
- **Reviewer:** @reviewer (Senior Security Architect & Code Reviewer)
- **Hạng mục thẩm định:** Rà soát các task Phase 8, so sánh giữa việc giữ nguyên hướng báo cáo học thuật hay tìm hướng đi mới.
- **Kết luận thẩm định:** 🟢 **APPROVE & STRATEGIC RECOMMENDATION: KẾ THỪA 100% BÁO CÁO CỐT LÕI + MỞ RỘNG ĐỘT PHÁ CẢI TIẾN**

### 1. Phân Tích So Sánh Độc Lập:
1. **Lý do bắt buộc giữ hướng tiếp cận của Báo cáo hiện tại (Core Base):**
   - **Cơ sở toán học vững chắc:** Thuật toán *Sliding Window Counter* trên collections.deque với chi phí khấu hao $\mathcal{O}(1)$ đã triệt tiêu hoàn toàn lỗ hổng *Bursty Boundary Attack* (vốn là nhược điểm chí mạng của Fixed Window Counter).
   - **Đối chiếu học thuật quốc tế:** Đã trích dẫn và bám sát 2 bài báo uy tín: *Yakhchi et al. (IEEE Access, 2020)* về định hình lưu lượng và *Al-Haija et al. (Elsevier, 2022)* về điều tiết hạn ngạch thích ứng rủi ro.
   - **Cơ chế liên tầng độc đáo (Defense-in-Depth):** Phối hợp trực tiếp với Decision Engine (Phase 7) để siết phạt 50% hạn mức khi điểm rủi ro  \in [60, 80)$.
   - **Chuẩn hóa công nghiệp:** Đạt chuẩn IETF RFC 6585 (HTTP 429) và RFC 7807 (Problem Details JSON), đầy đủ headers Retry-After, X-RateLimit-*.
   - **Chất lượng kiểm thử:** Toàn bộ 85/85 tests PASSED, 0 lint errors.

2. **Rủi ro nếu đập đi tìm hướng đi mới từ đầu:**
   - Dễ gây vỡ kiến trúc (Architectural Drift), trễ hạn nộp đồ án và mất đi nền tảng lý thuyết đã viết rất công phu trong Chương 1 và tài liệu học thuật.

### 2. Hai Đề Xuất Đột Phá Nâng Cấp (Tạo Điểm Nhấn Sáng Tạo Đồ Án):
Thay vì đổi hướng, Coder nên giữ nguyên core trên và phát triển thêm 1 trong 2 tính năng mở rộng sau:
- [ ] **Đề xuất 1 (Khuyên dùng - Điểm 10 sáng tạo): Exponential Backoff Throttling:**
  - Theo dõi lịch sử vi phạm của từng IP trong 10 phút gần nhất.
  - Nếu một IP chạm trần phạt $\ge 3$ lần liên tiếp, tự động nâng thời gian chờ theo cấp số nhân (\text{s} \to 120\text{s} \to 300\text{s}$), hoặc kích hoạt chuyển trạng thái sang tạm khóa IP (Temporary Blacklist).
- [ ] **Đề xuất 2 (Thực tế production): Fingerprint / Session-Aware Throttling:**
  - Kết hợp định danh: $\text{Key} = \text{IP} \mathbin{\Vert} \text{SessionID / Bearer Token}$ thay vì chỉ dựa vào IP thuần túy, ngăn ngừa phạt oan (False Positive Throttling) cho các client lành tính đang dùng chung dải mạng NAT/WiFi trường học.

### 3. Lệnh Mẫu Cho User Copy Vào Phiên Coder (Khi Muốn Mở Rộng):
`	ext
Hãy đọc docs/REVIEW_FEEDBACK.md và thực hiện bổ sung tính năng Exponential Backoff Throttling cho Rate Limiter theo đề xuất của @reviewer.
`

---

# 📋 REVIEW FEEDBACK & ACTIONABLE TASKS (DÀNH CHO PHIÊN CODER)

## Cập Nhật Mới Nhất: PR #85 (Task 6.1 & 6.2 - Isolation Forest Training & Anomaly Score Normalization)
- **Reviewer:** @reviewer (Senior Security Architect & Code Reviewer)
- **Trạng thái thẩm định:** 🟢 **APPROVE (9.7/10) - PHASE 6 KHỞI ĐỘNG XUẤT SẮC, ĐỦ ĐIỀU KIỆN MERGE ✅**
- **Đánh giá mức độ bám sát Kế hoạch (Plan Alignment):**
  - [x] Triển khai trọn vẹn cả Task 6.1 (`ml-engine/models/train_iforest.py`) và Task 6.2 (Chuẩn hóa Risk Score 0–100 theo tiêu chuẩn MDPI Electronics 2025).
  - [x] Huấn luyện độc lập trên baseline $10.000$ mẫu Benign thuần túy (`data/synthetic_benign.csv`) với 17 đặc trưng canonical.
  - [x] Siêu tham số chuẩn học thuật Liu et al. (ICDM 2008): $n\_estimators=100$, $max\_samples=256$, $contamination=0.01$, $n\_jobs=1$.
  - [x] Tỷ lệ báo động nhầm (False Alarm Rate) trên tập kiểm định Validation $2.000$ mẫu cực thấp: **chỉ $0.70\%$** (Inlier Rate: $99.30\%$), điểm rủi ro trung bình trên Benign chỉ $1.99 / 100$.
  - [x] Độ trễ suy luận siêu tốc: **$0.010\text{ms}$ / mẫu** (chưa tới $10\mu\text{s}$, ~100.000 req/s), file model nén gọn $241\text{ KB}$.
  - [x] Khóa mã băm SHA-256 `14ffdee985408642785ccdbb035bc7fecc0b6921316fb6c7b06ae1f741c08e71` khớp chính xác 100%.
  - [x] Thêm 7 unit tests mới trong `test_train_iforest.py`. Toàn bộ **191 tests** (112 tests unit/ml-engine + 79 tests gateway) PASS 100%. Linter 0 lỗi.
- **Lưu ý & Khuyến nghị kỹ thuật:**
  - [x] **Khuyến nghị an ninh:** Đã bổ sung bước xác thực mã SHA-256 trước khi load `iforest_model.joblib` trong `AnomalyDetector` (tương tự khuyến nghị của PR #84) để chống tấn công deserialization CWE-502.
  - [x] **Nhiệm vụ hoàn thành:** Task 6.3 (Issue #28): Kiểm thử bắt tấn công Zero-Day & Obfuscation Evasion** xuất báo cáo `docs/reports/anomaly_eval.md`.
- **Hành động tiếp theo:**
  1. Merge PR #85 vào nhánh `main`.
  2. Bắt đầu Task 6.3 (Đánh giá bắt Zero-Day và Payload Evasion bằng Isolation Forest).

---

## Lịch Sử Thẩm Định: PR #84 (Task 5.3 - Champion Model Serialization & Gateway Integration)
- **Reviewer:** @reviewer
- **Trạng thái thẩm định:** 🟢 **APPROVE (9.5/10) - PHASE 5 CHÍNH THỨC HOÀN THÀNH 100% ✅**

---

## Lịch Sử Thẩm Định: PR #83 (Task 5.2 - Champion RF Fine-Tuning, Validation & Feature Importance)
- **Reviewer:** @reviewer
- **Trạng thái thẩm định:** 🟢 **APPROVE (9.2/10) - ĐÃ KHẮC PHỤC HOÀN TOÀN FEEDBACK ✅**

---

## Lịch Sử Thẩm Định: PR #82 (Task 5.1 - Multi-Model Candidate Benchmarking Pipeline)
- **Reviewer:** @reviewer
- **Trạng thái thẩm định:** 🟢 **APPROVE (9.6/10) - SẴN SÀNG MERGE VÀO MAIN ✅**
