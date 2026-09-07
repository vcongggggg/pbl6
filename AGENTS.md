# Hướng Dẫn & Quy Tắc Thực Hiện PBL6 (AGENTS.md)

Tài liệu này định nghĩa các ràng buộc hành vi bắt buộc cho AI Agent khi thực thi công việc trong repository PBL6.

---

## 1. Quy tắc GitHub Tasks & Issues (Bắt buộc kiểm tra trước khi tạo)
- **Kiểm tra trùng lặp**: Luôn kiểm tra danh sách issues (`gh issue list` hoặc GitHub tool) hoặc file `scripts/create_all_subtasks.py` trước khi tạo task mới.
- **Tránh trùng số Task**: Tuyệt đối không tự gán số Task (như `Task 9.4`) nếu số đó đã tồn tại trong Backlog. Nếu là task phát sinh, tự động tăng lên số tiếp theo (ví dụ: `Task 9.5`).
- **Liên kết Phase cha**: Mọi subtask phải được liên kết vào Parent Issue tương ứng (Phase 9 là #10) và gán nhãn đầy đủ (`phase-9`, `dashboard`, `member-a`).

## 2. Quy tắc Tính nhất quán UI & Thang đo (Metrics & Scale)
- **Thang đo Threat Score**: Thang đo chuẩn toàn hệ thống là `0 - 100`. Tuyệt đối không hardcode mẫu số tùy tiện (như `/ 10.0`).
- **Drawer / Modal UX**: Phải có backdrop mờ, đóng được bằng phím `Escape` và click bên ngoài.
- **Biểu đồ & Bảng**: Kiểm tra responsive, không để text bị cắt xén (`whitespace-nowrap`, font size phù hợp).

## 3. Quy trình Kiểm thử trước khi Bàn giao (Verification)
- **Backend**: Chạy `pytest gateway/tests` đảm bảo 100% tests pass.
- **Frontend**: Chạy `npm run build` trong `dashboard` không có lỗi TypeScript hay cú pháp.
- **Docker**: Rebuild và kiểm tra container bằng `docker compose ps`.

## 4. Ngôn ngữ
- Toàn bộ Issues, PR, Commits và trao đổi kỹ thuật phải dùng **Tiếng Việt chuyên nghiệp**.

## 5. Quy tắc Đồng bộ Tài liệu & Chống Trôi Kiến Trúc (Docs Sync & Anti-Drift)
- **Cập nhật Docs ngay khi đổi kiến trúc/hạ tầng**: Khi thay đổi Upstream Target (như thay OWASP Juice Shop bằng `vulnerable-api` Bookie Bookstore), đổi Port hoặc thêm cơ chế mới, **bắt buộc chạy `grep_search`** để rà soát và cập nhật toàn bộ `README.md`, thư mục `docs/` và sơ đồ kiến trúc.
- **Xóa sạch di chứng code/test cũ**: Cập nhật toàn bộ file test (`tests/integration/test_gateway_live.py`) và scripts mock, không để sót endpoints hoặc mocks của Juice Shop cũ.

## 6. Quy tắc Thẩm định Source Code Thực tế & Phân định Cổng Dịch vụ (Single Source of Truth)
- **Đọc trực tiếp `docker-compose.yml`**: Không dựa vào trí nhớ cũ khi hướng dẫn User về URL, Port hay cách truy cập. Luôn đọc file cấu hình thực tế.
- **Bảng phân định Cổng dịch vụ chuẩn**:
  - `http://localhost:3000`: **SOC Dashboard UI** (Next.js 14 Frontend).
  - `http://localhost:8000`: **WAF Gateway** (FastAPI Reverse Proxy).
  - `http://localhost:5000`: **Target Web API** (`vulnerable-api` Bookie Bookstore).
  - *Cảnh báo*: Tuyệt đối không nhầm lẫn port 3000 của Dashboard với Juice Shop ngày xưa, và không để Gateway trỏ nhầm sang Juice Shop.
