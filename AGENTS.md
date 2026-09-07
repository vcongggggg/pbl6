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
