# Shared Module

Thư mục `shared/` dành riêng cho các contracts, types, schemas và utility functions dùng chung giữa các thành phần trong dự án (ví dụ giữa Gateway, ML Engine, và Testing scripts).

## Quy định:
- Không đưa business logic đặc thù của từng service vào đây.
- Các module phải có tính độc lập cao, không phụ thuộc vòng (circular dependency).
