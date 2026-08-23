# Attack Lab Component (Local Security Testing)

Thư mục `attack-lab/` chịu trách nhiệm cung cấp các kịch bản tấn công (attack scenarios) và công cụ tự động hóa gửi request phục vụ kiểm thử, đo đạc và demo phòng thủ an ninh mạng trong môi trường Lab.

## Cấu trúc thư mục:
```text
attack-lab/
├── scenarios/
│   ├── sqli.json               # Kịch bản SQL Injection
│   ├── xss.json                # Kịch bản Cross-Site Scripting
│   ├── traversal.json          # Kịch bản Path Traversal
│   ├── command_injection.json  # Kịch bản Command Injection
│   ├── brute_force.json        # Kịch bản dò quét xác thực
│   ├── api_abuse.json          # Kịch bản gửi request tần suất cao
│   └── obfuscated.json         # Kịch bản payload biến đổi / mã hóa
├── campaigns/                  # Kịch bản chuỗi tấn công tổng hợp
└── runner.py                   # CLI tool thực thi gửi request tự động
```

## Nguyên tắc an toàn:
- Mọi payload và kịch bản chỉ được gửi tới địa chỉ đích trong môi trường Lab cục bộ (Target API / Gateway).
- Tuyệt đối không gửi payload tới các hệ thống bên ngoài hoặc môi trường thực tế.

> **LƯU Ý (Phase 0):** Chưa triển khai các kịch bản payload hoặc runner. Module này sẽ được xây dựng trong **Phase 10 — Attack Lab**.
