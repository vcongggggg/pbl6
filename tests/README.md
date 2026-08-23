# Testing Strategy & Root Test Suite

Thư mục `tests/` định nghĩa cấu trúc và chiến lược kiểm thử cho toàn bộ hệ thống Web API Security Platform.

## Phân loại kiểm thử trong dự án:

1. **Unit Tests (`gateway/tests/`, `ml-engine/tests/`):**
   - Kiểm thử từng hàm, module trích xuất đặc trưng, rule patterns, risk engine, database models độc lập.

2. **Integration Tests (`tests/integration/`):**
   - Kiểm thử tương tác giữa Gateway $\leftrightarrow$ Target Web API, Gateway $\leftrightarrow$ SQLite DB, Dashboard $\leftrightarrow$ Gateway API.

3. **Security & Evasion Tests (`tests/security/`):**
   - Kiểm thử phát hiện các mẫu payload tấn công (SQLi, XSS, Path Traversal, Command Injection) và các payload biến đổi (obfuscated, encoded).
   - Kiểm thử False Positive Rate trên các request lành tính có chứa ký tự đặc biệt.
   - Kiểm thử bảo mật cho chính Admin API (Unauthenticated access, invalid API key).

4. **Performance Benchmark (`tests/performance/`):**
   - Đo đạc độ trễ (latency) và thông lượng (throughput) qua các tầng: Direct API vs Gateway vs Gateway+ML vs Gateway+Hybrid.

## Cách chạy kiểm thử:
```bash
# Chạy toàn bộ unit tests
pytest

# Chạy kèm đo coverage
pytest --cov=gateway
```
