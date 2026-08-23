# Hướng Dẫn Phát Triển & Môi Trường (Development Guide)

Tài liệu này cung cấp hướng dẫn thiết lập môi trường phát triển cục bộ, chạy kiểm thử, định dạng mã nguồn và vận hành hệ thống qua Docker.

---

## 1. Yêu Cầu Cài Đặt (Prerequisites)

* **Python:** Phiên bản 3.11 trở lên (Khuyến nghị Python 3.12).
* **Node.js:** Phiên bản 18+ kèm `npm`.
* **Docker & Docker Compose:** Đã cài đặt và đang chạy Docker Desktop.
* **Git:** Quản lý mã nguồn.

---

## 2. Thiết Lập Môi Trường (Environment Setup)

### Bước 1: Sao chép cấu hình mẫu
Từ thư mục gốc dự án:
```bash
# Trên Linux/macOS
cp .env.example .env

# Trên Windows PowerShell
Copy-Item .env.example .env
```

### Bước 2: Cài đặt thư viện Backend
```bash
cd gateway
pip install -e .
# Hoặc cài đặt dependencies trực tiếp
pip install fastapi uvicorn pydantic pydantic-settings sqlalchemy httpx pytest pytest-cov ruff
cd ..
```

### Bước 3: Cài đặt thư viện Frontend
```bash
cd dashboard
npm install
cd ..
```

---

## 3. Khởi Chạy Cục Bộ (Local Execution)

### A. Khởi chạy Gateway Backend
```bash
cd gateway
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
* Kiểm tra endpoint: [http://localhost:8000/health](http://localhost:8000/health)
* Tài liệu Swagger API: [http://localhost:8000/docs](http://localhost:8000/docs)

### B. Khởi chạy Dashboard Frontend
```bash
cd dashboard
npm run dev
```
* Truy cập giao diện: [http://localhost:3000](http://localhost:3000)

---

## 4. Khởi Chạy Bằng Docker Compose (Khuyến nghị)

Để khởi chạy toàn bộ hệ thống gồm Target Web API (Juice Shop), Gateway và Dashboard chỉ với 1 lệnh:

```bash
# Build và chạy ngầm các container
docker compose up --build -d

# Xem log thời gian thực
docker compose logs -f

# Dừng và dọn dẹp containers
docker compose down
```

Các cổng dịch vụ khi chạy Docker:
* **Gateway:** [http://localhost:8000](http://localhost:8000)
* **Dashboard:** [http://localhost:3001](http://localhost:3001)
* **Target Juice Shop:** [http://localhost:3000](http://localhost:3000)

---

## 5. Kiểm Thử & Kiểm Tra Chất Lượng Mã Nguồn (Testing & Quality)

### A. Chạy Unit Tests
```bash
cd gateway
pytest
cd ..
```

### B. Kiểm tra Lint & Format (Ruff)
```bash
# Kiểm tra lỗi linting
ruff check .

# Tự động sửa các lỗi format cơ bản
ruff format .
```

### C. Kiểm tra Build Frontend
```bash
cd dashboard
npm run build
cd ..
```

---

## 6. Xử Lý Sự Cố Thường Gặp (Troubleshooting)

1. **Lỗi cổng bị chiếm dụng (Port conflict):**
   * Đảm bảo các cổng `8000`, `3000`, `3001` không bị ứng dụng khác chiếm giữ trước khi chạy `docker compose up`.
2. **Lỗi không tìm thấy file database:**
   * SQLite tự động tạo file tại `data/waf_security.db`. Đảm bảo thư mục `data/` có quyền ghi.
