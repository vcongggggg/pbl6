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

Để khởi chạy toàn bộ hệ thống gồm Target Web API tự xây dựng (`vulnerable-api`), Gateway và Dashboard chỉ với 1 lệnh:

```bash
# Build và chạy ngầm các container
docker compose up --build -d

# Xem log thời gian thực
docker compose logs -f

# Dừng và dọn dẹp containers
docker compose down
```

Các cổng dịch vụ khi chạy Docker:
* **Gateway (WAF):** [http://localhost:8000](http://localhost:8000)
* **Dashboard (SOC):** [http://localhost:3000](http://localhost:3000) (hoặc 3001)
* **Target Vulnerable Web API:** [http://localhost:5000](http://localhost:5000)

---

## 5. Thiết Lập Thao Trường Đối Kháng 2 Máy (Cyber Range Qua Mạng LAN)

Mô hình diễn tập thực chiến giữa 2 máy tính vật lý kết nối chung mạng Wi-Fi/LAN:

### Bước 1: Thiết lập Máy 1 (Blue Team — Defender)
1. Kiểm tra địa chỉ IP mạng LAN của Máy 1 (ví dụ: `192.168.1.15`):
   ```bash
   ipconfig   # Trên Windows PowerShell
   ```
2. Đảm bảo Gateway lắng nghe trên `0.0.0.0:8000` để các máy khác trong mạng gọi tới được.
3. Khởi chạy toàn bộ stack:
   ```bash
   docker compose up -d
   ```
4. Mở Dashboard tại `http://localhost:3000` để sẵn sàng quan sát cảnh báo.

### Bước 2: Thiết lập Máy 2 (Red Team — Attacker)
1. Kết nối vào chung mạng Wi-Fi/LAN với Máy 1.
2. Kiểm tra kết nối tới Máy 1:
   ```bash
   curl http://192.168.1.15:8000/health
   curl http://192.168.1.15:8000/api/proxy/api/v1/health
   ```
3. Khởi chạy AI Attack Planner hoặc runner kịch bản tấn công:
   ```bash
   python attack-lab/cli.py --target http://192.168.1.15:8000/api/proxy --campaign sqli
   ```
4. Quan sát phản hồi: Nếu WAF chặn sẽ trả về `HTTP 403 Forbidden`, AI Attack Planner sẽ tự động chuyển sang chế độ Adaptive Evasion để thử vượt rào!

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
