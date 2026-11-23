# BÁO CÁO KIỂM TOÁN VÀ XÁC THỰC CỤM DOCKER COMPOSE MULTI-CONTAINER (BLUE TEAM v2.0)

- **Mã công việc:** Task 12.2 & Sprint 4 Hardening (`INFRA-PBL6-001`)
- **Người thực hiện:** Nguyễn Văn Công (`vcongggggg` — Tech Lead / Blue Team)
- **Thời gian tái kiểm định:** 2026-11-23
- **Kết luận:** `[VERIFIED PASS]` — Đạt chuẩn cấu hình Multi-Container Hardened

---

## 1. Bảng Tổng Hợp Kiểm Định Hạ Tầng Container (Verification Matrix)

| Hạng mục kiểm tra | Trạng thái | Chi tiết kỹ thuật đã xác minh |
| :--- | :---: | :--- |
| **`docker-compose.yml` Syntax & Env** | **PASS** | `docker compose config --quiet` thoát mã `0` (0 cảnh báo) |
| **Default WAF Mode** | **PASS** | `WAF_MODE=${WAF_MODE:-ACTIVE_BLOCKING}` (an toàn mặc định) |
| **Per-Service `.dockerignore`** | **PASS** | Đủ 3 tệp riêng tại `gateway/.dockerignore`, `dashboard/.dockerignore`, `vulnerable-api/.dockerignore` |
| **Non-Root Container Hardening** | **PASS** | `gateway/Dockerfile` & `vulnerable-api/Dockerfile`: `USER appuser` (UID 1001); `dashboard/Dockerfile`: `USER nextjs` (UID 1001) |
| **Node.js Runtime Alignment** | **PASS** | `dashboard/Dockerfile` đồng bộ `node:20-alpine` + `RUN npm ci` khớp CI |
| **Gateway ML Runtime Dependencies** | **PASS** | `gateway/pyproject.toml` khai báo đầy đủ `xgboost>=2.0.0`, `numpy`, `scikit-learn`, `fastapi`, `uvicorn` |
| **Zero-Pickle Read-Only Artifacts** | **PASS** | Bind mount `./ml-engine/artifacts:/app/ml-engine/artifacts:ro` (`xgb_v2.ubj`, `iforest_v2.npz`, `*_metadata.json`) + `./ml-engine/features:/app/ml-engine/features:ro` |
| **Target API Loopback Isolation** | **PASS** | `vulnerable-api` chỉ bind `127.0.0.1:5000:5000` (chặn truy cập trực tiếp từ mạng LAN vượt qua WAF) |
| **Next.js BFF Secret Protection** | **PASS** | `ADMIN_API_KEY` chỉ truyền server-side vào `gateway` và `dashboard`; không dùng `NEXT_PUBLIC_ADMIN_API_KEY` |

---

## 2. Kiến Trúc Điều Phối 3 Container (`pbl6-network`)

```text
  [ Client / Red Team LAN ]  --->  Port 8000  --->  [ pbl6-gateway (USER appuser) ]
                                                    FastAPI Async WAF + XGBoost v2 + IForest v2
                                                    Volumes: ./data (RW), ./ml-engine/artifacts (RO)
                                                              |
                                         (condition: service_healthy, internal pbl6-network)
                                                              v
                                                    [ pbl6-vulnerable-api (USER appuser) ]
                                                    Django Bookie Bookstore (127.0.0.1:5000 loopback)

  [ SOC Analyst Browser ]    --->  Port 3000  --->  [ pbl6-dashboard (USER nextjs) ]
                                                    Next.js 14 + Server-Side BFF (/api/gateway/*)
                                                    BACKEND_URL=http://gateway:8000 (X-API-Key server-side)
```

---

## 3. Lệnh Vận Hành Cụm Container Cho Buổi Demo

```bash
# 1. Đảm bảo tệp .env tồn tại (copy từ .env.example nếu chạy máy mới)
cp .env.example .env

# 2. Build và khởi chạy cụm 3 container ở chế độ nền
docker compose up --build -d

# 3. Kiểm tra trạng thái healthcheck của cả 3 container
docker compose ps

# 4. Theo dõi log thời gian thực của WAF Gateway
docker compose logs -f gateway

# 5. Dừng cụm container sau khi hoàn tất trình chiếu
docker compose down
```
