# BÁO CÁO KIỂM TOÁN VÀ XÁC THỰC CỤM DOCKER COMPOSE MULTI-CONTAINER (PHASE F2 — 4 CONTAINERS)

- **Mã công việc:** Phase F2 Hardening (`INFRA-PBL6-001` / 1-Command Clean-Checkout Demo)
- **Người thực hiện:** Nguyễn Văn Công (`vcongggggg` — Tech Lead / Blue Team)
- **Thời gian tái kiểm định:** 2026-11-25
- **Kết luận:** `[VERIFIED PASS]` — Sẵn sàng khởi chạy 1 lệnh (`docker compose up --build -d`) trên bản clone sạch không cần `cp .env.example .env`

---

## 1. Bảng Tổng Hợp Kiểm Định Hạ Tầng Container (Verification Matrix)

| Hạng mục kiểm tra | Trạng thái | Chi tiết kỹ thuật đã xác minh |
| :--- | :---: | :--- |
| **`docker-compose.yml` Syntax & Env** | **PASS** | `docker compose config` thoát mã `0` trên repo sạch không cần `.env` |
| **1-Command Clean Checkout** | **PASS** | `ADMIN_API_KEY=${ADMIN_API_KEY:-dev-admin-secret-key-change-me}`, `WAF_MODE=${WAF_MODE:-ACTIVE_BLOCKING}` & `DEMO_ADMIN_PASSWORD=${DEMO_ADMIN_PASSWORD:-}` có giá trị mặc định inline; `vulnerable-api/entrypoint.sh` tự sinh mật khẩu ngẫu nhiên tạm thời (ephemeral) nếu `DEMO_ADMIN_PASSWORD` để trống (không hardcode mật khẩu tĩnh trong image) |
| **4-Container Topology** | **PASS** | `vulnerable-api` + `ml-engine` + `gateway` + `dashboard` trên mạng bridge `pbl6-network` |
| **Zero `./attack-lab` Isolation** | **PASS** | Không có bất kỳ volume mount hoặc dependency nào tới `./attack-lab` trong cả 4 container |
| **ML Engine Sidecar (`pbl6-ml-engine`)** | **PASS** | `python:3.12-slim` mount `:ro` chỉ `./ml-engine/artifacts` & `./ml-engine/features`, xác thực SHA-256 `xgb_v2.ubj` + `iforest_v2.npz`, chạy smoke inference 26-D và phục vụ `GET /health` (`127.0.0.1:8001`) |
| **Gateway In-Process ML Inference** | **PASS** | `gateway` giữ suy luận nội tiến trình (in-process) qua `./ml-engine/artifacts:ro` & `./ml-engine/features:ro` để bảo toàn độ trễ ~0.7ms inline |
| **Per-Service `.dockerignore`** | **PASS** | Đã xác minh sạch trên `gateway/.dockerignore`, `dashboard/.dockerignore`, `vulnerable-api/.dockerignore` |
| **Non-Root Container Hardening** | **PASS** | `vulnerable-api`, `ml-engine`, `gateway`: `USER appuser` (UID 1001); `dashboard`: `USER nextjs` (UID 1001) |
| **Ordered Healthchecks** | **PASS** | `gateway` phụ thuộc `vulnerable-api` (`service_healthy`) & `ml-engine` (`service_healthy`); `dashboard` phụ thuộc `gateway` (`service_healthy`) và có healthcheck `http://127.0.0.1:3000` |
| **Target API & ML Loopback Isolation** | **PASS** | `vulnerable-api` chỉ bind `127.0.0.1:5000:5000`; `ml-engine` chỉ bind `127.0.0.1:8001:8001` |
| **Next.js Standalone & BFF Secret** | **PASS** | `dashboard/next.config.js` cấu hình `output: "standalone"`; `ADMIN_API_KEY` chỉ cấp cho server-side BFF (`BACKEND_URL=http://gateway:8000`) |

---

## 2. Kiến Trúc Điều Phối 4 Container (`pbl6-network`) & Quy Tắc Cô Lập Volume

```text
  [ Client / Red Team LAN ]  --->  Port 8000  --->  [ pbl6-gateway (USER appuser) ]
                                                    FastAPI Async WAF (In-process XGBoost v2 + IForest v2)
                                                    Mounts: ./data (RW),
                                                            ./ml-engine/artifacts (RO),
                                                            ./ml-engine/features (RO)
                                                    Depends on: vulnerable-api (healthy), ml-engine (healthy)
                                                              |
                                         (internal pbl6-network -> http://vulnerable-api:5000)
                                                              v
                                                    [ pbl6-vulnerable-api (USER appuser) ]
                                                    Django Bookie Bookstore (127.0.0.1:5000 loopback)

  [ Artifact Integrity ]     --->  127.0.0.1:8001 [ pbl6-ml-engine (USER appuser) ]
                                                    Python 3.12 + SHA-256 verify + 26-D smoke check (/health)
                                                    Mounts ONLY: ./ml-engine/artifacts (RO),
                                                                 ./ml-engine/features (RO)

  [ SOC Analyst Browser ]    --->  Port 3000  --->  [ pbl6-dashboard (USER nextjs) ]
                                                    Next.js 14 standalone + Server-Side BFF (/api/gateway/*)
                                                    Healthcheck: http://127.0.0.1:3000
                                                    Depends on: gateway (healthy)
```

### Quy Tắc Cô Lập Volume & An Toàn Production Demo (Strict Isolation Rules)
1. **Tuyệt đối không mount `./attack-lab`:** Cả 4 service (`vulnerable-api`, `ml-engine`, `gateway`, `dashboard`) không có bất kỳ volume mount, build context, hay import nào trỏ tới `./attack-lab`.
2. **Chỉ đọc (Read-Only `:ro`) cho AI Artifacts & Feature Extractor:** `./ml-engine/artifacts` (`xgb_v2.ubj`, `iforest_v2.npz`, `*_metadata.json`) và `./ml-engine/features` chỉ được mount `:ro` vào `ml-engine` và `gateway`.
3. **Tách biệt lưu trữ bền vững (`./data:/app/data`):** Chỉ `gateway` ghi SQLite WAL (`waf_security.db`) vào `./data`.
4. **Loopback Binding cho dịch vụ nội bộ:** `vulnerable-api` (`127.0.0.1:5000:5000`) và `ml-engine` (`127.0.0.1:8001:8001`) không phơi ra giao diện mạng LAN bên ngoài.
5. **Quản lý mật khẩu runtime (`DEMO_ADMIN_PASSWORD`):** Biến môi trường `DEMO_ADMIN_PASSWORD` được truyền vào `vulnerable-api` lúc chạy container (`docker-compose.yml` & `.env.example`); khi để trống, `vulnerable-api/entrypoint.sh` tự động sinh mật khẩu ngẫu nhiên tạm thời (ephemeral) tại runtime — tuyệt đối không nhúng mật khẩu cứng trong `Dockerfile` hay tài liệu kiểm định.

---

## 3. Lệnh Vận Hành 1 Lệnh Cho Bản Clone Sạch (1-Command Demo)

```bash
# 1. Khởi chạy toàn bộ cụm 4 container ngay trên bản clone sạch (KHÔNG cần cp .env.example .env)
docker compose up --build -d

# 2. Kiểm tra cả 4 container đều đạt trạng thái healthy
docker compose ps

# 3. Kiểm tra nhanh health endpoint của ml-engine và gateway
curl -fsS http://127.0.0.1:8001/health
curl -fsS http://127.0.0.1:8000/health

# 4. Theo dõi log thời gian thực của WAF Gateway
docker compose logs -f gateway

# 5. Dừng cụm container sau khi hoàn tất trình chiếu
docker compose down
```

---

## 4. Bằng Chứng Boot Sạch & Live Arena Qua Next.js BFF (Phase F — 2026-11-25)

Đã kiểm chứng khởi chạy **1 lệnh** trên bản checkout sạch (không `.env`, không `node_modules`, không `./attack-lab` mount) ghi nhận đầy đủ tại [docker_compose_clean_boot_phase_f.log](docker_compose_clean_boot_phase_f.log):
- **4/4 Container `healthy`:** `pbl6-vulnerable-api` (`127.0.0.1:5000`), `pbl6-ml-engine` (`127.0.0.1:8001`, SHA-256 + 26-D smoke check `PASSED` trong `79.01 ms`), `pbl6-gateway` (`:8000`, `ml_status=available`), `pbl6-dashboard` (`:3000` / test host `${DASHBOARD_PORT:-3000}:3000`).
- **Kiểm toán cô lập Volume (`docker inspect` + `docker exec ls /app`):** `pbl6-gateway` chỉ mount `./data` (RW), `./ml-engine/artifacts:ro`, `./ml-engine/features:ro`; `pbl6-ml-engine` chỉ mount `./ml-engine/artifacts:ro`, `./ml-engine/features:ro` — **`0` mount hoặc thư mục `./attack-lab`**.
- **Demo Live Arena qua BFF (`/api/gateway/api/dashboard/arena/pentest/*`):**
  - `POST /pentest/run` (`execution_mode=live_http`, `hybrid_v3`, `full_pentest`): `battle_id=pentest-730245caa5`, **`blocked=8/8 (100%)`**, `winner=BLUE_TEAM`.
  - `POST /pentest/replay` (`execution_mode=live_http`): **`matched=8/8 (100.0%)`**.
  - `POST /pentest/replay-benchmark`: `total=100` (`benign=50`, `attack=50`), `TP=42`, `TN=50`, `FP=0`, **`op_fpr_pct=0.0%` (`matches_fp_measurement=True`)**.
  - `POST /pentest/export`: Xuất bằng chứng D4 tại `docs/reports/history/arena_live_20261125_064412_ed7e0ef.json` (`git_head_sha=ed7e0efea14978a0d4e64257b694455539b81649`, SHA-256 `ca0ffc73e130f3ec24bdb43356ce4a1aebe2712d59383d180ca392c99d4c9f43`, kiểm chứng tái tạo `REPRODUCE_MATCH=True`).
