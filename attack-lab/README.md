# Attack Lab Component (Local Security Testing)

Thư mục `attack-lab/` chịu trách nhiệm cung cấp các kịch bản tấn công (attack scenarios) và công cụ tự động hóa gửi request phục vụ kiểm thử, đo đạc và demo phòng thủ an ninh mạng trong môi trường Lab.

## Cấu trúc thư mục:
```text
attack-lab/
├── agent/
│   ├── recon.py                 # Task 10.1: OpenAPI reconnaissance
│   ├── planner.py               # Task 10.2: offline planner
│   ├── tools.py                 # Task 10.3: HttpDispatcher & SqlmapApiWrapper
│   └── evasion.py               # Task 10.3: Semantic tamper & EvasionEngine
├── environment/
│   ├── actions.py               # Stable discrete action vocabulary
│   ├── attack_graph.py          # Graph from attack_surface.json
│   └── env.py                   # State machine and reward adapter
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

## Task 10.2 — Attack Graph Environment

`agent/planner.py` reads the Task 10.1 `attack_surface.json` (or a ReconReport
dictionary) and returns endpoint/action candidates. `environment/` defines the
stable discrete action indices and a fixed-width observation for the future
PyTorch agent: 17 episode/endpoint/telemetry features, one-hot
vulnerability-family features, and a 14-entry action-availability mask.
Candidates expose a phase and named transformation descriptor. The environment
is offline: it does not build payloads or send
requests. The authorized campaign runner supplies normalized response
telemetry to `AttackEnvironment.step()`.

Reward contract: HTTP 403 gives `-1`; `+10` requires explicit
`confirmed_bypass: true` telemetry. Any other response, including other 2xx or
4xx statuses, is not treated as a bypass. Planning-only steps without response
telemetry return `0`.
A contradictory `403` plus `confirmed_bypass: true` record is rejected.

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path("attack-lab").resolve()))
from agent.planner import AttackPlanner

planner = AttackPlanner("attack-lab/scenarios/attack_surface.json")
plan = planner.reset()
candidate = plan["candidates"][0]
next_plan = planner.step(candidate["action_id"], {"status_code": 403})
```

The `attack-lab` directory has a hyphen, so add it to `sys.path` (or
`PYTHONPATH`) and import `agent.planner`; it cannot itself be a Python package
name.

## Task 10.3 — Tool-Augmented Evasion Engine

`agent/tools.py` và `agent/evasion.py` triển khai công cụ kiểm thử động (DAST) và cơ chế biến dị payload thích ứng (Adaptive Mutation) khi bị WAF chặn (HTTP 403):

- **HttpDispatcher (`agent/tools.py`)**:
  - Gửi request HTTP an toàn qua WAF Gateway (`http://localhost:8000`).
  - Hỗ trợ rate limiting, retry tự động với backoff.
  - Bóc tách WAF telemetry headers: `X-WAF-Action`, `X-WAF-Risk-Score`, `X-WAF-ML-Type`, `X-Request-ID` và response body JSON.
- **SqlmapApiWrapper (`agent/tools.py`)**:
  - Tương tác với REST API của `sqlmapapi.py` (tạo task, cấu hình options, khởi chạy scan, lấy log và kết quả phát hiện).
- **ToolRegistry (`agent/tools.py`)**:
  - Quản lý danh mục công cụ DAST tích hợp.
- **EvasionEngine & Tamper Catalog (`agent/evasion.py`)**:
  - Cung cấp tập luật biến dị bảo toàn ngữ nghĩa (Semantic-Preserving Tamper Mutations) cho 4 họ tấn công chính:
    - **SQLi**: `space2comment`, `randomcase`, `charencode`, `between_replacement`, `hex_encode`.
    - **XSS**: `event_handler_obfuscate`, `html_entity_encode`, `mixed_case_tags`, `protocol_double_slash`, `decimal_encode`.
    - **Path Traversal**: `double_encoding`, `dot_segment_padding`, `null_byte_injection`, `nested_traversal`.
    - **Command Injection**: `ifs_space_replacement`, `brace_expansion`, `backslash_escape`, `variable_expansion`.
  - Vòng lặp thích ứng `evade()`: Khi nhận HTTP 403 từ WAF, tự động áp dụng tuần tự các kỹ thuật biến dị để tìm kiếm payload bypass WAF mà vẫn giữ tính toàn vẹn ngữ nghĩa khai thác.

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path("attack-lab").resolve()))
from agent.tools import HttpDispatcher
from agent.evasion import EvasionEngine

dispatcher = HttpDispatcher(base_url="http://localhost:8000")
engine = EvasionEngine(dispatcher=dispatcher, max_rounds=5)

# Chạy vòng lặp biến dị thích ứng với payload mẫu
result = engine.evade(
    method="GET",
    endpoint="/api/v1/books",
    param_name="title",
    attack_type="sqli",
    original_payload="' UNION SELECT 1, @@version -- "
)

print(f"Bypass thành công: {result.success}")
print(f"Vòng lặp đã thử: {result.rounds_attempted}")
print(f"Payload cuối: {result.final_payload}")
```

## Task 10.4 — Red Team CLI Runner & AI Campaign Orchestrator

`runner.py` là công cụ dòng lệnh (CLI Runner) điều phối các chiến dịch kiểm thử bảo mật tự động và đánh giá độ bền đối kháng (Adversarial Robustness) của WAF Gateway. Module tích hợp trinh sát bề mặt OpenAPI, môi trường Attack Graph, mô hình Deep RL DQN (`models/evasion_agent.pt`) và bộ luật biến dị bảo toàn ngữ nghĩa (`agent/evasion.py`).

### 1. Cú pháp & Cờ lệnh CLI (`python attack-lab/runner.py`)

| Cờ lệnh (Flag) | Viết tắt | Mặc định | Mô tả chi tiết |
| :--- | :---: | :---: | :--- |
| `--mode` | `-m` | `ai_agent` | Chế độ thực thi: `ai_agent` (né tránh thích ứng đa vòng bằng DQN/Tamper), `replay` (chạy lại 1 vòng với payload gốc), `live` (bắn trực tiếp vào Gateway). |
| `--campaign` | `-c` | `all` | Phân loại tấn công: `sqli`, `xss`, `traversal`, `cmd`, hoặc `all`. |
| `--target` | `-t` | `http://localhost:8000` | URL Gateway WAF (đường dẫn proxy an toàn). |
| `--max-rounds` | `-r` | `4` | Số vòng thử đột biến tối đa cho mỗi endpoint khi bị chặn 403. |
| `--output` | `-o` | `attack-lab/artifacts/campaign_report.json` | Đường dẫn file JSON xuất kết quả đo lường chi tiết. |
| `--dry-run` | `-d` | `False` | Cờ chạy mô phỏng cục bộ không mở kết nối socket mạng (phục vụ CI/CD và offline testing). |
| `--quiet` | `-q` | `False` | Tắt bảng hiển thị terminal đẹp mắt (chỉ xuất JSON report). |
| `--surface` | `-s` | `attack-lab/scenarios/attack_surface.json` | Đường dẫn file đặc tả bề mặt tấn công sau trinh sát. |
| `--model` | | `attack-lab/models/evasion_agent.pt` | Đường dẫn checkpoint mô hình DQN In-house PyTorch. |

### 2. Các ví dụ chạy phổ biến

#### Chạy mô phỏng kiểm thử nhanh (Dry-run mode, toàn bộ 4 họ tấn công):
```bash
python attack-lab/runner.py --dry-run
```

#### Chạy chiến dịch SQL Injection đối kháng trực tiếp WAF Gateway:
```bash
python attack-lab/runner.py --mode ai_agent --campaign sqli --target http://localhost:8000 --max-rounds 4
```

#### Chạy chế độ Replay để đo lường tỷ lệ phát hiện Baseline của WAF:
```bash
python attack-lab/runner.py --mode replay --campaign all --output attack-lab/artifacts/baseline_replay.json
```

#### Chạy kiểm thử tự động trong CI/CD không in bảng terminal:
```bash
python attack-lab/runner.py --dry-run --campaign all --quiet --output artifacts/ci_report.json
```

### 3. Tích hợp Python API (`run_campaign`)

Backend API (ví dụ: `arena.py` cho màn hình AI Arena trên Dashboard) có thể trực tiếp import và gọi hàm `run_campaign()`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path("attack-lab").resolve()))
from runner import run_campaign

# Thực thi chiến dịch và nhận kết quả cấu trúc
report = run_campaign(
    mode="ai_agent",
    campaign="sqli",
    target="http://localhost:8000",
    max_rounds=4,
    dry_run=False,
    quiet=True
)

summary = report["summary"]
print(f"Tổng số request: {summary['total_requests']}")
print(f"Số request bị chặn: {summary['blocked_count']}")
print(f"Tỷ lệ bypass: {summary['bypass_rate_pct']}%")
print(f"Threat Score trung bình: {summary['avg_threat_score']} / 100")
```

### 4. Quy chuẩn Thang đo & Báo cáo Telemetry
- **Thang đo Threat Score:** Tuân thủ quy tắc chuẩn toàn hệ thống `0 - 100` (theo `AGENTS.md`).
- **Telemetry mỗi vòng (Round Telemetry):** `round`, `technique`, `payload`, `status_code`, `is_blocked`, `threat_score`, `latency_ms`, `confirmed_bypass`.

---

## Nguyên tắc an toàn:
- Mọi payload và kịch bản chỉ được gửi tới địa chỉ đích trong môi trường Lab cục bộ (Target API / Gateway).
- Tuyệt đối không gửi payload tới các hệ thống bên ngoài hoặc môi trường thực tế.
