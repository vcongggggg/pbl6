# Attack Lab Component (Local Security Testing)

Thư mục `attack-lab/` chịu trách nhiệm cung cấp các kịch bản tấn công (attack scenarios) và công cụ tự động hóa gửi request phục vụ kiểm thử, đo đạc và demo phòng thủ an ninh mạng trong môi trường Lab.

## Cấu trúc thư mục:
```text
attack-lab/
├── agent/
│   ├── recon.py                 # Task 10.1: OpenAPI reconnaissance
│   └── planner.py               # Task 10.2: offline planner
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

## Nguyên tắc an toàn:
- Mọi payload và kịch bản chỉ được gửi tới địa chỉ đích trong môi trường Lab cục bộ (Target API / Gateway).
- Tuyệt đối không gửi payload tới các hệ thống bên ngoài hoặc môi trường thực tế.

> **LƯU Ý (Phase 0):** Chưa triển khai các kịch bản payload hoặc runner. Module này sẽ được xây dựng trong **Phase 10 — Attack Lab**.
