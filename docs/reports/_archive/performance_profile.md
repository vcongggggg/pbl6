# Blue Team v2.0 — Gateway Performance & High-Concurrency Profiling Report

**Generated At (UTC):** 2026-11-21T14:50:43.589215+00:00
**Benchmark Mode:** `in_process_asgi`
**ML Model:** `Champion Cost-Sensitive Regularized XGBoost v2.0` (`xgb_v2.ubj`)
**Anomaly Model:** `iforest_v2.npz`

---

## 1. Real Sub-Millisecond Internal Component Micro-Benchmark

| Component | Iterations | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|:---|---:|---:|---:|---:|---:|
| `input_normalizer` | 500 | 0.0199 | 0.0184 | 0.0249 | 0.0335 |
| `rule_engine` | 500 | 0.1952 | 0.1702 | 0.3178 | 0.4326 |
| `feature_extractor_26d` | 500 | 0.1549 | 0.1432 | 0.2305 | 0.2713 |
| `ml_detector_xgb_v2` | 500 | 0.6176 | 0.5325 | 1.1165 | 1.9182 |
| `anomaly_detector_iforest_v2` | 500 | 0.0949 | 0.0847 | 0.1558 | 0.2237 |
| `risk_and_decision_engine` | 500 | 0.0086 | 0.0081 | 0.0104 | 0.0146 |
| `sliding_window_rate_limiter` | 500 | 0.0040 | 0.0038 | 0.0042 | 0.0077 |

- **Combined AI Pipeline Mean (`26-D + XGBoost v2 + IForest v2`):** **0.8674 ms/req**
- **Full Synchronous Inspection Mean:** **1.0951 ms/req**

---

## 2. High-Concurrency Gateway Throughput & Latency

### 2.1 Benign Traffic Passthrough (`HTTP 200 OK`)

| Concurrency (C) | Requests | Duration (s) | Throughput (RPS) | Success (%) | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 100 | 0.497 | **201.00** | 100.0% | 4.95 | 4.58 | 7.55 | 8.22 |
| 10 | 100 | 0.288 | **346.67** | 100.0% | 26.58 | 26.56 | 32.41 | 33.59 |
| 25 | 100 | 0.279 | **358.12** | 100.0% | 62.98 | 62.07 | 82.25 | 89.02 |
| 50 | 500 | 1.470 | **340.14** | 100.0% | 139.26 | 125.08 | 232.63 | 244.12 |

### 2.2 Active Attack Blocking (`HTTP 403 Forbidden`)

| Concurrency (C) | Requests | Duration (s) | Throughput (RPS) | Success (%) | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 100 | 0.567 | **176.41** | 100.0% | 5.64 | 5.20 | 8.41 | 11.09 |
| 10 | 100 | 0.452 | **221.08** | 100.0% | 42.44 | 31.59 | 116.94 | 135.84 |
| 25 | 100 | 0.276 | **362.18** | 100.0% | 62.45 | 63.25 | 73.09 | 76.48 |
| 50 | 500 | 1.974 | **253.31** | 100.0% | 179.96 | 169.34 | 293.65 | 315.34 |

---

## 3. Process Resource Telemetry (`psutil`)

```json
{
  "pid": 2772,
  "process_cpu_percent": 113.4,
  "rss_memory_before_mb": 306.1,
  "rss_memory_after_mb": 320.29,
  "rss_memory_delta_mb": 14.19
}
```
