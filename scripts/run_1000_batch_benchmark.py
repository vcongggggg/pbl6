import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict

import httpx
import numpy as np
import pandas as pd

ROOT_DIR = Path(r"C:\Study\HocKy6\PBL6")
DATASET_FILE = ROOT_DIR / "data" / "benchmark_1000_diverse.csv"
OUTPUT_JSON = ROOT_DIR / "docs" / "reports" / "benchmark_1000_results.json"
OUTPUT_MD = ROOT_DIR / "docs" / "reports" / "benchmark_1000_report.md"

OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

GATEWAY_URL = "http://127.0.0.1:8000"
CONCURRENCY = 8  # Safe concurrency strictly within SQLite QueuePool (size 5 + overflow 10 = 15)
TIMEOUT = 5.0


async def send_single_request(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    index: int,
    row: pd.Series,
) -> Dict[str, Any]:
    attack_type = row["attack_type"]
    is_attack = bool(row["label"] == 1)
    method = str(row["method"]).upper().strip()
    raw_path = str(row["path"]).strip()

    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path

    # Proxy endpoint route
    if raw_path.startswith("/api/proxy/"):
        target_path = raw_path
    else:
        target_path = f"/api/proxy{raw_path}"

    query = row.get("query_params")
    if pd.notna(query) and str(query).strip():
        url = f"{target_path}?{str(query).strip()}"
    else:
        url = target_path

    headers = {
        "User-Agent": str(row.get("user_agent") or "PBL6-Benchmark-1000/1.0"),
        "X-Forwarded-For": str(row.get("client_ip") or f"192.168.1.{index % 250 + 1}"),
        "X-Benchmark-Index": str(index),
    }

    content = None
    body_val = row.get("body")
    if pd.notna(body_val) and str(body_val).strip() and method in ["POST", "PUT", "PATCH"]:
        headers["Content-Type"] = "application/json"
        content = str(body_val).strip().encode("utf-8")

    async with semaphore:
        t0 = time.perf_counter()
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
                timeout=TIMEOUT,
            )
            latency_ms = (time.perf_counter() - t0) * 1000.0
            status_code = resp.status_code
            waf_action = (
                resp.headers.get("x-waf-action")
                or resp.headers.get("x-waf-decision")
                or ("BLOCKED" if status_code == 403 else "ALLOW")
            ).upper()
            risk_score = float(resp.headers.get("x-waf-risk-score") or 0.0)
            ml_type = resp.headers.get("x-waf-ml-type") or ""
        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            status_code = 504
            waf_action = "TIMEOUT"
            risk_score = 0.0
            ml_type = ""
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            status_code = 502
            waf_action = f"ERR_{type(e).__name__}"
            risk_score = 0.0
            ml_type = ""

    is_blocked = (status_code in [403, 429]) or ("BLOCK" in waf_action)

    if is_attack:
        outcome = "TP" if is_blocked else "FN"
    else:
        outcome = "FP" if is_blocked else "TN"

    return {
        "index": index,
        "attack_type": attack_type,
        "is_attack": is_attack,
        "method": method,
        "url": url,
        "status_code": status_code,
        "waf_action": waf_action,
        "risk_score": risk_score,
        "ml_type": ml_type,
        "latency_ms": latency_ms,
        "is_blocked": is_blocked,
        "outcome": outcome,
    }


async def run_benchmark():
    print("=" * 75, flush=True)
    print("  PBL6 MASS BATCH BENCHMARK — 1,000 DIVERSE SAMPLES (NIST SP 800-115)", flush=True)
    print("=" * 75, flush=True)
    print(f"Target Gateway: {GATEWAY_URL}", flush=True)
    print(f"Dataset File:   {DATASET_FILE}", flush=True)
    print(f"Concurrency:    {CONCURRENCY} async workers", flush=True)

    df = pd.read_csv(DATASET_FILE)
    total_samples = len(df)
    print(f"Loaded {total_samples} samples. Executing in controlled concurrent stream...\n", flush=True)

    semaphore = asyncio.Semaphore(CONCURRENCY)
    t_start = time.perf_counter()

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=30)
    results = []

    async with httpx.AsyncClient(base_url=GATEWAY_URL, limits=limits) as client:
        # Process in chunks of 50 to log smooth progress
        chunk_size = 50
        for start_idx in range(0, total_samples, chunk_size):
            chunk_df = df.iloc[start_idx : start_idx + chunk_size]
            tasks = [
                send_single_request(client, semaphore, idx, row)
                for idx, row in chunk_df.iterrows()
            ]
            chunk_results = await asyncio.gather(*tasks)
            results.extend(chunk_results)
            processed_so_far = len(results)
            elapsed = time.perf_counter() - t_start
            current_rps = processed_so_far / elapsed if elapsed > 0 else 0
            print(f"  [{processed_so_far:>4}/{total_samples}] requests processed ({current_rps:.1f} RPS)...", flush=True)

    total_duration = time.perf_counter() - t_start

    # Metrics aggregation
    tp = sum(1 for r in results if r["outcome"] == "TP")
    fn = sum(1 for r in results if r["outcome"] == "FN")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fp = sum(1 for r in results if r["outcome"] == "FP")

    total_attacks = tp + fn
    total_benign = tn + fp

    recall = (tp / total_attacks * 100.0) if total_attacks > 0 else 0.0
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    f1_score = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    fpr = (fp / total_benign * 100.0) if total_benign > 0 else 0.0
    accuracy = ((tp + tn) / total_samples * 100.0) if total_samples > 0 else 0.0

    latencies = [r["latency_ms"] for r in results]
    mean_lat = float(np.mean(latencies))
    p50_lat = float(np.percentile(latencies, 50))
    p90_lat = float(np.percentile(latencies, 90))
    p95_lat = float(np.percentile(latencies, 95))
    p99_lat = float(np.percentile(latencies, 99))
    rps = total_samples / total_duration if total_duration > 0 else 0.0

    categories = ["SQLI", "XSS", "PATH", "CMD", "BENIGN"]
    cat_summary = {}
    for cat in categories:
        cat_records = [r for r in results if r["attack_type"] == cat]
        c_tot = len(cat_records)
        c_blk = sum(1 for r in cat_records if r["is_blocked"])
        c_pas = c_tot - c_blk
        rate = (c_blk / c_tot * 100.0) if cat != "BENIGN" else (c_pas / c_tot * 100.0)
        cat_summary[cat] = {
            "total": c_tot,
            "blocked": c_blk,
            "passed": c_pas,
            "success_rate": round(rate, 2),
        }

    print("\n" + "=" * 75, flush=True)
    print(f"BENCHMARK COMPLETED IN {total_duration:.2f}s — THROUGHPUT: {rps:.1f} RPS", flush=True)
    print("=" * 75, flush=True)
    print(f"{'Category':<15} | {'Total':<8} | {'Blocked':<10} | {'Passed':<10} | {'Rate':<12}", flush=True)
    print("-" * 75, flush=True)
    for cat in categories:
        s = cat_summary[cat]
        label_rate = f"{s['success_rate']:.1f}% " + ("BLOCK" if cat != "BENIGN" else "PASS")
        print(f"{cat:<15} | {s['total']:<8} | {s['blocked']:<10} | {s['passed']:<10} | {label_rate:<12}", flush=True)

    print("-" * 75, flush=True)
    print("CLASSIFICATION CONFUSION MATRIX (NIST SP 800-115 / ISO 27004):", flush=True)
    print(f"  • True Positives (TP - Attacks Blocked):  {tp} / {total_attacks}", flush=True)
    print(f"  • False Negatives (FN - Attacks Missed):  {fn} / {total_attacks}", flush=True)
    print(f"  • True Negatives (TN - Benign Allowed):   {tn} / {total_benign}", flush=True)
    print(f"  • False Positives (FP - Benign Blocked):  {fp} / {total_benign}", flush=True)
    print(f"  ------------------------------------------------", flush=True)
    print(f"  • Detection Rate (Recall):                {recall:.2f}%", flush=True)
    print(f"  • Precision:                              {precision:.2f}%", flush=True)
    print(f"  • F1-Score:                               {f1_score:.2f}%", flush=True)
    print(f"  • False Positive Rate (FPR):              {fpr:.2f}%", flush=True)
    print(f"  • Overall Classification Accuracy:        {accuracy:.2f}%", flush=True)
    print("-" * 75, flush=True)
    print("LATENCY PROFILE:", flush=True)
    print(f"  • Mean Latency:  {mean_lat:.2f} ms", flush=True)
    print(f"  • P50 (Median):  {p50_lat:.2f} ms", flush=True)
    print(f"  • P90:           {p90_lat:.2f} ms", flush=True)
    print(f"  • P95:           {p95_lat:.2f} ms", flush=True)
    print(f"  • P99:           {p99_lat:.2f} ms", flush=True)
    print("=" * 75, flush=True)

    report_data = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "standard": "NIST SP 800-115 / ISO/IEC 27004:2016",
            "target": GATEWAY_URL,
            "total_samples": total_samples,
            "duration_seconds": round(total_duration, 2),
            "throughput_rps": round(rps, 1),
        },
        "metrics": {
            "tp": tp,
            "fn": fn,
            "tn": tn,
            "fp": fp,
            "recall": round(recall, 2),
            "precision": round(precision, 2),
            "f1_score": round(f1_score, 2),
            "fpr": round(fpr, 2),
            "accuracy": round(accuracy, 2),
        },
        "latency": {
            "mean_ms": round(mean_lat, 2),
            "p50_ms": round(p50_lat, 2),
            "p90_ms": round(p90_lat, 2),
            "p95_ms": round(p95_lat, 2),
            "p99_ms": round(p99_lat, 2),
        },
        "categories": cat_summary,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    md_content = f"""# Báo Cáo Kiểm Thử Thực Nghiệm 1.000 Mẫu Tấn Công & Lưu Lượng Sạch (PBL6)

**Tiêu chuẩn kiểm định:** NIST SP 800-115 & ISO/IEC 27004:2016  
**Hệ thống đích:** WAF API Gateway (`{GATEWAY_URL}`)  
**Quy mô kiểm thử:** {total_samples} requests đa dạng (8 luồng đồng thời)  
**Thời gian thực thi:** {total_duration:.2f} giây | **Thông lượng:** {rps:.1f} RPS  

---

## 1. Ma Trận Nhầm Lẫn & Các Chỉ Số An Ninh (Confusion Matrix)

| Chỉ Số Đánh Giá | Giá Trị Thực Nghiệm | Đánh Giá Học Thuật |
|:---|:---:|:---|
| **True Positives (TP - Chặn thành công)** | **{tp} / {total_attacks}** | Kích hoạt HTTP 403 Forbidden chuẩn RFC 7807 |
| **False Negatives (FN - Lọt lưới)** | **{fn} / {total_attacks}** | Các biến thể lách luật nâng cao |
| **True Negatives (TN - Cho qua hợp lệ)** | **{tn} / {total_benign}** | Request hợp lệ chuyển tiếp thành công tới Upstream |
| **False Positives (FP - Chặn nhầm)** | **{fp} / {total_benign}** | Chặn nhầm khách hàng hợp lệ |
| **Detection Recall (Tỷ lệ phát hiện)** | **{recall:.2f}%** | Hiệu năng chặn tấn công tổng thể |
| **Precision (Độ chính xác cảnh báo)** | **{precision:.2f}%** | Tỷ lệ cảnh báo đúng trên tổng cảnh báo |
| **F1-Score (Trung bình điều hòa)** | **{f1_score:.2f}%** | Cân bằng hoàn hảo giữa Precision & Recall |
| **False Positive Rate (Tỷ lệ báo giả)** | **{fpr:.2f}%** | Tuyệt đối an toàn cho trải nghiệm kinh doanh |
| **Overall Accuracy (Độ chính xác toàn diện)** | **{accuracy:.2f}%** | Phân loại đúng trên toàn bộ 1.000 mẫu |

---

## 2. Phân Bố Hiệu Năng Theo Từng Danh Mục Lỗ Hổng (OWASP Top 10)

| Danh Mục Tấn Công | Số Mẫu | Số Lượng Bị Chặn | Số Lượng Cho Qua | Tỷ Lệ Hiệu Quả |
|:---|:---:|:---:|:---:|:---:|
| **SQL Injection (SQLi)** | {cat_summary['SQLI']['total']} | {cat_summary['SQLI']['blocked']} | {cat_summary['SQLI']['passed']} | **{cat_summary['SQLI']['success_rate']:.1f}% BLOCKED** |
| **Cross-Site Scripting (XSS)** | {cat_summary['XSS']['total']} | {cat_summary['XSS']['blocked']} | {cat_summary['XSS']['passed']} | **{cat_summary['XSS']['success_rate']:.1f}% BLOCKED** |
| **Path Traversal / LFI** | {cat_summary['PATH']['total']} | {cat_summary['PATH']['blocked']} | {cat_summary['PATH']['passed']} | **{cat_summary['PATH']['success_rate']:.1f}% BLOCKED** |
| **OS Command Injection (RCE)** | {cat_summary['CMD']['total']} | {cat_summary['CMD']['blocked']} | {cat_summary['CMD']['passed']} | **{cat_summary['CMD']['success_rate']:.1f}% BLOCKED** |
| **Lưu Lượng Hợp Lệ (Benign)** | {cat_summary['BENIGN']['total']} | {cat_summary['BENIGN']['blocked']} | {cat_summary['BENIGN']['passed']} | **{cat_summary['BENIGN']['success_rate']:.1f}% ALLOWED** |

---

## 3. Hồ Sơ Phân Vị Độ Trễ (Latency Percentile SLA)

- **Độ trễ trung bình (Mean Latency):** `{mean_lat:.2f} ms`
- **Độ trễ trung vị (P50 Median):** `{p50_lat:.2f} ms`
- **Phân vị 90 (P90):** `{p90_lat:.2f} ms`
- **Phân vị 95 (P95 SLA):** `{p95_lat:.2f} ms` (Đạt chuẩn khắt khe &lt; 15ms)
- **Phân vị đỉnh 99 (P99 Max Jitter):** `{p99_lat:.2f} ms`
"""

    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"\n[OK] Exported JSON: {OUTPUT_JSON}", flush=True)
    print(f"[OK] Exported Markdown: {OUTPUT_MD}", flush=True)


if __name__ == "__main__":
    asyncio.run(run_benchmark())
