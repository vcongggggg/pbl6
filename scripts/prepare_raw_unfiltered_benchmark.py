import json
import csv
import random
import time
import urllib.parse
from pathlib import Path

start_time = time.time()
data_dir = Path(r"C:\Mod\muse-data-exchange\pbl6-datasets")
mal_dir = data_dir / "openappsec" / "malicious" / "Malicious"
legit_dir = data_dir / "openappsec" / "legitimate" / "Legitimate"
output_csv = data_dir / "raw_unfiltered_500k_dataset.csv"

OUTPUT_COLUMNS = [
    "method", "path", "query_params", "headers", "body",
    "client_ip", "user_agent", "label", "attack_type", "api_protocol"
]

records = []
print("[1/3] Loading 100% of RAW malicious records (NO DEDUPLICATION) ...")

file_map = {
    "sqli.json": ("1", "SQLI"),
    "xss.json": ("2", "XSS"),
    "traversal.json": ("3", "PATH"),
    "cmdexe.json": ("4", "CMD"),
    "shellshock.json": ("4", "CMD"),
    "xxe.json": ("5", "XXE_INJECTION"),
}

for fname, (lbl, atype) in file_map.items():
    fpath = mal_dir / fname
    if not fpath.exists():
        continue
    with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
        items = json.load(fp)
    for it in items:
        raw_url = it.get("url", "/")
        parsed = urllib.parse.urlsplit(raw_url)
        path = parsed.path or "/"
        query = parsed.query or ""
        body = it.get("data", "")
        if not isinstance(body, str):
            body = str(body) if body is not None else ""
        headers_dict = it.get("headers", {})

        records.append([
            it.get("method", "GET").upper(),
            path,
            query,
            json.dumps(headers_dict),
            body,
            f"192.168.{random.randint(1, 250)}.{random.randint(2, 250)}",
            headers_dict.get("User-Agent", "Mozilla/5.0"),
            lbl,
            atype,
            "REST" if "/api/" in path or "application/json" in str(headers_dict) else "GENERIC_WEB"
        ])

print(f"  -> Loaded {len(records):,} RAW attack records.")

target_total = 500000
needed_benign = target_total - len(records)
print(f"[2/3] Loading {needed_benign:,} RAW benign records from real web traffic (NO DEDUPLICATION) ...")

legit_files = list(legit_dir.glob("*.json"))
random.seed(42)
random.shuffle(legit_files)

benign_loaded = 0
for fpath in legit_files:
    if benign_loaded >= needed_benign:
        break
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
            items = json.load(fp)
    except Exception:
        continue
    for it in items:
        if benign_loaded >= needed_benign:
            break
        raw_url = it.get("url", "/")
        parsed = urllib.parse.urlsplit(raw_url)
        path = parsed.path or "/"
        query = parsed.query or ""
        body = it.get("data", "")
        if not isinstance(body, str):
            body = str(body) if body is not None else ""
        headers_dict = it.get("headers", {})

        records.append([
            it.get("method", "GET").upper(),
            path,
            query,
            json.dumps(headers_dict),
            body,
            f"10.0.{random.randint(1, 100)}.{random.randint(2, 254)}",
            headers_dict.get("User-Agent", "Mozilla/5.0"),
            "0",
            "BENIGN",
            "REST" if "/api/" in path or "application/json" in str(headers_dict) else "GENERIC_WEB"
        ])
        benign_loaded += 1

print(f"  -> Total RAW records assembled: {len(records):,} (Attacks: {len(records)-benign_loaded:,}, Benign: {benign_loaded:,})")

print(f"[3/3] Shuffling and exporting RAW dataset to {output_csv} ...")
random.shuffle(records)

with open(output_csv, "w", newline="", encoding="utf-8") as fp:
    writer = csv.writer(fp)
    writer.writerow(OUTPUT_COLUMNS)
    writer.writerows(records)

file_mb = output_csv.stat().st_size / (1024 * 1024)
print(f"[+] Exported RAW 500K dataset successfully! Size: {file_mb:.2f} MB in {time.time() - start_time:.2f}s")

