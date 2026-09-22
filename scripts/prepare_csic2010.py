import json
import os
import random
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
import pandas as pd

ROOT_DIR = Path(r"C:\Study\HocKy6\PBL6")
BENCHMARK_DIR = ROOT_DIR / "data" / "benchmarks" / "csic2010"
RAW_DIR = BENCHMARK_DIR / "raw"
OUTPUT_CSV = BENCHMARK_DIR / "csic_2010_benchmark.csv"

RAW_DIR.mkdir(parents=True, exist_ok=True)

URL_ANOMALOUS = "https://raw.githubusercontent.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010/master/anomalousTrafficTest.txt"
URL_NORMAL = "https://raw.githubusercontent.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010/master/normalTrafficTraining.txt"


def download_file(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 10000:
        print(f"File already exists: {dest} ({dest.stat().st_size} bytes)")
        return
    print(f"Downloading {url} to {dest} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as f:
        f.write(resp.read())
    print(f"Downloaded {dest.stat().st_size} bytes successfully.")


def parse_http_requests(file_path: Path, is_attack: bool) -> list[dict]:
    print(f"Parsing {file_path.name} ...")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Match HTTP request line starts
    pattern = re.compile(r"^(GET|POST|PUT|DELETE)\s+(http[^\s]+)\s+HTTP", re.MULTILINE)
    matches = list(pattern.finditer(content))
    records = []

    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        block = content[start:end].strip()

        method = m.group(1).upper()
        full_url = m.group(2)
        parsed = urllib.parse.urlsplit(full_url)
        path = parsed.path or "/"
        query = parsed.query or ""

        # Extract headers and body
        # Headers and body are separated by an empty line (\n\n or \r\n\r\n)
        parts = re.split(r"\r?\n\r?\n", block, maxsplit=1)
        headers_block = parts[0] if len(parts) > 0 else ""
        body = parts[1].strip() if len(parts) > 1 else ""

        # Parse basic headers
        headers_dict = {}
        for line in headers_block.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip()] = v.strip()

        # Determine attack subtype for anomalous traffic
        if is_attack:
            combined = (query + " " + body).lower()
            if any(k in combined for k in ["select", "union", "insert", "drop", "--", "or 1=1", "waitfor", "sleep("]):
                attack_type = "SQLI"
            elif any(k in combined for k in ["script", "alert(", "onerror", "onload", "<svg", "<img", "javascript:"]):
                attack_type = "XSS"
            elif any(k in combined for k in ["../", "..\\", "/etc/passwd", "win.ini", "boot.ini"]):
                attack_type = "PATH"
            elif any(k in combined for k in [";", "&&", "||", "|", "whoami", "cat /etc"]):
                attack_type = "CMD"
            else:
                attack_type = "ANOMALY_TAMPER"
            label = 1
        else:
            attack_type = "BENIGN"
            label = 0

        records.append({
            "method": method,
            "path": path,
            "query_params": query,
            "headers": json.dumps(headers_dict, ensure_ascii=False),
            "body": body,
            "client_ip": f"192.168.10.{i % 250 + 1}",
            "user_agent": headers_dict.get("User-Agent", "CSIC-2010-Client/1.0"),
            "label": label,
            "attack_type": attack_type,
        })

    print(f"Extracted {len(records)} requests from {file_path.name}.")
    return records


def main():
    raw_anomalous = RAW_DIR / "anomalousTrafficTest.txt"
    raw_normal = RAW_DIR / "normalTrafficTraining.txt"

    download_file(URL_ANOMALOUS, raw_anomalous)
    download_file(URL_NORMAL, raw_normal)

    attacks = parse_http_requests(raw_anomalous, is_attack=True)
    benigns = parse_http_requests(raw_normal, is_attack=False)

    random.seed(42)
    sample_attack = random.sample(attacks, min(1500, len(attacks)))
    sample_benign = random.sample(benigns, min(1500, len(benigns)))

    combined = sample_attack + sample_benign
    random.shuffle(combined)

    df = pd.DataFrame(combined)
    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

    print("\n" + "=" * 70)
    print(f"SUCCESS: Saved CSIC 2010 Benchmark Dataset to {OUTPUT_CSV}")
    print(f"Total benchmark samples: {len(df)}")
    print("=" * 70)
    print("Class Distribution (Label):")
    print(df["label"].value_counts())
    print("\nAttack Subtype Breakdown:")
    print(df["attack_type"].value_counts())


if __name__ == "__main__":
    main()
