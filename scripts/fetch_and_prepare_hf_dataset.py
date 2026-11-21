"""Download and standardize Hugging Face HTTP Attack Dataset for PBL6 WAF Engine.

Dataset: SecureAI-SE/http-attack-requests
Academic context: Multi-class Web Application Firewall detection dataset with real-world
HTTP GET/POST URLs covering SQLi, XSS, SSRF, SSTI, and Path Traversal.

Standardized PBL6 Schema:
  method,path,query_params,headers,body,client_ip,user_agent,label,attack_type
"""

from __future__ import annotations

import json
import random
import sys
import urllib.parse
from pathlib import Path
import pandas as pd
from datasets import load_dataset

ROOT_DIR = Path(r"C:\Study\HocKy6\PBL6")
OUTPUT_DIR = ROOT_DIR / "data" / "external" / "hf_http_attacks"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# PBL6 canonical label mapping
# 0: BENIGN, 1: SQLI, 2: XSS, 3: PATH, 4: CMDI
LABEL_MAPPING = {
    0: (0, "BENIGN"),
    1: (1, "SQLI"),
    2: (2, "XSS"),
    3: (0, "SSRF_BENIGN_CONTEXT"),  # or can be treated as anomaly
    4: (4, "CMDI_SSTI"),            # Code injection / SSTI
    5: (3, "PATH"),                 # Path Traversal
    6: (3, "PATH_LFI"),             # Obfuscated Path Traversal / LFI
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


def parse_hf_split(dataset_split, split_name: str) -> pd.DataFrame:
    print(f"Processing split: {split_name} ({len(dataset_split)} rows)...")
    records = []
    
    for idx, row in enumerate(dataset_split):
        raw_url = row["request"]
        raw_label = row["label"]
        
        parsed = urllib.parse.urlsplit(raw_url)
        path = parsed.path or "/"
        query = parsed.query or ""
        
        # If query is empty but URL had params without leading ?
        if not query and "?" in raw_url:
            query = raw_url.split("?", 1)[1]
            
        mapped_label, attack_type = LABEL_MAPPING.get(raw_label, (1, "ATTACK_GENERIC"))
        ua = USER_AGENTS[idx % len(USER_AGENTS)]
        host = parsed.netloc or "localhost:8000"
        
        headers_dict = {
            "Host": host,
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        
        client_ip = f"192.168.1.{ (idx % 250) + 1 }"
        
        records.append({
            "method": "GET",
            "path": path,
            "query_params": query,
            "headers": json.dumps(headers_dict, ensure_ascii=False),
            "body": "",
            "client_ip": client_ip,
            "user_agent": ua,
            "label": mapped_label,
            "attack_type": attack_type,
        })
        
    df = pd.DataFrame(records)
    out_file = OUTPUT_DIR / f"{split_name}.csv"
    df.to_csv(out_file, index=False, encoding="utf-8")
    print(f"  -> Saved {len(df)} rows to {out_file}")
    print(f"  -> Label distribution:\n{df['attack_type'].value_counts()}\n")
    return df


def main():
    print("Loading 'SecureAI-SE/http-attack-requests' from Hugging Face...")
    ds = load_dataset("SecureAI-SE/http-attack-requests")
    
    train_df = parse_hf_split(ds["train"], "train")
    val_df = parse_hf_split(ds["validation"], "val")
    test_df = parse_hf_split(ds["test"], "test")
    
    total_samples = len(train_df) + len(val_df) + len(test_df)
    print(f"Successfully generated dataset at: {OUTPUT_DIR}")
    print(f"Total samples: {total_samples}")


if __name__ == "__main__":
    main()
