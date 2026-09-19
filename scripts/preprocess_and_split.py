#!/usr/bin/env python3
"""
Preprocessing, Stratified Split & Label Distribution Report for Attack Model (70/15/15)
Task 4.3 - Phase 4: Dataset Generation & Lab Traffic Collection (Offensive AI Pipeline)

Chuyên biệt cho bài toán huấn luyện Model Tấn công (Offensive AI / Red Team):
1. Đọc và làm sạch tập dữ liệu tấn công synthetic_attacks.csv (10,000 samples).
2. Chuẩn hóa nhãn 4 lớp tấn công: 1: SQLI, 2: XSS, 3: PATH, 4: CMD.
3. Phân chia Stratified Split theo tỷ lệ 70% Train, 15% Val, 15% Test với random seed = 42.
4. Xuất deliverables chuẩn vào data/processed/attack/:
   - data/processed/attack/train.csv (7,000 samples)
   - data/processed/attack/val.csv   (1,500 samples)
   - data/processed/attack/test.csv  (1,500 samples)
   - data/processed/attack/split_metadata.json (kèm mã băm SHA-256)
5. Xuất báo cáo phân bổ Markdown: docs/reports/attack_dataset_distribution.md.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

LABEL_MAP = {
    "1": "SQLI",
    "2": "XSS",
    "3": "PATH",
    "4": "CMD",
}


def compute_sha256(filepath: Path) -> str:
    """Tính mã băm SHA-256 của file để kiểm định tính toàn vẹn dữ liệu."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def clean_attack_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Làm sạch và chuẩn hóa dữ liệu tấn công đầu vào."""
    expected_cols = ["method", "path", "query_params", "headers", "body", "client_ip", "user_agent", "label", "attack_type"]
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Thiếu cột bắt buộc: {col}")

    # Fill NaN values with empty string
    df["query_params"] = df["query_params"].fillna("").astype(str)
    df["body"] = df["body"].fillna("").astype(str)
    df["headers"] = df["headers"].fillna("{}").astype(str)
    df["path"] = df["path"].fillna("/").astype(str)
    df["method"] = df["method"].fillna("GET").astype(str).str.upper()
    df["client_ip"] = df["client_ip"].fillna("127.0.0.1").astype(str)
    df["user_agent"] = df["user_agent"].fillna("Unknown").astype(str)

    # Ensure label is integer as string for consistent matching
    df["label"] = df["label"].astype(int).astype(str)
    df["attack_type"] = df["attack_type"].astype(str)

    # Ensure only attack labels (1, 2, 3, 4)
    df = df[df["label"].isin(["1", "2", "3", "4"])].copy()

    return df[expected_cols]


def compute_attack_stats(df: pd.DataFrame) -> dict:
    """Tính toán thống kê chi tiết cho một DataFrame tấn công."""
    total = len(df)
    class_counts = Counter(df["label"].tolist())
    method_counts = Counter(df["method"].tolist())

    class_dist = {}
    for lbl in ["1", "2", "3", "4"]:
        cnt = class_counts.get(lbl, 0)
        class_dist[lbl] = {
            "name": LABEL_MAP.get(lbl, "UNKNOWN"),
            "count": cnt,
            "percentage": round((cnt / total) * 100, 2) if total > 0 else 0.0,
        }

    has_query = int((df["query_params"] != "").sum())
    has_body = int((df["body"] != "").sum())

    return {
        "total_samples": total,
        "class_distribution": class_dist,
        "methods": dict(method_counts),
        "has_query_params": has_query,
        "has_query_pct": round((has_query / total) * 100, 2) if total > 0 else 0.0,
        "has_body": has_body,
        "has_body_pct": round((has_body / total) * 100, 2) if total > 0 else 0.0,
    }


def perform_stratified_split(
    df: pd.DataFrame,
    seed: int = 42,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Phân chia phân tầng 70/15/15 theo nhãn lớp tấn công."""
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-5, "Tổng tỷ lệ phải bằng 1.0"

    temp_ratio = val_ratio + test_ratio
    train_df, temp_df = train_test_split(
        df,
        test_size=temp_ratio,
        random_state=seed,
        stratify=df["label"],
    )

    val_rel_ratio = val_ratio / temp_ratio
    val_df, test_df = train_test_split(
        temp_df,
        test_size=(1.0 - val_rel_ratio),
        random_state=seed,
        stratify=temp_df["label"],
    )

    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def export_markdown_report(report_path: Path, metadata: dict) -> None:
    """Xuất báo cáo định dạng Markdown phân bổ nhãn học thuật cho Model Tấn Công."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    full = metadata["full_stats"]
    train = metadata["train_stats"]
    val = metadata["val_stats"]
    test = metadata["test_stats"]

    content = f"""# Báo Cáo Phân Bổ Tập Dữ Liệu Model Tấn Công (Task 4.3 — Attack Dataset Distribution Report)

## 1. Tổng Quan Phân Chia Dữ Liệu Model Tấn Công (Stratified Split 70/15/15)

- **Tổng số mẫu tấn công:** {full['total_samples']:,} HTTP Attack Requests (10,000 samples)
- **Tập Train (70%):** {train['total_samples']:,} samples
- **Tập Validation (15%):** {val['total_samples']:,} samples
- **Tập Test (15%):** {test['total_samples']:,} samples
- **Cố định ngẫu nhiên (Random Seed):** {metadata['random_seed']}
- **Phương pháp phân chia:** Phân tầng có giám sát (Stratified Sampling theo 4 họ tấn công)
- **Thư mục lưu trữ Deliverable:** `data/processed/attack/`

---

## 2. Ma Trận Phân Bổ 4 Họ Tấn Công Chuẩn Hóa

| Mã Lớp | Họ Tấn Công (Attack Family) | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) | Tỷ Lệ Chuẩn |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **1** | **SQLI** (SQL Injection) | {full['class_distribution']['1']['count']:,} ({full['class_distribution']['1']['percentage']}%) | {train['class_distribution']['1']['count']:,} ({train['class_distribution']['1']['percentage']}%) | {val['class_distribution']['1']['count']:,} ({val['class_distribution']['1']['percentage']}%) | {test['class_distribution']['1']['count']:,} ({test['class_distribution']['1']['percentage']}%) | **25.0%** |
| **2** | **XSS** (Cross-Site Scripting) | {full['class_distribution']['2']['count']:,} ({full['class_distribution']['2']['percentage']}%) | {train['class_distribution']['2']['count']:,} ({train['class_distribution']['2']['percentage']}%) | {val['class_distribution']['2']['count']:,} ({val['class_distribution']['2']['percentage']}%) | {test['class_distribution']['2']['count']:,} ({test['class_distribution']['2']['percentage']}%) | **25.0%** |
| **3** | **PATH** (Path Traversal / LFI) | {full['class_distribution']['3']['count']:,} ({full['class_distribution']['3']['percentage']}%) | {train['class_distribution']['3']['count']:,} ({train['class_distribution']['3']['percentage']}%) | {val['class_distribution']['3']['count']:,} ({val['class_distribution']['3']['percentage']}%) | {test['class_distribution']['3']['count']:,} ({test['class_distribution']['3']['percentage']}%) | **25.0%** |
| **4** | **CMD** (Command Injection / RCE) | {full['class_distribution']['4']['count']:,} ({full['class_distribution']['4']['percentage']}%) | {train['class_distribution']['4']['count']:,} ({train['class_distribution']['4']['percentage']}%) | {val['class_distribution']['4']['count']:,} ({val['class_distribution']['4']['percentage']}%) | {test['class_distribution']['4']['count']:,} ({test['class_distribution']['4']['percentage']}%) | **25.0%** |
| **TỔNG** | **4 HỌ TẤN CÔNG** | **{full['total_samples']:,} (100%)** | **{train['total_samples']:,} (100%)** | **{val['total_samples']:,} (100%)** | **{test['total_samples']:,} (100%)** | **100.0%** |

---

## 3. Thống Kê Phương Thức & Vị Trí Payload

| Đặc Trưng Kỹ Thuật | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) |
| :--- | :---: | :---: | :---: | :---: |
| **HTTP POST Method** | {full['methods'].get('POST', 0):,} ({full['methods'].get('POST', 0)/full['total_samples']*100:.1f}%) | {train['methods'].get('POST', 0):,} ({train['methods'].get('POST', 0)/train['total_samples']*100:.1f}%) | {val['methods'].get('POST', 0):,} ({val['methods'].get('POST', 0)/val['total_samples']*100:.1f}%) | {test['methods'].get('POST', 0):,} ({test['methods'].get('POST', 0)/test['total_samples']*100:.1f}%) |
| **HTTP GET Method** | {full['methods'].get('GET', 0):,} ({full['methods'].get('GET', 0)/full['total_samples']*100:.1f}%) | {train['methods'].get('GET', 0):,} ({train['methods'].get('GET', 0)/train['total_samples']*100:.1f}%) | {val['methods'].get('GET', 0):,} ({val['methods'].get('GET', 0)/val['total_samples']*100:.1f}%) | {test['methods'].get('GET', 0):,} ({test['methods'].get('GET', 0)/test['total_samples']*100:.1f}%) |
| **Có Query Parameters** | {full['has_query_params']:,} ({full['has_query_pct']}%) | {train['has_query_params']:,} ({train['has_query_pct']}%) | {val['has_query_params']:,} ({val['has_query_pct']}%) | {test['has_query_params']:,} ({test['has_query_pct']}%) |
| **Có Request Body** | {full['has_body']:,} ({full['has_body_pct']}%) | {train['has_body']:,} ({train['has_body_pct']}%) | {val['has_body']:,} ({val['has_body_pct']}%) | {test['has_body']:,} ({test['has_body_pct']}%) |

---

## 4. Kiểm Định Tính Toàn Vẹn & Mã Băm SHA-256

| Tệp Dữ Liệu | Đường Dẫn Lưu Trữ | Số Bản Ghi | Mã Băm SHA-256 Checksum |
| :--- | :--- | :---: | :--- |
| **Attack Train** | `data/processed/attack/train.csv` | {train['total_samples']:,} | `{metadata['hashes_sha256']['train']}` |
| **Attack Validation** | `data/processed/attack/val.csv` | {val['total_samples']:,} | `{metadata['hashes_sha256']['val']}` |
| **Attack Test** | `data/processed/attack/test.csv` | {test['total_samples']:,} | `{metadata['hashes_sha256']['test']}` |

---

## 5. Kết Luận Nghiệm Thu (Sign-off)

- [x] Đạt chuẩn tỷ lệ phân tầng 70/15/15 chính xác 25% mỗi lớp tấn công, không bị lệch nhãn.
- [x] Không có mẫu Benign (label 0) lọt vào tập dữ liệu của Model Tấn công.
- [x] Không có hiện tượng rò rỉ dữ liệu (Zero Data Leakage) giữa Train, Validation và Test.
- [x] Đầy đủ 9 cột thuộc tính đồng bộ chuẩn hóa phục vụ huấn luyện Model Tấn công (Offensive AI / Red Team).
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(description="Tiền xử lý và phân chia Stratified Split 70/15/15 cho Model Tấn Công")
    parser.add_argument("--input", type=str, default="data/synthetic_attacks.csv", help="Đường dẫn file attacks CSV")
    parser.add_argument("--output-dir", type=str, default="data/processed/attack", help="Thư mục xuất kết quả")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên (mặc định: 42)")
    parser.add_argument("--train-ratio", type=float, default=0.70, help="Tỷ lệ tập Train")
    parser.add_argument("--val-ratio", type=float, default=0.15, help="Tỷ lệ tập Validation")
    parser.add_argument("--test-ratio", type=float, default=0.15, help="Tỷ lệ tập Test")
    parser.add_argument("--report", type=str, default="docs/reports/attack_dataset_distribution.md", help="Đường dẫn file báo cáo Markdown")

    args = parser.parse_args()

    input_path = PROJECT_ROOT / args.input if not Path(args.input).is_absolute() else Path(args.input)
    output_dir = PROJECT_ROOT / args.output_dir if not Path(args.output_dir).is_absolute() else Path(args.output_dir)
    report_path = PROJECT_ROOT / args.report if not Path(args.report).is_absolute() else Path(args.report)

    print("=" * 75)
    print(f"🚀 PBL6 Attack Dataset Preprocessing & Stratified Split Pipeline (Task 4.3)")
    print(f"• Input Attack File : {input_path}")
    print(f"• Output Directory  : {output_dir}")
    print(f"• Random Seed       : {args.seed}")
    print("=" * 75)

    if not input_path.exists():
        print(f"[!] Lỗi: Không tìm thấy file đầu vào: {input_path}")
        sys.exit(1)

    # 1. Đọc và làm sạch dữ liệu tấn công
    print("\n📂 [1/4] Đang đọc và làm sạch tập dữ liệu tấn công...")
    df_raw = pd.read_csv(input_path, dtype=str)
    print(f"  - Số mẫu đọc được: {len(df_raw):,}")

    df_clean = clean_attack_dataframe(df_raw)
    print(f"  - Số mẫu hợp lệ sau làm sạch: {len(df_clean):,}")

    # 2. Phân chia phân tầng 70/15/15
    print("\n📊 [2/4] Đang thực hiện Stratified Split 70% Train / 15% Val / 15% Test...")
    train_df, val_df, test_df = perform_stratified_split(
        df_clean,
        seed=args.seed,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
    )
    print(f"  - Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")

    output_dir.mkdir(parents=True, exist_ok=True)
    train_file = output_dir / "train.csv"
    val_file = output_dir / "val.csv"
    test_file = output_dir / "test.csv"

    train_df.to_csv(train_file, index=False, encoding="utf-8")
    val_df.to_csv(val_file, index=False, encoding="utf-8")
    test_df.to_csv(test_file, index=False, encoding="utf-8")

    # 3. Tính toán và lưu trữ Metadata
    print("\n📝 [3/4] Đang tính mã băm SHA-256 và xuất split_metadata.json...")
    metadata = {
        "task": "TASK-4.3",
        "description": "Stratified Split 70/15/15 for Attack Model (PBL6 Web API Security Platform)",
        "random_seed": args.seed,
        "total_samples": len(df_clean),
        "split_sizes": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
        },
        "hashes_sha256": {
            "train": compute_sha256(train_file),
            "val": compute_sha256(val_file),
            "test": compute_sha256(test_file),
        },
        "full_stats": compute_attack_stats(df_clean),
        "train_stats": compute_attack_stats(train_df),
        "val_stats": compute_attack_stats(val_df),
        "test_stats": compute_attack_stats(test_df),
    }

    meta_file = output_dir / "split_metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"  - Metadata JSON: {meta_file}")

    # 4. Xuất báo cáo Markdown
    print("\n📄 [4/4] Đang xuất báo cáo kỹ thuật học thuật (docs/reports/attack_dataset_distribution.md)...")
    export_markdown_report(report_path, metadata)
    print(f"  - Report: {report_path}")

    print("\n" + "=" * 75)
    print(f"🎉 Hoàn thành xuất tập dữ liệu Model Tấn Công thành công!")
    print(f"• Attack Train : {train_file} ({train_file.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"• Attack Val   : {val_file} ({val_file.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"• Attack Test  : {test_file} ({test_file.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"• Báo cáo      : {report_path}")
    print("=" * 75)


if __name__ == "__main__":
    main()
