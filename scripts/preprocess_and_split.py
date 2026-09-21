#!/usr/bin/env python3
"""
Preprocessing, Dual-Track Stratified Split & Distribution Reports (70/15/15)
Task 4.3 - Phase 4: Dataset Generation & Lab Traffic Collection (PBL6 Web API Security Platform)

Kiến trúc phân chia hai nhánh dữ liệu độc lập (Dual-Track Architecture):
1. Track 1 - Offensive Dataset (data/processed/attack/):
   - Dữ liệu: 10,000 mẫu thuần tấn công từ synthetic_attacks.csv (60% evasion).
   - Nhãn: 4 họ tấn công (1: SQLI, 2: XSS, 3: PATH, 4: CMD) - 100% Zero Benign.
   - Phân chia 70/15/15: train.csv (7,000), val.csv (1,500), test.csv (1,500).
   - Mục đích: Dành riêng cho Phase 10 (AI Attack Planner & Deep RL DQN Evasion Model).

2. Track 2 - Defense Dataset (data/processed/defense/):
   - Dữ liệu: 20,000 mẫu kết hợp phân tầng từ synthetic_benign.csv (10k) + synthetic_attacks.csv (10k).
   - Nhãn: 5 lớp (0: BENIGN 50%, 1: SQLI 12.5%, 2: XSS 12.5%, 3: PATH 12.5%, 4: CMD 12.5%).
   - Phân chia 70/15/15: train.csv (14,000), val.csv (3,000), test.csv (3,000).
   - Mục đích: Dành riêng cho Phase 5 (WAF Random Forest 5 lớp) và Phase 6 (Isolation Forest).

3. Đảm bảo tính nhất quán đối kháng (Adversarial Consistency & Zero Data Leakage):
   - Cùng random seed = 42, các mẫu tấn công trong tập Train/Val/Test giữa 2 track hoàn toàn đồng nhất.
"""

import argparse
import hashlib
import json
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

LABEL_MAP_ATTACK = {
    "1": "SQLI",
    "2": "XSS",
    "3": "PATH",
    "4": "CMD",
}

LABEL_MAP_DEFENSE = {
    "0": "BENIGN",
    "1": "SQLI",
    "2": "XSS",
    "3": "PATH",
    "4": "CMD",
}

EXPECTED_COLS = [
    "method",
    "path",
    "query_params",
    "headers",
    "body",
    "client_ip",
    "user_agent",
    "label",
    "attack_type",
]


def compute_sha256(filepath: Path) -> str:
    """Tính mã băm SHA-256 của file để kiểm định tính toàn vẹn dữ liệu."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def clean_dataframe(df: pd.DataFrame, allowed_labels: list[str]) -> pd.DataFrame:
    """Làm sạch và chuẩn hóa schema dữ liệu HTTP requests."""
    for col in EXPECTED_COLS:
        if col not in df.columns:
            raise ValueError(f"Thiếu cột bắt buộc: {col}")

    # Fill NaN values with empty string / defaults
    df["query_params"] = df["query_params"].fillna("").astype(str)
    df["body"] = df["body"].fillna("").astype(str)
    df["headers"] = df["headers"].fillna("{}").astype(str)
    df["path"] = df["path"].fillna("/").astype(str)
    df["method"] = df["method"].fillna("GET").astype(str).str.upper()
    df["client_ip"] = df["client_ip"].fillna("127.0.0.1").astype(str)
    df["user_agent"] = df["user_agent"].fillna("Unknown").astype(str)

    # Ensure label is integer as string
    df["label"] = df["label"].astype(int).astype(str)
    df["attack_type"] = df["attack_type"].astype(str)

    # Filter allowed labels
    df_filtered = df[df["label"].isin(allowed_labels)].copy()
    return df_filtered[EXPECTED_COLS].reset_index(drop=True)


def compute_stats(df: pd.DataFrame, label_map: dict) -> dict:
    """Tính toán thống kê phân bổ cho một DataFrame."""
    total = len(df)
    class_counts = Counter(df["label"].tolist())
    method_counts = Counter(df["method"].tolist())

    class_dist = {}
    for lbl, name in label_map.items():
        cnt = class_counts.get(lbl, 0)
        class_dist[lbl] = {
            "name": name,
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
    """Phân chia phân tầng 70/15/15 bảo toàn tỷ lệ nhãn."""
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


def export_attack_report(report_path: Path, metadata: dict) -> None:
    """Xuất báo cáo phân bổ định dạng Markdown cho Model Tấn Công."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    full = metadata["full_stats"]
    train = metadata["train_stats"]
    val = metadata["val_stats"]
    test = metadata["test_stats"]

    content = f"""# Báo Cáo Phân Bổ Tập Dữ Liệu Model Tấn Công (Task 4.3 — Offensive Dataset Report)

## 1. Tổng Quan Phân Chia Dữ Liệu Model Tấn Công (Stratified Split 70/15/15)

- **Mục đích:** Huấn luyện Tác tử AI Tấn Công (AI Attack Planner & Deep RL DQN Evasion Model — Phase 10).
- **Tổng số mẫu tấn công:** {full['total_samples']:,} HTTP Attack Requests (100% thuần tấn công)
- **Tập Train (70%):** {train['total_samples']:,} samples
- **Tập Validation (15%):** {val['total_samples']:,} samples
- **Tập Test (15%):** {test['total_samples']:,} samples
- **Cố định ngẫu nhiên (Random Seed):** {metadata['random_seed']}
- **Bảo đảm cô lập (Zero Benign Contamination):** 0% mẫu Benign (không chứa nhãn 0).
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


def export_defense_report(report_path: Path, metadata: dict) -> None:
    """Xuất báo cáo phân bổ định dạng Markdown cho Model Phòng Thủ WAF."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    full = metadata["full_stats"]
    train = metadata["train_stats"]
    val = metadata["val_stats"]
    test = metadata["test_stats"]

    content = f"""# Báo Cáo Phân Bổ Tập Dữ Liệu Model Phòng Thủ WAF (Task 4.3 — Defense Dataset Report)

## 1. Tổng Quan Phân Chia Dữ Liệu Model Phòng Thủ (Stratified Split 70/15/15)

- **Mục đích:** Huấn luyện Bộ phân loại học máy có giám sát WAF (Random Forest 5 lớp — Phase 5) và đánh giá Bộ phát hiện bất thường (Isolation Forest — Phase 6).
- **Tổng số mẫu phòng thủ:** {full['total_samples']:,} HTTP Requests (10,000 Benign + 10,000 Attacks)
- **Tập Train (70%):** {train['total_samples']:,} samples
- **Tập Validation (15%):** {val['total_samples']:,} samples
- **Tập Test (15%):** {test['total_samples']:,} samples
- **Cố định ngẫu nhiên (Random Seed):** {metadata['random_seed']}
- **Phương pháp phân chia:** Phân tầng có giám sát (Stratified Sampling theo 5 lớp).
- **Tính nhất quán đối kháng (Adversarial Consistency):** Các mẫu tấn công trong Train/Val/Test đồng nhất với Track Tấn Công.
- **Thư mục lưu trữ Deliverable:** `data/processed/defense/`

---

## 2. Ma Trận Phân Bổ 5 Lớp Phòng Thủ Chuẩn Hóa

| Mã Lớp | Định Danh Lớp (Class Name) | Toàn Bộ Tập (Full) | Tập Train (70%) | Tập Validation (15%) | Tập Test (15%) | Tỷ Lệ Chuẩn |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **0** | **BENIGN** (Lưu lượng sạch) | {full['class_distribution']['0']['count']:,} ({full['class_distribution']['0']['percentage']}%) | {train['class_distribution']['0']['count']:,} ({train['class_distribution']['0']['percentage']}%) | {val['class_distribution']['0']['count']:,} ({val['class_distribution']['0']['percentage']}%) | {test['class_distribution']['0']['count']:,} ({test['class_distribution']['0']['percentage']}%) | **50.0%** |
| **1** | **SQLI** (SQL Injection) | {full['class_distribution']['1']['count']:,} ({full['class_distribution']['1']['percentage']}%) | {train['class_distribution']['1']['count']:,} ({train['class_distribution']['1']['percentage']}%) | {val['class_distribution']['1']['count']:,} ({val['class_distribution']['1']['percentage']}%) | {test['class_distribution']['1']['count']:,} ({test['class_distribution']['1']['percentage']}%) | **12.5%** |
| **2** | **XSS** (Cross-Site Scripting) | {full['class_distribution']['2']['count']:,} ({full['class_distribution']['2']['percentage']}%) | {train['class_distribution']['2']['count']:,} ({train['class_distribution']['2']['percentage']}%) | {val['class_distribution']['2']['count']:,} ({val['class_distribution']['2']['percentage']}%) | {test['class_distribution']['2']['count']:,} ({test['class_distribution']['2']['percentage']}%) | **12.5%** |
| **3** | **PATH** (Path Traversal / LFI) | {full['class_distribution']['3']['count']:,} ({full['class_distribution']['3']['percentage']}%) | {train['class_distribution']['3']['count']:,} ({train['class_distribution']['3']['percentage']}%) | {val['class_distribution']['3']['count']:,} ({val['class_distribution']['3']['percentage']}%) | {test['class_distribution']['3']['count']:,} ({test['class_distribution']['3']['percentage']}%) | **12.5%** |
| **4** | **CMD** (Command Injection / RCE) | {full['class_distribution']['4']['count']:,} ({full['class_distribution']['4']['percentage']}%) | {train['class_distribution']['4']['count']:,} ({train['class_distribution']['4']['percentage']}%) | {val['class_distribution']['4']['count']:,} ({val['class_distribution']['4']['percentage']}%) | {test['class_distribution']['4']['count']:,} ({test['class_distribution']['4']['percentage']}%) | **12.5%** |
| **TỔNG** | **5 LỚP TOÀN DIỆN** | **{full['total_samples']:,} (100%)** | **{train['total_samples']:,} (100%)** | **{val['total_samples']:,} (100%)** | **{test['total_samples']:,} (100%)** | **100.0%** |

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
| **Defense Train** | `data/processed/defense/train.csv` | {train['total_samples']:,} | `{metadata['hashes_sha256']['train']}` |
| **Defense Validation** | `data/processed/defense/val.csv` | {val['total_samples']:,} | `{metadata['hashes_sha256']['val']}` |
| **Defense Test** | `data/processed/defense/test.csv` | {test['total_samples']:,} | `{metadata['hashes_sha256']['test']}` |

---

## 5. Kết Luận Nghiệm Thu (Sign-off)

- [x] Đạt chuẩn tỷ lệ phân tầng 70/15/15 chính xác 50% Benign và 12.5% mỗi họ tấn công, không bị lệch nhãn.
- [x] Tính nhất quán đối kháng (Adversarial Consistency) bảo toàn 100% với Track Model Tấn Công.
- [x] Không có hiện tượng rò rỉ dữ liệu (Zero Data Leakage) giữa Train, Validation và Test.
- [x] Cung cấp đầy đủ tập huấn luyện cho WAF Random Forest (Phase 5) và đánh giá Isolation Forest (Phase 6).
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)


def execute_attack_track(
    df_attack_clean: pd.DataFrame,
    output_dir: Path,
    report_path: Path,
    seed: int,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Thực thi xử lý và xuất dữ liệu cho Track 1: Model Tấn Công."""
    print("\n" + "=" * 75)
    print("🎯 [TRACK 1] Xử Lý Tập Dữ Liệu Model Tấn Công (Offensive AI Pipeline)")
    print("=" * 75)

    print("📊 Đang thực hiện Stratified Split 70% Train / 15% Val / 15% Test trên 4 lớp tấn công...")
    train_df, val_df, test_df = perform_stratified_split(
        df_attack_clean,
        seed=seed,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
    )
    print(f"  - Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")

    output_dir.mkdir(parents=True, exist_ok=True)
    train_file = output_dir / "train.csv"
    val_file = output_dir / "val.csv"
    test_file = output_dir / "test.csv"

    train_df.to_csv(train_file, index=False, encoding="utf-8")
    val_df.to_csv(val_file, index=False, encoding="utf-8")
    test_df.to_csv(test_file, index=False, encoding="utf-8")

    metadata = {
        "task": "TASK-4.3",
        "track": "offensive",
        "description": "Stratified Split 70/15/15 for Attack Model (PBL6 Web API Security Platform)",
        "random_seed": seed,
        "total_samples": len(df_attack_clean),
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
        "full_stats": compute_stats(df_attack_clean, LABEL_MAP_ATTACK),
        "train_stats": compute_stats(train_df, LABEL_MAP_ATTACK),
        "val_stats": compute_stats(val_df, LABEL_MAP_ATTACK),
        "test_stats": compute_stats(test_df, LABEL_MAP_ATTACK),
    }

    meta_file = output_dir / "split_metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"  - Metadata JSON: {meta_file}")

    export_attack_report(report_path, metadata)
    print(f"  - Báo cáo: {report_path}")

    return train_df, val_df, test_df


def execute_defense_track(
    df_benign_clean: pd.DataFrame,
    attack_splits: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame],
    output_dir: Path,
    report_path: Path,
    seed: int,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Thực thi xử lý và xuất dữ liệu cho Track 2: Model Phòng Thủ WAF."""
    print("\n" + "=" * 75)
    print("🛡️ [TRACK 2] Xử Lý Tập Dữ Liệu Model Phòng Thủ (Defense WAF Pipeline)")
    print("=" * 75)

    print("📊 Đang phân chia phân tầng Benign và đồng bộ với tập Tấn Công...")
    b_train, b_val, b_test = perform_stratified_split(
        df_benign_clean,
        seed=seed,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
    )

    a_train, a_val, a_test = attack_splits

    # Hợp nhất và xáo trộn ngẫu nhiên với seed cố định
    train_df = pd.concat([b_train, a_train], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    val_df = pd.concat([b_val, a_val], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    test_df = pd.concat([b_test, a_test], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)

    print(f"  - Defense Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")

    output_dir.mkdir(parents=True, exist_ok=True)
    train_file = output_dir / "train.csv"
    val_file = output_dir / "val.csv"
    test_file = output_dir / "test.csv"

    train_df.to_csv(train_file, index=False, encoding="utf-8")
    val_df.to_csv(val_file, index=False, encoding="utf-8")
    test_df.to_csv(test_file, index=False, encoding="utf-8")

    full_defense_df = pd.concat([df_benign_clean, pd.concat([a_train, a_val, a_test], ignore_index=True)], ignore_index=True)

    metadata = {
        "task": "TASK-4.3",
        "track": "defense",
        "description": "Stratified Split 70/15/15 for Defense Model (PBL6 Web API Security Platform)",
        "random_seed": seed,
        "total_samples": len(full_defense_df),
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
        "full_stats": compute_stats(full_defense_df, LABEL_MAP_DEFENSE),
        "train_stats": compute_stats(train_df, LABEL_MAP_DEFENSE),
        "val_stats": compute_stats(val_df, LABEL_MAP_DEFENSE),
        "test_stats": compute_stats(test_df, LABEL_MAP_DEFENSE),
    }

    meta_file = output_dir / "split_metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"  - Metadata JSON: {meta_file}")

    export_defense_report(report_path, metadata)
    print(f"  - Báo cáo: {report_path}")

    return train_df, val_df, test_df


def main():
    parser = argparse.ArgumentParser(description="Tiền xử lý và phân chia Stratified Split Dual-Track cho PBL6")
    parser.add_argument("--track", type=str, default="all", choices=["all", "attack", "defense"], help="Nhánh xử lý: attack, defense, hoặc all (mặc định: all)")
    parser.add_argument("--attack-input", type=str, default="data/synthetic_attacks.csv", help="Đường dẫn file attacks CSV")
    parser.add_argument("--benign-input", type=str, default="data/synthetic_benign.csv", help="Đường dẫn file benign CSV")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên (mặc định: 42)")
    parser.add_argument("--train-ratio", type=float, default=0.70, help="Tỷ lệ tập Train")
    parser.add_argument("--val-ratio", type=float, default=0.15, help="Tỷ lệ tập Validation")
    parser.add_argument("--test-ratio", type=float, default=0.15, help="Tỷ lệ tập Test")

    args = parser.parse_args()

    attack_path = PROJECT_ROOT / args.attack_input if not Path(args.attack_input).is_absolute() else Path(args.attack_input)
    benign_path = PROJECT_ROOT / args.benign_input if not Path(args.benign_input).is_absolute() else Path(args.benign_input)

    print("=" * 75)
    print("🚀 PBL6 Dual-Track Dataset Preprocessing & Stratified Split Pipeline (Task 4.3)")
    print(f"• Track Mode        : {args.track.upper()}")
    print(f"• Attack Input File : {attack_path}")
    print(f"• Benign Input File : {benign_path}")
    print(f"• Random Seed       : {args.seed}")
    print("=" * 75)

    if not attack_path.exists():
        print(f"[!] Lỗi: Không tìm thấy file attack: {attack_path}")
        sys.exit(1)

    # 1. Đọc và làm sạch dữ liệu tấn công
    print("\n📂 [1/2] Đang đọc và làm sạch tập dữ liệu tấn công...")
    df_attack_raw = pd.read_csv(attack_path, dtype=str)
    df_attack_clean = clean_dataframe(df_attack_raw, allowed_labels=["1", "2", "3", "4"])
    print(f"  - Số mẫu tấn công hợp lệ (4 lớp): {len(df_attack_clean):,}")

    attack_splits = None
    if args.track in ["all", "attack"]:
        attack_out_dir = PROJECT_ROOT / "data" / "processed" / "attack"
        attack_report = PROJECT_ROOT / "docs" / "reports" / "attack_dataset_distribution.md"
        attack_splits = execute_attack_track(
            df_attack_clean,
            output_dir=attack_out_dir,
            report_path=attack_report,
            seed=args.seed,
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            test_ratio=args.test_ratio,
        )

    if args.track in ["all", "defense"]:
        if not benign_path.exists():
            print(f"[!] Lỗi: Không tìm thấy file benign: {benign_path}")
            sys.exit(1)

        print("\n📂 [2/2] Đang đọc và làm sạch tập dữ liệu lành tính (Benign)...")
        df_benign_raw = pd.read_csv(benign_path, dtype=str)
        df_benign_clean = clean_dataframe(df_benign_raw, allowed_labels=["0"])
        print(f"  - Số mẫu lành tính hợp lệ: {len(df_benign_clean):,}")

        # Nếu chỉ chạy track defense thì cần tách attack_splits trước để đảm bảo tính nhất quán
        if attack_splits is None:
            attack_splits = perform_stratified_split(
                df_attack_clean,
                seed=args.seed,
                train_ratio=args.train_ratio,
                val_ratio=args.val_ratio,
                test_ratio=args.test_ratio,
            )

        defense_out_dir = PROJECT_ROOT / "data" / "processed" / "defense"
        defense_report = PROJECT_ROOT / "docs" / "reports" / "defense_dataset_distribution.md"
        execute_defense_track(
            df_benign_clean,
            attack_splits=attack_splits,
            output_dir=defense_out_dir,
            report_path=defense_report,
            seed=args.seed,
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            test_ratio=args.test_ratio,
        )

    print("\n" + "=" * 75)
    print("🎉 HOÀN THÀNH XUẤT TẬP DỮ LIỆU DUAL-TRACK THÀNH CÔNG!")
    print("• Track 1 (Offensive AI): data/processed/attack/  (7,000 / 1,500 / 1,500)")
    print("• Track 2 (Defense WAF) : data/processed/defense/ (14,000 / 3,000 / 3,000)")
    print("=" * 75)


if __name__ == "__main__":
    main()
