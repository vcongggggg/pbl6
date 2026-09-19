"""
Unit tests for Task 4.3: Preprocessing, Stratified Split & Label Distribution Report for Attack Model (70/15/15)
Verifies schema, row counts, 4 attack classes distribution, zero benign leakage, and SHA-256 integrity.
"""

import csv
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ATTACK_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "attack"
REPORT_PATH = PROJECT_ROOT / "docs" / "reports" / "attack_dataset_distribution.md"
METADATA_PATH = ATTACK_PROCESSED_DIR / "split_metadata.json"

EXPECTED_COLUMNS = [
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


def count_csv_rows(filepath: Path) -> tuple[list[str], int]:
    with open(filepath, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        count = sum(1 for _ in reader)
    return header, count


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def test_attack_processed_files_exist():
    """Verify that all attack split CSVs, metadata JSON, and Markdown report exist."""
    assert (ATTACK_PROCESSED_DIR / "train.csv").exists()
    assert (ATTACK_PROCESSED_DIR / "val.csv").exists()
    assert (ATTACK_PROCESSED_DIR / "test.csv").exists()
    assert METADATA_PATH.exists()
    assert REPORT_PATH.exists()


def test_exact_row_counts_attack_splits():
    """Verify that attack splits match 70/15/15 ratio (7,000, 1,500, 1,500)."""
    header, train_count = count_csv_rows(ATTACK_PROCESSED_DIR / "train.csv")
    assert header == EXPECTED_COLUMNS
    assert train_count == 7000

    header, val_count = count_csv_rows(ATTACK_PROCESSED_DIR / "val.csv")
    assert header == EXPECTED_COLUMNS
    assert val_count == 1500

    header, test_count = count_csv_rows(ATTACK_PROCESSED_DIR / "test.csv")
    assert header == EXPECTED_COLUMNS
    assert test_count == 1500


def test_stratified_class_distribution_attack():
    """Verify exact stratification: 25% for each of the 4 attack classes across all splits."""
    expected_ratios = {
        "train": {"1": 1750, "2": 1750, "3": 1750, "4": 1750},
        "val": {"1": 375, "2": 375, "3": 375, "4": 375},
        "test": {"1": 375, "2": 375, "3": 375, "4": 375},
    }

    for split_name in ["train", "val", "test"]:
        filepath = ATTACK_PROCESSED_DIR / f"{split_name}.csv"
        counts = {"1": 0, "2": 0, "3": 0, "4": 0}
        with open(filepath, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lbl = row["label"]
                assert lbl in counts, f"Unexpected label {lbl} found in attack split {split_name}"
                counts[lbl] += 1

        assert counts == expected_ratios[split_name], f"Attack stratification failed for {split_name}: {counts}"


def test_zero_benign_leakage():
    """Verify that no benign samples (label 0) exist in the attack model dataset."""
    for split_name in ["train", "val", "test"]:
        filepath = ATTACK_PROCESSED_DIR / f"{split_name}.csv"
        with open(filepath, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                assert row["label"] != "0", f"Benign sample leaked into {split_name}: {row}"
                assert row["attack_type"] != "BENIGN", f"Benign attack_type leaked into {split_name}"


def test_metadata_integrity_and_sha256():
    """Verify that split_metadata.json matches file properties and real SHA-256 hashes."""
    with open(METADATA_PATH, mode="r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["task"] == "TASK-4.3"
    assert meta["total_samples"] == 10000
    assert meta["split_sizes"] == {"train": 7000, "val": 1500, "test": 1500}

    assert meta["hashes_sha256"]["train"] == compute_sha256(ATTACK_PROCESSED_DIR / "train.csv")
    assert meta["hashes_sha256"]["val"] == compute_sha256(ATTACK_PROCESSED_DIR / "val.csv")
    assert meta["hashes_sha256"]["test"] == compute_sha256(ATTACK_PROCESSED_DIR / "test.csv")


def test_markdown_report_contents():
    """Verify that docs/reports/attack_dataset_distribution.md contains key sections."""
    content = REPORT_PATH.read_text(encoding="utf-8")
    assert "Attack Dataset Distribution Report" in content
    assert "10,000" in content
    assert "SQLI" in content
    assert "XSS" in content
    assert "PATH" in content
    assert "CMD" in content
    assert "SHA-256" in content
