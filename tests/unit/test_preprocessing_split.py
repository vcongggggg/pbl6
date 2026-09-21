"""
Unit tests for Task 4.3: Preprocessing, Dual-Track Stratified Split & Label Distribution Reports (70/15/15)
Verifies:
1. Track 1 (Offensive Dataset): Schema, row counts, 4 classes, zero benign leakage, SHA-256.
2. Track 2 (Defense Dataset): Schema, row counts, 5 classes (50% Benign + 12.5% each attack), SHA-256.
3. Adversarial Consistency: Attack samples in train/val/test are synchronized between tracks.
"""

import csv
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ATTACK_DIR = PROJECT_ROOT / "data" / "processed" / "attack"
DEFENSE_DIR = PROJECT_ROOT / "data" / "processed" / "defense"

ATTACK_REPORT = PROJECT_ROOT / "docs" / "reports" / "attack_dataset_distribution.md"
DEFENSE_REPORT = PROJECT_ROOT / "docs" / "reports" / "defense_dataset_distribution.md"

ATTACK_META = ATTACK_DIR / "split_metadata.json"
DEFENSE_META = DEFENSE_DIR / "split_metadata.json"

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
    assert (ATTACK_DIR / "train.csv").exists()
    assert (ATTACK_DIR / "val.csv").exists()
    assert (ATTACK_DIR / "test.csv").exists()
    assert ATTACK_META.exists()
    assert ATTACK_REPORT.exists()


def test_defense_processed_files_exist():
    """Verify that all defense split CSVs, metadata JSON, and Markdown report exist."""
    assert (DEFENSE_DIR / "train.csv").exists()
    assert (DEFENSE_DIR / "val.csv").exists()
    assert (DEFENSE_DIR / "test.csv").exists()
    assert DEFENSE_META.exists()
    assert DEFENSE_REPORT.exists()


def test_exact_row_counts_attack_splits():
    """Verify that attack splits match 70/15/15 ratio (7,000, 1,500, 1,500)."""
    header, train_count = count_csv_rows(ATTACK_DIR / "train.csv")
    assert header == EXPECTED_COLUMNS
    assert train_count == 7000

    header, val_count = count_csv_rows(ATTACK_DIR / "val.csv")
    assert header == EXPECTED_COLUMNS
    assert val_count == 1500

    header, test_count = count_csv_rows(ATTACK_DIR / "test.csv")
    assert header == EXPECTED_COLUMNS
    assert test_count == 1500


def test_exact_row_counts_defense_splits():
    """Verify that defense splits match 70/15/15 ratio (14,000, 3,000, 3,000)."""
    header, train_count = count_csv_rows(DEFENSE_DIR / "train.csv")
    assert header == EXPECTED_COLUMNS
    assert train_count == 14000

    header, val_count = count_csv_rows(DEFENSE_DIR / "val.csv")
    assert header == EXPECTED_COLUMNS
    assert val_count == 3000

    header, test_count = count_csv_rows(DEFENSE_DIR / "test.csv")
    assert header == EXPECTED_COLUMNS
    assert test_count == 3000


def test_stratified_class_distribution_attack():
    """Verify exact stratification: 25% for each of the 4 attack classes in Track 1."""
    expected_ratios = {
        "train": {"1": 1750, "2": 1750, "3": 1750, "4": 1750},
        "val": {"1": 375, "2": 375, "3": 375, "4": 375},
        "test": {"1": 375, "2": 375, "3": 375, "4": 375},
    }

    for split_name in ["train", "val", "test"]:
        filepath = ATTACK_DIR / f"{split_name}.csv"
        counts = {"1": 0, "2": 0, "3": 0, "4": 0}
        with open(filepath, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lbl = row["label"]
                assert lbl in counts, f"Unexpected label {lbl} found in attack split {split_name}"
                counts[lbl] += 1

        assert counts == expected_ratios[split_name], f"Attack stratification failed for {split_name}: {counts}"


def test_stratified_class_distribution_defense():
    """Verify exact stratification: 50% Benign, 12.5% each attack class in Track 2."""
    expected_ratios = {
        "train": {"0": 7000, "1": 1750, "2": 1750, "3": 1750, "4": 1750},
        "val": {"0": 1500, "1": 375, "2": 375, "3": 375, "4": 375},
        "test": {"0": 1500, "1": 375, "2": 375, "3": 375, "4": 375},
    }

    for split_name in ["train", "val", "test"]:
        filepath = DEFENSE_DIR / f"{split_name}.csv"
        counts = {"0": 0, "1": 0, "2": 0, "3": 0, "4": 0}
        with open(filepath, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lbl = row["label"]
                assert lbl in counts, f"Unexpected label {lbl} found in defense split {split_name}"
                counts[lbl] += 1

        assert counts == expected_ratios[split_name], f"Defense stratification failed for {split_name}: {counts}"


def test_zero_benign_leakage_in_attack_track():
    """Verify that no benign samples (label 0) exist in the attack model dataset."""
    for split_name in ["train", "val", "test"]:
        filepath = ATTACK_DIR / f"{split_name}.csv"
        with open(filepath, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                assert row["label"] != "0", f"Benign sample leaked into {split_name}: {row}"
                assert row["attack_type"] != "BENIGN", f"Benign attack_type leaked into {split_name}"


def test_adversarial_consistency_between_tracks():
    """Verify that the set of attack requests in Track 1 matches the attack requests in Track 2 per split."""
    req_cols = ["method", "path", "query_params", "body"]

    for split_name in ["train", "val", "test"]:
        attack_file = ATTACK_DIR / f"{split_name}.csv"
        defense_file = DEFENSE_DIR / f"{split_name}.csv"

        with open(attack_file, mode="r", encoding="utf-8") as f:
            attack_fps = set("||".join(row[c] for c in req_cols) for row in csv.DictReader(f))

        with open(defense_file, mode="r", encoding="utf-8") as f:
            defense_attack_fps = set(
                "||".join(row[c] for c in req_cols)
                for row in csv.DictReader(f)
                if row["label"] != "0"
            )

        assert attack_fps == defense_attack_fps, (
            f"Adversarial inconsistency in {split_name} split! Attack samples differ between tracks."
        )


def test_metadata_integrity_and_sha256_both_tracks():
    """Verify that split_metadata.json matches file properties and real SHA-256 hashes for both tracks."""
    # Track 1
    with open(ATTACK_META, mode="r", encoding="utf-8") as f:
        meta_a = json.load(f)
    assert meta_a["task"] == "TASK-4.3"
    assert meta_a["track"] == "offensive"
    assert meta_a["total_samples"] == 10000
    assert meta_a["split_sizes"] == {"train": 7000, "val": 1500, "test": 1500}
    assert meta_a["hashes_sha256"]["train"] == compute_sha256(ATTACK_DIR / "train.csv")
    assert meta_a["hashes_sha256"]["val"] == compute_sha256(ATTACK_DIR / "val.csv")
    assert meta_a["hashes_sha256"]["test"] == compute_sha256(ATTACK_DIR / "test.csv")

    # Track 2
    with open(DEFENSE_META, mode="r", encoding="utf-8") as f:
        meta_d = json.load(f)
    assert meta_d["task"] == "TASK-4.3"
    assert meta_d["track"] == "defense"
    assert meta_d["total_samples"] == 20000
    assert meta_d["split_sizes"] == {"train": 14000, "val": 3000, "test": 3000}
    assert meta_d["hashes_sha256"]["train"] == compute_sha256(DEFENSE_DIR / "train.csv")
    assert meta_d["hashes_sha256"]["val"] == compute_sha256(DEFENSE_DIR / "val.csv")
    assert meta_d["hashes_sha256"]["test"] == compute_sha256(DEFENSE_DIR / "test.csv")


def test_markdown_reports_contents_both_tracks():
    """Verify that both markdown reports exist and contain required headers and metrics."""
    # Attack Report
    content_a = ATTACK_REPORT.read_text(encoding="utf-8")
    assert "Offensive Dataset Report" in content_a
    assert "10,000" in content_a
    assert "SQLI" in content_a
    assert "SHA-256" in content_a

    # Defense Report
    content_d = DEFENSE_REPORT.read_text(encoding="utf-8")
    assert "Defense Dataset Report" in content_d
    assert "20,000" in content_d
    assert "BENIGN" in content_d
    assert "SQLI" in content_d
    assert "SHA-256" in content_d
