"""
Unit tests for Task 4.2: Synthetic Malicious Attack HTTP Traffic Dataset & Generator
Verifies schema compliance, row count, 4 attack families distribution, label mapping, and evasion techniques.
"""

import csv
import json
import sys
from pathlib import Path

# Add project root and gateway to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
GATEWAY_PATH = PROJECT_ROOT / "gateway"
SCRIPTS_PATH = PROJECT_ROOT / "scripts"

if str(GATEWAY_PATH) not in sys.path:
    sys.path.insert(0, str(GATEWAY_PATH))
if str(SCRIPTS_PATH) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_PATH))

# pyrefly: ignore [missing-import]
# pyrefly: ignore [missing-import]
from generate_synthetic_attacks import generate_attack_dataset  # noqa: E402

ATTACK_CSV_PATH = PROJECT_ROOT / "data" / "synthetic_attacks.csv"
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


def test_attack_csv_file_exists():
    """Verify that data/synthetic_attacks.csv exists and is not empty."""
    assert ATTACK_CSV_PATH.exists(), f"File not found: {ATTACK_CSV_PATH}"
    assert ATTACK_CSV_PATH.stat().st_size > 100_000, "File size is unexpectedly small"


def test_attack_csv_exact_row_count():
    """Verify that dataset contains exactly 10,000 attack samples (plus 1 header row)."""
    with open(ATTACK_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        row_count = sum(1 for _ in reader)

    assert header == EXPECTED_COLUMNS, f"Header mismatch: {header}"
    assert row_count == 10000, f"Expected 10,000 rows, found {row_count}"


def test_attack_families_distribution():
    """Verify equal distribution of 4 attack families (2,500 samples per class)."""
    counts = {"SQLI": 0, "XSS": 0, "PATH": 0, "CMD": 0}
    label_map = {"SQLI": "1", "XSS": "2", "PATH": "3", "CMD": "4"}

    with open(ATTACK_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            atk = row["attack_type"]
            assert atk in counts, f"Unexpected attack_type: {atk}"
            assert row["label"] == label_map[atk], f"Label mismatch for {atk}: {row['label']} vs {label_map[atk]}"
            counts[atk] += 1

    for atk, cnt in counts.items():
        assert cnt == 2500, f"Expected 2,500 samples for {atk}, found {cnt}"


def test_attack_csv_schema_and_types():
    """Verify schema integrity, valid methods, non-empty paths, and JSON headers."""
    valid_methods = {"GET", "POST", "PUT", "DELETE"}
    with open(ATTACK_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            assert row["method"] in valid_methods, f"Invalid method on row {idx}: {row['method']}"
            assert row["path"].startswith("/"), f"Invalid path on row {idx}: {row['path']}"
            assert len(row["client_ip"]) > 6, f"Invalid client_ip on row {idx}"
            assert len(row["user_agent"]) > 3, f"Invalid user_agent on row {idx}"

            # Ensure headers is valid JSON
            headers_dict = json.loads(row["headers"])
            assert isinstance(headers_dict, dict)
            assert "Host" in headers_dict
            assert "User-Agent" in headers_dict


def test_target_endpoints_coverage():
    """Verify that attacks target vulnerable endpoints on vulnerable-api."""
    paths = set()
    with open(ATTACK_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            paths.add(row["path"])

    assert "/api/v1/vulnerable/auth/login/" in paths
    assert "/api/v1/vulnerable/books/search/" in paths
    assert "/api/v1/vulnerable/reviews/" in paths
    assert "/api/v1/vulnerable/files/download/" in paths
    assert "/api/v1/vulnerable/admin/ping/" in paths


def test_presence_of_evasion_variations():
    """Verify presence of obfuscation / evasion variations (comments, encoding, IFS, etc.)."""
    evasion_indicators = [
        "/**/",          # SQL comment injection
        "%252e%252e",    # Double URL encoded traversal
        "$IFS",          # Bash IFS variable substitution
        "%00",           # Null byte injection
        "String.fromCharCode", # Obfuscated JS
        "onerror=",      # Alternative event handler
        "$(",            # Subshell command execution
    ]
    found_indicators = {ind: False for ind in evasion_indicators}

    with open(ATTACK_CSV_PATH, mode="r", encoding="utf-8") as f:
        content = f.read()
        for ind in evasion_indicators:
            if ind in content:
                found_indicators[ind] = True

    for ind, found in found_indicators.items():
        assert found, f"Evasion indicator '{ind}' not found in dataset"


def test_attack_generator_reproducibility():
    """Verify that attack generator produces deterministic output given the same seed."""
    run1 = generate_attack_dataset(total_count=40, seed=999)
    run2 = generate_attack_dataset(total_count=40, seed=999)
    assert run1 == run2, "Attack generator is not deterministic with the same seed"
