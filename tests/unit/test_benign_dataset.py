"""
Unit tests for Task 4.1: Synthetic Benign HTTP Traffic Dataset & Generator
Verifies schema compliance, row count, label consistency, and 0% False Positive rate on WAF Rule Engine.
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
from app.security.engine import RuleEngine  # noqa: E402

# pyrefly: ignore [missing-import]
from generate_synthetic_benign import generate_benign_dataset  # noqa: E402

BENIGN_CSV_PATH = PROJECT_ROOT / "data" / "synthetic_benign.csv"
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


def test_benign_csv_file_exists():
    """Verify that data/synthetic_benign.csv exists and is not empty."""
    assert BENIGN_CSV_PATH.exists(), f"File not found: {BENIGN_CSV_PATH}"
    assert BENIGN_CSV_PATH.stat().st_size > 100_000, "File size is unexpectedly small"


def test_benign_csv_exact_row_count():
    """Verify that dataset contains exactly 10,000 samples (plus 1 header row)."""
    with open(BENIGN_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        row_count = sum(1 for _ in reader)

    assert header == EXPECTED_COLUMNS, f"Header mismatch: {header}"
    assert row_count == 10000, f"Expected 10,000 rows, found {row_count}"


def test_benign_csv_schema_and_types():
    """Verify schema integrity, valid methods, non-empty paths, and JSON headers."""
    valid_methods = {"GET", "POST", "PUT", "DELETE"}
    with open(BENIGN_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            assert row["method"] in valid_methods, f"Invalid method on row {idx}: {row['method']}"
            assert row["path"].startswith("/"), f"Invalid path on row {idx}: {row['path']}"
            assert row["label"] == "0", f"Invalid label on row {idx}: {row['label']}"
            assert row["attack_type"] == "BENIGN", f"Invalid attack_type on row {idx}: {row['attack_type']}"
            assert len(row["client_ip"]) > 6, f"Invalid client_ip on row {idx}"
            assert len(row["user_agent"]) > 10, f"Invalid user_agent on row {idx}"

            # Ensure headers is valid JSON
            headers_dict = json.loads(row["headers"])
            assert isinstance(headers_dict, dict)
            assert "Host" in headers_dict
            assert "User-Agent" in headers_dict


def test_benign_distribution_coverage():
    """Verify that dataset contains diverse endpoints covering all 6 simulated categories."""
    paths = set()
    methods = set()
    has_body_count = 0
    has_query_count = 0

    with open(BENIGN_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            paths.add(row["path"])
            methods.add(row["method"])
            if row["body"]:
                has_body_count += 1
            if row["query_params"]:
                has_query_count += 1

    assert "GET" in methods and "POST" in methods
    # Check coverage of vulnerable-api endpoints
    assert any("/api/v1/vulnerable/books/search/" in p for p in paths)
    assert any("/api/v1/vulnerable/reviews/" in p for p in paths)
    assert any("/api/v1/vulnerable/files/download/" in p for p in paths)
    assert any("/api/v1/vulnerable/auth/login/" in p for p in paths)
    assert any("/books/" in p for p in paths)
    assert any("/cart/" in p for p in paths)

    # Significant proportions have queries and bodies
    assert has_query_count > 2000, f"Too few queries: {has_query_count}"
    assert has_body_count > 1000, f"Too few bodies: {has_body_count}"


def test_benign_zero_false_positives_rule_engine():
    """Sample 500 requests across dataset and verify Rule Engine detects 0 attacks."""
    engine = RuleEngine()
    false_positives = []

    with open(BENIGN_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # Check every 20th sample (500 samples distributed across whole file)
        for idx, row in enumerate(reader):
            if idx % 20 != 0:
                continue

            body_bytes = row["body"].encode("utf-8") if row["body"] else None
            headers_dict = json.loads(row["headers"]) if row["headers"] else None

            res = engine.inspect_request(
                path=row["path"],
                query_params=row["query_params"] if row["query_params"] else None,
                headers=headers_dict,
                body_bytes=body_bytes,
            )

            if res.is_attack:
                false_positives.append((idx, row["path"], row["query_params"], [m.rule_id for m in res.matches]))

    assert len(false_positives) == 0, f"False positives detected: {false_positives}"


def test_generator_reproducibility():
    """Verify that generator produces deterministic output given the same random seed."""
    run1 = generate_benign_dataset(total_count=50, seed=123)
    run2 = generate_benign_dataset(total_count=50, seed=123)
    assert run1 == run2, "Generator is not deterministic with the same seed"
