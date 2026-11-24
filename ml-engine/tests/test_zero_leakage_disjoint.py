"""Automated Zero-Leakage Canonical Hash Disjointness Test (Phase A1.3 / D3).

Verifies that `defense_v2/{train,val,test}.csv` have zero canonical hash overlap
among themselves and zero overlap against `csic_2010_benchmark.csv` and
`benchmark_1000_diverse.csv`. Gracefully skips on lightweight CI runners where
the >50 MB `defense_v2/train.csv` is `.gitignore`d, while asserting the committed
verification report `docs/reports/zero_leakage_v3_verification.json` is valid.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
ML_ENGINE_DIR = ROOT_DIR / "ml-engine"
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.canonicalizer import canonicalize_http_request, canonicalize_payload  # noqa: E402


def _canon_hash(path: Any, query: Any, body: Any) -> str:
    p_s = str(path) if pd.notna(path) else ""
    q_s = str(query) if pd.notna(query) else ""
    b_s = str(body) if pd.notna(body) else ""
    req = canonicalize_http_request(path=p_s, query_params=q_s, body=b_s, headers=None)
    return hashlib.sha256(canonicalize_payload(req).encode("utf-8", errors="replace")).hexdigest()


def test_committed_zero_leakage_report_integrity():
    report_path = ROOT_DIR / "docs" / "reports" / "zero_leakage_v3_verification.json"
    assert report_path.is_file(), "Missing committed zero_leakage_v3_verification.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["zero_leakage_verified"] is True
    for pair_name, overlap_cnt in data["pairwise_canonical_hash_overlaps"].items():
        assert overlap_cnt == 0, f"Overlap detected in {pair_name}: {overlap_cnt}"


def test_live_defense_v2_disjoint_canonical_hashes():
    d2_dir = ROOT_DIR / "data" / "processed" / "defense_v2"
    train_csv = d2_dir / "train.csv"
    val_csv = d2_dir / "val.csv"
    test_csv = d2_dir / "test.csv"
    if not (train_csv.is_file() and val_csv.is_file() and test_csv.is_file()):
        pytest.skip("defense_v2 CSV files (>50MB gitignored) not present in this CI checkout.")

    def _hashes(csv_path: Path) -> set[str]:
        df = pd.read_csv(csv_path)
        return {_canon_hash(r.get("path"), r.get("query_params"), r.get("body")) for _, r in df.iterrows()}

    h_train = _hashes(train_csv)
    h_val = _hashes(val_csv)
    h_test = _hashes(test_csv)
    h_csic = _hashes(ROOT_DIR / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv")
    h_b1000 = _hashes(ROOT_DIR / "data" / "benchmark_1000_diverse.csv")

    assert len(h_train & h_val) == 0
    assert len(h_train & h_test) == 0
    assert len(h_val & h_test) == 0
    d2_all = h_train | h_val | h_test
    assert len(d2_all & h_csic) == 0
    assert len(d2_all & h_b1000) == 0
