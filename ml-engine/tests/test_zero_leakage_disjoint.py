"""Automated Zero-Leakage Canonical Hash Disjointness Test (Phase A1.3 / D3 / E4).

Verifies that `defense_v2/{train,val,test}.csv` have zero canonical hash overlap
among themselves and zero overlap against:
  - `data/benchmarks/csic2010/csic_2010_benchmark.csv`
  - `data/benchmark_1000_diverse.csv`
  - `data/benchmarks/strange_suite_v33.json` (which preserves Strange v1 + 20 new cases)
  - `data/benchmarks/blind_heldout_vault_v2.json` (Independent Blind Held-Out Vault v2)

Also verifies cryptographic pre-lock integrity of `blind_heldout_vault_v2_lock.json`
against `blind_heldout_vault_v2.json` and the committed `zero_leakage_v3_verification.json`.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.parse
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


def case_to_http_tuple(case: dict[str, Any]) -> tuple[str, str, str]:
    """Converts a Strange Suite / Blind Vault JSON case to canonicalizable (path, query, body)."""
    family = str(case.get("family", "")).upper()
    endpoint_tpl = str(case.get("endpoint", "/"))
    method = str(case.get("method", "GET")).upper()
    rtype = str(case.get("request_type", "query"))
    param = str(case.get("param_name", ""))
    extra = dict(case.get("extra_fields", {}))
    payload = str(case.get("baseline_payload", ""))

    path = endpoint_tpl
    query_str = ""
    body_str = ""

    if family == "NOSQL_INJECTION":
        try:
            parsed_op = json.loads(payload)
        except Exception:
            parsed_op = {"$ne": ""}
        body_obj = dict(extra)
        body_obj[param or "username"] = parsed_op
        body_str = json.dumps(body_obj)
    elif rtype == "path" or "{" in endpoint_tpl:
        path = re.sub(r"\{[^}]+\}", str(payload or "1"), endpoint_tpl)
        if extra and method in ("POST", "PUT", "PATCH"):
            body_str = json.dumps(extra)
    elif method == "GET":
        if param:
            q_dict = dict(extra)
            q_dict[param] = payload
            query_str = urllib.parse.urlencode(q_dict)
    else:
        body_obj = dict(extra)
        if param:
            body_obj[param] = payload
        body_str = json.dumps(body_obj)

    return path, query_str, body_str


def load_suite_canonical_hashes(json_path: Path) -> set[str]:
    """Loads canonical SHA-256 hashes for all cases in a JSON benchmark suite."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    hashes: set[str] = set()
    for case in data.get("cases", []):
        p, q, b = case_to_http_tuple(case)
        hashes.add(_canon_hash(p, q, b))
    return hashes


def test_committed_zero_leakage_report_integrity():
    report_path = ROOT_DIR / "docs" / "reports" / "zero_leakage_v3_verification.json"
    assert report_path.is_file(), "Missing committed zero_leakage_v3_verification.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["zero_leakage_verified"] is True
    for pair_name, overlap_cnt in data["pairwise_canonical_hash_overlaps"].items():
        assert overlap_cnt == 0, f"Overlap detected in {pair_name}: {overlap_cnt}"


def test_blind_heldout_vault_v2_lock_integrity():
    vault_path = ROOT_DIR / "data" / "benchmarks" / "blind_heldout_vault_v2.json"
    lock_path = ROOT_DIR / "docs" / "reports" / "blind_heldout_vault_v2_lock.json"
    strange_path = ROOT_DIR / "data" / "benchmarks" / "strange_suite_v33.json"
    assert vault_path.is_file(), "Missing blind_heldout_vault_v2.json"
    assert lock_path.is_file(), "Missing blind_heldout_vault_v2_lock.json"
    assert strange_path.is_file(), "Missing strange_suite_v33.json"

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    actual_sha = hashlib.sha256(vault_path.read_bytes()).hexdigest().lower()
    assert lock["vault_file_sha256"].lower() == actual_sha
    assert lock["locked_before_e2_e3_retrain"] is True

    h_vault = load_suite_canonical_hashes(vault_path)
    h_strange = load_suite_canonical_hashes(strange_path)
    assert len(h_vault) >= 25
    assert len(h_strange) >= 36
    assert sorted(h_vault) == lock["canonical_request_sha256s"]
    assert len(h_vault & h_strange) == 0


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
    h_strange = load_suite_canonical_hashes(ROOT_DIR / "data" / "benchmarks" / "strange_suite_v33.json")
    h_vault = load_suite_canonical_hashes(ROOT_DIR / "data" / "benchmarks" / "blind_heldout_vault_v2.json")

    assert len(h_train & h_val) == 0
    assert len(h_train & h_test) == 0
    assert len(h_val & h_test) == 0
    d2_all = h_train | h_val | h_test
    assert len(d2_all & h_csic) == 0
    assert len(d2_all & h_b1000) == 0
    assert len(d2_all & h_strange) == 0
    assert len(d2_all & h_vault) == 0
    assert len(h_strange & h_vault) == 0
