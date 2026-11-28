"""Unit Tests for Continuous Quality Gates (Task D5 / SCI-PBL6-004).

Proves that scripts/verify_quality_gates.py strictly enforces quality criteria
by passing violating mock payloads and asserting non-zero exit codes:
1. Latency violation (6.0ms > 5.5ms threshold) -> Fails gate.
2. Operational FP violation (1.5% > 0.00% threshold) -> Fails gate.
3. Matrix mismatch / missing check -> Fails gate.
4. Committed production artifacts -> Passes 100% cleanly (exit code 0).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from scripts.verify_quality_gates import verify_quality_gates  # noqa: E402


def test_quality_gates_on_committed_artifacts_passes():
    """Verifies that all committed PBL6 v3.2 artifacts satisfy every quality gate."""
    passed, failures = verify_quality_gates(check_matrix=True, live_check=True)
    assert passed is True, f"Committed quality gates failed unexpectedly: {failures}"
    assert len(failures) == 0

    # Also test CLI execution directly
    cmd = [sys.executable, str(ROOT_DIR / "scripts" / "verify_quality_gates.py")]
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    assert res.returncode == 0, f"CLI verify_quality_gates failed: {res.stderr}\n{res.stdout}"


def test_quality_gates_fails_on_latency_violation(tmp_path: Path):
    """Verifies gate failure when E2E latency mean (6.0ms) exceeds 5.5ms SLA."""
    mock_latency = {
        "metadata": {"task_id": "mock_test"},
        "http_e2e_latency_ms": {
            "mean_ms": 6.000,  # Violates <= 5.5ms
            "p50_ms": 5.800,
            "p95_ms": 7.200,
            "p99_ms": 8.500,
        },
    }
    mock_file = tmp_path / "mock_latency.json"
    mock_file.write_text(json.dumps(mock_latency), encoding="utf-8")

    # 1. Test via Python function API
    passed, failures = verify_quality_gates(latency_file=mock_file, check_matrix=False)
    assert passed is False
    assert any("exceeds quality threshold" in f for f in failures)

    # 2. Test via CLI execution
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "verify_quality_gates.py"),
        "--latency-file",
        str(mock_file),
        "--skip-matrix",
    ]
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    assert res.returncode != 0, "Gate should have exited with non-zero on latency violation!"
    assert "Gate 1 Failed" in res.stderr or "QUALITY GATE VIOLATIONS" in res.stderr


def test_quality_gates_fails_on_fp_violation(tmp_path: Path):
    """Verifies gate failure when Operational FPR (1.5%) exceeds 0.00% target."""
    mock_fp = {
        "metadata": {"task_id": "mock_test"},
        "aggregate_summary": {
            "total_benign_evaluated": 1715,
            "fp_operational_count": 25,
            "fp_operational_pct": 1.500,  # Violates == 0.00%
        },
    }
    mock_file = tmp_path / "mock_fp.json"
    mock_file.write_text(json.dumps(mock_fp), encoding="utf-8")

    # 1. Test via Python function API
    passed, failures = verify_quality_gates(fp_file=mock_file, check_matrix=False)
    assert passed is False
    assert any("Operational FPR" in f for f in failures)

    # 2. Test via CLI execution
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "verify_quality_gates.py"),
        "--fp-file",
        str(mock_file),
        "--skip-matrix",
    ]
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    assert res.returncode != 0, "Gate should have exited with non-zero on FP violation!"
    assert "Gate 3 Failed" in res.stderr or "QUALITY GATE VIOLATIONS" in res.stderr


def test_quality_gates_fails_on_missing_or_corrupted_file(tmp_path: Path):
    """Verifies gate failure when required artifact file is missing or invalid."""
    non_existent = tmp_path / "does_not_exist.json"
    passed, failures = verify_quality_gates(latency_file=non_existent, check_matrix=False)
    assert passed is False
    assert any("does not exist" in f for f in failures)

    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("NOT_VALID_JSON{{{", encoding="utf-8")
    passed, failures = verify_quality_gates(latency_file=corrupt_file, check_matrix=False)
    assert passed is False
    assert any("Failed to parse" in f for f in failures)


def test_quality_gates_fails_on_matrix_mismatch(monkeypatch):
    """Verifies gate failure when thesis reconciliation matrix detects any discrepancy."""
    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="[FAIL] Metric mismatch: 26/27 matched. Discrepancy detected.",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)
    passed, failures = verify_quality_gates(check_matrix=True, live_check=False)
    assert passed is False
    assert any("Gate 4 Failed" in f for f in failures)

