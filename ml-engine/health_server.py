"""Lightweight ML Engine Health & Artifact Verification Server.

Loads and cryptographically verifies ``xgb_v2.ubj`` and ``iforest_v2.npz``
against their SHA-256 metadata manifests, executes a 26-D smoke inference
check using ``ml-engine/features``, and exposes ``GET /health`` on port 8001.

Zero dependency on ``attack-lab`` or ``gateway``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import signal
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

os.environ.setdefault("OMP_NUM_THREADS", "1")

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402

ML_ENGINE_DIR = Path(__file__).resolve().parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.extractor import CANONICAL_FEATURE_NAMES_V2, extract_26_from_http  # noqa: E402

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("waf.ml_engine.health")


def _verify_sha256(artifact_path: Path, meta_path: Path) -> tuple[str, dict[str, Any]]:
    """Verifies an artifact file's SHA-256 digest against its metadata JSON."""
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Missing model artifact: {artifact_path}")
    if not meta_path.is_file():
        raise FileNotFoundError(f"Missing model metadata: {meta_path}")

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    expected_hash = str(metadata.get("sha256_hash", "")).strip().lower()
    if not expected_hash:
        raise ValueError(f"Missing sha256_hash in metadata: {meta_path}")

    actual_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest().lower()
    if actual_hash != expected_hash:
        raise ValueError(
            f"SHA-256 mismatch for {artifact_path.name}: expected {expected_hash}, got {actual_hash}"
        )
    return actual_hash, metadata


def _iforest_npz_raw_score(npz_arrays: dict[str, Any], feat_26: np.ndarray) -> float:
    """Computes raw IsolationForest decision_function score from zero-pickle NPZ arrays."""
    center = npz_arrays["scaler_center"]
    scale = npz_arrays["scaler_scale"]
    x = [(float(feat_26[i]) - float(center[i])) / float(scale[i]) for i in range(26)]

    left_arr = npz_arrays["children_left"]
    right_arr = npz_arrays["children_right"]
    feat_arr = npz_arrays["feature"]
    thresh_arr = npz_arrays["threshold"]
    samples_arr = npz_arrays["n_node_samples"]
    c_n_table = npz_arrays["c_n_table"]
    c_max = float(npz_arrays["c_max"])
    offset = float(npz_arrays["offset"])

    n_trees = int(left_arr.shape[0])
    total_path = 0.0
    for tree_idx in range(n_trees):
        left = left_arr[tree_idx]
        right = right_arr[tree_idx]
        feat = feat_arr[tree_idx]
        thresh = thresh_arr[tree_idx]
        samples = samples_arr[tree_idx]

        node = 0
        depth = 0
        while int(left[node]) != -1:
            if x[int(feat[node])] <= float(thresh[node]):
                node = int(left[node])
            else:
                node = int(right[node])
            depth += 1

        n_samples = max(0, min(len(c_n_table) - 1, int(samples[node])))
        total_path += depth + float(c_n_table[n_samples])

    mean_path = total_path / max(1, n_trees)
    return float(-(2.0 ** (-mean_path / c_max)) - offset)


def verify_and_load_artifacts(artifacts_dir: Path | None = None) -> dict[str, Any]:
    """Verifies SHA-256 hashes, loads XGBoost + IForest v2, and runs a 26-D smoke check."""
    t0 = time.perf_counter()
    art_dir = artifacts_dir or Path(
        os.environ.get("ML_ARTIFACTS_DIR", str(ML_ENGINE_DIR / "artifacts"))
    )

    xgb_path = art_dir / "xgb_v2.ubj"
    xgb_meta_path = art_dir / "xgb_v2_metadata.json"
    iforest_path = art_dir / "iforest_v2.npz"
    iforest_meta_path = art_dir / "iforest_v2_metadata.json"

    xgb_sha256, xgb_meta = _verify_sha256(xgb_path, xgb_meta_path)
    iforest_sha256, iforest_meta = _verify_sha256(iforest_path, iforest_meta_path)

    booster = xgb.Booster({"nthread": 1})
    booster.load_model(str(xgb_path))
    booster.set_param({"nthread": 1})

    required_npz_keys = (
        "scaler_center",
        "scaler_scale",
        "children_left",
        "children_right",
        "feature",
        "threshold",
        "n_node_samples",
        "c_n_table",
        "c_max",
        "offset",
    )
    with np.load(str(iforest_path), allow_pickle=False) as npz:
        missing = [k for k in required_npz_keys if k not in npz]
        if missing:
            raise ValueError(f"iforest_v2.npz missing required arrays: {missing}")
        npz_arrays: dict[str, Any] = {k: npz[k] for k in required_npz_keys}

    if len(CANONICAL_FEATURE_NAMES_V2) != 26:
        raise RuntimeError(f"Expected 26 features, got {len(CANONICAL_FEATURE_NAMES_V2)}")

    vec_benign = extract_26_from_http(
        path="/api/v1/vulnerable/books/search/",
        query_params="q=Clean+Code",
        body=None,
    )
    vec_sqli = extract_26_from_http(
        path="/api/v1/vulnerable/books/search/",
        query_params="q=' OR 1=1--",
        body=None,
    )
    if vec_benign.shape != (26,) or vec_sqli.shape != (26,):
        raise RuntimeError(
            f"26-D smoke feature shape mismatch: benign={vec_benign.shape}, sqli={vec_sqli.shape}"
        )

    batch = np.vstack([vec_benign, vec_sqli]).astype(np.float32)
    probs = booster.predict(xgb.DMatrix(batch))
    if probs.shape != (2, 5) or not np.all(np.isfinite(probs)):
        raise RuntimeError(f"Unexpected XGBoost smoke output shape/values: {probs.shape}")

    benign_attack_prob = float(1.0 - probs[0][0])
    sqli_attack_prob = float(1.0 - probs[1][0])
    if sqli_attack_prob <= benign_attack_prob:
        raise RuntimeError(
            f"XGBoost smoke check failed: sqli_attack_prob={sqli_attack_prob:.4f} "
            f"<= benign_attack_prob={benign_attack_prob:.4f}"
        )

    iforest_benign_raw = _iforest_npz_raw_score(npz_arrays, vec_benign)
    iforest_sqli_raw = _iforest_npz_raw_score(npz_arrays, vec_sqli)
    if not (math.isfinite(iforest_benign_raw) and math.isfinite(iforest_sqli_raw)):
        raise RuntimeError("IsolationForest smoke inference returned non-finite score")

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    payload: dict[str, Any] = {
        "status": "ok",
        "service": "ml-engine",
        "feature_dim": 26,
        "sha256_verified": True,
        "models": {
            "xgb_v2": {
                "file": xgb_path.name,
                "version": xgb_meta.get("model_version", "2.0.0"),
                "sha256": xgb_sha256,
                "classes": xgb_meta.get("classes", []),
            },
            "iforest_v2": {
                "file": iforest_path.name,
                "version": iforest_meta.get("model_version", "2.0.0"),
                "sha256": iforest_sha256,
                "n_trees": int(npz_arrays["children_left"].shape[0]),
            },
        },
        "smoke_inference_passed": True,
        "smoke_check": {
            "benign_attack_prob": round(benign_attack_prob, 6),
            "sqli_attack_prob": round(sqli_attack_prob, 6),
            "iforest_benign_raw": round(iforest_benign_raw, 6),
            "iforest_sqli_raw": round(iforest_sqli_raw, 6),
        },
        "startup_ms": elapsed_ms,
    }
    logger.info(
        "ML Engine verified xgb_v2 (%s...) & iforest_v2 (%s...) + 26-D smoke check PASSED in %.2f ms",
        xgb_sha256[:12],
        iforest_sha256[:12],
        elapsed_ms,
    )
    return payload


def create_health_handler(health_payload: dict[str, Any]) -> type[BaseHTTPRequestHandler]:
    """Creates an HTTP handler serving the verified health payload on GET /health."""
    encoded_body = json.dumps(health_payload).encode("utf-8")

    class _HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] in ("/health", "/health/"):
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded_body)))
                self.end_headers()
                self.wfile.write(encoded_body)
                return

            not_found = b'{"detail":"Not Found"}'
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(not_found)))
            self.end_headers()
            self.wfile.write(not_found)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug(format, *args)

    return _HealthHandler


def main() -> None:
    """Entrypoint: verifies artifacts, runs 26-D smoke inference, and serves /health."""
    health_payload = verify_and_load_artifacts()
    host = os.environ.get("ML_HEALTH_HOST", "0.0.0.0")
    port = int(os.environ.get("ML_HEALTH_PORT", "8001"))

    server = ThreadingHTTPServer((host, port), create_health_handler(health_payload))
    server.daemon_threads = True

    def _shutdown(_signum: int, _frame: Any) -> None:
        logger.info("Shutting down ml-engine health server...")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("ML Engine health server listening on http://%s:%d/health", host, port)
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
