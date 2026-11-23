import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.ml_detector import MLDetector

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None

logger = logging.getLogger("waf.gateway.security.anomaly")


@dataclass
class AnomalyResult:
    """Inference outcome from Unsupervised Anomaly Detection (Isolation Forest)."""

    is_anomaly: bool
    raw_score: float | None
    anomaly_score: float | None
    latency_ms: float
    model_loaded: bool
    feature_vector: list[float] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serializes result into dictionary format."""
        return {
            "is_anomaly": self.is_anomaly,
            "raw_score": self.raw_score,
            "anomaly_score": self.anomaly_score,
            "latency_ms": self.latency_ms,
            "model_loaded": self.model_loaded,
        }


class AnomalyDetector:
    """Real-time anomaly detection service for the WAF Gateway using Isolation Forest.

    Conforms to:
      - MDPI Electronics (2025) Lightweight Ensemble WAF: 3-tier defense integration (<10ms budget).
      - Wiley (2015) & IEEE (2024): 17-dimensional morphological HTTP feature extraction.
      - NIST SP 800-115: Graceful fallback when model is absent or not yet trained by Member B.
    """

    DEFAULT_MODEL_PATHS: list[str] = [
        # Calibrated IsolationForest v2.0 (Multi-source 26-D)
        "ml-engine/artifacts/iforest_v2.joblib",
        "../ml-engine/artifacts/iforest_v2.joblib",
        "gateway/models/iforest_v2.joblib",
        # Legacy Isolation Forest models
        "ml-engine/artifacts/iforest_model.joblib",
        "ml-engine/models/iforest_model.joblib",
        "gateway/models/iforest_model.joblib",
        "../ml-engine/artifacts/iforest_model.joblib",
        "../ml-engine/models/iforest_model.joblib",
    ]

    def __init__(
        self,
        model_path: str | Path | None = None,
        anomaly_threshold: float = 60.0,
        allow_unverified: bool = False,
    ) -> None:
        """Initializes the Anomaly Detector and attempts pre-warmed model loading."""
        self._model: Any = None
        self._scaler: Any = None
        self._is_npz: bool = False
        self._npz_data: dict[str, Any] | None = None
        self._model_path: Path | None = None
        self._is_loaded: bool = False
        self._percentiles: dict[str, float] = {}
        self.anomaly_threshold = anomaly_threshold

        if model_path:
            self.load_model(model_path, allow_unverified=allow_unverified)
        else:
            self._attempt_auto_load()

    @property
    def is_loaded(self) -> bool:
        """Indicates whether the Isolation Forest model is active in RAM."""
        return self._is_loaded

    @property
    def model_path(self) -> Path | None:
        """Returns the filesystem path of the loaded model, if any."""
        return self._model_path

    def _attempt_auto_load(self) -> None:
        """Searches default model directories for pre-trained Isolation Forest artifacts."""
        repo_root = Path(__file__).resolve().parents[3]
        extended_candidates = [
            repo_root / "ml-engine" / "artifacts" / "iforest_v2.npz",
            repo_root / "gateway" / "models" / "iforest_v2.npz",
            repo_root / "ml-engine" / "artifacts" / "iforest_v2.joblib",
            repo_root / "gateway" / "models" / "iforest_v2.joblib",
            repo_root / "ml-engine" / "artifacts" / "iforest_model.joblib",
            repo_root / "ml-engine" / "models" / "iforest_model.joblib",
            repo_root / "gateway" / "models" / "iforest_model.joblib",
        ] + [Path(c) for c in self.DEFAULT_MODEL_PATHS]

        for p in extended_candidates:
            if p.exists() and p.is_file():
                if self.load_model(p):
                    return
        logger.info(
            "Isolation Forest model artifact not found. "
            "Gateway operating in Graceful Fallback Mode (NIST SP 800-115)."
        )

    def load_model(self, path: str | Path, allow_unverified: bool = False) -> bool:
        """Loads and pre-warms the Isolation Forest model into memory with fail-closed SHA-256 verification."""
        model_file = Path(path).resolve()
        if not model_file.exists():
            logger.warning(f"Isolation Forest model file not found at: {model_file}")
            self._is_loaded = False
            return False

        is_npz = model_file.suffix.lower() == ".npz"
        if not is_npz and joblib is None:
            logger.warning("joblib is not installed. Anomaly detection inference is disabled.")
            self._is_loaded = False
            return False

        # SEC-PBL6-005: Cryptographic SHA-256 hash verification
        stem = model_file.stem
        meta_candidates = [
            model_file.with_name(f"{stem}_metadata.json"),
            model_file.parent / f"{stem}_metadata.json",
            model_file.parent / "artifacts" / f"{stem}_metadata.json",
        ]
        if stem == "iforest_model":
            meta_candidates.extend([
                model_file.with_name("iforest_metadata.json"),
                model_file.parent / "artifacts" / "iforest_metadata.json",
            ])
        elif stem == "iforest_v2":
            meta_candidates.extend([
                model_file.with_name("iforest_v2_metadata.json"),
                model_file.parent / "artifacts" / "iforest_v2_metadata.json",
            ])

        verified = False
        meta_info: dict[str, Any] = {}
        for meta_candidate in meta_candidates:
            if meta_candidate.exists() and meta_candidate.is_file():
                try:
                    import hashlib
                    import json
                    meta_info = json.loads(meta_candidate.read_text(encoding="utf-8"))
                    expected_hash = meta_info.get("sha256_hash")
                    if expected_hash:
                        actual_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
                        if actual_hash != expected_hash:
                            logger.critical(
                                f"Cryptographic hash mismatch for {model_file}! Expected {expected_hash}, got {actual_hash}. "
                                "Aborting model load to prevent CWE-502 untrusted deserialization."
                            )
                            self._is_loaded = False
                            return False
                        logger.info(f"Model cryptographic integrity verified (SHA-256: {actual_hash[:12]}...).")
                        verified = True
                        break
                except Exception as ex:
                    logger.warning(f"Error checking cryptographic hash against {meta_candidate}: {ex}")

        if not verified and not allow_unverified:
            logger.critical(
                f"SEC-PBL6-005 Fail-Closed: Missing or invalid metadata/hash for {model_file}. "
                "Refusing to load unverified model artifact."
            )
            self._is_loaded = False
            return False

        try:
            start_time = time.perf_counter()
            if is_npz:
                npz = np.load(str(model_file), allow_pickle=False)
                scaler_center = npz["scaler_center"]
                scaler_scale = npz["scaler_scale"]
                left_arr = npz["children_left"]
                right_arr = npz["children_right"]
                feat_arr = npz["feature"]
                thresh_arr = npz["threshold"]
                samples_arr = npz["n_node_samples"]
                c_n_table = npz["c_n_table"]
                c_max = float(npz["c_max"])
                offset = float(npz["offset"])
                n_trees = left_arr.shape[0]
                tree_indices = np.arange(n_trees, dtype=np.int32)

                self._tree_lists = [
                    (
                        left_arr[i].tolist(),
                        right_arr[i].tolist(),
                        feat_arr[i].tolist(),
                        thresh_arr[i].tolist(),
                        samples_arr[i].tolist(),
                    )
                    for i in range(n_trees)
                ]
                self._center_list = scaler_center.tolist()
                self._scale_list = scaler_scale.tolist()
                self._c_n_list = c_n_table.tolist()

                self._npz_data = {
                    "center": scaler_center,
                    "scale": scaler_scale,
                    "left": left_arr,
                    "right": right_arr,
                    "feat": feat_arr,
                    "thresh": thresh_arr,
                    "samples": samples_arr,
                    "c_n_table": c_n_table,
                    "c_max": c_max,
                    "offset": offset,
                    "n_trees": n_trees,
                    "tree_indices": tree_indices,
                }
                self._is_npz = True
                self._scaler = None
                self._model = None
            else:
                loaded = joblib.load(model_file)
                # Support dict artifact (scaler + model) or raw sklearn model
                if isinstance(loaded, dict) and "model" in loaded:
                    self._scaler = loaded.get("scaler")
                    self._model = loaded["model"]
                else:
                    self._scaler = None
                    self._model = loaded
                self._is_npz = False
                self._npz_data = None

                if not hasattr(self._model, "decision_function"):
                    logger.error(f"Loaded artifact at {model_file} does not have 'decision_function'.")
                    self._is_loaded = False
                    return False

                # Enforce single-thread execution for real-time per-request WAF latency
                if hasattr(self._model, "n_jobs") and getattr(self._model, "n_jobs", None) != 1:
                    try:
                        self._model.n_jobs = 1
                    except Exception:
                        pass

            self._percentiles = meta_info.get("percentiles", {})
            self._model_path = Path(path)
            self._is_loaded = True
            load_elapsed = (time.perf_counter() - start_time) * 1000.0
            logger.info(
                f"Successfully loaded Isolation Forest model from {model_file} "
                f"in {load_elapsed:.2f}ms (pre-warmed in RAM)."
            )
            return True
        except Exception as e:
            logger.error(f"Failed to load Isolation Forest model from {model_file}: {e}")
            self._is_loaded = False
            return False

    def reload(self) -> bool:
        """Re-scans default model locations and loads the model if newly created."""
        if self._model_path and self._model_path.exists():
            return self.load_model(self._model_path)
        self._attempt_auto_load()
        return self._is_loaded

    def unload(self) -> None:
        """Unloads the Isolation Forest model from RAM (used for fallback or testing)."""
        self._model = None
        self._scaler = None
        self._is_npz = False
        self._npz_data = None
        self._tree_lists = []
        self._center_list = []
        self._scale_list = []
        self._c_n_list = []
        self._model_path = None
        self._is_loaded = False
        self._percentiles = {}

    def _predict_raw_score_npz(self, feat_26: Any) -> float:
        """Fast native list tree traversal for single-request inference (<0.2ms)."""
        d = self._npz_data
        if d is None or not getattr(self, "_tree_lists", None):
            return 0.0

        if isinstance(feat_26, np.ndarray):
            f_list = feat_26.tolist()
        else:
            f_list = list(feat_26)

        center = self._center_list
        scale = self._scale_list
        x = [(f_list[i] - center[i]) / scale[i] for i in range(26)]

        c_n_table = self._c_n_list
        c_max = d["c_max"]
        offset = d["offset"]

        total_path = 0.0
        for left, right, feat, thresh, samples in self._tree_lists:
            node = 0
            depth = 0
            while left[node] != -1:
                f_idx = feat[node]
                if x[f_idx] <= thresh[node]:
                    node = left[node]
                else:
                    node = right[node]
                depth += 1
            n_samples = samples[node]
            if n_samples > 512:
                n_samples = 512
            elif n_samples < 0:
                n_samples = 0
            total_path += depth + c_n_table[n_samples]

        mean_path = total_path / len(self._tree_lists)
        raw_score = -(2.0 ** (-mean_path / c_max)) - offset
        return float(raw_score)

    @classmethod
    def normalize_anomaly_score(
        cls,
        raw_decision_score: float,
        percentiles: dict[str, float] | None = None,
    ) -> float:
        """Standardizes raw Isolation Forest decision score into 0-100 risk scale.
        Uses empirical percentiles when available, otherwise falls back to standard piecewise continuous formula.
        """
        raw = float(raw_decision_score)
        if percentiles and "p50" in percentiles:
            p50 = percentiles.get("p50", 0.12)
            p25 = percentiles.get("p25", percentiles.get("p10", 0.08))
            p10 = percentiles.get("p10", 0.063)
            p95 = percentiles.get("p95", 0.15)

            if raw >= p50:
                norm = min(1.0, (raw - p50) / max(1e-5, p95 - p50))
                return round(max(0.0, 15.0 * (1.0 - norm)), 2)
            elif raw >= p25:
                norm = (raw - p25) / max(1e-5, p50 - p25)
                return round(30.0 - (15.0 * norm), 2)
            elif raw >= p10:
                norm = (raw - p10) / max(1e-5, p25 - p10)
                return round(60.0 - (30.0 * norm), 2)
            else:
                diff = min(1.0, (p10 - raw) / max(1e-5, abs(p10)))
                return round(min(100.0, 60.0 + (40.0 * diff)), 2)

        # Standard piecewise fallback formula
        if raw >= 0.0:
            return round(max(0.0, 30.0 - raw * 300.0), 2)
        return round(min(100.0, 30.0 + abs(raw) * 850.0), 2)

    def predict(
        self,
        payload: str,
        feature_vector: list[float] | None = None,
    ) -> AnomalyResult:
        """Executes real-time anomaly detection inference under < 10ms latency."""
        start_time = time.perf_counter()

        if not self._is_loaded or (self._model is None and not getattr(self, "_is_npz", False)):
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            return AnomalyResult(
                is_anomaly=False,
                raw_score=None,
                anomaly_score=None,
                latency_ms=latency_ms,
                model_loaded=False,
                feature_vector=None,
            )

        try:
            is_npz = getattr(self, "_is_npz", False)
            expected_dim = 26 if is_npz else getattr(self._model, "n_features_in_", 26 if self._scaler is not None else 17)
            if feature_vector is not None:
                features = feature_vector
                if expected_dim == 17 and len(features) == 26:
                    features = features[:17]
                elif expected_dim == 26 and len(features) == 17:
                    features = MLDetector.extract_features_26(payload)
            else:
                if expected_dim == 26 or self._scaler is not None or is_npz:
                    features = MLDetector.extract_features_26(payload)
                else:
                    features = MLDetector.extract_features(payload)

            if is_npz:
                inp_arr = np.asarray(features, dtype=np.float32)
                raw_score = self._predict_raw_score_npz(inp_arr)
            else:
                if np is not None:
                    inp = np.asarray([features], dtype=np.float32)
                else:
                    inp = [features]

                if self._scaler is not None:
                    inp = self._scaler.transform(inp)

                raw_scores = self._model.decision_function(inp)
                raw_score = float(raw_scores[0])

            anomaly_score = self.normalize_anomaly_score(raw_score, percentiles=self._percentiles)
            is_anomaly = anomaly_score >= self.anomaly_threshold

            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

            return AnomalyResult(
                is_anomaly=is_anomaly,
                raw_score=round(raw_score, 4),
                anomaly_score=anomaly_score,
                latency_ms=latency_ms,
                model_loaded=True,
                feature_vector=features,
            )
        except Exception as e:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            logger.error(f"Anomaly detection inference error: {e}")
            return AnomalyResult(
                is_anomaly=False,
                raw_score=None,
                anomaly_score=None,
                latency_ms=latency_ms,
                model_loaded=True,
                feature_vector=None,
            )


_anomaly_detector_instance: AnomalyDetector | None = None


def get_anomaly_detector() -> AnomalyDetector:
    """Provides a shared singleton instance of the AnomalyDetector."""
    global _anomaly_detector_instance
    if _anomaly_detector_instance is None:
        _anomaly_detector_instance = AnomalyDetector()
    return _anomaly_detector_instance
