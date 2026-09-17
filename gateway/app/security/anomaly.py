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
        "ml-engine/models/iforest_model.joblib",
        "gateway/models/iforest_model.joblib",
        "../ml-engine/models/iforest_model.joblib",
    ]

    def __init__(
        self,
        model_path: str | Path | None = None,
        anomaly_threshold: float = 60.0,
    ) -> None:
        """Initializes the Anomaly Detector and attempts pre-warmed model loading."""
        self._model: Any = None
        self._model_path: Path | None = None
        self._is_loaded: bool = False
        self.anomaly_threshold = anomaly_threshold

        if model_path:
            self.load_model(model_path)
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
        for candidate in self.DEFAULT_MODEL_PATHS:
            p = Path(candidate)
            if p.exists() and p.is_file():
                if self.load_model(p):
                    return
        logger.info(
            "Isolation Forest model artifact not found. "
            "Gateway operating in Graceful Fallback Mode (NIST SP 800-115)."
        )

    def load_model(self, path: str | Path) -> bool:
        """Loads and pre-warms the Isolation Forest model into memory."""
        if joblib is None:
            logger.warning("joblib is not installed. Anomaly detection inference is disabled.")
            self._is_loaded = False
            return False

        model_file = Path(path)
        if not model_file.exists():
            logger.warning(f"Isolation Forest model file not found at: {model_file.resolve()}")
            self._is_loaded = False
            return False

        try:
            start_time = time.perf_counter()
            loaded = joblib.load(model_file)
            load_elapsed = (time.perf_counter() - start_time) * 1000.0

            # Support dict artifact or raw sklearn model
            if isinstance(loaded, dict) and "model" in loaded:
                self._model = loaded["model"]
            else:
                self._model = loaded

            if not hasattr(self._model, "decision_function"):
                logger.error(f"Loaded artifact at {model_file} does not have 'decision_function'.")
                self._is_loaded = False
                return False

            self._model_path = model_file
            self._is_loaded = True
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
        self._model_path = None
        self._is_loaded = False

    @staticmethod
    def normalize_anomaly_score(raw_decision_score: float) -> float:
        """Standardizes raw Isolation Forest decision score into 0-100 risk scale.

        In scikit-learn IsolationForest:
          - decision_function(X) >= 0.0: inlier (normal traffic).
            Mapped to 0.0 - 30.0 (ALLOW).
          - decision_function(X) < 0.0: outlier (anomalous traffic / zero-day).
            Mapped to 30.0 - 100.0 (MONITOR, RATE_LIMIT, BLOCK).

        Piecewise continuous formula:
          - If raw >= 0: max(0.0, 30.0 - raw * 300.0)
          - If raw < 0:  min(100.0, 30.0 + abs(raw) * 850.0)
        """
        raw = float(raw_decision_score)
        if raw >= 0.0:
            return round(max(0.0, 30.0 - raw * 300.0), 2)
        return round(min(100.0, 30.0 + abs(raw) * 850.0), 2)

    def predict(self, payload: str) -> AnomalyResult:
        """Executes real-time anomaly detection inference under < 10ms latency.

        If model is unavailable, gracefully returns empty result (NIST SP 800-115).
        """
        start_time = time.perf_counter()

        if not self._is_loaded or self._model is None:
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
            features = MLDetector.extract_features(payload)
            # IsolationForest accepts 2D array [1, 17]
            raw_scores = self._model.decision_function([features])
            raw_score = float(raw_scores[0])
            anomaly_score = self.normalize_anomaly_score(raw_score)
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
