import logging
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import joblib
except ImportError:
    joblib = None

logger = logging.getLogger("waf.gateway.security.ml_detector")

FEATURE_NAMES: list[str] = [
    "length",
    "entropy",
    "count_single_quote",
    "count_double_quote",
    "count_less_than",
    "count_greater_than",
    "count_semicolon",
    "count_hyphen",
    "count_slash",
    "count_backslash",
    "count_parenthesis",
    "special_char_ratio",
    "sql_keyword_count",
    "xss_keyword_count",
    "sqli_regex_matches",
    "xss_regex_matches",
    "path_traversal_matches",
]

_SQL_KEYWORDS = re.compile(
    r"\b(select|union|insert|update|delete|drop|from|where|having|order by|group by|exec|waitfor|benchmark)\b",
    re.IGNORECASE,
)
_XSS_KEYWORDS = re.compile(
    r"\b(script|onerror|onload|alert|iframe|javascript|eval|prompt|confirm|document\.cookie)\b",
    re.IGNORECASE,
)
_SQLI_PATTERNS = re.compile(
    r"(\bunion\b.*\bselect\b|'--|--\s*$|/\*.*\*/|'\s*(or|and)\s*['\d=]|;\s*drop)",
    re.IGNORECASE,
)
_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|on\w+\s*=|<img\s+src=|<svg|<iframe)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|c:\\windows)",
    re.IGNORECASE,
)


@dataclass
class MLPredictionResult:
    """Inference outcome from Machine Learning classifier."""

    is_attack: bool
    attack_type: str
    confidence: float
    risk_score: float | None
    probabilities: dict[str, float]
    latency_ms: float
    model_loaded: bool
    feature_vector: list[float] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serializes result into dictionary format."""
        return {
            "is_attack": self.is_attack,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "probabilities": self.probabilities,
            "latency_ms": self.latency_ms,
            "model_loaded": self.model_loaded,
        }


class MLDetector:
    """Real-time machine learning inference service for the WAF Gateway.

    Conforms to:
      - MDPI Electronics (2025) Lightweight Ensemble WAF: Pre-warmed RAM model caching (<15ms latency).
      - Wiley (2015) & IEEE (2024): 17-dimensional morphological HTTP feature extraction.
      - NIST SP 800-115: Graceful fallback when model is absent or not yet trained by Member B.
    """

    DEFAULT_MODEL_PATHS: list[str] = [
        "ml-engine/models/rf_model.joblib",
        "gateway/models/rf_model.joblib",
        "../ml-engine/models/rf_model.joblib",
    ]

    def __init__(self, model_path: str | Path | None = None) -> None:
        """Initializes the ML inference service and attempts pre-warmed model loading."""
        self._model: Any = None
        self._classes: list[str] = []
        self._model_path: Path | None = None
        self._is_loaded: bool = False

        if model_path:
            self.load_model(model_path)
        else:
            self._attempt_auto_load()

    @property
    def is_loaded(self) -> bool:
        """Indicates whether the ML model is currently active in RAM."""
        return self._is_loaded

    @property
    def model_path(self) -> Path | None:
        """Returns the filesystem path of the loaded model, if any."""
        return self._model_path

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon entropy for string randomness measurement."""
        if not text:
            return 0.0
        length = len(text)
        frequencies: dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy = 0.0
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def extract_features(cls, payload: str) -> list[float]:
        """Extracts 17 morphological and keyword features from request payload (< 0.1ms)."""
        if not payload:
            return [0.0] * len(FEATURE_NAMES)

        length = float(len(payload))
        entropy = cls.calculate_shannon_entropy(payload)
        count_single_quote = float(payload.count("'"))
        count_double_quote = float(payload.count('"'))
        count_less_than = float(payload.count("<"))
        count_greater_than = float(payload.count(">"))
        count_semicolon = float(payload.count(";"))
        count_hyphen = float(payload.count("-"))
        count_slash = float(payload.count("/"))
        count_backslash = float(payload.count("\\"))
        count_parenthesis = float(payload.count("(") + payload.count(")"))

        special_chars = sum(1 for c in payload if not c.isalnum() and not c.isspace())
        special_char_ratio = round(special_chars / max(1.0, length), 4)

        sql_keyword_count = float(len(_SQL_KEYWORDS.findall(payload)))
        xss_keyword_count = float(len(_XSS_KEYWORDS.findall(payload)))
        sqli_regex_matches = float(len(_SQLI_PATTERNS.findall(payload)))
        xss_regex_matches = float(len(_XSS_PATTERNS.findall(payload)))
        path_traversal_matches = float(len(_PATH_TRAVERSAL_PATTERNS.findall(payload)))

        return [
            length,
            entropy,
            count_single_quote,
            count_double_quote,
            count_less_than,
            count_greater_than,
            count_semicolon,
            count_hyphen,
            count_slash,
            count_backslash,
            count_parenthesis,
            special_char_ratio,
            sql_keyword_count,
            xss_keyword_count,
            sqli_regex_matches,
            xss_regex_matches,
            path_traversal_matches,
        ]

    def _attempt_auto_load(self) -> None:
        """Searches default locations for a serialized Random Forest model."""
        for candidate in self.DEFAULT_MODEL_PATHS:
            p = Path(candidate)
            if p.exists() and p.is_file():
                if self.load_model(p):
                    return
        logger.info("No pre-trained ML model found on startup. Operating in Graceful Fallback mode.")

    def load_model(self, path: str | Path) -> bool:
        """Loads a serialized joblib model into memory."""
        if joblib is None:
            logger.warning("joblib is not installed in the current environment. Unable to load model.")
            return False

        resolved = Path(path).resolve()
        if not resolved.exists():
            logger.warning(f"Model file not found at: {resolved}")
            return False

        try:
            model = joblib.load(resolved)
            if not hasattr(model, "predict_proba"):
                logger.error(f"Loaded object from {resolved} does not implement predict_proba.")
                return False

            self._model = model
            self._classes = [str(c) for c in getattr(model, "classes_", ["BENIGN", "ATTACK"])]
            self._model_path = resolved
            self._is_loaded = True
            logger.info(f"Successfully loaded ML model from: {resolved} (classes: {self._classes})")
            return True
        except Exception as err:
            logger.error(f"Failed to load ML model from {resolved}: {err}")
            self._model = None
            self._is_loaded = False
            return False

    def unload(self) -> None:
        """Unloads the ML model from RAM (used for fallback or testing)."""
        self._model = None
        self._classes = []
        self._model_path = None
        self._is_loaded = False

    def predict(self, payload: str) -> MLPredictionResult:
        """Performs real-time machine learning inference within a <15ms latency budget.

        Args:
            payload: Aggregated request content (query string, parameters, body).

        Returns:
            MLPredictionResult with classification, confidence, and latency metrics.
        """
        start_time = time.perf_counter()

        # 1. Graceful Fallback if model is not loaded (Member B hasn't finished training)
        if not self._is_loaded or self._model is None:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return MLPredictionResult(
                is_attack=False,
                attack_type="BENIGN",
                confidence=0.0,
                risk_score=None,
                probabilities={},
                latency_ms=round(latency_ms, 3),
                model_loaded=False,
            )

        # 2. Extract 17 morphological features
        feature_vector = self.extract_features(payload)

        # 3. Model inference
        try:
            proba_array = self._model.predict_proba([feature_vector])[0]
            probabilities = {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self._classes, proba_array)
            }

            # Determine dominant class
            top_index = int(proba_array.argmax())
            dominant_class = self._classes[top_index]
            confidence = float(proba_array[top_index])

            is_attack = dominant_class.upper() != "BENIGN" and confidence >= 0.50

            # Scale risk score to 0 - 100
            if is_attack:
                risk_score = round(confidence * 100.0, 2)
            else:
                # If benign, risk score is proportional to non-benign residual probability
                benign_prob = probabilities.get("BENIGN", probabilities.get("benign", confidence))
                risk_score = round(max(0.0, (1.0 - benign_prob) * 30.0), 2)

            latency_ms = (time.perf_counter() - start_time) * 1000

            return MLPredictionResult(
                is_attack=is_attack,
                attack_type=dominant_class,
                confidence=round(confidence, 4),
                risk_score=risk_score,
                probabilities=probabilities,
                latency_ms=round(latency_ms, 3),
                model_loaded=True,
                feature_vector=feature_vector,
            )
        except Exception as err:
            logger.error(f"ML inference failed: {err}")
            latency_ms = (time.perf_counter() - start_time) * 1000
            return MLPredictionResult(
                is_attack=False,
                attack_type="BENIGN",
                confidence=0.0,
                risk_score=None,
                probabilities={},
                latency_ms=round(latency_ms, 3),
                model_loaded=True,
            )
