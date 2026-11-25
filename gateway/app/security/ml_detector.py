import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .normalizer import InputNormalizer

# Gateway workers execute single-request inline inference (nthread=1). Without
# OMP_NUM_THREADS=1, OpenMP initializes a multi-core spin-barrier thread pool on
# Windows that inflates per-request latency ~2.9x and causes thread contention under
# concurrent async load; setdefault preserves explicit operator env overrides.
os.environ.setdefault("OMP_NUM_THREADS", "1")

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import xgboost as xgb
except ImportError:
    xgb = None

logger = logging.getLogger("waf.gateway.security.ml_detector")

# Ensure ml-engine is accessible for unified feature extraction (Master Plan A5)
for candidate in [
    Path(__file__).resolve().parents[3] / 'ml-engine',
    Path(__file__).resolve().parents[2] / 'ml-engine',
    Path('/app/ml-engine'),
    Path('ml-engine'),
]:
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from features.extractor import (  # noqa: E402
    CANONICAL_FEATURE_NAMES,
    extract_17_vector,
    extract_26_from_http,
    extract_26_vector,
)
from features.payload import calculate_entropy  # noqa: E402

FEATURE_NAMES: list[str] = CANONICAL_FEATURE_NAMES

_INPUT_NORMALIZER = InputNormalizer()
_SUSPICIOUS_SYNTAX_RE = re.compile(
    r"(['\"<>();$&|\\{}`=]|/\*|\*/|--|\.\.|\\u00)"
)
_BENIGN_PARAM_VALUE_RE = re.compile(
    r"^(?:"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)?"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|-?\d+(?:\.\d+)?"
    r")$"
)


def normalize_http_for_ml(
    path: str,
    query_params: str | None = None,
    body: str | None = None,
) -> tuple[str, str | None, str | None]:
    """Normalizes HTTP path, query string, and body for ML feature extraction.

    Decodes form/query '+' -> space (preserving '+' inside JSON/XML/plain payloads)
    and applies bounded multi-pass canonicalization via cached InputNormalizer.
    """
    norm_path = _INPUT_NORMALIZER.normalize(path) if path else ""

    if query_params is None:
        norm_query: str | None = None
    elif query_params == "":
        norm_query = ""
    else:
        norm_query = _INPUT_NORMALIZER.normalize(query_params.replace("+", " "))

    if body is None:
        norm_body: str | None = None
    elif body == "":
        norm_body = ""
    else:
        body_stripped = body.lstrip()
        is_structured_non_form = body_stripped.startswith(("{", "[", "<"))
        is_form_body = (
            not is_structured_non_form
            and "=" in body
            and ("&" in body or not any(ch.isspace() for ch in body_stripped.split("=", 1)[0]))
        )
        body_work = body.replace("+", " ") if is_form_body else body
        norm_body = _INPUT_NORMALIZER.normalize(body_work)

    return norm_path, norm_query, norm_body


def _extract_http_params(
    norm_query: str | None,
    norm_body: str | None,
    raw_body: str | None = None,
) -> list[tuple[str, str]]:
    """Extracts (key, value) pairs from normalized query string and body (JSON or form)."""
    params: list[tuple[str, str]] = []

    if norm_query:
        for seg in norm_query.split("&"):
            if not seg:
                continue
            if "=" in seg:
                k, v = seg.split("=", 1)
                params.append((k, v))
            else:
                params.append(("", seg))

    if norm_body:
        stripped = norm_body.lstrip()
        if stripped.startswith(("{", "[")):
            parsed_obj: Any = None
            need_norm = False
            try:
                parsed_obj = json.loads(norm_body, object_pairs_hook=list)
            except Exception:
                if raw_body:
                    try:
                        parsed_obj = json.loads(raw_body, object_pairs_hook=list)
                        need_norm = True
                    except Exception:
                        parsed_obj = None
            if parsed_obj is not None:
                stack: list[tuple[str, Any]] = [("", parsed_obj)]
                visited = 0
                while stack and visited < 64:
                    key, val = stack.pop()
                    visited += 1
                    if isinstance(val, str):
                        if val:
                            v_norm = _INPUT_NORMALIZER.normalize(val) if need_norm else val
                            params.append((key, v_norm))
                            if v_norm.lstrip().startswith(("{", "[")):
                                try:
                                    nested_val = json.loads(v_norm, object_pairs_hook=list)
                                except Exception:
                                    nested_val = None
                                if nested_val is not None:
                                    stack.append((key, nested_val))
                    elif isinstance(val, dict):
                        for ck, cv in reversed(list(val.items())):
                            stack.append((str(ck), cv))
                    elif isinstance(val, list) and val and all(
                        isinstance(el, tuple) and len(el) == 2 for el in val
                    ):
                        for ck, cv in reversed(val):
                            stack.append((str(ck), cv))
                    elif isinstance(val, list):
                        for item in reversed(val):
                            stack.append((key, item))
        elif not stripped.startswith("<") and "=" in norm_body:
            for seg in norm_body.split("&"):
                if not seg:
                    continue
                if "=" in seg:
                    k, v = seg.split("=", 1)
                    params.append((k, v))
                else:
                    params.append(("", seg))

    return params


__all__ = [
    "MLDetector",
    "MLPredictionResult",
    "FEATURE_NAMES",
    "extract_17_vector",
    "extract_26_vector",
    "extract_26_from_http",
    "normalize_http_for_ml",
]

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
    feature_names: list[str] | None = None
    model_name: str | None = None
    model_version: str | None = None

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
            "feature_vector": self.feature_vector,
            "feature_names": self.feature_names,
            "model_name": self.model_name,
            "model_version": self.model_version,
        }


class MLDetector:
    """Real-time machine learning inference service for the WAF Gateway.

    Conforms to:
      - MDPI Electronics (2025) Lightweight Ensemble WAF: Pre-warmed RAM model caching (<15ms latency).
      - Wiley (2015) & IEEE (2024): 17-dimensional morphological HTTP feature extraction.
      - NIST SP 800-115: Graceful fallback when model is absent or not yet trained by Member B.
    """

    DEFAULT_MODEL_PATHS: list[str] = [
        # Champion XGBoost v2.0 (Zero-Pickle UBJSON format)
        "ml-engine/artifacts/xgb_v2.ubj",
        "../ml-engine/artifacts/xgb_v2.ubj",
        "gateway/models/xgb_v2.ubj",
        # Champion Supervised Models (Model-Agnostic: XGBoost / RF / LightGBM)
        "ml-engine/artifacts/rf_model.joblib",
        "ml-engine/artifacts/best_model.joblib",
        "ml-engine/artifacts/xgb_model.joblib",
        "ml-engine/models/rf_model.joblib",
        "ml-engine/models/best_model.joblib",
        "ml-engine/models/xgb_model.joblib",
        "gateway/models/rf_model.joblib",
        "gateway/models/best_model.joblib",
        "../ml-engine/artifacts/rf_model.joblib",
        "../ml-engine/artifacts/best_model.joblib",
        "../ml-engine/artifacts/xgb_model.joblib",
    ]

    def __init__(
        self,
        model_path: str | Path | None = None,
        allow_unverified: bool = False,
    ) -> None:
        """Initializes the ML inference service and attempts pre-warmed model loading."""
        self._model: Any = None
        self._classes: list[str] = []
        self._model_path: Path | None = None
        self._is_loaded: bool = False
        self._is_ubj: bool = False
        self._feature_dim: int = 17
        self._model_name: str | None = None
        self._model_version: str | None = None
        self._feature_names: list[str] | None = None
        self._attack_threshold: float = 0.5
        self._compiled_lut: dict[str, Any] | None = None

        if model_path:
            self.load_model(model_path, allow_unverified=allow_unverified)
        else:
            self._attempt_auto_load()

    @property
    def is_loaded(self) -> bool:
        """Indicates whether the ML model is currently active in RAM."""
        return self._is_loaded

    @property
    def ml_available(self) -> bool:
        """Indicates whether the ML model is available and operational for inference (Master Plan A3)."""
        return self._is_loaded and self._model is not None

    @property
    def model_path(self) -> Path | None:
        """Returns the filesystem path of the loaded model, if any."""
        return self._model_path

    @property
    def model_name(self) -> str | None:
        """Returns the loaded model name from metadata."""
        return self._model_name

    @property
    def model_version(self) -> str | None:
        """Returns the model version string."""
        return self._model_version

    @property
    def classes(self) -> list[str]:
        """Returns the target classes array."""
        return self._classes

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon entropy for string randomness measurement via unified extractor."""
        return calculate_entropy(text)

    @classmethod
    def extract_features(cls, payload: str) -> list[float]:
        """Extracts canonical 17 features using unified ML Engine extractor (Master Plan A5)."""
        return extract_17_vector(payload, normalize=False).tolist()

    @classmethod
    def extract_features_26(cls, payload: str) -> list[float]:
        """Extracts canonical 26 features using unified ML Engine extractor v2.0."""
        return extract_26_vector(payload, normalize=False).tolist()

    def _attempt_auto_load(self) -> None:
        """Searches default locations for a serialized model."""
        repo_root = Path(__file__).resolve().parents[3]
        extended_candidates = [
            repo_root / "ml-engine" / "artifacts" / "xgb_v2.ubj",
            repo_root / "gateway" / "models" / "xgb_v2.ubj",
            repo_root / "ml-engine" / "artifacts" / "rf_model.joblib",
            repo_root / "ml-engine" / "artifacts" / "best_model.joblib",
            repo_root / "ml-engine" / "artifacts" / "xgb_model.joblib",
        ] + [Path(c) for c in self.DEFAULT_MODEL_PATHS]

        for p in extended_candidates:
            if p.exists() and p.is_file():
                if self.load_model(p):
                    return
        logger.info("No pre-trained ML model found on startup. Operating in Graceful Fallback mode.")

    def load_model(self, path: str | Path, allow_unverified: bool = False) -> bool:
        """Loads model (XGBoost UBJSON or joblib) with fail-closed SHA-256 verification."""
        resolved = Path(path).resolve()
        if not resolved.exists():
            logger.warning(f"Model file not found at: {resolved}")
            self._is_loaded = False
            return False

        # SEC-PBL6-005: Cryptographic SHA-256 integrity verification
        stem = resolved.stem
        meta_candidates = [
            resolved.with_name(f"{stem}_metadata.json"),
            resolved.parent / f"{stem}_metadata.json",
            resolved.parent / "artifacts" / f"{stem}_metadata.json",
        ]
        if stem in ("rf_model", "best_model"):
            meta_candidates.extend([
                resolved.with_name("rf_metadata.json"),
                resolved.parent / "artifacts" / "rf_metadata.json",
            ])
        elif stem == "xgb_v2":
            meta_candidates.extend([
                resolved.with_name("xgb_v2_metadata.json"),
                resolved.parent / "artifacts" / "xgb_v2_metadata.json",
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
                        actual_hash = hashlib.sha256(resolved.read_bytes()).hexdigest()
                        if actual_hash != expected_hash:
                            logger.critical(
                                f"Cryptographic hash mismatch for {resolved}! Expected {expected_hash}, got {actual_hash}. "
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
                f"SEC-PBL6-005 Fail-Closed: Missing or invalid metadata/hash for {resolved}. "
                "Refusing to load unverified model artifact."
            )
            self._is_loaded = False
            return False

        is_ubj = resolved.suffix.lower() in (".ubj", ".json")
        try:
            if is_ubj:
                if xgb is None:
                    logger.error("xgboost library is required to load UBJSON model.")
                    self._is_loaded = False
                    return False
                booster = xgb.Booster({"nthread": 1})
                booster.set_param({"nthread": 1})
                booster.load_model(str(resolved))
                booster.set_param({"nthread": 1})
                self._model = booster
                self._thread_local = threading.local()
                self._is_ubj = True
                self._feature_dim = meta_info.get("feature_count", 26)
                self._classes = meta_info.get(
                    "classes",
                    ["BENIGN", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SQL_INJECTION", "XSS"],
                )
                self._compiled_lut = self._compile_ubj_branchless_lut(booster)
            else:
                if joblib is None:
                    logger.warning("joblib is not installed in the current environment. Unable to load model.")
                    self._is_loaded = False
                    return False
                model = joblib.load(resolved)
                if not hasattr(model, "predict_proba"):
                    logger.error(f"Loaded object from {resolved} does not implement predict_proba.")
                    self._is_loaded = False
                    return False

                # Enforce single-thread execution for real-time per-request WAF latency
                if hasattr(model, "n_jobs") and getattr(model, "n_jobs", None) != 1:
                    try:
                        model.n_jobs = 1
                    except Exception:
                        pass

                self._model = model
                self._is_ubj = False
                self._feature_dim = 17
                self._classes = [str(c) for c in getattr(model, "classes_", ["BENIGN", "ATTACK"])]

            self._model_name = meta_info.get("model_name", "RandomForestClassifier" if not is_ubj else "XGBClassifier")
            self._model_version = meta_info.get("model_version", "1.0.0")
            self._feature_names = meta_info.get("feature_names", FEATURE_NAMES[:self._feature_dim])
            self._attack_threshold = float(meta_info.get("attack_threshold", 0.5))

            self._model_path = Path(path)
            self._is_loaded = True
            logger.info(f"Successfully loaded ML model from: {resolved} (classes: {self._classes})")
            return True
        except Exception as err:
            logger.error(f"Failed to load ML model from {resolved}: {err}")
            self._model = None
            self._is_loaded = False
            return False

    def _compile_ubj_branchless_lut(self, booster: Any) -> dict[str, Any] | None:
        """Compiles verified UBJSON trees into flat branchless NumPy lookup tables in RAM.

        Eliminates per-request ctypes JSON config serialization and OpenMP spin-barrier
        overhead while preserving bit-exact float32 tree split semantics.
        """
        if np is None:
            return None
        try:
            raw_model = json.loads(booster.save_raw(raw_format="json"))
            learner = raw_model["learner"]
            obj_name = learner.get("objective", {}).get("name", "")
            if obj_name not in ("multi:softprob", "multi:softmax"):
                return None
            model_param = learner["learner_model_param"]
            num_class = int(model_param["num_class"])
            if num_class < 2:
                return None
            base_raw = str(model_param.get("base_score", "0.5"))
            base_vals = (
                json.loads(base_raw)
                if base_raw.startswith("[")
                else [float(base_raw)] * num_class
            )
            base_logits = np.asarray(base_vals, dtype=np.float64)

            trees = learner["gradient_booster"]["model"]["trees"]
            n_trees = len(trees)
            if n_trees == 0 or n_trees % num_class != 0:
                return None
            max_nodes = max(len(t["left_children"]) for t in trees)
            total_slots = n_trees * max_nodes

            flat_feat = np.zeros(total_slots, dtype=np.intp)
            flat_thresh = np.zeros(total_slots, dtype=np.float32)
            flat_children = np.zeros((total_slots, 2), dtype=np.intp)
            flat_weights = np.zeros(total_slots, dtype=np.float32)
            max_depth = 0
            max_feat_idx = 0

            for ti, t in enumerate(trees):
                base = ti * max_nodes
                lc = t["left_children"]
                rc = t["right_children"]
                sc = t["split_conditions"]
                si = t["split_indices"]
                for ni in range(len(lc)):
                    slot = base + ni
                    if lc[ni] == -1:
                        flat_children[slot, 0] = slot
                        flat_children[slot, 1] = slot
                        flat_weights[slot] = sc[ni]
                    else:
                        f_idx = int(si[ni])
                        if f_idx > max_feat_idx:
                            max_feat_idx = f_idx
                        flat_feat[slot] = f_idx
                        flat_thresh[slot] = sc[ni]
                        flat_children[slot, 0] = base + lc[ni]
                        flat_children[slot, 1] = base + rc[ni]

                d = 0
                stk = [(0, 0)]
                while stk:
                    nd, dp = stk.pop()
                    if dp > d:
                        d = dp
                    if lc[nd] != -1:
                        stk.append((lc[nd], dp + 1))
                        stk.append((rc[nd], dp + 1))
                if d > max_depth:
                    max_depth = d

            return {
                "booster_id": id(booster),
                "num_class": num_class,
                "max_depth": max_depth,
                "max_feat_idx": max_feat_idx,
                "root_slots": np.arange(n_trees, dtype=np.intp) * max_nodes,
                "flat_feat": flat_feat,
                "flat_thresh": flat_thresh,
                "flat_children": flat_children,
                "flat_weights": flat_weights,
                "base_logits": base_logits,
            }
        except Exception as exc:
            logger.debug(f"Skipping LUT compilation, using native Booster fallback: {exc}")
            return None

    def unload(self) -> None:
        """Unloads the ML model from RAM (used for fallback or testing)."""
        self._model = None
        self._classes = []
        self._model_path = None
        self._is_loaded = False
        self._is_ubj = False
        self._model_name = None
        self._model_version = None
        self._feature_names = None
        self._attack_threshold = 0.5
        self._compiled_lut = None

    def predict(
        self,
        payload: str,
        feature_vector: list[float] | None = None,
    ) -> MLPredictionResult:
        """Performs real-time machine learning inference within a <15ms latency budget."""
        start_time = time.perf_counter()

        if not self._is_loaded or self._model is None:
            logger.error("ML model is unavailable or failed to load. Operating in Fail-Safe mode.")
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

        expected_dim = getattr(self, "_feature_dim", 26 if getattr(self, "_is_ubj", False) else 17)
        if feature_vector is not None:
            feat = feature_vector
            if expected_dim == 17 and len(feat) == 26:
                feat = feat[:17]
            elif expected_dim == 26 and len(feat) == 17:
                feat = self.extract_features_26(payload)
        else:
            if getattr(self, "_is_ubj", False) or expected_dim == 26:
                feat = self.extract_features_26(payload)
            else:
                feat = self.extract_features(payload)

        try:
            if getattr(self, "_is_ubj", False):
                lut = getattr(self, "_compiled_lut", None)
                if (
                    np is not None
                    and lut is not None
                    and lut.get("booster_id") == id(self._model)
                    and len(feat) > lut["max_feat_idx"]
                ):
                    tl = getattr(self, "_thread_local", None)
                    if tl is None:
                        tl = threading.local()
                        self._thread_local = tl
                    v1d = getattr(tl, "vec1d_buf", None)
                    if v1d is None or v1d.shape[0] != len(feat):
                        v1d = np.zeros(len(feat), dtype=np.float32)
                        tl.vec1d_buf = v1d
                    v1d[:] = feat
                    if not np.isnan(v1d).any():
                        idx = lut["root_slots"]
                        f_feat = lut["flat_feat"]
                        f_thresh = lut["flat_thresh"]
                        f_child = lut["flat_children"]
                        for _ in range(lut["max_depth"]):
                            idx = f_child[idx, (v1d[f_feat[idx]] >= f_thresh[idx]).view(np.uint8)]
                        logits = lut["base_logits"] + lut["flat_weights"][idx].reshape(-1, lut["num_class"]).sum(axis=0)
                        logits = logits - logits.max()
                        exp_l = np.exp(logits)
                        proba_array = exp_l / exp_l.sum()
                    else:
                        proba_array = self._model.inplace_predict(v1d.reshape(1, -1))[0]
                elif np is not None:
                    tl = getattr(self, "_thread_local", None)
                    if tl is None:
                        tl = threading.local()
                        self._thread_local = tl
                    buf = getattr(tl, "input_buf", None)
                    if buf is None or buf.shape[1] != len(feat):
                        buf = np.zeros((1, len(feat)), dtype=np.float32)
                        tl.input_buf = buf
                    buf[0, :] = feat
                    proba_array = self._model.inplace_predict(buf)[0]
                else:
                    inp = np.asarray([feat], dtype=np.float32)
                    proba_array = self._model.inplace_predict(inp)[0]
            else:
                if np is not None:
                    inp = np.asarray([feat], dtype=np.float32)
                else:
                    inp = [feat]
                proba_array = self._model.predict_proba(inp)[0]

            probabilities = {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self._classes, proba_array)
            }

            benign_idx = -1
            for i, c in enumerate(self._classes):
                if c.upper() == "BENIGN":
                    benign_idx = i
                    break

            benign_prob = float(proba_array[benign_idx]) if benign_idx >= 0 else 0.0
            attack_prob = 1.0 - benign_prob
            threshold = getattr(self, "_attack_threshold", 0.5)

            if attack_prob >= threshold:
                best_att_idx = None
                best_att_prob = -1.0
                for i, c in enumerate(self._classes):
                    if i != benign_idx and proba_array[i] > best_att_prob:
                        best_att_prob = float(proba_array[i])
                        best_att_idx = i
                if best_att_idx is not None:
                    dominant_class = self._classes[best_att_idx]
                    confidence = best_att_prob
                else:
                    top_index = int(proba_array.argmax())
                    dominant_class = self._classes[top_index]
                    confidence = float(proba_array[top_index])
                is_attack = True
                risk_score = round(max(50.0, attack_prob * 100.0), 2)
            else:
                dominant_class = "BENIGN"
                confidence = benign_prob
                is_attack = False
                risk_score = round(max(0.0, attack_prob * 30.0), 2)

            latency_ms = (time.perf_counter() - start_time) * 1000

            return MLPredictionResult(
                is_attack=is_attack,
                attack_type=dominant_class,
                confidence=round(confidence, 4),
                risk_score=risk_score,
                probabilities=probabilities,
                latency_ms=round(latency_ms, 3),
                model_loaded=True,
                feature_vector=feat if isinstance(feat, list) else feat.tolist(),
                feature_names=getattr(self, "_feature_names", FEATURE_NAMES[:self._feature_dim]),
                model_name=getattr(self, "_model_name", None),
                model_version=getattr(self, "_model_version", None),
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
                model_loaded=False,
            )

    def predict_http(
        self,
        path: str,
        query_params: str | None = None,
        body: str | None = None,
        feature_vector: list[float] | None = None,
    ) -> tuple[MLPredictionResult, list[float]]:
        """Normalizes HTTP request components and runs global + per-parameter max-pooling inference."""
        start_time = time.perf_counter()
        norm_path, norm_query, norm_body = normalize_http_for_ml(
            path=path,
            query_params=query_params,
            body=body,
        )
        global_vec = (
            list(feature_vector)
            if feature_vector is not None
            else extract_26_from_http(
                path=norm_path,
                query_params=norm_query,
                body=norm_body,
            ).tolist()
        )
        payload_text = " ".join(p for p in (norm_path, norm_query, norm_body) if p).strip()
        global_res = self.predict(payload_text, feature_vector=global_vec)

        if not global_res.model_loaded or global_res.risk_score is None:
            global_res.latency_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return global_res, global_vec

        params = _extract_http_params(norm_query, norm_body, raw_body=body)
        context_len = (len(norm_query) if norm_query else 0) + (len(norm_body) if norm_body else 0)

        best_res = global_res
        if len(params) >= 2 or context_len > 40:
            scored_candidates: list[tuple[int, float, str, str]] = []
            for k, v in params:
                if not v or _BENIGN_PARAM_VALUE_RE.match(v):
                    continue
                matches = _SUSPICIOUS_SYNTAX_RE.findall(v)
                if matches:
                    count = len(matches)
                    density = count / max(1, len(v))
                    scored_candidates.append((count, density, k, v))

            if scored_candidates:
                scored_candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
                for _cnt, _dens, k, v in scored_candidates[:2]:
                    param_query = f"{k}={v}" if k else v
                    param_vec = extract_26_from_http(
                        path=norm_path,
                        query_params=param_query,
                        body=None,
                    ).tolist()
                    param_res = self.predict(param_query, feature_vector=param_vec)
                    if (
                        param_res.model_loaded
                        and param_res.risk_score is not None
                        and param_res.risk_score > (best_res.risk_score or 0.0)
                    ):
                        best_res = param_res

        total_latency_ms = round((time.perf_counter() - start_time) * 1000, 3)
        if best_res is global_res:
            global_res.latency_ms = total_latency_ms
            return global_res, global_vec

        combined = MLPredictionResult(
            is_attack=bool(global_res.is_attack or best_res.is_attack),
            attack_type=best_res.attack_type if best_res.is_attack else global_res.attack_type,
            confidence=best_res.confidence,
            risk_score=max(global_res.risk_score, best_res.risk_score or 0.0),
            probabilities=best_res.probabilities,
            latency_ms=total_latency_ms,
            model_loaded=best_res.model_loaded,
            feature_vector=global_vec,
            feature_names=best_res.feature_names,
            model_name=best_res.model_name,
            model_version=best_res.model_version,
        )
        return combined, global_vec
