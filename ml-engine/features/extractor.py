"""Unified 17-Dimensional Feature Vector Pipeline & Normalizer.

This module implements Task 3.4 (Issue #17) for the WAF ML Defense Engine.
It unifies:
- Task 3.1: Morphological and statistical payload features (12 features)
- Task 3.2: Attack keyword frequencies and regex pattern matches (5 canonical features)
into an exact 17-dimensional feature vector (numpy.ndarray) compatible with
Random Forest and Isolation Forest classifiers.

Optionally, it integrates Task 3.3 (23 HTTP context features) for extended
multimodal requests (40 dimensions total).

It also provides:
- FeatureNormalizer (empirical default bounds or trainable Min-Max scaling)
- High-throughput batch feature extraction (< 0.05ms/sample)
- Composite payload aggregation from HTTP request components (path, query, body)

Academic & Industry Foundation:
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): 17-dimensional unified vector model.
- [Ref 10] M. Hasan et al. (IEEE Access 2023): Systematic feature tokenization for SQLi.
- [Ref 09] MDPI Electronics 2025: Lightweight feature extraction for real-time inline WAF.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping

import numpy as np

from .http_context import (
    HTTP_CONTEXT_FEATURE_NAMES,
    extract_http_context_features,
)
from .keywords import (
    extract_keyword_features,
)
from .payload import (
    extract_payload_features,
)

CANONICAL_FEATURE_NAMES: list[str] = [
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

EXTENDED_FEATURE_NAMES: list[str] = CANONICAL_FEATURE_NAMES + HTTP_CONTEXT_FEATURE_NAMES


# -----------------------------------------------------------------------------
# COMPOSITE PAYLOAD RESOLVER
# -----------------------------------------------------------------------------

def resolve_payload_text(
    payload_or_request: Any = None,
    path: str | None = None,
    query_params: Any = None,
    body: Any = None,
) -> str:
    """Extracts or resolves a unified string payload from diverse request representations.

    Supports:
    - Raw string / bytes payload directly
    - Dictionary or mapping representing an HTTP request (keys: 'path', 'query_params', 'body')
    - Explicit component kwargs
    """
    if payload_or_request is None:
        parts: list[str] = []
        if path:
            parts.append(str(path))
        if query_params:
            if isinstance(query_params, str):
                parts.append(query_params)
            elif isinstance(query_params, Mapping):
                parts.append("&".join(f"{k}={v}" for k, v in query_params.items()))
        if body:
            if isinstance(body, (str, bytes)):
                parts.append(str(body))
            elif isinstance(body, Mapping):
                try:
                    parts.append(json.dumps(body))
                except Exception:
                    parts.append(str(body))
        return " ".join(parts).strip()

    if isinstance(payload_or_request, str):
        return payload_or_request
    if isinstance(payload_or_request, bytes):
        try:
            return payload_or_request.decode("utf-8", errors="replace")
        except Exception:
            return str(payload_or_request)

    if isinstance(payload_or_request, Mapping):
        # Extract components from dict
        req_path = str(payload_or_request.get("path", "") or path or "")
        req_q = payload_or_request.get("query_params") or query_params or ""
        req_b = payload_or_request.get("body") or body or ""

        q_str = ""
        if isinstance(req_q, str):
            q_str = req_q
        elif isinstance(req_q, Mapping):
            q_str = "&".join(f"{k}={v}" for k, v in req_q.items())

        b_str = ""
        if isinstance(req_b, str):
            b_str = req_b
        elif isinstance(req_b, bytes):
            b_str = req_b.decode("utf-8", errors="replace")
        elif isinstance(req_b, Mapping):
            try:
                b_str = json.dumps(req_b)
            except Exception:
                b_str = str(req_b)

        parts = [p for p in [req_path, q_str, b_str] if p]
        return " ".join(parts).strip()

    return str(payload_or_request)


# -----------------------------------------------------------------------------
# FEATURE CONTAINER
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class CanonicalFeatureVector:
    """Immutable container holding the canonical 17-dimensional feature vector."""

    length: float
    entropy: float
    count_single_quote: float
    count_double_quote: float
    count_less_than: float
    count_greater_than: float
    count_semicolon: float
    count_hyphen: float
    count_slash: float
    count_backslash: float
    count_parenthesis: float
    special_char_ratio: float
    sql_keyword_count: float
    xss_keyword_count: float
    sqli_regex_matches: float
    xss_regex_matches: float
    path_traversal_matches: float

    def to_dict(self) -> dict[str, float]:
        """Serializes features into a dictionary keyed by CANONICAL_FEATURE_NAMES."""
        return asdict(self)

    def to_list(self) -> list[float]:
        """Returns the 17 features as an ordered Python float list."""
        return [getattr(self, name) for name in CANONICAL_FEATURE_NAMES]

    def to_numpy(self, dtype: np.dtype = np.float32) -> np.ndarray:
        """Converts features to a 1D NumPy array of shape (17,)."""
        return np.array(self.to_list(), dtype=dtype)


# -----------------------------------------------------------------------------
# MIN-MAX FEATURE NORMALIZER
# -----------------------------------------------------------------------------

# Empirical maximum upper bounds for the 17 canonical features (derived from Web security baselines)
EMPIRICAL_MAX_BOUNDS: np.ndarray = np.array(
    [
        2048.0,  # length
        8.0,     # entropy (Shannon entropy max for 256 byte distribution is 8.0)
        50.0,    # count_single_quote
        50.0,    # count_double_quote
        50.0,    # count_less_than
        50.0,    # count_greater_than
        50.0,    # count_semicolon
        50.0,    # count_hyphen
        50.0,    # count_slash
        50.0,    # count_backslash
        50.0,    # count_parenthesis
        1.0,     # special_char_ratio (already bounded in [0, 1])
        20.0,    # sql_keyword_count
        20.0,    # xss_keyword_count
        10.0,    # sqli_regex_matches
        10.0,    # xss_regex_matches
        10.0,    # path_traversal_matches
    ],
    dtype=np.float32,
)

EMPIRICAL_MIN_BOUNDS: np.ndarray = np.zeros(17, dtype=np.float32)


class FeatureNormalizer:
    """Min-Max normalizer for 17-dimensional feature vectors.

    Can operate in:
    1. Default empirical mode: Uses standardized domain upper bounds.
    2. Fitted mode: Learns min and max vectors from training data matrix X.
    """

    def __init__(
        self,
        min_bounds: np.ndarray | None = None,
        max_bounds: np.ndarray | None = None,
        clip: bool = True,
    ) -> None:
        self.clip = clip
        self.min_bounds = (
            min_bounds.copy().astype(np.float32)
            if min_bounds is not None
            else EMPIRICAL_MIN_BOUNDS.copy()
        )
        self.max_bounds = (
            max_bounds.copy().astype(np.float32)
            if max_bounds is not None
            else EMPIRICAL_MAX_BOUNDS.copy()
        )
        # Prevent division by zero
        diff = self.max_bounds - self.min_bounds
        diff[diff == 0.0] = 1.0
        self.scale_range = diff

    def fit(self, X: np.ndarray) -> FeatureNormalizer:
        """Fits normalizer bounds from data matrix X (shape: [N, 17])."""
        arr = np.asarray(X, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        self.min_bounds = np.min(arr, axis=0)
        self.max_bounds = np.max(arr, axis=0)
        diff = self.max_bounds - self.min_bounds
        diff[diff == 0.0] = 1.0
        self.scale_range = diff
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Applies Min-Max scaling to input array X."""
        arr = np.asarray(X, dtype=np.float32)
        scaled = (arr - self.min_bounds) / self.scale_range
        if self.clip:
            scaled = np.clip(scaled, 0.0, 1.0)
        return scaled

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fits on X and returns transformed X."""
        return self.fit(X).transform(X)


# -----------------------------------------------------------------------------
# MAIN PIPELINE EXTRACTOR
# -----------------------------------------------------------------------------

class FeatureExtractorPipeline:
    """Production unified feature vector pipeline for WAF Machine Learning."""

    def __init__(
        self,
        normalizer: FeatureNormalizer | None = None,
        normalize_by_default: bool = False,
    ) -> None:
        self.normalizer = normalizer or FeatureNormalizer()
        self.normalize_by_default = normalize_by_default

    def extract_canonical_features(
        self,
        sample: Any = None,
        path: str | None = None,
        query_params: Any = None,
        body: Any = None,
    ) -> CanonicalFeatureVector:
        """Extracts the exact 17 canonical features as a CanonicalFeatureVector."""
        text = resolve_payload_text(sample, path=path, query_params=query_params, body=body)

        morph = extract_payload_features(text)
        kw = extract_keyword_features(text)

        return CanonicalFeatureVector(
            length=morph.length,
            entropy=morph.entropy,
            count_single_quote=morph.count_single_quote,
            count_double_quote=morph.count_double_quote,
            count_less_than=morph.count_less_than,
            count_greater_than=morph.count_greater_than,
            count_semicolon=morph.count_semicolon,
            count_hyphen=morph.count_hyphen,
            count_slash=morph.count_slash,
            count_backslash=morph.count_backslash,
            count_parenthesis=morph.count_parenthesis,
            special_char_ratio=morph.special_char_ratio,
            sql_keyword_count=kw.sql_keyword_count,
            xss_keyword_count=kw.xss_keyword_count,
            sqli_regex_matches=kw.sqli_regex_matches,
            xss_regex_matches=kw.xss_regex_matches,
            path_traversal_matches=kw.path_traversal_matches,
        )

    def extract_vector(
        self,
        sample: Any = None,
        normalize: bool | None = None,
        include_http_context: bool = False,
        path: str | None = None,
        query_params: Any = None,
        body: Any = None,
        method: str = "GET",
        headers: Any = None,
        user_agent: str | None = None,
    ) -> np.ndarray:
        """Extracts a 1D NumPy array feature vector.

        Args:
            sample: Raw payload string or request mapping.
            normalize: If True, applies Min-Max scaling to canonical features.
            include_http_context: If True, appends 23 HTTP context features (40-dim).

        Returns:
            np.ndarray of shape (17,) or (40,).
        """
        canonical = self.extract_canonical_features(
            sample, path=path, query_params=query_params, body=body
        )
        vec = canonical.to_numpy(dtype=np.float32)

        should_normalize = (
            normalize if normalize is not None else self.normalize_by_default
        )
        if should_normalize:
            vec = self.normalizer.transform(vec)

        if not include_http_context:
            return vec

        # Extract HTTP context features
        if isinstance(sample, Mapping):
            http_feat = extract_http_context_features(
                method=sample.get("method", method),
                path=sample.get("path", path or "/"),
                query_params=sample.get("query_params", query_params),
                headers=sample.get("headers", headers),
                body=sample.get("body", body),
                user_agent=sample.get("user_agent", user_agent),
            )
        else:
            http_feat = extract_http_context_features(
                method=method,
                path=path or "/",
                query_params=query_params,
                headers=headers,
                body=body,
                user_agent=user_agent,
            )

        http_vec = np.array(http_feat.to_list(), dtype=np.float32)
        return np.concatenate([vec, http_vec])

    def extract_batch(
        self,
        samples: list[Any],
        normalize: bool | None = None,
        include_http_context: bool = False,
    ) -> np.ndarray:
        """Batch-extracts feature matrix for a list of samples.

        Returns:
            np.ndarray of shape (N, 17) or (N, 40).
        """
        vectors = [
            self.extract_vector(
                sample,
                normalize=normalize,
                include_http_context=include_http_context,
            )
            for sample in samples
        ]
        if not vectors:
            dim = 40 if include_http_context else 17
            return np.empty((0, dim), dtype=np.float32)
        return np.vstack(vectors)


# Global default instance for direct top-level access
_DEFAULT_PIPELINE = FeatureExtractorPipeline()


def extract_17_features(sample: Any = None, **kwargs: Any) -> CanonicalFeatureVector:
    """Convenience function returning the canonical 17-dimensional dataclass."""
    return _DEFAULT_PIPELINE.extract_canonical_features(sample, **kwargs)


def extract_17_vector(sample: Any = None, normalize: bool = False, **kwargs: Any) -> np.ndarray:
    """Convenience function returning a 1D NumPy array of 17 features."""
    return _DEFAULT_PIPELINE.extract_vector(sample, normalize=normalize, **kwargs)


def extract_batch_vectors(
    samples: list[Any],
    normalize: bool = False,
    include_http_context: bool = False,
) -> np.ndarray:
    """Convenience function for high-throughput batch extraction."""
    return _DEFAULT_PIPELINE.extract_batch(
        samples, normalize=normalize, include_http_context=include_http_context
    )
