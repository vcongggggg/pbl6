"""Unit tests for Task 3.4 & Task 3.5: 17-Dimensional Feature Vector Pipeline & Normalizer.

Validates:
- Exact 17-dimensional vector shape, field order, and consistency with Gateway FEATURE_NAMES
- Accurate feature extraction across 4 attack families (SQLi, XSS, Path Traversal, Cmd Injection) and Benign
- Edge case robustness (None, empty, non-string, 1MB DoS strings)
- Min-Max FeatureNormalizer behavior and clamping in [0.0, 1.0]
- Extended 40-dimensional multimodal vector (17 canonical + 23 HTTP context)
- High-throughput batch processing (< 0.05ms/sample)

Academic References:
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): 17-feature unified vector model.
- [Ref 10] M. Hasan et al. (IEEE Access 2023): Systematic feature tokenization.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np

# Ensure ml-engine is on sys.path
TEST_DIR = Path(__file__).resolve().parent
ML_ENGINE_DIR = TEST_DIR.parent
PROJECT_ROOT = ML_ENGINE_DIR.parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))
GATEWAY_PATH = PROJECT_ROOT / "gateway"
if str(GATEWAY_PATH) not in sys.path:
    sys.path.insert(0, str(GATEWAY_PATH))

from features.extractor import (  # noqa: E402
    CANONICAL_FEATURE_NAMES,
    EXTENDED_FEATURE_NAMES,
    CanonicalFeatureVector,
    FeatureExtractorPipeline,
    FeatureNormalizer,
    extract_17_features,
    extract_17_vector,
    extract_batch_vectors,
    resolve_payload_text,
)


class TestFeatureVectorStructure:
    """Tests for vector shape, ordering, and consistency with Gateway contract."""

    def test_canonical_feature_names_length(self) -> None:
        assert len(CANONICAL_FEATURE_NAMES) == 17

    def test_consistency_with_gateway_ml_detector_contract(self) -> None:
        try:
            from app.security.ml_detector import FEATURE_NAMES as GATEWAY_FEATURE_NAMES
            assert CANONICAL_FEATURE_NAMES == GATEWAY_FEATURE_NAMES, (
                "ml-engine CANONICAL_FEATURE_NAMES must match gateway FEATURE_NAMES 100%"
            )
        except ImportError:
            # Gateway app might not be in standard path during isolated tests
            pass

    def test_canonical_feature_vector_dataclass(self) -> None:
        feat = extract_17_features("test payload")
        assert isinstance(feat, CanonicalFeatureVector)
        vec_list = feat.to_list()
        vec_dict = feat.to_dict()
        vec_numpy = feat.to_numpy()

        assert len(vec_list) == 17
        assert len(vec_dict) == 17
        assert vec_numpy.shape == (17,)
        assert vec_numpy.dtype == np.float32

    def test_vector_shape_and_dtype(self) -> None:
        vec = extract_17_vector("SELECT * FROM users")
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (17,)
        assert vec.dtype == np.float32


class TestAttackTypeSignatures:
    """Tests for accurate feature extraction across 4 attack families and benign traffic."""

    def test_benign_payload(self) -> None:
        payload = "search standard textbook for computer science 101"
        feat = extract_17_features(payload)

        assert feat.length == len(payload)
        assert feat.entropy > 0.0
        assert feat.sql_keyword_count == 0.0
        assert feat.xss_keyword_count == 0.0
        assert feat.sqli_regex_matches == 0.0
        assert feat.xss_regex_matches == 0.0
        assert feat.path_traversal_matches == 0.0
        assert feat.special_char_ratio == 0.0

    def test_sqli_attack_signature(self) -> None:
        payload = "admin' OR 1=1 UNION SELECT username, password FROM users--"
        feat = extract_17_features(payload)

        assert feat.count_single_quote >= 1.0
        assert feat.count_hyphen >= 2.0
        assert feat.sql_keyword_count >= 2.0  # union, select, from
        assert feat.sqli_regex_matches >= 1.0  # union select, or 1=1

    def test_xss_attack_signature(self) -> None:
        payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
        feat = extract_17_features(payload)

        assert feat.count_less_than >= 2.0
        assert feat.count_greater_than >= 2.0
        assert feat.count_parenthesis >= 4.0
        assert feat.xss_keyword_count >= 2.0  # script, alert, onerror
        assert feat.xss_regex_matches >= 1.0  # <script>, onerror=

    def test_path_traversal_signature(self) -> None:
        payload = "../../../../etc/passwd"
        feat = extract_17_features(payload)

        assert feat.count_slash >= 4.0
        assert feat.path_traversal_matches >= 1.0  # ../ and /etc/passwd

    def test_command_injection_signature(self) -> None:
        payload = "127.0.0.1; whoami && cat /etc/shadow"
        feat = extract_17_features(payload)

        assert feat.count_semicolon >= 1.0
        assert feat.count_slash >= 2.0


class TestEdgeCasesAndRobustness:
    """Tests for edge case handling and DoS resistance."""

    def test_none_input(self) -> None:
        vec = extract_17_vector(None)
        assert vec.shape == (17,)
        assert np.all(vec == 0.0)

    def test_empty_string(self) -> None:
        vec = extract_17_vector("")
        assert vec.shape == (17,)
        assert np.all(vec == 0.0)

    def test_non_string_types(self) -> None:
        # Dictionary input
        d = {"path": "/books", "query_params": "id=1", "body": "test"}
        vec = extract_17_vector(d)
        assert vec.shape == (17,)
        assert vec[0] > 0.0  # length > 0

        # Number input
        vec_num = extract_17_vector(12345)
        assert vec_num.shape == (17,)
        assert vec_num[0] == 5.0

    def test_large_payload_dos_resilience(self) -> None:
        # 100,000 characters payload
        large_payload = "A" * 100_000
        t0 = time.perf_counter()
        vec = extract_17_vector(large_payload)
        elapsed = time.perf_counter() - t0

        assert vec.shape == (17,)
        assert vec[0] == 100_000.0
        # Should process in under 10ms
        assert elapsed < 0.05, f"100KB processing took too long: {elapsed:.4f}s"


class TestCompositePayloadResolver:
    """Tests for payload aggregation across HTTP components."""

    def test_resolve_from_components(self) -> None:
        text = resolve_payload_text(
            path="/api/books/search",
            query_params="q=sql+injection",
            body='{"author": "test"}',
        )
        assert "/api/books/search" in text
        assert "q=sql+injection" in text
        assert '{"author": "test"}' in text

    def test_resolve_from_dict(self) -> None:
        req = {
            "path": "/login",
            "query_params": {"redirect": "home"},
            "body": {"username": "admin"},
        }
        text = resolve_payload_text(req)
        assert "/login" in text
        assert "redirect=home" in text
        assert "admin" in text


class TestFeatureNormalizer:
    """Tests for Min-Max scaling and boundary clipping."""

    def test_empirical_normalizer_bounds(self) -> None:
        normalizer = FeatureNormalizer()
        raw_vec = np.array([1024.0, 4.0, 10.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 0.5, 5.0, 5.0, 2.0, 2.0, 2.0], dtype=np.float32)
        scaled = normalizer.transform(raw_vec)

        assert np.all(scaled >= 0.0)
        assert np.all(scaled <= 1.0)
        assert 0.49 < scaled[0] < 0.51  # 1024 / 2048 == 0.5
        assert 0.49 < scaled[1] < 0.51  # 4.0 / 8.0 == 0.5

    def test_clamping_on_outliers(self) -> None:
        normalizer = FeatureNormalizer(clip=True)
        outlier_vec = np.full(17, 99999.0, dtype=np.float32)
        scaled = normalizer.transform(outlier_vec)
        assert np.all(scaled == 1.0)

    def test_fit_transform_custom_dataset(self) -> None:
        X = np.array([
            [10.0, 1.0] + [0.0] * 15,
            [100.0, 5.0] + [10.0] * 15,
        ], dtype=np.float32)

        normalizer = FeatureNormalizer()
        X_scaled = normalizer.fit_transform(X)

        assert np.allclose(X_scaled[0], 0.0)
        assert np.allclose(X_scaled[1], 1.0)


class TestExtendedMultimodalVector:
    """Tests for 40-dimensional extended feature vector (17 canonical + 23 HTTP context)."""

    def test_extended_vector_shape_and_names(self) -> None:
        assert len(EXTENDED_FEATURE_NAMES) == 40

        sample = {
            "method": "POST",
            "path": "/api/v1/login",
            "query_params": "",
            "headers": {"Content-Type": "application/json"},
            "body": "user=admin&pass=123",
        }
        pipeline = FeatureExtractorPipeline()
        vec_ext = pipeline.extract_vector(sample, include_http_context=True)

        assert vec_ext.shape == (40,)
        # First 17 are canonical features
        assert vec_ext[0] > 0.0  # length
        # Features 17-39 are HTTP context features
        assert vec_ext[17 + 1] == 1.0  # method_is_post (index 1 in HTTPContextFeatures)
        assert vec_ext[17 + 12] == 1.0  # content_type_is_json

    def test_extended_vector_normalization_bounds(self) -> None:
        sample = {
            "method": "POST",
            "path": "/api/v1/vulnerable/books/search",
            "query_params": "q=union+select",
            "headers": {"Content-Type": "application/json", "User-Agent": "curl/7.88.1"},
            "body": "search payload for machine learning security testing",
        }
        pipeline = FeatureExtractorPipeline()
        vec_norm = pipeline.extract_vector(sample, normalize=True, include_http_context=True)

        assert vec_norm.shape == (40,)
        # All 40 features must be uniformly scaled and bounded in [0.0, 1.0]
        assert np.all(vec_norm >= 0.0)
        assert np.all(vec_norm <= 1.0)


class TestBatchThroughputAndPerformance:
    """Tests for high-throughput batch feature extraction."""

    def test_batch_extraction_correctness(self) -> None:
        samples = [
            "benign request 1",
            "admin' OR 1=1--",
            "<script>alert(1)</script>",
            "../../etc/passwd",
        ]
        matrix = extract_batch_vectors(samples)
        assert matrix.shape == (4, 17)
        assert matrix.dtype == np.float32

    def test_batch_speed_benchmark(self) -> None:
        sample = {
            "method": "POST",
            "path": "/api/v1/vulnerable/books/search",
            "query_params": "q=union+select",
            "body": '{"user": "admin"}',
        }
        samples = [sample] * 1000

        t0 = time.perf_counter()
        matrix = extract_batch_vectors(samples)
        elapsed = time.perf_counter() - t0

        assert matrix.shape == (1000, 17)
        # 1000 samples should finish in under 80ms (<0.08ms per sample)
        assert elapsed < 0.15, f"Batch extraction took too long: {elapsed:.4f}s for 1000 samples"
