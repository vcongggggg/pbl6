"""Unit tests for Task 3.3: HTTP Context & Protocol Metadata Feature Extractor.

Verifies method one-hot encoding, path/query topology, content-type categorization,
header anomalies, scanner user-agent detection, and batch processing performance.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure ml-engine is on sys.path
TEST_DIR = Path(__file__).resolve().parent
ML_ENGINE_DIR = TEST_DIR.parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.http_context import (  # noqa: E402
    HTTP_CONTEXT_FEATURE_NAMES,
    HTTPContextFeatures,
    extract_http_context_features,
    extract_http_context_features_batch,
    extract_http_context_from_dict,
)


class TestHTTPMethodEncoding:
    """Tests for HTTP method one-hot categorization."""

    def test_get_method(self) -> None:
        feat = extract_http_context_features(method="GET")
        assert feat.method_is_get == 1.0
        assert feat.method_is_post == 0.0
        assert feat.method_is_other == 0.0

    def test_post_method(self) -> None:
        feat = extract_http_context_features(method="POST")
        assert feat.method_is_get == 0.0
        assert feat.method_is_post == 1.0
        assert feat.method_is_other == 0.0

    def test_put_delete_patch_methods(self) -> None:
        feat_put = extract_http_context_features(method="put")
        assert feat_put.method_is_put == 1.0

        feat_del = extract_http_context_features(method="DELETE")
        assert feat_del.method_is_delete == 1.0

        feat_patch = extract_http_context_features(method="PATCH")
        assert feat_patch.method_is_patch == 1.0

    def test_other_and_fallback_methods(self) -> None:
        feat_options = extract_http_context_features(method="OPTIONS")
        assert feat_options.method_is_other == 1.0
        assert feat_options.method_is_get == 0.0

        # None or empty fallback to GET
        feat_none = extract_http_context_features(method=None)
        assert feat_none.method_is_get == 1.0


class TestURITopology:
    """Tests for URI path length, depth, and query ratios."""

    def test_root_path(self) -> None:
        feat = extract_http_context_features(path="/")
        assert feat.path_length == 1.0
        assert feat.path_depth == 0.0

    def test_nested_path_depth(self) -> None:
        feat = extract_http_context_features(path="/api/v1/vulnerable/books/search/")
        # Segments: 'api', 'v1', 'vulnerable', 'books', 'search'
        assert feat.path_depth == 5.0
        assert feat.path_length == len("/api/v1/vulnerable/books/search/")

    def test_inline_query_separation(self) -> None:
        feat = extract_http_context_features(path="/api/search?q=test&page=2")
        assert feat.path_length == len("/api/search")
        assert feat.query_length == len("q=test&page=2")
        assert feat.query_param_count == 2.0
        assert feat.query_to_path_ratio > 0.0


class TestQueryParameterBehavior:
    """Tests for query parameter parsing and ratios."""

    def test_empty_query(self) -> None:
        feat = extract_http_context_features(path="/api/books", query_params=None)
        assert feat.query_length == 0.0
        assert feat.query_param_count == 0.0
        assert feat.query_to_path_ratio == 0.0

    def test_urlencoded_query_string(self) -> None:
        q = "author=Jane+Austen&genre=classic&limit=10"
        feat = extract_http_context_features(path="/api/books", query_params=q)
        assert feat.query_length == float(len(q))
        assert feat.query_param_count == 3.0
        assert feat.query_to_path_ratio == float(len(q) / (len("/api/books") + 1.0))

    def test_dict_query_params(self) -> None:
        params = {"q": "python", "page": "1"}
        feat = extract_http_context_features(path="/search", query_params=params)
        assert feat.query_param_count == 2.0
        assert feat.query_length > 0.0


class TestContentTypeCategorization:
    """Tests for Content-Type header analysis."""

    def test_json_content_type(self) -> None:
        headers = {"Content-Type": "application/json; charset=utf-8"}
        feat = extract_http_context_features(headers=headers)
        assert feat.content_type_is_json == 1.0
        assert feat.content_type_is_form == 0.0
        assert feat.content_type_is_missing == 0.0

    def test_form_urlencoded_content_type(self) -> None:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        feat = extract_http_context_features(headers=headers)
        assert feat.content_type_is_form == 1.0
        assert feat.content_type_is_json == 0.0
        assert feat.content_type_is_missing == 0.0

    def test_multipart_and_xml(self) -> None:
        feat_multi = extract_http_context_features(headers={"content-type": "multipart/form-data; boundary=xyz"})
        assert feat_multi.content_type_is_multipart == 1.0

        feat_xml = extract_http_context_features(headers={"content-type": "application/xml"})
        assert feat_xml.content_type_is_xml == 1.0

    def test_missing_content_type(self) -> None:
        feat = extract_http_context_features(headers={})
        assert feat.content_type_is_missing == 1.0
        assert feat.content_type_is_json == 0.0


class TestHeadersAndClientTelemetry:
    """Tests for header count, auth/cookie presence, and suspicious scanner UAs."""

    def test_header_count_and_json_headers(self) -> None:
        json_headers = '{"Host": "localhost", "Authorization": "Bearer token123", "Cookie": "session=abc"}'
        feat = extract_http_context_features(headers=json_headers)
        assert feat.header_count == 3.0
        assert feat.has_authorization == 1.0
        assert feat.has_cookie == 1.0

    def test_suspicious_scanner_user_agents(self) -> None:
        scanners = [
            "Nikto/2.1.6",
            "sqlmap/1.7#stable (https://sqlmap.org)",
            "python-requests/2.31.0",
            "curl/7.88.1",
            "Go-http-client/1.1",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            "PostmanRuntime/7.32.3",
        ]
        for ua in scanners:
            feat = extract_http_context_features(user_agent=ua)
            assert feat.is_suspicious_user_agent == 1.0, f"Expected {ua} to be flagged as suspicious"
            assert feat.user_agent_length == float(len(ua))

    def test_benign_browser_user_agent(self) -> None:
        benign_ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        feat = extract_http_context_features(user_agent=benign_ua)
        assert feat.is_suspicious_user_agent == 0.0
        assert feat.user_agent_length == float(len(benign_ua))


class TestContentLengthMismatch:
    """Tests for HTTP Request Smuggling / Desync discrepancy detection."""

    def test_matching_content_length(self) -> None:
        body = '{"username": "admin"}'
        headers = {"Content-Length": str(len(body))}
        feat = extract_http_context_features(headers=headers, body=body)
        assert feat.content_length_mismatch == 0.0
        assert feat.body_length == float(len(body))

    def test_mismatched_content_length(self) -> None:
        body = '{"username": "admin"}'
        # Declared length is 200, actual is ~21 -> mismatch flagged
        headers = {"Content-Length": "200"}
        feat = extract_http_context_features(headers=headers, body=body)
        assert feat.content_length_mismatch == 1.0


class TestHTTPContextContainerAndBatch:
    """Tests for container serialization and batch processing speed."""

    def test_feature_names_and_vector_length(self) -> None:
        feat = extract_http_context_features()
        assert isinstance(feat, HTTPContextFeatures)
        vector = feat.to_list()
        feat_dict = feat.to_dict()

        assert len(vector) == len(HTTP_CONTEXT_FEATURE_NAMES)
        assert len(feat_dict) == len(HTTP_CONTEXT_FEATURE_NAMES)
        assert all(isinstance(v, float) for v in vector)

    def test_extract_from_dict(self) -> None:
        sample = {
            "method": "POST",
            "path": "/api/v1/vulnerable/auth/login",
            "query_params": "",
            "headers": '{"Host": "localhost", "Content-Type": "application/json"}',
            "body": '{"username": "admin", "password": "password123"}',
            "user_agent": "Mozilla/5.0",
        }
        feat = extract_http_context_from_dict(sample)
        assert feat.method_is_post == 1.0
        assert feat.content_type_is_json == 1.0
        assert feat.path_depth == 5.0
        assert feat.body_length > 0.0

    def test_batch_extraction_and_speed(self) -> None:
        sample = {
            "method": "GET",
            "path": "/api/v1/vulnerable/books/search",
            "query_params": "q=union+select",
            "headers": '{"Host": "localhost", "User-Agent": "curl/7.88"}',
            "body": "",
            "user_agent": "curl/7.88",
        }
        samples = [sample] * 1000

        t0 = time.perf_counter()
        batch_results = extract_http_context_features_batch(samples)
        elapsed = time.perf_counter() - t0

        assert len(batch_results) == 1000
        # 1000 samples should complete in well under 100ms (<0.1ms per sample)
        assert elapsed < 0.10, f"Batch processing too slow: {elapsed:.4f}s for 1000 items"
