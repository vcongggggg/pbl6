"""HTTP Context and Protocol Metadata Feature Extractor.

This module implements Task 3.3 (Issue #16) for the WAF ML Defense Engine.
It extracts HTTP request protocol, metadata, and behavioral context features:
1. HTTP Method One-Hot Encoding (GET, POST, PUT, DELETE, PATCH, OTHER)
2. URI & Query Parameter Behavior (path length, path depth, query length, param count, query/path ratio)
3. Content-Type Category Flags (JSON, Form-urlencoded, Multipart, XML, Missing)
4. Header Anomalies & Telemetry (header count, auth/cookie presence, user-agent length, suspicious scanner UA)
5. Request Body & Content-Length Discrepancy (body length, content-length mismatch)

Academic & Industry Foundation:
- [Ref 07] CSIC 2010 HTTP Dataset: Request behavior, protocol metadata, and parameter structure.
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): Request protocol behavior and structural analysis.
- [Ref 09] MDPI Electronics 2025: Lightweight feature extraction for real-time inline WAF.
- [Ref 12] OWASP ModSecurity Core Rule Set (CRS v4.0): Scanner detection & Protocol enforcement.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping
from urllib.parse import parse_qsl

# -----------------------------------------------------------------------------
# PRE-COMPILED REGEX PATTERNS (Case-Insensitive)
# -----------------------------------------------------------------------------

# Automated scanners, security testing tools, and generic scripting HTTP clients
_SUSPICIOUS_UA_REGEX = re.compile(
    r"\b("
    r"sqlmap|nikto|nmap|masscan|w3af|acunetix|nessus|openvas|arachni|"
    r"qualys|metasploit|burpcollaborator|burp\s*suite|hydra|dirbuster|gobuster|"
    r"ffuf|wfuzz|havij|zap|zaproxy|commix|pangolin|python-requests|"
    r"python-urllib|go-http-client|curl|wget|postmanruntime|postman|"
    r"libwww-perl|lwp-trivial|httplib|scrapy|phantomjs|headless"
    r")\b",
    re.IGNORECASE,
)

HTTP_CONTEXT_FEATURE_NAMES: list[str] = [
    "method_is_get",
    "method_is_post",
    "method_is_put",
    "method_is_delete",
    "method_is_patch",
    "method_is_other",
    "path_length",
    "path_depth",
    "query_length",
    "query_param_count",
    "query_to_path_ratio",
    "body_length",
    "content_type_is_json",
    "content_type_is_form",
    "content_type_is_multipart",
    "content_type_is_xml",
    "content_type_is_missing",
    "header_count",
    "has_authorization",
    "has_cookie",
    "user_agent_length",
    "is_suspicious_user_agent",
    "content_length_mismatch",
]


# -----------------------------------------------------------------------------
# FEATURE CONTAINER
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class HTTPContextFeatures:
    """Container holding HTTP protocol, context, and metadata features."""

    # Method One-Hot Encoding
    method_is_get: float
    method_is_post: float
    method_is_put: float
    method_is_delete: float
    method_is_patch: float
    method_is_other: float

    # URI & Query Topology
    path_length: float
    path_depth: float
    query_length: float
    query_param_count: float
    query_to_path_ratio: float

    # Body Metrics
    body_length: float

    # Content-Type Categories
    content_type_is_json: float
    content_type_is_form: float
    content_type_is_multipart: float
    content_type_is_xml: float
    content_type_is_missing: float

    # Headers & Client Telemetry
    header_count: float
    has_authorization: float
    has_cookie: float
    user_agent_length: float
    is_suspicious_user_agent: float
    content_length_mismatch: float

    def to_dict(self) -> dict[str, float]:
        """Serializes features into a dictionary."""
        return asdict(self)

    def to_list(self) -> list[float]:
        """Returns all 23 HTTP context features as an ordered float list."""
        return [getattr(self, name) for name in HTTP_CONTEXT_FEATURE_NAMES]


# -----------------------------------------------------------------------------
# HELPER PARSERS
# -----------------------------------------------------------------------------

def _parse_headers(raw_headers: Any) -> dict[str, str]:
    """Safely normalizes headers into a lowercase-keyed dictionary."""
    if not raw_headers:
        return {}
    if isinstance(raw_headers, str):
        raw_headers = raw_headers.strip()
        if not raw_headers:
            return {}
        try:
            parsed = json.loads(raw_headers)
            if isinstance(parsed, dict):
                return {str(k).lower(): str(v) for k, v in parsed.items()}
        except Exception:
            return {}
    elif isinstance(raw_headers, Mapping):
        return {str(k).lower(): str(v) for k, v in raw_headers.items()}
    elif isinstance(raw_headers, list):
        out: dict[str, str] = {}
        for item in raw_headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out[str(item[0]).lower()] = str(item[1])
        return out
    return {}


def _parse_query(query_params: Any) -> tuple[int, int]:
    """Calculates query length and number of parameters."""
    if not query_params:
        return 0, 0
    if isinstance(query_params, str):
        q = query_params.strip()
        if not q:
            return 0, 0
        if q.startswith("?"):
            q = q[1:]
        # If it is formatted as JSON string (from datasets or structured logs)
        if q.startswith("{") and q.endswith("}"):
            try:
                data = json.loads(q)
                if isinstance(data, dict):
                    return len(q), len(data)
            except Exception:
                pass
        try:
            parsed_params = parse_qsl(q, keep_blank_values=True)
            param_count = len(parsed_params) if parsed_params else (1 if "=" in q else 0)
        except Exception:
            param_count = q.count("&") + 1 if "=" in q else 0
        return len(q), param_count
    elif isinstance(query_params, Mapping):
        return sum(len(str(k)) + len(str(v)) + 2 for k, v in query_params.items()), len(query_params)
    elif isinstance(query_params, list):
        return sum(len(str(item)) for item in query_params), len(query_params)
    return len(str(query_params)), 1


# -----------------------------------------------------------------------------
# MAIN EXTRACTOR FUNCTIONS
# -----------------------------------------------------------------------------

def extract_http_context_features(
    method: Any = "GET",
    path: Any = "/",
    query_params: Any = None,
    headers: Any = None,
    body: Any = None,
    user_agent: Any = None,
    **kwargs: Any,
) -> HTTPContextFeatures:
    """Extracts HTTP protocol, topology, and client metadata features.

    Args:
        method: HTTP method (e.g. GET, POST, PUT, DELETE, PATCH).
        path: URI path string (e.g. /api/v1/books/search).
        query_params: Query string or parsed parameter dictionary.
        headers: Request headers dictionary, JSON string, or tuple list.
        body: Request payload body (str, bytes, or JSON).
        user_agent: Optional explicit User-Agent string (overrides headers).

    Returns:
        HTTPContextFeatures dataclass instance.
    """
    # 1. Method One-Hot Encoding
    method_str = str(method).strip().upper() if method else "GET"
    method_is_get = 1.0 if method_str == "GET" else 0.0
    method_is_post = 1.0 if method_str == "POST" else 0.0
    method_is_put = 1.0 if method_str == "PUT" else 0.0
    method_is_delete = 1.0 if method_str == "DELETE" else 0.0
    method_is_patch = 1.0 if method_str == "PATCH" else 0.0
    method_is_other = (
        1.0
        if (
            not (
                method_is_get
                or method_is_post
                or method_is_put
                or method_is_delete
                or method_is_patch
            )
        )
        else 0.0
    )

    # 2. URI Path Topology
    path_str = str(path).strip() if path else "/"
    # Strip query string if path includes '?'
    if "?" in path_str:
        path_only, inline_q = path_str.split("?", 1)
        path_str = path_only
        if not query_params:
            query_params = inline_q

    path_length = float(len(path_str))
    # Count segments (e.g. '/api/v1/books' has segments 'api', 'v1', 'books' -> depth 3)
    path_segments = [seg for seg in path_str.split("/") if seg]
    path_depth = float(len(path_segments))

    # 3. Query Parameter Behavior & Ratios
    query_len, param_count = _parse_query(query_params)
    query_length = float(query_len)
    query_param_count = float(param_count)
    # Ratio: query length compared to path length
    query_to_path_ratio = float(query_length / (path_length + 1.0))

    # 4. Body Length
    if body is None:
        body_len = 0
    elif isinstance(body, (str, bytes)):
        body_len = len(body)
    else:
        body_len = len(str(body))
    body_length = float(body_len)

    # 5. Headers & Client Telemetry
    hdr_dict = _parse_headers(headers)
    header_count = float(len(hdr_dict))

    # Content-Type Analysis
    content_type = hdr_dict.get("content-type", "").lower()
    if not content_type:
        content_type_is_json = 0.0
        content_type_is_form = 0.0
        content_type_is_multipart = 0.0
        content_type_is_xml = 0.0
        content_type_is_missing = 1.0
    else:
        content_type_is_missing = 0.0
        content_type_is_json = 1.0 if "application/json" in content_type else 0.0
        content_type_is_form = (
            1.0 if "application/x-www-form-urlencoded" in content_type else 0.0
        )
        content_type_is_multipart = 1.0 if "multipart/form-data" in content_type else 0.0
        content_type_is_xml = (
            1.0 if ("application/xml" in content_type or "text/xml" in content_type) else 0.0
        )

    # Authorization & Cookie flags
    has_authorization = (
        1.0 if ("authorization" in hdr_dict or "proxy-authorization" in hdr_dict) else 0.0
    )
    has_cookie = 1.0 if "cookie" in hdr_dict else 0.0

    # User-Agent Analysis
    ua_str = str(user_agent).strip() if user_agent else hdr_dict.get("user-agent", "").strip()
    user_agent_length = float(len(ua_str))
    is_suspicious_ua = 1.0 if bool(_SUSPICIOUS_UA_REGEX.search(ua_str)) else 0.0

    # Content-Length Mismatch
    content_length_header = hdr_dict.get("content-length")
    content_length_mismatch = 0.0
    if content_length_header is not None:
        try:
            declared_len = int(content_length_header)
            # If difference is more than 5 bytes, flag potential smuggling / desync
            if abs(declared_len - body_len) > 5:
                content_length_mismatch = 1.0
        except (ValueError, TypeError):
            content_length_mismatch = 1.0

    return HTTPContextFeatures(
        method_is_get=method_is_get,
        method_is_post=method_is_post,
        method_is_put=method_is_put,
        method_is_delete=method_is_delete,
        method_is_patch=method_is_patch,
        method_is_other=method_is_other,
        path_length=path_length,
        path_depth=path_depth,
        query_length=query_length,
        query_param_count=query_param_count,
        query_to_path_ratio=query_to_path_ratio,
        body_length=body_length,
        content_type_is_json=content_type_is_json,
        content_type_is_form=content_type_is_form,
        content_type_is_multipart=content_type_is_multipart,
        content_type_is_xml=content_type_is_xml,
        content_type_is_missing=content_type_is_missing,
        header_count=header_count,
        has_authorization=has_authorization,
        has_cookie=has_cookie,
        user_agent_length=user_agent_length,
        is_suspicious_user_agent=is_suspicious_ua,
        content_length_mismatch=content_length_mismatch,
    )


def extract_http_context_from_dict(sample: Mapping[str, Any]) -> HTTPContextFeatures:
    """Extracts features from a dictionary representation of an HTTP request (e.g. CSV row)."""
    return extract_http_context_features(
        method=sample.get("method", "GET"),
        path=sample.get("path", "/"),
        query_params=sample.get("query_params"),
        headers=sample.get("headers"),
        body=sample.get("body"),
        user_agent=sample.get("user_agent"),
    )


def extract_http_context_features_batch(
    samples: list[Mapping[str, Any]],
) -> list[HTTPContextFeatures]:
    """Batch-extracts HTTP context features for a list of request dictionaries."""
    return [extract_http_context_from_dict(sample) for sample in samples]
