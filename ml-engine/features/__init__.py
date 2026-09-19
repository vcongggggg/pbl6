"""ML Engine Features Package.

This package provides feature extraction modules for Web API Security:
- payload.py: Morphological and statistical payload features (Task 3.1)
- keywords.py: Attack keyword frequencies and regex pattern matches (Task 3.2)
- http_context.py: HTTP context, headers, and request metadata (Task 3.3)
- extractor.py: 17-dimensional unified feature vectorizer pipeline (Task 3.4)

Academic Foundation:
- [Ref 08] Torrano-Gimenez et al. (Wiley 2015): Combining Expert Knowledge with Automatic Feature Extraction.
- [Ref 07] CSIC 2010 HTTP Dataset: Statistical baseline profiling for anomaly detection.
- [Ref 09] MDPI Electronics 2025: Lightweight feature extraction for real-time WAF inline scoring.
"""

from .http_context import (
    HTTP_CONTEXT_FEATURE_NAMES,
    HTTPContextFeatures,
    extract_http_context_features,
    extract_http_context_features_batch,
    extract_http_context_from_dict,
)
from .keywords import (
    AttackKeywordFeatures,
    count_cmd_injection_patterns,
    count_cmd_keywords,
    count_path_traversal_patterns,
    count_sql_keywords,
    count_sqli_patterns,
    count_xss_keywords,
    count_xss_patterns,
    extract_keyword_features,
    extract_keyword_features_batch,
)
from .payload import (
    PayloadMorphologyFeatures,
    calculate_entropy,
    calculate_special_char_ratio,
    extract_char_counts,
    extract_payload_features,
    extract_payload_features_batch,
)

__all__ = [
    "AttackKeywordFeatures",
    "HTTPContextFeatures",
    "HTTP_CONTEXT_FEATURE_NAMES",
    "PayloadMorphologyFeatures",
    "calculate_entropy",
    "calculate_special_char_ratio",
    "count_cmd_injection_patterns",
    "count_cmd_keywords",
    "count_path_traversal_patterns",
    "count_sql_keywords",
    "count_sqli_patterns",
    "count_xss_keywords",
    "count_xss_patterns",
    "extract_char_counts",
    "extract_http_context_features",
    "extract_http_context_features_batch",
    "extract_http_context_from_dict",
    "extract_keyword_features",
    "extract_keyword_features_batch",
    "extract_payload_features",
    "extract_payload_features_batch",
]

