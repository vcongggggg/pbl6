import sys
from pathlib import Path

import numpy as np

TEST_DIR = Path(__file__).resolve().parent
ML_ENGINE_DIR = TEST_DIR.parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.canonicalizer import (  # noqa: E402
    canonicalize_http_request,
    canonicalize_payload,
    get_encoding_layer_depth,
)
from features.extractor import (  # noqa: E402
    CANONICAL_FEATURE_NAMES,
    CANONICAL_FEATURE_NAMES_V2,
    extract_17_vector,
    extract_26_features,
    extract_26_from_http,
    extract_26_vector,
    extract_batch_26_vectors,
)


def test_canonicalize_payload_normalizations():
    # URL percent decoding + HTML unescape + zero-width strip + whitespace
    raw = "%3Cscr%20ipt%3Ealert%281%29%3C%2Fscript%3E"
    canon = canonicalize_payload(raw)
    assert "<scr ipt>alert(1)</script>" in canon

    zero_width = "<scr\u200bipt>alert(1)</script>"
    assert canonicalize_payload(zero_width) == "<script>alert(1)</script>"

    encoding_depth = get_encoding_layer_depth("%253Cscript%253E")
    assert encoding_depth >= 2


def test_canonicalize_http_request():
    canon = canonicalize_http_request(
        path="/api/v1/search",
        query_params={"q": "admin' OR 1=1--"},
        body={"comment": "<script>alert(1)</script>"},
        headers={"user-agent": "Mozilla/5.0", "cookie": "session=xyz"},
    )
    assert "/api/v1/search" in canon
    assert "admin' OR 1=1--" in canon
    assert "<script>alert(1)</script>" in canon


def test_26_feature_extraction_dimension_and_consistency():
    assert len(CANONICAL_FEATURE_NAMES) == 17
    assert len(CANONICAL_FEATURE_NAMES_V2) == 26

    # Test 17-D backward compatibility
    v17 = extract_17_vector("SELECT * FROM users WHERE id=1")
    assert v17.shape == (17,)
    assert isinstance(v17, np.ndarray)

    # Test 26-D vector
    v26 = extract_26_vector("SELECT * FROM users WHERE id=1")
    assert v26.shape == (26,)
    assert isinstance(v26, np.ndarray)

    feat_v2 = extract_26_features("SELECT * FROM users WHERE id=1")
    assert len(feat_v2.to_list()) == 26
    assert len(feat_v2.to_dict()) == 26
    assert feat_v2.sql_keyword_count >= 2

    # Test command injection features (f18, f19)
    cmd_v2 = extract_26_features("; whoami && id")
    assert cmd_v2.cmd_keyword_count >= 2
    assert cmd_v2.cmd_regex_matches >= 1

    # Test batch extraction
    samples = ["SELECT * FROM users", "<script>alert(1)</script>", "GET /index.html"]
    batch = extract_batch_26_vectors(samples)
    assert batch.shape == (3, 26)


def test_training_serving_skew_zero():
    """Verifies SCI-PBL6-001: exact zero feature skew between training and serving."""
    row = {
        "path": "/api/v1/users",
        "query_params": "id=%27%20OR%201=1--",
        "body": '{"user": "admin"}',
    }
    v_train = extract_batch_26_vectors([row])[0]
    v_serve = extract_26_from_http(
        path=row["path"],
        query_params=row["query_params"],
        body=row["body"],
    )
    assert np.array_equal(v_train, v_serve)
    assert v_train.shape == (26,)
    # Verify encoding_layer_depth at index 19 detected decoding
    assert v_train[19] >= 1.0
