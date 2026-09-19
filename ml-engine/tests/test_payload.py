"""Unit tests for Task 3.1: Morphological Payload Feature Extraction.

Validates Shannon entropy calculation, special character counting,
special character ratio, and dataclass serialization for payload strings.

Academic References:
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): "Combining Expert Knowledge with
  Automatic Feature Extraction for Reliable Web Attack Detection"
"""

import math
import sys
import time
from pathlib import Path

# Ensure ml-engine is on sys.path
TEST_DIR = Path(__file__).resolve().parent
ML_ENGINE_DIR = TEST_DIR.parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.payload import (  # noqa: E402
    PayloadMorphologyFeatures,
    calculate_entropy,
    calculate_special_char_ratio,
    extract_char_counts,
    extract_payload_features,
    extract_payload_features_batch,
)


class TestShannonEntropy:
    """Test suite for Shannon Entropy calculation [Ref 08]."""

    def test_entropy_empty_or_none(self) -> None:
        assert calculate_entropy("") == 0.0
        assert calculate_entropy(None) == 0.0

    def test_entropy_single_character(self) -> None:
        assert calculate_entropy("a") == 0.0
        assert calculate_entropy("Z") == 0.0

    def test_entropy_identical_characters(self) -> None:
        assert calculate_entropy("aaaaaaa") == 0.0
        assert calculate_entropy("1111111111") == 0.0

    def test_entropy_two_balanced_characters(self) -> None:
        # P('a') = 0.5, P('b') = 0.5 -> H = - (0.5*(-1) + 0.5*(-1)) = 1.0
        entropy = calculate_entropy("abab")
        assert math.isclose(entropy, 1.0, rel_tol=1e-5)

    def test_entropy_four_balanced_characters(self) -> None:
        # P(x) = 0.25 for 4 chars -> H = - 4 * (0.25 * log2(0.25)) = - 4 * (0.25 * -2) = 2.0
        entropy = calculate_entropy("abcd")
        assert math.isclose(entropy, 2.0, rel_tol=1e-5)

    def test_entropy_real_world_payloads(self) -> None:
        benign = "alice.smith"
        sqli = "admin' OR 1=1 --"
        obfuscated = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

        h_benign = calculate_entropy(benign)
        h_sqli = calculate_entropy(sqli)
        h_obfuscated = calculate_entropy(obfuscated)

        assert h_benign > 2.0
        assert h_sqli > 2.5
        # Highly diverse / base64 payload has high entropy
        assert h_obfuscated > 4.0


class TestSpecialCharacterExtraction:
    """Test suite for counting dangerous special characters."""

    def test_char_counts_empty_or_none(self) -> None:
        empty_counts = extract_char_counts("")
        assert all(count == 0 for count in empty_counts.values())

        none_counts = extract_char_counts(None)
        assert all(count == 0 for count in none_counts.values())

    def test_char_counts_precise(self) -> None:
        payload = "'\"<>;-/\\()"
        counts = extract_char_counts(payload)

        assert counts["count_single_quote"] == 1
        assert counts["count_double_quote"] == 1
        assert counts["count_less_than"] == 1
        assert counts["count_greater_than"] == 1
        assert counts["count_semicolon"] == 1
        assert counts["count_hyphen"] == 1
        assert counts["count_slash"] == 1
        assert counts["count_backslash"] == 1
        # '(' and ')' combined = 2
        assert counts["count_parenthesis"] == 2

    def test_char_counts_sqli_attack(self) -> None:
        sqli = "1' UNION SELECT NULL, password FROM users WHERE id=1; --"
        counts = extract_char_counts(sqli)

        assert counts["count_single_quote"] == 1
        assert counts["count_semicolon"] == 1
        assert counts["count_hyphen"] == 2
        assert counts["count_double_quote"] == 0
        assert counts["count_less_than"] == 0

    def test_char_counts_xss_attack(self) -> None:
        xss = "<script>alert('XSS')</script>"
        counts = extract_char_counts(xss)

        assert counts["count_less_than"] == 2
        assert counts["count_greater_than"] == 2
        assert counts["count_slash"] == 1
        assert counts["count_parenthesis"] == 2
        assert counts["count_single_quote"] == 2

    def test_char_counts_path_traversal(self) -> None:
        traversal = "../../../etc/passwd"
        counts = extract_char_counts(traversal)

        assert counts["count_slash"] == 4
        assert counts["count_backslash"] == 0


class TestSpecialCharRatio:
    """Test suite for special character ratio calculation."""

    def test_ratio_empty_or_none(self) -> None:
        assert calculate_special_char_ratio("") == 0.0
        assert calculate_special_char_ratio(None) == 0.0

    def test_ratio_pure_alphanumeric(self) -> None:
        assert calculate_special_char_ratio("HelloWorld123") == 0.0

    def test_ratio_pure_special(self) -> None:
        specials = "'\"<>;-/\\()%"
        assert calculate_special_char_ratio(specials) == 1.0

    def test_ratio_bounded(self) -> None:
        payload = "SELECT * FROM users WHERE '1'='1' --"
        ratio = calculate_special_char_ratio(payload)
        assert 0.0 < ratio < 1.0


class TestPayloadMorphologyExtractor:
    """Test suite for end-to-end morphology feature extraction."""

    def test_extract_payload_features_types_and_fields(self) -> None:
        payload = "admin' OR 1=1--"
        features = extract_payload_features(payload)

        assert isinstance(features, PayloadMorphologyFeatures)
        assert features.length == float(len(payload))
        assert features.entropy > 0.0
        assert features.count_single_quote == 1.0
        assert features.count_hyphen == 2.0
        assert features.special_char_ratio > 0.0

        # Verify serialization
        d = features.to_dict()
        assert len(d) == 12
        assert d["length"] == float(len(payload))

        lst = features.to_list()
        assert len(lst) == 12
        assert all(isinstance(val, float) for val in lst)

    def test_extract_non_string_types(self) -> None:
        # Numerical or None types handled safely
        feat_none = extract_payload_features(None)
        assert feat_none.length == 0.0
        assert feat_none.entropy == 0.0

        feat_int = extract_payload_features(12345)
        assert feat_int.length == 5.0

    def test_batch_extraction_and_speed(self) -> None:
        samples = [
            "normal_search_term",
            "1' UNION SELECT 1, 2, 3--",
            "<script>alert(1)</script>",
            "../../../../windows/system32/cmd.exe",
            "SELECT * FROM books WHERE price < 50;",
        ] * 200  # 1,000 samples

        start = time.perf_counter()
        results = extract_payload_features_batch(samples)
        duration = time.perf_counter() - start

        assert len(results) == 1000
        # Check sub-millisecond per sample performance (< 50ms total for 1,000 samples)
        assert duration < 0.1, f"Batch extraction took {duration*1000:.2f}ms, expected < 100ms"
