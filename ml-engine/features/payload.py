"""Payload Morphological and Statistical Feature Extractor.

This module implements Task 3.1 (Issue #14) for the WAF ML Defense Engine.
It extracts 12 morphological and statistical features from raw payload strings:
1. length: Total character length of the payload
2. entropy: Shannon entropy measuring character distribution chaos
3. count_single_quote: Occurrences of '
4. count_double_quote: Occurrences of "
5. count_less_than: Occurrences of <
6. count_greater_than: Occurrences of >
7. count_semicolon: Occurrences of ;
8. count_hyphen: Occurrences of -
9. count_slash: Occurrences of /
10. count_backslash: Occurrences of \\
11. count_parenthesis: Occurrences of ( and )
12. special_char_ratio: Ratio of suspicious special characters to length

Academic Foundation:
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): "Combining Expert Knowledge with
  Automatic Feature Extraction for Reliable Web Attack Detection"
- [Ref 07] CSIC 2010 HTTP Dataset: Statistical baseline profiling for anomaly detection.
- [Ref 09] MDPI Electronics 2025: Sub-millisecond morphological inspection for high-throughput WAF.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

# Standard set of suspicious characters commonly used in injection attacks:
# SQLi: ', ", ;, --, /*
# XSS: <, >, (, )
# Path Traversal & Cmd: /, \, %, ;
DEFAULT_SPECIAL_CHARS: frozenset[str] = frozenset("'\"<>;-/\\()%")


def calculate_entropy(text: str | None) -> float:
    """Calculates the base-2 Shannon Entropy of a string.

    Shannon entropy formula:
        H(X) = - sum(p(x) * log2(p(x))) for x in unique_chars

    Entropy indicates character unpredictability:
    - Normal text / benign parameters: typically 2.0 - 3.5
    - Obfuscated / base64 / shellcode / hex-encoded: typically > 3.8 - 4.5
    - Uniform or empty strings: 0.0

    Args:
        text: Input string payload.

    Returns:
        Shannon entropy as a float (>= 0.0).
    """
    if not text:
        return 0.0

    length = len(text)
    if length <= 1:
        return 0.0

    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return float(entropy)


def extract_char_counts(text: str | None) -> dict[str, int]:
    """Counts occurrences of individual dangerous special characters.

    Args:
        text: Input string payload.

    Returns:
        Dictionary mapping character feature names to their respective integer counts.
    """
    if not text:
        return {
            "count_single_quote": 0,
            "count_double_quote": 0,
            "count_less_than": 0,
            "count_greater_than": 0,
            "count_semicolon": 0,
            "count_hyphen": 0,
            "count_slash": 0,
            "count_backslash": 0,
            "count_parenthesis": 0,
        }

    return {
        "count_single_quote": text.count("'"),
        "count_double_quote": text.count('"'),
        "count_less_than": text.count("<"),
        "count_greater_than": text.count(">"),
        "count_semicolon": text.count(";"),
        "count_hyphen": text.count("-"),
        "count_slash": text.count("/"),
        "count_backslash": text.count("\\"),
        "count_parenthesis": text.count("(") + text.count(")"),
    }


def calculate_special_char_ratio(
    text: str | None,
    special_chars: frozenset[str] = DEFAULT_SPECIAL_CHARS,
) -> float:
    """Calculates the proportion of special characters relative to total length.

    Args:
        text: Input string payload.
        special_chars: Frozenset of characters considered special.

    Returns:
        Ratio as a float in [0.0, 1.0].
    """
    if not text:
        return 0.0

    length = len(text)
    if length == 0:
        return 0.0

    special_count = sum(1 for char in text if char in special_chars)
    return float(special_count / length)


@dataclass(frozen=True)
class PayloadMorphologyFeatures:
    """Container holding the 12 morphological features of a payload."""

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

    def to_dict(self) -> dict[str, float]:
        """Serializes features into a dictionary."""
        return asdict(self)

    def to_list(self) -> list[float]:
        """Serializes features into an ordered list matching canonical order."""
        return [
            self.length,
            self.entropy,
            self.count_single_quote,
            self.count_double_quote,
            self.count_less_than,
            self.count_greater_than,
            self.count_semicolon,
            self.count_hyphen,
            self.count_slash,
            self.count_backslash,
            self.count_parenthesis,
            self.special_char_ratio,
        ]


def extract_payload_features(text: Any) -> PayloadMorphologyFeatures:
    """Extracts all 12 morphological features from an input payload string.

    Args:
        text: Raw payload string or object (converted to str safely).

    Returns:
        PayloadMorphologyFeatures instance containing all 12 feature values.
    """
    if text is None:
        raw_text = ""
    elif not isinstance(text, str):
        raw_text = str(text)
    else:
        raw_text = text

    length = float(len(raw_text))
    entropy = calculate_entropy(raw_text)
    counts = extract_char_counts(raw_text)
    ratio = calculate_special_char_ratio(raw_text)

    return PayloadMorphologyFeatures(
        length=length,
        entropy=entropy,
        count_single_quote=float(counts["count_single_quote"]),
        count_double_quote=float(counts["count_double_quote"]),
        count_less_than=float(counts["count_less_than"]),
        count_greater_than=float(counts["count_greater_than"]),
        count_semicolon=float(counts["count_semicolon"]),
        count_hyphen=float(counts["count_hyphen"]),
        count_slash=float(counts["count_slash"]),
        count_backslash=float(counts["count_backslash"]),
        count_parenthesis=float(counts["count_parenthesis"]),
        special_char_ratio=ratio,
    )


def extract_payload_features_batch(texts: list[Any]) -> list[PayloadMorphologyFeatures]:
    """Batch-extracts morphological features for a list of payload samples.

    Args:
        texts: List of payload strings.

    Returns:
        List of PayloadMorphologyFeatures.
    """
    return [extract_payload_features(text) for text in texts]
