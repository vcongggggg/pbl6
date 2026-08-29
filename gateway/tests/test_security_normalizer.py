from app.security.normalizer import MAX_INPUT_LENGTH, InputNormalizer


def test_normalizer_url_decoding():
    """Verifies single and multi-pass URL decoding."""
    raw = "%27%20OR%201%3D1"
    _, normalized = InputNormalizer.get_canonical_representations(raw)
    assert normalized == "' OR 1=1"

    # Double URL encoding
    double_encoded = "%2527%2520OR%25201%253D1"
    _, double_norm = InputNormalizer.get_canonical_representations(double_encoded)
    assert double_norm == "' OR 1=1"


def test_normalizer_html_entities():
    """Verifies HTML entity unescaping."""
    raw = "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    _, normalized = InputNormalizer.get_canonical_representations(raw)
    assert normalized == "<script>alert('XSS')</script>"


def test_normalizer_null_bytes_and_whitespace():
    """Verifies null bytes removal and whitespace collapsing."""
    raw = "admin\x00'   OR   \t\n  1=1--"
    _, normalized = InputNormalizer.get_canonical_representations(raw)
    assert normalized == "admin' OR 1=1--"


def test_normalizer_unicode_normalization():
    """Verifies Unicode NFKC normalization on fullwidth characters."""
    # Fullwidth apostrophe and text
    raw = "＇ ＯＲ １＝１"
    _, normalized = InputNormalizer.get_canonical_representations(raw)
    assert normalized == "' OR 1=1"


def test_normalizer_length_bounded():
    """Verifies huge inputs are safely truncated without crashing."""
    huge_input = "A" * (MAX_INPUT_LENGTH + 5000)
    raw_bounded, normalized = InputNormalizer.get_canonical_representations(huge_input)
    assert len(raw_bounded) == MAX_INPUT_LENGTH
    assert len(normalized) == MAX_INPUT_LENGTH
