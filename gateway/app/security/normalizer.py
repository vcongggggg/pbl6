import html
import re
import unicodedata
import urllib.parse

# Hard limits to prevent resource exhaustion / ReDoS / memory bloat
MAX_NORMALIZATION_DEPTH = 3
MAX_INPUT_LENGTH = 16384  # 16 KB max length per input string


class InputNormalizer:
    """Canonicalizes and normalizes incoming HTTP payload strings safely."""

    @staticmethod
    def normalize(text: str, max_depth: int = MAX_NORMALIZATION_DEPTH) -> str:
        """Applies bounded multi-pass canonicalization to text."""
        if not text:
            return ""

        # Enforce maximum length limit
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]

        current = text

        # 1. Bounded iterative URL percent-decoding
        for _ in range(max_depth):
            try:
                decoded = urllib.parse.unquote(current)
            except Exception:
                break
            if decoded == current:
                break
            current = decoded

        # 2. HTML entity unescaping (&lt; -> <, &#x27; -> ', etc.)
        try:
            current = html.unescape(current)
        except Exception:
            pass

        # 3. Unicode NFKC normalization (converts fullwidth chars, accents, homoglyphs)
        try:
            current = unicodedata.normalize("NFKC", current)
        except Exception:
            pass

        # 4. Remove null bytes and non-printable control characters (except newline, tab, cr)
        current = current.replace("\x00", "")
        current = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", current)

        # 5. Normalize multiple whitespace sequences to a single space
        current = re.sub(r"\s+", " ", current)

        return current.strip()

    @classmethod
    def get_canonical_representations(cls, raw_text: str) -> tuple[str, str]:
        """Returns both original raw text (truncated if too long) and normalized text."""
        if not raw_text:
            return "", ""

        raw_bounded = raw_text[:MAX_INPUT_LENGTH]
        normalized = cls.normalize(raw_bounded)
        return raw_bounded, normalized
