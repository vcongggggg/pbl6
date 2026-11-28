import html
import re
import unicodedata
import urllib.parse

# Hard limits to prevent resource exhaustion / ReDoS / memory bloat
MAX_NORMALIZATION_DEPTH = 3
MAX_INPUT_LENGTH = 16384  # 16 KB max length per input string

_JSON_UNICODE_ASCII_RE = re.compile(r"\\u00([2-7][0-9a-fA-F])")
_HEX_ASCII_ESCAPE_RE = re.compile(r"\\x([2-7][0-9a-fA-F])")


def _decode_printable_ascii_hex(match: re.Match[str]) -> str:
    return chr(int(match.group(1), 16))


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

        # 1. Bounded iterative URL percent-decoding & JSON/hex printable ASCII escapes
        for _ in range(max_depth):
            prev = current
            try:
                current = urllib.parse.unquote(current)
            except Exception:
                pass
            if "\\u00" in current or "\\u00" in current.lower():
                current = _JSON_UNICODE_ASCII_RE.sub(_decode_printable_ascii_hex, current)
            if "\\x" in current or "\\x" in current.lower():
                current = _HEX_ASCII_ESCAPE_RE.sub(_decode_printable_ascii_hex, current)
            if current == prev:
                break

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

        # 4. Remove null bytes, non-printable control characters, and zero-width characters (SEC-PBL6-006)
        current = current.replace("\x00", "")
        current = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", current)
        current = re.sub(r"[\u200b-\u200f\ufeff]", "", current)

        # 4.1 Strip inline SQL comments (/*...*/) including multiline (/*\n...*/) to defeat obfuscation (SEC-PBL6-006)
        current = re.sub(r"/\*.*?\*/", " ", current, flags=re.DOTALL)

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
