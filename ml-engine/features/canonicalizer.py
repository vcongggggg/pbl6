"""Unified Payload & HTTP Request Canonicalizer (v2.0).

This module eliminates Training-Serving Skew (SCI-PBL6-001) by providing
a single, authoritative canonicalization pipeline used identically across:
1. Offline dataset curation (scripts/build_defense_dataset_v2.py)
2. Model training and evaluation (ml-engine/models/)
3. Offline zero-shot benchmarking (ml-engine/benchmarks/)
4. Online Gateway inference (gateway/app/api/proxy.py)
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
import urllib.parse
from typing import Any, Mapping

MAX_CANONICAL_DEPTH = 3
MAX_PAYLOAD_LENGTH = 16384


def canonicalize_payload(text: str | None, max_depth: int = MAX_CANONICAL_DEPTH) -> str:
    """Canonicalizes a raw string or payload with bounded normalization.

    Steps:
    1. Bounded iterative URL percent decoding (detecting encoding depth).
    2. HTML entity unescaping (&lt; -> <, &#x27; -> ', etc.).
    3. Unicode NFKC normalization (fullwidth chars, homoglyphs).
    4. Removal of null bytes, non-printable control chars, and zero-width chars ([\u200b-\u200f\ufeff]).
    5. Normalization of whitespace sequences to a single space.
    """
    if not text:
        return ""

    if not isinstance(text, str):
        text = str(text)

    # Enforce maximum length limit per single payload
    if len(text) > MAX_PAYLOAD_LENGTH:
        text = text[:MAX_PAYLOAD_LENGTH]

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

    # 2. HTML entity unescaping
    try:
        current = html.unescape(current)
    except Exception:
        pass

    # 3. Unicode NFKC normalization
    try:
        current = unicodedata.normalize("NFKC", current)
    except Exception:
        pass

    # 4. Remove null bytes, non-printable control characters, and zero-width characters
    current = current.replace("\x00", "")
    current = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", current)
    current = re.sub(r"[\u200b-\u200f\ufeff]", "", current)

    # 5. Normalize multiple whitespace sequences to a single space
    current = re.sub(r"\s+", " ", current)

    return current.strip()


def get_encoding_layer_depth(raw_text: str | None, max_depth: int = MAX_CANONICAL_DEPTH) -> int:
    """Measures the number of decoding layers applied before payload stabilizes."""
    if not raw_text or not isinstance(raw_text, str):
        return 0

    current = raw_text[:MAX_PAYLOAD_LENGTH]
    depth = 0

    for _ in range(max_depth):
        try:
            decoded = urllib.parse.unquote(current)
        except Exception:
            break
        if decoded != current:
            depth += 1
            current = decoded
        else:
            break

    try:
        unescaped = html.unescape(current)
        if unescaped != current:
            depth += 1
    except Exception:
        pass

    return min(depth, max_depth)


def canonicalize_http_request(
    path: str | None = None,
    query_params: Any = None,
    body: Any = None,
    headers: Mapping[str, str] | None = None,
) -> str:
    """Extracts and canonicalizes a composite HTTP request into a unified string.

    Tokens are ordered and canonicalized identically in training and runtime proxy.
    """
    tokens: list[str] = []

    if path:
        tokens.append(str(path))

    if query_params:
        if isinstance(query_params, str):
            tokens.append(urllib.parse.unquote(query_params))
        elif isinstance(query_params, Mapping):
            formatted_params = "&".join(f"{k}={v}" for k, v in query_params.items())
            tokens.append(formatted_params)

    if body:
        if isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="replace")
            tokens.append(body_str)
        elif isinstance(body, str):
            tokens.append(body)
        elif isinstance(body, (dict, list)):
            try:
                tokens.append(json.dumps(body))
            except Exception:
                tokens.append(str(body))
        else:
            tokens.append(str(body))

    # Safe inspectable headers if provided
    if headers:
        for hk in ("cookie", "user-agent", "referer"):
            val = headers.get(hk) or headers.get(hk.title())
            if val:
                tokens.append(f"{hk}:{val}")

    raw_joined = " ".join(tokens)
    return canonicalize_payload(raw_joined)
