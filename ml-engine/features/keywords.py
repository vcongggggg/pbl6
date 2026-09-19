"""Attack Keyword Frequency and Syntax Pattern Feature Extractor.

This module implements Task 3.2 (Issue #15) for the WAF ML Defense Engine.
It extracts keyword frequencies and syntactic injection patterns across 4 attack families:
1. sql_keyword_count: Frequency of SQL keywords (SELECT, UNION, DROP, WHERE, EXEC, etc.)
2. xss_keyword_count: Frequency of XSS keywords (script, alert, onerror, javascript, etc.)
3. sqli_regex_matches: High-confidence SQLi structural regex pattern matches (UNION SELECT, OR 1=1, '--')
4. xss_regex_matches: High-confidence XSS execution regex pattern matches (<script>, on*=, javascript:)
5. path_traversal_matches: Path traversal regex matches (../, ..\\, %2e%2e, /etc/passwd)
6. cmd_keyword_count: Frequency of OS command keywords (whoami, cat, id, netstat, etc.)
7. cmd_regex_matches: Command execution chaining syntax matches (; whoami, | sh, $(cmd), $IFS)

Academic Foundation:
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): Keyword frequency & pattern density.
- [Ref 10] M. Hasan et al. (IEEE Access 2023): Systematic review of SQLi detection via tokenization.
- [Ref 12] OWASP ModSecurity Core Rule Set (CRS v4.0): Attack token dictionary mappings.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

# -----------------------------------------------------------------------------
# PRE-COMPILED KEYWORD REGEX PATTERNS (Case-Insensitive)
# -----------------------------------------------------------------------------

# SQL keywords commonly leveraged in SQL Injection attacks
_SQL_KEYWORDS_REGEX = re.compile(
    r"\b("
    r"select|union|insert|update|delete|drop|truncate|from|where|having|"
    r"order\s+by|group\s+by|exec|execute|waitfor|benchmark|delay|sleep|"
    r"schema|information_schema|sqlite_master|table_name|column_name|"
    r"load_file|into\s+outfile|into\s+dumpfile|database|version|current_user|"
    r"declare|cast|convert"
    r")\b",
    re.IGNORECASE,
)

# XSS keywords and event handlers
_XSS_KEYWORDS_REGEX = re.compile(
    r"\b("
    r"script|onerror|onload|onclick|onmouseover|onfocus|ontoggle|onloadend|"
    r"alert|iframe|javascript|eval|prompt|confirm|document\.cookie|"
    r"document\.location|window\.location|fetch|xmlhttprequest|"
    r"string\.fromcharcode|innerhtml|outerhtml"
    r")\b",
    re.IGNORECASE,
)

# Command Injection keywords
_CMD_KEYWORDS_REGEX = re.compile(
    r"\b("
    r"whoami|cat|id|netstat|ps|curl|wget|nc|ncat|netcat|bash|sh|zsh|"
    r"cmd\.exe|powershell|ipconfig|ifconfig|systeminfo|uname|touch|rm|"
    r"chmod|chown|kill|pkill"
    r")\b",
    re.IGNORECASE,
)

# -----------------------------------------------------------------------------
# PRE-COMPILED SYNTAX PATTERN REGEXES (Structural Attack Signatures)
# -----------------------------------------------------------------------------

_SQLI_SYNTAX_REGEX = re.compile(
    r"("
    r"\bunion\b[\s\S]*?\bselect\b|"                  # UNION SELECT
    r"'\s*--|"                                        # Quote + SQL comment
    r"--\s*$|"                                        # End-of-line SQL comment
    r"/\*[\s\S]*?\*/|"                                # Inline comment /**/
    r"'\s*(or|and)\s*['\d\w]+\s*=\s*['\d\w]+|"       # ' OR 1=1 / ' OR 'a'='a
    r"\b(or|and)\b\s+[\d\w]+\s*=\s*[\d\w]+|"          # OR 1=1 without quote
    r";\s*(drop|delete|insert|update|select|exec)|"    # Semicolon stacked queries
    r"'\s*having\s+|"                                 # HAVING clause injection
    r"'\s*order\s+by\s+\d+"                          # ORDER BY probing
    r")",
    re.IGNORECASE,
)

_XSS_SYNTAX_REGEX = re.compile(
    r"("
    r"<script[\s\S]*?>[\s\S]*?</script>|"             # <script>...</script>
    r"<script[\s\S]*?>|"                              # Open <script>
    r"javascript\s*:|"                                # javascript: pseudo-protocol
    r"on\w+\s*=\s*['\"`]?[^'\">`\s]+|"               # Event handlers on*=...
    r"<img[\s\S]*?onerror\s*=|"                       # <img onerror=
    r"<svg[\s\S]*?onload\s*=|"                        # <svg onload=
    r"<iframe[\s\S]*?src\s*=|"                        # <iframe src=
    r"&#x?[0-9a-fA-F]+;"                              # HTML Entity obfuscation
    r")",
    re.IGNORECASE,
)

_PATH_TRAVERSAL_SYNTAX_REGEX = re.compile(
    r"("
    r"\.\./|"                                         # Linux traversal ../
    r"\.\.\\|"                                        # Windows traversal ..\
    r"\.\.//|"                                        # Filter bypass ..//
    r"\.\.\\\\|"                                      # Filter bypass ..\\
    r"%2e%2e[/\\%]|"                                  # URL-encoded ..
    r"%252e%252e|"                                    # Double URL-encoded ..
    r"/etc/passwd|"                                   # Sensitive file
    r"/etc/shadow|"                                   # Sensitive file
    r"c:\\windows|"                                   # Windows directory
    r"windows/system32|"                              # Windows system32
    r"boot\.ini"                                      # Legacy Windows file
    r")",
    re.IGNORECASE,
)

_CMD_INJECTION_SYNTAX_REGEX = re.compile(
    r"("
    r"[;&|]\s*(whoami|cat|id|netstat|ps|curl|wget|nc|bash|sh|cmd|powershell)\b|"  # Chained commands
    r"\$\([^\)]+\)|"                                  # Subshell $(cmd)
    r"`[^`]+`|"                                       # Backtick command `cmd`
    r"\$\{IFS\}|"                                     # ${IFS} variable substitution
    r"\$IFS(?:\$9|\b|[^a-zA-Z0-9_])|"                 # $IFS variable substitution (e.g. echo$IFS'test')
    r"\|\s*base64\s+-d\s*\|\s*(sh|bash)"              # Base64 pipe execution
    r")",
    re.IGNORECASE,
)


# -----------------------------------------------------------------------------
# HELPER EXTRACTION FUNCTIONS
# -----------------------------------------------------------------------------

def count_sql_keywords(text: str | None) -> int:
    """Counts occurrences of SQL keywords in text."""
    if not text:
        return 0
    return len(_SQL_KEYWORDS_REGEX.findall(text))


def count_xss_keywords(text: str | None) -> int:
    """Counts occurrences of XSS keywords and handlers in text."""
    if not text:
        return 0
    return len(_XSS_KEYWORDS_REGEX.findall(text))


def count_cmd_keywords(text: str | None) -> int:
    """Counts occurrences of OS command keywords in text."""
    if not text:
        return 0
    return len(_CMD_KEYWORDS_REGEX.findall(text))


def count_sqli_patterns(text: str | None) -> int:
    """Counts structural SQL Injection syntax pattern matches."""
    if not text:
        return 0
    return len(_SQLI_SYNTAX_REGEX.findall(text))


def count_xss_patterns(text: str | None) -> int:
    """Counts structural Cross-Site Scripting syntax pattern matches."""
    if not text:
        return 0
    return len(_XSS_SYNTAX_REGEX.findall(text))


def count_path_traversal_patterns(text: str | None) -> int:
    """Counts Path Traversal / LFI pattern matches."""
    if not text:
        return 0
    return len(_PATH_TRAVERSAL_SYNTAX_REGEX.findall(text))


def count_cmd_injection_patterns(text: str | None) -> int:
    """Counts OS Command Injection syntax pattern matches."""
    if not text:
        return 0
    return len(_CMD_INJECTION_SYNTAX_REGEX.findall(text))


# -----------------------------------------------------------------------------
# FEATURE CONTAINER & MAIN EXTRACTOR
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackKeywordFeatures:
    """Container holding keyword frequencies and attack syntax pattern matches.

    Attributes 1-5 correspond directly to items 13-17 in the 17-dimensional vector:
    - sql_keyword_count (idx 12 in 0-indexed vector)
    - xss_keyword_count (idx 13 in 0-indexed vector)
    - sqli_regex_matches (idx 14 in 0-indexed vector)
    - xss_regex_matches (idx 15 in 0-indexed vector)
    - path_traversal_matches (idx 16 in 0-indexed vector)

    Additional attributes provide rich command injection telemetry.
    """

    sql_keyword_count: float
    xss_keyword_count: float
    sqli_regex_matches: float
    xss_regex_matches: float
    path_traversal_matches: float
    cmd_keyword_count: float = 0.0
    cmd_regex_matches: float = 0.0

    def to_dict(self) -> dict[str, float]:
        """Serializes features into a dictionary."""
        return asdict(self)

    def to_canonical_5_list(self) -> list[float]:
        """Returns the canonical 5 features for the 17-dimensional vector."""
        return [
            self.sql_keyword_count,
            self.xss_keyword_count,
            self.sqli_regex_matches,
            self.xss_regex_matches,
            self.path_traversal_matches,
        ]

    def to_full_list(self) -> list[float]:
        """Returns all 7 keyword and pattern features."""
        return [
            self.sql_keyword_count,
            self.xss_keyword_count,
            self.sqli_regex_matches,
            self.xss_regex_matches,
            self.path_traversal_matches,
            self.cmd_keyword_count,
            self.cmd_regex_matches,
        ]


def extract_keyword_features(text: Any) -> AttackKeywordFeatures:
    """Extracts attack keyword frequencies and pattern matches from payload text.

    Args:
        text: Raw payload string or object.

    Returns:
        AttackKeywordFeatures dataclass instance.
    """
    if text is None:
        raw_text = ""
    elif not isinstance(text, str):
        raw_text = str(text)
    else:
        raw_text = text

    return AttackKeywordFeatures(
        sql_keyword_count=float(count_sql_keywords(raw_text)),
        xss_keyword_count=float(count_xss_keywords(raw_text)),
        sqli_regex_matches=float(count_sqli_patterns(raw_text)),
        xss_regex_matches=float(count_xss_patterns(raw_text)),
        path_traversal_matches=float(count_path_traversal_patterns(raw_text)),
        cmd_keyword_count=float(count_cmd_keywords(raw_text)),
        cmd_regex_matches=float(count_cmd_injection_patterns(raw_text)),
    )


def extract_keyword_features_batch(texts: list[Any]) -> list[AttackKeywordFeatures]:
    """Batch-extracts keyword features for a list of payload samples.

    Args:
        texts: List of payload strings.

    Returns:
        List of AttackKeywordFeatures.
    """
    return [extract_keyword_features(text) for text in texts]
