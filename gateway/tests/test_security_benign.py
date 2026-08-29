import json

from app.security.engine import RuleEngine

BENIGN_TEST_CASES = [
    # 1. Normal search queries
    {"path": "/rest/products/search", "query": "q=apple+juice", "body": None},
    {"path": "/rest/products/search", "query": "q=orange&limit=10&offset=0", "body": None},
    {"path": "/api/articles", "query": "category=tech&tag=python", "body": None},
    {"path": "/search", "query": "q=how+to+select+a+good+laptop", "body": None},
    {"path": "/search", "query": "q=union+of+european+football+associations", "body": None},
    {"path": "/search", "query": "q=drop+by+the+office+tomorrow", "body": None},

    # 2. Legitimate user profile & checkout JSON bodies
    {
        "path": "/api/Users",
        "query": None,
        "body": json.dumps({
            "email": "student.john@university.edu.vn",
            "name": "John Doe",
            "address": "123 Main Street, Apt 4B",
            "bio": "Software developer interested in databases and security",
        }).encode("utf-8"),
    },
    {
        "path": "/api/BasketItems",
        "query": None,
        "body": json.dumps({
            "ProductId": 5,
            "quantity": 2,
            "notes": "Please deliver between 2:00 PM and 5:00 PM; thank you.",
        }).encode("utf-8"),
    },
    {
        "path": "/api/Feedback",
        "query": None,
        "body": json.dumps({
            "comment": "Great product! Rating: 5/5 stars. My kids loved the apple juice & cookies.",
            "rating": 5,
        }).encode("utf-8"),
    },

    # 3. Filenames with multiple dots and standard extensions
    {"path": "/assets/public/images/product.preview.v2.png", "query": None, "body": None},
    {"path": "/downloads/report.final.draft.pdf", "query": "version=1.0.2", "body": None},

    # 4. Mathematical and punctuation heavy benign strings
    {"path": "/api/calculate", "query": "expr=10%2B20*30", "body": None},
    {"path": "/api/filter", "query": "price_min=10&price_max=100", "body": None},
]


def test_benign_corpus_produces_zero_detections():
    """Verifies that none of the benign corpus samples trigger false positive detections."""
    engine = RuleEngine()

    for idx, case in enumerate(BENIGN_TEST_CASES):
        result = engine.inspect_request(
            path=case["path"],
            query_params=case["query"],
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            body_bytes=case["body"],
        )
        assert not result.is_attack, (
            f"Benign test case #{idx} unexpectedly triggered attack detection: "
            f"matches={[m.rule_id for m in result.matches]}, case={case}"
        )
        assert result.rule_risk_score == 0.0
        assert result.total_matches == 0
