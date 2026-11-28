import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from app.security.ml_detector import (
    FEATURE_NAMES,
    MLDetector,
    MLPredictionResult,
    extract_26_from_http,
    normalize_http_for_ml,
)


def test_ml_detector_graceful_fallback_when_model_absent():
    """Verifies that MLDetector does not crash when model is absent,

    returning model_loaded=False and risk_score=None (NIST SP 800-115).
    """
    detector = MLDetector(model_path="/nonexistent/model.joblib")
    assert detector.is_loaded is False
    assert detector.model_path is None

    result = detector.predict("SELECT * FROM users WHERE id = 1")
    assert isinstance(result, MLPredictionResult)
    assert result.model_loaded is False
    assert result.is_attack is False
    assert result.risk_score is None
    assert result.confidence == 0.0
    assert result.latency_ms >= 0.0


def test_ml_detector_17_feature_extraction():
    """Verifies that extract_features accurately extracts 17 morphological features."""
    payload = "'; UNION SELECT * FROM users WHERE id=1; --"
    features = MLDetector.extract_features(payload)

    assert len(features) == 17
    assert len(features) == len(FEATURE_NAMES)

    # Check specific features
    assert features[0] == len(payload)  # length
    assert features[1] > 0.0  # entropy
    assert features[2] >= 1.0  # single quotes
    assert features[6] >= 2.0  # semicolons
    assert features[7] >= 2.0  # hyphens
    assert features[12] >= 2.0  # sql_keyword_count (union, select, from, where)
    assert features[14] >= 1.0  # sqli_regex_matches


def test_ml_detector_shannon_entropy():
    """Verifies that Shannon entropy measures randomness correctly."""
    zero_entropy = MLDetector.calculate_shannon_entropy("")
    assert zero_entropy == 0.0

    low_entropy = MLDetector.calculate_shannon_entropy("aaaaaaaaaa")
    assert low_entropy == 0.0

    high_entropy = MLDetector.calculate_shannon_entropy("a1B#9$xZ!q@7*k")
    assert high_entropy > 3.0


def test_ml_detector_sub_15ms_latency_with_active_model():
    """Verifies that inference execution complies with the sub-15ms budget (MDPI 2025)."""
    # 1. Train a lightweight mock RandomForestClassifier with 17 features
    rng = np.random.RandomState(42)
    X_train = rng.rand(50, 17)
    y_train = ["BENIGN"] * 25 + ["SQLI"] * 25

    clf = RandomForestClassifier(n_estimators=10, max_depth=4, random_state=42)
    clf.fit(X_train, y_train)

    # 2. Serialize to temporary joblib file
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "test_rf_model.joblib"
        joblib.dump(clf, model_file)

        # 3. Load model into MLDetector
        detector = MLDetector(model_path=model_file, allow_unverified=True)
        assert detector.is_loaded is True

        # 4. Warm up sklearn runtime before measuring steady-state latency across 10 predictions
        for _ in range(3):
            detector.predict("UNION SELECT password FROM accounts")

        latencies = []
        for _ in range(10):
            t0 = time.perf_counter()
            res = detector.predict("UNION SELECT password FROM accounts")
            elapsed = (time.perf_counter() - t0) * 1000
            latencies.append(elapsed)

            assert res.model_loaded is True
            assert res.confidence >= 0.0
            assert res.risk_score is not None

        avg_latency = sum(latencies) / len(latencies)
        assert avg_latency < 15.0, f"Average latency {avg_latency:.2f}ms exceeds 15ms threshold"


def test_ml_detector_hot_reload_and_unload():
    """Verifies that load_model and unload dynamically manage model state in RAM."""
    detector = MLDetector(model_path="/dummy/path")
    assert detector.is_loaded is False

    # Create dummy trained classifier
    clf = RandomForestClassifier(n_estimators=5, random_state=42)
    clf.fit([[0.0] * 17, [1.0] * 17], ["BENIGN", "SQLI"])

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "hot_reload_rf.joblib"
        joblib.dump(clf, model_file)

        # Hot load
        loaded = detector.load_model(model_file, allow_unverified=True)
        assert loaded is True
        assert detector.is_loaded is True
        assert detector.predict("test").model_loaded is True

        # Unload
        detector.unload()
        assert detector.is_loaded is False
        assert detector.predict("test").model_loaded is False


def test_sec_pbl6_005_fail_closed_on_hash_mismatch():
    """SEC-PBL6-005: Verifies that MLDetector strictly refuses to load models with tampered or mismatched hashes."""
    clf = RandomForestClassifier(n_estimators=3, random_state=42)
    clf.fit([[0.0] * 17, [1.0] * 17], ["BENIGN", "SQLI"])

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "tampered_rf.joblib"
        joblib.dump(clf, model_file)

        # Write metadata with an incorrect (mismatched) hash
        meta_file = Path(tmp_dir) / "tampered_rf_metadata.json"
        meta_file.write_text('{"sha256_hash": "0000000000000000000000000000000000000000000000000000000000000000"}')

        detector = MLDetector(model_path="/nonexistent")
        loaded = detector.load_model(model_file)
        assert loaded is False
        assert detector.is_loaded is False


def test_ml_detector_loads_champion_xgb_v2_ubj():
    """Verifies that MLDetector auto-loads champion xgb_v2.ubj artifact and executes 26-D inference within latency budget."""
    repo_root = Path(__file__).resolve().parents[2]
    xgb_path = repo_root / "ml-engine" / "artifacts" / "xgb_v2.ubj"
    if not xgb_path.exists():
        return

    detector = MLDetector(model_path=xgb_path)
    assert detector.is_loaded is True

    # Warm-up cold start
    detector.predict("SELECT 1")

    # Check inference with 26-D single-pass feature vector
    res = detector.predict("SELECT * FROM users WHERE '1'='1' UNION SELECT credit_card FROM payments")
    assert res.is_attack is True
    assert res.attack_type in ("SQL_INJECTION", "SQLI")
    assert res.confidence > 0.80
    assert res.latency_ms < 15.0


def test_normalize_http_for_ml_decoding_and_json_preservation():
    """Verifies URL/form '+' decoding without corrupting JSON payloads."""
    norm_path, norm_query, norm_body = normalize_http_for_ml(
        path="/api/v1/books%2Fsearch",
        query_params="q=%27+UNION+SELECT+1--&page=2",
        body="name=Maria+Gomez&comment=1%27+OR+1%3D1--",
    )
    assert norm_path == "/api/v1/books/search"
    assert norm_query == "q=' UNION SELECT 1--&page=2"
    assert norm_body == "name=Maria Gomez&comment=1' OR 1=1--"

    # JSON bodies must preserve '+' characters while still decoding URL/HTML obfuscation
    j_path, j_query, j_body = normalize_http_for_ml(
        path="/api/v1/calc",
        query_params=None,
        body='{"expr": "1+1=2", "note": "safe+string"}',
    )
    assert j_path == "/api/v1/calc"
    assert j_query is None
    assert j_body == '{"expr": "1+1=2", "note": "safe+string"}'


def test_predict_http_per_parameter_max_pooling_diluted_attack():
    """Verifies max(score_global, max_param_score) catches diluted multi-parameter SQLi/XSS."""
    repo_root = Path(__file__).resolve().parents[2]
    xgb_path = repo_root / "ml-engine" / "artifacts" / "xgb_v2.ubj"
    if not xgb_path.exists():
        return

    detector = MLDetector(model_path=xgb_path)
    assert detector.is_loaded is True

    # Diluted multi-parameter query where benign context surrounds SQLi/XSS parameter
    diluted_query = (
        "first_name=Maria&last_name=Gomez&email=maria.gomez@example.com&city=Danang"
        "&country=Vietnam&sort=asc&limit=20&offset=0"
        "&filter=%27+UNION+SELECT+username,password+FROM+users--"
    )
    norm_path, norm_query, norm_body = normalize_http_for_ml("/api/v1/books", diluted_query, None)
    global_vec = extract_26_from_http(path=norm_path, query_params=norm_query, body=norm_body).tolist()
    global_only_res = detector.predict(f"{norm_path} {norm_query}", feature_vector=global_vec)

    pooled_res, returned_vec = detector.predict_http("/api/v1/books", query_params=diluted_query, body=None)
    assert len(returned_vec) == 26
    assert returned_vec == global_vec
    assert pooled_res.risk_score is not None
    assert global_only_res.risk_score is not None
    assert pooled_res.risk_score >= global_only_res.risk_score
    assert pooled_res.is_attack is True

    # Also verify diluted JSON body XSS
    diluted_json = (
        '{"profile": {"name": "Alice Smith", "email": "alice@example.com", '
        '"bio": "Software engineer working on web APIs"}, '
        '"q": "<script>alert(document.cookie)</script>"}'
    )
    xss_res, xss_vec = detector.predict_http("/api/v1/profile", query_params=None, body=diluted_json)
    assert len(xss_vec) == 26
    assert xss_res.is_attack is True
    assert (xss_res.risk_score or 0.0) >= 50.0


def test_predict_http_benign_multi_param_and_latency_budget():
    """Verifies benign multi-parameter requests remain benign and mean latency stays < 1.5ms."""
    repo_root = Path(__file__).resolve().parents[2]
    xgb_path = repo_root / "ml-engine" / "artifacts" / "xgb_v2.ubj"
    if not xgb_path.exists():
        return

    detector = MLDetector(model_path=xgb_path)
    assert detector.is_loaded is True

    benign_query = "name=Maria+Gomez&email=maria@example.com&page=2&date=2026-11-25"
    # Warm-up
    for _ in range(10):
        detector.predict_http("/api/v1/users", query_params=benign_query, body=None)

    res, vec = detector.predict_http("/api/v1/users", query_params=benign_query, body=None)
    assert len(vec) == 26
    assert res.model_loaded is True
    assert res.is_attack is False
    assert (res.risk_score or 0.0) < 50.0

    # Latency budget check (< 1.5 ms mean over 200 calls across mixed benign & multi-param requests)
    t0 = time.perf_counter()
    for i in range(200):
        q = benign_query if i % 2 == 0 else "q=clean+architecture&category=books&page=1&limit=20"
        detector.predict_http("/api/v1/books", query_params=q, body=None)
    mean_ms = ((time.perf_counter() - t0) * 1000.0) / 200.0
    assert mean_ms < 1.5, f"predict_http mean latency {mean_ms:.3f}ms exceeds 1.5ms budget"

