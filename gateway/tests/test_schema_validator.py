"""Tests for Positive Security Model: OpenAPI Schema Validation (Master Plan B1)."""

import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.security.schema_validator import SchemaValidator


def test_schema_validator_clean_query():
    validator = SchemaValidator()
    violations = validator.validate_request(
        method="GET",
        path="/api/v1/vulnerable/books/search/",
        query_params="q=clean+search+query",
    )
    assert len(violations) == 0


def test_schema_validator_missing_required_param():
    validator = SchemaValidator()
    violations = validator.validate_request(
        method="GET",
        path="/api/v1/vulnerable/books/search/",
        query_params="",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "MISSING_PARAMETER"
    assert violations[0].field == "q"


def test_schema_validator_query_type_mismatch():
    validator = SchemaValidator()
    # book_id is expected to be integer
    violations = validator.validate_request(
        method="GET",
        path="/api/v1/vulnerable/reviews/",
        query_params="book_id=abc_not_an_int",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "TYPE_MISMATCH"
    assert violations[0].field == "book_id"


def test_schema_validator_clean_json_body():
    validator = SchemaValidator()
    body = json.dumps({"username": "alice", "password": "password123"}).encode("utf-8")
    violations = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/auth/login/",
        body_bytes=body,
        content_type="application/json",
    )
    assert len(violations) == 0


def test_schema_validator_missing_required_body_field():
    validator = SchemaValidator()
    # password is required
    body = json.dumps({"username": "alice"}).encode("utf-8")
    violations = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/auth/login/",
        body_bytes=body,
        content_type="application/json",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "MISSING_FIELD"
    assert violations[0].field == "password"


def test_schema_validator_invalid_json():
    validator = SchemaValidator()
    violations = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/auth/login/",
        body_bytes=b"invalid-json-payload-{{{",
        content_type="application/json",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "INVALID_JSON"


def test_schema_validator_body_type_mismatch():
    validator = SchemaValidator()
    # book_id should be integer, comment and author should be string
    body = json.dumps({
        "book_id": "not_an_int",
        "author": "Alice",
        "comment": "Nice book",
    }).encode("utf-8")
    violations = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/reviews/",
        body_bytes=body,
        content_type="application/json",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "TYPE_MISMATCH"
    assert violations[0].field == "book_id"


def test_schema_validator_enum_mismatch():
    validator = SchemaValidator()
    # status in order modification must be pending, paid, shipped, or cancelled
    body = json.dumps({
        "status": "illegal_forged_state",
        "shipping_address": "123 Street",
    }).encode("utf-8")
    violations = validator.validate_request(
        method="PATCH",
        path="/api/v1/vulnerable/orders/1/",
        body_bytes=body,
        content_type="application/json",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "ENUM_MISMATCH"
    assert violations[0].field == "status"


def test_schema_validator_profile_role_property_forbidden():
    validator = SchemaValidator()
    # 'role' has been completely removed from self-service profile update schema (Phase A3)
    body = json.dumps({
        "email": "user@example.com",
        "role": "admin",
    }).encode("utf-8")
    violations = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/users/profile/update/",
        body_bytes=body,
        content_type="application/json",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "ADDITIONAL_PROPERTY_NOT_ALLOWED"
    assert violations[0].field == "role"


def test_schema_validator_method_not_allowed():
    validator = SchemaValidator()
    violations = validator.validate_request(
        method="DELETE",
        path="/api/v1/vulnerable/books/search/",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "METHOD_NOT_ALLOWED"


def test_proxy_positive_security_strict_mode(client: TestClient):
    """Verifies that schema violations are blocked immediately in strict mode under ACTIVE_BLOCKING."""
    from app.db.models import WafConfigModel
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        prev_mode = cfg.value if cfg else None
        if cfg:
            cfg.value = "ACTIVE_BLOCKING"
        else:
            db.add(WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING"))
        db.commit()

    try:
        with patch.object(get_settings(), "schema_validation_enabled", True), \
             patch.object(get_settings(), "schema_strict_mode", True):

            # Missing required parameter 'q'
            res = client.get("/api/proxy/api/v1/vulnerable/books/search/")
            assert res.status_code == 400
            data = res.json()
            assert data["blocked"] is True
            assert data["status"] == 400
            assert "violations" in data
            assert any(v["field"] == "q" for v in data["violations"])
            assert res.headers.get("X-WAF-Schema-Violation") == "1"
    finally:
        with SessionLocal() as db:
            cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
            if prev_mode is None and cfg is not None:
                db.delete(cfg)
            elif cfg is not None:
                cfg.value = prev_mode
            db.commit()


def test_proxy_positive_security_flag_disabled(client: TestClient):
    """Verifies that when flag is disabled, schema validation is bypassed (backward compatibility)."""
    with patch.object(get_settings(), "schema_validation_enabled", False):
        # Even with missing parameter, doesn't return 400 from schema validation
        res = client.get("/api/proxy/api/v1/vulnerable/books/search/")
        assert res.headers.get("X-WAF-Schema-Violation") is None


def test_c3_fp_tuning_root_anomaly_and_openapi_routes():
    """Phase C3: Verifies 0.0 anomaly score on bare root '/' and valid schema on /openapi.json & /reviews/."""
    from app.security.anomaly import AnomalyDetector
    from app.security.ml_detector import extract_26_from_http

    anom = AnomalyDetector()
    assert anom.is_loaded is True
    vec_root = extract_26_from_http(path="/", query_params=None, body=None).tolist()
    res_root = anom.predict("/", feature_vector=vec_root)
    assert res_root.is_anomaly is False
    assert res_root.anomaly_score == 0.0

    validator = SchemaValidator()
    assert validator.validate_request(method="GET", path="/api/v1/vulnerable/openapi.json") == []
    assert validator.validate_request(method="GET", path="/api/v1/vulnerable/docs/") == []
    body_rev = json.dumps({"book_id": 10, "rating": 5, "review_text": "Excellent reference"}).encode("utf-8")
    assert (
        validator.validate_request(
            method="POST",
            path="/api/v1/vulnerable/reviews/",
            body_bytes=body_rev,
            content_type="application/json",
        )
        == []
    )


def test_route_tiered_schema_policy():
    """Verifies Phase D3 Route-Tiered Schema enforcement policy."""
    validator = SchemaValidator(enforcement_policy="route_tiered")

    # 1. Undocumented route receives notice with is_penalty=False
    v_undoc = validator.validate_request(method="GET", path="/unknown/endpoint/path/")
    assert len(v_undoc) == 1
    assert v_undoc[0].violation_type == "UNDOCUMENTED_ROUTE"
    assert v_undoc[0].is_penalty is False

    # 2. Documented search route allows pagination telemetry parameters
    v_search = validator.validate_request(
        method="GET",
        path="/api/v1/vulnerable/books/search/",
        query_params="q=Python&page=2&limit=20&sort=desc",
    )
    assert len(v_search) == 0

    # 3. Sensitive profile update endpoint strictly enforces additionalProperties=False
    v_sensitive = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/users/profile/update/",
        body_bytes=json.dumps({"email": "test@example.com", "role": "admin"}).encode("utf-8"),
        content_type="application/json",
    )
    assert any(v.violation_type == "ADDITIONAL_PROPERTY_NOT_ALLOWED" and v.is_penalty for v in v_sensitive)

    # 4. Off policy bypasses all checks
    assert validator.validate_request(method="POST", path="/invalid/", policy="off") == []

