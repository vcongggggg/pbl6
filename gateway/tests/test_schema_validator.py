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
    # role in user profile update must be user, moderator, or admin
    body = json.dumps({
        "email": "user@example.com",
        "role": "super_root_hacker",
    }).encode("utf-8")
    violations = validator.validate_request(
        method="POST",
        path="/api/v1/vulnerable/users/profile/update/",
        body_bytes=body,
        content_type="application/json",
    )
    assert len(violations) == 1
    assert violations[0].violation_type == "ENUM_MISMATCH"
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
    """Verifies that schema violations are blocked immediately in strict mode."""
    with patch.object(get_settings(), "schema_validation_enabled", True),          patch.object(get_settings(), "schema_strict_mode", True):

        # Missing required parameter 'q'
        res = client.get("/api/proxy/api/v1/vulnerable/books/search/")
        assert res.status_code == 400
        data = res.json()
        assert data["blocked"] is True
        assert data["status"] == 400
        assert "violations" in data
        assert any(v["field"] == "q" for v in data["violations"])
        assert res.headers.get("X-WAF-Schema-Violation") == "1"


def test_proxy_positive_security_flag_disabled(client: TestClient):
    """Verifies that when flag is disabled, schema validation is bypassed (backward compatibility)."""
    with patch.object(get_settings(), "schema_validation_enabled", False):
        # Even with missing parameter, doesn't return 400 from schema validation
        res = client.get("/api/proxy/api/v1/vulnerable/books/search/")
        assert res.headers.get("X-WAF-Schema-Violation") is None
