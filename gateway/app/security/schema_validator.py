"""OpenAPI Schema Validator for Positive Security Model (Master Plan B1).

Enforces schema contracts by validating HTTP methods, path routes, query parameters,
and request body payloads against OpenAPI 3.0 specification.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

logger = logging.getLogger("waf.gateway.security.schema_validator")


@dataclass(frozen=True, slots=True)
class SchemaViolation:
    """Represents a specific violation against the OpenAPI schema contract."""

    field: str
    reason: str
    violation_type: str

    def to_dict(self) -> dict[str, str]:
        return {
            "field": self.field,
            "reason": self.reason,
            "violation_type": self.violation_type,
        }


# Canonical Target API OpenAPI Spec Fallback (ensures offline reliability)
BUILTIN_TARGET_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {
        "title": "Bookie Bookstore Vulnerable API",
        "version": "1.0.0",
    },
    "paths": {
        "/api/v1/vulnerable/auth/login/": {
            "post": {
                "summary": "User & Admin Authentication",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                },
                                "required": ["username", "password"],
                            }
                        }
                    },
                },
            }
        },
        "/api/v1/vulnerable/books/search/": {
            "get": {
                "summary": "Search Books Catalog",
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
            }
        },
        "/api/v1/vulnerable/reviews/": {
            "get": {
                "summary": "Get Book Reviews",
                "parameters": [
                    {
                        "name": "book_id",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer"},
                    }
                ],
            },
            "post": {
                "summary": "Submit Book Review",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "book_id": {"type": "integer"},
                                    "author": {"type": "string"},
                                    "comment": {"type": "string"},
                                },
                                "required": ["author", "comment"],
                            }
                        }
                    },
                },
            },
        },
        "/api/v1/vulnerable/files/download/": {
            "get": {
                "summary": "Download System Document",
                "parameters": [
                    {
                        "name": "file",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
            }
        },
        "/api/v1/vulnerable/admin/ping/": {
            "post": {
                "summary": "Network Diagnostics Tool",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "host": {"type": "string"},
                                },
                                "required": ["host"],
                            }
                        }
                    },
                },
            }
        },
        "/api/v1/vulnerable/orders/{order_id}/": {
            "get": {
                "summary": "Order Detail",
                "parameters": [
                    {
                        "name": "order_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
            },
            "patch": {
                "summary": "Modify Order",
                "parameters": [
                    {
                        "name": "order_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {"type": "string"},
                                    "shipping_address": {"type": "string"},
                                },
                            }
                        }
                    },
                },
            },
        },
        "/api/v1/vulnerable/books/fetch-cover/": {
            "get": {
                "summary": "Fetch Book Cover",
                "parameters": [
                    {
                        "name": "url",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
            }
        },
        "/api/v1/vulnerable/users/profile/update/": {
            "post": {
                "summary": "Update Profile",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "email": {"type": "string"},
                                    "role": {"type": "string", "enum": ["user", "moderator", "admin"]},
                                },
                            }
                        }
                    },
                },
            }
        },
    },
}


class SchemaValidator:
    """Validates incoming requests against OpenAPI specification."""

    def __init__(
        self,
        target_api_url: str = "http://vulnerable-api:5000",
        cache_ttl_seconds: int = 600,
        spec: dict[str, Any] | None = None,
    ) -> None:
        self.target_api_url = target_api_url.rstrip("/")
        self.cache_ttl_seconds = cache_ttl_seconds
        self._spec: dict[str, Any] = spec or BUILTIN_TARGET_SPEC
        self._last_fetch: float = time.time() if spec else 0.0
        self._compiled_paths: list[tuple[re.Pattern[str], str, dict[str, Any]]] = []
        self._compile_path_patterns()

    def set_spec(self, spec: dict[str, Any]) -> None:
        """Explicitly sets OpenAPI schema specification and re-compiles paths."""
        self._spec = spec
        self._last_fetch = time.time()
        self._compile_path_patterns()

    def _compile_path_patterns(self) -> None:
        """Converts OpenAPI paths like '/orders/{order_id}/' to compiled regular expressions."""
        paths = self._spec.get("paths", {})
        compiled: list[tuple[re.Pattern[str], str, dict[str, Any]]] = []

        for raw_path, operations in paths.items():
            pattern_str = "^" + re.sub(r"\{[^}]+\}", r"([^/]+)", raw_path.rstrip("/")) + "/?$"
            regex = re.compile(pattern_str, re.IGNORECASE)
            compiled.append((regex, raw_path, operations))

        self._compiled_paths = compiled

    def _match_path(self, path: str) -> tuple[str, dict[str, Any]] | None:
        """Finds matching OpenAPI path template for an incoming request path."""
        clean_path = "/" + path.strip("/")
        # 1. Exact match attempt
        paths = self._spec.get("paths", {})
        if clean_path in paths:
            return clean_path, paths[clean_path]
        if f"{clean_path}/" in paths:
            return f"{clean_path}/", paths[f"{clean_path}/"]

        # 2. Regex pattern match for parameterized paths like {order_id}
        for regex, template, ops in self._compiled_paths:
            if regex.match(clean_path):
                return template, ops

        return None

    def validate_request(
        self,
        method: str,
        path: str,
        query_params: str | dict[str, Any] | None = None,
        body_bytes: bytes | None = None,
        content_type: str | None = None,
    ) -> list[SchemaViolation]:
        """Validates HTTP request parameters and payload against OpenAPI specification."""
        violations: list[SchemaViolation] = []
        clean_method = method.lower()

        normalized_path = "/" + path.strip("/")

        matched = self._match_path(normalized_path)
        if not matched:
            if normalized_path.startswith("/api/v1/vulnerable"):
                violations.append(
                    SchemaViolation(
                        field="path",
                        reason=f"Path '{normalized_path}' is not defined in target OpenAPI schema.",
                        violation_type="ROUTE_NOT_FOUND",
                    )
                )
            return violations

        template_path, operations = matched

        if clean_method not in operations:
            allowed_methods = [m.upper() for m in operations if m in {"get", "post", "put", "patch", "delete"}]
            violations.append(
                SchemaViolation(
                    field="method",
                    reason=f"Method '{method.upper()}' not allowed for path '{template_path}'. Allowed: {allowed_methods}",
                    violation_type="METHOD_NOT_ALLOWED",
                )
            )
            return violations

        operation_spec = operations[clean_method]

        # 1. Validate Query Parameters
        violations.extend(self._validate_query_params(operation_spec, query_params))

        # 2. Validate Request Body
        violations.extend(self._validate_request_body(operation_spec, body_bytes, content_type))

        return violations

    def _validate_query_params(
        self,
        op_spec: dict[str, Any],
        query_params: str | dict[str, Any] | None,
    ) -> list[SchemaViolation]:
        violations: list[SchemaViolation] = []
        declared_params = op_spec.get("parameters", [])

        parsed_query: dict[str, list[str]] = {}
        if isinstance(query_params, str) and query_params:
            parsed_query = parse_qs(query_params, keep_blank_values=True)
        elif isinstance(query_params, dict):
            for k, v in query_params.items():
                parsed_query[k] = [str(v)] if not isinstance(v, list) else [str(x) for x in v]

        for param in declared_params:
            if param.get("in") != "query":
                continue

            param_name = param.get("name", "")
            is_required = bool(param.get("required", False))
            param_schema = param.get("schema", {})
            param_type = param_schema.get("type", "string")

            if param_name not in parsed_query or not parsed_query[param_name]:
                if is_required:
                    violations.append(
                        SchemaViolation(
                            field=param_name,
                            reason=f"Required query parameter '{param_name}' is missing.",
                            violation_type="MISSING_PARAMETER",
                        )
                    )
                continue

            val = parsed_query[param_name][0]

            if param_type == "integer":
                if not re.match(r"^-?\d+$", val.strip()):
                    violations.append(
                        SchemaViolation(
                            field=param_name,
                            reason=f"Query parameter '{param_name}' expected integer, got '{val}'.",
                            violation_type="TYPE_MISMATCH",
                        )
                    )
            elif param_type == "number":
                try:
                    float(val.strip())
                except ValueError:
                    violations.append(
                        SchemaViolation(
                            field=param_name,
                            reason=f"Query parameter '{param_name}' expected number, got '{val}'.",
                            violation_type="TYPE_MISMATCH",
                        )
                    )
            elif param_type == "boolean":
                if val.lower() not in {"true", "false", "0", "1"}:
                    violations.append(
                        SchemaViolation(
                            field=param_name,
                            reason=f"Query parameter '{param_name}' expected boolean, got '{val}'.",
                            violation_type="TYPE_MISMATCH",
                        )
                    )

            if "enum" in param_schema and val not in param_schema["enum"]:
                violations.append(
                    SchemaViolation(
                        field=param_name,
                        reason=f"Query parameter '{param_name}' value '{val}' not in allowed enum {param_schema['enum']}.",
                        violation_type="ENUM_MISMATCH",
                    )
                )

        return violations

    def _validate_request_body(
        self,
        op_spec: dict[str, Any],
        body_bytes: bytes | None,
        content_type: str | None,
    ) -> list[SchemaViolation]:
        violations: list[SchemaViolation] = []
        req_body_spec = op_spec.get("requestBody")
        if not req_body_spec:
            return violations

        is_required = bool(req_body_spec.get("required", False))
        has_content = bool(body_bytes and body_bytes.strip())

        if is_required and not has_content:
            violations.append(
                SchemaViolation(
                    field="body",
                    reason="Request body is required but empty payload was received.",
                    violation_type="MISSING_BODY",
                )
            )
            return violations

        if not has_content:
            return violations

        content_spec = req_body_spec.get("content", {})
        json_spec = content_spec.get("application/json", {})
        schema = json_spec.get("schema")
        if not schema:
            return violations

        try:
            body_json = json.loads(body_bytes.decode("utf-8", errors="replace"))  # type: ignore
        except Exception:
            violations.append(
                SchemaViolation(
                    field="body",
                    reason="Invalid JSON format in request body.",
                    violation_type="INVALID_JSON",
                )
            )
            return violations

        if not isinstance(body_json, dict):
            violations.append(
                SchemaViolation(
                    field="body",
                    reason=f"Expected JSON object in request body, got {type(body_json).__name__}.",
                    violation_type="TYPE_MISMATCH",
                )
            )
            return violations

        required_fields = schema.get("required", [])
        for req_field in required_fields:
            if req_field not in body_json or body_json[req_field] is None:
                violations.append(
                    SchemaViolation(
                        field=req_field,
                        reason=f"Required JSON field '{req_field}' is missing in request body.",
                        violation_type="MISSING_FIELD",
                    )
                )

        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if prop_name not in body_json:
                continue

            val = body_json[prop_name]
            expected_type = prop_schema.get("type")

            if expected_type == "string" and not isinstance(val, str):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected string, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                    )
                )
            elif expected_type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected integer, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                    )
                )
            elif expected_type == "number" and (not isinstance(val, (int, float)) or isinstance(val, bool)):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected number, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                    )
                )
            elif expected_type == "boolean" and not isinstance(val, bool):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected boolean, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                    )
                )
            elif expected_type == "array" and not isinstance(val, list):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected array, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                    )
                )

            if "enum" in prop_schema and val not in prop_schema["enum"]:
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' value '{val}' is not in allowed enum {prop_schema['enum']}.",
                        violation_type="ENUM_MISMATCH",
                    )
                )

        return violations
