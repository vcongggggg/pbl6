"""OpenAPI Schema Validator for Positive Security Model (Master Plan B1 & Phase D3).

Enforces schema contracts by validating HTTP methods, path routes, query parameters,
and request body payloads against OpenAPI 3.0 specification with Route-Tiered Policy.
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

# Common pagination / query filtering parameters allowed in telemetry mode
_PAGINATION_TELEMETRY_PARAMS = {
    "page",
    "limit",
    "offset",
    "sort",
    "order",
    "search",
    "p",
    "page_size",
}

# Sensitive endpoints where additionalProperties=False is strictly locked
_SENSITIVE_ENDPOINT_PREFIXES = (
    "/api/v1/vulnerable/users/profile/update",
    "/api/v1/vulnerable/auth/login",
    "/api/v1/vulnerable/admin",
    "/users/profile/update",
    "/auth/login",
    "/admin",
)


@dataclass(frozen=True, slots=True)
class SchemaViolation:
    """Represents a specific violation against the OpenAPI schema contract."""

    field: str
    reason: str
    violation_type: str
    is_penalty: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "reason": self.reason,
            "violation_type": self.violation_type,
            "is_penalty": self.is_penalty,
        }


# Canonical Target API OpenAPI Spec Fallback (ensures offline reliability & synced with Bookie)
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
                                "additionalProperties": False,
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
                    },
                    {"name": "page", "in": "query", "required": False, "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}},
                    {"name": "offset", "in": "query", "required": False, "schema": {"type": "integer"}},
                    {"name": "sort", "in": "query", "required": False, "schema": {"type": "string"}},
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
                    },
                    {"name": "page", "in": "query", "required": False, "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}},
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
                                    "rating": {"type": "integer"},
                                    "review_text": {"type": "string"},
                                },
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
                                "additionalProperties": False,
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
                                    "status": {
                                        "type": "string",
                                        "enum": ["pending", "paid", "shipped", "cancelled"],
                                    },
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
                                "additionalProperties": False,
                                "properties": {
                                    "email": {"type": "string"},
                                },
                            }
                        }
                    },
                },
            }
        },
        "/api/v1/vulnerable/users/list/": {
            "get": {
                "summary": "List Users",
                "responses": {"200": {"description": "User account listing"}},
            }
        },
        "/api/v1/vulnerable/openapi.json": {
            "get": {
                "summary": "OpenAPI 3.0 Specification",
                "responses": {"200": {"description": "OpenAPI JSON contract"}},
            }
        },
        "/api/v1/vulnerable/docs/": {
            "get": {
                "summary": "Swagger UI Documentation",
                "responses": {"200": {"description": "Interactive API docs"}},
            }
        },
    },
}


def _derive_strict_prefixes(spec: dict[str, Any]) -> tuple[str, ...]:
    """Derives top-level route prefixes from an OpenAPI spec's paths."""
    prefixes: list[str] = []
    for raw_path in spec.get("paths", {}):
        stripped = str(raw_path).strip("/")
        if not stripped:
            continue
        top = "/" + stripped.split("/")[0]
        if top not in prefixes:
            prefixes.append(top)
    return tuple(prefixes) if prefixes else ("/",)


def _matches_prefix(path: str, prefix: str) -> bool:
    """Checks segment-aligned path prefix match."""
    clean_pref = "/" + prefix.strip("/")
    if clean_pref == "/":
        return True
    return path == clean_pref or path.startswith(clean_pref + "/")


class SchemaValidator:
    """Validates incoming requests against OpenAPI specification with Route-Tiered Policy."""

    def __init__(
        self,
        target_api_url: str = "http://vulnerable-api:5000",
        cache_ttl_seconds: int = 600,
        spec: dict[str, Any] | None = None,
        enforcement_policy: str = "route_tiered",
        strict_route_prefixes: tuple[str, ...] | None = None,
    ) -> None:
        self.target_api_url = target_api_url.rstrip("/")
        self.cache_ttl_seconds = cache_ttl_seconds
        self.enforcement_policy = enforcement_policy
        self._spec: dict[str, Any] = spec or BUILTIN_TARGET_SPEC
        self._explicit_strict_route_prefixes: tuple[str, ...] | None = (
            tuple(strict_route_prefixes) if strict_route_prefixes is not None else None
        )
        self.strict_route_prefixes: tuple[str, ...] = self._resolve_strict_prefixes(spec)
        self._last_fetch: float = time.time() if spec else 0.0
        self._compiled_paths: list[tuple[re.Pattern[str], str, dict[str, Any]]] = []
        self._compile_path_patterns()

    def _resolve_strict_prefixes(self, spec: dict[str, Any] | None) -> tuple[str, ...]:
        if self._explicit_strict_route_prefixes is not None:
            return self._explicit_strict_route_prefixes
        if spec is None or spec is BUILTIN_TARGET_SPEC:
            return ("/api/v1/vulnerable",)
        return _derive_strict_prefixes(spec)

    def set_spec(self, spec: dict[str, Any]) -> None:
        """Explicitly sets OpenAPI schema specification and re-compiles paths."""
        self._spec = spec
        self.strict_route_prefixes = self._resolve_strict_prefixes(spec)
        self._last_fetch = time.time()
        self._compile_path_patterns()

    def _compile_path_patterns(self) -> None:
        """Converts OpenAPI paths like '/orders/{order_id}/' to compiled regular expressions."""
        paths = self._spec.get("paths", {})
        compiled: list[tuple[re.Pattern[str], str, dict[str, Any]]] = []

        for raw_path, operations in paths.items():
            pattern_str = "^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", raw_path.rstrip("/")) + "/?$"
            regex = re.compile(pattern_str, re.IGNORECASE)
            compiled.append((regex, raw_path, operations))

        self._compiled_paths = compiled

    def _match_path(self, path: str) -> tuple[str, dict[str, Any], dict[str, str]] | None:
        """Finds matching OpenAPI path template and captured path parameters."""
        clean_path = "/" + path.strip("/")
        # 1. Exact match attempt
        paths = self._spec.get("paths", {})
        if clean_path in paths:
            return clean_path, paths[clean_path], {}
        if f"{clean_path}/" in paths:
            return f"{clean_path}/", paths[f"{clean_path}/"], {}

        # 2. Regex pattern match for parameterized paths like {order_id}
        for regex, template, ops in self._compiled_paths:
            m = regex.match(clean_path)
            if m:
                return template, ops, m.groupdict()

        return None

    def validate_request(
        self,
        method: str,
        path: str,
        query_params: str | dict[str, Any] | None = None,
        body_bytes: bytes | None = None,
        content_type: str | None = None,
        policy: str | None = None,
    ) -> list[SchemaViolation]:
        """Validates HTTP request parameters and payload against OpenAPI specification."""
        effective_policy = (policy or self.enforcement_policy).lower()
        if effective_policy == "off":
            return []

        violations: list[SchemaViolation] = []
        clean_method = method.lower()
        normalized_path = "/" + path.strip("/")

        matched = self._match_path(normalized_path)
        if not matched:
            if effective_policy == "route_tiered":
                # Route not in spec in route_tiered mode: telemetry notice only (0 penalty)
                violations.append(
                    SchemaViolation(
                        field="path",
                        reason=f"Path '{normalized_path}' is undocumented in target OpenAPI contract.",
                        violation_type="UNDOCUMENTED_ROUTE",
                        is_penalty=False,
                    )
                )
            elif effective_policy == "strict_all":
                if any(_matches_prefix(normalized_path, pref) for pref in self.strict_route_prefixes):
                    violations.append(
                        SchemaViolation(
                            field="path",
                            reason=f"Path '{normalized_path}' is not defined in target OpenAPI schema.",
                            violation_type="ROUTE_NOT_FOUND",
                            is_penalty=True,
                        )
                    )
            return violations

        template_path, operations, path_params = matched

        if clean_method not in operations:
            allowed_methods = [m.upper() for m in operations if m in {"get", "post", "put", "patch", "delete"}]
            violations.append(
                SchemaViolation(
                    field="method",
                    reason=f"Method '{method.upper()}' not allowed for path '{template_path}'. Allowed: {allowed_methods}",
                    violation_type="METHOD_NOT_ALLOWED",
                    is_penalty=True,
                )
            )
            return violations

        operation_spec = operations[clean_method]

        # 1. Validate Path Parameters
        violations.extend(self._validate_path_params(operation_spec, path_params))

        # 2. Validate Query Parameters
        violations.extend(self._validate_query_params(operation_spec, query_params, effective_policy))

        # 3. Validate Request Body
        violations.extend(self._validate_request_body(operation_spec, body_bytes, content_type, template_path, effective_policy))

        return violations

    def _validate_path_params(
        self,
        op_spec: dict[str, Any],
        path_params: dict[str, str],
    ) -> list[SchemaViolation]:
        violations: list[SchemaViolation] = []
        declared_params = op_spec.get("parameters", [])

        for param in declared_params:
            if param.get("in") != "path":
                continue

            param_name = param.get("name", "")
            param_schema = param.get("schema", {})
            param_type = param_schema.get("type", "string")
            val = path_params.get(param_name)

            if val is not None:
                if param_type == "integer":
                    if not re.match(r"^-?\d+$", val.strip()):
                        violations.append(
                            SchemaViolation(
                                field=param_name,
                                reason=f"Path parameter '{param_name}' expected integer, got '{val}'.",
                                violation_type="TYPE_MISMATCH",
                                is_penalty=True,
                            )
                        )
                elif param_type == "number":
                    try:
                        float(val.strip())
                    except ValueError:
                        violations.append(
                            SchemaViolation(
                                field=param_name,
                                reason=f"Path parameter '{param_name}' expected number, got '{val}'.",
                                violation_type="TYPE_MISMATCH",
                                is_penalty=True,
                            )
                        )

        return violations

    @staticmethod
    def _validate_string_scalar(
        field_name: str,
        val: str,
        schema: dict[str, Any],
        label: str,
    ) -> list[SchemaViolation]:
        """Validates string-encoded scalar constraints (type, enum, maxLength, pattern)."""
        violations: list[SchemaViolation] = []
        expected_type = schema.get("type", "string")

        if expected_type == "integer":
            if not re.match(r"^-?\d+$", val.strip()):
                violations.append(
                    SchemaViolation(
                        field=field_name,
                        reason=f"{label} '{field_name}' expected integer, got '{val}'.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )
        elif expected_type == "number":
            try:
                float(val.strip())
            except ValueError:
                violations.append(
                    SchemaViolation(
                        field=field_name,
                        reason=f"{label} '{field_name}' expected number, got '{val}'.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )
        elif expected_type == "boolean":
            if val.lower() not in {"true", "false", "0", "1"}:
                violations.append(
                    SchemaViolation(
                        field=field_name,
                        reason=f"{label} '{field_name}' expected boolean, got '{val}'.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )

        if "enum" in schema and val not in schema["enum"]:
            violations.append(
                SchemaViolation(
                    field=field_name,
                    reason=f"{label} '{field_name}' value '{val}' not in allowed enum {schema['enum']}.",
                    violation_type="ENUM_MISMATCH",
                    is_penalty=True,
                )
            )

        if "maxLength" in schema:
            max_len = int(schema["maxLength"])
            if len(val) > max_len:
                violations.append(
                    SchemaViolation(
                        field=field_name,
                        reason=f"{label} '{field_name}' length {len(val)} exceeds maxLength {max_len}.",
                        violation_type="MAX_LENGTH_EXCEEDED",
                        is_penalty=True,
                    )
                )

        if "pattern" in schema:
            pat = str(schema["pattern"])
            if not re.search(pat, val):
                violations.append(
                    SchemaViolation(
                        field=field_name,
                        reason=f"{label} '{field_name}' value does not match pattern '{pat}'.",
                        violation_type="PATTERN_MISMATCH",
                        is_penalty=True,
                    )
                )

        return violations

    def _validate_query_params(
        self,
        op_spec: dict[str, Any],
        query_params: str | dict[str, Any] | None,
        policy: str = "route_tiered",
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

            if param_name not in parsed_query or not parsed_query[param_name]:
                if is_required:
                    violations.append(
                        SchemaViolation(
                            field=param_name,
                            reason=f"Required query parameter '{param_name}' is missing.",
                            violation_type="MISSING_PARAMETER",
                            is_penalty=True,
                        )
                    )
                continue

            for val in parsed_query[param_name]:
                violations.extend(
                    self._validate_string_scalar(param_name, val, param_schema, "Query parameter")
                )

        # Validate undeclared query parameters according to enforcement policy
        declared_param_names = {p.get("name", "") for p in declared_params if p.get("in") == "query"}
        for qp in parsed_query:
            if qp not in declared_param_names:
                if policy == "strict_all":
                    violations.append(
                        SchemaViolation(
                            field=qp,
                            reason=f"Query parameter '{qp}' is not declared in OpenAPI contract.",
                            violation_type="UNDECLARED_PARAMETER",
                            is_penalty=True,
                        )
                    )
                elif qp in _PAGINATION_TELEMETRY_PARAMS:
                    # Permitted without penalty under route_tiered policy
                    pass
                elif policy == "route_tiered":
                    violations.append(
                        SchemaViolation(
                            field=qp,
                            reason=f"Query parameter '{qp}' is not declared in OpenAPI contract.",
                            violation_type="UNDECLARED_PARAMETER",
                            is_penalty=False,
                        )
                    )

        return violations

    def _validate_request_body(
        self,
        op_spec: dict[str, Any],
        body_bytes: bytes | None,
        content_type: str | None,
        template_path: str = "",
        policy: str = "route_tiered",
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
                    is_penalty=True,
                )
            )
            return violations

        if not has_content:
            return violations

        content_spec = req_body_spec.get("content", {})
        if not content_spec:
            return violations

        selected_ct = self._select_request_content_type(content_spec, content_type, body_bytes)
        if selected_ct is None:
            violations.append(
                SchemaViolation(
                    field="content-type",
                    reason=(
                        f"Content-Type '{content_type}' is not supported. "
                        f"Expected one of {list(content_spec.keys())}."
                    ),
                    violation_type="UNSUPPORTED_MEDIA_TYPE",
                    is_penalty=True,
                )
            )
            return violations

        media_spec = content_spec.get(selected_ct, {})
        schema = media_spec.get("schema")
        if not schema:
            return violations

        if selected_ct == "application/x-www-form-urlencoded":
            return self._validate_form_body(schema, body_bytes, template_path, policy)

        try:
            body_json = json.loads(body_bytes.decode("utf-8", errors="replace"))  # type: ignore
        except Exception:
            violations.append(
                SchemaViolation(
                    field="body",
                    reason="Invalid JSON format in request body.",
                    violation_type="INVALID_JSON",
                    is_penalty=True,
                )
            )
            return violations

        if not isinstance(body_json, dict):
            violations.append(
                SchemaViolation(
                    field="body",
                    reason=f"Expected JSON object in request body, got {type(body_json).__name__}.",
                    violation_type="TYPE_MISMATCH",
                    is_penalty=True,
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
                        is_penalty=True,
                    )
                )

        properties = schema.get("properties", {})
        if self._should_lock_additional(schema, template_path, policy) and properties:
            for extra_key in body_json.keys():
                if extra_key not in properties:
                    violations.append(
                        SchemaViolation(
                            field=extra_key,
                            reason=f"Additional property '{extra_key}' is not allowed on endpoint '{template_path}'.",
                            violation_type="ADDITIONAL_PROPERTY_NOT_ALLOWED",
                            is_penalty=True,
                        )
                    )

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
                        is_penalty=True,
                    )
                )
            elif expected_type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected integer, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )
            elif expected_type == "number" and (not isinstance(val, (int, float)) or isinstance(val, bool)):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected number, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )
            elif expected_type == "boolean" and not isinstance(val, bool):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected boolean, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )
            elif expected_type == "array" and not isinstance(val, list):
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' expected array, got {type(val).__name__}.",
                        violation_type="TYPE_MISMATCH",
                        is_penalty=True,
                    )
                )

            if "enum" in prop_schema and val not in prop_schema["enum"]:
                violations.append(
                    SchemaViolation(
                        field=prop_name,
                        reason=f"Field '{prop_name}' value '{val}' is not in allowed enum {prop_schema['enum']}.",
                        violation_type="ENUM_MISMATCH",
                        is_penalty=True,
                    )
                )

            if isinstance(val, str):
                if "maxLength" in prop_schema and len(val) > int(prop_schema["maxLength"]):
                    violations.append(
                        SchemaViolation(
                            field=prop_name,
                            reason=f"Field '{prop_name}' length {len(val)} exceeds maxLength {prop_schema['maxLength']}.",
                            violation_type="MAX_LENGTH_EXCEEDED",
                            is_penalty=True,
                        )
                    )
                if "pattern" in prop_schema and not re.search(str(prop_schema["pattern"]), val):
                    violations.append(
                        SchemaViolation(
                            field=prop_name,
                            reason=f"Field '{prop_name}' value does not match pattern '{prop_schema['pattern']}'.",
                            violation_type="PATTERN_MISMATCH",
                            is_penalty=True,
                        )
                    )

        return violations

    @staticmethod
    def _should_lock_additional(schema: dict[str, Any], template_path: str, policy: str) -> bool:
        is_sensitive_endpoint = any(template_path.startswith(pref) for pref in _SENSITIVE_ENDPOINT_PREFIXES)
        explicit_disallow = schema.get("additionalProperties") is False
        return explicit_disallow or (is_sensitive_endpoint and policy == "route_tiered") or (policy == "strict_all")

    @staticmethod
    def _select_request_content_type(
        content_spec: dict[str, Any],
        content_type: str | None,
        body_bytes: bytes | None,
    ) -> str | None:
        if content_type:
            ct_base = content_type.split(";")[0].strip().lower()
            for declared_ct in content_spec:
                if declared_ct.lower() == ct_base or declared_ct.lower() in ct_base:
                    return declared_ct
            return None

        has_json = "application/json" in content_spec
        has_form = "application/x-www-form-urlencoded" in content_spec
        if has_form and not has_json:
            return "application/x-www-form-urlencoded"
        if has_form and has_json:
            if body_bytes and body_bytes.lstrip().startswith((b"{", b"[")):
                return "application/json"
            if body_bytes and b"=" in body_bytes:
                return "application/x-www-form-urlencoded"
            return "application/json"
        if has_json:
            return "application/json"
        return next(iter(content_spec), None)

    def _validate_form_body(
        self,
        schema: dict[str, Any],
        body_bytes: bytes | None,
        template_path: str,
        policy: str,
    ) -> list[SchemaViolation]:
        violations: list[SchemaViolation] = []
        body_str = (body_bytes or b"").decode("utf-8", errors="replace")
        parsed_form = parse_qs(body_str, keep_blank_values=True)

        for req_field in schema.get("required", []):
            if req_field not in parsed_form or not parsed_form[req_field]:
                violations.append(
                    SchemaViolation(
                        field=req_field,
                        reason=f"Required form field '{req_field}' is missing in request body.",
                        violation_type="MISSING_FIELD",
                        is_penalty=True,
                    )
                )

        properties = schema.get("properties", {})
        if self._should_lock_additional(schema, template_path, policy) and properties:
            for extra_key in parsed_form:
                if extra_key not in properties:
                    violations.append(
                        SchemaViolation(
                            field=extra_key,
                            reason=f"Additional form property '{extra_key}' is not allowed on endpoint '{template_path}'.",
                            violation_type="ADDITIONAL_PROPERTY_NOT_ALLOWED",
                            is_penalty=True,
                        )
                    )

        for prop_name, prop_schema in properties.items():
            if prop_name not in parsed_form:
                continue
            for val in parsed_form[prop_name]:
                violations.extend(
                    self._validate_string_scalar(prop_name, val, prop_schema, "Form field")
                )

        return violations

    async def refresh_spec_from_target(self, client: Any | None = None) -> bool:
        """Fetches live OpenAPI specification from target API upstream with TTL cache and fallback."""
        now = time.time()
        if self._last_fetch and (now - self._last_fetch) < self.cache_ttl_seconds:
            return True

        close_client = False
        if client is None:
            import httpx

            client = httpx.AsyncClient(timeout=3.0)
            close_client = True

        try:
            for endpoint in ["/api/schema/", "/openapi.json", "/api/v1/schema/"]:
                url = f"{self.target_api_url}{endpoint}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict) and "paths" in data:
                            self.set_spec(data)
                            logger.info(f"Refreshed OpenAPI spec from {url}")
                            return True
                except Exception:
                    continue
        except Exception as err:
            logger.warning(f"Failed to refresh OpenAPI spec from target upstream: {err}")
        finally:
            if close_client:
                await client.aclose()
        return False
