"""OpenAPI Dynamic Security Test Synthesizer (Sprint 2 / Cyber Range Target-Agnostic).

Parses OpenAPI 3.0 / Swagger attack surfaces or ReconReports to dynamically synthesize
standard OWASP Web & API Top 10 security test cases for the Cyber Range testbed.
Eliminates static path hardcoding by deriving parameter bindings, HTTP verbs, and
request types directly from the target OpenAPI specification.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("attack_lab.synthesizer")

# Default baseline payloads for standard vulnerability families in the Cyber Range
CANONICAL_FAMILY_PAYLOADS: dict[str, dict[str, Any]] = {
    "SQL_INJECTION": {
        "query": "python' UNION SELECT id, username, email, password FROM auth_user --",
        "json": "admin' OR '1'='1",
        "keywords": ["title", "author", "id", "book", "results", "token", "access_token"],
        "campaign": "sqli",
    },
    "AUTH_BYPASS": {
        "json": "admin' OR '1'='1",
        "keywords": ["token", "access_token", "login successful", "welcome"],
        "campaign": "sqli",
        "canonical_family": "SQL_INJECTION",
    },
    "XSS": {
        "json": "<script>alert('PBL6_XSS')</script>",
        "query": "<script>alert('PBL6_XSS')</script>",
        "keywords": ["review", "id", "created", "comment"],
        "campaign": "xss",
    },
    "PATH_TRAVERSAL": {
        "query": "../../bookstore/settings/base.py",
        "path": "../../bookstore/settings/base.py",
        "keywords": ["SECRET_KEY", "root:", "settings", "DEBUG"],
        "campaign": "traversal",
    },
    "COMMAND_INJECTION": {
        "json": "127.0.0.1; whoami",
        "query": "127.0.0.1; whoami",
        "keywords": ["root", "bytes from", "PING", "ttl"],
        "campaign": "cmd",
    },
    "SSRF": {
        "query": "http://127.0.0.1:8000/api/dashboard/stats",
        "json": "http://127.0.0.1:8000/api/dashboard/stats",
        "keywords": ["stats", "status", "success", "metrics", "fetched_url"],
        "campaign": "ssrf",
    },
    "BOLA_IDOR": {
        "path": 1,
        "json": {"status": "cancelled", "shipping_address": "Hacked Address 404"},
        "keywords": ["order", "order_id", "status", "customer", "total_amount"],
        "campaign": "bola",
    },
    "MASS_ASSIGNMENT": {
        "json": "admin",
        "keywords": ["is_staff", "is_superuser", "role", "escalated", "admin"],
        "campaign": "mass_assignment",
    },
    "EXCESSIVE_DATA_EXPOSURE": {
        "query": "",
        "keywords": ["password_hash", "pbkdf2", "hash", "users", "admin"],
        "campaign": "data_exposure",
    },
}

# Fallback test cases if OpenAPI spec is unavailable
FALLBACK_TEST_CASES: list[dict[str, Any]] = [
    {
        "endpoint": "/api/v1/vulnerable/books/search/",
        "method": "GET",
        "family": "SQL_INJECTION",
        "campaign": "sqli",
        "param_name": "q",
        "request_type": "query",
        "baseline_payload": "python' UNION SELECT id, username, email, password FROM auth_user --",
        "extra_fields": {},
        "bypass_keywords": ["title", "author", "id", "book", "results"],
    },
    {
        "endpoint": "/api/v1/vulnerable/auth/login/",
        "method": "POST",
        "family": "SQL_INJECTION",
        "campaign": "sqli",
        "param_name": "username",
        "request_type": "json",
        "baseline_payload": "admin' OR '1'='1",
        "extra_fields": {"password": "password123"},
        "bypass_keywords": ["token", "access_token", "login successful", "welcome"],
    },
    {
        "endpoint": "/api/v1/vulnerable/reviews/",
        "method": "POST",
        "family": "XSS",
        "campaign": "xss",
        "param_name": "comment",
        "request_type": "json",
        "baseline_payload": "<script>alert('PBL6_XSS')</script>",
        "extra_fields": {"book_id": 1, "author": "Attacker"},
        "bypass_keywords": ["review", "id", "created", "comment"],
    },
    {
        "endpoint": "/api/v1/vulnerable/files/download/",
        "method": "GET",
        "family": "PATH_TRAVERSAL",
        "campaign": "traversal",
        "param_name": "file",
        "request_type": "query",
        "baseline_payload": "../../bookstore/settings/base.py",
        "extra_fields": {},
        "bypass_keywords": ["SECRET_KEY", "root:", "settings", "DEBUG"],
    },
    {
        "endpoint": "/api/v1/vulnerable/admin/ping/",
        "method": "POST",
        "family": "COMMAND_INJECTION",
        "campaign": "cmd",
        "param_name": "host",
        "request_type": "json",
        "baseline_payload": "127.0.0.1; whoami",
        "extra_fields": {},
        "bypass_keywords": ["root", "bytes from", "PING", "ttl"],
    },
    {
        "endpoint": "/api/v1/vulnerable/books/fetch-cover/",
        "method": "GET",
        "family": "SSRF",
        "campaign": "ssrf",
        "param_name": "url",
        "request_type": "query",
        "baseline_payload": "http://127.0.0.1:8000/api/dashboard/stats",
        "extra_fields": {},
        "bypass_keywords": ["status", "success", "fetched_url"],
    },
    {
        "endpoint": "/api/v1/vulnerable/orders/{order_id}/",
        "method": "GET",
        "family": "BOLA_IDOR",
        "campaign": "bola",
        "param_name": "order_id",
        "request_type": "path",
        "baseline_payload": "1",
        "extra_fields": {},
        "bypass_keywords": ["order", "order_id", "total_amount"],
    },
    {
        "endpoint": "/api/v1/vulnerable/users/profile/update/",
        "method": "POST",
        "family": "MASS_ASSIGNMENT",
        "campaign": "mass_assignment",
        "param_name": "role",
        "request_type": "json",
        "baseline_payload": "admin",
        "extra_fields": {"user_id": 1, "is_staff": True, "is_superuser": True},
        "bypass_keywords": ["is_staff", "role", "admin"],
    },
]


@dataclass
class SynthesizedTestCase:
    """A single synthesized security test case for the Cyber Range testbed."""

    endpoint: str
    method: str
    family: str
    campaign: str
    param_name: str
    request_type: str  # query, json, path
    baseline_payload: Any
    extra_fields: dict[str, Any] = field(default_factory=dict)
    bypass_keywords: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "family": self.family,
            "campaign": self.campaign,
            "param_name": self.param_name,
            "request_type": self.request_type,
            "baseline_payload": self.baseline_payload,
            "extra_fields": self.extra_fields,
            "bypass_keywords": self.bypass_keywords,
        }


class OpenAPIPayloadSynthesizer:
    """Dynamically parses OpenAPI specs / attack surface to synthesize test fixtures."""

    def __init__(self, attack_surface_source: dict[str, Any] | Path | str | None = None) -> None:
        self.surface_data: dict[str, Any] | None = None
        if attack_surface_source is not None:
            self.load_source(attack_surface_source)
        else:
            self._try_load_default()

    def _try_load_default(self) -> None:
        """Attempts to load from default scenarios/attack_surface.json if present."""
        default_path = Path(__file__).resolve().parent.parent / "scenarios" / "attack_surface.json"
        if default_path.is_file():
            try:
                with open(default_path, "r", encoding="utf-8") as f:
                    self.surface_data = json.load(f)
                logger.info("Loaded default attack surface from %s", default_path)
            except Exception as e:
                logger.warning("Could not load default attack surface: %e", e)

    def load_source(self, source: dict[str, Any] | Path | str) -> None:
        """Loads attack surface data from a dictionary, JSON string, or file path."""
        if isinstance(source, dict):
            self.surface_data = source
        elif isinstance(source, (Path, str)):
            p = Path(source)
            if p.is_file():
                with open(p, "r", encoding="utf-8") as f:
                    self.surface_data = json.load(f)
            else:
                try:
                    self.surface_data = json.loads(str(source))
                except Exception as e:
                    logger.warning("Failed to parse source as JSON: %s", e)
                    self.surface_data = None

    def synthesize_test_cases(self, campaign: str = "all") -> list[dict[str, Any]]:
        """Synthesizes structured security test cases based on the loaded OpenAPI surface."""
        if not self.surface_data or "endpoints" not in self.surface_data:
            logger.info("No attack surface loaded; falling back to standard test cases.")
            return self._filter_campaign(FALLBACK_TEST_CASES, campaign)

        cases: list[dict[str, Any]] = []
        endpoints = self.surface_data.get("endpoints", [])

        for ep in endpoints:
            path: str = ep.get("path", "")
            method: str = ep.get("method", "GET").upper()
            pot_vulns = ep.get("potential_vulnerabilities", [])
            params = ep.get("parameters", [])
            req_body = ep.get("request_body") or {}
            body_fields = req_body.get("fields", [])

            # 1. Process explicit potential vulnerabilities
            for vuln in pot_vulns:
                vuln_type = vuln.get("vuln_type", "GENERAL").upper()
                target_params = vuln.get("target_params", [])
                primary_param = target_params[0] if target_params else ""

                cfg = CANONICAL_FAMILY_PAYLOADS.get(vuln_type)
                if not cfg:
                    continue

                canonical_family = cfg.get("canonical_family", vuln_type)
                cmp_name = cfg.get("campaign", "misc")
                keywords = list(cfg.get("keywords", []))

                # Determine request type and payload
                req_type = "query"
                baseline = cfg.get("query")
                extra: dict[str, Any] = {}

                # Check if target is a path parameter (e.g. {order_id})
                if "{" in path and "}" in path and any(p.get("location") == "path" for p in params):
                    req_type = "path"
                    baseline = str(cfg.get("path", "1"))
                    if not primary_param:
                        path_p = [p for p in params if p.get("location") == "path"]
                        primary_param = path_p[0].get("name", "id") if path_p else "id"

                # Check if target is in JSON request body
                elif method in ("POST", "PUT", "PATCH") and (body_fields or vuln_type == "MASS_ASSIGNMENT"):
                    req_type = "json"
                    baseline = cfg.get("json")

                    if vuln_type == "MASS_ASSIGNMENT":
                        # OWASP API3 Mass Assignment: prefer privileged field or inject undocumented role/is_admin
                        priv_candidates = ("role", "user_role", "is_admin", "is_superuser", "is_staff", "permissions")
                        matched_priv = next(
                            (tp for tp in target_params if tp.lower() in priv_candidates),
                            None,
                        )
                        primary_param = matched_priv or "role"
                        extra["is_admin"] = True
                    elif not primary_param and body_fields:
                        primary_param = body_fields[0].get("name", "")

                    # Construct extra non-target fields from schema examples
                    for bf in body_fields:
                        bname = bf.get("name")
                        if bname and bname != primary_param:
                            ex = bf.get("example")
                            if ex is not None:
                                extra[bname] = ex
                            elif bf.get("field_type") == "integer":
                                extra[bname] = 1
                            elif bf.get("field_type") == "boolean":
                                extra[bname] = True
                            else:
                                extra[bname] = "user@example.com" if "mail" in bname.lower() else "test"

                # Otherwise default to query param
                else:
                    req_type = "query"
                    baseline = cfg.get("query")
                    if not primary_param and params:
                        query_p = [p for p in params if p.get("location") == "query"]
                        if query_p:
                            primary_param = query_p[0].get("name", "q")

                if primary_param:
                    cases.append(
                        SynthesizedTestCase(
                            endpoint=path,
                            method=method,
                            family=canonical_family,
                            campaign=cmp_name,
                            param_name=primary_param,
                            request_type=req_type,
                            baseline_payload=baseline,
                            extra_fields=extra,
                            bypass_keywords=keywords,
                        ).to_dict()
                    )

            # 2. Process implicit endpoints (e.g. user directory list)
            if not pot_vulns and ep.get("primary_category") == "INFORMATIONAL":
                if "list" in path or "users" in path:
                    cfg = CANONICAL_FAMILY_PAYLOADS["EXCESSIVE_DATA_EXPOSURE"]
                    cases.append(
                        SynthesizedTestCase(
                            endpoint=path,
                            method=method,
                            family="EXCESSIVE_DATA_EXPOSURE",
                            campaign=cfg["campaign"],
                            param_name="",
                            request_type="query",
                            baseline_payload="",
                            extra_fields={},
                            bypass_keywords=list(cfg["keywords"]),
                        ).to_dict()
                    )

        # Deduplicate cases by (endpoint, method, family, param_name)
        seen: set[tuple[str, str, str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for c in cases:
            key = (c["endpoint"], c["method"], c["family"], c["param_name"])
            if key not in seen:
                seen.add(key)
                deduped.append(c)

        if not deduped:
            return self._filter_campaign(FALLBACK_TEST_CASES, campaign)

        return self._filter_campaign(deduped, campaign)

    @staticmethod
    def _filter_campaign(cases: list[dict[str, Any]], campaign: str) -> list[dict[str, Any]]:
        """Filters test cases by specific campaign name."""
        if not campaign or campaign == "all":
            return cases
        norm_camp = campaign.lower().strip()
        matched = [c for c in cases if c.get("campaign", "").lower() == norm_camp]
        return matched if matched else cases
