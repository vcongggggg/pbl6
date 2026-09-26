import json
import os
import sys
import tempfile
from pathlib import Path

# Ensure attack-lab is on sys.path
attack_lab_path = str(Path(__file__).parents[2] / "attack-lab")
if attack_lab_path not in sys.path:
    sys.path.insert(0, attack_lab_path)

from agent.recon import APIReconAgent, ReconReport  # noqa: E402

MOCK_OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Mock Target Vulnerable API",
        "version": "1.0.0",
        "description": "Mock spec for testing offensive AI reconnaissance.",
    },
    "paths": {
        "/api/v1/vulnerable/auth/login/": {
            "post": {
                "summary": "User & Admin Authentication",
                "description": "Vulnerable to SQL Injection Auth Bypass and Brute Force.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string", "example": "admin' OR '1'='1"},
                                    "password": {"type": "string", "example": "password123"},
                                },
                                "required": ["username", "password"],
                            }
                        }
                    },
                },
                "responses": {"200": {"description": "Authenticated"}},
            }
        },
        "/api/v1/vulnerable/books/search/": {
            "get": {
                "summary": "Search Books Catalog",
                "description": "Vulnerable to SQL Injection UNION-based data extraction.",
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "python' UNION SELECT null--"},
                    }
                ],
                "responses": {"200": {"description": "Search results"}},
            }
        },
        "/api/v1/vulnerable/files/download/": {
            "get": {
                "summary": "Download Document",
                "description": "Vulnerable to Path Traversal / Local File Inclusion.",
                "parameters": [
                    {
                        "name": "file",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "../../etc/passwd"},
                    }
                ],
                "responses": {"200": {"description": "File content"}},
            }
        },
        "/api/v1/vulnerable/admin/ping/": {
            "post": {
                "summary": "Network Diagnostics",
                "description": "Vulnerable to Command Injection (RCE).",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "host": {"type": "string", "example": "127.0.0.1; whoami"},
                                },
                                "required": ["host"],
                            }
                        }
                    },
                },
                "responses": {"200": {"description": "Ping output"}},
            }
        },
        "/api/v1/vulnerable/reviews/": {
            "post": {
                "summary": "Submit Review",
                "description": "Vulnerable to Stored XSS.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "book_id": {"type": "integer"},
                                    "author": {"type": "string"},
                                    "comment": {"type": "string", "example": "<script>alert(1)</script>"},
                                },
                                "required": ["comment"],
                            }
                        }
                    },
                },
                "responses": {"201": {"description": "Review added"}},
            }
        },
        "/api/v1/vulnerable/orders/{order_id}/": {
            "get": {
                "summary": "Order Detail BOLA",
                "description": "Broken Object Level Authorization.",
                "parameters": [
                    {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "Order details"}},
            }
        },
        "/api/v1/vulnerable/books/fetch-cover/": {
            "get": {
                "summary": "Fetch Book Cover",
                "description": "Server-Side Request Forgery.",
                "parameters": [
                    {"name": "url", "in": "query", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {"200": {"description": "Cover image"}},
            }
        },
    },
}


def test_recon_from_local_spec_file():
    """Verify loading and parsing OpenAPI spec from a local JSON file."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(MOCK_OPENAPI_SPEC, f)
        temp_spec_path = f.name

    try:
        agent = APIReconAgent(target_base_url="http://192.168.1.15:8000")
        report = agent.run(local_file=temp_spec_path)

        assert isinstance(report, ReconReport)
        assert report.api_title == "Mock Target Vulnerable API"
        assert report.summary["total_endpoints"] == 7
        assert report.summary["total_paths"] == 7

        # Check endpoints and categories
        endpoints_by_path = {ep.path: ep for ep in report.endpoints}

        # 1. Login endpoint -> AUTH_BYPASS
        login_ep = endpoints_by_path["/api/v1/vulnerable/auth/login/"]
        assert login_ep.method == "POST"
        assert login_ep.primary_category == "AUTH_BYPASS"
        assert any(ind.vuln_type == "AUTH_BYPASS" for ind in login_ep.potential_vulnerabilities)

        # 2. Search endpoint -> SQL_INJECTION
        search_ep = endpoints_by_path["/api/v1/vulnerable/books/search/"]
        assert search_ep.method == "GET"
        assert search_ep.primary_category == "SQL_INJECTION"
        assert len(search_ep.parameters) == 1
        assert search_ep.parameters[0].name == "q"

        # 3. File download -> PATH_TRAVERSAL
        file_ep = endpoints_by_path["/api/v1/vulnerable/files/download/"]
        assert file_ep.method == "GET"
        assert file_ep.primary_category == "PATH_TRAVERSAL"
        assert file_ep.parameters[0].name == "file"

        # 4. Admin ping -> COMMAND_INJECTION
        ping_ep = endpoints_by_path["/api/v1/vulnerable/admin/ping/"]
        assert ping_ep.method == "POST"
        assert ping_ep.primary_category == "COMMAND_INJECTION"

        # 5. Review submit -> XSS
        review_ep = endpoints_by_path["/api/v1/vulnerable/reviews/"]
        assert review_ep.method == "POST"
        assert review_ep.primary_category == "XSS"

        # 6. Order detail -> BOLA_IDOR
        order_ep = endpoints_by_path["/api/v1/vulnerable/orders/{order_id}/"]
        assert order_ep.method == "GET"
        assert order_ep.primary_category == "BOLA_IDOR"

        # 7. Fetch cover -> SSRF
        ssrf_ep = endpoints_by_path["/api/v1/vulnerable/books/fetch-cover/"]
        assert ssrf_ep.method == "GET"
        assert ssrf_ep.primary_category == "SSRF"

    finally:
        if os.path.exists(temp_spec_path):
            os.remove(temp_spec_path)


def test_recon_save_and_to_dict():
    """Verify JSON export and dict conversion of ReconReport."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(MOCK_OPENAPI_SPEC, f)
        temp_spec_path = f.name

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as out_f:
        output_json = out_f.name

    try:
        agent = APIReconAgent()
        report = agent.run(local_file=temp_spec_path)
        report.save_json(output_json)

        assert os.path.exists(output_json)
        with open(output_json, "r", encoding="utf-8") as r:
            saved_data = json.load(r)

        assert saved_data["api_title"] == "Mock Target Vulnerable API"
        assert "endpoints" in saved_data
        assert len(saved_data["endpoints"]) == 7
    finally:
        if os.path.exists(temp_spec_path):
            os.remove(temp_spec_path)
        if os.path.exists(output_json):
            os.remove(output_json)


def test_recon_inherits_security_and_path_parameters_without_duplicate_bola():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Security inheritance", "version": "1"},
        "security": [{"BearerAuth": []}],
        "paths": {
            "/orders/{order_id}": {
                "parameters": [
                    {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "locale", "in": "query", "schema": {"type": "string"}},
                ],
                "get": {"summary": "Order", "responses": {"200": {"description": "OK"}}},
                "delete": {
                    "security": [],
                    "parameters": [
                        {"name": "locale", "in": "query", "schema": {"type": "string", "default": "vi"}}
                    ],
                    "responses": {"204": {"description": "Deleted"}},
                },
            }
        },
    }
    agent = APIReconAgent()
    agent.raw_spec = spec
    get_profile = agent.parse_endpoint(
        "/orders/{order_id}", "get", spec["paths"]["/orders/{order_id}"]["get"], spec["paths"]["/orders/{order_id}"]
    )
    delete_profile = agent.parse_endpoint(
        "/orders/{order_id}", "delete", spec["paths"]["/orders/{order_id}"]["delete"], spec["paths"]["/orders/{order_id}"]
    )

    assert get_profile.requires_auth is True
    assert {parameter.name for parameter in get_profile.parameters} == {"order_id", "locale"}
    assert sum(indicator.vuln_type == "BOLA_IDOR" for indicator in get_profile.potential_vulnerabilities) == 1
    assert delete_profile.requires_auth is False
    assert len([parameter for parameter in delete_profile.parameters if parameter.name == "locale"]) == 1
