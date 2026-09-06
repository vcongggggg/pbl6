"""
Vulnerable REST API Module for Bookie Bookstore.
Designed specifically for PBL6 - Web API Security & Autonomous Red Teaming Cyber Range.

Contains intentional OWASP Top 10 vulnerabilities:
1. SQL Injection (Auth Bypass & UNION-based Search)
2. Stored & Reflected Cross-Site Scripting (XSS)
3. Path Traversal / Local File Inclusion (LFI)
4. Command Injection (RCE) via Network Ping Tool
5. OpenAPI 3.0 specification endpoint for AI Attack Planner reconnaissance.
"""

import json
import os
import subprocess
from django.conf import settings
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def vulnerable_login(request):
    """
    POST /api/v1/vulnerable/auth/login/
    Intentional Vulnerability: SQL Injection (Auth Bypass) & Brute Force.
    Query concatenated directly without parameterized inputs.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed. Use POST."}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else request.POST
    except Exception:
        data = request.POST

    username = data.get("username", "")
    password = data.get("password", "")

    if not username:
        return JsonResponse({"error": "Username is required"}, status=400)

    # Intentional SQL Injection vulnerability (String concatenation)
    raw_query = f"SELECT id, username, email, is_staff, is_superuser FROM auth_user WHERE username = '{username}' AND password = '{password}'"

    try:
        with connection.cursor() as cursor:
            cursor.execute(raw_query)
            user_row = cursor.fetchone()

        if user_row:
            user_info = {
                "id": user_row[0],
                "username": user_row[1],
                "email": user_row[2],
                "role": "admin" if user_row[3] or user_row[4] else "customer",
                "is_staff": bool(user_row[3]),
                "is_superuser": bool(user_row[4]),
            }
            return JsonResponse({
                "status": "success",
                "message": "Authentication successful (SQLi Exploited or Valid Credential)",
                "token": f"bookie_token_{user_row[0]}_x99a2f",
                "user": user_info,
                "executed_query": raw_query,
            }, status=200)
        else:
            return JsonResponse({
                "status": "failed",
                "message": "Invalid username or password",
                "executed_query": raw_query,
            }, status=401)
    except Exception as exc:
        return JsonResponse({
            "status": "error",
            "error_type": "DatabaseException",
            "message": str(exc),
            "executed_query": raw_query,
        }, status=500)


def vulnerable_search(request):
    """
    GET /api/v1/vulnerable/books/search/?q=...
    Intentional Vulnerability: SQL Injection (UNION-based Search).
    Concatenates query string directly into SELECT statement.
    """
    q = request.GET.get("q", "").strip()
    if not q:
        return JsonResponse({"status": "ok", "count": 0, "results": []})

    # Intentional UNION-based SQL Injection vulnerability
    raw_query = f"SELECT id, title, author, price FROM books_book WHERE title LIKE '%{q}%' OR author LIKE '%{q}%'"

    try:
        with connection.cursor() as cursor:
            cursor.execute(raw_query)
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return JsonResponse({
            "status": "success",
            "count": len(results),
            "query": q,
            "results": results,
            "executed_query": raw_query,
        }, status=200)
    except Exception as exc:
        return JsonResponse({
            "status": "error",
            "error_type": "DatabaseException",
            "message": str(exc),
            "executed_query": raw_query,
        }, status=500)


# In-memory store for vulnerable reviews
_VULNERABLE_REVIEWS = [
    {
        "id": 1,
        "book_id": 1,
        "author": "Alice",
        "comment": "Sách rất hay, cốt truyện cuốn hút!",
    },
    {
        "id": 2,
        "book_id": 1,
        "author": "Bob",
        "comment": "Giao hàng nhanh, đóng gói cẩn thận 5 sao.",
    },
]

@csrf_exempt
def vulnerable_reviews(request):
    """
    GET /api/v1/vulnerable/reviews/?book_id=...
    POST /api/v1/vulnerable/reviews/
    Intentional Vulnerability: Stored & Reflected Cross-Site Scripting (XSS).
    Accepts raw HTML/JavaScript payloads and returns without sanitization.
    """
    if request.method == "GET":
        book_id = request.GET.get("book_id")
        reviews = _VULNERABLE_REVIEWS
        if book_id:
            try:
                b_id = int(book_id)
                reviews = [r for r in reviews if r.get("book_id") == b_id]
            except ValueError:
                pass
        return JsonResponse({
            "status": "success",
            "count": len(reviews),
            "reviews": reviews,
        }, status=200)

    elif request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8")) if request.body else request.POST
        except Exception:
            data = request.POST

        author = data.get("author", "Anonymous")
        comment = data.get("comment", "")
        book_id = data.get("book_id", 1)

        new_review = {
            "id": len(_VULNERABLE_REVIEWS) + 1,
            "book_id": int(book_id) if str(book_id).isdigit() else 1,
            "author": author,
            "comment": comment,  # Raw unescaped payload
        }
        _VULNERABLE_REVIEWS.append(new_review)

        return JsonResponse({
            "status": "success",
            "message": "Review added successfully (XSS payload stored)",
            "review": new_review,
        }, status=201)

    return JsonResponse({"error": "Method not allowed"}, status=405)


def vulnerable_file_download(request):
    """
    GET /api/v1/vulnerable/files/download/?file=...
    Intentional Vulnerability: Path Traversal / Local File Inclusion (LFI).
    Reads files from disk without canonicalization or directory jail check.
    """
    filename = request.GET.get("file", "").strip()
    if not filename:
        return JsonResponse({"error": "Missing 'file' parameter."}, status=400)

    # Intentional Path Traversal vulnerability: no check against '..'
    base_dir = os.path.join(settings.BASE_DIR, "media")
    target_path = os.path.join(base_dir, filename)

    try:
        if not os.path.exists(target_path):
            return JsonResponse({
                "status": "not_found",
                "message": f"File '{filename}' not found.",
                "attempted_path": target_path,
            }, status=404)

        with open(target_path, "rb") as f:
            content = f.read()

        # Try to return text if UTF-8, else binary
        try:
            text_content = content.decode("utf-8")
            return HttpResponse(text_content, content_type="text/plain; charset=utf-8")
        except UnicodeDecodeError:
            return HttpResponse(content, content_type="application/octet-stream")
    except Exception as exc:
        return JsonResponse({
            "status": "error",
            "message": str(exc),
            "attempted_path": target_path,
        }, status=500)


@csrf_exempt
def vulnerable_admin_ping(request):
    """
    POST /api/v1/vulnerable/admin/ping/
    Intentional Vulnerability: Command Injection (Remote Code Execution - RCE).
    Executes raw shell command with user-supplied host parameter.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed. Use POST."}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8")) if request.body else request.POST
    except Exception:
        data = request.POST

    host = data.get("host", "").strip()
    if not host:
        return JsonResponse({"error": "Missing 'host' parameter."}, status=400)

    # Intentional Command Injection vulnerability (shell=True or string interpolation)
    if os.name == "nt":
        cmd = f"ping -n 1 {host}"
    else:
        cmd = f"ping -c 1 {host}"

    try:
        output = subprocess.getoutput(cmd)
        return JsonResponse({
            "status": "success",
            "host": host,
            "command": cmd,
            "output": output,
        }, status=200)
    except Exception as exc:
        return JsonResponse({
            "status": "error",
            "command": cmd,
            "message": str(exc),
        }, status=500)


def vulnerable_openapi_spec(request):
    """
    GET /api/v1/vulnerable/openapi.json
    Provides an OpenAPI 3.0 schema for the AI Attack Planner on Machine 2.
    """
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Bookie Bookstore Vulnerable API",
            "version": "1.0.0",
            "description": "Target Web API with intentional OWASP Top 10 vulnerabilities for PBL6 Cyber Range.",
        },
        "servers": [
            {"url": "/api/proxy", "description": "WAF Gateway Proxy URL (Machine 1)"},
            {"url": "/", "description": "Direct Target URL"},
        ],
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
                    "responses": {
                        "200": {"description": "Authenticated successfully"},
                        "401": {"description": "Invalid credentials"},
                    },
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
                            "schema": {"type": "string", "example": "python' UNION SELECT id, username, email, password FROM auth_user --"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Book search results"},
                    },
                }
            },
            "/api/v1/vulnerable/reviews/": {
                "get": {
                    "summary": "Get Book Reviews",
                    "description": "Returns reviews containing stored XSS payloads.",
                    "parameters": [
                        {"name": "book_id", "in": "query", "schema": {"type": "integer", "example": 1}}
                    ],
                    "responses": {"200": {"description": "List of reviews"}},
                },
                "post": {
                    "summary": "Submit Book Review",
                    "description": "Vulnerable to Stored XSS.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "book_id": {"type": "integer", "example": 1},
                                        "author": {"type": "string", "example": "Attacker"},
                                        "comment": {"type": "string", "example": "<script>alert('PBL6_XSS')</script>"},
                                    },
                                    "required": ["author", "comment"],
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "Review created"}},
                },
            },
            "/api/v1/vulnerable/files/download/": {
                "get": {
                    "summary": "Download System Document / Sample Chapter",
                    "description": "Vulnerable to Path Traversal / Local File Inclusion.",
                    "parameters": [
                        {
                            "name": "file",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string", "example": "../../bookstore/settings/base.py"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "File contents returned"},
                        "404": {"description": "File not found"},
                    },
                }
            },
            "/api/v1/vulnerable/admin/ping/": {
                "post": {
                    "summary": "Network Diagnostics Tool",
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
                    "responses": {"200": {"description": "Ping diagnostic output"}},
                }
            },
        },
    }
    return JsonResponse(spec, status=200)


def vulnerable_docs_ui(request):
    """
    GET /api/v1/vulnerable/docs/
    Returns a self-contained Swagger UI HTML page.
    """
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bookie Vulnerable API - Swagger UI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; background: #0f172a; }
        .swagger-ui { background: #fff; padding: 20px; border-radius: 8px; margin: 20px; }
        .top-banner { background: #1e293b; color: #38bdf8; padding: 16px 24px; font-family: sans-serif; font-weight: bold; }
    </style>
</head>
<body>
    <div class="top-banner">
        🛡️ Bookie Bookstore — Intentional Vulnerability Testbed (PBL6 Cyber Range)
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/api/v1/vulnerable/openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ]
            });
        };
    </script>
</body>
</html>"""
    return HttpResponse(html_content, content_type="text/html; charset=utf-8")
