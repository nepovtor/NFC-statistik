from __future__ import annotations

import sqlite3
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nfc_app.app import create_app
from nfc_app.auth import (
    get_request_ip,
    hash_password,
    is_admin_request_allowed,
    is_ip_allowed_for_admin,
    normalize_client_id,
    safe_admin_path,
    safe_client_path,
    verify_password,
)
from nfc_app.database import init_db
from nfc_app.settings import settings
from nfc_app.urls import build_public_tag_url
from nfc_app.validators import is_public_http_url


@contextmanager
def override_settings(**updates):
    original_values = {}
    for key, value in updates.items():
        original_values[key] = getattr(settings, key)
        object.__setattr__(settings, key, value)
    try:
        yield
    finally:
        for key, value in original_values.items():
            object.__setattr__(settings, key, value)


class DummyRequest:
    def __init__(self, base_url: str, headers: dict | None = None, client_host: str = "127.0.0.1"):
        self.base_url = base_url
        self.headers = headers or {}
        self.client = type("Client", (), {"host": client_host})()


def test_runtime_settings(**updates):
    base_updates = {
        "session_secret": "test-session-secret",
        "admin_login": "admin",
        "admin_password_hash": hash_password("AdminSecret123"),
        "secure_cookies": False,
        "login_rate_limit_attempts": 5,
        "login_rate_limit_window_minutes": 15,
    }
    base_updates.update(updates)
    return override_settings(**base_updates)


def extract_csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise AssertionError("csrf_token input not found in HTML")
    return match.group(1)


class AuthTests(unittest.TestCase):
    def test_hash_password_roundtrip(self):
        password_hash = hash_password("Secret123")
        self.assertTrue(verify_password("Secret123", password_hash))
        self.assertFalse(verify_password("WrongPass", password_hash))

    def test_safe_paths(self):
        self.assertEqual(safe_admin_path("/admin/tags"), "/admin/tags")
        self.assertEqual(safe_admin_path("/client"), "/admin")
        self.assertEqual(safe_client_path("/client/tags"), "/client/tags")
        self.assertEqual(safe_client_path("/admin"), "/client")

    def test_normalize_client_id(self):
        self.assertIsNone(normalize_client_id(""))
        self.assertEqual(normalize_client_id("7"), 7)
        with self.assertRaises(ValueError):
            normalize_client_id("0")

    def test_is_ip_allowed_for_admin(self):
        self.assertTrue(is_ip_allowed_for_admin("127.0.0.1"))
        self.assertTrue(is_ip_allowed_for_admin("100.101.102.103"))
        self.assertTrue(is_ip_allowed_for_admin("fd7a:115c:a1e0::1"))
        self.assertFalse(is_ip_allowed_for_admin("8.8.8.8"))

    def test_get_request_ip_prefers_forwarded_header_when_enabled(self):
        request = DummyRequest(
            "http://127.0.0.1:8001/",
            headers={"x-forwarded-for": "100.100.100.100, 172.18.0.2"},
            client_host="172.18.0.2",
        )
        with override_settings(trust_proxy_headers=True):
            self.assertEqual(get_request_ip(request), "100.100.100.100")

    def test_is_admin_request_allowed_with_tailscale_only(self):
        tailscale_request = DummyRequest("http://127.0.0.1:8001/", client_host="100.100.100.100")
        public_request = DummyRequest("http://127.0.0.1:8001/", client_host="8.8.8.8")
        with override_settings(admin_tailscale_only=True, trust_proxy_headers=False):
            self.assertTrue(is_admin_request_allowed(tailscale_request))
            self.assertFalse(is_admin_request_allowed(public_request))


class UrlTests(unittest.TestCase):
    def test_build_public_tag_url_from_request(self):
        request = DummyRequest("http://127.0.0.1:8001/")
        with override_settings(public_base_url=""):
            self.assertEqual(build_public_tag_url(request, "menu7"), "http://127.0.0.1:8001/go/menu7")

    def test_build_public_tag_url_from_settings(self):
        request = DummyRequest("http://127.0.0.1:8001/")
        with override_settings(public_base_url="https://nfc.example.com"):
            self.assertEqual(build_public_tag_url(request, "menu7"), "https://nfc.example.com/go/menu7")

    def test_is_public_http_url(self):
        self.assertTrue(is_public_http_url("https://nfc.example.com/menu7"))
        self.assertTrue(is_public_http_url("http://127.0.0.1:8001/go/test"))
        self.assertFalse(is_public_http_url("ftp://nfc.example.com"))
        self.assertFalse(is_public_http_url("/relative/path"))


class DatabaseTests(unittest.TestCase):
    def test_init_db_creates_tables_and_default_tags(self):
        with TemporaryDirectory() as tmp_dir:
            temp_db = Path(tmp_dir) / "test.db"
            with test_runtime_settings(db_path=temp_db):
                init_db()
                conn = sqlite3.connect(temp_db)
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                tags_count = conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
                admins_count = conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
                conn.close()

        self.assertIn("clients", tables)
        self.assertIn("tags", tables)
        self.assertIn("visits", tables)
        self.assertIn("admins", tables)
        self.assertIn("sessions", tables)
        self.assertIn("login_attempts", tables)
        self.assertGreaterEqual(tags_count, 4)
        self.assertEqual(admins_count, 1)


class SecurityFlowTests(unittest.TestCase):
    def test_admin_login_requires_valid_csrf_and_logout_revokes_session(self):
        with TemporaryDirectory() as tmp_dir:
            temp_db = Path(tmp_dir) / "test.db"
            with test_runtime_settings(db_path=temp_db):
                init_db()
                app = create_app()
                with TestClient(app) as client:
                    login_page = client.get("/admin/login")
                    self.assertEqual(login_page.status_code, 200)

                    bad_login = client.post(
                        "/admin/login",
                        data={"login": "admin", "password": "AdminSecret123", "next": "/admin", "csrf_token": "bad-token"},
                        follow_redirects=False,
                    )
                    self.assertEqual(bad_login.status_code, 303)
                    self.assertIn("/admin/login?message=", bad_login.headers["location"])

                    fresh_login_page = client.get("/admin/login")
                    fresh_csrf_token = extract_csrf_token(fresh_login_page.text)

                    ok_login = client.post(
                        "/admin/login",
                        data={"login": "admin", "password": "AdminSecret123", "next": "/admin", "csrf_token": fresh_csrf_token},
                        follow_redirects=False,
                    )
                    self.assertEqual(ok_login.status_code, 303)
                    self.assertEqual(ok_login.headers["location"], "/admin")

                    dashboard = client.get("/admin")
                    self.assertEqual(dashboard.status_code, 200)
                    dashboard_csrf = extract_csrf_token(dashboard.text)

                    logout = client.post(
                        "/admin/logout",
                        data={"csrf_token": dashboard_csrf},
                        follow_redirects=False,
                    )
                    self.assertEqual(logout.status_code, 303)
                    self.assertIn("/admin/login?message=", logout.headers["location"])

                    redirected_dashboard = client.get("/admin", follow_redirects=False)
                    self.assertEqual(redirected_dashboard.status_code, 303)
                    self.assertIn("/admin/login?next=", redirected_dashboard.headers["location"])

    def test_public_go_route_uses_forwarded_client_ip(self):
        with TemporaryDirectory() as tmp_dir:
            temp_db = Path(tmp_dir) / "test.db"
            with test_runtime_settings(db_path=temp_db, trust_proxy_headers=True):
                init_db()
                app = create_app()
                with TestClient(app) as client:
                    response = client.get(
                        "/go/table1",
                        headers={"x-forwarded-for": "203.0.113.10, 172.18.0.2"},
                        follow_redirects=False,
                    )
                    self.assertEqual(response.status_code, 302)

                conn = sqlite3.connect(temp_db)
                ip_address = conn.execute("SELECT ip_address FROM visits ORDER BY id DESC LIMIT 1").fetchone()[0]
                conn.close()

        self.assertEqual(ip_address, "203.0.113.10")

    def test_admin_login_is_rate_limited_after_repeated_failures(self):
        with TemporaryDirectory() as tmp_dir:
            temp_db = Path(tmp_dir) / "test.db"
            with test_runtime_settings(db_path=temp_db, login_rate_limit_attempts=2, login_rate_limit_window_minutes=15):
                init_db()
                app = create_app()
                with TestClient(app) as client:
                    for _ in range(2):
                        login_page = client.get("/admin/login")
                        csrf_token = extract_csrf_token(login_page.text)
                        response = client.post(
                            "/admin/login",
                            data={"login": "admin", "password": "WrongPassword", "next": "/admin", "csrf_token": csrf_token},
                            follow_redirects=False,
                        )
                        self.assertEqual(response.status_code, 303)
                        self.assertIn("/admin/login?message=", response.headers["location"])

                    blocked_login_page = client.get("/admin/login")
                    blocked_csrf_token = extract_csrf_token(blocked_login_page.text)
                    blocked = client.post(
                        "/admin/login",
                        data={"login": "admin", "password": "AdminSecret123", "next": "/admin", "csrf_token": blocked_csrf_token},
                        follow_redirects=False,
                    )
                    self.assertEqual(blocked.status_code, 303)
                    self.assertIn("%D0%A1%D0%BB%D0%B8%D1%88%D0%BA%D0%BE%D0%BC+%D0%BC%D0%BD%D0%BE%D0%B3%D0%BE", blocked.headers["location"])


class AppFactoryTests(unittest.TestCase):
    def test_create_app_registers_main_routes(self):
        app = create_app()
        self.assertIsInstance(app, FastAPI)
        route_paths = {route.path for route in app.router.routes}
        self.assertIn("/", route_paths)
        self.assertIn("/healthz", route_paths)
        self.assertIn("/readyz", route_paths)
        self.assertIn("/admin", route_paths)
        self.assertIn("/client", route_paths)
        self.assertIn("/client/tags/{tag_id}/update", route_paths)
        self.assertIn("/go/{tag_code}", route_paths)


if __name__ == "__main__":
    unittest.main()
