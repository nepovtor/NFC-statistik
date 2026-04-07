from __future__ import annotations

import sqlite3
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI

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
            with override_settings(db_path=temp_db):
                init_db()
                conn = sqlite3.connect(temp_db)
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                tags_count = conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
                conn.close()

        self.assertIn("clients", tables)
        self.assertIn("tags", tables)
        self.assertIn("visits", tables)
        self.assertGreaterEqual(tags_count, 4)


class AppFactoryTests(unittest.TestCase):
    def test_create_app_registers_main_routes(self):
        app = create_app()
        self.assertIsInstance(app, FastAPI)
        route_paths = {route.path for route in app.router.routes}
        self.assertIn("/", route_paths)
        self.assertIn("/admin", route_paths)
        self.assertIn("/client", route_paths)
        self.assertIn("/client/tags/{tag_id}/update", route_paths)
        self.assertIn("/go/{tag_code}", route_paths)


if __name__ == "__main__":
    unittest.main()
