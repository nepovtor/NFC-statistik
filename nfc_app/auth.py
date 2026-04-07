from __future__ import annotations

import hashlib
import ipaddress
import hmac
import re
import secrets
import sqlite3
from typing import Optional
from urllib.parse import quote_plus

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .database import get_connection
from .settings import settings


def get_next_path(request: Request) -> str:
    return request.url.path + (f"?{request.url.query}" if request.url.query else "")


def _get_forwarded_ip(request: Request) -> Optional[str]:
    if not settings.trust_proxy_headers:
        return None

    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        first_hop = forwarded_for.split(",", 1)[0].strip()
        if first_hop:
            return first_hop

    real_ip = request.headers.get("x-real-ip", "").strip()
    return real_ip or None


def get_request_ip(request: Request) -> Optional[str]:
    forwarded_ip = _get_forwarded_ip(request)
    if forwarded_ip:
        return forwarded_ip

    if request.client:
        return request.client.host
    return None


def is_ip_allowed_for_admin(ip_value: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    for network_value in settings.admin_allowed_networks:
        try:
            network = ipaddress.ip_network(network_value, strict=False)
        except ValueError:
            continue
        if ip in network:
            return True
    return False


def is_admin_request_allowed(request: Request) -> bool:
    if not settings.admin_tailscale_only:
        return True

    request_ip = get_request_ip(request)
    if not request_ip:
        return False
    return is_ip_allowed_for_admin(request_ip)


def admin_tailscale_block_response() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="ru">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Админка только через Tailscale</title>
            <style>
                body { margin: 0; font-family: Arial, sans-serif; background: #081120; color: #e5edf7; }
                main { max-width: 680px; margin: 8vh auto; padding: 24px; }
                .panel { padding: 24px; border-radius: 18px; background: rgba(15, 23, 42, 0.96); border: 1px solid rgba(148, 163, 184, 0.18); }
                h1 { margin-top: 0; font-size: 30px; }
                p { line-height: 1.6; color: #cbd5e1; }
                code { padding: 2px 6px; border-radius: 8px; background: rgba(56, 189, 248, 0.1); }
            </style>
        </head>
        <body>
            <main>
                <section class="panel">
                    <h1>Админка доступна только через Tailscale</h1>
                    <p>Публичный вход в <code>/admin</code> отключён. Открой админку через Tailscale с сервера, его Tailscale IP или через Tailscale Serve.</p>
                </section>
            </main>
        </body>
        </html>
        """,
        status_code=403,
    )


def safe_admin_path(next_path: str) -> str:
    return next_path if next_path.startswith("/admin") else "/admin"


def safe_client_path(next_path: str) -> str:
    return next_path if next_path.startswith("/client") else "/client"


def sign_value(value: str) -> str:
    return hmac.new(settings.admin_session_secret.encode("utf-8"), value.encode("utf-8"), "sha256").hexdigest()


def build_signed_cookie(value: str) -> str:
    return f"{value}.{sign_value(value)}"


def read_signed_cookie(request: Request, cookie_name: str) -> Optional[str]:
    cookie = request.cookies.get(cookie_name, "")
    if "." not in cookie:
        return None
    value, signature = cookie.rsplit(".", 1)
    expected_signature = sign_value(value)
    if not hmac.compare_digest(signature, expected_signature):
        return None
    return value


def build_admin_cookie() -> str:
    return build_signed_cookie("admin")


def build_client_cookie(client_id: int) -> str:
    return build_signed_cookie(f"client:{client_id}")


def has_admin_access(request: Request) -> bool:
    return read_signed_cookie(request, settings.admin_cookie_name) == "admin"


def get_client_id_from_request(request: Request) -> Optional[int]:
    value = read_signed_cookie(request, settings.client_cookie_name)
    if not value or not value.startswith("client:"):
        return None
    client_part = value.split(":", 1)[1]
    if not client_part.isdigit():
        return None
    return int(client_part)


def get_current_client(request: Request) -> Optional[sqlite3.Row]:
    client_id = get_client_id_from_request(request)
    if not client_id:
        return None

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, name, login, is_active, created_at
        FROM clients
        WHERE id = ?
        """,
        (client_id,),
    )
    client = cur.fetchone()
    conn.close()

    if not client or int(client["is_active"]) != 1:
        return None
    return client


def require_admin(request: Request) -> Optional[RedirectResponse]:
    if has_admin_access(request):
        return None
    return RedirectResponse(url="/admin/login?next=" + quote_plus(get_next_path(request)), status_code=303)


def require_client(request: Request) -> Optional[RedirectResponse]:
    if get_current_client(request):
        return None
    return RedirectResponse(url="/client/login?next=" + quote_plus(get_next_path(request)), status_code=303)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    if "$" not in password_hash:
        return hmac.compare_digest(password, password_hash)
    salt, stored_digest = password_hash.split("$", 1)
    try:
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000).hex()
    except ValueError:
        return False
    return hmac.compare_digest(digest, stored_digest)


def valid_client_login(login: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._@-]{3,50}", login))


def normalize_client_id(raw_value: str) -> Optional[int]:
    value = (raw_value or "").strip()
    if not value:
        return None
    client_id = int(value)
    if client_id <= 0:
        raise ValueError
    return client_id


def client_exists(cursor: sqlite3.Cursor, client_id: int) -> bool:
    cursor.execute("SELECT id FROM clients WHERE id = ?", (client_id,))
    return cursor.fetchone() is not None
