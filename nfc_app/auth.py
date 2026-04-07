from __future__ import annotations

import getpass
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import sys
from typing import Optional
from urllib.parse import quote_plus

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from .database import get_connection, now_str
from .settings import settings

SESSION_SCOPE_ADMIN = "admin"
SESSION_SCOPE_CLIENT = "client"

SESSION_PRINCIPAL_GUEST = "guest"
SESSION_PRINCIPAL_ADMIN = "admin"
SESSION_PRINCIPAL_CLIENT = "client"

PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 200_000


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


def _cookie_name(scope: str) -> str:
    if scope == SESSION_SCOPE_ADMIN:
        return settings.admin_cookie_name
    if scope == SESSION_SCOPE_CLIENT:
        return settings.client_cookie_name
    raise ValueError(f"Unsupported scope: {scope}")


def _session_cache_attr(scope: str) -> str:
    return f"_{scope}_session_cache"


def _set_cached_session(request: Request, scope: str, session: Optional[dict]) -> None:
    setattr(request.state, _session_cache_attr(scope), session)


def _get_cached_session(request: Request, scope: str) -> tuple[bool, Optional[dict]]:
    attr_name = _session_cache_attr(scope)
    if hasattr(request.state, attr_name):
        return True, getattr(request.state, attr_name)
    return False, None


def _hash_session_token(raw_token: str) -> str:
    return hmac.new(settings.session_secret.encode("utf-8"), raw_token.encode("utf-8"), "sha256").hexdigest()


def _session_expiry_str() -> str:
    return datetime_offset_str(hours=settings.session_ttl_hours)


def datetime_offset_str(*, hours: int = 0) -> str:
    from datetime import datetime, timedelta

    return (datetime.utcnow() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def _request_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "").strip()


def _load_session(request: Request, scope: str) -> Optional[dict]:
    cookie_value = request.cookies.get(_cookie_name(scope), "").strip()
    if not cookie_value:
        return None

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            s.*,
            a.login AS admin_login,
            a.is_active AS admin_is_active,
            c.name AS client_name,
            c.login AS client_login,
            c.is_active AS client_is_active,
            c.created_at AS client_created_at
        FROM sessions s
        LEFT JOIN admins a ON a.id = s.admin_id
        LEFT JOIN clients c ON c.id = s.client_id
        WHERE s.scope = ?
          AND s.session_token_hash = ?
          AND s.revoked_at IS NULL
          AND s.expires_at > ?
        """,
        (scope, _hash_session_token(cookie_value), now_str()),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    session = dict(row)

    if session["principal_type"] == SESSION_PRINCIPAL_ADMIN and (not session["admin_id"] or int(session["admin_is_active"] or 0) != 1):
        conn.close()
        return None
    if session["principal_type"] == SESSION_PRINCIPAL_CLIENT and (not session["client_id"] or int(session["client_is_active"] or 0) != 1):
        conn.close()
        return None

    last_seen_at = now_str()
    expires_at = _session_expiry_str()
    cur.execute(
        """
        UPDATE sessions
        SET last_seen_at = ?, expires_at = ?, ip_address = ?, user_agent = ?
        WHERE id = ?
        """,
        (last_seen_at, expires_at, get_request_ip(request), _request_user_agent(request), session["id"]),
    )
    conn.commit()
    conn.close()

    session["last_seen_at"] = last_seen_at
    session["expires_at"] = expires_at
    return session


def get_scope_session(request: Request, scope: str, principal_type: str | None = None) -> Optional[dict]:
    has_cache, cached_session = _get_cached_session(request, scope)
    if has_cache:
        if principal_type and cached_session and cached_session["principal_type"] != principal_type:
            return None
        return cached_session

    session = _load_session(request, scope)
    _set_cached_session(request, scope, session)
    if principal_type and session and session["principal_type"] != principal_type:
        return None
    return session


def _create_session(
    request: Request,
    scope: str,
    principal_type: str,
    *,
    admin_id: int | None = None,
    client_id: int | None = None,
) -> tuple[dict, str]:
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    created_at = now_str()
    session = {
        "scope": scope,
        "principal_type": principal_type,
        "admin_id": admin_id,
        "client_id": client_id,
        "csrf_token": csrf_token,
        "ip_address": get_request_ip(request),
        "user_agent": _request_user_agent(request),
        "created_at": created_at,
        "last_seen_at": created_at,
        "expires_at": _session_expiry_str(),
        "revoked_at": None,
    }

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO sessions (
            scope,
            principal_type,
            admin_id,
            client_id,
            session_token_hash,
            csrf_token,
            ip_address,
            user_agent,
            created_at,
            last_seen_at,
            expires_at,
            revoked_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            scope,
            principal_type,
            admin_id,
            client_id,
            _hash_session_token(raw_token),
            csrf_token,
            session["ip_address"],
            session["user_agent"],
            session["created_at"],
            session["last_seen_at"],
            session["expires_at"],
        ),
    )
    session["id"] = cur.lastrowid
    conn.commit()

    if admin_id is not None:
        cur.execute("SELECT login, is_active FROM admins WHERE id = ?", (admin_id,))
        admin_row = cur.fetchone()
        if admin_row:
            session["admin_login"] = admin_row["login"]
            session["admin_is_active"] = admin_row["is_active"]

    if client_id is not None:
        cur.execute(
            """
            SELECT name, login, is_active, created_at
            FROM clients
            WHERE id = ?
            """,
            (client_id,),
        )
        client_row = cur.fetchone()
        if client_row:
            session["client_name"] = client_row["name"]
            session["client_login"] = client_row["login"]
            session["client_is_active"] = client_row["is_active"]
            session["client_created_at"] = client_row["created_at"]

    conn.close()
    _set_cached_session(request, scope, session)
    return session, raw_token


def ensure_scope_session(request: Request, scope: str) -> tuple[dict, Optional[str]]:
    session = get_scope_session(request, scope)
    if session:
        return session, None
    return _create_session(request, scope, SESSION_PRINCIPAL_GUEST)


def _rotate_session(
    request: Request,
    scope: str,
    principal_type: str,
    *,
    admin_id: int | None = None,
    client_id: int | None = None,
) -> tuple[dict, str]:
    existing_session = get_scope_session(request, scope)
    if not existing_session:
        return _create_session(request, scope, principal_type, admin_id=admin_id, client_id=client_id)

    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    created_at = now_str()
    updated_session = dict(existing_session)
    updated_session.update(
        {
            "scope": scope,
            "principal_type": principal_type,
            "admin_id": admin_id,
            "client_id": client_id,
            "csrf_token": csrf_token,
            "ip_address": get_request_ip(request),
            "user_agent": _request_user_agent(request),
            "created_at": created_at,
            "last_seen_at": created_at,
            "expires_at": _session_expiry_str(),
            "revoked_at": None,
        }
    )
    updated_session.pop("admin_login", None)
    updated_session.pop("admin_is_active", None)
    updated_session.pop("client_name", None)
    updated_session.pop("client_login", None)
    updated_session.pop("client_is_active", None)
    updated_session.pop("client_created_at", None)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE sessions
        SET scope = ?,
            principal_type = ?,
            admin_id = ?,
            client_id = ?,
            session_token_hash = ?,
            csrf_token = ?,
            ip_address = ?,
            user_agent = ?,
            created_at = ?,
            last_seen_at = ?,
            expires_at = ?,
            revoked_at = NULL
        WHERE id = ?
        """,
        (
            updated_session["scope"],
            updated_session["principal_type"],
            updated_session["admin_id"],
            updated_session["client_id"],
            _hash_session_token(raw_token),
            updated_session["csrf_token"],
            updated_session["ip_address"],
            updated_session["user_agent"],
            updated_session["created_at"],
            updated_session["last_seen_at"],
            updated_session["expires_at"],
            existing_session["id"],
        ),
    )

    if admin_id is not None:
        cur.execute("SELECT login, is_active FROM admins WHERE id = ?", (admin_id,))
        admin_row = cur.fetchone()
        if admin_row:
            updated_session["admin_login"] = admin_row["login"]
            updated_session["admin_is_active"] = admin_row["is_active"]

    if client_id is not None:
        cur.execute(
            """
            SELECT name, login, is_active, created_at
            FROM clients
            WHERE id = ?
            """,
            (client_id,),
        )
        client_row = cur.fetchone()
        if client_row:
            updated_session["client_name"] = client_row["name"]
            updated_session["client_login"] = client_row["login"]
            updated_session["client_is_active"] = client_row["is_active"]
            updated_session["client_created_at"] = client_row["created_at"]

    conn.commit()
    conn.close()
    _set_cached_session(request, scope, updated_session)
    return updated_session, raw_token


def create_admin_session(request: Request, admin_id: int) -> tuple[dict, str]:
    return _rotate_session(request, SESSION_SCOPE_ADMIN, SESSION_PRINCIPAL_ADMIN, admin_id=admin_id)


def create_client_session(request: Request, client_id: int) -> tuple[dict, str]:
    return _rotate_session(request, SESSION_SCOPE_CLIENT, SESSION_PRINCIPAL_CLIENT, client_id=client_id)


def revoke_scope_session(request: Request, scope: str) -> None:
    session = get_scope_session(request, scope)
    if not session:
        _set_cached_session(request, scope, None)
        return

    conn = get_connection()
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE id = ?",
        (now_str(), session["id"]),
    )
    conn.commit()
    conn.close()
    _set_cached_session(request, scope, None)


def set_scope_cookie(response: Response, scope: str, raw_token: str) -> None:
    response.set_cookie(
        _cookie_name(scope),
        raw_token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=settings.session_ttl_hours * 60 * 60,
        path="/",
    )


def clear_scope_cookie(response: Response, scope: str) -> None:
    response.delete_cookie(
        _cookie_name(scope),
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def get_session_csrf_token(request: Request, scope: str) -> str:
    session = get_scope_session(request, scope)
    return session["csrf_token"] if session else ""


def validate_csrf_token(request: Request, scope: str, csrf_token: str) -> bool:
    session = get_scope_session(request, scope)
    if not session or not csrf_token:
        return False
    return hmac.compare_digest(csrf_token, session["csrf_token"])


def get_admin_session(request: Request) -> Optional[dict]:
    return get_scope_session(request, SESSION_SCOPE_ADMIN, principal_type=SESSION_PRINCIPAL_ADMIN)


def has_admin_access(request: Request) -> bool:
    return get_admin_session(request) is not None


def get_current_client(request: Request) -> Optional[dict]:
    session = get_scope_session(request, SESSION_SCOPE_CLIENT, principal_type=SESSION_PRINCIPAL_CLIENT)
    if not session or not session.get("client_id"):
        return None

    return {
        "id": session["client_id"],
        "name": session["client_name"],
        "login": session["client_login"],
        "is_active": session["client_is_active"],
        "created_at": session["client_created_at"],
    }


def require_admin(request: Request) -> Optional[RedirectResponse]:
    if has_admin_access(request):
        return None
    return RedirectResponse(url="/admin/login?next=" + quote_plus(get_next_path(request)), status_code=303)


def require_client(request: Request) -> Optional[RedirectResponse]:
    if get_current_client(request):
        return None
    return RedirectResponse(url="/client/login?next=" + quote_plus(get_next_path(request)), status_code=303)


def _pbkdf2_digest(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations).hex()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = _pbkdf2_digest(password, salt, PASSWORD_ITERATIONS)
    return f"{PASSWORD_SCHEME}${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith(f"{PASSWORD_SCHEME}$"):
        try:
            _, iterations, salt, stored_digest = password_hash.split("$", 3)
            digest = _pbkdf2_digest(password, salt, int(iterations))
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(digest, stored_digest)

    if password_hash.count("$") == 1:
        salt, stored_digest = password_hash.split("$", 1)
        try:
            digest = _pbkdf2_digest(password, salt, 100_000)
        except ValueError:
            return False
        return hmac.compare_digest(digest, stored_digest)

    return hmac.compare_digest(password, password_hash)


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


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if not args or args[0] != "hash-password":
        print("Usage: python3 -m nfc_app.auth hash-password [password]", file=sys.stderr)
        return 1

    if len(args) > 1:
        password = args[1]
    else:
        password = getpass.getpass("Password: ")
    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        return 1

    print(hash_password(password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
