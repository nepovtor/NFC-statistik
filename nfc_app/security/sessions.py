from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import quote_plus

from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from ..database import close_connection, commit_connection, get_connection, now_str
from ..settings import settings
from .constants import (
    SESSION_PRINCIPAL_ADMIN,
    SESSION_PRINCIPAL_CLIENT,
    SESSION_PRINCIPAL_GUEST,
    SESSION_SCOPE_ADMIN,
    SESSION_SCOPE_CLIENT,
)
from .network import get_request_ip


def get_next_path(request: Request) -> str:
    return request.url.path + (f"?{request.url.query}" if request.url.query else "")


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


def datetime_offset_str(*, hours: int = 0) -> str:
    return (datetime.utcnow() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def _session_expiry_str() -> str:
    return datetime_offset_str(hours=settings.session_ttl_hours)


def _parse_timestamp(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _should_refresh_session(session: dict) -> bool:
    last_seen_at = _parse_timestamp(session.get("last_seen_at"))
    if last_seen_at is None:
        return True
    return datetime.utcnow() - last_seen_at >= timedelta(minutes=settings.session_touch_interval_minutes)


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
        close_connection(conn)
        return None

    session = dict(row)

    if session["principal_type"] == SESSION_PRINCIPAL_ADMIN and (not session["admin_id"] or int(session["admin_is_active"] or 0) != 1):
        close_connection(conn)
        return None
    if session["principal_type"] == SESSION_PRINCIPAL_CLIENT and (not session["client_id"] or int(session["client_is_active"] or 0) != 1):
        close_connection(conn)
        return None

    if _should_refresh_session(session):
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
        commit_connection(conn)
        session["last_seen_at"] = last_seen_at
        session["expires_at"] = expires_at
    close_connection(conn)

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
    commit_connection(conn)

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

    close_connection(conn)
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

    commit_connection(conn)
    close_connection(conn)
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
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (now_str(), session["id"]))
    commit_connection(conn)
    close_connection(conn)
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
