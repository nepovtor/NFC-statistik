from __future__ import annotations

from fastapi.responses import Response

from ..settings import settings
from .constants import SESSION_SCOPE_ADMIN, SESSION_SCOPE_CLIENT

__all__ = ["clear_scope_cookie", "cookie_name_for_scope", "set_scope_cookie"]


def cookie_name_for_scope(scope: str) -> str:
    if scope == SESSION_SCOPE_ADMIN:
        return settings.admin_cookie_name
    if scope == SESSION_SCOPE_CLIENT:
        return settings.client_cookie_name
    raise ValueError(f"Unsupported scope: {scope}")


def set_scope_cookie(response: Response, scope: str, raw_token: str) -> None:
    response.set_cookie(
        cookie_name_for_scope(scope),
        raw_token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=settings.session_ttl_hours * 60 * 60,
        path="/",
    )


def clear_scope_cookie(response: Response, scope: str) -> None:
    response.delete_cookie(
        cookie_name_for_scope(scope),
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )
