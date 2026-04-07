from __future__ import annotations

from typing import Optional
from urllib.parse import quote_plus

from fastapi import Request
from fastapi.responses import RedirectResponse

from .constants import (
    SESSION_PRINCIPAL_ADMIN,
    SESSION_PRINCIPAL_CLIENT,
    SESSION_SCOPE_ADMIN,
    SESSION_SCOPE_CLIENT,
)
from .paths import get_next_path
from .session_store import get_scope_session

__all__ = [
    "get_admin_session",
    "get_current_client",
    "has_admin_access",
    "require_admin",
    "require_client",
]


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
