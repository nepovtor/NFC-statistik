from __future__ import annotations

import hmac

from fastapi import Request

from .session_store import get_scope_session

__all__ = ["get_session_csrf_token", "validate_csrf_token"]


def get_session_csrf_token(request: Request, scope: str) -> str:
    session = get_scope_session(request, scope)
    return session["csrf_token"] if session else ""


def validate_csrf_token(request: Request, scope: str, csrf_token: str) -> bool:
    session = get_scope_session(request, scope)
    if not session or not csrf_token:
        return False
    return hmac.compare_digest(csrf_token, session["csrf_token"])
