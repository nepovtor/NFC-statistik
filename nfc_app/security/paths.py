from __future__ import annotations

from fastapi import Request

__all__ = ["get_next_path", "safe_admin_path", "safe_client_path"]


def get_next_path(request: Request) -> str:
    return request.url.path + (f"?{request.url.query}" if request.url.query else "")


def safe_admin_path(next_path: str) -> str:
    return next_path if next_path.startswith("/admin") else "/admin"


def safe_client_path(next_path: str) -> str:
    return next_path if next_path.startswith("/client") else "/client"
