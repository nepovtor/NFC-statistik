from __future__ import annotations

from urllib.parse import quote

from fastapi import Request

from .settings import settings


def get_public_base_url(request: Request) -> str:
    if settings.public_base_url:
        return settings.public_base_url
    return str(request.base_url).rstrip("/")


def build_public_tag_url(request: Request, tag_code: str) -> str:
    return f"{get_public_base_url(request)}/go/{quote(tag_code)}"
