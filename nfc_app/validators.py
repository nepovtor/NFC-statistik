from __future__ import annotations

from urllib.parse import urlparse


def is_public_http_url(value: str) -> bool:
    if not value:
        return False

    parsed = urlparse(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
