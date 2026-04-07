from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _normalize_base_url(value: str) -> str:
    return value.strip().rstrip("/")


def _env_flag(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    app_title: str
    app_version: str
    base_dir: Path
    db_path: Path
    admin_password: str
    admin_session_secret: str
    admin_cookie_name: str
    client_cookie_name: str
    public_base_url: str
    admin_tailscale_only: bool
    trust_proxy_headers: bool
    admin_allowed_networks: tuple[str, ...]
    default_tags: dict[str, str] = field(default_factory=dict)


BASE_DIR = Path(__file__).resolve().parent.parent

settings = Settings(
    app_title="NFC Statistics App",
    app_version="4.0",
    base_dir=BASE_DIR,
    db_path=Path(os.getenv("NFC_STATS_DB_PATH", str(BASE_DIR / "nfc_stats.db"))),
    admin_password=os.getenv("ADMIN_PASSWORD", "пароль"),
    admin_session_secret=os.getenv("ADMIN_SESSION_SECRET", "nfc-admin-session-secret-change-me"),
    admin_cookie_name="admin_auth",
    client_cookie_name="client_auth",
    public_base_url=_normalize_base_url(os.getenv("PUBLIC_BASE_URL", "")),
    admin_tailscale_only=_env_flag("ADMIN_TAILSCALE_ONLY", False),
    trust_proxy_headers=_env_flag("TRUST_PROXY_HEADERS", False),
    admin_allowed_networks=_split_csv(
        os.getenv(
            "ADMIN_ALLOWED_NETWORKS",
            "127.0.0.1/32,::1/128,100.64.0.0/10,fd7a:115c:a1e0::/48",
        )
    ),
    default_tags={
        "table1": "https://example.com/menu/table1",
        "table2": "https://example.com/menu/table2",
        "instagram": "https://instagram.com",
        "telegram": "https://t.me",
    },
)
