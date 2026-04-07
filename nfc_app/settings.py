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


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return int(raw_value.strip())


def _env_first(*names: str) -> str:
    for name in names:
        raw_value = os.getenv(name)
        if raw_value is not None:
            return raw_value.strip()
    return ""


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    app_title: str
    app_version: str
    base_dir: Path
    db_path: Path
    app_env: str
    session_secret: str
    admin_login: str
    admin_password_hash: str
    admin_cookie_name: str
    client_cookie_name: str
    session_ttl_hours: int
    session_touch_interval_minutes: int
    secure_cookies: bool
    login_rate_limit_attempts: int
    login_rate_limit_window_minutes: int
    sqlite_busy_timeout_ms: int
    sqlite_journal_mode: str
    public_base_url: str
    admin_tailscale_only: bool
    trust_proxy_headers: bool
    admin_allowed_networks: tuple[str, ...]
    default_tags: dict[str, str] = field(default_factory=dict)


def validate_runtime_settings() -> None:
    missing_names: list[str] = []
    if not settings.session_secret:
        missing_names.append("SESSION_SECRET")
    if not settings.admin_login:
        missing_names.append("ADMIN_LOGIN")
    if not settings.admin_password_hash:
        missing_names.append("ADMIN_PASSWORD_HASH")

    if missing_names:
        raise RuntimeError(
            "Missing required environment variables: "
            + ", ".join(missing_names)
            + ". Configure them before starting the app."
        )

    if settings.sqlite_journal_mode.upper() not in {"WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"}:
        raise RuntimeError("SQLITE_JOURNAL_MODE must be one of WAL, DELETE, TRUNCATE, PERSIST, MEMORY or OFF.")
    if settings.session_ttl_hours <= 0:
        raise RuntimeError("SESSION_TTL_HOURS must be greater than zero.")
    if settings.session_touch_interval_minutes <= 0:
        raise RuntimeError("SESSION_TOUCH_INTERVAL_MINUTES must be greater than zero.")
    if settings.login_rate_limit_attempts <= 0:
        raise RuntimeError("LOGIN_RATE_LIMIT_ATTEMPTS must be greater than zero.")
    if settings.login_rate_limit_window_minutes <= 0:
        raise RuntimeError("LOGIN_RATE_LIMIT_WINDOW_MINUTES must be greater than zero.")
    if settings.sqlite_busy_timeout_ms <= 0:
        raise RuntimeError("SQLITE_BUSY_TIMEOUT_MS must be greater than zero.")


BASE_DIR = Path(__file__).resolve().parent.parent
app_env = _env_first("APP_ENV") or "development"

settings = Settings(
    app_title="NFC Statistics App",
    app_version="4.1",
    base_dir=BASE_DIR,
    db_path=Path(os.getenv("NFC_STATS_DB_PATH", str(BASE_DIR / "nfc_stats.db"))),
    app_env=app_env,
    session_secret=_env_first("SESSION_SECRET", "ADMIN_SESSION_SECRET"),
    admin_login=_env_first("ADMIN_LOGIN"),
    admin_password_hash=_env_first("ADMIN_PASSWORD_HASH"),
    admin_cookie_name="admin_auth",
    client_cookie_name="client_auth",
    session_ttl_hours=_env_int("SESSION_TTL_HOURS", 12),
    session_touch_interval_minutes=_env_int("SESSION_TOUCH_INTERVAL_MINUTES", 5),
    secure_cookies=_env_flag("COOKIE_SECURE", app_env == "production"),
    login_rate_limit_attempts=_env_int("LOGIN_RATE_LIMIT_ATTEMPTS", 5),
    login_rate_limit_window_minutes=_env_int("LOGIN_RATE_LIMIT_WINDOW_MINUTES", 15),
    sqlite_busy_timeout_ms=_env_int("SQLITE_BUSY_TIMEOUT_MS", 5000),
    sqlite_journal_mode=_env_first("SQLITE_JOURNAL_MODE") or "WAL",
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
