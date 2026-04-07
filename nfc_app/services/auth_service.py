from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..repositories.security_repository import (
    clear_failed_login_attempts,
    count_recent_failed_attempts_by_ip,
    count_recent_failed_attempts_by_login,
    get_admin_auth_record,
    get_client_auth_record,
    get_oldest_recent_failed_attempt,
    prune_login_attempts,
    record_login_attempt,
)
from ..security.constants import SESSION_SCOPE_ADMIN, SESSION_SCOPE_CLIENT
from ..security.passwords import verify_password
from ..settings import settings


@dataclass(frozen=True)
class LoginResult:
    ok: bool
    principal_id: int | None = None
    message: str | None = None
    retry_after_seconds: int = 0
    reason: str = "invalid_credentials"


def _now() -> datetime:
    return datetime.utcnow()


def _to_str(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _window_start() -> datetime:
    return _now() - timedelta(minutes=settings.login_rate_limit_window_minutes)


def _prune_old_attempts() -> None:
    prune_login_attempts(_to_str(_now() - timedelta(minutes=settings.login_rate_limit_window_minutes * 4)))


def _retry_after_seconds(oldest_attempted_at: str | None) -> int:
    if not oldest_attempted_at:
        return settings.login_rate_limit_window_minutes * 60

    oldest = datetime.strptime(oldest_attempted_at, "%Y-%m-%d %H:%M:%S")
    expires_at = oldest + timedelta(minutes=settings.login_rate_limit_window_minutes)
    remaining = int((expires_at - _now()).total_seconds())
    return max(1, remaining)


def _rate_limit_message(retry_after_seconds: int) -> str:
    retry_after_minutes = max(1, (retry_after_seconds + 59) // 60)
    return f"Слишком много неудачных попыток входа. Попробуй снова через {retry_after_minutes} мин."


def _is_rate_limited(scope: str, login_key: str, ip_address: str) -> tuple[bool, int]:
    since_time = _to_str(_window_start())
    login_failures = count_recent_failed_attempts_by_login(scope, login_key, since_time)
    ip_failures = count_recent_failed_attempts_by_ip(scope, ip_address, since_time)
    if login_failures < settings.login_rate_limit_attempts and ip_failures < settings.login_rate_limit_attempts:
        return False, 0

    oldest_attempted_at = get_oldest_recent_failed_attempt(scope, login_key, ip_address, since_time)
    return True, _retry_after_seconds(oldest_attempted_at)


def _authenticate(scope: str, login_key: str, password: str, ip_address: str, *, admin: bool) -> LoginResult:
    _prune_old_attempts()

    is_blocked, retry_after_seconds = _is_rate_limited(scope, login_key, ip_address)
    if is_blocked:
        return LoginResult(
            ok=False,
            message=_rate_limit_message(retry_after_seconds),
            retry_after_seconds=retry_after_seconds,
            reason="rate_limited",
        )

    principal = get_admin_auth_record(login_key) if admin else get_client_auth_record(login_key)
    is_valid = bool(principal) and int(principal["is_active"]) == 1 and verify_password(password, principal["password_hash"])

    record_login_attempt(scope, login_key, ip_address, was_success=is_valid)

    if not is_valid:
        return LoginResult(ok=False, message="Неверный логин или пароль", reason="invalid_credentials")

    clear_failed_login_attempts(scope, login_key, ip_address)
    return LoginResult(ok=True, principal_id=int(principal["id"]), reason="ok")


def authenticate_admin(login_key: str, password: str, ip_address: str) -> LoginResult:
    return _authenticate(SESSION_SCOPE_ADMIN, login_key, password, ip_address, admin=True)


def authenticate_client(login_key: str, password: str, ip_address: str) -> LoginResult:
    return _authenticate(SESSION_SCOPE_CLIENT, login_key, password, ip_address, admin=False)
