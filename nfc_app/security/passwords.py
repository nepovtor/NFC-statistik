from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
from typing import Optional


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 200_000


def _pbkdf2_digest(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations).hex()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = _pbkdf2_digest(password, salt, PASSWORD_ITERATIONS)
    return f"{PASSWORD_SCHEME}${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith(f"{PASSWORD_SCHEME}$"):
        try:
            _, iterations, salt, stored_digest = password_hash.split("$", 3)
            digest = _pbkdf2_digest(password, salt, int(iterations))
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(digest, stored_digest)

    if password_hash.count("$") == 1:
        salt, stored_digest = password_hash.split("$", 1)
        try:
            digest = _pbkdf2_digest(password, salt, 100_000)
        except ValueError:
            return False
        return hmac.compare_digest(digest, stored_digest)

    return hmac.compare_digest(password, password_hash)


def valid_client_login(login: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._@-]{3,50}", login))


def normalize_client_id(raw_value: str) -> Optional[int]:
    value = (raw_value or "").strip()
    if not value:
        return None
    client_id = int(value)
    if client_id <= 0:
        raise ValueError
    return client_id


def client_exists(cursor: sqlite3.Cursor, client_id: int) -> bool:
    cursor.execute("SELECT id FROM clients WHERE id = ?", (client_id,))
    return cursor.fetchone() is not None
