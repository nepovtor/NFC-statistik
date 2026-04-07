from __future__ import annotations

from ..database import get_connection, now_str


def get_admin_auth_record(login: str) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, login, password_hash, is_active
        FROM admins
        WHERE login = ?
        """,
        (login,),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_client_auth_record(login: str) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, login, password_hash, is_active
        FROM clients
        WHERE login = ?
        """,
        (login,),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def record_login_attempt(scope: str, login_key: str, ip_address: str, was_success: bool) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO login_attempts (scope, login_key, ip_address, was_success, attempted_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (scope, login_key, ip_address, 1 if was_success else 0, now_str()),
    )
    conn.commit()
    conn.close()


def clear_failed_login_attempts(scope: str, login_key: str, ip_address: str) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        DELETE FROM login_attempts
        WHERE scope = ?
          AND was_success = 0
          AND (login_key = ? OR ip_address = ?)
        """,
        (scope, login_key, ip_address),
    )
    conn.commit()
    conn.close()


def count_recent_failed_attempts_by_login(scope: str, login_key: str, since_time: str) -> int:
    if not login_key:
        return 0

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE scope = ?
          AND login_key = ?
          AND was_success = 0
          AND attempted_at >= ?
        """,
        (scope, login_key, since_time),
    )
    total = int(cur.fetchone()["total"])
    conn.close()
    return total


def count_recent_failed_attempts_by_ip(scope: str, ip_address: str, since_time: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE scope = ?
          AND ip_address = ?
          AND was_success = 0
          AND attempted_at >= ?
        """,
        (scope, ip_address, since_time),
    )
    total = int(cur.fetchone()["total"])
    conn.close()
    return total


def get_oldest_recent_failed_attempt(scope: str, login_key: str, ip_address: str, since_time: str) -> str | None:
    conn = get_connection()
    cur = conn.cursor()
    if login_key:
        cur.execute(
            """
            SELECT attempted_at
            FROM login_attempts
            WHERE scope = ?
              AND was_success = 0
              AND attempted_at >= ?
              AND (login_key = ? OR ip_address = ?)
            ORDER BY attempted_at ASC
            LIMIT 1
            """,
            (scope, since_time, login_key, ip_address),
        )
    else:
        cur.execute(
            """
            SELECT attempted_at
            FROM login_attempts
            WHERE scope = ?
              AND was_success = 0
              AND attempted_at >= ?
              AND ip_address = ?
            ORDER BY attempted_at ASC
            LIMIT 1
            """,
            (scope, since_time, ip_address),
        )
    row = cur.fetchone()
    conn.close()
    return row["attempted_at"] if row else None


def prune_login_attempts(before_time: str) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (before_time,))
    conn.commit()
    conn.close()
