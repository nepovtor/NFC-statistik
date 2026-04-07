from __future__ import annotations

from .common import rows_to_dicts
from ..database import close_connection, commit_connection, get_connection, now_str


def _build_audit_filters(action: str, admin_login: str, actions: tuple[str, ...] | None = None) -> tuple[str, list[str]]:
    conditions: list[str] = []
    params: list[str] = []

    if action:
        conditions.append("action = ?")
        params.append(action)
    elif actions:
        placeholders = ", ".join(["?"] * len(actions))
        conditions.append(f"action IN ({placeholders})")
        params.extend(actions)

    if admin_login:
        conditions.append("admin_login = ?")
        params.append(admin_login)

    where_sql = ""
    if conditions:
        where_sql = "WHERE " + " AND ".join(conditions)
    return where_sql, params


def create_admin_audit_log(
    admin_id: int | None,
    admin_login: str,
    action: str,
    target_type: str,
    target_id: str | None,
    target_label: str | None,
    ip_address: str | None,
    user_agent: str | None,
    details_json: str | None,
) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO admin_audit_logs (
            admin_id,
            admin_login,
            action,
            target_type,
            target_id,
            target_label,
            ip_address,
            user_agent,
            details_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            admin_id,
            admin_login,
            action,
            target_type,
            target_id,
            target_label,
            ip_address,
            user_agent,
            details_json,
            now_str(),
        ),
    )
    commit_connection(conn)
    close_connection(conn)


def count_admin_audit_logs(action: str = "", admin_login: str = "") -> int:
    conn = get_connection()
    cur = conn.cursor()
    where_sql, params = _build_audit_filters(action, admin_login)
    cur.execute(f"SELECT COUNT(*) AS total FROM admin_audit_logs {where_sql}", params)
    total = int(cur.fetchone()["total"])
    close_connection(conn)
    return total


def list_admin_audit_logs(limit: int, page: int = 1, action: str = "", admin_login: str = "") -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    where_sql, params = _build_audit_filters(action, admin_login)
    offset = max(page - 1, 0) * limit
    cur.execute(
        f"""
        SELECT
            id,
            admin_id,
            admin_login,
            action,
            target_type,
            target_id,
            target_label,
            ip_address,
            user_agent,
            details_json,
            created_at
        FROM admin_audit_logs
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def count_admin_audit_logs_for_actions(actions: tuple[str, ...], admin_login: str = "") -> int:
    if not actions:
        return 0

    conn = get_connection()
    cur = conn.cursor()
    where_sql, params = _build_audit_filters("", admin_login, actions=actions)
    cur.execute(f"SELECT COUNT(*) AS total FROM admin_audit_logs {where_sql}", params)
    total = int(cur.fetchone()["total"])
    close_connection(conn)
    return total


def get_latest_admin_audit_event_for_actions(actions: tuple[str, ...], admin_login: str = "") -> dict | None:
    if not actions:
        return None

    conn = get_connection()
    cur = conn.cursor()
    where_sql, params = _build_audit_filters("", admin_login, actions=actions)
    cur.execute(
        f"""
        SELECT
            id,
            admin_id,
            admin_login,
            action,
            target_type,
            target_id,
            target_label,
            ip_address,
            user_agent,
            details_json,
            created_at
        FROM admin_audit_logs
        {where_sql}
        ORDER BY id DESC
        LIMIT 1
        """,
        params,
    )
    row = cur.fetchone()
    close_connection(conn)
    return dict(row) if row else None
