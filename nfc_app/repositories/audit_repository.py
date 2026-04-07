from __future__ import annotations

from .common import rows_to_dicts
from ..database import close_connection, commit_connection, get_connection, now_str


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


def list_admin_audit_logs(limit: int) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
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
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows
