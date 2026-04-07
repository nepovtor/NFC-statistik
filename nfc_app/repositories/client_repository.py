from __future__ import annotations

from .common import rows_to_dicts
from ..database import close_connection, commit_connection, get_connection


def list_tags_for_client(client_id: int) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            t.id,
            t.code,
            t.name,
            t.target_url,
            t.is_active,
            t.created_at,
            (SELECT COUNT(*) FROM visits v WHERE v.tag_code = t.code) AS clicks
        FROM tags t
        WHERE t.client_id = ?
        ORDER BY t.id DESC
        """,
        (client_id,),
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def get_client_tag(tag_id: int, client_id: int) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, code
        FROM tags
        WHERE id = ? AND client_id = ?
        """,
        (tag_id, client_id),
    )
    row = cur.fetchone()
    close_connection(conn)
    return dict(row) if row else None


def update_client_tag(tag_id: int, client_id: int, name: str, target_url: str, is_active: int) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE tags
        SET name = ?, target_url = ?, is_active = ?
        WHERE id = ? AND client_id = ?
        """,
        (name, target_url, is_active, tag_id, client_id),
    )
    commit_connection(conn)
    close_connection(conn)
