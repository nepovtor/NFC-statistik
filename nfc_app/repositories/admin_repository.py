from __future__ import annotations

from .common import rows_to_dicts
from ..database import close_connection, commit_connection, get_connection, now_str


def list_clients_with_stats() -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            c.id,
            c.name,
            c.login,
            c.is_active,
            c.created_at,
            (SELECT COUNT(*) FROM tags t WHERE t.client_id = c.id) AS tags_count,
            (
                SELECT COUNT(*)
                FROM visits v
                JOIN tags t ON t.code = v.tag_code
                WHERE t.client_id = c.id
            ) AS visits_count
        FROM clients c
        ORDER BY c.id DESC
        """
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def create_client(name: str, login: str, password_hash: str) -> None:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO clients (name, login, password_hash, is_active, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (name, login, password_hash, now_str()),
        )
        commit_connection(conn)
    finally:
        close_connection(conn)


def toggle_client_status(client_id: int) -> bool | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM clients WHERE id = ?", (client_id,))
    row = cur.fetchone()
    if not row:
        close_connection(conn)
        return None

    new_status = 0 if int(row["is_active"]) == 1 else 1
    cur.execute("UPDATE clients SET is_active = ? WHERE id = ?", (new_status, client_id))
    commit_connection(conn)
    close_connection(conn)
    return bool(new_status)


def list_clients_for_assignment() -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, login, is_active FROM clients ORDER BY name ASC, login ASC")
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def get_client_identity(client_id: int) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM clients WHERE id = ?", (client_id,))
    row = cur.fetchone()
    close_connection(conn)
    return dict(row) if row else None


def list_tags_with_clients() -> list[dict]:
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
            t.client_id,
            c.name AS client_name,
            c.login AS client_login,
            c.is_active AS client_is_active,
            (SELECT COUNT(*) FROM visits v WHERE v.tag_code = t.code) AS clicks
        FROM tags t
        LEFT JOIN clients c ON c.id = t.client_id
        ORDER BY t.id DESC
        """
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def create_tag(code: str, name: str, target_url: str, owner_id: int | None) -> None:
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO tags (code, name, target_url, is_active, created_at, client_id)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
            (code, name, target_url, now_str(), owner_id),
        )
        commit_connection(conn)
    finally:
        close_connection(conn)


def get_tag_identity(tag_id: int) -> dict | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, is_active FROM tags WHERE id = ?", (tag_id,))
    row = cur.fetchone()
    close_connection(conn)
    return dict(row) if row else None


def assign_tag_owner(tag_id: int, owner_id: int | None) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE tags SET client_id = ? WHERE id = ?", (owner_id, tag_id))
    changed = cur.rowcount > 0
    commit_connection(conn)
    close_connection(conn)
    return changed


def toggle_tag_status(tag_id: int) -> bool | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM tags WHERE id = ?", (tag_id,))
    row = cur.fetchone()
    if not row:
        close_connection(conn)
        return None

    new_status = 0 if int(row["is_active"]) == 1 else 1
    cur.execute("UPDATE tags SET is_active = ? WHERE id = ?", (new_status, tag_id))
    commit_connection(conn)
    close_connection(conn)
    return bool(new_status)


def delete_tag(tag_id: int) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
    changed = cur.rowcount > 0
    commit_connection(conn)
    close_connection(conn)
    return changed
