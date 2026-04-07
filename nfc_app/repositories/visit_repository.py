from __future__ import annotations

from .common import rows_to_dicts
from ..database import close_connection, commit_connection, get_connection
from ..visit_policy import prepare_visit_storage_payload


def _build_admin_visit_filters(tag: str, client_login: str) -> tuple[str, list[str]]:
    conditions: list[str] = []
    params: list[str] = []

    if tag:
        conditions.append("v.tag_code = ?")
        params.append(tag)

    if client_login:
        conditions.append("c.login = ?")
        params.append(client_login)

    where_sql = ""
    if conditions:
        where_sql = "WHERE " + " AND ".join(conditions)
    return where_sql, params


def record_visit(
    tag_code: str,
    target_url: str,
    visited_at: str,
    ip_address: str,
    user_agent: str,
    referer: str,
) -> None:
    visit_payload = prepare_visit_storage_payload(
        tag_code=tag_code,
        target_url=target_url,
        visited_at=visited_at,
        ip_address=ip_address,
        user_agent=user_agent,
        referer=referer,
    )
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO visits (tag_code, target_url, visited_at, ip_address, user_agent, referer)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            visit_payload["tag_code"],
            visit_payload["target_url"],
            visit_payload["visited_at"],
            visit_payload["ip_address"],
            visit_payload["user_agent"],
            visit_payload["referer"],
        ),
    )
    commit_connection(conn)
    close_connection(conn)


def list_admin_visit_tag_codes() -> list[str]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT code FROM tags ORDER BY code ASC")
    codes = [row["code"] for row in cur.fetchall()]
    close_connection(conn)
    return codes


def list_client_visit_tag_codes(client_id: int) -> list[str]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT code FROM tags WHERE client_id = ? ORDER BY code ASC", (client_id,))
    codes = [row["code"] for row in cur.fetchall()]
    close_connection(conn)
    return codes


def list_admin_visits(tag: str, client_login: str, limit: int) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    where_sql, params = _build_admin_visit_filters(tag, client_login)
    cur.execute(
        f"""
        SELECT
            v.id,
            v.tag_code,
            v.target_url,
            v.visited_at,
            v.ip_address,
            v.user_agent,
            v.referer,
            c.name AS client_name,
            c.login AS client_login
        FROM visits v
        LEFT JOIN tags t ON t.code = v.tag_code
        LEFT JOIN clients c ON c.id = t.client_id
        {where_sql}
        ORDER BY v.id DESC
        LIMIT ?
        """,
        [*params, limit],
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def list_admin_visits_for_export(tag: str, client_login: str, limit: int) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    where_sql, params = _build_admin_visit_filters(tag, client_login)
    cur.execute(
        f"""
        SELECT
            v.id,
            v.tag_code,
            v.target_url,
            v.visited_at,
            v.ip_address,
            v.user_agent,
            v.referer,
            c.name AS client_name,
            c.login AS client_login
        FROM visits v
        LEFT JOIN tags t ON t.code = v.tag_code
        LEFT JOIN clients c ON c.id = t.client_id
        {where_sql}
        ORDER BY v.id DESC
        LIMIT ?
        """,
        [*params, limit],
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def list_client_visits(client_id: int, tag: str, limit: int) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    if tag:
        cur.execute(
            """
            SELECT
                v.id,
                v.tag_code,
                v.target_url,
                v.visited_at,
                v.ip_address,
                v.user_agent,
                v.referer
            FROM visits v
            JOIN tags t ON t.code = v.tag_code
            WHERE t.client_id = ? AND v.tag_code = ?
            ORDER BY v.id DESC
            LIMIT ?
            """,
            (client_id, tag, limit),
        )
    else:
        cur.execute(
            """
            SELECT
                v.id,
                v.tag_code,
                v.target_url,
                v.visited_at,
                v.ip_address,
                v.user_agent,
                v.referer
            FROM visits v
            JOIN tags t ON t.code = v.tag_code
            WHERE t.client_id = ?
            ORDER BY v.id DESC
            LIMIT ?
            """,
            (client_id, limit),
        )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows


def list_client_visits_for_export(client_id: int, tag: str, limit: int) -> list[dict]:
    conn = get_connection()
    cur = conn.cursor()
    params: list[object] = [client_id]
    where_sql = "WHERE t.client_id = ?"
    if tag:
        where_sql += " AND v.tag_code = ?"
        params.append(tag)
    cur.execute(
        f"""
        SELECT
            v.id,
            v.tag_code,
            v.target_url,
            v.visited_at,
            v.ip_address,
            v.user_agent,
            v.referer
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        {where_sql}
        ORDER BY v.id DESC
        LIMIT ?
        """,
        [*params, limit],
    )
    rows = rows_to_dicts(cur.fetchall())
    close_connection(conn)
    return rows
