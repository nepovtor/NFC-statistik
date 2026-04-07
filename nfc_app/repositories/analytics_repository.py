from __future__ import annotations

from datetime import datetime, timedelta

from ..database import close_connection, get_connection


def _time_windows() -> tuple[str, str]:
    today_start = datetime.now().strftime("%Y-%m-%d 00:00:00")
    last_24h = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    return today_start, last_24h


def get_admin_dashboard_snapshot() -> dict:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS count FROM visits")
    total_visits = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM tags")
    total_tags = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM tags WHERE is_active = 1")
    active_tags = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM clients")
    total_clients = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM tags WHERE client_id IS NOT NULL")
    assigned_tags = cur.fetchone()["count"]

    today_start, last_24h = _time_windows()

    cur.execute("SELECT COUNT(*) AS count FROM visits WHERE visited_at >= ?", (today_start,))
    today_visits = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM visits WHERE visited_at >= ?", (last_24h,))
    last_24h_visits = cur.fetchone()["count"]

    cur.execute(
        """
        SELECT v.tag_code, COUNT(*) AS total_clicks
        FROM visits v
        GROUP BY v.tag_code
        ORDER BY total_clicks DESC, v.tag_code ASC
        LIMIT 8
        """
    )
    top_tags = cur.fetchall()

    cur.execute(
        """
        SELECT
            t.code,
            t.name,
            t.target_url,
            t.is_active,
            t.client_id,
            c.name AS client_name,
            c.login AS client_login,
            c.is_active AS client_is_active,
            (SELECT COUNT(*) FROM visits v WHERE v.tag_code = t.code) AS clicks
        FROM tags t
        LEFT JOIN clients c ON c.id = t.client_id
        ORDER BY clicks DESC, t.code ASC
        LIMIT 8
        """
    )
    tags = cur.fetchall()

    cur.execute(
        """
        SELECT
            v.id,
            v.tag_code,
            v.visited_at,
            v.ip_address,
            v.user_agent
        FROM visits v
        ORDER BY v.id DESC
        LIMIT 10
        """
    )
    last_visits = cur.fetchall()
    close_connection(conn)

    return {
        "total_visits": total_visits,
        "total_tags": total_tags,
        "active_tags": active_tags,
        "total_clients": total_clients,
        "assigned_tags": assigned_tags,
        "today_visits": today_visits,
        "last_24h_visits": last_24h_visits,
        "top_tags": top_tags,
        "tags": tags,
        "last_visits": last_visits,
    }


def get_client_dashboard_snapshot(client_id: int) -> dict:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS count FROM tags WHERE client_id = ?", (client_id,))
    total_tags = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM tags WHERE client_id = ? AND is_active = 1", (client_id,))
    active_tags = cur.fetchone()["count"]

    cur.execute(
        """
        SELECT COUNT(*) AS count
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        WHERE t.client_id = ?
        """,
        (client_id,),
    )
    total_visits = cur.fetchone()["count"]

    today_start, last_24h = _time_windows()

    cur.execute(
        """
        SELECT COUNT(*) AS count
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        WHERE t.client_id = ? AND v.visited_at >= ?
        """,
        (client_id, today_start),
    )
    today_visits = cur.fetchone()["count"]

    cur.execute(
        """
        SELECT COUNT(*) AS count
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        WHERE t.client_id = ? AND v.visited_at >= ?
        """,
        (client_id, last_24h),
    )
    last_24h_visits = cur.fetchone()["count"]

    cur.execute(
        """
        SELECT v.tag_code, COUNT(*) AS total_clicks
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        WHERE t.client_id = ?
        GROUP BY v.tag_code
        ORDER BY total_clicks DESC, v.tag_code ASC
        LIMIT 8
        """,
        (client_id,),
    )
    top_tags = cur.fetchall()

    cur.execute(
        """
        SELECT
            t.code,
            t.name,
            t.target_url,
            t.is_active,
            (SELECT COUNT(*) FROM visits v WHERE v.tag_code = t.code) AS clicks
        FROM tags t
        WHERE t.client_id = ?
        ORDER BY clicks DESC, t.code ASC
        LIMIT 8
        """,
        (client_id,),
    )
    tags = cur.fetchall()

    cur.execute(
        """
        SELECT
            v.id,
            v.tag_code,
            v.visited_at,
            v.ip_address,
            v.user_agent
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        WHERE t.client_id = ?
        ORDER BY v.id DESC
        LIMIT 10
        """,
        (client_id,),
    )
    last_visits = cur.fetchall()
    close_connection(conn)

    return {
        "total_tags": total_tags,
        "active_tags": active_tags,
        "total_visits": total_visits,
        "today_visits": today_visits,
        "last_24h_visits": last_24h_visits,
        "top_tags": top_tags,
        "tags": tags,
        "last_visits": last_visits,
    }
