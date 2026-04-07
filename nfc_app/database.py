from __future__ import annotations

import sqlite3
from datetime import datetime

from .settings import settings


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cursor: sqlite3.Cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row["name"] == column_name for row in cursor.fetchall())


def init_db() -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            login TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            client_id INTEGER REFERENCES clients(id)
        )
        """
    )

    if not column_exists(cur, "tags", "client_id"):
        cur.execute("ALTER TABLE tags ADD COLUMN client_id INTEGER")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag_code TEXT NOT NULL,
            target_url TEXT NOT NULL,
            visited_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            referer TEXT
        )
        """
    )

    cur.execute("CREATE INDEX IF NOT EXISTS idx_tags_client_id ON tags(client_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_visits_tag_code ON visits(tag_code)")

    for code, url in settings.default_tags.items():
        cur.execute(
            """
            INSERT OR IGNORE INTO tags (code, name, target_url, is_active, created_at, client_id)
            VALUES (?, ?, ?, 1, ?, NULL)
            """,
            (code, code.capitalize(), url, now_str()),
        )

    conn.commit()
    conn.close()
