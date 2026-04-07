from __future__ import annotations

import sqlite3
import sys
from datetime import datetime
from typing import Callable

from .settings import settings, validate_runtime_settings


Migration = Callable[[sqlite3.Connection], None]


def now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {settings.sqlite_busy_timeout_ms}")
    conn.execute(f"PRAGMA journal_mode = {settings.sqlite_journal_mode.upper()}")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def column_exists(cursor: sqlite3.Cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row["name"] == column_name for row in cursor.fetchall())


def _ensure_schema_migrations_table(cursor: sqlite3.Cursor) -> None:
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )


def _insert_default_tags(cursor: sqlite3.Cursor) -> None:
    for code, url in settings.default_tags.items():
        cursor.execute(
            """
            INSERT OR IGNORE INTO tags (code, name, target_url, is_active, created_at, client_id)
            VALUES (?, ?, ?, 1, ?, NULL)
            """,
            (code, code.capitalize(), url, now_str()),
        )


def _bootstrap_admin(cursor: sqlite3.Cursor) -> None:
    cursor.execute("SELECT id FROM admins WHERE login = ?", (settings.admin_login,))
    admin = cursor.fetchone()
    if admin:
        cursor.execute(
            """
            UPDATE admins
            SET password_hash = ?, is_active = 1
            WHERE id = ?
            """,
            (settings.admin_password_hash, admin["id"]),
        )
        return

    cursor.execute(
        """
        INSERT INTO admins (login, password_hash, is_active, created_at)
        VALUES (?, ?, 1, ?)
        """,
        (settings.admin_login, settings.admin_password_hash, now_str()),
    )


def _migration_001_base_schema(conn: sqlite3.Connection) -> None:
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
            client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL
        )
        """
    )
    if not column_exists(cur, "tags", "client_id"):
        cur.execute("ALTER TABLE tags ADD COLUMN client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL")

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
    _insert_default_tags(cur)


def _migration_002_admin_sessions(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,
            principal_type TEXT NOT NULL,
            admin_id INTEGER REFERENCES admins(id) ON DELETE CASCADE,
            client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
            session_token_hash TEXT NOT NULL UNIQUE,
            csrf_token TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        )
        """
    )

    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_scope_hash ON sessions(scope, session_token_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
    _bootstrap_admin(cur)


def _migration_003_login_attempts(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,
            login_key TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            was_success INTEGER NOT NULL DEFAULT 0,
            attempted_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_scope_login_time ON login_attempts(scope, login_key, attempted_at)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_scope_ip_time ON login_attempts(scope, ip_address, attempted_at)"
    )


MIGRATIONS: tuple[tuple[str, Migration], ...] = (
    ("001_base_schema", _migration_001_base_schema),
    ("002_admin_sessions", _migration_002_admin_sessions),
    ("003_login_attempts", _migration_003_login_attempts),
)


def run_migrations() -> None:
    validate_runtime_settings()
    conn = get_connection()
    cur = conn.cursor()
    _ensure_schema_migrations_table(cur)
    cur.execute("SELECT name FROM schema_migrations")
    applied_migrations = {row["name"] for row in cur.fetchall()}

    for name, migration in MIGRATIONS:
        if name in applied_migrations:
            continue
        migration(conn)
        cur.execute(
            "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
            (name, now_str()),
        )

    conn.commit()
    conn.close()


def init_db() -> None:
    run_migrations()


def assert_database_ready() -> None:
    conn = get_connection()
    cur = conn.cursor()
    _ensure_schema_migrations_table(cur)
    cur.execute("SELECT name FROM schema_migrations")
    applied_migrations = {row["name"] for row in cur.fetchall()}
    conn.close()

    missing_migrations = [name for name, _ in MIGRATIONS if name not in applied_migrations]
    if missing_migrations:
        raise RuntimeError(
            "Database migrations are pending: "
            + ", ".join(missing_migrations)
            + ". Run `python3 -m nfc_app.database migrate` before starting the app."
        )


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    action = args[0] if args else "migrate"

    if action == "migrate":
        run_migrations()
        print(f"Applied database migrations for {settings.db_path}")
        return 0
    if action == "check":
        validate_runtime_settings()
        assert_database_ready()
        print(f"Database is ready: {settings.db_path}")
        return 0

    print("Usage: python3 -m nfc_app.database [migrate|check]", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
