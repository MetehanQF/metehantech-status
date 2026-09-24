"""Persistent SQLite audit trail for authenticated administration actions."""

from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "admin_activity.db"
ACTIVITY_LIMITS = {50, 100, 500}


def db_path():
    configured = os.environ.get("ADMIN_ACTIVITY_DB", "").strip()
    return Path(configured) if configured else DEFAULT_DB_PATH


def connect():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    os.chmod(path, 0o600)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS admin_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT NOT NULL
        )
    """)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS admin_activity_recent ON admin_activity(id DESC)"
    )
    connection.execute("""
        CREATE TABLE IF NOT EXISTS admin_pending_restart (
            target TEXT PRIMARY KEY,
            requested_at TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT NOT NULL
        )
    """)
    return connection


def record_activity(action, target, result, client_ip, user_agent, *, timestamp=None):
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    with closing(connect()) as connection:
        connection.execute(
            "INSERT INTO admin_activity(timestamp, action, target, result, client_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, action[:80], target[:160], result[:160], client_ip[:64], user_agent[:200]),
        )
        connection.commit()


def get_activity(limit=50):
    if limit not in ACTIVITY_LIMITS:
        raise ValueError("Invalid activity limit")
    with closing(connect()) as connection:
        rows = connection.execute(
            "SELECT timestamp, action, target, result, client_ip, user_agent FROM admin_activity ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        dict(zip(("timestamp", "action", "target", "result", "client_ip", "user_agent"), row))
        for row in rows
    ]


def set_pending_restart(target, client_ip, user_agent):
    with closing(connect()) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO admin_pending_restart(target, requested_at, client_ip, user_agent) VALUES (?, ?, ?, ?)",
            (target, datetime.now(timezone.utc).isoformat(), client_ip[:64], user_agent[:200]),
        )
        connection.commit()


def clear_pending_restart(target):
    with closing(connect()) as connection:
        connection.execute("DELETE FROM admin_pending_restart WHERE target = ?", (target,))
        connection.commit()


def complete_pending_restart(target):
    """Convert a durable self-restart marker into a success record on next boot."""
    with closing(connect()) as connection:
        row = connection.execute(
            "SELECT client_ip, user_agent FROM admin_pending_restart WHERE target = ?",
            (target,),
        ).fetchone()
        if row is None:
            return False
        connection.execute(
            "INSERT INTO admin_activity(timestamp, action, target, result, client_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                "service_restart_success",
                target,
                "success",
                row[0],
                row[1],
            ),
        )
        connection.execute("DELETE FROM admin_pending_restart WHERE target = ?", (target,))
        connection.commit()
        return True
