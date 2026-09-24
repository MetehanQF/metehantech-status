"""Transition-based alarms stored alongside metric history in SQLite."""

import math
import re
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from incidents import apply_transition, ensure_schema as ensure_incidents_schema, reconcile_baseline

DB_PATH = Path(__file__).resolve().parent / "data" / "metrics.db"
RETENTION_SECONDS = 30 * 86400
SEVERITIES = {"info", "warning", "critical", "recovery"}
SOURCE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")
SERVICE_SOURCES = {
    "MetehanTech Home": "metehantech_home",
    "MetehanTech Clan": "metehantech_clan",
    "Cloudflare Tunnel": "cloudflared",
    "Tailscale": "tailscale",
    "RustDesk": "rustdesk",
    "Docker": "docker",
}
NUMBER_PATTERN = re.compile(r"^\s*(-?\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class Observation:
    state: str
    label: str
    value: float | None = None


def number(value):
    match = NUMBER_PATTERN.match(str(value))
    if not match:
        return None
    result = float(match.group(1))
    return result if math.isfinite(result) else None


def metric_state(metric, value):
    if value is None:
        return None
    warning, critical = (70, 80) if metric == "temperature" else (80, 90)
    return "critical" if value >= critical else "warning" if value >= warning else "normal"


def observations(snapshot):
    """Map known current conditions to stable source/type keys."""
    found = {}
    for device in snapshot.get("devices", []):
        source = device.get("id")
        if source not in {"pi5", "pcold"}:
            continue
        label = device.get("name") or ("Raspberry Pi 5" if source == "pi5" else "MetehanTechPcOld")
        online = device.get("online")
        if not isinstance(online, bool):
            continue
        found[(source, "online")] = Observation("up" if online else "down", label)
        if not online:
            continue
        for metric in ("temperature", "ram", "disk"):
            value = number(device.get("metrics", {}).get(metric))
            state = metric_state(metric, value)
            if state:
                found[(source, metric)] = Observation(state, label, value)
        checks = device.get("checks", {})
        if source == "pi5" and isinstance(checks.get("Throttled"), bool):
            found[(source, "throttled")] = Observation("down" if checks["Throttled"] else "up", label)
        if source == "pcold":
            for name in ("Docker", "SMART"):
                value = checks.get(name)
                if isinstance(value, bool):
                    found[(source, name.lower())] = Observation("up" if value else "down", label)
    for service in snapshot.get("services", []):
        label = service.get("name")
        source = SERVICE_SOURCES.get(label)
        operational = service.get("operational")
        if source and isinstance(operational, bool):
            found[(source, "service")] = Observation("up" if operational else "down", label)
    return found


def connect(db_path=DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical','recovery')),
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active','resolved','informational'))
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS events_time ON events(timestamp DESC, id DESC)")
    connection.execute("CREATE INDEX IF NOT EXISTS events_filter ON events(source, severity, timestamp DESC)")
    ensure_incidents_schema(connection)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS event_states (
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            state TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(source, event_type)
        )
    """)
    return connection


def event_details(source, event_type, observation, previous):
    state, label, value = observation.state, observation.label, observation.value
    if event_type in {"temperature", "ram", "disk"}:
        metric = {"temperature": "Temperature", "ram": "RAM", "disk": "Disk"}[event_type]
        unit = "°C" if event_type == "temperature" else "%"
        if state == "normal":
            return ("recovery", f"{metric} recovered", f"{label} {metric.lower()} returned to normal at {value:g}{unit}.", "resolved")
        return (state, f"{metric} {state}", f"{label} {metric.lower()} reached {value:g}{unit}.", "active")
    if state == "up":
        if event_type == "online":
            title = f"{label} online again"
        elif event_type == "throttled":
            title = "Raspberry Pi 5 throttling cleared"
        elif event_type == "smart":
            title = "SMART recovered"
        else:
            title = f"{label} recovered" if source != "pcold" else "MetehanTechPcOld Docker recovered"
        return ("recovery", title, f"{label} is operational again.", "resolved")
    if event_type == "online":
        title = f"{label} offline"
    elif event_type == "throttled":
        title = "Raspberry Pi 5 throttling detected"
    elif event_type == "smart":
        title = "SMART problem"
    else:
        title = f"{label} down" if source != "pcold" else "MetehanTechPcOld Docker down"
    return ("critical", title, f"{label} is not operational.", "active")


def process_snapshot(snapshot, *, baseline=False, db_path=DB_PATH, now=None):
    """Write only transitions. The first snapshot after each restart is a quiet baseline."""
    current = observations(snapshot)
    timestamp = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).isoformat()
    cutoff = datetime.fromtimestamp((time.time() if now is None else now) - RETENTION_SECONDS, timezone.utc).isoformat()
    inserted = 0
    with closing(connect(db_path)) as connection:
        if baseline:
            # Reconcile stale active rows without manufacturing recovery events.
            active = connection.execute("SELECT id, source, event_type, severity FROM events WHERE status = 'active'").fetchall()
            for event_id, source, event_type, severity in active:
                known = current.get((source, event_type))
                expected = "warning" if known and known.state == "warning" else "critical" if known and known.state in {"critical", "down"} else None
                if known and severity != expected:
                    connection.execute("UPDATE events SET status = 'resolved' WHERE id = ?", (event_id,))
            reconcile_baseline(connection, current, timestamp)
            connection.execute("DELETE FROM event_states")
            connection.executemany(
                "INSERT INTO event_states(source, event_type, state, updated_at) VALUES (?, ?, ?, ?)",
                ((source, event_type, observation.state, timestamp) for (source, event_type), observation in current.items()),
            )
        else:
            previous = {(source, event_type): (state, updated_at) for source, event_type, state, updated_at in connection.execute("SELECT source, event_type, state, updated_at FROM event_states")}
            for (source, event_type), observation in current.items():
                old, old_time = previous.get((source, event_type), (None, None))
                if old == observation.state:
                    continue
                connection.execute(
                    "INSERT INTO event_states(source, event_type, state, updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(source, event_type) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
                    (source, event_type, observation.state, timestamp),
                )
                if old is None:
                    continue  # Newly observable condition starts at its first known state.
                connection.execute(
                    "UPDATE events SET status = 'resolved' WHERE source = ? AND event_type = ? AND status = 'active'",
                    (source, event_type),
                )
                if observation.state in {"normal", "up"} and old in {"normal", "up"}:
                    continue
                details = event_details(source, event_type, observation, old)
                apply_transition(connection, source, event_type, old, old_time, observation, details, timestamp)
                severity, title, message, status = details
                connection.execute(
                    "INSERT INTO events(timestamp, severity, source, event_type, title, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (timestamp, severity, source, event_type, title, message, status),
                )
                inserted += 1
        connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        connection.commit()
    return inserted


def get_events(*, limit=50, severity=None, source=None, db_path=DB_PATH):
    where = []
    params = []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if source == "services":
        where.append("source NOT IN ('pi5', 'pcold')")
    elif source:
        where.append("source = ?")
        params.append(source)
    query = "SELECT id, timestamp, severity, source, event_type, title, message, status FROM events"
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
    params.append(limit)
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = [dict(row) for row in connection.execute(query, params)]
        active = connection.execute("SELECT COUNT(*) FROM event_states WHERE state IN ('warning','critical','down')").fetchone()[0]
        active += connection.execute("SELECT COUNT(*) FROM incidents WHERE external_event_id IS NOT NULL AND status = 'active'").fetchone()[0]
    return {"events": rows, "active_incidents": active}
