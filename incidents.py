"""Incident pairing and idempotent import of the external Pi watchdog."""

import logging
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import requests
import network

DB_PATH = Path(__file__).resolve().parent / "data" / "metrics.db"
WATCHDOG_URL = "http://{0}/incidents".format(network.endpoint("PCOLD_LAN_IP", 8766))
EXTERNAL_ID = re.compile(r"^pcold-watchdog-[A-Za-z0-9_-]{1,80}$")
LOG = logging.getLogger(__name__)


def ensure_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            started_at TEXT NOT NULL,
            resolved_at TEXT,
            duration_seconds INTEGER,
            status TEXT NOT NULL CHECK(status IN ('active','resolved')),
            external_event_id TEXT UNIQUE
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS incidents_time ON incidents(started_at DESC, id DESC)")
    connection.execute("CREATE INDEX IF NOT EXISTS incidents_filter ON incidents(source, status, started_at DESC)")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS incidents_active_local ON incidents(source, incident_type) WHERE status = 'active' AND external_event_id IS NULL")


def incident_type_for(event_type):
    return {
        "online": "device_offline",
        "service": "service_down",
        "docker": "docker_down",
        "smart": "smart_problem",
        "throttled": "throttled",
    }.get(event_type, event_type)


def duration(started_at, resolved_at):
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(resolved_at)
        if start.tzinfo is None or end.tzinfo is None or end < start:
            return None
        return int((end - start).total_seconds())
    except (TypeError, ValueError):
        return None


def reconcile_baseline(connection, current, timestamp):
    """Close stale local incidents quietly when restart baseline is healthy."""
    for source, event_type, started_at in connection.execute(
        "SELECT source, incident_type, started_at FROM incidents WHERE status = 'active' AND external_event_id IS NULL"
    ).fetchall():
        observed = None
        for (current_source, current_type), value in current.items():
            if current_source == source and incident_type_for(current_type) == event_type:
                observed = value
                break
        if observed and observed.state in {"normal", "up"}:
            connection.execute(
                "UPDATE incidents SET status = 'resolved', resolved_at = ?, duration_seconds = ? "
                "WHERE source = ? AND incident_type = ? AND status = 'active' AND external_event_id IS NULL",
                (timestamp, duration(started_at, timestamp), source, event_type),
            )


def apply_transition(connection, source, event_type, old_state, old_time, observation, details, timestamp):
    """Pair a transition with one local incident; threshold escalations keep its start."""
    kind = incident_type_for(event_type)
    severity, title, message, _ = details
    unhealthy = observation.state in {"warning", "critical", "down"}
    prior_unhealthy = old_state in {"warning", "critical", "down"}
    active = connection.execute(
        "SELECT id, started_at, severity, title FROM incidents WHERE source = ? AND incident_type = ? "
        "AND status = 'active' AND external_event_id IS NULL ORDER BY id DESC LIMIT 1",
        (source, kind),
    ).fetchone()
    if unhealthy:
        if active:
            peak_severity = "critical" if active[2] == "critical" or severity == "critical" else "warning"
            peak_title = active[3] if active[2] == "critical" and severity == "warning" else title
            connection.execute(
                "UPDATE incidents SET severity = ?, title = ?, message = ? WHERE id = ?",
                (peak_severity, peak_title, message, active[0]),
            )
        else:
            started_at = old_time if prior_unhealthy and old_time else timestamp
            connection.execute(
                "INSERT INTO incidents(source, incident_type, severity, title, message, started_at, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'active')",
                (source, kind, severity, title, message, started_at),
            )
    elif prior_unhealthy:
        if active:
            connection.execute(
                "UPDATE incidents SET status = 'resolved', resolved_at = ?, duration_seconds = ? WHERE id = ?",
                (timestamp, duration(active[1], timestamp), active[0]),
            )
        elif old_time:
            # The issue was already present at startup; pair its later recovery with
            # the first observed baseline time without creating a startup alarm.
            connection.execute(
                "INSERT INTO incidents(source, incident_type, severity, title, message, started_at, "
                "resolved_at, duration_seconds, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'resolved')",
                (source, kind, "warning" if old_state == "warning" else "critical",
                 f"{event_type.replace('_', ' ').title()} {old_state}", message, old_time, timestamp,
                 duration(old_time, timestamp)),
            )


def connect(db_path=DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    ensure_schema(connection)
    return connection


def get_incidents(*, limit=20, status=None, source=None, db_path=DB_PATH):
    where = []
    params = []
    if status:
        where.append("status = ?")
        params.append(status)
    if source:
        where.append("source = ?")
        params.append(source)
    query = "SELECT id, source, incident_type, severity, title, message, started_at, resolved_at, duration_seconds, status, external_event_id FROM incidents"
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY started_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = [dict(row) for row in connection.execute(query, params)]
    return {"incidents": rows}


def normalize_external(raw):
    if not isinstance(raw, dict):
        return None
    external_id = raw.get("external_event_id")
    if not isinstance(external_id, str) or not EXTERNAL_ID.fullmatch(external_id):
        return None
    if raw.get("event_type") != "device_offline":
        return None
    started_at = raw.get("detected_at")
    try:
        start = datetime.fromisoformat(started_at)
        if start.tzinfo is None:
            return None
        started_at = start.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None
    recovered_at = raw.get("recovered_at")
    if recovered_at is not None:
        try:
            recovered = datetime.fromisoformat(recovered_at)
            if recovered.tzinfo is None or recovered < start:
                return None
            recovered_at = recovered.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            return None
    return external_id, started_at, recovered_at


def import_external(payload, db_path=DB_PATH):
    """Import read-only watchdog records by stable ID; later recovery updates them."""
    rows = payload.get("incidents") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return 0
    imported = 0
    from events import connect as event_connect
    with closing(event_connect(db_path)) as connection:
        for raw in rows[:500]:
            normalized = normalize_external(raw)
            if not normalized:
                continue
            external_id, started_at, recovered_at = normalized
            status = "resolved" if recovered_at else "active"
            current = connection.execute(
                "SELECT id, status FROM incidents WHERE external_event_id = ?", (external_id,)
            ).fetchone()
            if current is None:
                connection.execute(
                    "INSERT INTO incidents(source, incident_type, severity, title, message, started_at, "
                    "resolved_at, duration_seconds, status, external_event_id) "
                    "VALUES ('pi5', 'device_offline', 'critical', 'Raspberry Pi 5 offline', "
                    "'External laptop watchdog detected the Pi as unreachable.', ?, ?, ?, ?, ?)",
                    (started_at, recovered_at, duration(started_at, recovered_at) if recovered_at else None, status, external_id),
                )
                connection.execute(
                    "INSERT INTO events(timestamp, severity, source, event_type, title, message, status) "
                    "VALUES (?, 'critical', 'pi5', 'online', 'Raspberry Pi 5 offline', "
                    "'External laptop watchdog detected the Pi as unreachable.', ?)",
                    (started_at, 'resolved' if recovered_at else 'active'),
                )
                if recovered_at:
                    connection.execute(
                        "INSERT INTO events(timestamp, severity, source, event_type, title, message, status) "
                        "VALUES (?, 'recovery', 'pi5', 'online', 'Raspberry Pi 5 online again', "
                        "'External laptop watchdog confirmed the Pi recovered.', 'resolved')",
                        (recovered_at,),
                    )
                imported += 1
            elif current[1] == "active" and recovered_at:
                connection.execute(
                    "UPDATE incidents SET resolved_at = ?, duration_seconds = ?, status = 'resolved' WHERE id = ?",
                    (recovered_at, duration(started_at, recovered_at), current[0]),
                )
                connection.execute(
                    "UPDATE events SET status = 'resolved' WHERE source = 'pi5' AND event_type = 'online' "
                    "AND timestamp = ? AND status = 'active'",
                    (started_at,),
                )
                connection.execute(
                    "INSERT INTO events(timestamp, severity, source, event_type, title, message, status) "
                    "VALUES (?, 'recovery', 'pi5', 'online', 'Raspberry Pi 5 online again', "
                    "'External laptop watchdog confirmed the Pi recovered.', 'resolved')",
                    (recovered_at,),
                )
                imported += 1
        connection.commit()
    return imported


def sync_external(db_path=DB_PATH):
    """LAN-only backend request. Failure leaves existing local data untouched."""
    try:
        response = requests.get(WATCHDOG_URL, timeout=2, allow_redirects=False)
        if response.status_code != 200:
            return 0
        return import_external(response.json(), db_path=db_path)
    except (requests.RequestException, ValueError, OSError, sqlite3.Error) as error:
        LOG.debug("External watchdog sync unavailable: %s", error)
        return 0
