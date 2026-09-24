"""SQLite history collection for the status dashboard."""

import fcntl
import logging
import math
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path

from events import process_snapshot
from incidents import sync_external
from alerts import evaluate_snapshot, start_stale_monitor, sync_watchdog_alerts

DB_PATH = Path(__file__).resolve().parent / "data" / "metrics.db"
LOCK_PATH = DB_PATH.parent / "collector.lock"
RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
INTERVAL = 60
RETENTION = 7 * 86400
LOG = logging.getLogger(__name__)
_number = re.compile(r"^\s*(\d+(?:\.\d+)?)")


def numeric(value):
    """Convert display metrics to numbers; unknown values become SQL NULL."""
    match = _number.match(str(value))
    if not match:
        return None
    number = float(match.group(1))
    return number if math.isfinite(number) else None


def connect(db_path=DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            device TEXT NOT NULL CHECK(device IN ('pi5', 'pcold')),
            temperature REAL,
            ram REAL,
            disk REAL,
            load REAL,
            UNIQUE(timestamp, device)
        )
    """)
    if 'cpu' not in {row[1] for row in connection.execute('PRAGMA table_info(metrics)')}:
        connection.execute('ALTER TABLE metrics ADD COLUMN cpu REAL')
    connection.execute("CREATE INDEX IF NOT EXISTS metrics_lookup ON metrics(device, timestamp)")
    return connection


def collect_once(status_provider, db_path=DB_PATH, now=None):
    """Take one snapshot without changing the live /api/status response."""
    snapshot = status_provider()
    timestamp = int(time.time() if now is None else now)
    rows = []
    for device in snapshot.get("devices", []):
        if device.get("id") not in {"pi5", "pcold"} or not device.get("online"):
            continue
        metrics = device.get("metrics", {})
        rows.append((timestamp, device["id"], *(numeric(metrics.get(key)) for key in ("temperature", "ram", "disk", "load", "cpu"))))
    with closing(connect(db_path)) as connection:
        connection.executemany(
            "INSERT OR IGNORE INTO metrics(timestamp, device, temperature, ram, disk, load, cpu) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        connection.execute("DELETE FROM metrics WHERE timestamp < ?", (timestamp - RETENTION,))
        connection.commit()
    return len(rows)


def get_history(device, range_name, db_path=DB_PATH):
    since = int(time.time()) - RANGES[range_name]
    if not db_path.exists():
        return []
    # Bound both SQL output and frontend data. Old CPU samples remain NULL.
    bucket = max(1, RANGES[range_name] // 240)
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)) as connection:
        has_cpu = 'cpu' in {r[1] for r in connection.execute('PRAGMA table_info(metrics)')}
        cpu = 'AVG(cpu)' if has_cpu else 'NULL'
        rows = connection.execute(
            f"SELECT MAX(timestamp), AVG(temperature), AVG(ram), AVG(disk), AVG(load), {cpu} "
            "FROM metrics WHERE device=? AND timestamp>=? GROUP BY CAST(timestamp / ? AS INTEGER) ORDER BY MAX(timestamp) LIMIT 242",
            (device, since, bucket),
        ).fetchall()
    return [dict(timestamp=datetime.fromtimestamp(r[0], timezone.utc).isoformat(),
                 temperature=r[1], ram=r[2], disk=r[3], load=r[4], cpu=r[5]) for r in rows]


def start_collector(status_provider):
    """A process-wide lock keeps one collector active across accidental duplicates."""
    def run():
        try:
            LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOCK_PATH.open("w") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    LOG.warning("History collector already running; skipping this instance")
                    return
                start_stale_monitor()
                first_snapshot = True
                while True:
                    started = time.monotonic()
                    try:
                        snapshot = status_provider()
                    except Exception:
                        LOG.exception("Status collection failed; web server remains available")
                    else:
                        try:
                            collect_once(lambda: snapshot)
                            from control_center import publish_snapshot
                            publish_snapshot(snapshot)
                            from app import _container_details
                            from docker_alerts import evaluate_restarts
                            evaluate_restarts(_container_details, now=time.time())
                        except Exception:
                            LOG.exception("History collection failed; web server remains available")
                        try:
                            process_snapshot(snapshot, baseline=first_snapshot)
                            first_snapshot = False
                        except Exception:
                            LOG.exception("Event collection failed; web server remains available")
                        try:
                            evaluate_snapshot(snapshot)
                        except Exception:
                            LOG.exception("Alert evaluation failed; web server remains available")
                        try:
                            from dns_center import summary as dns_summary
                            from dns_alerts import evaluate_dns, evaluate_cluster
                            summary = dns_summary()
                            evaluate_dns(summary, now=time.time())
                            evaluate_cluster(summary.get('cluster'), now=time.time())
                        except Exception:
                            LOG.exception("DNS alert evaluation failed; web server remains available")
                    try:
                        sync_external()
                    except Exception:
                        LOG.exception("External incident sync failed; web server remains available")
                    try:
                        sync_watchdog_alerts()
                    except Exception:
                        LOG.exception("Watchdog alert sync failed; web server remains available")
                    time.sleep(max(0, INTERVAL - (time.monotonic() - started)))
        except OSError:
            LOG.exception("Could not start history collector; web server remains available")

    thread = threading.Thread(target=run, name="metrics-collector", daemon=True)
    thread.start()
    return thread
