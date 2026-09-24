"""External Pi reachability watchdog for MetehanTechPcOld (Python stdlib only)."""

import json
import logging
import os
import socket
import sqlite3
import subprocess
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG_PATH = "/etc/metehantech-watchdog/network.env"


class NetworkConfigError(RuntimeError):
    """Gerekli bir ag degeri tanimli degil."""


def _env(name):
    """Ortam degiskenini dondur; tanimsizsa anlamli hata firlat.

    Bu betik PcOld uzerinde calisir ve degerlerini systemd'nin
    EnvironmentFile=-/etc/metehantech-watchdog/network.env satirindan alir.
    Kaynak kodda gercek adres fallback'i bilerek yoktur: yanlis yapilandirma,
    yanlis bir host'u izlemek yerine acik hatayla ortaya cikmalidir.
    """
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise NetworkConfigError(
            "{0} tanimli degil. PcOld uzerinde {1} dosyasini olusturun; birim "
            "onu EnvironmentFile ile yukler.".format(name, CONFIG_PATH)
        )
    return value


# Izlenen Pi'nin adresi ve bu watchdog'un dinleyecegi yerel adres.
PI_ADDRESS = _env("PI5_LAN_IP")
LISTEN_ADDRESS = _env("PCOLD_LAN_IP")
LISTEN_PORT = 8766
DB_PATH = Path("/var/lib/metehantech-watchdog/events.db")
INTERVAL = 60
FAILURES_TO_DOWN = 3
LOG = logging.getLogger("metehantech-watchdog")


def utc(now=None):
    return datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).isoformat()


def connect(db_path=DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            external_event_id TEXT NOT NULL UNIQUE,
            detected_at TEXT NOT NULL,
            recovered_at TEXT,
            duration_seconds INTEGER,
            event_type TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('down','recovered'))
        )
    """)
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS watchdog_one_active ON incidents(event_type) WHERE state = 'down'")
    connection.execute("CREATE TABLE IF NOT EXISTS watchdog_state (id INTEGER PRIMARY KEY CHECK(id = 1), failures INTEGER NOT NULL)")
    connection.execute("INSERT OR IGNORE INTO watchdog_state(id, failures) VALUES (1, 0)")
    connection.commit()
    return connection


def check_pi():
    """ICMP is preferred; the dashboard TCP port is a positive fallback."""
    try:
        result = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "2", PI_ADDRESS],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=4, check=False,
        )
        if result.returncode == 0:
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        with socket.create_connection((PI_ADDRESS, 5200), timeout=2):
            return True
    except OSError:
        return False


def observe(reachable, *, now=None, db_path=DB_PATH):
    """Persist three-failure detection and one-success recovery transactionally."""
    timestamp = utc(now)
    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        failures = connection.execute("SELECT failures FROM watchdog_state WHERE id = 1").fetchone()[0]
        active = connection.execute(
            "SELECT id, detected_at FROM incidents WHERE event_type = 'device_offline' AND state = 'down'"
        ).fetchone()
        if reachable:
            connection.execute("UPDATE watchdog_state SET failures = 0 WHERE id = 1")
            if active:
                seconds = max(0, int((datetime.fromisoformat(timestamp) - datetime.fromisoformat(active[1])).total_seconds()))
                connection.execute(
                    "UPDATE incidents SET recovered_at = ?, duration_seconds = ?, state = 'recovered' WHERE id = ?",
                    (timestamp, seconds, active[0]),
                )
                LOG.info("Pi recovered after %s seconds", seconds)
                connection.commit()
                return "recovered"
        else:
            failures += 1
            connection.execute("UPDATE watchdog_state SET failures = ? WHERE id = 1", (failures,))
            if failures >= FAILURES_TO_DOWN and not active:
                event_id = f"pcold-watchdog-{datetime.fromisoformat(timestamp).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
                connection.execute(
                    "INSERT INTO incidents(external_event_id, detected_at, event_type, state) VALUES (?, ?, 'device_offline', 'down')",
                    (event_id, timestamp),
                )
                LOG.warning("Pi unreachable after %s consecutive checks", failures)
                connection.commit()
                return "down"
        connection.commit()
        return "up" if reachable else "pending" if failures < FAILURES_TO_DOWN else "down"


def list_incidents(db_path=DB_PATH):
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(
            "SELECT external_event_id, detected_at, recovered_at, duration_seconds, event_type, state "
            "FROM incidents ORDER BY detected_at DESC LIMIT 500"
        )]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.client_address[0] not in {PI_ADDRESS, LISTEN_ADDRESS, "127.0.0.1"}:
            self.send_error(403)
            return
        if self.path != "/incidents":
            self.send_error(404)
            return
        try:
            body = json.dumps({"incidents": list_incidents()}, separators=(",", ":")).encode("utf-8")
        except (OSError, sqlite3.Error):
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        LOG.info("%s - %s", self.client_address[0], format % args)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with closing(connect()):
        pass
    server = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True, name="watchdog-http").start()
    LOG.info("Read-only watchdog API listening on %s:%s", LISTEN_ADDRESS, LISTEN_PORT)
    while True:
        started = time.monotonic()
        try:
            observe(check_pi())
        except (OSError, sqlite3.Error, ValueError):
            LOG.exception("Watchdog sample failed; retrying")
        time.sleep(max(0, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
