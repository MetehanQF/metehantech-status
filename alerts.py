from health_model import DISK_WARNING, DISK_CRITICAL, TEMP_WARNING, TEMP_CRITICAL, RAM_WARNING, STALE_WARNING, STALE_CRITICAL
"""Persistent infrastructure alert rules for the private Control Center."""

from contextlib import closing
from datetime import datetime, timezone
import math
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import network


DB_PATH = Path(__file__).resolve().parent / "data" / "alerts.db"
METRICS_DB_PATH = Path(__file__).resolve().parent / "data" / "metrics.db"
ALERT_LIMITS = {50, 100, 500}
ALERT_STATUSES = {"active", "resolved"}
ALERT_SEVERITIES = {"info", "warning", "critical"}
STALE_INTERVAL = 30
SERVICE_FAILURES = 2
TEMP_SAMPLES = 2
RAM_SAMPLES = 5
RESTART_GRACE_SECONDS = 60
NUMBER_PATTERN = re.compile(r"^\s*(-?\d+(?:\.\d+)?)")
SERVICE_UNITS = {
    "metehantech-status.service": "MetehanTech Control Center",
    "metehantech-home.service": "MetehanTech Home",
    "clan-web.service": "MetehanTech Clan",
}
LOG = logging.getLogger(__name__)
CLOUD_ALERTS_MARKER = Path("/srv/metehantech-cloud/.alerts-enabled")
CLOUD_ROOT = Path("/srv/metehantech-cloud")
CLOUD_BACKUPS_DB = Path(__file__).resolve().parent / "data" / "backups.db"
CLOUD_CONTAINERS = {
    "metehantech-nextcloud-app": ("nextcloud_unavailable", "Nextcloud unavailable"),
    "metehantech-nextcloud-db": ("database_unavailable", "Nextcloud database unavailable"),
    "metehantech-nextcloud-redis": ("redis_unavailable", "Nextcloud Redis unavailable"),
}


def utc(now=None):
    return datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).isoformat()


def number(value):
    match = NUMBER_PATTERN.match(str(value))
    if not match:
        return None
    parsed = float(match.group(1))
    return parsed if math.isfinite(parsed) else None


def configured_db_path():
    configured = os.environ.get("ALERTS_DB", "").strip()
    return Path(configured) if configured else DB_PATH


def connect(db_path=None):
    path = Path(db_path) if db_path is not None else configured_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    os.chmod(path, 0o600)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
            source TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            target TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active','resolved')),
            last_value TEXT,
            threshold TEXT NOT NULL,
            duration_seconds INTEGER,
            external_ref TEXT UNIQUE
        )
    """)
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS alerts_one_active "
        "ON alerts(source, alert_type, target) WHERE status = 'active'"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS alerts_recent ON alerts(updated_at DESC, id DESC)"
    )
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alert_states (
            state_key TEXT PRIMARY KEY,
            consecutive INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alert_maintenance (
            target TEXT PRIMARY KEY,
            suppressed_until REAL NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    return connection


def _duration(started_at, ended_at):
    return max(0, int((datetime.fromisoformat(ended_at) - datetime.fromisoformat(started_at)).total_seconds()))


def _counter(state_key, failing, timestamp, db_path):
    with closing(connect(db_path)) as connection:
        old = connection.execute(
            "SELECT consecutive FROM alert_states WHERE state_key = ?", (state_key,)
        ).fetchone()
        value = (old[0] if old else 0) + 1 if failing else 0
        connection.execute(
            "INSERT INTO alert_states(state_key, consecutive, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(state_key) DO UPDATE SET consecutive = excluded.consecutive, updated_at = excluded.updated_at",
            (state_key, value, timestamp),
        )
        connection.commit()
    return value


def _apply_condition(*, source, alert_type, target, title, message, severity, last_value,
                     threshold, recover=False, touch=False, timestamp, db_path):
    """Open/update one active alert, resolve it, or hold it through hysteresis."""
    with closing(connect(db_path)) as connection:
        active = connection.execute(
            "SELECT id, created_at FROM alerts WHERE source = ? AND alert_type = ? AND target = ? AND status = 'active'",
            (source, alert_type, target),
        ).fetchone()
        if recover:
            if active:
                connection.execute(
                    "UPDATE alerts SET updated_at = ?, resolved_at = ?, status = 'resolved', last_value = ?, "
                    "duration_seconds = ? WHERE id = ?",
                    (timestamp, timestamp, last_value, _duration(active[1], timestamp), active[0]),
                )
        elif severity:
            if active:
                connection.execute(
                    "UPDATE alerts SET updated_at = ?, severity = ?, title = ?, message = ?, last_value = ?, threshold = ? WHERE id = ?",
                    (timestamp, severity, title, message, last_value, threshold, active[0]),
                )
            else:
                connection.execute(
                    "INSERT INTO alerts(created_at, updated_at, severity, source, alert_type, target, title, message, status, last_value, threshold) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                    (timestamp, timestamp, severity, source, alert_type, target, title, message, last_value, threshold),
                )
        elif touch and active:
            connection.execute(
                "UPDATE alerts SET updated_at = ?, message = ?, last_value = ? WHERE id = ?",
                (timestamp, message, last_value, active[0]),
            )
        connection.commit()


def _metric_rule(*, source, target, alert_type, label, value, warning=None, critical=None,
                 recovery, samples=1, unit, db_path, now):
    if value is None:
        return
    timestamp = utc(now)
    threshold = ";".join(
        part for part in (
            f"warning>={warning:g}{unit}" if warning is not None else "",
            f"critical>={critical:g}{unit}" if critical is not None else "",
            f"recovery<{recovery:g}{unit}",
            f"samples={samples}" if samples > 1 else "",
        ) if part
    )
    unhealthy = (critical is not None and value >= critical) or (warning is not None and value >= warning)
    count = _counter(f"metric:{source}:{alert_type}", unhealthy, timestamp, db_path)
    severity = None
    if unhealthy and count >= samples:
        severity = "critical" if critical is not None and value >= critical else "warning"
    recovered = value < recovery
    title = f"{label} {'critical' if severity == 'critical' else 'warning'}"
    message = f"{target} {label.lower()} is {value:g}{unit}."
    _apply_condition(
        source=source, alert_type=alert_type, target=target, title=title, message=message,
        severity=severity, last_value=f"{value:g}{unit}", threshold=threshold,
        recover=recovered, touch=not unhealthy and not recovered, timestamp=timestamp, db_path=db_path,
    )


def suppress_service(unit, *, seconds=RESTART_GRACE_SECONDS, reason="planned_restart", now=None, db_path=None):
    if unit not in SERVICE_UNITS:
        raise ValueError("Service is not allowed")
    current = time.time() if now is None else now
    with closing(connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO alert_maintenance(target, suppressed_until, reason, created_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(target) DO UPDATE SET suppressed_until = excluded.suppressed_until, reason = excluded.reason, created_at = excluded.created_at",
            (unit, current + seconds, reason, utc(current)),
        )
        connection.commit()


def clear_service_suppression(unit, *, db_path=None):
    with closing(connect(db_path)) as connection:
        connection.execute("DELETE FROM alert_maintenance WHERE target = ?", (unit,))
        connection.commit()


def _suppressed(unit, now, db_path):
    with closing(connect(db_path)) as connection:
        connection.execute("DELETE FROM alert_maintenance WHERE suppressed_until <= ?", (now,))
        row = connection.execute(
            "SELECT 1 FROM alert_maintenance WHERE target = ? AND suppressed_until > ?", (unit, now)
        ).fetchone()
        connection.commit()
    return row is not None


def read_service_states():
    states = {}
    for unit in SERVICE_UNITS:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", unit], capture_output=True, text=True,
                timeout=2, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            states[unit] = None
        else:
            states[unit] = result.returncode == 0 and result.stdout.strip() == "active"
    return states


def _cloud_backup_active(backups_db=CLOUD_BACKUPS_DB):
    if not Path(backups_db).exists():
        return False
    try:
        with closing(sqlite3.connect(backups_db, timeout=2)) as connection:
            return connection.execute(
                "SELECT 1 FROM backups WHERE source_node='cloud' AND status IN ('queued','running') LIMIT 1"
            ).fetchone() is not None
    except sqlite3.Error:
        return False


def _container_healthy(name):
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", name],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.returncode == 0 and result.stdout.strip() in {"healthy", "running"}


def evaluate_cloud_health(*, db_path=None, now=None, marker=CLOUD_ALERTS_MARKER, root=CLOUD_ROOT):
    """Evaluate only the fixed Personal Cloud stack after deployment enables its marker."""
    if not Path(marker).exists():
        return
    current = time.time() if now is None else now
    timestamp = utc(current)
    backup_active = _cloud_backup_active()
    for container, (alert_type, title) in CLOUD_CONTAINERS.items():
        healthy = _container_healthy(container)
        if not isinstance(healthy, bool):
            continue
        count = _counter(f"cloud:{container}", not healthy, timestamp, db_path)
        _apply_condition(
            source="personal_cloud", alert_type=alert_type, target=container,
            title=title, message=f"{container} is {'healthy' if healthy else 'unavailable'}.",
            severity="critical" if not healthy and count >= SERVICE_FAILURES else None,
            last_value="healthy" if healthy else "unavailable",
            threshold=f"critical after {SERVICE_FAILURES} consecutive failures", recover=healthy,
            timestamp=timestamp, db_path=db_path,
        )

    maintenance = None
    try:
        result = subprocess.run(
            ["docker", "exec", "-u", "33", "metehantech-nextcloud-app", "php", "occ", "config:system:get", "maintenance"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode == 0:
            maintenance = result.stdout.strip().lower() in {"1", "true", "yes"}
    except (OSError, subprocess.TimeoutExpired):
        pass
    if isinstance(maintenance, bool):
        unexpected = maintenance and not backup_active
        count = _counter("cloud:unexpected_maintenance", unexpected, timestamp, db_path)
        _apply_condition(
            source="personal_cloud", alert_type="unexpected_maintenance", target="metehantech-nextcloud-app",
            title="Nextcloud maintenance mode active", message="Nextcloud maintenance mode is active outside a cloud backup.",
            severity="critical" if unexpected and count >= SERVICE_FAILURES else None,
            last_value="active" if maintenance else "off",
            threshold=f"critical after {SERVICE_FAILURES} consecutive unexpected samples", recover=not unexpected,
            timestamp=timestamp, db_path=db_path,
        )

    # Nextcloud background jobs drive trash/version expiry and preview cleanup. A stalled
    # cron container is silent otherwise: the web UI keeps working while retention stops.
    last_cron = None
    try:
        result = subprocess.run(
            ["docker", "exec", "-u", "33", "metehantech-nextcloud-app", "php", "occ",
             "config:app:get", "core", "lastcron"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode == 0:
            last_cron = int(result.stdout.strip())
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    if last_cron:
        cron_age = max(0, (current - last_cron) / 60)
        severity = "critical" if cron_age > 60 else "warning" if cron_age > 15 else None
        _apply_condition(
            source="personal_cloud", alert_type="cloud_cron_stale", target="metehantech-nextcloud-cron",
            title="Nextcloud background jobs stale",
            message=f"Last Nextcloud cron run was {cron_age:.0f} minutes ago.",
            severity=severity, last_value=f"{cron_age:.0f}m",
            threshold="warning>15m;critical>60m;recovery<=15m", recover=cron_age <= 15,
            timestamp=timestamp, db_path=db_path,
        )

    try:
        usage = shutil.disk_usage(root)
    except OSError:
        usage = None
    if usage and usage.total:
        percent = usage.used * 100 / usage.total
        _metric_rule(
            source="personal_cloud", target="Personal Cloud storage", alert_type="cloud_disk_usage",
            label="Disk usage", value=percent, warning=DISK_WARNING, critical=DISK_CRITICAL, recovery=80,
            samples=2, unit="%", db_path=db_path, now=current,
        )

    if Path(CLOUD_BACKUPS_DB).exists():
        try:
            with closing(sqlite3.connect(CLOUD_BACKUPS_DB, timeout=2)) as connection:
                row = connection.execute(
                    "SELECT finished_at FROM backups WHERE source_node='cloud' AND status='success' "
                    "AND verification_status='verified' ORDER BY id DESC LIMIT 1"
                ).fetchone()
        except sqlite3.Error:
            row = None
        if row:
            age_hours = max(0, (current - datetime.fromisoformat(row[0]).timestamp()) / 3600)
            severity = "critical" if age_hours > 72 else "warning" if age_hours > 26 else None
            _apply_condition(
                source="personal_cloud", alert_type="cloud_backup_stale", target="Personal Cloud backup",
                title="Personal Cloud backup stale", message=f"Last verified cloud backup is {age_hours:.1f} hours old.",
                severity=severity, last_value=f"{age_hours:.1f}h",
                threshold="warning>26h;critical>72h;recovery<=26h", recover=age_hours <= 26,
                timestamp=timestamp, db_path=db_path,
            )


def evaluate_snapshot(snapshot, *, service_states=None, db_path=None, now=None):
    """Evaluate one existing collector snapshot without performing HTTP uptime probes."""
    current = time.time() if now is None else now
    devices = {item.get("id"): item for item in snapshot.get("devices", []) if isinstance(item, dict)}
    pi = devices.get("pi5", {})
    pcold = devices.get("pcold", {})

    pi_metrics = pi.get("metrics", {})
    _metric_rule(source="pi5", target="Raspberry Pi 5", alert_type="cpu_temperature",
                 label="CPU temperature", value=number(pi_metrics.get("temperature")),
                 warning=TEMP_WARNING, critical=TEMP_CRITICAL, recovery=72, samples=TEMP_SAMPLES, unit="°C",
                 db_path=db_path, now=current)
    _metric_rule(source="pi5", target="Raspberry Pi 5", alert_type="disk_usage",
                 label="Disk usage", value=number(pi_metrics.get("disk")),
                 warning=DISK_WARNING, critical=DISK_CRITICAL, recovery=80, unit="%", db_path=db_path, now=current)
    _metric_rule(source="pi5", target="Raspberry Pi 5", alert_type="ram_usage",
                 label="RAM usage", value=number(pi_metrics.get("ram")),
                 warning=RAM_WARNING, recovery=85, samples=RAM_SAMPLES, unit="%", db_path=db_path, now=current)

    throttled = pi.get("checks", {}).get("Throttled")
    if isinstance(throttled, bool):
        _apply_condition(
            source="pi5", alert_type="throttling", target="Raspberry Pi 5",
            title="Raspberry Pi throttling detected", message="Throttling or undervoltage is active.",
            severity="critical" if throttled else None, last_value="detected" if throttled else "clear",
            threshold="critical when throttling/undervoltage is detected", recover=not throttled,
            timestamp=utc(current), db_path=db_path,
        )

    if pcold.get("online") is True:
        pc_metrics = pcold.get("metrics", {})
        _metric_rule(source="pcold", target="MetehanTechPcOld", alert_type="disk_usage",
                     label="Disk usage", value=number(pc_metrics.get("disk")),
                     warning=DISK_WARNING, critical=DISK_CRITICAL, recovery=80, unit="%", db_path=db_path, now=current)
        _metric_rule(source="pcold", target="MetehanTechPcOld", alert_type="ram_usage",
                     label="RAM usage", value=number(pc_metrics.get("ram")),
                     warning=RAM_WARNING, critical=95, recovery=85, samples=RAM_SAMPLES, unit="%", db_path=db_path, now=current)
        smart = pcold.get("checks", {}).get("SMART")
        if isinstance(smart, bool):
            _apply_condition(
                source="pcold", alert_type="smart_problem", target="MetehanTechPcOld",
                title="MetehanTechPcOld SMART problem", message="SMART health check is reporting a problem.",
                severity=None if smart else "critical", last_value="OK" if smart else "problem",
                threshold="critical when SMART health is not OK", recover=smart,
                timestamp=utc(current), db_path=db_path,
            )

    states = read_service_states() if service_states is None else service_states
    for unit, label in SERVICE_UNITS.items():
        running = states.get(unit)
        if not isinstance(running, bool):
            continue
        if not running and _suppressed(unit, current, db_path):
            _counter(f"service:{unit}", False, utc(current), db_path)
            continue
        count = _counter(f"service:{unit}", not running, utc(current), db_path)
        _apply_condition(
            source="systemd", alert_type="service_unavailable", target=unit,
            title=f"{label} unavailable", message=f"{unit} is {'running' if running else 'not running'}.",
            severity="critical" if not running and count >= SERVICE_FAILURES else None,
            last_value="running" if running else "down", threshold=f"critical after {SERVICE_FAILURES} consecutive failures",
            recover=running, timestamp=utc(current), db_path=db_path,
        )
    from cpu_alerts import evaluate_cpu
    evaluate_cpu(snapshot, db_path=db_path, now=current)
    evaluate_cloud_health(db_path=db_path, now=current)


def _camera_condition(*, snapshot, field, expected=True, source, alert_type, target,
                      title, message, failure_samples, recovery_samples, threshold,
                      severity="critical", db_path=None, now=None):
    current = time.time() if now is None else now
    value = snapshot
    for part in field.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    failing = value is not expected
    timestamp = utc(current)
    failures = _counter(f"camera:{alert_type}:failure", failing, timestamp, db_path)
    recoveries = _counter(f"camera:{alert_type}:recovery", not failing, timestamp, db_path)
    _apply_condition(
        source=source, alert_type=alert_type, target=target, title=title, message=message,
        severity=severity if failing and failures >= failure_samples else None,
        last_value="down" if failing else "healthy", threshold=threshold,
        recover=not failing and recoveries >= recovery_samples,
        touch=failing and failures < failure_samples,
        timestamp=timestamp, db_path=db_path,
    )


def evaluate_camera_health(snapshot, *, rules=None, db_path=None, now=None):
    """Evaluate private Camera Center conditions with persisted debounce counters."""
    selected = set(rules or {"camera", "frigate", "stream", "nfs", "recording", "disk"})
    common = {"snapshot": snapshot, "db_path": db_path, "now": now}
    paused = snapshot.get('processing_paused') is True
    if paused:
        # OFF is an intentional state, not a recovered stream. Preserve other checks.
        for kind in ('stream_unavailable', 'recording_stopped'):
            _apply_condition(source='camera_center', alert_type=kind, target='tapo_c211',
                title='Camera processing paused', message='Camera intentionally OFF; stream/recording monitoring paused.',
                severity=None, last_value='intentionally_paused', threshold='camera enabled state',
                recover=True, timestamp=utc(now), db_path=db_path)
            _counter(f'camera:{kind}:failure', False, utc(now), db_path)
    if "camera" in selected:
        _camera_condition(
            **common, field="camera.online", source="camera_center", alert_type="camera_offline",
            target="Tapo C211", title="Tapo C211 offline",
            message="The camera RTSP endpoint is unavailable.", failure_samples=3,
            recovery_samples=2, threshold="critical after 3 consecutive 10-second failures",
        )
    if "frigate" in selected:
        _camera_condition(
            **common, field="frigate.running", source="camera_center", alert_type="frigate_down",
            target="metehantech-frigate.service", title="Frigate unavailable",
            message="The supervised Frigate service is not running.", failure_samples=2,
            recovery_samples=2, threshold="critical after 2 consecutive 15-second failures",
        )
    if "stream" in selected and not paused:
        stream_ok = bool(snapshot.get("stream", {}).get("available")) and bool(snapshot.get("go2rtc", {}).get("healthy"))
        stream_snapshot = {"stream_ok": stream_ok}
        _camera_condition(
            snapshot=stream_snapshot, db_path=db_path, now=now, field="stream_ok",
            source="camera_center", alert_type="stream_unavailable", target="tapo_c211",
            title="Camera stream unavailable", message="Frigate/go2rtc cannot consume the Tapo C211 stream.",
            failure_samples=3, recovery_samples=2, threshold="critical after 3 consecutive checks",
        )
    if "nfs" in selected:
        _camera_condition(
            **common, field="nfs.mounted", source="camera_center", alert_type="nfs_unavailable",
            target=network.get("PCOLD_LAN_IP") + ":/srv/metehantech-camera", title="Camera NFS storage unavailable",
            message="The validated PcOld camera NFS mount is unavailable.", failure_samples=3,
            recovery_samples=3, threshold="critical after 3 consecutive 20-second failures",
        )
    if "recording" in selected and not paused:
        _camera_condition(
            **common, field="recording.active", source="camera_center", alert_type="recording_stopped",
            target="tapo_c211", title="Camera recording stopped",
            message="Continuous recording has not advanced for at least 90 seconds.", failure_samples=1,
            recovery_samples=2, threshold="critical after 90 seconds without recording progress",
        )
    if "disk" in selected:
        storage = snapshot.get("storage", {})
        free = storage.get("free_bytes")
        total = storage.get("total_bytes")
        if isinstance(free, int) and isinstance(total, int) and total > 0:
            gib = free / (1024 ** 3)
            percent = free / total * 100
            level = (
                "emergency" if gib < 10 else
                "critical" if gib < 20 or 100-percent >= DISK_CRITICAL else
                "warning" if gib < 40 or 100-percent >= DISK_WARNING else None
            )
            _apply_condition(
                source="camera_center", alert_type="recording_disk_space", target="PcOld camera storage",
                title=f"Recording disk {level}" if level else "Recording disk space recovered",
                message=f"Camera storage has {gib:.1f} GiB ({percent:.1f}%) free.",
                severity="critical" if level in {"critical", "emergency"} else "warning" if level else None,
                last_value=f"{gib:.1f}GiB/{percent:.1f}%", threshold=f"warning<40GiB or used>={DISK_WARNING}%;critical<20GiB or used>={DISK_CRITICAL}%;emergency<10GiB",
                recover=level is None, timestamp=utc(now), db_path=db_path,
            )


def start_camera_monitor(status_provider, *, db_path=None):
    """Run exact camera alert cadences without blocking public status collection."""
    schedule = {
        "camera": 10, "stream": 10, "recording": 10,
        "frigate": 15, "nfs": 20, "disk": 20,
    }

    def run():
        due = {name: 0.0 for name in schedule}
        while True:
            current = time.time()
            selected = {name for name, deadline in due.items() if current >= deadline}
            if selected:
                try:
                    snapshot = status_provider()
                    evaluate_camera_health(snapshot, rules=selected, db_path=db_path, now=current)
                except Exception:
                    LOG.exception("Camera Center alert evaluation failed")
                for name in selected:
                    due[name] = current + schedule[name]
            time.sleep(5)

    thread = threading.Thread(target=run, name="camera-alert-monitor", daemon=True)
    thread.start()
    return thread


def _latest_metric(device, metrics_db_path):
    path = Path(metrics_db_path)
    if not path.exists():
        return None
    with closing(sqlite3.connect(path, timeout=5)) as connection:
        row = connection.execute("SELECT MAX(timestamp) FROM metrics WHERE device = ?", (device,)).fetchone()
    return row[0] if row else None


def evaluate_staleness(*, metrics_db_path=METRICS_DB_PATH, db_path=None, now=None):
    current = time.time() if now is None else now
    for device, target, alert_type in (
        ("pi5", "Metrics collector", "collector_stale"),
        ("pcold", "MetehanTechPcOld", "metrics_stale"),
    ):
        latest = _latest_metric(device, metrics_db_path)
        age = None if latest is None else max(0, int(current - latest))
        severity = "critical" if age is None or age > STALE_CRITICAL else "warning" if age > STALE_WARNING else None
        value = "no samples" if age is None else f"{age}s"
        _apply_condition(
            source=device, alert_type=alert_type, target=target,
            title=f"{target} metrics stale", message=f"Latest metrics sample age is {value}.",
            severity=severity, last_value=value, threshold="warning>120s;critical>300s;recovery<=120s",
            recover=age is not None and age <= STALE_WARNING, timestamp=utc(current), db_path=db_path,
        )


def sync_watchdog_alerts(*, incidents_db_path=METRICS_DB_PATH, db_path=None):
    """Project already-imported watchdog incidents into alerts; never probe PcOld here."""
    path = Path(incidents_db_path)
    if not path.exists():
        return 0
    with closing(sqlite3.connect(path, timeout=5)) as incidents:
        rows = incidents.execute(
            "SELECT started_at, resolved_at, duration_seconds, status, external_event_id "
            "FROM incidents WHERE external_event_id IS NOT NULL ORDER BY id"
        ).fetchall()
    changed = 0
    with closing(connect(db_path)) as connection:
        for started, resolved, duration_seconds, status, external_ref in rows:
            existing = connection.execute(
                "SELECT id, status FROM alerts WHERE external_ref = ?", (external_ref,)
            ).fetchone()
            updated = resolved or started
            if existing is None:
                connection.execute(
                    "INSERT INTO alerts(created_at, updated_at, resolved_at, severity, source, alert_type, target, title, message, status, last_value, threshold, duration_seconds, external_ref) "
                    "VALUES (?, ?, ?, 'critical', 'pcold_watchdog', 'watchdog_incident', 'Raspberry Pi 5', 'External watchdog: Raspberry Pi 5 offline', "
                    "'Existing MetehanTechPcOld watchdog incident.', ?, ?, 'PcOld watchdog confirmed Pi unreachable', ?, ?)",
                    (started, updated, resolved, status, status, duration_seconds, external_ref),
                )
                changed += 1
            elif existing[1] == "active" and status == "resolved":
                connection.execute(
                    "UPDATE alerts SET updated_at = ?, resolved_at = ?, status = 'resolved', last_value = 'resolved', duration_seconds = ? WHERE id = ?",
                    (updated, resolved, duration_seconds, existing[0]),
                )
                changed += 1
        connection.commit()
    return changed


def get_alerts(*, status=None, severity=None, limit=50, db_path=None):
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError("Invalid status")
    if severity is not None and severity not in ALERT_SEVERITIES:
        raise ValueError("Invalid severity")
    if limit not in ALERT_LIMITS:
        raise ValueError("Invalid limit")
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    query = "SELECT id, created_at, updated_at, resolved_at, severity, source, alert_type, target, title, message, status, last_value, threshold, duration_seconds FROM alerts"
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY updated_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query, params)]


def get_alert_summary(*, db_path=None, now=None):
    today = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    with closing(connect(db_path)) as connection:
        critical = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='active' AND severity='critical'").fetchone()[0]
        warning = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='active' AND severity='warning'").fetchone()[0]
        resolved_today = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='resolved' AND resolved_at >= ?", (today,)).fetchone()[0]
    return {"active_critical": critical, "active_warning": warning, "resolved_today": resolved_today}


def start_stale_monitor(*, metrics_db_path=METRICS_DB_PATH, db_path=None):
    def run():
        while True:
            try:
                evaluate_staleness(metrics_db_path=metrics_db_path, db_path=db_path)
            except (OSError, sqlite3.Error):
                LOG.exception("Alert staleness evaluation failed")
            time.sleep(STALE_INTERVAL)

    thread = threading.Thread(target=run, name="alert-stale-monitor", daemon=True)
    thread.start()
    return thread


def telegram_enabled():
    """Reserved feature flag; v1 intentionally sends no Telegram messages."""
    return os.environ.get("ALERT_TELEGRAM_ENABLED", "0") == "1"
