"""Authenticated, whitelist-only administration routes."""

from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps
import ipaddress
import os
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

import network

from activity import (
    ACTIVITY_LIMITS,
    clear_pending_restart,
    complete_pending_restart,
    get_activity,
    record_activity,
    set_pending_restart,
)
from alerts import (
    ALERT_LIMITS,
    ALERT_SEVERITIES,
    ALERT_STATUSES,
    clear_service_suppression,
    get_alert_summary,
    get_alerts,
    suppress_service,
)
from backups import (
    LIMITS as BACKUP_LIMITS,
    backup_summary,
    enqueue_backup,
    fail_backup,
    get_backup,
    list_backups,
    update_backup,
    validate_backup_id,
    verify_restore_point,
)
from camera import get_camera_status


ALLOWED_SERVICES = {
    "metehantech-status.service": "MetehanTech Status",
    "metehantech-home.service": "MetehanTech Home",
    "clan-web.service": "MetehanTech Clan",
}
LOG_LINE_COUNTS = {100, 500}
LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
SELF_SERVICE = "metehantech-status.service"
RESTART_MESSAGES = {
    "metehantech-home.service": "MetehanTech Home restarted successfully.",
    "clan-web.service": "MetehanTech Clan restarted successfully.",
}
BACKUP_JOB_UNITS = {
    "pi": "metehantech-backup-pi.service",
    "pcold": "metehantech-backup-pcold.service",
    "cloud": "metehantech-backup-cloud.service",
}
CLOUD_CONTAINERS = {
    "nextcloud": "metehantech-nextcloud-app",
    "postgresql": "metehantech-nextcloud-db",
    "redis": "metehantech-nextcloud-redis",
    "cron": "metehantech-nextcloud-cron",
}
CLOUD_DATA_ROOT = "/srv/metehantech-cloud"

admin = Blueprint("admin", __name__)
_attempts = defaultdict(deque)
_attempts_lock = threading.Lock()


def configure_admin(app):
    """Apply secure session defaults and register admin routes."""
    app.secret_key = os.environ.get("ADMIN_SESSION_SECRET") or secrets.token_hex(32)
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("ADMIN_COOKIE_SECURE", "1") != "0",
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )
    app.register_blueprint(admin)
    try:
        complete_pending_restart(SELF_SERVICE)
    except (OSError, sqlite3.Error):
        app.logger.exception("Could not reconcile pending Control Center restart")


def _run(args, timeout=5):
    """Run a fixed argv command; callers must validate every variable first."""
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        current_app.logger.exception("Admin command failed: %s", args[0])
        return None


def _password_hash():
    return os.environ.get("ADMIN_PASSWORD_HASH", "")


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_valid():
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


def _client_ip():
    """Trust Cloudflare's IP header only from the localhost-only tunnel hop."""
    peer = request.remote_addr or "unknown"
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return "unknown"
    if peer_ip.is_loopback:
        candidate = request.headers.get("CF-Connecting-IP", "").strip()
        try:
            return str(ipaddress.ip_address(candidate)) if candidate else str(peer_ip)
        except ValueError:
            pass
    return str(peer_ip)


def _user_agent():
    return request.user_agent.string[:200] or "unknown"


def _audit(action, target, result):
    try:
        record_activity(action, target, result, _client_ip(), _user_agent())
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not write admin activity")


def _login_blocked(key):
    now = time.monotonic()
    with _attempts_lock:
        attempts = _attempts[key]
        while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        return len(attempts) >= LOGIN_ATTEMPTS


def _record_failure(key):
    with _attempts_lock:
        _attempts[key].append(time.monotonic())


def _clear_failures(key):
    with _attempts_lock:
        _attempts.pop(key, None)


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("admin.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def csrf_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _csrf_valid():
            return jsonify({"error": "Invalid CSRF token"}), 403
        return view(*args, **kwargs)

    return wrapped


def _docker_whitelist():
    """Read an operator-owned exact-name whitelist, never names supplied by a request."""
    return {
        name.strip()
        for name in os.environ.get("ADMIN_DOCKER_CONTAINERS", "").split(",")
        if name.strip()
    }


def _service_state(unit):
    return _service_snapshot(unit)[0]


def _service_snapshot(unit):
    result = _run(["systemctl", "show", unit, "--property=ActiveState,SubState,MainPID", "--no-pager"])
    if result is None:
        return "unknown", "0"
    values = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    return values.get("SubState") or values.get("ActiveState") or "unknown", values.get("MainPID", "0")


def _wait_for_service_restart(unit, old_pid):
    for _ in range(60):
        state, pid = _service_snapshot(unit)
        if state == "running" and pid not in {"", "0", old_pid}:
            return True
        time.sleep(0.25)
    return False


def _container_state(name):
    result = _run(["docker", "inspect", "--format", "{{.State.Status}}", name])
    if result is None or result.returncode != 0:
        return "unavailable"
    return result.stdout.strip() or "unknown"


def _container_health(name):
    result = _run(["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", name])
    if result is None or result.returncode != 0:
        return "unavailable"
    return result.stdout.strip() or "unknown"


@admin.get("/admin/login")
def login():
    if session.get("admin_authenticated"):
        return redirect(url_for("admin.dashboard"))
    return render_template("admin_login.html", csrf_token=_csrf_token(), configured=bool(_password_hash()))


@admin.post("/admin/login")
def login_submit():
    key = _client_ip()
    if not _csrf_valid():
        _audit("login_failure", "admin", "invalid_csrf")
        return render_template("admin_login.html", csrf_token=_csrf_token(), configured=bool(_password_hash()), error="Session expired. Please try again."), 403
    if _login_blocked(key):
        _audit("login_failure", "admin", "rate_limited")
        return render_template("admin_login.html", csrf_token=_csrf_token(), configured=bool(_password_hash()), error="Too many attempts. Try again later."), 429
    password_hash = _password_hash()
    password = request.form.get("password", "")[:1024]
    if not password_hash or not password or not check_password_hash(password_hash, password):
        _record_failure(key)
        _audit("login_failure", "admin", "invalid_credentials")
        return render_template("admin_login.html", csrf_token=_csrf_token(), configured=bool(password_hash), error="Invalid credentials."), 401
    _clear_failures(key)
    session.clear()
    session["admin_authenticated"] = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    _audit("login_success", "admin", "success")
    return redirect(url_for("admin.dashboard"))


@admin.post("/admin/logout")
@admin_required
def logout():
    if not _csrf_valid():
        return "Invalid CSRF token", 403
    _audit("logout", "admin", "success")
    session.clear()
    return redirect(url_for("admin.login"))


@admin.get("/admin")
@admin_required
def dashboard():
    # Ag adresleri sablona sunucudan gecirilir; ne sablonda ne de istemci JS'inde
    # sabit tutulur. Kaynak: /etc/metehantech-status/network.env
    return render_template(
        "admin.html",
        csrf_token=_csrf_token(),
        backup_center_enabled=True,
        lan_host=network.get("PI5_LAN_IP"),
        tailscale_host=network.get("PI5_TAILSCALE_IP"),
    )


@admin.get("/api/admin/health")
@admin_required
def admin_health():
    return jsonify({"ok": True})


@admin.get("/api/admin/activity")
@admin_required
def activity_log():
    limit = request.args.get("limit", type=int)
    if limit not in ACTIVITY_LIMITS:
        return jsonify({"error": "Limit must be 50, 100 or 500"}), 400
    try:
        entries = get_activity(limit)
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not read admin activity")
        return jsonify({"error": "Activity log is unavailable"}), 503
    _audit("activity_viewed", "admin_activity", "success")
    return jsonify({"entries": entries, "limit": limit})


@admin.get("/api/admin/alerts")
@admin_required
def alerts_list():
    status = request.args.get("status") or None
    severity = request.args.get("severity") or None
    limit = request.args.get("limit", 50, type=int)
    if status not in ALERT_STATUSES | {None} or severity not in ALERT_SEVERITIES | {None} or limit not in ALERT_LIMITS:
        return jsonify({"error": "Invalid alert filter"}), 400
    try:
        entries = get_alerts(status=status, severity=severity, limit=limit)
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not read alerts")
        return jsonify({"error": "Alerts are unavailable"}), 503
    return jsonify({"alerts": entries, "limit": limit})


@admin.get("/api/admin/alerts/summary")
@admin_required
def alerts_summary():
    try:
        return jsonify(get_alert_summary())
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not read alert summary")
        return jsonify({"error": "Alert summary is unavailable"}), 503


@admin.get("/api/admin/camera")
@admin_required
def camera_summary():
    try:
        return jsonify(get_camera_status())
    except (OSError, ValueError):
        current_app.logger.exception("Could not read Camera Center status")
        return jsonify({"error": "Camera Center status is unavailable"}), 503


@admin.get("/api/admin/backups")
@admin_required
def backups_list():
    limit = request.args.get("limit", 50, type=int)
    if limit not in BACKUP_LIMITS:
        return jsonify({"error": "Limit must be 50, 100 or 500"}), 400
    try:
        return jsonify({"backups": list_backups(limit), "limit": limit})
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not read backup history")
        return jsonify({"error": "Backup history is unavailable"}), 503


@admin.get("/api/admin/backups/summary")
@admin_required
def backups_summary():
    try:
        return jsonify(backup_summary())
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not read backup summary")
        return jsonify({"error": "Backup summary is unavailable"}), 503


@admin.get("/api/admin/backups/assurance")
@admin_required
def backups_assurance():
    """Per-flow assurance level, freshness, and component coverage. Read-only.

    Deliberately separate from /summary rather than folded into it: the existing
    summary shape is consumed by the deployed frontend, and changing it under a
    running process is how a dashboard starts lying.
    """
    try:
        from backup_validator import live_assurance
        return jsonify(live_assurance())
    except (OSError, sqlite3.Error, ValueError, ImportError):
        current_app.logger.exception("Could not build backup assurance report")
        return jsonify({"error": "Backup assurance report is unavailable"}), 503


def _start_backup(node):
    unit = BACKUP_JOB_UNITS[node]
    try:
        record = enqueue_backup(node)
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not queue backup")
        return jsonify({"error": "Could not queue backup"}), 503
    _audit("backup_requested", node, record["backup_id"])
    result = _run(["sudo", "-n", "systemctl", "start", "--no-block", unit])
    if result is None or result.returncode != 0:
        try:
            fail_backup(record["backup_id"], "Backup unit could not be started")
        except (OSError, sqlite3.Error, KeyError):
            current_app.logger.exception("Could not persist backup start failure")
        _audit("backup_start_failure", node, "unit_start_failed")
        return jsonify({"error": "Backup permission is unavailable or the job could not start"}), 503
    _audit("backup_started", node, record["backup_id"])
    return jsonify({"ok": True, "backup": record, "message": "Backup queued."}), 202


@admin.post("/api/admin/backups/pi/start")
@admin_required
@csrf_required
def start_pi_backup():
    return _start_backup("pi")


@admin.post("/api/admin/backups/pcold/start")
@admin_required
@csrf_required
def start_pcold_backup():
    return _start_backup("pcold")


@admin.post("/api/admin/backups/cloud/start")
@admin_required
@csrf_required
def start_cloud_backup():
    return _start_backup("cloud")


@admin.get("/api/admin/cloud/summary")
@admin_required
def cloud_summary():
    usage = shutil.disk_usage(CLOUD_DATA_ROOT) if os.path.isdir(CLOUD_DATA_ROOT) else None
    try:
        last_backup = backup_summary()["nodes"].get("cloud")
    except (OSError, sqlite3.Error):
        last_backup = None
    return jsonify({
        "url": "https://cloud.metehantech.com",
        "containers": {
            label: {"name": name, "state": _container_state(name), "health": _container_health(name)}
            for label, name in CLOUD_CONTAINERS.items()
        },
        "storage": None if usage is None else {
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0,
        },
        "last_backup": last_backup,
        "sensitive_configuration": "NOT ENABLED",
    })


@admin.get("/api/admin/backups/<backup_id>")
@admin_required
def backup_detail(backup_id):
    try:
        validate_backup_id(backup_id)
        record = get_backup(backup_id)
    except ValueError:
        return jsonify({"error": "Invalid backup id"}), 404
    except (OSError, sqlite3.Error):
        return jsonify({"error": "Backup history is unavailable"}), 503
    if record is None:
        return jsonify({"error": "Backup not found"}), 404
    return jsonify({"backup": record})


@admin.post("/api/admin/backups/<backup_id>/verify")
@admin_required
@csrf_required
def verify_backup(backup_id):
    try:
        validate_backup_id(backup_id)
        record = get_backup(backup_id)
    except ValueError:
        return jsonify({"error": "Invalid backup id"}), 404
    except (OSError, sqlite3.Error):
        return jsonify({"error": "Backup history is unavailable"}), 503
    if record is None or record["status"] not in {"success", "verification_failed"} or not record["restore_point_path"]:
        return jsonify({"error": "Verified restore point not found"}), 404
    try:
        if record["restore_point_path"].startswith("ssh://"):
            from backup_job import _remote, choose_pcold_host
            host = choose_pcold_host()
            _remote(host, "verify", backup_id, timeout=120)
            verification = {"checksum_status": "verified", "verification_status": "verified"}
        else:
            verification = verify_restore_point(record["restore_point_path"])
        record = update_backup(
            backup_id,
            status="success",
            checksum_status=verification["checksum_status"],
            verification_status=verification["verification_status"],
            phase="Completed",
            error_summary=None,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        try:
            record = update_backup(
                backup_id,
                status="verification_failed",
                phase="Verification failed",
                checksum_status="failed",
                verification_status="failed",
                error_summary=str(error)[:500],
            )
        except (OSError, sqlite3.Error, KeyError):
            current_app.logger.exception("Could not persist verification failure")
        _audit("backup_verification", backup_id, "failed")
        return jsonify({"error": "Backup verification failed", "backup": record}), 422
    _audit("backup_verification", backup_id, "verified")
    return jsonify({"ok": True, "backup": record})


@admin.get("/api/admin/resources")
@admin_required
def resources():
    services = [
        {"id": unit, "name": label, "state": _service_state(unit)}
        for unit, label in ALLOWED_SERVICES.items()
    ]
    containers = [
        {"id": name, "name": name, "state": _container_state(name)}
        for name in sorted(_docker_whitelist())
    ]
    return jsonify({"services": services, "containers": containers})


@admin.post("/api/admin/services/<unit>/restart")
@admin_required
@csrf_required
def restart_service(unit):
    if unit not in ALLOWED_SERVICES:
        return jsonify({"error": "Service is not allowed"}), 404
    try:
        suppress_service(unit)
    except (OSError, sqlite3.Error):
        current_app.logger.exception("Could not create restart alert suppression")
        return jsonify({"error": "Could not safely create restart grace period"}), 503
    _audit("service_restart_requested", unit, "requested")
    if unit == SELF_SERVICE:
        try:
            set_pending_restart(unit, _client_ip(), _user_agent())
        except (OSError, sqlite3.Error):
            current_app.logger.exception("Could not persist self-restart marker")
            _audit("service_restart_failure", unit, "activity_storage_failed")
            return jsonify({"error": "Could not safely schedule Control Center restart"}), 503
        result = _run(["sudo", "-n", "systemctl", "restart", "--no-block", unit])
        if result is None or result.returncode != 0:
            clear_pending_restart(unit)
            clear_service_suppression(unit)
            _audit("service_restart_failure", unit, "command_failed")
            return jsonify({"error": "Restart permission is unavailable or restart failed"}), 503
        return jsonify({"ok": True, "self_restart": True, "message": "Restarting Control Center... reconnecting."}), 202

    old_pid = _service_snapshot(unit)[1]
    result = _run(["sudo", "-n", "systemctl", "restart", "--no-block", unit])
    if result is None or result.returncode != 0:
        clear_service_suppression(unit)
        _audit("service_restart_failure", unit, "command_failed")
        return jsonify({"error": "Restart permission is unavailable or restart failed"}), 503
    if not _wait_for_service_restart(unit, old_pid):
        _audit("service_restart_failure", unit, "did_not_return_running")
        return jsonify({"error": "Service did not return to running state"}), 503
    _audit("service_restart_success", unit, "success")
    return jsonify({"ok": True, "message": RESTART_MESSAGES[unit]})


@admin.get("/api/admin/services/<unit>/logs")
@admin_required
def service_logs(unit):
    if unit not in ALLOWED_SERVICES:
        return jsonify({"error": "Service is not allowed"}), 404
    lines = request.args.get("lines", type=int)
    if lines not in LOG_LINE_COUNTS:
        return jsonify({"error": "Lines must be 100 or 500"}), 400
    result = _run(["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"], timeout=10)
    if result is None or result.returncode != 0:
        _audit("logs_viewed", unit, "failure")
        return jsonify({"error": "Logs are unavailable"}), 503
    _audit("logs_viewed", unit, f"success:{lines}")
    return jsonify({"resource": unit, "lines": lines, "log": result.stdout})


@admin.post("/api/admin/containers/<name>/restart")
@admin_required
@csrf_required
def restart_container(name):
    if name not in _docker_whitelist():
        return jsonify({"error": "Container is not allowed"}), 404
    _audit("container_restart_requested", name, "requested")
    result = _run(["docker", "restart", "--time", "10", name], timeout=20)
    if result is None or result.returncode != 0:
        _audit("container_restart_failure", name, "command_failed")
        return jsonify({"error": "Container restart failed"}), 503
    _audit("container_restart_success", name, "success")
    return jsonify({"ok": True, "message": "Container restarted."})


@admin.get("/api/admin/containers/<name>/logs")
@admin_required
def container_logs(name):
    if name not in _docker_whitelist():
        return jsonify({"error": "Container is not allowed"}), 404
    lines = request.args.get("lines", type=int)
    if lines not in LOG_LINE_COUNTS:
        return jsonify({"error": "Lines must be 100 or 500"}), 400
    result = _run(["docker", "logs", "--tail", str(lines), name], timeout=10)
    if result is None or result.returncode != 0:
        _audit("container_logs_viewed", name, "failure")
        return jsonify({"error": "Logs are unavailable"}), 503
    _audit("container_logs_viewed", name, f"success:{lines}")
    return jsonify({"resource": name, "lines": lines, "log": result.stdout + result.stderr})
