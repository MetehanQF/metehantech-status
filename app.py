"""MetehanTech System Status dashboard."""

from datetime import datetime, timezone
import math
import os
import shutil
import sqlite3
import subprocess

import psutil
import requests
import urllib3
from flask import Flask, jsonify, render_template, request

from admin import configure_admin
from history import RANGES, get_history, start_collector
from events import SEVERITIES, SOURCE_PATTERN, get_events
from incidents import get_incidents

app = Flask(__name__)
configure_admin(app)
from control_center import control
app.register_blueprint(control)
from dns_center import dns
import network
app.register_blueprint(dns)

# PcOld's Portainer HTTPS port serves its own self-signed certificate.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
PORTAINER_URL = "https://{0}/".format(network.endpoint("PCOLD_LAN_IP", 9443))


@app.after_request
def secure_response(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' blob:; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    if request.path.startswith("/admin") or request.path.startswith("/api/admin"):
        response.headers["Cache-Control"] = "no-store"
    return response


def read_temperature():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", encoding="ascii") as source:
            return f"{int(source.read().strip()) / 1000:.1f} °C"
    except (OSError, ValueError):
        return "UNKNOWN"


def read_ram():
    try:
        with open("/proc/meminfo", encoding="ascii") as source:
            values = {}
            for line in source:
                key, _, value = line.partition(":")
                if key in {"MemTotal", "MemAvailable"}:
                    values[key] = int(value.split()[0])
        total = values["MemTotal"]
        available = values["MemAvailable"]
        if total <= 0 or not 0 <= available <= total:
            return "UNKNOWN"
        return f"{(total - available) / total * 100:.1f}%"
    except (OSError, ValueError, KeyError, IndexError):
        return "UNKNOWN"


def read_disk():
    try:
        usage = shutil.disk_usage("/")
        return f"{usage.used / usage.total * 100:.1f}%" if usage.total else "UNKNOWN"
    except OSError:
        return "UNKNOWN"


def read_load():
    try:
        return f"{os.getloadavg()[0]:.2f}"
    except (OSError, AttributeError):
        return "UNKNOWN"


def read_cpu_percent():
    try:
        return f"{psutil.cpu_percent(interval=0.3):.1f}%"
    except Exception:
        return "UNKNOWN"


def run_command(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def service_active(unit):
    result = run_command(["systemctl", "is-active", unit])
    if result is None:
        return None
    state = result.stdout.strip()
    if state == "active" and result.returncode == 0:
        return True
    if state in {"inactive", "failed", "activating", "deactivating"}:
        return False
    return None


def read_throttled():
    result = run_command(["vcgencmd", "get_throttled"])
    if result is None or result.returncode != 0:
        return None
    try:
        key, value = result.stdout.strip().split("=", 1)
        if key != "throttled":
            return None
        return int(value, 16) != 0
    except ValueError:
        return None


def http_healthy(url):
    try:
        response = requests.get(url, timeout=2, allow_redirects=False)
        return 200 <= response.status_code <= 399
    except requests.RequestException:
        return None


CLOUD_CONTAINERS = (
    ("Nextcloud", "metehantech-nextcloud-app"),
    ("Nextcloud PostgreSQL", "metehantech-nextcloud-db"),
    ("Nextcloud Redis", "metehantech-nextcloud-redis"),
    ("Nextcloud Cron", "metehantech-nextcloud-cron"),
)
CLOUD_ROOT = "/srv/metehantech-cloud"
CLOUD_BACKUPS_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "backups.db")


_container_details = []
MONITORED_CONTAINERS = CLOUD_CONTAINERS + (
    ('Home Assistant', 'metehantech-homeassistant'),
    ('Frigate', 'metehantech-frigate'),
    ('Mosquitto', 'metehantech-mosquitto'),
    ('AdGuard Home', 'metehantech-adguard'),
)

def read_cloud_containers():
    """One docker inspect for the whole Personal Cloud stack keeps /api/status cheap."""
    global _container_details
    names = [name for _, name in MONITORED_CONTAINERS]
    result = run_command(["docker", "inspect", "--format",
                          "{{.Name}} {{if .State.Health}}{{.State.Health.Status}}"
                          "{{else}}{{.State.Status}}{{end}} {{.RestartCount}} {{.State.StartedAt}}", *names])
    states = {}; details = []
    if result is not None:
        for line in result.stdout.splitlines():
            fields = line.strip().lstrip('/').split()
            if len(fields) != 4 or fields[0] not in names: continue
            name, state, count, started = fields
            states[name] = state
            details.append({'name':name, 'state':state, 'restart_count':int(count) if count.isdigit() else None, 'started_at':started})
    _container_details = details
    return {label: (states[name] in {'healthy', 'running'} if name in states else None)
            for label, name in CLOUD_CONTAINERS}


def read_cloud_backup():
    """Last verified Personal Cloud restore point; never infers success from an attempt."""
    if not os.path.exists(CLOUD_BACKUPS_DB):
        return {"age_hours": None, "backup_id": None, "finished_at": None}
    try:
        connection = sqlite3.connect(f"file:{CLOUD_BACKUPS_DB}?mode=ro", uri=True, timeout=2)
        try:
            row = connection.execute(
                "SELECT backup_id, finished_at FROM backups WHERE source_node='cloud' "
                "AND status='success' AND verification_status='verified' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return {"age_hours": None, "backup_id": None, "finished_at": None}
    if not row:
        return {"age_hours": None, "backup_id": None, "finished_at": None}
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(row[1])).total_seconds() / 3600
    except (TypeError, ValueError):
        age = None
    return {"backup_id": row[0], "finished_at": row[1],
            "age_hours": None if age is None else round(max(0.0, age), 1)}


def read_cloud():
    """Personal Cloud panel: containers, reachability, storage headroom, last backup."""
    containers = read_cloud_containers()
    try:
        usage = shutil.disk_usage(CLOUD_ROOT)
        storage = {"used_percent": round(usage.used / usage.total * 100, 1) if usage.total else None,
                   "free_gb": round(usage.free / 1024 ** 3, 1)}
    except OSError:
        storage = {"used_percent": None, "free_gb": None}
    return {
        "containers": containers,
        "reachable": http_healthy("http://127.0.0.1:5300/status.php"),
        "storage": storage,
        "last_backup": read_cloud_backup(),
    }


def old_pc_metric(value, suffix=""):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return "UNKNOWN"
    return f"{value:g}{suffix}"


def old_pc_check(value):
    if not isinstance(value, str):
        return None
    state = value.strip().upper()
    if state == "OK":
        return True
    if state in {"UNKNOWN", ""}:
        return None
    return False


def portainer_healthy():
    """Independent reachability probe; not routed through the PcOld agent."""
    try:
        response = requests.get(PORTAINER_URL, timeout=2, verify=False, allow_redirects=False)
        return 200 <= response.status_code <= 399
    except requests.RequestException:
        return False


def read_old_pc():
    """Read the laptop API once per dashboard request, with a two-second limit."""
    device = {
        "id": "pcold",
        "name": "MetehanTechPcOld",
        "kind": "Secondary node",
        "online": False,
        "metrics": {key: "UNKNOWN" for key in ("temperature", "ram", "disk", "load", "cpu")},
        "checks": {"Docker": None, "SMART": None, "Portainer": portainer_healthy()},
    }
    try:
        response = requests.get("http://{0}/status".format(network.endpoint("PCOLD_LAN_IP", 8765)), timeout=2)
        if response.status_code != 200:
            return device
        data = response.json()
        if not isinstance(data, dict):
            return device
    except (requests.RequestException, ValueError):
        return device

    device["online"] = True
    uptime = format_uptime(data.get("uptime"))
    if uptime:
        device["uptime"] = uptime
    device["metrics"] = {
        "temperature": old_pc_metric(data.get("temperature"), " °C"),
        "ram": old_pc_metric(data.get("ram"), "%"),
        "disk": old_pc_metric(data.get("disk"), "%"),
        "load": old_pc_metric(data.get("load")),
        "cpu": old_pc_metric(data.get("cpu"), "%"),
    }
    device["checks"]["Docker"] = old_pc_check(data.get("docker"))
    device["checks"]["SMART"] = old_pc_check(data.get("smart"))
    return device


def read_pi_uptime():
    try:
        with open("/proc/uptime", encoding="ascii") as source:
            return format_uptime(float(source.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def format_uptime(seconds):
    if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds < 0:
        return None
    minutes = int(seconds // 60)
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def get_status():
    """Collect fresh local status for each API request."""
    docker = service_active("docker")
    cloudflared = service_active("cloudflared")
    tailscale = service_active("tailscaled")
    rustdesk = service_active("rustdesk")
    throttled = read_throttled()
    devices = [
        {
            "id": "pi5",
            "name": "Raspberry Pi 5",
            "kind": "Primary node",
            "online": True,
            "uptime": read_pi_uptime(),
            "metrics": {
                "temperature": read_temperature(),
                "ram": read_ram(),
                "disk": read_disk(),
                "load": read_load(),
                "cpu": read_cpu_percent(),
            },
            "checks": {
                "Docker": docker,
                "Cloudflared": cloudflared,
                "Tailscale": tailscale,
                "RustDesk": rustdesk,
                "Throttled": throttled,
            },
        },
        read_old_pc(),
    ]
    cloud = read_cloud()
    services = [
        {"name": "MetehanTech Home", "operational": http_healthy("http://127.0.0.1:5100")},
        {"name": "MetehanTech Clan", "operational": http_healthy("http://127.0.0.1:5000")},
        {"name": "Personal Cloud", "operational": cloud["reachable"]},
        *({"name": label, "operational": state} for label, state in cloud["containers"].items()),
        # Reachability only. No query, client or domain data reaches the public page.
        {"name": "AdGuard Home", "operational": http_healthy("http://127.0.0.1:3000/login.html")},
        {"name": "Cloudflare Tunnel", "operational": cloudflared},
        {"name": "Tailscale", "operational": tailscale},
        {"name": "RustDesk", "operational": rustdesk},
        {"name": "Docker", "operational": docker},
    ]
    operational = all(device["online"] for device in devices) and all(
        service["operational"] is True for service in services
    ) and all(
        (value is False if name == "Throttled" else value is True)
        for device in devices
        for name, value in device["checks"].items()
    )
    return {
        "operational": operational,
        "devices": devices,
        "services": services,
        "personal_cloud": cloud,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "demo": False,
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    from control_center import build_summary, cached_status
    data = cached_status() or get_status()
    data["health"] = build_summary()["health"]
    return jsonify(data)


@app.get("/api/history")
def history():
    device = request.args.get("device", "")
    range_name = request.args.get("range", "")
    if device not in {"pi5", "pcold"} or range_name not in RANGES:
        return jsonify({"error": "Invalid device or range"}), 400
    try:
        return jsonify(get_history(device, range_name))
    except (OSError, sqlite3.Error):
        app.logger.exception("History read failed")
        return jsonify({"error": "History temporarily unavailable"}), 503


@app.get("/api/events")
def events():
    raw_limit = request.args.get("limit", "50")
    severity = request.args.get("severity")
    source = request.args.get("source")
    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify({"error": "Invalid limit"}), 400
    if not 1 <= limit <= 200 or (severity and severity not in SEVERITIES) or (source and not SOURCE_PATTERN.fullmatch(source)):
        return jsonify({"error": "Invalid event filter"}), 400
    try:
        return jsonify(get_events(limit=limit, severity=severity, source=source))
    except (OSError, sqlite3.Error):
        app.logger.exception("Events read failed")
        return jsonify({"error": "Events temporarily unavailable"}), 503


@app.get("/api/incidents")
def incidents():
    raw_limit = request.args.get("limit", "20")
    status_filter = request.args.get("status")
    source = request.args.get("source")
    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify({"error": "Invalid limit"}), 400
    if not 1 <= limit <= 200 or (status_filter and status_filter not in {"active", "resolved"}) or (source and not SOURCE_PATTERN.fullmatch(source)):
        return jsonify({"error": "Invalid incident filter"}), 400
    try:
        return jsonify(get_incidents(limit=limit, status=status_filter, source=source))
    except (OSError, sqlite3.Error):
        app.logger.exception("Incidents read failed")
        return jsonify({"error": "Incidents temporarily unavailable"}), 503


if __name__ == "__main__":
    start_collector(get_status)
    app.run(host="0.0.0.0", port=5200)
