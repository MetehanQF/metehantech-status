"""Secret-free Camera Center health collection for the private admin UI."""

from datetime import datetime, timezone
import os
import json
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import threading
import time

import requests
import network
import deployment


CAMERA_IP = network.get("CAMERA_LAN_IP")
NFS_SERVER = network.get("PCOLD_LAN_IP")
NFS_SOURCE = NFS_SERVER + ":/srv/metehantech-camera"
MEDIA_ROOT = "/mnt/metehantech-camera"
FRIGATE_API = "http://127.0.0.1:5400"
MIB = 1024 * 1024
CANARY_DB_PATH = Path(__file__).resolve().parent / "data" / "camera_canary.db"

_state_lock = threading.Lock()
_state = {
    "last_motion_count": None,
    "last_motion_at": None,
    "last_recording_marker": None,
    "last_recording_change": None,
    "storage_baseline_used": None,
    "storage_baseline_at": None,
}
_size_pattern = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([KMG]iB)$")


def _tcp_reachable(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _service_active(unit):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True,
            timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "active"


def _mount_identity():
    """Read kernel mount metadata without performing I/O on the hard NFS mount."""
    found = (None, None)
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as source:
            for line in source:
                left, separator, right = line.strip().partition(" - ")
                if not separator:
                    continue
                fields = left.split()
                remote = right.split()
                if len(fields) > 4 and len(remote) > 1 and fields[4] == MEDIA_ROOT:
                    found = (remote[0], remote[1])
                    if remote[0] in {"nfs", "nfs4"}:
                        return found
    except OSError:
        pass
    return found


def _json(path):
    try:
        response = requests.get(f"{FRIGATE_API}{path}", timeout=2)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError):
        return None


def _summary_values(summary):
    today = datetime.now().astimezone().date().isoformat()
    row = next((item for item in summary or [] if item.get("day") == today), {})
    hours = row.get("hours") if isinstance(row.get("hours"), list) else []
    return {
        "events": sum(max(0, int(item.get("events", 0))) for item in hours),
        "motion": sum(max(0, int(item.get("motion", 0))) for item in hours),
        "duration": sum(max(0, int(item.get("duration", 0))) for item in hours),
    }


def _derived(values, used_bytes, now):
    with _state_lock:
        motion = values["motion"]
        previous_motion = _state["last_motion_count"]
        if previous_motion is not None and motion > previous_motion:
            _state["last_motion_at"] = datetime.fromtimestamp(now, timezone.utc).isoformat()
        _state["last_motion_count"] = motion

        marker = values["duration"]
        if _state["last_recording_marker"] != marker:
            _state["last_recording_marker"] = marker
            _state["last_recording_change"] = now
        elif _state["last_recording_change"] is None:
            _state["last_recording_change"] = now

        if used_bytes is not None and _state["storage_baseline_used"] is None:
            _state["storage_baseline_used"] = used_bytes
            _state["storage_baseline_at"] = now
        growth = None
        baseline_at = _state["storage_baseline_at"]
        if used_bytes is not None and baseline_at is not None and now - baseline_at >= 300:
            delta = max(0, used_bytes - _state["storage_baseline_used"])
            growth = int(delta * 86400 / max(1, now - baseline_at))

        last_change = _state["last_recording_change"]
        return {
            "last_motion": _state["last_motion_at"],
            "recording_marker": marker,
            "recording_fresh": marker > 0 and last_change is not None and now - last_change <= 90,
            "daily_growth_bytes": growth,
        }


def _processing_paused(now):
    """Observe fresh, secret-free Frigate enabled state from the local HA bridge."""
    try:
        # Opsiyonel: yerel Home Assistant koprusunun ciktisi.
        path = deployment.optional_path('HA_RUNTIME_STATUS')
        if path is None:
            return False
        data = json.loads(path.read_text())
        return 0 <= now-float(data['updated']) < 90 and data.get('frigate',{}).get('enabled') is False
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _collect_camera_status(now=None):
    """Return bounded, credential-free state; never read Frigate configuration or logs."""
    current = time.time() if now is None else now
    camera_online = _tcp_reachable(CAMERA_IP, 554)
    nfs_network = _tcp_reachable(NFS_SERVER, 2049)
    fstype, source = _mount_identity()
    nfs_mounted = fstype in {"nfs", "nfs4"} and source == NFS_SOURCE and nfs_network
    frigate_running = _service_active("metehantech-frigate.service")

    stats = _json("/api/stats") if frigate_running else None
    camera_stats = ((stats or {}).get("cameras") or {}).get("tapo_c211") or {}
    stream_available = float(camera_stats.get("camera_fps") or 0) > 0
    reconnects = int(camera_stats.get("reconnects_last_hour") or 0)
    stalls = int(camera_stats.get("stalls_last_hour") or 0)

    streams = _json("/api/go2rtc/streams") if stats is not None else None
    go2rtc_healthy = isinstance(streams, dict) and {
        "tapo_c211_main", "tapo_c211_sub"
    }.issubset(streams)

    values = _summary_values(_json("/api/tapo_c211/recordings/summary") if stats is not None else None)
    storage = ((stats or {}).get("service") or {}).get("storage") or {}
    media = storage.get("/media/frigate/recordings") or {}
    used_bytes = int(float(media["used"]) * MIB) if isinstance(media.get("used"), (int, float)) else None
    free_bytes = int(float(media["free"]) * MIB) if isinstance(media.get("free"), (int, float)) else None
    total_bytes = int(float(media["total"]) * MIB) if isinstance(media.get("total"), (int, float)) else None
    derived = _derived(values, used_bytes, current)
    recording_active = bool(nfs_mounted and stream_available and derived["recording_fresh"])

    return {
        "camera": {"name": "Tapo C211", "online": camera_online},
        "processing_paused": _processing_paused(current),
        "frigate": {"running": frigate_running, "api_healthy": stats is not None},
        "go2rtc": {"healthy": go2rtc_healthy},
        "stream": {
            "available": stream_available,
            "camera_fps": camera_stats.get("camera_fps"),
            "process_fps": camera_stats.get("process_fps"),
            "detection_fps": camera_stats.get("detection_fps"),
            "ffmpeg_pid": camera_stats.get("ffmpeg_pid"),
            "reconnects_last_hour": reconnects,
            "stalls_last_hour": stalls,
        },
        "recording": {
            "active": recording_active,
            "marker": derived["recording_marker"],
        },
        "nfs": {"mounted": nfs_mounted},
        "storage": {
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
            "total_bytes": total_bytes,
            "daily_growth_bytes": derived["daily_growth_bytes"],
        },
        "last_motion": derived["last_motion"],
        "events_today": values["events"],
        "motion_activity_today": values["motion"],
        "updated_at": datetime.fromtimestamp(current, timezone.utc).isoformat(),
    }


def _size_bytes(value):
    match = _size_pattern.match(value.strip())
    if not match:
        return None
    scale = {"KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}[match.group(2)]
    return int(float(match.group(1)) * scale)


def _docker_sample():
    try:
        stats = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", "metehantech-frigate"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        inspect = subprocess.run(
            ["docker", "inspect", "--format", "{{.RestartCount}}", "metehantech-frigate"],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None, None
    cpu, separator, memory = stats.stdout.strip().partition("|")
    memory_used = memory.split("/", 1)[0].strip() if separator else ""
    try:
        cpu_percent = float(cpu.rstrip("%"))
    except ValueError:
        cpu_percent = None
    try:
        restarts = int(inspect.stdout.strip()) if inspect.returncode == 0 else None
    except ValueError:
        restarts = None
    return cpu_percent, _size_bytes(memory_used), restarts


def _host_sample():
    values = {}
    try:
        with open("/proc/meminfo", encoding="ascii") as source:
            for line in source:
                key, _, raw = line.partition(":")
                if key in {"MemAvailable", "SwapTotal", "SwapFree"}:
                    values[key] = int(raw.split()[0]) * 1024
        with open("/sys/class/thermal/thermal_zone0/temp", encoding="ascii") as source:
            temperature = int(source.read().strip()) / 1000
    except (OSError, ValueError, IndexError):
        temperature = None
    swap = None
    if "SwapTotal" in values and "SwapFree" in values:
        swap = values["SwapTotal"] - values["SwapFree"]
    try:
        load = os.getloadavg()[0]
    except (OSError, AttributeError):
        load = None
    return values.get("MemAvailable"), swap, temperature, load


def collect_canary_sample(*, db_path=CANARY_DB_PATH, now=None):
    current = time.time() if now is None else now
    status = get_camera_status(now=current)
    cpu, memory, restarts = _docker_sample()
    available, swap, temperature, load = _host_sample()
    try:
        response = requests.get("https://cloud.metehantech.com/status.php", timeout=5)
        nextcloud_latency = response.elapsed.total_seconds() if response.status_code == 200 else None
    except requests.RequestException:
        nextcloud_latency = None
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS samples (
                timestamp REAL PRIMARY KEY, frigate_cpu REAL, frigate_memory INTEGER,
                mem_available INTEGER, swap_used INTEGER, temperature REAL, load1 REAL,
                nextcloud_latency REAL, reconnects INTEGER, stalls INTEGER,
                storage_used INTEGER, storage_free INTEGER, container_restarts INTEGER,
                camera_online INTEGER, stream_available INTEGER, recording_active INTEGER,
                nfs_mounted INTEGER
            )
        """)
        connection.execute(
            "INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                current, cpu, memory, available, swap, temperature, load, nextcloud_latency,
                status["stream"]["reconnects_last_hour"], status["stream"]["stalls_last_hour"],
                status["storage"]["used_bytes"], status["storage"]["free_bytes"], restarts,
                int(status["camera"]["online"]), int(status["stream"]["available"]),
                int(status["recording"]["active"]), int(status["nfs"]["mounted"]),
            ),
        )
        connection.commit()
    os.chmod(path, 0o600)
    return status


def start_canary_collector(*, interval=60, db_path=CANARY_DB_PATH):
    def run():
        while True:
            started = time.monotonic()
            try:
                collect_canary_sample(db_path=db_path)
            except Exception:
                # Gunicorn owns logging; collection failure must never affect the UI.
                pass
            time.sleep(max(1, interval - (time.monotonic() - started)))

    thread = threading.Thread(target=run, name="camera-canary-collector", daemon=True)
    thread.start()
    return thread

_camera_cache = None
_camera_cache_time = 0.0
_camera_cache_lock = threading.Lock()

def get_camera_status(now=None):
    global _camera_cache, _camera_cache_time
    if now is not None:
        return _collect_camera_status(now=now)
    with _camera_cache_lock:
        if _camera_cache is None or time.monotonic() - _camera_cache_time >= 9:
            _camera_cache = _collect_camera_status()
            _camera_cache_time = time.monotonic()
        return _camera_cache
