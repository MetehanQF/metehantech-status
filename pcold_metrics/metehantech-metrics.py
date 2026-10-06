#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import os
import shutil
import subprocess
import threading
import time


def run_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3,
            check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


def get_temperature():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        return None


def get_ram():
    try:
        meminfo = {}

        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, value = line.split(":", 1)
                meminfo[key] = int(value.strip().split()[0])

        total = meminfo["MemTotal"]
        available = meminfo["MemAvailable"]

        return round((1 - available / total) * 100, 1)
    except Exception:
        return None


def get_disk():
    try:
        total, used, free = shutil.disk_usage("/")
        return round(used / total * 100, 1)
    except Exception:
        return None


def get_load():
    try:
        return round(os.getloadavg()[0], 2)
    except Exception:
        return None


# CPU utilization averaged from the newest stored /proc/stat snapshot that is at least
# MIN_WINDOW seconds old up to now (~60 s with the Pi collector). Never sleeps. Warm-up,
# counter resets and read errors return None (JSON null) instead of a fabricated 0.
MIN_WINDOW = 30.0
MAX_WINDOW = 300.0
STORE_SPACING = 5.0


def read_proc_stat(path="/proc/stat"):
    with open(path, "r") as f:
        parts = f.readline().split()
    if not parts or parts[0] != "cpu":
        raise ValueError("unexpected /proc/stat format")
    values = list(map(int, parts[1:9]))  # user..steal; guest is already in user/nice
    if len(values) < 5:
        raise ValueError("unexpected /proc/stat format")
    idle = values[3] + values[4]  # idle + iowait
    total = sum(values)
    return idle, total


class CpuSampler:
    def __init__(self, read_counters=read_proc_stat, clock=time.monotonic):
        self._read = read_counters
        self._clock = clock
        self._lock = threading.Lock()
        self._snapshots = []

    def sample(self):
        with self._lock:
            now = self._clock()
            try:
                idle, total = self._read()
            except (OSError, ValueError):
                return None
            self._snapshots = [s for s in self._snapshots if now - s[0] <= MAX_WINDOW]
            reference = None
            for snap in reversed(self._snapshots):
                if now - snap[0] >= MIN_WINDOW:
                    reference = snap
                    break
            if not self._snapshots or now - self._snapshots[-1][0] >= STORE_SPACING:
                self._snapshots.append((now, idle, total))
            if reference is None:
                return None
            total_delta = total - reference[2]
            idle_delta = idle - reference[1]
            if total_delta <= 0 or idle_delta < 0 or idle_delta > total_delta:
                self._snapshots = [(now, idle, total)]
                return None
            value = (1 - idle_delta / total_delta) * 100
            if not math.isfinite(value):
                return None
            return round(min(100.0, max(0.0, value)), 1)


CPU_SAMPLER = CpuSampler()


def get_cpu():
    try:
        return CPU_SAMPLER.sample()
    except Exception:
        return None


def get_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            return float(f.read().split()[0])
    except Exception:
        return None


def service_status(service):
    result = run_command(["systemctl", "is-active", service])
    return "OK" if result == "active" else "DOWN"


def smart_status():
    result = run_command(["/usr/sbin/smartctl", "-H", "/dev/sda"])

    if result is None:
        return "UNKNOWN"

    if "PASSED" in result:
        return "OK"

    return "DOWN"


class MetricsHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path != "/status":
            self.send_response(404)
            self.end_headers()
            return

        data = {
            "hostname": os.uname().nodename,
            "online": True,
            "temperature": get_temperature(),
            "ram": get_ram(),
            "disk": get_disk(),
            "load": get_load(),
            "cpu": get_cpu(),
            "uptime": get_uptime(),
            "docker": service_status("docker"),
            "smart": smart_status()
        }

        body = json.dumps(data).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    CPU_SAMPLER.sample()  # baseline at start; first value after MIN_WINDOW
    server = HTTPServer(("0.0.0.0", 8765), MetricsHandler)

    print("MetehanTech metrics server listening on port 8765")
    server.serve_forever()
