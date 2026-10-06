#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import shutil
import subprocess
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


def read_proc_stat():
    with open("/proc/stat", "r") as f:
        parts = f.readline().split()
    values = list(map(int, parts[1:]))
    idle = values[3] + values[4]  # idle + iowait
    total = sum(values)
    return idle, total


def get_cpu():
    try:
        idle1, total1 = read_proc_stat()
        time.sleep(0.3)
        idle2, total2 = read_proc_stat()
        total_delta = total2 - total1
        idle_delta = idle2 - idle1
        if total_delta <= 0:
            return None
        return round((1 - idle_delta / total_delta) * 100, 1)
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


server = HTTPServer(("0.0.0.0", 8765), MetricsHandler)

print("MetehanTech metrics server listening on port 8765")
server.serve_forever()
