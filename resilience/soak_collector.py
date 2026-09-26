#!/usr/bin/env python3
"""Unattended soak collector for MetehanTech.

Runs detached, samples every SAMPLE_INTERVAL seconds until DURATION elapses, and
writes one JSON object per sample to a size-bounded JSONL file. It is entirely
self-contained: no model, no network egress beyond the existing LAN SSH path to
PcOld and loopback HTTP to local services, and nothing that writes to production.

Design constraints this file has to honour:
  * It must survive its parent dying, so it is started detached and keeps no
    handle on the caller.
  * It must not become the thing that destabilises the host it is measuring, so
    every probe is timeout-bounded and the process runs niced.
  * A probe that fails must be recorded as an error inside the sample, not
    allowed to kill the run. A soak with a gap is still evidence; a soak that
    died at minute 12 is not.
  * Output size is capped and rotated, so a pathological loop cannot fill the
    disk it is supposed to be watching.
"""

from _harness import pcold_ssh, results_dir, write_results  # noqa: E402  (repo-relative path setup)
import deployment  # noqa: E402
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time

BASE = results_dir()
SAMPLES = BASE / "soak-samples.jsonl"
STATUS = BASE / "soak-status.json"
MAX_BYTES = 20 * 1024 * 1024
KEEP_ROTATIONS = 2

DURATION = int(os.environ.get("SOAK_DURATION_SECONDS", 5 * 3600))
INTERVAL = int(os.environ.get("SOAK_INTERVAL_SECONDS", 300))

#: Resolved on first use, not at import — see `_harness.pcold_ssh`. A soak run on
#: an unconfigured clone still samples the local host; only the peer probe skips.
_PCOLD_SSH = None

HTTP_TARGETS = {
    "status_center": "http://127.0.0.1:5000/",
    "metehantech_home": "http://127.0.0.1:5100/",
    "clan_dashboard": "http://127.0.0.1:5200/",
    "nextcloud": "http://127.0.0.1:5300/status.php",
    "frigate": "http://127.0.0.1:5400/api/version",
}
WATCHED_UNITS = ("metehantech-status", "metehantech-home", "clan-web", "cloudflared",
                 "metehantech-frigate", "docker")
_stop = False


def _handle_stop(signum, frame):
    global _stop
    _stop = True


def run(argv, timeout=20):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout.strip(), result.returncode
    except (OSError, subprocess.SubprocessError) as error:
        return f"__error__ {type(error).__name__}: {error}", -1


def sh(command, timeout=20):
    return run(["sh", "-c", command], timeout)[0]


def pcold_sh(command, timeout=25):
    global _PCOLD_SSH
    if _PCOLD_SSH is None:
        try:
            _PCOLD_SSH = pcold_ssh()
        except deployment.DeploymentConfigError as error:
            # A probe that cannot be configured is recorded, never fatal: a soak
            # with one skipped probe is still evidence.
            return {"host": None, "reachable": False, "configured": False,
                    "output": f"not configured: {error}"}
    ssh = _PCOLD_SSH
    output = ""
    for host in ssh.hosts:
        argv = ["ssh", "-i", ssh.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=6", f"{ssh.user}@{host}", "sh", "-c", shlex.quote(command)]
        output, code = run(argv, timeout)
        if code == 0:
            return {"host": host, "reachable": True, "configured": True, "output": output}
    return {"host": None, "reachable": False, "configured": True, "output": output}


# ------------------------------------------------------------------ Pi probes

def sample_pi():
    load1, load5, load15 = (float(v) for v in Path("/proc/loadavg").read_text().split()[:3])
    meminfo = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        meminfo[key] = int(value.split()[0]) * 1024

    stat = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    fields = [int(v) for v in stat]
    total = sum(fields)
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)

    temp = None
    try:
        temp = int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000
    except (OSError, ValueError):
        pass

    disk_io = {}
    for line in Path("/proc/diskstats").read_text().splitlines():
        parts = line.split()
        if len(parts) > 9 and parts[2] in {"nvme0n1", "sda"}:
            disk_io[parts[2]] = {"sectors_read": int(parts[5]), "sectors_written": int(parts[9])}

    network = {}
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
        name, _, values = line.partition(":")
        name = name.strip()
        if name in {"eth0", "wlan0", "tailscale0"}:
            numbers = values.split()
            network[name] = {"rx_bytes": int(numbers[0]), "tx_bytes": int(numbers[8])}

    failed = sh("systemctl --failed --no-legend --no-pager | wc -l")
    failed_user = sh("systemctl --user --failed --no-legend --no-pager | wc -l")
    units = {name: sh(f"systemctl is-active {shlex.quote(name)}") for name in WATCHED_UNITS}

    df_root = sh("df -Pk / | tail -1").split()
    return {
        "load": {"1m": load1, "5m": load5, "15m": load15},
        "cpu_jiffies": {"total": total, "idle": idle},
        "memory": {
            "total_bytes": meminfo.get("MemTotal"),
            "available_bytes": meminfo.get("MemAvailable"),
            "swap_total_bytes": meminfo.get("SwapTotal"),
            "swap_free_bytes": meminfo.get("SwapFree"),
        },
        "temperature_c": temp,
        "disk_io": disk_io,
        "network": network,
        "failed_units": int(failed) if failed.isdigit() else None,
        "failed_user_units": int(failed_user) if failed_user.isdigit() else None,
        "unit_states": units,
        "root_filesystem": {"used_bytes": int(df_root[2]) * 1024,
                            "available_bytes": int(df_root[3]) * 1024} if len(df_root) > 3 else None,
    }


def sample_docker():
    listing, code = run(["docker", "ps", "-a", "--format",
                         "{{.Names}}\t{{.State}}\t{{.Status}}"], timeout=25)
    containers = {}
    if code == 0:
        for line in listing.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                containers[parts[0]] = {"state": parts[1], "status": parts[2]}

    stats, code = run(["docker", "stats", "--no-stream", "--format",
                       "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"], timeout=45)
    if code == 0:
        for line in stats.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0] in containers:
                containers[parts[0]]["cpu_percent"] = parts[1].rstrip("%")
                containers[parts[0]]["mem_usage"] = parts[2]

    # RestartCount is the number that matters for a soak: a container that keeps
    # dying and coming back looks healthy in `docker ps` at any single instant.
    names = list(containers)
    if names:
        restarts, code = run(["docker", "inspect", "--format",
                              "{{.Name}}\t{{.RestartCount}}\t{{.State.Health.Status}}"] + names,
                             timeout=30)
        if code == 0:
            for line in restarts.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    name = parts[0].lstrip("/")
                    if name in containers:
                        containers[name]["restart_count"] = int(parts[1]) if parts[1].isdigit() else None
                        containers[name]["health"] = parts[2] if len(parts) > 2 else None
    return containers


def sample_http():
    results = {}
    for name, url in HTTP_TARGETS.items():
        output, code = run(["curl", "-fsS", "-o", "/dev/null", "--max-time", "10",
                            "-w", "%{http_code} %{time_total}", url], timeout=15)
        if code == 0 and " " in output:
            status, _, elapsed = output.partition(" ")
            results[name] = {"http_status": int(status), "latency_seconds": float(elapsed),
                             "ok": status.startswith("2") or status.startswith("3")}
        else:
            results[name] = {"http_status": None, "latency_seconds": None, "ok": False,
                             "error": output[:200]}
    return results


def sample_frigate():
    output, code = run(["curl", "-fsS", "--max-time", "10", "http://127.0.0.1:5400/api/stats"],
                       timeout=15)
    if code != 0:
        return {"available": False, "error": output[:200]}
    try:
        stats = json.loads(output)
    except ValueError:
        return {"available": False, "error": "unparseable stats payload"}
    cameras = {}
    for name, data in (stats.get("cameras") or {}).items():
        cameras[name] = {
            "camera_fps": data.get("camera_fps"), "process_fps": data.get("process_fps"),
            "skipped_fps": data.get("skipped_fps"), "detection_fps": data.get("detection_fps"),
            "expected_fps": data.get("expected_fps"),
            "connection_quality": data.get("connection_quality"),
            "reconnects_last_hour": data.get("reconnects_last_hour"),
            "stalls_last_hour": data.get("stalls_last_hour"),
        }
    service = stats.get("service") or {}
    return {"available": True, "cameras": cameras,
            "uptime_seconds": service.get("uptime"), "version": service.get("version"),
            "storage": service.get("storage")}


def sample_pcold():
    probe = pcold_sh(
        "cat /proc/loadavg; echo '---'; free -b | sed -n 2p; echo '---'; df -Pk / | tail -1; "
        "echo '---'; for u in metehantech-dashboard metehantech-metrics metehantech-watchdog "
        "docker ssh fail2ban; do printf '%s=%s ' \"$u\" \"$(systemctl is-active $u)\"; done; echo; "
        "echo '---'; (/usr/sbin/smartctl -A /dev/sda 2>&1 | "
        "grep -E 'Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|"
        "UDMA_CRC_Error_Count|Temperature_Celsius' || echo 'smart_unavailable')")
    if not probe["reachable"]:
        return {"reachable": False, "error": probe["output"][:300]}
    blocks = [b.strip() for b in probe["output"].split("---")]
    result = {"reachable": True, "host": probe["host"]}
    try:
        load = blocks[0].split()
        result["load"] = {"1m": float(load[0]), "5m": float(load[1]), "15m": float(load[2])}
    except (IndexError, ValueError):
        result["load"] = None
    try:
        memory = blocks[1].split()
        result["memory"] = {"total_bytes": int(memory[1]), "used_bytes": int(memory[2]),
                            "available_bytes": int(memory[6])}
    except (IndexError, ValueError):
        result["memory"] = None
    try:
        df = blocks[2].split()
        result["root_filesystem"] = {"used_bytes": int(df[2]) * 1024,
                                     "available_bytes": int(df[3]) * 1024}
    except (IndexError, ValueError):
        result["root_filesystem"] = None
    result["services"] = dict(
        pair.split("=", 1) for pair in blocks[3].split() if "=" in pair) if len(blocks) > 3 else {}
    smart = {}
    if len(blocks) > 4 and "smart_unavailable" not in blocks[4]:
        for line in blocks[4].splitlines():
            fields = line.split()
            if len(fields) >= 10:
                smart[fields[1]] = fields[9]
    result["smart"] = smart or {"available": False,
                                "reason": "smartctl not runnable from the restricted backup account"}
    return result


def sample_backups():
    try:
        import backups
        import backup_validator as bv
        records = backups.list_backups(500)
        report = bv.assurance_report(
            records,
            attestations=bv.load_attestations(BASE / "restore-results.json"))
        flows = {node: {k: flow[k] for k in
                        ("assurance_level", "freshness", "verified_age_hours")}
                 for node, flow in report["flows"].items()}
        active = [r for r in records if r["status"] in {"queued", "running"}]
        return {"flows": flows, "stuck_jobs": len(report["stuck_jobs"]),
                "active_jobs": [{"backup_id": r["backup_id"], "status": r["status"],
                                 "phase": r["phase"]} for r in active],
                "healthy": report["healthy"]}
    except Exception as error:                     # noqa: BLE001 - never kill the soak
        return {"error": f"{type(error).__name__}: {str(error)[:200]}"}


def sample_timers():
    output = sh("systemctl --user list-timers 'metehantech-backup-auto-*' "
                "--all --no-pager --no-legend")
    timers = []
    for line in output.splitlines():
        if "metehantech-backup-auto" in line:
            timers.append(re.sub(r"\s+", " ", line.strip())[:200])
    return timers


def sample_mounts():
    mounts = {}
    # Root is always sampled; extra targets come from MONITORED_MOUNTS.
    targets = ["/"] + [str(p) for p in deployment.path_list("MONITORED_MOUNTS")]
    for target in targets:
        output, code = run(["findmnt", "-n", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "-T", target],
                           timeout=15)
        mounts[target] = {"available": code == 0, "detail": output[:200]}
    camera_dir = deployment.optional("CAMERA_MEDIA_DIR")
    if not camera_dir:
        return {"status": "skipped", "reason": "CAMERA_MEDIA_DIR not configured"}
    listing, code = run(["ls", camera_dir], timeout=15)
    mounts["camera_volume_listable"] = code == 0
    return mounts


def sample_cloudflare():
    """Existing journal only. No tunnel configuration is read, touched, or changed."""
    output = sh("journalctl -u cloudflared --since '-10 min' --no-pager -p warning -o cat "
                "2>/dev/null | tail -20")
    active = sh("systemctl is-active cloudflared")
    return {"unit_state": active,
            "recent_warning_lines": len([l for l in output.splitlines() if l.strip()]),
            "sample": output[-500:] if output else None}


def sample_openclaw():
    state = sh("systemctl --user is-active openclaw-gateway 2>/dev/null || echo not-a-user-unit")
    running = sh("pgrep -fa 'openclaw' | head -3")
    return {"user_unit_state": state, "process_present": bool(running.strip()),
            "detail": running[:300] if running else None}


def rotate_if_needed():
    if SAMPLES.exists() and SAMPLES.stat().st_size > MAX_BYTES:
        for index in range(KEEP_ROTATIONS - 1, 0, -1):
            older = SAMPLES.with_suffix(f".jsonl.{index}")
            newer = SAMPLES.with_suffix(f".jsonl.{index + 1}")
            if older.exists():
                older.rename(newer)
        SAMPLES.rename(SAMPLES.with_suffix(".jsonl.1"))


def collect(sequence, started_at):
    began = time.monotonic()
    sample = {"sequence": sequence, "at": datetime.now(timezone.utc).isoformat()}
    for name, probe in (("pi", sample_pi), ("docker", sample_docker), ("http", sample_http),
                        ("frigate", sample_frigate), ("pcold", sample_pcold),
                        ("backups", sample_backups), ("timers", sample_timers),
                        ("mounts", sample_mounts), ("cloudflare", sample_cloudflare),
                        ("openclaw", sample_openclaw)):
        try:
            sample[name] = probe()
        except Exception as error:                 # noqa: BLE001 - one bad probe must not end the soak
            sample[name] = {"__probe_error__": f"{type(error).__name__}: {str(error)[:200]}"}
    sample["collection_seconds"] = round(time.monotonic() - began, 3)
    sample["elapsed_seconds"] = round(time.monotonic() - started_at, 1)
    return sample


def main():
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    try:
        os.nice(10)
    except OSError:
        pass

    BASE.mkdir(parents=True, exist_ok=True)
    started_wall = datetime.now(timezone.utc)
    started_at = time.monotonic()
    deadline = started_at + DURATION

    def write_status(state, sequence):
        STATUS.write_text(json.dumps({
            "state": state, "pid": os.getpid(), "started_at": started_wall.isoformat(),
            "duration_seconds": DURATION, "interval_seconds": INTERVAL,
            "expected_samples": DURATION // INTERVAL, "samples_written": sequence,
            "samples_path": str(SAMPLES),
            "expected_finish_at": datetime.fromtimestamp(
                started_wall.timestamp() + DURATION, timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2) + "\n")

    sequence = 0
    write_status("running", sequence)
    while not _stop and time.monotonic() < deadline:
        cycle_start = time.monotonic()
        sample = collect(sequence, started_at)
        rotate_if_needed()
        with SAMPLES.open("a") as handle:
            handle.write(json.dumps(sample, ensure_ascii=False) + "\n")
        sequence += 1
        write_status("running", sequence)
        # Sleep in short slices so a SIGTERM is honoured promptly.
        target = cycle_start + INTERVAL
        while not _stop and time.monotonic() < target and time.monotonic() < deadline:
            time.sleep(min(5, max(0.1, target - time.monotonic())))
    write_status("stopped" if _stop else "completed", sequence)
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
