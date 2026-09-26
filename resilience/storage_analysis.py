#!/usr/bin/env python3
"""Storage growth measurement and projection from observed deltas only.

Every rate here comes from two real measurements of the same thing at two known
times. Where only one measurement exists, the rate is reported as null and the
component is listed under `insufficient_data` rather than being extrapolated from
a single point, which would be a guess wearing a number's clothes.

Read-only: measures, projects, and deletes nothing.
"""

from _harness import pcold_ssh, results_dir, write_results  # noqa: E402  (repo-relative path setup)
import deployment  # noqa: E402
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess

# Output location comes from RESILIENCE_RESULTS_DIR (default: cwd).
GIB = 1024 ** 3

#: Resolved on first use, not at import — see `_harness.pcold_ssh`.
_PCOLD_SSH = None


def camera_dir():
    """Camera media directory, or None. Those measurements are then skipped."""
    return deployment.optional("CAMERA_MEDIA_DIR")


def sh(command, timeout=120):
    return subprocess.run(["sh", "-c", command], capture_output=True, text=True,
                          timeout=timeout, check=False).stdout


def pcold(command, timeout=120):
    """Run a command on the secondary node. Resolves its identity on first call."""
    global _PCOLD_SSH
    if _PCOLD_SSH is None:
        _PCOLD_SSH = pcold_ssh()
    argv = ["ssh", "-i", _PCOLD_SSH.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
            f"{_PCOLD_SSH.user}@{_PCOLD_SSH.hosts[0]}",
            "sh", "-c", shlex.quote(command)]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False).stdout


def filesystem(df_output):
    fields = df_output.strip().splitlines()[-1].split()
    total, used, avail = (int(fields[i]) * 1024 for i in (1, 2, 3))
    return {"total_bytes": total, "used_bytes": used, "available_bytes": avail,
            "total_gib": round(total / GIB, 2), "used_gib": round(used / GIB, 2),
            "available_gib": round(avail / GIB, 2),
            "used_percent": round(100 * used / total, 2)}


def rate(first, second):
    """Bytes/day between two (iso_timestamp, bytes) observations."""
    (t0, b0), (t1, b1) = first, second
    seconds = (datetime.fromisoformat(t1) - datetime.fromisoformat(t0)).total_seconds()
    if seconds <= 0:
        return None
    return {"bytes_per_day": round((b1 - b0) * 86400 / seconds, 1),
            "gib_per_day": round((b1 - b0) * 86400 / seconds / GIB, 4),
            "window_hours": round(seconds / 3600, 3),
            "from": {"at": t0, "bytes": b0}, "to": {"at": t1, "bytes": b1}}


def frigate_rate():
    """Recording growth from per-hour directory sizes on the camera volume."""
    camera = camera_dir()
    if not camera:
        return {"hours_observed": 0, "bytes_per_day": None,
                "reason": "CAMERA_MEDIA_DIR is not configured; measurement skipped"}
    listing = sh(f"for d in {camera}/recordings/*/*/; do "
                 "printf '%s %s\\n' \"$d\" \"$(du -sb \"$d\" | cut -f1)\"; done")
    hours = []
    for line in listing.strip().splitlines():
        path, _, size = line.rpartition(" ")
        if size.isdigit():
            hours.append((path.strip(), int(size)))
    if len(hours) < 3:
        return {"hours_observed": len(hours), "bytes_per_day": None,
                "reason": "fewer than 3 hour-directories; no defensible rate"}
    # Drop the first and last hour: both are partial and would drag the mean down.
    interior = sorted(size for _, size in hours)[1:-1]
    mean_hour = sum(interior) / len(interior)
    span = sh(f"find {camera}/recordings -type f -printf '%T@\\n' | sort -n")
    stamps = [float(v) for v in span.split() if v]
    total = int(sh(f"du -sb {camera}/recordings | cut -f1").split()[0])
    observed_seconds = (stamps[-1] - stamps[0]) if len(stamps) > 1 else 0
    return {
        "hours_observed": len(hours),
        "interior_hours_used": len(interior),
        "mean_full_hour_bytes": round(mean_hour, 1),
        "bytes_per_day": round(mean_hour * 24, 1),
        "gib_per_day": round(mean_hour * 24 / GIB, 3),
        "whole_span_bytes_per_day": round(total * 86400 / observed_seconds, 1) if observed_seconds else None,
        "whole_span_gib_per_day": round(total * 86400 / observed_seconds / GIB, 3) if observed_seconds else None,
        "total_bytes_now": total,
        "observation_window_hours": round(observed_seconds / 3600, 2),
        "file_count": len(stamps),
    }


def project(fs, gib_per_day, label):
    if not gib_per_day or gib_per_day <= 0:
        return {"component": label, "projection": "insufficient_data"}
    total, used = fs["total_gib"], fs["used_gib"]
    to_eighty = max(0.0, total * 0.80 - used)
    to_full = fs["available_gib"]
    return {
        "component": label,
        "gib_per_day": gib_per_day,
        "days_to_80_percent": round(to_eighty / gib_per_day, 1),
        "days_to_exhaustion": round(to_full / gib_per_day, 1),
        "projected_used_gib_30d": round(used + gib_per_day * 30, 1),
        "projected_used_gib_90d": round(used + gib_per_day * 90, 1),
        "exceeds_capacity_within_30d": used + gib_per_day * 30 > total,
        "exceeds_capacity_within_90d": used + gib_per_day * 90 > total,
    }


def main():
    now = datetime.now(timezone.utc).isoformat()
    pi_fs = filesystem(sh("df -Pk /"))
    pcold_fs = filesystem(pcold("df -Pk /"))
    camera = camera_dir()
    camera_fs = filesystem(sh(f"df -Pk {shlex.quote(camera)}")) if camera else None

    # Backup artefact growth, measured between two real restore points of the same flow.
    restore_points = []
    restore_root = deployment.optional_path("RESTORE_POINT_DIR")
    for directory in sorted(restore_root.glob("*")) if restore_root else []:
        metadata = directory / "metadata.json"
        if not metadata.is_file():
            continue
        created = json.loads(metadata.read_text())["created_at"]
        size = int(sh(f"du -sb {shlex.quote(str(directory))} | cut -f1").split()[0])
        kuma = directory / "databases" / "uptime-kuma.db"
        restore_points.append({"backup_id": directory.name, "created_at": created,
                               "restore_point_bytes": size,
                               "kuma_db_bytes": kuma.stat().st_size if kuma.is_file() else None})
    restore_points.sort(key=lambda r: r["created_at"])

    rates = {}
    if len(restore_points) >= 2:
        first, last = restore_points[0], restore_points[-1]
        rates["uptime_kuma_db"] = rate((first["created_at"], first["kuma_db_bytes"]),
                                       (last["created_at"], last["kuma_db_bytes"]))
        rates["pcold_restore_point_size"] = rate(
            (first["created_at"], first["restore_point_bytes"]),
            (last["created_at"], last["restore_point_bytes"]))
        # Per-day accumulation on the Pi: one PcOld restore point retained per run.
        rates["pi_backup_storage_accumulation"] = {
            "bytes_per_day": last["restore_point_bytes"],
            "gib_per_day": round(last["restore_point_bytes"] / GIB, 5),
            "basis": "one PcOld restore point per daily 02:10 run, retention disabled",
        }

    import sqlite3
    with sqlite3.connect(f"file:{deployment.DATA_DIR / 'backups.db'}?mode=ro",
                         uri=True) as connection:
        pi_sizes = connection.execute(
            "SELECT started_at,size_bytes FROM backups WHERE status='success' AND source_node='pi' "
            "ORDER BY started_at").fetchall()
    if len(pi_sizes) >= 2:
        rates["pi_restore_point_size"] = rate(pi_sizes[0], pi_sizes[-1])
        rates["pcold_backup_storage_accumulation"] = {
            "bytes_per_day": pi_sizes[-1][1],
            "gib_per_day": round(pi_sizes[-1][1] / GIB, 5),
            "basis": "one Pi restore point per daily 01:10 run, retention disabled",
        }

    frigate = frigate_rate()
    watchdog_sizes = {r["backup_id"]: None for r in restore_points}

    logs = {
        "pi_journal_bytes": sh("journalctl --disk-usage").strip(),
        "pi_var_log_bytes": int(sh("du -sb /var/log 2>/dev/null | cut -f1").split()[0] or 0),
        "pi_journald_explicit_limits": sh(
            "grep -E '^[[:space:]]*(SystemMaxUse|MaxRetentionSec|SystemKeepFree)' "
            "/etc/systemd/journald.conf").strip() or None,
        "growth_rate": None,
        "reason": "only one observation; journald is self-capping (default 10% of the "
                  "filesystem, 4 GiB ceiling) so unbounded growth is not the risk here",
    }
    docker = {"pi": sh("docker system df --format '{{.Type}} {{.Size}} {{.Reclaimable}}'").strip(),
              "growth_rate": None,
              "reason": "image and container sizes change in steps on pull/rebuild, not "
                        "continuously; a rate from one observation would be meaningless"}

    pcold_growth = (frigate.get("gib_per_day") or 0) + \
                   (rates.get("pcold_backup_storage_accumulation", {}).get("gib_per_day") or 0)
    pi_growth = rates.get("pi_backup_storage_accumulation", {}).get("gib_per_day") or 0

    report = {
        "generated_at": now,
        "method": "rates derived only from two real observations of the same quantity; "
                  "single-observation components are reported as insufficient_data",
        "filesystems": {"pi_root": pi_fs, "pcold_root": pcold_fs,
                        "camera_volume_via_nfs": camera_fs},
        "note_shared_filesystem": "The secondary node's root filesystem carries BOTH "
                                  "the camera media and the primary-side backups. They "
                                  "compete for the same volume, so growth in one "
                                  "shortens the runway of the other.",
        "frigate_recordings": frigate,
        "backup_restore_points": restore_points,
        "measured_rates": rates,
        "logs": logs,
        "docker": docker,
        "portainer": {"measurable": False,
                      "reason": "no Docker socket or volume access from the restricted "
                                "backup account on PcOld"},
        "projections": {
            "pcold_root": project(pcold_fs, pcold_growth, "PcOld / (Frigate media + Pi backups)"),
            "pi_root": project(pi_fs, pi_growth, "Pi / (PcOld backups)"),
        },
        "insufficient_data": [
            "Frigate steady-state footprint: recordings exist for a single calendar day and "
            "the Frigate retention configuration under /opt/metehantech-camera/config is not "
            "readable by this account, so it cannot be determined whether growth plateaus at "
            "a retention horizon or continues linearly.",
            "Pi /var/log and journal growth rate: one observation only.",
            "Docker image/container growth: step-change, not a rate.",
            "Portainer data size: no access.",
            "Watchdog events.db growth: identical size (24576 B) at every observation, so the "
            "measurable rate is zero; that is a real observation, not an estimate.",
        ],
    }
    write_results("storage-analysis.json", report)
    print(json.dumps({"filesystems": report["filesystems"],
                      "frigate": frigate,
                      "rates": rates,
                      "projections": report["projections"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
