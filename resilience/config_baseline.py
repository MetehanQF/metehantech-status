#!/usr/bin/env python3
"""Generate config-baseline.json: SHA256 fingerprints of MetehanTech configuration.

Records hashes, sizes and modes only. File *contents* are never emitted, so a
secret-bearing file can be fingerprinted for drift detection without its value
ever entering the baseline. Files that cannot be read are recorded as
unreadable with the reason, never silently dropped — a config that vanishes
from the baseline must be distinguishable from a config nobody could see.

Usage:
    python3 config_baseline.py                 write config-baseline.json
    python3 config_baseline.py --output PATH   write it somewhere explicit
    python3 config_baseline.py --compare PATH  diff live state against a baseline

The default output location comes from OPENCLAW_WORKSPACE. When that is not
configured the tool says so and exits 3 rather than guessing a path, and the
secondary-node half of the baseline is recorded as "not configured" rather than
failing the run.
"""

from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

from _harness import pcold_ssh  # noqa: E402  (also sets up the repo-relative path)
import deployment  # noqa: E402

#: Derived from the module's own location, so it needs no configuration.
STATUS = deployment.PROJECT_ROOT


def default_output():
    """Where a baseline is written when `--output` is not given.

    `None` when `OPENCLAW_WORKSPACE` is unconfigured. The tool then reports that
    it is not configured and exits, rather than inventing a location.
    """
    workspace = deployment.optional_path("OPENCLAW_WORKSPACE")
    return workspace / "config-baseline.json" if workspace else None


def groups():
    """The local fingerprint set.

    A function, not a module constant: it reads `BACKUP_SSH_KEY`, and resolving a
    mandatory deployment value at import time would make this module unloadable
    on an unconfigured clone.
    """
    return {
        "system_units": [
            "/etc/systemd/system/metehantech-status.service",
            "/etc/systemd/system/metehantech-home.service",
            "/etc/systemd/system/clan-web.service",
            "/etc/systemd/system/cloudflared.service",
            "/etc/systemd/system/metehantech-frigate.service",
            "/etc/systemd/system/metehantech-camera-pcold-route.service",
            "/etc/systemd/system/metehantech-backup-pi.service",
            "/etc/systemd/system/metehantech-backup-pcold.service",
            "/etc/systemd/system/metehantech-backup-cloud.service",
        ],
        "user_units": [
            str(Path.home() / ".config/systemd/user" / f"metehantech-backup-auto-{n}.{s}")
            for n in ("pi", "pcold", "cloud") for s in ("service", "timer")
        ],
        "docker_compose": [
            "/opt/metehantech-cloud/compose.yaml",
            "/opt/metehantech-cloud/.env",
            "/opt/metehantech-cloud/redis.conf",
            "/opt/metehantech-cloud/apache-vhost.conf",
            "/opt/metehantech-cloud/apache-proxy.conf",
        ],
        "frigate_config": [
            "/opt/metehantech-camera/config/config.yml",
            "/opt/metehantech-camera/config/config.yaml",
        ],
        "backup_scripts": [
            str(STATUS / n) for n in (
                "backups.py", "backup_job.py", "backup_hardening.py",
                "backup_retention.py", "backup_schedule.py", "backup_supplement.py",
                "backup_validator.py",
            )
        ],
        "status_scripts": [
            str(STATUS / n) for n in (
                "app.py", "wsgi.py", "admin.py", "alerts.py", "activity.py",
                "camera.py", "events.py", "history.py", "incidents.py",
                "requirements.txt", "install-systemd.sh", "metehantech-status.service",
            )
        ],
        # Sibling applications to fingerprint, from BACKUP_EXTRA_SOURCES. Empty when
        # unconfigured — nothing is guessed.
        "app_config": [
            str(root / name)
            for root in deployment.path_list("BACKUP_EXTRA_SOURCES")
            for name in ("app.py", "requirements.txt")
        ],
        # This harness fingerprints itself: drift here means the checks changed.
        "automation_scripts": [
            str(Path(__file__).resolve().parent / n)
            for n in ("restore_lab.py", "config_baseline.py",
                      "soak_collector.py", "failure_sim.py", "storage_analysis.py")
        ],
        # Fingerprinted, never read. The backup key joins the set only when it is
        # configured; an unconfigured clone simply has one fewer path to watch.
        "secret_bearing_fingerprint_only": [
            "/etc/metehantech-status/admin.env",
            "/etc/clan-web.env",
            "/etc/cloudflared/token",
        ] + ([key] if (key := deployment.optional("BACKUP_SSH_KEY")) else []),
    }


PCOLD_GROUPS = {
    "pcold_system_units": [
        "/etc/systemd/system/metehantech-dashboard.service",
        "/etc/systemd/system/metehantech-metrics.service",
        "/etc/systemd/system/metehantech-watchdog.service",
        "/etc/systemd/system/metehantech-backup-export.service",
    ],
    "pcold_scripts": [
        "/usr/local/libexec/metehantech-backup-receiver",
        "/usr/local/libexec/metehantech-backup-pcold-export",
        "/usr/local/bin/metehantech-metrics.py",
    ],
}


def fingerprint_local(path):
    target = Path(path)
    try:
        st = target.lstat()
    except OSError as error:
        return {"present": False, "reason": f"{type(error).__name__}: {error.strerror}"}
    if not target.is_file():
        return {"present": False, "reason": "not a regular file"}
    entry = {"present": True, "bytes": st.st_size, "mode": oct(st.st_mode)[-4:],
             "uid": st.st_uid, "gid": st.st_gid}
    try:
        entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    except OSError as error:
        entry["sha256"] = None
        entry["reason"] = f"unreadable: {type(error).__name__}"
    return entry


def ssh_base(ssh, host):
    return ["ssh", "-i", ssh.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=8", f"{ssh.user}@{host}"]


def choose_host(ssh):
    for host in ssh.hosts:
        result = subprocess.run(ssh_base(ssh, host) + ["true"], capture_output=True, timeout=15, check=False)
        if result.returncode == 0:
            return host
    return None


def fingerprint_remote(ssh, host, paths):
    """One round trip: stat + sha256sum for every path, tolerating unreadable files."""
    script = "for f in %s; do if [ -f \"$f\" ]; then printf '%%s|' \"$f\"; " \
             "stat -c '%%s|%%a|%%u|%%g' \"$f\" 2>/dev/null | tr -d '\\n'; printf '|'; " \
             "sha256sum \"$f\" 2>/dev/null | cut -d' ' -f1 | tr -d '\\n'; echo; " \
             "else echo \"$f|||||ABSENT\"; fi; done" % " ".join(shlex.quote(p) for p in paths)
    result = subprocess.run(ssh_base(ssh, host) + ["sh", "-c", shlex.quote(script)],
                            capture_output=True, text=True, timeout=120, check=False)
    entries = {}
    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 6:
            continue
        path, size, mode, uid, gid, digest = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        if digest == "ABSENT" or not size:
            entries[path] = {"present": False, "reason": "absent or unreadable from backup account"}
        else:
            entries[path] = {"present": True, "bytes": int(size), "mode": mode.rjust(4, "0"),
                             "uid": int(uid), "gid": int(gid), "sha256": digest or None}
    for path in paths:
        entries.setdefault(path, {"present": False, "reason": "no response for path"})
    return entries


def build():
    baseline = {
        "schema": "metehantech.config-baseline.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contains_secret_values": False,
        "note": "SHA256/size/mode fingerprints only. No file contents are recorded.",
        "nodes": {"pi": {}, "pcold": {}},
    }
    for group, paths in groups().items():
        baseline["nodes"]["pi"][group] = {p: fingerprint_local(p) for p in paths}

    # The secondary node needs deployment configuration. Without it the local
    # half of the baseline is still worth having, so record why the remote half
    # is missing instead of failing the whole run.
    try:
        ssh = pcold_ssh()
    except deployment.DeploymentConfigError as error:
        ssh = None
        unreachable = f"not configured: {error}"
    else:
        host = choose_host(ssh)
        unreachable = "PcOld unreachable at baseline time"

    baseline["nodes"]["pcold"]["_transport"] = {
        "host": host if ssh else None,
        "account": ssh.user if ssh else None,
        "reachable": bool(ssh) and host is not None,
        "configured": ssh is not None,
        "note": "Restricted backup account: no Docker socket, no /var/lib/docker access.",
    }
    if ssh and host:
        for group, paths in PCOLD_GROUPS.items():
            baseline["nodes"]["pcold"][group] = fingerprint_remote(ssh, host, paths)
    else:
        for group, paths in PCOLD_GROUPS.items():
            baseline["nodes"]["pcold"][group] = {
                p: {"present": False, "reason": unreachable} for p in paths}

    counts = {"present": 0, "absent": 0, "unreadable": 0}
    for node in baseline["nodes"].values():
        for group, entries in node.items():
            if group.startswith("_"):
                continue
            for entry in entries.values():
                if entry.get("present") and entry.get("sha256"):
                    counts["present"] += 1
                elif entry.get("present"):
                    counts["unreadable"] += 1
                else:
                    counts["absent"] += 1
    baseline["summary"] = counts
    return baseline


def compare(baseline_path):
    old = json.loads(Path(baseline_path).read_text())
    new = build()
    changes = {"changed": [], "appeared": [], "disappeared": []}
    for node in ("pi", "pcold"):
        for group, entries in old["nodes"].get(node, {}).items():
            if group.startswith("_"):
                continue
            fresh = new["nodes"].get(node, {}).get(group, {})
            for path, before in entries.items():
                after = fresh.get(path, {"present": False, "reason": "not in current baseline set"})
                key = f"{node}:{path}"
                if before.get("present") and not after.get("present"):
                    changes["disappeared"].append(key)
                elif not before.get("present") and after.get("present"):
                    changes["appeared"].append(key)
                elif before.get("sha256") != after.get("sha256"):
                    changes["changed"].append({
                        "path": key,
                        "sha256_before": before.get("sha256"),
                        "sha256_after": after.get("sha256"),
                        "mode_before": before.get("mode"), "mode_after": after.get("mode"),
                    })
    return changes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", metavar="PATH", default=None)
    parser.add_argument("--output", default=None,
                        help="where to write the baseline. Defaults to "
                             "$OPENCLAW_WORKSPACE/config-baseline.json; required "
                             "when that is not configured.")
    args = parser.parse_args(argv)

    if args.compare:
        print(json.dumps(compare(args.compare), indent=2))
        return 0

    output = Path(args.output) if args.output else default_output()
    if output is None:
        print("NOT CONFIGURED — OPENCLAW_WORKSPACE is unset, so there is no default "
              "location to write the baseline to.")
        print("  Set OPENCLAW_WORKSPACE in /etc/metehantech-status/deploy.env, "
              "or pass --output PATH.")
        return 3

    baseline = build()
    output.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    print(json.dumps(baseline["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
