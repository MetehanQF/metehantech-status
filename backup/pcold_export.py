#!/usr/bin/env python3
"""Root-owned fixed-source exporter for MetehanTechPcOld."""

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys


BACKUP_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z-pcold-full-[a-f0-9]{6}$")
STATE_ROOT = Path(os.environ.get("PCOLD_BACKUP_STATE_ROOT", "/var/lib/metehantech-backup"))
REQUEST_FILE = STATE_ROOT / "requests" / "next"
EXPORT_ROOT = STATE_ROOT / "export"
BACKUP_USER = os.environ.get("PCOLD_BACKUP_USER", "metehanbackup")
BACKUP_GROUP = os.environ.get("PCOLD_BACKUP_GROUP", "metehanbackup")
EXPORT_OWNER = os.environ.get("PCOLD_BACKUP_EXPORT_OWNER", "root")
WATCHDOG_DB = Path(os.environ.get("PCOLD_WATCHDOG_DB", "/var/lib/private/metehantech-watchdog/events.db"))
UPTIME_ROOT = Path(os.environ.get("PCOLD_UPTIME_ROOT", "/var/lib/docker/volumes/uptime-kuma-data/_data"))
UPTIME_DB = UPTIME_ROOT / "kuma.db"
# Kullaniciya ozel dashboard dizini bu deployment'a baglidir ve tahmin EDILMEZ.
# PCOLD_DASHBOARD_ROOT tanimli degilse arsiv kapsamindan cikar; kaynak kodda
# gercek makine yolu fallback'i bilerek birakilmamistir.
_DASHBOARD_ROOT = os.environ.get("PCOLD_DASHBOARD_ROOT", "").strip()

ARCHIVE_SOURCES = (
    (Path(_DASHBOARD_ROOT),) if _DASHBOARD_ROOT else ()
) + (
    Path("/usr/local/bin/metehantech-metrics.py"),
    Path("/opt/metehantech-watchdog"),
    Path("/etc/systemd/system/metehantech-dashboard.service"),
    Path("/etc/systemd/system/metehantech-metrics.service"),
    Path("/etc/systemd/system/metehantech-watchdog.service"),
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_backup_id(value):
    if not BACKUP_ID_PATTERN.fullmatch(value or ""):
        raise ValueError("Invalid backup id")
    return value


def run(argv, timeout=180):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip()[:500])
    return result


def snapshot_sqlite(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=10)) as src:
        with closing(sqlite3.connect(destination, timeout=10)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError(f"SQLite integrity failed: {source.name}")
    os.chmod(destination, 0o640)


def archive(destination, sources, excludes=()):
    available = [Path(path).resolve() for path in sources if Path(path).exists()]
    if not available:
        raise RuntimeError(f"No sources for {destination.name}")
    argv = ["tar", "--zstd", "-cf", str(destination)]
    argv.extend(f"--exclude={pattern}" for pattern in excludes)
    argv.extend(["-C", "/"])
    argv.extend(str(path).lstrip("/") for path in available)
    run(argv)
    os.chmod(destination, 0o640)


def manifest(root):
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify(root):
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or not re.fullmatch(r"[a-f0-9]{64}", digest) or ".." in Path(relative).parts:
            raise RuntimeError("Invalid checksum manifest")
        target = (root / relative).resolve()
        if root.resolve() not in target.parents or not target.is_file():
            raise RuntimeError("Unsafe manifest path")
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"Checksum mismatch: {relative}")
    for archive_path in root.glob("*.tar.zst"):
        run(["tar", "--zstd", "-tf", str(archive_path)], timeout=30)
    for db in root.rglob("*.db"):
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError(f"SQLite integrity failed: {db.name}")


def set_tree_access(root):
    for path in [root, *root.rglob("*")]:
        shutil.chown(path, user=EXPORT_OWNER, group=BACKUP_GROUP)
        os.chmod(path, 0o750 if path.is_dir() else 0o640)


def write_status(backup_id, status, error=None):
    status_dir = STATE_ROOT / "status"
    status_dir.mkdir(parents=True, exist_ok=True)
    path = status_dir / f"{backup_id}.json"
    path.write_text(json.dumps({"backup_id": backup_id, "status": status, "error": error}) + "\n", encoding="utf-8")
    shutil.chown(path, user=EXPORT_OWNER, group=BACKUP_GROUP)
    os.chmod(path, 0o640)


def export(backup_id):
    backup_id = validate_backup_id(backup_id)
    staging = EXPORT_ROOT / ".staging" / backup_id
    final = EXPORT_ROOT / backup_id
    if staging.exists() or final.exists():
        raise RuntimeError("Export already exists")
    staging.mkdir(parents=True, mode=0o700)
    try:
        archive(staging / "pcold-applications.tar.zst", ARCHIVE_SOURCES)
        snapshot_sqlite(WATCHDOG_DB, staging / "databases" / "watchdog-events.db")
        snapshot_sqlite(UPTIME_DB, staging / "databases" / "uptime-kuma.db")
        archive(
            staging / "uptime-kuma-files.tar.zst",
            (UPTIME_ROOT,),
            ("*/kuma.db", "*/kuma.db-wal", "*/kuma.db-shm"),
        )
        metadata = {
            "format_version": 1,
            "source_node": "pcold",
            "created_at": utc_now(),
            "sources": [str(path) for path in ARCHIVE_SOURCES],
            "uptime_kuma": str(UPTIME_ROOT),
            "watchdog_database": str(WATCHDOG_DB),
            "portainer": "excluded_pending_supported_export",
            "docker_socket": "excluded",
            "docker_images": "excluded",
            "sensitive_configuration": "NOT ENABLED",
            "retention": "disabled",
        }
        (staging / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        manifest(staging)
        verify(staging)
        EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final)
        set_tree_access(final)
        write_status(backup_id, "ready")
    except Exception as error:
        if staging.exists():
            shutil.rmtree(staging)
        write_status(backup_id, "failed", str(error)[:500])
        raise


def main():
    if os.geteuid() != 0:
        raise SystemExit("PcOld exporter must run as root")
    backup_id = validate_backup_id(REQUEST_FILE.read_text(encoding="ascii").strip())
    REQUEST_FILE.unlink()
    export(backup_id)


if __name__ == "__main__":
    main()
