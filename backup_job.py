"""Systemd oneshot entry point for fixed-whitelist Backup Center jobs."""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from backup_hardening import storage_guard, strict_verify, LOCAL_STORAGE, REMOTE_STORAGE

import network
import deployment

from backups import (
    claim_queued,
    directory_stats,
    fail_backup,
    sqlite_snapshot,
    update_backup,
    utc_now,
    validate_backup_id,
    verify_restore_point,
    write_manifest,
)


PROJECT_ROOT = Path(__file__).resolve().parent
WORK_ROOT = Path(os.environ.get("BACKUP_WORK_ROOT", PROJECT_ROOT / "data" / "backup-work"))
LOCK_PATH = Path(os.environ.get("BACKUP_LOCK_PATH", PROJECT_ROOT / "data" / "backup.lock"))
PI_DESTINATION = Path(os.environ.get("BACKUP_PI_DESTINATION", "/srv/metehantech-backups/from-pcold"))
PCOLD_DESTINATION = "/srv/metehantech-backups/from-pi"
PCOLD_EXPORT_ROOT = "/var/lib/metehantech-backup/export"
PCOLD_USER = deployment.get("BACKUP_REMOTE_USER")
PCOLD_HOSTS = (network.get("PCOLD_LAN_IP"), network.get("PCOLD_TAILSCALE_IP"))
SSH_KEY = deployment.path("BACKUP_SSH_KEY")
REMOTE_HELPER = "/usr/local/libexec/metehantech-backup-receiver"
CLOUD_APP = "metehantech-nextcloud-app"
CLOUD_DB = "metehantech-nextcloud-db"
CLOUD_DEPLOYMENT_SOURCES = (
    Path("/opt/metehantech-cloud/compose.yaml"),
    Path("/opt/metehantech-cloud/.env"),
    Path("/opt/metehantech-cloud/redis.conf"),
    # Apache carries the trusted-proxy, HSTS and per-entry-point .well-known rules.
    # Without these a restored host serves Nextcloud with the wrong scheme and host.
    Path("/opt/metehantech-cloud/apache-vhost.conf"),
    Path("/opt/metehantech-cloud/apache-proxy.conf"),
)
CLOUD_SENSITIVE_EXCLUDES = (
    "/etc/metehantech-cloud/secrets",
)

# Bu projenin kendisi her zaman yedeklenir; ek kardes projeler deployment
# yapilandirmasindan gelir (BACKUP_EXTRA_SOURCES, iki nokta ile ayrilmis).
PI_SOURCES = (deployment.PROJECT_ROOT,) + deployment.path_list("BACKUP_EXTRA_SOURCES")

# Manifest'te raporlanir; backup_supplement ayni degeri kullanir.
_WORKSPACE_ROOT = deployment.optional_path("OPENCLAW_WORKSPACE")
PI_DATABASES = (
    deployment.DATA_DIR / "metrics.db",
    deployment.DATA_DIR / "alerts.db",
    deployment.DATA_DIR / "admin_activity.db",
    deployment.DATA_DIR / "backups.db",
    # Camera Center canary history; excluded from applications.tar.zst by */data/*.db.
    deployment.DATA_DIR / "camera_canary.db",
)
PI_SYSTEM_FILES = (
    Path("/etc/systemd/system/metehantech-status.service"),
    Path("/etc/systemd/system/metehantech-home.service"),
    Path("/etc/systemd/system/clan-web.service"),
    Path("/etc/systemd/system/cloudflared.service"),
    Path("/etc/systemd/system/metehantech-frigate.service"),
    Path("/etc/systemd/system/metehantech-camera-pcold-route.service"),
)
# Include the allowlisted user units, without user-manager or Gateway secrets.
PI_SYSTEM_FILES += tuple(
    (Path.home() / ".config" / "systemd" / "user") / f"metehantech-backup-auto-{node}.{suffix}"
    for node in ("pi", "pcold", "cloud") for suffix in ("service", "timer")
)
SENSITIVE_EXCLUDES = (
    "/etc/metehantech-status/admin.env",
    "/etc/clan-web.env",
    "/etc/cloudflared/token",
)
ARCHIVE_EXCLUDES = (
    "*/.venv", "*/.venv/*", "*/__pycache__", "*/__pycache__/*",
    "*/.cache", "*/.cache/*", "*/.pytest_cache", "*/.pytest_cache/*",
    "*/backup-hardening", "*/backup-hardening/*",
    "*.pyc", "*.tmp", "*.swp", "*/data/*.db", "*/data/*.db-wal", "*/data/*.db-shm",
    "*/metehantech_backups", "*/metehantech_backups/*", "*/backup-work", "*/backup-work/*",
)


def _run(argv, timeout=120, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()[:500]
        raise RuntimeError(detail)
    return result


def _archive(destination, sources, excludes=()):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    existing = [Path(source).resolve() for source in sources if Path(source).exists()]
    if not existing:
        raise RuntimeError(f"No sources available for {destination.name}")
    argv = ["tar", "--zstd", "-cf", str(destination)]
    argv.extend(f"--exclude={pattern}" for pattern in excludes)
    argv.extend(["-C", "/"])
    argv.extend(str(source).lstrip("/") for source in existing)
    _run(argv, timeout=180)
    os.chmod(destination, 0o600)
    return destination


def _container_archive(destination):
    """Archive fixed Nextcloud paths while excluding the secret-bearing config.php."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tar_process = subprocess.Popen(
        [
            "docker", "exec", "-u", "33", CLOUD_APP, "tar", "-C", "/var/www/html",
            "--exclude=config/config.php", "-cf", "-", "config", "data", "custom_apps", "themes",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    with destination.open("wb") as output:
        zstd_process = subprocess.Popen(
            ["zstd", "-T0", "-6", "-c"],
            stdin=tar_process.stdout,
            stdout=output,
            stderr=subprocess.PIPE,
        )
        tar_process.stdout.close()
        zstd_error = zstd_process.communicate(timeout=1800)[1]
        tar_error = tar_process.communicate(timeout=60)[1]
    if tar_process.returncode or zstd_process.returncode:
        detail = (tar_error or zstd_error or b"cloud archive failed").decode(errors="replace")[:500]
        raise RuntimeError(detail)
    os.chmod(destination, 0o600)
    return destination


def _redacted_system_config(destination):
    """Export Nextcloud's non-private config view; sensitive values remain redacted."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = _run(
        ["docker", "exec", "-u", "33", CLOUD_APP, "php", "occ", "config:list", "system"],
        timeout=120,
    )
    payload = json.loads(result.stdout)
    if "system" not in payload or "***REMOVED SENSITIVE VALUE***" not in result.stdout:
        raise RuntimeError("Nextcloud redacted configuration export was not safe")
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(destination, 0o600)
    return destination


def _postgres_dump(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        result = subprocess.run(
            ["docker", "exec", CLOUD_DB, "pg_dump", "-U", "nextcloud", "-d", "nextcloud", "-Fc"],
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=600,
            check=False,
        )
    if result.returncode:
        raise RuntimeError((result.stderr or b"pg_dump failed").decode(errors="replace")[:500])
    os.chmod(destination, 0o600)
    return destination


def _occ(*args, check=True):
    return _run(["docker", "exec", "-u", "33", CLOUD_APP, "php", "occ", *args], timeout=120, check=check)


def build_cloud_staging(staging, deployment_sources=CLOUD_DEPLOYMENT_SOURCES):
    staging = Path(staging)
    staging.mkdir(parents=True, exist_ok=False)
    maintenance_enabled = False
    try:
        _occ("maintenance:mode", "--on")
        maintenance_enabled = True
        _postgres_dump(staging / "database" / "nextcloud.pgdump")
        _container_archive(staging / "nextcloud-files.tar.zst")
        _redacted_system_config(staging / "nextcloud-system-config.redacted.json")
        _archive(staging / "deployment-metadata.tar.zst", deployment_sources)
    finally:
        if maintenance_enabled:
            _occ("maintenance:mode", "--off", check=False)
    metadata = {
        "format_version": 1,
        "source_node": "cloud",
        "created_at": utc_now(),
        "sources": [
            "/var/www/html/config (config.php excluded; redacted export included)", "/var/www/html/data",
            "/var/www/html/custom_apps", "/var/www/html/themes",
            "PostgreSQL pg_dump custom format", "/opt/metehantech-cloud",
        ],
        "database_format": "postgresql_custom",
        "database_restore": "pg_restore --no-owner --no-acl into a database owned by the Compose PostgreSQL user",
        "redis": "excluded_noncritical_cache",
        "sensitive_configuration": {
            "status": "excluded_sensitive_pending_encryption",
            "paths": list(CLOUD_SENSITIVE_EXCLUDES),
        },
        "retention": "disabled",
    }
    (staging / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.chmod(staging / "metadata.json", 0o600)
    write_manifest(staging)
    return staging


def build_pi_staging(staging, sources=PI_SOURCES, databases=PI_DATABASES, system_files=PI_SYSTEM_FILES):
    staging = Path(staging)
    staging.mkdir(parents=True, exist_ok=False)
    _archive(staging / "applications.tar.zst", sources, ARCHIVE_EXCLUDES)
    _archive(staging / "system-units.tar.zst", system_files)
    db_dir = staging / "databases"
    for source in databases:
        source = Path(source)
        if source.exists():
            sqlite_snapshot(source, db_dir / source.name)
    metadata = {
        "format_version": 1,
        "source_node": "pi",
        "created_at": utc_now(),
        "sources": [str(path) for path in sources],
        "system_files": [str(path) for path in system_files],
        "databases": [str(path) for path in databases],
        "openclaw_workspace": (
            f"{_WORKSPACE_ROOT} (content scanned; .git and secret-bearing files excluded)"
            if _WORKSPACE_ROOT else "not configured"),
        "excluded_patterns": list(ARCHIVE_EXCLUDES),
        "sensitive_configuration": {
            "status": "excluded_sensitive_pending_encryption",
            "paths": list(SENSITIVE_EXCLUDES),
        },
        "portainer": "not_applicable",
        "retention": "disabled",
    }
    (staging / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.chmod(staging / "metadata.json", 0o600)
    write_manifest(staging)
    return verify_restore_point(staging.parent / "placeholder") if False else staging


def _ssh_base(host):
    return [
        "ssh", "-i", str(SSH_KEY), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", f"{PCOLD_USER}@{host}",
    ]


def _remote(host, *args, timeout=30):
    return _run(_ssh_base(host) + [REMOTE_HELPER, *args], timeout=timeout)


def choose_pcold_host():
    errors = []
    for host in PCOLD_HOSTS:
        try:
            _remote(host, "ping", timeout=12)
            return host
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            errors.append(f"{host}: {error}")
    raise RuntimeError("PcOld unavailable over LAN and Tailscale: " + "; ".join(errors))


def transfer_pi_restore_point(staging, backup_id, host):
    validate_backup_id(backup_id)
    storage_guard(PCOLD_DESTINATION, REMOTE_STORAGE, _ssh_base(host))
    _remote(host, "prepare", backup_id)
    destination = f"{PCOLD_USER}@{host}:{PCOLD_DESTINATION}/.staging/{backup_id}/"
    _run([
        "rsync", "-a", "--delete", "-e",
        f"ssh -i {SSH_KEY} -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes",
        f"{Path(staging)}/", destination,
    ], timeout=1800)
    _remote(host, "verify-finalize", backup_id, timeout=120)
    return f"ssh://{PCOLD_USER}@{host}{PCOLD_DESTINATION}/{backup_id}"


def request_pcold_export(backup_id, host):
    validate_backup_id(backup_id)
    _remote(host, "request-export", backup_id)
    _run(_ssh_base(host) + ["sudo", "-n", "/usr/bin/systemctl", "start", "--no-block", "metehantech-backup-export.service"])
    for _ in range(120):
        result = _remote(host, "export-ready", backup_id, timeout=15)
        if result.stdout.strip() == "ready":
            return
        if result.stdout.strip().startswith("failed:"):
            raise RuntimeError(result.stdout.strip()[7:])
        time.sleep(1)
    raise RuntimeError("PcOld export timed out")


def pull_pcold_restore_point(staging, backup_id, host):
    validate_backup_id(backup_id)
    staging = Path(staging)
    staging.mkdir(parents=True, exist_ok=False)
    source = f"{PCOLD_USER}@{host}:{PCOLD_EXPORT_ROOT}/{backup_id}/"
    _run([
        "rsync", "-a", "-e",
        f"ssh -i {SSH_KEY} -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes",
        source, f"{staging}/",
    ], timeout=300)
    return verify_restore_point(staging, allow_staging=True)


@contextmanager
def global_lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another backup job holds the global lock") from error
        yield


def cleanup_incomplete(node, backup_id):
    validate_backup_id(backup_id)
    root = WORK_ROOT if node in {"pi", "cloud"} else PI_DESTINATION / ".staging"
    candidate = (root / backup_id).resolve()
    root = root.resolve()
    if candidate.parent != root or candidate.name != backup_id:
        raise ValueError("Unsafe staging cleanup path")
    if candidate.exists():
        shutil.rmtree(candidate)


def run_pi_job(record):
    backup_id = record["backup_id"]
    work = WORK_ROOT / backup_id
    if work.exists():
        shutil.rmtree(work)
    update_backup(backup_id, phase="Snapshotting databases")
    storage_guard(PROJECT_ROOT / "data")
    build_pi_staging(work)
    from backup_supplement import add_supplement
    add_supplement(work, "pi")
    strict_verify(work, "pi")
    update_backup(backup_id, phase="Transferring")
    host = choose_pcold_host()
    restore_path = transfer_pi_restore_point(work, backup_id, host)
    update_backup(backup_id, phase="Verifying checksum")
    result = verify_restore_point(work)
    size, count = directory_stats(work)
    update_backup(
        backup_id, status="success", phase="Completed", finished_at=utc_now(),
        size_bytes=size, files_count=count, checksum_status=result["checksum_status"],
        verification_status=result["verification_status"], restore_point_path=restore_path,
    )
    shutil.rmtree(work)


def run_pcold_job(record):
    backup_id = record["backup_id"]
    storage_guard(PI_DESTINATION)
    host = choose_pcold_host()
    storage_guard(PCOLD_EXPORT_ROOT, REMOTE_STORAGE, _ssh_base(host))
    update_backup(backup_id, phase="Preparing remote export")
    request_pcold_export(backup_id, host)
    staging_root = PI_DESTINATION / ".staging"
    staging = staging_root / backup_id
    final = PI_DESTINATION / backup_id
    if staging.exists() or final.exists():
        raise RuntimeError("Restore point already exists")
    update_backup(backup_id, phase="Transferring")
    pull_pcold_restore_point(staging, backup_id, host)
    from backup_supplement import add_supplement
    add_supplement(staging, "pcold", _ssh_base(host))
    strict_verify(staging, "pcold")
    storage_guard(PI_DESTINATION)
    update_backup(backup_id, phase="Finalizing")
    PI_DESTINATION.mkdir(parents=True, exist_ok=True)
    os.replace(staging, final)
    result = verify_restore_point(final)
    size, count = directory_stats(final)
    update_backup(
        backup_id, status="success", phase="Completed", finished_at=utc_now(),
        size_bytes=size, files_count=count, checksum_status=result["checksum_status"],
        verification_status=result["verification_status"], restore_point_path=str(final),
    )


def run_cloud_job(record):
    backup_id = record["backup_id"]
    work = WORK_ROOT / backup_id
    if work.exists():
        shutil.rmtree(work)
    update_backup(backup_id, phase="Entering maintenance mode")
    build_cloud_staging(work)
    update_backup(backup_id, phase="Verifying local snapshot")
    result = strict_verify(work, "cloud")
    update_backup(backup_id, phase="Transferring")
    host = choose_pcold_host()
    restore_path = transfer_pi_restore_point(work, backup_id, host)
    update_backup(backup_id, phase="Verifying checksum")
    _remote(host, "verify", backup_id, timeout=1800)
    size, count = directory_stats(work)
    update_backup(
        backup_id, status="success", phase="Completed", finished_at=utc_now(),
        size_bytes=size, files_count=count, checksum_status=result["checksum_status"],
        verification_status=result["verification_status"], restore_point_path=restore_path,
    )
    shutil.rmtree(work)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or argv[0] not in {"pi", "pcold", "cloud"}:
        raise SystemExit("usage: backup_job.py pi|pcold|cloud")
    node = argv[0]
    record = claim_queued(node)
    if record is None:
        raise SystemExit("no queued backup")
    try:
        with global_lock():
            {"pi": run_pi_job, "pcold": run_pcold_job, "cloud": run_cloud_job}[node](record)
    except Exception as error:
        cleanup_incomplete(node, record["backup_id"])
        fail_backup(record["backup_id"], error)
        raise


if __name__ == "__main__":
    main()
