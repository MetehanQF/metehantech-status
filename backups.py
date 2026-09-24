"""Persistent Backup Center metadata and restore-point verification."""

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


DB_PATH = Path(__file__).resolve().parent / "data" / "backups.db"
BACKUP_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z-(?:pi|pcold|cloud)-full-[a-f0-9]{6}$")
NODES = {"pi", "pcold", "cloud"}
STATUSES = {"queued", "running", "success", "failed", "verification_failed"}
ACTIVE_STATUSES = {"queued", "running"}
LIMITS = {50, 100, 500}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def configured_db_path():
    configured = os.environ.get("BACKUPS_DB", "").strip()
    return Path(configured) if configured else DB_PATH


def connect(db_path=None):
    path = Path(db_path) if db_path is not None else configured_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    os.chmod(path, 0o600)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id TEXT NOT NULL UNIQUE,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            source_node TEXT NOT NULL CHECK(source_node IN ('pi','pcold','cloud')),
            destination_node TEXT NOT NULL CHECK(destination_node IN ('pi','pcold','cloud')),
            backup_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('queued','running','success','failed','verification_failed')),
            phase TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            files_count INTEGER NOT NULL DEFAULT 0,
            checksum_status TEXT NOT NULL DEFAULT 'pending',
            verification_status TEXT NOT NULL DEFAULT 'pending',
            error_summary TEXT,
            restore_point_path TEXT
        )
    """)
    schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='backups'"
    ).fetchone()[0]
    if "'cloud'" not in schema:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            CREATE TABLE backups_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_id TEXT NOT NULL UNIQUE,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                source_node TEXT NOT NULL CHECK(source_node IN ('pi','pcold','cloud')),
                destination_node TEXT NOT NULL CHECK(destination_node IN ('pi','pcold','cloud')),
                backup_type TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('queued','running','success','failed','verification_failed')),
                phase TEXT NOT NULL,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                files_count INTEGER NOT NULL DEFAULT 0,
                checksum_status TEXT NOT NULL DEFAULT 'pending',
                verification_status TEXT NOT NULL DEFAULT 'pending',
                error_summary TEXT,
                restore_point_path TEXT
            )
        """)
        connection.execute("INSERT INTO backups_v2 SELECT * FROM backups")
        connection.execute("DROP TABLE backups")
        connection.execute("ALTER TABLE backups_v2 RENAME TO backups")
        connection.commit()
    connection.execute("CREATE INDEX IF NOT EXISTS backups_recent ON backups(started_at DESC, id DESC)")
    connection.execute("CREATE INDEX IF NOT EXISTS backups_status ON backups(status, source_node)")
    return connection


def validate_backup_id(backup_id):
    if not isinstance(backup_id, str) or not BACKUP_ID_PATTERN.fullmatch(backup_id):
        raise ValueError("Invalid backup id")
    return backup_id


def new_backup_id(node, now=None, token=None):
    if node not in NODES:
        raise ValueError("Invalid node")
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    suffix = token or os.urandom(3).hex()
    backup_id = f"{stamp}-{node}-full-{suffix}"
    return validate_backup_id(backup_id)


def enqueue_backup(node, db_path=None, backup_id=None):
    if node not in NODES:
        raise ValueError("Invalid node")
    backup_id = validate_backup_id(backup_id) if backup_id else new_backup_id(node)
    destination = "pi" if node == "pcold" else "pcold"
    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = connection.execute(
            "SELECT backup_id FROM backups WHERE status IN ('queued','running') LIMIT 1"
        ).fetchone()
        if active:
            connection.rollback()
            raise RuntimeError("A backup job is already queued or running")
        connection.execute(
            "INSERT INTO backups(backup_id,started_at,source_node,destination_node,backup_type,status,phase) "
            "VALUES (?,?,?,?,?,'queued','Queued')",
            (backup_id, utc_now(), node, destination, "full"),
        )
        connection.commit()
    return get_backup(backup_id, db_path)


def claim_queued(node, db_path=None):
    if node not in NODES:
        raise ValueError("Invalid node")
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM backups WHERE source_node=? AND status='queued' ORDER BY id LIMIT 1",
            (node,),
        ).fetchone()
        if row is None:
            connection.rollback()
            return None
        connection.execute(
            "UPDATE backups SET status='running', phase='Preparing', error_summary=NULL WHERE id=?",
            (row["id"],),
        )
        connection.commit()
    return get_backup(row["backup_id"], db_path)


def update_backup(backup_id, db_path=None, **fields):
    validate_backup_id(backup_id)
    allowed = {
        "finished_at", "status", "phase", "size_bytes", "files_count",
        "checksum_status", "verification_status", "error_summary", "restore_point_path",
    }
    if not fields or not set(fields) <= allowed:
        raise ValueError("Invalid backup update")
    if "status" in fields and fields["status"] not in STATUSES:
        raise ValueError("Invalid status")
    assignments = ", ".join(f"{name}=?" for name in fields)
    values = list(fields.values()) + [backup_id]
    with closing(connect(db_path)) as connection:
        cursor = connection.execute(f"UPDATE backups SET {assignments} WHERE backup_id=?", values)
        if cursor.rowcount != 1:
            raise KeyError(backup_id)
        connection.commit()
    return get_backup(backup_id, db_path)


def fail_backup(backup_id, error, db_path=None, verification=False):
    return update_backup(
        backup_id,
        db_path,
        status="verification_failed" if verification else "failed",
        phase="Verification failed" if verification else "Failed",
        finished_at=utc_now(),
        checksum_status="failed" if verification else "pending",
        verification_status="failed" if verification else "pending",
        error_summary=str(error)[:500],
    )


def get_backup(backup_id, db_path=None):
    validate_backup_id(backup_id)
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM backups WHERE backup_id=?", (backup_id,)).fetchone()
    return dict(row) if row else None


def list_backups(limit=50, db_path=None):
    if limit not in LIMITS:
        raise ValueError("Invalid limit")
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM backups ORDER BY started_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def backup_summary(db_path=None):
    records = {}
    with closing(connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        for node in sorted(NODES):
            row = connection.execute(
                "SELECT * FROM backups WHERE source_node=? ORDER BY started_at DESC,id DESC LIMIT 1",
                (node,),
            ).fetchone()
            records[node] = dict(row) if row else None
        running = connection.execute(
            "SELECT backup_id,source_node,status,phase FROM backups "
            "WHERE status IN ('queued','running') ORDER BY id LIMIT 1"
        ).fetchone()
    return {
        "nodes": records,
        "active_job": dict(running) if running else None,
        "sensitive_configuration": "NOT ENABLED",
        "portainer_backup": "excluded_pending_supported_export",
        "retention": "disabled",
        "automatic_timer": "disabled",
        "encryption_tools": {"age": bool(shutil.which("age")), "gpg": bool(shutil.which("gpg"))},
    }


def sqlite_snapshot(source, destination):
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=10)) as src:
        with closing(sqlite3.connect(destination, timeout=10)) as dst:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")
            result = dst.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise RuntimeError(f"SQLite integrity check failed for {source.name}")
    os.chmod(destination, 0o600)
    return destination


def _file_digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_manifest(root):
    root = Path(root).resolve()
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(root).as_posix()
        digest = _file_digest(path)
        entries.append(f"{digest}  {relative}")
    (root / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
    return len(entries)


def _safe_manifest_path(root, relative):
    if not relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise ValueError("Unsafe manifest path")
    target = (root / relative).resolve()
    if root not in target.parents:
        raise ValueError("Manifest path escaped restore point")
    if target.is_symlink() or not target.is_file():
        raise ValueError("Manifest entry is not a regular file")
    return target


def verify_restore_point(path, allow_staging=False):
    root = Path(path).resolve()
    if not root.is_dir() or (not allow_staging and (root.name == ".staging" or ".staging" in root.parts)):
        raise ValueError("Invalid restore point")
    manifest = root / "SHA256SUMS"
    metadata = root / "metadata.json"
    if not manifest.is_file() or not metadata.is_file():
        raise ValueError("Required backup metadata is missing")
    checked = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid checksum manifest")
        target = _safe_manifest_path(root, relative)
        if _file_digest(target) != digest:
            raise ValueError(f"Checksum mismatch: {relative}")
        checked += 1
    if checked == 0:
        raise ValueError("Empty checksum manifest")
    json.loads(metadata.read_text(encoding="utf-8"))
    for archive in root.glob("*.tar.zst"):
        result = subprocess.run(
            ["tar", "--zstd", "-tf", str(archive)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError(f"Unreadable archive: {archive.name}")
    for database in root.rglob("*.db"):
        with closing(sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True, timeout=10)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError(f"SQLite integrity check failed: {database.name}")
    return {"files_checked": checked, "checksum_status": "verified", "verification_status": "verified"}


def directory_stats(path):
    root = Path(path)
    files = [entry for entry in root.rglob("*") if entry.is_file()]
    return sum(entry.stat().st_size for entry in files), len(files)
