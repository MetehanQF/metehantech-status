#!/usr/bin/env python3
"""Restricted receiver and export request helper for the metehanbackup account."""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys


ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z-(?:pi|pcold|cloud)-full-[a-f0-9]{6}$")
DESTINATION = Path(os.environ.get("PCOLD_PI_BACKUP_DESTINATION", "/srv/metehantech-backups/from-pi"))
STATE_ROOT = Path(os.environ.get("PCOLD_BACKUP_STATE_ROOT", "/var/lib/metehantech-backup"))


def backup_id(value):
    if not ID_PATTERN.fullmatch(value or ""):
        raise ValueError("Invalid backup id")
    return value


def within(root, path):
    root, path = root.resolve(), path.resolve()
    if root != path and root not in path.parents:
        raise ValueError("Path escaped backup root")
    return path


def verify(root):
    root = within(DESTINATION, Path(root))
    manifest = root / "SHA256SUMS"
    metadata = root / "metadata.json"
    if not manifest.is_file() or not metadata.is_file():
        raise ValueError("Required metadata missing")
    json.loads(metadata.read_text(encoding="utf-8"))
    checked = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or not re.fullmatch(r"[a-f0-9]{64}", digest) or ".." in Path(relative).parts:
            raise ValueError("Invalid manifest")
        target = within(root, root / relative)
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Checksum mismatch: {relative}")
        checked += 1
    if not checked:
        raise ValueError("Empty manifest")
    for archive in root.glob("*.tar.zst"):
        result = subprocess.run(["tar", "--zstd", "-tf", str(archive)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            raise ValueError(f"Unreadable archive: {archive.name}")
    for db in root.rglob("*.db"):
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError(f"SQLite integrity failed: {db.name}")


def command(argv):
    if argv == ["ping"]:
        print("ok")
        return
    if len(argv) != 2:
        raise ValueError("Invalid command")
    action, value = argv
    value = backup_id(value)
    if action == "prepare":
        staging = DESTINATION / ".staging" / value
        final = DESTINATION / value
        if final.exists():
            raise ValueError("Restore point already exists")
        staging.mkdir(parents=True, mode=0o700, exist_ok=True)
        print("prepared")
    elif action == "verify-finalize":
        staging = DESTINATION / ".staging" / value
        final = DESTINATION / value
        try:
            verify(staging)
            os.replace(staging, final)
            verify(final)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise
        print("finalized")
    elif action == "verify":
        verify(DESTINATION / value)
        print("verified")
    elif action == "request-export":
        if "-pcold-full-" not in value:
            raise ValueError("Wrong source node")
        request_dir = STATE_ROOT / "requests"
        request_dir.mkdir(parents=True, exist_ok=True)
        request = request_dir / "next"
        if request.exists() and request.read_text(encoding="ascii").strip() != value:
            raise ValueError("Export request already exists")
        request.write_text(value + "\n", encoding="ascii")
        os.chmod(request, 0o600)
        print("requested")
    elif action == "export-ready":
        status = STATE_ROOT / "status" / f"{value}.json"
        if not status.exists():
            print("pending")
            return
        payload = json.loads(status.read_text(encoding="utf-8"))
        print("ready" if payload.get("status") == "ready" else f"failed:{payload.get('error','unknown')}")
    else:
        raise ValueError("Invalid command")


if __name__ == "__main__":
    try:
        command(sys.argv[1:])
    except (OSError, ValueError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
