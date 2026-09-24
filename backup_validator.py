#!/usr/bin/env python3
"""Backup assurance levels for the Backup Center.

A backup that arrived is not a backup that is readable, and a backup that is
readable is not a backup that restores. This module keeps those three claims
separate and refuses to let a cheap check imply an expensive one:

  TRANSFER_SUCCESS  the restore point exists where it should, is identifiable,
                    and carries every payload the job is supposed to produce.
  VERIFIED          every byte was re-read: manifest complete, SHA256 matched,
                    archives listable, SQLite integrity ok, PostgreSQL dump
                    fully parseable. Still says nothing about restoring.
  RESTORE_TESTED    an actual restore of this backup id was performed and its
                    result attested in an external evidence file.

RESTORE_TESTED is never derived. It can only be reached by presenting an
attestation that names the same backup id, so no amount of checksum passing can
promote a backup into it. This module performs read-only checks and never
writes to, deletes, or restores over anything.
"""

from contextlib import closing
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import deployment


LEVELS = ("NONE", "TRANSFER_SUCCESS", "VERIFIED", "RESTORE_TESTED")
BACKUP_ID_PATTERN = re.compile(r"^(\d{8}T\d{6}Z)-(pi|pcold|cloud)-full-([a-f0-9]{6})$")
PROJECT_ROOT = Path(__file__).resolve().parent

# Payloads each job produces unconditionally. Absence is a regression, not a state.
REQUIRED_PAYLOADS = {
    "pi": (
        "applications.tar.zst", "system-units.tar.zst",
        "coverage-supplement.tar.zst", "openclaw-workspace.tar.zst",
        "databases/metrics.db", "databases/alerts.db",
        "databases/admin_activity.db", "databases/backups.db",
    ),
    "pcold": (
        "pcold-applications.tar.zst", "uptime-kuma-files.tar.zst",
        "coverage-supplement.tar.zst",
        "databases/watchdog-events.db", "databases/uptime-kuma.db",
    ),
    "cloud": (
        "database/nextcloud.pgdump", "nextcloud-files.tar.zst",
        "deployment-metadata.tar.zst", "nextcloud-system-config.redacted.json",
    ),
}
# Optional sources. A missing one is reported, never fatal: a hard requirement on
# an optional file turns a legitimate application change into permanent backup failure.
EXPECTED_OPTIONAL = {
    "pi": ("databases/camera_canary.db",),
    "pcold": (),
    "cloud": (),
}
MIN_PAYLOAD_BYTES = {".db": 512, ".pgdump": 512, ".json": 32}
DEFAULT_MIN_BYTES = 32
CLOUD_DB_CONTAINER = "metehantech-nextcloud-db"


def _level_index(level):
    return LEVELS.index(level)


def _digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


class Report:
    """Accumulates check outcomes and computes the highest honest level."""

    def __init__(self, path, node=None):
        self.path = str(path)
        self.node = node
        self.backup_id = None
        self.checks = []
        self.started_at = datetime.now(timezone.utc).isoformat()

    def record(self, name, status, detail="", level="TRANSFER_SUCCESS"):
        self.checks.append({"name": name, "status": status, "detail": detail, "gates": level})
        return status == "pass"

    def _blocked_at(self, level):
        return [c for c in self.checks if c["status"] == "fail" and c["gates"] == level]

    @property
    def level(self):
        if self._blocked_at("TRANSFER_SUCCESS"):
            return "NONE"
        if self._blocked_at("VERIFIED"):
            return "TRANSFER_SUCCESS"
        if self._blocked_at("RESTORE_TESTED"):
            return "VERIFIED"
        # RESTORE_TESTED is only reachable when an attestation check actually ran and passed.
        if any(c["name"] == "restore_attestation" and c["status"] == "pass" for c in self.checks):
            return "RESTORE_TESTED"
        return "VERIFIED"

    def as_dict(self):
        failures = [c for c in self.checks if c["status"] == "fail"]
        return {
            "backup_id": self.backup_id,
            "node": self.node,
            "path": self.path,
            "level": self.level,
            "started_at": self.started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "checks_run": len(self.checks),
            "passed": sum(1 for c in self.checks if c["status"] == "pass"),
            "failed": len(failures),
            "warnings": [c for c in self.checks if c["status"] == "warn"],
            "skipped": [c for c in self.checks if c["status"] == "skip"],
            "failures": failures,
            "checks": self.checks,
        }


def load_attestations(source):
    """Read restore evidence. Returns {backup_id: evidence}. Never invents entries."""
    source = Path(source)
    if not source.is_file():
        return {}
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    records = {}
    if isinstance(data, dict) and "cloud_backup_id" in data:
        tested = {k: v for k, v in data.items()
                  if isinstance(v, dict) and v.get("status") == "RESTORE_TESTED"}
        if tested:
            records[data["cloud_backup_id"]] = {
                "source": str(source),
                "components": sorted(tested),
                "tested_at": data.get("finished_at"),
            }
    if isinstance(data, dict) and isinstance(data.get("attestations"), dict):
        for backup_id, evidence in data["attestations"].items():
            records[backup_id] = {"source": str(source), **evidence}
    return records


def check_identity(report, root):
    """Backup id, node, and timestamp must agree between path, name, and metadata."""
    match = BACKUP_ID_PATTERN.fullmatch(root.name)
    if not match:
        report.record("backup_id_format", "fail",
                      f"directory name is not a valid backup id: {root.name}")
        return None
    report.backup_id = root.name
    stamp, node, _ = match.groups()
    if report.node and report.node != node:
        report.record("node_identity", "fail",
                      f"caller expected node {report.node}, id declares {node}")
    else:
        report.node = node
        report.record("node_identity", "pass", node)

    metadata_path = root / "metadata.json"
    if not metadata_path.is_file():
        report.record("metadata_present", "fail", "metadata.json missing")
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except ValueError as error:
        report.record("metadata_parses", "fail", str(error)[:200])
        return None
    report.record("metadata_parses", "pass")

    if metadata.get("source_node") != node:
        report.record("source_identity", "fail",
                      f"metadata source_node={metadata.get('source_node')!r} != id node {node!r}")
    else:
        report.record("source_identity", "pass", node)

    try:
        created = datetime.fromisoformat(metadata["created_at"])
        declared = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as error:
        report.record("timestamp_valid", "fail", str(error)[:200])
        return metadata
    drift = abs((created - declared).total_seconds())
    if drift > 900:
        report.record("timestamp_consistent", "fail",
                      f"metadata created_at is {drift:.0f}s from the id timestamp")
    else:
        report.record("timestamp_consistent", "pass", f"drift {drift:.0f}s")
    if created > datetime.now(timezone.utc).astimezone(timezone.utc):
        report.record("timestamp_not_future", "fail", "backup is timestamped in the future")
    else:
        report.record("timestamp_not_future", "pass")
    return metadata


def check_freshness(report, metadata, max_age_hours):
    if not metadata or "created_at" not in metadata:
        report.record("freshness", "skip", "no usable timestamp")
        return
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(metadata["created_at"])).total_seconds()
    hours = age / 3600
    if max_age_hours is None:
        report.record("freshness", "pass", f"age {hours:.1f}h (no threshold requested)")
    elif hours > max_age_hours:
        report.record("freshness", "warn", f"age {hours:.1f}h exceeds {max_age_hours}h")
    else:
        report.record("freshness", "pass", f"age {hours:.1f}h")


def check_required_payloads(report, root):
    node = report.node
    if node not in REQUIRED_PAYLOADS:
        report.record("required_payloads", "skip", f"no payload contract for node {node!r}")
        return
    missing, undersized = [], []
    for relative in REQUIRED_PAYLOADS[node]:
        target = root / relative
        if not target.is_file():
            missing.append(relative)
            continue
        floor = MIN_PAYLOAD_BYTES.get(target.suffix, DEFAULT_MIN_BYTES)
        if target.stat().st_size < floor:
            undersized.append(f"{relative} ({target.stat().st_size}B < {floor}B)")
    if missing or undersized:
        report.record("required_payloads", "fail",
                      f"missing={missing} undersized={undersized}")
    else:
        report.record("required_payloads", "pass",
                      f"{len(REQUIRED_PAYLOADS[node])} required payloads present")

    absent = [r for r in EXPECTED_OPTIONAL.get(node, ()) if not (root / r).is_file()]
    if absent:
        report.record("expected_optional_payloads", "warn",
                      f"configured-but-absent: {absent}; confirm the source still exists")
    else:
        report.record("expected_optional_payloads", "pass")


def check_manifest(report, root):
    """Complete coverage both ways: every manifest line resolves, every file is listed."""
    manifest = root / "SHA256SUMS"
    if not manifest.is_file():
        report.record("manifest_present", "fail", "SHA256SUMS missing", level="VERIFIED")
        return
    report.record("manifest_present", "pass")

    listed, mismatches, unsafe = [], [], []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or not re.fullmatch(r"[a-f0-9]{64}", digest):
            unsafe.append(line[:80])
            continue
        if relative.startswith("/") or ".." in Path(relative).parts:
            unsafe.append(relative)
            continue
        target = root / relative
        if target.is_symlink() or not target.is_file():
            mismatches.append(f"{relative}: not a regular file")
            continue
        listed.append(relative)
        if _digest(target) != digest:
            mismatches.append(f"{relative}: checksum mismatch")

    if unsafe:
        report.record("manifest_wellformed", "fail", f"unsafe/invalid entries: {unsafe[:5]}", level="VERIFIED")
    else:
        report.record("manifest_wellformed", "pass", f"{len(listed)} entries")
    if not listed:
        report.record("manifest_nonempty", "fail", "manifest covers zero files", level="VERIFIED")
    else:
        report.record("manifest_nonempty", "pass")
    if mismatches:
        report.record("checksums_match", "fail", "; ".join(mismatches[:5]), level="VERIFIED")
    else:
        report.record("checksums_match", "pass", f"{len(listed)} files re-hashed")

    actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
              if p.is_file() and p.name != "SHA256SUMS"}
    # A zero-byte WAL plus its SHM beside a manifested DB is a regenerable cache the
    # legacy PcOld verifier leaves behind. Nonzero WAL means real unmanifested data.
    caches = set()
    for relative in actual - set(listed):
        if relative.endswith(("-wal", "-shm")) and relative[:-4] in listed and relative[:-4].endswith(".db"):
            wal = root / (relative[:-4] + "-wal")
            if wal.is_file() and wal.stat().st_size == 0:
                caches.add(relative)
    unmanifested = actual - set(listed) - caches
    if unmanifested:
        report.record("manifest_complete", "fail",
                      f"files present but not manifested: {sorted(unmanifested)[:5]}", level="VERIFIED")
    else:
        report.record("manifest_complete", "pass",
                      f"ignored regenerable caches: {sorted(caches)}" if caches else "exact coverage")

    symlinks = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_symlink()]
    if symlinks:
        report.record("no_symlinks", "fail", f"{symlinks[:5]}", level="VERIFIED")
    else:
        report.record("no_symlinks", "pass")


def check_archives(report, root):
    archives = sorted(root.rglob("*.tar.zst"))
    if not archives:
        report.record("archive_integrity", "skip", "no tar.zst payloads")
        return
    broken = []
    for archive in archives:
        result = subprocess.run(["tar", "--zstd", "-tf", str(archive)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True, timeout=300, check=False)
        if result.returncode != 0:
            broken.append(f"{archive.name}: {(result.stderr or '').strip()[:120]}")
    if broken:
        report.record("archive_integrity", "fail", "; ".join(broken), level="VERIFIED")
    else:
        report.record("archive_integrity", "pass", f"{len(archives)} archives listable")


def check_sqlite(report, root):
    databases = sorted(root.rglob("*.db"))
    if not databases:
        report.record("sqlite_integrity", "skip", "no SQLite payloads")
        return
    broken = []
    for database in databases:
        try:
            uri = f"file:{database}?mode=ro&immutable=1"
            with closing(sqlite3.connect(uri, uri=True, timeout=10)) as connection:
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    broken.append(f"{database.name}: integrity_check failed")
        except sqlite3.DatabaseError as error:
            broken.append(f"{database.name}: {str(error)[:120]}")
    if broken:
        report.record("sqlite_integrity", "fail", "; ".join(broken), level="VERIFIED")
    else:
        report.record("sqlite_integrity", "pass", f"{len(databases)} databases ok")


def check_postgres_dump(report, root):
    """Parse the whole custom dump. --file=/dev/null never connects to a database."""
    dumps = sorted(root.rglob("*.pgdump"))
    if not dumps:
        report.record("postgres_dump_parses", "skip", "no PostgreSQL dump payloads")
        return
    broken = []
    for dump in dumps:
        try:
            with dump.open("rb") as handle:
                result = subprocess.run(
                    ["docker", "exec", "-i", CLOUD_DB_CONTAINER, "pg_restore", "--file=/dev/null"],
                    stdin=handle, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    timeout=600, check=False)
            if result.returncode != 0:
                broken.append(f"{dump.name}: {(result.stderr or b'').decode(errors='replace').strip()[:160]}")
        except (OSError, subprocess.SubprocessError) as error:
            report.record("postgres_dump_parses", "skip",
                          f"pg_restore unavailable ({str(error)[:120]}); dump not proven parseable")
            return
    if broken:
        report.record("postgres_dump_parses", "fail", "; ".join(broken), level="VERIFIED")
    else:
        report.record("postgres_dump_parses", "pass", f"{len(dumps)} dumps fully parsed")


def check_secret_leak(report, root):
    """Cloud application archive must never carry config.php."""
    archive = root / "nextcloud-files.tar.zst"
    if not archive.is_file():
        report.record("no_secret_config_in_archive", "skip", "not a cloud restore point")
        return
    try:
        listing = subprocess.check_output(["tar", "--zstd", "-tf", str(archive)],
                                          text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as error:
        report.record("no_secret_config_in_archive", "fail", str(error)[:160], level="VERIFIED")
        return
    leaked = [n for n in listing.splitlines() if Path(n).name == "config.php"]
    if leaked:
        report.record("no_secret_config_in_archive", "fail", f"secret config present: {leaked[:3]}", level="VERIFIED")
    else:
        report.record("no_secret_config_in_archive", "pass")


def check_storage(report, root, expected=None):
    """Destination filesystem identity, writability, and headroom."""
    try:
        result = subprocess.run(["findmnt", "-J", "-T", str(root)],
                                capture_output=True, text=True, timeout=20, check=True)
        rows = json.loads(result.stdout).get("filesystems", [])
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        report.record("storage_identity", "fail", str(error)[:160])
        return
    if len(rows) != 1:
        report.record("storage_identity", "fail", "cannot uniquely identify the backup filesystem")
        return
    row = rows[0]
    if expected and any(row.get(k) != v for k, v in expected.items()):
        report.record("storage_identity", "fail",
                      f"filesystem identity mismatch: got "
                      f"{ {k: row.get(k) for k in expected} }, expected {expected}")
    else:
        report.record("storage_identity", "pass",
                      f"{row.get('source')} {row.get('fstype')} on {row.get('target')}")
    if "rw" not in (row.get("options") or "").split(","):
        report.record("storage_writable", "fail", "destination filesystem is not mounted rw")
    else:
        report.record("storage_writable", "pass")
    try:
        df = subprocess.run(["df", "-Pk", str(root)], capture_output=True, text=True, timeout=20, check=True)
        free = int(df.stdout.splitlines()[-1].split()[3]) * 1024
    except (OSError, subprocess.SubprocessError, IndexError, ValueError) as error:
        report.record("storage_free_space", "fail", str(error)[:160])
        return
    if free < 2 * 1024 ** 3:
        report.record("storage_free_space", "fail", f"{free / 1024 ** 3:.2f} GiB free, below the 2 GiB floor")
    else:
        report.record("storage_free_space", "pass", f"{free / 1024 ** 3:.2f} GiB free")


def check_restore_attestation(report, attestations):
    """The only path to RESTORE_TESTED. Checksums can never substitute for this."""
    if not attestations:
        report.record("restore_attestation", "skip",
                      "no restore evidence supplied; VERIFIED is the ceiling")
        return
    evidence = attestations.get(report.backup_id)
    if not evidence:
        report.record("restore_attestation", "skip",
                      f"no restore evidence names {report.backup_id}; VERIFIED is the ceiling")
        return
    report.record("restore_attestation", "pass",
                  f"restored components {evidence.get('components')} "
                  f"attested at {evidence.get('tested_at')} in {evidence.get('source')}")


def validate_restore_point(path, node=None, attestations=None, max_age_hours=None,
                           expected_storage=None, deep=True):
    root = Path(path).resolve()
    report = Report(root, node)
    if not root.is_dir():
        report.record("restore_point_exists", "fail", "path is not a directory")
        return report.as_dict()
    if ".staging" in root.parts:
        report.record("restore_point_finalized", "fail",
                      "path is still under .staging; the job never finalized it")
        return report.as_dict()
    report.record("restore_point_exists", "pass")
    report.record("restore_point_finalized", "pass")

    metadata = check_identity(report, root)
    check_required_payloads(report, root)
    check_freshness(report, metadata, max_age_hours)
    check_storage(report, root, expected_storage)
    if deep:
        check_manifest(report, root)
        check_archives(report, root)
        check_sqlite(report, root)
        check_postgres_dump(report, root)
        check_secret_leak(report, root)
    else:
        for name in ("manifest_present", "checksums_match", "archive_integrity",
                     "sqlite_integrity", "postgres_dump_parses"):
            report.record(name, "skip", "deep verification not requested", level="VERIFIED")
        report.record("deep_verification", "fail",
                      "deep checks skipped; VERIFIED cannot be claimed", level="VERIFIED")
    check_restore_attestation(report, attestations or {})
    return report.as_dict()


def stuck_jobs(records, max_active_hours=6, now=None):
    """Queued/running records older than the threshold: a job that died mid-flight.

    Such a record is not a success and not a failure — it is an unfinished claim on
    the backup lock, and reporting it as either would be wrong.
    """
    now = now or datetime.now(timezone.utc)
    stuck = []
    for record in records:
        if record.get("status") not in {"queued", "running"}:
            continue
        try:
            age = (now - datetime.fromisoformat(record["started_at"])).total_seconds()
        except (KeyError, ValueError):
            stuck.append({**record, "age_hours": None, "reason": "unparseable started_at"})
            continue
        if age > max_active_hours * 3600:
            stuck.append({"backup_id": record.get("backup_id"), "status": record.get("status"),
                          "phase": record.get("phase"), "age_hours": round(age / 3600, 2),
                          "reason": f"active for {age / 3600:.1f}h, over the {max_active_hours}h threshold"})
    return stuck


def flow_state(records, source_node, max_age_hours=36, attestations=None):
    """Per-flow assurance summary for the Backup Center UI.

    Deliberately keeps 'the last attempt' and 'the last thing we trust' apart: a
    fresh failure sitting on top of an old success must not read as healthy, and an
    old success must not be hidden by a fresh failure.
    """
    attestations = attestations or {}
    node_records = [r for r in records if r.get("source_node") == source_node]
    latest = node_records[0] if node_records else None
    verified = next((r for r in node_records
                     if r.get("status") == "success" and r.get("verification_status") == "verified"), None)
    restore_tested = next((r for r in node_records if r.get("backup_id") in attestations), None)

    age_hours = None
    freshness = "unknown"
    if verified and verified.get("finished_at"):
        try:
            age = (datetime.now(timezone.utc)
                   - datetime.fromisoformat(verified["finished_at"])).total_seconds()
            age_hours = round(age / 3600, 2)
            freshness = ("ok" if age_hours <= 24
                         else "warning" if age_hours <= max_age_hours else "critical")
        except ValueError:
            freshness = "unknown"

    return {
        "source_node": source_node,
        "destination_node": (latest or {}).get("destination_node"),
        "last_attempt": {
            "backup_id": (latest or {}).get("backup_id"),
            "status": (latest or {}).get("status"),
            "phase": (latest or {}).get("phase"),
            "started_at": (latest or {}).get("started_at"),
            "error_summary": (latest or {}).get("error_summary"),
        } if latest else None,
        "last_verified": {
            "backup_id": verified["backup_id"],
            "finished_at": verified["finished_at"],
            "size_bytes": verified.get("size_bytes"),
            "files_count": verified.get("files_count"),
            "restore_point_path": verified.get("restore_point_path"),
        } if verified else None,
        "last_restore_tested": {
            "backup_id": restore_tested["backup_id"],
            "components": attestations[restore_tested["backup_id"]].get("components"),
            "tested_at": attestations[restore_tested["backup_id"]].get("tested_at"),
        } if restore_tested else None,
        "assurance_level": ("RESTORE_TESTED" if restore_tested
                            else "VERIFIED" if verified
                            else "TRANSFER_SUCCESS" if latest and latest.get("status") == "success"
                            else "NONE"),
        "verified_age_hours": age_hours,
        "freshness": freshness,
    }


# Component coverage that is not expressible as a source node. Each entry states where
# the component's data actually lives in a backup, or why it is not covered at all.
COMPONENT_COVERAGE = {
    "uptime_kuma": {
        "flow": "pcold",
        "payloads": ["databases/uptime-kuma.db", "uptime-kuma-files.tar.zst"],
        "restore_evidence_key": "uptime_kuma",
        "note": "Kuma keeps effectively all state in kuma.db; the file archive holds only "
                "empty screenshots/, upload/ and docker-tls/ directories.",
    },
    "portainer": {
        "flow": None,
        "payloads": [],
        "restore_evidence_key": "portainer",
        "note": "Not backed up. The restricted metehanbackup account on PcOld has no Docker "
                "socket and no /var/lib/docker access, and no supported authenticated export "
                "is reachable. A live BoltDB file copy would be an inconsistent snapshot.",
    },
}
FLOW_LABELS = {
    "pi": "Pi -> PcOld",
    "pcold": "PcOld -> Pi",
    "cloud": "Cloud (Nextcloud) -> PcOld",
}


def assurance_report(records, attestations=None, restore_results=None, max_age_hours=36):
    """One read-only view of every backup flow and component, for the Backup Center UI."""
    attestations = attestations or {}
    restore_results = restore_results or {}
    flows = {}
    for node, label in FLOW_LABELS.items():
        state = flow_state(records, node, max_age_hours=max_age_hours, attestations=attestations)
        flows[node] = {"label": label, **state}

    components = {}
    for name, spec in COMPONENT_COVERAGE.items():
        evidence = restore_results.get(spec["restore_evidence_key"]) or {}
        flow = flows.get(spec["flow"]) if spec["flow"] else None
        if not spec["flow"]:
            level = "NONE"
        elif evidence.get("status") == "RESTORE_TESTED":
            level = "RESTORE_TESTED"
        else:
            level = (flow or {}).get("assurance_level", "NONE")
        components[name] = {
            "covered": bool(spec["flow"]),
            "carried_by_flow": spec["flow"],
            "payloads": spec["payloads"],
            "assurance_level": level,
            "restore_status": evidence.get("status", "NOT_TESTED"),
            "restore_scope": evidence.get("scope"),
            "restore_reason": evidence.get("reason"),
            "note": spec["note"],
        }

    stuck = stuck_jobs(records)
    return {
        "schema": "metehantech.backup-assurance.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assurance_levels": list(LEVELS),
        "assurance_definitions": {
            "TRANSFER_SUCCESS": "Arrived at the destination and is identifiable. Not re-read.",
            "VERIFIED": "Every byte re-read: manifest complete, SHA256 matched, archives "
                        "listable, SQLite integrity ok, PostgreSQL dump fully parsed.",
            "RESTORE_TESTED": "An actual restore was performed and attested. Never inferred "
                              "from checksums.",
        },
        "flows": flows,
        "components": components,
        "stuck_jobs": stuck,
        "healthy": not stuck and all(
            f["freshness"] in {"ok", "warning"} for f in flows.values()
            if f["assurance_level"] != "NONE"),
    }


def live_assurance(max_age_hours=36):
    """Assemble the assurance report from the live Backup Center database."""
    import backups
    # Opsiyonel: geri yukleme tatbikati ciktisi bu deployment'a ozeldir.
    attestation_path = deployment.optional_path("RESTORE_ATTESTATION")
    restore_results = {}
    if attestation_path is not None and attestation_path.is_file():
        try:
            restore_results = json.loads(attestation_path.read_text(encoding="utf-8"))
        except ValueError:
            restore_results = {}
    return assurance_report(
        backups.list_backups(500),
        attestations=load_attestations(attestation_path),
        restore_results=restore_results,
        max_age_hours=max_age_hours,
    )


def main(argv=None):
    if argv is None and len(sys.argv) > 1 and sys.argv[1] == "assurance":
        report = live_assurance()
        print(json.dumps(report, indent=2))
        return 0
    parser = argparse.ArgumentParser(description="Validate a Backup Center restore point.")
    parser.add_argument("path", help="restore point directory")
    parser.add_argument("--node", choices=sorted(REQUIRED_PAYLOADS), default=None)
    # Varsayilan, yapilandirilmissa RESTORE_ATTESTATION; degilse yok. Kaynak kodda
    # gercek makine yolu fallback'i bilerek birakilmamistir.
    _attestation_default = deployment.optional_path("RESTORE_ATTESTATION")
    parser.add_argument("--attestations",
                        default=str(_attestation_default) if _attestation_default else None)
    parser.add_argument("--max-age-hours", type=float, default=None)
    parser.add_argument("--shallow", action="store_true",
                        help="identity and presence only; cannot reach VERIFIED")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args(argv)

    result = validate_restore_point(
        args.path, node=args.node,
        attestations=load_attestations(args.attestations),
        max_age_hours=args.max_age_hours, deep=not args.shallow)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['backup_id']}  node={result['node']}  LEVEL={result['level']}")
        print(f"  {result['passed']}/{result['checks_run']} checks passed, {result['failed']} failed")
        for check in result["failures"]:
            print(f"  FAIL  {check['name']}: {check['detail']}")
        for check in result["warnings"]:
            print(f"  WARN  {check['name']}: {check['detail']}")
        for check in result["skipped"]:
            print(f"  SKIP  {check['name']}: {check['detail']}")
    return 0 if result["level"] in {"VERIFIED", "RESTORE_TESTED"} else 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
