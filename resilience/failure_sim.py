#!/usr/bin/env python3
"""Synthetic failure harness: prove the backup path refuses to call broken things good.

Every scenario runs against throwaway copies inside a sandbox directory, a throwaway
metadata database, and a throwaway lock file. Production restore points, the live
backups.db, live mounts, live network and live disks are never modified.

Where a real fault source already exists on this host it is used rather than faked:

  read-only target    /boot/firmware and /snap/... are genuinely mounted ro
  insufficient disk   /boot/firmware genuinely has ~316 MiB free, under the 2 GiB floor
  wrong filesystem    /boot/firmware is genuinely vfat on a different device
  ambiguous mount     a stacked autofs-over-nfs4 mount point
  unreachable peer    192.0.2.1 is the reserved TEST-NET-1 blackhole, not a real host

Nothing is unmounted, no live disk is filled, and no live network path is cut.
Each scenario asserts a *negative*: the component must not report success.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback

from _harness import (  # noqa: E402  (sets up the repo-relative import path)
    LabGuardError, add_safety_args, parser, require_confirmation, resolve_lab,
    write_results,
)

# Restore points are supplied per run with --fixture. Nothing is read from a
# hard-coded location: this harness corrupts what it is given, so it must never
# guess where a real restore point lives.
FIXTURE_PCOLD = None
FIXTURE_CLOUD = None

RESULTS = []


def scenario(name, expectation):
    def decorate(function):
        function._scenario = (name, expectation)
        return function
    return decorate


def record(name, expectation, passed, observed, evidence=None):
    RESULTS.append({
        "scenario": name,
        "expectation": expectation,
        "result": "PASS" if passed else "FAIL",
        "observed": observed,
        "evidence": evidence,
    })
    print(f"[{'PASS' if passed else 'FAIL'}] {name}\n        expected: {expectation}\n        observed: {observed}")


def fresh_copy(sandbox, fixture, name):
    """Copy the fixture under a *valid* backup id.

    The directory name is part of the contract the validator checks, so a sandbox
    copy named after its scenario would fail identity first and mask the fault the
    scenario is actually trying to prove. Keep the fixture's timestamp and node,
    vary only the six-hex suffix.
    """
    stamp, rest = fixture.name.split("-", 1)
    node = rest.split("-")[0]
    suffix = hashlib.sha256(name.encode()).hexdigest()[:6]
    target = sandbox / f"{stamp}-{node}-full-{suffix}"
    shutil.copytree(fixture, target)
    for path in target.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o600)
    return target


def retime(root, when):
    """Rewrite metadata + directory name so the fixture carries a chosen timestamp."""
    metadata = json.loads((root / "metadata.json").read_text())
    metadata["created_at"] = when.isoformat()
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    import backups
    backups.write_manifest(root)
    stamp = when.strftime("%Y%m%dT%H%M%SZ")
    suffix = root.name.split("-", 1)[1]
    renamed = root.parent / f"{stamp}-{suffix}"
    root.rename(renamed)
    return renamed


# --------------------------------------------------------------------------- storage

def storage_scenarios():
    import backup_hardening as bh

    def expect_refusal(name, expectation, path, expected_identity):
        try:
            result = bh.storage_guard(path, expected_identity)
            record(name, expectation, False, f"storage_guard ACCEPTED the target: {result}")
        except Exception as error:
            record(name, expectation, True,
                   f"{type(error).__name__}: {error}", evidence=str(path))

    expect_refusal(
        "missing_backup_target",
        "storage_guard must refuse a destination path that does not exist",
        "/nonexistent/backup-destination",
        bh.LOCAL_STORAGE)

    expect_refusal(
        "read_only_backup_target",
        "storage_guard must refuse a genuinely read-only filesystem",
        "/boot/firmware",
        {"target": "/boot/firmware", "source": "/dev/nvme0n1p1", "fstype": "vfat"})

    expect_refusal(
        "wrong_filesystem_identity",
        "storage_guard must refuse a destination whose device/fstype is not the expected one",
        "/boot/firmware",
        bh.LOCAL_STORAGE)

    expect_refusal(
        "ambiguous_stacked_mount_nfs",
        "storage_guard must fail closed when the destination resolves to more than one filesystem",
        "/mnt/synthetic-share",
        {"target": "/mnt/synthetic-share", "source": "198.51.100.10:/srv/share", "fstype": "nfs4"})

    # Free-space floor in isolation. /run/user/1000 is a real tmpfs that is mounted rw and
    # uniquely identifiable, so identity and writability both pass and the ONLY thing that
    # can refuse it is the 2 GiB floor. Nothing is written to it; the guard only reads df.
    # A real tmpfs that is mounted rw and uniquely identifiable, derived from the
    # running uid rather than hard-coded.
    small = f"/run/user/{os.getuid()}"
    free = int(subprocess.run(["df", "-Pk", small], capture_output=True, text=True,
                              check=True).stdout.splitlines()[-1].split()[3]) * 1024
    expectation = "storage_guard must refuse a writable, correctly-identified destination with under 2 GiB free"
    if free >= 2 * 1024 ** 3:
        record("insufficient_free_space", expectation, False,
               f"{small} now has {free / 1024 ** 3:.2f} GiB free, so it no longer exercises the floor")
    else:
        try:
            bh.storage_guard(small, {"target": small, "source": "tmpfs", "fstype": "tmpfs"})
            record("insufficient_free_space", expectation, False,
                   f"storage_guard ACCEPTED a target with only {free / 1024 ** 3:.2f} GiB free")
        except Exception as error:
            isolated = "less than 2 GiB free" in str(error)
            record("insufficient_free_space", expectation, isolated,
                   f"{type(error).__name__}: {error} (target genuinely rw with "
                   f"{free / 1024 ** 3:.2f} GiB free)",
                   evidence=f"df -Pk {small} -> {free} bytes available; identity and rw checks both passed first")


# --------------------------------------------------------------------------- artifacts

def artifact_scenarios(sandbox):
    import backup_validator as bv
    import backup_hardening as bh

    def expect_not_verified(name, expectation, root, node, check_name=None):
        report = bv.validate_restore_point(root, node=node)
        failed = {c["name"] for c in report["failures"]}
        ok = report["level"] not in {"VERIFIED", "RESTORE_TESTED"}
        if check_name:
            ok = ok and check_name in failed
        record(name, expectation, ok,
               f"level={report['level']}, failed checks={sorted(failed) or 'none'}",
               evidence=str(root))
        return report

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "checksum-mismatch")
    target = root / "pcold-applications.tar.zst"
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 0xFF
    target.write_bytes(bytes(data))
    expect_not_verified("checksum_mismatch",
                        "a payload altered after manifesting must break the SHA256 check",
                        root, "pcold", "checksums_match")

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "corrupt-sqlite")
    database = root / "databases" / "uptime-kuma.db"
    blob = bytearray(database.read_bytes())
    blob[4096:8192] = b"\x00" * 4096          # clobber a page, keep the header
    database.write_bytes(bytes(blob))
    import backups as _b
    _b.write_manifest(root)                    # re-manifest so ONLY sqlite integrity can fail
    expect_not_verified("corrupt_sqlite_database",
                        "a corrupted SQLite payload must fail PRAGMA integrity_check even with a valid checksum",
                        root, "pcold", "sqlite_integrity")

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "corrupt-archive")
    archive = root / "pcold-applications.tar.zst"
    blob = bytearray(archive.read_bytes())
    blob[20:120] = b"\x00" * 100
    archive.write_bytes(bytes(blob))
    _b.write_manifest(root)
    expect_not_verified("corrupt_archive",
                        "an unreadable tar.zst must fail archive integrity even with a valid checksum",
                        root, "pcold", "archive_integrity")

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "missing-payload")
    (root / "databases" / "watchdog-events.db").unlink()
    _b.write_manifest(root)
    expect_not_verified("missing_required_payload",
                        "a restore point missing a contracted payload must not reach VERIFIED",
                        root, "pcold", "required_payloads")

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "unmanifested-file")
    (root / "smuggled.bin").write_bytes(b"content that no manifest line covers")
    expect_not_verified("unmanifested_file_present",
                        "a file present but absent from SHA256SUMS must fail manifest completeness",
                        root, "pcold", "manifest_complete")

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "symlink-injection")
    (root / "escape").symlink_to("/etc/passwd")
    expect_not_verified("symlink_in_restore_point",
                        "a symlink inside a restore point must be rejected, not followed",
                        root, "pcold", "no_symlinks")

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "future-timestamp")
    root = retime(root, datetime.now(timezone.utc) + timedelta(days=2))
    report = bv.validate_restore_point(root, node="pcold")
    failed = {c["name"] for c in report["failures"]}
    record("future_dated_backup",
           "a backup timestamped in the future must be rejected as untrustworthy",
           "timestamp_not_future" in failed and report["level"] == "NONE",
           f"level={report['level']}, failed={sorted(failed)}", evidence=str(root))

    root = fresh_copy(sandbox, FIXTURE_PCOLD, "stale-backup")
    stale_at = datetime.now(timezone.utc) - timedelta(days=9)
    root = retime(root, stale_at)
    report = bv.validate_restore_point(root, node="pcold", max_age_hours=36)
    warned = [c for c in report["warnings"] if c["name"] == "freshness"]
    record("stale_backup",
           "a 9-day-old backup must be surfaced as stale rather than silently accepted as current",
           bool(warned),
           f"level={report['level']}, freshness warning={warned[0]['detail'] if warned else 'ABSENT'}",
           evidence=str(root))
    try:
        bh.strict_verify(root, "pcold")
        record("stale_backup_strict_verify",
               "strict_verify must refuse to accept a stale artifact as a fresh success",
               False, "strict_verify ACCEPTED a 9-day-old artifact as fresh")
    except Exception as error:
        record("stale_backup_strict_verify",
               "strict_verify must refuse to accept a stale artifact as a fresh success",
               True, f"{type(error).__name__}: {error}")

    staging = sandbox / ".staging"
    staging.mkdir(exist_ok=True)
    root = fresh_copy(staging, FIXTURE_PCOLD, "unfinalized")
    report = bv.validate_restore_point(root, node="pcold")
    record("unfinalized_staging_directory",
           "a restore point still under .staging must never be treated as a completed backup",
           report["level"] == "NONE"
           and any(c["name"] == "restore_point_finalized" for c in report["failures"]),
           f"level={report['level']}", evidence=str(root))

    # The central guarantee of the assurance model.
    clean = fresh_copy(sandbox, FIXTURE_PCOLD, "clean-verified")
    report = bv.validate_restore_point(clean, node="pcold", attestations={})
    record("checksum_pass_does_not_imply_restore_tested",
           "a fully checksum-clean backup must stop at VERIFIED without restore evidence",
           report["level"] == "VERIFIED" and report["failed"] == 0,
           f"level={report['level']} with {report['failed']} failures", evidence=str(clean))

    forged = bv.validate_restore_point(
        clean, node="pcold",
        attestations={"20260101T000000Z-pcold-full-aaaaaa": {"components": ["fake"], "tested_at": "x"}})
    record("attestation_for_a_different_backup_is_ignored",
           "restore evidence naming another backup id must not promote this one",
           forged["level"] == "VERIFIED",
           f"level={forged['level']}", evidence="attestation id mismatch")


def pgdump_scenario(sandbox):
    """Corrupt PostgreSQL dump. Phase 3 already rejected one; this re-proves it in the validator."""
    import backup_validator as bv
    import backups as _b
    if FIXTURE_CLOUD is None or not FIXTURE_CLOUD.is_dir():
        record("corrupt_postgresql_dump",
               "a corrupted pg_dump must fail dump parsing",
               False, "cloud fixture unavailable in this sandbox")
        return
    root = fresh_copy(sandbox, FIXTURE_CLOUD, "corrupt-pgdump")
    dump = root / "database" / "nextcloud.pgdump"
    blob = bytearray(dump.read_bytes())
    blob[2048:6144] = b"\xde\xad\xbe\xef" * 1024
    dump.write_bytes(bytes(blob))
    _b.write_manifest(root)
    report = bv.validate_restore_point(root, node="cloud")
    failed = {c["name"] for c in report["failures"]}
    record("corrupt_postgresql_dump",
           "a corrupted pg_dump must fail full-dump parsing even with a valid checksum",
           "postgres_dump_parses" in failed and report["level"] != "VERIFIED",
           f"level={report['level']}, failed={sorted(failed)}",
           evidence="also independently rejected during the Phase 3 restore lab "
                    "(restore-results.json negative_pg_dump.rejected=true)")


# --------------------------------------------------------------------------- job control

def job_control_scenarios(sandbox):
    db_path = sandbox / "throwaway-backups.db"
    lock_path = sandbox / "throwaway-backup.lock"
    os.environ["BACKUPS_DB"] = str(db_path)
    os.environ["BACKUP_LOCK_PATH"] = str(lock_path)

    for module in ("backups", "backup_job"):
        sys.modules.pop(module, None)
    import backups
    import backup_job
    backup_job.LOCK_PATH = lock_path

    backups.enqueue_backup("pi", db_path=db_path)
    try:
        backups.enqueue_backup("pi", db_path=db_path)
        record("duplicate_backup_invocation",
               "a second backup must not be enqueued while one is queued or running",
               False, "a duplicate job was accepted")
    except RuntimeError as error:
        record("duplicate_backup_invocation",
               "a second backup must not be enqueued while one is queued or running",
               True, f"RuntimeError: {error}", evidence=str(db_path))

    with backup_job.global_lock():
        try:
            with backup_job.global_lock():
                record("lock_contention",
                       "a concurrent job must be refused the exclusive backup lock",
                       False, "the lock was acquired twice at once")
        except RuntimeError as error:
            record("lock_contention",
                   "a concurrent job must be refused the exclusive backup lock",
                   True, f"RuntimeError: {error}", evidence=str(lock_path))

    # Orphan active record left behind by a job that died mid-flight.
    import backup_validator as bv
    stale_started = (datetime.now(timezone.utc) - timedelta(hours=11)).isoformat()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO backups(backup_id,started_at,source_node,destination_node,backup_type,status,phase) "
            "VALUES (?,?,?,?,?,?,?)",
            ("20260101T000000Z-pi-full-bbbbbb", stale_started, "pi", "pcold", "full", "running", "Transferring"))
    records_ = backups.list_backups(50, db_path=db_path)
    stuck = bv.stuck_jobs(records_)
    summary = backups.backup_summary(db_path=db_path)
    record("orphan_running_record",
           "a job stuck in running for 11h must be reported as stuck, not as a success",
           any(s["backup_id"] == "20260101T000000Z-pi-full-bbbbbb" for s in stuck)
           and summary["nodes"]["pi"]["status"] != "success",
           f"stuck_jobs reported {len(stuck)} record(s); pi node status="
           f"{summary['nodes']['pi']['status']}",
           evidence=json.dumps(stuck))

    flow = bv.flow_state(records_, "pi")
    record("orphan_record_does_not_fake_assurance",
           "an unfinished job must not raise the flow's assurance level",
           flow["assurance_level"] == "NONE" and flow["freshness"] == "unknown",
           f"assurance_level={flow['assurance_level']}, freshness={flow['freshness']}")

    os.environ.pop("BACKUPS_DB", None)
    os.environ.pop("BACKUP_LOCK_PATH", None)
    for module in ("backups", "backup_job", "backup_validator"):
        sys.modules.pop(module, None)


def ssh_scenario():
    """Peer unreachable. 192.0.2.1 is reserved TEST-NET-1; no live network path is touched."""
    import importlib
    import backup_job
    importlib.reload(backup_job)
    original = backup_job.PCOLD_HOSTS
    backup_job.PCOLD_HOSTS = ("192.0.2.1", "192.0.2.2")
    try:
        host = backup_job.choose_pcold_host()
        record("ssh_backup_target_unreachable",
               "an unreachable backup peer must raise, not silently pick a local fallback",
               False, f"choose_pcold_host returned {host}")
    except RuntimeError as error:
        record("ssh_backup_target_unreachable",
               "an unreachable backup peer must raise, not silently pick a local fallback",
               True, f"RuntimeError: {str(error)[:200]}",
               evidence="hosts replaced with RFC 5737 TEST-NET-1 addresses in-process only")
    finally:
        backup_job.PCOLD_HOSTS = original


def describe_scenarios():
    """List what a confirmed run would exercise, without touching anything."""
    print("Scenarios this harness would run against COPIES of the given fixtures:")
    for group in (storage_scenarios, artifact_scenarios, pgdump_scenario,
                  job_control_scenarios, ssh_scenario):
        print(f"  - {group.__name__}")
    print("\nEach one corrupts a throwaway copy and asserts the validator rejects it.")
    print("Production restore points are never opened for writing.")


def main(argv=None):
    ap = parser(__doc__)
    add_safety_args(ap, needs_lab=True)
    args = ap.parse_args(argv)

    if not require_confirmation(
            args,
            "would copy each --fixture into --lab, corrupt the copy, and assert "
            "the backup validator refuses to call it good"):
        describe_scenarios()
        return 0

    try:
        lab = resolve_lab(args)
    except LabGuardError as exc:
        print(f"ABORT: {exc}")
        return 2

    global FIXTURE_PCOLD, FIXTURE_CLOUD
    FIXTURE_PCOLD = Path(args.fixture[0])
    FIXTURE_CLOUD = Path(args.fixture[1]) if len(args.fixture) > 1 else None

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sandbox = lab / stamp
    sandbox.mkdir(parents=True)
    print(f"sandbox: {sandbox}\n")

    for step in (storage_scenarios,):
        try:
            step()
        except Exception:
            record(step.__name__, "harness must complete", False, traceback.format_exc()[-400:])
    for step in (artifact_scenarios, pgdump_scenario, job_control_scenarios):
        try:
            step(sandbox)
        except Exception:
            record(step.__name__, "harness must complete", False, traceback.format_exc()[-400:])
    try:
        ssh_scenario()
    except Exception:
        record("ssh_scenario", "harness must complete", False, traceback.format_exc()[-400:])

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sandbox": str(sandbox),
        "fixtures": [str(f) for f in args.fixture],
        "production_touched": False,
        "scenarios_run": len(RESULTS),
        "passed": sum(1 for r in RESULTS if r["result"] == "PASS"),
        "failed": sum(1 for r in RESULTS if r["result"] == "FAIL"),
        "results": RESULTS,
    }
    write_results("failure-sim-results.json", report)
    print(f"\n{report['passed']}/{report['scenarios_run']} scenarios passed")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
