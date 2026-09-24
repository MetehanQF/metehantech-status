"""Tests for the backup assurance model, its checks, and its flow reporting.

Fixtures are synthesised in a temporary directory, so these tests neither read
nor touch any real restore point, the live metadata database, or a live mount.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import backups
import backup_validator as bv


def build_restore_point(root, node="pcold", created=None, backup_id=None, payloads=None):
    """A minimal but genuinely valid restore point: real zstd archives, real SQLite."""
    created = created or datetime.now(timezone.utc)
    stamp = created.strftime("%Y%m%dT%H%M%SZ")
    backup_id = backup_id or f"{stamp}-{node}-full-abc123"
    target = Path(root) / backup_id
    target.mkdir(parents=True)

    payloads = payloads if payloads is not None else bv.REQUIRED_PAYLOADS[node]
    for relative in payloads:
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".db":
            with sqlite3.connect(path) as connection:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
                connection.executemany("INSERT INTO t(v) VALUES (?)", [(f"row{i}",) for i in range(50)])
        elif path.name.endswith(".tar.zst"):
            with tempfile.TemporaryDirectory() as staging:
                filler = Path(staging) / "payload.txt"
                filler.write_text("content " * 200)
                subprocess.run(["tar", "--zstd", "-cf", str(path), "-C", staging, "payload.txt"],
                               check=True, capture_output=True, timeout=60)
        elif path.suffix == ".pgdump":
            path.write_bytes(b"PGDMP" + b"\x00" * 1024)
        else:
            path.write_text(json.dumps({"placeholder": True, "padding": "x" * 64}))

    (target / "metadata.json").write_text(json.dumps({
        "format_version": 1, "source_node": node, "created_at": created.isoformat(),
    }, indent=2))
    backups.write_manifest(target)
    return target


def level_of(target, **kwargs):
    kwargs.setdefault("deep", True)
    return bv.validate_restore_point(target, **kwargs)


class AssuranceModelTests(unittest.TestCase):
    """The three levels must stay distinct; a cheap check must never imply an expensive one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_clean_restore_point_stops_at_verified_without_restore_evidence(self):
        target = build_restore_point(self.root)
        report = level_of(target, node="pcold")
        self.assertEqual(report["level"], "VERIFIED")
        self.assertEqual(report["failed"], 0)

    def test_attestation_naming_this_backup_reaches_restore_tested(self):
        target = build_restore_point(self.root)
        report = level_of(target, node="pcold", attestations={
            target.name: {"components": ["uptime_kuma"], "tested_at": "2026-09-19T20:49:33Z",
                          "source": "restore-results.json"}})
        self.assertEqual(report["level"], "RESTORE_TESTED")

    def test_attestation_naming_a_different_backup_does_not_promote(self):
        target = build_restore_point(self.root)
        report = level_of(target, node="pcold", attestations={
            "20260101T000000Z-pcold-full-ffffff": {"components": ["x"], "tested_at": "y"}})
        self.assertEqual(report["level"], "VERIFIED")

    def test_shallow_validation_cannot_claim_verified(self):
        target = build_restore_point(self.root)
        report = level_of(target, node="pcold", deep=False)
        self.assertEqual(report["level"], "TRANSFER_SUCCESS")
        self.assertIn("deep_verification", {c["name"] for c in report["failures"]})

    def test_corruption_keeps_transfer_success_but_blocks_verified(self):
        """A backup that arrived but cannot be read is not 'partially fine'."""
        target = build_restore_point(self.root)
        database = target / "databases" / "uptime-kuma.db"
        blob = bytearray(database.read_bytes())
        blob[4096:8192] = b"\x00" * 4096
        database.write_bytes(bytes(blob))
        backups.write_manifest(target)
        report = level_of(target, node="pcold")
        self.assertEqual(report["level"], "TRANSFER_SUCCESS")
        self.assertIn("sqlite_integrity", {c["name"] for c in report["failures"]})


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_invalid_backup_id_directory_is_rejected_outright(self):
        target = build_restore_point(self.root)
        renamed = target.parent / "not-a-backup-id"
        target.rename(renamed)
        report = level_of(renamed, node="pcold")
        self.assertEqual(report["level"], "NONE")
        self.assertIn("backup_id_format", {c["name"] for c in report["failures"]})

    def test_metadata_source_node_must_match_the_id(self):
        target = build_restore_point(self.root, node="pcold")
        metadata = json.loads((target / "metadata.json").read_text())
        metadata["source_node"] = "pi"
        (target / "metadata.json").write_text(json.dumps(metadata))
        backups.write_manifest(target)
        report = level_of(target, node="pcold")
        self.assertIn("source_identity", {c["name"] for c in report["failures"]})

    def test_caller_node_expectation_mismatch_is_rejected(self):
        target = build_restore_point(self.root, node="pcold")
        report = level_of(target, node="pi")
        self.assertIn("node_identity", {c["name"] for c in report["failures"]})

    def test_future_dated_backup_is_rejected(self):
        future = datetime.now(timezone.utc) + timedelta(days=3)
        target = build_restore_point(self.root, created=future)
        report = level_of(target, node="pcold")
        self.assertEqual(report["level"], "NONE")
        self.assertIn("timestamp_not_future", {c["name"] for c in report["failures"]})

    def test_metadata_timestamp_drifting_from_the_id_is_rejected(self):
        created = datetime.now(timezone.utc)
        target = build_restore_point(self.root, created=created)
        metadata = json.loads((target / "metadata.json").read_text())
        metadata["created_at"] = (created - timedelta(hours=4)).isoformat()
        (target / "metadata.json").write_text(json.dumps(metadata))
        backups.write_manifest(target)
        report = level_of(target, node="pcold")
        self.assertIn("timestamp_consistent", {c["name"] for c in report["failures"]})

    def test_staging_directory_is_never_a_completed_backup(self):
        staging = self.root / ".staging"
        staging.mkdir()
        target = build_restore_point(staging)
        report = level_of(target, node="pcold")
        self.assertEqual(report["level"], "NONE")
        self.assertIn("restore_point_finalized", {c["name"] for c in report["failures"]})


class PayloadContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_missing_required_payload_fails(self):
        target = build_restore_point(self.root)
        (target / "databases" / "watchdog-events.db").unlink()
        backups.write_manifest(target)
        report = level_of(target, node="pcold")
        self.assertIn("required_payloads", {c["name"] for c in report["failures"]})

    def test_implausibly_small_payload_fails(self):
        target = build_restore_point(self.root)
        (target / "databases" / "watchdog-events.db").write_bytes(b"tiny")
        backups.write_manifest(target)
        report = level_of(target, node="pcold")
        self.assertIn("required_payloads", {c["name"] for c in report["failures"]})

    def test_absent_optional_payload_warns_instead_of_failing(self):
        """An optional source that legitimately disappeared must not destroy the backup."""
        target = build_restore_point(self.root, node="pi")
        report = level_of(target, node="pi")
        warned = {c["name"] for c in report["warnings"]}
        self.assertIn("expected_optional_payloads", warned)
        self.assertNotIn("expected_optional_payloads", {c["name"] for c in report["failures"]})
        self.assertEqual(report["level"], "VERIFIED")

    def test_present_optional_payload_passes_cleanly(self):
        payloads = list(bv.REQUIRED_PAYLOADS["pi"]) + list(bv.EXPECTED_OPTIONAL["pi"])
        target = build_restore_point(self.root, node="pi", payloads=payloads)
        report = level_of(target, node="pi")
        self.assertEqual(report["warnings"], [])
        self.assertEqual(report["level"], "VERIFIED")


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = build_restore_point(self.root)

    def failures(self):
        return {c["name"] for c in level_of(self.target, node="pcold")["failures"]}

    def test_altered_payload_breaks_the_checksum(self):
        payload = self.target / "pcold-applications.tar.zst"
        blob = bytearray(payload.read_bytes())
        blob[-1] ^= 0xFF
        payload.write_bytes(bytes(blob))
        self.assertIn("checksums_match", self.failures())

    def test_file_present_but_unmanifested_is_caught(self):
        (self.target / "smuggled.bin").write_bytes(b"x" * 64)
        self.assertIn("manifest_complete", self.failures())

    def test_symlink_is_rejected_not_followed(self):
        (self.target / "escape").symlink_to("/etc/passwd")
        self.assertIn("no_symlinks", self.failures())

    def test_path_traversal_entry_is_rejected(self):
        manifest = self.target / "SHA256SUMS"
        manifest.write_text(manifest.read_text() + f"{'0' * 64}  ../../etc/passwd\n")
        self.assertIn("manifest_wellformed", self.failures())

    def test_malformed_digest_is_rejected(self):
        manifest = self.target / "SHA256SUMS"
        manifest.write_text(manifest.read_text() + "nothexadecimal  metadata.json\n")
        self.assertIn("manifest_wellformed", self.failures())

    def test_empty_manifest_is_rejected(self):
        (self.target / "SHA256SUMS").write_text("")
        self.assertIn("manifest_nonempty", self.failures())

    def test_missing_manifest_is_rejected(self):
        (self.target / "SHA256SUMS").unlink()
        self.assertIn("manifest_present", self.failures())

    def test_empty_wal_and_shm_beside_a_manifested_db_are_tolerated(self):
        """The legacy PcOld verifier leaves these behind; they carry no data."""
        database = self.target / "databases" / "uptime-kuma.db"
        (database.parent / (database.name + "-wal")).write_bytes(b"")
        (database.parent / (database.name + "-shm")).write_bytes(b"\x00" * 32768)
        report = level_of(self.target, node="pcold")
        self.assertEqual(report["level"], "VERIFIED")

    def test_nonempty_wal_is_treated_as_unmanifested_data(self):
        database = self.target / "databases" / "uptime-kuma.db"
        (database.parent / (database.name + "-wal")).write_bytes(b"real wal data" * 64)
        self.assertIn("manifest_complete", self.failures())

    def test_corrupt_archive_fails_listing(self):
        payload = self.target / "pcold-applications.tar.zst"
        blob = bytearray(payload.read_bytes())
        blob[10:60] = b"\x00" * 50
        payload.write_bytes(bytes(blob))
        backups.write_manifest(self.target)
        self.assertIn("archive_integrity", self.failures())


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_stale_backup_warns_but_stays_verified(self):
        """Stale is a reporting problem, not an integrity problem. Do not conflate them."""
        old = datetime.now(timezone.utc) - timedelta(days=9)
        target = build_restore_point(self.root, created=old)
        report = level_of(target, node="pcold", max_age_hours=36)
        self.assertEqual(report["level"], "VERIFIED")
        self.assertIn("freshness", {c["name"] for c in report["warnings"]})

    def test_fresh_backup_does_not_warn(self):
        target = build_restore_point(self.root)
        report = level_of(target, node="pcold", max_age_hours=36)
        self.assertNotIn("freshness", {c["name"] for c in report["warnings"]})


class StuckJobTests(unittest.TestCase):
    def record(self, status, hours):
        return {"backup_id": f"2026010{hours % 10}T000000Z-pi-full-aaaaaa", "status": status,
                "phase": "Transferring",
                "started_at": (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()}

    def test_long_running_job_is_reported_stuck(self):
        stuck = bv.stuck_jobs([self.record("running", 11)])
        self.assertEqual(len(stuck), 1)
        self.assertGreater(stuck[0]["age_hours"], 6)

    def test_recent_job_is_not_reported_stuck(self):
        self.assertEqual(bv.stuck_jobs([self.record("running", 1)]), [])

    def test_finished_jobs_are_never_stuck(self):
        self.assertEqual(bv.stuck_jobs([{**self.record("success", 99), "status": "success"}]), [])

    def test_unparseable_start_time_is_surfaced_not_swallowed(self):
        stuck = bv.stuck_jobs([{"backup_id": "x", "status": "running", "started_at": "not-a-date"}])
        self.assertEqual(len(stuck), 1)
        self.assertIsNone(stuck[0]["age_hours"])


class FlowStateTests(unittest.TestCase):
    def record(self, **overrides):
        base = {"backup_id": "20260919T212329Z-pi-full-a408a6", "source_node": "pi",
                "destination_node": "pcold", "status": "success", "phase": "Completed",
                "checksum_status": "verified", "verification_status": "verified",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "size_bytes": 1947282, "files_count": 13, "restore_point_path": "ssh://x",
                "error_summary": None}
        return {**base, **overrides}

    def test_recent_failure_does_not_erase_the_last_verified_success(self):
        failure = self.record(backup_id="20260920T000000Z-pi-full-bbbbbb", status="failed",
                              verification_status="failed", error_summary="peer unreachable")
        flow = bv.flow_state([failure, self.record()], "pi")
        self.assertEqual(flow["last_attempt"]["status"], "failed")
        self.assertEqual(flow["last_verified"]["backup_id"], "20260919T212329Z-pi-full-a408a6")
        self.assertEqual(flow["assurance_level"], "VERIFIED")

    def test_recent_failure_does_not_read_as_healthy(self):
        failure = self.record(status="failed", verification_status="failed")
        flow = bv.flow_state([failure], "pi")
        self.assertEqual(flow["assurance_level"], "NONE")
        self.assertEqual(flow["freshness"], "unknown")

    def test_freshness_bands(self):
        for hours, expected in ((1, "ok"), (23.9, "ok"), (30, "warning"), (40, "critical")):
            finished = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            flow = bv.flow_state([self.record(finished_at=finished)], "pi", max_age_hours=36)
            self.assertEqual(flow["freshness"], expected, f"{hours}h should be {expected}")

    def test_no_records_for_a_flow_reports_unknown_not_healthy(self):
        flow = bv.flow_state([], "cloud")
        self.assertIsNone(flow["last_attempt"])
        self.assertEqual(flow["assurance_level"], "NONE")
        self.assertEqual(flow["freshness"], "unknown")

    def test_attestation_raises_the_flow_to_restore_tested(self):
        flow = bv.flow_state([self.record()], "pi", attestations={
            "20260919T212329Z-pi-full-a408a6": {"components": ["files"], "tested_at": "now"}})
        self.assertEqual(flow["assurance_level"], "RESTORE_TESTED")

    def test_transfer_success_without_verification_is_not_verified(self):
        flow = bv.flow_state([self.record(verification_status="pending")], "pi")
        self.assertEqual(flow["assurance_level"], "TRANSFER_SUCCESS")


class AttestationLoadingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "restore-results.json"

    def test_absent_file_yields_no_attestations(self):
        self.assertEqual(bv.load_attestations(self.path), {})

    def test_malformed_json_yields_no_attestations(self):
        self.path.write_text("{not json")
        self.assertEqual(bv.load_attestations(self.path), {})

    def test_results_without_any_restore_tested_component_yield_nothing(self):
        self.path.write_text(json.dumps({
            "cloud_backup_id": "20260918T173345Z-cloud-full-4095c9",
            "portainer": {"status": "SKIPPED", "reason": "no access"}}))
        self.assertEqual(bv.load_attestations(self.path), {})

    def test_restore_tested_components_are_attributed_to_the_named_backup(self):
        self.path.write_text(json.dumps({
            "cloud_backup_id": "20260918T173345Z-cloud-full-4095c9",
            "finished_at": "2026-09-19T20:49:33Z",
            "nextcloud_files": {"status": "RESTORE_TESTED"},
            "nextcloud_database": {"status": "RESTORE_TESTED"},
            "portainer": {"status": "SKIPPED"}}))
        loaded = bv.load_attestations(self.path)
        self.assertEqual(set(loaded), {"20260918T173345Z-cloud-full-4095c9"})
        self.assertEqual(loaded["20260918T173345Z-cloud-full-4095c9"]["components"],
                         ["nextcloud_database", "nextcloud_files"])

    def test_live_restore_results_file_parses_and_names_the_cloud_backup(self):
        # Canli ortam testi: yol yapilandirmadan gelir, kaynak kodda sabit degildir.
        configured = os.environ.get("RESTORE_ATTESTATION", "").strip()
        if not configured:
            self.skipTest("RESTORE_ATTESTATION not configured")
        live = Path(configured)
        if not live.is_file():
            self.skipTest("live restore-results.json not present")
        loaded = bv.load_attestations(live)
        self.assertIn("20260918T173345Z-cloud-full-4095c9", loaded)


if __name__ == "__main__":
    unittest.main()
