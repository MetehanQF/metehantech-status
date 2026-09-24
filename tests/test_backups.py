import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import backup_job
import backups
from backup import pcold_export, pcold_receiver


class BackupMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "backups.db"
        self.env = patch.dict(os.environ, {"BACKUPS_DB": str(self.db)}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_history_is_wal_persistent_and_global_concurrency_is_rejected(self):
        backup_id = "20260917T190500Z-pi-full-a1b2c3"
        record = backups.enqueue_backup("pi", backup_id=backup_id)
        self.assertEqual(record["status"], "queued")
        with self.assertRaises(RuntimeError):
            backups.enqueue_backup("pcold", backup_id="20260917T190501Z-pcold-full-d4e5f6")
        self.assertEqual(backups.claim_queued("pi")["status"], "running")
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(backups.list_backups()[0]["backup_id"], backup_id)
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_existing_schema_migrates_and_accepts_cloud_without_losing_history(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute("""CREATE TABLE backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT, backup_id TEXT NOT NULL UNIQUE,
                started_at TEXT NOT NULL, finished_at TEXT,
                source_node TEXT NOT NULL CHECK(source_node IN ('pi','pcold')),
                destination_node TEXT NOT NULL CHECK(destination_node IN ('pi','pcold')),
                backup_type TEXT NOT NULL, status TEXT NOT NULL,
                phase TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0,
                files_count INTEGER NOT NULL DEFAULT 0, checksum_status TEXT NOT NULL DEFAULT 'pending',
                verification_status TEXT NOT NULL DEFAULT 'pending', error_summary TEXT, restore_point_path TEXT
            )""")
            connection.execute(
                "INSERT INTO backups(backup_id,started_at,source_node,destination_node,backup_type,status,phase) VALUES(?,?,?,?,?,'success','Completed')",
                ("20260917T190500Z-pi-full-a1b2c3", "2026-09-17T19:05:00+00:00", "pi", "pcold", "full"),
            )
        record = backups.enqueue_backup("cloud", backup_id="20260917T190501Z-cloud-full-d4e5f6")
        self.assertEqual(record["source_node"], "cloud")
        self.assertEqual(record["destination_node"], "pcold")
        self.assertEqual(len(backups.list_backups()), 2)

    def test_sqlite_backup_api_and_integrity_check(self):
        source = self.root / "live.db"
        destination = self.root / "snapshot.db"
        with sqlite3.connect(source) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE values_table(value TEXT)")
            connection.execute("INSERT INTO values_table VALUES ('durable')")
        backups.sqlite_snapshot(source, destination)
        with sqlite3.connect(destination) as connection:
            self.assertEqual(connection.execute("SELECT value FROM values_table").fetchone()[0], "durable")
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_pi_staging_excludes_runtime_secrets_cache_and_backup_roots(self):
        source = self.root / "application"
        (source / ".venv").mkdir(parents=True)
        (source / "__pycache__").mkdir()
        (source / "data").mkdir()
        (source / "metehantech_backups").mkdir()
        (source / "app.py").write_text("app = True\n")
        (source / ".venv" / "private").write_text("exclude")
        (source / "__pycache__" / "app.pyc").write_bytes(b"exclude")
        (source / "metehantech_backups" / "loop.tar").write_bytes(b"exclude")
        live_db = source / "data" / "metrics.db"
        with sqlite3.connect(live_db) as connection:
            connection.execute("CREATE TABLE metric(value INTEGER)")
            connection.execute("INSERT INTO metric VALUES (1)")
        unit = self.root / "example.service"
        unit.write_text("[Service]\nExecStart=/bin/true\n")
        staging = self.root / "work" / "pi"
        backup_job.build_pi_staging(staging, sources=(source,), databases=(live_db,), system_files=(unit,))
        result = backups.verify_restore_point(staging)
        self.assertEqual(result["verification_status"], "verified")
        listing = subprocess.check_output(["tar", "--zstd", "-tf", staging / "applications.tar.zst"], text=True)
        self.assertIn("app.py", listing)
        self.assertNotIn(".venv", listing)
        self.assertNotIn("__pycache__", listing)
        self.assertNotIn("metehantech_backups", listing)
        self.assertNotIn("metrics.db", listing)
        metadata = json.loads((staging / "metadata.json").read_text())
        self.assertEqual(metadata["sensitive_configuration"]["status"], "excluded_sensitive_pending_encryption")
        self.assertTrue((staging / "databases" / "metrics.db").exists())

    def test_cloud_staging_uses_pg_dump_and_excludes_secret_directory(self):
        deploy = self.root / "compose.yaml"
        deploy.write_text("services: {}\n")
        staging = self.root / "work" / "cloud"
        def dump(path):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"PGDMP-test")
        def archive(path):
            Path(path).write_bytes(b"archive")
        def redacted(path):
            Path(path).write_text('{"system":{"secret":"***REMOVED SENSITIVE VALUE***"}}\n')
        with patch("backup_job._postgres_dump", side_effect=dump), \
             patch("backup_job._container_archive", side_effect=archive), \
             patch("backup_job._redacted_system_config", side_effect=redacted), \
             patch("backup_job._occ"), \
            patch("backup_job._archive", side_effect=lambda path, sources: Path(path).write_bytes(b"metadata-archive")):
            backup_job.build_cloud_staging(staging, deployment_sources=(deploy,))
        self.assertTrue((staging / "SHA256SUMS").is_file())
        self.assertTrue((staging / "database" / "nextcloud.pgdump").is_file())
        self.assertTrue((staging / "nextcloud-system-config.redacted.json").is_file())
        metadata = json.loads((staging / "metadata.json").read_text())
        self.assertEqual(metadata["database_format"], "postgresql_custom")
        self.assertIn("--no-owner", metadata["database_restore"])
        self.assertIn("--no-acl", metadata["database_restore"])
        self.assertEqual(metadata["redis"], "excluded_noncritical_cache")
        self.assertEqual(metadata["sensitive_configuration"]["status"], "excluded_sensitive_pending_encryption")

    def test_checksum_and_corrupt_archive_verification_failure(self):
        root = self.root / "restore"
        root.mkdir()
        (root / "metadata.json").write_text('{"format_version":1}\n')
        source = self.root / "source"
        source.mkdir()
        (source / "file.txt").write_text("safe")
        backup_job._archive(root / "files.tar.zst", (source,))
        backups.write_manifest(root)
        self.assertEqual(backups.verify_restore_point(root)["checksum_status"], "verified")
        with (root / "files.tar.zst").open("ab") as stream:
            stream.write(b"corruption")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            backups.verify_restore_point(root)

    def test_arbitrary_manifest_path_is_rejected(self):
        root = self.root / "restore"
        root.mkdir()
        (root / "metadata.json").write_text("{}")
        (root / "SHA256SUMS").write_text("0" * 64 + "  ../escape\n")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            backups.verify_restore_point(root)

    def test_lan_falls_back_to_tailscale(self):
        # Adresler conftest.py'nin enjekte ettigi dokumantasyon degerlerinden
        # turer; test production ag yapilandirmasina baglanmasin diye sabit yazilmaz.
        lan_host, tailscale_host = backup_job.PCOLD_HOSTS

        def remote(host, *args, **kwargs):
            if host == lan_host:
                raise RuntimeError("LAN unavailable")
            return type("Result", (), {"stdout": "ok\n"})()
        with patch("backup_job._remote", side_effect=remote):
            self.assertEqual(backup_job.choose_pcold_host(), tailscale_host)

    def test_incomplete_staging_cleanup_is_confined_to_job_root(self):
        backup_id = "20260917T190500Z-pi-full-a1b2c3"
        work = self.root / "work"
        staging = work / backup_id
        staging.mkdir(parents=True)
        (staging / "partial").write_text("incomplete")
        with patch.object(backup_job, "WORK_ROOT", work):
            backup_job.cleanup_incomplete("pi", backup_id)
        self.assertFalse(staging.exists())
        with self.assertRaises(ValueError):
            backup_job.cleanup_incomplete("pi", "../../etc")


class PcOldExporterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.watchdog = self.root / "events.db"
        self.uptime = self.root / "uptime"
        self.uptime.mkdir()
        self.kuma = self.uptime / "kuma.db"
        for database, table in ((self.watchdog, "events"), (self.kuma, "heartbeat")):
            with sqlite3.connect(database) as connection:
                connection.execute(f"CREATE TABLE {table}(id INTEGER)")
                connection.execute(f"INSERT INTO {table} VALUES (1)")
        (self.uptime / "upload.txt").write_text("attachment")
        self.dashboard = self.root / "dashboard"
        self.dashboard.mkdir()
        (self.dashboard / "app.py").write_text("print('dashboard')\n")
        self.portainer = self.root / "portainer_data"
        self.portainer.mkdir()
        (self.portainer / "portainer.db").write_text("must not be copied")
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        self.patches = [
            patch.object(pcold_export, "STATE_ROOT", self.state),
            patch.object(pcold_export, "REQUEST_FILE", self.state / "requests" / "next"),
            patch.object(pcold_export, "EXPORT_ROOT", self.state / "export"),
            patch.object(pcold_export, "WATCHDOG_DB", self.watchdog),
            patch.object(pcold_export, "UPTIME_ROOT", self.uptime),
            patch.object(pcold_export, "UPTIME_DB", self.kuma),
            patch.object(pcold_export, "ARCHIVE_SOURCES", (self.dashboard,)),
            patch.object(pcold_export, "BACKUP_USER", user),
            patch.object(pcold_export, "BACKUP_GROUP", group),
            patch.object(pcold_export, "EXPORT_OWNER", user),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_successful_pcold_export_uses_sqlite_snapshots_and_excludes_portainer(self):
        backup_id = "20260917T191000Z-pcold-full-a1b2c3"
        pcold_export.export(backup_id)
        final = self.state / "export" / backup_id
        pcold_export.verify(final)
        self.assertTrue((final / "databases" / "watchdog-events.db").exists())
        self.assertTrue((final / "databases" / "uptime-kuma.db").exists())
        all_names = "\n".join(str(path) for path in final.rglob("*"))
        self.assertNotIn("portainer", all_names)
        self.assertEqual(json.loads((final / "metadata.json").read_text())["portainer"], "excluded_pending_supported_export")

    def test_failed_export_cleans_staging_and_creates_no_final(self):
        backup_id = "20260917T191001Z-pcold-full-d4e5f6"
        with patch.object(pcold_export, "archive", side_effect=RuntimeError("archive failed")):
            with self.assertRaises(RuntimeError):
                pcold_export.export(backup_id)
        self.assertFalse((self.state / "export" / ".staging" / backup_id).exists())
        self.assertFalse((self.state / "export" / backup_id).exists())


class ReceiverSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dest = self.root / "destination"
        self.state = self.root / "state"
        self.dest.mkdir()
        self.patches = [
            patch.object(pcold_receiver, "DESTINATION", self.dest),
            patch.object(pcold_receiver, "STATE_ROOT", self.state),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_receiver_rejects_arbitrary_backup_id_and_cleans_bad_staging(self):
        with self.assertRaises(ValueError):
            pcold_receiver.command(["prepare", "../../etc"])
        backup_id = "20260917T190500Z-pi-full-a1b2c3"
        pcold_receiver.command(["prepare", backup_id])
        staging = self.dest / ".staging" / backup_id
        (staging / "metadata.json").write_text("{}")
        (staging / "SHA256SUMS").write_text("bad manifest\n")
        with self.assertRaises(ValueError):
            pcold_receiver.command(["verify-finalize", backup_id])
        self.assertFalse(staging.exists())
        self.assertFalse((self.dest / backup_id).exists())


if __name__ == "__main__":
    unittest.main()
