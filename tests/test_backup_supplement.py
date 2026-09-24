"""Tests for the non-secret coverage extensions added in Resilience v2.

The workspace scanner has one job that matters: never ship a credential, while
still shipping the engineering documentation that merely talks about credentials.
Getting that wrong in either direction is a real failure — over-exclusion produces
an empty archive that looks like coverage, under-exclusion leaks a secret into a
backup that lands on the peer node.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import backup_supplement as supplement


class WorkspaceScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
        return path

    def collect(self):
        files, status = supplement.collect_workspace(self.root)
        return {relative for relative, _ in files}, status

    def test_prose_about_secrets_is_kept(self):
        """Engineering docs discuss secrets constantly; excluding them is not safety."""
        self.write("REPORT.md", "The admin password file is excluded from the backup. "
                                "No token or api_key value is archived. See the secret policy.")
        included, _ = self.collect()
        self.assertIn("REPORT.md", included)

    def test_actual_credential_assignments_are_excluded(self):
        for name, body in (
            ("env.txt", "API_KEY=A1b2C3d4E5f6G7h8"),
            ("conf.yaml", "password: hunter2SuperLong99"),
            ("app.ini", "secret = 0123456789abcdef"),
            ("hdr.txt", 'authorization: "Bearer abcdefghijklmnop"'),
        ):
            with self.subTest(name=name):
                self.write(name, body)
        included, status = self.collect()
        for name in ("env.txt", "conf.yaml", "app.ini", "hdr.txt"):
            self.assertNotIn(name, included)
        excluded = {e["path"] for e in status["excluded"]}
        self.assertEqual(excluded, {"env.txt", "conf.yaml", "app.ini", "hdr.txt"})

    def test_private_key_material_is_excluded(self):
        self.write("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")
        included, _ = self.collect()
        self.assertNotIn("id_ed25519", included)

    def test_credentials_embedded_in_urls_are_excluded(self):
        self.write("camera.md", "Stream at rtsp://admin:somepassword@192.0.2.110/stream1")
        self.write("hook.md", "Endpoint https://user:tokenvalue@example.com/hook")
        included, _ = self.collect()
        self.assertNotIn("camera.md", included)
        self.assertNotIn("hook.md", included)

    def test_short_values_after_a_secret_name_do_not_trigger_exclusion(self):
        """`password: yes` is configuration, not a credential."""
        self.write("flags.yaml", "password: yes\ntoken: no\n")
        included, _ = self.collect()
        self.assertIn("flags.yaml", included)

    def test_uncontent_scannable_directories_are_skipped(self):
        self.write(".git/objects/ab/deadbeef", b"\x00compressed blob")
        self.write("__pycache__/mod.cpython-312.pyc", b"\x00pyc")
        self.write(".venv/lib/thing.py", "x = 1")
        self.write("node_modules/pkg/index.js", "module.exports = {}")
        self.write("keep.md", "ordinary document")
        included, _ = self.collect()
        self.assertEqual(included, {"keep.md"})

    def test_symlinks_are_recorded_and_not_followed(self):
        self.write("real.md", "content")
        (self.root / "link.md").symlink_to("/etc/passwd")
        included, status = self.collect()
        self.assertNotIn("link.md", included)
        self.assertIn("link.md", {e["path"] for e in status["excluded"]})
        self.assertIn("symlink", next(e["reason"] for e in status["excluded"]
                                      if e["path"] == "link.md"))

    def test_oversized_files_are_excluded_with_a_reason(self):
        self.write("huge.bin", b"a" * (supplement.WORKSPACE_MAX_FILE_BYTES + 1))
        included, status = self.collect()
        self.assertNotIn("huge.bin", included)
        self.assertIn("size limit", next(e["reason"] for e in status["excluded"]
                                         if e["path"] == "huge.bin"))

    def test_absent_workspace_is_reported_not_crashed(self):
        files, status = supplement.collect_workspace(self.root / "does-not-exist")
        self.assertEqual(files, [])
        self.assertIn("absent", status["skipped_reason"])

    def test_status_records_a_digest_for_every_included_file(self):
        self.write("a.md", "alpha")
        self.write("nested/b.md", "beta")
        _, status = self.collect()
        self.assertEqual(status["included_count"], 2)
        self.assertEqual({e["path"] for e in status["included"]}, {"a.md", "nested/b.md"})
        for entry in status["included"]:
            self.assertEqual(len(entry["sha256"]), 64)


class WorkspaceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "workspace"
        self.staging = self.root / "staging"
        self.source.mkdir()
        self.staging.mkdir()

    def test_archive_is_listable_and_contains_exactly_the_included_files(self):
        (self.source / "doc.md").write_text("a document mentioning a secret policy")
        (self.source / "leak.env").write_text("TOKEN=abcdefghijklmnop")
        status = supplement.add_workspace(self.staging, self.source)
        archive = self.staging / "openclaw-workspace.tar.zst"
        self.assertTrue(archive.is_file())
        listing = subprocess.check_output(["tar", "--zstd", "-tf", str(archive)],
                                          text=True, timeout=60).split()
        names = {Path(n).name for n in listing if not n.endswith("/")}
        self.assertIn("doc.md", names)
        self.assertNotIn("leak.env", names)
        self.assertEqual(status["included_count"], 1)

    def test_archive_is_written_with_restrictive_permissions(self):
        (self.source / "doc.md").write_text("content")
        supplement.add_workspace(self.staging, self.source)
        mode = (self.staging / "openclaw-workspace.tar.zst").stat().st_mode
        self.assertEqual(oct(mode)[-3:], "600")

    def test_empty_workspace_produces_no_archive_rather_than_an_empty_one(self):
        status = supplement.add_workspace(self.staging, self.source)
        self.assertIsNone(status["archive"])
        self.assertFalse((self.staging / "openclaw-workspace.tar.zst").exists())


class LiveWorkspaceTests(unittest.TestCase):
    """Guard the real workspace: it must be coverable and must not be leaking."""

    def setUp(self):
        # Canli ortam testi: yol deployment yapilandirmasindan gelir. Yapilandirma
        # yoksa (temiz bir klon, CI) test atlanir — kaynak kodda gercek makine
        # yolu fallback'i bilerek birakilmamistir.
        if supplement.WORKSPACE_ROOT is None:
            self.skipTest("OPENCLAW_WORKSPACE not configured")
        if not supplement.WORKSPACE_ROOT.is_dir():
            self.skipTest("live OpenClaw workspace not present")
        self.files, self.status = supplement.collect_workspace()

    def test_live_workspace_yields_a_non_trivial_set_of_files(self):
        self.assertGreater(self.status["included_count"], 10)
        self.assertGreater(self.status["included_bytes"], 10_000)

    def test_core_memory_files_are_covered(self):
        included = {relative for relative, _ in self.files}
        for required in ("AGENTS.md", "SOUL.md", "USER.md", "MEMORY.md"):
            self.assertIn(required, included)

    def test_no_included_file_carries_a_value_bearing_secret(self):
        for relative, data in self.files:
            with self.subTest(path=relative):
                self.assertIsNone(
                    supplement.WORKSPACE_VALUE_BEARING.search(data.decode("utf-8", errors="replace")),
                    f"{relative} would have shipped a credential")


class PayloadContractAlignmentTests(unittest.TestCase):
    """The verifier's fail-closed list and the validator's contract must not drift apart."""

    def test_hardening_and_validator_agree_on_required_pi_payloads(self):
        import backup_hardening
        import backup_validator
        source = Path(backup_hardening.__file__).read_text()
        for payload in backup_validator.REQUIRED_PAYLOADS["pi"]:
            self.assertIn(payload, source,
                          f"{payload} is required by the validator but absent from strict_verify")

    def test_camera_canary_is_optional_not_fail_closed(self):
        import backup_hardening
        import backup_validator
        self.assertIn("databases/camera_canary.db", backup_validator.EXPECTED_OPTIONAL["pi"])
        self.assertNotIn("camera_canary", Path(backup_hardening.__file__).read_text())

    def test_camera_canary_is_actually_configured_as_a_backup_source(self):
        import backup_job
        import deployment
        self.assertIn(deployment.DATA_DIR / "camera_canary.db",
                      backup_job.PI_DATABASES)

    def test_frigate_units_are_configured_as_backup_sources(self):
        import backup_job
        for unit in ("metehantech-frigate.service", "metehantech-camera-pcold-route.service"):
            self.assertIn(Path("/etc/systemd/system") / unit, backup_job.PI_SYSTEM_FILES)


if __name__ == "__main__":
    unittest.main()
