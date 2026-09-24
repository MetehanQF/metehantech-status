import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from werkzeug.security import generate_password_hash

import admin
import app
from activity import get_activity


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.password = "correct horse battery staple"
        self.env = patch.dict(os.environ, {
            "ADMIN_PASSWORD_HASH": generate_password_hash(self.password),
            "ADMIN_DOCKER_CONTAINERS": "approved-container",
            "ADMIN_ACTIVITY_DB": os.path.join(self.temp.name, "activity.db"),
            "ALERTS_DB": os.path.join(self.temp.name, "alerts.db"),
            "BACKUPS_DB": os.path.join(self.temp.name, "backups.db"),
        }, clear=False)
        self.env.start()
        admin._attempts.clear()
        app.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        self.client = app.app.test_client()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def login(self):
        self.client.get("/admin/login")
        return self.client.post("/admin/login", data={
            "password": self.password,
            "csrf_token": self.csrf(),
        })

    def test_public_dashboard_and_status_remain_public(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        with patch("app.get_status", return_value={"operational": True}), patch("control_center.build_summary", return_value={"health":"HEALTHY"}), patch("control_center.cached_status", return_value=None):
            response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["operational"])

    def test_all_management_endpoints_require_authentication(self):
        paths = [
            ("get", "/api/admin/resources"),
            ("get", "/api/admin/activity?limit=50"),
            ("get", "/api/admin/alerts?status=active&limit=50"),
            ("get", "/api/admin/alerts/summary"),
            ("get", "/api/admin/camera"),
            ("get", "/api/admin/backups?limit=50"),
            ("get", "/api/admin/backups/summary"),
            ("get", "/api/admin/backups/20260917T190500Z-pi-full-a1b2c3"),
            ("post", "/api/admin/backups/pi/start"),
            ("post", "/api/admin/backups/pcold/start"),
            ("post", "/api/admin/backups/cloud/start"),
            ("get", "/api/admin/cloud/summary"),
            ("post", "/api/admin/backups/20260917T190500Z-pi-full-a1b2c3/verify"),
            ("get", "/api/admin/health"),
            ("get", "/api/admin/services/metehantech-status.service/logs?lines=100"),
            ("post", "/api/admin/services/metehantech-status.service/restart"),
            ("get", "/api/admin/containers/approved-container/logs?lines=100"),
            ("post", "/api/admin/containers/approved-container/restart"),
        ]
        for method, path in paths:
            with self.subTest(path=path):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 401)

    def test_login_requires_valid_password_and_csrf(self):
        self.client.get("/admin/login")
        self.assertEqual(self.client.post("/admin/login", data={"password": self.password}).status_code, 403)
        self.client.get("/admin/login")
        response = self.client.post("/admin/login", data={"password": "wrong", "csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/admin")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"05 / BACKUP CENTER", page.data)
        self.assertIn(b"06 / CLOUD", page.data)
        self.assertIn(b"07 / CAMERA CENTER", page.data)
        self.assertIn(b"08 / ADMIN ACTIVITY", page.data)
        self.assertNotIn(b">Restore<", page.data)

    def test_login_is_rate_limited_after_five_failures(self):
        self.client.get("/admin/login")
        for _ in range(5):
            response = self.client.post("/admin/login", data={
                "password": "wrong",
                "csrf_token": self.csrf(),
            })
            self.assertEqual(response.status_code, 401)
        response = self.client.post("/admin/login", data={
            "password": self.password,
            "csrf_token": self.csrf(),
        })
        self.assertEqual(response.status_code, 429)

    def test_non_whitelisted_names_never_run_commands(self):
        self.login()
        with patch("admin._run") as run:
            response = self.client.post(
                "/api/admin/services/ssh.service/restart",
                headers={"X-CSRF-Token": self.csrf()},
            )
            self.assertEqual(response.status_code, 404)
            response = self.client.get("/api/admin/services/ssh.service/logs?lines=100")
            self.assertEqual(response.status_code, 404)
            response = self.client.post(
                "/api/admin/containers/not-approved/restart",
                headers={"X-CSRF-Token": self.csrf()},
            )
            self.assertEqual(response.status_code, 404)
            run.assert_not_called()

    def test_restart_requires_csrf_and_uses_fixed_argv(self):
        self.login()
        self.assertEqual(self.client.post("/api/admin/services/clan-web.service/restart").status_code, 403)
        completed = Mock(returncode=0, stdout="", stderr="")
        with patch("admin._service_snapshot", return_value=("running", "10")), \
             patch("admin._wait_for_service_restart", return_value=True) as wait, \
             patch("admin._run", return_value=completed) as run:
            response = self.client.post(
                "/api/admin/services/clan-web.service/restart",
                headers={"X-CSRF-Token": self.csrf()},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "MetehanTech Clan restarted successfully.")
        run.assert_called_once_with(["sudo", "-n", "systemctl", "restart", "--no-block", "clan-web.service"])
        wait.assert_called_once_with("clan-web.service", "10")

    def test_log_line_count_is_restricted(self):
        self.login()
        with patch("admin._run") as run:
            self.assertEqual(self.client.get("/api/admin/services/clan-web.service/logs?lines=101").status_code, 400)
            run.assert_not_called()
        completed = Mock(returncode=0, stdout="safe log\n", stderr="")
        with patch("admin._run", return_value=completed) as run:
            response = self.client.get("/api/admin/services/clan-web.service/logs?lines=500")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["log"], "safe log\n")
        run.assert_called_once_with(
            ["journalctl", "-u", "clan-web.service", "-n", "500", "--no-pager", "--output=short-iso"],
            timeout=10,
        )

    def test_activity_is_persistent_and_uses_trusted_cloudflare_ip(self):
        self.client.get("/admin/login")
        response = self.client.post(
            "/admin/login",
            data={"password": self.password, "csrf_token": self.csrf()},
            headers={"CF-Connecting-IP": "203.0.113.42", "User-Agent": "Activity Test/1.0"},
        )
        self.assertEqual(response.status_code, 302)
        entries = get_activity(50)
        self.assertEqual(entries[0]["action"], "login_success")
        self.assertEqual(entries[0]["client_ip"], "203.0.113.42")
        self.assertEqual(entries[0]["user_agent"], "Activity Test/1.0")
        response = self.client.get("/api/admin/activity?limit=50")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["entries"])

    def test_cloudflare_ip_is_ignored_from_non_loopback_peer(self):
        with app.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "198.51.100.7"}, headers={"CF-Connecting-IP": "203.0.113.42"}
        ):
            self.assertEqual(admin._client_ip(), "198.51.100.7")

    def test_self_restart_is_durable_and_uses_no_block(self):
        self.login()
        completed = Mock(returncode=0, stdout="", stderr="")
        with patch("admin._run", return_value=completed) as run:
            response = self.client.post(
                "/api/admin/services/metehantech-status.service/restart",
                headers={"X-CSRF-Token": self.csrf()},
            )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.get_json()["self_restart"])
        run.assert_called_once_with(["sudo", "-n", "systemctl", "restart", "--no-block", "metehantech-status.service"])

    def test_authenticated_alert_api_and_filter_validation(self):
        self.login()
        with patch("admin.get_alerts", return_value=[]) as get:
            response = self.client.get("/api/admin/alerts?status=active&severity=critical&limit=100")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["alerts"], [])
        get.assert_called_once_with(status="active", severity="critical", limit=100)
        self.assertEqual(self.client.get("/api/admin/alerts?status=bad&limit=50").status_code, 400)
        self.assertEqual(self.client.get("/api/admin/alerts?limit=51").status_code, 400)

    def test_authenticated_camera_api_is_secret_free(self):
        self.login()
        payload = {
            "camera": {"name": "Tapo C211", "online": True},
            "frigate": {"running": True, "api_healthy": True},
            "go2rtc": {"healthy": True},
            "recording": {"active": True},
            "nfs": {"mounted": True},
            "storage": {"used_bytes": 1, "free_bytes": 2},
        }
        with patch("admin.get_camera_status", return_value=payload):
            response = self.client.get("/api/admin/camera")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["camera"]["name"], "Tapo C211")
        self.assertNotIn("rtsp", response.get_data(as_text=True).lower())

    def test_backup_start_requires_csrf_and_uses_exact_unit(self):
        self.login()
        self.assertEqual(self.client.post("/api/admin/backups/pi/start").status_code, 403)
        self.assertEqual(self.client.post("/api/admin/backups/20260917T190500Z-pi-full-a1b2c3/verify").status_code, 403)
        self.assertEqual(self.client.post("/api/admin/backups/unapproved/start", headers={"X-CSRF-Token": self.csrf()}).status_code, 404)
        record = {
            "backup_id": "20260917T190500Z-pi-full-a1b2c3",
            "status": "queued",
            "source_node": "pi",
        }
        completed = Mock(returncode=0, stdout="", stderr="")
        with patch("admin.enqueue_backup", return_value=record) as enqueue, patch("admin._run", return_value=completed) as run:
            response = self.client.post("/api/admin/backups/pi/start", headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 202)
        enqueue.assert_called_once_with("pi")
        run.assert_called_once_with(["sudo", "-n", "systemctl", "start", "--no-block", "metehantech-backup-pi.service"])
        cloud_record = {
            "backup_id": "20260917T190501Z-cloud-full-d4e5f6",
            "status": "queued",
            "source_node": "cloud",
        }
        with patch("admin.enqueue_backup", return_value=cloud_record) as enqueue, patch("admin._run", return_value=completed) as run:
            response = self.client.post("/api/admin/backups/cloud/start", headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 202)
        enqueue.assert_called_once_with("cloud")
        run.assert_called_once_with(["sudo", "-n", "systemctl", "start", "--no-block", "metehantech-backup-cloud.service"])

    def test_backup_concurrency_and_arbitrary_id_are_rejected(self):
        self.login()
        with patch("admin.enqueue_backup", side_effect=RuntimeError("A backup job is already queued or running")), patch("admin._run") as run:
            response = self.client.post("/api/admin/backups/pcold/start", headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 409)
        run.assert_not_called()
        self.assertEqual(self.client.get("/api/admin/backups/..%2F..%2Fetc%2Fpasswd").status_code, 404)

    def test_authenticated_backup_api(self):
        self.login()
        response = self.client.get("/api/admin/backups?limit=50")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["backups"], [])
        summary = self.client.get("/api/admin/backups/summary")
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.get_json()["sensitive_configuration"], "NOT ENABLED")


if __name__ == "__main__":
    unittest.main()
