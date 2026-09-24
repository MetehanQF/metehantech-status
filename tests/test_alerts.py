import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from alerts import (
    evaluate_camera_health,
    evaluate_snapshot,
    evaluate_cloud_health,
    evaluate_staleness,
    get_alerts,
    suppress_service,
    sync_watchdog_alerts,
)


SERVICES_UP = {
    "metehantech-status.service": True,
    "metehantech-home.service": True,
    "clan-web.service": True,
}


def snapshot(*, temp="55 °C", ram="20%", disk="30%", throttled=False,
             pc_online=True, pc_ram="30%", pc_disk="20%", smart=True):
    return {
        "devices": [
            {
                "id": "pi5",
                "name": "Raspberry Pi 5",
                "online": True,
                "metrics": {"temperature": temp, "ram": ram, "disk": disk},
                "checks": {"Throttled": throttled},
            },
            {
                "id": "pcold",
                "name": "MetehanTechPcOld",
                "online": pc_online,
                "metrics": {"temperature": "50 °C", "ram": pc_ram, "disk": pc_disk},
                "checks": {"SMART": smart, "Docker": True},
            },
        ]
    }


class AlertRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.alerts_db = Path(self.temp.name) / "alerts.db"
        self.metrics_db = Path(self.temp.name) / "metrics.db"
        self.cloud_backups_patch = patch(
            "alerts.CLOUD_BACKUPS_DB",
            Path(self.temp.name) / "cloud-backups.db",
        )
        self.cloud_backups_patch.start()
        self.now = 1_800_000_000

    def tearDown(self):
        self.cloud_backups_patch.stop()
        self.temp.cleanup()

    def evaluate(self, data, minute=0, services=None):
        with patch("alerts.evaluate_cloud_health"):
            self._evaluate_isolated(data, minute, services)

    def _evaluate_isolated(self, data, minute, services):
        evaluate_snapshot(
            data,
            service_states=SERVICES_UP if services is None else services,
            db_path=self.alerts_db,
            now=self.now + minute * 60,
        )

    def test_temperature_threshold_crossing_requires_two_samples(self):
        self.evaluate(snapshot(temp="76 °C"), 0)
        self.assertEqual(get_alerts(db_path=self.alerts_db), [])
        self.evaluate(snapshot(temp="76 °C"), 1)
        rows = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "warning")

    def test_warning_escalates_to_critical_then_resolves_without_duplicate(self):
        self.evaluate(snapshot(temp="76 °C"), 0)
        self.evaluate(snapshot(temp="76 °C"), 1)
        self.evaluate(snapshot(temp="83.4 °C"), 2)
        self.evaluate(snapshot(temp="84 °C"), 3)
        active = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["severity"], "critical")
        self.assertEqual(active[0]["last_value"], "84°C")
        self.evaluate(snapshot(temp="71.9 °C"), 4)
        resolved = get_alerts(status="resolved", db_path=self.alerts_db)
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["status"], "resolved")
        self.assertEqual(resolved[0]["duration_seconds"], 180)

    def test_ram_requires_five_consecutive_samples_and_survives_reopen(self):
        for minute in range(4):
            self.evaluate(snapshot(ram="92%"), minute)
        self.assertEqual(get_alerts(db_path=self.alerts_db), [])
        # Every evaluation reconnects SQLite, proving the counter is process-independent.
        self.evaluate(snapshot(ram="92%"), 4)
        rows = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["alert_type"], "ram_usage")

    def test_service_second_failure_alerts_and_running_resolves(self):
        down = dict(SERVICES_UP, **{"clan-web.service": False})
        self.evaluate(snapshot(), 0, down)
        self.assertEqual(get_alerts(db_path=self.alerts_db), [])
        self.evaluate(snapshot(), 1, down)
        rows = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "clan-web.service")
        self.evaluate(snapshot(), 2, SERVICES_UP)
        self.assertEqual(len(get_alerts(status="resolved", db_path=self.alerts_db)), 1)

    def test_planned_restart_grace_suppresses_failures(self):
        down = dict(SERVICES_UP, **{"metehantech-home.service": False})
        suppress_service("metehantech-home.service", seconds=60, now=self.now, db_path=self.alerts_db)
        self.evaluate(snapshot(), 0, down)
        self.assertEqual(get_alerts(db_path=self.alerts_db), [])
        self.evaluate(snapshot(), 2, down)
        self.assertEqual(get_alerts(db_path=self.alerts_db), [])
        self.evaluate(snapshot(), 3, down)
        self.assertEqual(len(get_alerts(status="active", db_path=self.alerts_db)), 1)

    def test_metrics_stale_warning_critical_and_recovery(self):
        with sqlite3.connect(self.metrics_db) as connection:
            connection.execute("CREATE TABLE metrics(timestamp INTEGER, device TEXT)")
            connection.executemany(
                "INSERT INTO metrics(timestamp, device) VALUES (?, ?)",
                [(self.now - 121, "pi5"), (self.now, "pcold")],
            )
        evaluate_staleness(metrics_db_path=self.metrics_db, db_path=self.alerts_db, now=self.now)
        rows = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "warning")
        evaluate_staleness(metrics_db_path=self.metrics_db, db_path=self.alerts_db, now=self.now + 200)
        active = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(len(active), 2)
        collector = next(row for row in active if row["alert_type"] == "collector_stale")
        self.assertEqual(collector["severity"], "critical")
        with sqlite3.connect(self.metrics_db) as connection:
            connection.executemany(
                "INSERT INTO metrics(timestamp, device) VALUES (?, ?)",
                [(self.now + 200, "pi5"), (self.now + 200, "pcold")],
            )
        evaluate_staleness(metrics_db_path=self.metrics_db, db_path=self.alerts_db, now=self.now + 200)
        self.assertEqual(get_alerts(status="active", db_path=self.alerts_db), [])
        self.assertEqual(len(get_alerts(status="resolved", db_path=self.alerts_db)), 2)

    def test_pcold_smart_disk_and_sustained_ram(self):
        for minute in range(5):
            self.evaluate(snapshot(pc_disk="96%", pc_ram="96%", smart=False), minute)
        active = get_alerts(status="active", db_path=self.alerts_db)
        kinds = {row["alert_type"] for row in active if row["source"] == "pcold"}
        self.assertEqual(kinds, {"disk_usage", "ram_usage", "smart_problem"})

    def test_existing_watchdog_incident_is_projected_once_and_resolved(self):
        with sqlite3.connect(self.metrics_db) as connection:
            connection.execute("""
                CREATE TABLE incidents (
                    id INTEGER PRIMARY KEY, started_at TEXT, resolved_at TEXT,
                    duration_seconds INTEGER, status TEXT, external_event_id TEXT
                )
            """)
            connection.execute(
                "INSERT INTO incidents VALUES (1, ?, NULL, NULL, 'active', 'pcold-watchdog-test')",
                ("2027-01-15T08:00:00+00:00",),
            )
        self.assertEqual(sync_watchdog_alerts(incidents_db_path=self.metrics_db, db_path=self.alerts_db), 1)
        self.assertEqual(sync_watchdog_alerts(incidents_db_path=self.metrics_db, db_path=self.alerts_db), 0)
        self.assertEqual(len(get_alerts(db_path=self.alerts_db)), 1)
        with sqlite3.connect(self.metrics_db) as connection:
            connection.execute(
                "UPDATE incidents SET resolved_at=?, duration_seconds=120, status='resolved' WHERE id=1",
                ("2027-01-15T08:02:00+00:00",),
            )
        self.assertEqual(sync_watchdog_alerts(incidents_db_path=self.metrics_db, db_path=self.alerts_db), 1)
        row = get_alerts(db_path=self.alerts_db)[0]
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["duration_seconds"], 120)

    def test_cloud_alerts_require_marker_and_two_failures(self):
        marker = Path(self.temp.name) / ".alerts-enabled"
        root = Path(self.temp.name) / "cloud"
        root.mkdir()
        with patch("alerts._container_healthy", return_value=False), \
             patch("alerts._cloud_backup_active", return_value=False), \
             patch("alerts.subprocess.run", return_value=Mock(returncode=0, stdout="false\n")), \
             patch("alerts.shutil.disk_usage", return_value=Mock(total=100, used=50, free=50)):
            evaluate_cloud_health(db_path=self.alerts_db, now=self.now, marker=marker, root=root)
            self.assertEqual(get_alerts(db_path=self.alerts_db), [])
            marker.touch()
            evaluate_cloud_health(db_path=self.alerts_db, now=self.now, marker=marker, root=root)
            self.assertEqual(get_alerts(db_path=self.alerts_db), [])
            evaluate_cloud_health(db_path=self.alerts_db, now=self.now + 60, marker=marker, root=root)
        active = get_alerts(status="active", db_path=self.alerts_db)
        self.assertEqual(
            {row["alert_type"] for row in active},
            {"nextcloud_unavailable", "database_unavailable", "redis_unavailable"},
        )

    def test_camera_offline_requires_three_failures_and_two_recoveries(self):
        down = {"camera": {"online": False}}
        up = {"camera": {"online": True}}
        for offset in range(2):
            evaluate_camera_health(down, rules={"camera"}, db_path=self.alerts_db, now=self.now + offset * 10)
        self.assertEqual(get_alerts(status="active", db_path=self.alerts_db), [])
        evaluate_camera_health(down, rules={"camera"}, db_path=self.alerts_db, now=self.now + 20)
        self.assertEqual(len(get_alerts(status="active", db_path=self.alerts_db)), 1)
        evaluate_camera_health(up, rules={"camera"}, db_path=self.alerts_db, now=self.now + 30)
        self.assertEqual(len(get_alerts(status="active", db_path=self.alerts_db)), 1)
        evaluate_camera_health(up, rules={"camera"}, db_path=self.alerts_db, now=self.now + 40)
        self.assertEqual(len(get_alerts(status="resolved", db_path=self.alerts_db)), 1)

    def test_camera_disk_thresholds(self):
        snapshot = {"storage": {"free_bytes": 9 * 1024**3, "total_bytes": 210 * 1024**3}}
        evaluate_camera_health(snapshot, rules={"disk"}, db_path=self.alerts_db, now=self.now)
        alert = get_alerts(status="active", db_path=self.alerts_db)[0]
        self.assertEqual(alert["severity"], "critical")
        self.assertIn("emergency", alert["title"])


if __name__ == "__main__":
    unittest.main()
