import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from http.server import ThreadingHTTPServer
from threading import Thread
import requests

import app
from events import get_events, process_snapshot
import incidents
from incidents import get_incidents, import_external, sync_external
from watchdog_pcold import watchdog
from test_events import snapshot


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "metrics.db"
        self.now = int(time.time())

    def tearDown(self):
        self.temp.cleanup()

    def test_down_recovery_pair_and_duration(self):
        healthy = snapshot()
        down = snapshot(pc_online=False, docker=False)
        process_snapshot(healthy, baseline=True, db_path=self.db, now=self.now)
        self.assertEqual(get_incidents(db_path=self.db)["incidents"], [])
        process_snapshot(down, db_path=self.db, now=self.now + 60)
        process_snapshot(down, db_path=self.db, now=self.now + 120)
        active = get_incidents(status="active", db_path=self.db)["incidents"]
        self.assertEqual(len(active), 2)
        self.assertEqual(len(get_events(db_path=self.db)["events"]), 2)
        process_snapshot(healthy, db_path=self.db, now=self.now + 180)
        resolved = get_incidents(status="resolved", db_path=self.db)["incidents"]
        self.assertEqual(len(resolved), 2)
        self.assertTrue(all(item["duration_seconds"] == 120 for item in resolved))
        self.assertEqual(len(get_events(db_path=self.db)["events"]), 4)

    def test_threshold_escalation_keeps_one_incident_and_peak_severity(self):
        process_snapshot(snapshot(), baseline=True, db_path=self.db, now=self.now)
        for minute, temperature in enumerate(("72 °C", "83 °C", "75 °C"), 1):
            process_snapshot(snapshot(temp=temperature), db_path=self.db, now=self.now + minute * 60)
        active = get_incidents(status="active", source="pi5", db_path=self.db)["incidents"]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["severity"], "critical")
        process_snapshot(snapshot(temp="65 °C"), db_path=self.db, now=self.now + 240)
        resolved = get_incidents(status="resolved", source="pi5", db_path=self.db)["incidents"]
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["duration_seconds"], 180)

    def test_external_import_is_idempotent_and_updates_recovery(self):
        payload = {"incidents": [{"external_event_id": "pcold-watchdog-20260913T154211Z-a1b2c3d4", "detected_at": "2026-09-13T15:42:11+00:00", "recovered_at": None, "event_type": "device_offline", "state": "down"}]}
        self.assertEqual(import_external(payload, self.db), 1)
        self.assertEqual(import_external(payload, self.db), 0)
        self.assertEqual(len(get_incidents(db_path=self.db)["incidents"]), 1)
        payload["incidents"][0]["recovered_at"] = "2026-09-13T15:45:37+00:00"
        payload["incidents"][0]["duration_seconds"] = 206
        payload["incidents"][0]["state"] = "recovered"
        self.assertEqual(import_external(payload, self.db), 1)
        self.assertEqual(import_external(payload, self.db), 0)
        record = get_incidents(db_path=self.db)["incidents"][0]
        self.assertEqual(record["status"], "resolved")
        self.assertEqual(record["duration_seconds"], 206)
        self.assertEqual([row["severity"] for row in get_events(db_path=self.db)["events"]], ["recovery", "critical"])

    def test_external_sync_uses_backend_and_two_second_timeout(self):
        payload = {"incidents": [{"external_event_id": "pcold-watchdog-20260913T154211Z-a1b2c3d4", "detected_at": "2026-09-13T15:42:11+00:00", "recovered_at": None, "event_type": "device_offline", "state": "down"}]}
        response = Mock(status_code=200, json=lambda: payload)
        with patch("incidents.requests.get", return_value=response) as get:
            self.assertEqual(sync_external(self.db), 1)
            self.assertEqual(sync_external(self.db), 0)
            # Adres conftest.py'nin enjekte ettigi dokumantasyon degerinden turer;
            # test production ag yapilandirmasina baglanmasin diye sabit yazilmaz.
            get.assert_called_with(incidents.WATCHDOG_URL, timeout=2, allow_redirects=False)
        self.assertEqual(len(get_incidents(db_path=self.db)["incidents"]), 1)

    def test_api_validation(self):
        with patch("app.get_incidents", return_value={"incidents": []}):
            client = app.app.test_client()
            self.assertEqual(client.get("/api/incidents").status_code, 200)
            self.assertEqual(client.get("/api/incidents?status=bad").status_code, 400)
            self.assertEqual(client.get("/api/incidents?limit=0").status_code, 400)


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "events.db"
        self.now = int(time.time())

    def tearDown(self):
        self.temp.cleanup()

    def test_read_only_local_endpoint(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), watchdog.Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(watchdog, "list_incidents", return_value=[]):
                url = f"http://127.0.0.1:{server.server_port}/incidents"
                self.assertEqual(requests.get(url, timeout=2).json(), {"incidents": []})
                self.assertEqual(requests.post(url, timeout=2).status_code, 501)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_three_failures_then_recovery_survives_reopen(self):
        self.assertEqual(watchdog.observe(True, now=self.now, db_path=self.db), "up")
        self.assertEqual(watchdog.observe(False, now=self.now + 60, db_path=self.db), "pending")
        self.assertEqual(watchdog.observe(False, now=self.now + 120, db_path=self.db), "pending")
        self.assertEqual(watchdog.observe(False, now=self.now + 180, db_path=self.db), "down")
        self.assertEqual(watchdog.observe(False, now=self.now + 240, db_path=self.db), "down")
        self.assertEqual(len(watchdog.list_incidents(self.db)), 1)
        self.assertEqual(watchdog.observe(True, now=self.now + 300, db_path=self.db), "recovered")
        rows = watchdog.list_incidents(self.db)
        self.assertEqual(rows[0]["state"], "recovered")
        self.assertEqual(rows[0]["duration_seconds"], 120)
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
