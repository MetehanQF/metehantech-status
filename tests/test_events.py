import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app
from events import RETENTION_SECONDS, get_events, process_snapshot


def snapshot(*, pc_online=True, temp="55 °C", ram="20%", disk="30%", docker=True):
    return {
        "devices": [
            {"id": "pi5", "name": "Raspberry Pi 5", "online": True, "metrics": {"temperature": temp, "ram": ram, "disk": disk}, "checks": {"Throttled": False}},
            {"id": "pcold", "name": "MetehanTechPcOld", "online": pc_online, "metrics": {"temperature": "60 °C", "ram": "19%", "disk": "1%"}, "checks": {"Docker": True, "SMART": True}},
        ],
        "services": [{"name": "Docker", "operational": docker}],
    }


class EventTransitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "metrics.db"
        self.now = int(time.time())

    def tearDown(self):
        self.temp.cleanup()

    def test_baseline_down_and_recovery_are_not_duplicated(self):
        healthy = snapshot()
        self.assertEqual(process_snapshot(healthy, baseline=True, db_path=self.db, now=self.now), 0)
        self.assertEqual(get_events(db_path=self.db)["events"], [])
        down = snapshot(docker=False, pc_online=False)
        self.assertEqual(process_snapshot(down, db_path=self.db, now=self.now + 60), 2)
        self.assertEqual(process_snapshot(down, db_path=self.db, now=self.now + 120), 0)
        self.assertEqual(get_events(db_path=self.db)["active_incidents"], 2)
        self.assertEqual(process_snapshot(healthy, db_path=self.db, now=self.now + 180), 2)
        result = get_events(db_path=self.db)
        self.assertEqual(result["active_incidents"], 0)
        self.assertEqual(len(result["events"]), 4)
        self.assertEqual([event["severity"] for event in result["events"]], ["recovery", "recovery", "critical", "critical"])
        self.assertTrue(all(event["status"] == "resolved" for event in result["events"]))
        self.assertEqual(process_snapshot(healthy, baseline=True, db_path=self.db, now=self.now + 240), 0)
        self.assertEqual(len(get_events(db_path=self.db)["events"]), 4)

    def test_threshold_transitions_and_retention(self):
        process_snapshot(snapshot(), baseline=True, db_path=self.db, now=self.now)
        for minute, value in enumerate(("72 °C", "83 °C", "75 °C", "65 °C"), 1):
            process_snapshot(snapshot(temp=value), db_path=self.db, now=self.now + minute * 60)
        rows = get_events(source="pi5", db_path=self.db)["events"]
        self.assertEqual([row["severity"] for row in rows], ["recovery", "warning", "critical", "warning"])
        self.assertEqual(get_events(db_path=self.db)["active_incidents"], 0)
        with sqlite3.connect(self.db) as connection:
            connection.execute("INSERT INTO events(timestamp,severity,source,event_type,title,message,status) VALUES (datetime('now','-31 days'),'info','pi5','test','old','old','informational')")
        process_snapshot(snapshot(temp="65 °C"), db_path=self.db, now=self.now + 300)
        self.assertFalse(any(row["title"] == "old" for row in get_events(db_path=self.db)["events"]))

    def test_ram_disk_smart_throttled_transitions(self):
        healthy = snapshot()
        process_snapshot(healthy, baseline=True, db_path=self.db, now=self.now)
        alert = snapshot(ram="82%", disk="91%")
        alert["devices"][0]["checks"]["Throttled"] = True
        alert["devices"][1]["checks"]["Docker"] = False
        alert["devices"][1]["checks"]["SMART"] = False
        self.assertEqual(process_snapshot(alert, db_path=self.db, now=self.now + 60), 5)
        self.assertEqual(get_events(db_path=self.db)["active_incidents"], 5)
        self.assertEqual(process_snapshot(healthy, db_path=self.db, now=self.now + 120), 5)
        self.assertEqual(get_events(db_path=self.db)["active_incidents"], 0)
        self.assertEqual(len(get_events(severity="recovery", db_path=self.db)["events"]), 5)

    def test_api_validation_and_filters(self):
        with patch("app.get_events", return_value={"events": [], "active_incidents": 0}):
            client = app.app.test_client()
            self.assertEqual(client.get("/api/events").status_code, 200)
            self.assertEqual(client.get("/api/events?limit=201").status_code, 400)
            self.assertEqual(client.get("/api/events?severity=bad").status_code, 400)
            self.assertEqual(client.get("/api/events?source=bad%20value").status_code, 400)


if __name__ == "__main__":
    unittest.main()
