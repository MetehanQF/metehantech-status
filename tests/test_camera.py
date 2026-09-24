import unittest
from unittest.mock import patch

import camera


class CameraStatusTests(unittest.TestCase):
    def setUp(self):
        camera._state.update({
            "last_motion_count": None,
            "last_motion_at": None,
            "last_recording_marker": None,
            "last_recording_change": None,
            "storage_baseline_used": None,
            "storage_baseline_at": None,
        })

    def test_status_contains_no_stream_urls_or_credentials(self):
        stats = {
            "cameras": {"tapo_c211": {"camera_fps": 5, "reconnects_last_hour": 0, "stalls_last_hour": 0}},
            "service": {"storage": {"/media/frigate/recordings": {"used": 10, "free": 100, "total": 110}}},
        }
        summary = [{"day": "2026-09-19", "hours": [{"events": 0, "motion": 2, "duration": 10}]}]
        with patch("camera.datetime") as dt, patch("camera._tcp_reachable", return_value=True), \
             patch("camera._service_active", return_value=True), patch("camera._mount_identity", return_value=("nfs4", camera.NFS_SOURCE)), \
             patch("camera._json", side_effect=[stats, {"tapo_c211_main": {}, "tapo_c211_sub": {}}, summary]):
            dt.now.return_value.astimezone.return_value.date.return_value.isoformat.return_value = "2026-09-19"
            dt.fromtimestamp.return_value.isoformat.return_value = "timestamp"
            result = camera.get_camera_status(now=1000)
        rendered = repr(result).lower()
        self.assertNotIn("rtsp://", rendered)
        self.assertNotIn("password", rendered)
        self.assertTrue(result["recording"]["active"])
        self.assertTrue(result["nfs"]["mounted"])

    def test_wrong_nfs_source_is_offline(self):
        with patch("camera._tcp_reachable", return_value=True), patch("camera._service_active", return_value=False), \
             patch("camera._mount_identity", return_value=("nfs4", "wrong:/export")):
            result = camera.get_camera_status(now=1000)
        self.assertFalse(result["nfs"]["mounted"])

    def test_mount_identity_prefers_nfs_behind_systemd_automount(self):
        # Kaynak, conftest.py'nin enjekte ettigi dokumantasyon adresinden turer;
        # test production ag yapilandirmasina baglanmasin diye sabit yazilmaz.
        mountinfo = (
            "1 2 0:1 / /mnt/metehantech-camera rw - autofs systemd-1 rw\n"
            f"3 2 0:2 / /mnt/metehantech-camera rw - nfs4 {camera.NFS_SOURCE} rw\n"
        )
        with patch("builtins.open", unittest.mock.mock_open(read_data=mountinfo)):
            self.assertEqual(camera._mount_identity(), ("nfs4", camera.NFS_SOURCE))

    def test_binary_size_parser(self):
        self.assertEqual(camera._size_bytes("756.9MiB"), int(756.9 * 1024**2))
        self.assertIsNone(camera._size_bytes("unknown"))


if __name__ == "__main__":
    unittest.main()
