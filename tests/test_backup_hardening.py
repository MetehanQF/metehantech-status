from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import backup_hardening as hard
import backup_job
import backups
import backup_retention
import backup_schedule


class HardeningTests(unittest.TestCase):
    def test_nfs_missing_mount_wrong_export_and_readonly_are_rejected(self):
        expected = {'target': '/mnt/backup', 'source': '192.0.2.22:/backup', 'fstype': 'nfs4'}
        for row in [dict(hard.LOCAL_STORAGE, options='rw'), dict(expected, source='other:/backup', options='rw'), dict(expected, options='ro')]:
            with self.assertRaises(RuntimeError):
                hard.check_mount({'filesystems': [row]}, expected)
        self.assertEqual(hard.check_mount({'filesystems': [dict(expected, options='rw,relatime')]}, expected)['fstype'], 'nfs4')

    def test_existing_global_lock_excludes_second_process(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(backup_job, 'LOCK_PATH', Path(tmp) / 'lock'):
            with backup_job.global_lock():
                result = subprocess.run(['python3', '-c', 'import fcntl,sys; f=open(sys.argv[1],"a+"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)', str(backup_job.LOCK_PATH)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
            with backup_job.global_lock():
                pass

    def test_snapshot_verification_does_not_create_unmanifested_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'live.db'; dest=root/'snapshot'/'copy.db'
            with sqlite3.connect(source) as c:
                c.execute('PRAGMA journal_mode=WAL');c.execute('CREATE TABLE example(a)');c.execute('INSERT INTO example VALUES (42)')
            backups.sqlite_snapshot(source,dest)
            (dest.parent/'metadata.json').write_text('{}')
            backups.write_manifest(dest.parent)
            before = set(dest.parent.iterdir())
            backups.verify_restore_point(dest.parent)
            self.assertEqual(before, set(dest.parent.iterdir()))
            with sqlite3.connect(f'file:{dest}?immutable=1',uri=True) as c:
                self.assertEqual(c.execute('select a from example').fetchone()[0],42)

    def test_retention_keeps_newest_two_and_four_weekly_without_delete(self):
        now=datetime(2026,9,19,20,tzinfo=timezone.utc)
        rows=[]
        for days in range(70):
            rows.append({'backup_id':str(days),'source_node':'pi','status':'success','checksum_status':'verified','verification_status':'verified','finished_at':(now-timedelta(days=days)).isoformat()})
        result=backup_retention.plan(rows,now)
        self.assertFalse(result['deletion_enabled'])
        keep=set(result['nodes']['pi']['keep'])
        self.assertTrue({str(i) for i in range(7)} <= keep)
        self.assertTrue({'6','13','20','27'} <= keep)
        self.assertIn('69',result['nodes']['pi']['candidates_not_deleted'])
        small=backup_retention.plan(rows[-2:],now)
        self.assertEqual(small['nodes']['pi']['candidates_not_deleted'],[])

    def test_manifest_coverage_and_nonempty_legacy_wal_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(backups, 'verify_restore_point', return_value={'verification_status':'verified'}):
            root=Path(tmp)
            (root/'database').mkdir()
            (root/'database/sample.db').write_bytes(b'x'*512)
            (root/'metadata.json').write_text(json.dumps({'source_node':'pcold','created_at':backups.utc_now()}))
            backups.write_manifest(root)
            (root/'unlisted').write_text('not covered')
            with self.assertRaisesRegex(ValueError,'manifest'):
                hard.strict_verify(root,'pcold')
            (root/'unlisted').unlink()
            (root/'database/sample.db-wal').write_bytes(b'committed data')
            with self.assertRaisesRegex(ValueError,'manifest'):
                hard.strict_verify(root,'pcold')

    def test_cloud_schedule_uses_existing_fixed_runner_under_global_lock(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'BACKUPS_DB':tmp+'/db'}), patch.object(backup_job,'LOCK_PATH',Path(tmp)/'lock'), patch.object(backup_schedule,'log'), patch.object(backup_schedule,'snapshot_assurance'), patch.object(backup_job,'run_cloud_job') as cloud:
            self.assertEqual(backup_schedule.run('cloud'),0)
            cloud.assert_called_once()
            self.assertEqual(cloud.call_args.args[0]['source_node'],'cloud')

    def test_failure_is_recorded_not_success(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'BACKUPS_DB':tmp+'/db'}), patch.object(backup_job,'LOCK_PATH',Path(tmp)/'lock'), patch.object(backup_schedule,'log'), patch.object(backup_job,'run_pi_job',side_effect=ValueError('verification test failure')):
            self.assertEqual(backup_schedule.run('pi'),1)
            r=backups.list_backups()[0]
            self.assertEqual(r['status'],'verification_failed')
            self.assertIsNotNone(r['finished_at'])
            self.assertIsNone(r['restore_point_path'])


if __name__=='__main__': unittest.main()
