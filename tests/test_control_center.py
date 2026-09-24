import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import control_center as cc
import history
from health_model import worst, freshness, disk_health
from cpu_alerts import evaluate_cpu
from alerts import get_alerts

class ControlCenterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'ADMIN_ACTIVITY_DB':str(self.root/'activity.db'),'ALERTS_DB':str(self.root/'alerts.db'),'BACKUPS_DB':str(self.root/'backups.db')})
        self.env.start();self.client=app.app.test_client()
        self.dbpatch=patch.object(cc,'DB_PATH',self.root/'metrics.db');self.dbpatch.start()
    def tearDown(self):
        self.dbpatch.stop();self.env.stop();self.temp.cleanup()
    def auth(self):
        with self.client.session_transaction() as s:s['admin_authenticated']=True
    def test_new_endpoints_auth_and_fixed_inputs(self):
        for path in ['/api/admin/control-center','/api/admin/control-center/history?device=pi5&range=1h','/api/admin/control-center/camera-preview']:
            self.assertEqual(self.client.get(path).status_code,401)
        self.auth()
        for device in ['pi5;id','../../etc/passwd',"' OR 1=1 --"]:
            self.assertEqual(self.client.get('/api/admin/control-center/history',query_string={'device':device,'range':'1h'}).status_code,400)
        with patch('control_center.requests.get') as run:
            self.assertEqual(self.client.get('/api/admin/control-center/camera-preview?path=/etc/passwd').status_code,400)
            run.assert_not_called()
    def test_missing_collectors_unknown_and_no_500(self):
        self.auth()
        with patch.object(cc,'_snapshot',None), patch.object(cc,'_snapshot_at',None), patch('camera.get_camera_status',return_value={}):
            r=self.client.get('/api/admin/control-center')
        self.assertEqual(r.status_code,200);self.assertEqual(r.json['health'],'UNKNOWN')
    def test_offline_pcold_does_not_crash(self):
        self.auth()
        with patch.object(cc,'_snapshot',{'devices':[{'id':'pcold','online':False,'metrics':{}}]}), patch('camera.get_camera_status',return_value={}):
            r=self.client.get('/api/admin/control-center')
        self.assertEqual(r.status_code,200);self.assertEqual(r.json['health'],'CRITICAL')
    def test_health_precedence_and_staleness(self):
        self.assertEqual(worst(['HEALTHY','UNKNOWN']),'UNKNOWN')
        self.assertEqual(worst(['WARNING','CRITICAL','UNKNOWN']),'CRITICAL')
        self.assertEqual(freshness(121),'WARNING');self.assertEqual(freshness(301),'CRITICAL')
        self.assertEqual(freshness(None),'UNKNOWN');self.assertEqual(disk_health(85),'WARNING');self.assertEqual(disk_health(95),'CRITICAL')
    def test_additive_cpu_migration_and_bounded_history(self):
        path=self.root/'history.db'
        with sqlite3.connect(path) as c:
            c.execute('CREATE TABLE metrics(id INTEGER PRIMARY KEY, timestamp INTEGER, device TEXT,temperature REAL, ram REAL, disk REAL, load REAL, UNIQUE(timestamp,device))')
            c.executemany('INSERT INTO metrics(timestamp,device,ram) VALUES (?,?,?)',[(int(time.time())-i*60,'pi5',40) for i in range(10000)])
        with history.connect(path) as c:self.assertIn('cpu',[r[1] for r in c.execute('PRAGMA table_info(metrics)')])
        rows=history.get_history('pi5','7d',path)
        self.assertLessEqual(len(rows),242);self.assertGreater(len(rows),200);self.assertTrue(all(r['cpu'] is None for r in rows))
    def test_sustained_cpu_gap_and_recovery(self):
        path=self.root/'cpu.db'
        def run(cpu,now):evaluate_cpu({'devices':[{'id':'pi5','online':True,'metrics':{'cpu':cpu}}]},db_path=path,now=now)
        for t in range(1000,1300,60):run(95,t)
        self.assertEqual(get_alerts(status='active',db_path=path),[])
        run(95,1300);self.assertEqual(len(get_alerts(status='active',db_path=path)),1)
        run(30,1360);self.assertEqual(get_alerts(status='active',db_path=path),[])
        run(95,2000);run(95,2400);self.assertEqual(get_alerts(status='active',db_path=path),[])
    def test_docker_restart_burst_is_alert_only_and_recovers(self):
        from docker_alerts import evaluate_restarts
        path=self.root/'docker.db'
        for t,n in [(1000,5),(1060,6),(1120,7)]:evaluate_restarts([{'name':'fixed-container','restart_count':n}],now=t,db_path=path)
        self.assertEqual(get_alerts(status='active',db_path=path),[])
        evaluate_restarts([{'name':'fixed-container','restart_count':8}],now=1180,db_path=path)
        self.assertEqual(len(get_alerts(status='active',db_path=path)),1)
        evaluate_restarts([{'name':'fixed-container','restart_count':8}],now=1500,db_path=path)
        self.assertEqual(get_alerts(status='active',db_path=path),[])

    def test_all_views_render_without_external_assets(self):
        self.auth();r=self.client.get('/admin');self.assertEqual(r.status_code,200)
        for view in ['overview','systems','services','storage','network','alerts','activity','camera','cloud','backups']:
            self.assertIn(('id="view-'+view+'"').encode(),r.data)
        self.assertNotIn(b'<script src="https://',r.data)

if __name__=='__main__': unittest.main()
