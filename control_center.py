"""Authenticated presentation over existing collectors and stores; no control runner."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
import time

import psutil
import requests
from flask import Blueprint, jsonify, request, Response
from admin import admin_required
from health_model import worst, freshness, disk_health
from history import DB_PATH, RANGES, get_history
# 'network' bu modulde yerel bir degisken adi (satir 211), bu yuzden
# config modulu takma adla alinir.
import network as netcfg

control = Blueprint('control_center', __name__)
LOG = logging.getLogger(__name__)
_lock = threading.Lock()
_snapshot = None
_snapshot_at = None
_extra = {}


def _probe(url):
    try:
        r = requests.get(url, timeout=2, allow_redirects=False)
        return 200 <= r.status_code < 400
    except requests.RequestException:
        return None


def publish_snapshot(snapshot):
    """Called once/minute by the existing history collector, never from a UI request."""
    global _snapshot, _snapshot_at, _extra
    from app import run_command, _container_details
    now = time.time()
    extra = {"containers":deepcopy(_container_details)}
    from pcold_details import read_details
    extra['pcold_details'] = read_details()
    extra['hostname'] = os.uname().nodename
    extra['load_average'] = list(os.getloadavg())
    extra['swap_percent'] = psutil.swap_memory().percent
    extra['interfaces'] = [{'name': k, 'addresses': [a.address for a in v if a.family == 2]}
                           for k, v in psutil.net_if_addrs().items() if not k.startswith(('veth','br-','docker','lo'))]
    io = psutil.net_io_counters()
    extra['network'] = {'rx_bytes': io.bytes_recv, 'tx_bytes': io.bytes_sent}
    usage = psutil.disk_usage('/')
    extra['storage'] = {'name':'Pi5 NVMe /', 'total':usage.total, 'used':usage.used, 'free':usage.free,
                        'percent':round(usage.used/usage.total*100,1)}
    # DNS Center. Guarded so an AdGuard outage can never stall the whole snapshot.
    try:
        from dns_center import collect as collect_dns
        collect_dns(_container_details)
    except Exception:
        LOG.exception('DNS Center collection failed; other panels remain available')
    extra['home_assistant'] = _probe('http://127.0.0.1:8123/')
    extra['uptime_kuma'] = _probe('http://{0}/'.format(netcfg.endpoint('PCOLD_LAN_IP', 3001)))
    try:
        response = requests.get('http://127.0.0.1:5300/status.php', timeout=2)
        data = response.json() if response.ok else {}
        extra['nextcloud'] = {k:data.get(k) for k in ('versionstring','maintenance','needsDbUpgrade','installed')}
    except (requests.RequestException, ValueError):
        extra['nextcloud'] = {}
    failed = run_command(['systemctl','list-units','--state=failed','--no-legend','--plain','--no-pager'])
    extra['failed_units'] = [line.split()[0] for line in failed.stdout.splitlines() if line.strip()] if failed and failed.returncode == 0 else None
    units = ('metehantech-status.service','metehantech-home.service','clan-web.service',
             'metehantech-frigate.service','tailscaled.service','cloudflared.service','docker.service')
    result = run_command(['systemctl','show',*units,'--property=Id,ActiveState,SubState,ActiveEnterTimestamp','--no-pager'])
    extra['systemd'] = []
    if result and result.returncode == 0:
        for block in result.stdout.strip().split('\n\n'):
            values = dict(line.split('=',1) for line in block.splitlines() if '=' in line)
            if values.get('Id') in units:
                extra['systemd'].append(values)
    try:
        r = requests.get('http://127.0.0.1:5400/api/events', params={'camera':'tapo_c211','label':'person','limit':4,'has_snapshot':1}, timeout=2)
        events = r.json() if r.ok else []
        extra['person_events'] = [{k:e.get(k) for k in ('id','start_time','end_time','label','has_snapshot')} for e in events[:4] if isinstance(e,dict) and e.get('camera')=='tapo_c211'] if isinstance(events,list) else []
    except (requests.RequestException,ValueError):
        extra['person_events'] = None
    extra['next_backups'] = {}
    for node in ('pi','pcold','cloud'):
        result = run_command(['systemctl','--user','show',f'metehantech-backup-auto-{node}.timer',
                              '--property=NextElapseUSecRealtime','--value'])
        extra['next_backups'][node] = result.stdout.strip() if result and result.returncode == 0 else None
    with _lock:
        if _snapshot_at and _extra.get('network'):
            elapsed = now - _snapshot_at
            for direction in ('rx','tx'):
                delta = extra['network'][direction+'_bytes'] - _extra['network'][direction+'_bytes']
                extra['network'][direction+'_bytes_per_second'] = max(0,delta)/elapsed if elapsed > 0 else None
        _snapshot, _snapshot_at, _extra = deepcopy(snapshot), now, extra


def _latest_metrics():
    output = []
    if not DB_PATH.exists(): return output
    with sqlite3.connect(f'file:{DB_PATH}?mode=ro',uri=True,timeout=2) as db:
        db.row_factory = sqlite3.Row
        for device in ('pi5','pcold'):
            r = db.execute('SELECT * FROM metrics WHERE device=? ORDER BY timestamp DESC LIMIT 1',(device,)).fetchone()
            if r: output.append(dict(r))
    return output


def _safe(provider, fallback):
    try: return provider()
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, requests.RequestException): return fallback


def build_summary():
    from alerts import get_alerts, get_alert_summary
    from backups import backup_summary, list_backups
    from activity import get_activity
    from camera import get_camera_status
    with _lock:
        snapshot, collected, extra = deepcopy(_snapshot or {}), _snapshot_at, deepcopy(_extra)
    now = time.time()
    metrics = _safe(_latest_metrics, [])
    latest = {r['device']:r for r in metrics}
    alerts = _safe(lambda:get_alerts(status='active',limit=50), None)
    counts = _safe(get_alert_summary, None)
    camera = _safe(get_camera_status, {})
    backups = _safe(backup_summary, {})
    from backup_validator import flow_state
    backup_records = _safe(lambda:list_backups(500), [])
    flows = {node:flow_state(backup_records,node) for node in ('pi','pcold','cloud')}
    for flow in flows.values():
        attempt = flow.get('last_attempt') or {}
        flow['health'] = ('RUNNING' if attempt.get('status') in ('queued','running') else
                          'WARNING' if attempt.get('status') in ('failed','verification_failed') else
                          {'ok':'HEALTHY','warning':'WARNING','critical':'CRITICAL'}.get(flow['freshness'],'UNKNOWN'))
    timeline = []
    for row in _safe(lambda:get_alerts(limit=50), []):
        timeline.append({'time':row.get('resolved_at') or row['created_at'],'source':'alert',
                         'message':row['title'], 'result':row['status']})
    for row in _safe(lambda:get_activity(50), []):
        timeline.append({'time':row['timestamp'],'source':'admin','user':'admin',
                         'message':row['action']+' · '+row['target'],'result':row['result']})
    for row in _safe(lambda:list_backups(50), []):
        timeline.append({'time':row.get('finished_at') or row['started_at'],'source':'backup',
                         'message':row['source_node']+' backup','result':row['status']+' / '+str(row.get('verification_status'))})
    devices = snapshot.get('devices') or [{'id':k,'name':k,'online':None,'metrics':{}} for k in ('pi5','pcold')]
    health = []
    for d in devices:
        row = latest.get(d['id'],{})
        age = max(0,now-row['timestamp']) if row else None
        d['metrics_age_seconds'] = round(age,1) if age is not None else None
        d['freshness'] = freshness(age)
        own_alerts = [r['severity'].upper() for r in alerts or [] if r.get('source')==d['id']]
        states = [d['freshness'], *own_alerts]
        for name, value in d.get('checks',{}).items():
            if value is None: states.append('UNKNOWN')
            elif (value if name=='Throttled' else not value): states.append('CRITICAL' if name in ('SMART','Throttled') else 'WARNING')
        from history import numeric
        if any(numeric(d.get('metrics',{}).get(k)) is None for k in ('cpu','ram','disk')):
            states.append('UNKNOWN')
        if d.get('online') is False: states.append('CRITICAL')
        elif d.get('online') is None: states.append('UNKNOWN')
        d['health'] = worst(states)
        if not collected:
            d['metrics'] = {k:row.get(k) for k in ('cpu','ram','disk','temperature','load')}
            d['health'] = worst([d['health'],'UNKNOWN'])
        health.append(d['health'])
    collection_age = max(0,now-collected) if collected else None
    health.append(freshness(collection_age))
    for container in extra.get('containers',[]):
        health.append('HEALTHY' if container['state'] in ('running','healthy') else 'WARNING')
    if counts:
        if counts['active_critical']: health.append('CRITICAL')
        if counts['active_warning']: health.append('WARNING')
    else: health.append('UNKNOWN')
    # "AdGuard Home" already arrives inside snapshot['services'] from app.get_status();
    # adding it again here would duplicate the card in the Services view.
    from dns_center import summary as dns_summary
    dns = _safe(dns_summary, {'available':None,'health':'UNKNOWN','freshness':'UNKNOWN'})
    services = snapshot.get('services', [])
    services += [{'name':'Home Assistant','operational':extra.get('home_assistant')},
                 {'name':'Uptime Kuma','operational':extra.get('uptime_kuma')},
                 {'name':'Frigate','operational':camera.get('frigate',{}).get('api_healthy')}]
    for s in services:
        s['state'] = 'RUNNING' if s.get('operational') is True else 'DEGRADED' if s.get('operational') is False else 'UNKNOWN'
        health.append('HEALTHY' if s['state']=='RUNNING' else 'WARNING' if s['state']=='DEGRADED' else 'UNKNOWN')
    storage = []
    if extra.get('storage'): storage.append(extra['storage'])
    pc = next((d for d in devices if d['id']=='pcold'), {})
    from history import numeric
    storage.append({'name':'PcOld / + backup destination','percent':numeric(pc.get('metrics',{}).get('disk')),
                    **((extra.get('pcold_details') or {}).get('storage') or {'total':None,'used':None,'free':None}), 'smart':pc.get('checks',{}).get('SMART')})
    media = camera.get('storage',{})
    if media:
        total=media.get('total_bytes');used=media.get('used_bytes')
        storage.append({'name':'Camera NFS (PcOld filesystem)','total':total,'used':used,'free':media.get('free_bytes'),
                        'percent':100*used/total if total and used is not None else None})
    for disk in storage:
        disk['health'] = disk_health(disk.get('percent'))
        if disk['name'].startswith('Camera'):
            disk['health'] = worst([disk['health'], *[a['severity'].upper() for a in alerts or [] if a['alert_type']=='recording_disk_space']])
        disk['freshness'] = freshness(collection_age)
        health.append(disk['health'])
    health.append(dns.get('health','UNKNOWN'))
    health.extend(f['health'] if f['health']!='RUNNING' else 'UNKNOWN' for f in flows.values())
    if not backups: health.append('UNKNOWN')
    for node in backups.get('nodes',{}).values():
        if not node: health.append('UNKNOWN')
        elif node.get('status') in ('failed','verification_failed'): health.append('WARNING')
    network = [
        {'name':'Pi5','ip':', '.join(a for i in extra.get('interfaces',[]) for a in i['addresses']), 'online':True if collected else None},
        {'name':'PcOld','ip':netcfg.get('PCOLD_LAN_IP'),'online':pc.get('online')},
        {'name':'Tapo C211','ip':netcfg.get('CAMERA_LAN_IP'),'online':camera.get('camera',{}).get('online')},
        {'name':'Home Assistant','ip':netcfg.endpoint('PI5_LAN_IP',8123),'online':extra.get('home_assistant')},
        {'name':'Nextcloud','ip':'127.0.0.1:5300','online':snapshot.get('personal_cloud',{}).get('reachable')},
        {'name':'AdGuard Home (DNS)','ip':', '.join(dns.get('server_addresses') or []),'online':dns.get('available')},
    ]
    for n in network:
        n['observation_time'] = datetime.fromtimestamp(collected,timezone.utc).isoformat() if collected else None
        n['freshness'] = freshness(collection_age)
    return {'health':worst(health),'collection_age_seconds':collection_age,'devices':devices,'services':services,
            'dns':dns,
            'extra':extra,'alerts':alerts,'alert_counts':counts,'camera':camera,'backups':backups,
            'backup_flows':flows,'storage':storage,'network':network,'timeline':sorted(timeline,key=lambda r:r['time'],reverse=True)[:50],
            'updated_at':datetime.now(timezone.utc).isoformat()}


@control.get('/api/admin/control-center')
@admin_required
def summary():
    return jsonify(build_summary())


@control.get('/api/admin/control-center/history')
@admin_required
def history():
    device, span = request.args.get('device'), request.args.get('range')
    if device not in ('pi5','pcold') or span not in RANGES: return jsonify(error='Invalid device or range'),400
    try: return jsonify(get_history(device,span))
    except (OSError,sqlite3.Error): return jsonify(error='History unavailable'),503


@control.get('/api/admin/control-center/camera-preview')
@admin_required
def camera_preview():
    # Fixed camera, fixed origin; no path/URL/command supplied by a browser.
    if request.args: return jsonify(error='Parameters not accepted'),400
    try:
        with requests.get('http://127.0.0.1:5400/api/tapo_c211/latest.jpg',timeout=3,stream=True) as r:
            if r.status_code != 200 or not r.headers.get('Content-Type','').startswith('image/'):
                return jsonify(error='Preview unavailable'),503
            parts=[]; size=0
            for part in r.iter_content(65536):
                size += len(part)
                if size > 4*1024*1024: return jsonify(error='Preview too large'),503
                parts.append(part)
        return Response(b''.join(parts),mimetype='image/jpeg',headers={'Cache-Control':'no-store'})
    except requests.RequestException:
        return jsonify(error='Preview unavailable'),503


def cached_status():
    with _lock:
        return deepcopy(_snapshot)
