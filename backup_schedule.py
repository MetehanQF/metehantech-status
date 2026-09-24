#!/usr/bin/env python3
"""User-systemd scheduler for existing jobs; shared lock and existing Backup Center DB."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import time
import backup_job
import backups

STATE = Path(__file__).resolve().parent / 'data' / 'backup-hardening'


def log(event):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    event = {'logged_at': backups.utc_now(), **event}
    line = json.dumps(event, ensure_ascii=False)
    with (STATE / 'runs.jsonl').open('a') as f:
        f.write(line + '\n')
    print(line, flush=True)


def interrupted(signum, frame):
    raise RuntimeError('Backup interrupted by signal ' + str(signum))


def snapshot_assurance():
    """Append a per-flow assurance snapshot so freshness has history, not just a latest value.

    Best effort by design: a reporting failure must never turn a completed backup
    into a failed one.
    """
    try:
        from backup_validator import live_assurance
        report = live_assurance()
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        line = json.dumps({
            'logged_at': report['generated_at'],
            'healthy': report['healthy'],
            'stuck_jobs': len(report['stuck_jobs']),
            'flows': {node: {k: flow[k] for k in
                             ('assurance_level', 'freshness', 'verified_age_hours')}
                      for node, flow in report['flows'].items()},
            'components': {name: component['assurance_level']
                           for name, component in report['components'].items()},
        }, ensure_ascii=False)
        with (STATE / 'assurance.jsonl').open('a') as handle:
            handle.write(line + '\n')
        print(line, flush=True)
    except Exception as error:                     # noqa: BLE001 - reporting must not fail a backup
        print(json.dumps({'assurance_snapshot_error': str(error)[:300]}), flush=True)


def run(node):
    if node not in {'pi', 'pcold', 'cloud'}:
        raise ValueError('Invalid node')
    # Cloud runs at 03:10 and holds maintenance mode for the length of the snapshot
    # (~72s at 130 MB). Revisit once the Nextcloud data set passes a few GB, because
    # this window grows with the archive and is real downtime, not a pause.
    # Wait instead of losing simultaneous Persistent catch-up jobs after boot.
    deadline = time.monotonic() + 7200
    record = None
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    while True:
        lock = backup_job.global_lock()
        try:
            lock.__enter__()
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                log({'node': node, 'result': 'failed', 'error': 'Global backup lock wait timed out'})
                return 1
            time.sleep(5)
    started = time.monotonic()
    try:
        # A power loss can leave a running record. Never alter recent/manual queued jobs.
        for old in backups.list_backups(500):
            if old['status'] in {'queued', 'running'}:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(old['started_at'])).total_seconds()
                if age > 6 * 3600:
                    backups.fail_backup(old['backup_id'], 'Interrupted stale job recovered while holding exclusive backup lock; artifacts preserved')
        record = backups.enqueue_backup(node)
        record = backups.claim_queued(node)
        log({'node': node, 'backup_id': record['backup_id'], 'result': 'started', 'source': node, 'destination': record['destination_node'], 'started_at': record['started_at']})
        {'pi': backup_job.run_pi_job, 'pcold': backup_job.run_pcold_job,
         'cloud': backup_job.run_cloud_job}[node](record)
        result = backups.get_backup(record['backup_id'])
        log({**result, 'result': result['status'], 'duration_seconds': round(time.monotonic() - started, 3)})
        snapshot_assurance()
        return 0
    except Exception as e:
        failure = {}
        if record:
            failure = backups.fail_backup(record['backup_id'], e, verification=isinstance(e, ValueError))
        log({**failure, 'node': node, 'backup_id': record['backup_id'] if record else None, 'result': 'failed', 'duration_seconds': round(time.monotonic() - started, 3), 'error': str(e)[:500]})
        return 1
    finally:
        lock.__exit__(None, None, None)


if __name__ == '__main__':
    os.umask(0o077)
    if len(sys.argv) != 2:
        raise SystemExit('usage: backup_schedule.py pi|pcold|cloud')
    raise SystemExit(run(sys.argv[1]))
