#!/usr/bin/env python3
"""Read-only 7 daily + 4 weekly retention planner. Deletion is deliberately absent."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from zoneinfo import ZoneInfo
import backups


def plan(records, now=None):
    now = now or datetime.now(timezone.utc)
    zone = ZoneInfo('Europe/Istanbul')
    today = now.astimezone(zone).date()
    monday = today - timedelta(days=today.weekday())
    output = {'mode': 'dry-run-only', 'deletion_enabled': False, 'policy': '7 recent calendar days + 4 previous calendar weeks; retain newest two; retain unknown/unverified', 'nodes': {}}
    for node in sorted(backups.NODES):
        good = [r for r in records if r['source_node'] == node and r['status'] == 'success' and r['checksum_status'] == r['verification_status'] == 'verified' and r.get('finished_at')]
        good.sort(key=lambda r: r['finished_at'], reverse=True)
        keep = {r['backup_id'] for r in good[:2]}
        daily, weekly = set(), set()
        for r in good:
            day = datetime.fromisoformat(r['finished_at']).astimezone(zone).date()
            week = day - timedelta(days=day.weekday())
            if 0 <= (today - day).days < 7 and day not in daily:
                keep.add(r['backup_id']); daily.add(day)
            if 7 <= (monday - week).days <= 28 and week not in weekly:
                keep.add(r['backup_id']); weekly.add(week)
        output['nodes'][node] = {'verified_record_count': len(good), 'keep': sorted(keep), 'candidates_not_deleted': [r['backup_id'] for r in good if r['backup_id'] not in keep], 'deletion_gate': 'BLOCKED: requires fresh physical verification of newest AND previous restore points; no deletion implementation'}
    return output


def main():
    with sqlite3.connect(f'file:{backups.configured_db_path()}?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        result = plan([dict(r) for r in c.execute('SELECT * FROM backups')])
    target = Path(__file__).resolve().parent / 'data/backup-hardening'
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = target / 'retention-plan.json.tmp'
    temp.write_text(json.dumps(result, indent=2) + '\n')
    temp.replace(target / 'retention-plan.json')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    import os
    os.umask(0o077)
    main()
