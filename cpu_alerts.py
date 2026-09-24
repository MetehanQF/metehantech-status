"""Sustained CPU evaluation stored in the existing Alert Center state table."""
from contextlib import closing
from datetime import datetime
from health_model import CPU_WARNING, CPU_DURATION, STALE_WARNING


def evaluate_cpu(snapshot, *, db_path=None, now):
    from alerts import connect, number, _apply_condition, utc
    for device in snapshot.get('devices', []):
        source=device.get('id')
        if source not in ('pi5','pcold'): continue
        value=number(device.get('metrics',{}).get('cpu')) if device.get('online') else None
        high=value is not None and value > CPU_WARNING
        key='cpu_duration:'+source
        with closing(connect(db_path)) as db:
            old=db.execute('SELECT consecutive,updated_at FROM alert_states WHERE state_key=?',(key,)).fetchone()
            start=int(now) if high else 0
            if high and old and old[0] and 0 <= now-datetime.fromisoformat(old[1]).timestamp() <= STALE_WARNING:
                start=old[0]
            db.execute('INSERT OR REPLACE INTO alert_states(state_key,consecutive,updated_at) VALUES (?,?,?)',(key,start,utc(now)))
            db.commit()
        _apply_condition(source=source,alert_type='cpu_sustained',target=device.get('name',source),
                         title='Sustained CPU usage',message=f'CPU above {CPU_WARNING}% for at least five minutes.',
                         severity='warning' if high and now-start >= CPU_DURATION else None,
                         last_value=str(value),threshold=f'>{CPU_WARNING}% sustained {CPU_DURATION}s',
                         recover=value is not None and not high,timestamp=utc(now),db_path=db_path)
