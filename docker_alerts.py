"""Read-only restart observations; never restarts a container."""
from contextlib import closing


def evaluate_restarts(containers, *, now, db_path=None):
    from alerts import connect, _apply_condition, utc
    for item in containers:
        name=item['name'];count=item.get('restart_count')
        if not isinstance(count,int):continue
        prefix='docker_restart:'+name+':'
        with closing(connect(db_path)) as db:
            rows=db.execute('SELECT state_key,consecutive FROM alert_states WHERE state_key LIKE ?', (prefix+'%',)).fetchall()
            for key, old in rows:
                if float(key.rsplit(':',1)[1]) < now-300 or old>count:
                    db.execute('DELETE FROM alert_states WHERE state_key=?',(key,))
            db.execute('INSERT OR REPLACE INTO alert_states(state_key,consecutive,updated_at) VALUES (?,?,?)',(prefix+str(int(now)),count,utc(now)))
            minimum=db.execute('SELECT MIN(consecutive) FROM alert_states WHERE state_key LIKE ?',(prefix+'%',)).fetchone()[0]
            db.commit()
        delta=count-minimum
        _apply_condition(source='docker',alert_type='restart_burst',target=name,title='Repeated container restarts',
                         message=f'{name}: {delta} observed restarts within five minutes.',
                         severity='warning' if delta>=3 else None,last_value=str(delta),threshold='>=3 observed restarts / 300s',
                         recover=delta<3,timestamp=utc(now),db_path=db_path)
