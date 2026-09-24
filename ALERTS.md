# Alert Center v1

Alert Center is private to authenticated Control Center sessions. It does not perform public HTTP uptime checks; those remain owned by Uptime Kuma on MetehanTechPcOld.

## Data sources and rules

- The existing 60-second collector snapshot supplies Pi temperature, RAM, disk, throttling, and PcOld RAM, disk, and SMART values.
- Fixed-name `systemctl is-active` checks cover `metehantech-status.service`, `metehantech-home.service`, and `clan-web.service`.
- The independent 30-second stale monitor reads timestamps already stored in `data/metrics.db`.
- Existing imported watchdog incidents from `metrics.db` are projected by `external_event_id`; Alert Center does not probe the watchdog or public domains.

| Rule | Warning | Critical | Recovery / debounce |
|---|---:|---:|---|
| Pi CPU temperature | 75°C | 82°C | `<72°C`; 2 consecutive samples |
| Pi disk | 85% | 95% | `<80%` |
| Pi RAM | 90% | — | `<85%`; 5 consecutive samples |
| Pi throttling/undervoltage | — | detected | clear |
| Collector stale | `>120s` | `>300s` | `<=120s` |
| Systemd service | — | down | 2 consecutive failures; running resolves |
| PcOld metrics stale | `>120s` | `>300s` | `<=120s` |
| PcOld disk | — | 95% | `<90%` |
| PcOld RAM | — | 95% | `<90%`; 5 consecutive samples |
| PcOld SMART | — | not OK | OK |

Admin-requested service restarts create a persistent 60-second suppression window before the restart command. Failure counters reset during the window.

## Storage and API

`data/alerts.db` is SQLite/WAL with mode `0600`. A partial unique index permits only one active row per source/type/target while retaining resolved history. Counter and maintenance state are also persistent.
Tests set `ALERTS_DB` to a temporary database so they never write production alert state.

- `GET /api/admin/alerts?status=active&severity=critical&limit=50`
- `GET /api/admin/alerts/summary`

Both endpoints require the existing admin session. Limits are restricted to 50, 100, or 500.

## Telegram

Telegram delivery is intentionally inactive in v1. `ALERT_TELEGRAM_ENABLED=0` is set in the service unit and remains the code default. No bot token setting or delivery code is included yet.
