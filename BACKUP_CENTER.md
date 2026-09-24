# Backup Center v1

Backup Center is private to authenticated Control Center sessions. Backup Hardening v1 adds user-systemd automation for Pi/PcOld, verified artifacts, logs and read-only retention planning. It exposes no restore action. Cloud automation remains blocked because the current consistent snapshot needs maintenance mode.

## Fixed data flow

- Raspberry Pi 5 → `metehanbackup@MetehanTechPcOld:/srv/metehantech-backups/from-pi`
- MetehanTechPcOld → `/srv/metehantech-backups/from-pcold` on the Pi
- LAN `<PCOLD_LAN_IP>` is attempted first; Tailscale `<PCOLD_TAILSCALE_IP>` is the fallback.
- Every restore point is created under `.staging/<backup-id>` and atomically renamed only after verification.

Backup IDs match exactly:

```text
YYYYMMDDTHHMMSSZ-(pi|pcold)-full-<6 lowercase hex characters>
```

## Included

Pi:

- `<PROJECT_ROOT>`
- `<HOME>/metehantech_home`
- `<HOME>/clan_web`
- allowlisted non-secret systemd units
- `metrics.db`, `alerts.db`, `admin_activity.db`, and `backups.db` through the Python SQLite backup API

PcOld:

- the dashboard directory named by `PCOLD_DASHBOARD_ROOT` (omitted when unset)
- `/usr/local/bin/metehantech-metrics.py`
- `/opt/metehantech-watchdog`
- allowlisted service units
- watchdog `events.db` and Uptime Kuma `kuma.db` through the Python SQLite backup API
- non-database Uptime Kuma volume files

## Explicit exclusions

- `.venv`, Python caches, test caches, temporary files, and backup roots
- `/etc/metehantech-status/admin.env`
- `/etc/clan-web.env`
- `/etc/cloudflared/token`
- Portainer data until a supported consistent export is implemented
- Docker socket, images, layers, and container root filesystems

The UI reports `Sensitive configuration backup: NOT ENABLED`. On the Pi, GnuPG is available and `age` is absent. A future v1.1 may use recipient/public-key encryption, but the private decryption key must live off both production nodes and must never be stored beside the backup destination.

## Verification

Successful jobs require:

- a complete SHA256 manifest with safe relative paths;
- readable `tar.zst` archives;
- `PRAGMA integrity_check = ok` for every SQLite snapshot;
- valid metadata and an atomic staging-to-final rename.

No successful history record is written before those checks pass.

## Privilege boundary

The Control Center may start only:

- `metehantech-backup-pi.service`
- `metehantech-backup-pcold.service`

The PcOld `metehanbackup` account may start only `metehantech-backup-export.service`. No wildcard systemctl, shell, Docker group, or general sudo access is granted.

## Remaining disabled

- Cloud automatic timer (no-downtime safety gate)
- retention/deletion (dry-run planner installed)
- external backup freshness alerts (Kuma push not configured)
- production restore
- plaintext secret backup
- Portainer live database backup


## Backup Hardening v1 — 2026-09-19

- `systemctl --user list-timers 'metehantech-backup-auto-*'`: Pi daily 01:10, PcOld daily 02:10, explicit Europe/Istanbul timezone, Persistent=true. User linger enabled, so jobs do not depend on an interactive login. All job controllers run on Pi; PcOld uses its existing restricted root export service.
- Cloud timer at 03:10 is installed but **disabled**. Its wrapper refuses to invoke maintenance mode. Existing manual Cloud service is unchanged; it still enters maintenance mode and must not be used under a no-downtime requirement.
- `backup_schedule.py` reuses existing job functions, metadata DB and shared flock. Simultaneous catch-up jobs wait for the lock (up to 2 hours) instead of overlapping. Stale queued/running records older than 6 hours are marked interrupted only under the exclusive lock. Recent manually queued jobs are not reclaimed.
- Both current destination filesystems are local ext4, not NFS: Pi `/dev/nvme0n1p2` mounted `/`; PcOld `/dev/sda1` mounted `/`. `backup_hardening.storage_guard` pins these identities, requires RW and at least 2 GiB available. A future NFS destination MUST use exact NFS export/type/mount expectations; missing/wrong NFS fails closed in tests. Camera NFS is not used or changed.
- Required payload names/sizes, timestamp, source identity, SHA256 coverage, archive integrity and SQLite integrity are checked before a new success. Legacy PcOld may include unmanifested, regenerable SQLite SHM plus **zero-byte** WAL caches; those are explicitly excluded from payload coverage. Nonempty unmanifested WAL is rejected. New Pi snapshots use DELETE journal mode and verification is immutable/read-only.
- Cloud verification additionally rejects `config.php` in the application archive and parses the entire custom PostgreSQL dump with `pg_restore --file=/dev/null`, without connecting to a database. This is artifact validation, not a complete restore drill. Cloud secrets remain separately required for disaster recovery.
- `data/backup-hardening/runs.jsonl` and user journal hold per-run results; existing `data/backups.db` provides Backup Center history. Timings include start/end/duration, source/destination, size/checksum/verification, and errors. No remote alert is configured.
- `backup_retention.py` is **dry-run only**; no deletion path exists. It selects newest per recent 7 calendar days and 4 previous calendar weeks (Istanbul), always retaining newest two verified records. Candidates require physical re-verification of newest and predecessor before any future deletion implementation. Unknown/unverified directories and PcOld export caches are never deletion targets. Plan is refreshed after each successful scheduled job.
- Existing authenticated UI gets a separate last-verified-success/freshness field per direction: <24h OK; 24–36h warning; >36h critical. Latest attempt remains separate. Frontend uses last 500 records and reports unknown when none qualify; no false inference of success. Refresh every 60s while idle. No production web restart was performed; legacy summary API timer/retention fields remain unchanged in the currently running process. The added UI notice describes deployed scheduling explicitly.
- No Uptime Kuma DB/config mutation, secret migration, networking change, package install, reboot, or production restart is part of this rollout.
