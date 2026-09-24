# MetehanTech Status

A self-hosted **control centre for a two-node home lab**: one primary node (a
Raspberry Pi 5 running the services) and one secondary node (an old laptop acting
as NFS camera storage, backup target and external watchdog).

It is a single Flask application that answers one question well — *is everything
actually healthy, and can I prove it?* — instead of a generic metrics dashboard.
Every alert it raises is backed by a measurement it took itself, and every backup
it reports as good has been verified byte-for-byte.

> **Status:** running continuously in production on the author's home lab.
> ~7,300 lines of application code and ~2,800 lines of tests (11 test modules,
> 209 tests / 543 subtests).

---

## Screenshots

<!-- TODO: add dashboard screenshots here.
     Any screenshot must be scrubbed of LAN addresses, hostnames and device
     names before it is committed. -->

*Screenshots not included yet.*

---

## Features

**Control Center** — live host metrics (CPU, RAM, disk, temperature, throttling),
container state, service state, and a per-node health model. CPU load is sampled
as a delta over `/proc`, not a single `psutil` reading, because one-shot samples
lie.

**Alert Center** — 28 rule-driven alerts across disk, temperature, throttling,
RAM, CPU, containers, services, DNS and backup freshness. Alerts are debounced
over several cycles so a transient spike never pages you.

**Backup Center** — scheduled backups across three targets with retention,
*and* verification: every restore point is re-hashed and listed, staging is
confined to a job root, and a backup only counts as good when
`status='success' AND verification_status='verified'`. A workspace supplement
scans plain-text files and drops anything carrying a credential-shaped value
rather than redacting it in place.

**DNS Center** — two-resolver AdGuard Home cluster view: per-node health,
client identity resolution, query anomaly detection, and an explicit
open-resolver posture check. Client identity is only merged on hard evidence
(same universally administered MAC, or an explicit persistent record) — never
on a matching hostname.

**Camera Center** — Frigate/NFS storage health, mount identity checks that see
through `systemd` automount, and a canary that records whether recording is
actually happening.

**Incidents & Events** — an external watchdog on the secondary node records the
primary going away, so an outage of the primary still leaves an audit trail.

---

## Architecture

```
                    ┌─────────────────────────────────────┐
   browser ────────►│  Flask app (gunicorn, loopback)     │
                    │    app.py · admin.py · wsgi.py      │
                    └───────────────┬─────────────────────┘
                                    │
        ┌───────────────┬───────────┼───────────────┬──────────────┐
        ▼               ▼           ▼               ▼              ▼
   control_center   alerts      dns_center      camera        backups
   history          *_alerts    dns_cluster     incidents     backup_job
                                dns_inventory                 backup_validator
        │               │           │               │              │
        └───────────────┴───────────┴───────────────┴──────────────┘
                                    │
                         SQLite under  data/
                  metrics · alerts · backups · admin_activity
```

- **Collector** — a background thread samples metrics on a ~60 s cycle and holds
  an advisory `flock` so only one collector ever runs.
- **Config layer** — `network.py` (addresses) and `deployment.py` (paths and
  accounts) read configuration; `envfile.py` implements systemd
  `EnvironmentFile` semantics so system services, user timers and manual runs all
  resolve the same values.
- **Secondary node** — `watchdog_pcold/` is a standard-library-only service
  deployed separately; it watches the primary and exposes a read-only endpoint.

---

## Requirements

- Python 3.12+
- Linux with `systemd`
- `Flask`, `gunicorn`, `requests`, `psutil` (see `requirements.txt`)
- Optional, per feature: Docker, AdGuard Home, Frigate, an NFS target, SSH access
  to a backup host

---

## Installation

```bash
git clone https://github.com/<owner>/metehantech-status.git
cd metehantech-status

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 1. Configuration

Nothing about your machine is baked into the source. Three example files
describe everything the application needs:

| Example | Installed to | Holds |
|---|---|---|
| `admin.env.example` | `/etc/metehantech-status/admin.env` | admin password hash, session secret |
| `network.env.example` | `/etc/metehantech-status/network.env` | host addresses |
| `deploy.env.example` | `/etc/metehantech-status/deploy.env` | paths, backup account |

All example files contain **only** RFC 5737 (`192.0.2.0/24`) and RFC 6598
(`100.64.0.0/10`) documentation addresses and placeholder values.

```bash
# addresses and deployment paths
cp network.env.example deploy/network.env
cp deploy.env.example  deploy/deploy.env
chmod 600 deploy/network.env deploy/deploy.env
$EDITOR deploy/network.env deploy/deploy.env

sudo bash deploy/install-network-env.sh     # installs both, root:root 0600

# admin credentials
python3 -c "from werkzeug.security import generate_password_hash as g; print(g(input()))"
sudo install -m 600 -o root -g root admin.env.example /etc/metehantech-status/admin.env
sudo $EDITOR /etc/metehantech-status/admin.env
```

Configuration is resolved in this order: **process environment → config file**.
A config file is looked up in `$METEHANTECH_CONFIG_DIR`, then
`/etc/metehantech-status/`, then `~/.config/metehantech-status/`. Setting
`METEHANTECH_CONFIG_DIR` is exclusive — useful for isolated runs.

### 2. Service

```bash
bash install-systemd.sh
```

`metehantech-status.service` is a **template**: `__PROJECT_ROOT__` and
`__RUN_USER__` are substituted at install time from the script's own location
and the invoking user, so the unit contains no machine-specific path.

> **Never reload this service.** `history.start_collector()` attempts its `flock`
> exactly once and gives up permanently on failure; on reload the new worker is
> born while the old one still holds the lock, so you end up with *no* collector.
> Always use `systemctl restart --no-block metehantech-status.service`.

---

## Running the tests

```bash
.venv/bin/python -m pytest tests/ -q
```

Tests are **independent of any real deployment**. `tests/conftest.py` injects its
own synthetic values and pins the config search directory to a non-existent path,
so a real machine's configuration can never leak into a test run. Tests that need
live infrastructure skip themselves with a clear reason rather than failing.

```
206 passed, 4 skipped          # clean clone, nothing configured
209 passed, 543 subtests       # with live configuration present
```

---

## Security model

**Secrets never enter this repository.** They live outside it, and the source
carries no fallback to a real value.

| Secret | Where it lives |
|---|---|
| Admin password hash, session secret | `/etc/metehantech-status/admin.env` (root, `0600`) |
| Host addresses | `/etc/metehantech-status/network.env` (root, `0600`) |
| Deployment paths, backup account | `/etc/metehantech-status/deploy.env` (root, `0600`) |
| Database / cache passwords | Docker secrets under `/etc/…/secrets/`, referenced as `*_FILE` |
| Backup SSH key | outside the repo, path supplied by configuration |

Design rules this project follows:

- **No silent fallbacks.** A missing required value raises `NetworkConfigError` or
  `DeploymentConfigError`. Connecting to a *wrong* host is worse than not starting.
- **Optional features fail loudly, not quietly.** An unconfigured optional path
  disables its feature and says so in the status payload.
- **The app binds to loopback.** Exposure is a deliberate reverse-proxy decision,
  never a default.
- **Admin surface** is password-protected with CSRF tokens, secure cookies, rate
  limiting, and an exact-match allowlist for any container control (empty by
  default, which disables those controls).
- **The backup engine refuses to call broken things good** — see
  `tests/test_backup_validator.py` and `tests/test_backup_supplement.py`.

### Contributing

If you send a patch, please keep real addresses, hostnames, MAC addresses and
credentials out of it — including in test fixtures. Use the RFC documentation
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `100.64.0.0/10`).

---

## Repository layout

```
*.py                  application modules
static/ templates/    front-end
tests/                11 test modules
deploy/               systemd units, install scripts, Compose files (templates)
watchdog_pcold/       standalone watchdog for the secondary node
*.example             configuration templates — no real values
```

---

## Licence

[MIT](LICENSE) © 2026 Metehan Öztürk
