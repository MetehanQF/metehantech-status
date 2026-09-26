# Resilience harness

Tools that try to break this application's backup and restore path, so that a
backup reported as *good* has been proven good rather than assumed good.

They live inside the application they test and import its real modules
(`backup_validator`, `backup_hardening`, `deployment`, `network`) — so what runs
here is the same code that runs in production, not a reimplementation.

> **Everything here is read-only or dry-run by default.** The two destructive
> tools do nothing at all until you pass `--confirm`, and refuse to operate on
> a directory that overlaps the project, its `data/` directory, `/etc`, `/srv`
> or `/var` even when you do.

---

## What each tool proves

| Tool | Destructive? | Proves |
|---|---|---|
| [`failure_sim.py`](failure_sim.py) | yes — `--confirm` + `--lab` | the validator **refuses** corrupted restore points |
| [`restore_lab.py`](restore_lab.py) | yes — `--confirm` + `--lab` | a backup can actually be **restored and queried** |
| [`config_baseline.py`](config_baseline.py) | no | configuration drift, by fingerprint only |
| [`storage_analysis.py`](storage_analysis.py) | no | how long the storage runway really is |
| [`soak_collector.py`](soak_collector.py) | no | behaviour over hours, not over one sample |

---

## Failure simulation — `failure_sim.py`

A backup system that never says "no" is not a backup system. This harness
manufactures the failures a real one has to catch, against **throwaway copies**
of a restore point you nominate:

- a payload whose SHA-256 no longer matches its manifest
- a corrupted SQLite database inside the archive
- a truncated / corrupted tar archive
- a payload listed in the manifest but missing from disk
- a file present on disk but absent from the manifest
- a symlink injected into the restore tree
- a future-dated timestamp, and a stale backup past its freshness window
- an unfinalised staging directory
- a corrupted PostgreSQL custom dump
- storage-guard refusals: non-existent destination, read-only filesystem,
  ambiguous stacked mount, free-space floor
- SSH refusals: wrong host key, no agent, password auth disabled

Each scenario asserts the validator **rejects** it. A scenario that "passes"
means the system correctly refused.

```bash
# default: list what would run, change nothing
python3 resilience/failure_sim.py

# real run, against copies, in a throwaway directory
python3 resilience/failure_sim.py \
    --confirm \
    --lab /tmp/failure-lab \
    --fixture /path/to/verified-restore-point \
    --fixture /path/to/cloud-restore-point      # optional, enables the pgdump scenario
```

The fixture is copied before anything is corrupted; the restore point you point
at is only ever opened for reading.

## Restore validation — `restore_lab.py`

Extraction is not restoration. This one actually restores into disposable
containers — `--network none`, no published ports, no production mounts, and
the production databases are never connected to (only their *images* are
borrowed) — then checks the result:

- every extracted file matches the hash recorded during extraction
- the pgdump restores with `--exit-on-error` and the schema is sane: no invalid
  indexes, no unvalidated constraints, no orphaned storage rows
- every user file the restored database references exists in the restored tree,
  at the right size
- a deliberately damaged dump is **rejected** by `pg_restore`
- the monitoring SQLite copy opens and passes `pragma integrity_check`

```bash
python3 resilience/restore_lab.py            # dry run: lists required inputs

python3 resilience/restore_lab.py \
    --confirm \
    --lab /tmp/restore-lab \
    --cloud-source /path/to/verified-cloud-restore-point \
    --db-container  <existing-db-container-name> \
    --app-container <existing-app-container-name> \
    --secondary-fixture /path/to/secondary-restore-point   # optional
```

A synthetic throwaway config is generated for the application container; the
original instance secrets are never copied into the lab.

## Storage analysis — `storage_analysis.py`

Projects the storage runway from **two real measurements of the same thing at
two known times**. Where only one measurement exists the rate is reported as
`null` rather than guessed — a projection built on one sample is a fiction.

Read-only: `df`, `du`, `find`, a read-only SQLite connection, and SSH commands
that only read. Requires `BACKUP_SSH_KEY` and `BACKUP_REMOTE_USER`; the camera
and restore-point measurements are skipped unless `CAMERA_MEDIA_DIR` and
`RESTORE_POINT_DIR` are configured.

```bash
python3 resilience/storage_analysis.py
```

## Configuration baseline — `config_baseline.py`

Records SHA-256 fingerprints, sizes and modes of the configuration that matters
— including secret-bearing files. **File contents are never emitted**, so a
file holding a credential can be tracked for drift without its value ever
leaving the host.

```bash
python3 resilience/config_baseline.py
```

## Soak collector — `soak_collector.py`

Samples the system on an interval for a bounded duration and writes one JSON
object per sample to a size-capped JSONL file. Exists because a single reading
lies: CPU, memory fragmentation and mount health all need a window, not a
snapshot.

```bash
python3 resilience/soak_collector.py
```

---

## Configuration

These tools read the application's own configuration layer (`deployment.py`,
`network.py`) — see [`deploy.env.example`](../deploy.env.example). Nothing has a
real fallback: a missing required value raises `DeploymentConfigError` rather
than guessing a path.

| Key | Used by | Required? |
|---|---|---|
| `BACKUP_SSH_KEY`, `BACKUP_REMOTE_USER` | storage analysis, soak, baseline | yes |
| `RESTORE_POINT_DIR` | storage analysis | optional — measurement skipped |
| `CAMERA_MEDIA_DIR` | storage analysis, soak | optional — measurement skipped |
| `MONITORED_MOUNTS` | soak | optional — root is always sampled |
| `BACKUP_EXTRA_SOURCES`, `OPENCLAW_WORKSPACE` | baseline | optional |

Results go to `$RESILIENCE_RESULTS_DIR` (default: the current directory). No
output path is baked into the source.

---

## Do not run these against production

Explicitly:

- **Never** point `--lab` at `data/`, the project directory, `/etc`, `/srv` or
  `/var`. The guard refuses, but do not rely on the guard as your plan.
- **Never** run `restore_lab.py --confirm` expecting it to leave your containers
  alone if you pass a *production* container to `--db-container` — it reads that
  container's image name and starts a **new** one, but a typo in an unrelated
  flag is still your responsibility to catch.
- **Never** run `failure_sim.py --confirm` with `--fixture` pointing at the only
  copy of a restore point you care about. It copies before corrupting, but the
  copy needs somewhere to go and disk can fill.
- `soak_collector.py` runs for a long time by design. Start it deliberately, not
  as part of a test loop.

Safe to run anywhere, any time: `config_baseline.py`, `storage_analysis.py`, and
every tool without `--confirm`.
