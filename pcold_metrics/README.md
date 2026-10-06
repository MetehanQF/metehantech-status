# MetehanTechPcOld metrics agent

Standard-library-only HTTP agent on PcOld (`GET :8765/status`). The Pi status app reads it
from `read_old_pc()` on every collector cycle (60 s). Deployed by the operator as root:
`/usr/local/bin/metehantech-metrics.py` + `metehantech-metrics.service` (this directory).

## CPU semantics (Phase 6C.3)

`cpu` is utilization averaged from the newest stored `/proc/stat` snapshot that is at least
30 s old up to the request (≈60 s with the Pi collector). Requests never sleep. Warm-up after a
restart, a counter reset or a read error returns `null` (never a fabricated `0`); a real idle
machine returns a real `0.0`. Before 6C.3 the agent slept 0.3 s between two reads, so values
were short snapshots that quantized to `0` on this idle 2-core laptop. Same definition as the
Pi's `cpu_sampler.py`; the code is duplicated on purpose so the agent stays dependency-free.

## Deploy (operator, on PcOld)

The agent is staged by an unprivileged backup user (`BACKUP_USER` below), then installed with root:

```bash
# from the Pi (the backup user can write its own home only)
scp pcold_metrics/metehantech-metrics.py BACKUP_USER@PCOLD:metehantech-metrics.py.new
scp pcold_metrics/install-6c3.sh        BACKUP_USER@PCOLD:pcold-metrics-install-6c3.sh
# on PcOld
sudo bash ~/pcold-metrics-install-6c3.sh   # STAGE_DIR=… to override
```

The script checks the staged SHA-256, keeps `/usr/local/bin/metehantech-metrics.py.pre-6c3`,
restarts only `metehantech-metrics.service`, expects `null` during warm-up and a finite 0–100
value after 35 s, and restores the backup automatically on any failure.

Rollback: `sudo install -m 755 /usr/local/bin/metehantech-metrics.py.pre-6c3 /usr/local/bin/metehantech-metrics.py && sudo systemctl restart metehantech-metrics.service`
