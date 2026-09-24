"""Shared alert/display thresholds; unknown is never healthy."""
DISK_WARNING = 85
DISK_CRITICAL = 95
TEMP_WARNING = 75
TEMP_CRITICAL = 82
RAM_WARNING = 90
STALE_WARNING = 120
STALE_CRITICAL = 300
CPU_WARNING = 90
CPU_DURATION = 300


def worst(states):
    values = set(states)
    return next((s for s in ('CRITICAL', 'WARNING', 'UNKNOWN') if s in values), 'HEALTHY') if values else 'UNKNOWN'


def freshness(age):
    if age is None: return 'UNKNOWN'
    if age > STALE_CRITICAL: return 'CRITICAL'
    if age > STALE_WARNING: return 'WARNING'
    return 'HEALTHY'


def disk_health(value):
    if value is None: return 'UNKNOWN'
    return 'CRITICAL' if value >= DISK_CRITICAL else 'WARNING' if value >= DISK_WARNING else 'HEALTHY'
