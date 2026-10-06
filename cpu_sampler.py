"""Interval CPU utilization from /proc/stat counter deltas.

The value is CPU utilization averaged from the newest stored counter snapshot that is at
least ``MIN_WINDOW`` seconds old up to now. The status collector samples every 60 seconds,
so in steady state each value covers the previous ~60 s. No call ever sleeps or blocks.

Warm-up (no old-enough snapshot yet), a counter reset or unreadable counters return ``None``
so callers report the metric as unavailable instead of a fabricated 0.
"""

import math
import threading
import time

MIN_WINDOW = 30.0      # shortest window that may produce a value
MAX_WINDOW = 300.0     # older snapshots are discarded; a longer gap restarts warm-up
STORE_SPACING = 5.0    # bound memory when callers are frequent (<= 60 snapshots)


def read_proc_stat(path="/proc/stat"):
    """Return (idle, total) jiffies for the aggregate CPU line.

    idle = idle + iowait. total = user..steal; guest/guest_nice are already part of
    user/nice on Linux and are excluded to avoid double counting.
    """
    with open(path, encoding="ascii") as source:
        fields = source.readline().split()
    if not fields or fields[0] != "cpu":
        raise ValueError("unexpected /proc/stat format")
    values = [int(value) for value in fields[1:9]]
    if len(values) < 5:
        raise ValueError("unexpected /proc/stat format")
    return values[3] + values[4], sum(values)


class CpuSampler:
    def __init__(self, read_counters=read_proc_stat, clock=time.monotonic):
        self._read = read_counters
        self._clock = clock
        self._lock = threading.Lock()
        self._snapshots = []  # [(monotonic, idle, total)], oldest first

    def prime(self):
        """Record a baseline without producing a value (used at process start)."""
        self.sample()

    def sample(self):
        with self._lock:
            now = self._clock()
            try:
                idle, total = self._read()
            except (OSError, ValueError):
                return None
            self._snapshots = [snap for snap in self._snapshots if now - snap[0] <= MAX_WINDOW]
            reference = None
            for snap in reversed(self._snapshots):
                if now - snap[0] >= MIN_WINDOW:
                    reference = snap
                    break
            if not self._snapshots or now - self._snapshots[-1][0] >= STORE_SPACING:
                self._snapshots.append((now, idle, total))
            if reference is None:
                return None
            total_delta = total - reference[2]
            idle_delta = idle - reference[1]
            if total_delta <= 0 or idle_delta < 0 or idle_delta > total_delta:
                # Counter reset or inconsistent read: restart the window honestly.
                self._snapshots = [(now, idle, total)]
                return None
            value = (1 - idle_delta / total_delta) * 100
            if not math.isfinite(value):
                return None
            return round(min(100.0, max(0.0, value)), 1)
