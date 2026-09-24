"""Redundant DNS cluster view for the Control Center.

Two independent AdGuard resolvers serve the LAN directly. This module answers one
question per collector cycle: *would a client asking this address right now get a
correct, filtered answer?* — by actually asking it, not by checking that a port is open.

    2/2 answering -> HEALTHY
    1/2 answering -> DEGRADED   (DNS service continues; clients fail over)
    0/2 answering -> CRITICAL

Kept separate from dns_center.py so the existing single-resolver panel keeps working
unchanged while the secondary is not yet deployed.
"""
from copy import deepcopy
import subprocess
import threading
import time
import network

MEMBERS = (
    {"node": "pi5", "label": "Pi5 Resolver", "address": network.get("PI5_LAN_IP"), "role": "primary"},
    {"node": "pcold", "label": "PcOld Resolver", "address": network.get("PCOLD_LAN_IP"), "role": "secondary"},
)

RESOLVE_PROBE = "example.com"
FILTER_PROBE = "doubleclick.net"      # must come back 0.0.0.0 from a filtering resolver
PROBE_TIMEOUT = 3

_lock = threading.Lock()
_state = None
_state_at = None


def _dig(server, name, timeout=PROBE_TIMEOUT):
    started = time.perf_counter()
    try:
        result = subprocess.run(
            ["dig", f"+time={timeout}", "+tries=1", "+short", f"@{server}", name, "A"],
            capture_output=True, text=True, timeout=timeout + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    answers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return answers, elapsed


def probe(member):
    """Two real queries: does it resolve, and is it still filtering?"""
    address = member["address"]
    resolved, resolve_ms = _dig(address, RESOLVE_PROBE)
    filtered, filter_ms = _dig(address, FILTER_PROBE)

    answering = bool(resolved)
    filtering = filtered == ["0.0.0.0"]
    latencies = [ms for ms in (resolve_ms, filter_ms) if ms is not None]

    if answering and filtering:
        health = "HEALTHY"
    elif answering:
        # It answers but no longer blocks — clients would silently lose filtering.
        health = "DEGRADED"
    else:
        health = "CRITICAL"

    return {
        **member,
        "answering": answering,
        "filtering": filtering,
        "health": health,
        "latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "detail": ("serving filtered answers" if health == "HEALTHY" else
                   "answering but NOT filtering" if health == "DEGRADED" else
                   "no answer"),
    }


def collect():
    """Called once per minute from the existing collector. Never from a UI request."""
    global _state, _state_at
    members = [probe(member) for member in MEMBERS]
    serving = [m for m in members if m["answering"]]
    healthy = [m for m in members if m["health"] == "HEALTHY"]

    if len(healthy) == len(members):
        state = "HEALTHY"
    elif serving:
        state = "DEGRADED"
    else:
        state = "CRITICAL"

    summary = {
        "state": state,
        "members": members,
        "serving": len(serving),
        "healthy": len(healthy),
        "total": len(members),
        "redundant": len(serving) >= 2,
        "note": {
            "HEALTHY": "Both resolvers answering and filtering.",
            "DEGRADED": "One resolver is unavailable — DNS continues on the other, "
                        "but the cluster has no redundancy left.",
            "CRITICAL": "No resolver is answering. By design there is no third "
                        "fallback, so name resolution stops.",
        }[state],
    }
    with _lock:
        _state, _state_at = summary, time.time()
    return summary


def cached():
    with _lock:
        if _state is None:
            return None, None
        return deepcopy(_state), _state_at


def summary():
    state, collected = cached()
    if state is None:
        return {"state": "UNKNOWN", "members": [dict(m, health="UNKNOWN", answering=None,
                                                     filtering=None, latency_ms=None,
                                                     detail="not probed yet") for m in MEMBERS],
                "serving": None, "healthy": None, "total": len(MEMBERS), "redundant": None,
                "collection_age_seconds": None,
                "note": "DNS cluster has not been probed yet."}
    age = max(0.0, time.time() - collected) if collected else None
    return {**state, "collection_age_seconds": round(age, 1) if age is not None else None}
