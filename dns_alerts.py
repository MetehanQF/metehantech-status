"""DNS Center rules for the existing Alert Center.

Every rule is debounced through the shared `alert_states` counter table, so a single
failed probe never raises an alert — the condition has to hold across consecutive
60-second collector cycles. Recovery is symmetric: the alert resolves only after the
condition has been clear for the same number of cycles.
"""
from health_model import STALE_WARNING, STALE_CRITICAL
import network

SOURCE = "dns_center"
TARGET = "AdGuard Home"

UNAVAILABLE_WARNING = 2      # 2 consecutive misses (~2 min) before warning
UNAVAILABLE_CRITICAL = 5     # 5 consecutive misses (~5 min) before critical
PROTECTION_SAMPLES = 2
UPSTREAM_SAMPLES = 2
LATENCY_SAMPLES = 3
LATENCY_WARNING_MS = 250     # AdGuard's own average processing time, not round trip
RECOVERY_SAMPLES = 2
CLUSTER_SAMPLES = 2       # ride out a container restart without paging


def _debounced(key, failing, timestamp, db_path):
    from alerts import _counter
    fail = _counter(f"dns:{key}:fail", failing, timestamp, db_path)
    clear = _counter(f"dns:{key}:clear", not failing, timestamp, db_path)
    return fail, clear


def evaluate_dns(snapshot, *, now, db_path=None, collection_age=None):
    """snapshot is dns_center.summary(); collection_age lets the caller override age."""
    from alerts import _apply_condition, utc
    timestamp = utc(now)
    if snapshot is None:
        return

    age = snapshot.get("collection_age_seconds") if collection_age is None else collection_age
    available = snapshot.get("available")

    # --- 1. AdGuard reachable at all -------------------------------------------------
    missing = available is False
    fail, clear = _debounced("unavailable", missing, timestamp, db_path)
    severity = None
    if missing and fail >= UNAVAILABLE_CRITICAL:
        severity = "critical"
    elif missing and fail >= UNAVAILABLE_WARNING:
        severity = "warning"
    _apply_condition(
        source=SOURCE, alert_type="adguard_unavailable", target=TARGET,
        title="AdGuard Home unavailable",
        message="The AdGuard Home API on 127.0.0.1:3000 did not answer. LAN and Tailscale "
                "DNS on {0} / {1} may be down.".format(
                    network.endpoint("PI5_LAN_IP", 53), network.endpoint("PI5_TAILSCALE_IP", 53)),
        severity=severity, last_value="unreachable" if missing else "reachable",
        threshold=f"warning>={UNAVAILABLE_WARNING} cycles;critical>={UNAVAILABLE_CRITICAL} cycles",
        recover=available is True and clear >= RECOVERY_SAMPLES,
        touch=missing, timestamp=timestamp, db_path=db_path)

    # --- 2. Protection switched off --------------------------------------------------
    disabled = available is True and snapshot.get("protection_enabled") is False
    fail, clear = _debounced("protection_off", disabled, timestamp, db_path)
    _apply_condition(
        source=SOURCE, alert_type="dns_protection_disabled", target=TARGET,
        title="DNS filtering disabled",
        message="AdGuard Home is running with protection turned off; no domain is being filtered.",
        severity="warning" if disabled and fail >= PROTECTION_SAMPLES else None,
        last_value="disabled" if disabled else "enabled",
        threshold=f">={PROTECTION_SAMPLES} cycles",
        recover=available is True and not disabled and clear >= RECOVERY_SAMPLES,
        touch=disabled, timestamp=timestamp, db_path=db_path)

    # --- 3. Upstream resolvers -------------------------------------------------------
    upstreams = snapshot.get("upstreams")
    if available is True and upstreams:
        primary = [u for u in upstreams if u.get("role") == "upstream"]
        unhealthy = [u for u in upstreams if not u.get("healthy")]
        all_down = bool(primary) and not any(u.get("healthy") for u in primary)
        some_down = bool(unhealthy) and not all_down

        fail, clear = _debounced("upstream_all", all_down, timestamp, db_path)
        _apply_condition(
            source=SOURCE, alert_type="dns_upstream_all_down", target="DNS upstreams",
            title="All DNS upstreams unavailable",
            message="No configured upstream resolver answered AdGuard's probe. Resolution is "
                    "relying on the fallback resolver only.",
            severity="critical" if all_down and fail >= UPSTREAM_SAMPLES else None,
            last_value=", ".join(u["address"] for u in unhealthy)[:200] or "none",
            threshold=f">={UPSTREAM_SAMPLES} cycles",
            recover=not all_down and clear >= RECOVERY_SAMPLES,
            touch=all_down, timestamp=timestamp, db_path=db_path)

        fail, clear = _debounced("upstream_some", some_down, timestamp, db_path)
        _apply_condition(
            source=SOURCE, alert_type="dns_upstream_degraded", target="DNS upstreams",
            title="A DNS upstream is unavailable",
            message="At least one configured resolver failed AdGuard's probe; the remaining "
                    "resolvers are still answering.",
            severity="warning" if some_down and fail >= UPSTREAM_SAMPLES else None,
            last_value=", ".join(u["address"] for u in unhealthy)[:200] or "none",
            threshold=f">={UPSTREAM_SAMPLES} cycles",
            recover=not some_down and clear >= RECOVERY_SAMPLES,
            touch=some_down, timestamp=timestamp, db_path=db_path)

    # --- 4. Processing latency -------------------------------------------------------
    latency = snapshot.get("avg_processing_ms")
    if available is True and isinstance(latency, (int, float)):
        slow = latency > LATENCY_WARNING_MS
        fail, clear = _debounced("latency", slow, timestamp, db_path)
        _apply_condition(
            source=SOURCE, alert_type="dns_latency_high", target=TARGET,
            title="DNS processing time elevated",
            message=f"AdGuard's average processing time is {latency:g} ms.",
            severity="warning" if slow and fail >= LATENCY_SAMPLES else None,
            last_value=f"{latency:g}ms", threshold=f">{LATENCY_WARNING_MS}ms for {LATENCY_SAMPLES} cycles",
            recover=not slow and clear >= RECOVERY_SAMPLES,
            touch=slow, timestamp=timestamp, db_path=db_path)

    # --- 5. Collector staleness (same model as every other panel) --------------------
    if age is not None:
        severity = ("critical" if age > STALE_CRITICAL else
                    "warning" if age > STALE_WARNING else None)
        _apply_condition(
            source=SOURCE, alert_type="dns_collector_stale", target="DNS collector",
            title="DNS Center data is stale",
            message=f"The DNS collector last produced a sample {age:.0f}s ago.",
            severity=severity, last_value=f"{age:.0f}s",
            threshold=f"warning>{STALE_WARNING}s;critical>{STALE_CRITICAL}s",
            recover=severity is None, touch=severity is not None,
            timestamp=timestamp, db_path=db_path)



# --------------------------------------------------------------- cluster rules
def evaluate_cluster(cluster, *, now, db_path=None):
    """Redundant-resolver alerts. Debounced so a restart does not page anyone.

    One resolver down is a WARNING: DNS still works, but redundancy is gone.
    Both down is CRITICAL: by design there is no third fallback.
    """
    from alerts import _apply_condition, utc
    if not cluster or cluster.get("state") == "UNKNOWN":
        return
    timestamp = utc(now)
    state = cluster.get("state")

    both_down = state == "CRITICAL"
    fail, clear = _debounced("cluster_down", both_down, timestamp, db_path)
    _apply_condition(
        source=SOURCE, alert_type="dns_cluster_down", target="DNS cluster",
        title="Both DNS resolvers are down",
        message=(
            "Neither {0} nor {1} answered. There is deliberately no "
            "third fallback, so clients cannot resolve names."
        ).format(network.get("PI5_LAN_IP"), network.get("PCOLD_LAN_IP")),
        severity="critical" if both_down and fail >= CLUSTER_SAMPLES else None,
        last_value=f"{cluster.get('serving')}/{cluster.get('total')} serving",
        threshold=f"0 serving for {CLUSTER_SAMPLES} cycles",
        recover=not both_down and clear >= RECOVERY_SAMPLES,
        touch=both_down, timestamp=timestamp, db_path=db_path)

    degraded = state == "DEGRADED"
    fail, clear = _debounced("cluster_degraded", degraded, timestamp, db_path)
    _apply_condition(
        source=SOURCE, alert_type="dns_cluster_degraded", target="DNS cluster",
        title="DNS cluster has lost redundancy",
        message="One resolver is not serving filtered answers. DNS continues on the other, "
                "but a second failure would stop name resolution.",
        severity="warning" if degraded and fail >= CLUSTER_SAMPLES else None,
        last_value=f"{cluster.get('healthy')}/{cluster.get('total')} healthy",
        threshold=f">=1 member unhealthy for {CLUSTER_SAMPLES} cycles",
        recover=not degraded and clear >= RECOVERY_SAMPLES,
        touch=degraded, timestamp=timestamp, db_path=db_path)

    for member in cluster.get("members") or []:
        node = member.get("node")
        down = member.get("health") == "CRITICAL"
        unfiltered = member.get("health") == "DEGRADED"
        fail, clear = _debounced(f"node_{node}", down or unfiltered, timestamp, db_path)
        severity = None
        if fail >= CLUSTER_SAMPLES:
            severity = "warning" if (down or unfiltered) else None
        _apply_condition(
            source=SOURCE, alert_type="dns_resolver_unhealthy", target=member.get("label", node),
            title=f"{member.get('label', node)} is not serving DNS",
            message=(f"{member.get('address')}:53 — {member.get('detail')}."),
            severity=severity, last_value=member.get("detail"),
            threshold=f">={CLUSTER_SAMPLES} cycles",
            recover=member.get("health") == "HEALTHY" and clear >= RECOVERY_SAMPLES,
            touch=down or unfiltered, timestamp=timestamp, db_path=db_path)
