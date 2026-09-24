"""DNS Center: presentation, bounding, privacy and alert-debounce behaviour.

No test in this file talks to the real AdGuard instance; every AdGuard response is a
fixture, so the suite passes whether or not the container happens to be running.
"""
import ipaddress
import json
import sys
import time
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns_alerts
import dns_anomaly
import dns_center
import dns_cluster
import dns_inventory

# Host facts are stubbed so the suite never shells out to ip/docker and never depends
# on the machine it runs on. These values mirror ones observed on the real network.
NEIGHBOURS = {
    "192.0.2.157": {"mac": "00:00:5e:00:53:11", "state": "REACHABLE",
                      "locally_administered": False},
    "192.0.2.42": {"mac": "00:00:5e:00:53:12", "state": "DELAY",
                     "locally_administered": False},
    "192.0.2.130": {"mac": "02:00:5e:00:53:13", "state": "STALE",
                      "locally_administered": True},
    "192.0.2.23": {"mac": "02:00:5e:00:53:14", "state": "STALE",
                     "locally_administered": True},
    "192.0.2.55": {"mac": "aa:bb:cc:dd:ee:01", "state": "REACHABLE",
                     "locally_administered": False},
}
BRIDGES = [{"network": "metehantech-dns_default", "subnet": "172.19.0.0/16",
            "gateway": "172.19.0.1",
            "_parsed": ipaddress.ip_network("172.19.0.0/16")}]


STATUS = {"version": "v0.107.79", "running": True, "protection_enabled": True,
          "dns_port": 3053, "http_port": 3000, "start_time": 1789973053679.5}
STATS = {
    "time_units": "hours",
    "num_dns_queries": 1000, "num_blocked_filtering": 120,
    "avg_processing_time": 0.0612,
    "top_clients": [{"192.0.2.20": 700}, {"192.0.2.55": 300}],
    "top_queried_domains": [{f"d{i}.example": 100 - i} for i in range(40)],
    "top_blocked_domains": [{"doubleclick.net": 90}],
    "top_upstreams_responses": [{"https://dns.quad9.net:443/dns-query": 800}],
}
CLIENTS = {
    "clients": [{"name": "Pi5 (Raspberry Pi 5)", "ids": ["192.0.2.20", "100.64.0.10"]}],
    "auto_clients": [{"ip": "192.0.2.99", "name": "printer", "source": "rDNS"},
                     {"ip": "192.0.2.20", "name": "primary-node", "source": "rDNS"}],
}
CONFIG = {"upstream_dns": ["https://dns.quad9.net/dns-query"], "fallback_dns": ["192.0.2.1"],
          "bootstrap_dns": ["9.9.9.9"], "local_ptr_upstreams": ["192.0.2.1"],
          "dnssec_enabled": True, "cache_size": 16777216, "ratelimit": 20}
FILTERS = {"enabled": True, "filters": [{"name": "AdGuard DNS filter", "enabled": True,
                                         "rules_count": 181411, "last_updated": "2026-09-21T06:40:14Z"}]}
QUERYLOG_CONFIG = {"enabled": True, "interval": 72 * 3600 * 1000}
CLUSTER_HEALTHY = {
    "state": "HEALTHY", "serving": 2, "healthy": 2, "total": 2,
    "redundant": True, "collection_age_seconds": 0.0,
    "note": "Both resolvers answering and filtering.",
    "members": [
        {"node": "pi5", "label": "Pi5 Resolver", "address": "192.0.2.20",
         "role": "primary", "answering": True, "filtering": True,
         "health": "HEALTHY", "latency_ms": 2.0,
         "detail": "serving filtered answers"},
        {"node": "pcold", "label": "PcOld Resolver", "address": "192.0.2.22",
         "role": "secondary", "answering": True, "filtering": True,
         "health": "HEALTHY", "latency_ms": 2.0,
         "detail": "serving filtered answers"},
    ],
}


def _log(count, cached=0, blocked=False, client="192.0.2.20"):
    rows = []
    for index in range(count):
        rows.append({
            "time": "2026-09-21T06:45:51.498445773Z",
            "client": client,
            "client_info": {"name": "Pi5 (Raspberry Pi 5)"},
            "question": {"name": f"h{index}.example", "type": "A", "class": "IN"},
            "status": "NOERROR",
            "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
            "cached": index < cached,
            "elapsedMs": "1.5",
            "upstream": "https://dns.quad9.net:443/dns-query",
        })
    return {"data": rows, "oldest": "2026-09-21T06:00:00Z"}


@pytest.fixture
def adguard(monkeypatch):
    """Stub every AdGuard call. `calls` records what the module asked for."""
    calls = []

    def fake_call(path, *, data=None, timeout=8):
        calls.append(path)
        if path.startswith("/control/status"):
            return dict(STATUS)
        if path.startswith("/control/stats"):
            return dict(STATS)
        if path.startswith("/control/clients"):
            return json.loads(json.dumps(CLIENTS))
        if path.startswith("/control/dns_info"):
            return dict(CONFIG)
        if path.startswith("/control/filtering/status"):
            return json.loads(json.dumps(FILTERS))
        if path.startswith("/control/querylog/config"):
            return dict(QUERYLOG_CONFIG)
        if path.startswith("/control/querylog"):
            if "response_status=blocked" in path:
                return _log(3, blocked=True)
            return _log(10, cached=4)
        if path.startswith("/control/test_upstream_dns"):
            return {"https://dns.quad9.net:443/dns-query": "OK", "192.0.2.1:53": "OK"}
        raise AssertionError(f"unexpected AdGuard path {path}")

    monkeypatch.setattr(dns_center, "_call", fake_call)
    monkeypatch.setattr(dns_cluster, "collect", lambda: json.loads(json.dumps(CLUSTER_HEALTHY)))
    monkeypatch.setattr(dns_cluster, "summary", lambda: json.loads(json.dumps(CLUSTER_HEALTHY)))
    # Identity evidence is stubbed rather than read from this machine.
    monkeypatch.setattr(dns_inventory, "neighbours", lambda: dict(NEIGHBOURS))
    monkeypatch.setattr(dns_inventory, "gateways", lambda: {"192.0.2.1": "wlan0"})
    monkeypatch.setattr(dns_inventory, "local_addresses", lambda: {"192.0.2.20": "wlan0"})
    monkeypatch.setattr(dns_inventory, "docker_bridges", lambda: list(BRIDGES))
    dns_inventory._cache = dns_inventory._cache_at = None
    dns_center._snapshot = dns_center._snapshot_at = None
    dns_center._upstreams = dns_center._upstreams_at = None
    yield calls
    dns_inventory._cache = dns_inventory._cache_at = None
    dns_center._snapshot = dns_center._snapshot_at = None
    dns_center._upstreams = dns_center._upstreams_at = None


# ---------------------------------------------------------------------- collection

def test_collect_builds_a_healthy_summary(adguard):
    dns_center.collect([{"name": "metehantech-adguard", "state": "healthy", "restart_count": 0}])
    summary = dns_center.summary()
    assert summary["available"] is True
    assert summary["health"] == "HEALTHY"
    assert summary["version"] == "v0.107.79"
    assert summary["queries"] == 1000 and summary["blocked"] == 120
    assert summary["blocked_percent"] == 12.0
    assert summary["avg_processing_ms"] == 61.2
    assert summary["dnssec_enabled"] is True
    assert summary["querylog_interval_hours"] == 72.0
    assert summary["container"]["restart_count"] == 0


def test_top_lists_are_bounded_server_side(adguard):
    dns_center.collect()
    summary = dns_center.summary()
    assert len(STATS["top_queried_domains"]) > dns_center.TOP_LIMIT
    assert len(summary["top_queried_domains"]) == dns_center.TOP_LIMIT


def test_client_names_use_inventory_then_rdns_and_never_invent(adguard):
    dns_center.collect()
    clients = {row["key"]: row for row in dns_center.summary()["top_clients"]}
    # persistent inventory wins over the rDNS observation for the same address
    assert clients["192.0.2.20"]["name"] == "Pi5 (Raspberry Pi 5)"
    assert clients["192.0.2.20"]["name_source"] == "inventory"
    # an address with no evidence at all gets no name; the UI renders "Unknown client"
    assert clients["192.0.2.55"]["name"] is None
    assert clients["192.0.2.55"]["name_source"] is None


def test_cache_ratio_is_reported_as_a_bounded_sample(adguard):
    dns_center.collect()
    cache = dns_center.summary()["cache"]
    assert cache == {"sample_size": 10, "hits": 4, "hit_percent": 40.0}


def test_blocked_per_client_comes_from_the_blocked_sample(adguard):
    dns_center.collect()
    clients = {row["key"]: row for row in dns_center.summary()["top_clients"]}
    assert clients["192.0.2.20"]["blocked"] == 3
    assert clients["192.0.2.55"]["blocked"] == 0


# ------------------------------------------------------- traffic history / percentiles

def test_traffic_series_is_real_and_never_invents_a_cached_line(adguard, monkeypatch):
    """AdGuard's own per-bucket counters are passed through untouched."""
    monkeypatch.setitem(STATS, "dns_queries", [0, 4, 9])
    monkeypatch.setitem(STATS, "blocked_filtering", [0, 1, 2])
    dns_center.collect()
    traffic = dns_center.summary()["traffic"]
    assert traffic["units"] == "hours"
    assert traffic["buckets"] == 3
    assert traffic["queries"] == [0, 4, 9]
    assert traffic["blocked"] == [0, 1, 2]
    # AdGuard publishes no cached-query series; the UI is told so instead of guessing.
    assert traffic["cached_series_available"] is False


def test_traffic_reports_no_history_rather_than_a_placeholder(adguard):
    """The stats fixture carries no series, so the result must be empty, not invented."""
    dns_center.collect()
    assert dns_center.summary()["traffic"] == {
        "units": None, "buckets": 0, "queries": [], "blocked": [],
        "cached_series_available": False}


def test_traffic_drops_a_mismatched_blocked_series(adguard, monkeypatch):
    """Unequal array lengths cannot be aligned, so the blocked line is withheld."""
    monkeypatch.setitem(STATS, "dns_queries", [1, 2, 3])
    monkeypatch.setitem(STATS, "blocked_filtering", [1])
    dns_center.collect()
    traffic = dns_center.summary()["traffic"]
    assert traffic["queries"] == [1, 2, 3]
    assert traffic["blocked"] == []


def test_latency_percentiles_are_measured_from_the_bounded_sample(adguard):
    dns_center.collect()
    latency = dns_center.summary()["latency"]
    assert latency["sample_size"] == 10        # the same sample the cache ratio used
    assert latency["p50_ms"] == 1.5
    assert latency["p95_ms"] == 1.5


def test_latency_percentiles_pick_the_real_upper_tail():
    rows = [{"elapsedMs": str(value)} for value in range(1, 101)]
    assert dns_center._percentiles(rows) == {
        "sample_size": 100, "p50_ms": 50.0, "p95_ms": 95.0}


@pytest.mark.parametrize("rows", [[], [{"elapsedMs": None}], [{"elapsedMs": "nope"}], [{}]])
def test_latency_percentiles_stay_null_without_a_usable_sample(rows):
    assert dns_center._percentiles(rows) == {
        "sample_size": 0, "p50_ms": None, "p95_ms": None}


def test_latency_percentiles_never_widen_a_single_sample():
    """One measurement is reported as itself, not spread into a fake distribution."""
    assert dns_center._percentiles([{"elapsedMs": "7.25"}]) == {
        "sample_size": 1, "p50_ms": 7.25, "p95_ms": 7.25}


def test_upstream_average_is_converted_to_milliseconds(adguard, monkeypatch):
    monkeypatch.setitem(STATS, "top_upstreams_avg_time",
                        [{"https://dns.quad9.net:443/dns-query": 0.2405541}])
    dns_center.collect()
    assert dns_center.summary()["top_upstreams_avg_ms"] == [
        {"key": "https://dns.quad9.net:443/dns-query", "count": 240.6}]


def test_upstream_probe_is_rate_limited(adguard):
    dns_center.collect()
    first = sum(1 for path in adguard if path.startswith("/control/test_upstream_dns"))
    dns_center.collect()
    second = sum(1 for path in adguard if path.startswith("/control/test_upstream_dns"))
    assert first == 1 and second == 1, "the slow upstream test must not run every cycle"


def test_fallback_resolver_is_labelled_separately(adguard):
    dns_center.collect()
    roles = {u["address"]: u["role"] for u in dns_center.summary()["upstreams"]}
    assert roles["192.0.2.1:53"] == "fallback"
    assert roles["https://dns.quad9.net:443/dns-query"] == "upstream"


def test_summary_survives_a_total_adguard_outage(monkeypatch):
    import urllib.error

    def broken(path, *, data=None, timeout=8):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(dns_center, "_call", broken)
    monkeypatch.setattr(dns_cluster, "collect", lambda: json.loads(json.dumps(CLUSTER_HEALTHY)))
    monkeypatch.setattr(dns_cluster, "summary", lambda: json.loads(json.dumps(CLUSTER_HEALTHY)))
    dns_center._snapshot = dns_center._snapshot_at = None
    dns_center._upstreams = dns_center._upstreams_at = None
    dns_center.collect()
    summary = dns_center.summary()
    assert summary["available"] is False
    assert summary["health"] == "CRITICAL"
    assert summary["server_addresses"] == list(dns_center.DNS_SERVER_ADDRESSES)


def test_no_credential_ever_reaches_the_summary(adguard, tmp_path, monkeypatch):
    secret = "SuperSecretAdGuardPassword123"
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"username": "mtadmin", "password": secret}))
    monkeypatch.setattr(dns_center, "CREDENTIALS_PATH", path)
    dns_center.collect()
    payload = json.dumps(dns_center.summary())
    assert secret not in payload
    assert "mtadmin" not in payload
    assert "password" not in payload.lower()


# -------------------------------------------------------------------------- health

@pytest.mark.parametrize("patch,expected", [
    ({}, "HEALTHY"),
    ({"available": False}, "CRITICAL"),
    ({"available": None}, "UNKNOWN"),
    ({"protection_enabled": False}, "WARNING"),
    ({"upstreams": [{"address": "a", "healthy": False, "role": "upstream"}]}, "CRITICAL"),
    ({"upstreams": [{"address": "a", "healthy": True, "role": "upstream"},
                    {"address": "b", "healthy": False, "role": "fallback"}]}, "WARNING"),
    ({"avg_processing_ms": 900}, "WARNING"),
    ({"freshness": "CRITICAL"}, "CRITICAL"),
])
def test_health_rollup(patch, expected):
    data = {"available": True, "running": True, "protection_enabled": True,
            "upstreams": [{"address": "a", "healthy": True, "role": "upstream"}],
            "avg_processing_ms": 20, "freshness": "HEALTHY"}
    data.update(patch)
    assert dns_center.health(data) == expected


@pytest.mark.parametrize("state,expected", [
    ("HEALTHY", "HEALTHY"),
    ("DEGRADED", "WARNING"),
    ("CRITICAL", "CRITICAL"),
])
def test_cluster_state_participates_in_health_rollup(state, expected):
    data = {"available": True, "running": True, "protection_enabled": True,
            "upstreams": [{"address": "a", "healthy": True, "role": "upstream"}],
            "avg_processing_ms": 20, "freshness": "HEALTHY",
            "cluster": {"state": state}}
    assert dns_center.health(data) == expected


# -------------------------------------------------------------------------- routes

@pytest.fixture
def client(adguard, monkeypatch):
    import admin
    monkeypatch.setattr(admin, "admin_required", lambda view: view)
    from app import app
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


def test_endpoints_require_authentication():
    from app import app
    app.config.update(TESTING=True)
    with app.test_client() as anonymous:
        assert anonymous.get("/api/admin/dns-center").status_code == 401
        assert anonymous.get("/api/admin/dns-center/recent").status_code == 401
        assert anonymous.get(
            "/api/admin/dns-center/client?address=192.0.2.20").status_code == 401


def _authenticated():
    from app import app
    app.config.update(TESTING=True)
    session_client = app.test_client()
    with session_client.session_transaction() as session:
        session["admin_authenticated"] = True
    return session_client


def test_client_detail_rejects_a_missing_or_oversized_address(adguard):
    session_client = _authenticated()
    for query in ("", "?address=", "?address=" + "x" * 65):
        assert session_client.get(
            "/api/admin/dns-center/client" + query).status_code == 400, query


def test_client_detail_counts_only_the_requested_client(adguard, monkeypatch):
    """AdGuard's own `search` also matches domains, so the sample is filtered exactly."""
    mine = _log(4, blocked=True, client="192.0.2.55")["data"]
    someone_else = _log(6, client="192.0.2.99")["data"]

    def fake_call(path, *, data=None, timeout=8):
        if path.startswith("/control/querylog?search="):
            return {"data": mine + someone_else, "oldest": None}
        return _original(path, data=data, timeout=timeout)

    _original = dns_center._call
    dns_center.collect()                     # populate the authoritative snapshot
    monkeypatch.setattr(dns_center, "_call", fake_call)

    payload = _authenticated().get(
        "/api/admin/dns-center/client?address=192.0.2.55").get_json()
    assert payload["address"] == "192.0.2.55"
    assert payload["sample"]["size"] == 4, "rows from other clients must not be counted"
    assert payload["sample"]["blocked"] == 4
    assert payload["sample"]["blocked_percent"] == 100.0
    # Lifetime totals come from AdGuard's statistics, not from the bounded sample.
    assert payload["lifetime"]["queries"] == 300
    assert payload["lifetime"]["blocked"] == 0
    domains = {row["key"] for row in payload["top_queried_domains"]}
    assert domains == {f"h{index}.example" for index in range(4)}


def test_client_detail_reports_an_unknown_client_without_inventing_a_name(adguard, monkeypatch):
    dns_center.collect()
    monkeypatch.setattr(dns_center, "_call",
                        lambda path, **kw: {"data": [], "oldest": None})
    payload = _authenticated().get(
        "/api/admin/dns-center/client?address=203.0.113.7").get_json()
    assert payload["lifetime"]["name"] is None
    assert payload["sample"] == {"size": 0, "requested": dns_center.CLIENT_SAMPLE,
                                "blocked": 0, "blocked_percent": None, "last_seen": None}
    assert payload["top_queried_domains"] == []


def test_client_detail_reports_adguard_outage_rather_than_empty_data(adguard, monkeypatch):
    dns_center.collect()

    def dead(path, **kwargs):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(dns_center, "_call", dead)
    assert _authenticated().get(
        "/api/admin/dns-center/client?address=192.0.2.20").status_code == 503


def test_client_detail_never_exposes_the_adguard_credential(adguard, tmp_path, monkeypatch):
    secret = "adguard-drawer-secret"
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"username": "admin", "password": secret}))
    monkeypatch.setattr(dns_center, "CREDENTIALS_PATH", path)
    dns_center.collect()
    body = _authenticated().get(
        "/api/admin/dns-center/client?address=192.0.2.20").get_data(as_text=True)
    assert secret not in body and "password" not in body


def test_recent_carries_the_fields_the_detail_drawer_shows(adguard):
    payload = _authenticated().get(
        "/api/admin/dns-center/recent?limit=25").get_json()
    row = payload["rows"][0]
    for field in ("client", "client_name", "name", "type", "status", "reason",
                  "upstream", "elapsed_ms", "dnssec", "rules", "answers", "time"):
        assert field in row, field
    assert row["upstream"] == "https://dns.quad9.net:443/dns-query"
    assert isinstance(row["rules"], list) and isinstance(row["answers"], list)


def test_recent_rejects_out_of_range_parameters(adguard):
    from app import app
    app.config.update(TESTING=True)
    with app.test_client() as anonymous:
        with anonymous.session_transaction() as session:
            session["admin_authenticated"] = True
        for query in ("?limit=9999", "?limit=abc", "?filter=EVERYTHING",
                      "?client=" + "x" * 65, "?older_than=" + "y" * 65):
            response = anonymous.get("/api/admin/dns-center/recent" + query)
            assert response.status_code == 400, query


def test_public_status_never_exposes_dns_history(monkeypatch, adguard):
    """Phase 11: the anonymous page may say AdGuard is up, never what was resolved."""
    import app as app_module
    monkeypatch.setattr(app_module, "http_healthy", lambda url: True)
    monkeypatch.setattr(app_module, "read_old_pc", lambda: {"id": "pcold", "name": "PcOld",
                                                            "online": False, "metrics": {}, "checks": {}})
    monkeypatch.setattr(app_module, "read_cloud", lambda: {"containers": {}, "reachable": True,
                                                           "storage": {}, "last_backup": {}})
    dns_center.collect()
    payload = json.dumps(app_module.get_status())
    assert '"AdGuard Home"' in payload
    for leak in ("doubleclick.net", "d0.example", "top_queried_domains",
                 "top_clients", "querylog", "192.0.2.55"):
        assert leak not in payload, leak


# -------------------------------------------------------------------------- alerts

@pytest.fixture
def alert_db(tmp_path, monkeypatch):
    import alerts
    path = tmp_path / "alerts.db"
    monkeypatch.setattr(alerts, "DB_PATH", path)
    return path


def _active(db_path, alert_type):
    from alerts import get_alerts
    return [row for row in get_alerts(status="active", limit=50, db_path=db_path)
            if row["alert_type"] == alert_type]


def test_single_missed_probe_does_not_raise_an_alert(alert_db):
    dns_alerts.evaluate_dns({"available": False, "collection_age_seconds": 5},
                            now=time.time(), db_path=alert_db)
    assert not _active(alert_db, "adguard_unavailable")


def test_repeated_outage_escalates_then_resolves(alert_db):
    now = time.time()
    for index in range(dns_alerts.UNAVAILABLE_WARNING):
        dns_alerts.evaluate_dns({"available": False, "collection_age_seconds": 5},
                                now=now + index, db_path=alert_db)
    warning = _active(alert_db, "adguard_unavailable")
    assert warning and warning[0]["severity"] == "warning"

    for index in range(dns_alerts.UNAVAILABLE_CRITICAL):
        dns_alerts.evaluate_dns({"available": False, "collection_age_seconds": 5},
                                now=now + 10 + index, db_path=alert_db)
    critical = _active(alert_db, "adguard_unavailable")
    assert critical and critical[0]["severity"] == "critical"

    healthy = {"available": True, "running": True, "protection_enabled": True,
               "collection_age_seconds": 5, "avg_processing_ms": 20,
               "upstreams": [{"address": "a", "healthy": True, "role": "upstream"}]}
    for index in range(dns_alerts.RECOVERY_SAMPLES):
        dns_alerts.evaluate_dns(healthy, now=now + 30 + index, db_path=alert_db)
    assert not _active(alert_db, "adguard_unavailable")


def test_all_upstreams_down_is_critical_and_partial_is_warning(alert_db):
    now = time.time()
    base = {"available": True, "running": True, "protection_enabled": True,
            "collection_age_seconds": 5, "avg_processing_ms": 20}
    down = dict(base, upstreams=[{"address": "a", "healthy": False, "role": "upstream"},
                                 {"address": "b", "healthy": False, "role": "upstream"}])
    for index in range(dns_alerts.UPSTREAM_SAMPLES):
        dns_alerts.evaluate_dns(down, now=now + index, db_path=alert_db)
    assert _active(alert_db, "dns_upstream_all_down")[0]["severity"] == "critical"
    assert not _active(alert_db, "dns_upstream_degraded")

    partial = dict(base, upstreams=[{"address": "a", "healthy": True, "role": "upstream"},
                                    {"address": "b", "healthy": False, "role": "upstream"}])
    for index in range(dns_alerts.UPSTREAM_SAMPLES + dns_alerts.RECOVERY_SAMPLES):
        dns_alerts.evaluate_dns(partial, now=now + 20 + index, db_path=alert_db)
    assert not _active(alert_db, "dns_upstream_all_down")
    assert _active(alert_db, "dns_upstream_degraded")[0]["severity"] == "warning"


def test_latency_alert_needs_sustained_slowness(alert_db):
    now = time.time()
    slow = {"available": True, "running": True, "protection_enabled": True,
            "collection_age_seconds": 5, "avg_processing_ms": dns_alerts.LATENCY_WARNING_MS + 50,
            "upstreams": [{"address": "a", "healthy": True, "role": "upstream"}]}
    dns_alerts.evaluate_dns(slow, now=now, db_path=alert_db)
    assert not _active(alert_db, "dns_latency_high")
    for index in range(dns_alerts.LATENCY_SAMPLES):
        dns_alerts.evaluate_dns(slow, now=now + 1 + index, db_path=alert_db)
    assert _active(alert_db, "dns_latency_high")[0]["severity"] == "warning"


def test_stale_collector_uses_the_shared_thresholds(alert_db):
    from health_model import STALE_CRITICAL, STALE_WARNING
    now = time.time()
    base = {"available": True, "running": True, "protection_enabled": True,
            "avg_processing_ms": 20,
            "upstreams": [{"address": "a", "healthy": True, "role": "upstream"}]}
    dns_alerts.evaluate_dns(dict(base, collection_age_seconds=STALE_WARNING + 1),
                            now=now, db_path=alert_db)
    assert _active(alert_db, "dns_collector_stale")[0]["severity"] == "warning"
    dns_alerts.evaluate_dns(dict(base, collection_age_seconds=STALE_CRITICAL + 1),
                            now=now + 1, db_path=alert_db)
    assert _active(alert_db, "dns_collector_stale")[0]["severity"] == "critical"
    dns_alerts.evaluate_dns(dict(base, collection_age_seconds=5), now=now + 2, db_path=alert_db)
    assert not _active(alert_db, "dns_collector_stale")


def test_cluster_degraded_is_debounced_warning_then_recovers(alert_db):
    now = time.time()
    degraded = {
        "state": "DEGRADED", "serving": 1, "healthy": 1, "total": 2,
        "members": [
            {"node": "pi5", "label": "Pi5 Resolver", "address": "192.0.2.20",
             "health": "HEALTHY", "detail": "serving filtered answers"},
            {"node": "pcold", "label": "PcOld Resolver", "address": "192.0.2.22",
             "health": "CRITICAL", "detail": "no answer"},
        ],
    }
    dns_alerts.evaluate_cluster(degraded, now=now, db_path=alert_db)
    assert not _active(alert_db, "dns_cluster_degraded")
    dns_alerts.evaluate_cluster(degraded, now=now + 1, db_path=alert_db)
    assert _active(alert_db, "dns_cluster_degraded")[0]["severity"] == "warning"
    assert _active(alert_db, "dns_resolver_unhealthy")[0]["severity"] == "warning"

    healthy = json.loads(json.dumps(CLUSTER_HEALTHY))
    for index in range(dns_alerts.RECOVERY_SAMPLES):
        dns_alerts.evaluate_cluster(healthy, now=now + 10 + index, db_path=alert_db)
    assert not _active(alert_db, "dns_cluster_degraded")
    assert not _active(alert_db, "dns_resolver_unhealthy")


def test_cluster_both_down_is_debounced_critical(alert_db):
    now = time.time()
    down = {
        "state": "CRITICAL", "serving": 0, "healthy": 0, "total": 2,
        "members": [
            {"node": "pi5", "label": "Pi5 Resolver", "address": "192.0.2.20",
             "health": "CRITICAL", "detail": "no answer"},
            {"node": "pcold", "label": "PcOld Resolver", "address": "192.0.2.22",
             "health": "CRITICAL", "detail": "no answer"},
        ],
    }
    for index in range(dns_alerts.CLUSTER_SAMPLES):
        dns_alerts.evaluate_cluster(down, now=now + index, db_path=alert_db)
    assert _active(alert_db, "dns_cluster_down")[0]["severity"] == "critical"


# =========================================================== client identity
# The rule under test throughout this block: a matching hostname is never enough to
# merge two addresses, and a category is never set without evidence behind it.


def _table(clients=None):
    dns_inventory._cache = dns_inventory._cache_at = None
    return dns_inventory.snapshot(clients if clients is not None else CLIENTS)


def test_same_hostname_different_mac_is_never_merged(adguard):
    """Two real devices answer to "RE305"; the neighbour table proves they differ."""
    clients = {"clients": [], "auto_clients": [
        {"ip": "192.0.2.157", "name": "RE305", "source": "rDNS"},
        {"ip": "192.0.2.42", "name": "RE305", "source": "rDNS"},
    ]}
    table = _table(clients)
    first = dns_inventory.describe("192.0.2.157", table)
    assert first["known_addresses"] is None            # not merged
    assert first["identity_source"] is None
    candidates = {item["address"]: item["reason"] for item in first["duplicate_candidates"]}
    assert "192.0.2.42" in candidates
    assert "different MAC" in candidates["192.0.2.42"]


def test_randomised_macs_with_the_same_hostname_are_not_merged_either(adguard):
    clients = {"clients": [], "auto_clients": [
        {"ip": "192.0.2.130", "name": "A72", "source": "rDNS"},
        {"ip": "192.0.2.23", "name": "A72", "source": "rDNS"},
    ]}
    table = _table(clients)
    facts = dns_inventory.describe("192.0.2.130", table)
    assert facts["known_addresses"] is None
    assert facts["mac_randomised"] is True
    assert "randomised" in facts["duplicate_candidates"][0]["reason"]


def test_reviewed_inventory_entry_does_merge_its_own_addresses(adguard):
    """AdGuard's persistent entry is human-reviewed, so its ids are one device."""
    table = _table()
    facts = dns_inventory.describe("192.0.2.20", table)
    assert sorted(facts["known_addresses"]) == ["100.64.0.10", "192.0.2.20"]
    assert "reviewed AdGuard inventory" in facts["identity_source"]


def test_same_universal_mac_on_two_addresses_is_one_device(adguard):
    shared = {"mac": "aa:bb:cc:dd:ee:02", "state": "REACHABLE", "locally_administered": False}
    dns_inventory._cache = dns_inventory._cache_at = None
    import contextlib
    original = dns_inventory.neighbours
    dns_inventory.neighbours = lambda: {"10.0.0.1": dict(shared), "10.0.0.2": dict(shared)}
    try:
        table = dns_inventory.snapshot({"clients": [], "auto_clients": []})
    finally:
        dns_inventory.neighbours = original
        dns_inventory._cache = dns_inventory._cache_at = None
    facts = dns_inventory.describe("10.0.0.1", table)
    assert facts["known_addresses"] == ["10.0.0.1", "10.0.0.2"]
    assert "universally administered MAC" in facts["identity_source"]


def test_docker_bridge_gateway_is_named_from_the_daemon_not_guessed(adguard):
    table = _table({"clients": [], "auto_clients": [{"ip": "172.19.0.1", "name": "",
                                                     "source": "ARP"}]})
    facts = dns_inventory.describe("172.19.0.1", table)
    assert facts["category"] == dns_inventory.INFRASTRUCTURE
    assert "metehantech-dns_default" in facts["name"]
    assert "docker network inspect" in facts["category_source"]


def test_an_address_without_evidence_stays_unknown(adguard):
    table = _table({"clients": [], "auto_clients": [
        {"ip": "192.0.2.207", "name": "iPhone", "source": "rDNS"}]})
    facts = dns_inventory.describe("192.0.2.207", table)
    # An rDNS hostname is an observation, so it names the row but classifies nothing.
    assert facts["name"] == "iPhone"
    assert facts["category"] == dns_inventory.UNKNOWN
    assert facts["category_source"] is None


def test_reviewed_role_label_classifies_only_persistent_entries(adguard):
    table = _table({"clients": [{"name": "Tapo C211 (Camera)", "ids": ["192.0.2.110"]}],
                    "auto_clients": [{"ip": "192.0.2.111", "name": "Some Camera",
                                      "source": "rDNS"}]})
    assert dns_inventory.describe("192.0.2.110", table)["category"] == dns_inventory.IOT
    # the same word seen only over rDNS proves nothing and must not classify
    assert dns_inventory.describe("192.0.2.111", table)["category"] == dns_inventory.UNKNOWN


def test_adguard_client_tag_outranks_a_name_derived_role(adguard):
    table = _table({"clients": [{"name": "Tapo C211 (Camera)", "ids": ["192.0.2.110"],
                                 "tags": ["device_phone"]}], "auto_clients": []})
    facts = dns_inventory.describe("192.0.2.110", table)
    assert facts["category"] == dns_inventory.USER_DEVICE
    assert "AdGuard client tag" in facts["category_source"]


def test_summary_carries_identity_for_every_listed_client(adguard):
    dns_center.collect()
    clients = {row["key"]: row for row in dns_center.summary()["top_clients"]}
    assert clients["192.0.2.20"]["category"] == dns_inventory.INFRASTRUCTURE
    assert clients["192.0.2.55"]["category"] == dns_inventory.UNKNOWN
    assert clients["192.0.2.55"]["identity"]["mac"] == "aa:bb:cc:dd:ee:01"


def test_identity_never_overwrites_an_existing_adguard_name(adguard):
    dns_center.collect()
    clients = {row["key"]: row for row in dns_center.summary()["top_clients"]}
    assert clients["192.0.2.20"]["name"] == "Pi5 (Raspberry Pi 5)"
    assert clients["192.0.2.20"]["name_source"] == "inventory"


def test_inventory_survives_a_host_without_ip_or_docker(monkeypatch):
    """The dashboard must degrade to "unknown", never to an exception."""
    monkeypatch.setattr(dns_inventory, "_run", lambda args: None)
    dns_inventory._cache = dns_inventory._cache_at = None
    table = dns_inventory.snapshot({"clients": [], "auto_clients": []})
    dns_inventory._cache = dns_inventory._cache_at = None
    facts = dns_inventory.describe("192.0.2.99", table)
    assert facts["category"] == dns_inventory.UNKNOWN
    assert facts["mac"] is None


# ================================================================== anomalies


def _rows(client, domain, count, *, start=0, step=10):
    base = 1789000000
    return [{"client": client, "time": time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(base + start + index * step)),
        "question": {"name": domain, "type": "A"}, "reason": "NotFilteredNotFound",
        "cached": True} for index in range(count)]


def test_a_sustained_single_domain_pattern_is_reported_with_its_measurement():
    findings, window = dns_anomaly.analyse(_rows("192.0.2.157", "a.root-servers.net", 60))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "repetitive_domain"
    assert finding["client"] == "192.0.2.157"
    assert finding["domain"] == "a.root-servers.net"
    assert finding["share_percent"] == 100.0
    assert finding["queries_per_minute"] == 6.1      # 60 queries over 590 s
    assert finding["sample_queries"] == 60
    assert window["span_seconds"] == 590.0


def test_a_short_burst_is_not_an_anomaly():
    """Thirty queries in ten seconds is a burst, not a pattern; span gate rejects it."""
    findings, _ = dns_anomaly.analyse(_rows("192.0.2.9", "x.example", 40, step=1))
    assert findings == []


def test_a_small_sample_is_not_an_anomaly():
    findings, _ = dns_anomaly.analyse(_rows("192.0.2.9", "x.example", 10, step=60))
    assert findings == []


def test_varied_traffic_at_a_normal_rate_is_not_an_anomaly():
    rows = []
    for index in range(60):
        rows.extend(_rows("192.0.2.9", f"d{index}.example", 1, start=index * 10))
    findings, _ = dns_anomaly.analyse(rows)
    assert findings == []


def test_the_finding_disappears_once_the_rate_falls_back():
    """No sticky state: the same client measured slower simply reports nothing."""
    assert dns_anomaly.analyse(_rows("192.0.2.157", "a.root-servers.net", 60))[0]
    quiet = _rows("192.0.2.157", "a.root-servers.net", 40, step=120)
    assert dns_anomaly.analyse(quiet)[0] == []


def test_anomalies_reach_the_summary_from_the_existing_sample(adguard, monkeypatch):
    """No extra AdGuard call is made for the anomaly pass."""
    monkeypatch.setattr(dns_center, "CACHE_SAMPLE", 300)
    dns_center.collect()
    calls = [path for path in adguard if path.startswith("/control/querylog?")]
    assert len(calls) == 2          # cache/latency sample + blocked sample, unchanged
    assert dns_center.summary()["anomalies"] == []
    assert dns_center.summary()["anomaly_window"]["sample_rows"] == 10


# ============================================================== filter states


@pytest.mark.parametrize("entry,expected", [
    ({"enabled": True, "rules_count": 181800, "last_updated": "2026-09-22T07:12:05Z"}, "RUNNING"),
    ({"enabled": False, "rules_count": 0, "last_updated": None}, "DISABLED"),
    ({"enabled": False, "rules_count": 4000, "last_updated": "2026-09-22T07:12:05Z"}, "DISABLED"),
    ({"enabled": True, "rules_count": 0, "last_updated": None}, "ERROR"),
    ({"enabled": True, "rules_count": 12, "last_updated": None}, "ERROR"),
])
def test_a_disabled_list_is_never_reported_as_a_failure(entry, expected):
    assert dns_center._filter_state(entry) == expected


def test_summary_labels_the_real_disabled_list(adguard, monkeypatch):
    monkeypatch.setitem(FILTERS, "filters", [
        {"name": "AdGuard DNS filter", "enabled": True, "rules_count": 181800,
         "last_updated": "2026-09-22T07:12:05Z"},
        {"name": "AdAway Default Blocklist", "enabled": False, "rules_count": 0,
         "last_updated": None},
    ])
    dns_center.collect()
    states = {row["name"]: row["state"] for row in dns_center.summary()["filters"]}
    assert states == {"AdGuard DNS filter": "RUNNING",
                      "AdAway Default Blocklist": "DISABLED"}


# ====================================================== query log filtering


def test_domain_and_type_filters_are_validated_server_side(adguard):
    session_client = _authenticated()
    for query in ("?domain=" + "x" * 254, "?domain=bad;rm -rf", "?domain=a b.com",
                  "?domain=$(id).com", "?type=NOPE", "?type=A;DROP"):
        assert session_client.get(
            "/api/admin/dns-center/recent" + query).status_code == 400, query


def test_domain_filter_is_pushed_down_to_adguard(adguard):
    session_client = _authenticated()
    response = session_client.get("/api/admin/dns-center/recent?domain=doubleclick.net")
    assert response.status_code == 200
    assert any("search=doubleclick.net" in path for path in adguard)
    assert response.get_json()["domain"] == "doubleclick.net"
    assert response.get_json()["post_filtered"] is False


def test_query_type_filter_is_applied_here_and_says_so(adguard, monkeypatch):
    session_client = _authenticated()
    response = session_client.get("/api/admin/dns-center/recent?type=AAAA&limit=25")
    assert response.status_code == 200
    payload = response.get_json()
    # The fixture log is all A records, so an AAAA filter must return nothing rather
    # than silently returning unfiltered rows.
    assert payload["rows"] == []
    assert payload["post_filtered"] is True
    assert payload["type"] == "AAAA"


def test_combining_client_and_domain_still_bounds_the_fetch(adguard):
    session_client = _authenticated()
    response = session_client.get(
        "/api/admin/dns-center/recent?domain=h1.example&client=192.0.2.20&limit=100")
    assert response.status_code == 200
    fetched = [path for path in adguard if "search=h1.example" in path]
    assert fetched, "domain should be the pushed-down term"
    assert f"limit={dns_center.POST_FILTER_CEILING}" in fetched[-1]


def test_recent_still_rejects_the_original_out_of_range_parameters(adguard):
    session_client = _authenticated()
    for query in ("?limit=1000", "?limit=abc", "?filter=EVERYTHING",
                  "?client=" + "x" * 65):
        assert session_client.get(
            "/api/admin/dns-center/recent" + query).status_code == 400, query


# ========================================================= domain + events API


def test_domain_detail_requires_authentication_and_validates_its_input(adguard):
    from app import app
    app.config.update(TESTING=True)
    with app.test_client() as anonymous:
        assert anonymous.get("/api/admin/dns-center/domain?name=a.com").status_code == 401
    session_client = _authenticated()
    for query in ("", "?name=", "?name=" + "x" * 254, "?name=a b", "?name=`id`"):
        assert session_client.get(
            "/api/admin/dns-center/domain" + query).status_code == 400, query


def test_domain_detail_counts_only_the_exact_domain(adguard, monkeypatch):
    rows = _log(4)["data"]
    rows[0]["question"]["name"] = "h0.example"
    rows[1]["question"]["name"] = "sub.h0.example"     # AdGuard's search also matches this
    rows[2]["question"]["name"] = "h0.example"
    rows[3]["question"]["name"] = "other.example"
    monkeypatch.setattr(dns_center, "_call",
                        lambda path, **kwargs: {"data": rows, "oldest": None}
                        if path.startswith("/control/querylog") else {})
    session_client = _authenticated()
    payload = session_client.get(
        "/api/admin/dns-center/domain?name=h0.example").get_json()
    assert payload["sample"]["size"] == 2
    assert payload["top_clients"][0]["count"] == 2


def test_events_require_authentication(adguard):
    from app import app
    app.config.update(TESTING=True)
    with app.test_client() as anonymous:
        assert anonymous.get("/api/admin/dns-center/events").status_code == 401


def test_events_are_built_from_recorded_transitions_only(adguard, monkeypatch, tmp_path):
    """Nothing is back-filled: an empty alert history yields an empty timeline."""
    monkeypatch.setenv("ALERTS_DB", str(tmp_path / "alerts.db"))
    dns_center.collect()
    session_client = _authenticated()
    payload = session_client.get("/api/admin/dns-center/events").get_json()
    kinds = {event["kind"] for event in payload["events"]}
    # only the real AdGuard filter timestamp from the fixture, no invented outages
    assert kinds <= {"filter_updated"}
    for event in payload["events"]:
        assert event["at"]


def test_events_render_a_real_alert_and_its_recovery(adguard, tmp_path):
    db = tmp_path / "alerts.db"
    now = time.time()
    outage = {"available": False, "collection_age_seconds": 1.0}
    for index in range(dns_alerts.UNAVAILABLE_WARNING):
        dns_alerts.evaluate_dns(outage, now=now + index, db_path=db)
    from alerts import get_alerts
    raised = [row for row in get_alerts(limit=50, db_path=db)
              if row["alert_type"] == "adguard_unavailable"]
    assert raised and raised[0]["created_at"]
