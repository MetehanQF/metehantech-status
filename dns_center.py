"""DNS Center — authenticated presentation over the local AdGuard Home instance.

Design constraints this module keeps:
  * The AdGuard credential lives in a 0600 file next to the container and is read
    server-side only. It is never placed in a response body, a template, a log line
    or any browser-visible surface.
  * AdGuard is reached over loopback (127.0.0.1:3000) exclusively.
  * The expensive work (status/stats/clients + upstream probing) happens once per
    minute inside the existing history collector, exactly like every other panel.
    UI requests read a cached snapshot.
  * Every list handed to the frontend is bounded server-side. Raw query history is
    never streamed in bulk.
  * Nothing here is reachable without an authenticated admin session.
"""
from copy import deepcopy
import http.cookiejar
import json
import math
from pathlib import Path
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import Blueprint, jsonify, request

from admin import admin_required
from health_model import freshness
import dns_anomaly
import dns_inventory
import network
import deployment

BASE_URL = "http://127.0.0.1:3000"
CREDENTIALS_PATH = deployment.path("DNS_CREDENTIALS")
CONTAINER = "metehantech-adguard"
DNS_SERVER_ADDRESSES = (network.endpoint("PI5_LAN_IP", 53), network.endpoint("PI5_TAILSCALE_IP", 53))

TOP_LIMIT = 15                 # Phase: "Top 10/20" — keep the payload small
RECENT_LIMITS = {25, 50, 100}  # server-side allowlist for the Recent Activity view
RECENT_FILTERS = {"ALL": "all", "BLOCKED": "blocked", "ALLOWED": "processed"}
# Record types the query-type filter accepts. Anything outside this list is rejected
# rather than forwarded, so no caller-controlled string reaches AdGuard.
QUERY_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
               "HTTPS", "SVCB", "DS", "DNSKEY", "CAA", "NAPTR", "ANY"}
DOMAIN_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_*")
# A query-type filter has to be applied here because AdGuard's query log has no type
# parameter. Over-fetching bounds how much is read to still fill one page.
POST_FILTER_MULTIPLIER = 4
POST_FILTER_CEILING = 400
EVENT_LIMIT = 40               # DNS Events timeline depth
CACHE_SAMPLE = 300             # bounded sample used to derive a cache-hit ratio and p50/p95
BLOCKED_SAMPLE = 500           # bounded sample used to derive blocked-per-client
CLIENT_SAMPLE = 400            # bounded sample behind the per-client drawer
UPSTREAM_PROBE_INTERVAL = 600  # AdGuard's upstream test is slow; run it every 10 min
LATENCY_WARNING_MS = 250       # see dns_alerts.evaluate_dns

dns = Blueprint("dns_center", __name__)

_lock = threading.Lock()
_snapshot = None
_snapshot_at = None
_upstreams = None
_upstreams_at = None

_session_lock = threading.Lock()
_opener = None


# --------------------------------------------------------------------------- client


def _credentials():
    """Read the 0600 credential file. Callers must never return this value."""
    with CREDENTIALS_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data["username"], data["password"]


def _login():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    username, password = _credentials()
    payload = json.dumps({"name": username, "password": password}).encode()
    request_object = urllib.request.Request(
        BASE_URL + "/control/login", data=payload,
        headers={"Content-Type": "application/json"})
    with opener.open(request_object, timeout=5) as response:
        response.read()
    return opener


def _call(path, *, data=None, timeout=8):
    """One authenticated AdGuard call, re-authenticating once on session expiry."""
    global _opener
    for attempt in (1, 2):
        with _session_lock:
            if _opener is None:
                _opener = _login()
            opener = _opener
        headers = {"Content-Type": "application/json"} if data is not None else {}
        request_object = urllib.request.Request(
            BASE_URL + path,
            data=None if data is None else json.dumps(data).encode(),
            headers=headers)
        try:
            with opener.open(request_object, timeout=timeout) as response:
                body = response.read()
            return json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            if error.code in (401, 403) and attempt == 1:
                with _session_lock:
                    _opener = None
                continue
            raise
    raise urllib.error.URLError("authentication failed")


def _safe(provider, fallback=None):
    try:
        return provider()
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError):
        return fallback


# ----------------------------------------------------------------------- collection


def _client_names(clients):
    """IP -> display name, from AdGuard evidence only.

    Persistent entries come from the reviewed MetehanTech inventory. Auto entries come
    from rDNS / ARP / DHCP / hosts, which are observations rather than guesses. WHOIS is
    disabled in AdGuard, so nothing here is inferred from a public registry. Anything
    unmatched stays unnamed and the UI shows "Unknown client".
    """
    names = {}
    for entry in clients.get("auto_clients") or []:
        address, name = entry.get("ip"), entry.get("name")
        if address and name:
            names[address] = {"name": name, "source": entry.get("source") or "runtime"}
    for entry in clients.get("clients") or []:
        for address in entry.get("ids") or []:
            if entry.get("name"):
                names[address] = {"name": entry["name"], "source": "inventory"}
    return names


def _pairs(items, names=None, blocked=None, identity=None):
    """AdGuard returns top-lists as [{key: count}, …]. Flatten and bound them.

    ``identity`` is a dns_inventory table. When supplied, each client row also carries
    the provable identity facts (MAC, category, duplicate candidates) so the UI can
    filter and explain without a second round trip.
    """
    output = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        for key, count in item.items():
            row = {"key": key, "count": count}
            if names is not None:
                match = names.get(key)
                row["name"] = match["name"] if match else None
                row["name_source"] = match["source"] if match else None
            if blocked is not None:
                row["blocked"] = blocked.get(key, 0)
            if identity is not None:
                facts = _safe(lambda: dns_inventory.describe(key, identity))
                if facts:
                    # Provable evidence wins over a bare rDNS observation, but an
                    # existing AdGuard name is never overwritten with a guess.
                    if not row.get("name") and facts.get("name"):
                        row["name"] = facts["name"]
                        row["name_source"] = facts.get("name_source")
                    row["identity"] = facts
                    row["category"] = facts.get("category")
            output.append(row)
    return output[:TOP_LIMIT]


def _filter_state(entry):
    """RUNNING / DISABLED / ERROR — a switched-off list is not a failure.

    AdGuard reports an intentionally disabled list as ``enabled: false`` with zero
    rules and no ``last_updated``. That is a deliberate configuration, so it must not
    render in the same red as a list that is enabled but failed to load.
    """
    if not entry.get("enabled"):
        return "DISABLED"
    rules = entry.get("rules_count")
    if not isinstance(rules, int) or rules <= 0 or not entry.get("last_updated"):
        return "ERROR"
    return "RUNNING"


def _percentiles(rows):
    """Measured latency distribution from a bounded query-log sample.

    AdGuard publishes only ``avg_processing_time`` (a lifetime mean). A p95 therefore
    has to be measured, and the only real source is the per-query ``elapsedMs`` field.
    This reuses the sample already fetched for the cache ratio, so it costs no extra
    API call, and every value is reported together with the sample size it came from.
    Returns None-valued fields rather than a guess when the sample carries no latency.
    """
    values = []
    for row in rows or []:
        try:
            values.append(float(row["elapsedMs"]))
        except (KeyError, TypeError, ValueError):
            continue
    if not values:
        return {"sample_size": 0, "p50_ms": None, "p95_ms": None}
    values.sort()

    def at(percent):
        index = max(0, math.ceil(percent / 100 * len(values)) - 1)
        return round(values[index], 2)

    return {"sample_size": len(values), "p50_ms": at(50), "p95_ms": at(95)}


def _traffic(stats):
    """Real per-bucket history straight out of AdGuard's own statistics response.

    ``dns_queries`` / ``blocked_filtering`` are equal-length arrays of counters, one
    entry per ``time_units`` bucket, ordered oldest → newest; their sum matches
    ``num_dns_queries``. AdGuard publishes no cached-query series, so the UI plots
    total and blocked only and says so instead of inventing a third line.
    """
    queries = stats.get("dns_queries")
    blocked = stats.get("blocked_filtering")
    if not isinstance(queries, list) or not queries:
        return {"units": None, "buckets": 0, "queries": [], "blocked": [],
                "cached_series_available": False}
    if not isinstance(blocked, list) or len(blocked) != len(queries):
        blocked = []
    return {
        "units": stats.get("time_units"),
        "buckets": len(queries),
        "queries": queries,
        "blocked": blocked,
        # Stated explicitly so the frontend never has to assume why a line is absent.
        "cached_series_available": False,
    }


def _probe_upstreams(config):
    """AdGuard's own upstream test. Slow, so it is rate-limited by the caller."""
    body = {
        "upstream_dns": config.get("upstream_dns") or [],
        "bootstrap_dns": config.get("bootstrap_dns") or [],
        "fallback_dns": config.get("fallback_dns") or [],
        "private_upstream": config.get("local_ptr_upstreams") or [],
    }
    results = _call("/control/test_upstream_dns", data=body, timeout=45)
    fallback = set(body["fallback_dns"])
    upstreams = []
    for address, verdict in (results or {}).items():
        healthy = verdict == "OK"
        # AdGuard reports the normalised address ("9.9.9.9:53"); match on the host part.
        host = address.rsplit(":", 1)[0].strip("[]")
        upstreams.append({"address": address, "healthy": healthy,
                          "detail": None if healthy else str(verdict)[:200],
                          "role": "fallback" if (address in fallback or host in fallback) else "upstream"})
    return sorted(upstreams, key=lambda row: (row["role"], row["address"]))


def collect(container_states=None):
    """Called once per minute by the existing history collector. Never from a request."""
    global _snapshot, _snapshot_at, _upstreams, _upstreams_at
    now = time.time()

    started = time.perf_counter()
    status = _safe(lambda: _call("/control/status", timeout=5))
    api_latency_ms = round((time.perf_counter() - started) * 1000, 1) if status else None

    stats = _safe(lambda: _call("/control/stats", timeout=8), {}) or {}
    clients = _safe(lambda: _call("/control/clients", timeout=8), {}) or {}
    config = _safe(lambda: _call("/control/dns_info", timeout=8), {}) or {}
    filters = _safe(lambda: _call("/control/filtering/status", timeout=8), {}) or {}

    names = _client_names(clients)
    # Identity evidence (MAC, docker bridge, gateway, reviewed inventory). Built once
    # per cycle and reused for every client row; never rebuilt inside a request.
    identity = _safe(lambda: dns_inventory.snapshot(clients))

    # Cache-hit ratio is not exposed as a counter; derive it from a bounded sample and
    # label it as a sample in the UI rather than presenting it as a lifetime figure.
    sample = _safe(lambda: _call(f"/control/querylog?limit={CACHE_SAMPLE}", timeout=10), {}) or {}
    rows = sample.get("data") or []
    cached = sum(1 for row in rows if row.get("cached"))
    cache = {"sample_size": len(rows),
             "hits": cached,
             "hit_percent": round(cached / len(rows) * 100, 1) if rows else None}

    # Percentiles are measured from the same bounded sample that produced the cache
    # ratio — no extra AdGuard call. AdGuard exposes only a lifetime *average*, so the
    # UI must label these as a sample rather than as a lifetime figure.
    latency = _percentiles(rows)

    # Observation only, from the sample already in hand: no extra call, nothing blocked.
    anomalies, anomaly_window = _safe(lambda: dns_anomaly.analyse(rows), ([], None)) \
        or ([], None)

    blocked_sample = _safe(
        lambda: _call(f"/control/querylog?response_status=blocked&limit={BLOCKED_SAMPLE}", timeout=10), {}) or {}
    blocked_rows = blocked_sample.get("data") or []
    blocked_by_client = {}
    for row in blocked_rows:
        address = row.get("client")
        if address:
            blocked_by_client[address] = blocked_by_client.get(address, 0) + 1

    with _lock:
        stale_probe = _upstreams_at is None or now - _upstreams_at >= UPSTREAM_PROBE_INTERVAL
        upstream_cache, upstream_at = _upstreams, _upstreams_at
    if status and config and stale_probe:
        probed = _safe(lambda: _probe_upstreams(config))
        if probed is not None:
            upstream_cache, upstream_at = probed, now

    container = None
    for item in container_states or []:
        if item.get("name") == CONTAINER:
            container = item

    queries = stats.get("num_dns_queries")
    blocked = stats.get("num_blocked_filtering")
    snapshot = {
        "available": bool(status),
        "running": bool(status.get("running")) if status else None,
        "protection_enabled": status.get("protection_enabled") if status else None,
        "version": status.get("version") if status else None,
        "started_at": status.get("start_time") if status else None,
        "api_latency_ms": api_latency_ms,
        "server_addresses": list(DNS_SERVER_ADDRESSES),
        "admin_urls": {"lan": "http://" + network.endpoint("PI5_LAN_IP", 3000),
                       "tailscale": "http://" + network.endpoint("PI5_TAILSCALE_IP", 3000)},
        "gateway_address": network.get("ROUTER_LAN_IP"),
        "queries": queries,
        "blocked": blocked,
        "blocked_percent": round(blocked / queries * 100, 1) if queries and blocked is not None else (0.0 if queries == 0 else None),
        "avg_processing_ms": round(stats["avg_processing_time"] * 1000, 2) if isinstance(stats.get("avg_processing_time"), (int, float)) else None,
        "stats_window": stats.get("time_units"),
        "active_clients": len(stats.get("top_clients") or []) if stats else None,
        "cache": cache,
        "latency": latency,
        "traffic": _traffic(stats),
        "top_clients": _pairs(stats.get("top_clients"), names=names,
                              blocked=blocked_by_client, identity=identity),
        "top_queried_domains": _pairs(stats.get("top_queried_domains")),
        "top_blocked_domains": _pairs(stats.get("top_blocked_domains")),
        "top_upstreams": _pairs(stats.get("top_upstreams_responses")),
        "top_upstreams_avg_ms": [
            {"key": row["key"], "count": round(row["count"] * 1000, 1)}
            for row in _pairs(stats.get("top_upstreams_avg_time"))
            if isinstance(row.get("count"), (int, float))
        ],
        "upstreams": upstream_cache,
        "upstreams_checked_at": upstream_at,
        "configured_upstreams": config.get("upstream_dns") or [],
        "configured_fallback": config.get("fallback_dns") or [],
        "dnssec_enabled": config.get("dnssec_enabled"),
        "cache_size": config.get("cache_size"),
        "ratelimit": config.get("ratelimit"),
        "querylog_interval_hours": None,
        "filters": [{"name": f.get("name"), "enabled": f.get("enabled"),
                     "rules": f.get("rules_count"), "updated": f.get("last_updated"),
                     "url": f.get("url"), "state": _filter_state(f)}
                    for f in (filters.get("filters") or [])][:TOP_LIMIT],
        "filter_update_interval_hours": filters.get("interval"),
        "user_rules": len(filters.get("user_rules") or []),
        "filtering_enabled": filters.get("enabled"),
        "container": container,
        "blocked_sample_size": len(blocked_rows),
        "anomalies": anomalies,
        "anomaly_window": anomaly_window,
    }
    # Redundant-resolver view. Independent of the AdGuard API so it still reports
    # something useful when an API is down but the resolver itself is answering.
    try:
        from dns_cluster import collect as collect_cluster
        snapshot["cluster"] = collect_cluster()
    except Exception:
        snapshot["cluster"] = None
    querylog = _safe(lambda: _call("/control/querylog/config", timeout=5), {}) or {}
    interval = querylog.get("interval")
    if isinstance(interval, (int, float)):
        # AdGuard reports this in milliseconds on the modern endpoint.
        snapshot["querylog_interval_hours"] = round(interval / 3600000, 1) if interval > 10000 else interval
    snapshot["querylog_enabled"] = querylog.get("enabled")

    with _lock:
        _snapshot, _snapshot_at = snapshot, now
        _upstreams, _upstreams_at = upstream_cache, upstream_at
    return snapshot


def cached_snapshot():
    with _lock:
        if _snapshot is None:
            return None, None
        return deepcopy(_snapshot), _snapshot_at


def summary():
    """Shape consumed by both the Control Center summary and the DNS view."""
    snapshot, collected = cached_snapshot()
    now = time.time()
    age = max(0.0, now - collected) if collected else None
    if snapshot is None:
        return {"available": None, "health": "UNKNOWN", "freshness": "UNKNOWN",
                "collection_age_seconds": None,
                "server_addresses": list(DNS_SERVER_ADDRESSES),
                "note": "DNS collector has not produced a sample yet."}
    data = dict(snapshot)
    data["collection_age_seconds"] = round(age, 1) if age is not None else None
    data["freshness"] = freshness(age)
    from dns_cluster import summary as cluster_summary
    data["cluster"] = cluster_summary()
    data["health"] = health(data)
    return data


def health(data):
    if not data.get("available"):
        return "CRITICAL" if data.get("available") is False else "UNKNOWN"
    if data.get("running") is False or data.get("protection_enabled") is False:
        return "WARNING"
    upstreams = data.get("upstreams")
    if upstreams:
        primary = [u for u in upstreams if u["role"] == "upstream"]
        if primary and not any(u["healthy"] for u in primary):
            return "CRITICAL"
        if any(not u["healthy"] for u in upstreams):
            return "WARNING"
    latency = data.get("avg_processing_ms")
    if isinstance(latency, (int, float)) and latency > LATENCY_WARNING_MS:
        return "WARNING"
    cluster = data.get("cluster") or {}
    if cluster.get("state") == "CRITICAL":
        return "CRITICAL"
    if cluster.get("state") == "DEGRADED":
        return "WARNING"
    if data.get("freshness") in ("WARNING", "CRITICAL"):
        return data["freshness"]
    return "HEALTHY"


def service_state():
    """Entry for the existing Services view / public status services list."""
    snapshot, _ = cached_snapshot()
    if snapshot is None:
        return None
    if not snapshot.get("available"):
        return False
    if snapshot.get("running") is False:
        return False
    return True


# ---------------------------------------------------------------------------- routes


@dns.get("/api/admin/dns-center")
@admin_required
def dns_center():
    return jsonify(summary())


@dns.get("/api/admin/dns-center/client")
@admin_required
def client_detail():
    """Per-client detail for the DNS client drawer.

    Built from the same retained AdGuard query log the Recent Activity table already
    reads — there is no per-client statistics endpoint in AdGuard, so the only real
    source is a bounded query-log sample. The sample is filtered server-side on an
    exact client match (AdGuard's own ``search`` also matches domains), and the
    response always reports the sample size so the UI can label the numbers as a
    sample rather than as lifetime totals. Lifetime query/blocked counters come from
    the cached collector snapshot, which is authoritative.
    """
    address = request.args.get("address", "").strip()
    if not address or len(address) > 64:
        return jsonify(error="Invalid client"), 400

    path = "/control/querylog?" + urllib.parse.urlencode(
        {"search": address, "limit": CLIENT_SAMPLE})
    payload = _safe(lambda: _call(path, timeout=10))
    if payload is None:
        return jsonify(error="AdGuard unavailable"), 503

    queried, blocked_domains = {}, {}
    sampled = blocked_count = 0
    last_seen = None
    recent = []
    for row in payload.get("data") or []:
        # AdGuard's search matches the domain too; keep only this client's own queries.
        if row.get("client") != address:
            continue
        sampled += 1
        if len(recent) < 10:
            question = row.get("question") or {}
            recent.append({
                "time": row.get("time"),
                "name": question.get("name"),
                "type": question.get("type"),
                "status": row.get("status"),
                "blocked": str(row.get("reason", "")).startswith("Filtered"),
                "cached": bool(row.get("cached")),
                "elapsed_ms": round(float(row["elapsedMs"]), 2) if row.get("elapsedMs") else None,
            })
        if last_seen is None:
            last_seen = row.get("time")          # query log is newest-first
        domain = (row.get("question") or {}).get("name")
        if domain:
            queried[domain] = queried.get(domain, 0) + 1
            if str(row.get("reason", "")).startswith("Filtered"):
                blocked_domains[domain] = blocked_domains.get(domain, 0) + 1
        if str(row.get("reason", "")).startswith("Filtered"):
            blocked_count += 1

    def top(counter):
        return [{"key": key, "count": count} for key, count in
                sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:TOP_LIMIT]]

    snapshot, _ = cached_snapshot()
    lifetime = {"queries": None, "blocked": None, "blocked_percent": None,
                "name": None, "name_source": None}
    identity = None
    for entry in (snapshot or {}).get("top_clients") or []:
        if entry.get("key") == address:
            total, hits = entry.get("count"), entry.get("blocked")
            lifetime = {
                "queries": total,
                "blocked": hits,
                "blocked_percent": round(hits / total * 100, 1) if total and hits is not None else None,
                "name": entry.get("name"),
                "name_source": entry.get("name_source"),
            }
            identity = entry.get("identity")

    return jsonify({
        "address": address,
        "lifetime": lifetime,
        "identity": identity,
        "recent": recent,
        "sample": {
            "size": sampled,
            "requested": CLIENT_SAMPLE,
            "blocked": blocked_count,
            "blocked_percent": round(blocked_count / sampled * 100, 1) if sampled else None,
            "last_seen": last_seen,
        },
        "top_queried_domains": top(queried),
        "top_blocked_domains": top(blocked_domains),
        "available": bool(snapshot and snapshot.get("available")),
    })


@dns.get("/api/admin/dns-center/domain")
@admin_required
def domain_detail():
    """Per-domain detail, aggregated server-side from the retained query log.

    Same shape and same discipline as the client drawer: a bounded sample, an exact
    match applied here because AdGuard's ``search`` is a substring match, and the
    sample size reported so a capped number is never read as a lifetime total. This
    endpoint describes observed traffic only — it makes no claim about whether a
    domain is safe or malicious, because nothing in this system measures that.
    """
    name = request.args.get("name", "").strip().lower()
    if not name or len(name) > 253 or not set(name) <= DOMAIN_CHARS:
        return jsonify(error="Invalid domain"), 400

    path = "/control/querylog?" + urllib.parse.urlencode(
        {"search": name, "limit": CLIENT_SAMPLE})
    payload = _safe(lambda: _call(path, timeout=10))
    if payload is None:
        return jsonify(error="AdGuard unavailable"), 503

    clients, types, rules = {}, {}, {}
    sampled = blocked_count = cached_count = 0
    last_seen = first_seen = None
    for row in payload.get("data") or []:
        question = row.get("question") or {}
        if str(question.get("name") or "").lower() != name:
            continue
        sampled += 1
        if last_seen is None:
            last_seen = row.get("time")          # newest-first
        first_seen = row.get("time")
        address = row.get("client")
        if address:
            clients[address] = clients.get(address, 0) + 1
        kind = question.get("type")
        if kind:
            types[kind] = types.get(kind, 0) + 1
        if str(row.get("reason", "")).startswith("Filtered"):
            blocked_count += 1
            for rule in row.get("rules") or []:
                text = rule.get("text")
                if text:
                    rules[text] = rules.get(text, 0) + 1
        if row.get("cached"):
            cached_count += 1

    def top(counter):
        return [{"key": key, "count": count} for key, count in
                sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:TOP_LIMIT]]

    snapshot, _ = cached_snapshot()
    lifetime = None
    for bucket in ("top_queried_domains", "top_blocked_domains"):
        for entry in (snapshot or {}).get(bucket) or []:
            if str(entry.get("key") or "").lower() == name:
                lifetime = lifetime or {}
                lifetime["queries" if bucket == "top_queried_domains" else "blocked"] = entry.get("count")

    return jsonify({
        "domain": name,
        "lifetime": lifetime,
        "sample": {"size": sampled, "requested": CLIENT_SAMPLE,
                   "blocked": blocked_count, "cached": cached_count,
                   "blocked_percent": round(blocked_count / sampled * 100, 1) if sampled else None,
                   "last_seen": last_seen, "first_seen": first_seen},
        "query_types": top(types),
        "top_clients": top(clients),
        "matched_rules": top(rules),
        "available": bool(snapshot and snapshot.get("available")),
    })


@dns.get("/api/admin/dns-center/recent")
@admin_required
def recent():
    """Server-side filtered, bounded, cursor-paginated recent DNS activity."""
    raw_limit = request.args.get("limit", "50")
    response_filter = request.args.get("filter", "ALL").upper()
    client = request.args.get("client", "").strip()
    domain = request.args.get("domain", "").strip()
    query_type = request.args.get("type", "").strip().upper()
    cursor = request.args.get("older_than", "").strip()
    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify(error="Invalid limit"), 400
    if limit not in RECENT_LIMITS or response_filter not in RECENT_FILTERS:
        return jsonify(error="Invalid filter"), 400
    if len(client) > 64 or len(cursor) > 64:
        return jsonify(error="Invalid filter"), 400
    # A domain filter is forwarded to AdGuard, so it is validated on an allowlist of
    # characters a hostname can legitimately contain rather than merely escaped.
    if len(domain) > 253 or (domain and not set(domain) <= DOMAIN_CHARS):
        return jsonify(error="Invalid domain filter"), 400
    if query_type and query_type not in QUERY_TYPES:
        return jsonify(error="Invalid query type"), 400

    # AdGuard's query log takes a single free-text `search`, so only one of the two
    # text filters can be pushed down. The domain is the more selective of the pair;
    # whichever is not pushed down is applied here, over a bounded over-fetch.
    pushed = domain or client
    post_client = client if domain else ""
    fetch = limit
    if post_client or query_type:
        fetch = min(POST_FILTER_CEILING, limit * POST_FILTER_MULTIPLIER)

    params = {"limit": fetch, "response_status": RECENT_FILTERS[response_filter]}
    if pushed:
        params["search"] = pushed
    if cursor:
        params["older_than"] = cursor
    path = "/control/querylog?" + urllib.parse.urlencode(params)
    payload = _safe(lambda: _call(path, timeout=10))
    if payload is None:
        return jsonify(error="AdGuard unavailable"), 503

    def keep(row):
        if post_client and row.get("client") != post_client \
                and post_client.lower() not in str((row.get("client_info") or {}).get("name") or "").lower():
            return False
        if query_type and str((row.get("question") or {}).get("type") or "").upper() != query_type:
            return False
        return True

    snapshot, _ = cached_snapshot()
    rows = []
    for row in [item for item in (payload.get("data") or []) if keep(item)][:limit]:
        question = row.get("question") or {}
        info = row.get("client_info") or {}
        rows.append({
            "time": row.get("time"),
            "client": row.get("client"),
            "client_name": info.get("name") or None,
            "name": question.get("name"),
            "type": question.get("type"),
            "status": row.get("status"),
            "reason": row.get("reason"),
            "blocked": str(row.get("reason", "")).startswith("Filtered"),
            "cached": bool(row.get("cached")),
            "elapsed_ms": round(float(row["elapsedMs"]), 2) if row.get("elapsedMs") else None,
            "upstream": row.get("upstream") or None,
            # Present in every AdGuard query-log row; surfaced for the detail drawer.
            "dnssec": row.get("answer_dnssec"),
            "rules": [r.get("text") for r in (row.get("rules") or []) if r.get("text")][:3],
            "answers": [a.get("value") for a in (row.get("answer") or [])
                        if a.get("value")][:4],
        })
    return jsonify({"rows": rows, "older_than": payload.get("oldest") or None,
                    "limit": limit, "filter": response_filter,
                    "domain": domain or None, "client": client or None,
                    "type": query_type or None,
                    # True when a filter AdGuard cannot express was applied here, so a
                    # short page is a filtered page and not the end of the log.
                    "post_filtered": bool(post_client or query_type),
                    "fetched": len(payload.get("data") or []),
                    "available": bool(snapshot and snapshot.get("available"))})


@dns.get("/api/admin/dns-center/events")
@admin_required
def events():
    """DNS event timeline built from state changes this system already records.

    Two real sources, no new persistence layer and no invented history:
      * the existing Alert Center rows written by ``dns_alerts`` — every resolver
        outage, recovery, upstream failure and staleness transition is already stored
        there with its raised and resolved timestamps;
      * AdGuard's own ``last_updated`` per filter list, which is a dated fact.
    Before those rows exist there is simply nothing to show, and the UI says so.
    """
    try:
        import dns_alerts
        from alerts import get_alerts
        records = get_alerts(limit=100)
    except Exception:
        return jsonify(error="Alert history unavailable"), 503

    timeline = []
    for record in records:
        if record.get("source") != dns_alerts.SOURCE:
            continue
        timeline.append({
            "at": record.get("created_at"),
            "kind": "raised",
            "event_type": record.get("alert_type"),
            "severity": record.get("severity"),
            "target": record.get("target"),
            "title": record.get("title"),
            "detail": record.get("message"),
            "value": record.get("last_value"),
        })
        if record.get("resolved_at"):
            timeline.append({
                "at": record.get("resolved_at"),
                "kind": "resolved",
                "event_type": record.get("alert_type"),
                "severity": "info",
                "target": record.get("target"),
                "title": record.get("title") + " — recovered",
                "detail": "The condition stayed clear long enough for the alert to close.",
                "value": record.get("last_value"),
            })

    snapshot, _ = cached_snapshot()
    for entry in (snapshot or {}).get("filters") or []:
        if entry.get("updated"):
            timeline.append({
                "at": entry["updated"],
                "kind": "filter_updated",
                "event_type": "filter_list_updated",
                "severity": "info",
                "target": entry.get("name"),
                "title": "Filter list updated",
                "detail": f"{entry.get('name')} — {entry.get('rules')} rules.",
                "value": entry.get("state"),
            })

    timeline.sort(key=lambda item: str(item.get("at") or ""), reverse=True)
    return jsonify({"events": timeline[:EVENT_LIMIT],
                    "sources": ["Alert Center (dns_center rules)", "AdGuard filter metadata"],
                    "available": bool(timeline)})
