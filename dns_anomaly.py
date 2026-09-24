"""Observation-only DNS traffic anomalies.

This module *looks*. It never blocks, rewrites, filters or changes a device. It reads
the bounded query-log sample the collector has already fetched for the cache ratio —
so it costs no extra AdGuard call — and reports clients whose measured behaviour in
that sample is unusual, with the measurement attached.

A finding is emitted only when the sample is large enough and long enough to mean
something, and it disappears on its own as soon as the measured rate falls back under
the threshold. No client, domain or verdict is hardcoded anywhere in this file.
"""
from datetime import datetime, timezone

MIN_SAMPLES = 30        # below this a rate is noise, not a pattern
MIN_SPAN_SECONDS = 120  # and so is a burst measured over a couple of seconds
REPETITION_SHARE = 0.80  # one domain accounting for this much of a client's queries
REPETITION_RATE = 3.0   # queries/min sustained on that one domain
HIGH_RATE = 30.0        # queries/min from a single client, whatever it is asking for
MAX_FINDINGS = 6


def _moment(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def analyse(rows, *, now=None):
    """Return (findings, window) for a bounded newest-first query-log sample."""
    reference = datetime.now(timezone.utc) if now is None else now
    clients = {}
    newest = oldest = None

    for row in rows or []:
        address = row.get("client")
        if not address:
            continue
        moment = _moment(row.get("time"))
        domain = (row.get("question") or {}).get("name")
        entry = clients.setdefault(address, {
            "queries": 0, "domains": {}, "newest": None, "oldest": None,
            "blocked": 0, "cached": 0,
        })
        entry["queries"] += 1
        if domain:
            entry["domains"][domain] = entry["domains"].get(domain, 0) + 1
        if str(row.get("reason", "")).startswith("Filtered"):
            entry["blocked"] += 1
        if row.get("cached"):
            entry["cached"] += 1
        if moment is not None:
            if entry["newest"] is None or moment > entry["newest"]:
                entry["newest"] = moment
            if entry["oldest"] is None or moment < entry["oldest"]:
                entry["oldest"] = moment
            if newest is None or moment > newest:
                newest = moment
            if oldest is None or moment < oldest:
                oldest = moment

    findings = []
    for address, entry in clients.items():
        if entry["queries"] < MIN_SAMPLES or entry["newest"] is None or entry["oldest"] is None:
            continue
        span = (entry["newest"] - entry["oldest"]).total_seconds()
        if span < MIN_SPAN_SECONDS:
            continue
        rate = round(entry["queries"] / span * 60, 1)
        top_domain, top_count = max(entry["domains"].items(), key=lambda item: item[1]) \
            if entry["domains"] else (None, 0)
        share = round(top_count / entry["queries"] * 100, 1) if entry["queries"] else None

        kind = None
        if top_domain and share is not None and share >= REPETITION_SHARE * 100 \
                and round(top_count / span * 60, 1) >= REPETITION_RATE:
            kind = "repetitive_domain"
        elif rate >= HIGH_RATE:
            kind = "high_query_rate"
        if kind is None:
            continue

        findings.append({
            "kind": kind,
            "client": address,
            "domain": top_domain if kind == "repetitive_domain" else None,
            "queries_per_minute": rate,
            "domain_queries_per_minute": round(top_count / span * 60, 1) if top_domain else None,
            "share_percent": share,
            "sample_queries": entry["queries"],
            "sample_span_seconds": round(span, 1),
            "blocked_in_sample": entry["blocked"],
            "cached_in_sample": entry["cached"],
            "first_seen": entry["oldest"].isoformat(),
            "last_seen": entry["newest"].isoformat(),
            "measured_at": reference.isoformat(),
        })

    findings.sort(key=lambda item: -item["queries_per_minute"])
    window = {
        "sample_rows": len(rows or []),
        "oldest": oldest.isoformat() if oldest else None,
        "newest": newest.isoformat() if newest else None,
        "span_seconds": round((newest - oldest).total_seconds(), 1)
        if newest and oldest else None,
        "thresholds": {
            "min_samples": MIN_SAMPLES,
            "min_span_seconds": MIN_SPAN_SECONDS,
            "repetition_share_percent": REPETITION_SHARE * 100,
            "repetition_rate_per_minute": REPETITION_RATE,
            "high_rate_per_minute": HIGH_RATE,
        },
    }
    return findings[:MAX_FINDINGS], window
