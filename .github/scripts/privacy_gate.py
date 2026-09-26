#!/usr/bin/env python3
"""Fail the build if anything identifying a real installation reaches the repo.

This runs in CI on every push. It is a regression guard, not a one-time audit:
these repositories are extracted from a working home lab, so the risk is not
that a secret is committed deliberately — it is that a real address, hostname
or entity id comes along with an otherwise innocent change.

Three categories, all of which must be zero:

  SECRET/CREDENTIAL LEAK
  HARD-CODED MACHINE-SPECIFIC RUNTIME DEPENDENCY
  PERSONAL NETWORK IDENTIFIER

**What is deliberately allowed**, because it is documentation-safe or is the
project's own published naming:

  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24   RFC 5737 documentation
  100.64.0.0/24                                    RFC 6598 range, used in fixtures
  100.100.100.100                                  Tailscale's public MagicDNS resolver
  00:00:5e:00:53:xx                                RFC 7042 documentation MAC
  aa:bb:cc:dd:ee:xx                                obviously synthetic MAC
  example.com, example.invalid, *.example.*        RFC 2606
  this project's own container, unit and node names

Usage:  python3 .github/scripts/privacy_gate.py [path]
"""

from __future__ import annotations

import collections
import pathlib
import re
import struct
import sys

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv",
             "venv", ".mypy_cache", ".ruff_cache", "dist", "build"}

# --------------------------------------------------------------- allow-lists

#: Addresses that are safe by definition.
ALLOWED_IPS = re.compile(
    rb"^(?:"
    rb"127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d{1,3}|"
    rb"192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3}|"   # RFC 5737
    rb"100\.64\.0\.\d{1,3}|100\.100\.100\.100|"                          # RFC 6598 / MagicDNS
    rb"224\.0\.0\.\d{1,3}|239\.\d{1,3}\.\d{1,3}\.\d{1,3}|"               # multicast
    rb"8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112"  # public resolvers
    rb")$")

#: MAC ranges reserved for documentation, or plainly fake.
ALLOWED_MACS = re.compile(
    rb"^(?:[0-9a-f]{2}:00:5e:00:53:|aa:bb:cc:dd:ee:|00:00:00:00:00:|de:ad:be:ef:)", re.I)

#: A key block short enough to be a test fixture rather than real key material.
FIXTURE_KEY_MAX = 120


#: Infrastructure ranges that are the same on every machine and therefore
#: identify nobody: Docker's default bridge pools, WireGuard's conventional
#: subnet, and link-local. Reported for review, never failed on.
GENERIC_INFRA = re.compile(
    rb"^(?:172\.(?:1[6-9]|2\d|3[01])\.|10\.66\.66\.|169\.254\.)")


def real_ips(blob):
    """Addresses that would identify *this* household.

    The threat model is narrow on purpose. A home LAN prefix or a real Tailscale
    address pins down one installation. A Docker bridge gateway does not — every
    Docker host has the same ones — so flagging those only trains people to
    ignore the gate.
    """
    found = []
    for m in re.finditer(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        ip = m.group(0)
        if ALLOWED_IPS.match(ip) or GENERIC_INFRA.match(ip):
            continue
        if re.match(rb"^(?:192\.168\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)", ip):
            found.append(ip.decode())
    return found


def review_ips(blob):
    """Generic private addressing — surfaced for a human, not a failure."""
    out = []
    for m in re.finditer(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        ip = m.group(0)
        if ALLOWED_IPS.match(ip):
            continue
        if GENERIC_INFRA.match(ip) or re.match(rb"^10\.", ip):
            out.append(ip.decode())
    return out


def real_macs(blob):
    return [m.group(0).decode() for m in re.finditer(rb"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", blob, re.I)
            if not ALLOWED_MACS.match(m.group(0))]


def real_keys(blob):
    """Private key blocks with a body long enough to be real."""
    found = []
    for m in re.finditer(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----(.*?)-----END", blob, re.S):
        if len(m.group(1).strip()) > FIXTURE_KEY_MAX:
            found.append("private key block")
    return found


CHECKS = {
    "SECRET/CREDENTIAL LEAK": {
        "private key material": real_keys,
        "JWT / access token": lambda b: [m.group(0)[:24].decode(errors="replace")
                                         for m in re.finditer(rb"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.", b)],
        "bcrypt hash": lambda b: [m.group(0)[:16].decode() for m in re.finditer(rb"\$2[aby]\$\d\d\$[A-Za-z0-9./]{40,}", b)],
        "GitHub token": lambda b: [m.group(0)[:12].decode() for m in re.finditer(rb"\bgh[pousr]_[A-Za-z0-9]{30,}", b)],
        "AWS key": lambda b: [m.group(0).decode() for m in re.finditer(rb"\bAKIA[0-9A-Z]{16}\b", b)],
    },
    "HARD-CODED MACHINE-SPECIFIC RUNTIME DEPENDENCY": {
        "personal home directory": lambda b: sorted({m.group(0).decode() for m in re.finditer(
            rb"/home/(?!youruser\b|user\b|runner\b|youruser/)[a-z][a-z0-9_-]*/", b)}),
        "operator absolute path": lambda b: sorted({m.group(0).decode() for m in re.finditer(
            rb"/(?:Users|root)/[a-z][a-z0-9_-]*/", b, re.I)}),
    },
    "PERSONAL NETWORK IDENTIFIER": {
        "private / CGNAT address": lambda b: sorted(set(real_ips(b))),
        "MAC address": lambda b: sorted(set(real_macs(b))),
        "operator hostname": lambda b: sorted({m.group(0).decode() for m in re.finditer(
            rb"metehanqf-desktop", b, re.I)}),
        "personal email": lambda b: sorted({m.group(0).decode() for m in re.finditer(
            rb"[a-zA-Z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|proton(?:mail)?)\.[a-z]{2,}", b, re.I)}),
        "wifi SSID / BSSID": lambda b: sorted({m.group(0).decode() for m in re.finditer(
            rb"\bssid\s*[:=]\s*[\"']?(?!example|your|changeme)[A-Za-z0-9_-]{3,}", b, re.I)}),
    },
}


def png_metadata(path):
    """Text and EXIF chunks in a PNG can carry paths and software fingerprints."""
    try:
        d = path.read_bytes()
        if d[:8] != b"\x89PNG\r\n\x1a\n":
            return []
        i, meta = 8, []
        while i < len(d) - 8:
            ln = struct.unpack(">I", d[i:i + 4])[0]
            t = d[i + 4:i + 8].decode("ascii", "replace")
            if t in ("tEXt", "iTXt", "zTXt", "eXIf"):
                meta.append(t)
            i += 12 + ln
        return meta
    except Exception:
        return []


def main(argv=None):
    root = pathlib.Path((argv or sys.argv[1:] or ["."])[0]).resolve()
    findings = collections.defaultdict(lambda: collections.defaultdict(dict))
    scanned = 0

    # This file necessarily contains the literals it searches for, so scanning
    # it would report itself. Every other file, including anything else under
    # .github/, is still scanned.
    self_path = pathlib.Path(__file__).resolve()

    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(p in SKIP_DIRS for p in path.parts):
            continue
        if path.resolve() == self_path:
            continue
        scanned += 1
        blob = path.read_bytes()
        rel = str(path.relative_to(root))
        for category, checks in CHECKS.items():
            for label, fn in checks.items():
                hits = fn(blob)
                if hits:
                    findings[category][rel][label] = hits[:5]
        rv = review_ips(blob)
        if rv:
            findings["_review"][rel]["generic"] = sorted(set(rv))
        if path.suffix.lower() == ".png":
            meta = png_metadata(path)
            if meta:
                findings["PERSONAL NETWORK IDENTIFIER"][rel]["PNG metadata chunk"] = meta

    print(f"privacy gate — {scanned} files scanned under {root.name}\n")
    ok = True
    for category in CHECKS:
        hits = findings.get(category, {})
        total = sum(len(v) for v in hits.values())
        ok &= total == 0
        print(f"{category} = {total}  {'OK' if total == 0 else 'FAIL'}")
        for rel, detail in sorted(hits.items()):
            for label, values in detail.items():
                print(f"    ! {rel}: {label} -> {values}")
    review = sorted({ip for rel, d in findings.get("_review", {}).items()
                     for ips in d.values() for ip in ips})
    if review:
        print(f"\nreview only (generic infrastructure, not a failure): "
              f"{len(review)} distinct address(es)")
        print(f"    {review[:12]}")

    print("\n" + ("GATE PASSED" if ok else "GATE FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
