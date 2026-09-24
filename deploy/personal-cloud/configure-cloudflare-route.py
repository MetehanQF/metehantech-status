#!/usr/bin/env python3
"""Add the fixed Personal Cloud hostname to the existing remotely-managed tunnel."""

import base64
import getpass
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API = "https://api.cloudflare.com/client/v4"
HOSTNAME = "cloud.metehantech.com"
ORIGIN = "http://localhost:5300"
ZONE_NAME = "metehantech.com"
TUNNEL_TOKEN = Path("/etc/cloudflared/token")
# Geri alma anlik goruntusunun yazilacagi yer. Deployment'a ozel oldugu icin
# ortamdan gelir; tanimsizsa kullanicinin ev dizini altinda varsayilan bir yol
# kullanilir (makineye ozel mutlak yol kaynak kodda tutulmaz).
ROLLBACK = Path(
    os.environ.get("CLOUDFLARE_ROLLBACK_FILE")
    or (Path.home() / "metehantech_backups" / "cloudflare-pre-route.json")
)


class ApiError(RuntimeError):
    pass


def request(token, method, path, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(req, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        try:
            payload = json.load(error)
            detail = payload.get("errors") or [{"message": str(error)}]
        except Exception:
            detail = [{"message": str(error)}]
        raise ApiError(json.dumps(detail)) from error
    if not payload.get("success"):
        raise ApiError(json.dumps(payload.get("errors") or [{"message": "API request failed"}]))
    return payload.get("result")


def tunnel_identity():
    encoded = TUNNEL_TOKEN.read_text(encoding="ascii").strip()
    encoded += "=" * (-len(encoded) % 4)
    payload = json.loads(base64.urlsafe_b64decode(encoded))
    account_id, tunnel_id = payload.get("a"), payload.get("t")
    if not account_id or not tunnel_id:
        raise RuntimeError("Tunnel token did not contain account/tunnel identifiers")
    return account_id, tunnel_id


def main():
    if not TUNNEL_TOKEN.is_file():
        raise RuntimeError("Cloudflared token file is unavailable")
    token = getpass.getpass("Cloudflare scoped API token: ").strip()
    if not token:
        raise RuntimeError("API token is required")

    account_id, tunnel_id = tunnel_identity()
    request(token, "GET", "/user/tokens/verify")

    config_path = f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
    configuration = request(token, "GET", config_path) or {}
    original_config = configuration.get("config") or {}
    original_ingress = original_config.get("ingress") or []
    if not isinstance(original_ingress, list) or not original_ingress:
        raise RuntimeError("Remote tunnel ingress configuration is empty or invalid")

    zone_query = urlencode({"name": ZONE_NAME, "account.id": account_id, "status": "active"})
    zones = request(token, "GET", f"/zones?{zone_query}") or []
    if len(zones) != 1:
        raise RuntimeError(f"Expected one active {ZONE_NAME} zone; found {len(zones)}")
    zone_id = zones[0]["id"]

    dns_query = urlencode({"name": HOSTNAME, "per_page": 100})
    existing_dns = request(token, "GET", f"/zones/{zone_id}/dns_records?{dns_query}") or []
    expected_target = f"{tunnel_id}.cfargotunnel.com"

    existing_rule = next((rule for rule in original_ingress if rule.get("hostname") == HOSTNAME), None)
    if existing_rule and existing_rule.get("service") != ORIGIN:
        raise RuntimeError(f"{HOSTNAME} already points to a different tunnel service")

    new_config = json.loads(json.dumps(original_config))
    ingress = new_config.setdefault("ingress", [])
    ingress_changed = existing_rule is None
    if ingress_changed:
        insert_at = next((i for i, rule in enumerate(ingress) if not rule.get("hostname")), len(ingress))
        ingress.insert(insert_at, {"hostname": HOSTNAME, "service": ORIGIN})

    ROLLBACK.parent.mkdir(parents=True, exist_ok=True)
    ROLLBACK.write_text(
        json.dumps(
            {
                "account_id": account_id,
                "tunnel_id": tunnel_id,
                "zone_id": zone_id,
                "config": original_config,
                "dns_before": existing_dns,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    ROLLBACK.chmod(0o600)

    if ingress_changed:
        request(token, "PUT", config_path, {"config": new_config})

    dns_created = False
    try:
        if existing_dns:
            valid = (
                len(existing_dns) == 1
                and existing_dns[0].get("type") == "CNAME"
                and existing_dns[0].get("content") == expected_target
                and existing_dns[0].get("proxied") is True
            )
            if not valid:
                raise RuntimeError(f"{HOSTNAME} already has a conflicting DNS record")
        else:
            request(
                token,
                "POST",
                f"/zones/{zone_id}/dns_records",
                {
                    "type": "CNAME",
                    "name": HOSTNAME,
                    "content": expected_target,
                    "ttl": 1,
                    "proxied": True,
                    "comment": "MetehanTech Personal Cloud tunnel route",
                },
            )
            dns_created = True
    except Exception:
        if ingress_changed:
            request(token, "PUT", config_path, {"config": original_config})
        raise

    preserved = sorted(rule["hostname"] for rule in original_ingress if rule.get("hostname"))
    print(json.dumps({
        "ok": True,
        "hostname": HOSTNAME,
        "origin": ORIGIN,
        "ingress_created": ingress_changed,
        "dns_created": dns_created,
        "preserved_hostnames": preserved,
        "rollback_file": str(ROLLBACK),
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ApiError, OSError, ValueError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
