"""Client identity evidence for the DNS Center.

Nothing in this module guesses. Every fact it publishes carries the source that
produced it, and the UI is expected to show that source next to the value:

  * neighbour table (``ip -json neigh``) -> the link-layer MAC behind a LAN address
  * ``docker network inspect``           -> which bridge network an internal address is on
  * ``ip route`` / local interfaces      -> the default gateway and this host's own addresses
  * ``dns_cluster.MEMBERS``              -> the addresses this system actually runs a resolver on
  * AdGuard *persistent* clients         -> reviewed identity; several ids = one real device
  * AdGuard *auto* clients               -> an rDNS / DHCP / ARP observation, never proof

Duplicate-address policy (the important one):
Two addresses are reported as the *same* device only when a human-reviewed AdGuard
persistent entry lists both, or when the neighbour table shows the same universally
administered MAC on both. A matching hostname on its own is reported as an
**unmerged candidate** together with the reason it was not merged — DHCP hands the
same hostname to different hardware, and two different devices really do answer to
"RE305" on this network.

Everything is read-only: no configuration is written, no host is probed, and the
commands are fixed argument vectors with no user input anywhere near them.
"""
import ipaddress
import json
import subprocess
import threading
import time

# Categories the UI filters on. Anything this module cannot prove stays "unknown".
INFRASTRUCTURE = "infrastructure"
USER_DEVICE = "user_device"
IOT = "iot"
UNKNOWN = "unknown"

CACHE_TTL = 55          # refreshed once per collector cycle, never per request
COMMAND_TIMEOUT = 4

# Role words allowed to classify a device, read ONLY from the reviewed AdGuard
# persistent inventory (never from an rDNS observation). Longest match wins.
ROLE_MARKERS = (
    ("raspberry pi", INFRASTRUCTURE),
    ("access point", INFRASTRUCTURE),
    ("range extender", INFRASTRUCTURE),
    ("router", INFRASTRUCTURE),
    ("switch", INFRASTRUCTURE),
    ("server", INFRASTRUCTURE),
    ("node", INFRASTRUCTURE),
    ("nas", INFRASTRUCTURE),
    ("camera", IOT),
    ("doorbell", IOT),
    ("sensor", IOT),
    ("bulb", IOT),
    ("plug", IOT),
    ("thermostat", IOT),
    ("tv", IOT),
    ("android", USER_DEVICE),
    ("iphone", USER_DEVICE),
    ("ipad", USER_DEVICE),
    ("ios", USER_DEVICE),
    ("windows", USER_DEVICE),
    ("macos", USER_DEVICE),
    ("macbook", USER_DEVICE),
    ("laptop", USER_DEVICE),
    ("desktop", USER_DEVICE),
    ("phone", USER_DEVICE),
    ("tablet", USER_DEVICE),
    ("watch", USER_DEVICE),
)

# AdGuard's own client tags, if the operator ever sets them in AdGuard. Reading them
# costs nothing and they outrank a name-derived role because they are explicit.
TAG_CATEGORIES = {
    "device_phone": USER_DEVICE, "device_tablet": USER_DEVICE,
    "device_laptop": USER_DEVICE, "device_pc": USER_DEVICE,
    "device_audio": IOT, "device_camera": IOT, "device_gameconsole": IOT,
    "device_printer": IOT, "device_securityalarm": IOT, "device_tv": IOT,
    "device_nas": INFRASTRUCTURE, "device_router": INFRASTRUCTURE,
    "device_other": UNKNOWN,
}

_lock = threading.Lock()
_cache = None
_cache_at = None


# --------------------------------------------------------------------- host facts


def _run(args):
    """One fixed-argv read-only command. Returns stdout or None; never raises."""
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=COMMAND_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _json(args):
    raw = _run(args)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def neighbours():
    """address -> {mac, state, locally_administered} from the kernel ARP/NDP table.

    Entries without an ``lladdr`` (FAILED / INCOMPLETE) are dropped: an address the
    kernel never resolved carries no identity evidence at all.
    """
    table = {}
    for entry in _json(["ip", "-json", "neigh", "show"]) or []:
        address, mac = entry.get("dst"), entry.get("lladdr")
        if not address or not mac:
            continue
        first = mac.split(":")[0]
        try:
            local = bool(int(first, 16) & 0x02)
        except ValueError:
            continue
        state = entry.get("state") or []
        table[address] = {
            "mac": mac,
            "state": state[0] if isinstance(state, list) and state else None,
            "locally_administered": local,
        }
    return table


def gateways():
    """Default-route gateways, i.e. the addresses that are genuinely the router."""
    found = {}
    for entry in _json(["ip", "-json", "route", "show", "default"]) or []:
        gateway = entry.get("gateway")
        if gateway:
            found[gateway] = entry.get("dev")
    return found


def local_addresses():
    """Every address configured on this host, so Pi5's own traffic is recognisable."""
    addresses = {}
    for entry in _json(["ip", "-json", "-brief", "address", "show"]) or []:
        name = entry.get("ifname")
        for item in entry.get("addr_info") or []:
            local = item.get("local")
            if local:
                addresses[local] = name
    return addresses


def docker_bridges():
    """Bridge networks with their subnet and gateway, straight from the daemon.

    This is what turns an anonymous "172.19.0.1" into a named, provable bridge
    gateway instead of an unknown client.
    """
    names = _run(["docker", "network", "ls", "--format", "{{.Name}}"])
    if not names:
        return []
    wanted = [line.strip() for line in names.splitlines() if line.strip()]
    if not wanted:
        return []
    payload = _json(["docker", "network", "inspect", *wanted])
    bridges = []
    for network in payload or []:
        if network.get("Driver") != "bridge":
            continue
        for config in ((network.get("IPAM") or {}).get("Config") or []):
            subnet = config.get("Subnet")
            if not subnet:
                continue
            try:
                parsed = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                continue
            bridges.append({"network": network.get("Name"), "subnet": subnet,
                            "gateway": config.get("Gateway"), "_parsed": parsed})
    return bridges


def _bridge_for(address, bridges):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    for bridge in bridges:
        if parsed in bridge["_parsed"]:
            return bridge
    return None


# ------------------------------------------------------------------- AdGuard side


def _role_from_name(name):
    """Role parsed from a reviewed persistent name such as 'Tapo C211 (Camera)'."""
    lowered = (name or "").lower()
    for marker, category in ROLE_MARKERS:
        if marker in lowered:
            return category, marker
    return None, None


def _resolver_addresses():
    try:
        from dns_cluster import MEMBERS
    except Exception:
        return {}
    return {member["address"]: member.get("label") or member.get("node")
            for member in MEMBERS}


def snapshot(clients):
    """Build the identity table for one collector cycle.

    ``clients`` is AdGuard's /control/clients payload. The expensive part is the three
    host commands, so the result is cached for one collector interval.
    """
    global _cache, _cache_at
    now = time.time()
    with _lock:
        if _cache is not None and _cache_at is not None and now - _cache_at < CACHE_TTL:
            host = _cache
        else:
            host = None
    if host is None:
        host = {
            "neighbours": neighbours(),
            "gateways": gateways(),
            "local": local_addresses(),
            "bridges": docker_bridges(),
            "resolvers": _resolver_addresses(),
        }
        with _lock:
            _cache, _cache_at = host, now

    persistent = {}      # address -> reviewed entry
    groups = {}          # identity key -> [addresses]
    for entry in (clients or {}).get("clients") or []:
        name = entry.get("name")
        ids = [value for value in (entry.get("ids") or []) if value]
        if not name or not ids:
            continue
        for address in ids:
            persistent[address] = {"name": name, "ids": ids,
                                   "tags": entry.get("tags") or []}
        if len(ids) > 1:
            groups["inventory:" + name] = list(ids)

    observed = {}        # address -> {name, source} from rDNS / ARP / hosts
    for entry in (clients or {}).get("auto_clients") or []:
        address, name = entry.get("ip"), entry.get("name")
        if address and name:
            observed[address] = {"name": name, "source": entry.get("source") or "runtime"}

    # A universally administered MAC seen on two addresses is the same hardware.
    by_mac = {}
    for address, neighbour in host["neighbours"].items():
        if neighbour["locally_administered"]:
            continue
        by_mac.setdefault(neighbour["mac"], []).append(address)
    for mac, addresses in by_mac.items():
        if len(addresses) > 1:
            groups["mac:" + mac] = sorted(addresses)

    # Hostname collisions are recorded, never merged.
    by_hostname = {}
    for address in set(persistent) | set(observed):
        label = (persistent.get(address) or observed.get(address) or {}).get("name")
        if label:
            by_hostname.setdefault(label.lower(), []).append(address)

    return {"host": host, "persistent": persistent, "observed": observed,
            "groups": groups, "by_hostname": by_hostname}


def describe(address, table):
    """Everything provable about one client address.

    Returns a dict the API can hand straight to the UI. ``category`` is only ever
    something other than "unknown" when ``category_source`` names real evidence.
    """
    host = table["host"]
    reviewed = table["persistent"].get(address)
    seen = table["observed"].get(address)
    neighbour = host["neighbours"].get(address)

    name = (reviewed or {}).get("name") or (seen or {}).get("name") or None
    name_source = "inventory" if reviewed else ((seen or {}).get("source") if seen else None)

    category, category_source = UNKNOWN, None
    infra_role = None

    bridge = _bridge_for(address, host["bridges"])
    # A bridge gateway is also one of this host's own addresses, so the bridge is
    # checked first: "Docker bridge gateway (metehantech-dns_default)" is the precise
    # description, "this host" is merely true.
    if bridge is not None:
        category = INFRASTRUCTURE
        is_gateway = bridge.get("gateway") == address
        category_source = "docker network inspect · " + str(bridge["network"])
        infra_role = ("Docker bridge gateway · " + str(bridge["network"]) if is_gateway
                      else "Docker bridge member · " + str(bridge["network"]))
        if not name:
            # Provable, so it replaces "Unknown client" — this is not a guess.
            name = ("Docker bridge gateway (" + str(bridge["network"]) + ")" if is_gateway
                    else "Docker container (" + str(bridge["network"]) + ")")
            name_source = "docker"
    elif address in host["local"]:
        category, category_source = INFRASTRUCTURE, "address is configured on this host"
        infra_role = "This host · " + host["local"][address]
        if not name:
            name = "This host"
            name_source = "local interface"
    elif address in host["gateways"]:
        category, category_source = INFRASTRUCTURE, "default route gateway"
        infra_role = "LAN gateway · " + (host["gateways"][address] or "route")
        if not name:
            name = "Router (default gateway)"
            name_source = "ip route"
    elif address in host["resolvers"]:
        category, category_source = INFRASTRUCTURE, "configured DNS resolver node"
        infra_role = "DNS resolver · " + str(host["resolvers"][address])

    if category == UNKNOWN and reviewed:
        for tag in reviewed.get("tags") or []:
            if tag in TAG_CATEGORIES and TAG_CATEGORIES[tag] != UNKNOWN:
                category, category_source = TAG_CATEGORIES[tag], "AdGuard client tag · " + tag
                break
    if category == UNKNOWN and reviewed:
        role, marker = _role_from_name(reviewed.get("name"))
        if role:
            category = role
            category_source = "reviewed inventory role · " + marker

    # --- identity ---------------------------------------------------------------
    identity_key, identity_source, known = address, None, [address]
    for key, addresses in table["groups"].items():
        if address in addresses:
            identity_key, known = key, list(addresses)
            identity_source = ("reviewed AdGuard inventory entry" if key.startswith("inventory:")
                               else "same universally administered MAC in the neighbour table")
            break

    duplicates = []
    if name:
        for other in table["by_hostname"].get(name.lower(), []):
            if other == address or other in known:
                continue
            mine = host["neighbours"].get(address)
            theirs = host["neighbours"].get(other)
            if mine and theirs:
                reason = ("different MAC — different hardware"
                          if not mine["locally_administered"] and not theirs["locally_administered"]
                          else "MACs differ and at least one is randomised, so they prove nothing")
            else:
                reason = "no MAC evidence for at least one address"
            duplicates.append({"address": other, "hostname": name, "reason": reason})

    return {
        "address": address,
        "name": name,
        "name_source": name_source,
        "category": category,
        "category_source": category_source,
        "infrastructure_role": infra_role,
        "mac": (neighbour or {}).get("mac"),
        "mac_state": (neighbour or {}).get("state"),
        "mac_randomised": (neighbour or {}).get("locally_administered"),
        "identity_key": identity_key,
        "identity_source": identity_source,
        "known_addresses": known if len(known) > 1 else None,
        "duplicate_candidates": duplicates or None,
    }
