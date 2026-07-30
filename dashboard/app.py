#!/usr/bin/env python3
"""
Network Dashboard - Live Device Status Monitor
Built for the Jetson Network Scanner
"""

import ipaddress
import json
import os
import shlex
import re
import subprocess
import socket
import threading
from datetime import datetime
from pathlib import Path
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

from flask import Flask, render_template, jsonify, request, send_from_directory

from cron_control import (
    get_jobs_status,
    run_job_now,
    set_job_enabled,
    set_job_schedule,
)

app = Flask(__name__, static_folder='static', template_folder='templates')


@app.after_request
def _disable_caching_for_dynamic_pages(resp):
    """Avoid stale dashboard/API JSON behind browsers or reverse proxies."""
    path = request.path or ""
    if path.startswith("/api/") or path == "/":
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
    return resp


BASE_DIR = Path(__file__).resolve().parent.parent
DEVICE_GROUPS_CONFIG_FILE = BASE_DIR / "device_groups_config.json"
ALLOWED_BUILTIN_SECTION_IDS = frozenset({"ollama", "openclaw", "access_point", "other_wide", "tailscale"})
BUILTIN_SECTION_ITER = (
    "ollama",
    "openclaw",
    "access_point",
    "other_wide",
    "tailscale",
)
DEVICES_FILE = str(BASE_DIR / "devices.md")
CACHE_FILE = str(BASE_DIR / ".seen_devices.json")
SCAN_SNAPSHOTS_FILE = str(BASE_DIR / ".scan_snapshots.json")
DEEP_SCAN_RESULTS_FILE = str(BASE_DIR / "deep_scan_results.json")
SCAN_SCRIPT = str(BASE_DIR / "network_scan_agent.py")
LAN_LABELS_FILE = os.environ.get(
    "LAN_LABELS_FILE",
    str(Path.home() / ".config" / "lan-labels"),
)
KNOWN_HOSTNAME_OVERRIDES = {
    "192.168.0.98": "Irene's Watch",
    "192.168.0.81": "Friends Watch",
    "192.168.0.170": "Prime",
    "100.78.64.7": "Prime",
    "192.168.0.171": "borgson",
    "192.168.0.153": "Cindy",
    "192.168.0.151": "Cindy",
    "100.67.102.109": "x9-14",
    "192.168.0.172": "x19-14",
    "192.168.0.198": "belikemike",
    "100.71.191.72": "belikemike",
}
KNOWN_LABEL_OVERRIDES = {
    "192.168.0.170": "MacBook Pro M5 Max",
    "100.78.64.7": "MacBook Pro M5 Max",
    "192.168.0.171": "Nvidia AGX",
    "192.168.0.153": "PGX",
    "192.168.0.151": "PGX",
    "100.92.6.101": "PGX",
    "100.67.102.109": "Nicks Laptop",
    "192.168.0.172": "x19-14",
    "192.168.0.198": "Mac mini",
    "100.71.191.72": "Mac mini",
    "192.168.0.1": "Verizon 5G Hotspot",
}
KNOWN_MAC_OVERRIDES = {
    "192.168.0.98": "4e:0a:ec:36:fd:82",
    "192.168.0.81": "fa:5b:a6:ab:1a:7f",
    "192.168.0.153": "9c:c7:d3:87:eb:9c",
    "100.92.6.101": "9c:c7:d3:87:eb:9c",
}
KNOWN_SUBNET_OVERRIDES = {
    # Keep Prime (LAN + Tailscale) anchored to local LAN when mesh alias is active.
    "192.168.0.170": "Local LAN (192.168.0.0/24)",
    "100.78.64.7": "Local LAN (192.168.0.0/24)",
    "192.168.0.198": "Local LAN (192.168.0.0/24)",
    "100.71.191.72": "Local LAN (192.168.0.0/24)",
}
ONLINE_ALIAS_SYNC_CLUSTERS = [
    {"192.168.0.170", "100.78.64.7"},
    {"192.168.0.198", "100.71.191.72"},
]
HIDDEN_DEVICE_IPS = {
    "100.70.174.39",
    "100.95.15.82",
    "100.79.216.111",
    "100.65.1.48",
}

OLLAMA_SERVER_IPS = frozenset({
    "192.168.0.170",
    "100.78.64.7",
    "192.168.0.153",
    "192.168.0.151",
    "100.92.6.101",
    "192.168.0.198",
    "100.71.191.72",
})

ACCESS_POINT_GATEWAY_IP = "192.168.0.1"

_DEFAULT_DEVICE_GROUPS_CONFIG = {
    "version": 1,
    "section_order": [
        {"type": "builtin", "id": "ollama"},
        {"type": "builtin", "id": "openclaw"},
        {"type": "builtin", "id": "access_point"},
        {"type": "builtin", "id": "other_wide"},
        {"type": "builtin", "id": "tailscale"},
        {"type": "custom", "id": "cg-personal"},
    ],
    "custom_groups": {
        "cg-personal": {
            "name": "Personal Devices",
            "ips": ["192.168.0.190", "192.168.0.152"],
        },
    },
    "openclaw_excluded_ips": [],
    "builtin_names": {},
    "section_pins": {},
    "section_bans": {},
}

BUILTIN_SECTION_META = {
    "ollama": {"title": "Ollama Servers", "subtitle": "", "accent": "amber"},
    "openclaw": {"title": "OpenClaw Devices", "subtitle": "192.168.0.0/24", "accent": "sky"},
    "access_point": {"title": "Access Point", "subtitle": "192.168.0.1", "accent": "violet"},
    "other_wide": {"title": "Other networks & devices", "subtitle": "", "accent": "zinc"},
    "tailscale": {"title": "Tailscale devices", "subtitle": "100.x mesh", "accent": "emerald"},
}

_CUSTOM_GROUP_ACCENTS = ["rose", "fuchsia", "orange", "cyan", "lime", "pink"]


def _ensure_device_groups_config_file() -> None:
    if DEVICE_GROUPS_CONFIG_FILE.exists():
        return
    try:
        with open(DEVICE_GROUPS_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(_DEFAULT_DEVICE_GROUPS_CONFIG, f, indent=2)
    except OSError as e:
        print(f"Warning: could not write default device groups config: {e}")


def _normalize_device_groups_config(raw: dict) -> dict:
    data = dict(_DEFAULT_DEVICE_GROUPS_CONFIG)
    if isinstance(raw, dict):
        if raw.get("version") is not None:
            data["version"] = raw["version"]
        if isinstance(raw.get("section_order"), list) and raw["section_order"]:
            data["section_order"] = raw["section_order"]
        if isinstance(raw.get("custom_groups"), dict):
            data["custom_groups"] = {
                k: {
                    "name": str((v or {}).get("name") or "Custom group"),
                    "ips": [str(x).strip() for x in ((v or {}).get("ips") or []) if str(x).strip()],
                }
                for k, v in raw["custom_groups"].items()
            }
        if isinstance(raw.get("openclaw_excluded_ips"), list):
            data["openclaw_excluded_ips"] = [
                str(x).strip() for x in raw["openclaw_excluded_ips"] if str(x).strip()
            ]
        if isinstance(raw.get("builtin_names"), dict):
            data["builtin_names"] = {
                str(k).strip(): str(v).strip()
                for k, v in raw["builtin_names"].items()
                if str(k).strip() in ALLOWED_BUILTIN_SECTION_IDS and str(v).strip()
            }
        if isinstance(raw.get("section_pins"), dict):
            data["section_pins"] = {
                str(k).strip(): str(v).strip()
                for k, v in raw["section_pins"].items()
                if str(k).strip()
                and str(v).strip() in ALLOWED_BUILTIN_SECTION_IDS
            }
        if isinstance(raw.get("section_bans"), dict):
            data["section_bans"] = {}
            for k, v in raw["section_bans"].items():
                bid = str(k).strip()
                if bid not in ALLOWED_BUILTIN_SECTION_IDS:
                    continue
                data["section_bans"][bid] = [
                    str(x).strip() for x in (v or []) if str(x).strip()
                ]
    return data


def load_device_groups_config() -> dict:
    _ensure_device_groups_config_file()
    try:
        with open(DEVICE_GROUPS_CONFIG_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: device groups config unreadable ({e}); using defaults")
        loaded = {}
    return _normalize_device_groups_config(loaded)


def save_device_groups_config(cfg: dict) -> None:
    normalized = _normalize_device_groups_config(cfg)
    tmp_path = DEVICE_GROUPS_CONFIG_FILE.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)
    tmp_path.replace(DEVICE_GROUPS_CONFIG_FILE)


def validate_device_groups_config(cfg: dict) -> tuple[bool, str]:
    """Return (ok, error_message)."""
    so = cfg.get("section_order")
    if not isinstance(so, list) or not so:
        return False, "section_order must be a non-empty list"
    seen_builtin = set()
    for sec in so:
        if not isinstance(sec, dict):
            return False, "invalid section_order entry"
        st = sec.get("type")
        sid = sec.get("id")
        if st == "builtin":
            if sid not in ALLOWED_BUILTIN_SECTION_IDS:
                return False, f"unknown builtin section id: {sid}"
            if sid in seen_builtin:
                return False, f"duplicate builtin section: {sid}"
            seen_builtin.add(sid)
        elif st == "custom":
            if not sid or not isinstance(sid, str):
                return False, "custom section needs a string id"
            cgs = cfg.get("custom_groups") or {}
            if sid not in cgs:
                return False, f"custom group not defined: {sid}"
        else:
            return False, f"invalid section type: {st}"
    return True, ""


def _classify_builtin_section(
    device: dict,
    forbidden: frozenset[str],
    openclaw_excluded: frozenset[str],
) -> str:
    """Pick exactly one builtin section; forbidden omits those buckets (for re-homing)."""
    if "ollama" not in forbidden and device.get("ollama_server"):
        return "ollama"
    if "access_point" not in forbidden and _device_is_access_point(device):
        return "access_point"
    if (
        "openclaw" not in forbidden
        and _device_has_openclaw_lan_subnet(device)
        and not (_device_ip_set(device) & openclaw_excluded)
    ):
        return "openclaw"
    if (
        "other_wide" not in forbidden
        and _device_has_openclaw_lan_subnet(device)
        and (_device_ip_set(device) & openclaw_excluded)
    ):
        return "other_wide"
    if "tailscale" not in forbidden and _device_is_tailscale_only(device):
        return "tailscale"
    if "other_wide" not in forbidden:
        return "other_wide"
    if "tailscale" not in forbidden and _device_is_tailscale_only(device):
        return "tailscale"
    return "other_wide"


def _dedupe_device_list(devices: list) -> list:
    seen: set[int] = set()
    out = []
    for d in devices:
        i = id(d)
        if i in seen:
            continue
        seen.add(i)
        out.append(d)
    return out


def _apply_section_bans_and_rehome(
    builtin_lists: dict[str, list],
    section_bans: dict,
    openclaw_excluded: frozenset[str],
) -> None:
    """Remove banned devices from each section and re-home (repeat until stable)."""
    changed = True
    rounds = 0
    while changed and rounds < 24:
        changed = False
        rounds += 1
        for bid in BUILTIN_SECTION_ITER:
            ban_ips = frozenset((section_bans or {}).get(bid) or [])
            if not ban_ips:
                continue
            cur = builtin_lists.get(bid) or []
            remain: list = []
            evicted: list = []
            for d in cur:
                if _device_ip_set(d) & ban_ips:
                    evicted.append(d)
                else:
                    remain.append(d)
            if not evicted:
                builtin_lists[bid] = remain
                continue
            builtin_lists[bid] = remain
            changed = True
            for d in evicted:
                dest = _classify_builtin_section(
                    d,
                    frozenset({bid}),
                    openclaw_excluded,
                )
                lst = builtin_lists.setdefault(dest, [])
                if not any(id(x) == id(d) for x in lst):
                    lst.append(d)


def build_ip_to_custom_group(cfg: dict) -> dict[str, str]:
    """Map IP -> custom group id; first matching section in section_order wins."""
    ip_to_gid: dict[str, str] = {}
    groups = cfg.get("custom_groups") or {}
    for sec in cfg.get("section_order") or []:
        if sec.get("type") != "custom":
            continue
        gid = sec.get("id")
        if not gid or gid not in groups:
            continue
        for ip in groups[gid].get("ips") or []:
            ip = str(ip).strip()
            if ip and ip not in ip_to_gid:
                ip_to_gid[ip] = gid
    return ip_to_gid


def build_section_order_for_api(cfg: dict) -> list[dict]:
    out: list[dict] = []
    cg = cfg.get("custom_groups") or {}
    ai = 0
    for sec in cfg.get("section_order") or []:
        stype = sec.get("type")
        sid = sec.get("id")
        if stype == "builtin" and sid in BUILTIN_SECTION_META:
            meta = BUILTIN_SECTION_META[sid]
            names = (cfg.get("builtin_names") or {}) if isinstance(cfg, dict) else {}
            title = names.get(sid) or meta["title"]
            out.append({
                "key": sid,
                "type": "builtin",
                "title": title,
                "subtitle": meta.get("subtitle", ""),
                "accent": meta.get("accent", "zinc"),
            })
        elif stype == "custom" and sid:
            name = (cg.get(sid) or {}).get("name") or "Custom group"
            ac = _CUSTOM_GROUP_ACCENTS[ai % len(_CUSTOM_GROUP_ACCENTS)]
            ai += 1
            out.append({
                "key": f"custom:{sid}",
                "type": "custom",
                "title": name,
                "subtitle": "",
                "accent": ac,
                "group_id": sid,
            })
    return out


def _device_ip_set(device: dict) -> set[str]:
    ips: set[str] = set()
    primary = device.get("ip")
    if primary:
        ips.add(str(primary))
    for addr in device.get("ip_addresses") or []:
        if addr:
            ips.add(str(addr))
    return ips


def _device_is_access_point(device: dict) -> bool:
    """Default gateway / hotspot shown as its own Access Point group."""
    return ACCESS_POINT_GATEWAY_IP in _device_ip_set(device)


def _device_has_openclaw_lan_subnet(device: dict) -> bool:
    """True when any address is a host on 192.168.0.0/24 (excludes .0 and .255)."""
    for raw in _device_ip_set(device):
        ip = str(raw).strip()
        if not ip.startswith("192.168.0."):
            continue
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        try:
            last = int(parts[3])
        except ValueError:
            continue
        if 1 <= last <= 254:
            return True
    return False


def _device_is_tailscale_only(device: dict) -> bool:
    """True when every known address for this device is a Tailscale IPv4 (100.x)."""
    ips = _device_ip_set(device)
    if not ips:
        return False
    for ip in ips:
        if not is_tailscale_ip(str(ip).strip()):
            return False
    return True


def _is_ollama_server_device(device: dict) -> bool:
    if _device_ip_set(device) & OLLAMA_SERVER_IPS:
        return True
    hostname = str(device.get("hostname") or "").strip().lower()
    base = hostname.split(".")[0] if hostname else ""
    base = base.split("-")[0] if base else ""
    return base in ("prime", "cindy", "belikemike")


def _ollama_server_rank(device: dict) -> int:
    """Sort order within Ollama Servers: Prime, Cindy, belikemike."""
    ips = _device_ip_set(device)
    if ips & {"192.168.0.170", "100.78.64.7"}:
        return 0
    if ips & {"192.168.0.153", "192.168.0.151", "100.92.6.101"}:
        return 1
    if ips & {"192.168.0.198", "100.71.191.72"}:
        return 2
    hostname = str(device.get("hostname") or "").strip().lower()
    base = hostname.split(".")[0].split("-")[0] if hostname else ""
    return {"prime": 0, "cindy": 1, "belikemike": 2}.get(base, 99)


def load_ip_labels():
    """Load user-defined IP->label aliases from ~/.config/lan-labels."""
    labels = {}
    try:
        if not os.path.exists(LAN_LABELS_FILE):
            return labels
        with open(LAN_LABELS_FILE, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    labels[parts[0]] = parts[1].strip()
    except Exception as e:
        print(f"Warning: could not load LAN labels: {e}")
    return labels


IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def choose_device_name(ip: str, *candidates):
    """Pick display name from detected hostname candidates, else IP."""
    for value in candidates:
        if value in (None, "", "—", "None"):
            continue
        text = str(value).strip()
        if not text or text == ip or IPV4_RE.match(text):
            continue
        return text
    return ip


def is_active_status(status: str) -> bool:
    """Only treat explicitly online devices as active."""
    return status == "Online"


def normalize_mac(mac: str) -> str:
    """Normalize MAC for grouping; return empty string when unavailable."""
    if mac in (None, "", "—", "None"):
        return ""
    return str(mac).strip().lower().replace("-", ":")


def is_tailscale_ip(ip: str) -> bool:
    return isinstance(ip, str) and ip.startswith("100.")


def _ordered_ips_for_manual_merge(present):
    """
    Member order for explicit manual_clusters in collapse_duplicate_devices.
    Tailscale IPs first (sorted); LAN IPs sorted with 192.168.0.153 before 192.168.0.151
    so the merged card's primary stays the canonical Wi‑Fi address when both NICs are up.
    """
    ts = sorted(ip for ip in present if is_tailscale_ip(str(ip)))
    lan = sorted(
        (ip for ip in present if not is_tailscale_ip(str(ip))),
        key=lambda ip: (str(ip) != "192.168.0.153", str(ip)),
    )
    return ts + lan


def ip_subnet_prefix(ip: str) -> str:
    if not isinstance(ip, str):
        return ""
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
    return ".".join(parts[:3])


def canonical_hostname_for_grouping(device: dict) -> str:
    """
    Normalize hostname for cross-network correlation.
    Example: thinkstation.tailxxxx.ts.net -> thinkstation
    """
    if not isinstance(device, dict):
        return ""

    hostname = str(device.get("hostname", "")).strip().lower()
    ip = str(device.get("ip", "")).strip()
    if not hostname or hostname in ("—", "none") or hostname == ip:
        return ""
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        return ""

    # Normalize common suffixes.
    hostname = re.sub(r"\.tail[^.]*\.ts\.net$", "", hostname)
    hostname = re.sub(r"\.ts\.net$", "", hostname)
    hostname = re.sub(r"\.local$", "", hostname)
    return hostname.strip()


def load_deep_scan_results_map():
    """Per-IP payloads from the last merged deep_scan_results.json run."""
    try:
        if not os.path.exists(DEEP_SCAN_RESULTS_FILE):
            return {}
        with open(DEEP_SCAN_RESULTS_FILE, "r") as f:
            payload = json.load(f)
        results = payload.get("results") if isinstance(payload, dict) else None
        return results if isinstance(results, dict) else {}
    except Exception:
        return {}


def format_deep_services_preview(services, limit=5):
    """Short single-line summary of nmap service fingerprints for device cards."""
    if not isinstance(services, dict) or not services:
        return ""
    parts = []
    for k in sorted(services.keys())[:limit]:
        val = str(services.get(k) or "").strip().replace("\n", " ")
        if len(val) > 56:
            val = val[:53] + "…"
        parts.append(f"{k}: {val}")
    joined = " · ".join(parts)
    if len(joined) > 260:
        return joined[:257] + "…"
    return joined


def collapse_duplicate_devices(devices):
    """
    Collapse duplicate logical devices so UI shows one card even with multiple IPs.
    Priority:
      1) Same normalized MAC across multiple IPs
      2) Correlated iPhone aliases on local LAN
    """
    if not devices:
        return devices

    by_ip = {d.get("ip"): d for d in devices if d.get("ip")}
    groups = []
    grouped_ips = set()

    # Group by duplicate MAC first (high confidence).
    mac_groups = {}
    for d in devices:
        mac = normalize_mac(d.get("mac"))
        if not mac:
            continue
        mac_groups.setdefault(mac, []).append(d)
    for _, members in mac_groups.items():
        ips = sorted({m["ip"] for m in members if m.get("ip")})
        # Guardrail: skip same-subnet MAC merges; these can be ARP artifacts
        # (e.g. router MAC shown for multiple LAN hosts).
        prefixes = {ip_subnet_prefix(ip) for ip in ips if ip_subnet_prefix(ip)}
        if len(ips) > 1 and len(prefixes) > 1:
            groups.append(ips)
            grouped_ips.update(ips)

    # Correlate Tailscale + local LAN aliases by canonical hostname.
    hostname_groups = {}
    for d in devices:
        canon = canonical_hostname_for_grouping(d)
        if not canon:
            continue
        hostname_groups.setdefault(canon, []).append(d)
    for _, members in hostname_groups.items():
        ips = sorted({m.get("ip") for m in members if m.get("ip")})
        if len(ips) < 2:
            continue
        has_tailscale = any(is_tailscale_ip(ip) for ip in ips)
        has_non_tailscale = any(not is_tailscale_ip(ip) for ip in ips)
        if not (has_tailscale and has_non_tailscale):
            continue
        # Avoid creating overlapping duplicate groups.
        if any(set(ips).issubset(set(existing)) for existing in groups):
            continue
        groups.append(ips)
        grouped_ips.update(ips)

    # Correlate known iPhone aliases (private-MAC rotation + routed-subnet alias).
    iphone_cluster = ["192.168.0.49", "192.168.0.131"]
    iphone_present = [ip for ip in iphone_cluster if ip in by_ip]
    if len(iphone_present) >= 2:
        cluster_hostnames = [
            str(by_ip[ip].get("hostname", "")).strip().lower()
            for ip in iphone_present
        ]
        hostname_hints = [
            name for name in cluster_hostnames
            if name and ("iphone" in name or "irenes-iphone.local" in name)
        ]
        if hostname_hints:
            # Remove overlapping groups first so this cluster is rendered as one card.
            normalized_groups = []
            for g in groups:
                if set(g) & set(iphone_present):
                    continue
                normalized_groups.append(g)
            groups = normalized_groups
            grouped_ips = {ip for g in groups for ip in g}
            groups.append(sorted(iphone_present))
            grouped_ips.update(iphone_present)

    # Correlate known watch aliases (private-MAC rotation + routed-subnet alias).
    watch_cluster = ["192.168.0.98", "192.168.0.112"]
    watch_present = [ip for ip in watch_cluster if ip in by_ip]
    if len(watch_present) >= 2:
        cluster_hostnames = [
            str(by_ip[ip].get("hostname", "")).strip().lower()
            for ip in watch_present
        ]
        hostname_hints = [name for name in cluster_hostnames if name and "watch" in name]
        if hostname_hints:
            # Remove overlapping groups first so this cluster is rendered as one card.
            normalized_groups = []
            for g in groups:
                if set(g) & set(watch_present):
                    continue
                normalized_groups.append(g)
            groups = normalized_groups
            grouped_ips = {ip for g in groups for ip in g}
            groups.append(sorted(watch_present))
            grouped_ips.update(watch_present)

    # Explicit operator-defined merges for known same-device dual addressing.
    manual_clusters = [
        ["192.168.0.170", "100.78.64.7"],
        ["192.168.0.153", "192.168.0.151", "100.92.6.101"],
        ["100.67.102.109", "192.168.0.172"],
        ["192.168.0.198", "100.71.191.72"],
        ["192.168.0.158", "100.106.159.8"],
    ]
    for cluster in manual_clusters:
        present = [ip for ip in cluster if ip in by_ip]
        if len(present) < 2:
            continue
        # Remove overlaps so explicit mapping wins.
        normalized_groups = []
        for g in groups:
            if set(g) & set(present):
                continue
            normalized_groups.append(g)
        groups = normalized_groups
        grouped_ips = {ip for g in groups for ip in g}
        groups.append(_ordered_ips_for_manual_merge(present))
        grouped_ips.update(present)

    merged_devices = []
    for ips in groups:
        members = [by_ip[ip] for ip in ips if ip in by_ip]
        if not members:
            continue

        online_members = [m for m in members if m.get("status") == "Online"]
        online_primary_lan_members = [
            m for m in online_members
            if str(m.get("ip", "")).startswith("192.168.0.")
        ]
        primary_lan_members = [
            m for m in members
            if str(m.get("ip", "")).startswith("192.168.0.")
        ]
        online_non_tailscale = [
            m for m in online_members
            if not is_tailscale_ip(m.get("ip"))
        ]
        non_tailscale_members = [
            m for m in members
            if not is_tailscale_ip(m.get("ip"))
        ]
        # Prefer 192.168.0.0/24 as primary identity when present.
        primary = (
            online_primary_lan_members[0]
            if online_primary_lan_members else (
                primary_lan_members[0]
                if primary_lan_members else (
                    online_non_tailscale[0]
                    if online_non_tailscale else (
                        online_members[0]
                        if online_members else (
                            non_tailscale_members[0]
                            if non_tailscale_members else members[0]
                        )
                    )
                )
            )
        )

        status = "Online" if online_members else ("Offline" if all(m.get("status") == "Offline" for m in members) else "Unknown")
        status_color = "emerald" if status == "Online" else ("red" if status == "Offline" else "amber")

        ip_addresses = sorted(
            {m.get("ip") for m in members if m.get("ip")},
            key=lambda ip: (
                0 if str(ip).startswith("192.168.0.") else 1,
                1 if is_tailscale_ip(ip) else 0,
                ip,
            ),
        )
        per_ip_status = []
        for m in sorted(members, key=lambda item: item.get("ip", "")):
            per_ip_status.append({
                "ip": m.get("ip"),
                "status": m.get("status", "Unknown"),
                "last_seen": m.get("last_seen", "—"),
                "last_status_time": m.get("last_status_time", m.get("last_seen", "—")),
                "subnet_group": m.get("subnet_group", "Other Networks"),
            })
        current_ip_set = {m.get("ip") for m in members if m.get("ip")}
        should_sync_online_alias = (
            status == "Online"
            and any(cluster.issubset(current_ip_set) for cluster in ONLINE_ALIAS_SYNC_CLUSTERS)
        )
        if should_sync_online_alias:
            for row in per_ip_status:
                row["status"] = "Online"

        member_labels = [m.get("label") for m in members if m.get("label") not in (None, "", "—", "None")]
        merged = dict(primary)
        # Prefer richest deep-scan hints across LAN + Tailscale aliases.
        deep_os_pick = (merged.get("deep_os") or "").strip()
        svc_pick = (merged.get("deep_services_preview") or "").strip()
        scan_ts_pick = (merged.get("deep_scan_time") or "").strip()
        access_pick = (merged.get("access_methods_hint") or "").strip()
        for m in members:
            mo = (m.get("deep_os") or "").strip()
            if mo and mo != "Unknown" and len(mo) > len(deep_os_pick):
                deep_os_pick = mo
            ms = (m.get("deep_services_preview") or "").strip()
            if ms and len(ms) > len(svc_pick):
                svc_pick = ms
            mt = (m.get("deep_scan_time") or "").strip()
            if mt > scan_ts_pick:
                scan_ts_pick = mt
            ah = (m.get("access_methods_hint") or "").strip()
            if ah and len(ah) > len(access_pick):
                access_pick = ah
        if deep_os_pick:
            merged["deep_os"] = deep_os_pick
        if svc_pick:
            merged["deep_services_preview"] = svc_pick
        if scan_ts_pick:
            merged["deep_scan_time"] = scan_ts_pick
        if access_pick:
            merged["access_methods_hint"] = access_pick
        merged["ip"] = primary.get("ip")
        merged["ip_addresses"] = ip_addresses
        merged["ip_display"] = ", ".join(ip_addresses)
        merged["status"] = status
        merged["status_color"] = status_color
        merged["subnet_group"] = primary.get("subnet_group")
        merged["per_ip_status"] = per_ip_status
        # Merge timestamps across all correlated IPs.
        first_seen_candidates = [m.get("first_seen") for m in members if m.get("first_seen") not in (None, "", "—")]
        if first_seen_candidates:
            merged["first_seen"] = min(first_seen_candidates)
        last_seen_candidates = [m.get("last_seen") for m in members if m.get("last_seen") not in (None, "", "—")]
        if last_seen_candidates:
            merged["last_seen"] = max(last_seen_candidates)

        # Make transition history explicit about source IP.
        merged_events = []
        for m in members:
            src_ip = m.get("ip")
            for ev in (m.get("events") or []):
                if not isinstance(ev, dict) or not ev.get("timestamp"):
                    continue
                ev_copy = dict(ev)
                ev_copy["ip"] = src_ip
                merged_events.append(ev_copy)
        merged["events"] = sorted(
            merged_events,
            key=lambda ev: ev.get("timestamp", ""),
            reverse=True,
        )[:50]
        # When merged members have distinct non-IP hostnames, show both names.
        hostname_candidates = []
        for m in members:
            name = str(m.get("hostname") or "").strip()
            if not name or name in ("—", "None"):
                continue
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", name):
                continue
            if name not in hostname_candidates:
                hostname_candidates.append(name)
        if len(hostname_candidates) >= 2:
            merged["hostname"] = " / ".join(hostname_candidates)
        primary_ip = str(primary.get("ip") or "")
        preferred_hostname = KNOWN_HOSTNAME_OVERRIDES.get(primary_ip)
        if preferred_hostname:
            merged["hostname"] = preferred_hostname
        preferred_label = KNOWN_LABEL_OVERRIDES.get(primary_ip)
        if preferred_label:
            merged["label"] = preferred_label
            merged["labels"] = sorted(set(member_labels + [preferred_label]))
        elif member_labels:
            merged["label"] = member_labels[0]
            merged["labels"] = sorted(set(member_labels))
        # Keep a stable MAC if any member has one.
        for m in members:
            mac = m.get("mac")
            if mac not in (None, "", "—", "None"):
                merged["mac"] = mac
                break
        merged_devices.append(merged)

    # Keep non-grouped devices as-is.
    for d in devices:
        if d.get("ip") not in grouped_ips:
            d["ip_addresses"] = [d.get("ip")]
            d["ip_display"] = d.get("ip")
            d["per_ip_status"] = [{
                "ip": d.get("ip"),
                "status": d.get("status", "Unknown"),
                "last_seen": d.get("last_seen", "—"),
                "last_status_time": d.get("last_status_time", d.get("last_seen", "—")),
                "subnet_group": d.get("subnet_group", "Other Networks"),
            }]
            d["labels"] = [d["label"]] if d.get("label") not in (None, "", "—", "None") else []
            merged_devices.append(d)

    return merged_devices


def parse_markdown_devices():
    """Parse rich device information from devices.md including tables and Access Details section"""
    device_info = {}
    def clean_cell(value: str) -> str:
        if value is None:
            return ""
        return value.replace("**", "").replace("`", "").strip()

    try:
        with open(DEVICES_FILE, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        i = 0
        current_section = ""
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Parse markdown tables (main device inventory)
            if line.startswith('|') and ('IP' in line or 'Hostname' in line or 'Address' in line):
                headers = [h.strip() for h in line.split('|') if h.strip()]
                i += 2  # Skip separator
                
                while i < len(lines) and lines[i].strip().startswith('|'):
                    row_cells = [cell.strip() for cell in lines[i].split('|') if cell.strip()]
                    if len(row_cells) >= 2:
                        ip = None
                        hostname = "—"
                        identity = "Unknown Device"
                        mac = "—"
                        ports = "—"
                        access = ""
                        manufacturer = "—"
                        
                        for j, cell in enumerate(row_cells):
                            if j < len(headers):
                                header = headers[j].lower()
                                if any(x in header for x in ['ip', 'address']):
                                    ip = clean_cell(cell)
                                elif 'hostname' in header and clean_cell(cell) not in ['—', '', 'None']:
                                    hostname = clean_cell(cell)
                                elif any(x in header for x in ['identity', 'device']):
                                    identity = clean_cell(cell).replace('*', '').strip()
                                elif 'mac' in header and clean_cell(cell) not in ['—', '', 'None']:
                                    mac = clean_cell(cell)
                                elif any(x in header for x in ['port', 'ports']):
                                    ports = clean_cell(cell)
                                elif any(x in header for x in ['access', 'method']):
                                    access = clean_cell(cell)
                                elif any(x in header for x in ['manufacturer', 'vendor']):
                                    manufacturer = clean_cell(cell)
                        
                        if ip:
                            existing = device_info.get(ip, {})
                            existing_hostname = existing.get("hostname")
                            existing_identity = existing.get("identity")
                            existing_mac = existing.get("mac")
                            existing_ports = existing.get("ports")
                            existing_access = existing.get("access")
                            existing_manufacturer = existing.get("manufacturer")

                            # Keep richer/known values if a later table row is sparse.
                            merged = {
                                "hostname": hostname,
                                "identity": identity,
                                "mac": mac,
                                "ports": ports,
                                "access": access,
                                "manufacturer": manufacturer,
                                "source": "table"
                            }
                            if existing:
                                if merged["hostname"] in ("—", "", "None", None) and existing_hostname not in ("—", "", "None", None):
                                    merged["hostname"] = existing_hostname
                                if merged["identity"] in ("Unknown Device", "Unknown", "—", "", None) and existing_identity not in ("Unknown Device", "Unknown", "—", "", None):
                                    merged["identity"] = existing_identity
                                if merged["mac"] in ("—", "", "None", None) and existing_mac not in ("—", "", "None", None):
                                    merged["mac"] = existing_mac
                                if merged["ports"] in ("—", "", "None", None) and existing_ports not in ("—", "", "None", None):
                                    merged["ports"] = existing_ports
                                if merged["access"] in ("—", "", "None", None) and existing_access not in ("—", "", "None", None):
                                    merged["access"] = existing_access
                                if merged["manufacturer"] in ("—", "", "None", None) and existing_manufacturer not in ("—", "", "None", None):
                                    merged["manufacturer"] = existing_manufacturer
                                if existing.get("details"):
                                    merged["details"] = existing["details"]

                            device_info[ip] = merged
                    i += 1
                continue
            
            # Parse Access Details by Device Type section for richer info
            if line.startswith('## Access Details') or line.startswith('### '):
                current_section = line
            elif line.startswith('**') and ':' in line and any(ip_pattern in line for ip_pattern in ['192.168.', '100.', '172.']):
                # Extract IP from bold device headers
                import re
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Look ahead for details
                    details = []
                    j = i + 1
                    while j < len(lines) and not lines[j].strip().startswith('**') and not lines[j].strip().startswith('###'):
                        if lines[j].strip().startswith('- '):
                            details.append(lines[j].strip()[2:].strip())
                        j += 1
                    
                    if ip in device_info:
                        device_info[ip]["details"] = details
                        if "access" not in device_info[ip] or not device_info[ip]["access"]:
                            device_info[ip]["access"] = " | ".join([d for d in details if "Access" in d or "Web" in d or "SSH" in d][:2])
                    else:
                        device_info[ip] = {
                            "hostname": "—",
                            "identity": line.replace('**', '').split(':')[0].strip(),
                            "mac": "—",
                            "ports": "—",
                            "access": " | ".join([d for d in details if any(k in d for k in ["Access", "Web", "SSH", "HTTP"])]),
                            "manufacturer": "—",
                            "details": details,
                            "source": "access_section"
                        }
            
            i += 1
    except Exception as e:
        print(f"Error parsing markdown: {e}")
    
    return device_info


def load_scan_history():
    """Load scan history rows from yesterday + today in devices.md."""
    rows = []
    try:
        if not os.path.exists(DEVICES_FILE):
            return rows
        with open(DEVICES_FILE, "r") as f:
            lines = f.readlines()

        in_section = False
        for raw in lines:
            line = raw.strip()
            if line.startswith("## 📊 Scan History"):
                in_section = True
                continue
            if in_section and line.startswith("## ") and "Scan History" not in line:
                break
            if not in_section:
                continue
            if not line.startswith("|"):
                continue
            # Skip table header and separator
            if "Scan Time" in line or "---" in line:
                continue
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 4:
                rows.append({
                    "scan_time": parts[0],
                    "new_devices": parts[1],
                    "online": parts[2],
                    "total_known": parts[3],
                })
    except Exception as e:
        print(f"Warning: could not parse scan history: {e}")

    # Keep only today + yesterday
    now = datetime.now()
    today = now.date()
    yesterday = today.fromordinal(today.toordinal() - 1)
    filtered = []
    for r in rows:
        try:
            ts = datetime.strptime(r["scan_time"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        if ts.date() in (today, yesterday):
            filtered.append(r)

    return filtered


def load_recent_change_hostnames_from_md():
    """
    Parse 'Recent Online/Offline Changes' table in devices.md.
    Returns: {scan_time: {"online":[...], "offline":[...]}}
    """
    changes_by_scan = {}
    try:
        if not os.path.exists(DEVICES_FILE):
            return changes_by_scan
        with open(DEVICES_FILE, "r") as f:
            lines = f.readlines()

        in_section = False
        for raw in lines:
            line = raw.strip()
            if line.startswith("## Recent Online/Offline Changes"):
                in_section = True
                continue
            if in_section and line.startswith("## "):
                break
            if not in_section or not line.startswith("|"):
                continue
            if "Status" in line or "---" in line:
                continue

            parts = [p.strip() for p in line.split("|")[1:-1]]
            # Expected rough shape: status | devices | scan time/extra | notes...
            if len(parts) < 3:
                continue
            status_col = parts[0].replace("*", "").strip().lower()
            devices_col = parts[1].strip()

            # Find timestamp in any column.
            scan_time = None
            for p in parts:
                try:
                    datetime.strptime(p[:19], "%Y-%m-%d %H:%M:%S")
                    scan_time = p[:19]
                    break
                except Exception:
                    continue
            if not scan_time:
                continue

            if scan_time not in changes_by_scan:
                changes_by_scan[scan_time] = {"online": [], "offline": []}

            if devices_col in ("—", "-", "None", ""):
                continue

            # Devices column may have comma-separated hostnames.
            names = [n.strip() for n in devices_col.split(",") if n.strip()]
            if "online" in status_col:
                changes_by_scan[scan_time]["online"].extend(names)
            elif "offline" in status_col:
                changes_by_scan[scan_time]["offline"].extend(names)
    except Exception as e:
        print(f"Warning: could not parse recent change hostnames: {e}")

    return changes_by_scan


def load_scan_snapshots():
    """Load exact historical online snapshots captured at scan time."""
    try:
        if not os.path.exists(SCAN_SNAPSHOTS_FILE):
            return {}
        with open(SCAN_SNAPSHOTS_FILE, "r") as f:
            rows = json.load(f)
        by_time = {}
        for r in rows:
            ts = r.get("scan_time")
            if not ts:
                continue
            devs = r.get("online_devices", [])
            m = {}
            for d in devs:
                ip = d.get("ip")
                if not ip:
                    continue
                m[ip] = {
                    "ip": ip,
                    "hostname": d.get("hostname", ip)
                }
            by_time[ts] = m
        return by_time
    except Exception:
        return {}


def infer_online_devices_for_scan(scan_time_str: str):
    """Best-effort reconstruction of which devices were online at a given scan time."""
    try:
        scan_time = datetime.strptime(scan_time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return []

    online_devices = []
    md_info = parse_markdown_devices()
    labels = load_ip_labels()

    try:
        if not os.path.exists(CACHE_FILE):
            return []
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)
    except Exception:
        return []

    def looks_like_host(ip_addr: str) -> bool:
        parts = ip_addr.split(".")
        if len(parts) != 4:
            return False
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return False
        if nums[0] == 127:
            return False
        if nums[-1] in (0, 255):
            return False
        return True

    for ip, record in cache.items():
        if not looks_like_host(ip):
            continue
        try:
            first_seen = datetime.strptime(record.get("first_seen", ""), "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(record.get("last_seen", ""), "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue

        if first_seen > scan_time:
            continue

        # Build status timeline: assume online at first_seen, then apply events up to scan_time.
        status = "online"
        events = record.get("events", [])
        parsed_events = []
        for ev in events:
            ts = ev.get("timestamp")
            kind = ev.get("event")
            if not ts or kind not in ("online", "offline"):
                continue
            try:
                ev_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            parsed_events.append((ev_time, kind))
        parsed_events.sort(key=lambda x: x[0])

        for ev_time, kind in parsed_events:
            if ev_time <= scan_time:
                status = kind
            else:
                break

        # Heuristic fallback when no events exist in older records.
        if not parsed_events and first_seen <= scan_time <= last_seen:
            status = "online"

        if status == "online":
            rich = md_info.get(ip, {})
            hostname = choose_device_name(
                ip,
                rich.get("hostname"),
                record.get("hostname"),
                labels.get(ip),
            )
            online_devices.append({
                "ip": ip,
                "hostname": hostname,
                "identity": rich.get("identity", record.get("type", "Unknown Device")),
            })

    online_devices.sort(key=lambda x: x["hostname"].lower())
    return online_devices


def enrich_scan_history_with_state_changes(scan_history_rows):
    """
    For each scan row, compute devices that changed state compared to the previous scan.
    Expects rows in newest -> oldest order.
    """
    if not scan_history_rows:
        return scan_history_rows

    md_info = parse_markdown_devices()
    md_recent_changes = load_recent_change_hostnames_from_md()
    snapshots_by_time = load_scan_snapshots()
    labels = load_ip_labels()
    try:
        with open(CACHE_FILE, "r") as f:
            cache_records = json.load(f)
    except Exception:
        cache_records = {}

    # Cache online-device sets per scan time
    online_by_scan = {}
    for row in scan_history_rows:
        scan_time = row.get("scan_time", "")
        online_list = infer_online_devices_for_scan(scan_time)
        online_by_scan[scan_time] = {d["ip"]: d for d in online_list}

    def host_for_ip(ip: str) -> str:
        rich = md_info.get(ip, {})
        rec = cache_records.get(ip, {})
        return choose_device_name(
            ip,
            rich.get("hostname"),
            rec.get("hostname"),
            labels.get(ip),
        )

    def event_hostnames_between(prev_time_str: str, curr_time_str: str):
        """Collect hostnames that had online/offline events between two scans."""
        try:
            prev_time = datetime.strptime(prev_time_str, "%Y-%m-%d %H:%M:%S")
            curr_time = datetime.strptime(curr_time_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return [], []

        online_hosts = []
        offline_hosts = []
        for ip, rec in cache_records.items():
            for ev in rec.get("events", []):
                ts = ev.get("timestamp")
                kind = ev.get("event")
                if kind not in ("online", "offline") or not ts:
                    continue
                try:
                    ev_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if prev_time < ev_time <= curr_time:
                    name = host_for_ip(ip)
                    if kind == "online":
                        online_hosts.append(name)
                    else:
                        offline_hosts.append(name)
        # Preserve order, remove duplicates
        seen = set()
        online_hosts = [h for h in online_hosts if not (h in seen or seen.add(h))]
        seen = set()
        offline_hosts = [h for h in offline_hosts if not (h in seen or seen.add(h))]
        return online_hosts, offline_hosts

    def to_int(value, default=0):
        try:
            return int(str(value).strip())
        except Exception:
            return default

    enriched = []
    for idx, row in enumerate(scan_history_rows):
        current_time = row.get("scan_time", "")
        current_map = snapshots_by_time.get(current_time, online_by_scan.get(current_time, {}))
        current_online_count = to_int(row.get("online", 0))

        if idx + 1 < len(scan_history_rows):
            prev_row = scan_history_rows[idx + 1]
            prev_time = prev_row.get("scan_time", "")
            prev_map = snapshots_by_time.get(prev_time, online_by_scan.get(prev_time, {}))
            prev_online_count = to_int(prev_row.get("online", 0))
        else:
            prev_map = {}
            prev_online_count = 0

        row_copy = dict(row)
        delta_online = current_online_count - prev_online_count

        # Use Online column delta as source of truth for direction and count.
        inferred_added_ips = sorted(set(current_map.keys()) - set(prev_map.keys()))
        inferred_removed_ips = sorted(set(prev_map.keys()) - set(current_map.keys()))
        event_online_hosts, event_offline_hosts = event_hostnames_between(prev_time if idx + 1 < len(scan_history_rows) else "1970-01-01 00:00:00", current_time)

        if delta_online > 0:
            came_online_ips = inferred_added_ips[:delta_online]
            went_offline_ips = []
        elif delta_online < 0:
            came_online_ips = []
            went_offline_ips = inferred_removed_ips[:abs(delta_online)]
        else:
            came_online_ips = []
            went_offline_ips = []

        came_online = [current_map[ip].get("hostname", ip) for ip in came_online_ips]
        went_offline = [prev_map[ip].get("hostname", ip) for ip in went_offline_ips]

        # Prefer explicit hostnames from devices.md Recent Online/Offline Changes.
        md_changes = md_recent_changes.get(current_time, {})
        if delta_online > 0 and md_changes.get("online"):
            came_online = md_changes.get("online", [])[:delta_online]
        if delta_online < 0 and md_changes.get("offline"):
            went_offline = md_changes.get("offline", [])[:abs(delta_online)]

        # Then prefer explicit event-derived hostnames when available.
        if delta_online > 0 and event_online_hosts:
            came_online = event_online_hosts[:delta_online]
        if delta_online < 0 and event_offline_hosts:
            went_offline = event_offline_hosts[:abs(delta_online)]

        # Fallback: infer from first_seen / last_seen deltas between scans.
        try:
            curr_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
            prev_dt = datetime.strptime(prev_time, "%Y-%m-%d %H:%M:%S") if idx + 1 < len(scan_history_rows) else datetime.min
        except Exception:
            curr_dt = None
            prev_dt = None

        if curr_dt and prev_dt:
            if delta_online > 0 and len(came_online) < delta_online:
                candidates = []
                for ip, rec in cache_records.items():
                    ts = rec.get("first_seen")
                    if not ts:
                        continue
                    try:
                        t = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        continue
                    if prev_dt < t <= curr_dt:
                        candidates.append(host_for_ip(ip))
                for name in candidates:
                    if name not in came_online:
                        came_online.append(name)
                    if len(came_online) >= delta_online:
                        break

            if delta_online < 0 and len(went_offline) < abs(delta_online):
                candidates = []
                for ip, rec in cache_records.items():
                    ts = rec.get("last_seen")
                    if not ts:
                        continue
                    try:
                        t = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        continue
                    if prev_dt < t <= curr_dt:
                        candidates.append(host_for_ip(ip))
                for name in candidates:
                    if name not in went_offline:
                        went_offline.append(name)
                    if len(went_offline) >= abs(delta_online):
                        break

        # Ensure displayed hostname counts align with online delta even when inference is incomplete.
        if delta_online > 0 and len(came_online) < delta_online:
            missing = delta_online - len(came_online)
            came_online.extend([f"Unresolved (+{i+1})" for i in range(missing)])
        if delta_online < 0 and len(went_offline) < abs(delta_online):
            missing = abs(delta_online) - len(went_offline)
            went_offline.extend([f"Unresolved (-{i+1})" for i in range(missing)])

        row_copy["state_changes"] = {
            "online": came_online,
            "offline": went_offline,
            "online_count": len(came_online),
            "offline_count": len(went_offline),
            "delta_online": delta_online,
            "reported_online": current_online_count,
            "previous_online": prev_online_count,
        }
        enriched.append(row_copy)

    return enriched


def build_scan_status_matrix(scan_history_rows):
    """
    Build a scan/device matrix where each row is a scan time and each column is a device.
    Status is carried forward until a change is detected at a later scan.
    """
    snapshots_by_time = load_scan_snapshots()
    if not scan_history_rows:
        # Fallback to snapshot timeline when markdown scan-history rows are unavailable.
        fallback_rows = [
            {"scan_time": ts}
            for ts in sorted(snapshots_by_time.keys(), reverse=True)
        ]
        scan_history_rows = fallback_rows
    if not scan_history_rows:
        return {"devices": [], "rows": []}

    # scan_history_rows are newest->oldest; process oldest->newest for state propagation.
    chronological_rows = list(reversed(scan_history_rows))
    online_sets_by_scan = {}
    device_ips = set()

    for row in chronological_rows:
        scan_time = row.get("scan_time", "")
        snapshot = snapshots_by_time.get(scan_time)
        if snapshot:
            online_map = snapshot
        else:
            inferred = infer_online_devices_for_scan(scan_time)
            online_map = {d["ip"]: d for d in inferred if d.get("ip")}

        online_ips = set(online_map.keys())
        online_sets_by_scan[scan_time] = online_ips
        device_ips.update(online_ips)

    # Include currently known devices as columns even if they never appeared online in recent rows.
    current_devices, _ = load_device_data()
    for d in current_devices:
        ip = d.get("ip")
        if ip:
            device_ips.add(ip)

    ordered_devices = sorted(device_ips)
    device_meta = {}
    current_state = {ip: "Unknown" for ip in ordered_devices}
    matrix_rows = []

    for d in current_devices:
        ip = d.get("ip")
        if not ip:
            continue
        device_meta[ip] = {
            "hostname": d.get("hostname", ip),
            "label": d.get("label", ""),
        }

    for row in chronological_rows:
        scan_time = row.get("scan_time", "")
        online_ips = online_sets_by_scan.get(scan_time, set())
        cell_map = {}
        transition_map = {}

        for ip in ordered_devices:
            next_state = "Online" if ip in online_ips else "Offline"
            prev_state = current_state.get(ip, "Unknown")
            transition = "none"
            if prev_state != "Unknown" and next_state != prev_state:
                transition = "online" if next_state == "Online" else "offline"

            current_state[ip] = next_state
            cell_map[ip] = next_state
            transition_map[ip] = transition

        matrix_rows.append({
            "scan_time": scan_time,
            "cells": cell_map,
            "transitions": transition_map,
        })

    # Return newest scan at top.
    matrix_rows.reverse()
    return {
        "devices": ordered_devices,
        "device_meta": device_meta,
        "rows": matrix_rows,
    }


def load_device_data():
    """Load and enrich device data from cache + rich markdown details"""
    devices = []
    md_info = parse_markdown_devices()
    labels = load_ip_labels()
    deep_map = load_deep_scan_results_map()

    def get_subnet_group(ip: str) -> str:
        if ip in KNOWN_SUBNET_OVERRIDES:
            return KNOWN_SUBNET_OVERRIDES[ip]
        if ip == "24.192.17.178":
            return "External/Public Internet"
        if ip.startswith("192.168.0."):
            return "Local LAN (192.168.0.0/24)"
        if ip.startswith("192.168.1."):
            return "Adjacent Subnet (192.168.1.0/24)"
        if ip.startswith("192.168.100."):
            return "Adjacent Subnet (192.168.100.0/24)"
        if ip.startswith("172.17."):
            return "Docker Network (172.17.0.0/16)"
        if ip.startswith("100."):
            return "Tailscale Mesh VPN"
        return "Other Networks"
    
    # Load from JSON cache (status, timestamps)
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                cache = json.load(f)
                
            for ip, data in cache.items():
                if ip in HIDDEN_DEVICE_IPS:
                    continue
                status = data.get("last_status", "unknown")
                last_seen = data.get("last_seen", "—")
                cache_hostname = data.get("hostname", "—")
                
                # Get rich info from markdown if available
                rich = md_info.get(ip, {})
                
                rich_hostname = rich.get("hostname")
                hostname = choose_device_name(ip, cache_hostname, rich_hostname)
                
                cached_identity = (data.get("identity") or "").strip()
                if cached_identity and cached_identity not in ("Unknown Device", "Unknown", "—", "None"):
                    identity = cached_identity
                else:
                    device_type = (data.get("type") or "Unknown").strip()
                    if device_type and device_type != "Unknown":
                        identity = device_type
                    else:
                        rich_identity = rich.get("identity")
                        identity = (
                            rich_identity
                            if rich_identity not in ["Unknown Device", "Unknown", "—", "None", None, ""]
                            else "Unknown device"
                        )
                mac = rich.get("mac", data.get("mac", "—"))
                if ip in KNOWN_MAC_OVERRIDES and mac in (None, "", "—", "None"):
                    mac = KNOWN_MAC_OVERRIDES[ip]
                rich_manufacturer = rich.get("manufacturer")
                if rich_manufacturer in (None, "", "—", "None"):
                    manufacturer = data.get("manufacturer", "—")
                else:
                    manufacturer = rich_manufacturer
                rich_ports = rich.get("ports")
                if rich_ports in (None, "", "—", "None"):
                    rich_ports = data.get("ports", "—")
                if isinstance(rich_ports, list):
                    ports = ", ".join(str(p) for p in rich_ports) if rich_ports else "—"
                else:
                    ports = rich_ports

                deep_row = deep_map.get(ip, {})
                if not isinstance(deep_row, dict):
                    deep_row = {}
                deep_os = (data.get("deep_os") or "").strip()
                if not deep_os:
                    deep_os = (deep_row.get("os") or "").strip()
                if deep_os == "Unknown":
                    deep_os = ""
                svc_src = data.get("services") if isinstance(data.get("services"), dict) else {}
                svc_preview = format_deep_services_preview(svc_src)
                if not svc_preview:
                    svc_preview = format_deep_services_preview(
                        deep_row.get("services") if isinstance(deep_row.get("services"), dict) else {}
                    )
                deep_scan_ts = (data.get("deep_scan_time") or deep_row.get("scan_time") or "").strip()
                access_hint = (data.get("access_methods_hint") or "").strip()

                # Drop legacy stealth-tagged devices from previous network installs.
                if "stealth" in str(identity).lower():
                    continue

                # Determine visual status
                if status == "online" or "online" in str(identity).lower():
                    status_color = "emerald"
                    status_text = "Online"
                elif status == "offline":
                    status_color = "red"
                    status_text = "Offline"
                else:
                    status_color = "amber"
                    status_text = "Unknown"
                
                devices.append({
                    "ip": ip,
                    "hostname": hostname,
                    "label": "",
                    "identity": identity,
                    "subnet_group": get_subnet_group(ip),
                    "status": status_text,
                    "status_color": status_color,
                    "last_seen": last_seen,
                    "type": identity.split('/')[0].strip() if '/' in identity else identity,
                    "mac": mac,
                    "manufacturer": manufacturer,
                    "first_seen": data.get("first_seen", "—"),
                    "ports": ports,
                    "events": data.get("events", []),
                    "last_status_time": data.get("last_status_time", last_seen),
                    "deep_os": deep_os,
                    "deep_services_preview": svc_preview,
                    "deep_scan_time": deep_scan_ts,
                    "access_methods_hint": access_hint,
                })
    except Exception as e:
        print(f"Error loading cache: {e}")
    
    # Collapse correlated aliases (MAC, known clusters, Tailscale<->LAN hostname pairs).
    devices = collapse_duplicate_devices(devices)

    cfg = load_device_groups_config()
    ip_to_custom = build_ip_to_custom_group(cfg)
    openclaw_excluded = frozenset(cfg.get("openclaw_excluded_ips") or [])

    custom_buckets: dict[str, list] = {gid: [] for gid in (cfg.get("custom_groups") or {})}
    builtin_input: list = []
    for d in devices:
        gid = None
        for ip in _device_ip_set(d):
            if ip in ip_to_custom:
                gid = ip_to_custom[ip]
                break
        if gid:
            custom_buckets.setdefault(gid, []).append(d)
        else:
            builtin_input.append(d)

    for d in builtin_input:
        d["ollama_server"] = _is_ollama_server_device(d)

    pins_cfg = cfg.get("section_pins") or {}
    pinned_by: dict[str, list] = {bid: [] for bid in BUILTIN_SECTION_ITER}
    unpinned: list = []
    for d in builtin_input:
        pin_target = None
        for ip in sorted(_device_ip_set(d)):
            tgt = pins_cfg.get(ip)
            if tgt in ALLOWED_BUILTIN_SECTION_IDS:
                pin_target = tgt
                break
        if pin_target:
            pinned_by[pin_target].append(d)
        else:
            unpinned.append(d)

    ollama_devices = [d for d in unpinned if d.get("ollama_server")]
    non_ollama = [d for d in unpinned if not d.get("ollama_server")]
    access_point_devices = [d for d in non_ollama if _device_is_access_point(d)]
    rest_non_ollama = [d for d in non_ollama if not _device_is_access_point(d)]
    openclaw_devices = [d for d in rest_non_ollama if _device_has_openclaw_lan_subnet(d)]
    other_networks_lan = [d for d in openclaw_devices if _device_ip_set(d) & openclaw_excluded]
    openclaw_devices = [d for d in openclaw_devices if not (_device_ip_set(d) & openclaw_excluded)]
    other_devices = [d for d in rest_non_ollama if not _device_has_openclaw_lan_subnet(d)]
    tailscale_only_devices = [d for d in other_devices if _device_is_tailscale_only(d)]
    other_wide_devices = [d for d in other_devices if not _device_is_tailscale_only(d)]
    other_wide_devices = other_wide_devices + other_networks_lan

    ollama_devices = _dedupe_device_list(ollama_devices + pinned_by["ollama"])
    openclaw_devices = _dedupe_device_list(openclaw_devices + pinned_by["openclaw"])
    access_point_devices = _dedupe_device_list(access_point_devices + pinned_by["access_point"])
    other_wide_devices = _dedupe_device_list(other_wide_devices + pinned_by["other_wide"])
    tailscale_only_devices = _dedupe_device_list(tailscale_only_devices + pinned_by["tailscale"])

    def status_priority(d):
        if d["status"] == "Online":
            return 0
        if d["status"] == "Unknown":
            return 1
        if d["status"] == "Offline":
            return 2
        return 3

    def name_priority(d):
        """Put devices with real hostnames before those that only show IP"""
        hostname = d.get("hostname", "")
        if (
            not hostname
            or hostname == d.get("ip", "")
            or hostname.startswith("192.168.")
            or hostname.startswith("100.")
            or hostname.startswith("172.")
        ):
            return 1
        return 0

    for _gid, lst in custom_buckets.items():
        lst.sort(
            key=lambda x: (
                status_priority(x),
                name_priority(x),
                x.get("hostname", "").lower(),
            )
        )

    builtin_lists = {
        "ollama": ollama_devices,
        "openclaw": openclaw_devices,
        "access_point": access_point_devices,
        "other_wide": other_wide_devices,
        "tailscale": tailscale_only_devices,
    }

    _apply_section_bans_and_rehome(
        builtin_lists,
        cfg.get("section_bans") or {},
        openclaw_excluded,
    )

    for bid in BUILTIN_SECTION_ITER:
        lst = _dedupe_device_list(builtin_lists.get(bid) or [])
        if bid == "ollama":
            lst.sort(
                key=lambda x: (
                    _ollama_server_rank(x),
                    status_priority(x),
                    name_priority(x),
                    x.get("hostname", "").lower(),
                )
            )
        else:
            lst.sort(
                key=lambda x: (
                    status_priority(x),
                    name_priority(x),
                    x.get("hostname", "").lower(),
                )
            )
        builtin_lists[bid] = lst

    merged: list = []
    for sec in cfg.get("section_order") or []:
        st = sec.get("type")
        sid = sec.get("id")
        if st == "builtin" and sid in builtin_lists:
            for d in builtin_lists[sid]:
                d["section_key"] = sid
                merged.append(d)
        elif st == "custom" and sid:
            sk = f"custom:{sid}"
            for d in custom_buckets.get(sid, []):
                d["section_key"] = sk
                merged.append(d)

    merged_ids = {id(d) for d in merged}
    for bid, lst in builtin_lists.items():
        for d in lst:
            if id(d) not in merged_ids:
                d["section_key"] = bid
                merged.append(d)
                merged_ids.add(id(d))
    for gid, lst in custom_buckets.items():
        for d in lst:
            if id(d) not in merged_ids:
                d["section_key"] = f"custom:{gid}"
                merged.append(d)
                merged_ids.add(id(d))

    for d in merged:
        sk = d.get("section_key") or ""
        d["ollama_server"] = sk == "ollama"
        d["openclaw_lan"] = sk == "openclaw"
        d["access_point"] = sk == "access_point"
        d["tailscale_only"] = sk == "tailscale"
        d["personal_device"] = sk.startswith("custom:")

    section_order = build_section_order_for_api(cfg)
    return merged, section_order


def build_watch_correlation_findings():
    """Build concise watch-correlation findings for dashboard display."""
    watches = [
        {
            "ip": "192.168.0.98, 192.168.0.112",
            "hostname": "Irene's Watch",
            "mac": "4e:0a:ec:36:fd:82",
            "discovered": "Merged alias across subnets",
        },
    ]

    conclusion = (
        "Dashboard now treats 192.168.0.98 and 192.168.0.112 as one logical device "
        "labeled Irene's Watch."
    )
    source_url = "https://support.apple.com/en-us/HT211227"
    source_summary = (
        "Apple states Apple Watch can use private Wi-Fi addresses that differ per network "
        "and can rotate over time."
    )

    return {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "watches": watches,
        "conclusion": conclusion,
        "source_url": source_url,
        "source_summary": source_summary,
    }


def fetch_roku_device_info(ip: str):
    """
    Fetch Roku ECP /query/device-info payload if available.
    Returns a dict of selected fields, or {} when unavailable.
    """
    url = f"http://{ip}:8060/query/device-info"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkPulse/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            xml_payload = resp.read()
        root = ET.fromstring(xml_payload)

        wanted = [
            "friendly-device-name",
            "user-device-location",
            "model-name",
            "model-number",
            "software-version",
            "software-build",
            "network-name",
            "power-mode",
            "uptime",
            "supports-airplay",
            "ecp-setting-mode",
            "developer-enabled",
        ]
        info = {}
        for key in wanted:
            node = root.find(key)
            if node is not None and node.text not in (None, ""):
                info[key] = node.text
        return info
    except (urllib.error.URLError, ET.ParseError, TimeoutError, ValueError):
        return {}
    except Exception:
        return {}


def fetch_roku_playback_info(ip: str):
    """
    Fetch best-effort Roku playback context.
    Returns active app/screensaver, plus limited-mode hint when media-player is blocked.
    """
    result = {}

    # Active app is usually available even when richer media-player data is blocked.
    active_app_url = f"http://{ip}:8060/query/active-app"
    try:
        req = urllib.request.Request(active_app_url, headers={"User-Agent": "NetworkPulse/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            payload = resp.read()
        root = ET.fromstring(payload)

        app_node = root.find("app")
        if app_node is not None:
            result["active_app_name"] = (app_node.text or "").strip()
            result["active_app_id"] = app_node.get("id", "")
            result["active_app_type"] = app_node.get("type", "")
            result["active_app_ui_location"] = app_node.get("ui-location", "")

        screensaver_node = root.find("screensaver")
        if screensaver_node is not None:
            result["screensaver_name"] = (screensaver_node.text or "").strip()
    except Exception:
        pass

    # Probe media-player once to detect limited-mode restrictions for display context.
    media_player_url = f"http://{ip}:8060/query/media-player"
    try:
        req = urllib.request.Request(media_player_url, headers={"User-Agent": "NetworkPulse/1.0"})
        with urllib.request.urlopen(req, timeout=2.5):
            result["media_player_access"] = "available"
    except urllib.error.HTTPError as e:
        if e.code == 403:
            result["media_player_access"] = "limited_mode_blocked"
    except Exception:
        pass

    return result


def check_online_status():
    """Quick outbound connectivity probe for dashboard online/offline indicator."""
    probe_urls = [
        "https://clients3.google.com/generate_204",
        "https://1.1.1.1",
    ]
    for url in probe_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetworkPulse/1.0"})
            with urllib.request.urlopen(req, timeout=2.5):
                return {
                    "online": True,
                    "label": "ONLINE",
                    "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
        except Exception:
            continue
    return {
        "online": False,
        "label": "OFFLINE",
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_public_ip():
    """Fetch current public WAN egress IPv4 for dashboard header."""
    urls = [
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetworkPulse/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                raw = resp.read().decode("utf-8").strip()
            candidate = raw.split()[0] if raw else ""
            if not candidate:
                continue
            parsed = ipaddress.ip_address(candidate)
            if parsed.version == 4:
                return str(parsed)
        except Exception:
            continue
    return "Unavailable"


def get_local_ip():
    """Best-effort primary local LAN IP for dashboard header."""
    probe_targets = [("8.8.8.8", 80), ("1.1.1.1", 80)]
    for host, port in probe_targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((host, port))
            ip = sock.getsockname()[0]
            sock.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            continue
    return "Unavailable"


def get_tailscale_ip():
    """Return first IPv4 Tailscale address, if available."""
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode != 0:
            return "Unavailable"
        for line in (result.stdout or "").splitlines():
            ip = line.strip()
            if ip.startswith("100."):
                return ip
    except Exception:
        pass
    return "Unavailable"


_DOCKER_PRINT_SKIP_IPV4 = frozenset({"172.17.0.1", "172.18.0.1"})


def iter_dashboard_ipv4_listen_addrs():
    """IPv4 addresses browsers may use to reach this host (LAN + Tailscale)."""
    seen = set()
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            for part in (result.stdout or "").split():
                ip = part.strip()
                if not ip or ip.startswith("127.") or ip in _DOCKER_PRINT_SKIP_IPV4:
                    continue
                try:
                    parsed = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if parsed.version != 4:
                    continue
                if ip not in seen:
                    seen.add(ip)
                    yield ip
    except Exception:
        pass
    if seen:
        return
    lan = get_local_ip()
    if lan and lan != "Unavailable":
        yield lan
    ts = get_tailscale_ip()
    if ts and ts != "Unavailable":
        yield ts


def print_dashboard_listen_hints(port: int, scheme: str = "http") -> None:
    """Log URLs for each reachable IPv4 (sorted LAN before Tailscale)."""
    addrs = sorted(
        iter_dashboard_ipv4_listen_addrs(),
        key=lambda x: (x.startswith("100."), x),
    )
    for ip in addrs:
        label = "Tailscale" if ip.startswith("100.") else "LAN"
        print(f" - {scheme}://{ip}:{port}/ ({label})")


def get_active_users():
    """Return logged-in users with session detail (local vs ssh)."""
    users = {}
    try:
        result = subprocess.run(
            ["who"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        for line in (result.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            username = parts[0]
            terminal = parts[1]
            host = parts[4].strip("()") if len(parts) >= 5 else ""
            if terminal.startswith("pts/"):
                session_type = "ssh"
            elif terminal == ":0" or terminal.startswith("tty"):
                session_type = "local"
            else:
                session_type = "other"

            entry = users.setdefault(username, {"username": username, "sessions": []})
            entry["sessions"].append({
                "terminal": terminal,
                "host": host,
                "type": session_type,
            })
    except Exception:
        pass
    return sorted(users.values(), key=lambda u: u["username"])


READ_CMD_EXEC_AUDIT_SH = str(BASE_DIR / "dashboard" / "bin" / "read_cmd_exec_audit.sh")


def audit_helper_use_sudo() -> bool:
    return os.environ.get("AUDIT_USE_SUDO", "1").strip().lower() not in ("0", "false", "no")


def audit_helper_argv(since: str) -> list[str]:
    """Argv list for running read_cmd_exec_audit.sh (no shell)."""
    configured = os.environ.get("AUDIT_HELPER_CMD", "").strip()
    if configured:
        return shlex.split(resolve_audit_helper_cmd(since))
    if audit_helper_use_sudo():
        return ["sudo", "-n", READ_CMD_EXEC_AUDIT_SH, since]
    return [READ_CMD_EXEC_AUDIT_SH, since]


def resolve_audit_helper_cmd(since: str) -> str:
    """Resolve audit helper command from env or safe default (string form for logs / custom AUDIT_HELPER_CMD)."""
    configured = os.environ.get("AUDIT_HELPER_CMD", "").strip()
    if configured:
        if "{since}" in configured:
            return configured.replace("{since}", since)
        return f"{configured} {since}"
    # ausearch normally needs root to read audit logs; NOPASSWD sudoers entry recommended.
    if audit_helper_use_sudo():
        return f"sudo -n {shlex.quote(READ_CMD_EXEC_AUDIT_SH)} {shlex.quote(since)}"
    return f"{READ_CMD_EXEC_AUDIT_SH} {since}"


def resolve_wifi_scan_cmd() -> str:
    """Resolve WiFi scan command from env or safe default."""
    # Default: run the helper directly (often works under NetworkManager without root).
    # Set WIFI_SCAN_USE_SUDO=1 plus NOPASSWD sudoers when `iw scan` must run as root.
    helper = BASE_DIR / "dashboard" / "bin" / "scan_wifi_ssids.sh"
    use_sudo = os.environ.get("WIFI_SCAN_USE_SUDO", "0").strip().lower() not in ("0", "false", "no")
    default_cmd = f"sudo -n {helper}" if use_sudo else f"{helper}"
    return os.environ.get("WIFI_SCAN_CMD", default_cmd).strip()


def resolve_trace_helper_cmd(action: str, minutes: int = 15) -> str:
    """Resolve trace helper command from env or safe default."""
    helper = BASE_DIR / "dashboard" / "bin" / "network_trace_control.sh"
    default_cmd = f"sudo -n {helper} {action} {minutes}"
    configured = os.environ.get("TRACE_HELPER_CMD", "").strip()
    if not configured:
        return default_cmd
    cmd = configured
    if "{action}" in cmd:
        cmd = cmd.replace("{action}", action)
    else:
        cmd = f"{cmd} {action}"
    if "{minutes}" in cmd:
        cmd = cmd.replace("{minutes}", str(minutes))
    else:
        cmd = f"{cmd} {minutes}"
    return cmd


def get_network_trace(action: str = "summary", minutes: int = 15):
    """Manage network trace capture and fetch ingress/egress summaries."""
    action = (action or "summary").strip().lower()
    if action not in {"start", "stop", "status", "summary"}:
        return {
            "ok": False,
            "message": "Invalid trace action. Use start, stop, status, or summary.",
        }

    helper_cmd = resolve_trace_helper_cmd(action, minutes)
    try:
        result = subprocess.run(
            shlex.split(helper_cmd),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as e:
        return {
            "ok": False,
            "message": f"Failed to execute trace helper: {e}",
            "action": action,
        }

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0:
        # If helper returned structured JSON on a non-zero code, surface it directly.
        if stdout:
            try:
                payload = json.loads(stdout)
                if isinstance(payload, dict):
                    payload.setdefault("ok", False)
                    payload.setdefault("action", action)
                    return payload
            except Exception:
                pass
        lowered = stderr.lower()
        if "password is required" in lowered or "a password is required" in lowered:
            return {
                "ok": False,
                "message": "Trace helper needs NOPASSWD sudo authorization.",
                "action": action,
            }
        if "not allowed to execute" in lowered or "permission denied" in lowered:
            return {
                "ok": False,
                "message": "Trace helper is not authorized yet. Install the network-trace sudoers rule.",
                "action": action,
            }
        return {
            "ok": False,
            "message": stderr or "Trace helper failed.",
            "action": action,
        }

    payload = None
    if stdout:
        try:
            payload = json.loads(stdout)
        except Exception:
            payload = None
    if isinstance(payload, dict):
        payload.setdefault("ok", True)
        payload.setdefault("action", action)
        return payload
    return {
        "ok": True,
        "action": action,
        "message": stdout or "Trace helper completed.",
    }


def get_wifi_ssids(limit: int = 80):
    """Return nearby WiFi SSIDs using a helper command (usually sudo-wrapped)."""
    helper_cmd = resolve_wifi_scan_cmd()
    timeout_s = 45
    try:
        timeout_s = int(os.environ.get("WIFI_SCAN_TIMEOUT_SEC", "45"))
    except Exception:
        timeout_s = 45
    timeout_s = max(10, min(timeout_s, 120))

    try:
        result = subprocess.run(
            shlex.split(helper_cmd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except Exception as e:
        return {
            "ok": False,
            "message": f"Failed to execute WiFi scan helper: {e}",
            "networks": [],
        }

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        # Optional fallback: direct execution can work on some hosts, but it may
        # return only cached/current SSID data when active scans are restricted.
        allow_unpriv_fallback = os.environ.get(
            "WIFI_SCAN_ALLOW_UNPRIVILEGED_FALLBACK", "1"
        ).strip().lower() in ("1", "true", "yes")
        if allow_unpriv_fallback and helper_cmd.startswith("sudo -n "):
            direct_cmd = helper_cmd[len("sudo -n ") :]
            try:
                retry = subprocess.run(
                    shlex.split(direct_cmd),
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                )
                if retry.returncode == 0:
                    result = retry
                    stdout = (result.stdout or "").strip()
                    stderr = (result.stderr or "").strip()
                else:
                    stderr = (retry.stderr or stderr).strip()
            except Exception:
                pass

    if result.returncode != 0:
        lowered = stderr.lower()
        if "password is required" in lowered or "a password is required" in lowered:
            return {
                "ok": False,
                "message": "WiFi scan helper needs NOPASSWD sudo authorization. Install the provided sudoers rule for scan_wifi_ssids.sh.",
                "networks": [],
            }
        if "not allowed to execute" in lowered or "permission denied" in lowered:
            return {
                "ok": False,
                "message": "WiFi scan helper is not authorized yet. Add a sudoers rule for the dashboard user.",
                "networks": [],
            }
        return {
            "ok": False,
            "message": stderr or "WiFi scan failed.",
            "networks": [],
        }

    try:
        data = json.loads(stdout) if stdout else {}
    except Exception:
        return {
            "ok": False,
            "message": "WiFi scan helper returned invalid JSON output.",
            "networks": [],
        }

    networks = data.get("networks", [])
    if not isinstance(networks, list):
        networks = []

    def score(n):
        raw = n.get("signal_dbm")
        try:
            return float(raw)
        except Exception:
            return -999.0

    networks = sorted(networks, key=score, reverse=True)[: max(1, limit)]
    interface = data.get("interface", "unknown")
    return {
        "ok": True,
        "message": f"Showing {len(networks)} nearby WiFi networks on {interface}.",
        "interface": interface,
        "networks": networks,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ausearch may emit multi-megabyte type=EXECVE lines (full argv as a0..an). Skip them;
# we display PROCTITLE + SYSCALL exe= instead.
AUDIT_PARSE_MAX_STDOUT_CHARS = 15 * 1024 * 1024
AUDIT_PARSE_MAX_LINE_CHARS = 16384
AUDIT_DISPLAY_MAX_COMMAND_CHARS = 512
AUDIT_SUBPROCESS_TIMEOUT_SEC = 15


def get_audit_activity(limit: int = 300, since: str = "today", user_filter: str = ""):
    """
    Return recent cmd_exec audit events.
    Uses ausearch output when readable; otherwise returns a permission hint.
    """
    cmd = audit_helper_argv(since)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=AUDIT_SUBPROCESS_TIMEOUT_SEC,
        )
    except Exception as e:
        return {
            "ok": False,
            "message": f"Failed to execute ausearch: {e}",
            "events": [],
        }

    stdout = result.stdout or ""
    if len(stdout) > AUDIT_PARSE_MAX_STDOUT_CHARS:
        stdout = stdout[:AUDIT_PARSE_MAX_STDOUT_CHARS]
    stderr = result.stderr or ""
    combined_err = (stderr or "").strip()
    err_low = combined_err.lower()

    # ausearch exits non-zero with "<no matches>" when the query matches nothing.
    if result.returncode != 0 and "<no matches>" in err_low:
        return {
            "ok": True,
            "message": f"No cmd_exec audit events since {since}.",
            "users": [],
            "events": [],
        }

    if result.returncode != 0 and not stdout.strip():
        if "no new privileges" in err_low:
            return {
                "ok": False,
                "message": (
                    "Audit command attempted privilege escalation in a no-new-privileges "
                    "environment (common with systemd NoNewPrivileges=yes). Remove that restriction "
                    "for the dashboard service, or run the dashboard interactively without it. "
                    "Alternatively configure AUDIT_HELPER_CMD if a non-setuid path can read audit logs."
                ),
                "events": [],
            }
        if "ausearch not found" in err_low or "no such file or directory" in err_low:
            return {
                "ok": False,
                "message": (
                    "Linux audit tools are missing or not installed. Run: sudo apt-get install -y auditd "
                    "Then copy dashboard/audit-rules.d/99-network-pulse-cmd-exec.rules to /etc/audit/rules.d/, "
                    "run sudo augenrules --load, and install network-pulse-audit.sudoers so the dashboard user "
                    "may run read_cmd_exec_audit.sh via sudo -n."
                ),
                "events": [],
            }
        if "permission denied" in err_low or "Permission denied" in combined_err:
            return {
                "ok": False,
                "message": (
                    "Audit helper cannot read the audit log (permission denied). Install the NOPASSWD sudoers rule: "
                    "run dashboard/bin/install_audit_sudoers.sh once (enter your sudo password), "
                    "or: sudo install -m 440 dashboard/network-pulse-audit.sudoers /etc/sudoers.d/network-pulse-audit "
                    "&& sudo visudo -cf /etc/sudoers.d/network-pulse-audit"
                ),
                "events": [],
            }
        if "password is required" in err_low or "a password is required" in err_low:
            return {
                "ok": False,
                "message": (
                    "Dashboard runs sudo -n for audit logs; NOPASSWD is required. Run once: "
                    "dashboard/bin/install_audit_sudoers.sh "
                    "(or install dashboard/network-pulse-audit.sudoers into /etc/sudoers.d/network-pulse-audit). "
                    "Ensure the sudoers path matches READ_CMD_EXEC_AUDIT_SH on this host."
                ),
                "events": [],
            }
        if (
            "not allowed" in err_low
            or "not permitted to execute" in err_low
            or "unknown user" in err_low
            or err_low.startswith("sudo:")
        ):
            return {
                "ok": False,
                "message": (
                    "Audit helper is not authorized yet. Add a sudoers rule so the dashboard Linux user may run "
                    f"{READ_CMD_EXEC_AUDIT_SH} as root without a password "
                    "(see dashboard/bin/install_audit_sudoers.sh and network-pulse-audit.sudoers). "
                    "If you run under systemd with NoNewPrivileges=yes, sudo cannot work; disable that for this unit."
                ),
                "events": [],
            }
        return {
            "ok": False,
            "message": combined_err or "No audit data available.",
            "events": [],
        }

    events = []
    users_seen = set()
    current = {}
    msg_time_re = re.compile(r"msg=audit\(([^)]+)\)")
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("----"):
            if current.get("timestamp") or current.get("user") or current.get("command"):
                events.append(current)
            current = {}
            continue
        if line.startswith("time->"):
            current["timestamp"] = line.replace("time->", "").strip()
            continue
        if "msg=audit(" in line and "timestamp" not in current:
            m = msg_time_re.search(line)
            if m:
                current["timestamp"] = m.group(1)
        if len(line) > AUDIT_PARSE_MAX_LINE_CHARS:
            continue
        if line.startswith("type=EXECVE"):
            continue
        if line.startswith("type=PROCTITLE"):
            # Extract command payload after proctitle=
            marker = "proctitle="
            idx = line.find(marker)
            if idx != -1:
                cmd = line[idx + len(marker) :].strip()
                if len(cmd) > AUDIT_DISPLAY_MAX_COMMAND_CHARS:
                    cmd = cmd[:AUDIT_DISPLAY_MAX_COMMAND_CHARS] + "…"
                current["command"] = cmd
            continue
        if line.startswith("type=SYSCALL"):
            # Capture auid and exe when present.
            for token in line.split():
                if token.startswith("auid=") and "user" not in current:
                    current["auid"] = token.split("=", 1)[1]
                elif token.startswith("uid=") and "uid" not in current:
                    current["uid"] = token.split("=", 1)[1]
                elif token.startswith("exe=") and "exe" not in current:
                    current["exe"] = token.split("=", 1)[1].strip('"')
            continue

    if current.get("timestamp") or current.get("user") or current.get("command"):
        events.append(current)

    normalized = []
    for e in events:
        actor = e.get("auid")
        if actor in (None, "", "unset"):
            actor = e.get("uid", "unknown")
        e["user"] = actor
        if actor not in (None, "", "unset"):
            users_seen.add(actor)
        if not e.get("command") and e.get("exe"):
            e["command"] = os.path.basename(e["exe"])
        normalized.append(e)

    if user_filter:
        normalized = [e for e in normalized if str(e.get("user", "")).lower() == user_filter.lower()]

    normalized = [e for e in normalized if e.get("timestamp") or e.get("command")]
    normalized = list(reversed(normalized))[:max(1, limit)]
    return {
        "ok": True,
        "message": f"Showing {len(normalized)} cmd_exec events since {since}.",
        "users": sorted(users_seen),
        "events": normalized,
    }


@app.route('/')
def index():
    """Main dashboard page"""
    devices, dashboard_section_order = load_device_data()
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    watch_findings = build_watch_correlation_findings()
    local_ip = get_local_ip()
    tailscale_ip = get_tailscale_ip()
    public_ip = get_public_ip()

    return render_template(
        'index.html',
        devices=devices,
        last_updated=last_updated,
        total_devices=len(devices),
        online_count=len([d for d in devices if is_active_status(d.get('status', ''))]),
        watch_findings=watch_findings,
        local_ip=local_ip,
        tailscale_ip=tailscale_ip,
        public_ip=public_ip,
        dashboard_section_order=dashboard_section_order,
    )


@app.route("/api/device-groups", methods=["GET", "PUT"])
def api_device_groups():
    """Load or persist dashboard group layout (device_groups_config.json)."""
    if request.method == "GET":
        return jsonify(load_device_groups_config())
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "expected JSON object"}), 400
    normalized = _normalize_device_groups_config(data)
    ok, err = validate_device_groups_config(normalized)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    try:
        save_device_groups_config(normalized)
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True})


@app.route('/api/devices')
def api_devices():
    """JSON API endpoint for live updates"""
    devices, section_order = load_device_data()
    scan_history = enrich_scan_history_with_state_changes(load_scan_history())
    scan_matrix = build_scan_status_matrix(scan_history)
    connectivity = check_online_status()
    watch_findings = build_watch_correlation_findings()
    active_users = get_active_users()
    local_ip = get_local_ip()
    tailscale_ip = get_tailscale_ip()
    return jsonify({
        "devices": devices,
        "section_order": section_order,
        "scan_history": scan_history,
        "scan_matrix": scan_matrix,
        "watch_findings": watch_findings,
        "active_users": active_users,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(devices),
        "online": len([d for d in devices if is_active_status(d.get('status', ''))]),
        "connectivity": connectivity,
        "public_ip": get_public_ip(),
        "local_ip": local_ip,
        "tailscale_ip": tailscale_ip,
    })


@app.route('/api/device/<ip>')
def api_device_detail(ip):
    """Return full details including event history and deep scan results"""
    devices, _ = load_device_data()
    device = next((d for d in devices if ip in _device_ip_set(d)), None)
    
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    # Add more context from markdown if available
    md_info = parse_markdown_devices()
    rich = md_info.get(ip, {})
    
    # Load deep scan results
    deep_scan_data = {}
    try:
        if os.path.exists(DEEP_SCAN_RESULTS_FILE):
            with open(DEEP_SCAN_RESULTS_FILE, 'r') as f:
                deep_results = json.load(f)
                deep_scan_data = deep_results.get("results", {}).get(ip, {})
    except Exception as e:
        print(f"Warning: Could not load deep scan data: {e}")
    
    # Merge additional details
    extra = {}
    details = list(rich.get("details", [])) if rich.get("details") else []

    # Try live Roku ECP device-info enrichment (fast timeout).
    roku_info = fetch_roku_device_info(ip)
    roku_live_lines = []
    if roku_info:
        extra["roku_device_info"] = roku_info
        roku_live_lines.extend([
            f"Roku Name: {roku_info.get('friendly-device-name', '—')}",
            f"Location: {roku_info.get('user-device-location', '—')}",
            f"Model: {roku_info.get('model-name', '—')} ({roku_info.get('model-number', '—')})",
            f"Software: {roku_info.get('software-version', '—')} build {roku_info.get('software-build', '—')}",
            f"Network: {roku_info.get('network-name', '—')}",
            f"Power Mode: {roku_info.get('power-mode', '—')}",
            f"ECP Mode: {roku_info.get('ecp-setting-mode', '—')}",
            f"AirPlay Support: {roku_info.get('supports-airplay', '—')}",
            f"Developer Mode Enabled: {roku_info.get('developer-enabled', '—')}",
            f"Uptime (seconds): {roku_info.get('uptime', '—')}",
        ])

    # Add best-effort "what's playing" context from Roku active app data.
    roku_playback = fetch_roku_playback_info(ip)
    if roku_playback:
        extra["roku_playback"] = roku_playback
        playback_lines = []
        active_name = roku_playback.get("active_app_name")
        active_type = roku_playback.get("active_app_type")
        active_ui = roku_playback.get("active_app_ui_location")
        if active_name:
            playback_lines.append(
                f"Now Playing (Active App): {active_name}"
                f"{f' [{active_type}]' if active_type else ''}"
                f"{f' @ {active_ui}' if active_ui else ''}"
            )
        screensaver_name = roku_playback.get("screensaver_name")
        if screensaver_name:
            playback_lines.append(f"Screensaver: {screensaver_name}")
        if roku_playback.get("media_player_access") == "limited_mode_blocked":
            playback_lines.append("Playback metadata endpoint (/query/media-player) blocked in Roku Limited mode.")
        roku_live_lines.extend(playback_lines)

    # Normalize Roku detail formatting across devices while keeping data live.
    if roku_live_lines:
        details = roku_live_lines

    if details:
        extra["details"] = details
    if rich.get("details"):
        extra["details"] = details
    if rich.get("access") and ip != "192.168.0.192":
        extra["access_methods"] = rich["access"]
    if rich.get("source"):
        extra["source"] = rich["source"]
    
    response_access_methods = "See device documentation"
    if ip != "192.168.0.192":
        response_access_methods = rich.get("access", "See device documentation")

    return jsonify({
        "device": device,
        "rich_info": rich,
        "history": device.get("events", []),
        "per_ip_status": device.get("per_ip_status", []),
        "ip_addresses": device.get("ip_addresses", [device.get("ip")]),
        "ip_display": device.get("ip_display", device.get("ip")),
        "deep_scan": deep_scan_data,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ports": rich.get("ports", device.get("ports", "—")),
        "access_methods": response_access_methods,
        "mac": device.get("mac", "—"),
        "manufacturer": device.get("manufacturer", "—"),
        **extra
    })


@app.route('/api/audit')
def api_audit():
    """Return recent Linux audit cmd_exec activity."""
    since = request.args.get("since", "today")
    user_filter = request.args.get("user", "").strip()
    return jsonify(get_audit_activity(since=since, user_filter=user_filter))


@app.route('/api/wifi/ssids')
def api_wifi_ssids():
    """Return nearby WiFi SSIDs from a privileged helper command."""
    try:
        limit = int(request.args.get("limit", "80"))
    except Exception:
        limit = 80
    limit = max(1, min(limit, 200))
    return jsonify(get_wifi_ssids(limit=limit))


@app.route('/api/trace')
def api_trace():
    """Start/stop/status/summary for ingress/egress network tracing."""
    action = request.args.get("action", "summary")
    try:
        minutes = int(request.args.get("minutes", "15"))
    except Exception:
        minutes = 15
    minutes = max(1, min(minutes, 240))
    return jsonify(get_network_trace(action=action, minutes=minutes))


@app.route('/api/scan/<path:scan_time>/online')
def api_scan_online_devices(scan_time):
    """Return inferred online devices for a selected scan timestamp."""
    devices = infer_online_devices_for_scan(scan_time)
    return jsonify({
        "scan_time": scan_time,
        "online_devices": devices,
        "count": len(devices),
    })


@app.route('/api/cron')
def api_cron_status():
    """Return scheduled scan cron job status and recent log tails."""
    return jsonify(get_jobs_status())


@app.route('/api/cron/<job_id>', methods=['POST'])
def api_cron_update(job_id):
    """Enable/disable a cron job or update its schedule."""
    job_id = (job_id or "").strip().lower()
    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or request.args.get("action") or "").strip().lower()

    try:
        from cron_control import CRON_JOBS
        if job_id not in CRON_JOBS:
            return jsonify({"ok": False, "message": f"Unknown job: {job_id}"}), 404
    except Exception:
        pass

    if action == "run":
        ok, message, pid = run_job_now(job_id)
        return jsonify({
            "ok": ok,
            "message": message,
            "pid": pid,
            **get_jobs_status(),
        }), (200 if ok else 409)

    if action == "enable":
        schedule = (payload.get("schedule") or "").strip() or None
        ok, message = set_job_enabled(job_id, True, schedule=schedule)
        return jsonify({"ok": ok, "message": message, **get_jobs_status()}), (200 if ok else 400)

    if action == "disable":
        ok, message = set_job_enabled(job_id, False)
        return jsonify({"ok": ok, "message": message, **get_jobs_status()}), (200 if ok else 400)

    schedule = (payload.get("schedule") or "").strip()
    if schedule:
        ok, message = set_job_schedule(job_id, schedule)
        return jsonify({"ok": ok, "message": message, **get_jobs_status()}), (200 if ok else 400)

    return jsonify({
        "ok": False,
        "message": "Unknown action. Use run, enable, disable, or provide schedule.",
    }), 400


@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """Trigger a network scan"""
    try:
        result = subprocess.run(
            ['python3', SCAN_SCRIPT], 
            capture_output=True, 
            text=True, 
            cwd=str(BASE_DIR),
            timeout=int(os.environ.get("NETWORK_SCAN_TIMEOUT_SEC", "300")),
        )
        success = result.returncode == 0
        return jsonify({
            "success": success,
            "message": "Network scan completed successfully!" if success else "Scan completed with warnings.",
            "output": result.stdout[-500:] if result.stdout else "No output",
            "error": result.stderr[-300:] if result.stderr else None
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Scan timed out (configure NETWORK_SCAN_TIMEOUT_SEC if needed)."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


def _start_adhoc_https_listener(flask_app: Flask) -> None:
    """
    Serve the same app over HTTPS with a fresh self-signed cert (Werkzeug adhoc).
    Helps browsers that upgrade http:// to https:// on custom IPs. Disable by setting
    NETWORK_PULSE_ADHOC_TLS_PORT=0 (or empty).
    """
    raw = os.environ.get("NETWORK_PULSE_ADHOC_TLS_PORT", "5443").strip()
    if raw in ("", "0", "false", "no", "off"):
        return
    try:
        tls_port = int(raw)
    except ValueError:
        print(f"NETWORK_PULSE_ADHOC_TLS_PORT invalid: {raw!r}")
        return
    bind_host = os.environ.get("NETWORK_PULSE_BIND_ADDR", "0.0.0.0").strip() or "0.0.0.0"

    def runner():
        try:
            from werkzeug.serving import run_simple

            run_simple(
                bind_host,
                tls_port,
                flask_app,
                threaded=True,
                ssl_context="adhoc",
                use_reloader=False,
                use_debugger=False,
            )
        except OSError as e:
            print(f"Adhoc HTTPS could not bind {bind_host}:{tls_port}: {e}")
        except Exception as e:
            print(f"Adhoc HTTPS server error: {e}")

    threading.Thread(target=runner, daemon=True, name="network-pulse-adhoc-tls").start()


if __name__ == '__main__':
    # Create directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    bind_host = os.environ.get("NETWORK_PULSE_BIND_ADDR", "0.0.0.0").strip() or "0.0.0.0"
    try:
        bind_port = int(os.environ.get("NETWORK_PULSE_PORT", "5000"))
    except ValueError:
        bind_port = 5000
    # Debug/reloader breaks a stable second listener on 5443; default off so LAN + HTTPS work reliably.
    debug_mode = os.environ.get("NETWORK_PULSE_DEBUG", "0").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    print(f"Network Dashboard listening on http://{bind_host}:{bind_port}")
    if bind_host not in ("0.0.0.0", "::", "::0"):
        print(
            "Tip: set NETWORK_PULSE_BIND_ADDR=0.0.0.0 to listen on LAN and Tailscale at once."
        )
    print(f"Audit helper command (effective): {resolve_audit_helper_cmd('today')}")
    print("Reachability (HTTP):")
    print_dashboard_listen_hints(bind_port, scheme="http")
    raw_tls = os.environ.get("NETWORK_PULSE_ADHOC_TLS_PORT", "5443").strip()
    if raw_tls not in ("", "0", "false", "no", "off") and not debug_mode:
        try:
            tls_hint = int(raw_tls)
        except ValueError:
            tls_hint = None
        if tls_hint:
            print("HTTPS (self-signed, same UI as HTTP):")
            print_dashboard_listen_hints(tls_hint, scheme="https")
    print("Browsers that force HTTPS-only should use the HTTPS URL above or disable HTTPS-only for this LAN.")
    print("Firewall (UFW): sudo dashboard/bin/open_firewall_for_pulse.sh — opens LAN + Tailscale to this port.")
    if debug_mode:
        print("NETWORK_PULSE_DEBUG is on (hot reload). Adhoc HTTPS on 5443 is disabled — use DEBUG=0 for TLS.")
    else:
        _start_adhoc_https_listener(app)
    app.run(host=bind_host, port=bind_port, debug=debug_mode)
