#!/usr/bin/env python3
"""Classify all cached devices and write type + identity summary for the dashboard."""

from __future__ import annotations

import concurrent.futures
import json
import re
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_FILE = BASE_DIR / ".seen_devices.json"
DEEP_RESULTS_FILE = BASE_DIR / "deep_scan_results.json"
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Common vendor OUIs for short hints in identity text.
OUI_VENDORS = {
    "20:6e:f1": "Espressif (ESP32-class)",
    "9c:c7:d3": "HP Inc",
    "fa:5b:a6": "Apple (private MAC)",
    "4e:0a:ec": "Apple (private MAC)",
    "00:50:56": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
}


def _import_scan_helpers():
    sys.path.insert(0, str(BASE_DIR))
    from network_scan_agent import (  # noqa: WPS433
        COMMON_PORTS,
        infer_device_type_from_ports,
        scan_ports,
    )

    return COMMON_PORTS, infer_device_type_from_ports, scan_ports


def normalize_ports(value) -> list[int]:
    if isinstance(value, list):
        out = []
        for item in value:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return sorted(set(out))
    if isinstance(value, str) and value not in ("", "—", "None"):
        parts = re.split(r"[,\s]+", value)
        out = []
        for part in parts:
            try:
                out.append(int(part))
            except ValueError:
                continue
        return sorted(set(out))
    return []


def hostname_stem(hostname: str, ip: str) -> str:
    host = (hostname or "").strip()
    if not host or host == ip or IPV4_RE.match(host):
        return ""
    host = host.split(".")[0]
    return host.lower()


def classify_from_hostname(hostname: str, ip: str) -> tuple[str, list[str]]:
    """Return (device_type, evidence_strings)."""
    host = (hostname or "").lower()
    stem = hostname_stem(hostname, ip)
    evidence: list[str] = []

    if ip.startswith("100.") or ".ts.net" in host:
        if any(x in host for x in ("iphone", "ipad")):
            return "Mobile Phone", ["Tailscale peer", "Apple mobile naming"]
        if "macbook" in host:
            return "Laptop", ["Tailscale peer", "MacBook naming"]
        if any(x in host for x in ("watch",)):
            return "Wearable", ["Tailscale peer", "watch naming"]
        if any(x in host for x in ("android", "motorola", "samsung", "pixel", "phone")):
            return "Mobile Phone", ["Tailscale peer", "mobile naming"]
        if any(x in host for x in ("roku", "chromecast", "firetv", "appletv")):
            return "Streaming Device", ["Tailscale peer", "streaming naming"]
        if any(x in host for x in ("printer", "ipp", "hp-", "epson", "canon")):
            return "Printer", ["Tailscale peer", "printer naming"]
        if any(x in host for x in ("proxmox", "pve", "esxi", "hyperv")):
            return "Hypervisor", ["Tailscale peer", "virtualization naming"]
        if any(x in host for x in ("jetson", "raspberry", "pi-", "arduino")):
            return "Edge / SBC", ["Tailscale peer", "SBC naming"]
        if any(x in host for x in ("server", "nas", "synology", "qnap")):
            return "Server", ["Tailscale peer", "server naming"]
        if stem in ("zerothguard", "borgson", "wintermute", "bender", "castor", "prime"):
            return "Workstation / Server", ["Tailscale peer", f"host '{stem}'"]
        return "Tailscale Peer", ["Tailscale mesh (100.x)"]

    if host.endswith(".mg8702") or ".mg8702" in host:
        evidence.append("Router local DNS (.MG8702)")
        if host.startswith("desktop-") or "desktop" in host:
            return "Windows PC", evidence + ["Windows desktop naming"]
        if any(x in host for x in ("motorola", "samsung", "iphone", "ipad", "pixel", "android")):
            return "Mobile Phone", evidence + ["mobile device naming"]
        if host in ("home.mg8702", "home"):
            return "Router / Gateway", evidence + ["gateway hostname"]
        if any(x in host for x in ("printer", "hp-", "epson")):
            return "Printer", evidence + ["printer naming"]
        if "zerothguard" in host:
            return "Linux Server", evidence + ["server naming"]
        if host.startswith("inunziata"):
            return "Smart Home / IoT", evidence + ["IoT-style hostname"]
        return "LAN Device", evidence

    if any(x in host for x in ("esp32", "esp8266", "espressif")):
        return "IoT / Microcontroller", ["ESP naming"]
    if "roku" in host:
        return "Streaming Device", ["Roku naming"]
    if any(x in host for x in ("iphone", "ipad", "android", "watch")):
        return "Mobile Phone", ["mobile naming"]
    if any(x in host for x in ("printer", "ipp", "cups")):
        return "Printer", ["printer naming"]
    if any(x in host for x in ("router", "gateway", "ap-", "wifi")):
        return "Router / Gateway", ["router naming"]
    if any(x in host for x in ("nas", "synology", "qnap")):
        return "NAS", ["NAS naming"]
    if any(x in host for x in ("cam", "camera", "ring", "nest")):
        return "Camera / Smart Home", ["camera naming"]

    if ip.endswith(".1"):
        return "Router / Gateway", ["typical gateway address (.1)"]

    return "", evidence


def classify_from_mac(mac: str) -> tuple[str, list[str]]:
    normalized = (mac or "").strip().lower().replace("-", ":")
    if not normalized or normalized == "—":
        return "", []
    prefix = normalized[:8]
    vendor = OUI_VENDORS.get(prefix)
    if not vendor:
        return "", []
    if "espressif" in vendor.lower():
        return "IoT / Microcontroller", [f"MAC vendor {vendor}"]
    if "apple" in vendor.lower():
        return "Mobile / Apple Device", [f"MAC vendor {vendor}"]
    if "raspberry" in vendor.lower():
        return "Edge / SBC", [f"MAC vendor {vendor}"]
    return "", [f"MAC vendor {vendor}"]


def classify_from_ports(hostname: str, ports: list[int], infer_fn) -> tuple[str, list[str]]:
    if not ports:
        return "", []
    device_type = infer_fn(hostname or "", ports)
    if device_type == "Unknown":
        return "", []
    port_txt = ", ".join(str(p) for p in ports[:8])
    if len(ports) > 8:
        port_txt += f" (+{len(ports) - 8})"
    return device_type, [f"open ports {port_txt}"]


def merge_type(*candidates: str) -> str:
    for value in candidates:
        if value and value != "Unknown":
            return value
    return "Unknown"


def build_identity_summary(device_type: str, hostname: str, ip: str, evidence: list[str]) -> str:
    if device_type == "Unknown" or not device_type:
        if hostname and hostname != ip and not IPV4_RE.match(hostname):
            return f"Unknown device — hostname {hostname}"
        return "Unknown device — no classification signals yet"

    unique_evidence: list[str] = []
    seen = set()
    for item in evidence:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_evidence.append(item)

    if unique_evidence:
        return f"{device_type} — {' · '.join(unique_evidence[:3])}"
    return device_type


def classify_record(
    ip: str,
    record: dict,
    deep_row: dict | None,
    infer_fn,
    scan_ports_fn,
    common_ports: list[int],
    probe_online: bool,
) -> tuple[str, str]:
    hostname = str(record.get("hostname") or ip)
    mac = str(record.get("mac") or "—")

    ports = normalize_ports(record.get("ports"))
    if deep_row:
        ports = sorted(set(ports + normalize_ports(deep_row.get("tcp_ports")) + normalize_ports(deep_row.get("ports"))))

    if probe_online and record.get("last_status") == "online" and len(ports) < 2:
        try:
            ports = sorted(set(ports + (scan_ports_fn(ip, common_ports) or [])))
            record["ports"] = ports
        except Exception:
            pass

    type_host, ev_host = classify_from_hostname(hostname, ip)
    type_mac, ev_mac = classify_from_mac(mac)
    type_ports, ev_ports = classify_from_ports(hostname, ports, infer_fn)

    deep_os = ""
    if deep_row and deep_row.get("os") not in (None, "", "Unknown"):
        deep_os = str(deep_row.get("os")).strip()
    elif record.get("deep_os") not in (None, "", "Unknown"):
        deep_os = str(record.get("deep_os")).strip()

    device_type = merge_type(type_ports, type_host, type_mac)
    evidence = ev_ports + ev_host + ev_mac
    if deep_os:
        evidence.append(f"OS hint {deep_os[:80]}")

    identity = build_identity_summary(device_type, hostname, ip, evidence)
    return device_type, identity


def main() -> int:
    if not CACHE_FILE.is_file():
        print(f"Cache not found: {CACHE_FILE}", file=sys.stderr)
        return 1

    common_ports, infer_fn, scan_ports_fn = _import_scan_helpers()
    cache = json.loads(CACHE_FILE.read_text())
    deep_map: dict = {}
    if DEEP_RESULTS_FILE.is_file():
        payload = json.loads(DEEP_RESULTS_FILE.read_text())
        deep_map = payload.get("results") if isinstance(payload, dict) else {}
        if not isinstance(deep_map, dict):
            deep_map = {}

    online_count = sum(1 for r in cache.values() if r.get("last_status") == "online")
    print(f"Classifying {len(cache)} devices ({online_count} online, probing open ports on online hosts)...")

    changed = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    type_counts: dict[str, int] = {}

    for ip, record in cache.items():
        if not isinstance(record, dict):
            continue
        deep_row = deep_map.get(ip) if isinstance(deep_map.get(ip), dict) else {}
        device_type, identity = classify_record(
            ip,
            record,
            deep_row,
            infer_fn,
            scan_ports_fn,
            common_ports,
            probe_online=True,
        )
        old_type = record.get("type", "Unknown")
        old_identity = record.get("identity", "")
        record["type"] = device_type
        record["identity"] = identity
        record["identity_classified_at"] = now
        type_counts[device_type] = type_counts.get(device_type, 0) + 1
        if old_type != device_type or old_identity != identity:
            changed += 1

    CACHE_FILE.write_text(json.dumps(cache, indent=2) + "\n")
    print(f"Updated {changed} records.")
    print("Type breakdown:")
    for name, count in sorted(type_counts.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {name}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
