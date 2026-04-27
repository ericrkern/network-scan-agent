#!/usr/bin/env python3
"""
Network Dashboard - Live Device Status Monitor
Built for the Jetson Network Scanner
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

from flask import Flask, render_template, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='static', template_folder='templates')

DEVICES_FILE = "/home/jetson/Documents/Network/devices.md"
CACHE_FILE = "/home/jetson/Documents/Network/.seen_devices.json"
SCAN_SNAPSHOTS_FILE = "/home/jetson/Documents/Network/.scan_snapshots.json"
SCAN_SCRIPT = "/home/jetson/Documents/Network/network_scan_agent.py"
LAN_LABELS_FILE = os.environ.get("LAN_LABELS_FILE", "/home/jetson/.config/lan-labels")
KNOWN_HOSTNAME_OVERRIDES = {
    "192.168.0.98": "Irene's Watch",
    "192.168.50.3": "Irene's Watch",
    "192.168.0.81": "Friends Watch",
}
KNOWN_MAC_OVERRIDES = {
    "192.168.0.98": "4e:0a:ec:36:fd:82",
    "192.168.0.81": "fa:5b:a6:ab:1a:7f",
}


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


def choose_device_name(ip: str, *candidates):
    """Pick best display name: real hostname -> configured label -> IP."""
    for value in candidates:
        if value in (None, "", "—", "None"):
            continue
        if value == ip:
            continue
        return value

    labels = load_ip_labels()
    label = labels.get(ip)
    if label not in (None, "", "—", "None"):
        return label
    return ip


def is_active_status(status: str) -> bool:
    """Only treat explicitly online devices as active."""
    return status == "Online"


def normalize_mac(mac: str) -> str:
    """Normalize MAC for grouping; return empty string when unavailable."""
    if mac in (None, "", "—", "None"):
        return ""
    return str(mac).strip().lower().replace("-", ":")


def collapse_duplicate_devices(devices):
    """
    Collapse duplicate logical devices so UI shows one card even with multiple IPs.
    Priority:
      1) Same normalized MAC across multiple IPs
      2) Correlated iPhone pair (192.168.0.49 + 192.168.50.106)
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
        if len(ips) > 1:
            groups.append(ips)
            grouped_ips.update(ips)

    # Correlate the known iPhone pair when both records exist.
    iphone_pair = ["192.168.0.49", "192.168.50.106"]
    if all(ip in by_ip for ip in iphone_pair):
        if not all(ip in grouped_ips for ip in iphone_pair):
            hostnames = [str(by_ip[ip].get("hostname", "")).strip().lower() for ip in iphone_pair]
            if hostnames[0] and hostnames[0] == hostnames[1]:
                groups.append(iphone_pair)
                grouped_ips.update(iphone_pair)

    # User-confirmed watch aliases across subnets.
    watch_pair = ["192.168.0.98", "192.168.50.3"]
    if all(ip in by_ip for ip in watch_pair):
        if not all(ip in grouped_ips for ip in watch_pair):
            groups.append(watch_pair)
            grouped_ips.update(watch_pair)

    merged_devices = []
    for ips in groups:
        members = [by_ip[ip] for ip in ips if ip in by_ip]
        if not members:
            continue

        online_members = [m for m in members if m.get("status") == "Online"]
        primary = online_members[0] if online_members else members[0]

        status = "Online" if online_members else ("Offline" if all(m.get("status") == "Offline" for m in members) else "Unknown")
        status_color = "emerald" if status == "Online" else ("red" if status == "Offline" else "amber")

        ip_addresses = sorted({m.get("ip") for m in members if m.get("ip")})
        per_ip_status = []
        for m in sorted(members, key=lambda item: item.get("ip", "")):
            per_ip_status.append({
                "ip": m.get("ip"),
                "status": m.get("status", "Unknown"),
                "last_seen": m.get("last_seen", "—"),
                "last_status_time": m.get("last_status_time", m.get("last_seen", "—")),
                "subnet_group": m.get("subnet_group", "Other Networks"),
            })

        member_labels = [m.get("label") for m in members if m.get("label") not in (None, "", "—", "None")]
        merged = dict(primary)
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
        if member_labels:
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


def load_device_data():
    """Load and enrich device data from cache + rich markdown details"""
    devices = []
    md_info = parse_markdown_devices()
    labels = load_ip_labels()

    def get_subnet_group(ip: str) -> str:
        if ip == "24.192.17.178":
            return "External/Public Internet"
        if ip.startswith("192.168.0."):
            return "Local LAN (192.168.0.0/24)"
        if ip.startswith("192.168.50."):
            return "Adjacent Subnet (192.168.50.0/24)"
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
                status = data.get("last_status", "unknown")
                last_seen = data.get("last_seen", "—")
                cache_hostname = data.get("hostname", "—")
                
                # Get rich info from markdown if available
                rich = md_info.get(ip, {})
                
                rich_hostname = rich.get("hostname")
                hostname = choose_device_name(ip, rich_hostname, cache_hostname, labels.get(ip))
                if ip in KNOWN_HOSTNAME_OVERRIDES and hostname in (None, "", "—", ip):
                    hostname = KNOWN_HOSTNAME_OVERRIDES[ip]
                
                rich_identity = rich.get("identity")
                identity = rich_identity if rich_identity not in ["Unknown Device", "Unknown", "—", "None", None, ""] else data.get("type", "Unknown Device")
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
                    "label": labels.get(ip, ""),
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
                    "last_status_time": data.get("last_status_time", last_seen)
                })
    except Exception as e:
        print(f"Error loading cache: {e}")
    
    # Sort by subnet group first, then status/name
    subnet_order = {
        "Local LAN (192.168.0.0/24)": 0,
        "Adjacent Subnet (192.168.50.0/24)": 1,
        "Adjacent Subnet (192.168.100.0/24)": 2,
        "Docker Network (172.17.0.0/16)": 3,
        "Other Networks": 4,
        "Tailscale Mesh VPN": 5,
        "External/Public Internet": 6,
    }

    def status_priority(d):
        if d["status"] == "Online": return 0
        if d["status"] == "Unknown": return 1
        if d["status"] == "Offline": return 2
        return 3

    def name_priority(d):
        """Put devices with real hostnames before those that only show IP"""
        hostname = d.get("hostname", "")
        # If hostname is just an IP address or very generic, treat it as "no name"
        if not hostname or hostname == d.get("ip", "") or hostname.startswith("192.168.") or hostname.startswith("100.") or hostname.startswith("172."):
            return 1  # no-name devices at bottom
        return 0  # named devices first

    devices = collapse_duplicate_devices(devices)

    devices.sort(
        key=lambda x: (
            subnet_order.get(x.get("subnet_group", "Other Networks"), 99),
            status_priority(x),
            name_priority(x),
            x.get("hostname", "").lower()
        )
    )
    return devices


def build_watch_correlation_findings():
    """Build concise watch-correlation findings for dashboard display."""
    watches = [
        {
            "ip": "192.168.0.98 (alias: 192.168.50.3)",
            "hostname": "Irene's Watch",
            "mac": "4e:0a:ec:36:fd:82",
            "discovered": "Merged alias across subnets",
        },
        {
            "ip": "192.168.0.81",
            "hostname": "Friends Watch",
            "mac": "fa:5b:a6:ab:1a:7f",
            "discovered": "2026-04-21 20:59:09",
        },
    ]

    conclusion = (
        "Dashboard now treats 192.168.0.98 and 192.168.50.3 as one logical device "
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
    """Fetch current public/WAN egress IP for dashboard header."""
    urls = [
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetworkPulse/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                ip = resp.read().decode("utf-8").strip()
            if ip:
                return ip
        except Exception:
            continue
    return "Unavailable"


@app.route('/')
def index():
    """Main dashboard page"""
    devices = load_device_data()
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    watch_findings = build_watch_correlation_findings()
    
    return render_template('index.html', 
                         devices=devices, 
                         last_updated=last_updated,
                         total_devices=len(devices),
                         online_count=len([d for d in devices if is_active_status(d.get('status', ''))]),
                         watch_findings=watch_findings)


@app.route('/api/devices')
def api_devices():
    """JSON API endpoint for live updates"""
    devices = load_device_data()
    scan_history = enrich_scan_history_with_state_changes(load_scan_history())
    connectivity = check_online_status()
    watch_findings = build_watch_correlation_findings()
    return jsonify({
        "devices": devices,
        "scan_history": scan_history,
        "watch_findings": watch_findings,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(devices),
        "online": len([d for d in devices if is_active_status(d.get('status', ''))]),
        "connectivity": connectivity,
        "public_ip": get_public_ip(),
    })


@app.route('/api/device/<ip>')
def api_device_detail(ip):
    """Return full details including event history and deep scan results"""
    devices = load_device_data()
    device = next((d for d in devices if d['ip'] == ip), None)
    
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    # Add more context from markdown if available
    md_info = parse_markdown_devices()
    rich = md_info.get(ip, {})
    
    # Load deep scan results
    deep_scan_data = {}
    try:
        deep_file = "/home/jetson/Documents/Network/deep_scan_results.json"
        if os.path.exists(deep_file):
            with open(deep_file, 'r') as f:
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


@app.route('/api/scan/<path:scan_time>/online')
def api_scan_online_devices(scan_time):
    """Return inferred online devices for a selected scan timestamp."""
    devices = infer_online_devices_for_scan(scan_time)
    return jsonify({
        "scan_time": scan_time,
        "online_devices": devices,
        "count": len(devices),
    })


@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """Trigger a network scan"""
    try:
        result = subprocess.run(
            ['python3', SCAN_SCRIPT], 
            capture_output=True, 
            text=True, 
            cwd="/home/jetson/Documents/Network",
            timeout=60
        )
        success = result.returncode == 0
        return jsonify({
            "success": success,
            "message": "Network scan completed successfully!" if success else "Scan completed with warnings.",
            "output": result.stdout[-500:] if result.stdout else "No output",
            "error": result.stderr[-300:] if result.stderr else None
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Scan timed out after 60 seconds."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


if __name__ == '__main__':
    # Create directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    print("Network Dashboard starting on http://0.0.0.0:5000")
    print("Accessible via:")
    print(" - Local: http://192.168.0.197:5000")
    print(" - Tailscale: http://100.70.174.39:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
