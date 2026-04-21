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

from flask import Flask, render_template, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='static', template_folder='templates')

DEVICES_FILE = "/home/jetson/Documents/Network/devices.md"
CACHE_FILE = "/home/jetson/Documents/Network/.seen_devices.json"
SCAN_SCRIPT = "/home/jetson/Documents/Network/network_scan_agent.py"


def parse_markdown_devices():
    """Parse rich device information from devices.md including tables and Access Details section"""
    device_info = {}
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
                        
                        for j, cell in enumerate(row_cells):
                            if j < len(headers):
                                header = headers[j].lower()
                                if any(x in header for x in ['ip', 'address']):
                                    ip = cell.strip()
                                elif 'hostname' in header and cell.strip() not in ['—', '', 'None']:
                                    hostname = cell.strip()
                                elif any(x in header for x in ['identity', 'device']):
                                    identity = cell.replace('**', '').replace('*', '').strip()
                                elif 'mac' in header and cell.strip() not in ['—', '', 'None']:
                                    mac = cell.strip()
                                elif any(x in header for x in ['port', 'ports']):
                                    ports = cell.strip()
                                elif any(x in header for x in ['access', 'method']):
                                    access = cell.strip()
                        
                        if ip:
                            device_info[ip] = {
                                "hostname": hostname,
                                "identity": identity,
                                "mac": mac,
                                "ports": ports,
                                "access": access,
                                "source": "table"
                            }
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


def infer_online_devices_for_scan(scan_time_str: str):
    """Best-effort reconstruction of which devices were online at a given scan time."""
    try:
        scan_time = datetime.strptime(scan_time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return []

    online_devices = []
    md_info = parse_markdown_devices()

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
            hostname = rich.get("hostname", record.get("hostname", "—"))
            if hostname in ("—", "", None):
                hostname = ip
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

    # Cache online-device sets per scan time
    online_by_scan = {}
    for row in scan_history_rows:
        scan_time = row.get("scan_time", "")
        online_list = infer_online_devices_for_scan(scan_time)
        online_by_scan[scan_time] = {d["ip"]: d for d in online_list}

    enriched = []
    for idx, row in enumerate(scan_history_rows):
        current_time = row.get("scan_time", "")
        current_map = online_by_scan.get(current_time, {})

        if idx + 1 < len(scan_history_rows):
            prev_time = scan_history_rows[idx + 1].get("scan_time", "")
            prev_map = online_by_scan.get(prev_time, {})
        else:
            prev_map = {}

        came_online_ips = sorted(set(current_map.keys()) - set(prev_map.keys()))
        went_offline_ips = sorted(set(prev_map.keys()) - set(current_map.keys()))

        came_online = [current_map[ip].get("hostname", ip) for ip in came_online_ips]
        went_offline = [prev_map[ip].get("hostname", ip) for ip in went_offline_ips]

        row_copy = dict(row)
        row_copy["state_changes"] = {
            "online": came_online,
            "offline": went_offline,
            "online_count": len(came_online),
            "offline_count": len(went_offline),
        }
        enriched.append(row_copy)

    return enriched


def load_device_data():
    """Load and enrich device data from cache + rich markdown details"""
    devices = []
    md_info = parse_markdown_devices()

    def get_subnet_group(ip: str) -> str:
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
                
                hostname = rich.get("hostname") or cache_hostname
                if hostname in ["—", None, ""]:
                    hostname = ip
                
                identity = rich.get("identity", data.get("type", "Unknown Device"))
                mac = rich.get("mac", data.get("mac", "—"))
                ports = rich.get("ports", "—")
                
                # Determine visual status
                if status == "online" or "online" in str(identity).lower():
                    status_color = "emerald"
                    status_text = "Online"
                elif status == "offline":
                    status_color = "red"
                    status_text = "Offline"
                elif "stealth" in str(identity).lower():
                    status_color = "amber"
                    status_text = "Stealth"
                else:
                    status_color = "amber"
                    status_text = "Unknown"
                
                devices.append({
                    "ip": ip,
                    "hostname": hostname,
                    "identity": identity,
                    "subnet_group": get_subnet_group(ip),
                    "status": status_text,
                    "status_color": status_color,
                    "last_seen": last_seen,
                    "type": identity.split('/')[0].strip() if '/' in identity else identity,
                    "mac": mac,
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
    }

    def status_priority(d):
        if d["status"] == "Online": return 0
        if d["status"] == "Stealth": return 1
        if d["status"] == "Offline": return 3
        return 2

    def name_priority(d):
        """Put devices with real hostnames before those that only show IP"""
        hostname = d.get("hostname", "")
        # If hostname is just an IP address or very generic, treat it as "no name"
        if not hostname or hostname == d.get("ip", "") or hostname.startswith("192.168.") or hostname.startswith("100.") or hostname.startswith("172."):
            return 1  # no-name devices at bottom
        return 0  # named devices first

    devices.sort(
        key=lambda x: (
            subnet_order.get(x.get("subnet_group", "Other Networks"), 99),
            status_priority(x),
            name_priority(x),
            x.get("hostname", "").lower()
        )
    )
    return devices


@app.route('/')
def index():
    """Main dashboard page"""
    devices = load_device_data()
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return render_template('index.html', 
                         devices=devices, 
                         last_updated=last_updated,
                         total_devices=len(devices),
                         online_count=len([d for d in devices if d['status'] == 'Online']))


@app.route('/api/devices')
def api_devices():
    """JSON API endpoint for live updates"""
    devices = load_device_data()
    scan_history = enrich_scan_history_with_state_changes(load_scan_history())
    return jsonify({
        "devices": devices,
        "scan_history": scan_history,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(devices),
        "online": len([d for d in devices if d['status'] == 'Online'])
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
    if rich.get("details"):
        extra["details"] = rich["details"]
    if rich.get("access"):
        extra["access_methods"] = rich["access"]
    if rich.get("source"):
        extra["source"] = rich["source"]
    
    return jsonify({
        "device": device,
        "rich_info": rich,
        "history": device.get("events", []),
        "deep_scan": deep_scan_data,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ports": rich.get("ports", device.get("ports", "—")),
        "access_methods": rich.get("access", "See device documentation"),
        "mac": device.get("mac", "—"),
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
