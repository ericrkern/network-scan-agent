#!/usr/bin/env python3
"""
Network Device Discovery Agent
Scans network for new devices every hour and updates devices.md
"""

import subprocess
import re
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import concurrent.futures
import importlib.util

# Configuration
DEVICES_FILE = "/home/jetson/Documents/Network/devices.md"
SEEN_DEVICES_CACHE = "/home/jetson/Documents/Network/.seen_devices.json"
SCAN_SNAPSHOTS_FILE = "/home/jetson/Documents/Network/.scan_snapshots.json"
NETWORKS = ["192.168.0.0/24", "192.168.50.0/24", "192.168.100.0/24"]
COMMON_PORTS = [22, 80, 443, 445, 631, 8080, 5900, 3000, 5000]
SCAN_TIMEOUT = 2
DEEP_SCAN_SCRIPT = "/home/jetson/Documents/Network/deep_scan.py"
DEEP_SCAN_RESULTS_FILE = "/home/jetson/Documents/Network/deep_scan_results.json"


def human_duration_since(first_seen_str: str) -> str:
    """Convert first_seen timestamp to human readable duration (e.g. '3 days, 14 hrs')"""
    try:
        first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        delta = now - first_seen

        days = delta.days
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60

        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    except:
        return "—"


def record_event(device_record, event_type: str, reason: str = "scan"):
    """Record an online/offline event for a device (keep last 15 events)"""
    if "events" not in device_record:
        device_record["events"] = []
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    device_record["events"].append({
        "timestamp": timestamp,
        "event": event_type,  # "online" or "offline"
        "reason": reason
    })
    
    # Keep only the most recent 15 events
    if len(device_record["events"]) > 15:
        device_record["events"] = device_record["events"][-15:]
    
    device_record["last_status"] = event_type
    device_record["last_status_time"] = timestamp
    return device_record


def format_first_seen(first_seen_str: str) -> str:
    """Format first seen timestamp for display"""
    try:
        dt = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d")
    except:
        return first_seen_str


def load_device_records():
    """Load persistent device records with first_seen timestamps and event history"""
    try:
        if os.path.exists(SEEN_DEVICES_CACHE):
            with open(SEEN_DEVICES_CACHE, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Migrate old simple list format to new dict format
                    print("   Migrating legacy cache to new format...")
                    records = {}
                    for ip in data:
                        records[ip] = {
                            "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "hostname": "—",
                            "mac": "—",
                            "type": "Unknown",
                            "events": [],
                            "last_status": "online",
                            "last_status_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                    return records
                # Ensure all records have events and status fields (migration)
                for ip, record in data.items():
                    if "events" not in record:
                        record["events"] = []
                    if "last_status" not in record:
                        record["last_status"] = "online"
                    if "last_status_time" not in record:
                        record["last_status_time"] = record.get("last_seen", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                return data
    except Exception as e:
        print(f"Warning: Could not load device records: {e}")
    return {}


def load_seen_ips(records):
    """Extract just the IP set for backward compatibility"""
    return set(records.keys())


def save_device_records(records):
    """Save rich device records with timestamps"""
    try:
        with open(SEEN_DEVICES_CACHE, 'w') as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save device records: {e}")


def save_seen_devices(seen_devices):
    """Save cache of seen devices"""
    try:
        with open(SEEN_DEVICES_CACHE, 'w') as f:
            json.dump(list(seen_devices), f)
    except Exception as e:
        print(f"Warning: Could not save seen devices cache: {e}")


def save_scan_snapshot(scan_time: str, online_ips, device_records):
    """Persist an exact per-scan online snapshot for later diffing in dashboard."""
    try:
        snapshots = []
        if os.path.exists(SCAN_SNAPSHOTS_FILE):
            with open(SCAN_SNAPSHOTS_FILE, "r") as f:
                try:
                    snapshots = json.load(f)
                except Exception:
                    snapshots = []

        online_devices = []
        for ip in sorted(set(online_ips)):
            rec = device_records.get(ip, {})
            hostname = rec.get("hostname", "—")
            if not hostname or hostname == "—":
                hostname = ip
            online_devices.append({
                "ip": ip,
                "hostname": hostname
            })

        snapshots.append({
            "scan_time": scan_time,
            "online_count": len(set(online_ips)),
            "online_devices": online_devices
        })

        # Keep most recent 500 snapshots.
        if len(snapshots) > 500:
            snapshots = snapshots[-500:]

        with open(SCAN_SNAPSHOTS_FILE, "w") as f:
            json.dump(snapshots, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save scan snapshot: {e}")


def load_previous_online_ips_from_snapshot():
    """
    IPs reported online in the last saved scan snapshot (before this run overwrites it).
    Used to deep-scan hosts that appear in the live set but were absent last cycle
    (e.g. Tailscale-only online, or status/cache edge cases).
    Returns None if no usable snapshot (avoid deep-scanning everyone on first use).
    """
    try:
        if not os.path.exists(SCAN_SNAPSHOTS_FILE):
            return None
        with open(SCAN_SNAPSHOTS_FILE, "r") as f:
            rows = json.load(f)
        if not isinstance(rows, list) or not rows:
            return None
        last = rows[-1]
        devs = last.get("online_devices") or []
        if not devs:
            return None
        ips = {d["ip"] for d in devs if isinstance(d, dict) and d.get("ip")}
        return ips if ips else None
    except Exception:
        return None


def merge_deep_scan_results_json(results_by_ip: dict):
    """Merge per-IP deep scan payloads into deep_scan_results.json for the dashboard."""
    if not results_by_ip:
        return
    merged = {}
    try:
        if os.path.exists(DEEP_SCAN_RESULTS_FILE):
            with open(DEEP_SCAN_RESULTS_FILE, "r") as f:
                existing = json.load(f)
            if isinstance(existing, dict) and isinstance(existing.get("results"), dict):
                merged = dict(existing["results"])
    except Exception as e:
        print(f"   Warning: could not read {DEEP_SCAN_RESULTS_FILE}: {e}")

    merged.update(results_by_ip)
    payload = {
        "scan_time": datetime.now().isoformat(),
        "devices_scanned": len(merged),
        "results": merged,
    }
    try:
        with open(DEEP_SCAN_RESULTS_FILE, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"   Deep scan JSON updated ({len(results_by_ip)} host(s) merged).")
    except Exception as e:
        print(f"   Warning: could not write {DEEP_SCAN_RESULTS_FILE}: {e}")


def ping_host(ip):
    """Ping a single host to check if it's alive"""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(SCAN_TIMEOUT), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        return ip if result.returncode == 0 else None
    except:
        return None


def is_tailscale_ipv4(ip: str) -> bool:
    """Return True when IP is in Tailscale CGNAT IPv4 range."""
    return isinstance(ip, str) and ip.startswith("100.")


def get_tailscale_peer_status():
    """
    Read Tailscale peer status from local daemon.
    Returns:
      {
        "online_ips": set[str],
        "known_ips": set[str],
        "hostnames": dict[str, str]
      }
    """
    result = {
        "online_ips": set(),
        "known_ips": set(),
        "hostnames": {},
    }
    try:
        proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return result

        payload = json.loads(proc.stdout)

        # Include local node status if it has a Tailscale IPv4.
        self_info = payload.get("Self", {}) if isinstance(payload, dict) else {}
        for ip in self_info.get("TailscaleIPs", []) or []:
            if not is_tailscale_ipv4(ip):
                continue
            result["known_ips"].add(ip)
            if self_info.get("Online") is True:
                result["online_ips"].add(ip)
            self_host = self_info.get("HostName")
            if self_host:
                result["hostnames"][ip] = self_host

        peers = payload.get("Peer", {}) if isinstance(payload, dict) else {}
        for peer in peers.values():
            if not isinstance(peer, dict):
                continue
            peer_host = peer.get("HostName")
            peer_online = bool(peer.get("Online"))
            for ip in peer.get("TailscaleIPs", []) or []:
                if not is_tailscale_ipv4(ip):
                    continue
                result["known_ips"].add(ip)
                if peer_online:
                    result["online_ips"].add(ip)
                if peer_host:
                    result["hostnames"][ip] = peer_host
    except Exception:
        # If tailscaled is unavailable, just fall back to LAN-only scan behavior.
        return result

    return result


def scan_ports(ip, ports):
    """Scan common TCP ports on a host"""
    open_ports = []
    for port in ports:
        try:
            result = subprocess.run(
                ["nc", "-z", "-w", "1", ip, str(port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )
            if result.returncode == 0:
                open_ports.append(port)
        except:
            pass
    return open_ports


def get_hostname(ip):
    """Try to resolve hostname via reverse DNS"""
    try:
        result = subprocess.run(
            ["getent", "hosts", ip],
            capture_output=True,
            text=True,
            timeout=3
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.split()
            return parts[1] if len(parts) > 1 else None
    except:
        pass
    return None


def get_mac(ip):
    """Get MAC address from ARP cache"""
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if ip in line and 'lladdr' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'lladdr':
                        return parts[i + 1]
    except:
        pass
    return None


def scan_network(network_cidr):
    """Scan a /24 network for live hosts"""
    base_ip = network_cidr.replace('/24', '')
    prefix = '.'.join(base_ip.split('.')[:3])
    
    live_hosts = []
    ips = [f"{prefix}.{i}" for i in range(1, 255)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_host, ips))
        live_hosts = [r for r in results if r]
    
    return live_hosts


def identify_device(ip, existing_records=None):
    """Gather all information about a device, preserving first_seen if known"""
    if existing_records is None:
        existing_records = {}

    hostname = get_hostname(ip)
    mac = get_mac(ip)
    ports = scan_ports(ip, COMMON_PORTS)

    # Determine device type based on ports/hostname
    device_type = "Unknown"
    if ports:
        if 631 in ports:
            device_type = "Printer/Scanner"
        elif 445 in ports or 139 in ports:
            device_type = "Windows/Samba Share"
        elif 22 in ports:
            device_type = "Linux/SSH Server"
        elif 80 in ports or 443 in ports:
            device_type = "Web Device"
        elif 5900 in ports:
            device_type = "VNC/Remote Desktop"

    if hostname:
        if "router" in hostname.lower() or "gateway" in hostname.lower():
            device_type = "Router/Gateway"
        elif "printer" in hostname.lower():
            device_type = "Printer"
        elif "iphone" in hostname.lower() or "phone" in hostname.lower():
            device_type = "Mobile Phone"
        elif "roku" in hostname.lower():
            device_type = "Streaming Device"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if we have historical record
    if ip in existing_records:
        record = existing_records[ip]
        first_seen = record.get("first_seen", now_str)
        # Update last seen and any new info
        record.update({
            "last_seen": now_str,
            "hostname": hostname or record.get("hostname", "—"),
            "mac": mac or record.get("mac", "—"),
            "type": device_type if device_type != "Unknown" else record.get("type", "Unknown")
        })
        existing_records[ip] = record
    else:
        # New device - record first seen time
        existing_records[ip] = {
            "first_seen": now_str,
            "last_seen": now_str,
            "hostname": hostname or "—",
            "mac": mac or "—",
            "type": device_type
        }
        first_seen = now_str

    return {
        "ip": ip,
        "hostname": hostname or "—",
        "mac": mac or "—",
        "ports": ports,
        "type": device_type,
        "discovered": now_str,
        "first_seen": first_seen,
        "duration": human_duration_since(first_seen)
    }, existing_records


def _load_deep_scan_module():
    """Load deep_scan.py dynamically so we can reuse its scanner function."""
    if not os.path.exists(DEEP_SCAN_SCRIPT):
        return None
    try:
        spec = importlib.util.spec_from_file_location("deep_scan_runtime", DEEP_SCAN_SCRIPT)
        if not spec or not spec.loader:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"   Warning: could not load deep scanner module: {e}")
        return None


def infer_device_type_from_ports(hostname: str, ports):
    """Infer a human-friendly device label from hostname + deep-scan ports."""
    ports = set(ports or [])
    host_l = (hostname or "").lower()

    if 445 in ports or 139 in ports or 3389 in ports:
        return "Windows"
    if 631 in ports:
        return "Printer/Scanner"
    if 5900 in ports:
        return "VNC/Remote Desktop"
    if 22 in ports and not (445 in ports or 139 in ports):
        return "Linux/SSH Server"
    if 8060 in ports or "roku" in host_l:
        return "Streaming Device"
    if "iphone" in host_l or "android" in host_l or "phone" in host_l:
        return "Mobile Phone"
    if "router" in host_l or "gateway" in host_l:
        return "Router/Gateway"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "Web Device"
    return "Unknown"


def access_methods_from_ports(ip: str, ports):
    """Generate likely access methods from discovered ports."""
    methods = []
    pset = set(ports or [])
    if 22 in pset:
        methods.append(f"SSH (`ssh user@{ip}`)")
    if 80 in pset:
        methods.append(f"HTTP (`http://{ip}`)")
    if 443 in pset:
        methods.append(f"HTTPS (`https://{ip}`)")
    if 445 in pset:
        methods.append(f"SMB (`smb://{ip}`)")
    if 3389 in pset:
        methods.append("RDP")
    if 631 in pset:
        methods.append("CUPS/IPP")
    if 5900 in pset:
        methods.append("VNC")
    if 8080 in pset:
        methods.append(f"HTTP-Alt (`http://{ip}:8080`)")
    if 8443 in pset:
        methods.append(f"HTTPS-Alt (`https://{ip}:8443`)")
    return ", ".join(methods) if methods else "No known access"


def run_online_deep_scan_and_enrich(online_transition_ips, device_records):
    """
    Deep scan devices that just came online/newly appeared and enrich cache records.
    Returns a list of enrichment rows for devices.md.
    """
    if not online_transition_ips:
        return []

    deep_mod = _load_deep_scan_module()
    if deep_mod is None or not hasattr(deep_mod, "run_nmap_deep_scan"):
        print("   Warning: deep scan module unavailable; skipping online deep scan trigger")
        return []

    print("\n🧪 Online detector triggered deep scans:")
    enrichment_rows = []
    results_by_ip = {}
    for ip in sorted(set(online_transition_ips)):
        print(f"   - Deep scanning {ip}...")
        try:
            deep = deep_mod.run_nmap_deep_scan(ip)
        except Exception as e:
            print(f"     ⚠️ deep scan failed for {ip}: {e}")
            continue

        if isinstance(deep, dict) and deep.get("ip"):
            results_by_ip[ip] = deep

        record = device_records.get(ip, {})
        hostname = get_hostname(ip) or record.get("hostname", "—")
        mac = get_mac(ip) or record.get("mac", "—")

        open_ports = deep.get("ports", []) if isinstance(deep, dict) else []
        if not open_ports:
            # Preserve previously known ports if deep scan had no response.
            open_ports = record.get("ports", [])

        inferred_type = infer_device_type_from_ports(hostname, open_ports)
        if inferred_type == "Unknown":
            inferred_type = record.get("type", "Unknown")

        # Enrich cache record for dashboard/API consumption.
        record["hostname"] = hostname or record.get("hostname", "—")
        record["mac"] = mac or record.get("mac", "—")
        record["type"] = inferred_type
        record["ports"] = open_ports
        if isinstance(deep, dict) and deep.get("services"):
            record["services"] = deep.get("services", {})
        device_records[ip] = record

        enrichment_rows.append({
            "ip": ip,
            "hostname": record.get("hostname", "—") or "—",
            "mac": record.get("mac", "—") or "—",
            "ports": ", ".join(map(str, open_ports)) if open_ports else "None",
            "access": access_methods_from_ports(ip, open_ports),
            "identity": inferred_type,
        })

    merge_deep_scan_results_json(results_by_ip)
    return enrichment_rows


def update_online_enrichment_table(rows):
    """Write/replace a compact table of online-trigger deep scan enrichment."""
    if not rows:
        return
    try:
        with open(DEVICES_FILE, "r") as f:
            content = f.read()
    except Exception as e:
        print(f"   Warning: could not read {DEVICES_FILE} for enrichment table: {e}")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    section_lines = [
        "## ⚡ Online Detector Enrichment",
        "",
        f"Updated: {timestamp}",
        "",
        "| IP | Hostname | MAC | Status | Open Ports | Access Method | Identity |",
        "|-----|----------|-----|--------|------------|---------------|----------|",
    ]
    for r in rows:
        section_lines.append(
            f"| {r['ip']} | {r['hostname']} | {r['mac']} | Online | {r['ports']} | {r['access']} | {r['identity']} |"
        )
    section = "\n".join(section_lines) + "\n"

    if "## ⚡ Online Detector Enrichment" in content:
        content = re.sub(
            r"## ⚡ Online Detector Enrichment.*?(?=\n## |\Z)",
            section.strip(),
            content,
            flags=re.DOTALL,
        )
    else:
        content = content.rstrip() + "\n\n---\n\n" + section

    try:
        with open(DEVICES_FILE, "w") as f:
            f.write(content)
        print("   Online detector enrichment table updated")
    except Exception as e:
        print(f"   Warning: could not write online enrichment table: {e}")


def extract_existing_ips(devices_file):
    """Extract all existing IP addresses from devices.md"""
    existing_ips = set()
    try:
        with open(devices_file, 'r') as f:
            content = f.read()
            # Match IP addresses in the file (improved pattern)
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            matches = re.findall(ip_pattern, content)
            existing_ips = set(matches)
            print(f"   Found {len(existing_ips)} existing IPs in database")
            if len(existing_ips) > 0:
                print(f"   Sample IPs: {list(existing_ips)[:5]}")
    except Exception as e:
        print(f"Warning: Could not read existing devices file: {e}")
    return existing_ips


def format_device_entry(device):
    """Format a device as a markdown entry with network uptime"""
    ports_str = ', '.join(map(str, device['ports'])) if device['ports'] else 'None detected'
    
    entry = f"""### New Device Discovered: {device['ip']}

| Attribute | Value |
|-----------|-------|
| **IP Address** | {device['ip']} |
| **Hostname** | {device['hostname']} |
| **MAC Address** | {device['mac']} |
| **Open Ports** | {ports_str} |
| **Device Type** | {device['type']} |
| **Discovered** | {device['discovered']} |

**Access Methods:**
"""
    
    if device['ports']:
        for port in device['ports']:
            if port == 22:
                entry += f"- SSH: `ssh user@{device['ip']}`\n"
            elif port == 80:
                entry += f"- HTTP: http://{device['ip']}\n"
            elif port == 443:
                entry += f"- HTTPS: https://{device['ip']}\n"
            elif port == 445:
                entry += f"- SMB: `smb://{device['ip']}`\n"
            elif port == 631:
                entry += f"- CUPS: http://{device['ip']}:631\n"
            elif port == 5900:
                entry += f"- VNC: `vncviewer {device['ip']}:5900`\n"
            elif port == 8080:
                entry += f"- HTTP Alt: http://{device['ip']}:8080\n"
    else:
        entry += "- No common services detected (may be client device)\n"
    
    entry += "\n---\n\n"
    return entry


def update_scan_history(new_count, total_known, online_count):
    """Update scan history section at the end of devices.md"""
    try:
        with open(DEVICES_FILE, 'r') as f:
            content = f.read()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_entry = f"| {timestamp} | {new_count} | {online_count} | {total_known} |\n"
        
        # Check if scan history section exists
        if "## 📊 Scan History" not in content:
            # Add new history section at the end
            history_section = f"""

---

## 📊 Scan History

| Scan Time | New Devices | Online | Total Known |
|-----------|-------------|--------|-------------|
{history_entry}

*Last updated: {timestamp}*
"""
            content = content.rstrip() + history_section
        else:
            # Append to existing table
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if '| Scan Time |' in line:
                    # Insert after header row and separator
                    insert_pos = i + 2
                    lines.insert(insert_pos, history_entry.rstrip())
                    break
            
            # Update last updated timestamp
            content = '\n'.join(lines)
            content = re.sub(r'\*Last updated: .*\*', f'*Last updated: {timestamp}*', content)
        
        with open(DEVICES_FILE, 'w') as f:
            f.write(content)
        
        print(f"   Scan history updated")
    except Exception as e:
        print(f"   Warning: Could not update scan history: {e}")


def update_devices_file(new_devices):
    """Add new devices to the top of devices.md"""
    if not new_devices:
        print("No new devices found.")
        return
    
    try:
        # Read existing content
        with open(DEVICES_FILE, 'r') as f:
            existing_content = f.read()
        
        # Create new section header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_section = f"""## 🔔 Network Scan Alert - {timestamp}

**{len(new_devices)} new device(s) discovered!**

"""
        
        # Add each new device
        for device in new_devices:
            new_section += format_device_entry(device)
        
        # Find the first header and insert before it, or prepend to file
        lines = existing_content.split('\n')
        insert_index = 0
        
        # Find where to insert (after title/header if exists)
        for i, line in enumerate(lines):
            if line.startswith('# ') and i > 0:
                insert_index = i + 1
                break
        
        # Insert new content
        new_lines = lines[:insert_index] + ['', new_section] + lines[insert_index:]
        new_content = '\n'.join(new_lines)
        
        # Write back
        with open(DEVICES_FILE, 'w') as f:
            f.write(new_content)
        
        print(f"✅ Updated {DEVICES_FILE} with {len(new_devices)} new device(s)")
        
    except Exception as e:
        print(f"❌ Error updating devices file: {e}")
        sys.exit(1)


def main():
    """Main scan function"""
    print(f"🔍 Network Scan Agent Started at {datetime.now()}")
    print("=" * 50)
    
    # Load rich device records (with first_seen timestamps)
    print("📋 Loading existing device records...")
    device_records = load_device_records()
    existing_ips = load_seen_ips(device_records)
    file_ips = extract_existing_ips(DEVICES_FILE)
    # Merge file IPs into records if missing
    for ip in file_ips:
        if ip not in device_records:
            device_records[ip] = {
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hostname": "—",
                "mac": "—",
                "type": "Unknown"
            }
    print(f"   Total known devices: {len(device_records)}")
    
    # Scan all networks
    all_live_hosts = []
    for network in NETWORKS:
        print(f"\n🌐 Scanning {network}...")
        live = scan_network(network)
        print(f"   Found {len(live)} live hosts")
        all_live_hosts.extend(live)

    # Tailscale peers don't reliably answer ICMP from this host; use daemon status.
    ts_status = get_tailscale_peer_status()
    ts_online_ips = sorted(ts_status.get("online_ips", set()))
    if ts_online_ips:
        print(f"\n🔐 Tailscale reports {len(ts_online_ips)} online peer(s)")
        all_live_hosts.extend(ts_online_ips)
    else:
        print("\n🔐 Tailscale peers online: 0 (or daemon unavailable)")

    # Keep cached hostnames aligned with Tailscale metadata (even when offline).
    ts_hostnames = ts_status.get("hostnames", {})
    for ip, ts_host in ts_hostnames.items():
        if not ts_host:
            continue
        if ip not in device_records:
            device_records[ip] = {
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hostname": ts_host,
                "mac": "—",
                "type": "Unknown",
                "events": [],
                "last_status": "offline",
                "last_status_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            continue
        current = device_records[ip].get("hostname", "—")
        if current in ("—", "", None):
            device_records[ip]["hostname"] = ts_host
    
    # Remove duplicates from live hosts
    all_live_hosts = list(set(all_live_hosts))
    print(f"\n📊 Total unique live hosts: {len(all_live_hosts)}")
    
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prev_online_ips = load_previous_online_ips_from_snapshot()

    # Filter out known devices
    new_ips = [ip for ip in all_live_hosts if ip not in existing_ips]
    
    # Update records with all seen devices (preserves first_seen)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    online_transition_ips = []
    for ip in all_live_hosts:
        if ip not in device_records:
            device_records[ip] = {
                "first_seen": now_str,
                "last_seen": now_str,
                "hostname": "—",
                "mac": "—",
                "type": "Unknown",
                "events": [],
                "last_status": "online",
                "last_status_time": now_str,
            }
            online_transition_ips.append(ip)
        else:
            previous_status = device_records[ip].get("last_status")
            device_records[ip]["last_seen"] = now_str
            if previous_status != "online":
                record_event(device_records[ip], "online", "scan")
                online_transition_ips.append(ip)
            else:
                device_records[ip]["last_status"] = "online"
                device_records[ip]["last_status_time"] = now_str

    # Mark known but currently unseen devices as offline.
    live_set = set(all_live_hosts)
    for ip, rec in device_records.items():
        if ip in live_set:
            continue
        if rec.get("last_status") != "offline":
            record_event(rec, "offline", "scan")
        else:
            rec["last_status_time"] = now_str

    # Deep scan: offline→online / first-seen, plus any host live now but missing from last snapshot
    # (covers Tailscale-only visibility and other edge cases).
    deep_scan_targets = set(online_transition_ips)
    if prev_online_ips is not None:
        appeared_live = set(all_live_hosts) - prev_online_ips
        if appeared_live:
            print(f"\n📌 Newly live vs last snapshot: {len(appeared_live)} host(s) (deep scan queue)")
        deep_scan_targets |= appeared_live

    enrichment_rows = run_online_deep_scan_and_enrich(sorted(deep_scan_targets), device_records)
    if enrichment_rows:
        update_online_enrichment_table(enrichment_rows)

    save_device_records(device_records)
    save_scan_snapshot(scan_timestamp, all_live_hosts, device_records)
    
    if not new_ips:
        print("\n✅ No new devices found. All clear!")
        print(f"   Known devices: {len(device_records)}")
        print(f"   Currently online: {len(all_live_hosts)}")
        # Still update scan history even if no new devices
        update_scan_history(0, len(device_records), len(all_live_hosts))
        return
    
    print(f"\n🆕 {len(new_ips)} NEW device(s) detected!")
    for ip in new_ips:
        print(f"   - {ip} (NEW!)")
    
    # Gather details on new devices (pass records to preserve first_seen)
    print("\n🔎 Gathering device details...")
    new_devices = []
    for ip in new_ips:
        print(f"   Investigating {ip}...", end=' ')
        device_info, device_records = identify_device(ip, device_records)
        new_devices.append(device_info)
        print(f"[{device_info['type']}]")
    
    # Update the file
    print("\n📝 Updating devices.md with new devices...")
    update_devices_file(new_devices)
    
    print("\n✨ Scan complete!")
    print(f"   New devices added: {len(new_devices)}")
    print(f"   Total known devices: {len(device_records)}")
    print(f"   Next scan: in 1 hour")
    
    # Update scan history
    update_scan_history(len(new_devices), len(device_records), len(all_live_hosts))


if __name__ == "__main__":
    main()
