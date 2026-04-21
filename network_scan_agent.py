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
from datetime import datetime
from pathlib import Path
import concurrent.futures

# Configuration
DEVICES_FILE = "/home/jetson/Documents/Network/devices.md"
SEEN_DEVICES_CACHE = "/home/jetson/Documents/Network/.seen_devices.json"
NETWORKS = ["192.168.0.0/24", "192.168.50.0/24", "192.168.100.0/24"]
COMMON_PORTS = [22, 80, 443, 445, 631, 8080, 5900, 3000, 5000]
SCAN_TIMEOUT = 2


def load_seen_devices():
    """Load cache of previously seen devices"""
    try:
        if os.path.exists(SEEN_DEVICES_CACHE):
            with open(SEEN_DEVICES_CACHE, 'r') as f:
                return set(json.load(f))
    except Exception as e:
        print(f"Warning: Could not load seen devices cache: {e}")
    return set()


def save_seen_devices(seen_devices):
    """Save cache of seen devices"""
    try:
        with open(SEEN_DEVICES_CACHE, 'w') as f:
            json.dump(list(seen_devices), f)
    except Exception as e:
        print(f"Warning: Could not save seen devices cache: {e}")


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


def identify_device(ip):
    """Gather all information about a device"""
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
    
    return {
        "ip": ip,
        "hostname": hostname or "—",
        "mac": mac or "—",
        "ports": ports,
        "type": device_type,
        "discovered": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


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
    """Format a device as a markdown entry"""
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
    
    # Get existing IPs from both cache and file
    print("📋 Loading existing device list...")
    cached_ips = load_seen_devices()
    file_ips = extract_existing_ips(DEVICES_FILE)
    existing_ips = cached_ips.union(file_ips)
    print(f"   Total known devices: {len(existing_ips)}")
    
    # Scan all networks
    all_live_hosts = []
    for network in NETWORKS:
        print(f"\n🌐 Scanning {network}...")
        live = scan_network(network)
        print(f"   Found {len(live)} live hosts")
        all_live_hosts.extend(live)
    
    # Remove duplicates from live hosts
    all_live_hosts = list(set(all_live_hosts))
    print(f"\n📊 Total unique live hosts: {len(all_live_hosts)}")
    
    # Filter out known devices
    new_ips = [ip for ip in all_live_hosts if ip not in existing_ips]
    
    # Update cache with all seen devices
    all_seen = existing_ips.union(set(all_live_hosts))
    save_seen_devices(all_seen)
    
    if not new_ips:
        print("\n✅ No new devices found. All clear!")
        print(f"   Known devices: {len(existing_ips)}")
        print(f"   Currently online: {len(all_live_hosts)}")
        # Still update scan history even if no new devices
        update_scan_history(0, len(all_seen), len(all_live_hosts))
        return
    
    print(f"\n🆕 {len(new_ips)} NEW device(s) detected!")
    for ip in new_ips:
        print(f"   - {ip} (NEW!)")
    
    # Gather details on new devices
    print("\n🔎 Gathering device details...")
    new_devices = []
    for ip in new_ips:
        print(f"   Investigating {ip}...", end=' ')
        device = identify_device(ip)
        new_devices.append(device)
        print(f"[{device['type']}]")
    
    # Update the file
    print("\n📝 Updating devices.md with new devices...")
    update_devices_file(new_devices)
    
    print("\n✨ Scan complete!")
    print(f"   New devices added: {len(new_devices)}")
    print(f"   Total known devices: {len(all_seen)}")
    print(f"   Next scan: in 1 hour")
    
    # Update scan history
    update_scan_history(len(new_devices), len(all_seen), len(all_live_hosts))


if __name__ == "__main__":
    main()
