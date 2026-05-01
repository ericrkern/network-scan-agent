# Network Scan Agent - Setup & Operation Guide

## Overview

The Network Scan Agent automatically scans for new devices on your network every hour and updates `devices.md` with any newly discovered devices.

## Components

### 1. Agent Script (`network_scan_agent.py`)
**Location:** `~/Documents/Network/network_scan_agent.py`

**Features:**
- Scans 2 networks: `192.168.0.0/24`, `192.168.100.0/24`
- Checks for open ports: 22, 80, 443, 445, 631, 8080, 5900, 3000, 5000
- Resolves hostnames and MAC addresses
- Identifies device types (printer, router, phone, etc.)
- Prevents duplicate entries using JSON cache
- Adds new devices with timestamp to top of `devices.md`
- Maintains scan history at bottom of file

### 2. Systemd Service (`network-scan-agent.service`)
**Location:** `~/.config/systemd/user/network-scan-agent.service`

**Purpose:** Defines how the agent runs (one-shot execution)

### 3. Systemd Timer (`network-scan-agent.timer`)
**Location:** `~/.config/systemd/user/network-scan-agent.timer`

**Schedule:**
- First run: 5 minutes after boot
- Subsequent runs: Every 1 hour

### 4. Device Cache (`.seen_devices.json`)
**Location:** `~/Documents/Network/.seen_devices.json`

**Purpose:** Tracks all previously seen devices to prevent duplicates

## How It Works

### Scan Process
1. **Load Cache** - Reads `.seen_devices.json` and extracts IPs from `devices.md`
2. **Network Scan** - Pings all 254 addresses in each /24 subnet
3. **Port Scan** - Checks common TCP ports on live hosts
4. **Device Identification** - Resolves hostnames, gets MACs, determines device type
5. **Compare** - Filters out devices already in cache/file
6. **Update File** - Adds new devices to top of `devices.md` with timestamp
7. **Update History** - Appends scan statistics to scan history table
8. **Save Cache** - Updates `.seen_devices.json`

### File Updates

**New Device Alert Format:**
```markdown
## 🔔 Network Scan Alert - 2026-04-20 15:36:51

**3 new device(s) discovered!**

### New Device Discovered: 192.168.0.100

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.100 |
| **Hostname** | new-device.local |
| **MAC Address** | aa:bb:cc:dd:ee:ff |
| **Open Ports** | 22, 80 |
| **Device Type** | Linux/SSH Server |
| **Discovered** | 2026-04-20 15:36:51 |

**Access Methods:**
- SSH: `ssh user@192.168.0.100`
- HTTP: http://192.168.0.100

---
```

**Scan History Format:**
```markdown
## 📊 Scan History

| Scan Time | New Devices | Online | Total Known |
|-----------|-------------|--------|-------------|
| 2026-04-20 15:36:51 | 0 | 13 | 35 |
| 2026-04-20 14:36:00 | 2 | 15 | 35 |

*Last updated: 2026-04-20 15:36:51*
```

## Management Commands

### Check Status
```bash
# View timer status
systemctl --user status network-scan-agent.timer

# View service status
systemctl --user status network-scan-agent.service

# List all timers
systemctl --user list-timers
```

### View Logs
```bash
# Follow agent logs
journalctl --user -u network-scan-agent.service -f

# View recent logs
journalctl --user -u network-scan-agent.service --since "1 hour ago"
```

### Manual Run
```bash
# Run agent immediately
python3 ~/Documents/Network/network_scan_agent.py
```

### Stop/Start/Restart
```bash
# Stop automatic scans
systemctl --user stop network-scan-agent.timer

# Start automatic scans
systemctl --user start network-scan-agent.timer

# Restart timer
systemctl --user restart network-scan-agent.timer

# Disable completely (won't start on boot)
systemctl --user disable network-scan-agent.timer

# Re-enable
systemctl --user enable network-scan-agent.timer
systemctl --user start network-scan-agent.timer
```

## File Locations Summary

| File | Purpose |
|------|---------|
| `~/Documents/Network/devices.md` | Main device inventory (gets updated) |
| `~/Documents/Network/network_scan_agent.py` | Agent script |
| `~/Documents/Network/.seen_devices.json` | Device cache (auto-managed) |
| `~/.config/systemd/user/network-scan-agent.service` | Systemd service |
| `~/.config/systemd/user/network-scan-agent.timer` | Systemd timer |

## Current Status

**Last Scan:** 2026-04-20 15:36:51  
**Status:** ✅ Active  
**Known Devices:** 35  
**Currently Online:** 13  
**Next Scan:** In ~1 hour (or check with `systemctl --user list-timers`)

## Troubleshooting

### Agent Not Running
```bash
# Check if timer is active
systemctl --user is-active network-scan-agent.timer

# Check for errors
journalctl --user -u network-scan-agent.service --since "1 day ago"
```

### Duplicates in devices.md
The agent should prevent duplicates via the cache. If duplicates appear:
```bash
# Clear the cache (forces fresh detection)
rm ~/Documents/Network/.seen_devices.json

# Run agent manually to rebuild cache
python3 ~/Documents/Network/network_scan_agent.py
```

### Scan Not Finding Devices
```bash
# Check network connectivity
ping 192.168.0.1

# Verify script permissions
ls -la ~/Documents/Network/network_scan_agent.py

# Test manual scan
python3 ~/Documents/Network/network_scan_agent.py
```

## Customization

### Change Scan Interval
Edit `~/.config/systemd/user/network-scan-agent.timer`:
```ini
[Timer]
OnBootSec=5min
OnUnitActiveSec=30min  # Change from 1h to 30min
```

Then reload:
```bash
systemctl --user daemon-reload
systemctl --user restart network-scan-agent.timer
```

### Add More Networks
Edit `~/Documents/Network/network_scan_agent.py`:
```python
NETWORKS = ["192.168.0.0/24", "192.168.100.0/24", "10.0.0.0/24"]
```

### Change Scanned Ports
Edit `~/Documents/Network/network_scan_agent.py`:
```python
COMMON_PORTS = [22, 80, 443, 445, 631, 8080, 5900, 3000, 5000, 1883, 9200]
```

## Security Notes

- Agent runs with user privileges (not root)
- Only scans internal networks (RFC 1918 addresses)
- Uses read-only network discovery (ping, port scans)
- Cache file contains only IP addresses (no credentials)
- No external network access required