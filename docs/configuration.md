# Network Tool Configuration Guide

This document explains how to install and configure the Network Scan + Dashboard tool on a new Linux machine, and where scan data is stored.

## 1) What This Tool Includes

- Network discovery agent (`network_scan_agent.py`)
- Optional deep scan runner (`deep_scan.py`)
- Web dashboard (`dashboard/app.py`)
- Dashboard helpers for audit, WiFi scan, and network trace
- Systemd service(s) for dashboard and periodic scan execution

## 2) Prerequisites

- Linux host (Debian/Ubuntu style commands below)
- Non-root operator user (examples use `yb`)
- `sudo` access for one-time setup
- Local network access
- Optional: Tailscale for remote dashboard access

Install required packages:

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap netcat-openbsd tcpdump tshark auditd
```

## 3) Place Project Files

Expected project root:

```bash
/usr/local/yb/.Network
```

Important paths:

- `/usr/local/yb/.Network/network_scan_agent.py`
- `/usr/local/yb/.Network/deep_scan.py`
- `/usr/local/yb/.Network/dashboard/app.py`
- `/usr/local/yb/.Network/dashboard/bin/read_cmd_exec_audit.sh`
- `/usr/local/yb/.Network/dashboard/bin/scan_wifi_ssids.sh`
- `/usr/local/yb/.Network/dashboard/bin/network_trace_control.sh`

Make helpers executable:

```bash
chmod +x /usr/local/yb/.Network/dashboard/bin/read_cmd_exec_audit.sh
chmod +x /usr/local/yb/.Network/dashboard/bin/scan_wifi_ssids.sh
chmod +x /usr/local/yb/.Network/dashboard/bin/network_trace_control.sh
```

## 4) Install Sudoers Rules for Dashboard Helpers

Install:

```bash
sudo install -m 440 /usr/local/yb/.Network/dashboard/network-pulse-audit.sudoers /etc/sudoers.d/network-pulse-audit
sudo install -m 440 /usr/local/yb/.Network/dashboard/network-pulse-wifi.sudoers /etc/sudoers.d/network-pulse-wifi
sudo install -m 440 /usr/local/yb/.Network/dashboard/network-pulse-trace.sudoers /etc/sudoers.d/network-pulse-trace
```

Validate:

```bash
sudo visudo -cf /etc/sudoers.d/network-pulse-audit
sudo visudo -cf /etc/sudoers.d/network-pulse-wifi
sudo visudo -cf /etc/sudoers.d/network-pulse-trace
```

Quick audit helper test:

```bash
sudo -n /usr/local/yb/.Network/dashboard/bin/read_cmd_exec_audit.sh today >/dev/null && echo OK
```

## 5) Configure Dashboard Service

You can run dashboard as either:

- system service: `/etc/systemd/system/network-pulse.service`
- user service: `~/.config/systemd/user/network-pulse.service`

Recommended environment settings for dashboard service:

- `PYTHONUNBUFFERED=1`
- `AUDIT_HELPER_CMD=sudo -n /usr/local/yb/.Network/dashboard/bin/read_cmd_exec_audit.sh {since}`

If using `sudo` helper commands, ensure:

- `NoNewPrivileges=no`

System service example (if using `/etc/systemd/system/network-pulse.service`):

```bash
sudo mkdir -p /etc/systemd/system/network-pulse.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/network-pulse.service.d/10-dashboard-env.conf >/dev/null
[Service]
Environment="AUDIT_HELPER_CMD=sudo -n /usr/local/yb/.Network/dashboard/bin/read_cmd_exec_audit.sh {since}"
NoNewPrivileges=no
EOF
sudo systemctl daemon-reload
sudo systemctl restart network-pulse.service
```

Verify:

```bash
systemctl show network-pulse.service -p Environment -p NoNewPrivileges --no-pager
```

## 6) Configure Periodic Network Scans

This is separate from the dashboard service.

If using systemd user timer approach, create:

- `~/.config/systemd/user/network-scan-agent.service`
- `~/.config/systemd/user/network-scan-agent.timer`

Example timer for every 15 minutes:

```ini
[Unit]
Description=Run network scan agent every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Unit=network-scan-agent.service

[Install]
WantedBy=timers.target
```

Enable timer:

```bash
systemctl --user daemon-reload
systemctl --user enable --now network-scan-agent.timer
systemctl --user list-timers | grep network-scan-agent
```

If using cron instead, add:

```cron
*/15 * * * * cd /usr/local/yb/.Network && /usr/bin/python3 network_scan_agent.py >> /usr/local/yb/.Network/scan_cron.log 2>&1
```

## 7) First-Time Validation

Run a manual scan:

```bash
cd /usr/local/yb/.Network
python3 network_scan_agent.py
```

Check dashboard APIs:

```bash
curl -s http://127.0.0.1:5000/api/devices | jq '.total, .online'
curl -s "http://127.0.0.1:5000/api/audit?since=today" | jq '.ok, .message'
curl -s "http://127.0.0.1:5000/api/wifi/ssids?limit=20" | jq '.ok, .message'
curl -s "http://127.0.0.1:5000/api/trace?action=summary&minutes=15" | jq '.ok'
```

## 8) Where Scan Data Is Stored

Primary data files in `/usr/local/yb/.Network`:

- `.seen_devices.json`
  - Device cache used to avoid duplicate "new device" alerts.
- `.scan_snapshots.json`
  - Historical online-device snapshots per scan timestamp.
- `devices.md`
  - Human-readable inventory and scan history timeline.
- `deep_scan_results.json`
  - Last deep scan result set used by dashboard details.

Related logs:

- `/usr/local/yb/.Network/deep_scan_cron.log`
  - Output from scheduled deep scan / automation scripts.
- `/usr/local/yb/.Network/scan_cron.log` (if you use the cron example above)
  - Network scan cron run output.
- `journalctl --user -u network-scan-agent.service`
  - Agent service logs (systemd user mode).
- `journalctl -u network-pulse.service`
  - Dashboard logs (system service mode).

Dashboard code/data references:

- Dashboard app: `/usr/local/yb/.Network/dashboard/app.py`
- Templates: `/usr/local/yb/.Network/dashboard/templates/index.html`
- Helper scripts: `/usr/local/yb/.Network/dashboard/bin/`

## 9) Troubleshooting

- Audit shows unauthorized
  - Validate sudoers file syntax with `visudo -cf`.
  - Confirm helper path in sudoers exactly matches helper on disk.
  - Confirm dashboard service has `AUDIT_HELPER_CMD` loaded.
  - If using sudo helper, set `NoNewPrivileges=no`.

- Dashboard runs but data does not update
  - Run manual scan and check timestamps in `devices.md`.
  - Check whichever scheduler you actually use (timer or cron).

- Port 5000 conflict
  - Another process may already be serving dashboard; check listeners and restart the correct service.

## 10) Operations Cheat Sheet

```bash
# Dashboard (system service)
sudo systemctl restart network-pulse.service
sudo systemctl status network-pulse.service --no-pager

# Dashboard (user service alternative)
systemctl --user restart network-pulse.service
systemctl --user status network-pulse.service --no-pager

# Agent timer
systemctl --user status network-scan-agent.timer --no-pager
systemctl --user status network-scan-agent.service --no-pager

# Run scan now
cd /usr/local/yb/.Network && python3 network_scan_agent.py
```

---

Installation is complete when:

- Dashboard is reachable on port `5000`
- `/api/audit` returns `ok: true`
- Scheduled scan mechanism is active (timer or cron)
- `devices.md` and `.scan_snapshots.json` update after a scan
