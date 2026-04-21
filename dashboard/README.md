# Network Pulse Dashboard

A beautiful, real-time web dashboard showing the online status of **all devices** on your network.

Built on top of the existing `network_scan_agent.py` and `.seen_devices.json` data.

## Features

- **Live status cards** for every discovered device (IP, hostname, type, last seen)
- **Color-coded status** (Green = Online, Red = Offline, Amber = Unknown/Stealth)
- **One-click network scan** - triggers the existing Python scanner
- **Search and filter** (Online / Offline / All)
- **Auto-refresh** every 25 seconds
- **Responsive** Tailwind UI with dark cyber theme
- **Terminal output modal** showing scan results

## Quick Start

```bash
cd /home/jetson/Documents/Network/dashboard

# Run the dashboard
python3 app.py
```

Then open: **http://localhost:5000** or **http://192.168.0.197:5000**

## As a Service (Recommended)

Create a systemd user service:

```bash
# After first run, you can set it up as a persistent service
cp network-pulse.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now network-pulse.service
```

## Tech Stack

- **Backend**: Flask + Python 3
- **Frontend**: Tailwind CSS + vanilla JS (no build step)
- **Data Source**: `.seen_devices.json` + `devices.md`
- **Scan Integration**: Calls existing `network_scan_agent.py`

## Access

- Default port: **5000**
- Runs as user `irene` (with root privileges via sudo when needed)
- Fully compatible with the existing network monitoring agent

---

**Made for irene** — the new default operator of this network.
