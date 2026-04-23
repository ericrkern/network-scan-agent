# Network Device Inventory
**Generated:** 2026-04-21  
**Source:** Multi-subnet scan from Jetson host (192.168.0.197)  
**Enhanced with:** First-seen timestamps and network uptime tracking (`On Network` column)

---

## Device Summary by Network

### Local LAN (192.168.0.0/24) — 10 Devices

| IP | Hostname | MAC | Status | Open Ports | Access Method | Identity |
|-----|----------|-----|--------|------------|---------------|----------|
| 192.168.0.1 | Motorola Router | c8:c7:50:f5:ca:1b | Online | 53, 80, 443, 5000 | Web UI (http/https), DNS | **Motorola MG8702 Router/Gateway** |
| 192.168.0.59 | — | 8a:33:76:dd:0b:cb | Online | None | No known access | Unknown client device |
| 192.168.0.67 | R7000.MG8702 | a0:04:60:31:85:a0 | Stealth (no ping) | UDP: 53,67,68,123,161,1900,5353,547,69,137,138,500,4500,5060 | SNMP, DHCP, VPN, VoIP | **Secondary Router/VPN Gateway** (Netgear R7000 or Lenovo) |
| 192.168.0.127 | DESKTOP-HN6QL1F.MG8702 | 70:8b:cd:7c:f4:54 | Online | 139, 445 | SMB/CIFS | **Windows/Samba File Share** |
| 192.168.0.135 | motorola-edge-2022.MG8702 | 8a:13:29:33:8a:2d | Online | None | No open ports | **Motorola Edge 2022 Phone** |
| 192.168.0.143 | — | 30:03:c8:4a:0a:84 | Online | 80, 443, 631, 8080 | Web UI, IPP | **HP Color LaserJet MFP M283fdw** |
| 192.168.0.158 | device.MG8702 | 44:61:32:c8:42:f0 | Online | None | No open ports | Unknown device |
| 192.168.0.197 | yahboom | — | **This Host** | 22, 631, 5900 | SSH, CUPS, VNC | **Jetson (Scan Source)** |
| 192.168.0.233 | RokuUltraB.MG8702 | d8:31:34:5f:40:b4 | Online | None | Roku protocol | **Roku Ultra Streaming Device** |
| 192.168.0.246 | esp32s3-9F9FA0.MG8702 | 20:6e:f1:9f:9f:a0 | Online | None | ESP32 protocol | **ESP32-S3 IoT Device** |

### Adjacent Subnet (192.168.50.0/24) — 1 Device

| IP | Hostname | Status | Open Ports | Access Method | Identity |
|-----|----------|--------|------------|---------------|----------|
| 192.168.50.1 | — | Online | 53, 80, 443, 5000 | Web UI, DNS | **Router Interface** (same as 192.168.0.1) |

### Adjacent Subnet (192.168.100.0/24) — 1 Device

| IP | Hostname | Status | Open Ports | Access Method | Identity |
|-----|----------|--------|------------|---------------|----------|
| 192.168.100.1 | — | Online | None | ICMP only | **Router Interface** (management disabled) |

### Docker Network (172.17.0.0/16) — 1 Device

| IP | Hostname | Status | Open Ports | Access Method | Identity |
|-----|----------|--------|------------|---------------|----------|
| 172.17.0.1 | yahboom | Online | 22, 631, 5900 | SSH, CUPS, VNC | **Docker Bridge Interface** (local) |

### Tailscale Mesh VPN — 6 Devices

| IP | Hostname | Status | Open Ports | Access Method | Identity |
|-----|----------|--------|------------|---------------|----------|
| 100.71.191.72 | apple-mac-mini-m4-pro | Online | 22, 5900 | SSH, VNC | **Mac Mini** |
| 100.76.245.26 | Velas16s-macbookpro | Offline | — | — | **Offline/Unresponsive** |
| 100.78.64.7 | apple-macbook-pro-m5-prime-radiant | Online | 22, 5900, **18789** | SSH, VNC, Custom | **MacBook Pro** |
| 100.79.216.111 | erics-macbook-pro.tail2a3b45.ts.net | Online | 5000 | AirTunes | **MacBook Pro (AirPlay)** |
| 100.92.6.101 | thinkstation-pgx-cindy-crawford | Online | 22, 80, 8080, **18789** | SSH, HTTP, Custom | **OpenClaw Server/Lenovo ThinkStation** |
| 100.93.92.44 | irene-macbookair | Offline | — | — | **Offline/Unresponsive** |
| 100.95.15.82 | iphone172.tail2a3b45.ts.net | Online | None | iOS protocol | **iPhone** |
| 100.100.100.100 | magicdns.localhost-tailscale-daemon | Online | 53, 80, 8080 | DNS, HTTP | **Tailscale MagicDNS Service** |

---

## Device Connectivity Log

This table tracks when devices were first seen (came online), their last known activity, and current status. Updated by the hourly network scan agent.

| IP Address | Hostname | First Seen | Last Seen | On Network | Current Status |
|------------|----------|------------|-----------|------------|----------------|
| 192.168.0.1 | Motorola Router | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (Router) |
| 192.168.0.197 | yahboom | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (This Host) |
| 192.168.0.143 | — | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (Printer) |
| 192.168.0.233 | RokuUltraB.MG8702 | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (Streaming) |
| 100.71.191.72 | apple-mac-mini-m4-pro | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (Mac Mini) |
| 100.78.64.7 | apple-macbook-pro-m5-prime-radiant | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (MacBook Pro) |
| 100.92.6.101 | thinkstation-pgx-cindy-crawford | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Online** (OpenClaw Server) |
| 100.76.245.26 | Velas16s-macbookpro | 2026-04-20 | 2026-04-20 18:35 | ~14h | **Offline** |
| 100.93.92.44 | — | 2026-04-20 | 2026-04-20 18:35 | ~14h | **Offline** |
| 192.168.0.67 | R7000.MG8702 | 2026-04-20 | 2026-04-21 06:47 | ~1d 0h | **Stealth/Online** (Secondary Router) |

*Last updated: 2026-04-22 20:38:42*

---

## Recent Online/Offline Changes (Since Last Scan)

This table shows only devices that changed state (came online or went offline) between scans. Hostnames are included where known.

| Status       | Devices                          | Scan Time           | Notes |
|--------------|----------------------------------|---------------------|-------|
| **Online** | —                                 | None                         | 2026-04-21 07:01:43 | No devices came online in the latest scan. |
| **Offline**| —                                 | None                         | 2026-04-21 07:01:43 | No devices went offline in the latest scan. |
| **Online** | esp32s3-9F9FA0.MG8702             | ESP32-S3 IoT (192.168.0.246) | 2026-04-20 18:35:03 | New IoT device joined the LAN. |
| **Online** | device.MG8702                     | Unknown Client (192.168.0.158) | 2026-04-20 16:33:02 | New client device discovered. |

*This table is focused exclusively on state changes. The full scan history is in the section above.*
---

## Access Details by Device Type

### Network Infrastructure

**Primary Router: 192.168.0.1 / 192.168.50.1**
- Access: Web UI at http://192.168.0.1 or https://192.168.0.1:443
- Management port: 5000
- Services: DNS (53), Web Admin (80/443)
- Credentials: Unknown (would require testing or admin knowledge)

**Secondary Gateway: 192.168.0.67 (R7000)**
- Access: UDP services only (no web UI detected on standard ports)
- Services: VPN (500/4500), VoIP (5060), DHCP, DNS, SNMP
- Access method: SNMP v2/v3 (community unknown), VPN tunnel, SIP
- Status: Stealth device (no ping, no TCP)

### Computing Devices

**Your Jetson Host: 192.168.0.197**
- SSH access: `ssh user@192.168.0.197` (port 22)
- VNC access: `vncviewer 192.168.0.197:5900`
- CUPS printing: http://192.168.0.197:631

**Mac Mini: 100.71.191.72 (Tailscale)**
- SSH: `ssh user@100.71.191.72`
- VNC: `vncviewer 100.71.191.72:5900`
- Access: Requires Tailscale auth + device credentials

**MacBook Pro: 100.78.64.7 (Tailscale)**
- SSH: `ssh user@100.78.64.7`
- VNC: `vncviewer 100.78.64.7:5900`
- Custom port 18789: Unknown service (likely application-specific)

**OpenClaw Server: 100.92.6.101 (Tailscale)**
- HTTP: http://100.92.6.101 (OpenClaw Security Audit interface)
- HTTP Alt: http://100.92.6.101:8080
- SSH: `ssh user@100.92.6.101`
- Port 18789: OpenClaw service port
- Access: Requires Tailscale + web/ssh credentials

### IoT/Embedded Devices

**HP Printer: 192.168.0.143**
- Web UI: http://192.168.0.143 (HP EWS interface)
- IPP Printing: port 631
- ePrint/Cloud: port 8080
- Access: Usually admin/admin or no auth for basic functions

**Roku Ultra: 192.168.0.233**
- Protocol: Roku ECP (External Control Protocol)
- Port: 8060 (not scanned, standard Roku port)
- Access: HTTP API, mobile app control

**ESP32-S3: 192.168.0.246**
- Protocol: ESP32 native/MQTT/Web
- Access: Likely web interface or serial

**Motorola Phone: 192.168.0.135**
- No open ports detected
- Access: Likely cloud/Android services only

---

## Special Port 18789 Analysis

**Devices with port 18789 open:**
1. **100.78.64.7** (MacBook Pro)
2. **100.92.6.101** (OpenClaw Server)

**Service fingerprint:**
- Port 18789 is non-standard
- On OpenClaw server (100.92.6.101), likely OpenClaw agent/service port
- On MacBook Pro, possibly OpenClaw client or development instance

---

## Network Topology (Updated with All Discovered Devices)

### Physical Network Topology

```
Internet
    │
    ▼
[Motorola MG8702 Gateway]
  192.168.0.1 ──┬── 192.168.0.67 (R7000 VPN Gateway - stealth)
                │
                ├── 192.168.50.0/24 (Router sub-interface)
                │   └── 192.168.50.1
                │
                └── 192.168.100.0/24 (Router sub-interface)
                    └── 192.168.100.1 (management disabled)

192.168.0.0/24 (Main LAN)
├── Infrastructure ───────────────────────────────────────────────
│   ├── 192.168.0.1 ── Motorola MG8702 Router/Gateway
│   │                   [DNS 53, Web 80/443, Mgmt 5000]
│   │
│   ├── 192.168.0.67 ── R7000 VPN/Gateway (stealth device)
│   │                   [UDP: VPN 500/4500, VoIP 5060, SNMP 161]
│   │
│   └── 192.168.0.131 ── Apple DNS-SD Proxy ★ NEW
│                       [DNS-over-TLS 853, mDNS relay]
│
├── Computing Devices ────────────────────────────────────────────
│   ├── 192.168.0.197 ── Jetson (This Host) ★ SCAN SOURCE
│   │                   [SSH 22, VNC 5900, RDP 3389, CUPS 631]
│   │
│   ├── 192.168.0.127 ── Windows File Share
│   │                   [SMB 139/445]
│   │
│   ├── 192.168.0.59 ── Mobile Device (sleep/wake cycling) ★ MYSTERY
│   │                   [No open ports, UDP-responsive]
│   │
│   └── 192.168.0.135 ── Motorola Edge 2022 Phone
│
├── Peripherals/IoT ────────────────────────────────────────────
│   ├── 192.168.0.143 ── HP Color LaserJet MFP M283fdw
│   │                   [Web 80/443, IPP 631, ePrint 8080]
│   │
│   ├── 192.168.0.233 ── Roku Ultra Streaming Device
│   │                   [Roku ECP protocol]
│   │
│   ├── 192.168.0.158 ── Motorola IoT Device (silent) ★ MYSTERY
│   │                   [No services exposed, ping only]
│   │
│   └── 192.168.0.246 ── ESP32-S3 IoT Device
│
├── Offline/Powered Off ───────────────────────────────────────
│   ├── 192.168.0.142 ── Mystery Device (offline)
│   │                   [Last seen: TCP port 32, now FAILED ARP]
│   │
│   └── 192.168.0.182 ── Ghost Entry (disconnected)
│                       [No ARP, no response]
│
└── Virtual Interfaces (Local) ────────────────────────────────
    ├── 172.17.0.1 ── Docker Bridge (l4tbr0: usb0/usb1 DOWN)
    │
    └── 127.0.0.1 ── Localhost Services
        ├── Port 8888 (unknown service)
        ├── Port 11434 (Ollama LLM)
        └── Port 111 (RPCbind)

Tailscale Mesh VPN Overlay (encrypted tunnel via 100.70.174.39)
├── 100.71.191.72 ── Mac Mini
│                   [SSH 22, VNC 5900]
│
├── 100.78.64.7 ── MacBook Pro
│                  [SSH 22, VNC 5900, OpenClaw 18789]
│
├── 100.79.216.111 ── MacBook Pro (AirPlay mode)
│                     [AirTunes 5000]
│
├── 100.92.6.101 ── OpenClaw Server ★ KEY FINDING
│                   [HTTP 80/8080, SSH 22, OpenClaw 18789]
│                   [Hostname: thinkstationpgx-9c48]
│
├── 100.95.15.82 ── iPhone (Tailscale)
│
├── 100.100.100.100 ── Tailscale MagicDNS
│                      [DNS 53, HTTP 80/8080]
│
└── Offline Peers ─────────────────────────
    ├── 100.76.245.26 ── (unresponsive)
    └── 100.93.92.44 ── (unresponsive)
```

### Network Relationship Map

```
                    ┌─────────────────────────────────────────┐
                    │         Internet Gateway                │
                    │         192.168.0.1 (Motorola)          │
                    │  Routes: .50.x, .100.x subnets          │
                    └─────────────────────────────────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           │                          │                          │
           ▼                          ▼                          ▼
   ┌───────────────┐          ┌───────────────┐          ┌───────────────┐
   │ 192.168.0.67  │          │ 192.168.50.0  │          │ 192.168.100.0 │
   │ R7000 Gateway │          │    /24        │          │    /24        │
   │ [VPN/VoIP]    │          │ [Router intf] │          │ [Router intf] │
   └───────────────┘          └───────────────┘          └───────────────┘
           │                          │                          │
           │                    ┌─────┴─────┐              (management
           │                    │ .50.1     │               disabled)
           ▼                    └───────────┘
   ┌─────────────────────────────────────────────────────────────┐
   │                    192.168.0.0/24 (Main LAN)                  │
   │                                                               │
   │  Infrastructure          Computing           IoT/Services      │
   │  ─────────────────────────────────────────────────────────    │
   │  ├─ .1   Router        ├─ .59   Mobile      ├─ .143 Printer │
   │  ├─ .67  VPN GW        ├─ .127  Windows      ├─ .233 Roku    │
   │  ├─ .131 Apple DNS     ├─ .135  Phone       ├─ .158 Moto IoT│
   │  │                     ├─ .197  Jetson ★    └─ .246 ESP32   │
   │  │                     │                                     │
   │  Offline/Ghost         │                                     │
   │  ├─ .142 (mystery)     Tailscale Overlay                    │
   │  └─ .182 (ghost)       ├─ 100.92.6.101 OpenClaw ★          │
   │                        ├─ 100.78.64.7   MacBook            │
   │                        ├─ 100.71.191.72 Mac Mini           │
   │                        └─ ... (4 more Tailscale devices)    │
   └─────────────────────────────────────────────────────────────┘
```

### Legend
- ★ **Key Discovery**: Critical device identified during deep scan
- 🔒 **Secure Service**: TLS/encrypted port detected
- 📡 **Always-On**: 24/7 service device
- 😴 **Sleep/Wake**: Power-managed device (intermittent)
- 👻 **Ghost/Offline**: Device no longer reachable

---

## Total Device Count

| Network | Device Count |
|---------|-------------|
| 192.168.0.0/24 | 10 |
| 192.168.50.0/24 | 1 |
| 192.168.100.0/24 | 1 |
| 172.17.0.0/16 (Docker) | 1 |
| Tailscale | 6 (4 online) |
| **TOTAL** | **19** |

---

## Notes

- Stealth device 192.168.0.67 was discovered via ARP table, not ping scan
- No responsive devices found in 10.0.0.0/8 or 172.16.0.0/16 from this host
- OpenClaw service confirmed at 100.92.6.101 with HTTP interface
- Port 18789 appears to be OpenClaw-related (present on 2 Tailscale hosts)

---

## Mystery/Other Clients Deep Scan Results (2026-04-20)

### Summary
Comprehensive deep scan performed on suspected offline/powered-off devices. **Major discovery: Apple device identified with DNS-SD proxy service.**

### Detailed Findings by Device

| IP | Hostname | MAC | Deep Scan Results | Identity |
|-----|----------|-----|-------------------|----------|
| **192.168.0.59** | — | `8a:33:76:dd:0b:cb` | **RECOVERED** - Now responding to ping (was temporarily offline). ARP status: DELAY. No TCP ports. UDP-responsive via router. | Unknown client (sleeping/mobile device) |
| **192.168.0.131** | iPhone.MG8702 | `06:4d:1c:2e:e9:ab` | **IDENTIFIED: APPLE DNS-SD PROXY** - Port 853 (DNS-over-TLS) open. Certificate: `com.apple.dnssd-proxy` from Apple Inc. Bonjour/mDNS relay service active. Randomized MAC (privacy feature). | **Apple Device** - MacBook/iMac/Apple TV/Time Capsule acting as mesh relay |
| **192.168.0.142** | — | FAILED ARP | **OFFLINE** - No ping response. Previously showed port 32. ARP FAILED. May be wake-on-demand device or powered-off VM. | Unknown (possibly powered off) |
| **192.168.0.158** | device.MG8702 | `44:61:32:c8:42:f0` | **STALE ARP but pingable** - No open TCP ports. UDP-responsive. Hostname suggests Motorola device but no services exposed. | Unknown Motorola device (possibly IoT) |
| **192.168.0.182** | — | FAILED ARP | **OFFLINE** - No ping response. ARP FAILED. No historical data. | Unknown (offline or moved) |

### Key Discoveries

#### 192.168.0.131 - Apple DNS-SD Proxy Service
**Major Find:** TLS certificate analysis reveals:
```
Subject: CN = com.apple.dnssd-proxy C9D056D6-E831-414C-A376-0619112943B2
         OU = Networking, O = Apple Inc., L = Cupertino, ST = California, C = US
Algorithm: id-ecPublicKey, 384-bit ECDSA
Valid: Apr 17 2026 - Apr 17 2027
```

**Service Details:**
- **Port 853**: DNS-over-TLS (DoT) - Secure DNS proxy
- **Function**: Bonjour/mDNS relay for cross-network service discovery
- **Device Type**: Likely MacBook, iMac, Apple TV, or Airport/Time Capsule
- **Network Role**: Acts as mesh relay/extender for Apple services

#### 192.168.0.59 - Power Cycling Behavior
- **Initial scan**: ARP REACHABLE, then disappeared
- **Deep scan**: RECOVERED - responding again
- **Assessment**: Mobile device with aggressive power management (phone/tablet)
- **Pattern**: Device sleeps, drops ARP, wakes on network activity

#### 192.168.0.142 - Port 32 Mystery
- **Previous finding**: Port 32 TCP open (unusual)
- **Current status**: OFFLINE (FAILED ARP)
- **Port 32 significance**: Historically AppleTalk or messaging protocols
- **Assessment**: May be wake-on-demand device, VM, or Apple legacy device

#### 192.168.0.158 - Silent Motorola Device
- **Hostname**: device.MG8702 (suggests Motorola/Netgear ecosystem)
- **Behavior**: Responds to ping but no TCP services
- **Assessment**: Likely IoT sensor, smart home device, or managed switch

#### 192.168.0.182 - Ghost Entry
- **Status**: Complete ARP failure
- **Assessment**: Device has left network or MAC address changed

### VM Infrastructure Present but Inactive

**NVIDIA L4T Bridge (`l4tbr0`)**
- Status: DOWN (inactive)
- Interfaces: `usb0`, `usb1` (USB gadget mode)
- Can be used for USB networking to host PC or guest VMs
- Present on Jetson platforms for USB Device Mode

**No Active VM Platforms Detected:**
- KVM/libvirt: Not running
- VirtualBox/VMware: Not installed
- LXD/Incus: Not installed
- Docker: Installed but no running containers
- systemd-nspawn: No machines
- Kubernetes (k3s/minikube): Not running

### Local Services on This Host (192.168.0.197)

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | Standard access |
| 631 | CUPS | Printing service |
| 5900 | VNC | gnome-remote-desktop |
| 3389 | RDP | gnome-remote-desktop |
| 8888 | Unknown | Requires elevated privileges to identify |
| 11434 | Ollama | Local LLM/AI inference service |
| 111 | RPCbind | NFS/portmapper |

### R7000 Gateway (192.168.0.67) - Potential VM Host?

The R7000 device has extensive VPN capabilities (IPsec, IKE) and could potentially:
- Route to VM subnets via VPN tunnels
- Host VMs on its internal storage
- Act as a VLAN gateway for isolated VM networks

**Recommendation:** Access R7000 web interface (if available via non-standard ports) to check for VM hosting features.

### Updated Device Count (Final)

| Network | Original | After Deep Scan | Status Summary |
|---------|----------|-----------------|----------------|
| 192.168.0.0/24 | 10 | **13** | 10 active + 3 identified mystery devices |
| 192.168.50.0/24 | 1 | 1 | Router interface |
| 192.168.100.0/24 | 1 | 1 | Router interface (management off) |
| 172.17.0.0/16 | 1 | 1 | Docker bridge |
| Tailscale | 6 | 6 | Overlay network |
| **TOTAL** | **19** | **22** | **+3 mystery clients identified** |

### Mystery Client Classification

| Status | Devices |
|--------|---------|
| **Active & Identified** | 192.168.0.131 (Apple DNS-SD Proxy) |
| **Active but Unknown** | 192.168.0.59, 192.168.0.158 |
| **Offline/Sleeping** | 192.168.0.142, 192.168.0.182 |

### Power State Assessment

Based on deep scan behavior analysis:

- **Powered On but Silent**: 192.168.0.158 (IoT device, no user services)
- **Sleep/Wake Cycling**: 192.168.0.59 (mobile device, ARP disappeared then returned)
- **Powered Off/Disconnected**: 192.168.0.142, 192.168.0.182 (no response at all)
- **Always-On Service**: 192.168.0.131 (Apple DNS proxy actively serving requests)

---

## WiFi Network Scan Results (2026-04-20)

### Visible Wireless Networks

| SSID | BSSID | Channel | Frequency | Signal | Security | Status |
|------|-------|---------|-----------|--------|----------|--------|
| **Mags House** | C8:C7:50:F5:CA:1D | 149 | 5.745 GHz | **100%** (-27 dBm) | WPA2 | ✅ Connected |

### Connection Details

| Attribute | Value |
|-----------|-------|
| **Interface** | wlP1p1s0 |
| **Client MAC** | dc:4a:9e:de:a8:fe |
| **Current Band** | 5 GHz (802.11ac/ax) |
| **Channel Width** | 80 MHz |
| **TX Power** | 7.00 dBm |
| **Link Quality** | 70/70 (excellent) |
| **Data Rate** | 540 Mbit/s |

### Radio Capabilities

- **Supported Bands**: 2.4 GHz + 5 GHz
- **Total Channels**: 32
  - 2.4 GHz: Channels 1-13 (2.412-2.472 GHz)
  - 5 GHz: Channels 36-165 (5.18-5.825 GHz)
- **Current**: 5GHz @ 5745 MHz (Channel 149, 80MHz width)

### Analysis

- **Only one network visible** in current location
- **No guest networks** or neighboring SSIDs detected
- **Signal strength**: Excellent (-27 dBm indicates very close proximity to AP)
- **BSSID correlation**: C8:C7:50:F5:CA:1D matches the Motorola MG8702 router at 192.168.0.1
- **No hidden networks** detected in 2.4GHz or 5GHz bands

### WiFi Topology Relationship

```
Internet
    │
    ▼
[Motorola MG8702 Router]
  192.168.0.1 ─┬─ Ethernet/Wired devices
               │
               └── WiFi Access Point (wlan)
                    │
                    ├── 5GHz: Channel 149 (5745 MHz)
                    │   └── wlP1p1s0 (Jetson) ★ CONNECTED
                    │       MAC: dc:4a:9e:de:a8:fe
                    │       Rate: 540 Mbps
                    │
                    └── 2.4GHz: Available but unused
                        └── (No devices on 2.4GHz band)
```

---

## OpenClaw Systems with Telegram Integration (2026-04-20)

### OpenClaw Server (Tailscale)

| Attribute | Value |
|-----------|-------|
| **Server IP** | 100.92.6.101 |
| **Hostname** | thinkstationpgx-9c48.tail2a3b45.ts.net |
| **Web Interface** | http://100.92.6.101 |
| **Documentation** | http://100.92.6.101/docs/telegram_setup.md |
| **Status** | ⚠️ Configured but inactive (invalid bot token) |
| **Services** | HTTP (80), Alt-HTTP (8080), SSH (22), OpenClaw (18789) |

### Telegram Integration Status

| Component | Status | Details |
|-----------|--------|---------|
| Bot token configured | ✅ Yes | Stored in `~/.openclaw/openclaw.json` |
| Gateway plugin enabled | ✅ Yes | `plugins.entries.telegram.enabled: true` |
| Channel enabled | ✅ Yes | `channels.telegram.enabled: true` |
| DM policy | `pairing` | Users must pair before chatting |
| Group policy | `allowlist` | Groups must be explicitly allowed |
| Network reachability | ✅ Fixed | DNS-bypass proxy on `127.0.0.1:18788` |
| **Bot token validity** | ❌ **INVALID** | Returns 401 Unauthorized |
| Pairing | ❌ Blocked | Cannot pair until token fixed |

### Network Bypass Architecture

The OpenClaw server cannot reach Telegram API directly due to network interception:

```
Normal DNS:  api.telegram.org  →  10.122.11.69 (FAKE - intercepted)
Real IP:     api.telegram.org  →  149.154.167.99 (Actual Telegram)

Solution: Local DNS-bypass Proxy
├── File: ~/.openclaw/proxy/telegram-proxy.mjs
├── Listen: http://127.0.0.1:18788
├── Service: openclaw-telegram-proxy.service (systemd user)
└── Function: Routes api.telegram.org → 149.154.167.99:443
```

### Files and Locations

| File | Purpose |
|------|---------|
| `~/.openclaw/openclaw.json` | Main configuration with bot token |
| `~/.openclaw/proxy/telegram-proxy.mjs` | DNS-bypass proxy script |
| `~/.config/systemd/user/openclaw-telegram-proxy.service` | Systemd service unit |
| `/docs/telegram_setup.md` | Full setup documentation |

### How to Activate

**Step 1: Regenerate Bot Token**
1. Open Telegram, search **@BotFather**
2. Send `/mybots` → select bot → **API Token** → **Revoke**
3. Save new token

**Step 2: Update Configuration**
```bash
openclaw channels add --channel telegram --token "NEW_TOKEN"
```

**Step 3: Start Services**
```bash
systemctl --user start openclaw-telegram-proxy
openclaw gateway start
```

**Step 4: Pair Account**
1. DM the bot on Telegram
2. `openclaw pairing list telegram`
3. `openclaw pairing approve telegram <CODE>`

### Useful Commands

```bash
# Check channel status

## 🔔 Network Scan Alert - 2026-04-21 20:59:09

**1 new device(s) discovered!**

### New Device Discovered: 192.168.0.81

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.81 |
| **Hostname** | Watch.MG8702 |
| **MAC Address** | fa:5b:a6:ab:1a:7f |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-21 20:59:09 |

**Access Methods:**
- No common services detected (may be client device)

---



## 🔔 Network Scan Alert - 2026-04-20 18:35:03

**1 new device(s) discovered!**

### New Device Discovered: 192.168.0.49

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.49 |
| **Hostname** | iPhone.MG8702 |
| **MAC Address** | e6:40:e4:dc:e1:f0 |
| **Open Ports** | None detected |
| **Device Type** | Mobile Phone |
| **Discovered** | 2026-04-20 18:35:03 |

**Access Methods:**
- No common services detected (may be client device)

---



## 🔔 Network Scan Alert - 2026-04-20 16:33:02

**1 new device(s) discovered!**

### New Device Discovered: 192.168.0.192

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.192 |
| **Hostname** | 25RokuStreamingStickPlus.MG8702 |
| **MAC Address** | d4:be:dc:ed:dd:90 |
| **Open Ports** | None detected |
| **Device Type** | Streaming Device |
| **Discovered** | 2026-04-20 16:33:02 |

**Access Methods:**
- No common services detected (may be client device)

---



## 🔔 Network Scan Alert - 2026-04-20 15:32:37

**13 new device(s) discovered!**

### New Device Discovered: 192.168.0.1

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.1 |
| **Hostname** | home.MG8702 |
| **MAC Address** | 30:03:c8:4a:0a:84 |
| **Open Ports** | 80, 443, 5000 |
| **Device Type** | Web Device |
| **Discovered** | 2026-04-20 15:32:26 |

**Access Methods:**
- HTTP: http://192.168.0.1
- HTTPS: https://192.168.0.1

---

### New Device Discovered: 192.168.0.15

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.15 |
| **Hostname** | INUNZIATA-5ZNHG.MG8702 |
| **MAC Address** | 30:05:05:72:30:35 |
| **Open Ports** | 445 |
| **Device Type** | Windows/Samba Share |
| **Discovered** | 2026-04-20 15:32:34 |

**Access Methods:**
- SMB: `smb://192.168.0.15`

---

### New Device Discovered: 192.168.0.59

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.59 |
| **Hostname** | — |
| **MAC Address** | 8a:33:76:dd:0b:cb |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:32:35 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.127

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.127 |
| **Hostname** | DESKTOP-HN6QL1F.MG8702 |
| **MAC Address** | 70:8b:cd:7c:f4:54 |
| **Open Ports** | 445 |
| **Device Type** | Windows/Samba Share |
| **Discovered** | 2026-04-20 15:32:35 |

**Access Methods:**
- SMB: `smb://192.168.0.127`

---

### New Device Discovered: 192.168.0.131

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.131 |
| **Hostname** | iPhone.MG8702 |
| **MAC Address** | 06:4d:1c:2e:e9:ab |
| **Open Ports** | None detected |
| **Device Type** | Mobile Phone |
| **Discovered** | 2026-04-20 15:32:35 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.135

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.135 |
| **Hostname** | motorola-edge-2022.MG8702 |
| **MAC Address** | 8a:13:29:33:8a:2d |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:32:35 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.143

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.143 |
| **Hostname** | NPI8ABCE2.MG8702 |
| **MAC Address** | 30:03:c8:4a:0a:84 |
| **Open Ports** | 80, 443, 631, 8080 |
| **Device Type** | Printer/Scanner |
| **Discovered** | 2026-04-20 15:32:35 |

**Access Methods:**
- HTTP: http://192.168.0.143
- HTTPS: https://192.168.0.143
- CUPS: http://192.168.0.143:631
- HTTP Alt: http://192.168.0.143:8080

---

### New Device Discovered: 192.168.0.158

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.158 |
| **Hostname** | device.MG8702 |
| **MAC Address** | 44:61:32:c8:42:f0 |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:32:35 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.197

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.197 |
| **Hostname** | yahboom.MG8702 |
| **MAC Address** | — |
| **Open Ports** | 22, 631, 5900 |
| **Device Type** | Printer/Scanner |
| **Discovered** | 2026-04-20 15:32:36 |

**Access Methods:**
- SSH: `ssh user@192.168.0.197`
- CUPS: http://192.168.0.197:631
- VNC: `vncviewer 192.168.0.197:5900`

---

### New Device Discovered: 192.168.0.233

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.233 |
| **Hostname** | RokuUltraB.MG8702 |
| **MAC Address** | d8:31:34:5f:40:b4 |
| **Open Ports** | None detected |
| **Device Type** | Streaming Device |
| **Discovered** | 2026-04-20 15:32:36 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.246

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.246 |
| **Hostname** | — |
| **MAC Address** | 20:6e:f1:9f:9f:a0 |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:32:36 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.50.1

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.50.1 |
| **Hostname** | — |
| **MAC Address** | — |
| **Open Ports** | 80, 443, 5000 |
| **Device Type** | Web Device |
| **Discovered** | 2026-04-20 15:32:36 |

**Access Methods:**
- HTTP: http://192.168.50.1
- HTTPS: https://192.168.50.1

---

### New Device Discovered: 192.168.100.1

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.100.1 |
| **Hostname** | — |
| **MAC Address** | — |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:32:37 |

**Access Methods:**
- No common services detected (may be client device)

---



## 🔔 Network Scan Alert - 2026-04-20 15:31:43

**13 new device(s) discovered!**

### New Device Discovered: 192.168.0.1

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.1 |
| **Hostname** | home.MG8702 |
| **MAC Address** | 30:03:c8:4a:0a:84 |
| **Open Ports** | 80, 443, 5000 |
| **Device Type** | Web Device |
| **Discovered** | 2026-04-20 15:31:32 |

**Access Methods:**
- HTTP: http://192.168.0.1
- HTTPS: https://192.168.0.1

---

### New Device Discovered: 192.168.0.15

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.15 |
| **Hostname** | INUNZIATA-5ZNHG.MG8702 |
| **MAC Address** | 30:05:05:72:30:35 |
| **Open Ports** | 445 |
| **Device Type** | Windows/Samba Share |
| **Discovered** | 2026-04-20 15:31:40 |

**Access Methods:**
- SMB: `smb://192.168.0.15`

---

### New Device Discovered: 192.168.0.59

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.59 |
| **Hostname** | — |
| **MAC Address** | 8a:33:76:dd:0b:cb |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:31:41 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.127

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.127 |
| **Hostname** | DESKTOP-HN6QL1F.MG8702 |
| **MAC Address** | 70:8b:cd:7c:f4:54 |
| **Open Ports** | 445 |
| **Device Type** | Windows/Samba Share |
| **Discovered** | 2026-04-20 15:31:41 |

**Access Methods:**
- SMB: `smb://192.168.0.127`

---

### New Device Discovered: 192.168.0.131

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.131 |
| **Hostname** | iPhone.MG8702 |
| **MAC Address** | 06:4d:1c:2e:e9:ab |
| **Open Ports** | None detected |
| **Device Type** | Mobile Phone |
| **Discovered** | 2026-04-20 15:31:41 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.135

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.135 |
| **Hostname** | motorola-edge-2022.MG8702 |
| **MAC Address** | 8a:13:29:33:8a:2d |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:31:41 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.143

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.143 |
| **Hostname** | NPI8ABCE2.MG8702 |
| **MAC Address** | 30:03:c8:4a:0a:84 |
| **Open Ports** | 80, 443, 631, 8080 |
| **Device Type** | Printer/Scanner |
| **Discovered** | 2026-04-20 15:31:42 |

**Access Methods:**
- HTTP: http://192.168.0.143
- HTTPS: https://192.168.0.143
- CUPS: http://192.168.0.143:631
- HTTP Alt: http://192.168.0.143:8080

---

### New Device Discovered: 192.168.0.158

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.158 |
| **Hostname** | device.MG8702 |
| **MAC Address** | 44:61:32:c8:42:f0 |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:31:42 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.197

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.197 |
| **Hostname** | yahboom.MG8702 |
| **MAC Address** | — |
| **Open Ports** | 22, 631, 5900 |
| **Device Type** | Printer/Scanner |
| **Discovered** | 2026-04-20 15:31:42 |

**Access Methods:**
- SSH: `ssh user@192.168.0.197`
- CUPS: http://192.168.0.197:631
- VNC: `vncviewer 192.168.0.197:5900`

---

### New Device Discovered: 192.168.0.233

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.233 |
| **Hostname** | RokuUltraB.MG8702 |
| **MAC Address** | d8:31:34:5f:40:b4 |
| **Open Ports** | None detected |
| **Device Type** | Streaming Device |
| **Discovered** | 2026-04-20 15:31:42 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.0.246

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.0.246 |
| **Hostname** | — |
| **MAC Address** | 20:6e:f1:9f:9f:a0 |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:31:42 |

**Access Methods:**
- No common services detected (may be client device)

---

### New Device Discovered: 192.168.50.1

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.50.1 |
| **Hostname** | — |
| **MAC Address** | — |
| **Open Ports** | 80, 443, 5000 |
| **Device Type** | Web Device |
| **Discovered** | 2026-04-20 15:31:42 |

**Access Methods:**
- HTTP: http://192.168.50.1
- HTTPS: https://192.168.50.1

---

### New Device Discovered: 192.168.100.1

| Attribute | Value |
|-----------|-------|
| **IP Address** | 192.168.100.1 |
| **Hostname** | — |
| **MAC Address** | — |
| **Open Ports** | None detected |
| **Device Type** | Unknown |
| **Discovered** | 2026-04-20 15:31:43 |

**Access Methods:**
- No common services detected (may be client device)

---


openclaw channels status

# View gateway logs
openclaw logs --follow

# Check proxy service
systemctl --user status openclaw-telegram-proxy

# Run diagnostics
openclaw doctor
```

### PicoClaw (Local Instance)

**Location**: `~/Documents/picoclaw/`

PicoClaw is a lightweight Go-based OpenClaw implementation also supporting Telegram:

| File | Purpose |
|------|---------|
| `pkg/channels/telegram.go` | Telegram channel implementation |
| `pkg/channels/telegram_commands.go` | Bot command handlers |

**Status**: Installed but not configured for Telegram on this host.

### Summary

- **OpenClaw Server (100.92.6.101)**: Fully configured for Telegram but **inactive** due to expired bot token
- **Network workaround**: DNS-bypass proxy successfully routes around network interception
- **Action required**: Regenerate bot token via @BotFather to activate
- **Local PicoClaw**: Available in `~/Documents/picoclaw/` as alternative implementation

---

## Security Exposure Audit (2026-04-20)

### High-Risk Exposures

| Device IP | Open Ports | Risk Summary |
|-----------|------------|--------------|
| `192.168.0.15` | 135, 139, 445, 3389, 5985 | SMB + RDP + WinRM exposed on LAN (high lateral movement risk) |
| `192.168.0.127` | 135, 139, 445, 3389 | SMB + RDP exposed on LAN |
| `192.168.0.197` | 22, 111, 631, 3389, 5900 | SSH + RPC + RDP/VNC exposed; broad remote-access surface |
| `100.71.191.72` | 22, 5900 | SSH + VNC exposed over Tailscale |
| `100.78.64.7` | 22, 5900 | SSH + VNC exposed over Tailscale |

### Exposed Web/Admin Interfaces

| Device IP | Ports | Findings |
|-----------|-------|----------|
| `192.168.0.143` | 80, 8080 | Printer admin pages reachable (HTTP 200) |
| `100.92.6.101` | 80, 8080 | OpenClaw web interface reachable (HTTP 200) |
| `100.100.100.100` | 53, 80, 8080 | Tailscale local service endpoint reachable (expected) |
| `192.168.0.1` | 53, 80, 443, 5000 | Router admin/services exposed on LAN |
| `192.168.50.1` | 53, 80, 443, 5000 | Router admin/services exposed on routed subnet |

### Notes on Default Access

- This audit performed safe exposure checks only (ports, banners, HTTP status and content reachability).
- No credential brute-forcing or password guessing was performed.
- “Default access” can only be confirmed with explicit auth tests against each service.

### Recommended Next Checks

1. Validate SMB guest/null-session access on `192.168.0.15` and `192.168.0.127`.
2. Verify authentication requirements for printer/admin pages on `192.168.0.143`.
3. Confirm RDP NLA and SSH password-policy hardening on exposed hosts.
4. Restrict unnecessary LAN/Tailscale-exposed admin ports where possible.

---

## 📊 Scan History

| Scan Time | New Devices | Online | Total Known |
|-----------|-------------|--------|-------------|
| 2026-04-22 20:38:42 | 0 | 14 | 39 |
| 2026-04-22 20:16:11 | 0 | 14 | 39 |
| 2026-04-22 20:07:42 | 0 | 14 | 39 |
| 2026-04-22 19:38:21 | 0 | 14 | 39 |
| 2026-04-22 19:07:08 | 0 | 13 | 39 |
| 2026-04-22 18:34:42 | 0 | 12 | 39 |
| 2026-04-22 18:03:42 | 0 | 13 | 39 |
| 2026-04-22 17:32:42 | 0 | 13 | 39 |
| 2026-04-22 17:01:42 | 0 | 13 | 39 |
| 2026-04-22 16:30:42 | 0 | 13 | 39 |
| 2026-04-22 16:09:29 | 0 | 13 | 39 |
| 2026-04-22 15:31:02 | 0 | 9 | 38 |
| 2026-04-22 15:00:18 | 0 | 9 | 38 |
| 2026-04-22 14:59:27 | 0 | 9 | 38 |
| 2026-04-22 14:16:02 | 0 | 9 | 38 |
| 2026-04-22 13:15:02 | 0 | 9 | 38 |
| 2026-04-22 12:14:02 | 0 | 9 | 38 |
| 2026-04-22 11:13:02 | 0 | 9 | 38 |
| 2026-04-22 10:12:02 | 0 | 8 | 38 |
| 2026-04-22 09:11:02 | 0 | 9 | 38 |
| 2026-04-22 08:10:02 | 0 | 9 | 38 |
| 2026-04-22 07:09:02 | 0 | 8 | 38 |
| 2026-04-22 06:08:02 | 0 | 8 | 38 |
| 2026-04-22 05:07:02 | 0 | 9 | 38 |
| 2026-04-22 04:06:02 | 0 | 10 | 38 |
| 2026-04-22 03:05:02 | 0 | 9 | 38 |
| 2026-04-22 02:04:02 | 0 | 10 | 38 |
| 2026-04-22 01:03:02 | 0 | 10 | 38 |
| 2026-04-22 00:02:02 | 0 | 9 | 38 |
| 2026-04-21 23:01:02 | 0 | 10 | 38 |
| 2026-04-21 22:00:02 | 0 | 12 | 38 |
| 2026-04-21 20:59:09 | 1 | 13 | 38 |
| 2026-04-21 19:58:02 | 0 | 12 | 37 |
| 2026-04-21 18:57:02 | 0 | 12 | 37 |
| 2026-04-21 17:56:02 | 0 | 12 | 37 |
| 2026-04-21 16:55:02 | 0 | 12 | 37 |
| 2026-04-21 15:54:02 | 0 | 11 | 37 |
| 2026-04-21 14:53:02 | 0 | 11 | 37 |
| 2026-04-21 13:52:02 | 0 | 11 | 37 |
| 2026-04-21 12:51:02 | 0 | 11 | 37 |
| 2026-04-21 11:50:02 | 0 | 11 | 37 |
| 2026-04-21 11:42:48 | 0 | 11 | 37 |
| 2026-04-21 11:36:32 | 0 | 11 | 37 |
| 2026-04-21 10:49:02 | 0 | 10 | 37 |
| 2026-04-21 10:08:07 | 0 | 12 | 37 |
| 2026-04-21 10:05:17 | 0 | 12 | 37 |
| 2026-04-21 09:48:02 | 0 | 12 | 37 |
| 2026-04-21 08:47:22 | 0 | 12 | 37 |
| 2026-04-21 07:47:02 | 0 | 11 | 37 |
| 2026-04-21 07:01:43 | 0 | 11 | 37 |
| 2026-04-21 06:57:44 | 0 | 12 | 37 |
| 2026-04-21 06:47:02 | 0 | 11 | 37 |
| 2026-04-21 06:46:46 | 0 | 11 | 37 |
| 2026-04-21 05:46:02 | 0 | 11 | 37 |
| 2026-04-21 04:45:02 | 0 | 11 | 37 |
| 2026-04-21 03:44:02 | 0 | 11 | 37 |
| 2026-04-21 02:43:02 | 0 | 11 | 37 |
| 2026-04-21 01:42:02 | 0 | 11 | 37 |
| 2026-04-21 00:41:02 | 0 | 11 | 37 |
| 2026-04-20 23:40:02 | 0 | 11 | 37 |
| 2026-04-20 22:39:02 | 0 | 12 | 37 |
| 2026-04-20 21:38:02 | 0 | 11 | 37 |
| 2026-04-20 20:37:02 | 0 | 12 | 37 |
| 2026-04-20 19:36:02 | 0 | 12 | 37 |
| 2026-04-20 18:35:03 | 1 | 14 | 37 |
| 2026-04-20 17:34:02 | 0 | 13 | 36 |
| 2026-04-20 16:33:02 | 1 | 14 | 36 |
| 2026-04-20 15:36:51 | 0 | 13 | 35 |


*Last updated: 2026-04-22 20:38:42*

---

## Recent Online/Offline Changes (Since Last Scan)

This table shows only devices that changed state (came online or went offline) between scans. Hostnames are included where known.

| Status       | Devices                          | Scan Time           | Notes |
|--------------|----------------------------------|---------------------|-------|
| **Online** | —                                 | None                         | 2026-04-21 07:01:43 | No devices came online in the latest scan. |
| **Offline**| —                                 | None                         | 2026-04-21 07:01:43 | No devices went offline in the latest scan. |
| **Online** | esp32s3-9F9FA0.MG8702             | ESP32-S3 IoT (192.168.0.246) | 2026-04-20 18:35:03 | New IoT device joined the LAN. |
| **Online** | device.MG8702                     | Unknown Client (192.168.0.158) | 2026-04-20 16:33:02 | New client device discovered. |

*This table is focused exclusively on state changes. The full scan history is in the section above.*

---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---



---

## 🔬 Deep Scan Results - 2026-04-22 14:32:14

**Scanned 31 devices with full Nmap service/OS detection.**

### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 14:32:14. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 12:31:42. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 11:31:30. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 10:29:28. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 09:31:48. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 08:32:34. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 07:30:35. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 06:30:58. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 05:31:20. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 04:31:43. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 03:30:33. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 02:31:41. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 01:31:10. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-22 00:31:41. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 23:31:41. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 22:33:28. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 21:34:38. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 20:33:40. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 19:33:24. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- **100.79.216.111**: TCP [5000, 7000, 41009, 51403] | UDP [] | OS: Unknown

*Deep scan completed at 2026-04-21 18:33:58. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- **192.168.0.15**: TCP [135, 139, 445, 3389, 9595, 33354] | UDP [] | OS: Unknown

*Deep scan completed at 2026-04-21 17:32:57. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 16:33:56. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 15:32:38. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 14:32:06. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 13:33:33. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 12:32:31. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- **149.154.167.99**: TCP [80, 443] | UDP [] | OS: Unknown
- **192.168.50.1**: TCP [53, 80, 443, 5000] | UDP [] | OS: Unknown

*Deep scan completed at 2026-04-21 11:52:12. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- **149.154.167.99**: TCP [80, 443] | UDP [] | OS: Unknown

*Deep scan completed at 2026-04-21 11:41:56. Full JSON results in `deep_scan_results.json`.*
### Key Findings:
- No open ports discovered in this run (likely filtered/host firewalls).

*Deep scan completed at 2026-04-21 11:25:46. Full JSON results in `deep_scan_results.json`.*
### Key Findings:

*Deep scan completed at 2026-04-21 10:29:53. Full JSON results in `deep_scan_results.json`.*

---

## ⚡ Online Detector Enrichment

Updated: 2026-04-22 19:38:21

| IP | Hostname | MAC | Status | Open Ports | Access Method | Identity |
|-----|----------|-----|--------|------------|---------------|----------|
| 100.79.216.111 | erics-macbook-pro.tail2a3b45.ts.net | — | Online | None | No known access | Unknown |