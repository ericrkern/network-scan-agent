#!/usr/bin/env python3
"""
Deep Network Scanner (Aggressive Edition)

Performs multi-stage scanning:
1) Fast TCP discovery scan (top ports)
2) Full TCP scan on responsive hosts
3) UDP probe scan on responsive hosts
4) Detailed service/script scan on discovered open ports
5) Optional OS detection when running as root
"""

import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Configuration
BASE_DIR = Path(__file__).resolve().parent
DEVICES_FILE = str(BASE_DIR / "devices.md")
CACHE_FILE = str(BASE_DIR / ".seen_devices.json")
OUTPUT_FILE = str(BASE_DIR / "deep_scan_results.json")

COMMON_TCP_PORTS = [22, 53, 80, 135, 139, 443, 445, 631, 8080, 5900, 5000, 3000, 1883, 8060, 18789]
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 1900, 5353, 5060, 500, 4500]


def is_valid_host_ip(ip: str) -> bool:
    """Filter obvious non-host addresses and invalid entries."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    # Exclude loopback, multicast, broadcast-like, and /24 network addresses.
    if ip.startswith(("127.", "0.", "224.", "239.", "255.")):
        return False
    if octets[-1] in (0, 255):
        return False
    return True

def load_known_devices():
    """Load all devices from the cache and devices.md"""
    devices = set()
    
    # From JSON cache
    try:
        if Path(CACHE_FILE).exists():
            with open(CACHE_FILE, 'r') as f:
                cache = json.load(f)
                devices.update(cache.keys())
    except Exception as e:
        print(f"Warning: Could not read cache: {e}")
    
    # From devices.md
    try:
        with open(DEVICES_FILE, 'r') as f:
            content = f.read()
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            found_ips = re.findall(ip_pattern, content)
            devices.update(found_ips)
    except Exception as e:
        print(f"Warning: Could not read devices.md: {e}")
    
    # Filter non-host entries aggressively.
    valid_devices = {ip for ip in devices if is_valid_host_ip(ip)}
    return sorted(list(valid_devices))


def run_cmd(cmd: List[str], timeout: int = 90) -> Tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout or "", result.stderr or ""


def parse_open_ports(nmap_output: str) -> Tuple[List[int], List[int], Dict[str, str]]:
    tcp_ports: List[int] = []
    udp_ports: List[int] = []
    services: Dict[str, str] = {}

    for line in nmap_output.splitlines():
        line = line.strip()
        # Example: "22/tcp open  ssh OpenSSH 8.9p1 ..."
        m = re.match(r"^(\d+)\/(tcp|udp)\s+open\s+(.+)$", line)
        if not m:
            continue
        port = int(m.group(1))
        proto = m.group(2)
        svc = m.group(3).strip()
        if proto == "tcp":
            tcp_ports.append(port)
        else:
            udp_ports.append(port)
        services[f"{port}/{proto}"] = svc

    return sorted(set(tcp_ports)), sorted(set(udp_ports)), services


def extract_os_guess(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("OS details:"):
            return s.split(":", 1)[1].strip()
        if s.startswith("Aggressive OS guesses:"):
            return s.split(":", 1)[1].strip()
        if s.startswith("Service Info:"):
            return s.split(":", 1)[1].strip()
    return "Unknown"


def run_nmap_deep_scan(ip: str) -> Dict[str, Any]:
    """Run aggressive multi-stage scan on one IP."""
    print(f"  🔍 Deep scanning {ip}...", end=" ")

    scan_time = datetime.now().isoformat()
    aggregate_stdout: List[str] = []
    aggregate_stderr: List[str] = []
    service_details: Dict[str, str] = {}
    open_tcp: List[int] = []
    open_udp: List[int] = []
    os_guess = "Unknown"
    host_up = False

    try:
        # Stage 1: host discovery ping scan first (fast gate).
        cmd_ping = ["nmap", "-n", "-sn", "--host-timeout", "8s", ip]
        rc_ping, out_ping, err_ping = run_cmd(cmd_ping, timeout=20)
        aggregate_stdout.append(out_ping)
        aggregate_stderr.append(err_ping)
        if "Host is up" in out_ping:
            host_up = True

        # Stage 2: quick TCP discovery.
        cmd_quick = [
            "nmap", "-n", "-Pn", "-sT", "--open", "--reason", "-T4",
            "--top-ports", "300", "--host-timeout", "20s", ip
        ]
        rc, out, err = run_cmd(cmd_quick, timeout=45)
        aggregate_stdout.append(out)
        aggregate_stderr.append(err)

        if rc != 0 and not out:
            print("⚠️ quick-scan failed")
            return {
                "ip": ip,
                "hostname": "—",
                "os": "Unknown",
                "ports": [],
                "tcp_ports": [],
                "udp_ports": [],
                "services": {},
                "scan_time": scan_time,
                "status": "error",
                "error": (err.strip() or f"nmap exited with {rc}")[:400],
            }

        if "Host is up" in out:
            host_up = True

        t_ports, _, services = parse_open_ports(out)
        open_tcp.extend(t_ports)
        service_details.update(services)

        # Stage 3: full TCP/UDP only when host actually responds OR quick scan found ports.
        if host_up or open_tcp:
            cmd_full_tcp = [
                "nmap", "-n", "-Pn", "-sT", "--open", "--reason", "-T4",
                "-p-", "--max-retries", "1", "--min-rate", "1500", "--host-timeout", "45s", ip
            ]
            rc2, out2, err2 = run_cmd(cmd_full_tcp, timeout=60)
            aggregate_stdout.append(out2)
            aggregate_stderr.append(err2)
            t2, _, svc2 = parse_open_ports(out2)
            open_tcp.extend(t2)
            service_details.update(svc2)

            # Stage 3: UDP targeted scan for common infra/services.
            udp_arg = ",".join(str(p) for p in COMMON_UDP_PORTS)
            cmd_udp = [
                "nmap", "-n", "-Pn", "-sU", "--open", "--reason", "-T4",
                "--max-retries", "1", "--host-timeout", "30s", "-p", udp_arg, ip
            ]
            rc3, out3, err3 = run_cmd(cmd_udp, timeout=45)
            aggregate_stdout.append(out3)
            aggregate_stderr.append(err3)
            _, u3, svc3 = parse_open_ports(out3)
            open_udp.extend(u3)
            service_details.update(svc3)

        # Stage 4: service fingerprinting/scripts on discovered ports.
        all_ports = sorted(set(open_tcp + open_udp))
        if all_ports:
            detailed_ports = ",".join(str(p) for p in all_ports)
            cmd_detail = [
                "nmap", "-n", "-Pn", "-sV", "--version-all",
                "--script", "default,safe,banner,http-title,ssl-cert,ssh2-enum-algos,smb-os-discovery",
                "-p", detailed_ports, ip
            ]
            rc4, out4, err4 = run_cmd(cmd_detail, timeout=75)
            aggregate_stdout.append(out4)
            aggregate_stderr.append(err4)
            _, _, svc4 = parse_open_ports(out4)
            service_details.update(svc4)
            os_guess = extract_os_guess(out4)

        # Stage 5: optional OS detection if root.
        if os.geteuid() == 0 and (host_up or open_tcp):
            cmd_os = ["nmap", "-n", "-Pn", "-O", "--osscan-guess", ip]
            rc5, out5, err5 = run_cmd(cmd_os, timeout=90)
            aggregate_stdout.append(out5)
            aggregate_stderr.append(err5)
            os_guess_root = extract_os_guess(out5)
            if os_guess_root != "Unknown":
                os_guess = os_guess_root

        combined_stdout = "\n".join(aggregate_stdout)
        combined_stderr = "\n".join(aggregate_stderr).strip()

        result = {
            "ip": ip,
            "hostname": "—",
            "os": os_guess,
            "ports": sorted(set(open_tcp + open_udp)),  # backward-compatible for dashboard
            "tcp_ports": sorted(set(open_tcp)),
            "udp_ports": sorted(set(open_udp)),
            "services": service_details,
            "host_up": host_up,
            "scan_time": scan_time,
            "raw_output_length": len(combined_stdout),
            "stderr_tail": combined_stderr[-500:] if combined_stderr else "",
            "status": "success" if (host_up or open_tcp or open_udp) else "no_response",
        }

        print(
            f"✅ tcp:{len(result['tcp_ports'])} udp:{len(result['udp_ports'])} "
            f"os:{(os_guess[:28] + '...') if len(os_guess) > 28 else os_guess}"
        )
        return result

    except subprocess.TimeoutExpired:
        print("⏰ timeout")
        return {"ip": ip, "status": "timeout", "error": "Scan timed out"}
    except Exception as e:
        print(f"❌ {e}")
        return {"ip": ip, "status": "error", "error": str(e)}


def run_deep_scan():
    """Perform deep scan on all known devices"""
    print("🚀 Starting Deep Network Analysis")
    print("=" * 60)
    
    devices = load_known_devices()
    print(f"Found {len(devices)} host IPs to scan\n")
    
    results = {}
    start_time = time.time()
    
    for i, ip in enumerate(devices, 1):
        print(f"[{i:2d}/{len(devices)}] ", end="")
        result = run_nmap_deep_scan(ip)
        results[ip] = result
        time.sleep(0.15)  # be polite but faster
    
    duration = time.time() - start_time
    print(f"\n✅ Deep scan completed in {duration:.1f} seconds")
    print(f"   Results saved to {OUTPUT_FILE}")
    
    # Save results
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "devices_scanned": len(devices),
            "results": results
        }, f, indent=2)
    
    # Update devices.md with summary
    update_devices_md_with_deep_results(results)
    
    return results


def update_devices_md_with_deep_results(results):
    """Append deep scan summary to devices.md"""
    try:
        with open(DEVICES_FILE, 'r') as f:
            content = f.read()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        deep_summary = f"""

---

## 🔬 Deep Scan Results - {timestamp}

**Scanned {len(results)} devices with full Nmap service/OS detection.**

### Key Findings:
"""
        
        found = 0
        for ip, data in results.items():
            if data.get("status") in ("success", "no_response"):
                tcp = data.get("tcp_ports", [])
                udp = data.get("udp_ports", [])
                os_info = data.get("os", "Unknown")
                if tcp or udp:
                    found += 1
                    deep_summary += (
                        f"- **{ip}**: TCP {tcp if tcp else '[]'} | UDP {udp if udp else '[]'}"
                        f" | OS: {os_info[:60]}\n"
                    )
        if found == 0:
            deep_summary += "- No open ports discovered in this run (likely filtered/host firewalls).\n"
        
        deep_summary += f"\n*Deep scan completed at {timestamp}. Full JSON results in `deep_scan_results.json`.*\n"
        
        if "## 🔬 Deep Scan Results" in content:
            # Replace existing section
            content = re.sub(r'## 🔬 Deep Scan Results.*?(?=^#|\Z)', deep_summary, content, flags=re.DOTALL | re.MULTILINE)
        else:
            content = content.rstrip() + deep_summary
        
        with open(DEVICES_FILE, 'w') as f:
            f.write(content)
            
        print("   Updated devices.md with deep scan summary")
        
    except Exception as e:
        print(f"   Warning: Could not update devices.md: {e}")


if __name__ == "__main__":
    print("🧪 Network Deep Scanner (Aggressive)")
    print("This run performs quick discovery + full TCP + UDP + service script scans.")
    print("This may take several minutes.\n")
    
    try:
        run_deep_scan()
        print("\n🎉 Deep scan complete! Check the dashboard for updated device details.")
    except KeyboardInterrupt:
        print("\n\n🛑 Scan cancelled by user.")
    except Exception as e:
        print(f"\n💥 Error during deep scan: {e}")
