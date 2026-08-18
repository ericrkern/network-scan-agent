#!/usr/bin/env python3
"""Lightweight per-host probe when nmap is unavailable (macOS dev, minimal hosts)."""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Tuple

# High-value ports for identity, function, and threat analysis.
PROBE_TCP_PORTS: List[int] = sorted(
    {
        21, 22, 23, 53, 80, 81, 88, 135, 139, 161, 389, 443, 445, 515, 548, 554,
        587, 631, 1883, 3000, 32400, 3389, 3689, 5000, 5353, 5357, 5480, 5900,
        7000, 8000, 8008, 8080, 8123, 8443, 8554, 8883, 8888, 9000, 9100, 9443,
        10443, 37777, 49152, 62078,
    }
)

_HTTP_PORTS = {80, 81, 8080, 8008, 8443, 443, 5000, 3000}


def _tcp_open(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_tcp_ports(ip: str, ports: List[int] | None = None, *, workers: int = 24) -> List[int]:
    targets = ports or PROBE_TCP_PORTS
    open_ports: List[int] = []

    def check(port: int) -> Tuple[int, bool]:
        return port, _tcp_open(ip, port)

    with ThreadPoolExecutor(max_workers=min(workers, len(targets) or 1)) as pool:
        futures = [pool.submit(check, p) for p in targets]
        for fut in as_completed(futures):
            port, ok = fut.result()
            if ok:
                open_ports.append(port)
    return sorted(set(open_ports))


def _read_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(512)
            return data.decode("utf-8", errors="replace").strip().split("\n")[0][:200]
    except OSError:
        return ""


def _http_probe(ip: str, port: int, use_tls: bool = False) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=1.5) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as sock:
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                    data = sock.recv(4096).decode("utf-8", errors="replace")
        else:
            with socket.create_connection((ip, port), timeout=1.5) as sock:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                data = sock.recv(4096).decode("utf-8", errors="replace")
    except OSError:
        return out

    for line in data.split("\r\n")[:20]:
        low = line.lower()
        if low.startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()[:120]
        if low.startswith("www-authenticate:"):
            out["auth"] = line.split(":", 1)[1].strip()[:80]
    title = re.search(r"<title[^>]*>([^<]+)</title>", data, re.I)
    if title:
        out["http_title"] = title.group(1).strip()[:120]
    return out


def probe_services(ip: str, open_ports: List[int]) -> Dict[str, str]:
    services: Dict[str, str] = {}
    for port in open_ports:
        if port in _HTTP_PORTS:
            meta = _http_probe(ip, port, use_tls=port in (443, 8443))
            parts = []
            if meta.get("http_title"):
                parts.append(f'title="{meta["http_title"]}"')
            if meta.get("server"):
                parts.append(f'server={meta["server"]}')
            if meta.get("auth"):
                parts.append(f'auth={meta["auth"]}')
            services[f"{port}/tcp"] = "http " + " ".join(parts) if parts else "http open"
        elif port == 22:
            banner = _read_banner(ip, 22)
            services[f"{port}/tcp"] = banner or "ssh open"
        elif port == 23:
            banner = _read_banner(ip, 23)
            services[f"{port}/tcp"] = banner or "telnet open"
        elif port == 445:
            services[f"{port}/tcp"] = "microsoft-ds open"
        elif port == 554:
            services[f"{port}/tcp"] = "rtsp open"
        elif port == 1883:
            services[f"{port}/tcp"] = "mqtt open"
        elif port == 161:
            services[f"{port}/udp"] = "snmp (not probed without nmap)"
        else:
            services[f"{port}/tcp"] = "open"
    return services


def infer_os_from_services(services: Dict[str, str]) -> str:
    blob = " ".join(services.values()).lower()
    if "openssh" in blob or "ssh" in blob:
        if "ubuntu" in blob:
            return "Linux (Ubuntu hint)"
        if "darwin" in blob:
            return "macOS (SSH hint)"
        return "Linux/Unix (SSH)"
    if "microsoft-iis" in blob or "microsoft-ds" in blob:
        return "Windows (service hint)"
    if "nginx" in blob:
        return "Embedded/Linux (nginx)"
    if "hikvision" in blob or "dahua" in blob:
        return "Embedded camera firmware"
    if "nest" in blob or "google" in blob:
        return "Google/Nest embedded"
    return "Unknown"


def probe_host(ip: str) -> Dict[str, Any]:
    """Return deep_scan-compatible result using socket probes plus LAN inspectors."""
    scan_time = datetime.now().isoformat()
    open_tcp = scan_tcp_ports(ip)
    services = probe_services(ip, open_tcp)
    try:
        from host_inspect import inspect_host

        inspect = inspect_host(ip, open_tcp)
    except Exception:
        inspect = {"tools": ["tcp-connect"], "findings": [], "ip": ip}

    extra = [p for p in (inspect.get("extra_open_ports") or []) if isinstance(p, int)]
    if extra:
        for port in extra:
            if port not in open_tcp:
                open_tcp.append(port)
        services.update(probe_services(ip, extra))
    open_tcp = sorted(set(open_tcp))
    os_guess = inspect.get("os_guess") or infer_os_from_services(services)
    hostname = inspect.get("hostname") or "—"
    host_up = bool(open_tcp or inspect.get("reachable") or inspect.get("mac") or inspect.get("hostname"))
    if inspect.get("findings") and not open_tcp:
        services["inspect"] = "; ".join(inspect["findings"][:4])

    return {
        "ip": ip,
        "hostname": hostname,
        "os": os_guess,
        "ports": open_tcp,
        "tcp_ports": open_tcp,
        "udp_ports": [],
        "services": services,
        "host_up": host_up,
        "scan_time": scan_time,
        "probe_engine": "lightweight+inspect",
        "inspect": inspect,
        "status": "success" if host_up else "no_response",
        "error": None if host_up else "Host did not respond to ping, TCP, mDNS, SNMP, or UPnP probes",
    }
