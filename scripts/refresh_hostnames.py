#!/usr/bin/env python3
"""Resolve hostnames for all cached devices and write results to .seen_devices.json."""

from __future__ import annotations

import concurrent.futures
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_FILE = BASE_DIR / ".seen_devices.json"
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
NMAP_REPORT_RE = re.compile(r"^Nmap scan report for (.+?)(?: \(|$)")


def resolve_getent(ip: str) -> str | None:
    try:
        result = subprocess.run(
            ["getent", "hosts", ip],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.split()
            if len(parts) > 1 and parts[0] == ip:
                name = parts[1].rstrip(".")
                if name and name != ip:
                    return name
    except Exception:
        pass
    return None


def resolve_avahi(ip: str) -> str | None:
    for cmd in (["avahi-resolve-address", ip], ["avahi-resolve", "-a", ip]):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except FileNotFoundError:
            return None
        except Exception:
            continue
        if result.returncode != 0 or not result.stdout.strip():
            continue
        parts = result.stdout.strip().split()
        if len(parts) >= 2 and parts[0] == ip:
            name = parts[1].rstrip(".").removesuffix(".local")
            if name and name != ip:
                return name
    return None


def resolve_nmap(ip: str) -> str | None:
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-R", "--host-timeout", "6s", ip],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception:
        return None
    for line in result.stdout.splitlines():
        match = NMAP_REPORT_RE.match(line.strip())
        if not match:
            continue
        name = match.group(1).strip().rstrip(".")
        if name and name != ip and not IPV4_RE.match(name):
            return name
    return None


def resolve_hostname(ip: str) -> str:
    if not IPV4_RE.match(ip):
        return ip
    for resolver in (resolve_getent, resolve_avahi, resolve_nmap):
        name = resolver(ip)
        if name:
            return name
    return ip


def main() -> int:
    if not CACHE_FILE.is_file():
        print(f"Cache not found: {CACHE_FILE}", file=sys.stderr)
        return 1

    cache = json.loads(CACHE_FILE.read_text())
    ips = sorted(cache.keys())
    print(f"Resolving hostnames for {len(ips)} devices...")

    results: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        for ip, name in pool.map(lambda addr: (addr, resolve_hostname(addr)), ips):
            results[ip] = name

    changed = 0
    named = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip, name in results.items():
        record = cache.setdefault(ip, {})
        old = str(record.get("hostname") or "—")
        record["hostname"] = name
        record["hostname_refreshed_at"] = now
        if name != ip:
            named += 1
        if old != name:
            changed += 1

    CACHE_FILE.write_text(json.dumps(cache, indent=2) + "\n")
    print(f"Done: {named} detected hostnames, {len(ips) - named} fell back to IP, {changed} records updated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
