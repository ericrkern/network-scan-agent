#!/usr/bin/env python3
"""LAN host inspection: mDNS, UPnP/SSDP, WS-Discovery, SNMP, SMB, TLS, ARP, HTTP identity."""

from __future__ import annotations

import os
import re
import signal
import socket
import ssl
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

MDNS_TYPES = [
    "_http._tcp.",
    "_ipp._tcp.",
    "_ipps._tcp.",
    "_printer._tcp.",
    "_pdl-datastream._tcp.",
    "_scanner._tcp.",
    "_uscan._tcp.",
    "_uscans._tcp.",
    "_airplay._tcp.",
    "_raop._tcp.",
    "_googlecast._tcp.",
    "_hap._tcp.",
    "_companion-link._tcp.",
    "_smb._tcp.",
    "_ssh._tcp.",
    "_device-info._tcp.",
    "_workstation._tcp.",
    "_rfb._tcp.",
    "_adisk._tcp.",
    "_homekit._tcp.",
    "_matterc._udp.",
    "_spotify-connect._tcp.",
    "_hap._udp.",
]

_MDNS_RESOLVE_FIRST = {
    "_ipp._tcp.",
    "_ipps._tcp.",
    "_printer._tcp.",
    "_http._tcp.",
    "_airplay._tcp.",
    "_googlecast._tcp.",
    "_hap._tcp.",
    "_smb._tcp.",
    "_ssh._tcp.",
    "_companion-link._tcp.",
    "_scanner._tcp.",
    "_uscan._tcp.",
    "_workstation._tcp.",
}

_HTTP_PORTS = {
    80, 81, 443, 631, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8443, 8888,
    9000, 9090, 9443, 10443, 32400, 5480,
}
_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 993, 995, 1883, 3306, 5432, 6379}
_JUNK_HOSTNAMES = {
    "record", "rdata", "timestamp", "starting", "localhost", "local",
    "0.0.0.0", "no", "such", "arpa", "in-addr", "ptr",
    "workgroup", "mshome", "domain", "__msbrowse__", "msbrowse",
}

SNMP_OIDS = {
    "sysDescr": ".10.20.0.3.10.20.0.5",
    "sysObjectID": ".10.20.0.3.10.0.1.1",
    "sysName": ".10.20.0.3.10.0.1.5",
}


def _run(cmd: List[str], timeout: float = 3.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 1, "", ""


def _which(name: str) -> bool:
    rc, out, _ = _run(["/usr/bin/which", name], timeout=1.5)
    return rc == 0 and bool(out.strip())


def os_kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGINT)
    except OSError:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass


def _popen_collect(cmd: List[str], linger: float, drain: float = 1.0) -> str:
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        time.sleep(linger)
        if proc.poll() is None:
            os_kill_group(proc.pid)
        out, _ = proc.communicate(timeout=drain)
        return out or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _tcp_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _is_plausible_hostname(name: Optional[str]) -> bool:
    host = (name or "").strip().rstrip(".")
    if not host or len(host) < 2:
        return False
    low = host.lower()
    if low in _JUNK_HOSTNAMES or "no such" in low:
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return False
    if not re.search(r"[A-Za-z]", host):
        return False
    return True


def ping_ttl(ip: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"reachable": False, "ttl": None, "os_family": None, "tool": "ping"}
    for cmd in (
        ["ping", "-c", "1", "-W", "1000", ip],
        ["ping", "-c", "1", "-t", "2", ip],
    ):
        _, out, _ = _run(cmd, timeout=3)
        if "bytes from" not in out and "1 packets received" not in out and "1 received" not in out:
            continue
        if "0 packets received" in out or "100.0% packet loss" in out:
            continue
        info["reachable"] = True
        match = re.search(r"ttl[=:](\d+)", out, re.I)
        if match:
            ttl = int(match.group(1))
            info["ttl"] = ttl
            if ttl <= 64:
                info["os_family"] = "Linux/Unix/embedded (TTL≤64)"
            elif ttl <= 128:
                info["os_family"] = "Windows (TTL≤128)"
            else:
                info["os_family"] = "Network appliance (TTL≤255)"
        return info
    return info


def arp_mac(ip: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"mac": None, "tool": "arp"}
    ping_ttl(ip)
    _, out, _ = _run(["arp", "-n", ip], timeout=2)
    if not out.strip() or "incomplete" in out.lower():
        _, out, _ = _run(["arp", "-an"], timeout=2)
    for line in out.splitlines():
        if f"({ip})" not in line and not line.startswith(ip):
            continue
        if "incomplete" in line.lower():
            continue
        match = re.search(r" at ([0-9a-fA-F:.-]+)", line)
        if match:
            mac = match.group(1).replace("-", ":").lower()
            if mac not in {"ff:ff:ff:ff:ff:ff"}:
                info["mac"] = mac
                return info
    _, out, _ = _run(["ip", "neigh", "show", ip], timeout=2)
    match = re.search(r"lladdr\s+([0-9a-fA-F:]+)", out)
    if match:
        info["mac"] = match.group(1).lower()
    return info


def reverse_dns(ip: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"hostname": None, "tool": "dns"}
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if _is_plausible_hostname(name):
            info["hostname"] = name.rstrip(".")
            return info
    except OSError:
        pass
    ptr = ".".join(reversed(ip.split("."))) + ".in-addr.arpa."
    names = _dns_sd_query(ptr, "PTR", timeout=2.0)
    for name in names:
        if _is_plausible_hostname(name):
            info["hostname"] = name.rstrip(".")
            info["tool"] = "mdns"
            return info
    return info


def _dns_sd_query(name: str, rrtype: str, timeout: float = 2.0) -> List[str]:
    if not _which("dns-sd"):
        return []
    out = _popen_collect(["dns-sd", "-Q", name, rrtype], linger=timeout, drain=1.2)
    hits: List[str] = []
    for line in out.splitlines():
        if "Add" not in line or "No Such Record" in line:
            continue
        # Timestamp A/R Flags IF Name Type Class Rdata...
        parts = line.split()
        if len(parts) < 8:
            continue
        rdata = parts[7]
        if rdata in {"0.0.0.0", "Record"}:
            continue
        hits.append(rdata.strip(".").strip("'"))
    return hits


def _mdns_resolve(instance: str, stype: str) -> Dict[str, str]:
    info: Dict[str, str] = {"name": instance, "type": stype.rstrip("."), "hostname": "", "ipv4": ""}
    if not instance or not _which("dns-sd"):
        return info
    st = stype.rstrip(".")
    out = _popen_collect(["dns-sd", "-L", instance, st, "local."], linger=1.25, drain=0.9)
    host_m = re.search(r"hostname\s*=\s*'([^']+)'", out, re.I)
    ip_m = re.search(r"IPv4 address\s*=\s*([0-9.]+)", out, re.I)
    if host_m:
        info["hostname"] = host_m.group(1).rstrip(".")
    if ip_m:
        info["ipv4"] = ip_m.group(1)
    if not info["ipv4"] and info["hostname"]:
        gout = _popen_collect(["dns-sd", "-G", "v4", info["hostname"] + ".local."], linger=1.0, drain=0.8)
        gm = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", gout)
        if gm:
            info["ipv4"] = gm.group(1)
    return info


def mdns_services(ip: str, hostname: Optional[str] = None) -> Dict[str, Any]:
    info: Dict[str, Any] = {"services": [], "names": [], "hostname": None, "tool": "dns-sd"}
    if not _which("dns-sd"):
        info["tool"] = None
        return info
    stem = (hostname or "").split(".")[0].lower()
    octet = ip.rsplit(".", 1)[-1]

    def browse(stype: str) -> List[Tuple[str, str]]:
        rows: List[Tuple[str, str]] = []
        out = _popen_collect(["dns-sd", "-B", stype, "local."], linger=1.25, drain=0.8)
        for line in out.splitlines():
            if "Add" not in line or "No Such Record" in line:
                continue
            match = re.search(r"\bAdd\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+(.+?)\s*$", line)
            if not match:
                continue
            inst = match.group(3).strip()
            if inst and inst.lower() not in _JUNK_HOSTNAMES:
                rows.append((inst, stype))
        return rows

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(browse, st) for st in MDNS_TYPES]
        candidates: List[Tuple[str, str]] = []
        for fut in as_completed(futures):
            candidates.extend(fut.result())

    unique: List[Tuple[str, str]] = []
    seen = set()
    for inst, stype in candidates:
        key = (inst.lower(), stype)
        if key in seen:
            continue
        seen.add(key)
        unique.append((inst, stype))

    # Prefer advertisements likely to belong to this host, then resolve A records.
    def score(item: Tuple[str, str]) -> Tuple[int, int]:
        inst, stype = item
        inst_l = inst.lower()
        pri = 0 if stype in _MDNS_RESOLVE_FIRST else 1
        match_n = 0 if (stem and stem in inst_l) or octet in inst_l else 1
        return (match_n, pri)

    unique.sort(key=score)
    to_resolve = unique[:28]
    found: List[Dict[str, str]] = []
    resolved_host: Optional[str] = None
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_mdns_resolve, inst, stype): (inst, stype) for inst, stype in to_resolve}
        for fut in as_completed(futs):
            inst, stype = futs[fut]
            try:
                row = fut.result()
            except Exception:
                continue
            ipv4 = row.get("ipv4") or ""
            inst_l = inst.lower()
            belongs = ipv4 == ip or (not ipv4 and stem and stem in inst_l)
            if not belongs:
                continue
            entry = {
                "name": inst,
                "type": stype.rstrip("."),
                "hostname": row.get("hostname") or "",
            }
            found.append(entry)
            if _is_plausible_hostname(row.get("hostname")) and not resolved_host:
                resolved_host = row["hostname"]

    info["services"] = found[:16]
    info["names"] = sorted({row["name"] for row in found})[:16]
    info["hostname"] = resolved_host
    return info


def ssdp_upnp(ip: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "tool": "ssdp",
        "friendly_name": None,
        "manufacturer": None,
        "model": None,
        "model_number": None,
        "device_type": None,
        "location": None,
    }
    payload = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(2.2)
    locations: List[str] = []
    try:
        try:
            sock.sendto(payload, ("239.255.255.250", 1900))
        except OSError:
            pass
        try:
            sock.sendto(payload, (ip, 1900))
        except OSError:
            pass
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if addr[0] != ip:
                continue
            text = data.decode("utf-8", errors="replace")
            for line in text.split("\r\n"):
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    if loc and loc not in locations:
                        locations.append(loc)
    finally:
        sock.close()

    if not locations:
        for path in ("/rootDesc.xml", "/description.xml", "/upnp/desc", "/DeviceDescription.xml"):
            locations.append(f"http://{ip}:80{path}")

    for loc in locations[:4]:
        parsed = _parse_upnp_xml(loc)
        if parsed.get("manufacturer") or parsed.get("friendly_name"):
            info.update(parsed)
            info["location"] = loc
            return info
    if locations:
        info["location"] = locations[0]
    return info


def _parse_upnp_xml(url: str) -> Dict[str, Optional[str]]:
    empty: Dict[str, Optional[str]] = {
        "friendly_name": None,
        "manufacturer": None,
        "model": None,
        "model_number": None,
        "device_type": None,
    }
    try:
        req = Request(url, headers={"User-Agent": "ZerothGuard-Inventory/1.0"})
        with urlopen(req, timeout=2.0) as resp:
            xml_text = resp.read(64_000).decode("utf-8", errors="replace")
    except OSError:
        return empty
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return empty
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def text_of(*tags: str) -> str:
        for tag in tags:
            node = root.find(f".//{ns}{tag}") if ns else root.find(f".//{tag}")
            if node is not None and (node.text or "").strip():
                return node.text.strip()[:120]
        return ""

    return {
        "friendly_name": text_of("friendlyName") or None,
        "manufacturer": text_of("manufacturer") or None,
        "model": text_of("modelName", "modelDescription") or None,
        "model_number": text_of("modelNumber", "serialNumber") or None,
        "device_type": text_of("deviceType") or None,
    }


def ws_discovery(ip: str) -> Dict[str, Any]:
    """ONVIF / WSDAPI probe — inventory only, no authentication."""
    info: Dict[str, Any] = {"tool": "ws-discovery", "types": None, "xaddrs": None, "scopes": None}
    msgid = f"uuid:{uuid.uuid4()}"
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<e:Header>"
        f"<w:MessageID>{msgid}</w:MessageID>"
        "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
        "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
        "</e:Header>"
        "<e:Body><d:Probe/></e:Body></e:Envelope>"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(1.8)
    replies: List[str] = []
    try:
        try:
            sock.sendto(body, ("239.255.255.250", 3702))
        except OSError:
            pass
        try:
            sock.sendto(body, (ip, 3702))
        except OSError:
            pass
        deadline = time.time() + 1.6
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except (socket.timeout, OSError):
                break
            if addr[0] != ip:
                continue
            replies.append(data.decode("utf-8", errors="replace"))
    finally:
        sock.close()
    if not replies:
        return info
    blob = " ".join(replies)
    types = re.search(r"<[^>]*Types[^>]*>([^<]+)</", blob, re.I)
    xaddrs = re.search(r"<[^>]*XAddrs[^>]*>([^<]+)</", blob, re.I)
    scopes = re.search(r"<[^>]*Scopes[^>]*>([^<]+)</", blob, re.I)
    if types:
        info["types"] = types.group(1).strip()[:160]
    if xaddrs:
        info["xaddrs"] = xaddrs.group(1).strip()[:200]
    if scopes:
        info["scopes"] = scopes.group(1).strip()[:240]
        name_m = re.search(r"name/([^/\s]+)", info["scopes"], re.I)
        if name_m:
            info["name"] = re.sub(r"%20", " ", name_m.group(1))[:80]
        hw_m = re.search(r"hardware/([^/\s]+)", info["scopes"], re.I)
        if hw_m:
            info["hardware"] = re.sub(r"%20", " ", hw_m.group(1))[:80]
    return info


def snmp_identity(ip: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"tool": "snmp", "sysDescr": None, "sysName": None, "sysObjectID": None}
    if not (_which("snmpget") or _which("snmpwalk")):
        info["tool"] = None
        return info
    oid_aliases = {
        "sysDescr": [SNMP_OIDS["sysDescr"], "SNMPv2-MIB::sysDescr.0", "sysDescr.0"],
        "sysName": [SNMP_OIDS["sysName"], "SNMPv2-MIB::sysName.0", "sysName.0"],
        "sysObjectID": [SNMP_OIDS["sysObjectID"], "SNMPv2-MIB::sysObjectID.0"],
    }
    for community in ("public",):
        for ver in ("2c", "1"):
            hit = False
            for field, aliases in oid_aliases.items():
                val = ""
                for oid in aliases:
                    rc, out, _ = _run(
                        ["snmpget", f"-v{ver}", "-c", community, "-t", "1", "-r", "0", "-Ovq", ip, oid],
                        timeout=2.2,
                    )
                    val = (out or "").strip().strip('"')
                    if rc == 0 and val and "Timeout" not in val and "No Such" not in val and "Error" not in val:
                        break
                    val = ""
                if val:
                    info[field] = val[:200]
                    hit = True
            if hit:
                info["community"] = community
                return info
    return info


def netbios_status(ip: str) -> Dict[str, Any]:
    """UDP/137 NBSTAT — Windows workstation / server NetBIOS computer name (no auth)."""
    info: Dict[str, Any] = {
        "tool": "netbios",
        "netbios_name": None,
        "workgroup": None,
        "names": [],
    }
    # Standard NBSTAT query for '*' (node status).
    name = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # encoded '*' + NULs + type 0x00
    trx = os.urandom(2)
    packet = (
        trx
        + b"\x00\x00"  # flags
        + b"\x00\x01"  # questions
        + b"\x00\x00\x00\x00\x00\x00"
        + bytes([len(name)])
        + name
        + b"\x00"
        + b"\x00\x21"  # NBSTAT
        + b"\x00\x01"  # IN
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.8)
    try:
        sock.sendto(packet, (ip, 137))
        data, addr = sock.recvfrom(4096)
    except OSError:
        return info
    finally:
        sock.close()
    if not data or addr[0] != ip or len(data) < 57:
        return info

    # Find the name-count byte that precedes 18-byte NetBIOS name entries.
    # Responses vary (compression pointers); scan for a plausible table.
    best: List[Dict[str, Any]] = []
    for start in range(12, min(len(data) - 19, 120)):
        count = data[start]
        if count < 1 or count > 32:
            continue
        need = 1 + count * 18
        if start + need > len(data):
            continue
        names: List[Dict[str, Any]] = []
        pos = start + 1
        ok = True
        for _ in range(count):
            raw = data[pos : pos + 15]
            name_type = data[pos + 15]
            flags = int.from_bytes(data[pos + 16 : pos + 18], "big")
            pos += 18
            try:
                label = raw.decode("ascii").rstrip(" \x00")
            except UnicodeDecodeError:
                ok = False
                break
            if not label or not re.fullmatch(r"[A-Za-z0-9_$-]{1,15}", label):
                # Allow one odd master-browser marker; otherwise reject this offset.
                if "__MSBROWSE__" in label.upper() or label.startswith("\x01\x02"):
                    continue
                ok = False
                break
            names.append(
                {
                    "name": label,
                    "type": name_type,
                    "flags": flags,
                    "group": bool(flags & 0x8000),
                }
            )
        if ok and names and len(names) >= len(best):
            best = names
    if not best:
        return info

    workstation = None
    fileserver = None
    domain = None
    for entry in best:
        raw_name = entry["name"]
        if not _is_plausible_hostname(raw_name):
            continue
        if entry["group"] or entry["type"] in {0x1E, 0x1D, 0x01}:
            if entry["type"] in {0x00, 0x1E} and not domain:
                domain = raw_name
            continue
        if entry["type"] == 0x00 and workstation is None:
            workstation = raw_name
        elif entry["type"] == 0x20 and fileserver is None:
            fileserver = raw_name
    info["names"] = best[:12]
    info["netbios_name"] = workstation or fileserver
    info["workgroup"] = domain
    return info


def _parse_smbutil_status(text: str) -> Dict[str, Any]:
    """Parse `smbutil status` / `smbutil status -a` output."""
    server = None
    workgroup = None
    unique_names: List[Tuple[int, str]] = []  # (type, name)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("using ip") or line.lower().startswith("netbios name"):
            continue
        low = line.lower()
        if low.startswith("server:"):
            candidate = line.split(":", 1)[1].strip().strip("'\"")
            if _is_plausible_hostname(candidate):
                server = candidate.split()[0][:15]
            continue
        if low.startswith("workgroup:"):
            candidate = line.split(":", 1)[1].strip().strip("'\"").split()[0]
            if candidate and candidate.lower() not in _JUNK_HOSTNAMES:
                workgroup = candidate[:15]
            continue
        # Table row: NAME  0xNN  UNIQUE|GROUP  [desc]
        m = re.match(
            r"^([A-Za-z0-9_$-]{1,15})\s+(?:0x)?([0-9A-Fa-f]{2})\s+(UNIQUE|GROUP)\b",
            line,
            re.I,
        )
        if not m:
            continue
        name = m.group(1)
        ntype = int(m.group(2), 16)
        kind = m.group(3).upper()
        if kind == "GROUP":
            if ntype in {0x00, 0x1E} and not workgroup and name.lower() not in _JUNK_HOSTNAMES:
                workgroup = name
            continue
        if not _is_plausible_hostname(name):
            continue
        unique_names.append((ntype, name))

    workstation = next((n for t, n in unique_names if t == 0x00), None)
    fileserver = next((n for t, n in unique_names if t == 0x20), None)
    master = next((n for t, n in unique_names if t == 0x1D), None)
    netbios = workstation or fileserver or server or master
    if netbios and netbios.lower() in _JUNK_HOSTNAMES:
        netbios = workstation or fileserver
        if netbios and netbios.lower() in _JUNK_HOSTNAMES:
            netbios = None
    return {
        "netbios_name": netbios,
        "workgroup": workgroup,
        "names": [n for _, n in unique_names],
    }


def smb_identity(ip: str) -> Dict[str, Any]:
    """Resolve Windows/SMB NetBIOS name via smbutil and/or UDP NBSTAT."""
    info: Dict[str, Any] = {
        "tool": None,
        "netbios_name": None,
        "workgroup": None,
        "names": [],
    }

    if _which("smbutil"):
        for args in (
            ["smbutil", "status", "-a", ip],
            ["smbutil", "status", ip],
        ):
            _rc, out, err = _run(args, timeout=4.0)
            text = f"{out}\n{err}"
            low = text.lower()
            if not text.strip() or "unable to get status" in low or "timed out" in low:
                continue
            parsed = _parse_smbutil_status(text)
            if parsed.get("netbios_name") or parsed.get("workgroup") or parsed.get("names"):
                info["tool"] = "smbutil"
                info["netbios_name"] = parsed.get("netbios_name")
                info["workgroup"] = parsed.get("workgroup")
                info["names"] = parsed.get("names") or []
                if info["netbios_name"]:
                    break

    if not info.get("netbios_name"):
        nb = netbios_status(ip)
        if nb.get("netbios_name"):
            info["tool"] = "netbios" if not info.get("tool") else f"{info['tool']}+netbios"
            info["netbios_name"] = nb["netbios_name"]
            info["workgroup"] = info.get("workgroup") or nb.get("workgroup")
            info["names"] = info.get("names") or nb.get("names") or []
        elif nb.get("workgroup") and not info.get("workgroup"):
            info["workgroup"] = nb.get("workgroup")

    if info.get("netbios_name"):
        info["netbios_name"] = str(info["netbios_name"]).split(".")[0].strip()[:80]
        if not _is_plausible_hostname(info["netbios_name"]):
            info["netbios_name"] = None
    return info


def prefer_windows_hostname(
    *,
    dns_name: Optional[str] = None,
    mdns_name: Optional[str] = None,
    netbios_name: Optional[str] = None,
    wsd_name: Optional[str] = None,
    snmp_name: Optional[str] = None,
    ssdp_name: Optional[str] = None,
    os_guess: Optional[str] = None,
    open_ports: Optional[List[int]] = None,
) -> Optional[str]:
    """Pick the best display hostname; prefer NetBIOS/computer name for Windows."""
    ports = set(open_ports or [])
    windows_likely = bool(
        (os_guess or "") and "windows" in str(os_guess).lower()
    ) or bool(ports & {139, 445, 3389, 5985, 5986, 135, 5357})

    ranked: List[Tuple[int, str]] = []

    def add(score: int, value: Optional[str]) -> None:
        if _is_plausible_hostname(value):
            ranked.append((score, str(value).strip().rstrip(".")))

    # NetBIOS / SMB computer name is authoritative for Windows boxes.
    add(100 if windows_likely else 85, netbios_name)
    add(90 if windows_likely else 70, wsd_name)
    add(60, mdns_name)
    add(40 if windows_likely else 55, dns_name)
    add(35, snmp_name)
    add(25, ssdp_name)
    if not ranked:
        return None
    ranked.sort(key=lambda row: (-row[0], len(row[1])))
    return ranked[0][1]


def tls_identity(ip: str, port: int = 443) -> Dict[str, Any]:
    info: Dict[str, Any] = {"tool": "tls", "cn": None, "org": None, "issuer": None, "port": port}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=2.0) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as sock:
                cert = sock.getpeercert()
    except OSError:
        return info
    if not cert:
        return _tls_via_openssl(ip, port)
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    info["cn"] = subject.get("commonName")
    info["org"] = subject.get("organizationName")
    info["issuer"] = issuer.get("commonName") or issuer.get("organizationName")
    return info


def _tls_via_openssl(ip: str, port: int) -> Dict[str, Any]:
    info: Dict[str, Any] = {"tool": "tls", "cn": None, "org": None, "issuer": None, "port": port}
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{ip}:{port}", "-servername", ip],
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=4,
        )
        text = proc.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return info
    match = re.search(r"subject=([^\n]+)", text)
    if match:
        subj = match.group(1)
        cn = re.search(r"CN\s*=\s*([^,/]+)", subj)
        org = re.search(r"O\s*=\s*([^,/]+)", subj)
        if cn:
            info["cn"] = cn.group(1).strip()
        if org:
            info["org"] = org.group(1).strip()
    iss = re.search(r"issuer=([^\n]+)", text)
    if iss:
        info["issuer"] = iss.group(1).strip()[:120]
    return info


def http_identity(ip: str, ports: List[int]) -> Dict[str, Any]:
    pages: List[Dict[str, str]] = []
    for port in ports:
        if port not in _HTTP_PORTS:
            continue
        meta = _http_head(ip, port, port in {443, 8443, 9443, 10443})
        if meta:
            pages.append(meta)
    return {"tool": "http", "pages": pages}


def _http_head(ip: str, port: int, use_tls: bool) -> Dict[str, str]:
    out: Dict[str, str] = {"port": str(port)}
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((ip, port), timeout=2.0)
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = socket.create_connection((ip, port), timeout=2.0)
        with sock:
            sock.sendall(
                b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: ZerothGuard-Inventory/1.0\r\n\r\n"
                % ip.encode()
            )
            data = sock.recv(8192).decode("utf-8", errors="replace")
    except OSError:
        return {}
    headers, _, body = data.partition("\r\n\r\n")
    for line in headers.split("\r\n")[:30]:
        low = line.lower()
        if low.startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()[:120]
        elif low.startswith("www-authenticate:"):
            out["auth"] = line.split(":", 1)[1].strip()[:100]
        elif low.startswith("x-powered-by:"):
            out["powered_by"] = line.split(":", 1)[1].strip()[:80]
        elif low.startswith("location:"):
            out["location"] = line.split(":", 1)[1].strip()[:120]
    title = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
    if title:
        out["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:120]
    gen = re.search(r'name="generator"\s+content="([^"]+)"', body, re.I)
    if gen:
        out["generator"] = gen.group(1)[:80]
    return out if len(out) > 1 else {}


def rtsp_identity(ip: str, ports: List[int]) -> Dict[str, Any]:
    info: Dict[str, Any] = {"tool": "rtsp", "banner": None}
    for port in ports:
        if port not in {554, 8554}:
            continue
        try:
            with socket.create_connection((ip, port), timeout=2.0) as sock:
                sock.sendall(b"OPTIONS rtsp://%b:%d/ RTSP/1.0\r\nCSeq: 1\r\n\r\n" % (ip.encode(), port))
                data = sock.recv(1024).decode("utf-8", errors="replace")
        except OSError:
            continue
        server = re.search(r"Server:\s*(.+)", data, re.I)
        info["banner"] = (server.group(1).strip() if server else data.split("\r\n")[0])[:160]
        info["port"] = port
        break
    return info


def tcp_banners(ip: str, ports: List[int]) -> Dict[str, Any]:
    banners: Dict[str, str] = {}
    for port in ports:
        if port not in _BANNER_PORTS:
            continue
        try:
            with socket.create_connection((ip, port), timeout=1.4) as sock:
                sock.settimeout(1.2)
                if port == 1883:
                    # MQTT CONNECT with client id zg-inventory; read CONNACK only.
                    sock.sendall(b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06zg-inv")
                data = sock.recv(256)
        except OSError:
            continue
        text = data.decode("utf-8", errors="replace").strip().split("\n")[0][:160]
        if text:
            banners[str(port)] = text
        elif port == 1883 and data:
            banners[str(port)] = "mqtt (broker responded)"
    return {"tool": "banner", "banners": banners}


def _extra_http_ports(ip: str, known: List[int]) -> List[int]:
    extra = []
    for port in (80, 443, 631, 8080, 8443, 8008, 8888, 5000, 8123, 9000, 32400):
        if port in known:
            continue
        if _tcp_open(ip, port, timeout=0.35):
            extra.append(port)
    return extra


def _future_result(fut, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        value = fut.result()
    except Exception:
        return default
    return value if isinstance(value, dict) else default


def inspect_host(ip: str, open_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """Run complementary LAN inspection tools against one host."""
    ports = list(open_ports or [])
    tools_run: List[str] = []
    findings: List[str] = []
    out: Dict[str, Any] = {
        "ip": ip,
        "tools": tools_run,
        "findings": findings,
        "hostname": None,
        "mac": None,
        "manufacturer": None,
        "model": None,
        "model_number": None,
        "os_guess": None,
    }

    with ThreadPoolExecutor(max_workers=8) as pool:
        ping_f = pool.submit(ping_ttl, ip)
        arp_f = pool.submit(arp_mac, ip)
        dns_f = pool.submit(reverse_dns, ip)
        ssdp_f = pool.submit(ssdp_upnp, ip)
        wsd_f = pool.submit(ws_discovery, ip)
        snmp_f = pool.submit(snmp_identity, ip)
        smb_f = pool.submit(smb_identity, ip)
        tls_f = pool.submit(tls_identity, ip, 443)

        ping = _future_result(ping_f, {"reachable": False})
        arp = _future_result(arp_f, {"mac": None})
        dns = _future_result(dns_f, {"hostname": None, "tool": "dns"})
        try:
            mdns = mdns_services(ip, hostname=dns.get("hostname"))
        except Exception:
            mdns = {"services": [], "names": [], "tool": None}
        ssdp = _future_result(ssdp_f, {"tool": "ssdp"})
        wsd = _future_result(wsd_f, {"tool": "ws-discovery"})
        snmp = _future_result(snmp_f, {"sysDescr": None, "sysName": None})
        smb = _future_result(smb_f, {"netbios_name": None})
        tls = _future_result(tls_f, {"cn": None, "org": None})
        if not tls.get("cn") and 8443 in ports:
            try:
                tls = tls_identity(ip, 8443)
            except Exception:
                pass

    try:
        extra = _extra_http_ports(ip, ports)
    except Exception:
        extra = []
    all_ports = sorted(set(ports + extra))
    try:
        http = http_identity(ip, all_ports)
    except Exception:
        http = {"tool": "http", "pages": []}
    try:
        rtsp = rtsp_identity(ip, all_ports)
    except Exception:
        rtsp = {"tool": "rtsp", "banner": None}
    try:
        banners = tcp_banners(ip, all_ports)
    except Exception:
        banners = {"tool": "banner", "banners": {}}
    if extra:
        out["extra_open_ports"] = extra

    if ping.get("reachable"):
        tools_run.append("ping")
        out["reachable"] = True
        if ping.get("os_family"):
            out["os_guess"] = ping["os_family"]
            findings.append(ping["os_family"])
    else:
        out["reachable"] = False
    if arp.get("mac"):
        tools_run.append("arp")
        out["mac"] = arp["mac"]
        findings.append(f"MAC {arp['mac']}")

    if mdns.get("services"):
        tools_run.append("mdns")
        out["mdns"] = mdns
        findings.append("mDNS: " + ", ".join(
            f"{s.get('name')} ({s.get('type')})" for s in mdns["services"][:4]
        ))
    if ssdp.get("manufacturer") or ssdp.get("friendly_name"):
        tools_run.append("ssdp")
        out["upnp"] = ssdp
        out["manufacturer"] = ssdp.get("manufacturer") or out["manufacturer"]
        out["model"] = ssdp.get("model") or out["model"]
        out["model_number"] = ssdp.get("model_number") or out["model_number"]
        findings.append(
            "UPnP "
            + " ".join(x for x in (ssdp.get("manufacturer"), ssdp.get("model"), ssdp.get("friendly_name")) if x)
        )
    if wsd.get("types") or wsd.get("name") or wsd.get("xaddrs"):
        tools_run.append("ws-discovery")
        out["ws_discovery"] = wsd
        label = wsd.get("name") or wsd.get("hardware") or wsd.get("types")
        findings.append(f"WS-Discovery {label}")
        if wsd.get("name") and not out.get("model"):
            out["model"] = wsd["name"]
        if wsd.get("hardware") and not out.get("model_number"):
            out["model_number"] = wsd["hardware"]
        if wsd.get("types") and "windows" in str(wsd.get("types") or "").lower() and not out.get("os_guess"):
            out["os_guess"] = "Windows (WS-Discovery)"
    if snmp.get("sysDescr") or snmp.get("sysName"):
        tools_run.append("snmp")
        out["snmp"] = snmp
        descr = snmp.get("sysDescr") or ""
        findings.append(f"SNMP {descr[:80]}" if descr else f"SNMP name {snmp.get('sysName')}")
        if "linux" in descr.lower() and not out.get("os_guess"):
            out["os_guess"] = descr.split(",")[0][:80]
        if "windows" in descr.lower() and not out.get("os_guess"):
            out["os_guess"] = "Windows (SNMP)"
    if smb.get("netbios_name"):
        tools_run.append(str(smb.get("tool") or "smb"))
        out["smb"] = smb
        findings.append(f"NetBIOS {smb['netbios_name']}")
        if smb.get("workgroup"):
            findings.append(f"Workgroup {smb['workgroup']}")
        if not out.get("os_guess"):
            out["os_guess"] = "Windows (NetBIOS/SMB)"

    mdns_host = mdns.get("hostname")
    if not mdns_host and mdns.get("names"):
        candidate = mdns["names"][0]
        if _is_plausible_hostname(candidate):
            mdns_host = candidate
    if dns.get("hostname") and dns.get("tool"):
        tools_run.append(str(dns.get("tool") or "dns"))

    host = prefer_windows_hostname(
        dns_name=dns.get("hostname"),
        mdns_name=mdns_host,
        netbios_name=smb.get("netbios_name"),
        wsd_name=wsd.get("name"),
        snmp_name=snmp.get("sysName"),
        ssdp_name=ssdp.get("friendly_name"),
        os_guess=out.get("os_guess"),
        open_ports=all_ports,
    )
    if host:
        out["hostname"] = host
        if f"Hostname {host}" not in findings:
            findings.append(f"Hostname {host}")

    if tls.get("cn") or tls.get("org"):
        tools_run.append("tls")
        out["tls"] = tls
        if tls.get("org") and not out.get("manufacturer"):
            out["manufacturer"] = tls["org"]
        findings.append("TLS " + " / ".join(x for x in (tls.get("cn"), tls.get("org")) if x))
    if http.get("pages"):
        tools_run.append("http")
        out["http"] = http
        page = http["pages"][0]
        title = page.get("title") or page.get("server")
        if title:
            findings.append(f"HTTP {title}")
        if page.get("server") and not out.get("os_guess"):
            out["os_guess"] = page["server"]
    if rtsp.get("banner"):
        tools_run.append("rtsp")
        out["rtsp"] = rtsp
        findings.append(f"RTSP {rtsp['banner']}")
    if banners.get("banners"):
        tools_run.append("banner")
        out["banners"] = banners["banners"]
        first = next(iter(banners["banners"].items()))
        findings.append(f"Banner {first[0]}/tcp {first[1][:80]}")

    out["tools"] = sorted(set(tools_run))
    out["findings"] = findings[:14]
    out["open_ports_used"] = all_ports
    return out
