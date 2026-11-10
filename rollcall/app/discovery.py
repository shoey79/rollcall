"""Network discovery: scan private address ranges for devices that could be added to Rollcall.

For each address: a ping, a quick TCP probe of common service ports (also for addresses that don't
answer ping, as Windows often doesn't), then for anything that answered: its DNS name, a NetBIOS
name query (Windows name, workgroup or domain, and MAC address), an SNMP read of the system group,
a SIP OPTIONS probe and the title of its web page. Each device gets a guess at what it is and which
Rollcall checks would suit it.

Only private addresses (RFC 1918, CGNAT 100.64/10, link-local) are scanned, at most 1,024 per range.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import socket
import ssl
import struct
import time

import sipcheck
import snmp as snmplib

MAX_PER_RANGE = 1024
MAX_TOTAL = 4096
PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 135, 139, 389, 443, 445, 515, 548, 554, 631, 636, 873, 902, 1433, 1883,
         3000, 3306, 3389, 5000, 5001, 5432, 5900, 5985, 8006, 8007, 8080, 8086, 8096, 8123, 8443, 8530, 9100, 9392, 32400]
QUICK = [22, 80, 135, 443, 445, 3389, 8080, 9100]  # for addresses that don't answer ping
# Home Assistant's own container networks (Supervisor and Docker): never worth suggesting
INTERNAL = [ipaddress.ip_network("172.30.32.0/23"), ipaddress.ip_network("172.17.0.0/16")]
SYS = "1.3.6.1.2.1.1"
_TITLE = re.compile(rb"<title[^>]*>\s*(.*?)\s*</title>", re.I | re.S)


# ---------------------------------------------------------------- address ranges
def parse_ranges(text: str) -> tuple[list[str], list[str]]:
    """Addresses to scan from 'CIDR, a.b.c.d-e, a.b.c.d-a.b.c.e or single addresses' (comma, space or
    newline separated). Returns (addresses, problems). Public addresses are refused."""
    out, problems, seen = [], [], set()
    for part in re.split(r"[\s,;]+", text or ""):
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                if net.version != 4:
                    raise ValueError("IPv4 only")
                hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            elif "-" in part:
                a, b = part.split("-", 1)
                start = ipaddress.ip_address(a)
                end = ipaddress.ip_address(b) if "." in b else ipaddress.ip_address(".".join(a.split(".")[:3] + [b]))
                if end < start:
                    start, end = end, start
                if int(end) - int(start) + 1 > MAX_PER_RANGE:
                    raise ValueError(f"more than {MAX_PER_RANGE} addresses")
                hosts = [ipaddress.ip_address(i) for i in range(int(start), int(end) + 1)]
            else:
                hosts = [ipaddress.ip_address(part)]
        except ValueError as err:
            problems.append(f"{part}: {err}")
            continue
        if len(hosts) > MAX_PER_RANGE:
            problems.append(f"{part}: more than {MAX_PER_RANGE} addresses; use a /22 or smaller")
            continue
        bad = [h for h in hosts if h.version != 4 or not (h.is_private or h in ipaddress.ip_network("100.64.0.0/10")) or h.is_loopback]
        if bad:
            problems.append(f"{part}: only private addresses can be scanned")
            continue
        for h in hosts:
            if str(h) not in seen:
                seen.add(str(h))
                out.append(str(h))
    if len(out) > MAX_TOTAL:
        problems.append(f"{len(out)} addresses is too many; at most {MAX_TOTAL} at once")
        out = []
    return out, problems


def suggest_ranges(host_ips: list[str], local: list[str]) -> list[str]:
    """Ranges worth scanning: Home Assistant's own networks, then the /24s of computers already in Rollcall."""
    out = []
    for cidr in local:
        try:
            net = ipaddress.ip_interface(cidr).network
        except ValueError:
            continue
        if net.version == 4 and net.is_private and not net.is_loopback and not any(net.overlaps(x) for x in INTERNAL):
            # a big network (e.g. a /16) is too much to scan: suggest the /24 Home Assistant is in
            n = str(net) if net.prefixlen >= 22 else str(ipaddress.ip_network(f"{cidr.split('/')[0]}/24", strict=False))
            if n not in out:
                out.append(n)
    counts: dict[str, int] = {}
    for ip in host_ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.version == 4 and a.is_private and not a.is_loopback:
            n = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            counts[n] = counts.get(n, 0) + 1
    for n, _c in sorted(counts.items(), key=lambda x: -x[1]):
        if n not in out:
            out.append(n)
    return out[:6]


# ---------------------------------------------------------------- probes
async def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (asyncio.TimeoutError, OSError):
        return False
    w.close()
    try:
        await asyncio.wait_for(w.wait_closed(), 1)
    except Exception:  # noqa: BLE001
        pass
    return True


async def reverse_dns(ip: str) -> str:
    try:
        name, _ = await asyncio.wait_for(asyncio.get_running_loop().getnameinfo((ip, 0), socket.NI_NAMEREQD), 2)
        return name
    except Exception:  # noqa: BLE001
        return ""


class _Udp(asyncio.DatagramProtocol):
    def __init__(self):
        self.fut = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_exception(exc)


async def nbstat(ip: str, timeout: float = 1.0) -> dict:
    """NetBIOS node status (UDP 137): the computer's name, its workgroup or domain, and its MAC address."""
    tid = secrets.randbits(16)
    q = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"AA" * 15 + b"\x00" + struct.pack(">HH", 0x21, 1)
    loop = asyncio.get_running_loop()
    try:
        t, p = await loop.create_datagram_endpoint(_Udp, remote_addr=(ip, 137))
    except OSError:
        return {}
    try:
        t.sendto(q)
        data = await asyncio.wait_for(p.fut, timeout)
    except (asyncio.TimeoutError, OSError):
        return {}
    finally:
        t.close()
    try:
        i = 12 + 34 + 2 + 2 + 4 + 2  # header, question name, type, class, TTL, length
        if data[12] & 0xC0 == 0xC0:  # compressed name pointer in the answer
            i = 12 + 2 + 2 + 2 + 4 + 2
        n = data[i]
        i += 1
        names = []
        for _ in range(n):
            raw, kind, flags = data[i:i + 15], data[i + 15], struct.unpack(">H", data[i + 16:i + 18])[0]
            names.append((raw.decode("ascii", "replace").strip(), kind, bool(flags & 0x8000)))
            i += 18
        mac = data[i:i + 6]
        out = {}
        uniq = [nm for nm, k, grp in names if k == 0x00 and not grp]
        grp = [nm for nm, k, g in names if k == 0x00 and g]
        if uniq:
            out["name"] = uniq[0]
        if grp:
            out["workgroup"] = grp[0]
        if len(mac) == 6 and any(mac):
            out["mac"] = ":".join(f"{b:02X}" for b in mac)
        return out
    except (IndexError, struct.error):
        return {}


async def snmp_info(ip: str, community: str, timeout: float = 1.5) -> dict:
    try:
        async with snmplib.Session(ip, community, timeout=timeout, retries=0) as s:
            v = await s.get([f"{SYS}.1.0", f"{SYS}.2.0", f"{SYS}.5.0", f"{SYS}.6.0"])
    except Exception:  # noqa: BLE001
        return {}
    if not v:
        return {}
    clean = lambda x: re.sub(r"\s+", " ", str(x or "")).strip()[:200]  # noqa: E731
    return {"descr": clean(v.get(f"{SYS}.1.0")), "object_id": clean(v.get(f"{SYS}.2.0")),
            "name": clean(v.get(f"{SYS}.5.0")), "location": clean(v.get(f"{SYS}.6.0"))}


async def sip_info(ip: str) -> dict:
    try:
        code, reason, agent, _ms = await sipcheck.options(ip, 5060, timeout=1.2)
    except Exception:  # noqa: BLE001
        return {}
    return {"code": code, "reason": reason, "agent": agent[:120]}


_ctx = None


def _tls():
    global _ctx
    if _ctx is None:
        _ctx = ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode = ssl.CERT_NONE
    return _ctx


async def http_info(ip: str, port: int, tls: bool, timeout: float = 2.5) -> dict:
    """The status, Server header and page title of http(s)://ip:port/ (no redirects followed)."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=_tls() if tls else None,
                                                              server_hostname="" if tls else None), timeout)
    except Exception:  # noqa: BLE001
        return {}
    try:
        w.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Rollcall discovery\r\nAccept: text/html\r\n\r\n".encode())
        await w.drain()
        data = b""
        while len(data) < 16384:
            chunk = await asyncio.wait_for(r.read(4096), timeout)
            if not chunk:
                break
            data += chunk
    except Exception:  # noqa: BLE001
        pass
    finally:
        w.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else b"")
    if not m:
        return {}
    hdr = {k.strip().lower(): v.strip() for k, _, v in (ln.decode("latin-1").partition(":") for ln in lines[1:])}
    t = _TITLE.search(body)
    title = re.sub(r"\s+", " ", t.group(1).decode("utf-8", "replace")).strip()[:120] if t else ""
    return {"status": int(m.group(1)), "server": hdr.get("server", "")[:80], "title": title,
            "location": hdr.get("location", "")[:120]}


# ---------------------------------------------------------------- what is it?
def classify(d: dict) -> dict:
    """A guess at what the device is, its Rollcall icon, suggested presets and a make/model if known."""
    p = set(d.get("ports") or [])
    s = d.get("snmp") or {}
    descr = (s.get("descr") or "").lower()
    web = " ".join(f"{(w.get('title') or '')} {(w.get('server') or '')}" for w in (d.get("web") or {}).values()).lower()
    sip = d.get("sip") or {}
    agent = (sip.get("agent") or "").lower()
    model, kind, icon, presets = "", "", "", []

    def has(*xs):
        return all(x in p for x in xs)

    if has(88, 389, 53):
        kind, icon, presets = "Domain controller", "server", ["dc"]
    elif has(25) and (has(443) or has(80)) and ("outlook" in web or "exchange" in web or has(135)):
        kind, icon, presets = "Exchange server", "server", ["exchange"]
    elif has(1433):
        kind, icon, presets = "SQL Server", "database", ["sql"] + (["rds"] if has(3389) else [])
    elif re.search(r"\bups\b|management card|powernet|smart-ups|eaton|cyberpower|\bapc\b", descr) or "network management card" in web:
        kind, icon, presets = "UPS", "ups", ["snmp"]
    elif "pi-hole" in web:
        kind, icon, presets = "Pi-hole", "dns", ["pihole"]
    elif "home assistant" in web or has(8123):
        kind, icon, presets = "Home Assistant", "home", ["homeassistant"]
    elif has(8006):
        kind, icon, presets = "Proxmox VE", "server", ["proxmox"]
    elif has(902) or "vmware esxi" in web or "esxi" in descr:
        kind, icon, presets = "VMware ESXi", "server", ["esxi"]
    elif "idrac" in web or "integrated dell remote access" in web or "ilo" in web.split() or "supermicro" in web:
        kind, icon, presets = "Server management (BMC)", "server", ["idrac"]
    elif "unifi" in web:
        kind, icon, presets = "UniFi controller", "network", ["unifi"] if has(8443) else []
    elif sip.get("code") or re.search(r"spa\d{3}|linksys|cisco/spa|grandstream|yealink|polycom|snom|fanvil", agent):
        kind, icon = "VoIP phone or ATA", "voip"
        presets = ["ata2"] if re.search(r"spa1[12]\d", agent) else ["voip"]
        model = (sip.get("agent") or "").split("-")[0].replace("Cisco/", "Cisco ")
    elif has(9100) or has(631) or has(515) or re.search(r"printer|laserjet|jetdirect|officejet|brother|kyocera|ricoh|xerox|canon|epson|lexmark|konica", descr + " " + web):
        kind, icon, presets = "Printer", "printer", ["printer"]
    elif re.search(r"synology|diskstation", descr + " " + web) or has(5000, 5001):
        kind, icon, presets = "NAS (Synology)", "nas", ["synology", "fileserver"]
    elif re.search(r"qnap|qts", descr + " " + web):
        kind, icon, presets = "NAS (QNAP)", "nas", ["qnap", "fileserver"]
    elif re.search(r"terastation|linkstation|buffalo", descr + " " + web):
        kind, icon, presets = "NAS (Buffalo)", "nas", ["fileserver"]
    elif re.search(r"truenas|freenas", descr + " " + web):
        kind, icon, presets = "NAS (TrueNAS)", "nas", ["truenas", "fileserver"]
    elif re.search(r"switch|procurve|aruba|catalyst|cisco ios|netgear|gs\d{3}|ubiquiti|edgeswitch|mikrotik|routeros|fortigate|sonicwall|draytek|juniper", descr):
        kind, icon, presets = "Network switch or router", "network", []
    elif has(554):
        kind, icon, presets = "IP camera / NVR", "camera", ["camera"]
    elif has(3389) and (has(445) or has(135)):
        kind, icon, presets = "Windows computer", "server", ["rds"] + (["fileserver"] if has(445) else [])
    elif has(445) or has(135):
        kind, icon, presets = "Windows computer", "pc", ["fileserver"] if has(445) else []
    elif has(22):
        kind, icon, presets = "Linux / SSH", "server", ["ssh"]
    elif has(80) or has(443):
        kind, icon, presets = "Web interface", "network", []
    else:
        kind, icon = "Device", ""
    if s and "snmp" not in presets and kind not in ("Windows computer",):
        presets.append("snmp")
    if not model and s.get("descr"):
        mn = re.search(r"\bMN:\s*([\w-]+)", s["descr"])  # APC cards: "... MN:AP9617 HR:A10"
        if mn:
            model = ("APC " if "apc" in descr else "") + mn.group(1)
        elif len(s["descr"]) <= 60 or "," in s["descr"][:60]:
            model = s["descr"].split(",")[0][:60]
    agent_hint = "windows" if kind in ("Domain controller", "Exchange server", "SQL Server", "Windows computer") else "linux" if kind == "Linux / SSH" else ""
    return {"kind": kind, "icon": icon, "presets": presets, "model": model, "agent": agent_hint}


def best_name(d: dict) -> str:
    """NetBIOS name, then SNMP sysName, then the DNS name (first part), then the model."""
    for n in ((d.get("netbios") or {}).get("name"), (d.get("snmp") or {}).get("name"), d.get("dns")):
        if n:
            n = n.strip().rstrip(".")
            return n.split(".")[0] if not re.fullmatch(r"[\d.]+", n) else n
    return d.get("model") or ""


# ---------------------------------------------------------------- the scan
class Scan:
    """One scan in progress (or finished). Progress is in done/total; results build up as it goes."""

    def __init__(self, addresses: list[str], community: str, ping, known: dict[str, str], who: str = ""):
        self.addresses, self.community, self.ping, self.known, self.who = addresses, community or "public", ping, known, who
        self.total, self.done, self.found = len(addresses), 0, 0
        self.results: list[dict] = []
        self.started, self.finished = time.time(), None
        self.cancelled = False
        self.task: asyncio.Task | None = None

    async def _one(self, ip: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            if self.cancelled:
                return
            alive, _ms = await self.ping(ip)
            check = PORTS if alive else QUICK
            opened = await asyncio.gather(*(tcp_open(ip, port, 0.8) for port in check))
            ports = [port for port, ok in zip(check, opened) if ok]
            if not alive and not ports:
                return
            if not alive:  # it's there but blocks ping: finish the port list
                rest = [port for port in PORTS if port not in QUICK]
                more = await asyncio.gather(*(tcp_open(ip, port, 0.8) for port in rest))
                ports = sorted(ports + [port for port, ok in zip(rest, more) if ok])
            dns, nb, sn, sip = await asyncio.gather(reverse_dns(ip), nbstat(ip), snmp_info(ip, self.community), sip_info(ip))
            web = {}
            for port, tls in ((80, False), (443, True), (8080, False), (8443, True), (5001, True)):
                if port in ports:
                    w = await http_info(ip, port, tls)
                    if w:
                        web[str(port)] = w
            d = {"ip": ip, "ping": alive, "ports": ports, "dns": dns, "netbios": nb, "snmp": sn, "sip": sip, "web": web}
            d.update(classify(d))
            d["name"] = best_name(d)
            d["known"] = self.known.get(ip)
            self.results.append(d)
            self.found += 1

    async def run(self) -> None:
        sem = asyncio.Semaphore(64)

        async def step(ip):
            try:
                await self._one(ip, sem)
            except Exception:  # noqa: BLE001 - one odd device mustn't stop the scan
                pass
            finally:
                self.done += 1
        try:
            await asyncio.gather(*(step(ip) for ip in self.addresses))
        finally:
            self.results.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
            self.finished = time.time()

    def summary(self) -> dict:
        return {"total": self.total, "done": self.done, "found": self.found, "started": self.started, "finished": self.finished,
                "cancelled": self.cancelled, "by": self.who, "running": self.finished is None}
