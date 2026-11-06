"""A small SNMP v2c client (GET and GETBULK walks over UDP), with no dependencies,
plus the readers Rollcall uses for switches, PoE and Buffalo TeraStation NAS units."""
from __future__ import annotations

import asyncio
import secrets
import time

# --------------------------------------------------------------------------
# BER encoding
# --------------------------------------------------------------------------
END = object()  # noSuchObject / noSuchInstance / endOfMibView


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _int(v: int) -> bytes:
    return _tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(chunk)
    return _tlv(0x06, bytes(body))


def _request(community: str, pdu_tag: int, req_id: int, oids: list[str], a: int = 0, b: int = 0) -> bytes:
    binds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(pdu_tag, _int(req_id) + _int(a) + _int(b) + _tlv(0x30, binds))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)


def _read(buf: bytes, i: int) -> tuple[int, bytes, int]:
    tag = buf[i]
    n = buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def _dec_oid(b: bytes) -> str:
    out = [b[0] // 40, b[0] % 40]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            out.append(v)
            v = 0
    return ".".join(map(str, out))


def _value(tag: int, body: bytes):
    if tag == 0x02:
        return int.from_bytes(body, "big", signed=True) if body else 0
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(body, "big") if body else 0
    if tag == 0x04:
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.hex(":")
    if tag == 0x06:
        return _dec_oid(body)
    if tag == 0x40:
        return ".".join(str(x) for x in body)
    if tag in (0x80, 0x81, 0x82):
        return END
    if tag == 0x05:
        return None
    return body.hex()


def _parse(buf: bytes) -> tuple[int, int, list[tuple[str, object]]]:
    _, msg, _ = _read(buf, 0)
    i = 0
    _, _ver, i = _read(msg, i)
    _, _comm, i = _read(msg, i)
    _, pdu, _ = _read(msg, i)
    j = 0
    _, rid, j = _read(pdu, j)
    _, err, j = _read(pdu, j)
    _, _idx, j = _read(pdu, j)
    _, binds, _ = _read(pdu, j)
    out, k = [], 0
    while k < len(binds):
        _, vb, k = _read(binds, k)
        _, ob, m = _read(vb, 0)
        vt, vv, _ = _read(vb, m)
        out.append((_dec_oid(ob), _value(vt, vv)))
    return int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big"), out


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------
class SnmpError(Exception):
    pass


class _Proto(asyncio.DatagramProtocol):
    def __init__(self):
        self.waiting: dict[int, asyncio.Future] = {}

    def datagram_received(self, data, addr):
        try:
            rid, err, binds = _parse(data)
        except Exception:  # noqa: BLE001 - ignore anything malformed
            return
        fut = self.waiting.pop(rid, None)
        if fut and not fut.done():
            fut.set_result((err, binds))

    def error_received(self, exc):
        for fut in self.waiting.values():
            if not fut.done():
                fut.set_exception(exc)
        self.waiting.clear()


class Session:
    """One device. Use as `async with Session(ip, community) as s:`."""

    def __init__(self, host: str, community: str, timeout: float = 2.0, retries: int = 1, port: int = 161):
        self.host, self.community, self.timeout, self.retries, self.port = host, community, timeout, retries, port
        self.requests = 0

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, self.proto = await loop.create_datagram_endpoint(_Proto, remote_addr=(self.host, self.port))
        return self

    async def __aexit__(self, *exc):
        self.transport.close()

    async def _ask(self, tag: int, oids: list[str], a: int = 0, b: int = 0, timeout: float | None = None):
        for attempt in range(self.retries + 1):
            rid = secrets.randbelow(2 ** 31 - 1) + 1
            fut = asyncio.get_running_loop().create_future()
            self.proto.waiting[rid] = fut
            self.transport.sendto(_request(self.community, tag, rid, oids, a, b))
            self.requests += 1
            try:
                err, binds = await asyncio.wait_for(fut, timeout or self.timeout)
            except asyncio.TimeoutError:
                self.proto.waiting.pop(rid, None)
                continue
            except OSError as e:  # e.g. port unreachable
                self.proto.waiting.pop(rid, None)
                raise SnmpError(f"no SNMP reply ({e.strerror or e})") from None
            if err:
                raise SnmpError(f"device returned SNMP error {err}")
            return binds
        raise SnmpError("no SNMP reply (check SNMP is on and the community name is right)")

    async def get(self, oids: list[str]) -> dict[str, object]:
        return {o: v for o, v in await self._ask(0xA0, oids) if v is not END}

    async def walk(self, root: str, limit: int = 3000, timeout: float | None = None, per: int = 25) -> dict[str, object]:
        """Every value under root, keyed by the OID suffix after root (e.g. '3.1.2')."""
        root = root.strip(".")
        out, cur = {}, root
        while len(out) < limit:
            binds = await self._ask(0xA5, [cur], 0, per, timeout)
            if not binds:
                break
            done = False
            for oid, val in binds:
                if val is END or not oid.startswith(root + "."):
                    done = True
                    break
                out[oid[len(root) + 1:]] = val
                cur = oid
            if done:
                break
        return out


def _cols(walked: dict[str, object]) -> dict[str, dict[str, object]]:
    """{'col.index': v} -> {index: {col: v}}"""
    rows: dict[str, dict[str, object]] = {}
    for k, v in walked.items():
        col, _, idx = k.partition(".")
        rows.setdefault(idx, {})[col] = v
    return rows


# --------------------------------------------------------------------------
# What Rollcall reads
# --------------------------------------------------------------------------
SYS = "1.3.6.1.2.1.1"
IF_TYPES_PHYSICAL = {6, 62, 69, 117}           # ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet
PSE_DETECT = {1: "disabled", 2: "searching", 3: "delivering power", 4: "fault", 5: "test", 6: "other fault"}
PSE_MAIN = {1: "on", 2: "off", 3: "faulty"}
PRIORITY = {1: "critical", 2: "high", 3: "low"}
BUFFALO = "1.3.6.1.4.1.5227.27.1"
NAS_DISK = {-1: "not supported", 1: "normal", 2: "OK, in array 1", 3: "OK, in array 2", 4: "hot spare", 5: "degraded",
            6: "removed", 7: "hot spare removed", 8: "degraded, removed", 9: "removed", 10: "OK, in array 3",
            11: "OK, in array 4", 12: "media cartridge", 13: "OK, in array 5", 14: "OK, in array 6"}
NAS_DISK_BAD = {5, 6, 8, 9}
NAS_RAID = {-1: "not supported", 1: "off", 2: "RAID 0", 3: "RAID 1", 4: "RAID 5", 5: "RAID 6", 6: "RAID 10",
            7: "RAID 50", 8: "RAID 51", 9: "RAID 60", 10: "RAID 61"}


def _smart(v) -> str:
    """TeraStations report SMART as a number (1 = healthy) or, on some firmware, as text."""
    if v is None or v == "":
        return ""
    if isinstance(v, int):
        return {1: "OK", 0: "not checked", -1: "not supported"}.get(v, f"warning (code {v})")
    return str(v)


async def poll(host: str, community: str, timeout: float = 2.0, port: int = 161) -> dict:
    """Everything Rollcall shows for an SNMP device. Raises SnmpError if it doesn't answer."""
    t0 = time.monotonic()
    async with Session(host, community, timeout, port=port) as s:
        sysv = await s.get([f"{SYS}.1.0", f"{SYS}.2.0", f"{SYS}.3.0", f"{SYS}.5.0", f"{SYS}.6.0"])
        if not sysv:
            raise SnmpError("the device answered but returned no system information")
        out = {"descr": str(sysv.get(f"{SYS}.1.0") or ""), "object_id": str(sysv.get(f"{SYS}.2.0") or ""),
               "uptime_s": (sysv.get(f"{SYS}.3.0") or 0) // 100 if isinstance(sysv.get(f"{SYS}.3.0"), int) else None,
               "name": str(sysv.get(f"{SYS}.5.0") or ""), "location": str(sysv.get(f"{SYS}.6.0") or ""),
               "ports": [], "poe": None, "nas": None}

        # Interfaces: physical ports only (not VLANs, LAGs, the CPU or absent slots)
        cols = {}
        for col, oid in (("descr", "1.3.6.1.2.1.2.2.1.2"), ("type", "1.3.6.1.2.1.2.2.1.3"),
                         ("admin", "1.3.6.1.2.1.2.2.1.7"), ("oper", "1.3.6.1.2.1.2.2.1.8"),
                         ("in_err", "1.3.6.1.2.1.2.2.1.14"), ("out_err", "1.3.6.1.2.1.2.2.1.20"),
                         ("name", "1.3.6.1.2.1.31.1.1.1.1"), ("speed", "1.3.6.1.2.1.31.1.1.1.15"),
                         ("alias", "1.3.6.1.2.1.31.1.1.1.18")):
            try:
                cols[col] = await s.walk(oid)
            except SnmpError:
                if col in ("descr", "type", "oper"):
                    raise
                cols[col] = {}
        for idx, typ in cols["type"].items():
            oper = cols["oper"].get(idx)
            if typ not in IF_TYPES_PHYSICAL or oper == 6:  # 6 = notPresent
                continue
            out["ports"].append({
                "index": int(idx), "name": str(cols["name"].get(idx) or cols["descr"].get(idx) or idx),
                "descr": str(cols["descr"].get(idx) or ""), "alias": str(cols["alias"].get(idx) or ""),
                "admin_up": cols["admin"].get(idx) == 1, "up": oper == 1, "speed_mbps": cols["speed"].get(idx),
                "in_errors": cols["in_err"].get(idx), "out_errors": cols["out_err"].get(idx)})
        out["ports"].sort(key=lambda p: p["index"])

        # PoE (POWER-ETHERNET-MIB), if the switch has it
        try:
            ports = _cols(await s.walk("1.3.6.1.2.1.105.1.1.1"))
            mains = _cols(await s.walk("1.3.6.1.2.1.105.1.3.1.1"))
        except SnmpError:
            ports, mains = {}, {}
        if ports or mains:
            m = next(iter(mains.values()), {})
            out["poe"] = {
                "power_w": m.get("2"), "status": PSE_MAIN.get(m.get("3"), str(m.get("3") or "")),
                "used_w": m.get("4"), "threshold_pct": m.get("5"),
                "ports": sorted(({"index": int(idx.split(".")[-1]), "group": int(idx.split(".")[0]),
                                  "enabled": r.get("3") == 1, "state": PSE_DETECT.get(r.get("6"), str(r.get("6"))),
                                  "fault": r.get("6") in (4, 6), "priority": PRIORITY.get(r.get("7"), ""),
                                  "class": (r.get("10") - 1) if isinstance(r.get("10"), int) and r.get("10") > 0 else None,
                                  "denied": r.get("12") or 0, "overload": r.get("13") or 0, "short": r.get("14") or 0}
                                 for idx, r in ports.items() if "." in idx), key=lambda p: (p["group"], p["index"]))}

        # Buffalo TeraStation (BUFFALO-NAS-MIB)
        if out["object_id"].startswith("1.3.6.1.4.1.5227") or "terastation" in out["descr"].lower():
            nas = {"disks": [], "arrays": [], "errors": [], "info": {}, "unavailable": []}
            try:
                for idx, r in sorted(_cols(await s.walk(f"{BUFFALO}.2.1", timeout=max(timeout, 5))).items(), key=lambda kv: int(kv[0] or 0)):
                    st = r.get("2")
                    nas["disks"].append({"index": int(idx), "status": NAS_DISK.get(st, str(st)), "bad": st in NAS_DISK_BAD,
                                         "spare_missing": st == 7, "smart": _smart(r.get("5")),
                                         "model": str(r.get("30") or "").strip(), "capacity_gib": r.get("24")})
                for idx, r in sorted(_cols(await s.walk(f"{BUFFALO}.3.1", timeout=max(timeout, 5))).items(), key=lambda kv: int(kv[0] or 0)):
                    cap, used = r.get("5"), r.get("8")
                    nas["arrays"].append({"index": int(idx), "raid": NAS_RAID.get(r.get("2"), str(r.get("2"))),
                                          "configured": r.get("2") not in (1, -1, None),
                                          "capacity_gib": cap if isinstance(cap, int) and cap >= 0 else None,
                                          "used_gib": used if isinstance(used, int) and used >= 0 else None})
            except SnmpError as err:
                nas["error"] = f"couldn't read the disks and arrays: {err}"
            # The NAS builds these on request, so they can be slow: give them longer, ask for
            # fewer rows at a time, and don't alert if they don't come back.
            s.retries = 0
            try:
                errs = _cols(await s.walk(f"{BUFFALO}.4.1", timeout=8, per=10))
                for idx, r in sorted(errs.items()):
                    text = " ".join(str(v) for k, v in sorted(r.items(), key=lambda kv: int(kv[0])) if k != "1" and v not in (None, ""))
                    if text.strip():
                        nas["errors"].append(text.strip()[:200])
            except SnmpError:
                nas["unavailable"].append("errors")
            # Model and firmware are already in sysDescr, so the NAS's slow system-information table isn't read.
            s.retries = 1
            out["nas"] = nas
        out["requests"] = s.requests
    out["took_ms"] = int((time.monotonic() - t0) * 1000)
    return out


def evaluate(d: dict, watch: set[int], prev: dict | None) -> tuple[str, list[dict]]:
    """Problems in a poll. Returns (worst level, items) with level ok / warn / crit."""
    items: list[dict] = []
    add = lambda level, what, detail="": items.append({"level": level, "what": what, "detail": detail})  # noqa: E731
    up = d.get("uptime_s")
    if isinstance(up, int) and up < 3600:
        add("warn", "Restarted", f"{max(1, up // 60)} min ago")
    for p in d.get("ports") or []:
        if p["index"] not in watch:
            continue
        label = f"Port {p['name']}" + (f" ({p['alias']})" if p["alias"] else "")
        if not p["admin_up"]:
            add("warn", label, "disabled")
        elif not p["up"]:
            add("crit", label, "down")
    poe = d.get("poe")
    if poe:
        if poe.get("status") and poe["status"] != "on":
            add("crit", "PoE", f"power supply {poe['status']}")
        if poe.get("power_w") and poe.get("used_w") is not None and poe.get("threshold_pct"):
            pct = poe["used_w"] * 100 / poe["power_w"]
            if pct >= poe["threshold_pct"]:
                add("warn", "PoE budget", f"{poe['used_w']} of {poe['power_w']} W ({pct:.0f}%)")
        before = {p["index"]: p for p in ((prev or {}).get("poe") or {}).get("ports") or []}
        for p in poe.get("ports") or []:
            if p["fault"]:
                add("crit", f"PoE port {p['index']}", p["state"])
            b = before.get(p["index"])
            if b:
                for k, word in (("overload", "overload"), ("short", "short circuit"), ("denied", "power denied")):
                    if (p.get(k) or 0) > (b.get(k) or 0):
                        add("warn", f"PoE port {p['index']}", word)
    nas = d.get("nas")
    if nas:
        if nas.get("error"):
            add("warn", "NAS", nas["error"])
        for k in nas.get("disks") or []:
            if k["bad"]:
                add("crit", f"Disk {k['index']}", k["status"])
            elif k["spare_missing"]:
                add("warn", f"Disk {k['index']}", "hot spare removed")
            if any(w in k["smart"].lower() for w in ("fail", "bad", "caution", "warn", "error")) and not k["bad"]:
                add("warn", f"Disk {k['index']} SMART", k["smart"])
        for a in nas.get("arrays") or []:
            if a["configured"] and a["capacity_gib"] and a["used_gib"] is not None:
                pct = a["used_gib"] * 100 / a["capacity_gib"]
                if pct >= 97:
                    add("crit", f"Array {a['index']}", f"{pct:.0f}% full")
                elif pct >= 90:
                    add("warn", f"Array {a['index']}", f"{pct:.0f}% full")
        for e in nas.get("errors") or []:
            add("warn", "NAS reports", e)
    worst = "crit" if any(i["level"] == "crit" for i in items) else "warn" if items else "ok"
    return worst, items
