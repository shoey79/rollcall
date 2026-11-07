"""A small SNMP client (v2c, and v3 with authentication and privacy; GET and GETBULK walks over UDP),
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


# --------------------------------------------------------------------------
# SNMP v3 security (USM: RFC 3414, AES RFC 3826, SHA-2 RFC 7860)
# --------------------------------------------------------------------------
import hashlib  # noqa: E402
import hmac  # noqa: E402

AUTH = {  # name: (hash, digest bytes sent)
    "MD5": ("md5", 12), "SHA": ("sha1", 12), "SHA-224": ("sha224", 16),
    "SHA-256": ("sha256", 24), "SHA-384": ("sha384", 32), "SHA-512": ("sha512", 48)}
PRIV = {"DES": 16, "AES-128": 16, "AES-192": 24, "AES-256": 32}  # localized key bytes needed
_USM_REPORTS = {
    "1.3.6.1.6.3.15.1.1.1.0": "the device doesn't allow this security level for that user",
    "1.3.6.1.6.3.15.1.1.3.0": "unknown SNMP v3 user name",
    "1.3.6.1.6.3.15.1.1.5.0": "wrong authentication password or protocol",
    "1.3.6.1.6.3.15.1.1.6.0": "wrong privacy password or protocol",
}
_NOT_IN_TIME = "1.3.6.1.6.3.15.1.1.2.0"
_UNKNOWN_ENGINE = "1.3.6.1.6.3.15.1.1.4.0"


def _password_key(password: str, hname: str) -> bytes:
    """RFC 3414 A.2: the password repeated to 1 MB, hashed."""
    pw = password.encode()
    return hashlib.new(hname, (pw * (1048576 // len(pw) + 1))[:1048576]).digest()


def _localize(key: bytes, engine: bytes, hname: str) -> bytes:
    return hashlib.new(hname, key + engine + key).digest()


def _priv_key(password: str, hname: str, engine: bytes, need: int) -> bytes:
    k = _localize(_password_key(password, hname), engine, hname)
    while len(k) < need:  # AES-192/256 with a short hash: extend as Net-SNMP does (Blumenthal)
        k += hashlib.new(hname, k).digest()
    return k[:need]


def _cipher(priv: str, key: bytes, iv: bytes):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if priv == "DES":
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # cryptography < 43
            TripleDES = algorithms.TripleDES  # noqa: N806
        k = key[:8]
        return Cipher(TripleDES(k + k + k), modes.CBC(iv))  # 3DES with K1=K2=K3 is single DES
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:  # cryptography < 47
        CFB = modes.CFB  # noqa: N806
    return Cipher(algorithms.AES(key), CFB(iv))


class V3:
    """User settings for SNMP v3."""

    def __init__(self, user: str, auth: str | None = None, auth_pass: str = "", priv: str | None = None,
                 priv_pass: str = "", context: str = ""):
        if auth and auth not in AUTH:
            raise ValueError(f"unknown authentication protocol {auth}")
        if priv and priv not in PRIV:
            raise ValueError(f"unknown privacy protocol {priv}")
        if priv and not auth:
            raise ValueError("privacy needs authentication too")
        self.user, self.auth, self.auth_pass, self.priv, self.priv_pass, self.context = \
            user, auth, auth_pass, priv, priv_pass, context
        self._keys: dict[bytes, tuple[bytes, bytes]] = {}

    def keys(self, engine: bytes) -> tuple[bytes, bytes]:
        if engine not in self._keys:
            hname = AUTH[self.auth][0] if self.auth else "sha1"
            ak = _localize(_password_key(self.auth_pass, hname), engine, hname) if self.auth else b""
            pk = _priv_key(self.priv_pass, hname, engine, PRIV[self.priv]) if self.priv else b""
            self._keys[engine] = (ak, pk)
        return self._keys[engine]


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------
_ERRSTAT = {6: "the device refused access (noAccess)",
            16: "the device doesn't allow this user or community at this security level (authorizationError)"}


class SnmpError(Exception):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status  # SNMP error-status from the device; None for no reply; -1 for a security problem


class _Proto(asyncio.DatagramProtocol):
    def __init__(self):
        self.waiting: dict[int, asyncio.Future] = {}
        self.key = None  # datagram -> id it answers

    def datagram_received(self, data, addr):
        try:
            k = self.key(data)
        except Exception:  # noqa: BLE001 - ignore anything malformed
            return
        fut = self.waiting.pop(k, None)
        if fut and not fut.done():
            fut.set_result(data)

    def error_received(self, exc):
        for fut in self.waiting.values():
            if not fut.done():
                fut.set_exception(exc)
        self.waiting.clear()


def _binds(pdu: bytes) -> tuple[int, int, list[tuple[str, object]]]:
    j = 0
    _, rid, j = _read(pdu, j)
    _, err, j = _read(pdu, j)
    _, _idx, j = _read(pdu, j)
    _, bl, _ = _read(pdu, j)
    out, k = [], 0
    while k < len(bl):
        _, vb, k = _read(bl, k)
        _, ob, m = _read(vb, 0)
        vt, vv, _ = _read(vb, m)
        out.append((_dec_oid(ob), _value(vt, vv)))
    return int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big"), out


def _v3_header(data: bytes) -> dict:
    _, msg, _ = _read(data, 0)
    i = 0
    _, ver, i = _read(msg, i)
    if int.from_bytes(ver, "big") != 3:
        raise ValueError("not v3")
    _, glob, i = _read(msg, i)
    g = 0
    _, mid, g = _read(glob, g)
    _, _max, g = _read(glob, g)
    _, flags, g = _read(glob, g)
    _, sp, i = _read(msg, i)
    _, sec, _ = _read(sp, 0)
    q = 0
    _, eng, q = _read(sec, q)
    _, boots, q = _read(sec, q)
    _, etime, q = _read(sec, q)
    _, user, q = _read(sec, q)
    _, authp, q = _read(sec, q)
    _, privp, q = _read(sec, q)
    dtag, dbody, _ = _read(msg, i)
    return {"id": int.from_bytes(mid, "big"), "flags": flags[0] if flags else 0, "engine": eng,
            "boots": int.from_bytes(boots, "big") if boots else 0, "time": int.from_bytes(etime, "big") if etime else 0,
            "user": user, "authp": authp, "privp": privp, "dtag": dtag, "data": dbody}


class Session:
    """One device. Use as `async with Session(ip, community) as s:`, or pass v3=V3(...) for SNMP v3."""

    def __init__(self, host: str, community: str = "", timeout: float = 2.0, retries: int = 1, port: int = 161,
                 per: int = 25, v3: V3 | None = None):
        self.host, self.community, self.timeout, self.retries, self.port = host, community, timeout, retries, port
        self.requests = 0
        self.per = per  # rows asked for at a time; lowered if the device can't keep up
        self.v3 = v3
        self.engine, self.boots, self.etime, self.etime_at = b"", 0, 0, 0.0
        self._salt = secrets.randbits(64)

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, self.proto = await loop.create_datagram_endpoint(_Proto, remote_addr=(self.host, self.port))
        self.proto.key = (lambda d: _v3_header(d)["id"]) if self.v3 else self._v2_key
        return self

    @staticmethod
    def _v2_key(data: bytes) -> int:
        _, msg, _ = _read(data, 0)
        i = 0
        _, _ver, i = _read(msg, i)
        _, _comm, i = _read(msg, i)
        _, pdu, _ = _read(msg, i)
        return _binds(pdu)[0]

    async def __aexit__(self, *exc):
        self.transport.close()

    async def _send(self, key: int, packet: bytes, timeout: float) -> bytes | None:
        fut = asyncio.get_running_loop().create_future()
        self.proto.waiting[key] = fut
        self.transport.sendto(packet)
        self.requests += 1
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self.proto.waiting.pop(key, None)
            return None
        except OSError as e:  # e.g. port unreachable
            self.proto.waiting.pop(key, None)
            raise SnmpError(f"no SNMP reply ({e.strerror or e})") from None

    async def _ask(self, tag: int, oids: list[str], a: int = 0, b: int = 0, timeout: float | None = None):
        if self.v3:
            return await self._ask_v3(tag, oids, a, b, timeout)
        for _attempt in range(self.retries + 1):
            rid = secrets.randbelow(2 ** 31 - 1) + 1
            data = await self._send(rid, _request(self.community, tag, rid, oids, a, b), timeout or self.timeout)
            if data is None:
                continue
            _, msg, _ = _read(data, 0)
            i = 0
            _, _ver, i = _read(msg, i)
            _, _comm, i = _read(msg, i)
            _, pdu, _ = _read(msg, i)
            _, err, binds = _binds(pdu)
            if err:
                raise SnmpError(_ERRSTAT.get(err, f"device returned SNMP error {err}"), err)
            return binds
        raise SnmpError("no SNMP reply (check SNMP is on and the community name is right)")

    # ---- v3 ----
    def _v3_packet(self, msg_id: int, flags: int, scoped: bytes, user: bytes) -> bytes:
        v = self.v3
        authp = privp = b""
        data = _tlv(0x30, scoped)
        if flags & 2:  # privacy
            ak, pk = v.keys(self.engine)
            self._salt = (self._salt + 1) & (2 ** 64 - 1)
            if v.priv == "DES":
                privp = self.boots.to_bytes(4, "big") + (self._salt & 0xFFFFFFFF).to_bytes(4, "big")
                iv = bytes(x ^ y for x, y in zip(pk[8:16], privp))
                plain = data + b"\x00" * (-len(data) % 8)
            else:
                privp = self._salt.to_bytes(8, "big")
                iv = self.boots.to_bytes(4, "big") + self._engine_time().to_bytes(4, "big") + privp
                plain = data
            enc = _cipher(v.priv, pk, iv).encryptor()
            data = _tlv(0x04, enc.update(plain) + enc.finalize())
        if flags & 1:
            authp = b"\x00" * AUTH[v.auth][1]
        sec = _tlv(0x30, _tlv(0x04, self.engine) + _int(self.boots) + _int(self._engine_time() if self.engine else 0)
                   + _tlv(0x04, user) + _tlv(0x04, authp) + _tlv(0x04, privp))
        glob = _tlv(0x30, _int(msg_id) + _int(65507) + _tlv(0x04, bytes([flags])) + _int(3))
        packet = _tlv(0x30, _int(3) + glob + _tlv(0x04, sec) + data)
        if flags & 1:
            ak, _ = v.keys(self.engine)
            hname, n = AUTH[v.auth]
            digest = hmac.new(ak, packet, hname).digest()[:n]
            at = packet.index(_tlv(0x04, authp)) + 2
            packet = packet[:at] + digest + packet[at + n:]
        return packet

    def _engine_time(self) -> int:
        return int(self.etime + (time.monotonic() - self.etime_at))

    def _flags(self) -> int:
        return (1 if self.v3.auth else 0) | (2 if self.v3.priv else 0) | 4  # 4 = reportable

    async def _discover(self, timeout: float) -> None:
        """Learn the device's engine ID, boots and time (RFC 3414 4)."""
        for _attempt in range(self.retries + 1):
            mid = secrets.randbelow(2 ** 31 - 1) + 1
            scoped = _tlv(0x04, b"") + _tlv(0x04, b"") + _tlv(0xA0, _int(mid) + _int(0) + _int(0) + _tlv(0x30, b""))
            data = await self._send(mid, self._v3_packet(mid, 4, scoped, b""), timeout)
            if data is None:
                continue
            h = _v3_header(data)
            self.engine, self.boots, self.etime, self.etime_at = h["engine"], h["boots"], h["time"], time.monotonic()
            if not self.engine:
                raise SnmpError("the device didn't send its SNMP engine ID", -1)
            return
        raise SnmpError("no SNMP v3 reply (check SNMP v3 is on for this device)")

    def _open(self, h: dict, raw: bytes) -> bytes:
        """Check a reply's signature and decrypt it; returns the scoped PDU's contents."""
        v = self.v3
        if h["flags"] & 1:
            if not v.auth:
                raise SnmpError("the device's reply was signed, but no authentication protocol is set", -1)
            ak, _ = v.keys(self.engine)
            hname, n = AUTH[v.auth]
            if len(h["authp"]) != n:
                raise SnmpError("the device's reply wasn't signed as expected", -1)
            at = raw.find(h["authp"])
            zeroed = raw[:at] + b"\x00" * n + raw[at + n:]
            if not hmac.compare_digest(hmac.new(ak, zeroed, hname).digest()[:n], h["authp"]):
                raise SnmpError("the device's reply failed its signature check (wrong authentication password?)", -1)
        if h["flags"] & 2:
            if not v.priv:
                raise SnmpError("the device's reply was encrypted, but no privacy protocol is set", -1)
            _, pk = v.keys(self.engine)
            if v.priv == "DES":
                iv = bytes(x ^ y for x, y in zip(pk[8:16], h["privp"]))
            else:
                iv = h["boots"].to_bytes(4, "big") + h["time"].to_bytes(4, "big") + h["privp"]
            dec = _cipher(v.priv, pk, iv).decryptor()
            plain = dec.update(h["data"]) + dec.finalize()
            try:
                _, scoped, _ = _read(plain, 0)
            except IndexError:
                raise SnmpError("couldn't decrypt the reply (wrong privacy password or protocol)", -1) from None
            return scoped
        return h["data"]

    async def _ask_v3(self, tag: int, oids: list[str], a: int, b: int, timeout: float | None):
        timeout = timeout or self.timeout
        if not self.engine:
            await self._discover(timeout)
        user = self.v3.user.encode()
        for attempt in range(self.retries + 2):
            mid = secrets.randbelow(2 ** 31 - 1) + 1
            binds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
            pdu = _tlv(tag, _int(mid) + _int(a) + _int(b) + _tlv(0x30, binds))
            scoped = _tlv(0x04, self.engine) + _tlv(0x04, self.v3.context.encode()) + pdu
            data = await self._send(mid, self._v3_packet(mid, self._flags(), scoped, user), timeout)
            if data is None:
                continue
            h = _v3_header(data)
            body = self._open(h, data)
            i = 0
            _, _ceng, i = _read(body, i)
            _, _cname, i = _read(body, i)
            ptag, pbody, _ = _read(body, i)
            _, err, vbinds = _binds(pbody)
            if ptag == 0xA8:  # Report: a USM problem
                oid = vbinds[0][0] if vbinds else ""
                if oid in (_NOT_IN_TIME, _UNKNOWN_ENGINE) and attempt == 0:
                    self.engine, self.boots, self.etime, self.etime_at = h["engine"], h["boots"], h["time"], time.monotonic()
                    continue
                raise SnmpError(_USM_REPORTS.get(oid, f"the device refused the request ({oid})"), -1)
            if self.v3.auth and not h["flags"] & 1:
                raise SnmpError("the device's reply wasn't signed", -1)
            if err:
                raise SnmpError(_ERRSTAT.get(err, f"device returned SNMP error {err}"), err)
            return vbinds
        raise SnmpError("no SNMP v3 reply (check the privacy password and protocol: devices ignore requests they can't decrypt)")

    async def get(self, oids: list[str]) -> dict[str, object]:
        return {o: v for o, v in await self._ask(0xA0, oids) if v is not END}

    async def walk(self, root: str, limit: int = 3000, timeout: float | None = None, per: int | None = None) -> dict[str, object]:
        """Every value under root, keyed by the OID suffix after root (e.g. '3.1.2').
        Small switches often can't answer large GETBULK requests in time (or say tooBig):
        if that happens, ask for fewer rows at a time and carry on."""
        root = root.strip(".")
        out, cur = {}, root
        while len(out) < limit:
            n = min(per or self.per, self.per)
            try:
                binds = await self._ask(0xA5, [cur], 0, n, timeout)
            except SnmpError as err:
                if n > 1 and err.status in (None, 1, 5):  # no reply, tooBig, genErr
                    self.per = max(1, n // 3)
                    continue
                raise
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


async def poll(host: str, community: str, timeout: float = 2.0, port: int = 161, per: int = 25, v3: V3 | None = None) -> dict:
    """Everything Rollcall shows for an SNMP device. Raises SnmpError if it doesn't answer."""
    t0 = time.monotonic()
    timing: dict[str, int] = {}
    missing: list[str] = []

    async def timed(name, coro, optional=True):
        t = time.monotonic()
        try:
            return await coro
        except SnmpError:
            if not optional:
                raise
            missing.append(name)
            return {}
        finally:
            timing[name] = timing.get(name, 0) + int((time.monotonic() - t) * 1000)

    async with Session(host, community, timeout, port=port, per=per, v3=v3) as s:
        sysv = await s.get([f"{SYS}.1.0", f"{SYS}.2.0", f"{SYS}.3.0", f"{SYS}.5.0", f"{SYS}.6.0"])
        if not sysv:
            raise SnmpError("the device answered but returned no system information")
        out = {"descr": str(sysv.get(f"{SYS}.1.0") or ""), "object_id": str(sysv.get(f"{SYS}.2.0") or ""),
               "uptime_s": (sysv.get(f"{SYS}.3.0") or 0) // 100 if isinstance(sysv.get(f"{SYS}.3.0"), int) else None,
               "name": str(sysv.get(f"{SYS}.5.0") or ""), "location": str(sysv.get(f"{SYS}.6.0") or ""),
               "ports": [], "poe": None, "nas": None, "uptime_source": "snmp"}
        # sysUpTime is how long the SNMP service has been running, which on Linux-based kit (NAS units)
        # restarts with the network. HOST-RESOURCES-MIB's hrSystemUptime is the device's own uptime.
        try:
            hr = (await s.get(["1.3.6.1.2.1.25.1.1.0"])).get("1.3.6.1.2.1.25.1.1.0")
            if isinstance(hr, int) and hr > 0:
                out["uptime_s"], out["uptime_source"] = hr // 100, "system"
        except SnmpError:
            pass

        # Interfaces: physical ports only (not VLANs, LAGs, the CPU or absent slots)
        cols = {}
        for col, oid in (("descr", "1.3.6.1.2.1.2.2.1.2"), ("type", "1.3.6.1.2.1.2.2.1.3"),
                         ("admin", "1.3.6.1.2.1.2.2.1.7"), ("oper", "1.3.6.1.2.1.2.2.1.8"),
                         ("in_err", "1.3.6.1.2.1.2.2.1.14"), ("out_err", "1.3.6.1.2.1.2.2.1.20"),
                         ("name", "1.3.6.1.2.1.31.1.1.1.1"), ("speed", "1.3.6.1.2.1.31.1.1.1.15"),
                         ("alias", "1.3.6.1.2.1.31.1.1.1.18")):
            cols[col] = await timed({"descr": "ports", "type": "ports", "oper": "ports", "admin": "port admin state",
                                     "in_err": "port errors", "out_err": "port errors", "name": "port names",
                                     "speed": "port speeds", "alias": "port descriptions"}[col], s.walk(oid),
                                    optional=col not in ("descr", "type", "oper"))
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
        ports = _cols(await timed("PoE", s.walk("1.3.6.1.2.1.105.1.1.1")))
        mains = _cols(await timed("PoE", s.walk("1.3.6.1.2.1.105.1.3.1.1")))
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
        out["per"] = s.per
        out["timing"] = timing
        out["missing"] = sorted(set(missing))
    out["took_ms"] = int((time.monotonic() - t0) * 1000)
    return out


def evaluate(d: dict, watch: set[int], prev: dict | None) -> tuple[str, list[dict]]:
    """Problems in a poll. Returns (worst level, items) with level ok / warn / crit."""
    items: list[dict] = []
    add = lambda level, what, detail="": items.append({"level": level, "what": what, "detail": detail})  # noqa: E731
    up = d.get("uptime_s")
    if isinstance(up, int) and up < 3600:
        add("warn", "Restarted", f"{max(1, up // 60)} min ago" + ("" if d.get("uptime_source") == "system"
                                                               else " (or its SNMP service did)"))
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
