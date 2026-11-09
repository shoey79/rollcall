"""A small SNMP client (v1, v2c, and v3 with authentication and privacy; GET, and GETBULK or GETNEXT
walks over UDP), plus the readers Rollcall uses for switches, PoE, Buffalo TeraStation NAS units and UPSs."""
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


def _request(community: str, pdu_tag: int, req_id: int, oids: list[str], a: int = 0, b: int = 0, version: int = 2) -> bytes:
    binds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(pdu_tag, _int(req_id) + _int(a) + _int(b) + _tlv(0x30, binds))
    return _tlv(0x30, _int(0 if version == 1 else 1) + _tlv(0x04, community.encode()) + pdu)


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
    def __init__(self, msg: str, status: int | None = None, index: int = 0):
        super().__init__(msg)
        self.status = status  # SNMP error-status from the device; None for no reply; -1 for a security problem
        self.index = index    # which OID in the request it's about (1-based; 0 = the whole request)


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


def _err_index(pdu: bytes) -> int:
    j = 0
    _, _rid, j = _read(pdu, j)
    _, _err, j = _read(pdu, j)
    _, idx, _ = _read(pdu, j)
    return int.from_bytes(idx, "big") if idx else 0


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
                 per: int = 25, v3: V3 | None = None, version: int = 2):
        self.host, self.community, self.timeout, self.retries, self.port = host, community, timeout, retries, port
        self.version = 3 if v3 else (1 if version == 1 else 2)  # v1: old kit (e.g. APC AP9617 cards) ignores v2c
        self.requests = 0
        self.timeouts = 0
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
            self.timeouts += 1
            return None
        except OSError as e:  # e.g. port unreachable
            self.proto.waiting.pop(key, None)
            raise SnmpError(f"no SNMP reply ({e.strerror or e})") from None

    async def _ask(self, tag: int, oids: list[str], a: int = 0, b: int = 0, timeout: float | None = None):
        if self.v3:
            return await self._ask_v3(tag, oids, a, b, timeout)
        for _attempt in range(self.retries + 1):
            rid = secrets.randbelow(2 ** 31 - 1) + 1
            data = await self._send(rid, _request(self.community, tag, rid, oids, a, b, self.version), timeout or self.timeout)
            if data is None:
                continue
            _, msg, _ = _read(data, 0)
            i = 0
            _, _ver, i = _read(msg, i)
            _, _comm, i = _read(msg, i)
            _, pdu, _ = _read(msg, i)
            _, err, binds = _binds(pdu)
            if err:
                raise SnmpError(_ERRSTAT.get(err, f"device returned SNMP error {err}"), err, _err_index(pdu))
            return binds
        raise SnmpError("no SNMP reply (check SNMP is on, the community name is right, the device allows this address"
                        + (", and that it speaks SNMP v2c: older kit may only answer v1)" if self.version == 2 else ")"))

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

    async def get(self, oids: list[str], timeout: float | None = None) -> dict[str, object]:
        if self.version != 1:
            return {o: v for o, v in await self._ask(0xA0, oids, timeout=timeout) if v is not END}
        # SNMP v1 has no "no such object" value: the device rejects the whole request and says which
        # OID it didn't have (noSuchName), so drop that one and ask again.
        oids = list(oids)
        while oids:
            try:
                return {o: v for o, v in await self._ask(0xA0, oids, timeout=timeout) if v is not END}
            except SnmpError as err:
                if err.status != 2:
                    raise
                if not 1 <= err.index <= len(oids):
                    return {}
                oids.pop(err.index - 1)
        return {}

    async def walk(self, root: str, limit: int = 3000, timeout: float | None = None, per: int | None = None) -> dict[str, object]:
        """Every value under root, keyed by the OID suffix after root (e.g. '3.1.2').
        Small switches often can't answer large GETBULK requests in time (or say tooBig):
        if that happens, ask for fewer rows at a time and carry on."""
        root = root.strip(".")
        out, cur = {}, root
        if self.version == 1:  # no GETBULK in v1: one GETNEXT per value; noSuchName marks the end
            while len(out) < limit:
                try:
                    binds = await self._ask(0xA1, [cur], timeout=timeout)
                except SnmpError as err:
                    if err.status == 2:
                        break
                    raise
                if not binds or binds[0][1] is END or binds[0][0] == cur or not binds[0][0].startswith(root + "."):
                    break
                cur = binds[0][0]
                out[cur[len(root) + 1:]] = binds[0][1]
            return out
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


# UPSs: APC's PowerNet-MIB (Network Management Cards), or the standard UPS-MIB (RFC 1628) that
# Eaton, CyberPower, Riello and most others' network cards also answer.
APC = "1.3.6.1.4.1.318.1.1.1"
APC_OUTPUT = {1: "unknown", 2: "on mains", 3: "on battery", 4: "on mains, boosting low voltage", 5: "sleeping (timed)",
              6: "bypassed (by software)", 7: "off", 8: "rebooting", 9: "bypassed (by switch)", 10: "bypassed: hardware failure",
              11: "sleeping until power returns", 12: "on mains, trimming high voltage", 13: "eco mode", 14: "hot standby",
              15: "on battery (test)", 16: "emergency static bypass", 17: "static bypass standby", 18: "power-saving mode",
              19: "spot mode", 20: "eConversion", 21: "charger spot mode", 22: "inverter spot mode", 23: "active load",
              24: "battery discharge spot mode", 25: "inverter standby", 26: "charger only", 27: "distributed energy reserve",
              28: "self-test"}
APC_ON_BATTERY, APC_BYPASS, APC_OFF = {3}, {6, 9, 16}, {5, 7, 10, 11}
APC_BATTERY = {1: "unknown", 2: "normal", 3: "low", 4: "fault", 5: "no battery"}
APC_TRANSFER = {1: "none", 2: "high input voltage", 3: "brownout", 4: "blackout (power cut)", 5: "small momentary sag",
                6: "deep momentary sag", 7: "small momentary spike", 8: "large momentary spike", 9: "self-test",
                10: "rapid change of input voltage"}
APC_DIAG = {1: "passed", 2: "failed", 3: "invalid test", 4: "in progress"}
APC_CAL = {1: "OK", 2: "invalid", 3: "in progress"}
APC_SCHEDULE = {1: "unknown", 2: "every 2 weeks", 3: "weekly", 4: "at turn on", 5: "never", 6: "every 4 weeks",
                7: "every 12 weeks", 8: "2 weeks after the last test", 9: "a week after the last test", 10: "every 8 weeks",
                11: "every 26 weeks", 12: "every 52 weeks"}
UPSMIB = "1.3.6.1.2.1.33.1"
UPS_SOURCE = {1: "other", 2: "none (output off)", 3: "on mains", 4: "bypassed", 5: "on battery", 6: "on mains, boosting low voltage",
              7: "on mains, trimming high voltage"}
UPS_BATTERY = {1: "unknown", 2: "normal", 3: "low", 4: "depleted"}
UPS_TEST = {1: "passed", 2: "passed with warnings", 3: "failed", 4: "aborted", 5: "in progress", 6: "never run"}
UPS_ALARMS = {1: "battery bad", 2: "on battery", 3: "low battery", 4: "battery depleted", 5: "temperature out of range",
              6: "input out of range", 7: "output out of range", 8: "output overloaded", 9: "on bypass", 10: "bypass out of range",
              11: "output off (as requested)", 12: "UPS off (as requested)", 13: "charger failed", 14: "output off",
              15: "UPS system off", 16: "fan failure", 17: "fuse failure", 18: "general fault", 19: "self-test failed",
              20: "lost contact with the UPS", 21: "awaiting power", 22: "shutdown pending", 23: "shutdown imminent",
              24: "test in progress"}
# Makers whose network cards answer UPS-MIB: Eaton/Powerware, MGE, CyberPower, Riello, Socomec, Vertiv/Liebert,
# Tripp Lite, Legrand, Salicru, Delta, Huawei. Others are asked if "UPS" appears in their description or name.
UPS_ENTERPRISES = {"534", "705", "3808", "5491", "4555", "476", "850", "13891", "19536", "2254", "2011", "935"}


def _apc_date(v) -> str:
    """APC cards give dates as mm/dd/yy or mm/dd/yyyy; returns yyyy-mm-dd ('' if unreadable)."""
    import re
    m = re.match(r"\s*(\d{1,2})/(\d{1,2})/(\d{2}|\d{4})\s*$", str(v or ""))
    if not m:
        return ""
    mo, d, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
    y += 2000 if y < 70 else 1900 if y < 100 else 0
    return f"{y:04d}-{mo:02d}-{d:02d}" if 1 <= mo <= 12 and 1 <= d <= 31 else ""


def _num(v):
    return v if isinstance(v, int) else None


async def read_apc(s: "Session") -> dict | None:
    A = APC
    g = await get_many(s, [f"{A}.{x}.0" for x in (
        "1.1.1", "1.1.2", "1.2.1", "1.2.2", "1.2.3", "2.1.1", "2.1.2", "2.1.3", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5",
        "2.2.6", "3.2.1", "3.2.4", "3.2.5", "4.1.1", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "7.2.1", "7.2.3", "7.2.4", "7.2.6",
        "7.2.7")])
    if f"{A}.4.1.1.0" not in g and f"{A}.2.1.1.0" not in g:
        return None  # an APC card that isn't on a UPS (a PDU or environment monitor)
    v = lambda x: g.get(f"{A}.{x}.0")  # noqa: E731
    out_st, bat = _num(v("4.1.1")), _num(v("2.1.1"))
    runtime = _num(v("2.2.3"))
    return {
        "kind": "APC", "model": str(v("1.1.1") or "").strip(), "name": str(v("1.1.2") or "").strip(),
        "firmware": str(v("1.2.1") or "").strip(), "made": _apc_date(v("1.2.2")), "serial": str(v("1.2.3") or "").strip(),
        "output": APC_OUTPUT.get(out_st, str(out_st or "")) if out_st else "", "on_battery": out_st in APC_ON_BATTERY,
        "bypass": out_st in APC_BYPASS, "off": out_st in APC_OFF,
        "battery": APC_BATTERY.get(bat, str(bat or "")) if bat else "", "battery_low": bat == 3, "battery_fault": bat in (4, 5),
        "charge_pct": _num(v("2.2.1")), "battery_temp_c": _num(v("2.2.2")),
        "runtime_min": runtime // 6000 if runtime is not None else None,
        "on_battery_s": _num(v("2.1.2")) // 100 if _num(v("2.1.2")) is not None else None,
        "replace": v("2.2.4") == 2, "replaced": _apc_date(v("2.1.3")),
        "bad_packs": _num(v("2.2.6")) or 0, "packs": _num(v("2.2.5")),
        "input_v": _num(v("3.2.1")), "input_hz": _num(v("3.2.4")),
        "last_transfer": APC_TRANSFER.get(_num(v("3.2.5")), "") if v("3.2.5") is not None else "",
        "output_v": _num(v("4.2.1")), "output_hz": _num(v("4.2.2")), "load_pct": _num(v("4.2.3")), "output_a": _num(v("4.2.4")),
        "test_schedule": APC_SCHEDULE.get(_num(v("7.2.1")), "") if v("7.2.1") is not None else "",
        "self_test": APC_DIAG.get(_num(v("7.2.3")), "") if v("7.2.3") is not None else "",
        "self_test_failed": v("7.2.3") == 2, "self_test_date": _apc_date(v("7.2.4")),
        "calibration": APC_CAL.get(_num(v("7.2.6")), "") if v("7.2.6") is not None else "",
        "calibration_date": _apc_date(v("7.2.7")), "alarms": []}


async def read_upsmib(s: "Session") -> dict | None:
    U = UPSMIB
    g = await get_many(s, [f"{U}.{x}" for x in (
        "1.1.0", "1.2.0", "1.3.0", "1.5.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.7.0", "3.2.0", "3.3.1.2.1", "3.3.1.3.1",
        "4.1.0", "4.2.0", "4.4.1.2.1", "4.4.1.3.1", "4.4.1.5.1", "6.1.0", "7.3.0")])
    if f"{U}.2.1.0" not in g and f"{U}.4.1.0" not in g:
        return None  # not a UPS after all
    v = lambda x: g.get(f"{U}.{x}")  # noqa: E731
    src, bat = _num(v("4.1.0")), _num(v("2.1.0"))
    alarms = []
    if _num(v("6.1.0")):
        try:  # upsAlarmDescr: each present alarm's well-known OID
            for oid in (await s.walk(f"{U}.6.2.1.2", limit=40)).values():
                n = str(oid).rsplit(".", 1)[-1]
                alarms.append(UPS_ALARMS.get(int(n), f"alarm {n}") if str(oid).startswith(f"{U}.6.3.") and n.isdigit() else str(oid))
        except SnmpError:
            alarms.append(f"{v('6.1.0')} alarm(s)")
    tenth = lambda x: round(v(x) / 10, 1) if _num(v(x)) is not None else None  # noqa: E731
    test = _num(v("7.3.0"))
    return {
        "kind": "UPS-MIB", "model": " ".join(str(x).strip() for x in (v("1.1.0"), v("1.2.0")) if x).strip(),
        "name": str(v("1.5.0") or "").strip(), "firmware": str(v("1.3.0") or "").strip(), "made": "", "serial": "",
        "output": UPS_SOURCE.get(src, str(src or "")) if src else "", "on_battery": src == 5, "bypass": src == 4, "off": src == 2,
        "battery": UPS_BATTERY.get(bat, str(bat or "")) if bat else "", "battery_low": bat == 3, "battery_fault": bat == 4,
        "charge_pct": _num(v("2.4.0")), "battery_temp_c": _num(v("2.7.0")), "runtime_min": _num(v("2.3.0")),
        "on_battery_s": _num(v("2.2.0")), "replace": "battery bad" in alarms, "replaced": "", "bad_packs": 0, "packs": None,
        "input_v": _num(v("3.3.1.3.1")), "input_hz": tenth("3.3.1.2.1"), "last_transfer": "",
        "output_v": _num(v("4.4.1.2.1")), "output_hz": tenth("4.2.0"), "load_pct": _num(v("4.4.1.5.1")), "output_a": tenth("4.4.1.3.1"),
        "test_schedule": "", "self_test": UPS_TEST.get(test, "") if test else "", "self_test_failed": test == 3,
        "self_test_date": "", "calibration": "", "calibration_date": "", "alarms": alarms}


def _smart(v) -> str:
    """TeraStations report SMART as a number (1 = healthy) or, on some firmware, as text."""
    if v is None or v == "":
        return ""
    if isinstance(v, int):
        return {1: "OK", 0: "not checked", -1: "not supported"}.get(v, f"warning (code {v})")
    return str(v)


async def get_many(s: "Session", oids: list[str], batch: int = 10) -> dict[str, object]:
    """GET a list of OIDs, a batch per request. A batch that fails is retried an OID at a time
    (some devices reject a whole request if one OID is unknown)."""
    out: dict[str, object] = {}
    for n in range(0, len(oids), batch):
        chunk = oids[n:n + batch]
        try:
            out.update(await s.get(chunk))
        except SnmpError as err:
            if err.status is None and len(chunk) > 1 and s.timeouts > 6:
                raise  # the device has stopped answering
            if len(chunk) == 1:
                continue
            for o in chunk:
                try:
                    out.update(await s.get([o]))
                except SnmpError:
                    pass
    return out


async def poll(host: str, community: str, timeout: float = 2.0, port: int = 161, per: int = 25, v3: V3 | None = None,
               ask_hr: bool = True, discovery: dict | None = None, version: int = 2) -> dict:
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

    async with Session(host, community, timeout, port=port, per=per, v3=v3, version=version) as s:
        sysv = await s.get([f"{SYS}.1.0", f"{SYS}.2.0", f"{SYS}.3.0", f"{SYS}.5.0", f"{SYS}.6.0"])
        if not sysv:
            raise SnmpError("the device answered but returned no system information")
        out = {"descr": str(sysv.get(f"{SYS}.1.0") or ""), "object_id": str(sysv.get(f"{SYS}.2.0") or ""),
               "uptime_s": (sysv.get(f"{SYS}.3.0") or 0) // 100 if isinstance(sysv.get(f"{SYS}.3.0"), int) else None,
               "name": str(sysv.get(f"{SYS}.5.0") or ""), "location": str(sysv.get(f"{SYS}.6.0") or ""),
               "ports": [], "poe": None, "nas": None, "ups": None, "uptime_source": "snmp"}
        # sysUpTime is how long the SNMP service has been running, which on Linux-based kit (NAS units)
        # restarts with the network. HOST-RESOURCES-MIB's hrSystemUptime is the device's own uptime.
        # Asked once per device: some switches (e.g. Netgear smart switches) stall their SNMP service
        # when asked for something they don't have, so a device that doesn't answer isn't asked again.
        out["hr"] = False
        if ask_hr:
            t = time.monotonic()
            retries, s.retries = s.retries, 0
            try:
                hr = (await s.get(["1.3.6.1.2.1.25.1.1.0"], timeout=min(timeout, 1.5))).get("1.3.6.1.2.1.25.1.1.0")
                if isinstance(hr, int) and hr > 0:
                    out["uptime_s"], out["uptime_source"], out["hr"] = hr // 100, "system", True
            except SnmpError:
                pass
            finally:
                s.retries = retries
                timing["device uptime"] = int((time.monotonic() - t) * 1000)

        # Discovery (every 6 hours, or when there's none): which interfaces are physical ports, their
        # names and descriptions, and which are PoE ports. Each check then only fetches the live values
        # for those, a dozen per request: a few requests instead of walking every interface (VLANs,
        # LAGs...) column by column, which slow switches can't keep up with.
        IF, IFX, PSE, MAIN = "1.3.6.1.2.1.2.2.1", "1.3.6.1.2.1.31.1.1.1", "1.3.6.1.2.1.105.1.1.1", "1.3.6.1.2.1.105.1.3.1.1"
        disc = discovery if discovery and time.time() - discovery.get("at", 0) < 6 * 3600 and discovery.get("ports") is not None else None
        if disc is None:
            types = await timed("ports", s.walk(f"{IF}.3"), optional=False)
            if not types:
                raise SnmpError("the device didn't list its interfaces")
            opers = await timed("ports", s.walk(f"{IF}.8"))
            phys = [i for i, t in types.items() if t in IF_TYPES_PHYSICAL and opers.get(i) != 6]  # 6 = notPresent
            names = await timed("port names", get_many(s, [f"{IFX}.1.{i}" for i in phys] + [f"{IF}.2.{i}" for i in phys]))
            alias = await timed("port descriptions", get_many(s, [f"{IFX}.18.{i}" for i in phys]))
            poe_idx = list(await timed("PoE", s.walk(f"{PSE}.6", limit=200)))
            groups = sorted({i.split(".")[0] for i in poe_idx if "." in i}) or (["1"] if poe_idx else [])
            disc = {"at": time.time(), "poe": poe_idx, "poe_groups": groups,
                    "ports": {i: {"name": str(names.get(f"{IFX}.1.{i}") or names.get(f"{IF}.2.{i}") or i),
                                  "descr": str(names.get(f"{IF}.2.{i}") or ""), "alias": str(alias.get(f"{IFX}.18.{i}") or "")}
                              for i in phys}}
            if "port names" in missing or "port descriptions" in missing:
                disc["at"] = time.time() - 6 * 3600 + 600  # try again in 10 minutes rather than 6 hours
        out["discovery"] = disc

        live = await timed("ports", get_many(s, [f"{c}.{i}" for i in disc["ports"]
                                                   for c in (f"{IF}.7", f"{IF}.8", f"{IFX}.15", f"{IF}.14", f"{IF}.20")]))
        if disc["ports"] and not any(k.startswith(f"{IF}.8.") for k in live):
            raise SnmpError("no SNMP reply for the port states")
        for i, meta in disc["ports"].items():
            out["ports"].append({
                "index": int(i), "name": meta["name"], "descr": meta["descr"], "alias": meta["alias"],
                "admin_up": live.get(f"{IF}.7.{i}") == 1, "up": live.get(f"{IF}.8.{i}") == 1,
                "speed_mbps": live.get(f"{IFX}.15.{i}"),
                "in_errors": live.get(f"{IF}.14.{i}"), "out_errors": live.get(f"{IF}.20.{i}")})
        out["ports"].sort(key=lambda p: p["index"])

        # PoE (POWER-ETHERNET-MIB), if the switch has it: only the columns used
        if disc.get("poe"):
            got = await timed("PoE", get_many(s, [f"{PSE}.{c}.{i}" for i in disc["poe"] for c in ("3", "6", "7", "10", "12", "13", "14")]
                                               + [f"{MAIN}.{c}.{g}" for g in disc["poe_groups"] for c in ("2", "3", "4", "5")]))
            ports = {i: {c: got.get(f"{PSE}.{c}.{i}") for c in ("3", "6", "7", "10", "12", "13", "14")} for i in disc["poe"]}
            mains = {g: {c: got.get(f"{MAIN}.{c}.{g}") for c in ("2", "3", "4", "5")} for g in disc["poe_groups"]}
            if got:
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

        # UPS: APC cards by their sysObjectID; others only if they look like a UPS, since some
        # switches stall when asked for things they don't have.
        import re
        oid, text = out["object_id"], f'{out["descr"]} {out["name"]}'
        ent = oid.split(".")[6] if oid.startswith("1.3.6.1.4.1.") and oid.count(".") >= 6 else ""
        reader = read_apc if ent == "318" else read_upsmib if (
            oid.startswith("1.3.6.1.2.1.33") or ent in UPS_ENTERPRISES or re.search(r"\bups\b", text, re.I)) else None
        if reader:
            got = await timed("UPS", reader(s))
            if got:
                out["ups"] = got
            elif got == {} and ent == "318":  # no answer for the UPS's values
                out["ups"] = {"error": "the card didn't answer for the UPS's status"}
        out["requests"] = s.requests
        out["per"] = s.per
        out["timeouts"] = s.timeouts
        out["timing"] = timing
        out["missing"] = sorted(set(missing))
    out["took_ms"] = int((time.monotonic() - t0) * 1000)
    out["polled"] = time.time()
    return out


UPS_LIMITS = {"runtime_warn": 15, "runtime_crit": 5, "load_warn": 80, "load_crit": 95, "temp_warn": 40}


def boot_time(d: dict, now: float | None = None) -> float | None:
    """When the device (or its SNMP service) last started, from the uptime in a poll."""
    up = d.get("uptime_s")
    if not isinstance(up, int):
        return None
    return (d.get("polled") or now or time.time()) - up


def evaluate(d: dict, watch: set[int], prev: dict | None, limits: dict | None = None,
             restart_ack: float | None = None) -> tuple[str, list[dict]]:
    """Problems in a poll. Returns (worst level, items) with level ok / warn / crit.
    restart_ack: the start time of a restart someone acknowledged; it's no longer flagged."""
    lim = {**UPS_LIMITS, **(limits or {})}
    items: list[dict] = []
    add = lambda level, what, detail="": items.append({"level": level, "what": what, "detail": detail})  # noqa: E731
    up = d.get("uptime_s")
    booted = boot_time(d)
    acked = bool(restart_ack and booted and abs(booted - restart_ack) < 300)
    if isinstance(up, int) and up < 3600 and not acked:
        add("warn", "Restarted", f"{max(1, up // 60)} min ago" + ("" if d.get("uptime_source") == "system"
                                                               else " (or its SNMP service did)"))
        items[-1]["ack"] = "restart"
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
    ups = d.get("ups")
    if ups and ups.get("error"):
        add("warn", "UPS", ups["error"])
    elif ups:
        if ups.get("on_battery"):
            add("crit", "UPS", "on battery" + (f" for {ups['on_battery_s'] // 60} min" if ups.get("on_battery_s") else "")
                + (f", {ups['runtime_min']} min left" if ups.get("runtime_min") is not None else ""))
        elif ups.get("off"):
            add("crit", "UPS", ups["output"] or "output off")
        elif ups.get("bypass"):
            add("warn", "UPS", f"{ups['output']}: not protecting the load")
        if ups.get("battery_low"):
            add("crit", "UPS battery", "low")
        elif ups.get("battery_fault"):
            add("crit", "UPS battery", ups["battery"])
        if ups.get("replace") or ups.get("bad_packs"):
            add("crit", "UPS battery", "needs replacing" + (f" ({ups['bad_packs']} bad pack(s))" if ups.get("bad_packs") else ""))
        if ups.get("self_test_failed"):
            when = ""
            if ups.get("self_test_date"):
                import datetime as _dt
                try:
                    when = " on " + _dt.date.fromisoformat(ups["self_test_date"]).strftime("%d %b %Y").lstrip("0")
                except ValueError:
                    pass
            add("crit", "UPS self-test", "failed" + when)
        rt = ups.get("runtime_min")
        if rt is not None and not ups.get("on_battery") and not ups.get("off"):
            if rt < lim["runtime_crit"]:
                add("crit", "UPS runtime", f"only {rt} min on battery")
            elif rt < lim["runtime_warn"]:
                add("warn", "UPS runtime", f"only {rt} min on battery")
        ld = ups.get("load_pct")
        if ld is not None:
            if ld >= lim["load_crit"]:
                add("crit", "UPS load", f"{ld}%")
            elif ld >= lim["load_warn"]:
                add("warn", "UPS load", f"{ld}%")
        t = ups.get("battery_temp_c")
        if t is not None and t >= lim["temp_warn"]:
            add("warn", "UPS battery", f"{t} °C")
        shown = {"on battery", "low battery", "battery depleted", "battery bad", "self-test failed", "on bypass", "test in progress"}
        for a in ups.get("alarms") or []:
            if a not in shown:
                add("crit" if a in ("output overloaded", "shutdown pending", "shutdown imminent", "charger failed",
                                    "general fault", "fan failure", "fuse failure", "output off", "UPS system off") else "warn", "UPS", a)
    worst = "crit" if any(i["level"] == "crit" for i in items) else "warn" if items else "ok"
    return worst, items
