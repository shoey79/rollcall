"""Fire TV / Android TV over network ADB: read-only.

Rollcall talks ADB (Android Debug Bridge) to the stick over the network (port 5555), with a key of its own, and runs
a fixed set of shell commands that only read: getprop, /proc files, df, dumpsys and pm list. It never sends key
presses, installs or removes anything, or changes a setting. Nothing needs installing on the stick; network debugging
has to be on (Settings → My Fire TV → Developer options), and the TV asks "Allow USB debugging?" once for Rollcall's
key.

Network ADB gives full control of the stick to anything on the network that the TV has allowed, and anything at all
can ask (the TV then shows the prompt). Keep sticks on a network of their own if you can, and turn ADB off on sticks
you don't monitor.

The ADB protocol is small and done here by hand (as Starlink's gRPC is), so the add-on needs nothing extra: messages
are a 24-byte header (command, arg0, arg1, length, checksum, magic) and a payload. CNXN connects, AUTH answers the
stick's challenge with Rollcall's RSA key (or offers the public key, which makes the TV ask), OPEN starts a shell
command, WRTE carries its output, OKAY acknowledges, CLSE ends it.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import struct
import time
from pathlib import Path

DEFAULT_PORT = 5555
A_CNXN, A_AUTH, A_OPEN, A_OKAY, A_CLSE, A_WRTE, A_STLS = (int.from_bytes(x, "little") for x in
                                                          (b"CNXN", b"AUTH", b"OPEN", b"OKAY", b"CLSE", b"WRTE", b"STLS"))
VERSION, MAX_DATA = 0x01000001, 256 * 1024
AUTH_TOKEN, AUTH_SIGNATURE, AUTH_RSAPUBLICKEY = 1, 2, 3
MAX_OUTPUT = 2 * 1024 * 1024


class FireTVError(Exception):
    """level "warn": something to do on the TV (allow Rollcall), not a fault."""

    def __init__(self, msg: str, level: str | None = None):
        super().__init__(msg)
        self.level = level


# ---- Rollcall's key ------------------------------------------------------------------------------------------------
class Key:
    """Rollcall's own ADB key (RSA 2048), kept in the add-on's data folder. The TV remembers it once allowed."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._key = None

    def key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        if self._key is None:
            if self.path.exists():
                self._key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
            else:
                k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
                os.replace(tmp, self.path)
                self._key = k
        return self._key

    def sign(self, token: bytes) -> bytes:
        """ADB signs the stick's 20-byte challenge as if it were a SHA-1 digest."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        return self.key().sign(token, padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))

    def public(self) -> bytes:
        """The public key in Android's format (what the stick stores once allowed), named for the TV's prompt."""
        return android_pubkey(self.key().public_key().public_numbers()) + b" Rollcall@homeassistant\x00"

    def fingerprint(self) -> str:
        """As the TV's prompt shows it: MD5 of the Android-format key, in hex pairs."""
        import hashlib
        raw = base64.b64decode(android_pubkey(self.key().public_key().public_numbers()))
        return ":".join(f"{b:02X}" for b in hashlib.md5(raw).digest())  # noqa: S324 - what Android shows, not security


def android_pubkey(nums) -> bytes:
    """struct RSAPublicKey {u32 words; u32 n0inv; u8 n[256] (LE); u8 rr[256] (LE); u32 e}, base64."""
    n, e = nums.n, nums.e
    words = 2048 // 32
    n0inv = (-pow(n, -1, 1 << 32)) % (1 << 32)
    rr = pow(2, 4096, n)
    raw = struct.pack("<II", words, n0inv) + n.to_bytes(256, "little") + rr.to_bytes(256, "little") + struct.pack("<I", e)
    return base64.b64encode(raw)


# ---- ADB over TCP --------------------------------------------------------------------------------------------------
def message(cmd: int, a0: int, a1: int, data: bytes = b"") -> bytes:
    return struct.pack("<6I", cmd, a0, a1, len(data), sum(data) & 0xFFFFFFFF, cmd ^ 0xFFFFFFFF) + data


class Adb:
    """One connection to a stick. Only shell commands, and only the ones this module builds."""

    def __init__(self, host: str, port: int, key: Key, timeout: float = 15):
        self.host, self.port, self.key, self.timeout = host, port, key, timeout
        self.r: asyncio.StreamReader | None = None
        self.w: asyncio.StreamWriter | None = None
        self.max_data = 4096
        self.banner = ""
        self.offered_key = False
        self._local = 0

    async def _read(self, timeout: float | None = None) -> tuple[int, int, int, bytes]:
        head = await asyncio.wait_for(self.r.readexactly(24), timeout or self.timeout)
        cmd, a0, a1, n, _crc, magic = struct.unpack("<6I", head)
        if magic != cmd ^ 0xFFFFFFFF or n > MAX_DATA:
            raise FireTVError("the TV's answer wasn't ADB (is something else on that port?)")
        data = await asyncio.wait_for(self.r.readexactly(n), timeout or self.timeout) if n else b""
        return cmd, a0, a1, data

    def _send(self, cmd: int, a0: int, a1: int, data: bytes = b"") -> None:
        self.w.write(message(cmd, a0, a1, data))

    async def connect(self, auth_wait: float = 45) -> None:
        try:
            self.r, self.w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), self.timeout)
        except (OSError, asyncio.TimeoutError) as err:
            raise FireTVError(f"no answer on port {self.port}: is network debugging on (Developer options → ADB "
                              f"debugging)? ({type(err).__name__})") from None
        try:
            self._send(A_CNXN, VERSION, MAX_DATA, b"host::\x00")
            await self.w.drain()
            signed = False
            while True:
                # After the public key is offered, the stick waits for someone to press Allow on the TV
                cmd, a0, a1, data = await self._read(auth_wait if self.offered_key else None)
                if cmd == A_CNXN:
                    self.max_data = max(1024, min(a1 or 4096, MAX_DATA))
                    self.banner = data.rstrip(b"\x00").decode("utf-8", "replace")
                    return
                if cmd == A_STLS:
                    raise FireTVError("the TV wants wireless debugging with pairing (Android 11+), which Rollcall "
                                      "doesn't do: use ADB debugging over the network on port 5555")
                if cmd != A_AUTH or a0 != AUTH_TOKEN:
                    raise FireTVError("the TV answered something unexpected while connecting")
                if not signed:
                    signed = True
                    self._send(A_AUTH, AUTH_SIGNATURE, 0, self.key.sign(data))
                elif not self.offered_key:  # not allowed yet: offer the key, and the TV asks
                    self.offered_key = True
                    self._send(A_AUTH, AUTH_RSAPUBLICKEY, 0, self.key.public())
                else:
                    raise FireTVError("the TV hasn't allowed Rollcall yet", "warn")
                await self.w.drain()
        except asyncio.TimeoutError:
            if self.offered_key:
                raise FireTVError("waiting for Allow on the TV: it shows \"Allow USB debugging?\" for Rollcall's "
                                  "key; tick \"Always allow from this computer\" and choose Allow", "warn") from None
            raise FireTVError("the TV didn't answer in time") from None
        except asyncio.IncompleteReadError:
            raise FireTVError("the TV closed the connection: it may have refused Rollcall's key (choose Allow on "
                              "the TV next time it asks), or another ADB client is connected", "warn") from None

    async def shell(self, cmd: str, timeout: float = 30) -> str:
        """A shell command's output (stdout and stderr together, as ADB gives them)."""
        self._local += 1
        local = self._local
        self._send(A_OPEN, local, 0, b"shell:" + cmd.encode() + b"\x00")
        await self.w.drain()
        out = bytearray()
        remote = 0
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise FireTVError("a command took too long")
            try:
                c, a0, a1, data = await self._read(left)
            except asyncio.TimeoutError:
                raise FireTVError("a command took too long") from None
            except asyncio.IncompleteReadError:
                raise FireTVError("the TV closed the connection") from None
            if a1 != local:
                continue
            if c == A_OKAY:
                remote = a0
            elif c == A_WRTE:
                remote = a0
                out += data
                if len(out) > MAX_OUTPUT:
                    raise FireTVError("a command's output was too big")
                self._send(A_OKAY, local, remote)
                await self.w.drain()
            elif c == A_CLSE:
                if remote:
                    self._send(A_CLSE, local, remote)
                    await self.w.drain()
                return out.decode("utf-8", "replace")

    async def close(self) -> None:
        if self.w:
            try:
                self.w.close()
                await asyncio.wait_for(self.w.wait_closed(), 2)
            except Exception:  # noqa: BLE001
                pass


# ---- What's read --------------------------------------------------------------------------------------------------
# Every command Rollcall runs on a stick, all in one shell. All of them only read. The CPU is sampled over 2 seconds
# (Fire OS's load average counts waiting kernel tasks, so it reads 5-6 on an idle 4-core stick and isn't used).
SECTIONS = (
    ("props", "getprop"),
    ("uptime", "cat /proc/uptime"),
    ("cpu", "grep -c ^processor /proc/cpuinfo; head -1 /proc/stat; sleep 2; head -1 /proc/stat"),
    ("meminfo", "cat /proc/meminfo"),
    ("df", "df -k /data 2>/dev/null"),
    ("wifi", "dumpsys wifi | grep -m 3 -E 'mWifiInfo|Wi-Fi is'"),
    ("thermal", "ls /sys/class/thermal 2>&1 | head -1; for z in /sys/class/thermal/thermal_zone*; do echo \"$(cat $z/type 2>&1) $(cat $z/temp 2>&1)\"; done"),
    ("power", "dumpsys power | grep -m 3 -E 'mWakefulness=|Display Power: state='"),
    ("focus", "dumpsys window | grep -m 2 -E 'mCurrentFocus|mFocusedApp'"),
    ("packages_3p", "pm list packages -3 -i"),
    ("packages_disabled", "pm list packages -d"),
    ("versions", "dumpsys package packages | grep -E '^  Package \\[|versionName='"),
    ("boot_count", "settings get global boot_count"),
)
MARK = "@@rollcall:"


def script() -> str:
    return "; ".join(f"echo {MARK}{name}; {cmd}" for name, cmd in SECTIONS)


def split(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines(keepends=True):
        if line.startswith(MARK):
            cur = line[len(MARK):].strip()
            out[cur] = ""
        elif cur:
            out[cur] += line
    return out


SAFE_PKG = re.compile(r"^[A-Za-z0-9_.]{1,200}$")


async def read(host: str, port: int, key: Key, timeout: float = 20, auth_wait: float = 45) -> dict:
    """Read a stick (about 6 s: each pm and settings call starts Android's Java). Raises FireTVError. The first time,
    it waits auth_wait seconds for someone to choose Allow on the TV."""
    t0 = time.monotonic()
    adb = Adb(host, port, key, timeout)
    try:
        await adb.connect(auth_wait)
        raw = split(await adb.shell(script(), timeout=60))
        d = parse(raw)
        running = {}
        side = [p for p in d["sideloaded"] if SAFE_PKG.match(p)]
        if side:  # each sideloaded app: running, and how many services it has (e.g. a launcher's Home helper)
            cmd = "; ".join(f"echo {MARK}{p}; pidof {p}; dumpsys activity services {p} | grep -c ServiceRecord" for p in side)
            for p, txt in split(await adb.shell(cmd, timeout=30)).items():
                words = txt.split()
                n = words[-1] if words and words[-1].isdigit() else None
                running[p] = {"running": any(w.isdigit() for w in words[:-1]), "services": int(n) if n else None}
        d["sideloaded_running"] = running
    finally:
        await adb.close()
    d["read_ms"] = round((time.monotonic() - t0) * 1000)
    return d


def _props(text: str) -> dict:
    return {m.group(1): m.group(2) for m in re.finditer(r"^\[([^\]]+)\]: \[(.*)\]\s*$", text or "", re.M)}


def parse(raw: dict) -> dict:
    p = _props(raw.get("props", ""))
    d: dict = {"make": p.get("ro.product.manufacturer", ""), "model": p.get("ro.product.model", ""),
               "device": p.get("ro.product.device", "") or p.get("ro.product.name", ""),
               "android": p.get("ro.build.version.release", ""), "sdk": p.get("ro.build.version.sdk", ""),
               "build": p.get("ro.build.display.id", ""), "security_patch": p.get("ro.build.version.security_patch", "")}
    # Fire OS: ro.build.version.fireos is only the generation ("6.0") on some sticks; the marketing name has it all
    d["fire_os"] = ""
    for k in ("ro.build.mktg.fireos", "ro.build.version.name", "ro.build.version.fireos"):
        m = re.search(r"(\d+(?:\.\d+)+)", p.get(k, ""))
        if m:
            d["fire_os"] = m.group(1)
            break
    d["is_fire"] = bool(d["fire_os"]) or d["make"].lower() == "amazon"
    m = re.match(r"([\d.]+)", raw.get("uptime", ""))
    d["uptime_s"] = int(float(m.group(1))) if m else None
    c = raw.get("cpu", "").splitlines()
    stats = [list(map(int, ln.split()[1:])) for ln in c if ln.startswith("cpu ")]
    d["cores"] = int(c[0]) if c and c[0].strip().isdigit() else None
    d["cpu_pct"] = None
    if len(stats) == 2:
        a, b = stats
        idle = (b[3] + (b[4] if len(b) > 4 else 0)) - (a[3] + (a[4] if len(a) > 4 else 0))
        total = sum(b) - sum(a)
        d["cpu_pct"] = round(100 * (total - idle) / total, 1) if total > 0 else None
    mem = {k: int(v) for k, v in re.findall(r"^(\w+):\s+(\d+) kB", raw.get("meminfo", ""), re.M)}
    d["mem_total_mb"] = mem["MemTotal"] // 1024 if mem.get("MemTotal") else None
    d["mem_free_mb"] = mem.get("MemAvailable", mem.get("MemFree", 0)) // 1024 if mem.get("MemTotal") else None
    d["storage_total_mb"] = d["storage_free_mb"] = None
    for line in raw.get("df", "").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == "/data" and parts[1].isdigit():
            d["storage_total_mb"], d["storage_free_mb"] = int(parts[1]) // 1024, int(parts[3]) // 1024
            break
    w = raw.get("wifi", "")
    wifi: dict = {}
    for k, pat in (("rssi_dbm", r"RSSI: (-?\d+)"), ("link_mbps", r"Link speed: (\d+)"), ("freq_mhz", r"Frequency: (\d+)")):
        m = re.search(pat, w)
        if m:
            wifi[k] = int(m.group(1))
    if wifi.get("rssi_dbm") == -127:  # not connected over Wi-Fi
        wifi = {}
    if wifi.get("freq_mhz"):
        f = wifi["freq_mhz"]
        wifi["band"] = "2.4 GHz" if f < 3000 else "5 GHz" if f < 5950 else "6 GHz"
    if "Wi-Fi is disabled" in w or not wifi:
        wifi = {"off": True}
    d["wifi"] = wifi
    temps = []
    for line in raw.get("thermal", "").splitlines():
        parts = line.rsplit(" ", 1)
        if len(parts) == 2 and re.fullmatch(r"-?\d+", parts[1]):
            v = int(parts[1])
            t = v / 1000 if abs(v) > 1000 else v
            if -20 < t < 150:
                temps.append({"zone": parts[0].strip() or "?", "c": round(t, 1)})
    d["temps"] = temps
    d["temp_c"] = max((t["c"] for t in temps), default=None)
    d["temp_note"] = "" if temps else ("not readable over ADB on this model" if "ermission denied" in raw.get("thermal", "")
                                       else "not reported")
    m = re.search(r"mWakefulness=(\w+)", raw.get("power", ""))
    d["screen"] = {"Awake": "on", "Asleep": "standby", "Dreaming": "screensaver", "Dozing": "standby"}.get(m.group(1), m.group(1).lower()) if m else ""
    m = re.search(r"mCurrentFocus=Window\{\S+ \S+ ([^/\s}]+)", raw.get("focus", "")) or \
        re.search(r"mFocusedApp=.*? ([a-zA-Z0-9_.]+)/", raw.get("focus", ""))
    d["app_in_front"] = m.group(1) if m else ""
    versions, cur = {}, None
    for line in raw.get("versions", "").splitlines():
        m = re.match(r"\s*Package \[([^\]]+)\]", line)
        if m:
            cur = m.group(1)
            continue
        m = re.search(r"versionName=(\S+)", line)
        if m and cur and cur not in versions:
            versions[cur] = m.group(1)[:40]
    apps = []
    for line in raw.get("packages_3p", "").splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip()) or re.match(r"package:(\S+)()", line.strip())
        if m:
            inst = m.group(2) or "null"
            src = ("Appstore" if "venezia" in inst or "amazon" in inst else "Google Play" if inst == "com.android.vending"
                   else "sideloaded" if inst in ("null", "", "com.android.shell", "com.google.android.packageinstaller",
                                                "com.android.packageinstaller") else inst)
            apps.append({"package": m.group(1), "from": src, "version": versions.get(m.group(1), "")})
    d["apps"] = sorted(apps, key=lambda a: a["package"])
    d["sideloaded"] = [a["package"] for a in d["apps"] if a["from"] == "sideloaded"]
    d["disabled"] = sum(1 for ln in raw.get("packages_disabled", "").splitlines() if ln.startswith("package:"))
    bc = raw.get("boot_count", "").strip()
    d["boot_count"] = int(bc) if bc.isdigit() else None
    return d


# ---- What it means ------------------------------------------------------------------------------------------------
CPU_BUSY, CPU_CHECKS = 90.0, 3   # busy in this many checks in a row (video swings it, one check means little)
STORAGE_LOW_PCT, STORAGE_LOW_MB = 10, 500
WIFI_WEAK = -80


def evaluate(d: dict, prev: dict | None = None) -> tuple[bool, None, str, str | None, dict]:
    """(ok, latency, detail, level, memory to keep for next time). Amber, not red, for what it notices: the stick
    answers, so it's up. Memory: recent CPU readings, the most disabled apps seen, and which sideloaded apps run."""
    prev = prev or {}
    mem = {"cpu": (list(prev.get("cpu") or []) + ([d["cpu_pct"]] if d.get("cpu_pct") is not None else []))[-CPU_CHECKS:],
           "disabled_max": max(int(prev.get("disabled_max") or 0), int(d.get("disabled") or 0)),
           "running": {p: r.get("running") for p, r in (d.get("sideloaded_running") or {}).items()}}
    warn = []
    tot, free = d.get("storage_total_mb"), d.get("storage_free_mb")
    if tot and free is not None and (free < STORAGE_LOW_MB or free * 100 / tot < STORAGE_LOW_PCT):
        warn.append(f"storage low: {free} MB free")
    if len(mem["cpu"]) >= CPU_CHECKS and all(c >= CPU_BUSY for c in mem["cpu"]):
        warn.append(f"CPU busy in the last {CPU_CHECKS} checks ({mem['cpu'][-1]:.0f}%)")
    if prev.get("disabled_max") and (d.get("disabled") or 0) < int(prev["disabled_max"]):
        warn.append(f"{int(prev['disabled_max']) - (d.get('disabled') or 0)} disabled app(s) back on (a Fire OS update?)")
    for p, r in (d.get("sideloaded_running") or {}).items():
        if not r.get("running") and (prev.get("running") or {}).get(p):
            warn.append(f"{p} stopped running")
    rssi = (d.get("wifi") or {}).get("rssi_dbm")
    if rssi is not None and rssi < WIFI_WEAK:
        warn.append(f"Wi-Fi signal weak ({rssi} dBm)")
    name = " ".join(x for x in ("Fire OS " + d["fire_os"] if d.get("fire_os") else "Android " + str(d.get("android") or "?"),) if x)
    bits = [name]
    if d.get("screen"):
        bits.append("screen " + d["screen"] + (f" ({d['app_in_front']})" if d.get("app_in_front") and d["screen"] == "on" else ""))
    if d.get("cpu_pct") is not None:
        bits.append(f"CPU {d['cpu_pct']:.0f}%")
    if free is not None:
        bits.append(f"{free / 1024:.1f} GB free")
    if warn:
        return False, None, "; ".join(warn), "warn", mem
    return True, None, " · ".join(bits), None, mem


def mb(v) -> str:
    return "—" if v is None else f"{v / 1024:.1f} GB" if v >= 1024 else f"{v} MB"
