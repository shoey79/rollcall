"""Starlink: the dish's status, read from the dish itself (its local API) or through the Starlink account.

Two ways in, one reading:

Local (default): the dish answers gRPC on 192.168.100.1:9200 (SpaceX.API.Device.Device/Handle), with no sign-in,
as Home Assistant's own Starlink integration reads it. The address is fixed on the dish; a router in bypass mode
needs a route to it (see DOCS.md). gRPC runs over HTTP/2: rather than add a gRPC library to the add-on, this sends
the one request it needs over a plain HTTP/2 connection (prior knowledge, no TLS: the dish speaks cleartext) and
reads the answer's DATA frames. The trailers aren't decoded: an answer without a message is an error.

Account: for a dish Home Assistant can't reach (another site), the starlink.com session cookie, copied from the
browser after signing in, reads the same status through starlink.com's gRPC-web endpoint, as the community
integration ha-starlink-remote does. It's an unofficial API and may change. The cookie is only ever sent to
starlink.com hosts (redirects aren't followed), is kept with the device and never shown again; it expires when the
account signs in again in the same browser, so a private window is best. Read only: nothing here can reboot or
stow the dish (only get_status is ever built).

The status message (DishGetStatusResponse, field numbers from SpaceX's protobuf definitions):
  device_info 1 {id 1, hardware_version 2, software_version 3, country_code 4, bootcount 8}
  device_state 2 {uptime_s 1}       alerts 1005 {bools}     outage 1014 {cause 1, start_timestamp_ns 2, duration_ns 3}
  pop_ping_drop_rate 1003 (float)   downlink_throughput_bps 1007, uplink_throughput_bps 1008, pop_ping_latency_ms 1009
  obstruction_stats 1004 {fraction_obstructed 1, valid_s 4, currently_obstructed 5, time_obstructed 9}
  stow_requested 1010  eth_speed_mbps 1016  is_snr_above_noise_floor 1018  software_update_state 1021
  is_snr_persistently_low 1022  disablement_code 1024  swupdate_reboot_ready 1030  reboot_reason 1032
"""
from __future__ import annotations

import asyncio
import os
import re
import struct
import time
from urllib.parse import urlparse

import aiohttp

DEFAULT_ADDR = "192.168.100.1:9200"
GRPC_PATH = "/SpaceX.API.Device.Device/Handle"
ACCOUNT_API = "https://www.starlink.com/api/SpaceX.API.Device.Device/Handle"
TOKEN_URL = "https://starlink.com/api/auth/auth/refresh-token"
SERVICE_LINES_URL = "https://api.starlink.com/webagg/v2/accounts/service-lines"
PORTAL_HOME_URL = "https://www.starlink.com/account/home"
AUTH_USER_URL = "https://api.starlink.com/auth-rp/auth/user"
STARLINK_HOSTS = ("starlink.com", "www.starlink.com", "api.starlink.com")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
ADDR_RE = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.\-]+)(:\d{1,5})?$")
MAX_BYTES = 1024 * 1024

OUTAGE_CAUSES = {0: "unknown", 1: "starting up", 2: "stowed", 3: "too hot, shut down", 4: "no satellite schedule",
                 5: "no satellites", 6: "obstructed", 7: "no downlink", 8: "no pings", 9: "moving its motors",
                 10: "cable test", 11: "sleeping", 13: "searching the sky", 14: "transmitting stopped"}
# alerts field number -> (key, what it means, level): "warn" is amber (no notification), "info" is shown only
ALERTS = {
    1: ("motors_stuck", "motors stuck", "warn"),
    2: ("thermal_shutdown", "too hot, shut down", "crit"),
    3: ("thermal_throttle", "too hot, slowed down", "warn"),
    4: ("unexpected_location", "in an unexpected location", "warn"),
    5: ("mast_not_near_vertical", "mast not vertical", "warn"),
    6: ("slow_ethernet_speeds", "slow Ethernet link (below 1 Gb/s)", "warn"),
    7: ("roaming", "roaming", "info"),
    8: ("install_pending", "update installing", "info"),
    9: ("is_heating", "heating (melting snow)", "info"),
    10: ("power_supply_thermal_throttle", "power supply too hot", "warn"),
    11: ("is_power_save_idle", "power-save idle", "info"),
    16: ("low_motor_current", "low motor current", "warn"),
    17: ("lower_signal_than_predicted", "weaker signal than expected", "warn"),
    18: ("slow_ethernet_speeds_100", "slow Ethernet link (100 Mb/s)", "warn"),
    20: ("dish_water_detected", "water in the dish", "warn"),
    21: ("router_water_detected", "water in the router", "warn"),
    22: ("upsu_router_port_slow", "router port slow", "warn"),
    23: ("no_ethernet_link", "no Ethernet link", "warn"),
}
DISABLED = {2: "no active account", 3: "too far from the service address", 4: "in the ocean", 6: "blocked country",
            7: "over its data allowance", 8: "cell disabled", 10: "roaming restricted", 11: "unknown location",
            12: "account disabled", 13: "software too old", 14: "moving too fast for the plan"}
UPDATE_STATES = {2: "downloading an update", 3: "checking an update", 4: "installing an update",
                 5: "checking an update", 6: "update installed, waiting to restart"}
REBOOT_REASONS = {1: "restarted by hand", 2: "lost contact", 3: "software update", 4: "scheduled software update",
                  5: "restarted from the app"}
OBSTRUCTED_WARN = 0.01    # amber when obstructions cut it off for more than 1% of the time


class StarlinkError(Exception):
    """The dish or the account couldn't be read. login is True when starlink.com turned the sign-in down."""

    def __init__(self, msg: str, login: bool = False):
        super().__init__(msg)
        self.login = login


# ---- protobuf, just enough ------------------------------------------------------------------------------------
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(num: int, wire: int, payload: bytes = b"") -> bytes:
    key = _varint(num << 3 | wire)
    return key + (_varint(len(payload)) + payload if wire == 2 else payload)


def status_request(target_id: str = "") -> bytes:
    """Request{target_id 13, get_status 1004 = {}}: the only request this module ever builds."""
    out = _field(13, 2, target_id.encode()) if target_id else b""
    return out + _field(1004, 2, b"")


def decode(buf: bytes) -> dict[int, list]:
    """A message's fields: number -> values (varints as int, fixed32/64 as bytes, length-delimited as bytes)."""
    out: dict[int, list] = {}
    i, n = 0, len(buf)
    while i < n:
        key, i = _read_varint(buf, i)
        num, wire = key >> 3, key & 7
        if wire == 0:
            v, i = _read_varint(buf, i)
        elif wire == 1:
            v, i = buf[i:i + 8], i + 8
        elif wire == 2:
            ln, i = _read_varint(buf, i)
            v, i = buf[i:i + ln], i + ln
        elif wire == 5:
            v, i = buf[i:i + 4], i + 4
        else:
            raise ValueError(f"unexpected protobuf wire type {wire}")
        if i > n:
            raise ValueError("truncated protobuf message")
        out.setdefault(num, []).append(v)
    return out


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise ValueError("bad varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _f(m: dict, num: int):
    v = m.get(num)
    return v[-1] if v else None


def _float(m: dict, num: int) -> float | None:
    v = _f(m, num)
    return struct.unpack("<f", v)[0] if isinstance(v, (bytes, bytearray)) and len(v) == 4 else None


def _int(m: dict, num: int) -> int | None:
    v = _f(m, num)
    if isinstance(v, int):
        return v - (1 << 64) if v >= 1 << 63 else v
    return None


def _str(m: dict, num: int) -> str:
    v = _f(m, num)
    try:
        return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else ""
    except AttributeError:
        return ""


def _sub(m: dict, num: int) -> dict:
    v = _f(m, num)
    return decode(v) if isinstance(v, (bytes, bytearray)) else {}


def parse_response(buf: bytes) -> dict:
    """A Response holding dish_get_status (2004) -> what Rollcall shows. Raises StarlinkError if it holds none."""
    try:
        resp = decode(buf)
        if 2004 not in resp:
            st = _sub(resp, 2)
            msg = _str(st, 2)
            raise StarlinkError(f"the dish answered without its status{': ' + msg if msg else ''}")
        s = _sub(resp, 2004)
        info, state = _sub(s, 1), _sub(s, 2)
        alerts_m, outage_m, obs = _sub(s, 1005), _sub(s, 1014), _sub(s, 1004)
    except ValueError as err:
        raise StarlinkError(f"couldn't read the dish's answer ({err})") from None
    alerts = [{"key": k, "what": what, "level": lvl} for num, (k, what, lvl) in ALERTS.items() if _int(alerts_m, num)]
    d = {
        "id": _str(info, 1), "hardware": _str(info, 2), "software": _str(info, 3), "country": _str(info, 4),
        "uptime_s": _int(state, 1),
        "latency_ms": _round(_float(s, 1009), 1), "drop_rate": _round(_float(s, 1003), 4),
        "down_bps": _round(_float(s, 1007), 0), "up_bps": _round(_float(s, 1008), 0),
        "obstructed_now": bool(_int(obs, 5)), "obstructed_fraction": _round(_float(obs, 1), 4),
        "obstructed_time": _round(_float(obs, 9), 4), "obstruction_window_s": _round(_float(obs, 4), 0),
        "eth_mbps": _int(s, 1016), "stowed": bool(_int(s, 1010)),
        "snr_ok": None if _int(s, 1018) is None else bool(_int(s, 1018)), "snr_low": bool(_int(s, 1022)),
        "alerts": alerts,
        "update": UPDATE_STATES.get(_int(s, 1021) or 0, ""), "update_ready": bool(_int(s, 1030)),
        "reboot_reason": REBOOT_REASONS.get(_int(s, 1032) or 0, ""),
        "disabled": DISABLED.get(_int(s, 1024) or 0, ""),
        "outage": None,
    }
    # proto3 leaves out a number that's 0: in a status, a missing drop rate, throughput or obstruction is 0
    for k in ("drop_rate", "down_bps", "up_bps", "obstructed_fraction", "obstructed_time"):
        if d[k] is None:
            d[k] = 0
    if outage_m:
        cause = _int(outage_m, 1) or 0
        start = _int(outage_m, 2)
        dur = _int(outage_m, 3)
        d["outage"] = {"cause": OUTAGE_CAUSES.get(cause, f"cause {cause}"), "code": cause,
                       "since": round(start / 1e9) if start and start > 0 else None,
                       "for_s": round(dur / 1e9) if dur else None}
    if d["uptime_s"] is not None:
        d["since"] = int(time.time() - d["uptime_s"])
    return d


def _round(v, n):
    if v is None or v != v:   # NaN
        return None
    return round(v, n) if n else round(v)


# ---- local: gRPC over a plain HTTP/2 connection ---------------------------------------------------------------
def clean_addr(addr: str) -> str:
    """'192.168.100.1:9200' (port optional, 9200 by default). Raises ValueError."""
    addr = str(addr or "").strip()
    if addr.startswith(("http://", "https://")):
        addr = urlparse(addr).netloc
    addr = addr.rstrip("/")
    m = ADDR_RE.match(addr)
    if not m:
        raise ValueError("The dish address must be like 192.168.100.1:9200")
    if m.group(2) and not 1 <= int(m.group(2)[1:]) <= 65535:
        raise ValueError("The dish address has a port out of range")
    return addr if m.group(2) else f"{addr}:9200"


def split_addr(addr: str) -> tuple[str, int]:
    addr = clean_addr(addr)
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), int(port)


def _hpack_int(n: int, prefix_bits: int, first: int) -> bytes:
    limit = (1 << prefix_bits) - 1
    if n < limit:
        return bytes([first | n])
    out = bytearray([first | limit])
    n -= limit
    while n >= 128:
        out.append(n % 128 + 128)
        n //= 128
    out.append(n)
    return bytes(out)


def _hpack_str(s: str) -> bytes:
    b = s.encode()
    return _hpack_int(len(b), 7, 0) + b


def _headers_block(authority: str, path: str) -> bytes:
    """HPACK, without Huffman or the dynamic table: static indexes where the whole header matches, else literals."""
    out = bytearray(b"\x83\x86")                              # :method POST, :scheme http
    out += _hpack_int(4, 4, 0) + _hpack_str(path)             # :path (static name 4), literal value
    out += _hpack_int(1, 4, 0) + _hpack_str(authority)        # :authority (static name 1)
    out += _hpack_int(31, 4, 0) + _hpack_str("application/grpc")   # content-type (static name 31)
    for k, v in (("te", "trailers"), ("user-agent", "rollcall")):
        out += b"\x00" + _hpack_str(k) + _hpack_str(v)
    return bytes(out)


def _frame(ftype: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream.to_bytes(4, "big") + payload


async def grpc_call(host: str, port: int, path: str, message: bytes, timeout: float = 10) -> bytes:
    """One unary gRPC call over cleartext HTTP/2: the answer's message bytes."""
    async def run() -> bytes:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            window = 1 << 24
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                         + _frame(4, 0, 0, struct.pack(">HI", 4, window) + struct.pack(">HI", 2, 0))  # window, no push
                         + _frame(8, 0, 0, struct.pack(">I", window - 65535))
                         + _frame(1, 0x4, 1, _headers_block(f"{host}:{port}" if ":" not in host else f"[{host}]:{port}", path))
                         + _frame(0, 0x1, 1, b"\x00" + len(message).to_bytes(4, "big") + message))
            await writer.drain()
            body = bytearray()
            while True:
                head = await reader.readexactly(9)
                ln, ftype, flags, stream = int.from_bytes(head[:3], "big"), head[3], head[4], int.from_bytes(head[5:], "big") & 0x7FFFFFFF
                payload = await reader.readexactly(ln) if ln else b""
                if ftype == 4 and not flags & 0x1:            # SETTINGS: acknowledge
                    writer.write(_frame(4, 0x1, 0))
                    await writer.drain()
                elif ftype == 6 and not flags & 0x1:          # PING: answer
                    writer.write(_frame(6, 0x1, 0, payload))
                    await writer.drain()
                elif ftype == 7:                              # GOAWAY
                    code = int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else 0
                    if stream == 0 and body:
                        break
                    raise StarlinkError(f"the dish closed the connection (HTTP/2 error {code})")
                elif ftype == 3 and stream == 1:              # RST_STREAM
                    raise StarlinkError(f"the dish refused the request (HTTP/2 error {int.from_bytes(payload[:4], 'big')})")
                elif stream == 1 and ftype in (0, 1):
                    if flags & 0x8 and payload:               # padded
                        payload = payload[1:len(payload) - payload[0]]
                    if ftype == 0:
                        body += payload
                        if len(body) > MAX_BYTES:
                            raise StarlinkError("the dish's answer was too big")
                        if payload and not flags & 0x1:       # give the window back (the stream ends here otherwise)
                            writer.write(_frame(8, 0, 0, struct.pack(">I", len(payload)))
                                         + _frame(8, 0, 1, struct.pack(">I", len(payload))))
                            await writer.drain()
                    if flags & 0x1:                           # END_STREAM
                        break
            if len(body) < 5:
                raise StarlinkError("the dish answered without a status (it may not be a Starlink dish, or it refused the request)")
            if body[0]:
                raise StarlinkError("the dish sent a compressed answer, which Rollcall can't read")
            n = int.from_bytes(body[1:5], "big")
            return bytes(body[5:5 + n])
        finally:
            writer.close()
    try:
        return await asyncio.wait_for(run(), timeout)
    except asyncio.TimeoutError:
        raise StarlinkError(f"no answer from the dish at {host}:{port}") from None
    except asyncio.IncompleteReadError:
        raise StarlinkError("the dish closed the connection without answering") from None
    except OSError as err:
        raise StarlinkError(f"couldn't reach the dish at {host}:{port} ({err.strerror or err})") from None


async def read_local(addr: str, timeout: float = 10) -> dict:
    host, port = split_addr(addr or DEFAULT_ADDR)
    t0 = time.monotonic()
    raw = await grpc_call(host, port, GRPC_PATH, status_request(), timeout)
    d = parse_response(raw)
    d["ms"] = round((time.monotonic() - t0) * 1000)
    return d


# ---- account: starlink.com ------------------------------------------------------------------------------------
def clean_cookie(text: str) -> str:
    """The cookie as copied from the browser ('cookie: a=b; c=d' or 'a=b; c=d'). Raises ValueError."""
    text = str(text or "").strip()
    if text.lower().startswith("cookie:"):
        text = text[7:].strip()
    jar = parse_cookie(text)
    if not any(k.startswith("Starlink.Com.") for k in jar):
        raise ValueError("That doesn't look like the starlink.com cookie: copy the whole cookie header of a request "
                         "to starlink.com (it includes Starlink.Com.Sso)")
    if len(text) > 16000 or not text.isprintable():
        raise ValueError("That cookie is too long or has unexpected characters")
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def parse_cookie(text: str) -> dict:
    jar: dict[str, str] = {}
    for part in str(text or "").split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k:
            jar[k.strip()] = v.strip()
    return jar


# Tests point the account API at a stand-in (never set in the add-on)
TEST_BASE = os.environ.get("PM_STARLINK_TEST_BASE", "")


def _url(url: str) -> str:
    if not TEST_BASE:
        return url
    u = urlparse(url)
    return TEST_BASE.rstrip("/") + "/" + u.hostname + u.path


def _check_url(url: str) -> None:
    u = urlparse(url)
    if TEST_BASE and url.startswith(TEST_BASE):
        return
    if u.scheme != "https" or u.hostname not in STARLINK_HOSTS:
        raise StarlinkError("refusing to send the Starlink sign-in anywhere but starlink.com")


class Account:
    """A starlink.com session from a pasted cookie. state keeps the short-lived token between checks; the cookie
    is updated from what starlink.com sends back (cookie attribute)."""

    def __init__(self, cookie: str, state: dict | None = None, tls=None):
        self.jar = parse_cookie(cookie)
        self.state = state if state is not None else {}
        self.tls = tls
        self.changed = False
        self.primed = False
        self.trace: list[str] = []      # what each request did, for the log: status and cookie NAMES, never values

    @property
    def cookie(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.jar.items())

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"User-Agent": UA, "Cookie": self.cookie, "Accept": "*/*"}
        if self.jar.get("XSRF-TOKEN"):
            h["X-XSRF-TOKEN"] = self.jar["XSRF-TOKEN"]
        if self.state.get("token") and time.time() < self.state.get("until", 0):
            h["Authorization"] = f"Bearer {self.state['token']}"
        return {**h, **{k: v for k, v in (extra or {}).items() if not k.startswith("_")}}

    def _keep(self, r: aiohttp.ClientResponse) -> list[str]:
        """Take what starlink.com sets, as a browser would: new values, and cookies it deletes (empty, or
        already expired) dropped, so a stale short-lived access cookie isn't sent back. The names it touched."""
        touched = []
        for line in r.headers.getall("Set-Cookie", ()):
            first, _, attrs = line.partition(";")
            name, sep, value = first.strip().partition("=")
            name, value = name.strip(), value.strip()
            if not sep or not name:
                continue
            gone = not value
            for a in attrs.split(";"):
                k, _, v = a.strip().partition("=")
                k = k.strip().lower()
                try:
                    if k == "max-age" and int(v) <= 0:
                        gone = True
                    elif k == "expires":
                        from email.utils import parsedate_to_datetime
                        if parsedate_to_datetime(v.strip()).timestamp() < time.time():
                            gone = True
                except (ValueError, TypeError, OverflowError):
                    pass
            if gone:
                if self.jar.pop(name, None) is not None:
                    self.changed = True
                touched.append(name + " (removed)")
            else:
                if self.jar.get(name) != value:
                    self.jar[name] = value
                    self.changed = True
                touched.append(name)
        return touched

    async def _request(self, session, method: str, url: str, *, data: bytes | None = None, extra: dict | None = None,
                       timeout: float = 15) -> tuple[int, bytes]:
        url = _url(url)
        _check_url(url)
        try:
            async with session.request(method, url, data=data, headers=self._headers(extra), ssl=self.tls,
                                       allow_redirects=False, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                touched = self._keep(r)
                self.trace.append(f"{method} {urlparse(url).path[-40:]} -> {r.status}" + (f" sets {', '.join(touched)}" if touched else ""))
                body = await r.content.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise StarlinkError("starlink.com's answer was too big")
                if r.status in (301, 302, 303, 307, 308) and extra and extra.get("_follow"):
                    return r.status, (r.headers.get("Location") or "").encode()
                return r.status, body
        except asyncio.TimeoutError:
            raise StarlinkError("starlink.com didn't answer in time") from None
        except aiohttp.ClientError as err:
            raise StarlinkError(f"couldn't reach starlink.com ({err.__class__.__name__})") from None

    @staticmethod
    def _signed_out(status: int, body: bytes) -> bool:
        head = body[:300].lower()
        return status in (401, 403) or b"authenticated_user_required" in head or b"token_expired" in head

    async def _token(self, session) -> None:
        if self.state.get("token") and time.time() < self.state.get("until", 0):
            return
        status, body = await self._request(session, "GET", TOKEN_URL, extra={
            "Accept": "application/json", "Origin": "https://starlink.com", "Referer": "https://starlink.com/account/home"})
        if status != 200 and self._signed_out(status, body):
            # A pasted cookie has no expiry dates: the browser's short-lived access cookies may already be dead
            # on starlink.com's side, and sending them spoils the request. Drop them and ask once more.
            stale = [k for k in self.jar if k.startswith("Starlink.Com.") and "access" in k.lower()]
            if stale:
                for k in stale:
                    self.jar.pop(k)
                self.changed = True
                self.trace.append(f"dropped {', '.join(stale)} and asked again")
                status, body = await self._request(session, "GET", TOKEN_URL, extra={
                    "Accept": "application/json", "Origin": "https://starlink.com", "Referer": "https://starlink.com/account/home"})
        if status != 200:
            if self._signed_out(status, body) or 300 <= status < 400:
                raise StarlinkError("Starlink sign-in expired: paste a new cookie under Edit", login=True)
            raise StarlinkError(f"starlink.com answered HTTP {status} when renewing the sign-in")
        try:
            import json
            j = json.loads(body)
            token, life = j.get("accessToken"), int(j.get("expiresIn") or 0)
        except (ValueError, TypeError, AttributeError):
            raise StarlinkError("starlink.com's sign-in answer wasn't understood (its API may have changed)") from None
        if not isinstance(token, str) or len(token) < 20:
            raise StarlinkError("Starlink sign-in expired: paste a new cookie under Edit", login=True)
        self.state["token"], self.state["until"] = token, time.time() + max(life - 60, 30)

    async def prime(self, session) -> None:
        """Visit the account pages, as the browser does: this keeps the starlink.com session alive (it renews
        and rotates its cookies here) and drops the short-lived ones it has replaced. Without it the session
        lapses within minutes of the pasted cookie's access part expiring. Redirects are followed only while they
        stay on starlink.com. Best effort: whether the sign-in still works is decided by the token after it."""
        self.primed = True
        for url in (PORTAL_HOME_URL, AUTH_USER_URL):
            try:
                for _hop in range(5):
                    status, body = await self._request(session, "GET", url, extra={
                        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8", "_follow": "1"})
                    if status not in (301, 302, 303, 307, 308):
                        break
                    from urllib.parse import urljoin
                    url = urljoin(url, body.decode("latin-1"))
                    if urlparse(url).hostname not in STARLINK_HOSTS and not (TEST_BASE and url.startswith(TEST_BASE)):
                        self.trace.append("redirected away from starlink.com: not followed")
                        break
            except StarlinkError as err:
                self.trace.append(f"{urlparse(url).path}: {err}")

    async def _call(self, session, method: str, url: str, **kw) -> tuple[int, bytes]:
        if not self.primed:
            await self.prime(session)
        await self._token(session)
        status, body = await self._request(session, method, url, **kw)
        if self._signed_out(status, body):
            self.state.pop("token", None)                     # the token may have gone first: renew it once
            await self._token(session)
            status, body = await self._request(session, method, url, **kw)
            if self._signed_out(status, body):
                raise StarlinkError("Starlink sign-in expired: paste a new cookie under Edit", login=True)
        return status, body

    async def dishes(self, session) -> list[dict]:
        """The dishes on the account: [{id (the target), name}]."""
        import json
        status, body = await self._call(session, "GET", SERVICE_LINES_URL, extra={"Accept": "application/json"})
        if status != 200:
            raise StarlinkError(f"starlink.com answered HTTP {status} for the account's dishes")
        try:
            j = json.loads(body)
        except ValueError:
            raise StarlinkError("starlink.com's list of dishes wasn't understood (its API may have changed)") from None
        out = []
        for line in ((j.get("content") or {}).get("results") or []) if isinstance(j, dict) else []:
            where = line.get("nickname") or line.get("serviceLineNickname") or line.get("serviceLineNumber") or ""
            for t in line.get("userTerminals") or []:
                tid = str(t.get("userTerminalId") or "")
                if not tid:
                    continue
                name = t.get("nickname") or t.get("userTerminalNickname") or t.get("kitSerialNumber") or ""
                label = " · ".join(str(x) for x in (name, where) if x) or "Dish"
                out.append({"id": tid if tid.startswith("ut") else "ut" + tid, "name": str(label)[:100]})
        return out

    async def status(self, session, target: str) -> dict:
        msg = status_request(target)
        t0 = time.monotonic()
        status, body = await self._call(session, "POST", ACCOUNT_API, data=b"\x00" + len(msg).to_bytes(4, "big") + msg, extra={
            "Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1", "Accept": "application/grpc-web+proto",
            "Origin": "https://www.starlink.com", "Referer": "https://www.starlink.com/account/home"})
        if status != 200:
            raise StarlinkError(f"starlink.com answered HTTP {status} for the dish's status")
        i = 0
        while i + 5 <= len(body):                            # gRPC-web: [flag][length][bytes]..., 0x80 = trailers
            flag, n = body[i], int.from_bytes(body[i + 1:i + 5], "big")
            chunk = body[i + 5:i + 5 + n]
            if flag == 0:
                d = parse_response(chunk)
                d["ms"] = round((time.monotonic() - t0) * 1000)
                return d
            if flag & 0x80:
                text = chunk.decode("utf-8", "replace")
                m = re.search(r"grpc-message:\s*([^\r\n]+)", text)
                raise StarlinkError("starlink.com couldn't read the dish" + (f": {m.group(1)[:200]}" if m else
                                    " (it may be offline)"))
            i += 5 + n
        raise StarlinkError("starlink.com answered without the dish's status (it may be offline)")


# ---- what it means ----------------------------------------------------------------------------------------------
def mbps(bps) -> str:
    if bps is None:
        return "—"
    v = bps / 1e6
    return f"{v:.1f} Mb/s" if v < 100 else f"{v:.0f} Mb/s"


def evaluate(d: dict) -> tuple[bool, float | None, str, str | None]:
    """(ok, latency, detail, level). Red, with an alert, while the dish reports an outage, is shut down by heat or
    has its service disabled; amber (no alert) for its other alerts and heavy obstruction; otherwise green with
    its latency, drops and throughput."""
    lat = d.get("latency_ms")
    if d.get("disabled"):
        return False, None, f"Starlink service disabled: {d['disabled']}", None
    crit = [a["what"] for a in d.get("alerts") or [] if a["level"] == "crit"]
    if crit:
        return False, None, "Starlink dish " + "; ".join(crit), None
    if d.get("outage"):
        o = d["outage"]
        return False, None, f"Starlink offline: {o['cause']}" + (f" for {_dur(o['for_s'])}" if o.get("for_s") else ""), None
    bits = ["online"]
    if lat is not None:
        bits.append(f"{lat:g} ms")
    if d.get("drop_rate") is not None:
        bits.append(f"{d['drop_rate'] * 100:.1f}% drops")
    bits.append(f"↓ {mbps(d.get('down_bps'))} ↑ {mbps(d.get('up_bps'))}")
    warn = [a["what"] for a in d.get("alerts") or [] if a["level"] == "warn"]
    if (d.get("obstructed_time") or 0) > OBSTRUCTED_WARN:
        warn.append(f"obstructed {d['obstructed_time'] * 100:.1f}% of the time")
    if d.get("stowed"):
        warn.append("stowed")
    text = "Starlink " + ", ".join(bits)
    if warn:
        return False, lat, text + "; " + "; ".join(warn), "warn"
    return True, lat, text, None


def _dur(s) -> str:
    s = int(s or 0)
    if s < 120:
        return f"{s} s"
    if s < 7200:
        return f"{s // 60} min"
    return f"{s // 3600} h {s % 3600 // 60} min"
