"""OPNsense without an agent: its own REST API, read with an API key and secret.

Create a user in OPNsense (System, Access, Users) with only the read privileges below, then an API key for it
(the key and secret go in the device's Edit form). Every call here is a GET: nothing is changed.

  GET /api/diagnostics/system/system_information   name and version          (Lobby: Dashboard)
  GET /api/diagnostics/system/system_resources     memory                    (Lobby: Dashboard)
  GET /api/diagnostics/system/system_time          uptime and load           (Lobby: Dashboard)
  GET /api/diagnostics/firewall/pf_states          state table and its limit (Lobby: Dashboard)
  GET /api/diagnostics/system/system_temperature   temperatures              (Lobby: Dashboard)
  GET /api/routes/gateway/status                   gateways: status, delay, loss  (System: Gateways)
  GET /api/core/firmware/status                    version and whether an update is waiting  (System: Firmware)
  GET /api/diagnostics/interface/get_vip_status    CARP                      (Interfaces: Virtual IPs: Status)
  GET /api/ipsec/sessions/search_phase1            IPsec tunnels             (Status: IPsec)
  GET /api/openvpn/service/search_sessions         OpenVPN                   (Status: OpenVPN)

OPNsense before 25.7 named some of these in camelCase (systemInformation, systemResources, systemTime,
systemTemperature, searchPhase1, searchSessions); those are tried when the new name isn't found. A section the key
isn't allowed to read is left out rather than failing the check. The answer is turned into the same shape the
FreeBSD agent reports, so the same judging and the same Details apply.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from base64 import b64encode
from urllib.parse import urlparse

import aiohttp

KEY_RE = re.compile(r"^[A-Za-z0-9+/=]{20,128}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?/?$|^https?://\[[0-9A-Fa-f:]+\](:\d{1,5})?/?$")
MAX_BYTES = 4 * 1024 * 1024
OLD = {"system_information": "systemInformation", "system_resources": "systemResources", "system_time": "systemTime",
       "system_temperature": "systemTemperature", "search_phase1": "searchPhase1", "search_sessions": "searchSessions"}


class OpnsenseError(Exception):
    def __init__(self, msg: str, login: bool = False):
        super().__init__(msg)
        self.login = login


def clean_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not URL_RE.match(url):
        raise ValueError("Enter the address as https://name or https://name:port")
    return url


def default_url(host: str) -> str:
    return f"https://[{host}]" if ":" in host else f"https://{host}"


def same_server(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.hostname or "").lower() == (pb.hostname or "").lower()


async def _get(session, base: str, path: str, auth: str, tls, timeout: float):
    """JSON from path; None if it isn't there or the key may not read it (403)."""
    leaf = path.rsplit("/", 1)[-1]
    for p in [path] + ([path[:-len(leaf)] + OLD[leaf]] if leaf in OLD else []):
        try:
            async with session.get(base + p, headers={"Authorization": auth, "Accept": "application/json", "User-Agent": "Rollcall"},
                                   ssl=tls, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                body = bytearray()
                async for part in r.content.iter_chunked(65536):
                    body += part
                    if len(body) > MAX_BYTES:
                        raise OpnsenseError("answer too large")
                if r.status == 401:
                    raise OpnsenseError("the API key was turned down (check the key and secret)", login=True)
                if r.status == 403:
                    return None
                if 300 <= r.status < 400:
                    raise OpnsenseError(f"redirected (HTTP {r.status}); set the address it redirects to (https?)")
                if r.status == 404:
                    continue
                if r.status >= 400:
                    raise OpnsenseError(f"HTTP {r.status} from {p}")
                try:
                    return json.loads(body)
                except ValueError:
                    raise OpnsenseError(f"not OPNsense? {p} didn't answer with JSON") from None
        except asyncio.TimeoutError:
            raise OpnsenseError("no answer (timed out)") from None
        except aiohttp.ClientConnectorError as err:
            raise OpnsenseError((getattr(err, "strerror", None) or "can't connect").lower()) from None
        except aiohttp.ClientError as err:
            raise OpnsenseError(f"connection failed ({type(err).__name__})") from None
    return None


def _num(v) -> float | None:
    m = re.search(r"-?\d+(?:\.\d+)?", str(v if v is not None else ""))
    return float(m.group(0)) if m else None


def _uptime_s(text) -> int | None:
    """OPNsense's "3 days 04:05:06" (or "04:05:06")."""
    m = re.search(r"(?:(\d+)\s*days?,?\s*)?(\d+):(\d\d)(?::(\d\d))?", str(text or ""))
    if not m:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


def parse(info, res, tm, states, temps, gws, fwst, vips, ipsec, ovpn) -> dict:
    """The firewall dict the FreeBSD agent sends (agents.clean_firewall), plus what an agent would send separately."""
    d: dict = {"product": "OPNsense"}
    if isinstance(info, dict):
        d["name"] = str(info.get("name") or "")[:100]
        vers = info.get("versions")
        if isinstance(vers, list) and vers:
            d["version"] = str(vers[0])[:40]
    if isinstance(fwst, dict):
        prod = fwst.get("product") if isinstance(fwst.get("product"), dict) else {}
        cur = prod.get("product_version") or fwst.get("product_version")
        if cur:
            d["version"] = str(cur)[:40]
        st = str(fwst.get("status") or "").lower()
        latest = prod.get("product_latest") or fwst.get("product_latest") or fwst.get("upgrade_major_version")
        d["update"] = {"available": True if st in ("update", "upgrade") else False if st in ("none", "ok") else None,
                       "version": str(latest or "")[:30] or None if st in ("update", "upgrade") else None,
                       "checked": str(fwst.get("last_check") or "")[:30] or None}
    if isinstance(gws, dict):
        d["gateways"] = []
        for g in gws.get("items") or []:
            if not isinstance(g, dict):
                continue
            st = str(g.get("status") or "").lower()
            d["gateways"].append({"name": g.get("name"), "monitor": g.get("monitor") or g.get("address"),
                                  "delay_ms": _num(g.get("delay")), "stddev_ms": _num(g.get("stddev")), "loss_pct": _num(g.get("loss")),
                                  # OPNsense says "none" for a gateway that's fine; "delay+loss" for both
                                  "status": "online" if st in ("none", "") else ("loss" if "loss" in st else st),
                                  "substatus": g.get("status_translated")})
    if isinstance(vips, dict):
        d["carp"] = [{"interface": v.get("interface"), "vhid": v.get("vhid"), "state": str(v.get("status") or "").upper()}
                     for v in vips.get("rows") or [] if isinstance(v, dict) and (v.get("mode") or "carp").lower() == "carp" and v.get("vhid")]
    if isinstance(ipsec, dict):
        rows = [r for r in ipsec.get("rows") or [] if isinstance(r, dict)]
        name = lambda r: str(r.get("phase1desc") or r.get("name") or r.get("remote-host") or "")[:60]  # noqa: E731
        up = [r for r in rows if r.get("connected") in (True, "true", 1, "1")]
        d["ipsec"] = {"configured": len(rows), "mobile": 0, "up": len(up), "down": [name(r) for r in rows if r not in up]}
    if isinstance(ovpn, dict):
        d["openvpn"] = []
        for r in ovpn.get("rows") or []:
            if not isinstance(r, dict):
                continue
            kind = "server" if str(r.get("type") or "").lower() == "server" else "client"
            d["openvpn"].append({"name": str(r.get("description") or r.get("id") or "")[:60], "kind": kind,
                                 "state": str(r.get("status") or "").upper(), "clients": int(_num(r.get("connected_clients")) or 0)})
    if isinstance(states, dict) and _num(states.get("current")) is not None:
        d["states"] = {"current": int(_num(states["current"])), "limit": int(_num(states.get("limit")) or 0) or None}
    extra: dict = {}
    if isinstance(res, dict) and isinstance(res.get("memory"), dict):
        m = res["memory"]
        tot, used = _num(m.get("total")), _num(m.get("used"))
        if tot:
            extra["mem_pct"] = round(100 * (used or 0) / tot)
            extra["mem_total_mb"] = round(tot / 1048576)
    if isinstance(tm, dict):
        extra["uptime_s"] = _uptime_s(tm.get("uptime"))
        la = [x for x in (_num(p) for p in str(tm.get("loadavg") or "").split(",")) if x is not None]
        if la:
            extra["load"] = la[:3]
    if isinstance(temps, list):
        extra["temps"] = {"sensors": [{"name": str(t.get("type_translated") or t.get("device") or "")[:40], "celsius": _num(t.get("temperature"))}
                                      for t in temps if isinstance(t, dict) and _num(t.get("temperature")) is not None][:16]}
    d["extra"] = extra
    return d


async def poll(base: str, key: str, secret: str, tls, timeout: float = 20.0) -> dict:
    auth = "Basic " + b64encode(f"{key}:{secret}".encode()).decode()
    t0 = time.monotonic()
    async with aiohttp.ClientSession() as s:
        info = await _get(s, base, "/api/diagnostics/system/system_information", auth, tls, timeout)
        fwst = await _get(s, base, "/api/core/firmware/status", auth, tls, timeout)
        if info is None and fwst is None:
            raise OpnsenseError("the API key can read neither the dashboard nor the firmware status (give its user "
                                "Lobby: Dashboard and System: Firmware)", login=True)
        ms = round((time.monotonic() - t0) * 1000, 1)
        got = {}
        for k, p in (("res", "/api/diagnostics/system/system_resources"), ("tm", "/api/diagnostics/system/system_time"),
                     ("states", "/api/diagnostics/firewall/pf_states"), ("temps", "/api/diagnostics/system/system_temperature"),
                     ("gws", "/api/routes/gateway/status"), ("vips", "/api/diagnostics/interface/get_vip_status"),
                     ("ipsec", "/api/ipsec/sessions/search_phase1"), ("ovpn", "/api/openvpn/service/search_sessions")):
            got[k] = await _get(s, base, p, auth, tls, timeout)
    d = parse(info, got["res"], got["tm"], got["states"], got["temps"], got["gws"], fwst, got["vips"], got["ipsec"], got["ovpn"])
    d["ms"] = ms
    d["read_sections"] = sorted(k for k, v in {"info": info, "firmware": fwst, **got}.items() if v is not None)
    return d
