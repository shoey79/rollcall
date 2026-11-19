"""Plex Media Server: what's playing and the server's state, read by the add-on with a Plex token.

Endpoints (Plex Media Server's HTTP API; answers are XML):
  GET /identity                the server answers (no token needed)
  GET /                        version, friendlyName, transcoderActiveVideoSessions
  GET /status/sessions         what's playing: a Video or Track per stream, with its User (title),
                               Player (title, product, state playing/paused/buffering, local), the item's
                               title, grandparentTitle / parentIndex / index (an episode), year, duration and
                               viewOffset (ms), and a TranscodeSession (videoDecision / audioDecision
                               transcode, copy or directplay; videoCodec, sourceVideoCodec, height,
                               transcodeHwRequested) when the server is transcoding it
  GET /updater/status          a Release element when a newer Plex is available
  GET /activities              what the server is busy with (Activity title, subtitle, progress)
  GET /library/sections        each library (Directory key, type, title); its size from
                               /library/sections/<key>/all with X-Plex-Container-Size 0 (totalSize)

The token goes in the X-Plex-Token header (never the address), and is only ever sent to the address set for
the device: redirects aren't followed. Find it in Plex Web: open any item, "Get Info", "View XML", and copy
the X-Plex-Token from the address of the page that opens.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import aiohttp

from jellyfin import URL_RE, same_server  # noqa: F401  (same address rules)

TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")
MAX_BYTES = 4 * 1024 * 1024


class PlexError(Exception):
    """Plex couldn't be read. login is True when it turned the token down; dropped is True when it closed the
    connection, as Plex does to plain HTTP when its secure connections are set to Required."""

    def __init__(self, msg: str, login: bool = False, dropped: bool = False):
        super().__init__(msg)
        self.login, self.dropped = login, dropped


def default_url(host: str) -> str:
    return f"http://[{host}]:32400" if ":" in host and not host.startswith("[") else f"http://{host}:32400"


def clean_url(url: str) -> str:
    """'http://plex.example.local:32400/' -> 'http://plex.example.local:32400'. Raises ValueError."""
    url = str(url or "").strip().rstrip("/")
    if not URL_RE.match(url):
        raise ValueError("The Plex address must be like http://192.168.1.20:32400 (no query or user name)")
    u = urlparse(url)
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError("The Plex address has a port out of range")
    return url


def _headers(token: str | None) -> dict:
    h = {"Accept": "application/xml", "User-Agent": "Rollcall", "X-Plex-Product": "Rollcall",
         "X-Plex-Client-Identifier": "rollcall-home-assistant", "X-Plex-Container-Start": "0"}
    if token:
        h["X-Plex-Token"] = token
    return h


async def _get(session: aiohttp.ClientSession, url: str, headers: dict, tls, timeout: float) -> ET.Element:
    try:
        async with session.get(url, headers=headers, ssl=tls, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status in (401, 403):
                raise PlexError("the token was refused (copy X-Plex-Token from Plex Web: Get Info, View XML)", login=True)
            if 300 <= r.status < 400:
                raise PlexError(f"redirected (HTTP {r.status}); set the address it redirects to")
            if r.status >= 400:
                raise PlexError(f"HTTP {r.status} from {urlparse(url).path}")
            body = bytearray()  # the whole answer, however many pieces it comes in
            async for part in r.content.iter_chunked(65536):
                body += part
                if len(body) > MAX_BYTES:
                    raise PlexError("answer too large")
    except asyncio.TimeoutError:
        raise PlexError("no answer (timed out)") from None
    except aiohttp.ClientConnectorError as err:
        raise PlexError((getattr(err, "strerror", None) or "can't connect").lower()) from None
    except (aiohttp.ServerDisconnectedError, aiohttp.ClientOSError, aiohttp.ClientPayloadError) as err:
        raise PlexError(f"connection closed by Plex ({type(err).__name__})", dropped=True) from None
    except aiohttp.ClientError as err:
        raise PlexError(f"connection failed ({type(err).__name__})") from None
    if b"<!DOCTYPE" in bytes(body[:2000]).upper() or b"<!ENTITY" in bytes(body[:4000]).upper():
        raise PlexError(f"not Plex? {urlparse(url).path} answered with a web page")
    try:
        return ET.fromstring(bytes(body))
    except ET.ParseError:
        raise PlexError(f"not Plex? {urlparse(url).path} didn't answer with XML") from None


async def poll(base: str, token: str, tls: ssl.SSLContext | None, timeout: float = 15.0) -> dict:
    """Read the server. Raises PlexError if it can't be reached or turns the token down.

    Plex with its secure connections set to Required drops plain HTTP, so then HTTPS is tried on the same
    port; the result's "base" says which answered, for the next check."""
    try:
        return await _poll(base, token, tls, timeout)
    except PlexError as err:
        if not (err.dropped and base.startswith("http://")):
            raise
        try:
            return await _poll("https://" + base[len("http://"):], token, tls, timeout)
        except PlexError:
            raise err from None


async def _poll(base: str, token: str, tls: ssl.SSLContext | None, timeout: float) -> dict:
    t0 = time.monotonic()
    async with aiohttp.ClientSession() as session:
        ident = await _get(session, base + "/identity", _headers(None), tls, timeout)
        ms = round((time.monotonic() - t0) * 1000, 1)
        h = _headers(token)
        root = await _get(session, base + "/", h, tls, timeout)
        sessions = await _get(session, base + "/status/sessions", h, tls, timeout)
        opt = {}
        for k, path in (("updater", "/updater/status"), ("activities", "/activities"), ("sections", "/library/sections")):
            try:
                opt[k] = await _get(session, base + path, h, tls, timeout)
            except PlexError:
                opt[k] = None
        counts = []
        for d in (opt["sections"].findall("Directory") if opt["sections"] is not None else [])[:12]:
            key, typ = d.get("key"), d.get("type")
            if not (key and key.isdigit()):
                continue
            n = sub = None
            try:
                n = (await _get(session, f"{base}/library/sections/{key}/all", {**h, "X-Plex-Container-Size": "0"}, tls, timeout)).get("totalSize")
                if typ == "show":  # episodes too (type 4)
                    sub = (await _get(session, f"{base}/library/sections/{key}/all?type=4", {**h, "X-Plex-Container-Size": "0"}, tls, timeout)).get("totalSize")
            except PlexError:
                pass
            counts.append({"name": (d.get("title") or "Library")[:60], "type": (typ or "")[:20], "count": _int(n), "episodes": _int(sub)})
    return {**parse(ident, root, sessions, opt["updater"], opt["activities"], counts, ms), "base": base}


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _title(x: ET.Element) -> str:
    """What's playing, as people would say it: a series' episode, a film and its year, a song and artist."""
    t, kind = x.get("title") or "", x.get("type")
    if kind == "episode" and x.get("grandparentTitle"):
        s, e = _int(x.get("parentIndex")), _int(x.get("index"))
        return f"{x.get('grandparentTitle')}{f' S{s:02d}E{e:02d}' if s is not None and e is not None else ''} · {t}"[:160]
    if kind == "track" and (x.get("grandparentTitle") or x.get("originalTitle")):
        return f"{x.get('originalTitle') or x.get('grandparentTitle')} – {t}"[:160]
    if kind == "movie" and x.get("year"):
        return f"{t} ({x.get('year')})"[:160]
    return t[:160]


def _stream(x: ET.Element) -> dict:
    user, player, tr = x.find("User"), x.find("Player"), x.find("TranscodeSession")
    sess = x.find("Session")
    dur, off = _int(x.get("duration")), _int(x.get("viewOffset"))
    vd = (tr.get("videoDecision") if tr is not None else "") or ""
    ad = (tr.get("audioDecision") if tr is not None else "") or ""
    if tr is None:
        part = x.find("Media/Part")
        method = "Direct stream" if part is not None and part.get("decision") == "copy" else "Direct play"
    elif "transcode" in (vd, ad):
        method = "Transcoding"
    else:
        method = "Direct stream"
    out = {"user": (user.get("title") if user is not None else "") or "", "client": ((player.get("product") if player is not None else "") or "")[:60],
           "device": ((player.get("title") if player is not None else "") or "")[:60], "title": _title(x), "type": (x.get("type") or "")[:20],
           "method": method, "paused": player is not None and player.get("state") == "paused",
           "position_s": off // 1000 if off is not None and off >= 0 else None, "runtime_s": dur // 1000 if dur else None,
           "remote": sess is not None and sess.get("location") == "wan", "transcode": "", "reasons": []}
    out["user"] = out["user"][:60]
    if method == "Transcoding":
        video = "" if x.get("type") == "track" else (
            "video copied" if vd == "copy" else f"video {tr.get('sourceVideoCodec') or '?'} to {tr.get('videoCodec') or '?'}" if vd == "transcode" else "")
        audio = "audio copied" if ad == "copy" else f"audio to {tr.get('audioCodec') or '?'}" if ad == "transcode" else ""
        bits = [video, audio, f"{tr.get('height')}p" if _int(tr.get("height")) else "",
                "hardware" if tr.get("transcodeHwRequested") == "1" else "",
                "throttled" if tr.get("throttled") == "1" else ""]
        out["transcode"] = ", ".join(b for b in bits if b)[:120]
    return out


def parse(ident, root, sessions, updater=None, activities=None, counts=None, ms: float | None = None) -> dict:
    """The parts Rollcall uses, from Plex's answers (ElementTree elements, or None where unread)."""
    playing = [_stream(x) for x in list(sessions)[:20]] if sessions is not None else []
    rel = updater.find("Release") if updater is not None else None
    busy = [{"title": (a.get("title") or "")[:80], "subtitle": (a.get("subtitle") or "")[:120], "progress": _int(a.get("progress"))}
            for a in (activities.findall("Activity") if activities is not None else [])][:10]
    return {"name": (root.get("friendlyName") or "")[:100], "version": (root.get("version") or (ident.get("version") if ident is not None else "") or "")[:40],
            "streams": len(playing) if sessions is not None else None, "transcodes": sum(p["method"] == "Transcoding" for p in playing),
            "playing": playing, "users": len({p["user"] for p in playing if p["user"]}) if sessions is not None else None,
            "update": (rel.get("version") or "a newer version")[:40] if rel is not None else "", "activities": busy,
            "library": [c for c in (counts or []) if c.get("count") is not None][:12], "ms": ms}


def evaluate(d: dict) -> tuple[bool, float | None, str, str | None]:
    """(ok, latency, detail, level): green with the version and streams; amber (never an alert) when an update
    is available. Plex not answering, or turning the token down, is decided by the caller."""
    bits = [f"Plex {d['version'].split('-')[0]}" if d.get("version") else "Plex"]
    if d.get("streams") is not None:
        n, t = d["streams"], d.get("transcodes") or 0
        bits.append(f"{n} stream{'' if n == 1 else 's'}" + (f" ({t} transcoding)" if t else ""))
    if d.get("update"):
        return False, None, "; ".join(bits + [f"update available ({d['update'].split('-')[0]})"]), "warn"
    return True, d.get("ms"), "; ".join(bits), None
