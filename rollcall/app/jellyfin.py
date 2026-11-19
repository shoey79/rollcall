"""Jellyfin: the server's health, read by the add-on with a Jellyfin API key.

Endpoints (Jellyfin's REST API, as documented at api.jellyfin.org; 10.9 to 10.11):
  GET /health                  "Healthy", "Degraded" or "Unhealthy" as plain text; no key needed
  GET /System/Info             Version, ServerName, HasPendingRestart, HasUpdateAvailable
  GET /ScheduledTasks          each task's Name, State, IsHidden and LastExecutionResult (Status:
                               Completed, Failed, Cancelled or Aborted; EndTimeUtc; ErrorMessage)
  GET /Sessions                each client session; one with a NowPlayingItem is a stream, and
                               PlayState.PlayMethod "Transcode" means the server is transcoding it
                               (TranscodingInfo.TranscodeReasons says why). UserName, Client,
                               DeviceName, PlayState.PositionTicks / IsPaused, NowPlayingItem.RunTimeTicks
  GET /Plugins                 each plugin's Name, Version and Status (Active, Restart, Malfunctioned,
                               NotSupported, Superceded, Deleted, Disabled): one that isn't Active is
                               usually why a restart is pending
  GET /Items/Counts            how many movies, series, episodes, albums, songs, books... the server has

The key goes in the `Authorization: MediaBrowser Token="..."` header, the form Jellyfin prefers (the
X-Emby-Token header and api_key query are deprecated and go in Jellyfin 12). It's only ever sent to the
address set for the device: redirects aren't followed, so a key can't be handed on to somewhere else.

Jellyfin 10.9 stopped checking for its own updates (HasUpdateAvailable is always false), so a newer
version is also looked for in Jellyfin's GitHub releases, once every 12 hours. That request carries
nothing about the server or the key.
"""
from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
from urllib.parse import quote, urlparse

import aiohttp

KEY_RE = re.compile(r"^[A-Za-z0-9]{16,128}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?(/[A-Za-z0-9._~\-/]*)?$|^https?://\[[0-9A-Fa-f:]+\](:\d{1,5})?(/[A-Za-z0-9._~\-/]*)?$")
RELEASES = "https://api.github.com/repos/jellyfin/jellyfin/releases/latest"
RELEASE_EVERY = 12 * 3600
MAX_BYTES = 2 * 1024 * 1024
FAILED = ("Failed", "Aborted")


class JellyfinError(Exception):
    """Jellyfin couldn't be read. login is True when it turned the API key down."""

    def __init__(self, msg: str, login: bool = False):
        super().__init__(msg)
        self.login = login


def clean_url(url: str) -> str:
    """'http://jf.example.local:8096/' -> 'http://jf.example.local:8096'. Raises ValueError."""
    url = str(url or "").strip().rstrip("/")
    if not URL_RE.match(url):
        raise ValueError("The Jellyfin address must be like http://192.168.1.20:8096 (no query or user name)")
    u = urlparse(url)
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError("The Jellyfin address has a port out of range")
    return url


def default_url(host: str) -> str:
    return f"http://[{host}]:8096" if ":" in host and not host.startswith("[") else f"http://{host}:8096"


def same_server(a: str, b: str) -> bool:
    """Whether two addresses are on the same machine (the same name or IP address), for keeping its key: a
    key goes only to the machine it was given for, but http or https, and the port, can change."""
    try:
        ha, hb = (urlparse(a).hostname or "").lower(), (urlparse(b).hostname or "").lower()
        return bool(ha) and ha == hb
    except ValueError:
        return False


def _auth(key: str) -> dict:
    return {"Authorization": f'MediaBrowser Client="Rollcall", Device="Home Assistant", DeviceId="rollcall", '
                             f'Version="1", Token="{quote(key, safe="")}"',
            "Accept": "application/json", "User-Agent": "Rollcall"}


async def _get(session: aiohttp.ClientSession, url: str, headers: dict, tls, timeout: float, as_json: bool = True):
    try:
        async with session.get(url, headers=headers, ssl=tls, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status in (401, 403):
                raise JellyfinError("the API key was refused (create one under Dashboard, API Keys)", login=True)
            if 300 <= r.status < 400:
                raise JellyfinError(f"redirected (HTTP {r.status}); set the address it redirects to")
            if r.status >= 400:
                raise JellyfinError(f"HTTP {r.status} from {urlparse(url).path}")
            # The whole answer: one read only gives what has arrived so far, and an answer that came in
            # more than one piece was read half, so it "wasn't JSON"
            body = bytearray()
            async for part in r.content.iter_chunked(65536):
                body += part
                if len(body) > MAX_BYTES:
                    raise JellyfinError("answer too large")
            body = bytes(body)
            if not as_json:
                return body.decode("utf-8", "replace").strip()
            try:
                return json.loads(body)
            except ValueError:
                raise JellyfinError(f"not Jellyfin? {urlparse(url).path} didn't answer with JSON") from None
    except asyncio.TimeoutError:
        raise JellyfinError("no answer (timed out)") from None
    except aiohttp.ClientConnectorError as err:
        raise JellyfinError((getattr(err, "strerror", None) or "can't connect").lower()) from None
    except aiohttp.ClientError as err:
        raise JellyfinError(f"connection failed ({type(err).__name__})") from None


async def poll(base: str, key: str, tls: ssl.SSLContext | None, timeout: float = 15.0) -> dict:
    """Read the server. Raises JellyfinError if it can't be reached or turns the key down."""
    t0 = time.monotonic()
    async with aiohttp.ClientSession() as session:
        health = await _get(session, base + "/health", {"User-Agent": "Rollcall"}, tls, timeout, as_json=False)
        ms = round((time.monotonic() - t0) * 1000, 1)
        h = _auth(key)
        info = await _get(session, base + "/System/Info", h, tls, timeout)
        if not isinstance(info, dict):
            raise JellyfinError("not Jellyfin? /System/Info had no server details")
        try:
            tasks = await _get(session, base + "/ScheduledTasks?isHidden=false", h, tls, timeout)
        except JellyfinError as err:
            if err.login:  # a key without admin rights can read System/Info but not tasks
                raise JellyfinError("the API key can't read scheduled tasks (use a key made under Dashboard, API Keys)", login=True) from None
            tasks = None
        try:
            sessions = await _get(session, base + "/Sessions?activeWithinSeconds=960", h, tls, timeout)
        except JellyfinError:
            sessions = None
        extra = {}
        for k, path in (("plugins", "/Plugins"), ("counts", "/Items/Counts")):
            try:
                extra[k] = await _get(session, base + path, h, tls, timeout)
            except JellyfinError:
                extra[k] = None
    return parse(health, info, tasks, sessions, ms, **extra)


TICKS = 10_000_000  # Jellyfin's ticks per second
COUNTS = (("MovieCount", "Movies"), ("SeriesCount", "Series"), ("EpisodeCount", "Episodes"), ("AlbumCount", "Albums"),
          ("SongCount", "Songs"), ("MusicVideoCount", "Music videos"), ("BookCount", "Books"), ("BoxSetCount", "Collections"))
PLUGIN_STATUS = {"Restart": "restart needed", "Malfunctioned": "failed to load", "NotSupported": "not supported by this version",
                 "Superceded": "replaced by a newer version", "Deleted": "removed, until a restart"}


def _words(reason: str) -> str:
    """'VideoCodecNotSupported' -> 'video codec not supported'"""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(reason or "")).lower().strip()[:60]


def _title(item: dict) -> str:
    """What's playing, as people would say it: a series' episode, a film and its year, a song and artist."""
    name = str(item.get("Name") or "")
    if item.get("Type") == "Episode" and item.get("SeriesName"):
        se = (f" S{int(item['ParentIndexNumber']):02d}E{int(item['IndexNumber']):02d}"
              if isinstance(item.get("ParentIndexNumber"), int) and isinstance(item.get("IndexNumber"), int) else "")
        return f"{item['SeriesName']}{se} · {name}"[:160]
    if item.get("Type") == "Audio" and item.get("Artists"):
        return f"{', '.join(str(a) for a in item['Artists'][:2])} – {name}"[:160]
    if item.get("ProductionYear") and item.get("Type") == "Movie":
        return f"{name} ({item['ProductionYear']})"[:160]
    return name[:160]


def _stream(s: dict) -> dict:
    item, ps, tr = s.get("NowPlayingItem") or {}, s.get("PlayState") or {}, s.get("TranscodingInfo") or {}
    run, pos = item.get("RunTimeTicks"), ps.get("PositionTicks")
    method = str(ps.get("PlayMethod") or "")
    out = {"user": str(s.get("UserName") or "")[:60], "client": str(s.get("Client") or "")[:60],
           "device": str(s.get("DeviceName") or "")[:60], "title": _title(item), "type": str(item.get("Type") or "")[:20],
           "method": {"DirectPlay": "Direct play", "DirectStream": "Direct stream", "Transcode": "Transcoding"}.get(method, method[:20]),
           "paused": ps.get("IsPaused") is True,
           "position_s": int(pos / TICKS) if isinstance(pos, (int, float)) and pos >= 0 else None,
           "runtime_s": int(run / TICKS) if isinstance(run, (int, float)) and run > 0 else None, "reasons": [], "transcode": ""}
    if method == "Transcode":
        out["reasons"] = [_words(r) for r in (tr.get("TranscodeReasons") or []) if r][:6]
        parts = [("video " + ("copied" if tr.get("IsVideoDirect") else f"to {tr.get('VideoCodec') or '?'}")) if item.get("Type") != "Audio" else "",
                 "audio " + ("copied" if tr.get("IsAudioDirect") else f"to {tr.get('AudioCodec') or '?'}"),
                 f"{tr['Height']}p" if isinstance(tr.get("Height"), int) and tr["Height"] else "",
                 f"{tr['Bitrate'] / 1e6:.1f} Mbit/s" if isinstance(tr.get("Bitrate"), (int, float)) and tr["Bitrate"] else ""]
        out["transcode"] = ", ".join(p for p in parts if p)[:120]
    return out


def parse(health: str, info: dict, tasks, sessions, ms: float | None = None, plugins=None, counts=None) -> dict:
    """The parts Rollcall uses, from Jellyfin's answers."""
    failed = []
    for t in tasks if isinstance(tasks, list) else []:
        if not isinstance(t, dict) or t.get("IsHidden"):
            continue
        res = t.get("LastExecutionResult") or {}
        if res.get("Status") in FAILED:
            failed.append({"name": str(t.get("Name") or "Task")[:80], "status": res.get("Status"),
                           "ended": str(res.get("EndTimeUtc") or "")[:40], "error": str(res.get("ErrorMessage") or "")[:200]})
    streams = transcodes = 0
    playing, users = [], set()
    for s in sessions if isinstance(sessions, list) else []:
        if not isinstance(s, dict):
            continue
        if s.get("UserName"):
            users.add(str(s["UserName"]))
        if s.get("NowPlayingItem"):
            streams += 1
            if ((s.get("PlayState") or {}).get("PlayMethod") or "") == "Transcode":
                transcodes += 1
            if len(playing) < 20:
                playing.append(_stream(s))
    attention = [{"name": str(p.get("Name") or "Plugin")[:80], "version": str(p.get("Version") or "")[:30],
                  "status": str(p.get("Status") or "")[:20], "why": PLUGIN_STATUS.get(str(p.get("Status") or ""), "")}
                 for p in (plugins if isinstance(plugins, list) else []) if isinstance(p, dict)
                 and p.get("Status") not in (None, "", "Active", "Disabled")][:20]
    lib = [{"name": label, "count": int(counts[k])} for k, label in COUNTS
           if isinstance(counts, dict) and isinstance(counts.get(k), int) and counts[k] > 0]
    return {"health": str(health or "")[:40], "version": str(info.get("Version") or "")[:40],
            "name": str(info.get("ServerName") or "")[:100], "restart": bool(info.get("HasPendingRestart")),
            "update": bool(info.get("HasUpdateAvailable")), "shutting_down": bool(info.get("IsShuttingDown")),
            "failed_tasks": failed, "tasks_read": isinstance(tasks, list),
            "streams": streams if isinstance(sessions, list) else None, "transcodes": transcodes, "ms": ms,
            "playing": playing, "users": len(users) if isinstance(sessions, list) else None,
            "plugins": attention, "plugins_read": isinstance(plugins, list), "library": lib}


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4])


def newer(latest: str | None, current: str) -> bool:
    return bool(latest and current and _ver(latest) > _ver(current))


def evaluate(d: dict, latest: str | None = None) -> tuple[bool, float | None, str, str | None]:
    """(ok, latency, detail, level) for the check: red while it's not healthy; amber (never an alert) for
    a pending restart, an update, a failed scheduled task or a degraded server; else green."""
    bits = [f"Jellyfin {d['version']}" if d.get("version") else "Jellyfin"]
    if d.get("streams") is not None:
        n, t = d["streams"], d.get("transcodes") or 0
        bits.append(f"{n} stream{'' if n == 1 else 's'}" + (f" ({t} transcoding)" if t else ""))
    health = (d.get("health") or "").lower()
    if d.get("shutting_down"):
        return False, None, "; ".join(bits + ["shutting down"]), None
    if health and health not in ("healthy", "degraded"):
        return False, None, "; ".join(bits + [f"health: {d['health']}"]), None
    warns = []
    if health == "degraded":
        warns.append("health: Degraded")
    if d.get("restart"):
        why = [f"{p['name']}: {p['why'] or p['status']}" for p in d.get("plugins") or []][:2]
        warns.append("restart pending" + (f" ({'; '.join(why)})" if why else ""))
    if d.get("update") or newer(latest, d.get("version") or ""):
        warns.append(f"update available{f' ({latest})' if latest and newer(latest, d.get('version') or '') else ''}")
    failed = d.get("failed_tasks") or []
    if failed:
        names = ", ".join(t["name"] for t in failed[:3]) + (f" +{len(failed) - 3} more" if len(failed) > 3 else "")
        warns.append(f"failed task{'' if len(failed) == 1 else 's'}: {names}")
    if warns:
        return False, None, "; ".join(bits + warns), "warn"
    return True, d.get("ms"), "; ".join(bits), None


_latest: dict = {"at": 0.0, "version": None}


async def latest_release(now: float | None = None) -> str | None:
    """Jellyfin's newest stable version from GitHub, cached for RELEASE_EVERY seconds (None if unknown)."""
    now = now or time.time()
    if now - _latest["at"] < RELEASE_EVERY:
        return _latest["version"]
    _latest["at"] = now - RELEASE_EVERY + 3600  # if this fails, try again in an hour
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(RELEASES, headers={"Accept": "application/vnd.github+json", "User-Agent": "Rollcall"},
                                   timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    j = await r.json(content_type=None)
                    tag = str((j or {}).get("tag_name") or "").lstrip("vV")
                    if re.fullmatch(r"\d+(\.\d+){1,3}", tag) and not (j or {}).get("prerelease"):
                        _latest["version"] = tag
                        _latest["at"] = now
    except Exception:  # noqa: BLE001 - offline or rate-limited: try again next time
        pass
    return _latest["version"]
