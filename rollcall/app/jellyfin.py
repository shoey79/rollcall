"""Jellyfin: the server's health, read by the add-on with a Jellyfin API key.

Endpoints (Jellyfin's REST API, as documented at api.jellyfin.org; 10.9 to 10.11):
  GET /health                  "Healthy", "Degraded" or "Unhealthy" as plain text; no key needed
  GET /System/Info             Version, ServerName, HasPendingRestart, HasUpdateAvailable
  GET /ScheduledTasks          each task's Name, State, IsHidden and LastExecutionResult (Status:
                               Completed, Failed, Cancelled or Aborted; EndTimeUtc; ErrorMessage)
  GET /Sessions                each client session; one with a NowPlayingItem is a stream, and
                               PlayState.PlayMethod "Transcode" means the server is transcoding it

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
    """Whether two addresses are the same Jellyfin server (scheme, host and port), for keeping its key."""
    try:
        ua, ub = urlparse(a), urlparse(b)
        pa = ua.port or (443 if ua.scheme == "https" else 80)
        pb = ub.port or (443 if ub.scheme == "https" else 80)
        return (ua.scheme, (ua.hostname or "").lower(), pa) == (ub.scheme, (ub.hostname or "").lower(), pb)
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
            body = await r.content.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise JellyfinError("answer too large")
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
    return parse(health, info, tasks, sessions, ms)


def parse(health: str, info: dict, tasks, sessions, ms: float | None = None) -> dict:
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
    for s in sessions if isinstance(sessions, list) else []:
        if isinstance(s, dict) and s.get("NowPlayingItem"):
            streams += 1
            if ((s.get("PlayState") or {}).get("PlayMethod") or "") == "Transcode":
                transcodes += 1
    return {"health": str(health or "")[:40], "version": str(info.get("Version") or "")[:40],
            "name": str(info.get("ServerName") or "")[:100], "restart": bool(info.get("HasPendingRestart")),
            "update": bool(info.get("HasUpdateAvailable")), "shutting_down": bool(info.get("IsShuttingDown")),
            "failed_tasks": failed, "tasks_read": isinstance(tasks, list),
            "streams": streams if isinstance(sessions, list) else None, "transcodes": transcodes, "ms": ms}


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
        warns.append("restart pending")
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
