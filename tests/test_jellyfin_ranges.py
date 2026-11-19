"""The Jellyfin check (against a stand-in Jellyfin server) and named IP ranges.

Run from the repository root:  python3 -m pytest tests/test_jellyfin_ranges.py
"""
import asyncio
import sys
from pathlib import Path

import pytest
from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import iprange  # noqa: E402
import jellyfin as jf  # noqa: E402
import main  # noqa: E402
import settingslib  # noqa: E402

KEY = "0123456789abcdef0123456789abcdef"


def fake_jellyfin(state):
    """A stand-in for the parts of Jellyfin's API the check reads."""
    seen = state.setdefault("seen", [])

    def authed(req):
        seen.append((req.path, req.headers.get("Authorization", "")))
        return req.headers.get("Authorization", "").endswith(f'Token="{state.get("key", KEY)}"')

    async def health(req):
        seen.append((req.path, req.headers.get("Authorization", "")))
        return web.Response(text=state.get("health", "Healthy"))

    async def info(req):
        if not authed(req):
            return web.Response(status=401)
        return web.json_response({"ServerName": "media", "Version": state.get("version", "10.10.7"),
                                  "HasPendingRestart": state.get("restart", False), "HasUpdateAvailable": False})

    async def tasks(req):
        if not authed(req):
            return web.Response(status=401)
        return web.json_response([
            {"Name": "Scan Media Library", "State": "Idle", "IsHidden": False,
             "LastExecutionResult": {"Status": state.get("scan", "Completed"), "EndTimeUtc": "2026-11-18T03:00:00Z",
                                     "ErrorMessage": "Access to the path is denied"}},
            {"Name": "Hidden one", "IsHidden": True, "LastExecutionResult": {"Status": "Failed"}},
            {"Name": "Clean Cache Directory", "State": "Idle", "LastExecutionResult": {"Status": "Completed"}},
        ])

    async def sessions(req):
        if not authed(req):
            return web.Response(status=401)
        return web.json_response([
            {"NowPlayingItem": {"Name": "A film"}, "PlayState": {"PlayMethod": "Transcode"}},
            {"NowPlayingItem": {"Name": "An episode"}, "PlayState": {"PlayMethod": "DirectPlay"}},
            {"Client": "Idle browser"},
        ][:state.get("sessions", 3)])

    async def moved(req):
        seen.append((req.path, req.headers.get("Authorization", "")))
        raise web.HTTPFound("http://elsewhere.example.local/System/Info")

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_get("/System/Info", info)
    app.router.add_get("/ScheduledTasks", tasks)
    app.router.add_get("/Sessions", sessions)
    app.router.add_get("/moved/health", health)
    app.router.add_get("/moved/System/Info", moved)
    return app


def with_server(state, fn):
    async def go():
        runner = web.AppRunner(fake_jellyfin(state))
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            return await fn(f"http://127.0.0.1:{port}")
        finally:
            await runner.cleanup()
    return asyncio.run(go())


def test_healthy_server_reads_version_streams_and_tasks():
    st = {}
    d = with_server(st, lambda base: jf.poll(base, KEY, None, timeout=5))
    assert d["version"] == "10.10.7" and d["name"] == "media" and d["streams"] == 2 and d["transcodes"] == 1
    assert d["failed_tasks"] == [] and d["tasks_read"]
    ok, _ms, detail, level = jf.evaluate(d, latest="10.10.7")
    assert ok and level is None and detail == "Jellyfin 10.10.7; 2 streams (1 transcoding)"
    # The key goes in the Authorization header, and not to /health, which doesn't need it.
    auth = dict(st["seen"])
    assert auth["/health"] == "" and auth["/System/Info"].startswith("MediaBrowser ") and f'Token="{KEY}"' in auth["/System/Info"]


def test_failed_task_restart_and_update_are_amber_not_alerts():
    d = with_server({"scan": "Failed", "restart": True}, lambda base: jf.poll(base, KEY, None, timeout=5))
    assert d["failed_tasks"][0]["name"] == "Scan Media Library" and len(d["failed_tasks"]) == 1   # hidden ones skipped
    ok, _ms, detail, level = jf.evaluate(d, latest="10.11.2")
    assert not ok and level == "warn"
    assert "restart pending" in detail and "update available (10.11.2)" in detail and "failed task: Scan Media Library" in detail
    assert jf.evaluate({**d, "failed_tasks": [], "restart": False}, latest="10.9.0")[0]  # older "latest": no update


def test_unhealthy_or_unreachable_is_red_and_a_refused_key_is_amber():
    d = with_server({"health": "Unhealthy"}, lambda base: jf.poll(base, KEY, None, timeout=5))
    ok, _ms, detail, *level = jf.evaluate(d)
    assert not ok and level == [None] and "health: Unhealthy" in detail
    with pytest.raises(jf.JellyfinError) as e:
        with_server({"key": "somethingelse0000"}, lambda base: jf.poll(base, KEY, None, timeout=5))
    assert e.value.login
    with pytest.raises(jf.JellyfinError) as e:
        asyncio.run(jf.poll("http://127.0.0.1:9", KEY, None, timeout=2))
    assert not e.value.login


def test_key_is_never_sent_on_through_a_redirect():
    st = {}
    with pytest.raises(jf.JellyfinError, match="redirected"):
        with_server(st, lambda base: jf.poll(base + "/moved", KEY, None, timeout=5))
    assert [p for p, _ in st["seen"]] == ["/moved/health", "/moved/System/Info"]   # nothing followed


def test_addresses_and_keys_are_checked():
    assert jf.clean_url("http://192.168.1.20:8096/") == "http://192.168.1.20:8096"
    assert jf.clean_url("https://media.example.local/jellyfin") == "https://media.example.local/jellyfin"
    for bad in ("ftp://x", "http://user:pw@host", "http://host/?api_key=1", "media.example.local"):
        with pytest.raises(ValueError):
            jf.clean_url(bad)
    assert jf.default_url("192.168.1.20") == "http://192.168.1.20:8096"
    assert jf.same_server("http://192.168.1.20:8096", "http://192.168.1.20:8096/jellyfin")
    assert not jf.same_server("http://192.168.1.20:8096", "http://192.168.1.21:8096")
    entry = main.validate_entry({"name": "Media", "host": "192.168.1.20", "checks": ["jellyfin-api"],
                                 "jellyfin_url": "", "jellyfin_key": KEY})
    assert entry["checks"] == ["jellyfin-api"] and entry["jellyfin_key"] == KEY and entry["jellyfin_url"] == ""
    assert main.parse_check("jellyfin-api")[0]["kind"] == "jellyfin"
    with pytest.raises(ValueError):
        main.validate_entry({"name": "Media", "host": "192.168.1.20", "jellyfin_url": "", "jellyfin_key": "x y"})


def test_key_stays_with_its_server(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "HOSTS_PATH", tmp_path / "hosts.json")
    m = main.Monitor.__new__(main.Monitor)
    m.hosts = {}
    m._save_hosts = lambda: None
    m.publish_soon = lambda h: None

    async def dismiss(*_a):
        pass
    m.dismiss = dismiss
    h = main.Host(key="media", name="Media", host="192.168.1.20", checks=["jellyfin-api"], jf_key=KEY)
    h.services = main.Monitor._build_services(h.name, h.checks)
    base = {"name": "Media", "host": "192.168.1.20", "checks": ["jellyfin-api"]}
    asyncio.run(m.update_host(h, {**base, "jellyfin_url": "http://192.168.1.20:8096/"}))
    assert h.jf_key == KEY                                  # same server: kept
    asyncio.run(m.update_host(h, {**base, "host": "192.168.1.30"}))
    assert h.jf_key == KEY                                  # its own address set, so moving the device doesn't matter
    asyncio.run(m.update_host(h, {**base, "jellyfin_url": "http://192.168.1.99:8096"}))
    assert h.jf_key == ""                                   # another server: the key isn't sent there


# --- named IP ranges --------------------------------------------------------------------------

def test_ranges_name_addresses_smallest_first():
    r = iprange.Ranges(["Network=10.0.0.0/16", "Printers=10.0.5.0/24", "IoT=192.168.20.10-200, 192.168.21.*", "junk"])
    assert r.name_of("10.0.5.9") == "Printers" and r.name_of("10.0.200.1") == "Network"
    assert r.name_of("192.168.20.10") == "IoT" and r.name_of("192.168.20.201") is None
    assert r.name_of("192.168.21.77") == "IoT" and r.name_of(None) is None and r.name_of("server.example.local") is None


def test_ranges_setting_is_checked():
    out, err = settingslib.clean({"ip_ranges": ["Servers = 10.0.1.0/24", " Workstations=10.0.2.10-250 "]})
    assert not err and out["ip_ranges"] == ["Servers=10.0.1.0/24", "Workstations=10.0.2.10-250"]
    for bad in (["10.0.1.0/24"], ["Servers="], ["Servers=10.0.1.300"], ["Servers=10.*.1"]):
        _out, err = settingslib.clean({"ip_ranges": bad})
        assert "ip_ranges" in err, bad
