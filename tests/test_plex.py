"""The Plex check (plex.py): what's playing, by whom, and the server's state, read with a Plex token.

A stand-in Plex answers in Plex's XML (made-up users and titles): an episode being transcoded, a film paused
and played directly, a song; an update waiting; a library scan running.

Run from the repository root:  python3 -m pytest tests/test_plex.py
"""
import asyncio
import sys
from pathlib import Path

import pytest
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import plex as px  # noqa: E402

TOKEN = "AbCdEf-123_xyz7890qwe"

ROOT = '<MediaContainer friendlyName="Media" version="1.41.2.9200-c6bbc1b53" transcoderActiveVideoSessions="1"/>'
IDENTITY = '<MediaContainer machineIdentifier="abc" version="1.41.2.9200-c6bbc1b53"/>'
SESSIONS = """<MediaContainer size="3">
 <Video type="episode" title="The Pilot" grandparentTitle="Example Show" parentIndex="1" index="2" duration="2700000" viewOffset="900000">
  <Media><Part decision="transcode"/></Media>
  <User title="alice"/><Player title="Living room TV" product="Plex for Android (TV)" state="playing"/>
  <Session location="lan"/>
  <TranscodeSession videoDecision="transcode" audioDecision="copy" sourceVideoCodec="hevc" videoCodec="h264" height="1080" transcodeHwRequested="1"/>
 </Video>
 <Video type="movie" title="A Film" year="2019" duration="6000000" viewOffset="60000">
  <Media><Part decision="directplay"/></Media>
  <User title="bob"/><Player title="Phone" product="Plex for iOS" state="paused"/><Session location="wan"/>
 </Video>
 <Track type="track" title="A Song" grandparentTitle="An Artist" duration="200000" viewOffset="30000">
  <Media><Part decision="copy"/></Media>
  <User title="alice"/><Player title="Kitchen" product="Plexamp" state="playing"/>
 </Track>
</MediaContainer>"""
UPDATER = '<MediaContainer canInstall="1"><Release version="1.41.3.9314-a0bfb8370" state="notify"/></MediaContainer>'
ACTIVITIES = '<MediaContainer><Activity type="library.update.section" title="Scanning Films" subtitle="Updating metadata" progress="42"/></MediaContainer>'
SECTIONS = '<MediaContainer><Directory key="1" type="movie" title="Films"/><Directory key="2" type="show" title="TV"/></MediaContainer>'


def fake_plex(state):
    def xml(text):
        return web.Response(text=text, content_type="application/xml")

    def need_token(text):
        async def h(req):
            state.setdefault("tokens", []).append(req.headers.get("X-Plex-Token"))
            if req.headers.get("X-Plex-Token") != TOKEN:
                return web.Response(status=401)
            return xml(text)
        return h

    async def section(req):
        if req.headers.get("X-Plex-Token") != TOKEN:
            return web.Response(status=401)
        key, ep = req.match_info["key"], req.query.get("type") == "4"
        return xml(f'<MediaContainer size="0" totalSize="{ {"1": 412, "2": 38}[key] if not ep else 2210}"/>')

    async def identity(req):
        state.setdefault("tokens", []).append(req.headers.get("X-Plex-Token"))
        return xml(IDENTITY)

    app = web.Application()
    app.router.add_get("/identity", identity)
    app.router.add_get("/", need_token(ROOT))
    app.router.add_get("/status/sessions", need_token(state.get("sessions", SESSIONS)))
    app.router.add_get("/updater/status", need_token(state.get("updater", UPDATER)))
    app.router.add_get("/activities", need_token(ACTIVITIES))
    app.router.add_get("/library/sections", need_token(SECTIONS))
    app.router.add_get("/library/sections/{key}/all", section)
    return app


def with_server(state, fn):
    async def go():
        runner = web.AppRunner(fake_plex(state))
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            return await fn(f"http://127.0.0.1:{port}")
        finally:
            await runner.cleanup()
    return asyncio.run(go())


def test_whats_playing_and_by_whom():
    st = {}
    d = with_server(st, lambda base: px.poll(base, TOKEN, None, timeout=5))
    assert d["name"] == "Media" and d["streams"] == 3 and d["transcodes"] == 1 and d["users"] == 2
    ep, film, song = d["playing"]
    assert ep == {"user": "alice", "client": "Plex for Android (TV)", "device": "Living room TV", "title": "Example Show S01E02 · The Pilot",
                  "type": "episode", "method": "Transcoding", "paused": False, "position_s": 900, "runtime_s": 2700, "remote": False,
                  "transcode": "video hevc to h264, audio copied, 1080p, hardware", "reasons": []}
    assert (film["title"], film["method"], film["paused"], film["remote"]) == ("A Film (2019)", "Direct play", True, True)
    assert (song["title"], song["method"]) == ("An Artist – A Song", "Direct stream")
    assert d["update"] == "1.41.3.9314-a0bfb8370"
    assert d["activities"] == [{"title": "Scanning Films", "subtitle": "Updating metadata", "progress": 42}]
    assert d["library"] == [{"name": "Films", "type": "movie", "count": 412, "episodes": None},
                            {"name": "TV", "type": "show", "count": 38, "episodes": 2210}]
    assert st["tokens"][0] is None and set(st["tokens"][1:]) == {TOKEN}       # /identity is asked without the token
    ok, _, detail, level = px.evaluate(d)
    assert not ok and level == "warn" and detail == "Plex 1.41.2.9200; 3 streams (1 transcoding); update available (1.41.3.9314)"


def test_nothing_playing_and_up_to_date_is_green():
    d = with_server({"sessions": '<MediaContainer size="0"/>', "updater": '<MediaContainer canInstall="0"/>'},
                    lambda base: px.poll(base, TOKEN, None, timeout=5))
    assert px.evaluate(d)[0] and px.evaluate(d)[2] == "Plex 1.41.2.9200; 0 streams" and d["playing"] == []


def test_a_wrong_token_or_a_web_page_says_so():
    with pytest.raises(px.PlexError) as e:
        with_server({}, lambda base: px.poll(base, "WrongToken123", None, timeout=5))
    assert e.value.login
    with pytest.raises(px.PlexError) as e:
        asyncio.run(px.poll("http://127.0.0.1:9", TOKEN, None, timeout=2))
    assert not e.value.login


def test_address_and_token_rules():
    assert px.clean_url("http://plex.example.local:32400/") == "http://plex.example.local:32400"
    assert px.default_url("192.168.1.20") == "http://192.168.1.20:32400"
    with pytest.raises(ValueError):
        px.clean_url("http://user@plex.example.local:32400")
    assert px.TOKEN_RE.match(TOKEN) and not px.TOKEN_RE.match("has spaces in it")
