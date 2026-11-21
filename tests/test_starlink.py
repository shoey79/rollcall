"""Starlink (starlink.py): the dish's status from its local API (gRPC over HTTP/2) or through the Starlink account
(starlink.com's gRPC-web), checked against stand-ins built on the real grpcio and protobuf libraries
(starlink_fake.py), and end to end through the real add-on.

Run from the repository root:  python3 -m pytest tests/test_starlink.py
"""
import asyncio
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "rollcall" / "app"), str(HERE)]

grpc = pytest.importorskip("grpc", reason="needs grpcio for the stand-in dish")
pytest.importorskip("google.protobuf", reason="needs protobuf for the stand-in dish")
aiohttp = pytest.importorskip("aiohttp")

import starlink as sl  # noqa: E402
import starlink_fake as fk  # noqa: E402

TARGET = "ut00000000-11111111-22222222"


@pytest.fixture
def dish():
    d = fk.FakeDish()
    yield d
    d.stop()


@pytest.fixture
def com(monkeypatch):
    c = fk.FakeStarlinkCom()
    monkeypatch.setattr(sl, "TEST_BASE", c.base)
    return c


def read(addr, timeout=10):
    return asyncio.run(sl.read_local(addr, timeout))


# ---- the dish's local API --------------------------------------------------------------------------------------
def test_reads_a_healthy_dish_and_only_ever_asks_for_its_status(dish):
    d = read(dish.addr)
    assert d["software"] == "2026.11.01.mr12345" and d["hardware"] == "rev4_prod1" and d["uptime_s"] == 86400 * 3 + 3600
    assert d["latency_ms"] == 31.5 and d["down_bps"] == 48250000 and d["up_bps"] == 5100000 and d["drop_rate"] == 0.002
    assert d["obstructed_time"] == 0.0005 and d["eth_mbps"] == 1000 and d["outage"] is None and d["alerts"] == []
    ok, ms, text, level = sl.evaluate(d)
    assert ok and ms == 31.5 and level is None
    assert text == "Starlink online, 31.5 ms, 0.2% drops, ↓ 48.2 Mb/s ↑ 5.1 Mb/s"
    assert len(dish.requests) == 1 and dish.requests[0].HasField("get_status") and not dish.requests[0].HasField("reboot")


@pytest.mark.parametrize("change, ok, level, words", [
    ({"outage": {"cause": 6, "start_timestamp_ns": 1, "duration_ns": 45_000_000_000}}, False, None, "Starlink offline: obstructed for 45 s"),
    ({"outage": {"cause": 5}}, False, None, "Starlink offline: no satellites"),
    ({"alerts": {"thermal_shutdown": True}}, False, None, "too hot, shut down"),
    ({"disablement_code": 2}, False, None, "Starlink service disabled: no active account"),
    ({"disablement_code": 1}, True, None, "Starlink online"),                       # OKAY
    ({"alerts": {"motors_stuck": True}}, False, "warn", "motors stuck"),
    ({"alerts": {"mast_not_near_vertical": True}}, False, "warn", "mast not vertical"),
    ({"alerts": {"thermal_throttle": True}}, False, "warn", "too hot, slowed down"),
    ({"alerts": {"slow_ethernet_speeds": True}}, False, "warn", "slow Ethernet link"),
    ({"alerts": {"is_heating": True}}, True, None, "Starlink online"),            # melting snow: shown, not amber
    ({"obstruction_stats": {"time_obstructed": 0.034, "fraction_obstructed": 0.02}}, False, "warn", "obstructed 3.4% of the time"),
    ({"stow_requested": True}, False, "warn", "stowed"),
])
def test_what_the_dish_says_decides_the_colour(dish, change, ok, level, words):
    dish.status = {**fk.healthy(), **change}
    got = sl.evaluate(read(dish.addr))
    assert got[0] is ok and got[3] == level and words in got[2], got


def test_zeros_the_dish_leaves_out_count_as_zero(dish):
    """proto3 omits 0: a clear sky and no dropped pings must still show as 0, not as unknown (seen on a Mini)."""
    dish.status = {**fk.healthy(), "pop_ping_drop_rate": 0.0, "downlink_throughput_bps": 0.0, "uplink_throughput_bps": 0.0,
                   "obstruction_stats": {}}
    d = read(dish.addr)
    assert (d["drop_rate"], d["down_bps"], d["up_bps"], d["obstructed_time"], d["obstructed_fraction"]) == (0, 0, 0, 0, 0)
    assert sl.evaluate(d)[2] == "Starlink online, 31.5 ms, 0.0% drops, ↓ 0.0 Mb/s ↑ 0.0 Mb/s"


def test_update_and_restart_details(dish):
    dish.status = {**fk.healthy(), "software_update_state": 6, "swupdate_reboot_ready": True, "reboot_reason": 3}
    d = read(dish.addr)
    assert d["update"] == "update installed, waiting to restart" and d["update_ready"] and d["reboot_reason"] == "software update"
    assert sl.evaluate(d)[0] is True       # the dish restarts itself for updates: nothing to do


def test_an_answer_without_a_status_is_an_error(dish):
    dish.status, dish.error = None, "made-up failure"
    with pytest.raises(sl.StarlinkError, match="without its status: made-up failure"):
        read(dish.addr)


def test_nothing_listening_and_something_else_listening():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(sl.StarlinkError, match="couldn't reach the dish"):
        read(f"127.0.0.1:{port}", 3)
    # Something that isn't a dish (a web server): an error, not a hang
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def answer():
        c, _ = srv.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        c.close()
    threading.Thread(target=answer, daemon=True).start()
    t0 = time.monotonic()
    with pytest.raises(sl.StarlinkError):
        read(f"127.0.0.1:{srv.getsockname()[1]}", 5)
    assert time.monotonic() - t0 < 5
    srv.close()


def test_a_silent_port_times_out():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    with pytest.raises(sl.StarlinkError, match="no answer from the dish"):
        read(f"127.0.0.1:{srv.getsockname()[1]}", 1.5)
    srv.close()


def test_dish_address():
    assert sl.clean_addr("192.168.100.1") == "192.168.100.1:9200"
    assert sl.clean_addr("192.168.100.1:9200") == "192.168.100.1:9200"
    assert sl.clean_addr("http://10.0.1.5:9200/") == "10.0.1.5:9200"
    assert sl.clean_addr("dishy.example.local:9201") == "dishy.example.local:9201"
    for bad in ("", "192.168.100.1:99999", "a b", "x;y"):
        with pytest.raises(ValueError):
            sl.clean_addr(bad)


# ---- the Starlink account ----------------------------------------------------------------------------------------
async def _acct(fn, cookie=None):
    a = sl.Account(cookie or fk.FakeStarlinkCom.cookie())
    async with aiohttp.ClientSession() as s:
        return a, await fn(a, s)


# ---- alignment and the obstruction map ---------------------------------------------------------------------------
def test_alignment_is_read_and_close_enough_is_fine(dish):
    d = read(dish.addr)
    assert d["alignment"] == {"tilt": 24.5, "az": 291.6, "el": 65.4, "want_az": 297.0, "want_el": 66.0}
    assert sl.alignment_off(d["alignment"]) == "" and sl.evaluate(d)[0] is True


@pytest.mark.parametrize("al, words", [
    ({"boresight_azimuth_deg": 250.0, "desired_boresight_azimuth_deg": 300.0}, "turn it 50° clockwise"),
    ({"boresight_azimuth_deg": 10.0, "desired_boresight_azimuth_deg": 340.0}, "turn it 30° anticlockwise"),   # across north
    ({"boresight_elevation_deg": 50.0, "desired_boresight_elevation_deg": 66.0}, "tilt it 16° flatter"),
])
def test_a_dish_knocked_out_of_alignment_is_amber(dish, al, words):
    dish.status = {**fk.healthy(), "alignment_stats": {**fk.healthy()["alignment_stats"], **al}}
    ok, _ms, text, level = sl.evaluate(read(dish.addr))
    assert not ok and level == "warn" and "out of alignment: " + words in text


def test_alignment_west_of_north_comes_as_negative_degrees(dish):
    # A dish facing north-west says e.g. -40°, wanting -44°: shown as 320° and 316°, close enough
    dish.status = {**fk.healthy(), "alignment_stats": {"tilt_angle_deg": 25.0, "boresight_azimuth_deg": -40.0,
                   "boresight_elevation_deg": 65.0, "desired_boresight_azimuth_deg": -44.0, "desired_boresight_elevation_deg": 66.0}}
    d = read(dish.addr)
    assert d["alignment"]["az"] == 320.0 and d["alignment"]["want_az"] == 316.0 and sl.evaluate(d)[0] is True


def test_no_alignment_from_the_dish_is_fine(dish):
    dish.status = {k: v for k, v in fk.healthy().items() if k != "alignment_stats"}
    d = read(dish.addr)
    assert "alignment" not in d and sl.evaluate(d)[0] is True


def test_obstruction_map_says_where(dish):
    dish.map = fk.sky(blocked=((30, 75, 0, 30),))         # trees to the north-east, low down
    m = asyncio.run(sl.read_map_local(dish.addr))
    assert (m["rows"], m["cols"], m["frame"], m["max_theta"]) == (123, 123, "earth", 80.0) and len(m["cells"]) == 123 * 123
    assert set(m["cells"]) <= set("-0123456789")
    su = sl.map_summary(m)
    assert su["where"][0] == "north-east" and su["height"] == "low, near the horizon" and 0 < su["blocked_pct"] < 15
    assert 40 < su["seen_pct"] < 70                       # a circle in a square, 80% of it seen
    # Only ever read: the dish was asked for the map, nothing else
    assert all(r.HasField("dish_get_obstruction_map") and not r.HasField("dish_clear_obstruction_map") for r in dish.requests)


def test_obstruction_map_clear_sky_and_overhead(dish):
    dish.map = fk.sky(blocked=())
    su = sl.map_summary(asyncio.run(sl.read_map_local(dish.addr)))
    assert su["blocked_pct"] == 0 and su["where"] == [] and su["height"] is None
    dish.map = fk.sky(blocked=((160, 250, 70, 90),))      # a branch overhead, towards the south-west
    su = sl.map_summary(asyncio.run(sl.read_map_local(dish.addr)))
    assert su["height"] == "high, near overhead"


def test_dish_frame_map_is_turned_by_the_heading(dish):
    dish.map = fk.sky(frame=2, blocked=((30, 75, 0, 30),))  # north-east of the dish's own heading
    m = asyncio.run(sl.read_map_local(dish.addr))
    assert m["frame"] == "dish" and sl.map_summary(m, az_offset=90)["where"][0] in ("south-east", "east")


def test_a_dish_without_the_map_says_so(dish):
    dish.map = None
    with pytest.raises(sl.StarlinkError, match="without its obstruction map: unimplemented"):
        asyncio.run(sl.read_map_local(dish.addr))


def test_account_reads_the_map_too(com):
    com.map = fk.sky(blocked=((180, 220, 10, 40),))
    _a, m = asyncio.run(_acct(lambda a, s: a.obstruction_map(s, TARGET)))
    assert sl.map_summary(m)["where"][0] in ("south", "south-west")


def test_account_lists_dishes_and_reads_one(com):
    a, dishes = asyncio.run(_acct(lambda a, s: a.dishes(s)))
    assert dishes == [{"id": TARGET, "name": "KIT000000000 · Garage"}]
    a, d = asyncio.run(_acct(lambda a, s: a.status(s, TARGET)))
    assert sl.evaluate(d)[0] is True and d["latency_ms"] == 31.5
    assert a.changed and "XSRF-TOKEN=xsrf-rotated" in a.cookie and "Starlink.Com.Sso=sso-made-up-" in a.cookie
    # only starlink.com hosts were sent anything
    assert {path.split("/")[1] for _m, path, _h in com.seen} <= set(sl.STARLINK_HOSTS)


def test_account_stays_signed_in_by_keeping_the_session_alive(com):
    """Issue 15: the sign-in lapsed within minutes. starlink.com keeps a session alive only through its account
    pages, rotating the session cookie there, and soon rejects the browser's short-lived access cookie: Rollcall
    visits those pages at each check, keeps what they set, and drops what they delete."""
    state, cookie = {}, fk.FakeStarlinkCom.cookie()
    com.stale_browser_cookie_revoked()
    for _ in range(12):                                   # an hour of checks, 5 minutes apart
        a = sl.Account(cookie, state)
        a2, d = asyncio.run(_acct(lambda acct, s: acct.status(s, TARGET), cookie))
        assert sl.evaluate(d)[0] is True, a2.trace
        cookie = a2.cookie
        assert "Starlink.Com.Access" not in cookie        # the deleted cookie isn't sent back
        com.clock += 300
        state.clear()                                     # a new token each time, as when it expires
    assert com.rotations >= 12 and "sso-made-up-0001" not in cookie
    assert any("account/home -> 200 sets Starlink.Com.Sso" in t for t in a2.trace)
    assert not any("made-up-0" in t for t in a2.trace)    # the log trace has cookie names, never values


def test_without_keeping_it_alive_the_session_lapses(com):
    """What happened before: the pasted cookie alone stops working once the session's idle time passes."""
    com.clock += fk.FakeStarlinkCom.IDLE + 1
    with pytest.raises(sl.StarlinkError, match="sign-in expired") as e:
        asyncio.run(_acct(lambda a, s: a.status(s, TARGET)))
    assert e.value.login


def test_account_offline_dish_and_expired_sign_in(com):
    com.status = None
    with pytest.raises(sl.StarlinkError, match="device offline") as e:
        asyncio.run(_acct(lambda a, s: a.status(s, TARGET)))
    assert not e.value.login
    com.expired = True
    with pytest.raises(sl.StarlinkError, match="sign-in expired") as e:
        asyncio.run(_acct(lambda a, s: a.status(s, TARGET)))
    assert e.value.login


def test_the_cookie_only_goes_to_starlink(monkeypatch):
    monkeypatch.setattr(sl, "TEST_BASE", "")
    a = sl.Account(fk.FakeStarlinkCom.cookie())
    for url in ("https://evil.example/api", "http://www.starlink.com/api", "https://starlink.com.evil.example/x"):
        with pytest.raises(sl.StarlinkError, match="only|anywhere"):
            asyncio.run(_acct(lambda a, s, u=url: a._request(s, "GET", u)))
    assert sl.clean_cookie("cookie: a=1; Starlink.Com.Sso=x") == "a=1; Starlink.Com.Sso=x"
    with pytest.raises(ValueError):
        sl.clean_cookie("session=abc")


# ---- end to end through the add-on -------------------------------------------------------------------------------
from test_update_signing_e2e import HAVE_ADDON_DEPS, UI, Addon, call  # noqa: E402


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_end_to_end_local_and_account(tmp_path, monkeypatch, dish):
    com = fk.FakeStarlinkCom()
    monkeypatch.setenv("PM_STARLINK_TEST_BASE", com.base)
    addon = Addon(tmp_path / "addon").start()
    try:
        def add(entry):
            st, body = call(addon.ui + "/api/hosts", entry, UI, "POST")
            assert st == 201, body[:300]

        def host(name):
            return next(h for h in addon.api("/api/status")["hosts"] if h["name"] == name)

        def check(name, want="green"):
            """Check now until the Starlink check shows want (a red can take a retry or two to confirm)."""
            for _ in range(8):
                before = host(name).get("last_check") or 0
                addon.api(f"/api/check/{host(name)['key']}", {}, "POST")
                for _ in range(40):
                    h = host(name)
                    if (h.get("last_check") or 0) > before:
                        break
                    time.sleep(0.25)
                s = next((x for x in h["services"] if x["kind"] == "starlink"), None)
                if s and s["status"] == want:
                    return h, s
            raise AssertionError((want, s, h.get("status")))

        # Local: the dish answers on the address given
        add({"name": "Dish", "host": "127.0.0.1", "checks": ["starlink"],
                                 "starlink_source": "local", "starlink_addr": dish.addr})
        h, s = check("Dish")
        assert s["status"] == "green" and "Starlink online" in s["detail"], s
        assert h["starlink"]["latency_ms"] == 31.5 and h["starlink_addr"] == dish.addr

        # The Starlink tab's obstruction map, read when it's opened, and kept for a few minutes
        m = addon.api(f"/api/hosts/{h['key']}/starlink/map")
        assert m["summary"]["where"][0] == "north-east" and m["rows"] == 123
        asked = len(dish.requests)
        assert addon.api(f"/api/hosts/{h['key']}/starlink/map")["read_at"] == m["read_at"] and len(dish.requests) == asked
        addon.api(f"/api/hosts/{h['key']}/starlink/map?fresh=1")
        assert len(dish.requests) == asked + 1
        assert h["starlink"]["alignment"]["want_az"] == 297.0

        dish.status = {**fk.healthy(), "outage": {"cause": 6}}
        h, s = check("Dish", "red")
        assert s["status"] == "red" and "obstructed" in s["detail"]
        dish.status = {**fk.healthy(), "alerts": {"motors_stuck": True}}
        h, s = check("Dish", "amber")
        assert s["status"] == "amber" and "motors stuck" in s["detail"]

        # Account: the dish list, then the dish read through starlink.com
        st, _ = call(addon.ui + "/api/starlink/dishes", {"cookie": "nope=1"}, UI, "POST")
        assert st == 400
        dishes = addon.api("/api/starlink/dishes", {"cookie": fk.FakeStarlinkCom.cookie()}, "POST")["dishes"]
        assert dishes[0]["id"] == TARGET
        add({"name": "Remote dish", "host": "127.0.0.1", "checks": ["starlink"],
                                 "starlink_source": "account", "starlink_cookie": fk.FakeStarlinkCom.cookie(),
                                 "starlink_dish": TARGET, "starlink_dish_name": dishes[0]["name"]})
        h, s = check("Remote dish")
        assert s["status"] == "green" and h["starlink_cookie_set"] is True and h["starlink_dish_name"] == "KIT000000000 · Garage"
        everything = json.dumps(addon.api("/api/status"))
        assert "sso-made-up" not in everything and "xsrf" not in everything     # the cookie is never shown again

        # Editing without pasting it again keeps the cookie; the renewed part was kept too
        addon.api(f"/api/hosts/{h['key']}", {"name": "Remote dish", "host": "127.0.0.1", "checks": ["starlink"],
                                             "starlink_source": "account", "starlink_dish": TARGET,
                                             "starlink_dish_name": "KIT000000000 · Garage"}, "PUT")
        h, s = check("Remote dish")
        assert s["status"] == "green", s
        saved = (tmp_path / "addon").rglob("*.json")
        assert any("xsrf-rotated" in p.read_text(errors="ignore") for p in saved)

        com.expired = True
        h, s = check("Remote dish", "amber")
        assert s["status"] == "amber" and "sign-in expired" in s["detail"]
    finally:
        addon.stop()
