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


def test_account_lists_dishes_and_reads_one(com):
    a, dishes = asyncio.run(_acct(lambda a, s: a.dishes(s)))
    assert dishes == [{"id": TARGET, "name": "KIT000000000 · Garage"}]
    a, d = asyncio.run(_acct(lambda a, s: a.status(s, TARGET)))
    assert sl.evaluate(d)[0] is True and d["latency_ms"] == 31.5
    assert a.changed and "XSRF-TOKEN=xsrf-rotated" in a.cookie and f"Starlink.Com.Sso={com.SSO}" in a.cookie
    # only starlink.com hosts were sent anything
    assert {path.split("/")[1] for _m, path, _h in com.seen} <= set(sl.STARLINK_HOSTS)


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
        assert com.SSO not in everything and "xsrf" not in everything     # the cookie is never shown again

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
