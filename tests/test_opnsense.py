"""OPNsense without an agent (opnsense.py): its API, against a stand-in built from the answers OPNsense documents and
the hass-opnsense integration reads. Judged with the FreeBSD agent's own firewall check.

Run from the repository root:  python3 -m pytest tests/test_opnsense.py
"""
import asyncio
import base64
import sys
from pathlib import Path

import pytest
from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import agents  # noqa: E402
import opnsense  # noqa: E402

KEY, SECRET = "w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt", "XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3"


def answers(down=False, update=False):
    return {
        "/api/diagnostics/system/system_information": {"name": "fw01.example.local", "versions": ["OPNsense 25.7.8-amd64", "FreeBSD 14.3-RELEASE-p5"]},
        "/api/diagnostics/system/system_resources": {"memory": {"total": "8589934592", "total_frmt": "8192 MB", "used": 2147483648, "used_frmt": "2048 MB"}},
        "/api/diagnostics/system/system_time": {"uptime": "3 days 04:05:06", "loadavg": "0.21, 0.18, 0.12", "datetime": "Wed Nov 26 10:00:00 GMT 2026"},
        "/api/diagnostics/firewall/pf_states": {"current": "95123", "limit": "100000"},
        "/api/diagnostics/system/system_temperature": [{"device": "dev.cpu.0.temperature", "type": "cpu", "type_translated": "CPU", "temperature": "48.0"}],
        "/api/routes/gateway/status": {"status": "ok", "items": [
            {"name": "WAN_DHCP", "address": "203.0.113.1", "status": "none", "status_translated": "Online", "loss": "0.0 %", "stddev": "0.4 ms", "delay": "8.2 ms", "monitor": "203.0.113.1"},
            {"name": "WAN2_PPPOE", "address": "198.51.100.1", "status": "down" if down else "delay+loss", "status_translated": "Offline" if down else "Latency, Packetloss",
             "loss": "100.0 %" if down else "12.0 %", "stddev": "~", "delay": "~" if down else "180.5 ms", "monitor": "198.51.100.1"}]},
        "/api/core/firmware/status": {"status": "update" if update else "none", "status_msg": "There are 3 updates available." if update else "Up to date",
                                      "product": {"product_version": "25.7.8", "product_latest": "25.7.9" if update else "25.7.8"}},
        "/api/diagnostics/interface/get_vip_status": {"rows": [{"interface": "lan", "vhid": "1", "status": "MASTER", "mode": "carp", "subnet": "192.168.1.1"},
                                                                {"interface": "wan", "vhid": "", "status": "", "mode": "ipalias", "subnet": "203.0.113.9"}], "total": 2},
        "/api/ipsec/sessions/search_phase1": {"rows": [{"phase1desc": "Site B", "connected": True}, {"phase1desc": "Site C", "connected": False}], "total": 2},
        "/api/openvpn/service/search_sessions": {"rows": [{"type": "server", "description": "Road warriors", "status": "ok", "connected_clients": 3},
                                                           {"type": "client", "description": "To DC", "status": "connected"}]},
    }


async def serve(routes: dict, forbid=(), legacy=False):
    app = web.Application()
    good = "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()

    def handler(path, value):
        async def h(req):
            if req.headers.get("Authorization") != good:
                return web.json_response({"status": 401, "message": "Authentication Failed"}, status=401)
            if path in forbid:
                return web.json_response({"status": 403, "message": "Forbidden"}, status=403)
            return web.json_response(value)
        return h
    for path, value in routes.items():
        if legacy:  # before 25.7: camelCase for some of them
            leaf = path.rsplit("/", 1)[-1]
            path = path[:-len(leaf)] + opnsense.OLD.get(leaf, leaf)
        app.router.add_get(path, handler(path, value))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


def poll(routes, key=KEY, secret=SECRET, **kw):
    async def go():
        runner, url = await serve(routes, **kw)
        try:
            return await opnsense.poll(url, key, secret, None, 10)
        finally:
            await runner.cleanup()
    return asyncio.run(go())


def test_reading_and_judging():
    d = poll(answers())
    fw = agents.clean_firewall(d)
    assert fw["product"] == "OPNsense" and fw["version"] == "25.7.8"
    assert [(g["name"], g["status"], g["delay_ms"], g["loss_pct"]) for g in fw["gateways"]] == [
        ("WAN_DHCP", "online", 8.2, 0.0), ("WAN2_PPPOE", "loss", 180.5, 12.0)]
    assert fw["carp"] == [{"interface": "lan", "state": "MASTER", "vhid": "1"}]          # an IP alias isn't CARP
    assert fw["ipsec"] == {"configured": 2, "mobile": 0, "up": 1, "down": ["Site C"]}
    assert [(o["name"], o["kind"], o["clients"]) for o in fw["openvpn"]] == [("Road warriors", "server", 3), ("To DC", "client", 0)]
    assert fw["states"] == {"current": 95123, "limit": 100000} and fw["update"]["available"] is False
    x = d["extra"]
    assert x["uptime_s"] == 3 * 86400 + 4 * 3600 + 5 * 60 + 6 and x["mem_pct"] == 25 and x["load"] == [0.21, 0.18, 0.12]
    assert x["temps"]["sensors"] == [{"name": "CPU", "celsius": 48.0}]
    c = agents.firewall_check(fw)
    assert c["level"] == "warn"
    assert "gateway WAN2_PPPOE loss (12% loss)" in c["detail"] and "IPsec down: Site C" in c["detail"] and "state table 95% full" in c["detail"]


def test_gateway_down_and_update():
    fw = agents.clean_firewall(poll(answers(down=True, update=True)))
    c = agents.firewall_check(fw)
    assert c["level"] == "crit" and "gateway WAN2_PPPOE down (100% loss)" in c["detail"]
    assert fw["update"] == {"checked": None, "available": True, "version": "25.7.9"}


def test_older_release_and_missing_privileges():
    d = poll(answers(), legacy=True)  # camelCase names before 25.7
    assert d["extra"]["uptime_s"] and agents.clean_firewall(d)["ipsec"]["up"] == 1
    d = poll(answers(), forbid=("/api/ipsec/sessions/search_phase1", "/api/diagnostics/interface/get_vip_status"))
    fw = agents.clean_firewall(d)
    assert fw["ipsec"] is None and fw["carp"] == [] and fw["gateways"]   # not allowed to read: left out, not an error
    assert "ipsec" not in d["read_sections"] and "gws" in d["read_sections"]


def test_bad_key_and_no_privileges():
    with pytest.raises(opnsense.OpnsenseError) as e:
        poll(answers(), secret="WrongSecretWrongSecretWrong")
    assert e.value.login
    with pytest.raises(opnsense.OpnsenseError) as e:
        poll(answers(), forbid=("/api/diagnostics/system/system_information", "/api/core/firmware/status"))
    assert e.value.login and "Lobby: Dashboard" in str(e.value)


def test_check_in_rollcall(tmp_path, monkeypatch):
    import main
    from test_ip_change_and_acks import monitor
    assert main.parse_check("opnsense:device")[0]["kind"] == "opnsense"
    e = main.validate_entry({"name": "FW01", "host": "192.168.1.1", "checks": ["opnsense:device"], "opnsense_url": "https://192.168.1.1:4443",
                             "opnsense_key": KEY, "opnsense_secret": SECRET})
    assert (e["opnsense_url"], e["opnsense_key"], e["opnsense_secret"]) == ("https://192.168.1.1:4443", KEY, SECRET)
    with pytest.raises(ValueError):
        main.validate_entry({"name": "FW01", "host": "192.168.1.1", "checks": [], "opnsense_url": "https://x", "opnsense_key": "not a key!"})
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "fw", "name": "FW01", "host": "127.0.0.1", "checks": ["opnsense:device"],
                                            "opnsense_key": KEY, "opnsense_secret": SECRET}])
    h = m.hosts["fw"]

    async def go(routes):
        runner, url = await serve(routes)
        try:
            h.op_url = url
            return await m.opnsense_check(h, 1000.0)
        finally:
            await runner.cleanup()
    r = asyncio.run(go(answers(down=True)))
    assert not r[0] and len(r) == 3 and "gateway WAN2_PPPOE down" in r[2]
    good = answers()
    good["/api/routes/gateway/status"]["items"].pop()
    good["/api/ipsec/sessions/search_phase1"]["rows"].pop()
    good["/api/diagnostics/firewall/pf_states"]["current"] = "1200"
    good["/api/core/firmware/status"] = answers(update=True)["/api/core/firmware/status"]
    r = asyncio.run(go(good))
    assert r[0] and "1 gateway online" in r[2] and "update 25.7.9 available" in r[2]
    assert h.op_data["fw"]["version"] == "25.7.8" and h.op_data["extra"]["mem_pct"] == 25
