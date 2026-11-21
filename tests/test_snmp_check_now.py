"""SNMP: Check now re-reads the port list (names and descriptions, normally every 6 hours), so a port just
described on the switch shows straight away.

Run from the repository root:  python3 -m pytest tests/test_snmp_check_now.py
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import main  # noqa: E402
from test_upstream import FakeHA  # noqa: E402


def test_check_now_rereads_the_port_list(tmp_path, monkeypatch):
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    (tmp_path / "hosts.json").write_text(json.dumps([{"id": "sw", "name": "Switch", "host": "10.0.1.2", "checks": []}]))
    m = main.Monitor(dict(main.DEFAULTS), main.Store(tmp_path / "db.sqlite"), FakeHA())
    h = m.hosts["sw"]
    alias = ["Old description"]
    asked = []

    async def poll(ip, community, *, discovery=None, **_k):
        asked.append(discovery)
        disc = discovery or {"at": 1.0, "poe": [], "poe_groups": [],
                             "ports": {"1": {"name": "g1", "descr": "Port 1", "alias": alias[0]}}}
        return {"discovery": disc, "per": 12, "ports": [{"index": 1, "name": "g1", "descr": "Port 1",
                                                        "alias": disc["ports"]["1"]["alias"], "up": True,
                                                        "admin_up": True, "speed_mbps": 1000}]}
    monkeypatch.setattr(main.snmplib, "poll", poll)

    asyncio.run(m.snmp_check(h, 100.0))
    asyncio.run(m.snmp_check(h, 400.0))
    assert asked[0] is None and asked[1] is not None            # discovered once, then reused
    alias[0] = "Uplink to SW02"                                 # described on the switch
    asyncio.run(m.snmp_check(h, 700.0))
    assert h.snmp_data["ports"][0]["alias"] == "Old description"  # an ordinary check doesn't see it yet

    # Check now (the endpoint sets this and makes the device due)
    h.snmp_rediscover = True
    asyncio.run(m.snmp_check(h, 1000.0))
    assert asked[-1] is None and h.snmp_data["ports"][0]["alias"] == "Uplink to SW02"
    assert h.snmp_rediscover is False
    asyncio.run(m.snmp_check(h, 1300.0))
    assert asked[-1] is not None                                # back to the remembered list


def test_the_check_now_endpoint_asks_for_it():
    src = (ROOT / "rollcall" / "app" / "main.py").read_text()
    body = src[src.index("    async def check_now(req):"):src.index("    async def host_metrics(req):")]
    assert "h.snmp_rediscover = True" in body and "h.next_due = 0" in body
