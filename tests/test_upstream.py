"""Upstream devices: devices behind a router show as unreachable when it's down, with one alert.

Run from the repository root:  python3 -m pytest tests/test_upstream.py
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import main  # noqa: E402


class FakeHA:
    async def fire(self, *a, **k): pass
    async def service(self, *a, **k): pass
    async def set_state(self, *a, **k): pass
    async def delete_state(self, *a, **k): pass
    async def get_json(self, *a, **k): return None


@pytest.fixture
def mon(tmp_path, monkeypatch):
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    (tmp_path / "hosts.json").write_text(json.dumps([
        {"id": "router", "name": "Router", "host": "10.0.1.1", "checks": []},
        {"id": "switch", "name": "Switch", "host": "10.0.1.2", "checks": [], "parent": "router"},
        {"id": "pc01", "name": "PC01", "host": "10.0.1.10", "checks": [], "parent": "switch"},
        {"id": "pc02", "name": "PC02", "host": "10.0.1.11", "checks": [], "parent": "router"},
        {"id": "srv01", "name": "SRV01", "host": "10.0.1.20", "checks": []},
    ]))
    opts = dict(main.DEFAULTS, interval=300, retry_interval=60)
    m = main.Monitor(opts, main.Store(tmp_path / "db.sqlite"), FakeHA())
    m.sent = []

    async def notify(title, message, tag=None, **_k):
        m.sent.append((title, message))
    m.notify = notify
    m.publish_soon = lambda h: None
    m.up = {h.host for h in m.hosts.values()}

    async def resolve(host):
        return host

    async def ping(ip, *_a, **_k):
        return (ip in m.up), (1.0 if ip in m.up else None)
    monkeypatch.setattr(main, "resolve", resolve)
    monkeypatch.setattr(main, "ping", ping)
    m.t = [10_000.0]
    monkeypatch.setattr(main.time, "time", lambda: m.t[0])
    return m


def run(m, *keys, step=5):
    for k in keys:
        m.t[0] += step
        asyncio.run(m.check(m.hosts[k]))


def test_router_down_sends_one_alert_listing_whats_behind_it(mon):
    run(mon, "router", "switch", "pc01", "pc02", "srv01")
    assert all(h.status == main.GREEN for h in mon.hosts.values())
    mon.up -= {"10.0.1.1", "10.0.1.2", "10.0.1.10", "10.0.1.11"}   # the router goes, taking everything behind it
    # Worst case: the devices behind it are checked first, twice (amber, then red), before the router.
    run(mon, "pc01", "pc02", "switch")
    run(mon, "pc01", "pc02", "switch")
    assert mon.hosts["pc02"].status == main.RED and mon.hosts["pc02"].alert_held
    assert mon.hosts["pc01"].unreachable and mon.hosts["pc01"].upstream_down == "switch"  # the switch went red too
    assert mon.sent == []                                     # held, waiting to hear about the router
    run(mon, "router")
    assert mon.hosts["router"].status == main.AMBER
    run(mon, "router")
    assert mon.hosts["router"].status == main.RED
    assert [t for t, _ in mon.sent] == ["🔴 Router is down"]
    assert "Devices behind it may also be affected (3): PC01, PC02, Switch." in mon.sent[0][1]
    for k in ("switch", "pc02"):                              # settled the moment the router went red
        assert mon.hosts[k].unreachable and mon.hosts[k].upstream_down == "router" and not mon.hosts[k].alert_held
    run(mon, "pc01")                                          # two levels down: settled at its own next check
    assert mon.hosts["pc01"].unreachable and mon.hosts["pc01"].upstream_down == "router"
    snap = {h["key"]: h for h in mon.snapshot()["hosts"]}
    assert snap["pc01"]["unreachable"] and snap["pc01"]["upstream_down"] == "Router" and snap["pc01"]["parent"] == "switch"
    # Back again: one "back up" for the router, none for the devices that never alerted.
    mon.up |= {"10.0.1.1", "10.0.1.2", "10.0.1.10", "10.0.1.11"}
    run(mon, "router")
    assert all(mon.hosts[k].next_due <= mon.t[0] + 1 for k in ("switch", "pc01", "pc02"))  # re-checked straight away
    run(mon, "switch", "pc01", "pc02")
    assert [t for t, _ in mon.sent] == ["🔴 Router is down", "🟢 Router is back up"]
    assert not any(h.unreachable for h in mon.hosts.values())


def test_device_down_behind_a_working_router_still_alerts(mon):
    run(mon, "router", "pc02")
    mon.up.discard("10.0.1.11")
    run(mon, "pc02", "pc02", step=60)                         # the router was last checked a while ago
    assert mon.hosts["pc02"].alert_held and mon.sent == []
    run(mon, "router")                                        # the router answers: PC02 really is down
    assert [t for t, _ in mon.sent] == ["🔴 PC02 is down"]
    assert "Router, which it's reached through, is answering." in mon.sent[0][1]
    assert not mon.hosts["pc02"].unreachable
    mon.up.add("10.0.1.11")
    run(mon, "pc02")
    assert mon.sent[-1][0] == "🟢 PC02 is back up"


def test_router_checked_moments_ago_means_no_wait(mon):
    run(mon, "router", "pc02")
    mon.up.discard("10.0.1.11")
    run(mon, "pc02", "pc02")                                  # the router answered seconds ago
    assert [t for t, _ in mon.sent] == ["🔴 PC02 is down"]


def test_held_alert_goes_out_if_the_router_isnt_checked_in_time(mon):
    run(mon, "router", "pc02")
    mon.hosts["router"].checking = True                       # e.g. a slow check
    mon.up.discard("10.0.1.11")
    run(mon, "pc02", "pc02", step=60)
    assert mon.sent == []
    mon.t[0] += main.Monitor.PARENT_WAIT + 1
    asyncio.run(mon._tick(mon.t[0], mon.t[0]))
    assert [t for t, _ in mon.sent] == ["🔴 PC02 is down"]


def test_router_back_but_device_still_down_gets_its_own_alert(mon):
    run(mon, "router", "pc02")
    mon.up -= {"10.0.1.1", "10.0.1.11"}
    run(mon, "router", "router", "pc02", "pc02")
    assert mon.hosts["pc02"].unreachable and [t for t, _ in mon.sent] == ["🔴 Router is down"]
    mon.up.add("10.0.1.1")
    run(mon, "router", "pc02")
    assert [t for t, _ in mon.sent] == ["🔴 Router is down", "🟢 Router is back up", "🔴 PC02 is down"]


def test_no_loops_and_deleting_the_router_frees_its_devices(mon):
    with pytest.raises(ValueError):
        mon.check_parent("router", "pc01")                    # PC01 is behind the router
    with pytest.raises(ValueError):
        mon.check_parent("router", "router")
    with pytest.raises(ValueError):
        mon.check_parent(None, "nope")
    mon.check_parent("srv01", "pc01")
    assert main.validate_entry({"name": "A", "host": "10.0.1.5", "parent": "router"})["parent"] == "router"
    with pytest.raises(ValueError):
        main.validate_entry({"name": "A", "host": "10.0.1.5", "parent": "../x"})
    asyncio.run(mon.delete_host(mon.hosts["router"]))
    assert mon.hosts["pc02"].parent == "" and mon.hosts["switch"].parent == ""
    assert mon.hosts["pc01"].parent == "switch"
    saved = {e["id"]: e for e in json.loads(main.HOSTS_PATH.read_text())}
    assert "parent" not in saved["pc02"] and saved["pc01"]["parent"] == "switch"


def test_snapshot_never_includes_the_jellyfin_key_and_names_ranges(mon):
    mon.hosts["srv01"].jf_key = "0123456789abcdef0123456789abcdef"
    mon.opts["ip_ranges"] = ["Servers=10.0.1.16-31", "Network=10.0.1.0/24"]
    run(mon, "srv01", "router")
    snap = {h["key"]: h for h in mon.snapshot()["hosts"]}
    assert snap["srv01"]["jellyfin_key_set"] and "0123456789abcdef" not in json.dumps(snap)
    assert snap["srv01"]["ip_range"] == "Servers" and snap["router"]["ip_range"] == "Network"


def test_ticking_the_devices_behind_a_switch_sets_them_all_at_once(mon):
    sw = mon.hosts["switch"]
    # tick PC01 (already behind it), PC02 (behind the router: moves) and SRV01 (behind nothing); unknown keys skipped
    behind = mon.check_downstream(sw, ["pc01", "pc02", "srv01", "nope", "switch"])
    assert mon.set_downstream(sw, behind) == 2
    assert [mon.hosts[k].parent for k in ("pc01", "pc02", "srv01")] == ["switch"] * 3
    # untick SRV01: cleared; PC01 and PC02 stay
    assert mon.set_downstream(sw, mon.check_downstream(sw, ["pc01", "pc02"])) == 1
    assert mon.hosts["srv01"].parent == "" and mon.hosts["pc02"].parent == "switch"
    saved = {e["id"]: e for e in json.loads(main.HOSTS_PATH.read_text())}
    assert saved["pc02"]["parent"] == "switch" and "parent" not in saved["srv01"]
    # the router is upstream of the switch, so it can't be behind it (a loop), nor can one being made upstream
    with pytest.raises(ValueError):
        mon.check_downstream(sw, ["router"])
    with pytest.raises(ValueError):
        mon.check_downstream(sw, ["srv01"], parent="srv01")
