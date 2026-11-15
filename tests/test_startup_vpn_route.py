"""Start-up allowance, Sophos VPN tunnels over SNMP, and agents choosing their address by subnet.

Run from the repository root:  python3 -m pytest tests/test_startup_vpn_route.py
"""
import asyncio
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import main  # noqa: E402
import snmp  # noqa: E402

AGENT = ROOT / "rollcall" / "app" / "agent" / "pingmonitor-agent.py"


# --- start-up allowance -------------------------------------------------------------------------

def _host(**kw):
    h = main.Host(key="srv01", name="SRV01", host="192.168.1.20", checks=[], next_due=0)
    for k, v in kw.items():
        setattr(h, k, v)
    return h


def test_whenever_on_computer_gets_its_allowance():
    h = _host(expect_off=True, startup_grace=10, sched_started=1000.0)
    assert main.startup_until(h, 1000 + 60) == 1000 + 600
    assert main.startup_until(h, 1000 + 601) is None          # over: alerts as usual
    h.off_schedule = True
    assert main.startup_until(h, 1000 + 60) is None           # switched off again


def test_timed_schedule_uses_its_own_allowance_and_always_on_has_none():
    h = _host(schedule={"windows": [], "grace": 5}, sched_started=1000.0)
    assert main.startup_until(h, 1100) == 1300
    assert main.startup_until(_host(sched_started=1000.0), 1001) is None
    assert main.startup_until(_host(expect_off=True, startup_grace=0, sched_started=1000.0), 1000) is None
    assert main.startup_until(_host(expect_off=True, sched_started=1000.0, maint_until=9e9), 1001) is None


def test_allowance_is_saved_for_whenever_on_computers():
    entry = main.validate_entry({"name": "SRV01", "host": "192.168.1.20", "checks": [], "expect_off": True, "grace": 30})
    assert entry["expect_off"] and entry["grace"] == 30
    try:
        main.validate_entry({"name": "SRV01", "host": "192.168.1.20", "checks": [], "expect_off": True, "grace": 999})
        raise AssertionError("accepted 999 minutes")
    except ValueError:
        pass


def test_service_down_while_starting_doesnt_alert_then_does_straight_after(monkeypatch):
    t = [1000.0]
    monkeypatch.setattr(main.time, "time", lambda: t[0])
    h = _host(expect_off=True, startup_grace=10, sched_started=1000.0, ip="192.168.1.20")
    svc = main.Service(key="rdp", **main.parse_check("tcp:3389")[0])
    svc.status = main.UNKNOWN
    h.services = [svc]
    changes = []

    async def tcp_down(*_a, **_k):
        return False, None, "connection refused"
    monkeypatch.setattr(main, "tcp_check", tcp_down)
    m = types.SimpleNamespace(sem=asyncio.Semaphore(4), svc_timeout=1, store=types.SimpleNamespace(add=lambda *a: None))

    async def on_change(_h, s, old, new):
        changes.append(new)
    m.on_service_change = on_change
    m._vpn_more_down = lambda *a: None
    run = lambda now: asyncio.run(main.Monitor.check_services(m, h, now))  # noqa: E731
    run(1060)
    assert svc.status == main.MAINT and svc.detail.startswith("starting up") and changes == [main.MAINT]
    run(1300)
    assert svc.status == main.MAINT                       # still within 10 minutes: no alert
    run(1601)
    assert svc.status == main.RED and changes[-1] == main.RED   # straight to red, not amber first


# --- Sophos VPN tunnels ----------------------------------------------------------------------------

def _vpn(*rows):
    return {"uptime_s": 99999, "uptime_source": "system", "ports": [],
            "vpn": {"tunnels": [{"name": n, "up": st == 1, "partial": st == 2, "active": act, "status": "x"} for n, st, act in rows]}}


def test_only_tunnels_switched_on_alert():
    worst, items = snmp.evaluate(_vpn(("Site2_Link", 1, True), ("Site3_Link", 0, True), ("Supplier_VPN", 0, False)), set(), None)
    assert worst == "crit" and [i["what"] for i in items] == ["VPN Site3_Link"]


def test_partly_up_is_amber_and_ignored_tunnels_never_alert():
    worst, items = snmp.evaluate(_vpn(("Backup_DC", 2, True)), set(), None)
    assert worst == "warn"
    worst, items = snmp.evaluate(_vpn(("Site3_Link", 0, True)), set(), None, vpn_ignore={"site3_link"})
    assert worst == "ok" and not items


def test_second_tunnel_down_gets_its_own_alert():
    sent = []
    h = _host(ip="192.168.1.1")
    s = main.Service(key="snmp", **main.parse_check("snmp")[0])
    m = types.SimpleNamespace(notify=None)

    async def notify(title, msg, tag=None, critical=False):
        sent.append(title)
    m.notify = notify
    h.snmp_items = [{"level": "crit", "what": "VPN Site3_Link", "detail": "down"}]
    h.vpn_alerted = {"VPN Site3_Link"}                       # covered by the first alert
    h.vpn_down_prev = {"VPN Site3_Link"}
    asyncio.run(main.Monitor._vpn_more_down(m, h, s))
    assert sent == []
    h.snmp_items.append({"level": "crit", "what": "VPN Site4_Link", "detail": "down"})
    asyncio.run(main.Monitor._vpn_more_down(m, h, s))
    assert sent == []                                       # seen once: wait for the next poll
    h.vpn_down_prev = {"VPN Site3_Link", "VPN Site4_Link"}
    asyncio.run(main.Monitor._vpn_more_down(m, h, s))
    assert sent == ["🟠 SRV01: VPN Site4_Link down"]


# --- agents choose their address by subnet ------------------------------------------------------

def _monitor(nets, inside="http://10.0.1.5:8100", outside="https://rollcall.example.local:8100"):
    m = types.SimpleNamespace(agent_settings={"servers": {"inside": inside, "outside": outside}, "internal_networks": nets})
    for n in ("internal_networks", "agent_route", "agent_side"):
        setattr(m, n, types.MethodType(getattr(main.Monitor, n), m))
    return m


def test_route_is_only_sent_once_both_addresses_and_a_network_are_set():
    assert _monitor([]).agent_route() is None
    assert _monitor(["10.0.1.0/24"], outside="").agent_route() is None
    assert _monitor(["10.0.1.0/24"]).agent_route()["networks"] == ["10.0.1.0/24"]


def test_drift_is_visible():
    m = _monitor(["10.0.1.0/24"])
    side = m.agent_side({"ips": ["10.0.1.20"], "sent_to": "https://rollcall.example.local:8100"})
    assert side == {"via": "outside", "expected": "inside"}
    assert m.agent_side({"ips": ["192.168.7.2"], "sent_to": "https://rollcall.example.local:8100/"}) == {"via": "outside", "expected": "outside"}
    assert m.agent_side({"ips": ["10.0.1.20"], "sent_to": "http://10.0.1.5:8100"})["via"] == "inside"


def _linux_agent():
    spec = importlib.util.spec_from_file_location("rc_linux_agent", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_linux_agent_chooses_by_its_own_address_not_the_last_one_that_worked():
    ag = _linux_agent()
    rt = ag.clean_route({"inside": "http://10.0.1.5:8100", "outside": "https://rollcall.example.local:8100", "networks": ["10.0.1.0/24"]})
    ag.ACTIVE.update(pushed=["http://10.0.1.5:8100", "https://rollcall.example.local:8100"],
                     preferred="https://rollcall.example.local:8100", route=rt)
    ag.ACTIVE["side"] = ag.route_side(rt, ["10.0.1.20"])
    assert ag.server_list("http://192.168.1.9:8100") == ["http://10.0.1.5:8100", "https://rollcall.example.local:8100", "http://192.168.1.9:8100"]
    ag.ACTIVE["side"] = ag.route_side(rt, ["192.168.7.2"])
    assert ag.server_list("http://192.168.1.9:8100")[0] == "https://rollcall.example.local:8100"
    ag.ACTIVE["route"] = None                               # not set: the old behaviour
    assert ag.server_list("http://192.168.1.9:8100")[0] == "https://rollcall.example.local:8100"


# --- Sophos RED: always "up", so judged by its keepalives ------------------------------------------

def _red(octets, polled, prev=None):
    d = {"polled": polled, "uptime_s": 99999, "uptime_source": "system",
         "ports": [{"index": 7, "name": "reds1", "alias": "", "admin_up": True, "up": True, "red": True, "in_octets": octets}]}
    snmp.red_activity(d, prev)
    return d


def test_red_disconnected_when_nothing_arrives_between_checks():
    d1 = _red(1000, 0)
    assert d1["ports"][0]["rx_idle"] is None                         # not known from one reading
    d2 = _red(1000, 300, d1)
    assert d2["ports"][0]["rx_idle"] is True
    worst, items = snmp.evaluate(d2, {7}, None)
    assert worst == "crit" and items[0]["what"] == "RED reds1"
    assert snmp.evaluate(d2, set(), None)[0] == "ok"                 # not ticked: just shown
    d3 = _red(1064, 600, d2)
    assert d3["ports"][0]["rx_idle"] is False and snmp.evaluate(d3, {7}, None)[0] == "ok"


def test_red_checks_close_together_keep_comparing_with_an_older_reading():
    d1 = _red(1000, 0)
    d2 = _red(1000, 20, d1)          # 20 s later: a keepalive may not have come yet
    d3 = _red(1000, 40, d2)
    assert d3["ports"][0]["rx_idle"] is None
    d4 = _red(1064, 50, d3)          # 50 s after the first reading, and it has moved
    assert d4["ports"][0]["rx_idle"] is False
    d5 = _red(10, 400, d4)           # counter went back (firewall restarted): traffic, not a disconnect
    assert d5["ports"][0]["rx_idle"] is False
