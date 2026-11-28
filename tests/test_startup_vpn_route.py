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

AGENT = ROOT / "rollcall" / "app" / "agent" / "rollcall-agent.py"


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


def test_service_already_red_stays_red_while_starting(monkeypatch):
    monkeypatch.setattr(main.time, "time", lambda: 1060.0)
    h = _host(expect_off=True, startup_grace=10, sched_started=1000.0, ip="192.168.1.20")
    svc = main.Service(key="rdp", **main.parse_check("tcp:3389")[0])
    svc.status, svc.failures = main.RED, 3                   # alerted before it was restarted
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
    asyncio.run(main.Monitor.check_services(m, h, 1060))
    assert svc.status == main.RED and changes == []           # no grey, so no second alert at the end


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

    async def notify(title, msg, tag=None, critical=False, level=None, cat=None):
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


# --- Dell iDRAC health ---------------------------------------------------------------------------

class _FakeSnmp:
    def __init__(self, values, v1=False):
        self.values, self.v1 = values, v1

    async def get(self, oids):
        if self.v1 and any(o not in self.values for o in oids):
            raise snmp.SnmpError("noSuchName")       # SNMP v1: one unknown name fails the lot
        return {o: self.values[o] for o in oids if o in self.values}


def test_idrac7_and_later_health_storage_and_power():
    s = _FakeSnmp({f"{snmp.IDRAC}.1.0": 3, f"{snmp.IDRAC}.3.0": 4, f"{snmp.IDRAC}.4.0": 3})
    d = asyncio.run(snmp.read_dell(s))
    assert d == {"system": "OK", "storage": "non-critical", "power": "off", "mib": "idrac"}
    worst, items = snmp.evaluate({"uptime_s": 99999, "ports": [], "dell": d}, set(), None)
    assert worst == "warn" and {i["what"] for i in items} == {"Storage health", "Server"}


def test_idrac6_over_snmp_v1():
    d = asyncio.run(snmp.read_dell(_FakeSnmp({snmp.DRAC6: 5}, v1=True)))
    assert d["system"] == "critical" and d["mib"] == "drac6"
    assert snmp.evaluate({"uptime_s": 99999, "ports": [], "dell": d}, set(), None)[0] == "crit"
    assert asyncio.run(snmp.read_dell(_FakeSnmp({}, v1=True))) is None


# --- acknowledging SNMP problems --------------------------------------------------------------------

def test_acknowledged_snmp_problem_stops_counting_until_it_gets_worse_or_clears():
    m = types.SimpleNamespace(ups_limits=lambda h: {}, _save_hosts=lambda: None)
    ev = lambda h, d, prune=True: main.Monitor.snmp_eval(m, h, d, None, prune=prune)  # noqa: E731
    h = _host()
    dell = lambda st, power="on": {"uptime_s": 99999, "uptime_source": "system", "ports": [],  # noqa: E731
                                   "dell": {"system": st, "storage": None, "power": power, "mib": "idrac"}}
    assert ev(h, dell("non-critical", "off"))[0] == "warn"
    h.snmp_acks = {"Server": "warn"}                                 # "powered off" acknowledged
    worst, items = ev(h, dell("non-critical", "off"))
    assert worst == "warn" and [i["what"] for i in items if i.get("acked")] == ["Server"]
    h.snmp_acks["Server health"] = "warn"
    assert ev(h, dell("non-critical", "off"))[0] == "ok"
    assert ev(h, dell("critical", "off"))[0] == "crit"               # worse: counts again, and the acknowledgement goes
    assert "Server health" not in h.snmp_acks and "Server" in h.snmp_acks
    ev(h, dell("OK", "on"))                                          # cleared: forgotten, so it alerts if it comes back
    assert h.snmp_acks == {}
    assert ev(h, dell("OK", "off"))[0] == "warn"


# --- acknowledging agent checks and Domain Admins additions -----------------------------------------

def test_domain_admin_addition_acknowledged():
    import agents
    dm = {"groups": [{"name": "Domain Admins", "members": [{"name": "admin", "kind": "user"}]}]}
    changes = [{"time": NOW_T - 600, "change": "added", "group": "Domain Admins", "account": "temp.contractor"}]
    assert agents.domain_state(dm, changes, NOW_T)[0] == agents.WARN
    assert agents.domain_state(dm, changes, NOW_T, ack_at=NOW_T - 60)[0] == agents.OK      # acknowledged after it
    later = changes + [{"time": NOW_T - 30, "change": "added", "group": "Enterprise Admins", "account": "other"}]
    assert agents.domain_state(dm, later, NOW_T, ack_at=NOW_T - 60)[1].startswith("other added")  # a new one shows


NOW_T = 1_800_000_000.0
