"""Cisco and Juniper over SNMP (owner's request, 23 Nov): built from the vendors' MIBs and checked against an SNMP
stand-in. Real kit can't be tested here: before relying on it, ask a user for snmpwalk output (names replaced).

Run from the repository root:  python3 -m pytest tests/test_netvendor.py
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import hints  # noqa: E402
import netvendor as nv  # noqa: E402
import snmp  # noqa: E402


class FakeSession:
    """GET and walks over a flat {oid: value} table, like snmp.Session."""
    def __init__(self, table):
        self.t = {k.strip("."): v for k, v in table.items()}
        self.asked = []

    async def get(self, oids):
        self.asked.append(("get", tuple(oids)))
        return {o: self.t[o] for o in oids if o in self.t}

    async def walk(self, root, limit=3000, **_):
        root = root.strip(".")
        self.asked.append(("walk", root))
        return {k[len(root) + 1:]: v for k, v in self.t.items() if k.startswith(root + ".")}


CISCO = {
    # CPU: one, its physical entity named
    f"{nv.CPU_TOTAL}.2.1": 1000, f"{nv.CPU_TOTAL}.7.1": 12, f"{nv.CPU_TOTAL}.8.1": 95,
    f"{nv.ENT_NAME}.1000": b"Switch 1 - CPU",
    # Memory (64-bit counters)
    f"{nv.EMEMPOOL}.3.1000.1": b"Processor", f"{nv.EMEMPOOL}.18.1000.1": 300_000_000, f"{nv.EMEMPOOL}.20.1000.1": 700_000_000,
    f"{nv.EMEMPOOL}.3.1000.2": b"lsmpi_io", f"{nv.EMEMPOOL}.18.1000.2": 99, f"{nv.EMEMPOOL}.20.1000.2": 1,   # I/O pool: full by design
    # ENVMON: a hot inlet, a failed fan, a missing power supply (not counted) and a good one
    f"{nv.ENVMON}.3.1.2.1": b"Inlet", f"{nv.ENVMON}.3.1.3.1": 52, f"{nv.ENVMON}.3.1.4.1": 56, f"{nv.ENVMON}.3.1.6.1": 2,
    f"{nv.ENVMON}.4.1.2.1": b"Fan 1", f"{nv.ENVMON}.4.1.3.1": 3,
    f"{nv.ENVMON}.5.1.2.1": b"PSU A", f"{nv.ENVMON}.5.1.3.1": 1,
    f"{nv.ENVMON}.5.1.2.2": b"PSU B", f"{nv.ENVMON}.5.1.3.2": 5,
    # A stack of two: one ready, one still coming up; the ring isn't redundant
    f"{nv.STACK}.1.1001": 1, f"{nv.STACK}.3.1001": 1, f"{nv.STACK}.6.1001": 4,
    f"{nv.STACK}.1.2001": 2, f"{nv.STACK}.3.2001": 2, f"{nv.STACK}.6.2001": 2,
    nv.STACK_RING: 2,
    # Running config changed after the last save
    nv.RUNNING_CHANGED: 5000, nv.STARTUP_CHANGED: 4000,
    # BGP: one up, one enabled but idle, one shut down
    f"{nv.BGP_PEER}.2.198.51.100.1": 6, f"{nv.BGP_PEER}.3.198.51.100.1": 2, f"{nv.BGP_PEER}.9.198.51.100.1": 64512,
    f"{nv.BGP_PEER}.2.198.51.100.2": 1, f"{nv.BGP_PEER}.3.198.51.100.2": 2, f"{nv.BGP_PEER}.9.198.51.100.2": 64513,
    f"{nv.BGP_PEER}.2.198.51.100.3": 1, f"{nv.BGP_PEER}.3.198.51.100.3": 1, f"{nv.BGP_PEER}.9.198.51.100.3": 64514,
}

JUNIPER = {
    f"{nv.JNX_OPERATING}.5.9.1.0.0": b"Routing Engine 0", f"{nv.JNX_OPERATING}.6.9.1.0.0": 2, f"{nv.JNX_OPERATING}.7.9.1.0.0": 41,
    f"{nv.JNX_OPERATING}.8.9.1.0.0": 7, f"{nv.JNX_OPERATING}.11.9.1.0.0": 38,
    f"{nv.JNX_OPERATING}.5.7.1.0.0": b"FPC: EX4300-48P @ 0/*/*", f"{nv.JNX_OPERATING}.6.7.1.0.0": 2, f"{nv.JNX_OPERATING}.7.7.1.0.0": 45,
    f"{nv.JNX_OPERATING}.5.4.2.0.0": b"Fan Tray 1", f"{nv.JNX_OPERATING}.6.4.2.0.0": 6,
    f"{nv.JNX_REDUNDANCY}.5.9.1.0.0": b"Routing Engine 0", f"{nv.JNX_REDUNDANCY}.6.9.1.0.0": 2, f"{nv.JNX_REDUNDANCY}.8.9.1.0.0": 1,
    nv.JNX_YELLOW: 3, nv.JNX_YELLOW_N: 1, nv.JNX_RED: 2, nv.JNX_RED_N: 0,
    f"{nv.JNX_FRU}.5.2.1.0.0": b"PEM 0", f"{nv.JNX_FRU}.8.2.1.0.0": 6,
    f"{nv.JNX_FRU}.5.2.2.0.0": b"PEM 1", f"{nv.JNX_FRU}.8.2.2.0.0": 8,
    f"{nv.JNX_FRU}.5.7.2.0.0": b"FPC 1", f"{nv.JNX_FRU}.8.7.2.0.0": 2,          # empty slot: not listed
    f"{nv.OSPF_NBR}.6.10.0.1.2.0": 8, f"{nv.OSPF_NBR}.6.10.0.1.3.0": 1,
}


def items(d):
    out = []
    nv.evaluate(d, lambda lv, what, detail="": out.append((lv, what, detail)))
    return out


def test_cisco():
    d = asyncio.run(nv.read_cisco(FakeSession(CISCO)))
    assert d["cpu"] == [{"name": "Switch 1 - CPU", "pct_1m": 12, "pct_5m": 95}]
    assert d["memory"][0] == {"name": "Processor", "used": 300_000_000, "free": 700_000_000}
    env = {e["name"]: e for e in d["env"]}
    assert set(env) == {"Inlet", "Fan 1", "PSU A"}                                  # PSU B isn't there
    assert env["Inlet"] == {"kind": "temperature", "name": "Inlet", "state": "warning", "celsius": 52, "limit": 56}
    assert [m["ready"] for m in d["stack"]] == [True, False] and d["stack_ring_full"] is False
    assert d["config_unsaved"] is True and "failover" not in d
    assert [p["peer"] for p in d["bgp"] if p["up"]] == ["198.51.100.1"]
    got = items(d)
    assert ("warn", "CPU", "Switch 1 - CPU 95% (5 min)") in got
    assert not any(w == "Memory" for _, w, _ in got)                               # 30%, and the I/O pool doesn't count
    assert ("warn", "Temperature", "Inlet: warning (52 °C)") in got and ("crit", "Fan", "Fan 1: critical") in got
    assert ("crit", "Stack", "switch 2 progressing") in got
    assert ("warn", "Stack", "the stack ring isn't redundant (a stack cable is out)") in got
    assert ("warn", "Configuration", "changed since it was last saved (write memory)") in got
    assert ("warn", "BGP", "198.51.100.2 idle") in got                               # the shut-down one doesn't alert
    assert nv.chips(d) == ["CPU 95%", "memory 30%", "52 °C", "stack of 2", "BGP 1/3"]


def test_cisco_asa_failover_and_entity_sensors():
    t = {f"{nv.FAILOVER}.2.6": b"Failover LAN Interface", f"{nv.FAILOVER}.3.6": 9,
         f"{nv.FAILOVER}.2.7": b"Secondary unit", f"{nv.FAILOVER}.3.7": 10,
         f"{nv.ENT_SENSOR}.1.21": 8, f"{nv.ENT_SENSOR}.3.21": 1, f"{nv.ENT_SENSOR}.4.21": 385, f"{nv.ENT_SENSOR}.5.21": 1,
         f"{nv.ENT_SENSOR}.1.22": 12, f"{nv.ENT_SENSOR}.4.22": 12000,                 # not a temperature
         f"{nv.ENT_NAME}.21": b"Chassis Temperature Sensor"}
    d = asyncio.run(nv.read_cisco(FakeSession(t)))
    assert d["failover"] == [{"unit": "primary", "detail": "Failover LAN Interface", "state": "active"},
                             {"unit": "secondary", "detail": "Secondary unit", "state": "standby"}]
    assert d["env"] == [{"kind": "temperature", "name": "Chassis Temperature Sensor", "celsius": 38.5, "state": "normal"}]
    assert items(d) == []
    d["failover"][0]["state"] = "standby"
    assert items(d)[0][:2] == ("crit", "Failover")


def test_juniper():
    d = asyncio.run(nv.read_juniper(FakeSession(JUNIPER)))
    comps = {c["name"]: c for c in d["components"]}
    assert comps["Routing Engine 0"] == {"name": "Routing Engine 0", "state": "running", "celsius": 41, "cpu_pct": 7, "mem_pct": 38}
    assert comps["Fan Tray 1"]["state"] == "down"
    assert d["redundancy"] == [{"name": "Routing Engine 0", "state": "master", "switchovers": 1}]
    assert d["alarms"] == {"yellow": True, "yellow_count": 1, "red": False, "red_count": 0}
    assert {f["name"]: f["offline"] for f in d["frus"]} == {"PEM 0": False, "PEM 1": True}
    assert [n["neighbour"] for n in d["ospf"]] == ["10.0.1.2", "10.0.1.3"]
    got = items(d)
    assert ("crit", "Component", "Fan Tray 1 down") in got and ("warn", "Chassis alarm", "1 yellow alarm(s)") in got
    assert ("warn", "FRU", "PEM 1 offline") in got and ("warn", "OSPF", "neighbour(s) down: 10.0.1.3") in got
    assert nv.chips(d) == ["CPU 7%", "memory 38%", "45 °C", "OSPF 1 up"]


def test_chosen_by_object_id_and_in_the_snmp_check():
    assert nv.vendor("1.3.6.1.4.1.9.1.2066") == "cisco" and nv.vendor("1.3.6.1.4.1.2636.1.1.1.2.132") == "juniper"
    assert nv.vendor("1.3.6.1.4.1.674.10892") is None
    d = {"netvendor": asyncio.run(nv.read_juniper(FakeSession(JUNIPER))), "ports": []}
    level, its = snmp.evaluate(d, set(), None)
    assert level == "crit" and any(i["what"] == "Chassis alarm" for i in its)
    # Nothing it doesn't have is asked twice, and nothing is ever set (GET and walks only)
    s = FakeSession({})
    assert asyncio.run(nv.read_cisco(s)) == {"vendor": "cisco"}
    assert all(kind in ("get", "walk") for kind, _ in s.asked)


def test_syslog_hints():
    for msg, start in (("%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down", "A port's link"),
                       ("%LINEPROTO-5-UPDOWN: Line protocol on Interface Tunnel1, changed state to down", "The line protocol"),
                       ("%SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.50)", "Someone changed"),
                       ("%SYS-5-RESTART: System restarted --", "The device restarted"),
                       ("%PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/7, putting Gi1/0/7 in err-disable state", "The switch shut a port"),
                       ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.1.2 on Vlan10 from FULL to DOWN", "A routing neighbour")):
        h = hints.known("syslog", msg, 1)
        assert h and h[0]["means"].startswith(start), msg
