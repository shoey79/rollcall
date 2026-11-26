"""Cisco and Juniper over SNMP: what each one's own MIBs say about the box itself (CPU, memory, fans, power,
temperatures, the stack or redundant routing engines, alarms), plus BGP and OSPF neighbours on either. Read only:
GET and GETBULK, like the rest of Rollcall's SNMP.

Everything here is chosen by the device's sysObjectID (enterprise 9: Cisco, 2636: Juniper). A device that doesn't
have a table simply leaves it out.
"""
from __future__ import annotations

import re

CISCO, JUNIPER = "1.3.6.1.4.1.9.", "1.3.6.1.4.1.2636."

# Cisco
CPU_TOTAL = "1.3.6.1.4.1.9.9.109.1.1.1.1"       # CISCO-PROCESS-MIB cpmCPUTotalEntry: .2 physical index, .7 1-min, .8 5-min
EMEMPOOL = "1.3.6.1.4.1.9.9.221.1.1.1.1"        # CISCO-ENHANCED-MEMPOOL cempMemPoolEntry: .3 name, .18/.20 HC used/free
MEMPOOL = "1.3.6.1.4.1.9.9.48.1.1.1"            # CISCO-MEMORY-POOL ciscoMemoryPoolEntry: .2 name, .5 used, .6 free
ENVMON = "1.3.6.1.4.1.9.9.13.1"                 # CISCO-ENVMON: .3.1 temperature, .4.1 fan, .5.1 power supply
ENV_STATE = {1: "normal", 2: "warning", 3: "critical", 4: "shutdown", 5: "not present", 6: "not working"}
STACK = "1.3.6.1.4.1.9.9.500.1.2.1.1"           # CISCO-STACKWISE cswSwitchInfoEntry: .1 number, .3 role, .6 state
STACK_RING = "1.3.6.1.4.1.9.9.500.1.1.3.0"      # cswRingRedundant: 1 true, 2 false
STACK_ROLE = {1: "master", 2: "member", 3: "not a member", 4: "standby"}
STACK_STATE = {1: "waiting", 2: "progressing", 3: "added", 4: "ready", 5: "SDM mismatch", 6: "version mismatch",
               7: "feature mismatch", 8: "new master init", 9: "provisioned", 10: "invalid", 11: "removed"}
RUNNING_CHANGED = "1.3.6.1.4.1.9.9.43.1.1.1.0"  # CISCO-CONFIG-MAN ccmHistoryRunningLastChanged (sysUpTime)
STARTUP_CHANGED = "1.3.6.1.4.1.9.9.43.1.1.3.0"  # ccmHistoryStartupLastChanged
FAILOVER = "1.3.6.1.4.1.9.9.147.1.2.1.1.1"      # CISCO-FIREWALL-MIB cfwHardwareStatusEntry: .2 text, .3 value (rows 6, 7)
FAILOVER_STATE = {1: "other", 2: "up", 3: "down", 4: "error", 5: "over temperature", 6: "busy", 7: "no media",
                  8: "backup", 9: "active", 10: "standby"}
# ENTITY-SENSOR (Nexus, IOS XE without ENVMON temperatures): celsius sensors, named from ENTITY-MIB
ENT_SENSOR = "1.3.6.1.2.1.99.1.1.1"             # .1 type (8 celsius), .2 scale, .3 precision, .4 value, .5 status
ENT_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"

# Juniper
JNX_OPERATING = "1.3.6.1.4.1.2636.3.1.13.1"     # .5 descr, .6 state, .7 temp, .8 cpu %, .11 buffer (memory) %
JNX_STATE = {1: "unknown", 2: "running", 3: "ready", 4: "reset", 5: "running at full speed", 6: "down", 7: "standby"}
JNX_REDUNDANCY = "1.3.6.1.4.1.2636.3.1.14.1"    # .5 descr, .6 current state, .8 switchover count
JNX_RED_STATE = {1: "unknown", 2: "master", 3: "backup", 4: "disabled", 5: "not installed", 6: "not running"}
JNX_YELLOW = "1.3.6.1.4.1.2636.3.4.2.2.1.0"     # jnxYellowAlarmState: 2 off, 3 on
JNX_YELLOW_N = "1.3.6.1.4.1.2636.3.4.2.2.2.0"
JNX_RED = "1.3.6.1.4.1.2636.3.4.2.3.1.0"
JNX_RED_N = "1.3.6.1.4.1.2636.3.4.2.3.2.0"
JNX_FRU = "1.3.6.1.4.1.2636.3.1.15.1"           # .5 name, .8 state
JNX_FRU_STATE = {1: "unknown", 2: "empty", 3: "present", 4: "ready", 5: "going online", 6: "online", 7: "going offline",
                 8: "offline", 9: "diagnostic", 10: "standby"}

# Both
BGP_PEER = "1.3.6.1.2.1.15.3.1"                 # BGP4-MIB bgpPeerEntry: .2 state, .3 admin, .9 remote AS (index: peer)
BGP_STATE = {1: "idle", 2: "connect", 3: "active", 4: "open sent", 5: "open confirm", 6: "established"}
OSPF_NBR = "1.3.6.1.2.1.14.10.1"                # OSPF-MIB ospfNbrEntry: .6 state (index: neighbour IP.0)
OSPF_STATE = {1: "down", 2: "attempt", 3: "init", 4: "two-way", 5: "exchange start", 6: "exchange", 7: "loading", 8: "full"}


def vendor(object_id: str) -> str | None:
    oid = str(object_id or "")
    return "cisco" if oid.startswith(CISCO) else "juniper" if oid.startswith(JUNIPER) else None


def _text(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        v = bytes(v).decode("utf-8", "replace")
    return str(v or "").strip().strip("\x00")[:80]


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _cols(walked: dict, cols: tuple[str, ...]) -> dict[str, dict[str, object]]:
    """{row index: {column: value}} from a walk keyed "column.index"."""
    rows: dict[str, dict[str, object]] = {}
    for k, v in walked.items():
        col, _, idx = str(k).partition(".")
        if col in cols and idx:
            rows.setdefault(idx, {})[col] = v
    return rows


async def _walk(s, root: str, cols: tuple[str, ...], limit: int = 2000) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = {}
    for c in cols:  # column by column: big tables, and devices that stall on wide GETBULKs
        for idx, v in (await s.walk(f"{root}.{c}", limit=limit)).items():
            out.setdefault(str(idx), {})[c] = v
    return out


async def _get(s, oids: list[str]) -> dict:
    from snmp import SnmpError
    try:
        return await s.get(oids)
    except SnmpError:
        return {}


async def _neighbours(s) -> dict:
    out = {}
    bgp = await _walk(s, BGP_PEER, ("2", "3", "9"), limit=4000)
    if bgp:
        out["bgp"] = sorted(({"peer": idx, "state": BGP_STATE.get(_int(r.get("2")), str(r.get("2"))), "up": _int(r.get("2")) == 6,
                              "enabled": _int(r.get("3")) == 2, "remote_as": _int(r.get("9"))} for idx, r in bgp.items()),
                            key=lambda x: x["peer"])[:200]
    ospf = await _walk(s, OSPF_NBR, ("6",), limit=2000)
    if ospf:
        out["ospf"] = sorted(({"neighbour": idx.rsplit(".", 1)[0] if idx.count(".") == 4 else idx,
                               "state": OSPF_STATE.get(_int(r.get("6")), str(r.get("6"))), "down": _int(r.get("6")) == 1}
                              for idx, r in ospf.items()), key=lambda x: x["neighbour"])[:200]
    return out


async def read_cisco(s) -> dict:
    d: dict = {"vendor": "cisco"}
    names = {}
    cpu = await _walk(s, CPU_TOTAL, ("2", "7", "8"))
    if cpu:
        ent = await s.walk(ENT_NAME, limit=3000) if any(_int(r.get("2")) for r in cpu.values()) else {}
        names = {str(k): _text(v) for k, v in ent.items()}
        d["cpu"] = [{"name": names.get(str(_int(r.get("2")) or ""), "") or f"CPU {idx}", "pct_1m": _int(r.get("7")), "pct_5m": _int(r.get("8"))}
                    for idx, r in sorted(cpu.items(), key=lambda kv: kv[0])][:16]
    mem = await _walk(s, EMEMPOOL, ("3", "18", "20"))
    if mem:
        d["memory"] = [{"name": _text(r.get("3")), "used": _int(r.get("18")), "free": _int(r.get("20"))} for r in mem.values()
                       if _int(r.get("18")) is not None and _int(r.get("20")) is not None][:16]
    if not d.get("memory"):
        mem = await _walk(s, MEMPOOL, ("2", "5", "6"))
        d["memory"] = [{"name": _text(r.get("2")), "used": _int(r.get("5")), "free": _int(r.get("6"))} for r in mem.values()
                       if _int(r.get("5")) is not None and _int(r.get("6")) is not None][:16]
        if not d["memory"]:
            del d["memory"]
    env = []
    for sub, kind, cols in (("3.1", "temperature", ("2", "3", "4", "6")), ("4.1", "fan", ("2", "3")), ("5.1", "power", ("2", "3"))):
        rows = await _walk(s, f"{ENVMON}.{sub}", cols)
        for r in rows.values():
            st = _int(r.get("6" if kind == "temperature" else "3"))
            if st == 5:
                continue  # not present
            e = {"kind": kind, "name": _text(r.get("2")), "state": ENV_STATE.get(st, str(st))}
            if kind == "temperature":
                e["celsius"], e["limit"] = _int(r.get("3")), _int(r.get("4"))
            env.append(e)
    if not any(e["kind"] == "temperature" for e in env):
        sens = await _walk(s, ENT_SENSOR, ("1", "2", "3", "4", "5"), limit=1000)
        if sens and not names:
            names = {str(k): _text(v) for k, v in (await s.walk(ENT_NAME, limit=3000)).items()}
        for idx, r in sens.items():
            if _int(r.get("1")) != 8 or _int(r.get("4")) is None:
                continue
            val = r["4"] / (10 ** (_int(r.get("3")) or 0))
            env.append({"kind": "temperature", "name": names.get(idx, f"sensor {idx}"), "celsius": round(val, 1),
                        "state": "normal" if _int(r.get("5")) == 1 else "not working" if _int(r.get("5")) == 3 else "unavailable"})
    if env:
        d["env"] = env[:60]
    stack = await _walk(s, STACK, ("1", "3", "6"))
    if len(stack) > 1:  # a stack of one isn't a stack
        d["stack"] = [{"switch": _int(r.get("1")), "role": STACK_ROLE.get(_int(r.get("3")), str(r.get("3"))),
                       "state": STACK_STATE.get(_int(r.get("6")), str(r.get("6"))), "ready": _int(r.get("6")) == 4}
                      for r in sorted(stack.values(), key=lambda r: _int(r.get("1")) or 0)][:16]
        ring = (await _get(s, [STACK_RING])).get(STACK_RING)
        d["stack_ring_full"] = None if _int(ring) is None else ring == 1
    cfg = await _get(s, [RUNNING_CHANGED, STARTUP_CHANGED])
    run, start = _int(cfg.get(RUNNING_CHANGED)), _int(cfg.get(STARTUP_CHANGED))
    if run is not None and start is not None:
        d["config_unsaved"] = run > start  # changed since it was last saved (both are sysUpTime ticks)
    fo = await _walk(s, FAILOVER, ("2", "3"))
    if "6" in fo or "7" in fo:
        d["failover"] = [{"unit": "primary" if idx == "6" else "secondary", "detail": _text(fo[idx].get("2")),
                          "state": FAILOVER_STATE.get(_int(fo[idx].get("3")), str(fo[idx].get("3")))} for idx in ("6", "7") if idx in fo]
    d.update(await _neighbours(s))
    return d


async def read_juniper(s) -> dict:
    d: dict = {"vendor": "juniper"}
    ops = await _walk(s, JNX_OPERATING, ("5", "6", "7", "8", "11"))
    comps = []
    for idx, r in sorted(ops.items()):
        name = _text(r.get("5"))
        if not name:
            continue
        comps.append({"name": name, "state": JNX_STATE.get(_int(r.get("6")), str(r.get("6"))), "celsius": _int(r.get("7")) or None,
                      "cpu_pct": _int(r.get("8")), "mem_pct": _int(r.get("11"))})
    if comps:
        # The routing engines and line cards (FPCs) say most; fans, PEMs and the midplane only their state
        d["components"] = comps[:80]
    red = await _walk(s, JNX_REDUNDANCY, ("5", "6", "8"))
    if red:
        d["redundancy"] = [{"name": _text(r.get("5")), "state": JNX_RED_STATE.get(_int(r.get("6")), str(r.get("6"))),
                            "switchovers": _int(r.get("8"))} for r in red.values()][:16]
    al = await _get(s, [JNX_YELLOW, JNX_YELLOW_N, JNX_RED, JNX_RED_N])
    if al:
        d["alarms"] = {"yellow": _int(al.get(JNX_YELLOW)) == 3, "yellow_count": _int(al.get(JNX_YELLOW_N)),
                       "red": _int(al.get(JNX_RED)) == 3, "red_count": _int(al.get(JNX_RED_N))}
    fru = await _walk(s, JNX_FRU, ("5", "8"))
    if fru:
        d["frus"] = [{"name": _text(r.get("5")), "state": JNX_FRU_STATE.get(_int(r.get("8")), str(r.get("8"))),
                      "offline": _int(r.get("8")) in (8, 9)} for r in fru.values() if _int(r.get("8")) != 2][:120]
    d.update(await _neighbours(s))
    return d


IO_POOL = re.compile(r"i/o|_io\b|\bio\b|lsmpi|driver text|reserve", re.I)


def evaluate(nv: dict, add, limits: dict | None = None) -> None:
    """Problems as SNMP check items: add(level, what, detail)."""
    lim = {"cpu_warn": 90, "mem_warn": 90, **(limits or {})}
    for c in nv.get("cpu") or []:
        if (c.get("pct_5m") or 0) >= lim["cpu_warn"]:
            add("warn", "CPU", f"{c['name']} {c['pct_5m']}% (5 min)")
    for m in nv.get("memory") or []:
        tot = (m.get("used") or 0) + (m.get("free") or 0)
        if tot and 100 * m["used"] / tot >= lim["mem_warn"] and not IO_POOL.search(m["name"]):  # I/O pools run full by design
            add("warn", "Memory", f"{m['name']} {100 * m['used'] / tot:.0f}% used")
    for e in nv.get("env") or []:
        if e["state"] in ("critical", "shutdown", "not working"):
            add("crit", e["kind"].capitalize() if e["kind"] != "power" else "Power supply", f"{e['name']}: {e['state']}")
        elif e["state"] == "warning":
            add("warn", e["kind"].capitalize() if e["kind"] != "power" else "Power supply", f"{e['name']}: warning"
                + (f" ({e['celsius']} °C)" if e.get("celsius") is not None else ""))
    for m in nv.get("stack") or []:
        if not m["ready"] and m["role"] != "not a member":
            add("crit", "Stack", f"switch {m['switch']} {m['state']}")
    if nv.get("stack_ring_full") is False:
        add("warn", "Stack", "the stack ring isn't redundant (a stack cable is out)")
    if nv.get("config_unsaved"):
        add("warn", "Configuration", "changed since it was last saved (write memory)")
    fo = {f["unit"]: f["state"] for f in nv.get("failover") or []}
    if fo and "active" not in fo.values():
        add("crit", "Failover", "no unit is active: " + ", ".join(f"{k} {v}" for k, v in fo.items()))
    elif fo and any(v in ("down", "error", "other") for v in fo.values()) and len(fo) == 2:
        add("warn", "Failover", ", ".join(f"{k} {v}" for k, v in fo.items()))
    for c in nv.get("components") or []:
        if c["state"] == "down" and c["name"]:
            add("crit", "Component", f"{c['name']} down")
        elif (c.get("cpu_pct") or 0) >= lim["cpu_warn"] and "routing engine" in c["name"].lower():
            add("warn", "CPU", f"{c['name']} {c['cpu_pct']}%")
    al = nv.get("alarms") or {}
    if al.get("red"):
        add("crit", "Chassis alarm", f"{al.get('red_count') or ''} red alarm(s)".strip())
    if al.get("yellow"):
        add("warn", "Chassis alarm", f"{al.get('yellow_count') or ''} yellow alarm(s)".strip())
    for f in nv.get("frus") or []:
        if f["offline"]:
            add("warn", "FRU", f"{f['name']} {f['state']}")
    down = [p for p in nv.get("bgp") or [] if p["enabled"] and not p["up"]]
    if down:
        add("warn", "BGP", ", ".join(f"{p['peer']} {p['state']}" for p in down[:5]) + (f" (+{len(down) - 5})" if len(down) > 5 else ""))
    od = [n for n in nv.get("ospf") or [] if n["down"]]
    if od:
        add("warn", "OSPF", "neighbour(s) down: " + ", ".join(n["neighbour"] for n in od[:5]))


def chips(nv: dict) -> list[str]:
    """Short readings for the dashboard's chips: CPU, memory, temperature, stack and neighbours."""
    out = []
    cpus = [c.get("pct_5m") for c in nv.get("cpu") or [] if c.get("pct_5m") is not None]
    cpus += [c["cpu_pct"] for c in nv.get("components") or [] if c.get("cpu_pct") and "routing engine" in c["name"].lower()]
    if cpus:
        out.append(f"CPU {max(cpus)}%")
    mems = [100 * m["used"] / ((m["used"] or 0) + (m["free"] or 0)) for m in nv.get("memory") or []
            if (m.get("used") or 0) + (m.get("free") or 0) and not IO_POOL.search(m.get("name") or "")]
    mems += [c["mem_pct"] for c in nv.get("components") or [] if c.get("mem_pct") and "routing engine" in c["name"].lower()]
    if mems:
        out.append(f"memory {max(mems):.0f}%")
    temps = [e["celsius"] for e in nv.get("env") or [] if e.get("celsius") is not None]
    temps += [c["celsius"] for c in nv.get("components") or [] if c.get("celsius")]
    if temps:
        out.append(f"{max(temps)} °C")
    if nv.get("stack"):
        out.append(f"stack of {len(nv['stack'])}")
    if nv.get("bgp"):
        out.append(f"BGP {sum(p['up'] for p in nv['bgp'])}/{len(nv['bgp'])}")
    if nv.get("ospf"):
        out.append(f"OSPF {sum(n['neighbour'] != '' and not n['down'] for n in nv['ospf'])} up")
    return out
