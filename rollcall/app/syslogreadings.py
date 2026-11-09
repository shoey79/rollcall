"""Readings picked out of a device's syslog messages, for the Logs tab: temperatures and fan
speeds, time sync and firmware checks. Worked out from the stored messages when asked, so
nothing extra is kept and they survive restarts.

Buffalo TeraStation / LinkStation:
  fanctld.sh  "temp0=73 temp1=38 temp2=37"   temperatures, °C
  fanctld.sh  "fan0=slow->1060"              fan mode and speed (RPM)
  linkstation "[Success] Sync to ntp server" / "[Fail] Cannot sync to ntp server"
  S40B_update_notifications.sh "version_is_latest"
"""
from __future__ import annotations

import re

DAY = 86400
_TEMP = re.compile(r"\btemp(\d+)=(-?\d+(?:\.\d+)?)\b")
_FAN = re.compile(r"\bfan(\d+)=([A-Za-z]+)->(\d+)\b")
_MEMFREE = re.compile(r"\bMemFree:\s*(\d+)\s*kB", re.I)
_MEMTOTAL = re.compile(r"\bMemTotal:\s*(\d+)\s*kB", re.I)
_BOOT = re.compile(r"\bLinux version \d|\bSystem started: ip@")
# Cisco / Linksys / Sipura SPA ATAs and phones, with Debug Level 3 and the line's SIP debug on
_REG_OK = re.compile(r"\[(\d+)\]RegOK\.?\s*NextReg in (\d+)")
_REG_FAIL = re.compile(r"\[(\d+)\]RegFail\.?\s*(.*)|REGISTER_FAIL\S*,\s*lid:\s*(\d+)")
_REG_TO = re.compile(r"\bREGISTER sip:([^\s;>]+)")


def registrations(logs, key: str, now: float) -> list[dict]:
    """Each SIP line's registration as the device logs it: registered (and when it's due again),
    failed, or lapsed (no re-registration well after it was due, while the device is still logging)."""
    ok = logs.query(key, since=now - 2 * DAY, q="RegOK", limit=40)
    fail = logs.query(key, since=now - 2 * DAY, q="RegFail", limit=40) + logs.query(key, since=now - 2 * DAY, q="REGISTER_FAIL", limit=40)
    if not ok and not fail:
        return []
    lines: dict[int, dict] = {}
    for r in ok:
        if m := _REG_OK.search(r["msg"]):
            n = int(m.group(1)) + 1
            ln = lines.setdefault(n, {"line": n})
            if r["ts"] > ln.get("ok", 0):
                ln["ok"], ln["next_in"] = r["ts"], int(m.group(2))
    for r in fail:
        if m := _REG_FAIL.search(r["msg"]):
            n = int(m.group(1) or m.group(3)) + 1
            ln = lines.setdefault(n, {"line": n})
            if r["ts"] > ln.get("fail", 0):
                ln["fail"], ln["fail_msg"] = r["ts"], (m.group(2) or "").strip()[:120]
    to = next((m.group(1) for r in logs.query(key, since=now - 2 * DAY, q="REGISTER sip:", limit=5) if (m := _REG_TO.search(r["msg"]))), "")
    _n, last_msg = logs.stats(key, now - DAY)
    out = []
    for n in sorted(lines):
        ln = lines[n]
        ok_t, fail_t = ln.get("ok"), ln.get("fail")
        state, detail = "registered", ""
        if fail_t and (not ok_t or fail_t > ok_t) and now - fail_t > 60:  # give the device a retry first
            state = "failed"
            detail = "registration failed" + (f" ({ln['fail_msg']})" if ln.get("fail_msg") else "")
        elif ok_t:
            due = ok_t + ln["next_in"]
            grace = max(300, ln["next_in"])
            if now > due + grace and last_msg and last_msg > due + grace:  # still logging, but no re-registration
                state, detail = "lapsed", "no re-registration since it was due"
        elif not ok_t:
            state = "unknown"
        out.append({"line": n, "state": state, "detail": detail, "ok": ok_t, "next_in": ln.get("next_in"),
                    "fail": fail_t, "to": to})
    return out
_NTP_OK = re.compile(r"\[success\].*ntp", re.I)
_NTP_FAIL = re.compile(r"\[fail\].*ntp", re.I)


def _series(points: list[tuple[float, float]], n: int = 48) -> list[float]:
    """Up to n values, evenly picked from oldest to newest, for a sparkline."""
    if len(points) <= n:
        return [v for _t, v in points]
    step = (len(points) - 1) / (n - 1)
    return [points[round(i * step)][1] for i in range(n)]


def _reading(label: str, unit: str, points: list[tuple[float, float]], **extra) -> dict:
    vals = [v for _t, v in points]
    return {"label": label, "unit": unit, "value": vals[-1], "at": points[-1][0], "min": min(vals), "max": max(vals),
            "count": len(vals), "series": _series(points), **extra}


def readings(logs, key: str, now: float) -> dict:
    out: dict = {"sensors": [], "status": []}
    rows = logs.query(key, since=now - DAY, q="fanctld", limit=1500)
    if rows:
        temps: dict[str, list] = {}
        fans: dict[str, list] = {}
        modes: dict[str, str] = {}
        for r in sorted(rows, key=lambda r: r["ts"]):  # oldest first
            for n, v in _TEMP.findall(r["msg"]):
                temps.setdefault(n, []).append((r["ts"], float(v) if "." in v else int(v)))
            for n, mode, rpm in _FAN.findall(r["msg"]):
                fans.setdefault(n, []).append((r["ts"], int(rpm)))
                modes[n] = mode
        for n in sorted(temps, key=int):
            out["sensors"].append(_reading(f"Temperature (temp{n})", "°C", temps[n]))
        for n in sorted(fans, key=int):
            out["sensors"].append(_reading(f"Fan {int(n) + 1}", "RPM", fans[n], mode=modes.get(n, "")))
    # Small Linux devices (e.g. Cisco SPA ATAs) that log /proc/meminfo lines every few minutes
    mem = logs.query(key, since=now - DAY, q="MemFree", limit=600)
    pts = sorted(((r["ts"], int(m.group(1))) for r in mem if (m := _MEMFREE.search(r["msg"]))), key=lambda p: p[0])
    if pts:
        total = next((int(m.group(1)) for r in logs.query(key, since=now - 7 * DAY, q="MemTotal", limit=5)
                      if (m := _MEMTOTAL.search(r["msg"]))), None)
        out["sensors"].append(_reading("Memory free", "MB", [(t, round(v / 1024, 1)) for t, v in pts],
                                       **({"of": round(total / 1024, 1)} if total else {})))
    # A kernel boot banner in the log means the device started up
    boot = max((r for r in logs.query(key, since=now - 30 * DAY, q="Linux version", limit=20) if _BOOT.search(r["msg"])),
               key=lambda r: r["ts"], default=None)
    if boot:
        out["status"].append({"label": "Last started", "value": "restarted", "ok": True, "at": boot["ts"]})
    for reg in registrations(logs, key, now):
        good = reg["state"] == "registered"
        out["status"].append({"label": f"Line {reg['line']} registration" + (f" ({reg['to']})" if reg["to"] else ""),
                              "value": "registered" if good else reg["detail"] or reg["state"], "ok": good,
                              "at": reg["ok"] if good else (reg["fail"] or reg["ok"] or now), "reg": reg})
    ntp = max((r for r in logs.query(key, since=now - 7 * DAY, q="ntp server", limit=50)
               if _NTP_OK.search(r["msg"]) or _NTP_FAIL.search(r["msg"])), key=lambda r: r["ts"], default=None)
    if ntp:
        ok = bool(_NTP_OK.search(ntp["msg"]))
        out["status"].append({"label": "Time sync (NTP)", "value": "OK" if ok else "failed", "ok": ok, "at": ntp["ts"]})
    fw = logs.query(key, since=now - 7 * DAY, q="version_is_latest", limit=20)
    if fw:
        out["status"].append({"label": "Firmware check", "value": "up to date", "ok": True, "at": max(r["ts"] for r in fw)})
    return out
