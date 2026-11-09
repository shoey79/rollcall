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
    ntp = max((r for r in logs.query(key, since=now - 7 * DAY, q="ntp server", limit=50)
               if _NTP_OK.search(r["msg"]) or _NTP_FAIL.search(r["msg"])), key=lambda r: r["ts"], default=None)
    if ntp:
        ok = bool(_NTP_OK.search(ntp["msg"]))
        out["status"].append({"label": "Time sync (NTP)", "value": "OK" if ok else "failed", "ok": ok, "at": ntp["ts"]})
    fw = logs.query(key, since=now - 7 * DAY, q="version_is_latest", limit=20)
    if fw:
        out["status"].append({"label": "Firmware check", "value": "up to date", "ok": True, "at": max(r["ts"] for r in fw)})
    return out
