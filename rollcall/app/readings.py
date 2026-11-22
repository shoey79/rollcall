"""Readings as chips: any number an integration reads can be its own check on the device's row, with its value, and
optionally a condition that makes it a problem, e.g. Starlink's "Latency > 80" or "Rotation off > 15".

A reading check is written `reading:<source>.<reading>` with an optional condition (as for Home Assistant sensors):
`Latency=reading:starlink.latency>80`. Its value comes from the source's latest reading (the Starlink, Jellyfin, Plex,
iLO or UPS check on the same device), so it asks the device nothing extra. Linked Home Assistant devices' readings are
Home Assistant sensors, so they're added as `ha:` checks instead (the same picker offers them).
"""
from __future__ import annotations

import re

SOURCES = {"starlink": "Starlink", "jellyfin": "Jellyfin", "plex": "Plex", "ilo": "iLO", "ups": "UPS"}
RE = re.compile(r"^reading:([a-z]+)\.([a-z0-9_]{1,40})\s*(?:(>=|<=|!=|>|<|=)\s*(\S.{0,60}))?$", re.I)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")[:30] or "x"


def _turn(a: dict | None) -> float | None:
    if not a or not (a.get("want_az") or a.get("want_el")):
        return None
    return round(abs((a["want_az"] - a["az"] + 180) % 360 - 180), 1)


def _num(v) -> float | None:
    m = re.search(r"-?\d+(?:\.\d+)?", str(v or ""))
    return float(m.group(0)) if m else None


def catalog(source: str, d: dict | None, extra: dict | None = None) -> list[dict]:
    """The readings one source offers from its latest data: [{id, label, unit, value}] (value None: not read)."""
    if not isinstance(d, dict):
        return []
    out: list[dict] = []

    def add(rid, label, unit, value, hint=""):
        out.append({"id": rid, "label": label, "unit": unit, "value": value, **({"hint": hint} if hint else {})})
    if source == "starlink":
        al = d.get("alignment") or None
        add("latency", "Latency", "ms", d.get("latency_ms"))
        add("drops", "Pings dropped", "%", None if d.get("drop_rate") is None else round(d["drop_rate"] * 100, 2))
        add("download", "Download", "Mb/s", None if d.get("down_bps") is None else round(d["down_bps"] / 1e6, 1))
        add("upload", "Upload", "Mb/s", None if d.get("up_bps") is None else round(d["up_bps"] / 1e6, 1))
        add("obstructed", "Obstructed", "%", None if d.get("obstructed_fraction") is None else round(d["obstructed_fraction"] * 100, 2),
            "of the time")
        su = ((extra or {}).get("map") or {}).get("summary") or {}
        add("sky_blocked", "Sky blocked", "%", su.get("blocked_pct"), "of the sky seen, from the obstruction map")
        add("uptime", "Uptime", "h", None if d.get("uptime_s") is None else round(d["uptime_s"] / 3600, 1))
        add("rotation_off", "Rotation off", "°", _turn(al), "from where the dish wants to face")
        add("elevation_off", "Elevation off", "°", None if _turn(al) is None else round(abs(al["want_el"] - al["el"]), 1),
            "from where the dish wants to point")
        add("ethernet", "Ethernet", "Mb/s", d.get("eth_mbps"))
        add("signal", "Signal", "", None if d.get("snr_ok") is None and not d.get("snr_low") else
            ("weak" if d.get("snr_low") or d.get("snr_ok") is False else "ok"))
        add("update", "Update", "", "waiting" if d.get("update_ready") else "none")
    elif source in ("jellyfin", "plex"):
        add("streams", "Streams", "", d.get("streams"))
        add("transcodes", "Transcoding", "", d.get("transcodes"))
        add("users", "Users watching", "", d.get("users"))
        if source == "jellyfin":
            add("failed_tasks", "Failed tasks", "", len(d.get("failed_tasks") or []) if d.get("tasks_read", True) else None)
        add("update", "Update", "", "available" if d.get("update") else "none")
    elif source == "ilo":
        add("power", "Power", "W", _num((d.get("power_summary") or {}).get("reading")))
        for t in d.get("temps") or []:
            if t.get("reading") is not None and t.get("label"):
                add("temp_" + _slug(t["label"]), f"Temp {t['label']}", "°C", t["reading"])
        for f in d.get("fans") or []:
            if f.get("label") and _num(f.get("speed")) is not None:
                add("fan_" + _slug(f["label"]), f"{f['label']}", f.get("unit") or "%", _num(f.get("speed")))
    elif source == "ups":
        u = d.get("ups") or {}
        if u:
            add("charge", "Battery charge", "%", u.get("charge_pct"))
            add("runtime", "Runtime", "min", u.get("runtime_min"))
            add("load", "Load", "%", u.get("load_pct"))
            add("battery_temp", "Battery temp", "°C", u.get("battery_temp_c"))
            add("input_v", "Input", "V", u.get("input_v"))
            add("on_battery", "On battery", "", "yes" if u.get("on_battery") else "no")
    return out


def available(h) -> list[dict]:
    """Every reading this device's integrations offer now, with its source: for the picker in Edit."""
    kinds = {s.kind for s in h.services}
    out = []
    for src, data, extra in (("starlink", getattr(h, "sl_data", None), {"map": getattr(h, "sl_map", None)}),
                             ("jellyfin", getattr(h, "jf_data", None), None), ("plex", getattr(h, "px_data", None), None),
                             ("ilo", getattr(h, "ilo_data", None), None), ("ups", getattr(h, "snmp_data", None), None)):
        if {"ups": "snmp"}.get(src, src) not in kinds:
            continue
        for r in catalog(src, data, extra):
            out.append({"source": src, "source_name": SOURCES[src], **r})
    return out


def lookup(h, source: str, rid: str) -> dict | None:
    return next((r for r in available(h) if r["source"] == source and r["id"] == rid), None)


def shown(r: dict) -> str:
    v, u = r.get("value"), r.get("unit") or ""
    if v is None:
        return "no reading"
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v}{'' if not u else ('' if u in ('%', '°', '°C') else ' ') + u}"


def judge(r: dict | None, op: str | None, value: str | None) -> tuple[bool, str]:
    """(ok, what to show) for one reading against its condition. The condition describes a problem: met means
    failing. No reading yet isn't a problem (the source's own check says why)."""
    if r is None:
        return True, "not read yet"
    text = shown(r)
    if r.get("value") is None or not op:
        return True, text
    v = r["value"]
    if op in ("=", "!="):
        try:
            hit = float(v) == float(value)
        except (TypeError, ValueError):
            hit = str(v).lower() == str(value).lower()
        bad = hit if op == "=" else not hit
    else:
        try:
            x, limit = float(v), float(value)
        except (TypeError, ValueError):
            return False, f"{text} (not a number)"
        bad = {">": x > limit, ">=": x >= limit, "<": x < limit, "<=": x <= limit}[op]
    ops = {">": "above", ">=": "at or above", "<": "below", "<=": "at or below", "=": "is", "!=": "isn't"}
    return (not bad), text + (f" ({ops[op]} {value})" if bad else "")
