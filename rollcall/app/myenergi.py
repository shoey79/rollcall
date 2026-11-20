"""myenergi (the HACS "myenergi" integration): a Zappi EV charger, the hub, and Harvi wireless clamp senders,
which Home Assistant shows as separate devices. Linked together to one Rollcall device (1.93.0) they get tiles and
alerts here, on top of what hadevice.py does for any device.

Readings are found by what they measure, from the end of their names (e.g. "plug_status"), so renaming a device in
Home Assistant, or a serial number in an entity id, makes no difference.

- A Zappi fault (plug status "Fault/Restart") is red, so it alerts.
- An update available, or the grid supply outside the UK's limits (230 V +10%/-6%: 216-253 V; 49.5-50.5 Hz), is
  amber: worth a look, no alert.
- Generation is shown as myenergi measures it and never alerted on: a "generation" clamp can also see a home
  battery discharging, so it isn't necessarily solar.
- The integration reads myenergi's cloud, so when Home Assistant loses touch it may be myenergi's servers
  (hadevice.py says so).
"""
from __future__ import annotations

import re

from hadevice import UNAVAILABLE

VOLTS = (216.0, 253.0)
HERTZ = (49.5, 50.5)


def _find(ents, dom, pattern, exclude=None):
    """The first entity in a domain whose name ends with the pattern, as whole words. exclude: endings that also
    end with it but are something else (asking for "status" mustn't find "plug_status")."""
    rx = re.compile(r"(?:^|[ _])(?:" + pattern + r")$")
    nx = re.compile(r"(?:^|[ _])(?:" + exclude + r")$") if exclude else None
    for e in ents:
        if not e["entity_id"].startswith(dom + "."):
            continue
        names = [e["entity_id"].split(".", 1)[1].lower()] + e["key"].split()
        if any(rx.search(n) and not (nx and nx.search(n)) for n in names):
            return e
    return None


def _val(e):
    """A live reading's number (to 2 decimals, as myenergi gives kWh), or None."""
    if not e or e["state"] in UNAVAILABLE:
        return None
    try:
        f = round(float(e["state"]), 2)
    except (TypeError, ValueError):
        return None
    return int(f) if f.is_integer() else f


def _text(e):
    return str(e["state"]) if e and e["state"] not in UNAVAILABLE else None


def _watts(e):
    """A power reading in W (some are kW)."""
    v = _val(e)
    if v is None:
        return None
    return v * 1000 if (e.get("unit") or "").lower() == "kw" else v


def _kw(w):
    return f"{w / 1000:.2f} kW" if abs(w) >= 1000 else f"{round(w)} W"


def _kind(dev: dict, ents: list) -> str:
    model = f"{dev.get('model', '')} {dev.get('name', '')}".lower()
    if "zappi" in model or _find(ents, "sensor", "plug_status"):
        return "zappi"
    if "harvi" in model:
        return "harvi"
    if "hub" in model or _find(ents, "sensor", "voltage_grid|grid_import_today|hub_firmware"):
        return "hub"
    return "other"


def profile(d: dict, parts: list) -> None:
    """Tiles, problems and a summary from the myenergi devices linked here. parts: [(device info, its myenergi
    entities)]."""
    by = {}
    for dev, ents in parts:
        by.setdefault(_kind(dev, ents), []).append((dev, ents))
    tiles, items, summary = d["tiles"], d["items"], []
    zappis = by.get("zappi", [])
    for dev, z in zappis:
        name = dev.get("name") or "Zappi"
        status, plug = _find(z, "sensor", "status", exclude="plug_status"), _find(z, "sensor", "plug_status")
        mode, locked = _find(z, "select", "charge_mode"), _find(z, "binary_sensor", "locked")
        power, session = _find(z, "sensor", "power_ct_internal_load"), _find(z, "sensor", "charge_added_session")
        used, green = _find(z, "sensor", "energy_used_today"), _find(z, "sensor", "green_energy_today")
        update = _find(z, "binary_sensor", "update_available")
        st, pl = _text(status), _text(plug)
        fault = bool(pl and "fault" in pl.lower()) or bool(st and "fault" in st.lower())
        label = name if len(zappis) > 1 else "Zappi"
        if st or pl:
            tiles.append({"label": label, "value": st or pl, "sub": pl if st and pl else "", "level": "crit" if fault else ""})
        if fault:
            items.append({"level": "crit", "what": name, "detail": f"reports a fault ({pl or st}): check the charger, and the myenergi app"})
        if _text(mode):
            tiles.append({"label": "Mode", "value": _text(mode), "level": ""})
        w = _watts(power)
        if w is not None:
            tiles.append({"label": "Charging now", "value": _kw(max(w, 0)), "sub": "the Zappi's own clamp", "level": ""})
        if _val(session) is not None:
            tiles.append({"label": "Added this session", "value": f"{_val(session)} kWh", "level": ""})
        if _val(used) is not None:
            tiles.append({"label": "Charged today", "value": f"{_val(used)} kWh",
                          "sub": f"{_val(green)} kWh green" if _val(green) is not None else "", "level": ""})
        if _text(locked) in ("on", "off"):
            tiles.append({"label": "Charger", "value": "Locked" if _text(locked) == "on" else "Unlocked", "level": ""})
        if _text(update) == "on":
            items.append({"level": "warn", "what": name, "detail": "a firmware update is available (update it in the myenergi app)"})
        summary.append(", ".join(x for x in ((f"{label} {st.lower()}" if st else label) + (f" ({pl})" if pl else ""), _text(mode)) if x))

    hubs = by.get("hub", [])
    hub = [e for _, ents in hubs for e in ents]
    zappi = [e for _, ents in zappis for e in ents]
    # Grid and generation now: the hub's totals if it's linked (they already include every clamp), else the
    # clamps on the Zappi and Harvis themselves.
    grid = _watts(_find(hub, "sensor", "power_grid")) if hub else None
    if grid is None:
        grid = _watts(_find(zappi, "sensor", "power_ct_grid"))
    if grid is not None:
        tiles.append({"label": "Grid now", "value": _kw(abs(grid)), "sub": "exporting" if grid < 0 else "importing" if grid > 0 else "", "level": ""})
    home = _watts(_find(hub, "sensor", "home_consumption"))
    if home is not None:
        tiles.append({"label": "Home using", "value": _kw(home), "level": ""})
    gen = _watts(_find(hub, "sensor", "power_generation")) if hub else None
    if gen is None:
        clamps = [_watts(_find(ents, "sensor", "power_ct_generation")) for _, ents in zappis + by.get("harvi", [])]
        clamps = [c for c in clamps if c is not None]
        gen = sum(clamps) if clamps else None
    if gen is not None:
        tiles.append({"label": "Generation", "value": _kw(gen), "sub": "as myenergi measures it", "level": ""})
    volts, hz = _val(_find(hub, "sensor", "voltage_grid")), _val(_find(hub, "sensor", "frequency_grid"))
    if volts is not None or hz is not None:
        off_v = volts is not None and not VOLTS[0] <= volts <= VOLTS[1]
        off_hz = hz is not None and not HERTZ[0] <= hz <= HERTZ[1]
        tiles.append({"label": "Supply", "value": f"{volts} V" if volts is not None else f"{hz} Hz",
                      "sub": f"{hz} Hz" if volts is not None and hz is not None else "", "level": "warn" if off_v or off_hz else ""})
        if off_v:
            items.append({"level": "warn", "what": "Grid supply", "detail": f"{volts} V, outside the UK supply range ({VOLTS[0]:g}-{VOLTS[1]:g} V)"})
        if off_hz:
            items.append({"level": "warn", "what": "Grid supply", "detail": f"{hz} Hz, outside {HERTZ[0]}-{HERTZ[1]} Hz"})
        if volts is not None:
            summary.append(f"grid {volts} V")
    imp, exp = _val(_find(hub, "sensor", "grid_import_today")), _val(_find(hub, "sensor", "grid_export_today"))
    made = _val(_find(hub, "sensor", "generated_today"))
    if imp is not None or exp is not None:
        tiles.append({"label": "Grid today", "value": f"{imp if imp is not None else '—'} kWh in",
                      "sub": " · ".join(x for x in (f"{exp} kWh out" if exp is not None else "",
                                                     f"{made} kWh generated" if made is not None else "") if x), "level": ""})
    for dev, ents in hubs + by.get("harvi", []):
        if _text(_find(ents, "binary_sensor", "update_available")) == "on":
            items.append({"level": "warn", "what": dev.get("name") or "myenergi", "detail": "a firmware update is available (update it in the myenergi app)"})
    d["summary"] = "myenergi: " + "; ".join(summary) if summary else "myenergi"
