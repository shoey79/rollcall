"""The Home Assistant devices linked to a Rollcall device: their entities as they are now, and what
Rollcall makes of them. Integrations Rollcall knows (Pi-hole, myenergi) get headline tiles and
alerts; any other device gets its entities listed, an alert if Home Assistant has lost touch with
it, and any "problem" binary sensors that are on. A Rollcall device can link several Home Assistant
devices (1.93.0), e.g. the Zappi, hub and Harvi that the myenergi integration makes for one system."""
from __future__ import annotations

import re

KNOWN = {"pi_hole": "Pi-hole", "pi_hole_v6": "Pi-hole (V6, from HACS)", "myenergi": "myenergi"}
PIHOLE = ("pi_hole", "pi_hole_v6")
UNAVAILABLE = ("unavailable", "unknown", "", None)


def integration_name(platforms) -> str:
    for p in platforms:
        if p in KNOWN:
            return KNOWN[p]
    return ", ".join(p.replace("_", " ").title() for p in platforms)[:60]


def _key(e: dict) -> str:
    """What an entity measures, from its translation key, unique id or entity id."""
    tk = e.get("translation_key") or ""
    uid = str(e.get("unique_id") or "")
    uid = uid.rsplit("/", 1)[-1] if "/" in uid else ""
    return " ".join(x for x in (tk, uid, e.get("entity_id", "").split(".", 1)[-1]) if x).lower()


def _num(v):
    try:
        f = float(v)
        return int(f) if f.is_integer() else round(f, 1)
    except (TypeError, ValueError):
        return None


def _entities(ents: list[dict], states: dict) -> list[dict]:
    out = []
    for e in ents:
        st = states.get(e.get("entity_id")) or {}
        a = st.get("attributes") or {}
        out.append({
            "entity_id": e.get("entity_id"), "platform": e.get("platform"), "key": _key(e),
            "name": str(a.get("friendly_name") or e.get("name") or e.get("original_name") or e.get("entity_id")),
            "state": st.get("state") if st else "unavailable", "unit": a.get("unit_of_measurement") or "",
            "device_class": a.get("device_class") or "", "category": e.get("entity_category") or "",
            "title": a.get("title") or "", "installed": a.get("installed_version") or "", "latest": a.get("latest_version") or "",
            "changed": st.get("last_changed"),
        })
    out.sort(key=lambda x: (x["category"] != "", x["entity_id"].split(".")[0] != "sensor", x["name"].lower()))
    return out


def _device(dev: dict, ents: list[dict]) -> dict:
    platforms = sorted({e.get("platform") or "" for e in ents} - {""})
    return {"name": dev.get("name_by_user") or dev.get("name") or "", "manufacturer": dev.get("manufacturer") or "",
            "model": dev.get("model") or "", "sw_version": dev.get("sw_version") or "",
            "integration": integration_name(platforms), "url": dev.get("configuration_url") or ""}


def read(dev: dict, ents: list[dict], states: dict) -> dict:
    """One linked device (as before 1.93.0)."""
    return read_many([(dev, ents)], states)


def read_many(parts: list, states: dict, missing: list | None = None) -> dict:
    """The Home Assistant devices linked to one Rollcall device, e.g. the myenergi integration's Zappi, hub and
    Harvi: each one's entities under its own heading ("devices"), and what Rollcall makes of them all together
    (tiles, problems, a summary). parts: [(device registry entry, its entity registry entries)], first one the
    main device. missing: names of linked devices no longer in Home Assistant."""
    devices = [{"device": _device(dev, ents), "entities": _entities(ents, states)} for dev, ents in parts]
    every = [e for d in devices for e in d["entities"]]
    platforms = sorted({e["platform"] or "" for e in every} - {""})
    d = {"device": dict(devices[0]["device"]) if devices else {"name": "", "manufacturer": "", "model": "", "sw_version": "", "integration": "", "url": ""},
         "devices": devices, "entities": every, "tiles": [], "items": [], "summary": ""}
    if len(devices) > 1:
        d["device"]["integration"] = integration_name(platforms)
    items = d["items"]
    for name in missing or []:
        items.append({"level": "warn", "what": name or "Linked device", "detail": "is no longer in Home Assistant (Edit to link it again)"})
    many = len(devices) > 1
    for part in devices:
        ents = part["entities"]
        live = [e for e in ents if e["state"] not in UNAVAILABLE]
        if ents and not live:
            lost = f"all {len(ents)} entities are unavailable: it has lost touch with the device"
            if "myenergi" in {e["platform"] for e in ents}:
                lost += " (the myenergi integration reads myenergi's cloud, so it may be myenergi's servers rather than the device)"
            items.append({"level": "crit", "what": part["device"]["name"] if many else "Home Assistant", "detail": lost})
    for e in every:  # generic: problem sensors and pending updates
        dom = e["entity_id"].split(".")[0]
        if dom == "binary_sensor" and e["device_class"] == "problem" and e["state"] == "on":
            items.append({"level": "warn", "what": e["name"], "detail": "reports a problem"})
        if dom == "update" and e["state"] == "on":
            items.append({"level": "info", "what": "Update available", "detail": f"{e['title'] or e['name']} {e['latest']}".strip()
                          + (f" (running {e['installed']})" if e["installed"] else "")})
    if any(p in platforms for p in PIHOLE):
        _pihole(d, [e for e in every if e["platform"] in PIHOLE])
    if "myenergi" in platforms:
        import myenergi  # noqa: PLC0415  (its own module: Zappi, hub, Harvi)
        myenergi.profile(d, [(p["device"], [e for e in p["entities"] if e["platform"] == "myenergi"]) for p in devices])
    if not d["summary"]:
        live = [e for e in every if e["state"] not in UNAVAILABLE]
        d["summary"] = f"{len(live)} of {len(every)} entities available" if every else "no entities"
    return d


def _pihole(d: dict, ents: list[dict]) -> None:
    def find(dom, *words):
        for e in ents:
            if e["entity_id"].startswith(dom + ".") and any(re.search(w, e["key"]) for w in words):
                return e
        return None

    tiles, items = d["tiles"], d["items"]
    # The blocking switch: the integration's only switch, or (Pi-hole V6, which adds one per group) the "global" one
    switches = [e for e in ents if e["entity_id"].startswith("switch.")]
    blocking = next((e for e in switches if re.search(r"\bglobal\b", e["key"])), None) or \
        next((e for e in switches if not re.search(r"\bgroup\b", e["key"])), None)
    status = find("binary_sensor", r"\bstatus\b")  # on while blocking is enabled
    queries = find("sensor", r"dns_queries_today|\bdns_queries\b(?!_cached|_forwarded)")
    blocked = find("sensor", r"ads_blocked")
    pct = find("sensor", r"ads_percentage")
    clients = find("sensor", r"unique_clients")
    domains = find("sensor", r"domains_being_blocked|domains_blocked")
    cpu = find("sensor", r"cpu_use")
    mem = find("sensor", r"memory_use")
    msgs = find("sensor", r"ftl_info_message_count")
    src = blocking or status
    on = src["state"] if src else None
    if src:
        tiles.append({"label": "Ad blocking", "value": "On" if on == "on" else "Off" if on == "off" else str(on).title(),
                      "level": "warn" if on == "off" else "", "sub": "Pi-hole"})
        if on == "off":
            items.append({"level": "warn", "what": "Pi-hole", "detail": "ad blocking is turned off"})
    for e, label in ((queries, "DNS queries today"), (blocked, "Blocked today"), (pct, "Blocked"), (clients, "Clients"),
                     (domains, "Domains on blocklists"), (cpu, "CPU"), (mem, "Memory")):
        if e and _num(e["state"]) is not None:
            tiles.append({"label": label, "value": _num(e["state"]), "unit": e["unit"] if e["unit"] == "%" else "", "level": ""})
    if msgs and (_num(msgs["state"]) or 0) > 0:
        items.append({"level": "info", "what": "Pi-hole", "detail": f"{_num(msgs['state'])} diagnostic message(s) in Pi-hole (Tools → Pi-hole diagnosis)"})
    bits = []
    if on in ("on", "off"):
        bits.append(f"blocking {on}")
    if queries and _num(queries["state"]) is not None:
        bits.append(f"{_num(queries['state']):,} queries today")
    if pct and _num(pct["state"]) is not None:
        bits.append(f"{_num(pct['state'])}% blocked")
    d["summary"] = "Pi-hole: " + ", ".join(bits) if bits else "Pi-hole"
