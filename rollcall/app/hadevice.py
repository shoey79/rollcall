"""A Home Assistant device linked to a Rollcall computer: its entities as they are now, and what
Rollcall makes of them. Integrations Rollcall knows (Pi-hole so far) get headline tiles and
alerts; any other device gets its entities listed, an alert if Home Assistant has lost touch with
it, and any "problem" binary sensors that are on."""
from __future__ import annotations

import re

KNOWN = {"pi_hole": "Pi-hole"}
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


def read(dev: dict, ents: list[dict], states: dict) -> dict:
    platforms = sorted({e.get("platform") or "" for e in ents} - {""})
    out_ents = []
    for e in ents:
        st = states.get(e.get("entity_id")) or {}
        a = st.get("attributes") or {}
        out_ents.append({
            "entity_id": e.get("entity_id"), "platform": e.get("platform"), "key": _key(e),
            "name": str(a.get("friendly_name") or e.get("name") or e.get("original_name") or e.get("entity_id")),
            "state": st.get("state") if st else "unavailable", "unit": a.get("unit_of_measurement") or "",
            "device_class": a.get("device_class") or "", "category": e.get("entity_category") or "",
            "title": a.get("title") or "", "installed": a.get("installed_version") or "", "latest": a.get("latest_version") or "",
            "changed": st.get("last_changed"),
        })
    out_ents.sort(key=lambda x: (x["category"] != "", x["entity_id"].split(".")[0] != "sensor", x["name"].lower()))
    d = {"device": {"name": dev.get("name_by_user") or dev.get("name") or "", "manufacturer": dev.get("manufacturer") or "",
                    "model": dev.get("model") or "", "sw_version": dev.get("sw_version") or "",
                    "integration": integration_name(platforms), "url": dev.get("configuration_url") or ""},
         "entities": out_ents, "tiles": [], "items": [], "summary": ""}
    items = d["items"]
    live = [e for e in out_ents if e["state"] not in UNAVAILABLE]
    if out_ents and not live:
        items.append({"level": "crit", "what": "Home Assistant", "detail": f"all {len(out_ents)} entities are unavailable: it has lost touch with the device"})
    for e in out_ents:  # generic: problem sensors and pending updates
        dom = e["entity_id"].split(".")[0]
        if dom == "binary_sensor" and e["device_class"] == "problem" and e["state"] == "on":
            items.append({"level": "warn", "what": e["name"], "detail": "reports a problem"})
        if dom == "update" and e["state"] == "on":
            items.append({"level": "info", "what": "Update available", "detail": f"{e['title'] or e['name']} {e['latest']}".strip()
                          + (f" (running {e['installed']})" if e["installed"] else "")})
    if "pi_hole" in platforms:
        _pihole(d, [e for e in out_ents if e["platform"] == "pi_hole"])
    elif not d["summary"]:
        d["summary"] = f"{len(live)} of {len(out_ents)} entities available" if out_ents else "no entities"
    return d


def _pihole(d: dict, ents: list[dict]) -> None:
    def find(dom, *words):
        for e in ents:
            if e["entity_id"].startswith(dom + ".") and any(re.search(w, e["key"]) for w in words):
                return e
        return None

    tiles, items = d["tiles"], d["items"]
    blocking = next((e for e in ents if e["entity_id"].startswith("switch.")), None)
    status = find("binary_sensor", r"\bstatus\b")
    queries = find("sensor", r"dns_queries_today|\bdns_queries\b(?!_cached|_forwarded)")
    blocked = find("sensor", r"ads_blocked")
    pct = find("sensor", r"ads_percentage")
    clients = find("sensor", r"unique_clients")
    domains = find("sensor", r"domains_being_blocked|domains_blocked")
    on = blocking["state"] if blocking else None
    if blocking:
        tiles.append({"label": "Ad blocking", "value": "On" if on == "on" else "Off" if on == "off" else str(on).title(),
                      "level": "warn" if on == "off" else "", "sub": "Pi-hole"})
        if on == "off":
            items.append({"level": "warn", "what": "Pi-hole", "detail": "ad blocking is turned off"})
    if status and status["state"] == "off":
        items.append({"level": "crit", "what": "Pi-hole", "detail": "reports that it isn't running"})
    for e, label in ((queries, "DNS queries today"), (blocked, "Blocked today"), (pct, "Blocked"), (clients, "Clients"),
                     (domains, "Domains on blocklists")):
        if e and _num(e["state"]) is not None:
            tiles.append({"label": label, "value": _num(e["state"]), "unit": e["unit"] if e["unit"] == "%" else "", "level": ""})
    bits = []
    if on in ("on", "off"):
        bits.append(f"blocking {on}")
    if queries and _num(queries["state"]) is not None:
        bits.append(f"{_num(queries['state']):,} queries today")
    if pct and _num(pct["state"]) is not None:
        bits.append(f"{_num(pct['state'])}% blocked")
    d["summary"] = "Pi-hole: " + ", ".join(bits) if bits else "Pi-hole"
