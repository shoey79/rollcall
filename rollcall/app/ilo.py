"""HPE iLO 3 and iLO 4: the server's health, read with a user name and password.

Rollcall logs in over HTTPS and sends one RIBCL request (HPE's XML scripting interface, which
both iLO 3 and iLO 4 accept as a POST to /ribcl). It asks for the embedded health (fans,
temperatures, power supplies, storage and the "health at a glance" summary), whether the
server is powered on, and the server's model and iLO firmware. iLO answers with several XML
documents one after another, one per command.

iLO 4 lists each Smart Array controller, logical drive and physical drive. iLO 3 has no
storage section; on servers with a drive backplane it lists each bay under DRIVES instead.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr

MAX_BYTES = 4 * 1024 * 1024  # the embedded health of a big server is a few hundred KB


class IloError(Exception):
    """The iLO couldn't be read. login is True when it turned the user name or password down."""

    def __init__(self, msg: str, login: bool = False):
        super().__init__(msg)
        self.login = login


def request_xml(user: str, password: str) -> bytes:
    """One RIBCL request with every command Rollcall needs, read-only."""
    return (f'<?xml version="1.0"?>\r\n<LOCFG VERSION="2.21">\r\n<RIBCL VERSION="2.0">\r\n'
            f"<LOGIN USER_LOGIN={quoteattr(user)} PASSWORD={quoteattr(password)}>\r\n"
            '<RIB_INFO MODE="read"><GET_FW_VERSION/></RIB_INFO>\r\n'
            '<SERVER_INFO MODE="read"><GET_HOST_POWER_STATUS/><GET_HOST_DATA/><GET_EMBEDDED_HEALTH/></SERVER_INFO>\r\n'
            "</LOGIN>\r\n</RIBCL>\r\n</LOCFG>\r\n").encode("utf-8")


async def poll(host: str, user: str, password: str, tls: ssl.SSLContext, timeout: float = 60.0, port: int = 443) -> dict:
    """Read the iLO. Raises IloError if it can't be reached, refuses the login or answers nonsense."""
    t0 = time.monotonic()
    body = request_xml(user, password)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=tls, server_hostname=None), min(timeout, 15))
    except asyncio.TimeoutError:
        raise IloError("no answer on HTTPS (timed out)") from None
    except ConnectionRefusedError:
        raise IloError("HTTPS connection refused") from None
    except ssl.SSLError as err:
        raise IloError(f"TLS handshake failed ({(err.reason or type(err).__name__).replace('_', ' ').lower()})") from None
    except OSError as err:
        raise IloError((err.strerror or type(err).__name__).lower()) from None
    raw = b""
    try:
        hostport = host if port == 443 else f"{host}:{port}"
        if ":" in host and not host.startswith("["):
            hostport = f"[{host}]" if port == 443 else f"[{host}]:{port}"
        writer.write((f"POST /ribcl HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: Rollcall\r\nContent-Type: text/xml\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        await writer.drain()
        while len(raw) <= MAX_BYTES and not _complete(raw):
            left = timeout - (time.monotonic() - t0)
            if left <= 0:
                raise IloError("the iLO took too long to answer")
            chunk = await asyncio.wait_for(reader.read(65536), left)
            if not chunk:
                break
            raw += chunk
    except asyncio.TimeoutError:
        raise IloError("the iLO took too long to answer") from None
    except (ssl.SSLError, OSError, asyncio.IncompleteReadError) as err:
        if not raw:
            raise IloError(f"connection closed ({type(err).__name__})") from None
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass
    if len(raw) > MAX_BYTES:
        raise IloError("the iLO's answer was too large")
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep or not head.startswith(b"HTTP/"):
        raise IloError("not an HTTP answer (is this an iLO 3 or iLO 4?)")
    status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", status)
    code = int(m.group(1)) if m else 0
    if re.search(rb"(?im)^transfer-encoding:\s*chunked", head):
        rest = _unchunk(rest)
    if code == 404:
        raise IloError("this iLO doesn't accept RIBCL over HTTPS (iLO 2 and earlier aren't supported)")
    if code and code >= 400:
        raise IloError(f"the iLO answered HTTP {code}")
    d = parse(rest.decode("utf-8", "replace"))
    d["took_ms"] = round((time.monotonic() - t0) * 1000)
    return d


def _complete(raw: bytes) -> bool:
    """The whole answer has arrived (some iLOs keep the connection open despite Connection: close)."""
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        return False
    m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
    if m:
        return len(rest) >= int(m.group(1))
    if re.search(rb"(?im)^transfer-encoding:\s*chunked", head):
        return rest.endswith(b"\r\n0\r\n\r\n") or rest == b"0\r\n\r\n"
    return False


def _unchunk(data: bytes) -> bytes:
    out, i = b"", 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(data[i:j].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if n == 0:
            break
        out += data[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return out


# -- parsing ------------------------------------------------------------------------------
_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _docs(text: str) -> list[ET.Element]:
    """The XML documents in an iLO answer. iLO firmware sometimes leaves a bare & or a control
    character in a value, which isn't valid XML, so those are tidied before parsing."""
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        raise IloError("unexpected answer from the iLO")
    out = []
    for part in re.split(r"<\?xml[^>]*\?>", text):
        part = part.strip()
        if not part.startswith("<"):
            continue
        part = _CTRL.sub("", _AMP.sub("&amp;", part))
        try:
            out.append(ET.fromstring(part))
        except ET.ParseError:
            continue  # one broken document mustn't hide the others
    return out


def _v(el: ET.Element | None, tag: str) -> str:
    """The VALUE of a child element, e.g. <STATUS VALUE = "OK"/> -> "OK"."""
    if el is None:
        return ""
    c = el.find(tag)
    return (c.get("VALUE") or "").strip() if c is not None else ""


def _num(s: str) -> float | None:
    m = re.match(r"\s*(-?\d+(?:\.\d+)?)", s or "")
    return float(m.group(1)) if m else None


def parse(text: str) -> dict:
    """Turn the iLO's answer into Rollcall's view of it. Raises IloError if there's no health data."""
    docs = _docs(text)
    if not docs:
        raise IloError("not a RIBCL answer (is this an iLO 3 or iLO 4?)")
    errors, health = [], None
    d: dict = {"fans": [], "temps": [], "psus": [], "controllers": [], "backplanes": [], "glance": [], "power_summary": {}}
    for doc in docs:
        for r in doc.iter("RESPONSE"):
            st = (r.get("STATUS") or "0x0000").strip().lower()
            if st not in ("0x0000", "0x0", "0"):
                errors.append((st, (r.get("MESSAGE") or "").strip()))
        fw = doc.find(".//GET_FW_VERSION")
        if fw is not None:
            d["ilo"] = (fw.get("MANAGEMENT_PROCESSOR") or "").strip()[:20]
            d["firmware"] = (fw.get("FIRMWARE_VERSION") or "").strip()[:40]
        pw = doc.find(".//GET_HOST_POWER")
        if pw is not None:
            d["power"] = (pw.get("HOST_POWER") or "").strip().upper()[:10]
        for rec in doc.iter("SMBIOS_RECORD"):
            if rec.get("TYPE") == "1":
                for f in rec.iter("FIELD"):
                    if f.get("NAME") == "Product Name":
                        d["model"] = (f.get("VALUE") or "").strip()[:80]
        if health is None:
            health = doc.find(".//GET_EMBEDDED_HEALTH_DATA")
            if health is None and doc.tag == "GET_EMBEDDED_HEALTH_DATA":
                health = doc
    if health is None:
        for code, msg in errors:
            if code in ("0x005f", "0x005a") or re.search(r"login|credential|password|user", msg, re.I):
                raise IloError("the iLO refused the user name or password", login=True)
        if errors:
            raise IloError(f"the iLO said: {errors[0][1] or errors[0][0]}"[:200])
        raise IloError("no health data in the iLO's answer")
    _parse_health(health, d)
    return d


def _parse_health(h: ET.Element, d: dict) -> None:
    for f in h.findall("./FANS/FAN"):
        d["fans"].append({"label": _v(f, "LABEL")[:60], "zone": _v(f, "ZONE")[:40], "status": _v(f, "STATUS")[:40],
                          "speed": _v(f, "SPEED")[:20], "unit": ((f.find("SPEED").get("UNIT") or "") if f.find("SPEED") is not None else "")[:12]})
    for t in h.findall("./TEMPERATURE/TEMP"):
        d["temps"].append({"label": _v(t, "LABEL")[:60], "location": _v(t, "LOCATION")[:40], "status": _v(t, "STATUS")[:40],
                           "reading": _num(_v(t, "CURRENTREADING")), "caution": _num(_v(t, "CAUTION")), "critical": _num(_v(t, "CRITICAL"))})
    ps = h.find("./POWER_SUPPLIES")
    if ps is not None:
        summ = ps.find("POWER_SUPPLY_SUMMARY")
        if summ is not None:
            d["power_summary"] = {"reading": _v(summ, "PRESENT_POWER_READING")[:30], "redundancy": _v(summ, "POWER_SYSTEM_REDUNDANCY")[:40]}
        for s in ps.findall("SUPPLY"):
            d["psus"].append({"label": _v(s, "LABEL")[:60], "present": _v(s, "PRESENT")[:10], "status": _v(s, "STATUS")[:60],
                              "model": _v(s, "MODEL")[:40], "capacity": _v(s, "CAPACITY")[:20]})
        for b in ps.findall("SMART_STORAGE_BATTERY"):
            d.setdefault("batteries", []).append({"label": _v(b, "LABEL")[:60], "present": _v(b, "PRESENT")[:10], "status": _v(b, "STATUS")[:60]})
    for c in h.findall("./STORAGE/CONTROLLER"):
        ctl = {"label": _v(c, "LABEL")[:80], "model": _v(c, "MODEL")[:60], "status": _v(c, "STATUS")[:40],
               "controller_status": _v(c, "CONTROLLER_STATUS")[:40], "cache": _v(c, "CACHE_MODULE_STATUS")[:40],
               "firmware": _v(c, "FW_VERSION")[:20], "logical": [], "drives": [], "enclosures": []}
        for e in c.findall("DRIVE_ENCLOSURE"):
            ctl["enclosures"].append({"label": _v(e, "LABEL")[:60], "status": _v(e, "STATUS")[:40], "bays": _v(e, "DRIVE_BAY")[:10]})
        for ld in c.findall("LOGICAL_DRIVE"):
            ctl["logical"].append({"label": _v(ld, "LABEL")[:40], "status": _v(ld, "STATUS")[:60], "capacity": _v(ld, "CAPACITY")[:20],
                                   "raid": _v(ld, "FAULT_TOLERANCE")[:30],
                                   "drives": [_drive(p) for p in ld.findall("PHYSICAL_DRIVE")]})
        for p in c.findall("PHYSICAL_DRIVE"):  # not in a logical drive (spares, unassigned)
            ctl["drives"].append(_drive(p))
        d["controllers"].append(ctl)
    # iLO 3 (and some iLO 4 firmware without storage data): drive bays on each backplane, as a flat list
    for bp in h.findall("./DRIVES/BACKPLANE"):
        plane = {"enclosure": _v(bp, "ENCLOSURE_ADDR")[:20], "firmware": _v(bp, "FIRMWARE_VERSION")[:20], "bays": []}
        cur = None
        for el in bp:
            if el.tag == "DRIVE_BAY":
                cur = {"bay": (el.get("VALUE") or "").strip()[:10]}
                plane["bays"].append(cur)
            elif cur is not None and el.tag in ("PRODUCT_ID", "STATUS", "UID_LED"):
                cur[el.tag.lower()] = (el.get("VALUE") or "").strip()[:60]
        d["backplanes"].append(plane)
    g = h.find("./HEALTH_AT_A_GLANCE")
    if g is not None:
        for el in g:
            for attr in ("STATUS", "REDUNDANCY"):
                if el.get(attr) is not None:
                    d["glance"].append({"what": el.tag, "kind": attr.lower(), "value": el.get(attr).strip()[:40]})


def _drive(p: ET.Element) -> dict:
    return {"label": (_v(p, "LOCATION") or _v(p, "LABEL"))[:60], "status": _v(p, "STATUS")[:40], "model": _v(p, "MODEL")[:40],
            "capacity": _v(p, "CAPACITY")[:20], "media": _v(p, "MEDIA_TYPE")[:10], "config": _v(p, "DRIVE_CONFIGURATION")[:20]}


# -- judging --------------------------------------------------------------------------------
_NONE = re.compile(r"^(n/?a|not installed|not present|absent|unknown|other|not applicable|not configured|none|-|)$", re.I)
_CRIT = re.compile(r"fail|fault|critical|non-?recoverable|missing|\blost\b|offline|not functional", re.I)
_WARN = re.compile(r"degrad|predictive|rebuild|recover|caution|warning|interim|not redundant|mismatch|expanding|"
                   r"ready for|disabled|erasing|\bwait", re.I)
_OKISH = re.compile(r"^(ok|good|redundant|normal|complete|spare|discovery complete)", re.I)


def level_of(status: str) -> str | None:
    """'crit', 'warn', 'ok', or None when the status says nothing either way (absent, or text
    Rollcall doesn't know, which is shown but never alerts)."""
    s = (status or "").strip()
    if _NONE.match(s):
        return None
    if _CRIT.search(s) and not re.search(r"predictive", s, re.I):
        return "crit"
    if _WARN.search(s):
        return "warn"
    if _OKISH.match(s):
        return "ok"
    return None


GLANCE_NAMES = {"BIOS_HARDWARE": "BIOS/hardware", "FANS": "Fans", "TEMPERATURE": "Temperatures", "POWER_SUPPLIES": "Power supplies",
                "PROCESSOR": "Processors", "MEMORY": "Memory", "NETWORK": "Network", "STORAGE": "Storage", "BATTERY": "Storage battery",
                "VRM": "Voltage regulators"}
GLANCE_GROUP = {"FANS": "fans", "TEMPERATURE": "temps", "POWER_SUPPLIES": "psus", "STORAGE": "storage", "BATTERY": "battery"}


def _name(word: str, label: str) -> str:
    """"Fan 1" stays "Fan 1"; "01-Inlet Ambient" becomes "Temperature 01-Inlet Ambient"."""
    return label if label.lower().startswith(word.lower()) else f"{word} {label}".strip()


def evaluate(d: dict) -> list[dict]:
    """Problems in an iLO reading: [{"level": "warn"|"crit", "what", "detail", "group"}]. "what"
    names the part (e.g. "Drive Port 1I Box 1 Bay 2") and stays the same between readings, so it
    can be acknowledged or ignored."""
    items: list[dict] = []

    def add(level, what, detail, group):
        if level not in ("warn", "crit"):
            return
        old = next((i for i in items if i["what"] == what[:100]), None)
        if old is None:
            items.append({"level": level, "what": what[:100], "detail": detail[:160], "group": group})
        elif level == "crit" and old["level"] == "warn":  # the same part reported twice: the worse one counts
            old.update(level=level, detail=detail[:160])

    if d.get("power") == "OFF":
        add("warn", "Server", "powered off", "power")
    for f in d.get("fans") or []:
        add(level_of(f["status"]), _name("Fan", f["label"]), f["status"], "fans")
    for t in d.get("temps") or []:
        lvl, r = level_of(t["status"]), t.get("reading")
        if r is not None and r > 0:
            if t.get("critical") and t["critical"] > 0 and r >= t["critical"]:
                lvl = "crit"
            elif t.get("caution") and t["caution"] > 0 and r >= t["caution"] and lvl != "crit":
                lvl = "warn"
        lim = t.get("critical") if lvl == "crit" and t.get("critical") else t.get("caution")
        add(lvl, _name("Temperature", t["label"]), f"{r:g}°C" + (f" (limit {lim:g}°C)" if lim else "") if r is not None else t["status"], "temps")
    for p in d.get("psus") or []:
        if p.get("present", "").lower() == "no":
            continue
        add(level_of(p["status"]), _name("Power supply", p["label"]), p["status"], "psus")
    for b in d.get("batteries") or []:
        if b.get("present", "").lower() != "no":
            add(level_of(b["status"]), _name("Storage battery", b["label"]), b["status"], "battery")
    red = (d.get("power_summary") or {}).get("redundancy") or ""
    if level_of(red) in ("warn", "crit") and len([p for p in d.get("psus") or [] if p.get("present", "").lower() != "no"]) != 1:
        add("warn", "Power redundancy", red, "psus")
    many = len(d.get("controllers") or []) > 1
    for c in d.get("controllers") or []:
        cname = c["label"] or c["model"] or "controller"
        for field in ("status", "controller_status"):
            add(level_of(c[field]), f"Controller {cname}", c[field], "storage")
        lc = level_of(c["cache"])
        add(lc, f"Cache {cname}", c["cache"], "storage")
        for e in c.get("enclosures") or []:
            add(level_of(e["status"]), _name("Enclosure", e["label"]), e["status"], "storage")
        for ld in c.get("logical") or []:
            add(level_of(ld["status"]), f"Logical drive {ld['label']}" + (f" ({cname})" if many else ""),
                ld["status"] + (f", {ld['raid']}" if ld.get("raid") else ""), "storage")
            for p in ld.get("drives") or []:
                add(level_of(p["status"]), _name("Drive", p["label"]) + (f" ({cname})" if many else ""),
                    p["status"] + (f" ({p['model']})" if p.get("model") else ""), "storage")
        for p in c.get("drives") or []:
            add(level_of(p["status"]), _name("Drive", p["label"]) + (f" ({cname})" if many else ""),
                p["status"] + (f" ({p['model']})" if p.get("model") else ""), "storage")
    for bp in d.get("backplanes") or []:
        for b in bp.get("bays") or []:
            where = f"Drive bay {b.get('bay')}" + (f" (box {bp['enclosure']})" if bp.get("enclosure") and len(d["backplanes"]) > 1 else "")
            add(level_of(b.get("status") or ""), where, (b.get("status") or "") + (f" ({b['product_id']})" if b.get("product_id") else ""), "storage")
    # The summary: only for parts without detail above (e.g. memory), or when the detail found nothing
    covered = {i["group"] for i in items}
    for g in d.get("glance") or []:
        group = GLANCE_GROUP.get(g["what"], g["what"].lower())
        name = GLANCE_NAMES.get(g["what"], g["what"].replace("_", " ").capitalize())
        if g["kind"] == "redundancy":
            if g["what"] == "POWER_SUPPLIES" and len([p for p in d.get("psus") or [] if p.get("present", "").lower() != "no"]) == 1:
                continue  # a server with one power supply is never redundant
            what = {"FANS": "Fan redundancy", "POWER_SUPPLIES": "Power redundancy"}.get(g["what"], f"{name} redundancy")
            add("warn" if level_of(g["value"]) in ("warn", "crit") else None, what, g["value"], group)
        elif group not in covered:
            add(level_of(g["value"]), name, g["value"], group)
    return items


def summary(d: dict) -> str:
    """One line for a healthy server, e.g. "8 drives OK, 6 fans, 2 power supplies, 21°C inlet"."""
    bits = []
    drives = [p for c in d.get("controllers") or [] for ld in c.get("logical") or [] for p in ld.get("drives") or []]
    drives += [p for c in d.get("controllers") or [] for p in c.get("drives") or []]
    bays = [b for bp in d.get("backplanes") or [] for b in bp.get("bays") or [] if level_of(b.get("status") or "")]
    if drives or bays:
        bits.append(f"{len(drives) + len(bays)} drive{'s' if len(drives) + len(bays) != 1 else ''} OK")
    if d.get("fans"):
        bits.append(f"{len(d['fans'])} fan{'s' if len(d['fans']) != 1 else ''}")
    psus = [p for p in d.get("psus") or [] if p.get("present", "").lower() != "no"]
    if psus:
        bits.append(f"{len(psus)} power suppl{'ies' if len(psus) != 1 else 'y'}")
    inlet = next((t for t in d.get("temps") or [] if re.search(r"inlet|ambient", t["label"], re.I) and t.get("reading")), None)
    if inlet:
        bits.append(f"{inlet['reading']:g}°C inlet")
    if d.get("power") == "ON" and not bits:
        bits.append("powered on")
    return ", ".join(bits) or "answering"
