"""Agent support (Windows and Linux) for Rollcall.

- AgentStore: enrolment key, approved agents, pending requests, tokens (only
  SHA-256 hashes are stored) and each agent's last report.
- evaluate(): turns an agent report into dashboard checks (state checks such
  as disk space and services) and notable items (events, security, malware)
  that are alerted as they arrive.

Nothing here talks to Home Assistant; main.py does that.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from pathlib import Path

log = logging.getLogger("ping_monitor")

OK, WARN, CRIT = "ok", "warn", "crit"
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PENDING = 200

DEFAULT_EVENT_WATCH = ["Kernel-Power:41", "EventLog:6008", "BugCheck:1001", "disk:7", "disk:51",
                       "disk:153", "Ntfs:55", "Ntfs:98"]
DEFAULT_SECURITY_ALERT_IDS = [4740, 4720, 4726, 4728, 4732, 4756, 1102, 4719]
PASSIVE_AV_MODES = {"passive mode", "edr block mode", "sxs passive mode"}


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> float:
    return time.time()


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
class AgentStore:
    def __init__(self, path: Path, reports_dir: Path):
        self.path = path
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.data = {"enrol_key": None, "agents": {}, "pending": {}, "rejected": []}
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text()))
            except Exception as err:  # noqa: BLE001
                backup = path.with_suffix(f".bad-{int(_now())}.json")
                path.rename(backup)
                log.error("Could not read %s (%s); moved it to %s", path, err, backup.name)
        self._index()
        if not self.data.get("enrol_key"):
            self.data["enrol_key"] = secrets.token_urlsafe(24)
            self.save()
        self._index()

    def _index(self) -> None:
        self.by_hash = {a["token_hash"]: a for a in self.data["agents"].values()}
        self.pending_by_hash = {p["token_hash"]: p for p in self.data["pending"].values()}
        self.rejected = set(self.data.get("rejected") or [])

    def save(self) -> None:
        self.data["rejected"] = sorted(self.rejected)[-1000:]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        tmp.replace(self.path)
        self._index()

    # -- enrolment key ------------------------------------------------------
    @property
    def enrol_key(self) -> str:
        return self.data["enrol_key"]

    def check_key(self, key: str) -> bool:
        return hmac.compare_digest(str(key or ""), self.enrol_key)

    def rotate_key(self) -> str:
        self.data["enrol_key"] = secrets.token_urlsafe(24)
        self.save()
        return self.enrol_key

    # -- agents ---------------------------------------------------------------
    @property
    def agents(self) -> dict:
        return self.data["agents"]

    @property
    def pending(self) -> dict:
        return self.data["pending"]

    def lookup(self, token: str) -> tuple[str | None, dict | None]:
        if not TOKEN_RE.match(token or ""):
            return None, None
        h = token_hash(token)
        if h in self.by_hash:
            return "approved", self.by_hash[h]
        if h in self.pending_by_hash:
            return "pending", self.pending_by_hash[h]
        if h in self.rejected:
            return "rejected", None
        return None, None

    def request(self, info: dict, token: str, source_ip: str | None) -> tuple[str, dict | None]:
        """Record an enrolment request. Returns (status, pending_record_if_new)."""
        state, rec = self.lookup(token)
        if state in ("approved", "pending", "rejected"):
            return state, None
        hostname = info["hostname"]
        # One pending request per hostname: a newer one replaces the older.
        for pid, p in list(self.pending.items()):
            if p["hostname"].lower() == hostname.lower():
                del self.pending[pid]
        if len(self.pending) >= MAX_PENDING:
            oldest = min(self.pending.values(), key=lambda p: p["requested_at"])
            del self.pending[oldest["id"]]
        replaces = next((a["id"] for a in self.agents.values()
                         if a["hostname"].lower() == hostname.lower()), None)
        rec = {"id": secrets.token_hex(6), "token_hash": token_hash(token), "requested_at": _now(),
               "source_ip": source_ip, "replaces": replaces, **info}
        self.pending[rec["id"]] = rec
        self.save()
        return "new", rec

    def approve(self, pid: str) -> dict:
        p = self.pending.pop(pid)
        if p.get("replaces") and p["replaces"] in self.agents:
            old = self.agents.pop(p["replaces"])
            self.rejected.add(old["token_hash"])
            agent = {**old, **{k: p.get(k) for k in ("hostname", "fqdn", "ips", "os", "agent_version", "os_family")},
                     "token_hash": p["token_hash"]}
        else:
            agent = {"id": secrets.token_hex(6), "host_key": None, "last_report": None,
                     **{k: p.get(k) for k in ("hostname", "fqdn", "ips", "os", "agent_version", "os_family")},
                     "token_hash": p["token_hash"]}
        agent["approved_at"] = _now()
        self.agents[agent["id"]] = agent
        self.save()
        return agent

    def reject(self, pid: str) -> dict:
        p = self.pending.pop(pid)
        self.rejected.add(p["token_hash"])
        self.save()
        return p

    def revoke(self, aid: str) -> dict:
        a = self.agents.pop(aid)
        self.rejected.add(a["token_hash"])
        self.save()
        try:
            (self.reports_dir / f"{aid}.json").unlink()
        except FileNotFoundError:
            pass
        return a

    # -- reports -----------------------------------------------------------------
    def save_report(self, aid: str, data: dict) -> None:
        tmp = self.reports_dir / f"{aid}.tmp"
        tmp.write_text(json.dumps(data))
        tmp.replace(self.reports_dir / f"{aid}.json")

    def load_report(self, aid: str) -> dict | None:
        try:
            return json.loads((self.reports_dir / f"{aid}.json").read_text())
        except (FileNotFoundError, ValueError):
            return None


def clean_enrol_info(raw: dict) -> dict:
    """Validate the identity fields an agent sends when asking to join."""
    hostname = str(raw.get("hostname") or "").strip()
    if not HOSTNAME_RE.match(hostname):
        raise ValueError("invalid hostname")
    fqdn = str(raw.get("fqdn") or hostname).strip().lower()[:253]
    ips = [str(i) for i in (raw.get("ips") or []) if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(i))][:8]
    return {"hostname": hostname.upper(), "fqdn": fqdn, "ips": ips,
            "os": str(raw.get("os") or "")[:120], "agent_version": str(raw.get("agent_version") or "")[:20],
            "os_family": "linux" if raw.get("os_family") == "linux" else "windows"}


# --------------------------------------------------------------------------
# Report shape
# --------------------------------------------------------------------------
def _as_list(v) -> list:
    """PowerShell turns a one-item list into a bare object (and an empty one into
    null) in some places, so accept any of those wherever a list is expected."""
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if x is not None]
    return [v]


def _as_dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def normalize_report(r) -> dict:
    """Make an agent report safe to evaluate whatever PowerShell did to its lists."""
    r = _as_dict(r)
    for k in ("roles", "ips", "disks", "errors"):
        r[k] = _as_list(r.get(k))
    r["disks"] = [d for d in r["disks"] if isinstance(d, dict)]
    svc = r["services"] = _as_dict(r.get("services"))
    for k in ("watched", "stopped_auto"):
        svc[k] = [x for x in _as_list(svc.get(k)) if isinstance(x, dict)]
    ev = r["events"] = _as_dict(r.get("events"))
    ev["counts"] = {k: _as_dict(v) for k, v in _as_dict(ev.get("counts")).items()}
    ev["recent"] = [x for x in _as_list(ev.get("recent")) if isinstance(x, dict)]
    sec = r["security"] = _as_dict(r.get("security"))
    sec["items"] = [x for x in _as_list(sec.get("items")) if isinstance(x, dict)]
    fl = sec["failed_logons"] = _as_dict(sec.get("failed_logons"))
    fl["top"] = [x for x in _as_list(fl.get("top")) if isinstance(x, dict)]
    try:
        fl["count"] = int(fl.get("count") or 0)
    except (TypeError, ValueError):
        fl["count"] = 0
    c = r["checks"] = _as_dict(r.get("checks"))
    if "iis" in c:
        iis = c["iis"] = _as_dict(c["iis"])
        for k in ("app_pools", "sites"):
            iis[k] = [x for x in _as_list(iis.get(k)) if isinstance(x, dict)]
            for x in iis[k]:
                x["protocols"] = _as_list(x.get("protocols"))
    if "ad" in c:
        ad = c["ad"] = _as_dict(c["ad"])
        ad["replication"] = [x for x in _as_list(ad.get("replication")) if isinstance(x, dict)]
    for k in ("dhcp", "hyperv", "printers"):
        if k in c:
            c[k] = [x for x in _as_list(c[k]) if isinstance(x, dict)]
    if "defender" in c:
        d = c["defender"] = _as_dict(c["defender"])
        d["detections"] = [x for x in _as_list(d.get("detections")) if isinstance(x, dict)]
    if "rds" in c:
        c["rds"] = _as_dict(c["rds"])
    if "containers" in c:
        c["containers"] = [x for x in _as_list(c["containers"]) if isinstance(x, dict)]
    if "immich" in c:
        im = c["immich"] = _as_dict(c["immich"])
        im["queues"] = [x for x in _as_list(im.get("queues")) if isinstance(x, dict)]
    r["os_family"] = "linux" if r.get("os_family") == "linux" else "windows"
    t = {}
    for k, v in _as_dict(r.get("timings")).items():
        try:
            t[str(k)[:40]] = int(v)
        except (TypeError, ValueError):
            pass
    r["timings"] = t
    for k in ("run_ms", "cpu_ms", "peak_mem_mb"):
        try:
            r[k] = int(r[k]) if r.get(k) is not None else None
        except (TypeError, ValueError):
            r[k] = None
    return r


# --------------------------------------------------------------------------
# Ignore list
# --------------------------------------------------------------------------
class Ignore:
    """`agent_ignore` entries: a service name, or kind:value for other things.

    service:Name (or just Name), event:10016, apppool:Name, site:Name,
    disk:D:, dhcp:10.0.5.0, printer:Name, vm:Name
    """

    def __init__(self, entries):
        self.items: dict[str, set[str]] = {}
        for e in entries or []:
            e = str(e).strip()
            if not e:
                continue
            kind, _, value = e.partition(":") if ":" in e else ("service", "", e)
            kind = kind.lower()
            if kind not in ("service", "event", "apppool", "site", "disk", "dhcp", "printer", "vm"):
                kind, value = "service", e
            self.items.setdefault(kind, set()).add(value.strip().lower().rstrip(":"))

    def has(self, kind: str, value) -> bool:
        return str(value).strip().lower().rstrip(":") in self.items.get(kind, set())


def _watch_match(entries, source: str, event_id: int) -> bool:
    src = (source or "").lower()
    for e in entries or []:
        e = str(e).strip()
        if ":" in e:
            s, _, i = e.rpartition(":")
            if i.strip().isdigit() and int(i) == event_id and s.strip().lower() in src:
                return True
        elif e.isdigit() and int(e) == event_id:
            return True
    return False


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _check(key, label, level, detail, confirm=False, info=None):
    """confirm: a CRIT only goes red after two reports in a row (like ping)."""
    return {"key": key, "label": label, "level": level, "detail": detail, "confirm": confirm,
            "info": info or {}}


def _days_since(iso: str | None, now: float) -> float | None:
    if not iso:
        return None
    try:
        t = time.mktime(time.strptime(iso.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")) - time.timezone
        return max(0.0, (now - t) / 86400)
    except (ValueError, OverflowError):
        return None


IGNORE_KINDS = ("service", "event", "apppool", "site", "disk", "dhcp", "printer", "vm")


def disk_key(name) -> str:
    """'c', 'C:' and 'C:\\' all mean the same Windows volume; a Linux mount
    point ('/', '/srv/photos/') is kept as a path without a trailing slash."""
    s = str(name or "").strip()
    if s.startswith("/"):
        return s.rstrip("/") or "/"
    return s.rstrip("\\/").rstrip(":").upper() + ":"


def clean_ignore_item(kind: str, value: str) -> str:
    """Validate one ignore entry from the dashboard; returns 'kind:value'."""
    kind = str(kind or "").strip().lower()
    value = str(value or "").strip()
    if kind not in IGNORE_KINDS:
        raise ValueError(f"unknown kind '{kind}'")
    if not value or len(value) > 128 or any(c in value for c in "\r\n\t"):
        raise ValueError("invalid value")
    if kind == "event" and not value.isdigit():
        raise ValueError("an event must be a number")
    if kind == "disk":
        value = disk_key(value)
    return f"{kind}:{value}"


def evaluate(report: dict, opts: dict, now: float | None = None, settings: dict | None = None) -> dict:
    """Turn one agent report into {"checks": [...], "notable": {...}}.

    checks: state checks shown as chips (ok / warn / crit).
    notable: items to alert on as they arrive (events, security, malware).
    settings: per-server overrides from the dashboard:
              {"ignore": ["service:Spooler", ...], "disks": {"D:": {"warn": 8, "crit": 3}}}
    """
    now = now or _now()
    settings = settings or {}
    ign = Ignore(list(opts.get("agent_ignore") or []) + list(settings.get("ignore") or []))
    checks = []

    # Disk space: each volume against its own thresholds (dashboard override or default).
    warn_default = float(opts.get("agent_disk_warn", 15))
    crit_default = float(opts.get("agent_disk_crit", 5))
    overrides = {disk_key(k): v for k, v in (settings.get("disks") or {}).items()}
    vols = []
    for d in report.get("disks") or []:
        try:
            size, free = float(d.get("size_gb") or 0), float(d.get("free_gb") or 0)
        except (TypeError, ValueError):
            continue
        if size < 0.5 or ign.has("disk", d.get("name", "")):
            continue
        o = overrides.get(disk_key(d.get("name")), {})
        warn = float(o["warn"]) if o.get("warn") is not None else warn_default
        crit = float(o["crit"]) if o.get("crit") is not None else crit_default
        pct = round(100 * free / size, 1)
        lvl = CRIT if pct < crit else WARN if pct < warn else OK
        vols.append({"name": d.get("name"), "pct": pct, "free_gb": free, "size_gb": size,
                     "warn": warn, "crit": crit, "level": lvl})
    if vols:
        order = [OK, WARN, CRIT]
        level = max((v["level"] for v in vols), key=order.index)
        low = [v for v in vols if v["level"] != OK]
        if low:
            detail = ", ".join(f"{v['name']} {v['pct']:g}% free ({v['free_gb']:g} GB)"
                               for v in sorted(low, key=lambda v: (-order.index(v["level"]), v["pct"])))
        else:
            worst = min(vols, key=lambda v: v["pct"])
            detail = f"Lowest: {worst['name']} {worst['pct']:g}% free"
        checks.append(_check("disk", "Disk", level, detail, info={"volumes": vols}))

    # Services: role services that stopped are red after two reports;
    # other stopped automatic services are amber (worth a look, no alert).
    linux = report.get("os_family") == "linux"
    svc = report.get("services") or {}
    watched = [s for s in svc.get("watched") or [] if not ign.has("service", s.get("name"))]
    down = [s for s in watched if s.get("state") != "Running"]
    other = [s for s in svc.get("stopped_auto") or [] if not ign.has("service", s.get("name"))]
    if down:
        checks.append(_check("services", "Services", CRIT,
                             "Stopped: " + ", ".join(s.get("display") or s.get("name") for s in down),
                             confirm=True))
    elif other:
        checks.append(_check("services", "Services", WARN,
                             f"All {len(watched)} watched services running. "
                             + ("Failed systemd units: " if linux else "Other automatic services stopped: ")
                             + ", ".join(s.get("display") or s.get("name") for s in other[:8])
                             + (f" and {len(other) - 8} more" if len(other) > 8 else "")))
    else:
        checks.append(_check("services", "Services", OK,
                             f"All {len(watched)} watched services running" if watched else
                             ("No failed systemd units" if linux else "No stopped automatic services")))

    # Updates: reboot pending or not patched for a while.
    patch_days = _days_since(report.get("last_patch"), now)
    limit = float(opts.get("agent_patch_days", 60))  # 0 turns the age warning off
    kb = report.get("last_patch_kb")
    bits = []
    if report.get("pending_reboot"):
        bits.append("Reboot pending")
    if limit > 0 and patch_days is not None and patch_days > limit:
        bits.append(f"last update installed {int(patch_days)} days ago" + (f" ({kb})" if kb else ""))
    sec_upd, pend = report.get("security_updates"), report.get("updates_pending")
    # Ubuntu's unattended-upgrades installs security updates daily, so a few waiting is
    # normal; only flag them once nothing has been installed for a week.
    if isinstance(sec_upd, int) and sec_upd > 0 and (patch_days is None or patch_days > 7):
        bits.append(f"{sec_upd} security update(s) waiting" + (f" ({pend} in all)" if isinstance(pend, int) else ""))
    if bits or patch_days is not None or report.get("os_build"):
        if bits:
            detail = "; ".join(bits)
        elif patch_days is not None:
            detail = f"Last update installed {int(patch_days)} day(s) ago" + (f" ({kb})" if kb else "")
            if isinstance(pend, int):
                detail += (f"; {pend} update(s) available" + (f" ({sec_upd} security)" if sec_upd else "")) if pend else "; up to date"
        else:
            detail = f"Build {report.get('os_build')}"
        checks.append(_check("updates", "Updates", WARN if bits else OK, detail[0].upper() + detail[1:]))

    rc = report.get("checks") or {}
    iis = rc.get("iis")
    if iis:
        pools = [p for p in iis.get("app_pools") or [] if p.get("state") != "Started" and not ign.has("apppool", p.get("name"))]
        # "Unknown" means IIS couldn't say (e.g. an FTP site on an older agent): not a fault.
        sites = [s for s in iis.get("sites") or [] if s.get("state") not in ("Started", "Unknown")
                 and not ign.has("site", s.get("name"))]
        if pools or sites:
            parts = []
            if pools:
                parts.append("App pools stopped: " + ", ".join(p["name"] for p in pools))
            if sites:
                parts.append("Sites stopped: " + ", ".join(s["name"] for s in sites))
            checks.append(_check("iis", "IIS", CRIT, "; ".join(parts), confirm=True))
        else:
            checks.append(_check("iis", "IIS", OK, f"{len(iis.get('app_pools') or [])} app pools and "
                                 f"{len(iis.get('sites') or [])} sites started"))

    ad = rc.get("ad")
    if ad:
        fails = ad.get("replication") or []
        problems = []
        if fails:
            problems.append("Replication failing with " + ", ".join(
                sorted({(f.get("partner") or "?") for f in fails})))
        if ad.get("sysvol_shared") is False:
            problems.append("SYSVOL not shared")
        if ad.get("netlogon_shared") is False:
            problems.append("NETLOGON not shared")
        checks.append(_check("ad", "AD", CRIT if problems else OK,
                             "; ".join(problems) if problems else
                             f"Replication OK with {ad.get('partners', 0)} link(s); SYSVOL and NETLOGON shared",
                             confirm=True))

    dhcp = rc.get("dhcp")
    if dhcp is not None:
        scopes = [s for s in dhcp if s.get("active", True) and not ign.has("dhcp", s.get("scope"))]
        full = sorted((s for s in scopes if (s.get("in_use_pct") or 0) >= 85), key=lambda s: -s["in_use_pct"])
        level = CRIT if any(s["in_use_pct"] >= 95 for s in full) else WARN if full else OK
        detail = (", ".join(f"{s['scope']} {s.get('name') or ''} {s['in_use_pct']:g}% used ({s.get('free', 0)} free)".replace("  ", " ")
                            for s in full) if full else f"{len(scopes)} active scope(s), all below 85% used")
        checks.append(_check("dhcp", "DHCP", level, detail))

    vms = rc.get("hyperv")
    if vms is not None:
        vms = [v for v in vms if not ign.has("vm", v.get("name"))]
        bad = [v for v in vms if "critical" in (v.get("state") or "").lower()]
        running = sum(1 for v in vms if (v.get("state") or "").lower() == "running")
        checks.append(_check("hyperv", "Hyper-V", CRIT if bad else OK,
                             ("Critical state: " + ", ".join(f"{v['name']} ({v['state']})" for v in bad)) if bad
                             else f"{running} of {len(vms)} VMs running"))

    printers = rc.get("printers")
    if printers:
        bad = [p for p in printers if (p.get("status") or "Normal") not in ("Normal", "0", "") and not ign.has("printer", p.get("name"))]
        checks.append(_check("printers", "Printers", WARN if bad else OK,
                             ", ".join(f"{p['name']}: {p['status']}" for p in bad) if bad
                             else f"{len(printers)} shared printer(s) ready"))

    im = rc.get("immich")
    if im:
        ver = f" {im['version']}" if im.get("version") else ""
        if not im.get("ping"):
            checks.append(_check("immich", "Immich", CRIT,
                                 f"Immich not answering at {im.get('url')}" + (f": {im['error']}" if im.get("error") else ""),
                                 confirm=True))
        else:
            qs = im.get("queues") or []
            failed = [q for q in qs if (q.get("failed") or 0) > 0]
            paused = [q for q in qs if q.get("paused")]
            busy = sum((q.get("active") or 0) + (q.get("waiting") or 0) for q in qs)
            bits, level = [], OK
            if paused:
                level = WARN
                bits.append("paused: " + ", ".join(q["name"] for q in paused))
            if failed:
                level = WARN
                bits.append("failed jobs: " + ", ".join(f"{q['name']} ({q['failed']})" for q in failed))
            if im.get("api_error"):
                bits.append(im["api_error"])
            if not bits:
                bits.append(f"{busy} job(s) queued" if qs else "API answering")
            checks.append(_check("immich", "Immich", level, f"Immich{ver}: " + "; ".join(bits)))

    notable = {"events": [], "security": [], "detections": [], "failed_logons": None}

    defender = rc.get("defender")
    if defender and (defender.get("mode") or "").lower() not in PASSIVE_AV_MODES and defender.get("antivirus_enabled", True):
        level, bits = OK, []
        if defender.get("realtime") is False:
            level, bits = CRIT, ["Real-time protection is off"]
        if (defender.get("signature_age_days") or 0) > 7:
            level = max(level, WARN, key=[OK, WARN, CRIT].index)
            bits.append(f"virus definitions {defender['signature_age_days']} days old")
        dets = defender.get("detections") or []
        failed = [d for d in dets if not d.get("action_success", True)]
        if failed:
            level = CRIT
            bits.insert(0, "Threat not removed: " + ", ".join(sorted({d.get("threat") or "unknown" for d in failed})))
        notable["detections"] = dets
        detail = "; ".join(bits) if bits else f"Protected, definitions {defender.get('signature_age_days', 0)} day(s) old"
        checks.append(_check("defender", "Defender", level, detail[0].upper() + detail[1:]))

    # Events: Critical-level events and watched IDs are alerted as they arrive.
    watch = opts.get("agent_event_watch", DEFAULT_EVENT_WATCH)
    for e in (report.get("events") or {}).get("recent") or []:
        if ign.has("event", e.get("id")):
            continue
        e = dict(e)
        e["alert"] = e.get("level") == "Critical" or _watch_match(watch, e.get("source"), int(e.get("id") or 0))
        notable["events"].append(e)

    sec = report.get("security") or {}
    alert_ids = set(int(i) for i in opts.get("agent_security_alert_ids", DEFAULT_SECURITY_ALERT_IDS))
    for item in sec.get("items") or []:
        item = dict(item)
        item["alert"] = int(item.get("id") or 0) in alert_ids
        notable["security"].append(item)
    fl = sec.get("failed_logons") or {}
    threshold = int(opts.get("agent_failed_logons", 20))
    if fl.get("count"):
        notable["failed_logons"] = {**fl, "alert": fl["count"] >= threshold}

    # Security check: red while a burst of failed logons is happening.
    if fl.get("count", 0) >= threshold:
        top = fl.get("top") or []
        who = ", ".join(f"{t.get('account') or '?'} from {t.get('source') or '?'} ({t.get('count')})" for t in top[:3])
        checks.append(_check("security", "Security", CRIT, f"{fl['count']} failed logons since last report. {who}"))
    else:
        checks.append(_check("security", "Security", OK, "No unusual activity"))

    counts = (report.get("events") or {}).get("counts") or {}
    errs = sum((c.get("error") or 0) + (c.get("critical") or 0) for c in counts.values())
    checks.append(_check("events", "Journal" if linux else "Events", OK, f"{errs} new error(s) since last report"))
    return {"checks": checks, "notable": notable}
