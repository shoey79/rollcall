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
import math
import re
import secrets
import time
from datetime import datetime, timezone
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


def admin_key(a: dict) -> str:
    """What identifies a member of the Administrators group across reports: its SID if known."""
    return (a.get("sid") or f'{a.get("type")}:{a.get("account")}').lower()


# What motherboard makers leave in the BIOS when nobody fills in the system details (custom-built PCs)
HW_PLACEHOLDER = re.compile(
    r"^\s*(system manufacturer|system product name|system version|system serial number|system sku|to be filled by o\.?e\.?m\.?|"
    r"default string|not applicable|not specified|not available|none|n/?a|o\.?e\.?m\.?|oem manufacturer|invalid|undefined|unknown|"
    r"type1productconfigid|sku|x+|0+|1234567890|0123456789|123456789|base board serial number|chassis serial number|"
    r"default|empty|\.+|-+)\s*$", re.I)


def clean_hw(v) -> str:
    """A make, model or serial number, or '' if it's only a placeholder."""
    t = str(v or "").strip()
    return "" if not t or HW_PLACEHOLDER.match(t) else t


def normalize_report(r) -> dict:
    """Make an agent report safe to evaluate whatever PowerShell did to its lists."""
    r = _as_dict(r)
    for k in ("hw_vendor", "hw_model", "serial"):
        if k in r:
            r[k] = clean_hw(r[k])
    if "sessions" in r:
        r["sessions"] = [
            {"user": str(x.get("user") or "")[:80], "session": str(x.get("session") or "")[:30],
             "state": "disconnected" if x.get("state") == "disconnected" else "active",
             "idle_min": x["idle_min"] if isinstance(x.get("idle_min"), int) and x["idle_min"] >= 0 else 0,
             "since": str(x.get("since") or "")[:30], "from": str(x.get("from") or "")[:80], "tty": str(x.get("tty") or "")[:20]}
            for x in _as_list(r["sessions"]) if isinstance(x, dict) and x.get("user")][:50]
    # Why a restart is pending, and what was installed since the last one (Windows agent 1.0.39+;
    # Linux agents send reboot_packages from /var/run/reboot-required.pkgs)
    for k, n, ln in (("reboot_reasons", 8, 160), ("reboot_packages", 20, 160)):
        if k in r:
            r[k] = [str(x)[:ln] for x in (r[k] if isinstance(r[k], list) else []) if x][:n]
    if "agent_integrity" in r:
        g = _as_dict(r["agent_integrity"])
        r["agent_integrity"] = {"at": str(g.get("at") or "")[:30], "first": g.get("first") is True,
                                "what": [str(x)[:200] for x in (g.get("what") if isinstance(g.get("what"), list) else []) if x][:10]}
    if "last_patch_title" in r:
        r["last_patch_title"] = str(r["last_patch_title"] or "")[:200]
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
    if "admins" in sec:  # absent from older agents, so the UI can say an update is needed
        sec["admins"] = [{k: (x.get(k) if k in ("disabled", "builtin") else str(x.get(k) or "")[:200])
                          for k in ("account", "name", "domain", "type", "source", "sid", "disabled", "builtin")}
                         | {"via": [str(v)[:60] for v in _as_list(x.get("via"))][:6]}
                         for x in _as_list(sec.get("admins")) if isinstance(x, dict) and (x.get("account") or x.get("sid"))][:200]
    fl = sec["failed_logons"] = _as_dict(sec.get("failed_logons"))
    fl["top"] = [{k: (str(x.get(k) or "")[:160] if k != "count" else x.get("count")) for k in
                  ("account", "source", "count", "reason", "type", "via", "machine")} for x in _as_list(fl.get("top")) if isinstance(x, dict)][:10]
    try:
        fl["count"] = int(fl.get("count") or 0)
    except (TypeError, ValueError):
        fl["count"] = 0
    if "secrets" in r:
        r["secrets"] = clean_secret_status(r["secrets"])
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
    if "laps" in c:
        c["laps"] = {k: (v if isinstance(v, (bool, int, float)) or v is None else str(v)[:300]) for k, v in _as_dict(c["laps"]).items()}
    if "bitlocker" in c:
        bl = _as_dict(c["bitlocker"])
        c["bitlocker"] = {"volumes": [
            {"drive": str(v.get("drive") or "")[:3].upper(), "kind": "os" if v.get("kind") == "os" else "data",
             "protection": str(v.get("protection") or "unknown")[:10], "status": str(v.get("status") or "unknown")[:20],
             "percent": v.get("percent") if isinstance(v.get("percent"), (int, float)) else None,
             "method": str(v.get("method") or "")[:40], "protectors": [str(x)[:40] for x in _as_list(v.get("protectors"))][:12],
             "locked": v.get("locked") if isinstance(v.get("locked"), bool) else None}
            for v in _as_list(bl.get("volumes")) if isinstance(v, dict) and v.get("drive")][:26]}
        tpm = _as_dict(bl.get("tpm"))
        if tpm:
            c["bitlocker"]["tpm"] = {"present": tpm.get("present") if isinstance(tpm.get("present"), bool) else None,
                                     **{k: tpm.get(k) if isinstance(tpm.get(k), bool) else None for k in ("enabled", "activated")},
                                     **{k: str(tpm.get(k) or "")[:20] for k in ("version", "maker")}}
    if "nics" in c:
        def n(v):
            return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None
        c["nics"] = {"adapters": [
            {"name": str(a.get("name") or "")[:80], "desc": str(a.get("desc") or "")[:120],
             "status": a.get("status") if a.get("status") in NIC_STATUS else "down",
             "speed_mbps": n(a.get("speed_mbps")) or 0, "mac": str(a.get("mac") or "")[:40], "virtual": a.get("virtual") is True,
             "media": str(a.get("media") or "")[:40], "ips": [str(x)[:50] for x in _as_list(a.get("ips"))][:8],
             **{k: n(a.get(k)) for k in NIC_COUNTERS if n(a.get(k)) is not None}}
            for a in _as_list(_as_dict(c["nics"]).get("adapters")) if isinstance(a, dict) and a.get("name")][:40]}
    if "certs" in c:
        c["certs"] = {"certs": [
            {"thumbprint": str(x.get("thumbprint") or "").lower()[:40], "store": str(x.get("store") or "")[:30],
             **{k: str(x.get(k) or "")[:120] for k in ("subject", "issuer", "not_before", "not_after", "template")},
             "names": [str(n)[:120] for n in _as_list(x.get("names"))][:6], "self_signed": x.get("self_signed") is True,
             "used_by": [str(n)[:60] for n in _as_list(x.get("used_by"))][:4]}
            for x in _as_list(_as_dict(c["certs"]).get("certs")) if isinstance(x, dict) and x.get("thumbprint")][:60]}
    if "domain" in c:
        dm = _as_dict(c["domain"])
        acct = lambda a: {"name": str(a.get("name") or "")[:64], "kind": str(a.get("kind") or "user")[:10], "enabled": a.get("enabled") is not False,  # noqa: E731
                          "last_logon": str(a.get("last_logon") or "")[:25], "pwd_set": str(a.get("pwd_set") or "")[:25]}
        lst = lambda k, n=200: [acct(a) for a in _as_list(dm.get(k)) if isinstance(a, dict) and a.get("name")][:n]  # noqa: E731
        c["domain"] = {"domain": str(dm.get("domain") or "")[:120], "checked": str(dm.get("checked") or "")[:25],
                       "krbtgt_pwd_set": str(dm.get("krbtgt_pwd_set") or "")[:25],
                       "groups": [{"name": str(g.get("name") or "")[:64], "members": [acct(a) for a in _as_list(g.get("members")) if isinstance(a, dict) and a.get("name")][:100]}
                                  for g in _as_list(dm.get("groups")) if isinstance(g, dict) and g.get("name")][:12],
                       **{k: lst(k) for k in ("never_expires", "no_password", "stale_users", "stale_computers")}}
    if "exchange" in c:
        x = _as_dict(c["exchange"])
        num = lambda v: int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None  # noqa: E731
        c["exchange"] = {
            "queues": {k: num(v) for k, v in _as_dict(x.get("queues")).items() if k in ("delivery", "submission", "poison", "unreachable", "retry")},
            "queues_error": str(x.get("queues_error") or "")[:160],
            "components": [{"name": str(m.get("name") or "")[:60], "active": m.get("active") is not False, "by": [str(b)[:30] for b in _as_list(m.get("by"))][:6]}
                           for m in _as_list(x.get("components")) if isinstance(m, dict) and m.get("name")][:60],
            "back_pressure": [{"id": num(e.get("id")) or 0, "time": str(e.get("time") or "")[:25], "message": str(e.get("message") or "")[:300]}
                              for e in _as_list(x.get("back_pressure")) if isinstance(e, dict)][:10],
            "databases": [{**{k: str(d.get(k) or "")[:200] for k in ("name", "status", "index", "message")}, "active": d.get("active") is True,
                           "copy_queue": num(d.get("copy_queue")), "replay_queue": num(d.get("replay_queue"))}
                          for d in _as_list(x.get("databases")) if isinstance(d, dict) and d.get("name")][:50] if "databases" in x else None,
            "databases_error": str(x.get("databases_error") or "")[:200], "databases_checked": str(x.get("databases_checked") or "")[:25]}
    if "gpo" in c:
        g = _as_dict(c["gpo"])
        c["gpo"] = {"last_success": str(g.get("last_success") or "")[:25], "last_computer_success": str(g.get("last_computer_success") or "")[:25],
                    "failures_24h": g.get("failures_24h") if isinstance(g.get("failures_24h"), int) else 0,
                    "failures": [{"id": f.get("id") if isinstance(f.get("id"), int) else 0, "time": str(f.get("time") or "")[:25],
                                  "message": str(f.get("message") or "")[:300]} for f in _as_list(g.get("failures")) if isinstance(f, dict)][:10]}
    if "sysvol" in c:
        v = _as_dict(c["sysvol"])
        c["sysvol"] = {"state": v.get("state") if isinstance(v.get("state"), int) else None,
                       "frs_migration": v.get("frs_migration") if isinstance(v.get("frs_migration"), int) else None,
                       "frs_running": v.get("frs_running") is True, "wmi_error": str(v.get("wmi_error") or "")[:160],
                       "events": [{"id": e.get("id") if isinstance(e.get("id"), int) else 0, **{k: str(e.get(k) or "")[:240] for k in ("time", "partner", "message")}}
                                  for e in _as_list(v.get("events")) if isinstance(e, dict)][:40]}
    if "sql" in c:
        insts = []
        for i in _as_list(_as_dict(c["sql"]).get("instances"))[:8]:
            if not isinstance(i, dict) or not i.get("instance"):
                continue
            dbs = [{**{k: str(d.get(k) or "")[:128] for k in ("name", "state", "recovery", "log_wait", "created", "last_full", "last_diff", "last_log")},
                    **{k: d.get(k) is True for k in ("read_only", "snapshot", "system", "ag")},
                    "ag_preferred": d.get("ag_preferred") if isinstance(d.get("ag_preferred"), bool) else None,
                    **{k: float(d[k]) if isinstance(d.get(k), (int, float)) and not isinstance(d.get(k), bool) else None for k in ("log_mb", "log_used_pct")}}
                   for d in _as_list(i.get("databases")) if isinstance(d, dict) and d.get("name")][:100]
            jobs = [{**{k: str(j.get(k) or "")[:300] for k in ("name", "outcome", "last_run", "message")}, "enabled": j.get("enabled") is True}
                    for j in _as_list(i.get("jobs")) if isinstance(j, dict) and j.get("name")][:60]
            insts.append({**{k: str(i.get(k) or "")[:200] for k in ("instance", "version", "edition", "level", "login", "connect_error")},
                          "databases": dbs, "jobs": jobs if "jobs" in i else None, "backups_read": i.get("backups_read") is True,
                          "internal": i.get("internal") is True or str(i.get("instance") or "").upper().startswith("MICROSOFT##"),
                          "denied": [str(x)[:20] for x in _as_list(i.get("denied"))][:6], "errors": [str(x)[:220] for x in _as_list(i.get("errors"))][:6]})
        c["sql"] = {"instances": insts}
    if "tasks" in c:
        tk = _as_dict(c["tasks"])
        c["tasks"] = {"total": tk.get("total") if isinstance(tk.get("total"), int) else None, "tasks": [
            {**{k: str(x.get(k) or "")[:120] for k in ("name", "path", "state", "last_run", "next_run", "run_as", "action", "author")},
             "result": x.get("result") if isinstance(x.get("result"), int) and not isinstance(x.get("result"), bool) else None,
             "missed": x.get("missed") if isinstance(x.get("missed"), int) and not isinstance(x.get("missed"), bool) else None,
             "triggers": [str(t)[:20] for t in _as_list(x.get("triggers"))][:8]}
            for x in _as_list(tk.get("tasks")) if isinstance(x, dict) and x.get("name")][:80]}
    if "backups" in c:
        b = c["backups"] = _as_dict(c["backups"])
        b["jobs"] = [j for j in _as_list(b.get("jobs")) if isinstance(j, dict) and j.get("name")]
        for j in b["jobs"]:
            j["runs"] = [str(x) for x in _as_list(j.get("runs")) if x][-12:]
    if "storage" in c:
        st = c["storage"] = _as_dict(c["storage"])
        for k in ("physical", "virtual", "volumes", "dyn_disks", "drives"):
            st[k] = [x for x in _as_list(st.get(k)) if isinstance(x, dict)]
        st["warnings"] = [str(x)[:300] for x in _as_list(st.get("warnings")) if x][:20]
        st["hardware"] = [x for x in _as_list(st.get("hardware")) if isinstance(x, dict)]
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
            if kind not in IGNORE_KINDS:
                kind, value = "service", e
            self.items.setdefault(kind, set()).add(value.strip().lower().rstrip(":"))

    def has(self, kind: str, value) -> bool:
        return str(value).strip().lower().rstrip(":") in self.items.get(kind, set())


# --------------------------------------------------------------------------
# Security filters: expected, low-risk security events that shouldn't alert
# --------------------------------------------------------------------------
SEC_FILTER_FIELDS = ("account", "group", "by")


def _pretty_account(value) -> str:
    """A directory DN ("CN=Sam Lee,OU=...") shown as its name; anything else as it is."""
    v = str(value or "").strip()
    m = re.match(r"^CN=((?:[^,\\]|\\.)+)", v, re.I)
    return m.group(1).replace("\\", "") if m else v


def _wild(pattern: str) -> "re.Pattern":
    """A filter pattern as a regex: * is any run of characters, ? any one; the rest is literal.
    Matching ignores case and has to cover the whole value."""
    out = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(out + r"\Z", re.I | re.S)


def clean_sec_filter(raw) -> dict:
    """Validate one security filter from the dashboard.

    {"events": [4732], "account": "*\\LAPSAdmin", "group": "Builtin\\Administrators", "by": "SYSTEM*", "note": "..."}
    Every part that's given has to match. An empty events list means any event; an empty pattern
    means anything. A filter with nothing in it, or only wildcards, is refused."""
    raw = raw if isinstance(raw, dict) else {}
    events = []
    for e in raw.get("events") or []:
        try:
            e = int(e)
        except (TypeError, ValueError):
            raise ValueError("event IDs must be numbers") from None
        if not 1 <= e <= 65535:
            raise ValueError("event IDs must be between 1 and 65535")
        if e not in events:
            events.append(e)
    if len(events) > 20:
        raise ValueError("a filter can name up to 20 events")
    out = {"events": sorted(events)}
    for k in SEC_FILTER_FIELDS:
        v = str(raw.get(k) or "").strip()
        if len(v) > 128 or not v.isprintable():
            raise ValueError("patterns are up to 128 ordinary characters")
        out[k] = "" if not v.strip("*?") else v  # only wildcards = anything
    note = str(raw.get("note") or "").strip()
    if len(note) > 80 or not note.isprintable():
        raise ValueError("the note is up to 80 ordinary characters")
    out["note"] = note
    if not out["events"] and not any(out[k] for k in SEC_FILTER_FIELDS):
        raise ValueError("a filter needs an event type or an account, group or 'done by' to match")
    return out


def sec_filter_matches(f: dict, item: dict) -> bool:
    if f.get("events") and int(item.get("id") or 0) not in f["events"]:
        return False
    for k in SEC_FILTER_FIELDS:
        pat = f.get(k)
        if not pat:
            continue
        value = _pretty_account(item.get(k)) if k == "account" else str(item.get(k) or "")
        if not _wild(pat).match(value.strip()):
            return False
    return True


def apply_sec_filters(items: list, filters: list, alert_ids: set) -> None:
    """Decide which security events alert: those whose ID is in alert_ids, unless a filter matches.
    A filtered event stays in the list, marked with the filter that matched it."""
    for item in items:
        hit = next((f for f in filters or [] if sec_filter_matches(f, item)), None)
        item["alert"] = int(item.get("id") or 0) in alert_ids and not hit
        if hit:
            item["filtered"] = hit.get("note") or "filter"
            item["filter_id"] = hit.get("id") or ""
        else:
            item.pop("filtered", None)
            item.pop("filter_id", None)


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
NIC_STATUS = ("up", "down", "disabled", "notpresent")
NIC_COUNTERS = ("rx_bytes", "tx_bytes", "rx_errors", "tx_errors", "rx_drops", "tx_drops")


def nic_key(name: str) -> str:
    return str(name or "").strip().lower()[:80]


def nic_state(nics: dict, watch: dict) -> tuple[str, str, list] | None:
    """Ticked network adapters: red when disconnected or gone, amber when disabled or the link
    is slower than it was when ticked (e.g. 1 Gb/s down to 100 Mb/s). Unticked ones never alert."""
    if not watch:
        return None
    have = {nic_key(a["name"]): a for a in nics.get("adapters") or []}
    crit, warn = [], []
    for k, w in watch.items():
        a, nm = have.get(k), (w or {}).get("name") or k
        if not a or a["status"] == "notpresent":
            crit.append(f"{nm} missing")
        elif a["status"] == "down":
            crit.append(f"{nm} disconnected")
        elif a["status"] == "disabled":
            warn.append(f"{nm} disabled")
        elif (w or {}).get("speed") and a.get("speed_mbps") and a["speed_mbps"] < w["speed"]:
            warn.append(f"{nm} at {fmt_speed(a['speed_mbps'])} (was {fmt_speed(w['speed'])})")
    if crit:
        return CRIT, ", ".join(crit + warn), crit
    if warn:
        return WARN, ", ".join(warn), warn
    n = len(watch)
    return OK, f"{n} watched adapter{'s' if n != 1 else ''} up", []

# --------------------------------------------------------------------------
# Password exposure scan. The agents never send passwords: only where each one is
# (file, line, setting name, how many characters). Rollcall keeps only those fields.
# --------------------------------------------------------------------------
SECRET_RULES = {
    "cpassword": "Group Policy password (cpassword), readable by any domain user",
    "unattend": "Password in a Windows setup answer file",
    "securestring": "Password in a script (ConvertTo-SecureString -AsPlainText)",
    "param": "Password given on a command line",
    "netuse": "Password in a net use command",
    "netuser": "Password in a net user command",
    "url": "User name and password in a web address",
    "cmdline": "Password in a command (mysql, sshpass, curl)",
    "aws": "AWS access key",
    "github": "GitHub token",
    "slack": "Slack token",
    "azurekey": "Azure storage or Service Bus key",
    "connstring": "Password in a database connection string",
    "appsetting": "Password in an application setting",
    "xml": "Password in an XML setting",
    "keyvalue": "Password or secret in a setting",
    "notes": "Password written in a note or document",
    "savedlogin": "Saved password (.netrc or .pgpass)",
    "privkey": "Private key with no passphrase",
    "filename": "File name suggests it holds passwords",
    "sheet": "Spreadsheet with a password column",
    "autologon": "Automatic sign-in password in the registry",
}
SECRET_SCAN_MODES = ("off", "servers", "workstations", "all")
_SECRET_KEY_CHARS = re.compile(r"[^A-Za-z0-9_.\- ]")


def _int_or_none(v, hi):
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= hi else None


def clean_secret_finding(f) -> dict | None:
    """One finding as Rollcall keeps it: only these five fields, whatever an agent sent."""
    if not isinstance(f, dict) or f.get("rule") not in SECRET_RULES or not str(f.get("path") or "").strip():
        return None
    return {"path": str(f["path"]).strip()[:400], "line": _int_or_none(f.get("line"), 10_000_000), "rule": f["rule"],
            "key": _SECRET_KEY_CHARS.sub("", str(f.get("key") or ""))[:40], "len": _int_or_none(f.get("len"), 100_000)}


def clean_secret_status(s) -> dict:
    s = _as_dict(s)
    if not s.get("on"):
        return {"on": False}
    out = {"on": True, "scanning": s.get("scanning") is True, "truncated": s.get("truncated") is True,
           "hash": str(s.get("hash") or "")[:64]}
    for k in ("pass_start", "done_at"):
        out[k] = str(s[k])[:30] if s.get(k) else None
    for k in ("files", "errors", "count"):
        out[k] = _int_or_none(s.get(k), 100_000_000) or 0
    return out


def secret_key(f: dict) -> str:
    """What an Ignore button stores for a finding: the file, the rule and the setting (not the line, which moves)."""
    return f"{f.get('path') or ''}|{f.get('rule') or ''}|{f.get('key') or ''}"[:600]


def secrets_state(status: dict, findings: list, ign: "Ignore", ack_at: float = 0) -> tuple[str, str]:
    """Amber at most: a password in a file is worth fixing, not worth waking anyone for.
    ack_at: "Ignore all" was pressed then; findings first found by then don't count."""
    live = [f for f in findings if not ign.has("secret", secret_key(f)) and not (ack_at and (f.get("first") or 0) <= ack_at)]
    if live:
        files = sorted({f["path"] for f in live})
        names = ", ".join(re.split(r"[\\/]", p)[-1] for p in files[:3]) + (f" and {len(files) - 3} more" if len(files) > 3 else "")
        n = len(live)
        new = " new" if ack_at and any(not ign.has("secret", secret_key(f)) and (f.get("first") or 0) <= ack_at for f in findings) else ""
        return WARN, f"{n}{new} possible password{'s' if n != 1 else ''} in {len(files)} file{'s' if len(files) != 1 else ''}: {names}"
    if not status.get("done_at"):
        return OK, "First scan under way" if status.get("scanning") or not status.get("files") else "Scanning"
    ignored = len(findings)
    extra = f" ({ignored} ignored)" if ignored else ""
    return OK, f"None found in {status.get('files') or 0} files{extra}"


def fmt_speed(mbps: int) -> str:
    return f"{mbps / 1000:g} Gb/s" if mbps >= 1000 else f"{mbps} Mb/s"


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


DAY = 86400
IGNORE_KINDS = ("service", "event", "apppool", "site", "disk", "dhcp", "printer", "vm", "storage", "hardware", "update", "backup", "laps", "bitlocker", "cert", "task", "sqldb", "sqljob", "gpo", "sysvol", "exchange", "domain", "aduser", "secret")


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
    if not value or len(value) > (600 if kind == "secret" else 128) or any(c in value for c in "\r\n\t"):
        raise ValueError("invalid value")
    if kind == "event" and not value.isdigit():
        raise ValueError("an event must be a number")
    if kind == "disk":
        value = disk_key(value)
    return f"{kind}:{value}"


def _vt(v) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:3])


def immich_update(im: dict) -> bool:
    """True when a newer Immich release than the one running is known."""
    return bool(im.get("latest") and im.get("version") and _vt(im["latest"]) > _vt(im["version"]))


def _ts(iso) -> float | None:
    try:
        return datetime.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _day(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%d %b %Y").lstrip("0")


def laps_state(laps: dict, now: float, overdue_days: float = 3) -> tuple[str, str, dict]:
    """(level, detail, info) for LAPS: is the managed password being rotated on the policy's schedule?

    The due date comes from the password's expiry in AD when the agent could read it, otherwise from
    the last rotation (the account's password-last-set time, or Windows LAPS' own events) plus the
    policy's password age. Overdue by more than a day is amber; by more than overdue_days, red."""
    info: dict = {}
    if laps.get("problem"):
        return WARN, laps["problem"], info
    if not laps.get("enabled"):
        return WARN, f"{laps.get('product') or 'LAPS'} policy is set, but backup is disabled, so the password isn't managed", info
    if laps.get("dc") and not laps.get("legacy") and not laps.get("dsrm"):
        return OK, "Domain controller: LAPS isn't set to manage the DSRM password (ADBackupDSRMPassword is off)", info
    age = max(1, int(laps.get("age_days") or 30))
    rotated = max((t for t in (_ts(laps.get("password_set")), _ts(laps.get("last_rotation")), _ts(laps.get("last_backup"))) if t), default=None)
    exp = _ts(laps.get("expires")) if laps.get("expires") else None
    due = exp or (rotated + age * DAY if rotated else None)
    info = {"rotated": rotated, "due": due, "due_from": "Active Directory" if exp else "last rotation" if rotated else None}
    problems: list[tuple[str, str]] = []
    if laps.get("account_found") is False:
        problems.append((WARN, f"managed account '{laps.get('account') or 'built-in Administrator'}' not found"))
    if laps.get("expires") == "" and laps.get("backup") == "Active Directory":
        problems.append((WARN, "no LAPS password in Active Directory yet (not backed up, or the computer can't write it)"))
    if laps.get("last_error"):
        problems.append((WARN, "last LAPS run failed: " + str(laps["last_error"]).split("\n")[0][:160]))
    level, detail = OK, ""
    if due is None:
        if not problems:
            problems.append((WARN, "no password rotation recorded yet"))
    else:
        late = now - due
        if late > overdue_days * DAY:
            level, detail = CRIT, f"Password not rotated: due {_day(due)}, {int(late // DAY)} days overdue"
        elif late > DAY:
            level, detail = WARN, f"Password rotation overdue since {_day(due)}"
        else:
            detail = (f"Rotated {_day(rotated)}; " if rotated else "") + f"next due {_day(due)} (every {age} day{'s' if age != 1 else ''})"
    for lvl, why in problems:
        level = max(level, lvl, key=[OK, WARN, CRIT].index)
        detail = (detail + "; " if detail else "") + why
    return level, detail[0].upper() + detail[1:], info


BITLOCKER_REQUIRE = ("off", "workstations", "all")


def bitlocker_skip(bl: dict, workstation: bool, require: str = "workstations", virtual: str = "") -> str:
    """Why a computer gets no BitLocker check ('' if it does, or might): virtual machines never do,
    and one that doesn't use BitLocker is only expected to when require covers it and it has a TPM."""
    if virtual:
        return "virtual"
    if any(v["status"] != "decrypted" for v in bl.get("volumes") or []):
        return ""
    if not (require == "all" or (require == "workstations" and workstation)):
        return "not_required"
    if (bl.get("tpm") or {}).get("present") is not True:  # no TPM, or an agent too old to say
        return "no_tpm"
    return ""


def bitlocker_state(bl: dict, workstation: bool, require: str = "workstations", ign: "Ignore | None" = None,
                    pending_reboot: bool = False, virtual: str = "") -> tuple[str, str] | None:
    """(level, detail) for BitLocker on the fixed drives, or None when there's nothing to check.

    Virtual machines aren't checked. A physical computer that doesn't use BitLocker only gets the
    check when encryption is expected of it (require = "workstations", the default, for Windows 10/11;
    "all" for servers too; or "off") and it has a TPM to use. One that does use BitLocker is always
    checked: every fixed drive encrypted with protection on, and a recovery password on the Windows
    drive. Never red: an unencrypted drive isn't an outage."""
    if bitlocker_skip(bl, workstation, require, virtual):
        return None
    vols = [v for v in bl.get("volumes") or [] if not (ign and ign.has("bitlocker", v["drive"]))]
    if not vols:
        return None
    if not any(v["status"] != "decrypted" for v in vols):
        drives = ", ".join(v["drive"] for v in vols)
        tpm = bl.get("tpm") or {}
        has = "TPM" + (f" {tpm['version']}" if tpm.get("version") else "") + (" (turned off)" if tpm.get("enabled") is False else "")
        return WARN, f"Not encrypted: {drives} (BitLocker is off, though this computer has a {has})"
    problems, notes = [], []
    for v in vols:
        d, st = v["drive"], v["status"]
        pct = f" ({int(v['percent'])}%)" if v.get("percent") is not None else ""
        if v.get("locked"):
            problems.append(f"{d} is locked")
        elif st == "decrypted":
            problems.append(f"{d} isn't encrypted")
        elif st == "decrypting":
            problems.append(f"{d} is being decrypted{pct}")
        elif st in ("encrypting_paused", "decrypting_paused"):
            problems.append(f"{d} {'encryption' if st.startswith('enc') else 'decryption'} is paused{pct}")
        elif st == "encrypting":
            notes.append(f"{d} encrypting{pct}")
        elif v["protection"] == "off":
            # Windows Update and firmware updates suspend it until the next restart
            problems.append(f"{d} protection is suspended" + (" until the pending restart" if pending_reboot else ""))
        if v["kind"] == "os" and st != "decrypted" and v.get("protectors") and "Recovery password" not in v["protectors"]:
            problems.append(f"{d} has no recovery password")
    if problems:
        return WARN, _cap("; ".join(problems + notes))
    done = [v for v in vols if v["status"] == "encrypted"]
    methods = sorted({v["method"] for v in done if v.get("method")})
    detail = "; ".join(([", ".join(v["drive"] for v in done) + " encrypted" + (f" ({', '.join(methods)})" if methods else "")] if done else []) + notes)
    return OK, _cap(detail)


def _cap(s: str) -> str:
    return s[0].upper() + s[1:] if s else s


def cert_store_state(certs: list[dict], now: float, warn_days: int = 30, crit_days: int = 7,
                     ign: "Ignore | None" = None) -> tuple[str, str, dict] | None:
    """(level, detail, info) for the certificates in the computer's own stores, or None if there are none.

    info["states"] maps each thumbprint to (state, text) for the Details table. A certificate that a newer,
    valid one with the same name has replaced doesn't count (renewal leaves the old one behind), and nor
    does one that expired over 30 days ago and isn't bound to anything: those are leftovers. Anything
    else counts, bound or not, since services such as LDAPS and SQL Server pick a certificate themselves."""
    if not certs:
        return None
    states, bad = {}, []
    for c in certs:
        t, exp, start = c["thumbprint"], _ts(c["not_after"]), _ts(c["not_before"])
        if exp is None:
            continue
        name = (c["subject"] or "").lower()
        newer = any(o["thumbprint"] != t and (o["subject"] or "").lower() == name and (_ts(o["not_after"]) or 0) > exp
                    and (_ts(o["not_before"]) or 0) <= now < (_ts(o["not_after"]) or 0) for o in certs)
        days = (exp - now) / DAY
        when = f"expired {_day(exp)}" if days < 0 else f"expires {_day(exp)}"
        if ign and (ign.has("cert", t) or (name and ign.has("cert", c["subject"]))):
            states[t] = ("ignored", when)
        elif newer:
            states[t] = ("replaced", when + ", replaced by a newer certificate")
        elif days < 0 and not c["used_by"] and days < -30:
            states[t] = ("old", when + ", not in use")
        elif days < 0:
            states[t] = ("crit", when)
            bad.append((CRIT, -1e9 + days, c, f"expired on {_day(exp)}"))
        elif days <= crit_days:
            states[t] = ("crit", when)
            bad.append((CRIT, days, c, "expires within a day" if days < 1 else f"expires in {math.ceil(days)} day{'s' if math.ceil(days) > 1 else ''}"))
        elif days <= warn_days:
            states[t] = ("warn", when)
            bad.append((WARN, days, c, f"expires in {math.ceil(days)} days"))
        else:
            states[t] = ("ok", when)
    info = {"states": states}
    if not bad:
        valid = [c for c in certs if states.get(c["thumbprint"], ("",))[0] == "ok"]
        if not valid:
            return None
        soonest = min(valid, key=lambda c: _ts(c["not_after"]) or 0)
        return OK, f"{len(valid)} certificate(s) valid; next to expire: {soonest['subject'] or soonest['thumbprint'][:8]} on {_day(_ts(soonest['not_after']))}", info
    bad.sort(key=lambda b: (b[0] != CRIT, b[1]))
    lvl, _d, c, why = bad[0]
    use = f" ({', '.join(c['used_by'][:2])})" if c["used_by"] else ""
    more = f"; {len(bad) - 1} more within {warn_days} days" if len(bad) > 1 else ""
    return lvl, f"{c['subject'] or c['thumbprint'][:8]} {why}{use}{more}", info


# Task Scheduler results that aren't failures: ready, running, disabled, not yet run, no more runs, queued
TASK_OK_RESULTS = {0, 0x41300, 0x41301, 0x41302, 0x41303, 0x41304, 0x41325, 0x8004131F}  # last: an instance was already running
TASK_RESULT_TEXT = {0x1: "incorrect function or script error", 0x2: "file not found", 0x3: "path not found", 0x5: "access denied",
                    0x41306: "stopped before it finished", 0x800710E0: "refused to start (its conditions or account)",
                    0x80070002: "file not found", 0x80070005: "access denied", 0x8007052E: "the account's password is wrong",
                    0x80070569: "the account isn't allowed to log on as a batch job", 0x8004131F: "an instance was already running",
                    0xC000013A: "stopped (Ctrl+C or shutdown)", 0x80041326: "the task is disabled"}
# Other vendors' updaters and per-user tasks that fail routinely: listed, never alerted on
TASK_NOISE = re.compile(r"^(MicrosoftEdgeUpdate|GoogleUpdate|GoogleUpdater|OneDrive |Adobe|User_Feed_Synchronization|"
                        r"CreateExplorerShellUnelevatedTask|Firefox (Default Browser Agent|Background Update)|Opera |"
                        r"BraveSoftwareUpdate|ZoomUpdate|Intel|NVIDIA|NvTm|Lenovo|Dropbox|npcapwatchdog)", re.I)
TASK_NOISE_PATHS = re.compile(r"^\\(Mozilla|Google|GoogleSystem|Adobe|Intel|NVIDIA|Lenovo|Apple|Dropbox|Zoom|Opera|BraveSoftware)\\", re.I)
TASK_TIMED = {"daily", "weekly", "monthly", "time"}


def task_result_text(code) -> str:
    if code is None:
        return ""
    return f"0x{code:X}" + (f", {TASK_RESULT_TEXT[code]}" if code in TASK_RESULT_TEXT else "")


def task_state(t: dict, now: float, ign: "Ignore | None" = None) -> tuple[str, str]:
    """(state, why) for one scheduled task: ok, failed, missed, disabled, vendor (routine noise), running, ignored."""
    if ign and (ign.has("task", t["name"]) or ign.has("task", (t["path"] + t["name"]))):
        return "ignored", ""
    if t["state"].lower() == "disabled":
        return "disabled", "disabled"
    if t["state"].lower() == "running":
        return "running", "running now"
    vendor = bool(TASK_NOISE.match(t["name"]) or TASK_NOISE_PATHS.match(t["path"]))
    code = t.get("result")
    if code is not None and code not in TASK_OK_RESULTS and t.get("last_run"):
        return ("vendor" if vendor else "failed"), "last run failed (" + task_result_text(code) + ")"
    timed = bool(TASK_TIMED & set(t.get("triggers") or []))
    due = _ts(t.get("next_run")) if t.get("next_run") else None
    if timed and not vendor and ((t.get("missed") or 0) > 0 or (due and due < now - 3600)):
        n = t.get("missed") or 0
        return "missed", f"missed {n} scheduled run{'s' if n != 1 else ''}" if n else "was due over an hour ago and hasn't run"
    return ("vendor" if vendor else "ok"), ""


def tasks_check(tk: dict, now: float, ign: "Ignore | None" = None) -> tuple[str, str] | None:
    tasks = tk.get("tasks") or []
    if not tasks:
        return None
    bad = [(t, why) for t in tasks for st, why in [task_state(t, now, ign)] if st in ("failed", "missed")]
    if bad:
        t, why = bad[0]
        return WARN, f"{t['name']}: {why}" + (f"; {len(bad) - 1} more" if len(bad) > 1 else "")
    mine = [t for t in tasks if task_state(t, now, ign)[0] in ("ok", "running")]
    return OK, f"{len(mine)} scheduled task(s) OK" if mine else "No scheduled tasks of your own to watch"


GP_TEXT = {1006: "couldn't bind to a domain controller (LDAP)", 1030: "couldn't get the list of Group Policy objects",
           1053: "couldn't find the user or computer name", 1054: "couldn't find a domain controller",
           1055: "couldn't resolve the computer name", 1058: "couldn't read a policy from SYSVOL (gpt.ini)",
           1085: "a settings extension failed", 1096: "couldn't process a policy file (registry.pol)",
           1129: "no network connection to a domain controller"}


def gpo_state(g: dict, now: float) -> tuple[str, str] | None:
    """Group Policy: amber when the latest result is a failure and it hasn't applied for 3 hours (a refresh
    is every 90 minutes or so), or when it hasn't succeeded at all in 24 hours despite failing."""
    fails = g.get("failures") or []
    last_ok = _ts(g.get("last_success")) if g.get("last_success") else None
    last_fail = max((t for f in fails if (t := _ts(f.get("time")))), default=None)
    if last_fail and (not last_ok or last_fail > last_ok) and (not last_ok or now - last_ok > 3 * 3600):
        f = max(fails, key=lambda f: _ts(f.get("time")) or 0)
        what = GP_TEXT.get(f["id"]) or f"event {f['id']}"
        since = f"not applied for {int((now - last_ok) / 3600)} h" if last_ok else "not applied in the last 24 h"
        return WARN, f"Failing: {what}; {since}"
    if last_ok:
        return OK, "Applied " + (f"{int((now - last_ok) / 60)} min ago" if now - last_ok < 2 * 3600 else f"{int((now - last_ok) / 3600)} h ago") + \
            (f"; {g['failures_24h']} failure(s) in 24 h since resolved" if g.get("failures_24h") else "")
    return None


SYSVOL_STATES = {0: "uninitialised", 1: "initialised", 2: "initial sync", 3: "auto recovery", 4: "normal", 5: "in error"}


def sysvol_state(v: dict, now: float) -> tuple[str, str]:
    ev = sorted(v.get("events") or [], key=lambda e: _ts(e.get("time")) or 0)
    latest = lambda ids: max((e for e in ev if e["id"] in ids), key=lambda e: _ts(e.get("time")) or 0, default=None)  # noqa: E731
    t = lambda e: (_ts(e.get("time")) or 0) if e else 0  # noqa: E731
    if v.get("frs_migration") is not None and v["frs_migration"] < 3 or (v.get("frs_migration") is None and v.get("state") is None and v.get("frs_running")):
        return WARN, "SYSVOL still replicates with FRS, which Windows Server 2019 and later don't support; migrate it to DFS-R (dfsrmig)"
    dirty, resumed = latest({2213}), latest({2214})
    if dirty and t(dirty) > t(resumed):
        return CRIT, "DFS-R stopped replicating SYSVOL after an unclean shutdown (event 2213); it needs resuming"
    stale = latest({4012})
    if stale and t(stale) > t(latest({4602, 4604, 4614})):
        return CRIT, "DFS-R stopped replicating SYSVOL: this DC was offline too long (event 4012); it needs a non-authoritative sync"
    st = v.get("state")
    if st == 5:
        return CRIT, "DFS-R reports SYSVOL replication in error"
    if st in (0, 1, 2, 3):
        return WARN, f"SYSVOL replication is in {SYSVOL_STATES[st]}"
    down, up = latest({5002, 5008, 5014}), latest({5004})
    if down and t(down) > t(up) and now - t(down) > 3600:
        who = f" with {down['partner']}" if down.get("partner") else ""
        return WARN, f"DFS-R can't replicate SYSVOL{who} (event {down['id']})"
    if st == 4:
        return OK, "SYSVOL replicating normally (DFS-R)"
    return OK, "SYSVOL replication: no problems logged" + (f" (couldn't read its state: {v['wmi_error'][:80]})" if v.get("wmi_error") else "")


PRIVILEGED_GROUPS = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")


def domain_key(group: str, name: str) -> str:
    return f"{group.lower()}|{name.lower()}"


def domain_state(dm: dict, changes: list, now: float, krbtgt_days: int = 180, ign: "Ignore | None" = None) -> tuple[str, str]:
    """Domain-wide security, from the PDC emulator: recent additions to privileged groups (24 h),
    an old KRBTGT password, and enabled accounts that don't need a password. Other lists are for review."""
    bad = []
    added = [c for c in changes or [] if c.get("change") == "added" and now - (c.get("time") or 0) < DAY]
    for c in added[::-1]:
        bad.append(f"{c['account']} added to {c['group']}")
    k = _ts(dm.get("krbtgt_pwd_set")) if dm.get("krbtgt_pwd_set") else None
    if k and now - k > krbtgt_days * DAY:
        bad.append(f"KRBTGT password last reset {int((now - k) / DAY)} days ago")
    nopw = [a for a in dm.get("no_password") or [] if not (ign and ign.has("aduser", a["name"]))]
    if nopw:
        bad.append(f"{len(nopw)} enabled account(s) don't require a password ({', '.join(a['name'] for a in nopw[:3])})")
    if bad:
        return WARN, bad[0] + (f"; {len(bad) - 1} more" if len(bad) > 1 else "")
    priv = {a["name"].lower() for g in dm.get("groups") or [] if g["name"] in PRIVILEGED_GROUPS for a in g["members"] if a["kind"] == "user"}
    parts = [f"{len(priv)} privileged user account(s)"]
    if k:
        parts.append(f"KRBTGT reset {int((now - k) / DAY)} days ago")
    if dm.get("stale_computers") or dm.get("stale_users"):
        parts.append(f"{len(dm.get('stale_computers') or [])} stale computer(s), {len(dm.get('stale_users') or [])} stale user(s) to review")
    return OK, "; ".join(parts)


EX_NORMALLY_INACTIVE = {"forwardsyncdaemon", "provisioningrps"}
EX_DB_BAD = {"failed", "failedandsuspended", "dismounted", "servicedown"}
EX_DB_WARN = {"suspended", "disconnected", "initializing", "resynchronizing", "seeding", "seedingsource", "dismounting", "mounting"}


def exchange_state(x: dict, now: float, queue_warn: int = 250) -> tuple[str, str] | None:
    bad = []  # (level, text)
    comps = x.get("components") or []
    off = [m for m in comps if not m["active"] and m["name"].lower() not in EX_NORMALLY_INACTIVE]
    if any(m["name"].lower() == "serverwideoffline" for m in off):
        bad.append((WARN, "in maintenance mode (ServerWideOffline is inactive)"))
    elif off:
        bad.append((WARN, "component(s) inactive: " + ", ".join(m["name"] for m in off[:4])))
    bp = sorted(x.get("back_pressure") or [], key=lambda e: _ts(e["time"]) or 0)
    if bp:
        last = bp[-1]
        m = re.search(r"\bto (Normal|Medium|High)\b", last["message"], re.I)
        level = m.group(1).capitalize() if m else ("High" if last["id"] in (15006, 15007) else None)
        if level == "High":
            bad.append((CRIT, "back pressure is High: transport has stopped accepting mail"))
        elif level == "Medium":
            bad.append((WARN, "back pressure is Medium: transport is slowing down incoming mail"))
    q = x.get("queues") or {}
    if (q.get("delivery") or 0) >= queue_warn:
        bad.append((WARN, f"{q['delivery']} messages waiting for delivery"))
    if (q.get("submission") or 0) >= max(50, queue_warn // 2):
        bad.append((WARN, f"{q['submission']} messages in the submission queue"))
    if (q.get("poison") or 0) > 0:
        bad.append((WARN, f"{q['poison']} message(s) in the poison queue"))
    if (q.get("unreachable") or 0) >= 10:
        bad.append((WARN, f"{q['unreachable']} messages unreachable"))
    for d in x.get("databases") or []:
        st = d["status"].lower()
        if st in EX_DB_BAD:
            bad.append((CRIT, f"{d['name']} copy {d['status']}" + (f": {d['message'][:80]}" if d.get("message") else "")))
        elif st in EX_DB_WARN:
            bad.append((WARN, f"{d['name']} copy {d['status']}"))
        elif (d.get("copy_queue") or 0) > 10:
            bad.append((WARN, f"{d['name']} copy queue {d['copy_queue']}"))
        if d.get("index", "").lower() in ("failed", "failedandsuspended"):
            bad.append((WARN, f"{d['name']} search index {d['index']}"))
    if bad:
        bad.sort(key=lambda b: b[0] != CRIT)
        lvl = CRIT if any(b[0] == CRIT for b in bad) else WARN
        return lvl, bad[0][1][0].upper() + bad[0][1][1:] + (f"; {len(bad) - 1} more" if len(bad) > 1 else "")
    parts = []
    if q:
        parts.append(f"{q.get('delivery') or 0} queued")
    dbs = x.get("databases")
    if dbs:
        parts.append(f"{sum(1 for d in dbs if d['status'].lower() == 'mounted')} database(s) mounted, {sum(1 for d in dbs if d['status'].lower() == 'healthy')} copies healthy")
    return OK, "Mail flowing: " + ", ".join(parts) if parts else "No problems found"


SQL_BAD_STATES = {"SUSPECT", "RECOVERY_PENDING", "EMERGENCY"}
# Databases their own application protects or can rebuild: SQL backups of them aren't expected
SQL_SELF_MANAGED = re.compile(r"^(VeeamBackup|VeeamBackupReporting|VeeamOne|VeeamONE\w*|VBR\w*|SUSDB)$", re.I)


def sql_db_state(i: dict, d: dict, now: float, backup_hours: float = 36, ign: "Ignore | None" = None) -> tuple[str, str, str]:
    """(level, state, why) for one database: OK/WARN/CRIT plus a short state for the table."""
    name = d["name"]
    if ign and (ign.has("sqldb", name) or ign.has("sqldb", f"{i['instance']}\\{name}") or ign.has("sqldb", f"{i['instance']}\\*")):
        return OK, "ignored", ""
    if d["state"] in SQL_BAD_STATES:
        return CRIT, "bad", d["state"].replace("_", " ").lower()
    if d["state"] == "OFFLINE":
        return WARN, "offline", "offline"
    if d["state"] != "ONLINE":
        return OK, "other", d["state"].replace("_", " ").lower()  # restoring (log shipping) or recovering
    if d["snapshot"]:
        return OK, "snapshot", "database snapshot"
    if i.get("internal"):  # Windows Internal Database: its role (WSUS, AD FS, RD Broker) looks after backups
        return OK, "ok", "managed by Windows"
    problems = []
    managed = bool(SQL_SELF_MANAGED.match(name))
    if not d["system"] and not managed and i.get("backups_read") and not (d.get("ag") and d.get("ag_preferred") is False):
        last = max((t for t in (_ts(d.get("last_full")), _ts(d.get("last_diff"))) if t), default=None)
        created = _ts(d.get("created"))
        if not (created and now - created < backup_hours * 3600):
            if last is None:
                problems.append("no backup in the last 35 days")
            elif now - last > backup_hours * 3600:
                problems.append(f"last backup {int((now - last) / 3600)} h ago")
    if d["recovery"] in ("FULL", "BULK_LOGGED") and d["log_wait"] == "LOG_BACKUP" and not d["system"]:
        lastlog = _ts(d.get("last_log"))
        if not lastlog or now - lastlog > 24 * 3600:
            size = f" ({d['log_mb']:.0f} MB)" if d.get("log_mb") else ""
            problems.append(f"full recovery, but the log isn't being backed up, so it keeps growing{size}")
    if problems:
        return WARN, "attention", "; ".join(problems)
    return OK, "ok", "backed up by its application" if managed else ""


def sql_state(sql: dict, now: float, backup_hours: float = 36, ign: "Ignore | None" = None) -> tuple[str, str] | None:
    insts = sql.get("instances") or []
    if not insts:
        return None
    bad = []  # (level, text)
    ok_dbs = wid_dbs = 0
    for i in insts:
        n = i["instance"]
        if ign and ign.has("sqldb", f"{n}\\*"):
            continue
        if i.get("internal") and i.get("connect_error"):
            continue  # a role's internal database we can't reach: not worth an alert
        if i.get("connect_error"):
            why = i["connect_error"]
            hint = " (the computer's account, SYSTEM, needs a login)" if re.search(r"login failed", why, re.I) else ""
            bad.append((WARN, f"{n}: can't connect{hint}: {why[:120]}"))
            continue
        for d in i.get("databases") or []:
            lvl, _st, why = sql_db_state(i, d, now, backup_hours, ign)
            if lvl != OK:
                bad.append((lvl, f"{d['name']}: {why}"))
            elif d["state"] == "ONLINE" and not i.get("internal"):
                ok_dbs += 1
            elif d["state"] == "ONLINE":
                wid_dbs += 1
        for j in i.get("jobs") or []:
            if j["enabled"] and j["outcome"] == "failed" and not (ign and ign.has("sqljob", j["name"])):
                t = _ts(j.get("last_run"))
                if t and now - t < 30 * DAY:
                    bad.append((WARN, f"job '{j['name']}' failed"))
        if i.get("denied") and not i.get("internal"):
            bad.append((WARN, f"{n}: can't read {', '.join(i['denied'])} (permission; see Details)"))
    if bad:
        bad.sort(key=lambda b: b[0] != CRIT)
        lvl = CRIT if any(b[0] == CRIT for b in bad) else WARN
        return lvl, bad[0][1] + (f"; {len(bad) - 1} more" if len(bad) > 1 else "")
    backed = all(i.get("backups_read") for i in insts if not i.get("internal"))
    user = [i for i in insts if not i.get("internal")]
    parts = [f"{ok_dbs} database(s) online" + (" and backed up" if backed else "") + (f" on {len(user)} instances" if len(user) > 1 else "")] if user else []
    if wid_dbs:
        parts.append(f"Windows Internal Database: {wid_dbs} database(s) online")
    return OK, "; ".join(parts) or "No databases to check"


def backup_job_key(j: dict) -> str:
    return str(j.get("id") or j.get("name") or "")[:200]


def backup_forgotten(j: dict, forgot: dict) -> bool:
    """Forgotten from the dashboard, and nothing newer has arrived for it since."""
    f = (forgot or {}).get(backup_job_key(j))
    return bool(f) and (_ts(j.get("finished")) or 0) <= (_ts(f.get("finished")) or 0)


def backup_jobs_view(jobs: list, forgot: dict | None = None) -> list:
    """Veeam jobs as the checks should judge them.

    A backup copy job that copies several source jobs logs each source's copy as its own job,
    "<copy job>\\<source job>", and the copy job itself only logs a result when one of its own
    sessions ends (e.g. "Retry of Backup Copy job 'X' finished with Failed"). That can be hours
    or days later, so its failure would otherwise stick after every copy since has succeeded.
    It counts as superseded once copies have finished since it, and none of those failed.
    "Retry of " is also dropped from the type ("Retry of Backup Copy" -> "Backup Copy")."""
    out = []
    for j in jobs:
        if backup_forgotten(j, forgot):
            continue
        j = dict(j)
        if str(j.get("type") or "").startswith("Retry of "):
            j["type"] = j["type"][len("Retry of "):]
        out.append(j)
    for j in out:
        name, res = str(j.get("name") or ""), str(j.get("result") or "").lower()
        if not name or "\\" in name:
            continue
        kids = [c for c in out if str(c.get("name") or "").lower().startswith(name.lower() + "\\")]
        if kids:
            # Its copies are each checked for being overdue; the copy job itself only logs now and
            # then, so judge it by them: last success is the latest successful copy, and no overdue of its own.
            j["copies"] = len(kids)
            ok = [c.get("last_success") for c in kids if _ts(c.get("last_success"))]
            best = max(ok + [j.get("last_success")] if _ts(j.get("last_success")) else ok, key=_ts, default=None)
            if best:
                j["last_success"] = best
        if res not in ("failed", "warning", "stopped", "disconnected"):
            continue
        since = [c for c in kids if _ts(c.get("finished")) and _ts(j.get("finished")) and _ts(c.get("finished")) > _ts(j.get("finished"))]
        if since and all(str(c.get("result") or "").lower() in ("success", "warning") for c in since):
            j["superseded"] = {"result": j.get("result"), "finished": j.get("finished")}
            j["result"], j["detail"] = "Success", f"Last run {res}; {len(since)} copy session(s) have succeeded since"
            j["last_success"] = max((c.get("finished") for c in since), key=_ts)
    return out


def backup_job_state(j: dict, now: float) -> tuple[str, str]:
    """(level, why) for one Veeam job: its last result, and whether it's overdue."""
    res = (j.get("result") or "").lower()
    if j.get("source") == "Microsoft 365" and j.get("enabled") is False:
        return OK, "disabled"
    if res == "failed":
        return (WARN, "failed, will be retried") if j.get("retry") else (CRIT, "failed")
    if res in ("stopped", "disconnected", "notconfigured"):
        return WARN, res
    if j.get("source") == "Microsoft 365":
        nxt = _ts(j.get("next_run"))
        if nxt and now > nxt + 2 * 3600 and res not in ("running", "queued"):
            return WARN, "missed its scheduled run"
    elif not j.get("copies"):  # a copy job with per-source copies is judged by them (backup_jobs_view)
        last = _ts(j.get("last_success")) or _ts(j.get("finished"))
        runs = sorted(t for t in (_ts(x) for x in j.get("runs") or []) if t)
        gaps = sorted(b - a for a, b in zip(runs, runs[1:]) if b - a > 600)
        limit = 8 * 86400
        if len(gaps) >= 2:  # learn the job's rhythm from its recent runs
            limit = min(35 * 86400, max(26 * 3600, 1.5 * gaps[len(gaps) // 2] + 2 * 3600))
        if last and now - last > limit:
            return WARN, f"no successful run for {int((now - last) // 3600)} h"
    if res == "warning":
        return WARN, "finished with warnings"
    return OK, ""


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
        pk = report.get("reboot_packages") or []
        kbs = [m for x in pk for m in re.findall(r"KB\d{6,8}", x)] or [x if len(x) <= 60 else x[:57] + "..." for x in pk]
        bits.append("Reboot pending" + (f" ({', '.join(kbs[:2])}{f' and {len(kbs) - 2} more' if len(kbs) > 2 else ''})" if kbs else ""))
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
            if immich_update(im) and not ign.has("update", "immich"):
                level = max(level, WARN, key=[OK, WARN, CRIT].index)
                bits.insert(0, f"update available: v{im['latest']} (running v{im.get('version')})")
            if not bits:
                bits.append(f"{busy} job(s) queued" if qs else "API answering")
            checks.append(_check("immich", "Immich", level, f"Immich{ver}: " + "; ".join(bits)))

    st = rc.get("storage")
    if st:
        crit, warn, total = [], [], 0
        bad_words = ("lost communication", "failed", "detached", "incomplete", "missing", "error", "no redundancy")
        for d in st.get("physical") or []:
            nm = f"{d.get('name') or 'Disk'}" + (f" ({d.get('serial')})" if d.get("serial") else "")
            if ign.has("storage", d.get("name")) or ign.has("storage", d.get("serial")):
                continue
            total += 1
            h, s_ = (d.get("health") or "").lower(), (d.get("status") or "").lower()
            if h == "unhealthy" or any(w in s_ for w in bad_words):
                crit.append(f"disk {nm}: {d.get('status') or d.get('health')}")
            elif h == "warning" or "predictive" in s_:
                warn.append(f"disk {nm}: {d.get('status') or d.get('health')}")
        for v in st.get("virtual") or []:
            if ign.has("storage", v.get("name")):
                continue
            total += 1
            h, s_ = (v.get("health") or "").lower(), (v.get("status") or "").lower()
            label = f"{v.get('name')}" + (f" ({v.get('layout')})" if v.get("layout") else "")
            # Storage Spaces reports a failed disk as Degraded with health Warning; an
            # mdadm array that's already rebuilding says so, and is only amber.
            if h == "unhealthy" or ("degraded" in s_ and "rebuild" not in s_) or any(w in s_ for w in bad_words):
                crit.append(f"{label}: {v.get('status') or v.get('health')}")
            elif h == "warning":
                warn.append(f"{label}: {v.get('status') or v.get('health')}")
        for v in st.get("volumes") or []:
            name = f"{v.get('letter')}:" if v.get("letter") else (v.get("label") or v.get("volume"))
            if ign.has("storage", name) or ign.has("storage", v.get("volume")):
                continue
            total += 1
            s_ = (v.get("status") or "").lower()
            desc = f"{v.get('type')} {name} {v.get('status')}"
            if s_ in ("failed rd", "failed", "missing") or "fail" in s_:
                crit.append(desc.replace("Failed Rd", "failed redundancy (a disk has failed)"))
            elif s_ in ("rebuild", "resynching", "regenerating", "at risk") or s_ not in ("healthy", ""):
                warn.append(desc)
        for d in st.get("dyn_disks") or []:
            if ign.has("storage", d.get("disk")):
                continue
            crit.append(f"{d.get('disk')}: {d.get('status')}")
        for d in st.get("drives") or []:
            if ign.has("storage", d.get("name")):
                continue
            (warn if "pred" in (d.get("status") or "").lower() else crit).append(f"{d.get('name')}: {d.get('status')}")
        warn += [w for w in st.get("warnings") or [] if not ign.has("storage", w)]
        if crit or warn or total:
            if crit:
                checks.append(_check("storage", "Storage", CRIT, "; ".join(crit + warn), confirm=True))
            elif warn:
                checks.append(_check("storage", "Storage", WARN, "; ".join(warn)))
            else:
                checks.append(_check("storage", "Storage", OK, f"{total} disk(s) and array(s) healthy"))

    bk = rc.get("backups")
    if bk is not None:
        now_ = now or time.time()
        bad, warn, n = [], [], 0
        for j in backup_jobs_view(bk.get("jobs") or [], settings.get("backup_forgot")):
            if ign.has("backup", j.get("name")):
                continue
            n += 1
            lvl, why = backup_job_state(j, now_)
            if lvl == CRIT:
                bad.append(f"{j['name']}: {why}")
            elif lvl == WARN:
                warn.append(f"{j['name']}: {why}")
        if bad:
            checks.append(_check("backups", "Backups", CRIT, "; ".join(bad + warn)))
        elif warn:
            checks.append(_check("backups", "Backups", WARN, "; ".join(warn)))
        elif n:
            checks.append(_check("backups", "Backups", OK, f"All {n} job(s) OK"))

    # Server hardware from Dell OpenManage (power supplies, fans, temperatures, memory...).
    hw = [h for h in ((st or {}).get("hardware") or []) if not ign.has("hardware", h.get("component"))]
    if hw:
        # "Hardware Log" is how full the server's event log is, not a fault: shown in
        # Details, but it doesn't change the check.
        bad = [h for h in hw if (h.get("severity") or "Ok").lower() not in ("ok", "")
               and (h.get("component") or "").lower() != "hardware log"]
        crit_hw = [h for h in bad if (h.get("severity") or "").lower() in ("critical", "non-recoverable")]
        if bad:
            checks.append(_check("hardware", "Hardware", CRIT if crit_hw else WARN,
                                 "; ".join(f"{h.get('component')}: {h.get('severity')}" for h in bad), confirm=bool(crit_hw)))
        else:
            checks.append(_check("hardware", "Hardware", OK, f"All {len(hw)} components OK (OpenManage)"))

    laps = rc.get("laps")
    if laps and not ign.has("laps", "laps"):
        level, detail, info = laps_state(laps, now, float(opts.get("agent_laps_overdue_days", 3)))
        checks.append(_check("laps", "LAPS", level, detail, confirm=level == CRIT, info=info))

    dm = rc.get("domain")
    if dm and not ign.has("domain", "domain"):
        res = domain_state(dm, settings.get("domain_changes") or [], now, 180, ign)
        checks.append(_check("domain", "Domain security", res[0], res[1]))

    ex = rc.get("exchange")
    if ex and not ign.has("exchange", "exchange"):
        res = exchange_state(ex, now, int(opts.get("agent_exchange_queue_warn", 250)))
        if res:
            checks.append(_check("exchange", "Exchange", res[0], res[1], confirm=res[0] == CRIT))

    gp = rc.get("gpo")
    if gp and not ign.has("gpo", "gpo"):
        res = gpo_state(gp, now)
        if res:
            checks.append(_check("gpo", "Group Policy", res[0], res[1]))
    sv = rc.get("sysvol")
    if sv and not ign.has("sysvol", "sysvol"):
        res = sysvol_state(sv, now)
        checks.append(_check("sysvol", "SYSVOL replication", res[0], res[1], confirm=res[0] == CRIT))

    sq = rc.get("sql")
    if sq and not ign.has("sqldb", "sql"):
        res = sql_state(sq, now, float(opts.get("agent_sql_backup_hours", 36)), ign)
        if res:
            checks.append(_check("sql", "SQL Server", res[0], res[1], confirm=res[0] == CRIT))

    tk = rc.get("tasks")
    if tk and report.get("workstation") is not True and not ign.has("task", "tasks"):  # servers only: PCs are full of vendor tasks
        res = tasks_check(tk, now, ign)
        if res:
            checks.append(_check("tasks", "Scheduled tasks", res[0], res[1]))

    cs = rc.get("certs")
    if cs and not ign.has("cert", "certs"):
        res = cert_store_state(cs.get("certs") or [], now, int(opts.get("cert_warn_days", 30)), int(opts.get("cert_crit_days", 7)), ign)
        if res:
            checks.append(_check("certs", "Certificates", res[0], res[1], confirm=res[0] == CRIT, info=res[2]))

    bl = rc.get("bitlocker")
    if bl and not ign.has("bitlocker", "bitlocker"):
        require = str(opts.get("agent_bitlocker_require", "workstations"))
        res = bitlocker_state(bl, report.get("workstation") is True, require if require in BITLOCKER_REQUIRE else "workstations", ign,
                              report.get("pending_reboot") is True, str(report.get("virtual") or ""))
        if res:
            checks.append(_check("bitlocker", "BitLocker", res[0], res[1]))

    nics = rc.get("nics")
    if nics:
        res = nic_state(nics, settings.get("nic_watch") or {})
        if res:
            checks.append(_check("nics", "Network", res[0], res[1], confirm=res[0] == CRIT))

    gi = report.get("agent_integrity")
    if gi and gi.get("at"):
        # The agent found its own folder's permissions changed (e.g. opened up to read its log) and put them back
        when = _ts(gi["at"])
        what = "; ".join(gi.get("what") or []) or "permissions had been changed"
        acked = float(settings.get("integrity_ack") or 0)
        if gi.get("first"):
            checks.append(_check("integrity", "Agent files", OK, f"Locked down when the agent updated ({what})"))
        elif when and acked >= when:
            checks.append(_check("integrity", "Agent files", OK, f"Acknowledged: put back at {time.strftime('%H:%M %d %b', time.localtime(when))} ({what})"))
        elif when and time.time() - when < 86400:
            checks.append(_check("integrity", "Agent files", WARN, f"Put back at {time.strftime('%H:%M', time.localtime(when))}: {what}"))
        else:
            checks.append(_check("integrity", "Agent files", OK, f"Locked down (last put back {time.strftime('%d %b', time.localtime(when or 0))})"))

    rs = report.get("secrets")
    if rs and rs.get("on") and settings.get("secret_scan_on", True):  # turned off in Rollcall: gone straight away
        res = secrets_state(rs, settings.get("secret_findings") or [], ign, float(settings.get("secret_ack") or 0))
        checks.append(_check("secrets", "Passwords in files", res[0], res[1]))

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
    notable["security"] = [dict(item) for item in sec.get("items") or []]
    apply_sec_filters(notable["security"], settings.get("sec_filters") or [], alert_ids)
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
