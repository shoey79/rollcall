"""Known vulnerabilities (CVEs) in what the agents report, from public data Rollcall downloads.

- Windows: Microsoft's security update data (the MSRC CVRF API, monthly). Each CVE lists the build
  that fixes it on each Windows version, e.g. 10.0.17763.6414. A computer whose build (with its
  update revision, from the agent) is lower on the same Windows version is missing that fix, so no
  product names need matching. The last 12 months are kept; a computer further behind than that is
  already flagged by the Updates check.
- Linux: OSV.dev's data for Debian, Ubuntu, AlmaLinux and Rocky Linux. Either the add-on downloads
  each distro's data and matches here ("local": nothing about the computers is sent anywhere), or
  it asks OSV.dev's API with one combined list of package names and versions ("online"). Only
  vulnerabilities with a fixed version newer than the one installed count: something an update
  fixes, rather than issues the distro hasn't fixed (or decided not to).
- CISA's Known Exploited Vulnerabilities list: CVEs known to be attacked in the wild.

Scores are CVSS base scores: Microsoft's own, or computed here from the CVSS 3.x vector in the
OSV record. A CVE with no CVSS 3.x score only counts if it's known to be exploited.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import math
import re
import zipfile
from pathlib import Path

MSRC_LIST = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_MONTHS = 12
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_ZIP = "https://storage.googleapis.com/osv-vulnerabilities/{eco}/all.zip"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"

# The distros Rollcall checks: /etc/os-release ID -> (OSV export folder, record id prefix)
DISTROS = {"debian": ("Debian", "DEBIAN-CVE-"), "ubuntu": ("Ubuntu", "UBUNTU-CVE-"),
           "almalinux": ("AlmaLinux", "ALSA-"), "rocky": ("Rocky Linux", "RLSA-")}
ID_ALIASES = {"raspbian": "debian"}  # Raspberry Pi OS (32-bit) rebuilds Debian's packages
RPM_DISTROS = ("almalinux", "rocky")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


# -- CVSS 3.x base score ----------------------------------------------------------------------
_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """The base score of a CVSS 3.0 or 3.1 vector, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3."):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        av, ac, ui = _W["AV"][m["AV"]], _W["AC"][m["AC"]], _W["UI"][m["UI"]]
        c, i, a = (_W["C"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    return _roundup(min(1.08 * (impact + expl), 10)) if scope_changed else _roundup(min(impact + expl, 10))


def osv_score(rec: dict) -> float | None:
    """The highest CVSS 3.x base score in an OSV record's severity list."""
    best = None
    for s in rec.get("severity") or []:
        if isinstance(s, dict) and s.get("type") == "CVSS_V3":
            v = cvss3_score(str(s.get("score") or ""))
            if v is not None and (best is None or v > best):
                best = v
    return best


# -- version comparison -------------------------------------------------------------------------
def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    up, _, rev = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, up, rev


def dpkg_cmp(a: str, b: str) -> int:
    """Compare two Debian package versions the way dpkg does: -1, 0 or 1."""
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def _rpmvercmp(a: str, b: str) -> int:
    """rpm's rpmvercmp(): segments of digits or letters; ~ sorts before everything, ^ after."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if not (i < len(a) and a[i] == "~"):
                return 1
            if not (j < len(b) and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        isnum = a[i].isdigit()
        si, sj = i, j
        if isnum:
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
        else:
            while i < len(a) and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isalpha():
                j += 1
        x, y = a[si:i], b[sj:j]
        if not y:
            return 1 if isnum else -1
        if isnum:
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _evr(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    ver, _, rel = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, ver, rel


def rpm_cmp(a: str, b: str) -> int:
    """Compare two RPM versions ([epoch:]version-release): -1, 0 or 1."""
    ea, va, ra = _evr(a)
    eb, vb, rb = _evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpmvercmp(va, vb) or (_rpmvercmp(ra, rb) if ra and rb else 0)


def _build(v: str) -> tuple[int, ...] | None:
    parts = str(v or "").strip().split(".")
    return tuple(int(p) for p in parts) if len(parts) == 4 and all(p.isdigit() for p in parts) else None


# -- Microsoft -----------------------------------------------------------------------------------
_WINDOWS_OS = re.compile(r"^Windows (?:\d|Server|RT)(?!.*Hotpatch)", re.I)


def _val(d) -> str:
    return (d.get("Value") or "") if isinstance(d, dict) else ""


def msrc_compact(doc: dict) -> dict:
    """One month's CVRF document -> {"10.0.17763": {"CVE-…": [fixed revision, score, exploited, "KB…"]}}.
    Only Windows itself (a product named Windows with a fixed build of the form 10.0.BUILD.REV)."""
    names = {}
    if not isinstance(doc, dict):
        return {}
    for p in (doc.get("ProductTree") or {}).get("FullProductName") or []:
        if isinstance(p, dict):
            names[str(p.get("ProductID"))] = str(p.get("Value") or "")
    out: dict = {}
    for v in doc.get("Vulnerability") or []:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("CVE") or "")
        if not _CVE.fullmatch(cve):
            continue
        scores = {}
        for s in v.get("CVSSScoreSets") or []:
            if not isinstance(s, dict):
                continue
            try:
                sc = float(s.get("BaseScore"))
            except (TypeError, ValueError):
                continue
            for pid in s.get("ProductID") or []:
                scores[str(pid)] = max(sc, scores.get(str(pid), 0))
        exploited = any(t.get("Type") == 1 and re.search(r"Exploited:\s*Yes", str(_val(t.get("Description"))), re.I)
                        for t in v.get("Threats") or [] if isinstance(t, dict))
        for r in v.get("Remediations") or []:
            if not isinstance(r, dict) or r.get("Type") != 2:  # 2: vendor fix
                continue
            fb = _build(r.get("FixedBuild"))
            if not fb:
                continue
            pids = [str(p) for p in r.get("ProductID") or [] if _WINDOWS_OS.match(names.get(str(p), ""))]
            if not pids:  # not Windows itself (Office, SQL Server, the Windows SDK…), or a hotpatch-only edition
                continue
            prefix = f"{fb[0]}.{fb[1]}.{fb[2]}"
            score = max((scores.get(p, 0) for p in pids), default=0) or max(scores.values(), default=0)
            kb = str(_val(r.get("Description")))[:20]
            have = out.setdefault(prefix, {}).get(cve)
            # Several editions on the same build (e.g. Windows 11 24H2 and Server 2025): the latest fix
            if have is None or fb[3] > have[0]:
                out[prefix][cve] = [fb[3], score, exploited, f"KB{kb}" if kb.isdigit() else kb]
    return out


def msrc_merge(months: list[dict]) -> dict:
    """Months (oldest first) -> one index. A CVE revised in a later month takes the later fix."""
    idx: dict = {}
    for m in months:
        for prefix, cves in m.items():
            d = idx.setdefault(prefix, {})
            for cve, e in cves.items():
                old = d.get(cve)
                d[cve] = e if old is None or e[0] >= old[0] else [old[0], max(old[1], e[1]), old[2] or e[2], old[3]]
    return idx


def windows_findings(build: str, idx: dict, kev: set, min_score: float) -> list[dict]:
    """CVEs fixed in a later build of this computer's Windows version."""
    b = _build(build)
    if not b or not idx:
        return []
    out = []
    for cve, (rev, score, expl, kb) in (idx.get(f"{b[0]}.{b[1]}.{b[2]}") or {}).items():
        if b[3] >= rev:
            continue
        exploited = expl or cve in kev
        if exploited or score >= min_score:
            out.append({"cve": cve, "score": score or None, "exploited": exploited, "what": "Windows", "installed": build,
                        "fixed": f"{b[0]}.{b[1]}.{b[2]}.{rev}", "ref": kb, "src": "Microsoft"})
    return out


# -- Linux (OSV) ---------------------------------------------------------------------------------
def os_key(os_id: str, version_id: str) -> str | None:
    """("debian", "12") -> "debian:12"; ("almalinux", "9.4") -> "almalinux:9"; None if not covered."""
    i = ID_ALIASES.get(str(os_id or "").lower(), str(os_id or "").lower())
    v = str(version_id or "").strip()
    if i not in DISTROS or not re.fullmatch(r"\d+(\.\d+)*", v):
        return None
    if i in RPM_DISTROS or i == "debian":
        v = v.split(".")[0]
    return f"{i}:{v}"


def eco_key(ecosystem: str) -> str | None:
    """OSV ecosystem -> os_key: "Debian:12" -> "debian:12", "Ubuntu:22.04:LTS" -> "ubuntu:22.04",
    "Rocky Linux:9" -> "rocky:9". Ubuntu Pro and FIPS streams aren't matched."""
    parts = str(ecosystem or "").split(":")
    if len(parts) < 2:
        return None
    base = {"Debian": "debian", "Ubuntu": "ubuntu", "AlmaLinux": "almalinux", "Rocky Linux": "rocky"}.get(parts[0])
    if not base or not re.fullmatch(r"\d+(\.\d+)*", parts[1]):
        return None
    return f"{base}:{parts[1].split('.')[0] if base != 'ubuntu' else parts[1]}"


def osv_ecosystem(key: str) -> str | None:
    """os_key -> the ecosystem name OSV's API expects."""
    d, _, v = key.partition(":")
    if d == "debian":
        return f"Debian:{v}"
    if d == "ubuntu":
        yy, _, mm = v.partition(".")
        return f"Ubuntu:{v}:LTS" if mm == "04" and yy.isdigit() and int(yy) % 2 == 0 else f"Ubuntu:{v}"
    if d == "almalinux":
        return f"AlmaLinux:{v}"
    if d == "rocky":
        return f"Rocky Linux:{v}"
    return None


def osv_entries(rec: dict, wanted: set) -> list[tuple]:
    """(os_key, package, [cves, introduced, fixed, score]) for each fixed range in one OSV record."""
    if not isinstance(rec, dict) or rec.get("withdrawn"):
        return []
    rid = str(rec.get("id") or "")
    refs = [rid] + [str(x) for k in ("aliases", "upstream", "related") for x in rec.get(k) or []]
    cves = sorted({c for r in refs for c in _CVE.findall(r)}) or [rid]
    score = osv_score(rec)
    out = []
    for a in rec.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        key = eco_key(pkg.get("ecosystem"))
        name = str(pkg.get("name") or "")
        if key not in wanted or not name:
            continue
        for r in a.get("ranges") or []:
            if not isinstance(r, dict) or r.get("type") != "ECOSYSTEM":
                continue
            intro = None
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    intro = str(ev["introduced"])
                elif "fixed" in ev and intro is not None:
                    out.append((key, name, [" ".join(cves), intro, str(ev["fixed"]), score]))
                    intro = None
    return out


def osv_index_zip(path_or_bytes, distro: str, wanted: set) -> dict:
    """An OSV export (all.zip for one distro) -> {os_key: {package: [[cves, introduced, fixed, score], …]}},
    for the releases wanted only. Reads one record at a time, so memory stays small."""
    prefix = DISTROS[distro][1]
    idx: dict = {}
    src = io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, (bytes, bytearray)) else path_or_bytes
    with zipfile.ZipFile(src) as z:
        for n in z.namelist():
            if not n.endswith(".json") or not Path(n).name.startswith(prefix):
                continue
            try:
                rec = json.loads(z.read(n))
            except (ValueError, KeyError, zipfile.BadZipFile):
                continue
            for key, pkg, e in osv_entries(rec, wanted):
                idx.setdefault(key, {}).setdefault(pkg, []).append(e)
    return idx


def linux_findings(apps: list, key: str, idx: dict, kev: set, min_score: float) -> list[dict]:
    """CVEs in installed packages that a newer version of the package fixes."""
    pk = (idx or {}).get(key)
    if not pk:
        return []
    cmp = rpm_cmp if key.split(":")[0] in RPM_DISTROS else dpkg_cmp
    # One version per source package: the newest installed (e.g. the old kernel still installed
    # alongside the running one isn't counted).
    best: dict = {}
    for a in apps or []:
        names = {a.get("src") or a.get("name")} | ({a.get("name")} if key.split(":")[0] in RPM_DISTROS else set())
        ver = a.get("srcver") or a.get("version") or ""
        for n in names:
            if n and ver and (n not in best or cmp(ver, best[n][0]) > 0):
                best[n] = (ver, a.get("name"))
    out, seen = [], {}
    for n, (ver, shown) in best.items():
        for cves, intro, fixed, score in pk.get(n) or []:
            try:
                if (intro not in ("0", "") and cmp(ver, intro) < 0) or cmp(ver, fixed) >= 0:
                    continue
            except (ValueError, TypeError):
                continue
            for cve in cves.split():
                exploited = cve in kev
                if not (exploited or (score is not None and score >= min_score)):
                    continue
                f = {"cve": cve, "score": score, "exploited": exploited, "what": n, "installed": ver, "fixed": fixed,
                     "src": key.split(":")[0].capitalize().replace("Almalinux", "AlmaLinux")}
                if (cve, n) in seen:  # the same CVE in two ranges of this package: keep the later fix
                    if cmp(fixed, seen[(cve, n)]["fixed"]) > 0:
                        seen[(cve, n)].update(fixed=fixed)
                    continue
                seen[(cve, n)] = f
                out.append(f)
    return out


def summarise(findings: list[dict], min_score: float) -> tuple[str, str]:
    """("ok"|"warn"|"crit", detail) for the Vulnerabilities check: red only when one is known to be
    exploited; anything else at or above the score is amber."""
    if not findings:
        return "ok", f"No known vulnerabilities scoring {min_score:g} or more"
    findings = sorted(findings, key=lambda f: (not f["exploited"], -(f["score"] or 0), f["cve"]))
    expl = [f for f in findings if f["exploited"]]
    parts = []
    for f in findings[:3]:
        tag = ([f"{f['score']:.1f}"] if f["score"] else []) + (["exploited"] if f["exploited"] else [])
        parts.append(f"{f['what']} {f['cve']}" + (f" ({', '.join(tag)})" if tag else "")
                     + (f", fixed in {f['fixed']}" if f["what"] != "Windows" else ""))
    head = (f"{len(expl)} known-exploited, " if expl else "") + f"{len(findings)} CVE{'s' if len(findings) != 1 else ''}"
    win = [f["fixed"] for f in findings if f["what"] == "Windows"]
    tail = f"; Windows fixed in build {max(win, key=lambda v: _build(v) or ())}" if win else ""
    more = f" and {len(findings) - 3} more" if len(findings) > 3 else ""
    return ("crit" if expl else "warn"), f"{head}: {'; '.join(parts)}{more}{tail}"[:300]


# -- downloading ---------------------------------------------------------------------------------
class Feeds:
    """The downloaded data, kept in a folder under /data so a restart doesn't download it all again.
    refresh() is called about hourly; each source is only fetched again when it's ~a day old."""

    DAY = 20 * 3600

    def __init__(self, folder: Path, log):
        self.dir, self.log = folder, log
        self.msrc: dict = {}        # build prefix -> {cve: [fixed revision, score, exploited, kb]}
        self.kev: set = set()
        self.osv: dict = {}         # os_key -> {package: [[cves, introduced, fixed, score]]}
        self.covered: set = set()   # releases whose data is in (a release with nothing to fix has no entries)
        self.version = 0            # goes up whenever the data changes (cached results are redone)
        self.info: dict = {}        # for the dashboard: what's loaded, when, and any error
        self.meta: dict = {}

    # -- files
    def _read(self, name: str, default=None):
        try:
            return json.loads((self.dir / name).read_text())
        except (OSError, ValueError):
            return default

    def _write(self, name: str, data) -> None:
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")))
        tmp.replace(p)

    def load(self) -> None:
        self.meta = self._read("meta.json", {}) or {}
        months = [self._read(f"msrc/{m}.json", {}) or {} for m in self.meta.get("msrc_ids") or []]
        self.msrc = msrc_merge(list(reversed(months)))
        self.kev = set(self._read("kev.json", []) or [])
        self.osv = {}
        mode = self.meta.get("osv_mode")
        self.covered = set(self.meta.get("osv_covered") or []) if mode in ("local", "online") else set()
        if mode == "online":
            self.osv = (self._read("osv/online-index.json", {}) or {}).get("idx") or {}
        elif mode == "local":
            for d in DISTROS:
                self.osv.update((self._read(f"osv/{d}-index.json", {}) or {}).get("idx") or {})
        self.version += 1
        self._info()

    def _info(self) -> None:
        m = self.meta
        self.info = {"msrc_months": len(m.get("msrc_ids") or []), "msrc_at": m.get("msrc_at"), "kev": len(self.kev), "kev_at": m.get("kev_at"),
                     "osv_mode": m.get("osv_mode"), "osv_at": m.get("osv_at"), "osv_releases": sorted(self.osv),
                     "errors": dict(m.get("errors") or {})}

    def _err(self, what: str, err) -> None:
        self.meta.setdefault("errors", {})[what] = str(err)[:200]
        self.log.warning("Vulnerabilities: couldn't update %s (%s); trying again in an hour", what, err)

    def _ok(self, what: str) -> None:
        (self.meta.get("errors") or {}).pop(what, None)

    # -- sources
    async def _json(self, session, url: str, **kw):
        async with session.get(url, headers={"Accept": "application/json"}, **kw) as r:
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status}")
            body = await r.read()
        # Microsoft's monthly documents are many MB: parse them off the event loop
        return await asyncio.get_running_loop().run_in_executor(None, json.loads, body) if len(body) > 200_000 else json.loads(body)

    async def refresh_msrc(self, session, now: float) -> bool:
        if now - (self.meta.get("msrc_at") or 0) < self.DAY:
            return False
        lst = (await self._json(session, MSRC_LIST)).get("value") or []
        lst = sorted((d for d in lst if isinstance(d, dict) and d.get("ID") and d.get("CvrfUrl")),
                     key=lambda d: str(d.get("InitialReleaseDate") or ""), reverse=True)[:MSRC_MONTHS]
        seen = self.meta.setdefault("msrc_rev", {})
        changed = False
        for d in lst:
            mid = re.sub(r"[^A-Za-z0-9-]", "", str(d["ID"]))[:20]
            rev = str(d.get("CurrentReleaseDate") or "")
            if seen.get(mid) == rev and (self.dir / f"msrc/{mid}.json").exists():
                continue
            doc = await self._json(session, d["CvrfUrl"])
            compact = await asyncio.get_running_loop().run_in_executor(None, msrc_compact, doc)
            del doc
            self._write(f"msrc/{mid}.json", compact)
            seen[mid] = rev
            changed = True
        ids = [re.sub(r"[^A-Za-z0-9-]", "", str(d["ID"]))[:20] for d in lst]
        for p in (self.dir / "msrc").glob("*.json") if (self.dir / "msrc").exists() else []:
            if p.stem not in ids:
                p.unlink(missing_ok=True)
                seen.pop(p.stem, None)
                changed = True
        changed |= ids != self.meta.get("msrc_ids")
        self.meta.update(msrc_ids=ids, msrc_at=now)
        return changed

    async def refresh_kev(self, session, now: float) -> bool:
        if now - (self.meta.get("kev_at") or 0) < self.DAY:
            return False
        data = await self._json(session, KEV_URL)
        cves = sorted({str(v.get("cveID")) for v in data.get("vulnerabilities") or [] if isinstance(v, dict) and _CVE.fullmatch(str(v.get("cveID") or ""))})
        if not cves:
            raise RuntimeError("the list was empty")
        self.meta["kev_at"] = now
        if cves == sorted(self.kev):
            return False
        self._write("kev.json", cves)
        return True

    async def refresh_osv_local(self, session, wanted: set, now: float) -> bool:
        changed = False
        covered = set()
        for distro, (folder, _prefix) in DISTROS.items():
            want = sorted(k for k in wanted if k.startswith(distro + ":"))
            if not want:
                continue
            meta = self.meta.setdefault("osv_zip", {}).setdefault(distro, {})
            zpath = self.dir / f"osv/{distro}.zip"
            fresh = now - (meta.get("at") or 0) < self.DAY and zpath.exists()
            got_new = False
            if not fresh:
                hdrs = {"If-None-Match": meta["etag"]} if zpath.exists() and meta.get("etag") else {}
                async with session.get(OSV_ZIP.format(eco=folder.replace(" ", "%20")), headers=hdrs) as r:
                    if r.status == 200:
                        zpath.parent.mkdir(parents=True, exist_ok=True)
                        tmp = zpath.with_suffix(".tmp")
                        size = 0
                        with open(tmp, "wb") as f:
                            async for chunk in r.content.iter_chunked(1 << 20):
                                f.write(chunk)
                                size += len(chunk)
                        tmp.replace(zpath)
                        meta.update(etag=r.headers.get("ETag"), size=size)
                        got_new = True
                        self.log.info("Vulnerabilities: downloaded %s data from OSV (%.1f MB)", folder, size / 1e6)
                    elif r.status != 304:
                        raise RuntimeError(f"{folder}: HTTP {r.status}")
                meta["at"] = now
            idx_file = self._read(f"osv/{distro}-index.json", {}) or {}
            if got_new or idx_file.get("wanted") != want or idx_file.get("etag") != meta.get("etag"):
                idx = await asyncio.get_running_loop().run_in_executor(None, osv_index_zip, zpath, distro, set(want))
                await asyncio.get_running_loop().run_in_executor(
                    None, self._write, f"osv/{distro}-index.json", {"wanted": want, "etag": meta.get("etag"), "idx": idx})
                self.log.info("Vulnerabilities: %s index built for %s (%d packages)", folder, ", ".join(want),
                              sum(len(v) for v in idx.values()))
                changed = True
            covered |= set(want)
        if covered != set(self.meta.get("osv_covered") or []):
            self.meta["osv_covered"] = sorted(covered)
            changed = True
        return changed

    async def refresh_osv_online(self, session, queries: list, now: float) -> bool:
        """queries: [(os_key, package, version)], pooled across every computer."""
        qhash = hashlib.sha256(json.dumps(sorted(queries)).encode()).hexdigest()[:16]
        if qhash == self.meta.get("osv_qhash") and now - (self.meta.get("osv_online_at") or 0) < self.DAY:
            return False
        cache = self._read("osv/online-cache.json", {}) or {}
        ids: dict = {}  # id -> modified
        for i in range(0, len(queries), 500):
            part = queries[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": osv_ecosystem(k)}, "version": v} for k, n, v in part]}
            async with session.post(OSV_BATCH, json=body) as r:
                if r.status != 200:
                    raise RuntimeError(f"OSV query: HTTP {r.status}")
                res = await r.json(content_type=None)
            for (k, _n, _v), one in zip(part, res.get("results") or []):
                prefix = DISTROS[k.split(":")[0]][1]
                for v in (one or {}).get("vulns") or []:
                    vid = str(v.get("id") or "")
                    if vid.startswith(prefix):
                        ids[vid] = str(v.get("modified") or "")
        wanted = {k for k, _n, _v in queries}
        todo = [vid for vid, mod in ids.items() if (cache.get(vid) or {}).get("modified") != mod or (cache.get(vid) or {}).get("wanted") != sorted(wanted)]
        sem = asyncio.Semaphore(8)
        failed = []

        async def fetch(vid):
            async with sem:
                try:
                    rec = await self._json(session, OSV_VULN.format(id=vid))
                except Exception as err:  # noqa: BLE001 - one record mustn't stop the rest
                    self.log.debug("OSV %s: %s", vid, err)
                    failed.append(vid)
                    return
                cache[vid] = {"modified": ids[vid], "wanted": sorted(wanted),
                              "e": [[k, p, e] for k, p, e in osv_entries(rec, wanted)]}
        await asyncio.gather(*(fetch(v) for v in todo[:5000]))
        complete = not failed and len(todo) <= 5000  # otherwise the rest is fetched at the next hourly try
        idx: dict = {}
        for vid in ids:
            for k, p, e in (cache.get(vid) or {}).get("e") or []:
                idx.setdefault(k, {}).setdefault(p, []).append(e)
        cache = {k: v for k, v in cache.items() if k in ids}
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write, "osv/online-cache.json", cache)
        await loop.run_in_executor(None, self._write, "osv/online-index.json", {"idx": idx})
        if complete:
            self.meta.update(osv_qhash=qhash, osv_online_at=now, osv_covered=sorted(wanted))
        else:
            self.log.warning("Vulnerabilities: %d of %d OSV advisories still to fetch; trying again in an hour",
                             len(failed) + max(0, len(todo) - 5000), len(todo))
        self.log.info("Vulnerabilities: asked OSV about %d packages; %d advisories apply", len(queries), len(ids))
        return True

    async def refresh(self, session, now: float, linux_mode: str, wanted: set, queries: list) -> bool:
        """Bring everything up to date. True if anything changed (results need working out again)."""
        changed = False
        for what, job in (("Microsoft", lambda: self.refresh_msrc(session, now)), ("CISA", lambda: self.refresh_kev(session, now))):
            try:
                changed |= await job()
                self._ok(what)
            except Exception as err:  # noqa: BLE001
                self._err(what, err)
        if linux_mode != self.meta.get("osv_mode"):
            self.meta["osv_mode"] = linux_mode
            changed = True
        try:
            if linux_mode == "local" and wanted:
                changed |= await self.refresh_osv_local(session, wanted, now)
            elif linux_mode == "online" and queries:
                changed |= await self.refresh_osv_online(session, queries, now)
            if linux_mode in ("local", "online") and (wanted or queries):
                self.meta["osv_at"] = now
            self._ok("OSV")
        except Exception as err:  # noqa: BLE001
            self._err("OSV", err)
        self._write("meta.json", self.meta)
        if changed:
            await asyncio.get_running_loop().run_in_executor(None, self.load)
        else:
            self._info()
        return changed
