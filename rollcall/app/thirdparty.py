"""Known vulnerabilities in common Windows programs that Microsoft's update data doesn't cover (browsers, archivers,
PDF readers, remote-access tools...), from the US National Vulnerability Database (NVD).

Matching what Windows calls a program ("7-Zip 24.08 (x64)") to the NVD's name for it is where tools like this go
wrong, so Rollcall only checks programs on its own vetted list (CATALOG), plus any an admin adds by hand as
"program name = vendor:product". Each listed product's CVEs are fetched from the NVD's public API, which is only
told the product names in use, never device names or versions:

    GET https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>

Everything for a product is fetched once, then daily only what's changed since; the whole lot again monthly.
Without an API key the NVD allows 5 requests in 30 seconds, so requests are spaced out.

Each CVE's affected versions come from the NVD's own analysis (its "configurations"). CVEs the NVD hasn't analysed
yet have none and can't be matched, so a brand-new CVE may take a while to show.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000
SPACING = 6.5          # seconds between requests (5 per 30 s without a key)
FULL_DAYS = 30
DAY_HOURS = 20

# (what Rollcall calls it, the Windows program name it matches, NVD vendor:product names, where the version comes from)
# Versions come from the program's own version (DisplayVersion) unless "name" says to take them from its name.
CATALOG = [
    ("Google Chrome", r"^Google Chrome$", ["google:chrome"], None),
    ("Microsoft Edge", r"^Microsoft Edge$", ["microsoft:edge_chromium"], None),
    ("Mozilla Firefox", r"^Mozilla Firefox(?! ESR)\b", ["mozilla:firefox"], None),
    ("Mozilla Firefox ESR", r"^Mozilla Firefox ESR\b", ["mozilla:firefox_esr"], None),
    ("Mozilla Thunderbird", r"^Mozilla Thunderbird\b", ["mozilla:thunderbird"], None),
    ("7-Zip", r"^7-Zip\b", ["7-zip:7-zip"], None),
    ("WinRAR", r"^WinRAR\b", ["rarlab:winrar"], None),
    ("WinZip", r"^WinZip\b", ["corel:winzip"], None),
    ("Notepad++", r"^Notepad\+\+", [r"don_ho:notepad\+\+"], None),
    ("VLC media player", r"^VLC media player\b", ["videolan:vlc_media_player"], None),
    ("PuTTY", r"^PuTTY release\b", ["simon_tatham:putty"], None),
    ("WinSCP", r"^WinSCP\b", ["winscp:winscp"], None),
    ("FileZilla", r"^FileZilla\b(?! Server)", ["filezilla-project:filezilla_client"], None),
    ("FileZilla Server", r"^FileZilla Server\b", ["filezilla-project:filezilla_server"], None),
    ("KeePass", r"^KeePass Password Safe\b", ["keepass:keepass"], None),
    ("Wireshark", r"^Wireshark\b", ["wireshark:wireshark"], None),
    ("TeamViewer", r"^TeamViewer\b", ["teamviewer:teamviewer"], None),
    ("AnyDesk", r"^AnyDesk\b", ["anydesk:anydesk"], None),
    ("ScreenConnect", r"^(ConnectWise )?ScreenConnect$", ["connectwise:screenconnect"], None),
    ("TightVNC", r"^TightVNC\b", ["tightvnc:tightvnc"], None),
    ("UltraVNC", r"^UltraVNC\b", ["uvnc:ultravnc"], None),
    ("Zoom", r"^Zoom( Workplace)?( \((64|32)-bit\))?$", ["zoom:meetings", "zoom:workplace_desktop", "zoom:zoom"], None),
    ("Adobe Acrobat Reader", r"^Adobe Acrobat Reader\b", ["adobe:acrobat_reader_dc", "adobe:acrobat_reader"], None),
    ("Adobe Acrobat", r"^Adobe Acrobat( DC)?( \(64-bit\))?$", ["adobe:acrobat_dc", "adobe:acrobat"], None),
    ("Foxit PDF Reader", r"^Foxit (PDF )?Reader\b", ["foxit:pdf_reader", "foxit:reader"], None),
    ("LibreOffice", r"^LibreOffice\b", ["libreoffice:libreoffice"], None),
    ("GIMP", r"^GIMP\b", ["gimp:gimp"], None),
    ("Greenshot", r"^Greenshot\b", ["greenshot:greenshot"], None),
    ("Git", r"^Git( version [\d.]+)?$", ["git-scm:git", "git_for_windows_project:git_for_windows"], None),
    ("Python", r"^Python \d+\.\d+\.\d+ \((64|32)-bit\)$", ["python:python"], r"Python (\d+\.\d+\.\d+)"),
    ("Node.js", r"^Node\.js\b", ["nodejs:node.js"], None),
    ("Visual Studio Code", r"^Microsoft Visual Studio Code\b", ["microsoft:visual_studio_code"], None),
    ("PowerShell 7", r"^PowerShell 7\b", ["microsoft:powershell"], None),
    (".NET", r"^Microsoft \.NET (Runtime|Desktop Runtime|Host) - \d", ["microsoft:.net"], r"- (\d+\.\d+\.\d+)"),
    ("ASP.NET Core", r"^Microsoft ASP\.NET Core \d+\.\d+\.\d+ - ", ["microsoft:asp.net_core"], r"Core (\d+\.\d+\.\d+)"),
    ("VMware Tools", r"^VMware Tools$", ["vmware:tools"], None),
    ("Oracle VirtualBox", r"^Oracle (VM )?VirtualBox\b", ["oracle:vm_virtualbox"], None),
    ("Docker Desktop", r"^Docker Desktop$", ["docker:desktop"], None),
    ("OpenVPN", r"^OpenVPN \d", ["openvpn:openvpn"], r"OpenVPN (\d+\.\d+\.\d+)"),
    ("Cisco Secure Client", r"^Cisco (Secure Client|AnyConnect Secure Mobility Client)\b", ["cisco:secure_client", "cisco:anyconnect_secure_mobility_client"], None),
    ("GlobalProtect", r"^GlobalProtect$", ["paloaltonetworks:globalprotect"], None),
    ("FortiClient", r"^FortiClient\b", ["fortinet:forticlient"], None),
    ("Veeam Backup & Replication", r"^Veeam Backup & Replication( Server)?$", [r"veeam:veeam_backup_\&_replication", r"veeam:backup_\&_replication"], None),
    ("Openfire", r"^Openfire\b", ["igniterealtime:openfire"], None),
    ("Apache Tomcat", r"^Apache Tomcat \d", ["apache:tomcat"], None),
    ("MySQL Server", r"^MySQL Server \d", ["oracle:mysql"], None),
    ("MariaDB", r"^MariaDB \d", ["mariadb:mariadb"], None),
    ("PostgreSQL", r"^PostgreSQL \d", ["postgresql:postgresql"], None),
    ("Dell Command | Update", r"^Dell Command \| Update\b", ["dell:command_update"], None),
    ("Dell SupportAssist", r"^Dell SupportAssist\b", ["dell:supportassist_for_business_pcs", "dell:supportassist_for_home_pcs"], None),
]
_COMPILED = [(label, re.compile(rx, re.I), cpes, re.compile(vn) if vn else None) for label, rx, cpes, vn in CATALOG]
NOT_WINDOWS = {"android", "iphone_os", "ios", "ipados", "macos", "mac_os", "mac_os_x", "linux", "linux_kernel", "chrome_os", "chromeos", "tvos"}
PRODUCT_RE = re.compile(r"^[a-z0-9_\-.\\&+!~]+:[a-z0-9_\-.\\&+!~]+$", re.I)


def parse_extra(lines) -> list[tuple]:
    """Admin-added programs: "program name = vendor:product" lines. Bad lines are left out."""
    out = []
    for line in lines or []:
        name, sep, prod = str(line).partition("=")
        name, prod = name.strip(), prod.strip().lower()
        if not sep or not name or not PRODUCT_RE.match(prod):
            continue
        out.append((name, re.compile(r"^" + re.escape(name) + r"(?![A-Za-z0-9])", re.I), [prod], None))
    return out


def extra_errors(lines) -> list[str]:
    return [str(x) for x in lines or [] if str(x).strip() and not parse_extra([x])]


# -- versions -------------------------------------------------------------------------------------------
def _parts(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", str(v or ""))]


def ver_cmp(installed: str, bound: str) -> int:
    """Compare an installed version with one of the NVD's. Windows often adds parts the NVD doesn't use (8.0.11.34221
    for .NET 8.0.11), so the installed version is compared only as far as the NVD's goes; missing parts count as 0."""
    return _cmp(_parts(installed), _parts(bound))


def _cmp(a: list[int], b: list[int]) -> int:
    if not b:
        return 0
    if len(a) > len(b):
        a = a[:len(b)]
    n = max(len(a), len(b))
    a, b = a + [0] * (n - len(a)), b + [0] * (n - len(b))
    return (a > b) - (a < b)


def affected(version: str, r: list) -> bool:
    """r = [start incl, start excl, end incl, end excl, exact] (None where absent), as kept from the NVD."""
    return _affected(_parts(version), [_parts(x) if x else None for x in r])


def _affected(v: list[int], r: list) -> bool:
    """affected(), with the versions already split into numbers (thousands of comparisons per device)."""
    si, se, ei, ee, ex = r
    if ex is not None:
        return _cmp(v, ex) == 0
    if si is not None and _cmp(v, si) < 0:
        return False
    if se is not None and _cmp(v, se) <= 0:
        return False
    if ei is not None and _cmp(v, ei) > 0:
        return False
    if ee is not None and _cmp(v, ee) >= 0:
        return False
    return any(x is not None for x in r)


def installed_version(app: dict, from_name) -> str:
    if from_name:
        m = from_name.search(app.get("name") or "")
        if m:
            return m.group(1)
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", str(app.get("version") or ""))
    return m.group(1) if m else ""


def matches(apps: list[dict], extra: list | None = None) -> list[tuple]:
    """(index into the software list, label, NVD products, version) for each program on the list."""
    out = []
    entries = _COMPILED + list(extra or [])
    for i, a in enumerate(apps or []):
        name = str(a.get("name") or "")
        for label, rx, cpes, vn in entries:
            if rx.search(name):
                v = installed_version(a, vn)
                if v:
                    out.append((i, label, cpes, v))
                break
    return out


# -- the NVD's answers ------------------------------------------------------------------------------------
def _score(metrics: dict) -> float | None:
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for m in metrics.get(k) or []:
            s = ((m or {}).get("cvssData") or {}).get("baseScore")
            if isinstance(s, (int, float)):
                return float(s)
    return None


def _unescape(p: str) -> str:
    return re.sub(r"\\(.)", r"\1", p)


def parse_cve(cve: dict, product: str) -> tuple | None:
    """(score, ranges, summary) for this product, or None if the NVD doesn't (yet) say which versions it affects."""
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    vendor, prod = (_unescape(x) for x in product.split(":", 1))
    ranges = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                f = str(m.get("criteria") or "").split(":")
                if len(f) < 11 or f[2] != "a" or _unescape(f[3]).lower() != vendor.lower() or _unescape(f[4]).lower() != prod.lower():
                    continue
                if f[10].lower() in NOT_WINDOWS:
                    continue
                exact = _unescape(f[5]) if f[5] not in ("*", "-", "") else None
                r = [m.get("versionStartIncluding"), m.get("versionStartExcluding"), m.get("versionEndIncluding"), m.get("versionEndExcluding"), exact]
                if any(r) and r not in ranges:
                    ranges.append(r)
    if not ranges:
        return None
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "") or ""
    return _score(cve.get("metrics") or {}), ranges, desc[:160]


def findings(matched: list[tuple], data: "Data", kev: set) -> list[dict]:
    out, seen = [], set()
    for i, label, cpes, ver in matched:
        for prod in cpes:
            for cid, score, _ranges, summary, fixed in data.hits(prod, ver):
                if (i, cid) in seen:
                    continue
                seen.add((i, cid))
                out.append({"cve": cid, "score": score, "exploited": cid in kev, "what": label, "installed": ver,
                            "fixed": fixed, "source": "nvd", "title": summary, "app": i})
    return out


class Data:
    """Each product's CVEs from the NVD, kept under /data so a restart doesn't fetch them all again."""

    def __init__(self, folder: Path, log):
        self.dir, self.log = folder, log
        self.products: dict = {}    # "vendor:product" -> {"cves": {id: [score, ranges, summary]}, "at", "full_at", "n"}
        self.meta: dict = {}
        self.version = 0
        self._split: dict = {}      # (product, data version) -> its CVEs with their versions split into numbers
        self._hits: dict = {}       # (product, installed version, data version) -> what affects it

    def hits(self, prod: str, ver: str) -> list[tuple]:
        """[(cve, score, ranges, summary, the version that fixes it)] for one product at one installed version.
        Worked out once per product and version: many devices run the same Chrome."""
        key = (prod, ver, self.version)
        if key in self._hits:
            return self._hits[key]
        sk = (prod, self.version)
        if sk not in self._split:
            if len(self._split) > 400:
                self._split.clear()
            self._split[sk] = [(cid, score, ranges, summary, [[_parts(x) if x else None for x in r] for r in ranges])
                               for cid, (score, ranges, summary) in ((self.products.get(prod) or {}).get("cves") or {}).items()]
        v = _parts(ver)
        out = []
        for cid, score, ranges, summary, split in self._split[sk]:
            hit = [r for r, sp in zip(ranges, split) if _affected(v, sp)]
            if hit:
                ends = [r[3] for r in hit if r[3]]
                fixed = min(ends, key=_parts) if ends else (f"after {max((r[2] for r in hit if r[2]), key=_parts)}" if any(r[2] for r in hit) else "")
                out.append((cid, score, ranges, summary, fixed or "see the CVE"))
        if len(self._hits) > 5000:
            self._hits.clear()
        self._hits[key] = out
        return out

    def _file(self, prod: str) -> Path:
        return self.dir / (re.sub(r"[^a-z0-9_.-]", "_", prod.lower()) + ".json")

    def load(self) -> None:
        self.products = {}
        try:
            self.meta = json.loads((self.dir / "meta.json").read_text())
        except (OSError, ValueError):
            self.meta = {}
        for prod in self.meta.get("products") or []:
            try:
                self.products[prod] = json.loads(self._file(prod).read_text())
            except (OSError, ValueError):
                pass
        self.version += 1

    def _save(self, prod: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self._file(prod)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.products[prod], separators=(",", ":")))
        tmp.replace(p)
        self.meta["products"] = sorted(self.products)
        tmp = self.dir / "meta.tmp"
        tmp.write_text(json.dumps(self.meta))
        tmp.replace(self.dir / "meta.json")

    def status(self) -> dict:
        return {"products": {p: {"at": d.get("at"), "cves": len(d.get("cves") or {})} for p, d in self.products.items()},
                "errors": dict(self.meta.get("errors") or {})}

    async def _page(self, session, params: dict, key: str) -> dict:
        headers = {"Accept": "application/json", "User-Agent": "Rollcall"}
        if key:
            headers["apiKey"] = key
        for attempt in range(3):
            async with session.get(NVD_URL, params=params, headers=headers) as r:
                if r.status in (403, 429, 503) and attempt < 2:  # busy or rate-limited: wait and try again
                    await asyncio.sleep(30 * (attempt + 1))
                    continue
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status}")
                body = await r.read()
            return await asyncio.get_running_loop().run_in_executor(None, json.loads, body) if len(body) > 200_000 else json.loads(body)
        raise RuntimeError("the NVD kept asking to wait")

    async def fetch(self, session, prod: str, now: float, key: str = "") -> bool:
        """One product, in full or since it was last fetched. True if its CVEs changed."""
        old = self.products.get(prod) or {}
        full = not old.get("full_at") or now - old["full_at"] > FULL_DAYS * 86400 or now - (old.get("at") or 0) > 100 * 86400
        params = {"virtualMatchString": f"cpe:2.3:a:{prod}", "resultsPerPage": PAGE, "startIndex": 0}
        if not full:
            fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")  # noqa: E731
            params.update(lastModStartDate=fmt(old["at"] - 3600), lastModEndDate=fmt(now))
        cves = {} if full else dict(old.get("cves") or {})
        before = json.dumps(old.get("cves") or {}, sort_keys=True)
        while True:
            d = await self._page(session, params, key)
            for v in d.get("vulnerabilities") or []:
                c = (v or {}).get("cve") or {}
                cid = str(c.get("id") or "")
                if not cid:
                    continue
                parsed = parse_cve(c, prod)
                if parsed:
                    cves[cid] = list(parsed)
                else:
                    cves.pop(cid, None)
            total, got = int(d.get("totalResults") or 0), params["startIndex"] + int(d.get("resultsPerPage") or 0)
            if got >= total or not d.get("vulnerabilities"):
                break
            params["startIndex"] = got
            await asyncio.sleep(SPACING if not key else 1)
        self.products[prod] = {"cves": cves, "at": now, "full_at": now if full else old.get("full_at"), "n": len(cves)}
        self._save(prod)
        return json.dumps(cves, sort_keys=True) != before

    async def refresh(self, session, now: float, wanted: set, key: str = "") -> bool:
        changed = False
        due = sorted(p for p in wanted if now - ((self.products.get(p) or {}).get("at") or 0) > DAY_HOURS * 3600)
        for n, prod in enumerate(due):
            if n:
                await asyncio.sleep(SPACING if not key else 1)
            try:
                changed |= await self.fetch(session, prod, now, key)
                (self.meta.get("errors") or {}).pop(prod, None)
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001
                self.meta.setdefault("errors", {})[prod] = str(err)[:200]
                self.log.warning("Vulnerabilities: couldn't fetch %s from the NVD (%s); trying again later", prod, err)
        if changed:
            self.version += 1
        return changed
