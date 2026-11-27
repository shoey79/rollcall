"""WordPress sites on agent devices: what's installed, what's out of date and what's known to be vulnerable.

The Windows agent finds each install from IIS's own list of sites and reads its files (version.php, and the header at
the top of each plugin and theme); wp-config.php and the database are never opened. Here:

- updates: wordpress.org's public API, asked only about the slugs installed (never site names or addresses):
    GET https://api.wordpress.org/core/version-check/1.7/                                the newest WordPress
    GET https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=...   a plugin's newest version
    GET https://api.wordpress.org/themes/info/1.2/?action=theme_information&slug=...     a theme's
  A plugin wordpress.org has closed (often for a security problem) is flagged. Plugins and themes that aren't on
  wordpress.org (paid ones, the site's own) can't be checked for updates.
- known vulnerabilities: the Wordfence Intelligence feed (free, needs an API key from wordfence.com):
    GET https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production
  It's large, so it's read a record at a time and only an index of affected slugs and version ranges is kept.

Versions are compared the way PHP's version_compare() does (as WordPress and Wordfence do), except that a missing
part counts as 0, as Wordfence's own scanner treats it: 1.0 and 1.0.0 are the same.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path

CORE_URL = "https://api.wordpress.org/core/version-check/1.7/"
PLUGIN_URL = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}&request[fields][sections]=0&request[fields][description]=0&request[fields][reviews]=0&request[fields][banners]=0&request[fields][icons]=0&request[fields][screenshots]=0&request[fields][contributors]=0&request[fields][tags]=0&request[fields][ratings]=0"
THEME_URL = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={slug}&request[fields][sections]=0&request[fields][description]=0&request[fields][screenshot_url]=0&request[fields][tags]=0&request[fields][ratings]=0"
WORDFENCE_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,99}$")
INFO_DAYS = 1           # how old a plugin's or theme's wordpress.org answer may be
FEED_HOURS = 20         # how old the Wordfence feed may be
MAX_INSTALLS = 50


# -- versions (PHP's version_compare) ----------------------------------------------------------------
_SPECIAL = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "RC": 3, "rc": 3, "#": 4, "pl": 5, "p": 5}


def _canon(v: str) -> list[str]:
    v = re.sub(r"[-_+]", ".", str(v or ""))
    v = re.sub(r"(?<=\d)(?=[^\d.])|(?<=[^\d.])(?=\d)", ".", v)
    return [p for p in v.split(".") if p != ""]


def _part(a: str, b: str) -> int:
    da, db = a.isdigit(), b.isdigit()
    if da and db:
        return (int(a) > int(b)) - (int(a) < int(b))
    if not da and not db:
        x, y = _SPECIAL.get(a, -1), _SPECIAL.get(b, -1)
        return (x > y) - (x < y)
    # a number against a word: the number is newer, except against "pl"/"p" (a patch level)
    if da:
        return -1 if _SPECIAL.get(b, -1) >= 5 else 1
    return 1 if _SPECIAL.get(a, -1) >= 5 else -1


def php_cmp(a: str, b: str) -> int:
    pa, pb = _canon(a), _canon(b)
    for i in range(max(len(pa), len(pb))):
        # a missing part counts as 0, so 1.0 and 1.0.0 are the same (as Wordfence's own scanner compares them)
        x = pa[i] if i < len(pa) else "0"
        y = pb[i] if i < len(pb) else "0"
        c = _part(x, y)
        if c:
            return c
    return 0


def in_range(version: str, r: list) -> bool:
    """r = [from, from_inclusive, to, to_inclusive], with "*" for open ends (Wordfence's affected_versions)."""
    lo, lo_inc, hi, hi_inc = r
    if lo != "*":
        c = php_cmp(lo, version)
        if not (c < 0 or (lo_inc and c == 0)):
            return False
    if hi != "*":
        c = php_cmp(hi, version)
        if not (c > 0 or (hi_inc and c == 0)):
            return False
    return True


# -- what the agent sends ----------------------------------------------------------------------------
def _s(v, n: int) -> str:
    return re.sub(r"\s+", " ", str(v or "")).strip()[:n]


def clean(installs) -> list[dict]:
    out = []
    for w in installs if isinstance(installs, list) else []:
        if not isinstance(w, dict) or not _s(w.get("version"), 30):
            continue
        items = {}
        for kind in ("plugins", "themes"):
            lst = []
            for x in w.get(kind) if isinstance(w.get(kind), list) else []:
                if not isinstance(x, dict) or not _s(x.get("slug"), 100):
                    continue
                e = {"slug": _s(x["slug"], 100), "name": _s(x.get("name"), 120) or _s(x["slug"], 100), "version": _s(x.get("version"), 40)}
                if kind == "plugins" and x.get("mu"):
                    e["mu"] = True
                if kind == "themes" and x.get("parent"):
                    e["parent"] = _s(x["parent"], 100)
                lst.append(e)
            items[kind] = lst[:400]
        out.append({"site": _s(w.get("site"), 120), "path": _s(w.get("path"), 200) or "/", "dir": _s(w.get("dir"), 260),
                    "version": _s(w["version"], 30), **items})
        if len(out) >= MAX_INSTALLS:
            break
    return out


def site_label(w: dict) -> str:
    return (w.get("site") or "?") + ("" if w.get("path") in ("", "/") else w["path"])


# -- the Wordfence feed --------------------------------------------------------------------------------
def _iter_feed(path: Path, chunk: int = 1 << 20):
    """(key, record) for each entry of the feed's top-level object, read a piece at a time so the whole feed (tens
    of MB) is never held as Python objects at once."""
    dec = json.JSONDecoder()
    with open(path, "r", encoding="utf-8") as f:
        buf, pos, eof = f.read(chunk), 0, False

        def more():
            nonlocal buf, pos, eof
            new = f.read(chunk)
            if not new:
                eof = True
            buf, pos = buf[pos:] + new, 0

        def skip_ws():
            nonlocal pos
            while True:
                while pos < len(buf) and buf[pos] in " \t\r\n,":
                    pos += 1
                if pos < len(buf) or eof:
                    return
                more()

        skip_ws()
        if pos >= len(buf) or buf[pos] != "{":
            raise ValueError("not a JSON object")
        pos += 1
        while True:
            skip_ws()
            if pos >= len(buf) or buf[pos] == "}":
                return
            while True:  # key, colon and value: read more until a whole one fits
                try:
                    key, end = dec.raw_decode(buf, pos)
                    m = re.compile(r"\s*:\s*").match(buf, end)
                    if not m or m.end() >= len(buf):
                        raise ValueError
                    val, end2 = dec.raw_decode(buf, m.end())
                    break
                except ValueError:
                    if eof:
                        raise ValueError("feed ends part-way through") from None
                    more()
            pos = end2
            yield key, val


def index_feed(path: Path) -> dict:
    """{"plugin:slug" | "theme:slug" | "core:wordpress": [[id, cve, score, title, [ranges], [patched versions]]]}"""
    idx: dict = {}
    for _key, rec in _iter_feed(path):
        if not isinstance(rec, dict) or rec.get("informational"):
            continue
        cvss = rec.get("cvss") if isinstance(rec.get("cvss"), dict) else {}
        score = cvss.get("score") if isinstance(cvss.get("score"), (int, float)) else None
        for sw in rec.get("software") or []:
            if not isinstance(sw, dict) or sw.get("type") not in ("plugin", "theme", "core"):
                continue
            ranges = []
            for r in (sw.get("affected_versions") or {}).values():
                if isinstance(r, dict):
                    ranges.append([str(r.get("from_version") or "*"), bool(r.get("from_inclusive")),
                                   str(r.get("to_version") or "*"), bool(r.get("to_inclusive"))])
            if not ranges:
                continue
            k = f"{sw['type']}:{'wordpress' if sw['type'] == 'core' else str(sw.get('slug') or '').lower()}"
            idx.setdefault(k, []).append([str(rec.get("id") or ""), str(rec.get("cve") or "") or None, score,
                                          str(rec.get("title") or "")[:200], ranges, [str(v) for v in sw.get("patched_versions") or []][:10]])
    return idx


def findings(installs: list[dict], idx: dict, kev: set) -> list[dict]:
    """Known vulnerabilities in these installs, shaped like the Windows and Linux ones (vulns.py)."""
    out, seen = [], set()
    for w in installs:
        where = site_label(w)
        things = [("core", "wordpress", "WordPress", w.get("version"))]
        things += [("plugin", p["slug"].lower(), p["name"], p.get("version")) for p in w.get("plugins") or []]
        things += [("theme", t["slug"].lower(), t["name"], t.get("version")) for t in w.get("themes") or []]
        for kind, slug, name, ver in things:
            if not ver:
                continue
            for vid, cve, score, title, ranges, patched in idx.get(f"{kind}:{slug}", []):
                if not any(in_range(ver, r) for r in ranges):
                    continue
                key = (where, kind, slug, vid)
                if key in seen:
                    continue
                seen.add(key)
                newer = sorted((v for v in patched if php_cmp(v, ver) > 0), key=_canon)
                fixed = min(newer, key=lambda v: [int(x) if x.isdigit() else 0 for x in _canon(v)]) if newer else ""
                label = {"core": "WordPress", "plugin": f"{name} (plugin)", "theme": f"{name} (theme)"}[kind]
                out.append({"cve": cve or f"WF-{vid[:8]}", "score": score, "exploited": bool(cve and cve in kev),
                            "what": f"{label} on {where}", "installed": ver, "fixed": fixed or "no fix yet",
                            "source": "wordfence", "site": where, "item": label, "title": title,
                            "ref": f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{vid}" if vid else None})
    return out


# -- downloading -----------------------------------------------------------------------------------------
class Data:
    """wordpress.org's answers and the Wordfence index, kept under /data so a restart doesn't fetch them again."""

    def __init__(self, folder: Path, log):
        self.dir, self.log = folder, log
        self.core: dict = {}        # {"latest": "6.7.1", "at": ts}
        self.info: dict = {}        # "plugin:slug" -> {"latest", "closed", "at", "missing"?}
        self.wf: dict = {}          # the Wordfence index
        self.meta: dict = {}
        self.version = 0

    def _read(self, name, default):
        try:
            return json.loads((self.dir / name).read_text())
        except (OSError, ValueError):
            return default

    def _write(self, name, data) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / (name + ".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")))
        tmp.replace(self.dir / name)

    def load(self) -> None:
        self.core = self._read("core.json", {}) or {}
        self.info = self._read("info.json", {}) or {}
        self.wf = self._read("wordfence-index.json", {}) or {}
        self.meta = self._read("meta.json", {}) or {}
        self.version += 1

    def status(self) -> dict:
        m = self.meta
        return {"core_latest": self.core.get("latest"), "core_at": self.core.get("at"), "wf_at": m.get("wf_at"),
                "wf_entries": sum(len(v) for v in self.wf.values()), "errors": dict(m.get("errors") or {})}

    def _err(self, what, err) -> None:
        self.meta.setdefault("errors", {})[what] = str(err)[:200]
        self.log.warning("WordPress: couldn't update %s (%s); trying again later", what, err)

    def _ok(self, what) -> None:
        (self.meta.get("errors") or {}).pop(what, None)

    async def _get(self, session, url, **kw):
        async with session.get(url, headers={"Accept": "application/json", "User-Agent": "Rollcall"}, **kw) as r:
            body = await r.read()
            return r.status, body

    async def refresh(self, session, now: float, slugs: set, wf_key: str) -> bool:
        """Bring the answers for these slugs ({"plugin:x", "theme:y"}) and the Wordfence index up to date."""
        changed = False
        if now - (self.core.get("at") or 0) > 12 * 3600:
            try:
                st, body = await self._get(session, CORE_URL)
                if st != 200:
                    raise RuntimeError(f"HTTP {st}")
                offers = json.loads(body).get("offers") or []
                latest = next((o.get("version") for o in offers if o.get("response") in ("upgrade", "latest")), None) or (offers[0].get("version") if offers else None)
                if latest and latest != self.core.get("latest"):
                    changed = True
                self.core = {"latest": latest, "at": now}
                self._write("core.json", self.core)
                self._ok("wordpress.org")
            except Exception as err:  # noqa: BLE001
                self._err("wordpress.org", err)
        due = sorted(s for s in slugs if now - (self.info.get(s) or {}).get("at", 0) > INFO_DAYS * 86400)
        for i, s in enumerate(due[:300]):
            kind, slug = s.split(":", 1)
            if not SLUG_RE.match(slug):
                continue
            try:
                st, body = await self._get(session, (PLUGIN_URL if kind == "plugin" else THEME_URL).format(slug=slug))
                old = self.info.get(s) or {}
                if st == 404:
                    try:
                        why = json.loads(body)
                    except ValueError:
                        why = {}
                    # closed plugins answer with an error that says so; the rest simply aren't on wordpress.org
                    closed = isinstance(why, dict) and ("closed" in str(why.get("error") or "").lower() or why.get("closed"))
                    new = {"at": now, "closed": bool(closed), "missing": not closed,
                           **({"closed_date": str(why.get("closed_date") or "")[:20], "reason": str(why.get("reason_text") or why.get("reason") or "")[:100]} if closed else {})}
                elif st == 200 and isinstance(json.loads(body), dict) and json.loads(body).get("error"):
                    new = {"at": now, "closed": False, "missing": True}
                elif st == 200:
                    d = json.loads(body)
                    new = {"at": now, "latest": str(d.get("version") or "")[:40] or None,
                           "updated": str(d.get("last_updated") or "")[:30] or None, "tested": str(d.get("tested") or "")[:10] or None}
                else:
                    raise RuntimeError(f"HTTP {st}")
                if {k: v for k, v in new.items() if k != "at"} != {k: v for k, v in old.items() if k != "at"}:
                    changed = True
                self.info[s] = new
                self._ok("wordpress.org")
            except Exception as err:  # noqa: BLE001
                self._err("wordpress.org", err)
                break
            if i % 20 == 19:
                await asyncio.sleep(1)
        if due:
            self._write("info.json", self.info)
        if wf_key and now - (self.meta.get("wf_at") or 0) > FEED_HOURS * 3600:
            tmp = self.dir / "wordfence-feed.tmp"
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                async with session.get(WORDFENCE_URL, headers={"Authorization": f"Bearer {wf_key}", "Accept": "application/json",
                                                               "User-Agent": "Rollcall"}) as r:
                    if r.status in (401, 403):
                        raise RuntimeError("the Wordfence API key was turned down")
                    if r.status != 200:
                        raise RuntimeError(f"HTTP {r.status}")
                    with open(tmp, "wb") as f:
                        async for part in r.content.iter_chunked(1 << 16):
                            f.write(part)
                idx = await asyncio.get_running_loop().run_in_executor(None, index_feed, tmp)
                self.wf = idx
                self._write("wordfence-index.json", idx)
                self.meta["wf_at"] = now
                changed = True
                self._ok("Wordfence")
            except Exception as err:  # noqa: BLE001
                self._err("Wordfence", err)
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
        elif not wf_key and self.wf:
            self.wf, changed = {}, True
            self.meta.pop("wf_at", None)
            try:
                (self.dir / "wordfence-index.json").unlink()
            except OSError:
                pass
        self._write("meta.json", self.meta)
        if changed:
            self.version += 1
        return changed


def updates(installs: list[dict], data: Data) -> dict:
    """Per install: {"core": latest or None, "items": {"plugin:slug": {"latest", "closed", "missing"}}} and totals."""
    latest = data.core.get("latest")
    per, n_upd, n_closed, sites_out = [], 0, 0, 0
    for w in installs:
        items, upd = {}, 0
        core_new = latest if latest and php_cmp(latest, w.get("version") or "0") > 0 else None
        for kind in ("plugins", "themes"):
            for x in w.get(kind) or []:
                if x.get("mu"):
                    continue
                k = f"{kind[:-1]}:{x['slug'].lower()}"
                i = data.info.get(k) or {}
                e = {}
                if i.get("latest") and x.get("version") and php_cmp(i["latest"], x["version"]) > 0:
                    e["latest"] = i["latest"]
                    upd += 1
                if i.get("closed"):
                    e["closed"] = i.get("closed_date") or True
                    if i.get("reason"):
                        e["reason"] = i["reason"]
                    n_closed += 1
                if i.get("missing"):
                    e["missing"] = True
                if e:
                    items[k] = e
        n_upd += upd + (1 if core_new else 0)
        sites_out += 1 if (upd or core_new) else 0
        per.append({"core": core_new, "items": items})
    return {"sites": per, "updates": n_upd, "closed": n_closed, "sites_behind": sites_out}


def wanted(installs: list[dict]) -> set:
    out = set()
    for w in installs:
        for kind in ("plugins", "themes"):
            for x in w.get(kind) or []:
                if not x.get("mu"):
                    out.add(f"{kind[:-1]}:{x['slug'].lower()}")
    return out


def check(installs: list[dict], upd: dict, now: float | None = None) -> tuple[str, str]:
    """("ok"|"warn", detail) for the WordPress check: amber for updates waiting or a plugin closed on wordpress.org."""
    n = len(installs)
    if not n:
        return "ok", "No WordPress sites found"
    parts = []
    if upd["updates"]:
        parts.append(f"{upd['updates']} update{'s' if upd['updates'] != 1 else ''} waiting on {upd['sites_behind']} of {n} site{'s' if n != 1 else ''}")
    if upd["closed"]:
        parts.append(f"{upd['closed']} plugin{'s' if upd['closed'] != 1 else ''} closed on wordpress.org")
    if parts:
        return "warn", "; ".join(parts)
    return "ok", f"{n} site{'s' if n != 1 else ''}, all up to date"
