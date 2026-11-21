"""Manage > Database: how big Rollcall's database and data folder are, what takes the room, and whether it's healthy.

Health is SQLite's quick_check (once a day and on demand) plus the free space on the disk the data folder is on
(Home Assistant's disk). Damage is red, with an alert: restore from an export or a Home Assistant backup. Free space
below 10% is amber, below 5% red.

"Compact now" runs VACUUM, which rewrites the database without the free pages left by old history. It needs room for
two temporary copies, so it checks the free space first, and it holds up writes while it runs.

Everything here runs on the add-on's own database connection (in a worker thread), so it never competes with
Rollcall's own writes for a lock: they simply wait until it's done.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from pathlib import Path

DAY = 86400
DISK_WARN, DISK_CRIT = 10.0, 5.0          # percent free on the data folder's disk
CHECK_EVERY = DAY
CHECK_HOURS = range(3, 6)                 # the daily check runs in the small hours (Home Assistant's time zone)

# What each table holds, for people rather than programmers
TABLES = {
    "checks": "Check history (up/down and response times)",
    "metrics": "Agent readings (disk, CPU, memory, network) for graphs",
    "syslog": "Syslog messages",
}
METRIC_RES = {0: "every report", 3600: "hourly", 86400: "daily"}

# Files and folders in the data folder, by name
FOLDERS = {
    "ping_monitor.db": "Database", "ping_monitor.db-journal": "Database (journal)",
    "ping_monitor.db-wal": "Database (write-ahead log)", "ping_monitor.db-shm": "Database (shared memory)",
    "agent_reports": "Last report from each agent", "software": "Installed software lists",
    "secrets": "Where password scanning found passwords (never the passwords)",
    "vulns": "Vulnerability data", "winget-source2.msix": "Windows package catalogue (winget)",
    "icons": "Uploaded device pictures", "agent_tls": "Built-in HTTPS certificate",
    "restore_pending": "An import waiting for the next restart",
    "hosts.json": "Devices", "agents.json": "Agent enrolments", "agent_settings.json": "Agent and alert settings",
    "views.json": "Tabs", "maintenance.json": "Paused devices", "discovery.json": "Last network scan",
    "messages.json": "Messages to users' screens", "options.json": "Settings", "update_key.pem": "Agent update signing key",
    "db_health.json": "Last database check", "claude_hints.json": "Hints from Claude (answers kept for 30 days)",
}


def fmt_bytes(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("bytes", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _size(p: Path) -> int:
    try:
        if p.is_symlink():
            return 0
        if p.is_file():
            return p.stat().st_size
        total = 0
        for root, _dirs, files in os.walk(p):
            for f in files:
                try:
                    total += os.lstat(os.path.join(root, f)).st_size
                except OSError:
                    pass
        return total
    except OSError:
        return 0


def disk(path: Path) -> dict:
    """Free space on the disk a folder is on."""
    try:
        u = shutil.disk_usage(path)
    except OSError:
        return {}
    pct = 100.0 * u.free / u.total if u.total else 0.0
    return {"total": u.total, "free": u.free, "free_pct": round(pct, 1)}


def disk_level(d: dict) -> str:
    if not d:
        return "ok"
    return "crit" if d["free_pct"] < DISK_CRIT else "warn" if d["free_pct"] < DISK_WARN else "ok"


def folder(data_dir: Path, db_name: str) -> list[dict]:
    """Each file and folder in the data folder with its size, biggest first."""
    out = []
    try:
        entries = list(data_dir.iterdir())
    except OSError:
        return out
    for p in entries:
        name = p.name
        label = FOLDERS.get(name) or FOLDERS.get(name.replace(db_name, "ping_monitor.db"))
        if not label and name.startswith("before_import_"):
            label = "Data replaced by an import (kept in case it was needed; safe to delete once you're happy)"
        out.append({"name": name, "label": label or "", "bytes": _size(p), "folder": p.is_dir()})
    return sorted(out, key=lambda e: -e["bytes"])


def _dbstat(db: sqlite3.Connection) -> dict[str, int] | None:
    """Bytes per table, indexes included, or None when SQLite was built without the dbstat table."""
    try:
        owner = {n: t for n, t in db.execute("SELECT name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index')")}
        out: dict[str, int] = {}
        for name, size in db.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name"):
            t = owner.get(name, name)
            out[t] = out.get(t, 0) + int(size or 0)
        return out
    except sqlite3.Error:
        return None


def tables(db: sqlite3.Connection, opts: dict, per_host_syslog: int = 20000) -> tuple[list[dict], dict]:
    """What takes the room in the database: rows, oldest entry, size and how long each is kept."""
    page = db.execute("PRAGMA page_size").fetchone()[0]
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    free = db.execute("PRAGMA freelist_count").fetchone()[0]
    sizes = _dbstat(db)
    hist = int(opts.get("history_days") or 7)
    mdays = int(opts.get("metrics_days") or 365)
    keep = {"checks": f"{hist} days (History, in Settings)",
            "syslog": f"{hist} days, and at most {per_host_syslog:,} messages per device",
            "metrics": f"every report for 2 days, hourly for a month, daily for {mdays} days (Agent graphs, in Settings)"}
    have = {n for (n,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    rows, total_rows = [], 0
    for t, label in TABLES.items():
        if t not in have:
            continue
        n = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608 - fixed table names
        oldest = db.execute(f"SELECT MIN(ts) FROM {t}").fetchone()[0]  # noqa: S608
        e = {"table": t, "label": label, "rows": n, "oldest": oldest, "keep": keep.get(t, ""),
             "bytes": sizes.get(t) if sizes is not None else None}
        if t == "metrics":
            e["parts"] = [{"label": METRIC_RES.get(r, f"{r} s"), "rows": c}
                          for r, c in db.execute("SELECT res, COUNT(*) FROM metrics GROUP BY res ORDER BY res")]
        rows.append(e)
        total_rows += n
    used = (pages - free) * page
    if sizes is None and total_rows:  # no dbstat: share the used pages out by rows, and say it's an estimate
        for e in rows:
            e["bytes"], e["estimate"] = int(used * e["rows"] / total_rows), True
    return sorted(rows, key=lambda e: -(e["bytes"] or 0)), {"page_size": page, "pages": pages, "free_pages": free,
                                                          "reclaimable": free * page}


def quick_check(db: sqlite3.Connection) -> tuple[bool, list[str], float]:
    """(healthy, what SQLite found, seconds taken)."""
    t = time.monotonic()
    try:
        found = [r[0] for r in db.execute("PRAGMA quick_check(20)").fetchall()]
    except sqlite3.DatabaseError as e:  # damaged badly enough that the check itself fails
        return False, [str(e)], time.monotonic() - t
    ok = found == ["ok"]
    return ok, [] if ok else [str(x)[:300] for x in found], time.monotonic() - t


def vacuum_room(db_path: Path) -> tuple[bool, int, int]:
    """(enough room, bytes needed, bytes free): VACUUM writes a temporary copy and a journal, each up to the
    database's size, in the data folder (SQLITE_TMPDIR is pointed there while it runs)."""
    size = sum(_size(db_path.with_name(db_path.name + s)) for s in ("", "-journal", "-wal"))
    need = 2 * size + 50 * 1024 * 1024
    free = disk(db_path.parent).get("free", 0)
    return free >= need, need, free


def vacuum(db: sqlite3.Connection, db_path: Path) -> tuple[int, int, float]:
    """Compact the database: (size before, size after, seconds taken)."""
    before = _size(db_path)
    t = time.monotonic()
    old = os.environ.get("SQLITE_TMPDIR")
    os.environ["SQLITE_TMPDIR"] = str(db_path.parent)
    try:
        db.commit()
        db.execute("VACUUM")
    finally:
        if old is None:
            os.environ.pop("SQLITE_TMPDIR", None)
        else:
            os.environ["SQLITE_TMPDIR"] = old
    return before, _size(db_path), time.monotonic() - t


class Health:
    """The last integrity check and compaction, kept in a small file so they survive a restart."""

    def __init__(self, path: Path):
        self.path = path
        self.state: dict = {}
        try:
            self.state = json.loads(path.read_text())
        except (OSError, ValueError):
            pass
        self.busy = ""          # "check" or "compact" while one runs
        self.alerted: dict = {}  # what's been alerted, so each problem is only sent once

    def save(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            tmp.replace(self.path)
        except OSError:
            pass

    def due(self, now: float, local_hour: int, started: float) -> bool:
        last = self.state.get("checked") or 0
        if not last:
            return now - started > 600  # first time: ten minutes after start-up
        return now - last >= CHECK_EVERY - 3600 and local_hour in CHECK_HOURS or now - last > 2 * CHECK_EVERY

    def record_check(self, ok: bool, found: list[str], took: float, now: float) -> None:
        self.state.update(checked=now, ok=ok, found=found, took=round(took, 2))
        self.save()

    def record_compact(self, before: int, after: int, took: float, now: float) -> None:
        self.state.update(compacted=now, compact_before=before, compact_after=after, compact_took=round(took, 1))
        self.save()

    def summary(self, db_path: Path) -> dict:
        """For the Overview card: level, a few words, and the sizes."""
        d = disk(db_path.parent)
        dl = disk_level(d)
        size = sum(_size(db_path.with_name(db_path.name + s)) for s in ("", "-journal", "-wal"))
        damaged = self.state.get("checked") and self.state.get("ok") is False
        if damaged:
            level, text = "crit", "Database damaged: restore from an export or a backup"
        elif dl != "ok":
            level, text = dl, f"Home Assistant's disk is {100 - d['free_pct']:.0f}% full"
        else:
            level, text = "ok", "Healthy" if self.state.get("checked") else "Not checked yet"
        return {"level": level, "text": text, "db_bytes": size, "disk": d, "checked": self.state.get("checked"),
                "ok": None if not self.state.get("checked") else bool(self.state.get("ok")), "busy": self.busy}
