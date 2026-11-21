"""Manage > Database: sizes, what takes the room, the integrity check, free disk space and Compact now.

Run from the repository root:  python3 -m pytest tests/test_database.py
"""
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import dbhealth as dbh  # noqa: E402
import metrics as metricslib  # noqa: E402
import syslogrx  # noqa: E402

NOW = time.time()


def filled(path: Path, n=3000) -> sqlite3.Connection:
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute("CREATE TABLE checks (host TEXT NOT NULL, ts REAL NOT NULL, ok INTEGER NOT NULL, latency REAL)")
    db.execute("CREATE INDEX idx_checks ON checks(host, ts)")
    metricslib.Metrics(db)
    logs = syslogrx.LogStore(db)
    db.executemany("INSERT INTO checks VALUES (?, ?, 1, 1.5)", [(f"h{i % 20}", NOW - i * 60) for i in range(n)])
    db.executemany("INSERT INTO metrics VALUES (?, ?, ?, ?, 1, 1, 1, 1)",
                   [("h1", "cpu", res, NOW - i * 300) for i in range(400) for res in (0, 3600)])
    for i in range(500):
        logs.add("sw", NOW - i, {"sev": 6, "fac": 1, "app": "x", "msg": "port up " * 20})
    logs.flush()
    db.commit()
    return db


def test_what_takes_the_room(tmp_path):
    db = filled(tmp_path / "ping_monitor.db")
    rows, pages = dbh.tables(db, {"history_days": 7, "metrics_days": 365})
    by = {r["table"]: r for r in rows}
    assert by["checks"]["rows"] == 3000 and by["syslog"]["rows"] == 500 and by["metrics"]["rows"] == 800
    assert abs(by["checks"]["oldest"] - (NOW - 2999 * 60)) < 1
    assert all(r["bytes"] > 0 for r in rows) and "7 days" in by["checks"]["keep"] and "365 days" in by["metrics"]["keep"]
    assert [p["label"] for p in by["metrics"]["parts"]] == ["every report", "hourly"]
    assert rows == sorted(rows, key=lambda r: -r["bytes"]) and pages["page_size"] > 0


def test_sizes_are_estimated_without_dbstat(tmp_path, monkeypatch):
    db = filled(tmp_path / "ping_monitor.db")
    monkeypatch.setattr(dbh, "_dbstat", lambda _db: None)
    rows, _ = dbh.tables(db, {})
    assert all(r.get("estimate") and r["bytes"] > 0 for r in rows)


def test_data_folder_lists_everything_biggest_first(tmp_path):
    filled(tmp_path / "ping_monitor.db").close()
    (tmp_path / "agent_reports").mkdir()
    (tmp_path / "agent_reports" / "abc123.json").write_text("x" * 5000)
    (tmp_path / "before_import_20261101_120000").mkdir()
    (tmp_path / "hosts.json").write_text("[]")
    f = dbh.folder(tmp_path, "ping_monitor.db")
    names = [e["name"] for e in f]
    assert names[0] == "ping_monitor.db" and "agent_reports" in names
    assert next(e for e in f if e["name"] == "agent_reports")["bytes"] == 5000
    assert "safe to delete" in next(e for e in f if e["name"].startswith("before_import_"))["label"]


def test_quick_check_finds_damage(tmp_path):
    p = tmp_path / "ping_monitor.db"
    db = filled(p, 20000)
    assert dbh.quick_check(db)[:2] == (True, [])
    db.close()
    raw = bytearray(p.read_bytes())
    page = 4096
    for at in range(3 * page, len(raw) - page, 7 * page):  # scribble over a few pages, as a failing disk would
        raw[at + 100: at + 400] = b"\xa5" * 300
    p.write_bytes(bytes(raw))
    ok, found, _ = dbh.quick_check(sqlite3.connect(p))
    assert not ok and found


def test_disk_levels():
    assert dbh.disk_level({"free_pct": 50}) == "ok"
    assert dbh.disk_level({"free_pct": 9.9}) == "warn"
    assert dbh.disk_level({"free_pct": 4.9}) == "crit"


def test_daily_check_is_due_in_the_small_hours(tmp_path):
    h = dbh.Health(tmp_path / "db_health.json")
    assert not h.due(NOW, 14, NOW - 60)            # never checked, just started: wait
    assert h.due(NOW, 14, NOW - 700)               # ten minutes in: check
    h.record_check(True, [], 0.1, NOW)
    assert not h.due(NOW + 3600, 4, 0)             # done today
    assert h.due(NOW + 23 * 3600, 4, 0)            # tomorrow's small hours
    assert not h.due(NOW + 23 * 3600, 14, 0)       # but not in the afternoon
    assert h.due(NOW + 49 * 3600, 14, 0)           # unless it's been missed for two days
    assert json.loads((tmp_path / "db_health.json").read_text())["ok"] is True
    assert dbh.Health(tmp_path / "db_health.json").state["checked"] == NOW  # survives a restart


def test_summary_levels(tmp_path, monkeypatch):
    p = tmp_path / "ping_monitor.db"
    filled(p).close()
    h = dbh.Health(tmp_path / "db_health.json")
    assert h.summary(p)["text"] == "Not checked yet" and h.summary(p)["ok"] is None
    h.record_check(True, [], 0.1, NOW)
    assert h.summary(p)["level"] == "ok" and h.summary(p)["db_bytes"] > 0
    monkeypatch.setattr(dbh, "disk", lambda _p: {"total": 100, "free": 7, "free_pct": 7.0})
    assert h.summary(p)["level"] == "warn" and "93% full" in h.summary(p)["text"]
    h.record_check(False, ["page 3 is never used"], 0.1, NOW)
    assert h.summary(p)["level"] == "crit" and "restore" in h.summary(p)["text"]


def test_compact_gives_space_back_and_needs_room(tmp_path, monkeypatch):
    p = tmp_path / "ping_monitor.db"
    db = filled(p, 30000)
    db.execute("DELETE FROM checks")
    db.commit()
    room, need, _free = dbh.vacuum_room(p)
    assert room and need > 2 * p.stat().st_size
    before, after, _ = dbh.vacuum(db, p)
    assert after < before / 2 and dbh.quick_check(db)[0]
    assert db.execute("SELECT COUNT(*) FROM syslog").fetchone()[0] == 500  # nothing else lost
    monkeypatch.setattr(dbh, "disk", lambda _p: {"total": 100, "free": 10, "free_pct": 10.0})
    assert dbh.vacuum_room(p)[0] is False


# ---- end to end through the add-on -------------------------------------------------------------------------------
from test_update_signing_e2e import HAVE_ADDON_DEPS, Addon  # noqa: E402


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_end_to_end(tmp_path):
    addon = Addon(tmp_path / "addon").start()
    try:
        st = addon.api("/api/status")
        assert st["db_health"]["text"] == "Not checked yet" and st["db_health"]["db_bytes"] > 0
        info = addon.api("/api/database")
        assert {t["table"] for t in info["tables"]} == {"checks", "metrics", "syslog"}
        assert any(f["name"] == "ping_monitor.db" for f in info["folder"]) and info["summary"]["disk"]["total"] > 0
        info = addon.api("/api/database/check", {}, "POST")
        assert info["state"]["ok"] is True and addon.api("/api/status")["db_health"]["text"] == "Healthy"
        out = addon.api("/api/database/compact", {}, "POST")
        assert out["after"] > 0 and out["state"]["compacted"]
        assert "compacted the database" in (tmp_path / "addon" / "addon.log").read_text()
    finally:
        addon.stop()


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_damage_alerts_once_and_recovery_says_so(tmp_path, monkeypatch):
    import asyncio
    import main
    from test_upstream import FakeHA
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json"), ("DB_HEALTH_PATH", "db_health.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    m = main.Monitor(dict(main.DEFAULTS), main.Store(tmp_path / "db.sqlite"), FakeHA())
    sent = []

    async def notify(title, message, **kw):
        sent.append((title, kw.get("level")))
    m.notify = notify
    bad = [False]
    monkeypatch.setattr(main.dblib, "quick_check", lambda db: (False, ["page 7: btreeInitPage() returns error code 11"], 0.1) if bad[0] else (True, [], 0.1))

    async def run():
        await m.db_check()
        bad[0] = True
        await m.db_check()
        await m.db_check()
        bad[0] = False
        await m.db_check()
    asyncio.run(run())
    assert sent == [("🔴 Rollcall's database is damaged", "red"), ("🟢 Rollcall's database is OK again", "ok")]


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_nearly_full_disk_alerts_once(tmp_path, monkeypatch):
    import asyncio
    import main
    from test_upstream import FakeHA
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json"), ("DB_HEALTH_PATH", "db_health.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    m = main.Monitor(dict(main.DEFAULTS), main.Store(tmp_path / "db.sqlite"), FakeHA())
    m.dbh.record_check(True, [], 0.1, time.time())
    sent = []

    async def notify(title, message, **kw):
        sent.append(title)
    m.notify = notify
    free = [3.0]
    monkeypatch.setattr(main.dblib, "disk", lambda _p: {"total": 100 << 30, "free": int(free[0] * (1 << 30)), "free_pct": free[0]})

    async def run():
        for pct in (3.0, 2.0, 8.0, 30.0, 30.0):
            free[0] = pct
            await m.db_health_tick(time.time())
    asyncio.run(run())
    assert sent == ["🔴 Home Assistant's disk is nearly full", "🟢 Home Assistant's disk has room again"]
