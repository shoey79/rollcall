"""DFS Replication check on file servers: red when replication has stopped, amber while a folder syncs
or recovers (e.g. the volume being scanned after an unclean shutdown) or a partner can't be reached.

Run from the repository root:  python3 -m pytest tests/test_dfsr.py
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402

NOW = time.time()


def at(hours_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - hours_ago * 3600))


def ev(i, hours_ago, **kw):
    return {"id": i, "time": at(hours_ago), "partner": "", "folder": "", "volume": "", "message": "", **kw}


def folders(*states):
    return [{"name": n, "group": "Files", "state": s} for n, s in zip(("Projects", "Shared", "Archive"), states)]


def state(folders_, events=(), **kw):
    return A.dfsr_state({"folders": folders_, "events": list(events), "service": "Running", "wmi_error": "", **kw}, NOW)


def test_normal():
    assert state(folders(4, 4)) == (A.OK, "2 replicated folder(s) replicating normally")


def test_recovering_after_an_unclean_shutdown_is_amber_until_it_finishes():
    level, detail = state(folders(3, 4), [ev(2212, 0.3, volume="D:")])
    assert level == A.WARN and "recovering its database on D:" in detail and "Projects in auto recovery" in detail
    assert state(folders(4, 4), [ev(2212, 2, volume="D:"), ev(2214, 1, volume="D:")])[0] == A.OK
    assert state(folders(4, 4), [ev(2212, 2, volume="D:")])[0] == A.OK      # all folders normal again: done


def test_stopped_is_red():
    level, detail = state(folders(4, 4), [ev(2213, 1, volume="C:")])
    assert level == A.CRIT and "stopped replicating on C: after an unclean shutdown" in detail
    assert state(folders(4, 4), [ev(2213, 2), ev(2214, 1)])[0] == A.OK      # resumed
    assert state(folders(5, 4))[0] == A.CRIT
    assert state(folders(4), [ev(4012, 3, folder="Projects")])[1].startswith("DFS-R: stopped replicating Projects: offline too long")
    assert state(folders(4), service="Stopped")[0] == A.CRIT


def test_partner_unreachable_for_over_an_hour():
    assert state(folders(4), [ev(5008, 0.5, partner="FS02.contoso.local")])[0] == A.OK
    level, detail = state(folders(4), [ev(5008, 2, partner="FS02.contoso.local")])
    assert level == A.WARN and "can't reach FS02.contoso.local" in detail
    assert state(folders(4), [ev(5008, 2), ev(5004, 1)])[0] == A.OK


def test_ignored_folder_and_report_tidying():
    ign = A.Ignore(["dfsr:Projects"])
    assert A.dfsr_state({"folders": folders(5, 4), "events": [], "service": "Running"}, NOW, ign) == (A.OK, "1 replicated folder(s) replicating normally")
    r = A.normalize_report({"checks": {"dfsr": {"folders": [{"name": "Projects", "group": "Files", "state": "x"}, "junk"],
                                                "events": [{"id": 2212, "time": at(1), "volume": "D:"}]}}})
    d = r["checks"]["dfsr"]
    assert d["folders"] == [{"name": "Projects", "group": "Files", "state": None}] and d["events"][0]["volume"] == "D:"
