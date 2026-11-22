"""Scheduled tasks: runs missed while the computer was off don't count as missed, and Rollcall's own agent task
isn't watched as a scheduled task (it counts every 5-minute run missed overnight).

Run from the repository root:  python3 -m pytest tests/test_tasks_missed_while_off.py
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents  # noqa: E402

NOW = datetime(2026, 11, 22, 9, tzinfo=timezone.utc).timestamp()
H, DAY = 3600, 86400


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def task(name="Nightly copy", path="\\", **kw):
    return {"name": name, "path": path, "state": "Ready", "result": 0, "triggers": ["daily"],
            "last_run": iso(NOW - 2 * DAY), "next_run": iso(NOW + 17 * H), "missed": 0, **kw}


def state(t, uptime=None):
    return agents.task_state(t, NOW, None, None if uptime is None else NOW - uptime)


def test_rollcall_agent_task_is_not_watched():
    t = task("Ping Monitor Agent", triggers=["time"], missed=140, last_run=iso(NOW - 12 * H))
    assert state(t, uptime=600)[0] == "own"
    assert state(task("Ping Monitor Agent (start-up)", triggers=["startup"]))[0] == "own"
    assert state(task("Ping Monitor Agent", path="\\Vendor\\", missed=3), uptime=30 * DAY)[0] == "missed"  # someone else's


def test_missed_while_off_after_a_start_up():
    t = task(missed=1, last_run=iso(NOW - 30 * H))         # due at 02:00, the server started at 08:50
    assert state(t, uptime=600) == ("off", "missed 1 scheduled run while the computer was off")


def test_due_over_an_hour_ago_but_before_start_up():
    t = task(missed=0, next_run=iso(NOW - 7 * H), last_run=iso(NOW - 31 * H))
    assert state(t, uptime=2 * H)[0] == "off"


def test_missed_while_on_still_counts():
    t = task(missed=2, last_run=iso(NOW - 3 * H))           # ran after the start-up, then missed runs
    assert state(t, uptime=10 * H) == ("missed", "missed 2 scheduled runs")
    t = task(missed=0, next_run=iso(NOW - 2 * H), last_run=iso(NOW - 26 * H))   # due since the start-up, didn't run
    assert state(t, uptime=5 * H)[0] == "missed"


def test_up_for_more_than_a_day_without_running_counts_again():
    t = task(missed=1, last_run=iso(NOW - 3 * DAY))
    assert state(t, uptime=30 * H)[0] == "missed"
    assert state(task(triggers=["weekly"], missed=1, last_run=iso(NOW - 6 * DAY)), uptime=3 * DAY)[0] == "off"


def test_always_scheduled_while_off_is_flagged_after_a_week():
    t = task(missed=9, last_run=iso(NOW - 9 * DAY))
    st, why = state(t, uptime=H)
    assert st == "missed" and "hasn't run since 13 Nov 2026" in why and "as soon as possible" in why


def test_without_a_start_up_time_it_works_as_before():
    assert state(task(missed=1)) == ("missed", "missed 1 scheduled run")


def test_check_through_evaluate():
    report = {"hostname": "SRV01", "os": "Windows Server 2019", "workstation": False, "uptime_s": 900,
              "collected": iso(NOW), "checks": {"tasks": {"tasks": [
                  task("Ping Monitor Agent", triggers=["time"], missed=150, last_run=iso(NOW - 13 * H)),
                  task(missed=1, last_run=iso(NOW - 30 * H)), task("Report", triggers=["weekly"])]}}}
    c = next(c for c in agents.evaluate(report, {}, NOW, {})["checks"] if c["key"] == "tasks")
    assert c["level"] == "ok" and c["detail"] == "2 scheduled task(s) OK"   # the agent's own task left out
    report["uptime_s"] = 40 * H
    c = next(c for c in agents.evaluate(report, {}, NOW, {})["checks"] if c["key"] == "tasks")
    assert c["level"] == "warn" and c["detail"].startswith("Nightly copy: missed 1 scheduled run") and "Ping Monitor" not in c["detail"]
