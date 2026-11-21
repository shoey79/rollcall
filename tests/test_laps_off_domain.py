"""LAPS: a device that hasn't been on the domain network says so instead of a bare LAPS error, and stays amber
(issue 16). Run from the repository root:  python3 -m pytest tests/test_laps_off_domain.py
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents  # noqa: E402

NOW = datetime(2026, 11, 21, 12, tzinfo=timezone.utc).timestamp()
DAY = 86400


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def laps(**kw):
    return {"product": "Windows LAPS", "enabled": True, "backup": "Active Directory", "age_days": 30,
            "account": "admin", "account_found": True, "password_set": iso(NOW - 40 * DAY), **kw}


def check(report, opts=None):
    out = agents.evaluate({"hostname": "PC01", "os": "Windows 11", **report}, opts or {}, NOW, {})
    return next(c for c in out["checks"] if c["key"] == "laps")


def test_overdue_on_the_network_is_still_red():
    c = check({"checks": {"laps": laps()}, "uptime_s": 5 * DAY})
    assert c["level"] == "crit" and "overdue" in c["detail"]


def test_away_from_the_domain_says_since_when_and_stays_amber():
    gpo = {"last_success": iso(NOW - 12 * DAY), "last_computer_success": iso(NOW - 12 * DAY),
           "failures": [{"id": 1129, "time": iso(NOW - 3600), "message": "x"}]}
    c = check({"checks": {"laps": laps(last_error="Failed to find a domain controller (0x8007054B)"), "gpo": gpo},
               "uptime_s": 5 * DAY})
    assert c["level"] == "warn" and not c.get("confirm")
    assert "Hasn't been on the domain network since 9 Nov 2026" in c["detail"]
    assert "Group Policy and LAPS" in c["detail"]
    assert "0x8007054B" not in c["detail"]


def test_group_policy_and_time_sync_without_a_laps_error():
    gpo = {"last_success": iso(NOW - 20 * 3600), "failures": [{"id": 1054, "time": iso(NOW - 600), "message": "x"}]}
    tm = {"role": "member", "offset_s": None, "error": "The computer did not resync because no time data was available"}
    c = check({"checks": {"laps": laps(), "gpo": gpo, "time": tm}, "uptime_s": 5 * DAY})
    assert c["level"] == "warn" and "since 20 Nov 2026" in c["detail"] and "Group Policy and time sync" in c["detail"]


def test_one_weak_sign_is_not_enough():
    tm = {"role": "member", "offset_s": None, "error": "no time data"}
    c = check({"checks": {"laps": laps(), "time": tm}, "uptime_s": 5 * DAY})
    assert c["level"] == "crit"


def test_just_started_is_amber():
    c = check({"checks": {"laps": laps()}, "uptime_s": 1800})
    assert c["level"] == "warn" and "started less than 2 hours ago" in c["detail"]


def test_healthy_laps_untouched():
    c = check({"checks": {"laps": laps(password_set=iso(NOW - 2 * DAY))}, "uptime_s": 5 * DAY})
    assert c["level"] == "ok"
