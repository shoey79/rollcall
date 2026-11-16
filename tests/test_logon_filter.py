"""Failed-logon filters: expected failed logons (e.g. a service on the server trying a wrong account
against itself) can be filtered so they don't count towards the failed-logon limit or alert.

Run from the repository root:  python3 -m pytest tests/test_logon_filter.py
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402

GW = {"account": "CONTOSO\\SRV01", "source": "::1", "count": 30, "reason": "user name doesn't exist", "type": "network", "via": "NTLM"}
REAL = {"account": "CONTOSO\\admin", "source": "192.168.1.50", "count": 4, "reason": "wrong password", "type": "network", "via": "NTLM"}


def report(*top):
    return {"os": "windows", "hostname": "SRV01", "agent_version": "1.0.43",
            "security": {"failed_logons": {"count": sum(t["count"] for t in top), "top": [dict(t) for t in top]}}}


def security(result):
    return next(c for c in result["checks"] if c["key"] == "security")


def test_cleaning_a_logon_filter():
    f = A.clean_sec_filter({"kind": "logon", "account": " CONTOSO\\SRV01 ", "source": "::1", "reason": "*", "note": "gateway"})
    assert f == {"kind": "logon", "account": "CONTOSO\\SRV01", "source": "::1", "reason": "", "note": "gateway"}
    with pytest.raises(ValueError, match="needs an account"):
        A.clean_sec_filter({"kind": "logon", "account": "*", "source": ""})
    # A logon filter never hides a security event, and an event filter never hides failed logons
    assert not A.sec_filter_matches(f, {"id": 4625, "account": "CONTOSO\\SRV01"})
    assert not A.logon_filter_matches({"events": [4625], "account": "*"}, GW)


def test_filtered_failed_logons_dont_count():
    opts = {"agent_failed_logons": 20}
    r = A.evaluate(report(GW, REAL), opts, settings={})
    assert security(r)["level"] == A.CRIT and r["notable"]["failed_logons"]["alert"]

    flt = {**A.clean_sec_filter({"kind": "logon", "account": "*\\srv01", "source": "::1"}), "id": "f1", "note": ""}
    r = A.evaluate(report(GW, REAL), opts, settings={"sec_filters": [flt]})
    fl = r["notable"]["failed_logons"]
    assert security(r)["level"] == A.OK and not fl["alert"] and fl["filtered"] == 30 and fl["count"] == 34
    assert fl["top"][0]["filtered"] == "filter" and fl["top"][0]["filter_id"] == "f1" and "filtered" not in fl["top"][1]

    # A real burst on top of the filtered noise still alerts, naming only the unfiltered accounts
    burst = {**REAL, "count": 25}
    r = A.evaluate(report(GW, burst), opts, settings={"sec_filters": [flt]})
    assert security(r)["level"] == A.CRIT
    assert security(r)["detail"].startswith("25 failed logons since last report (30 more filtered). CONTOSO\\admin from")
    assert "SRV01" not in security(r)["detail"]


def test_removing_the_filter_counts_them_again():
    entry = {"count": 34, "top": [dict(GW), dict(REAL)]}
    flt = {"kind": "logon", "source": "::1", "account": "", "reason": "", "id": "f1"}
    A.apply_logon_filters(entry, [flt], 20)
    assert not entry["alert"] and entry["filtered"] == 30
    A.apply_logon_filters(entry, [], 20)
    assert entry["alert"] and entry["filtered"] == 0 and not any("filtered" in t for t in entry["top"])
