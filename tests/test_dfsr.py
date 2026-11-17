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


def state(folders_, events=(), errors=(), **kw):
    return A.dfsr_state({"folders": folders_, "events": list(events), "errors": list(errors), "service": "Running", "wmi_error": "", **kw}, NOW)


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


def err(i, hours_ago, level=2, count=1, folder=""):
    return {"id": i, "level": level, "count": count, "time": at(hours_ago), "folder": folder, "message": f"The DFS Replication service had problem {i}."}


def test_other_errors_alert_and_warnings_dont():
    level, detail = state(folders(4, 4), errors=[err(6404, 0.2, count=3, folder="Projects")])
    assert level == A.WARN
    assert detail == "DFS-R: event 6404 (Projects): a replicated folder's local path is invalid or can't be reached, 3 times in 24 h"
    assert state(folders(3, 4), errors=[err(9999, 1)])[1].endswith("event 9999: The DFS Replication service had problem 9999.")
    assert state(folders(4, 4), errors=[err(4302, 0.5, level=3)])[0] == A.OK          # warnings are listed only
    assert state(folders(4, 4), errors=[err(6404, 25)])[0] == A.OK                     # not in the last day
    assert state(folders(4, 4), errors=[err(6404, 2, folder="Projects")])[0] == A.OK   # folder normal again since


def test_an_error_can_be_ignored_by_id():
    ign = A.Ignore(["dfsr:event:6404"])
    v = {"folders": folders(4), "events": [], "service": "Running", "errors": [err(6404, 0.1), err(4206, 0.1)]}
    level, detail = A.dfsr_state(v, NOW, ign)
    assert level == A.WARN and "6404" not in detail and "4206" in detail
    r = A.normalize_report({"checks": {"dfsr": {"folders": [], "errors": [{"id": 6404, "level": 9, "count": "x", "time": at(1)}, 5]}}})
    assert r["checks"]["dfsr"]["errors"] == [{"id": 6404, "level": 2, "count": 1, "time": at(1), "folder": "", "message": ""}]


# -- the Time check (domain-joined Windows computers) --------------------------------------------
def tm(**kw):
    return {"role": "member", "target": "DC01.contoso.local", "offset_s": 0.2, "error": "", "source": "DC01.contoso.local", "type": "NT5DS", **kw}


def test_time_offsets():
    assert A.time_state(tm()) == (A.OK, "Within 0.2 s of DC01.contoso.local; syncing from DC01.contoso.local")
    assert A.time_state(tm(offset_s=-75.0)) == (A.WARN, "75.0 s behind DC01.contoso.local")
    level, detail = A.time_state(tm(offset_s=262.5))
    assert level == A.CRIT and detail.startswith("4.4 min ahead of DC01.contoso.local")
    assert A.time_state(tm(offset_s=20), warn_s=10, crit_s=30)[0] == A.WARN


def test_time_not_syncing_and_unreachable():
    assert A.time_state(tm(source="Local CMOS Clock"))[0] == A.WARN
    assert A.time_state(tm(offset_s=None, error="error: 0x800705B4"))[0] == A.OK      # says so, doesn't alert
    assert A.time_state(tm(offset_s=None, error="x", source="Free-running System Clock"))[0] == A.WARN


def test_pdc_emulator_needs_a_real_source():
    assert A.time_state(tm(role="pdc", source="Local CMOS Clock", offset_s=None))[0] == A.WARN
    assert A.time_state(tm(role="pdc", source="time.windows.com,0x9", offset_s=None)) == (A.OK, "PDC emulator, syncing from time.windows.com,0x9")
    r = A.normalize_report({"checks": {"time": {"role": "boss", "offset_s": "1", "source": "x" * 500}}})
    assert r["checks"]["time"]["role"] == "member" and r["checks"]["time"]["offset_s"] is None and len(r["checks"]["time"]["source"]) == 160


# -- the OpenWrt agent's internet (WAN) check ------------------------------------------------------
def wif(name, proto, up, **kw):
    return {"name": name, "proto": proto, "up": up, "autostart": True, "uptime_s": 273600 if up else None,
            "device": "eth1", "ipv4": "203.0.113.25" if up and proto != "dhcpv6" else "", "ipv6": "", "gateway": "", "error": "", "dns": [], **kw}


def test_wan():
    assert A.wan_state({"interfaces": [wif("wan", "dhcp", True)]}) == (A.OK, "wan up 3 d, 203.0.113.25")
    assert A.wan_state({"interfaces": [wif("wan", "pppoe", False, error="AUTH_FAILED")]}) == (A.CRIT, "Down: wan (pppoe), AUTH_FAILED")
    level, detail = A.wan_state({"interfaces": [wif("wan", "dhcp", True), wif("wan6", "dhcpv6", False, error="NO_ADDRESS")]})
    assert level == A.WARN and detail.startswith("IPv6 down: wan6 (dhcpv6), NO_ADDRESS")
    assert A.wan_state({"interfaces": [wif("wan", "dhcp", False), wif("wan6", "dhcpv6", False)]})[0] == A.CRIT
    assert A.wan_state({"interfaces": [wif("wan", "dhcp", False, autostart=False)]})[0] == A.OK          # switched off on purpose
    assert A.wan_state({"interfaces": [wif("wan6", "dhcpv6", False)]}, A.Ignore(["wan:wan6"]))[0] == A.OK


def test_openwrt_report_is_tidied():
    r = A.normalize_report({"agent_kind": "sh", "os_family": "linux", "checks": {"wan": {"interfaces": [
        {"name": "wan", "proto": "dhcp", "up": "yes", "uptime_s": "x", "dns": ["1.1.1.1"] * 9}, "junk"]}}})
    assert r["agent_kind"] == "sh"
    assert r["checks"]["wan"]["interfaces"] == [{"name": "wan", "proto": "dhcp", "up": False, "autostart": True, "uptime_s": None,
        "device": "", "ipv4": "", "ipv6": "", "gateway": "", "error": "", "dns": ["1.1.1.1"] * 4}]
    assert A.normalize_report({"agent_kind": "python"})["agent_kind"] is None
