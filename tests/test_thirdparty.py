"""Vulnerabilities in other Windows programs (rollcall/app/thirdparty.py): Rollcall's list of programs, matching
installed versions against the NVD's affected ranges, admin-added programs, and fetching from the NVD. The NVD
answers follow its published CVE API 2.0 format with made-up CVEs.

Run from the repository root:  python3 -m pytest tests/test_thirdparty.py
"""
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import main  # noqa: E402
import thirdparty as tp  # noqa: E402
from test_ip_change_and_acks import monitor  # noqa: E402
from test_wordpress import FakeSession  # noqa: E402

APPS = [{"name": "7-Zip 23.01 (x64)", "version": "23.01"},
        {"name": "Google Chrome", "version": "131.0.6778.70"},
        {"name": "Google Chrome Remote Desktop Host", "version": "131.0.6778.70"},   # not Chrome itself
        {"name": "Notepad++ (64-bit x64)", "version": "8.7.1"},
        {"name": "Python 3.12.7 (64-bit)", "version": "3.12.7150.0"},
        {"name": "Python 3.12.7 Core Interpreter (64-bit)", "version": "3.12.7150.0"},
        {"name": "Microsoft .NET Runtime - 8.0.10 (x64)", "version": "64.40.4567"},
        {"name": "Zoom Outlook Plugin", "version": "5.17.0"},
        {"name": "Openfire 4.8.1", "version": "4.8.1"},
        {"name": "Some Internal App", "version": "1.0"}]


def cve(cid, product, matches, score=7.5, status="Analyzed"):
    return {"cve": {"id": cid, "vulnStatus": status, "descriptions": [{"lang": "en", "value": f"Something bad in {product}."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
                    "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}]}}


def m(criteria, **kw):
    return {"vulnerable": True, "criteria": criteria, **kw}


NVD = {
    "7-zip:7-zip": [cve("CVE-2026-7001", "7-Zip", [m("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", versionEndExcluding="24.07")], 7.8),
                    cve("CVE-2026-7002", "7-Zip", [m("cpe:2.3:a:7-zip:7-zip:22.00:*:*:*:*:*:*:*")], 5.5)],          # exact, not ours
    "google:chrome": [cve("CVE-2026-8001", "Chrome", [m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding="131.0.6778.85")], 8.8),
                      cve("CVE-2026-8002", "Chrome", [m("cpe:2.3:a:google:chrome:*:*:*:*:*:android:*:*", versionEndExcluding="200")], 9.6),  # Android only
                      cve("CVE-2026-8003", "Chrome", [], 9.0, status="Awaiting Analysis"),
                      cve("CVE-2026-8004", "Chrome", [m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding="999")], 9.9, status="Rejected")],
    r"don_ho:notepad\+\+": [cve("CVE-2026-9001", "Notepad++", [m(r"cpe:2.3:a:don_ho:notepad\+\+:*:*:*:*:*:*:*:*", versionEndIncluding="8.7.1")], 7.8)],
    "python:python": [cve("CVE-2026-9101", "Python", [m("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", versionStartIncluding="3.12.0", versionEndExcluding="3.12.8")], 7.5)],
    "microsoft:.net": [cve("CVE-2026-9201", ".NET", [m("cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*", versionStartIncluding="8.0.0", versionEndExcluding="8.0.11")], 9.8)],
    "igniterealtime:openfire": [cve("CVE-2026-9301", "Openfire", [m("cpe:2.3:a:igniterealtime:openfire:*:*:*:*:*:*:*:*", versionEndExcluding="4.8.2")], 9.1)],
}


def test_versions():
    c = tp.ver_cmp
    assert c("8.0.10.34221", "8.0.10") == 0 and c("8.0.10.34221", "8.0.11") < 0    # extra Windows parts aren't counted
    assert c("0.81.0.0", "0.81") == 0 and c("131.0.6778.70", "131.0.6778.85") < 0 and c("24.08", "24.07") > 0
    assert tp.affected("8.7.1", [None, None, "8.7.1", None, None]) and not tp.affected("8.7.2", [None, None, "8.7.1", None, None])
    assert tp.affected("3.12.7", ["3.12.0", None, None, "3.12.8", None]) and not tp.affected("3.11.9", ["3.12.0", None, None, "3.12.8", None])
    assert tp.affected("22.00", [None, None, None, None, "22.00"]) and not tp.affected("23.01", [None, None, None, None, "22.00"])
    assert not tp.affected("1.0", [None, None, None, None, None])


def test_matches_the_list_only():
    got = {APPS[i]["name"]: (label, v) for i, label, _c, v in tp.matches(APPS)}
    assert got["7-Zip 23.01 (x64)"] == ("7-Zip", "23.01") and got["Google Chrome"] == ("Google Chrome", "131.0.6778.70")
    assert "Google Chrome Remote Desktop Host" not in got and "Zoom Outlook Plugin" not in got
    assert got["Python 3.12.7 (64-bit)"] == ("Python", "3.12.7") and "Python 3.12.7 Core Interpreter (64-bit)" not in got
    assert got["Microsoft .NET Runtime - 8.0.10 (x64)"] == (".NET", "8.0.10")     # from the name: Windows' own number isn't the version
    assert got["Openfire 4.8.1"] == ("Openfire", "4.8.1") and "Some Internal App" not in got
    extra = tp.parse_extra(["Some Internal App = acme:internal_app", "nonsense", "x = not a cpe"])
    assert len(extra) == 1 and tp.extra_errors(["nonsense", "a = b:c"]) == ["nonsense"]
    assert any(label == "Some Internal App" for _i, label, _c, _v in tp.matches(APPS, extra))


def test_parse_cve():
    s, r, d = tp.parse_cve(NVD["google:chrome"][0]["cve"], "google:chrome")
    assert s == 8.8 and r == [[None, None, None, "131.0.6778.85", None]] and "Chrome" in d
    assert tp.parse_cve(NVD["google:chrome"][1]["cve"], "google:chrome") is None      # Android only
    assert tp.parse_cve(NVD["google:chrome"][2]["cve"], "google:chrome") is None      # not analysed yet
    assert tp.parse_cve(NVD["google:chrome"][3]["cve"], "google:chrome") is None      # rejected
    assert tp.parse_cve(NVD[r"don_ho:notepad\+\+"][0]["cve"], r"don_ho:notepad\+\+")[1] == [[None, None, "8.7.1", None, None]]


class NvdSession(FakeSession):
    def get(self, url, headers=None, params=None, **kw):
        q = "virtualMatchString=" + (params or {}).get("virtualMatchString", "")
        self.asked.append((q, params or {}))
        prod = q.split("cpe:2.3:a:", 1)[1]
        items = NVD.get(prod, [])
        from test_wordpress import FakeResp
        return FakeResp(200, {"totalResults": len(items), "resultsPerPage": len(items), "startIndex": 0, "vulnerabilities": items})


def test_fetch_and_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(tp, "SPACING", 0)
    d = tp.Data(tmp_path / "nvd", logging.getLogger("t"))
    matched = tp.matches(APPS)
    wanted = {p for _i, _l, cpes, _v in matched for p in cpes}
    s = NvdSession({})
    now = time.time()
    assert asyncio.run(d.refresh(s, now, wanted)) is True
    assert all("10.0.1" not in json.dumps(p) and "PC01" not in json.dumps(p) for _q, p in s.asked)   # only product names leave
    found = {(f["what"], f["cve"]): f for f in tp.findings(matched, d, {"CVE-2026-9301"})}
    assert set(found) == {("7-Zip", "CVE-2026-7001"), ("Google Chrome", "CVE-2026-8001"), ("Notepad++", "CVE-2026-9001"),
                          ("Python", "CVE-2026-9101"), (".NET", "CVE-2026-9201"), ("Openfire", "CVE-2026-9301")}
    assert found[("7-Zip", "CVE-2026-7001")]["fixed"] == "24.07" and found[("Notepad++", "CVE-2026-9001")]["fixed"] == "after 8.7.1"
    assert found[("Openfire", "CVE-2026-9301")]["exploited"] and found[(".NET", "CVE-2026-9201")]["app"] == 6
    # a day later: only what changed since, asked with dates
    s2 = NvdSession({})
    asyncio.run(d.refresh(s2, now + 86400, wanted))
    assert s2.asked and all("lastModStartDate" in p for _q, p in s2.asked)
    d2 = tp.Data(tmp_path / "nvd", logging.getLogger("t"))
    d2.load()
    assert d2.products["google:chrome"]["cves"].keys() == {"CVE-2026-8001"}           # kept for after a restart


def test_monitor_alerts_and_software_badges(tmp_path, monkeypatch):
    monkeypatch.setattr(tp, "SPACING", 0)
    m_, _ = monitor(tmp_path, monkeypatch, [{"id": "pc", "name": "PC01", "host": "10.0.1.20", "checks": []}])
    h = m_.hosts["pc"]
    h.agent_id, h.agent_report = "a1", {"os_family": "windows", "os": "Microsoft Windows 11 Pro"}
    m_.software = lambda aid: {"hash": "x", "updated": 1, "apps": APPS}
    m_.vuln_findings = lambda h: []
    m_.vulnfeeds.kev = set()
    wanted = {p for _i, _l, cpes, _v in m_._tp_matched(h) for p in cpes}
    assert m_.tp_view(h)["checked"] == [] and "Google Chrome" in m_.tp_view(h)["pending"]
    asyncio.run(m_.tpdata.refresh(NvdSession({}), time.time(), wanted))
    assert "Google Chrome" in m_.tp_view(h)["checked"]
    vc = m_.vuln_check(h)                                     # at or above 9 (the default): .NET and Openfire
    assert vc["level"] == main.agentlib.WARN and set(vc["ids"]) == {"CVE-2026-9201", "CVE-2026-9301"}
    badges = m_.vulns_by_app(h)
    assert set(badges) == {6, 8} and badges[6][0]["cve"] == "CVE-2026-9201"
    m_.opts["vuln_third_party"] = False
    m_._tp.clear()
    assert m_.vuln_check(h)["level"] == main.agentlib.OK and m_.vulns_by_app(h) == {}


def test_acknowledge_takes_in_programs(tmp_path, monkeypatch):
    """Acknowledging the Vulnerabilities check stored only the operating system's CVEs, so a program's vulnerability
    (e.g. Chrome's) counted as new straight away and the check never cleared (owner reported, 27 Nov)."""
    import asyncio as aio
    monkeypatch.setattr(tp, "SPACING", 0)
    m_, _ = monitor(tmp_path, monkeypatch, [{"id": "pc", "name": "PC01", "host": "10.0.1.20", "checks": []}])
    h = m_.hosts["pc"]
    h.agent_id, h.agent_report = "a1", {"os_family": "windows", "os": "Microsoft Windows 11 Pro"}
    m_.software = lambda aid: {"hash": "x", "updated": 1, "apps": APPS}
    m_.vuln_findings = lambda h: []
    m_.vulnfeeds.kev = set()
    wanted = {p for _i, _l, cpes, _v in m_._tp_matched(h) for p in cpes}
    aio.run(m_.tpdata.refresh(NvdSession({}), time.time(), wanted))
    h.agent_checks = [main.Service(key="agent_vulns", label="Vulnerabilities", kind="agent", port=None, url=None, desc="")]
    h.agent_checks[0].status = main.AMBER
    h.agent_checks[0].detail = "2 CVEs"

    async def reevaluate(_h):
        pass
    m_.reevaluate = reevaluate
    aio.run(m_.acknowledge_check(h, "vulns", "admin"))
    ids = set(m_.agent_settings["hosts"]["pc"]["check_acks"]["vulns"]["ids"])
    assert set(m_.vuln_check(h)["ids"]) <= ids and "CVE-2026-9201" in ids
