"""End-of-life operating systems kept on purpose: their vulnerabilities are listed but never alert (vuln_skip_os, or a
single device excluded on its own). Devices on any other OS alert exactly as before.

Run from the repository root:  python3 -m pytest tests/test_vuln_eol.py
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import agents as agentlib  # noqa: E402
from test_ip_change_and_acks import monitor  # noqa: E402

FOUND = [{"cve": "CVE-2026-0001", "score": 9.8, "exploited": True, "what": "Windows", "installed": "10.0.19045.1", "fixed": "10.0.19045.9"},
         {"cve": "CVE-2026-0002", "score": 9.1, "exploited": False, "what": "Windows", "installed": "10.0.19045.1", "fixed": "10.0.19045.9"}]


def setup(tmp_path, monkeypatch):
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "w10", "name": "PC01", "host": "10.0.1.20", "checks": []},
                                           {"id": "w11", "name": "PC02", "host": "10.0.1.21", "checks": []},
                                           {"id": "u20", "name": "SRV01", "host": "10.0.1.30", "checks": []},
                                           {"id": "s12", "name": "SRV02", "host": "10.0.1.31", "checks": []}])
    for key, os_name, fam in (("w10", "Microsoft Windows 10 Pro", "windows"), ("w11", "Microsoft Windows 11 Pro", "windows"),
                              ("u20", "Ubuntu 20.04.6 LTS", "linux"), ("s12", "Microsoft Windows Server 2012 R2 Standard", "windows")):
        m.hosts[key].agent_id, m.hosts[key].agent_report = "a-" + key, {"os": os_name, "os_family": fam}
    m.vuln_findings = lambda h: list(FOUND)
    return m


def test_os_list_matches_whole_words(tmp_path, monkeypatch):
    m = setup(tmp_path, monkeypatch)
    assert all(m.vuln_skipped(h) is None for h in m.hosts.values())     # nothing excluded by default
    m.opts["vuln_skip_os"] = ["Windows 10", "ubuntu 20.04", "Windows Server 2012"]
    assert m.vuln_skipped(m.hosts["w10"]) == "Windows 10 is excluded as end of life"
    assert m.vuln_skipped(m.hosts["w11"]) is None                      # Windows 11 isn't Windows 10
    assert m.vuln_skipped(m.hosts["u20"]) == "ubuntu 20.04 is excluded as end of life"  # 20.04.6 LTS is 20.04
    assert m.vuln_skipped(m.hosts["s12"])                              # 2012 R2 is a 2012
    m.opts["vuln_skip_os"] = ["Windows 1", "  ", "Ubuntu 2"]
    assert all(m.vuln_skipped(h) is None for h in m.hosts.values())     # no partial numbers
    m.opts["vuln_skip_os"] = ["Ubuntu 20"]
    assert m.vuln_skipped(m.hosts["u20"])                              # a whole number: every 20.x


def test_excluded_device_lists_but_never_alerts(tmp_path, monkeypatch):
    m = setup(tmp_path, monkeypatch)
    assert m.vuln_check(m.hosts["w10"])["level"] == agentlib.CRIT        # before: an exploited one is red
    m.opts["vuln_skip_os"] = ["Windows 10"]
    c = m.vuln_check(m.hosts["w10"])
    assert c["level"] == agentlib.OK and c["ids"] == [] and c["excluded"]
    assert c["detail"] == "2 known vulnerabilities, not alerted: Windows 10 is excluded as end of life"
    v = m.vulns_view(m.hosts["w10"])
    assert len(v["found"]) == 2 and v["excluded"] and not v["excluded_here"]   # still listed in its tab
    c11 = m.vuln_check(m.hosts["w11"])
    assert c11["level"] == agentlib.CRIT and "excluded" not in c11       # Windows 11: exactly as before


def test_single_device_excluded_and_back(tmp_path, monkeypatch):
    m = setup(tmp_path, monkeypatch)
    h = m.hosts["w11"]

    async def reevaluate(_h):
        pass
    m.reevaluate = reevaluate
    asyncio.run(m.set_vuln_skip(h, True, "admin"))
    assert m.vuln_check(h)["level"] == agentlib.OK and m.vulns_view(h)["excluded_here"]
    assert m.vuln_check(m.hosts["w10"])["level"] == agentlib.CRIT       # only that device
    asyncio.run(m.set_vuln_skip(h, False, "admin"))
    assert m.vuln_check(h)["level"] == agentlib.CRIT and "vuln_skip" not in m.agent_settings["hosts"]["w11"]


# Releases, as the Settings ticks show them, and LTSC/LTSB/IoT kept apart from the plain release
import oslife  # noqa: E402

R = lambda os_name, **kw: {"os": os_name, **kw}  # noqa: E731


def test_releases_from_what_agents_report():
    g = oslife.group
    assert g(R("Microsoft Windows 10 Pro (10.0.19045.5371)")) == "Windows 10"
    assert g(R("Microsoft Windows 10 Enterprise LTSC (10.0.17763.6893)", os_build="10.0.17763.6893")) == "Windows 10 Enterprise LTSC 2019"
    assert g(R("Microsoft Windows 10 Enterprise LTSC (10.0.19044.5371)")) == "Windows 10 Enterprise LTSC 2021"
    assert g(R("Microsoft Windows 10 IoT Enterprise LTSC (10.0.19044.5371)")) == "Windows 10 IoT Enterprise LTSC 2021"
    assert g(R("Microsoft Windows 10 Enterprise 2016 LTSB (10.0.14393.7700)")) == "Windows 10 Enterprise LTSB 2016"
    assert g(R("Microsoft Windows 11 Enterprise LTSC (10.0.26100.3000)")) == "Windows 11 Enterprise LTSC 2024"
    assert g(R("Microsoft Windows 11 Pro (10.0.26100.3000)")) == "Windows 11 24H2 Home/Pro"
    assert g(R("Microsoft Windows 11 Pro (10.0.29999.1)")) == "Windows 11"   # a build Rollcall doesn't know yet
    assert g(R("Microsoft Windows 8.1 Pro (6.3.9600)")) == "Windows 8.1"
    assert g(R("Microsoft Windows Server 2012 R2 Standard (6.3.9600.0)")) == "Windows Server 2012 R2"
    assert g(R("Microsoft Windows Server 2019 Datacenter (10.0.17763.6893)")) == "Windows Server 2019"
    assert g(R("Ubuntu 20.04.6 LTS", os_id="ubuntu", os_version_id="20.04")) == "Ubuntu 20.04"
    assert g(R("Debian GNU/Linux 12 (bookworm)", os_id="debian", os_version_id="12")) == "Debian 12"
    assert g(R("Ubuntu 22.04.4 LTS")) == "Ubuntu 22.04"                 # no os-release fields: from the name
    assert g(R("Debian GNU/Linux 11 (bullseye)")) == "Debian 11"
    assert g(R("")) is None and g(None) is None


def test_plain_release_leaves_ltsc_alone():
    ltsc = R("Microsoft Windows 10 Enterprise LTSC (10.0.17763.6893)")
    iot = R("Microsoft Windows 10 IoT Enterprise LTSC (10.0.19044.5371)")
    w10 = R("Microsoft Windows 10 Pro (10.0.19045.5371)")
    assert oslife.matches("Windows 10", w10) and not oslife.matches("Windows 10", ltsc) and not oslife.matches("Windows 10", iot)
    assert oslife.matches("Windows 10 Enterprise LTSC 2019", ltsc) and not oslife.matches("Windows 10 Enterprise LTSC 2019", iot)
    assert oslife.matches("LTSC", ltsc) and oslife.matches("ltsc", iot)  # named: taken in
    assert not oslife.matches("Windows 10 Enterprise LTSC 2021", ltsc)
    assert not oslife.matches("2016", R("Microsoft Windows 10 Enterprise 2016 LTSB (10.0.14393.7700)"))  # a year alone isn't LTSB


def test_end_dates():
    assert oslife.end("Windows 10") == "2025-10-14" and oslife.ended("Windows 10", now=1795000000) is True
    assert oslife.end("Windows 10 Enterprise LTSC 2019") == "2029-01-09" and oslife.ended("Windows 10 Enterprise LTSC 2019", now=1795000000) is False
    assert oslife.end("Windows 11") is None and oslife.ended("Windows 11") is None   # feature update not known


NOV_28_2026 = 1795824000


def test_windows_11_by_feature_update_and_edition():
    g = oslife.group
    ent21 = R("Microsoft Windows 11 Enterprise (10.0.22000.3260)", os_build="10.0.22000.3260")
    assert g(ent21) == "Windows 11 21H2 Enterprise/Education"
    assert oslife.end(g(ent21)) == "2024-10-08" and oslife.ended(g(ent21), now=NOV_28_2026)
    assert g(R("Microsoft Windows 11 Education", os_build="10.0.22631.6000")) == "Windows 11 23H2 Enterprise/Education"
    assert g(R("Microsoft Windows 11 Pro Education", os_build="10.0.22631.6000")) == "Windows 11 23H2 Home/Pro"
    assert g(R("Microsoft Windows 11 Home", os_build="10.0.26200.7000")) == "Windows 11 25H2 Home/Pro"
    # Enterprise gets a year longer: 23H2 ended this month for both, a year apart
    assert oslife.end("Windows 11 23H2 Home/Pro") == "2025-11-11" and oslife.end("Windows 11 23H2 Enterprise/Education") == "2026-11-10"
    assert oslife.ended("Windows 11 24H2 Home/Pro", now=NOV_28_2026) and not oslife.ended("Windows 11 24H2 Enterprise/Education", now=NOV_28_2026)
    assert not oslife.ended("Windows 11 25H2 Home/Pro", now=NOV_28_2026)
    # LTSC on the same build as 24H2 is still its own release
    assert g(R("Microsoft Windows 11 Enterprise LTSC (10.0.26100.3000)")) == "Windows 11 Enterprise LTSC 2024"
    # An existing "Windows 11" tick still takes them all in; a feature-update tick takes in just that one
    assert oslife.matches("Windows 11", ent21) and oslife.matches("windows 11 21h2 enterprise/education", ent21)
    assert not oslife.matches("Windows 11 23H2 Enterprise/Education", ent21)
    assert not oslife.matches("Windows 11", R("Microsoft Windows 11 Enterprise LTSC (10.0.26100.3000)"))


def test_out_of_support_windows_11_says_so(tmp_path, monkeypatch):
    m = setup(tmp_path, monkeypatch)
    h = m.hosts["w11"]
    h.agent_report = {"os": "Microsoft Windows 11 Enterprise", "os_build": "10.0.22000.3260", "os_family": "windows"}
    m.vulnfeeds.msrc = {"x": 1}                                   # Microsoft's data is in, but nothing for 21H2
    why = m._vuln_why_not(h)
    assert why.startswith("Not checked: Windows 11 21H2 Enterprise/Education is out of support") and "8 Oct 2024" in why
    assert "probably" not in why
    h.agent_report["os_build"] = "10.0.29999.1"                   # not known: the old guess
    assert "probably out of support" in m._vuln_why_not(h)
    # Still in Microsoft's data (it only just ended) and up to date: no vulnerabilities, but it says it's out of support
    h.agent_report = {"os": "Microsoft Windows 11 Pro", "os_build": "10.0.26100.7000", "os_family": "windows"}
    m.vuln_findings = lambda h: []
    monkeypatch.setattr(oslife.time, "time", lambda: NOV_28_2026)
    c = m.vuln_check(h)
    assert c["level"] == agentlib.OK and "Windows 11 24H2 Home/Pro is out of support (security updates ended 13 Oct 2026)" in c["detail"]


def test_settings_lists_reported_releases(tmp_path, monkeypatch):
    m = setup(tmp_path, monkeypatch)
    m.hosts["s12"].agent_report = {"os": "Microsoft Windows 10 Enterprise LTSC (10.0.17763.1)", "os_family": "windows"}
    rel = m.os_releases()
    assert [r["name"] for r in rel] == ["Windows 10", "Windows 10 Enterprise LTSC 2019", "Windows 11", "Ubuntu 20.04"]
    assert all(r["devices"] == 1 for r in rel) and rel[0]["ends"] == "2025-10-14"
    m.opts["vuln_skip_os"] = ["Windows 10"]
    assert m.vuln_skipped(m.hosts["w10"]) and m.vuln_skipped(m.hosts["s12"]) is None    # LTSC 2019 still alerts
    m.opts["vuln_skip_os"] = ["windows 10 enterprise ltsc 2019"]                        # its tick
    assert m.vuln_skipped(m.hosts["s12"]) and m.vuln_skipped(m.hosts["w10"]) is None
