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
