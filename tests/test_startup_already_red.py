"""A check that was already red before a computer started up stays red during its start-up allowance:
going grey sent "no longer critical", then it alerted again once the allowance was over.

Run from the repository root:  python3 -m pytest tests/test_startup_already_red.py
"""
import asyncio
import sys
import time
from types import SimpleNamespace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import agents as agentlib  # noqa: E402
import main  # noqa: E402
from test_ip_change_and_acks import monitor  # noqa: E402
from test_startup_vpn_route import _host  # noqa: E402

VULNS = {"key": "vulns", "label": "Vulnerabilities", "level": agentlib.CRIT, "confirm": False,
         "detail": "2 known-exploited, 9 CVEs: ExampleApp CVE-2026-0001 (9.8, exploited)", "ids": ["CVE-2026-0001"]}


def _setup(tmp_path, monkeypatch, already):
    m, sent = monitor(tmp_path, monkeypatch, [{"id": "pc01", "name": "PC01", "host": "192.168.1.20", "checks": []}])
    notes = []

    async def notify(title, msg, tag=None, critical=False, level=None, cat=None):
        notes.append(title)
    m.notify = notify
    m.vuln_check = lambda h: dict(VULNS)
    m.wordpress_check = lambda h: None
    m.agents = SimpleNamespace(agents={})
    now = time.time()
    h = m.hosts["pc01"]
    h.expect_off, h.startup_grace, h.sched_started = True, 15, now - 60   # switched on a minute ago
    if already:
        sv = main.Service(key="agent_vulns", label="Vulnerabilities", kind="agent", port=None, url=None,
                          desc="agent: vulnerabilities")
        sv.status, sv.failures = main.RED, 2                              # alerted before it was switched off
        h.agent_checks = [sv]
    return m, h, notes, sent, now


def _vulns(h):
    return next(s for s in h.agent_checks if s.key == "agent_vulns")


def test_already_red_stays_red_without_a_recovery_or_second_alert(tmp_path, monkeypatch):
    m, h, notes, sent, now = _setup(tmp_path, monkeypatch, already=True)
    asyncio.run(m._apply(h, {}, {"checks": {}}, now))
    assert main.startup_until(h, now)                                     # within its allowance
    assert _vulns(h).status == main.RED and not _vulns(h).detail.startswith("starting up")
    assert not [n for n in notes if "Vulnerabilities" in n]               # no "no longer critical"
    assert not [s for s in sent if s[0].endswith("agent_vulns") and s[1] == "dismissed"]
    h.sched_started = now - 3600                                          # allowance over
    asyncio.run(m._apply(h, {}, {"checks": {}}, now, reeval=True))
    assert _vulns(h).status == main.RED and not [n for n in notes if "Vulnerabilities" in n]  # not alerted again


def test_new_problem_while_starting_still_waits(tmp_path, monkeypatch):
    m, h, notes, sent, now = _setup(tmp_path, monkeypatch, already=False)
    asyncio.run(m._apply(h, {}, {"checks": {}}, now))
    assert _vulns(h).status == main.MAINT and _vulns(h).detail.startswith("starting up")
    assert not [n for n in notes if "Vulnerabilities" in n]
    h.sched_started = now - 3600
    asyncio.run(m._apply(h, {}, {"checks": {}}, now, reeval=True))
    assert _vulns(h).status == main.RED and [n for n in notes if "Vulnerabilities" in n] == ["🟠 PC01: Vulnerabilities"]
