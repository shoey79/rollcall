"""1.99.0: an agent reporting a new address (DHCP) asks before Rollcall moves the device; a backup job's warning
can be acknowledged until its next run; security alerts stay until acknowledged by hand.

Run from the repository root:  python3 -m pytest tests/test_ip_change_and_acks.py
"""
import asyncio
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import agents as agentlib  # noqa: E402
import main  # noqa: E402
from test_upstream import FakeHA  # noqa: E402


def monitor(tmp_path, monkeypatch, hosts):
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    (tmp_path / "hosts.json").write_text(json.dumps(hosts))
    m = main.Monitor(dict(main.DEFAULTS), main.Store(tmp_path / "db.sqlite"), FakeHA())
    sent = []

    async def persist(nid, title, msg):
        sent.append((nid, title, msg))

    async def dismiss(nid):
        sent.append((nid, "dismissed", ""))
    m.persist, m.dismiss = persist, dismiss
    return m, sent


def test_ip_change_offer_accept_and_keep(tmp_path, monkeypatch):
    m, sent = monitor(tmp_path, monkeypatch, [
        {"id": "pc", "name": "PC01", "host": "192.168.1.20", "checks": ["rdp", "https://192.168.1.20:8443/", "tcp:192.168.1.200:22"]},
        {"id": "byname", "name": "SRV01", "host": "srv01.example.local", "checks": []}])
    rec = {"id": "a1", "ips": ["192.168.1.37", "10.0.1.5", "127.0.0.1"], "source_ip": "10.0.1.5", "last_report": time.time()}
    m.agents = SimpleNamespace(agents={"a1": rec, "a2": {**rec, "id": "a2"}})
    h, n = m.hosts["pc"], m.hosts["byname"]
    h.agent_id, n.agent_id = "a1", "a2"

    ch = m.ip_change(h)
    assert ch == {"current": "192.168.1.20", "suggested": "10.0.1.5", "ips": ["192.168.1.37", "10.0.1.5"]}
    assert m.ip_change(n) is None                     # monitored by name: DNS follows DHCP by itself
    rec["source_ip"] = "203.0.113.9"                  # through NAT: not one of its own, so its first one
    assert m.ip_change(h)["suggested"] == "192.168.1.37"

    asyncio.run(m.ip_change_notice(h))
    asyncio.run(m.ip_change_notice(h))
    assert len([s for s in sent if s[1] != "dismissed"]) == 1   # one notification, not one per report
    assert "192.168.1.20" in sent[0][2] and "192.168.1.37" in sent[0][2]

    # Keep: not asked again while it stays on these addresses
    assert asyncio.run(m.resolve_ip_change(h, "keep", "192.168.1.37", "admin"))
    assert m.ip_change(h) is None and h.host == "192.168.1.20"
    assert sent[-1] == ("ping_monitor_ip_pc", "dismissed", "")

    # A different new address asks again; accepting moves the device and the checks naming the old address
    rec["ips"] = ["192.168.1.44"]
    assert m.ip_change(h)["suggested"] == "192.168.1.44"
    assert not asyncio.run(m.resolve_ip_change(h, "accept", "192.168.1.99", "admin"))  # not one it reported
    assert asyncio.run(m.resolve_ip_change(h, "accept", "192.168.1.44", "admin"))
    assert h.host == "192.168.1.44" and h.ip is None
    assert h.checks == ["rdp", "https://192.168.1.44:8443/", "tcp:192.168.1.200:22"]  # .200 isn't .20
    assert m.ip_change(h) is None
    saved = json.loads((tmp_path / "hosts.json").read_text())
    assert next(x for x in saved if x["id"] == "pc")["host"] == "192.168.1.44"

    # An agent that has gone quiet doesn't ask
    rec["ips"], rec["last_report"] = ["192.168.1.50"], time.time() - 7200
    assert m.ip_change(h) is None


def test_backup_warning_acknowledged_until_next_run(tmp_path, monkeypatch):
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "srv", "name": "SRV01", "host": "10.0.1.10", "checks": []}])
    h = m.hosts["srv"]
    job = {"name": "Nightly", "product": "Veeam", "result": "Warning", "finished": "2026-11-25T02:00:00", "detail": "1 VM skipped"}
    h.agent_report = {"checks": {"backups": {"jobs": [job]}}}

    async def reevaluate(_h):
        pass
    m.reevaluate = reevaluate
    key = agentlib.backup_job_key(job)
    assert asyncio.run(m.ack_backup_job(h, key, "admin"))
    acks = m.agent_settings["hosts"]["srv"]["backup_ack"]
    view = agentlib.backup_jobs_view([dict(job)], None, acks)
    assert view[0]["acked"]
    assert agentlib.backup_job_state(view[0], time.time()) == (agentlib.OK, "warning acknowledged")

    # The next run warns again: a new run, so it's back
    later = {**job, "finished": "2026-11-26T02:00:00"}
    assert not agentlib.backup_jobs_view([later], None, acks)[0].get("acked")
    # A job that didn't warn can't be acknowledged; undo clears it
    h.agent_report["checks"]["backups"]["jobs"] = [{**job, "result": "Success"}]
    assert not asyncio.run(m.ack_backup_job(h, key, "admin"))
    assert asyncio.run(m.ack_backup_job(h, key, "admin", undo=True))
    assert "backup_ack" not in m.agent_settings["hosts"]["srv"]


def test_security_alerts_kept_until_acknowledged(tmp_path, monkeypatch):
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "srv", "name": "SRV01", "host": "10.0.1.10", "checks": []}])
    h = m.hosts["srv"]
    t0 = 1_000_000.0
    m._history_add(h, "security", [{"id": 4720, "msg": "account created", "alert": True}], t0)
    m._history_add(h, "failed_logons", [{"user": "admin", "count": 30, "alert": True}], t0)
    m._history_add(h, "events", [{"id": 7036, "msg": "service stopped", "alert": True}], t0)
    later = t0 + 3 * 86400                               # three days on, nobody has looked
    for k in ("security", "failed_logons", "events"):
        m._history_add(h, k, [], later)
    assert len(h.agent_history["security"]) == 1 and len(h.agent_history["failed_logons"]) == 1
    assert h.agent_history["events"] == []               # ordinary events are still the last 24 h
    assert len(m._recent(h, "security", later)) == 2
    m.agent_settings["hosts"].setdefault("srv", {})["ack"] = {"security": {"at": later, "by": "admin"}}
    assert m._recent(h, "security", later + 60) == []
    m._history_add(h, "security", [], later + 2 * 86400)  # acknowledged and over a day old: gone
    assert h.agent_history["security"] == []
