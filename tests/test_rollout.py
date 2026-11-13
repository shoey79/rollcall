"""Staged agent updates: a new agent version goes to one computer first, and the rest only get it
once that computer has reported on the new version. If it goes quiet, the rollout stops.

Run from the repository root:  python3 -m pytest tests/test_rollout.py
"""
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import main  # noqa: E402

M = main.Monitor
NEW = "9.9.9"


def fake_monitor():
    m = types.SimpleNamespace(agent_settings={"auto_update": {"windows": True}, "hosts": {}}, sent=[],
                              ROLLOUT_WAIT=M.ROLLOUT_WAIT, ROLLOUT_REPICK=M.ROLLOUT_REPICK)
    m._save_agent_settings = lambda: None
    for name in ("rollout", "_rollout_allows", "rollout_seen", "rollout_sent"):
        setattr(m, name, types.MethodType(getattr(M, name), m))
    m._rollout_failed = lambda os_name, r: (r.update(state="failed"), m.sent.append(os_name))
    return m


def agent(i, ws=False):
    return {"id": f"a{i}", "hostname": f"SRV0{i}", "workstation": ws}


def offer(m, a, version="1.0.0"):
    return m._rollout_allows("windows", NEW, a, {"os_family": "windows", "agent_version": version, "workstation": a["workstation"]})


def test_pilot_first_then_everyone(monkeypatch):
    m = fake_monitor()
    t = [1000.0]
    monkeypatch.setattr(main.time, "time", lambda: t[0])
    assert offer(m, agent(1)) is True                 # the first to ask is the pilot
    assert offer(m, agent(2)) is False                # the others wait
    m.rollout_sent(agent(1), "windows")
    t[0] += 300
    assert offer(m, agent(3)) is False
    m.rollout_seen(agent(1), {"os_family": "windows", "agent_version": NEW})  # the pilot reports on the new version
    assert m.agent_settings["rollout"]["windows"]["state"] == "ok"
    assert offer(m, agent(2)) is True and offer(m, agent(3)) is True


def test_quiet_pilot_stops_the_rollout(monkeypatch):
    m = fake_monitor()
    t = [1000.0]
    monkeypatch.setattr(main.time, "time", lambda: t[0])
    assert offer(m, agent(1)) is True
    m.rollout_sent(agent(1), "windows")
    t[0] += M.ROLLOUT_WAIT + 60                        # never reported again
    assert offer(m, agent(2)) is False
    assert m.agent_settings["rollout"]["windows"]["state"] == "failed" and m.sent == ["windows"]
    assert offer(m, agent(3)) is False                # stays stopped until an admin decides


def test_servers_are_preferred_as_pilot(monkeypatch):
    m = fake_monitor()
    t = [1000.0]
    monkeypatch.setattr(main.time, "time", lambda: t[0])
    assert offer(m, agent(1, ws=True)) is False       # a workstation asks first: wait for a server
    assert offer(m, agent(2)) is True
    assert m.agent_settings["rollout"]["windows"]["pilot"] == "a2"


def test_pilot_that_never_fetches_is_replaced(monkeypatch):
    m = fake_monitor()
    t = [1000.0]
    monkeypatch.setattr(main.time, "time", lambda: t[0])
    assert offer(m, agent(1)) is True                 # chosen, but switched off before fetching it
    t[0] += M.ROLLOUT_REPICK + 60
    assert offer(m, agent(2)) is True                 # another computer becomes the pilot
    assert offer(m, agent(1)) is False


def test_single_agent_that_goes_quiet_is_still_reported(monkeypatch):
    m = fake_monitor()
    m.rollout_watch = types.MethodType(M.rollout_watch, m)
    t = [1000.0]
    monkeypatch.setattr(main.time, "time", lambda: t[0])
    assert offer(m, agent(1)) is True                 # the only agent
    m.rollout_sent(agent(1), "windows")
    m.rollout_watch(t[0] + 60)
    assert m.sent == []
    m.rollout_watch(t[0] + M.ROLLOUT_WAIT + 60)       # no other agent asks; the timer notices
    assert m.agent_settings["rollout"]["windows"]["state"] == "failed" and m.sent == ["windows"]
