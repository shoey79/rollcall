"""Issue #17: the prompt to turn off plain HTTP for agents, and the warning after, judge each agent by the listener its
reports actually arrived on, not by the address it says it sent to."""
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rollcall" / "app"))

pytest.importorskip("aiohttp")
pytest.importorskip("cryptography")
import main  # noqa: E402

DAY = 86400


class TLS:
    def __init__(self, plain=True, off_at=None):
        self.state = {"https": True, "plain_http": plain, **({"plain_off_at": off_at} if off_at else {})}
        self.plain_http = plain


def ready(monkeypatch, agents, now, **tls):
    monkeypatch.setattr(main, "AGENT_TLS", TLS(**tls))
    fake = SimpleNamespace(agents=SimpleNamespace(agents={str(i): a for i, a in enumerate(agents)}),
                           TLS_ACTIVE_DAYS=main.Monitor.TLS_ACTIVE_DAYS, TLS_LOST_AFTER=main.Monitor.TLS_LOST_AFTER)
    return main.Monitor.tls_readiness(fake, now)


def test_ready_only_when_every_active_agent_arrived_over_https(monkeypatch):
    now = time.time()
    a = {"hostname": "PC01", "last_report": now - 60, "via": "https", "sent_to": "https://10.0.1.5:8101"}
    proxy = {"hostname": "SRV01", "last_report": now - 60, "via": "http", "sent_to": "https://proxy.example.local:8443"}
    old = {"hostname": "SRV02", "last_report": now - 60, "sent_to": "https://10.0.1.5:8101"}      # nothing known yet
    off = {"hostname": "PC02", "last_report": now - 5 * DAY, "via": "http"}
    assert ready(monkeypatch, [a, off], now)["ready"] is True                # a laptop off for days doesn't hold it back
    r = ready(monkeypatch, [a, proxy, off], now)
    assert r["ready"] is False and r["http"] == ["SRV01"] and r["quiet"] == ["PC02"]
    r = ready(monkeypatch, [a, old], now)
    assert r["ready"] is False and r["unknown"] == ["SRV02"]
    assert ready(monkeypatch, [], now)["ready"] is False


def test_agents_lost_after_plain_http_goes_off(monkeypatch):
    now = time.time()
    off_at = now - 3600
    still = {"hostname": "PC01", "last_report": now - 60, "via": "https"}
    lost = {"hostname": "SRV01", "last_report": off_at - 300, "via": "http"}
    long_gone = {"hostname": "PC02", "last_report": off_at - 9 * DAY, "via": "http"}
    r = ready(monkeypatch, [still, lost, long_gone], now, plain=False, off_at=off_at)
    assert r["lost"] == ["SRV01"]
    # not straight away: agents get half an hour to report first
    assert ready(monkeypatch, [still, lost], off_at + 600, plain=False, off_at=off_at)["lost"] == []
    # and not while plain HTTP is on
    assert ready(monkeypatch, [still, lost], now, plain=True, off_at=off_at)["lost"] == []
