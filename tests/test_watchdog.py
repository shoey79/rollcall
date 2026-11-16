"""The watchdog says where the add-on is stuck when something blocks it, and dropped connections
are one line instead of a traceback.

Run from the repository root:  python3 -m pytest tests/test_watchdog.py
"""
import asyncio
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import watchdog as W  # noqa: E402


def slow_work():
    time.sleep(2.5)  # something blocking the event loop


def test_a_blocked_loop_is_reported_with_where_it_is_stuck(caplog):
    log = logging.getLogger("test_watchdog")

    async def run():
        dog = W.Watchdog(log, stall=1.0)
        task = dog.start()
        await asyncio.sleep(0.6)
        slow_work()
        await asyncio.sleep(0.7)
        task.cancel()
        dog.stop.set()

    with caplog.at_level(logging.WARNING, logger="test_watchdog"):
        asyncio.run(run())
    msgs = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("Rollcall is held up") and "slow_work (test_watchdog.py:" in m for m in msgs), msgs
    assert any(m.startswith("Rollcall was held up for") and "answering again" in m for m in msgs), msgs


def test_dropped_connections_are_one_line(caplog):
    log = logging.getLogger("test_quiet")
    server = logging.getLogger("test_aiohttp_server")
    server.addFilter(W.QuietDisconnects(log))
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            try:
                raise ConnectionResetError("Cannot write to closing transport")
            except ConnectionResetError:
                server.exception("Error handling request")
        try:
            raise ValueError("a real bug")
        except ValueError:
            server.exception("Error handling request")
    recs = [(r.name, r.getMessage(), bool(r.exc_info)) for r in caplog.records]
    assert ("test_quiet", "A client closed the connection before Rollcall answered (it gave up waiting, or the connection dropped)", False) in recs
    assert sum(1 for r in recs if r[0] == "test_quiet") == 1                    # once a minute at most
    assert ("test_aiohttp_server", "Error handling request", True) in recs and len(recs) == 2   # real errors still logged
