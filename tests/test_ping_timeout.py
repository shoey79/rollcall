"""ping running out of time: if the ping process finished just as the time ran out, stopping it found nothing to stop
and the whole check failed with a traceback in the log (seen for computers that were off). Now it's simply no reply."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import main  # noqa: E402


class GoneProc:
    returncode = 1

    def __init__(self, finished_first: bool):
        self.finished_first, self.killed = finished_first, False

    async def communicate(self):
        raise asyncio.TimeoutError      # the time ran out

    def kill(self):
        if self.finished_first:
            raise ProcessLookupError()  # it had already gone
        self.killed = True

    async def wait(self):
        return 1


def run(monkeypatch, proc):
    async def fake_exec(*a, **kw):
        return proc
    monkeypatch.setattr(main, "PING_MODE", "icmp")
    monkeypatch.setattr(main.asyncio, "create_subprocess_exec", fake_exec)
    return asyncio.run(main.ping("pc01.example.local", 1, 1))


def test_process_already_gone(monkeypatch):
    assert run(monkeypatch, GoneProc(True)) == (False, None)


def test_process_still_running_is_stopped(monkeypatch):
    p = GoneProc(False)
    assert run(monkeypatch, p) == (False, None) and p.killed
