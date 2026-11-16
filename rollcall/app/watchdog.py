"""Spot the add-on being held up, and keep dropped connections out of the log as tracebacks.

- Watchdog: the add-on does everything on one event loop. If something blocks it (a slow file, a big
  calculation), agents and the dashboard wait, and agents may give up. A small thread checks a
  heartbeat from the loop; if the loop hasn't answered for STALL_SECONDS it logs where the loop is
  stuck (its current stack), then how long it was held up once it recovers.
- QuietDisconnects: when an agent or browser gives up and closes the connection before Rollcall
  answers, aiohttp logs a traceback ("Cannot write to closing transport"). That's replaced with one
  plain line, at most once a minute.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import traceback

STALL_SECONDS = 5.0


class Watchdog:
    def __init__(self, log: logging.Logger, stall: float = STALL_SECONDS):
        self.log, self.stall = log, stall
        self.beat = time.monotonic()
        self.loop_thread = threading.get_ident()
        self.stalled_since: float | None = None
        self.stop = threading.Event()

    async def heartbeat(self) -> None:
        self.loop_thread = threading.get_ident()
        while True:
            now = time.monotonic()
            if self.stalled_since is not None:
                self.log.warning("Rollcall was held up for %.0f s; it's answering again", now - self.stalled_since)
                self.stalled_since = None
            self.beat = now
            await asyncio.sleep(0.5)

    def where(self) -> str:
        """The event loop's current stack, innermost last, as the add-on's own lines where possible."""
        frame = sys._current_frames().get(self.loop_thread)
        if frame is None:
            return "(couldn't see where)"
        stack = traceback.extract_stack(frame)
        mine = [f for f in stack if "/site-packages/" not in f.filename and "/lib/python" not in f.filename] or stack
        return " <- ".join(f"{f.name} ({f.filename.rsplit('/', 1)[-1]}:{f.lineno})" for f in reversed(mine[-6:]))

    def watch(self) -> None:
        while not self.stop.wait(1.0):
            if self.stalled_since is None and time.monotonic() - self.beat > self.stall:
                self.stalled_since = self.beat
                self.log.warning("Rollcall is held up (no response for over %.0f s): busy in %s", self.stall, self.where())

    def start(self) -> asyncio.Task:
        threading.Thread(target=self.watch, name="watchdog", daemon=True).start()
        return asyncio.create_task(self.heartbeat())


class QuietDisconnects(logging.Filter):
    """Turn aiohttp's traceback for a client that has already gone into one line, at most once a minute."""

    def __init__(self, log: logging.Logger, every: float = 60.0):
        super().__init__()
        self.log, self.every, self.count = log, every, 0
        self.last: float | None = None  # not 0: the clock (seconds since boot) can be under a minute

    def filter(self, record: logging.LogRecord) -> bool:
        exc = record.exc_info[1] if record.exc_info else None
        if not isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return True
        self.count += 1
        now = time.monotonic()
        if self.last is None or now - self.last >= self.every:
            self.last = now
            n, self.count = self.count, 0
            self.log.warning("%s closed the connection before Rollcall answered (it gave up waiting, or the "
                             "connection dropped)", "A client" if n == 1 else f"{n} clients")
        return False
