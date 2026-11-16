"""The add-on's own log for the dashboard (Manage > Log), so it can be read without going to
Settings > Apps > Rollcall > Log in Home Assistant.

It's read from the Supervisor (GET /addons/self/logs), the same log Home Assistant shows, including
lines from before the last restart. If the Supervisor refuses (or isn't there), the lines Rollcall
has logged since it started are used instead, from a buffer kept in memory. Anything that looks like
a password, token or key is masked before it leaves the add-on.
"""
from __future__ import annotations

import collections
import logging
import re

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SECRET = [
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 ••••"),
    (re.compile(r"(?i)(?<![a-z])(password|passwd|pwd|secret|token|api[_-]?key|enrol(?:ment)?[_-]?key|client[_-]?secret|community)"
                r"(\"?\s*[:=]\s*\"?)([^\s\",;&]{3,})"), r"\1\2••••"),
    (re.compile(r"(?i)([?&](?:token|key|sig|code|password)=)[^&\s]+"), r"\1••••"),
]
LEVEL = re.compile(r"\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b")


def mask(line: str) -> str:
    for rx, rep in SECRET:
        line = rx.sub(rep, line)
    return line


def clean(text: str, limit: int) -> list[str]:
    lines = [mask(ANSI.sub("", ln.rstrip("\r"))) for ln in text.split("\n")]
    while lines and not lines[-1].strip():
        lines.pop()
    return lines[-limit:]


def level_of(line: str) -> str:
    m = LEVEL.search(line[:60])
    return m.group(1) if m else ""


class Buffer(logging.Handler):
    """The last few thousand lines Rollcall has logged, for when the Supervisor's log can't be read."""

    def __init__(self, size: int = 3000):
        super().__init__()
        self.lines: collections.deque[str] = collections.deque(maxlen=size)
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.extend(self.format(record).split("\n"))
        except Exception:  # noqa: BLE001
            pass


async def read(session, supervisor: str, token: str | None, buffer: Buffer, limit: int = 2000) -> tuple[str, list[str]]:
    """(source, lines): "supervisor" with Home Assistant's log for this add-on, or "memory" with the buffer."""
    if token:
        try:
            async with session.get(f"{supervisor}/addons/self/logs",
                                   headers={"Authorization": f"Bearer {token}", "Accept": "text/plain",
                                            "Range": f"entries=:-{limit}:"}) as r:
                if r.status == 200:
                    return "supervisor", clean(await r.text(errors="replace"), limit)
        except Exception:  # noqa: BLE001
            pass
    return "memory", clean("\n".join(buffer.lines), limit)
