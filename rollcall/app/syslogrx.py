"""Syslog receiver: parses RFC 3164 / RFC 5424 (and the looser formats small devices send),
and keeps messages in the add-on's SQLite database."""
from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
import time
from collections import deque

log = logging.getLogger("rollcall.syslog")

SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
FACILITY = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
            "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
            "local5", "local6", "local7"]
MAX_LEN = 2048

_PRI = re.compile(rb"^\s*<(\d{1,3})>")
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+)\s?(.*)$", re.S)
_3164 = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)(?:\.\d+)? (?:(\S+) )?(.*)$", re.S)
_TAG = re.compile(r"^([A-Za-z0-9_.\-/\[\]]{1,48}?)(?:\[\d+\])?:\s?(.*)$", re.S)


def parse(data: bytes) -> dict:
    """{sev, fac, host, app, msg} from one datagram. Unknown parts are left blank."""
    data = data[:MAX_LEN]
    pri, sev, fac = None, 5, 1  # no <PRI>: user.notice, as RFC 3164 says
    m = _PRI.match(data)
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            sev, fac = pri & 7, pri >> 3
        data = data[m.end():]
    text = data.decode("utf-8", "replace").replace("\x00", "").strip()
    if text.startswith("\ufeff"):
        text = text[1:]
    host = app = ""
    if m5 := _5424.match(text):
        host = "" if m5.group(2) == "-" else m5.group(2)
        app = "" if m5.group(3) == "-" else m5.group(3)
        text = m5.group(7).lstrip("\ufeff") or (m5.group(6) if m5.group(6) != "-" else "")
    elif m3 := _3164.match(text):
        rest = m3.group(3)
        host = m3.group(2) or ""
        if host.endswith(":"):  # "Mmm dd hh:mm:ss tag: msg" with no hostname
            app, host, text = re.sub(r"\[\d+\]$", "", host[:-1]), "", rest
        else:
            text = rest
            if t := _TAG.match(rest):
                app, text = t.group(1), t.group(2)
    elif t := _TAG.match(text):
        app, text = t.group(1), t.group(2)
    return {"sev": sev, "fac": fac, "host": host[:64], "app": app[:48], "msg": text.strip()[:MAX_LEN]}


class Receiver(asyncio.DatagramProtocol):
    """Calls on_message(ip, parsed) for each datagram, at most `rate` a second per sender."""

    def __init__(self, on_message, rate: int = 100):
        self.on_message, self.rate = on_message, rate
        self.buckets: dict[str, list[float]] = {}
        self.dropped = 0

    def datagram_received(self, data, addr):
        ip = addr[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        now = time.monotonic()
        b = self.buckets.setdefault(ip, [float(self.rate), now])
        b[0] = min(self.rate * 2.0, b[0] + (now - b[1]) * self.rate)
        b[1] = now
        if b[0] < 1:
            self.dropped += 1
            return
        b[0] -= 1
        if len(self.buckets) > 2000:
            self.buckets.clear()
        try:
            for line in data.split(b"\n") if data.count(b"\n") > 1 else [data]:
                if line.strip():
                    self.on_message(ip, parse(line))
        except Exception as err:  # noqa: BLE001 - one bad packet mustn't stop the receiver
            log.debug("Syslog from %s not understood: %s", ip, err)


class LogStore:
    """Messages per host key, in the same SQLite file as check history."""

    def __init__(self, db: sqlite3.Connection, per_host: int = 20000):
        self.db, self.per_host = db, per_host
        db.execute("CREATE TABLE IF NOT EXISTS syslog (id INTEGER PRIMARY KEY, host TEXT NOT NULL, ts REAL NOT NULL,"
                   " sev INTEGER NOT NULL, fac INTEGER NOT NULL, app TEXT, msg TEXT)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_syslog ON syslog(host, ts)")
        db.commit()
        self.pending: deque = deque()
        self.added = 0

    def add(self, host: str, ts: float, m: dict) -> None:
        self.pending.append((host, ts, m["sev"], m["fac"], m["app"], m["msg"]))
        if len(self.pending) > 50000:  # flusher stalled: keep the newest
            self.pending.popleft()

    def flush(self) -> None:
        if not self.pending:
            return
        rows = list(self.pending)
        self.pending.clear()
        self.db.executemany("INSERT INTO syslog (host, ts, sev, fac, app, msg) VALUES (?, ?, ?, ?, ?, ?)", rows)
        self.db.commit()
        self.added += len(rows)
        if self.added > 5000:  # now and then, keep each host to its newest per_host messages
            self.added = 0
            for (h,) in self.db.execute("SELECT host FROM syslog GROUP BY host HAVING COUNT(*) > ?", (self.per_host,)).fetchall():
                self.db.execute("DELETE FROM syslog WHERE host = ? AND id <= (SELECT id FROM syslog WHERE host = ?"
                                " ORDER BY id DESC LIMIT 1 OFFSET ?)", (h, h, self.per_host))
            self.db.commit()

    def query(self, host: str, since: float = 0, max_sev: int = 7, q: str = "", limit: int = 300) -> list[dict]:
        self.flush()
        sql = "SELECT ts, sev, fac, app, msg FROM syslog WHERE host = ? AND ts >= ? AND sev <= ?"
        args: list = [host, since, max_sev]
        if q:
            sql += " AND (msg LIKE ? ESCAPE '\\' OR app LIKE ? ESCAPE '\\')"
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like, like]
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [{"ts": r[0], "sev": r[1], "fac": r[2], "app": r[3] or "", "msg": r[4] or ""}
                for r in self.db.execute(sql, args).fetchall()]

    def stats(self, host: str, since: float) -> tuple[int, float | None]:
        self.flush()
        n, last = self.db.execute("SELECT COUNT(*), MAX(ts) FROM syslog WHERE host = ? AND ts >= ?", (host, since)).fetchone()
        return n or 0, last

    def rename(self, old: str, new: str) -> None:
        self.flush()
        self.db.execute("UPDATE syslog SET host = ? WHERE host = ?", (new, old))
        self.db.commit()

    def clear(self, host: str | None = None) -> None:
        self.flush()
        self.db.execute("DELETE FROM syslog" + (" WHERE host = ?" if host else ""), (host,) if host else ())
        self.db.commit()

    def prune(self, before: float) -> None:
        self.flush()
        self.db.execute("DELETE FROM syslog WHERE ts < ?", (before,))
        self.db.commit()


def matches(m: dict, words: list[str]) -> str | None:
    text = (m.get("app", "") + " " + m.get("msg", "")).lower()
    return next((w for w in words if w and w.lower() in text), None)


def alert_level(m: dict, threshold: int, keywords: list[str], ignore: list[str]) -> str | None:
    """'red' (critical or worse, or a keyword), 'amber' (within the alert threshold), or None."""
    if matches(m, ignore):
        return None
    if matches(m, keywords):
        return "red"
    if threshold < 0 or m["sev"] > threshold:
        return None
    return "red" if m["sev"] <= 2 else "amber"
