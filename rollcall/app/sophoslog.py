"""Sophos Firewall (SFOS: XG and XGS) syslog: mail and attack events picked out of the key="value" lines it sends,
for the tables on the firewall's Logs tab.

Mail: log_type "Anti-Spam" or "Anti-Virus" from the SMTP component (quarantined, rejected or delivered mail).
Attacks: log_type "IDP" (intrusion prevention) and "WAF" / "Web Server Protection".

Older SFOS (v18) and newer (v19.5 on) name some fields differently, so each column tries the names both use.
Kept in their own table for history_days, as mail details (sender, recipient, subject) are personal data; only
admins and editors can see them.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from collections import Counter, deque

DAY = 86400
_WANTED = re.compile(r'log_type="?(?:anti-?spam|anti-?virus|idp|waf|web server protection)\b', re.I)
_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')

MAIL_TYPES = {"anti-spam", "anti-virus", "antispam", "antivirus"}
ATTACK_TYPES = {"idp", "waf", "web server protection"}

# column: the field names SFOS uses for it, first found wins
MAIL = {
    "sender": ("from_email_address", "sender", "from"),
    "recipient": ("to_email_address", "recipient", "recipients", "to"),
    "subject": ("email_subject", "subject"),
    "reason": ("quarantine_reason", "reason", "spam_reason", "virus", "log_subtype"),
    "action": ("spamaction", "spam_action", "action", "status"),
    "size": ("mailsize", "mail_size", "email_size", "size"),
    "src_host": ("src_domainname", "src_host", "src_hostname", "sender_host"),
    "src_ip": ("src_ip",),
    "src_country": ("src_country_code", "src_country"),
}
ATTACK = {
    "message": ("signature_msg", "message", "reason", "msg"),
    "classification": ("classification", "category"),
    "priority": ("rule_priority", "priority", "severity"),
    "fw_rule": ("fw_rule_name", "fw_rule_id", "rule_id"),
    "src_ip": ("src_ip",),
    "src_country": ("src_country_code", "src_country"),
    "dst_ip": ("dst_ip",),
    "dst_port": ("dst_port",),
    "victim": ("victim", "target"),
    "action": ("log_subtype", "action"),  # Detect / Drop for IDP; Blocked / Allowed for WAF
    "url": ("url", "uri"),
}


def fields(msg: str) -> dict:
    """The key="value" pairs in one message (lower-case keys)."""
    out = {}
    for m in _KV.finditer(msg or ""):
        v = m.group(2) if m.group(2) is not None else m.group(3)
        out.setdefault(m.group(1).lower(), v.replace('\\"', '"'))
    return out


def _pick(f: dict, names: tuple) -> str:
    return next((f[n] for n in names if f.get(n) not in (None, "", "-")), "")


def event(msg: str) -> tuple[str, dict] | None:
    """("mail" | "attack", columns) for a Sophos mail or attack line, or None for anything else."""
    if "log_type=" not in (msg or "") or not _WANTED.search(msg):
        return None  # most of what a firewall sends: its traffic log
    f = fields(msg)
    lt = (f.get("log_type") or "").strip().lower()
    if lt in MAIL_TYPES and "smtp" in (f.get("log_component") or "").lower():
        cols = {k: _pick(f, v)[:300] for k, v in MAIL.items()}
        cols["kind"] = f.get("log_type", "")
        return "mail", cols
    if lt in ATTACK_TYPES:
        cols = {k: _pick(f, v)[:300] for k, v in ATTACK.items()}
        cols["kind"] = "IPS" if lt == "idp" else "WAF"
        return "attack", cols
    return None


class EventStore:
    """Mail and attack events per host key, in the same SQLite file as check history."""

    def __init__(self, db: sqlite3.Connection, per_host: int = 100000):
        self.db, self.per_host = db, per_host
        db.execute("CREATE TABLE IF NOT EXISTS fw_events (id INTEGER PRIMARY KEY, host TEXT NOT NULL, ts REAL NOT NULL,"
                   " kind TEXT NOT NULL, data TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_fw_events ON fw_events(host, kind, ts)")
        db.commit()
        self.pending: deque = deque()
        self.added = 0

    def add(self, host: str, ts: float, msg: str) -> bool:
        e = event(msg)
        if not e:
            return False
        self.pending.append((host, ts, e[0], json.dumps(e[1], separators=(",", ":"))))
        if len(self.pending) > 50000:
            self.pending.popleft()
        return True

    def flush(self) -> None:
        if not self.pending:
            return
        rows = list(self.pending)
        self.pending.clear()
        self.db.executemany("INSERT INTO fw_events (host, ts, kind, data) VALUES (?, ?, ?, ?)", rows)
        self.db.commit()
        self.added += len(rows)
        if self.added > 5000:
            self.added = 0
            for (h,) in self.db.execute("SELECT host FROM fw_events GROUP BY host HAVING COUNT(*) > ?", (self.per_host,)).fetchall():
                self.db.execute("DELETE FROM fw_events WHERE host = ? AND id <= (SELECT id FROM fw_events WHERE host = ?"
                                " ORDER BY id DESC LIMIT 1 OFFSET ?)", (h, h, self.per_host))
            self.db.commit()

    def has(self, host: str) -> dict:
        """{"mail": n, "attack": n}: how many of each are kept for this host."""
        self.flush()
        return dict(self.db.execute("SELECT kind, COUNT(*) FROM fw_events WHERE host = ? GROUP BY kind", (host,)).fetchall())

    def query(self, host: str, kind: str, since: float = 0, q: str = "", limit: int = 500, now: float | None = None) -> dict:
        """The newest events of one kind (filtered by q, any column), with counts per day and the top sources."""
        self.flush()
        now = now or time.time()
        rows = self.db.execute("SELECT ts, data FROM fw_events WHERE host = ? AND kind = ? AND ts >= ? ORDER BY id DESC",
                               (host, kind, since)).fetchall()
        ql = q.strip().lower()
        out, per_day, top, top2, n = [], Counter(), Counter(), Counter(), 0
        for ts, data in rows:
            try:
                d = json.loads(data)
            except ValueError:
                continue
            if ql and not any(ql in str(v).lower() for v in d.values()):
                continue
            n += 1
            per_day[time.strftime("%Y-%m-%d", time.localtime(ts))] += 1
            if kind == "mail":
                top[d.get("sender") or "(none)"] += 1
                top2[d.get("reason") or d.get("action") or "(none)"] += 1
            else:
                top[(d.get("src_ip") or "?") + (f" ({d['src_country']})" if d.get("src_country") else "")] += 1
                top2[d.get("message") or "(none)"] += 1
            if len(out) < limit:
                out.append({"ts": ts, **d})
        days = sorted(per_day.items())
        return {"rows": out, "total": n, "per_day": days, "top": top.most_common(10), "top2": top2.most_common(10)}

    def rename(self, old: str, new: str) -> None:
        self.flush()
        self.db.execute("UPDATE fw_events SET host = ? WHERE host = ?", (new, old))
        self.db.commit()

    def clear(self, host: str | None = None) -> None:
        self.flush()
        self.db.execute("DELETE FROM fw_events" + (" WHERE host = ?" if host else ""), (host,) if host else ())
        self.db.commit()

    def prune(self, before: float) -> None:
        self.flush()
        self.db.execute("DELETE FROM fw_events WHERE ts < ?", (before,))
        self.db.commit()
