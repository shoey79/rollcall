"""Messages to users' screens (1.93.0): a short plain-text message from a Rollcall admin, shown on the agent devices an
admin has included, under a heading the sender can't change: "Message from the Rollcall Administrator".

Off unless the `messages` option is on. A message goes in Rollcall's reply to each included agent's next report (so
within about 5 minutes), signed with Rollcall's own key (updatesign.py) so a reply changed on the way can't put a
message of its own on anyone's screen. Windows shows it in every signed-in session (WTSSendMessage, as `msg *`
does); Linux sends it to terminals (wall). Each agent says in its next report whether it showed it, and to how many
sessions; with nobody signed in it tries again at each report until the message expires.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path

HEADING = "Message from the Rollcall Administrator"
MAX_CHARS, MAX_LINES = 500, 12
EXPIRY_HOURS = (1, 4, 24, 72)
KEEP, KEEP_DAYS = 50, 30


def clean_text(text) -> str:
    """Plain text only: no control characters (bar new lines), at most 500 characters and 12 lines."""
    t = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    t = "".join(c for c in t if c == "\n" or (c.isprintable() and c not in "‪‫‬‭‮⁦⁧⁨⁩"))
    t = re.sub(r"\n{3,}", "\n\n", t).strip()
    if not t:
        raise ValueError("Write a message first")
    if len(t) > MAX_CHARS:
        raise ValueError(f"Keep it to {MAX_CHARS} characters")
    if t.count("\n") >= MAX_LINES:
        raise ValueError(f"Keep it to {MAX_LINES} lines")
    return t


def signed_text(m: dict) -> bytes:
    """What's signed for an agent: the message's id, expiry and text (agents build the same from the reply)."""
    return f"rollcall-message/1\nid={m['id']}\nexpires={int(m['expires'])}\n{m['text']}".encode("utf-8")


class Messages:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.included: list[str] = []
        self.sent: list[dict] = []
        try:
            d = json.loads(self.path.read_text())
            self.included = [str(k) for k in d.get("included") or []][:2000]
            self.sent = [m for m in d.get("sent") or [] if isinstance(m, dict) and m.get("id")][-KEEP:]
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"included": self.included, "sent": self.sent[-KEEP:]}, indent=1))
        os.replace(tmp, self.path)

    def set_included(self, keys) -> None:
        self.included = sorted({str(k) for k in keys})[:2000]
        self.save()

    def send(self, text: str, by: str, keys: list, hours: int, label: str) -> dict:
        if hours not in EXPIRY_HOURS:
            raise ValueError("Choose how long it stays")
        to = [k for k in dict.fromkeys(keys) if k in self.included]
        if not to:
            raise ValueError("None of those devices can receive messages: include them first")
        now = time.time()
        m = {"id": secrets.token_hex(8), "text": clean_text(text), "by": str(by or "")[:80], "at": now,
             "expires": now + hours * 3600, "to": to, "label": str(label or "")[:80], "status": {}}
        self.sent = [x for x in self.sent if now - x.get("at", 0) < KEEP_DAYS * 86400] + [m]
        self.save()
        return m

    def cancel(self, mid: str) -> bool:
        for m in self.sent:
            if m["id"] == mid and not m.get("cancelled"):
                m["cancelled"] = time.time()
                self.save()
                return True
        return False

    def pending(self, key: str, now: float | None = None) -> list[dict]:
        """Messages this device should show: included, sent to it, not shown there yet, not expired or cancelled."""
        now = time.time() if now is None else now
        if key not in self.included:
            return []
        return [m for m in self.sent if key in m["to"] and not m.get("cancelled") and m["expires"] > now
                and not (m["status"].get(key) or {}).get("shown")]

    def record(self, key: str, acks, now: float | None = None) -> None:
        """What a device said in its report: [{"id", "sessions"}]; sessions 0 means nobody was signed in."""
        now = time.time() if now is None else now
        changed = False
        by_id = {m["id"]: m for m in self.sent}
        for a in acks if isinstance(acks, list) else []:
            m = by_id.get(str((a or {}).get("id") or "")) if isinstance(a, dict) else None
            if not m or key not in m["to"]:
                continue
            n = a.get("sessions")
            n = n if isinstance(n, int) and not isinstance(n, bool) and 0 <= n < 10000 else 0
            st = m["status"].get(key) or {}
            if st.get("shown"):
                continue
            new = {"shown": now, "sessions": n} if n > 0 else {"waiting": now}
            if a.get("error"):
                new = {"error": str(a["error"])[:160], "at": now}
            if set(new) == set(st) and "waiting" in new:
                continue  # still waiting: no need to write the file at every report
            if new != st:
                m["status"][key] = new
                changed = True
        if changed:
            self.save()
